use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

// The level-aware helpers live in `crate::output`; re-exported here so every
// command module keeps one import path.
pub use crate::output::{log_error, log_info, log_success, log_warning, Level};

/// A subprocess that exited unsuccessfully, carrying what it said on the way
/// out.
///
/// ── ★ WHY THE CAUSE TRAVELS WITH THE ERROR ─────────────────────────────
/// Measured 2026-09-29 on ryn: a failed `darwin-rebuild switch` ended the
/// operator's terminal with `Command failed with exit code: Some(1)` and a
/// page of Rust frames. nix's own `error:` lines had been printed live, but
/// above all that, where nobody reads. The cause is the only line that
/// matters, so it is kept here and printed LAST, just before one line that
/// names the command and its exit code.
#[derive(Debug)]
pub struct CommandFailed {
    /// Program and subcommand only (`darwin-rebuild switch`), never the full
    /// argv, which can carry an operator-supplied `--option access-tokens`.
    pub command: String,
    /// `Some(n)` for an exit code, `None` when a signal ended it.
    pub code: Option<i32>,
    /// The error block from the command's stderr, ANSI-stripped. Empty when
    /// stderr was not captured.
    pub cause: Vec<String>,
}

impl std::fmt::Display for CommandFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(n) => write!(f, "`{}` failed with exit code {n}", self.command),
            None => write!(f, "`{}` was killed by a signal", self.command),
        }
    }
}

impl std::error::Error for CommandFailed {}

/// The short, secret-free name of a command: skip a leading `sudo` and its
/// flags, then take the program's basename and the words up to the first
/// flag.
pub fn command_name(cmd: &Command) -> String {
    let mut words: Vec<String> = std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|w| w.to_string_lossy().into_owned())
        .collect();
    if words.first().is_some_and(|w| w == "sudo") {
        words.remove(0);
        while words.first().is_some_and(|w| w.starts_with('-')) {
            words.remove(0);
        }
    }
    let mut it = words.into_iter();
    let Some(program) = it.next() else {
        return String::new();
    };
    let program = program.rsplit('/').next().unwrap_or(&program).to_owned();
    std::iter::once(program)
        .chain(it.take_while(|w| !w.starts_with('-')).take(2))
        .collect::<Vec<_>>()
        .join(" ")
}

fn failed(cmd: &Command, status: ExitStatus, cause: Vec<String>) -> anyhow::Error {
    anyhow::Error::new(CommandFailed {
        command: command_name(cmd),
        code: status.code(),
        cause,
    })
}

pub fn run_command(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("Failed to execute: {:?}", cmd))?;

    if !status.success() {
        return Err(failed(cmd, status, Vec::new()));
    }

    Ok(())
}

/// How many stderr lines are remembered for the cause block.
const STDERR_TAIL_LINES: usize = 200;
/// The most lines a cause block prints.
const CAUSE_MAX_LINES: usize = 40;
/// Printed when stderr carried no `error:` line at all.
const CAUSE_FALLBACK_LINES: usize = 15;

/// Assemble a byte stream into display lines: ANSI stripped, a `\r`
/// overwrite resolved to what was left on screen, blanks dropped.
#[derive(Default)]
struct LineTail {
    partial: Vec<u8>,
    lines: VecDeque<String>,
}

impl LineTail {
    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                let raw = String::from_utf8_lossy(&self.partial).into_owned();
                self.partial.clear();
                self.push(&raw);
            } else {
                self.partial.push(b);
            }
        }
    }

    fn push(&mut self, raw: &str) {
        // A pty turns `\n` into `\r\n` (ONLCR), so a trailing `\r` is a line
        // end, not an overwrite.
        let raw = raw.trim_end_matches('\r');
        let visible = raw.rsplit('\r').next().unwrap_or(raw);
        let line = strip_ansi(visible);
        if line.trim().is_empty() {
            return;
        }
        if self.lines.len() == STDERR_TAIL_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(line.trim_end().to_owned());
    }

    fn finish(&mut self) {
        if !self.partial.is_empty() {
            let raw = String::from_utf8_lossy(&self.partial).into_owned();
            self.partial.clear();
            self.push(&raw);
        }
    }

    /// The error block: from the first `error:` line in the tail to the end,
    /// or the last few lines when nothing says `error`.
    fn cause(&self) -> Vec<String> {
        let lines: Vec<&String> = self.lines.iter().collect();
        let start = lines
            .iter()
            .position(|l| l.trim_start().starts_with("error:"))
            .unwrap_or(lines.len().saturating_sub(CAUSE_FALLBACK_LINES));
        let block = &lines[start..];
        let skip = block.len().saturating_sub(CAUSE_MAX_LINES);
        block[skip..].iter().map(|l| (*l).clone()).collect()
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(ch) = it.next() {
        if ch == '\u{1b}' {
            match it.peek() {
                Some('[') => {
                    it.next();
                    for c in it.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(_) => {
                    it.next();
                }
                None => {}
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// How the child's stderr reaches the operator while we keep a copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StderrTee {
    /// A pseudo-terminal, so a child that draws progress for a terminal
    /// (nix's status bar) draws exactly what it drew before. Used when our
    /// own stderr is a terminal.
    Pty,
    /// A pipe, for when our stderr is not a terminal anyway.
    Pipe,
}

impl StderrTee {
    fn for_this_process() -> Self {
        if io::IsTerminal::is_terminal(&io::stderr()) {
            StderrTee::Pty
        } else {
            StderrTee::Pipe
        }
    }
}

/// Open a pty whose window size matches our stderr's. Both ends close on
/// exec; the child gets the slave through `Command::stderr`, which dup2s it.
#[cfg(unix)]
#[allow(unsafe_code)]
fn open_pty() -> io::Result<(std::fs::File, std::fs::File)> {
    use std::os::fd::FromRawFd;
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: zeroed winsize is a valid value; ioctl writes into it.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ on fd 2 writes one winsize into `ws`.
    let have_ws = unsafe { libc::ioctl(2, libc::TIOCGWINSZ, &mut ws) } == 0;
    let winp: *mut libc::winsize = if have_ws {
        &mut ws
    } else {
        std::ptr::null_mut()
    };
    // SAFETY: openpty writes two fds; name and termios are optional (null).
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            winp,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    for fd in [master, slave] {
        // SAFETY: fd was just returned by openpty and is owned here.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    // SAFETY: each fd is open, owned, and handed to exactly one File.
    Ok(unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    })
}

/// Copy `src` to our stderr as it arrives, keeping the tail. Returns once
/// `src` reaches EOF (or EIO, which is how a Linux pty master says the last
/// slave closed).
fn spawn_tee(
    mut src: impl Read + Send + 'static,
    tail: Arc<Mutex<LineTail>>,
) -> mpsc::Receiver<()> {
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        let mut err = io::stderr();
        loop {
            match src.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = err.write_all(&buf[..n]);
                    let _ = err.flush();
                    if let Ok(mut t) = tail.lock() {
                        t.feed(&buf[..n]);
                    }
                }
            }
        }
        if let Ok(mut t) = tail.lock() {
            t.finish();
        }
        let _ = done_tx.send(());
    });
    done_rx
}

fn pipe_ends() -> Result<(Box<dyn Read + Send>, Stdio)> {
    let (r, w) = io::pipe().context("could not open a pipe for stderr")?;
    Ok((Box::new(r), Stdio::from(w)))
}

/// Default wall-clock ceiling for a rebuild. Generous on purpose: a cold
/// build of a full darwin/NixOS closure legitimately takes a long time, and
/// killing real work is worse than the hang this guards against.
const DEFAULT_REBUILD_TIMEOUT_SECS: u64 = 5400; // 90 min

/// How long a rebuild may run before it is treated as wedged.
///
/// `FLEET_REBUILD_TIMEOUT_SECS=0` disables the guard entirely (back to the
/// old block-forever behaviour) for the rare genuinely-longer-than-90-minutes
/// build. Configure-off, not removed.
pub fn rebuild_timeout() -> Option<Duration> {
    match std::env::var("FLEET_REBUILD_TIMEOUT_SECS") {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(Duration::from_secs(n)),
            Err(_) => {
                log_warning(Level::Required, &format!(
                    "FLEET_REBUILD_TIMEOUT_SECS={v:?} is not a number — using default {DEFAULT_REBUILD_TIMEOUT_SECS}s"
                ));
                Some(Duration::from_secs(DEFAULT_REBUILD_TIMEOUT_SECS))
            }
        },
        Err(_) => Some(Duration::from_secs(DEFAULT_REBUILD_TIMEOUT_SECS)),
    }
}

/// Run a command, failing LOUDLY if it exceeds `timeout` instead of blocking
/// forever.
///
/// WHY THIS EXISTS (ryn, 2026-07-26): `darwin-rebuild switch` sat for 27
/// minutes with NO log progress, no builder children, and its GitHub sockets in
/// CLOSED state. nix ≥2.19 fetches git flake inputs IN-PROCESS via libgit2,
/// and a libgit2 fetch honours none of nix's download settings —
/// `connect-timeout`, `stalled-download-timeout` and `download-attempts` were
/// all set and none applied. The connection died, nothing noticed, and the
/// build parked indefinitely. `run_command` uses `.status()`, which blocks
/// forever, so the hang propagated all the way up with no diagnostic.
///
/// A wall-clock ceiling cannot distinguish "wedged" from "slow", so it is
/// deliberately generous. It converts an infinite hang into a loud, actionable
/// failure — the fleet's own rule: every orchestration step detects, reports
/// and exits; it never hangs.
///
/// The child is placed in its OWN PROCESS GROUP and the whole group is
/// signalled. That matters here specifically: the thing that wedges is a
/// GRANDCHILD (`nix build` under `darwin-rebuild` under `sudo`), so killing
/// only the direct child would orphan the actual hang.
pub fn run_command_timed(cmd: &mut Command, timeout: Option<Duration>) -> Result<()> {
    run_command_teed(cmd, timeout, StderrTee::for_this_process())
}

/// [`run_command_timed`] with the stderr transport chosen by the caller, so
/// tests can drive both the pty and the pipe path.
///
/// stderr is copied to ours LIVE — the operator sees exactly what they saw
/// when it was inherited — while the tail is kept, so a failure can end with
/// the command's own error instead of an exit code alone.
pub fn run_command_teed(
    cmd: &mut Command,
    timeout: Option<Duration>,
    tee: StderrTee,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let (reader, child_end): (Box<dyn Read + Send>, Stdio) = match tee {
        #[cfg(unix)]
        StderrTee::Pty => match open_pty() {
            Ok((master, slave)) => (Box::new(master), Stdio::from(slave)),
            // No pty available is not a reason to refuse the rebuild: fall
            // back to a pipe, which loses only the child's progress bar.
            Err(_) => pipe_ends()?,
        },
        _ => pipe_ends()?,
    };

    let spawned = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(child_end)
        .spawn()
        .with_context(|| format!("Failed to execute: {cmd:?}"));
    // Drop OUR copy of the child's end (the Command holds it until replaced);
    // otherwise the reader never sees EOF.
    cmd.stderr(Stdio::inherit());
    let mut child = spawned?;

    let tail = Arc::new(Mutex::new(LineTail::default()));
    let drained = spawn_tee(reader, Arc::clone(&tail));
    let finish = |status: ExitStatus| -> Result<()> {
        // A grandchild that kept stderr open must not hold the result hostage.
        let _ = drained.recv_timeout(Duration::from_secs(2));
        if status.success() {
            return Ok(());
        }
        let cause = tail.lock().map(|t| t.cause()).unwrap_or_default();
        Err(failed(cmd, status, cause))
    };

    let pid = child.id();
    let start = Instant::now();

    loop {
        if let Some(status) = child.try_wait().context("waiting on child")? {
            return finish(status);
        }

        let Some(timeout) = timeout else {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        };
        if start.elapsed() >= timeout {
            log_error(&format!(
                "no completion after {}s — treating as wedged and killing process group {pid}",
                timeout.as_secs()
            ));
            kill_group(pid);
            std::thread::sleep(Duration::from_secs(3));
            let _ = child.try_wait();
            kill_group_hard(pid);
            let _ = child.wait();

            anyhow::bail!(
                "rebuild exceeded {}s and was killed.\n\
                 \n\
                 This is usually a WEDGED flake-input fetch, not a slow build. nix\n\
                 fetches git inputs in-process via libgit2, which ignores\n\
                 connect-timeout / stalled-download-timeout / download-attempts, so a\n\
                 dropped connection parks forever instead of erroring.\n\
                 \n\
                 CONFIRM before retrying. The signal is whether the BUILD LOG is\n\
                 still advancing — NOT cpu%. The `nix build` client sits near 0%%\n\
                 CPU even on a perfectly healthy build, because the nix-daemon does\n\
                 the work in separate processes:\n\
                   a=$(wc -l < <logfile>); sleep 30; b=$(wc -l < <logfile>); echo $((b-a))\n\
                 Non-zero means it is building and you should raise the ceiling.\n\
                 Zero, plus no builder children, means it is genuinely wedged:\n\
                   pgrep -P $(pgrep -x nix-daemon | head -1) | wc -l\n\
                 \n\
                 If the build is genuinely this long, raise or disable the ceiling:\n\
                   FLEET_REBUILD_TIMEOUT_SECS=10800 fleet rebuild   # 3h\n\
                   FLEET_REBUILD_TIMEOUT_SECS=0     fleet rebuild   # no ceiling",
                timeout.as_secs()
            )
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

/// SIGTERM the child's process group (argv form — no shell).
fn kill_group(pid: u32) {
    let _ = Command::new("kill")
        .args(["-TERM", &format!("-{pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// SIGKILL the child's process group after the grace period.
fn kill_group_hard(pid: u32) {
    let _ = Command::new("kill")
        .args(["-KILL", &format!("-{pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn run_command_output(cmd: &mut Command) -> Result<String> {
    let output = cmd
        .output()
        .with_context(|| format!("Failed to execute: {:?}", cmd))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Command failed: {}", stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn ssh_cmd_with_config(user: &str, host: &str, ssh: &crate::config::ResolvedSsh) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o")
        .arg(format!("ConnectTimeout={}", ssh.connect_timeout));
    cmd.arg("-o")
        .arg(format!("StrictHostKeyChecking={}", ssh.strict_host_key));
    for (k, v) in &ssh.options {
        cmd.arg("-o").arg(format!("{}={}", k, v));
    }
    cmd.arg(format!("{}@{}", user, host));
    cmd
}

pub fn ssh_run_with_config(
    user: &str,
    host: &str,
    ssh: &crate::config::ResolvedSsh,
    remote_cmd: &str,
) -> Result<String> {
    let mut cmd = ssh_cmd_with_config(user, host, ssh);
    cmd.arg(remote_cmd);
    run_command_output(&mut cmd)
}

pub fn node_label(name: &str) -> String {
    format!("[{}]", name).cyan().bold().to_string()
}

pub fn confirm(msg: &str) -> Result<bool> {
    print!("{} {} ", "[?]".yellow().bold(), msg);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let answer = input.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

pub fn flake_dir() -> String {
    // Prefer local detection: walk up to find flake.nix
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(root) = super::rebuild::find_flake_root(&cwd) {
            return root.to_string_lossy().to_string();
        }
    }
    // Fall back to env var for backwards compatibility (nix wrapper sets this)
    std::env::var("FLEET_FLAKE_DIR").unwrap_or_else(|_| ".".to_string())
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    fn with_env<T>(val: Option<&str>, f: impl FnOnce() -> T) -> T {
        let prev = std::env::var("FLEET_REBUILD_TIMEOUT_SECS").ok();
        match val {
            Some(v) => unsafe { std::env::set_var("FLEET_REBUILD_TIMEOUT_SECS", v) },
            None => unsafe { std::env::remove_var("FLEET_REBUILD_TIMEOUT_SECS") },
        }
        let out = f();
        match prev {
            Some(p) => unsafe { std::env::set_var("FLEET_REBUILD_TIMEOUT_SECS", p) },
            None => unsafe { std::env::remove_var("FLEET_REBUILD_TIMEOUT_SECS") },
        }
        out
    }

    /// All env-var cases in ONE test on purpose: `FLEET_REBUILD_TIMEOUT_SECS`
    /// is process-global, so separate #[test] fns race under cargo's parallel
    /// runner and clobber each other's setup. (They did — `default_ceiling_is_on`
    /// failed on the first run for exactly this reason, not because the code
    /// was wrong.)
    #[test]
    fn timeout_resolution_covers_every_env_case() {
        // Default: a rebuild must NEVER be able to hang forever.
        with_env(None, || {
            assert_eq!(
                rebuild_timeout(),
                Some(Duration::from_secs(DEFAULT_REBUILD_TIMEOUT_SECS)),
                "default must be a finite ceiling"
            );
        });

        // Explicit opt-out, for a genuinely longer build.
        with_env(Some("0"), || assert_eq!(rebuild_timeout(), None));

        // Explicit value honoured.
        with_env(Some("120"), || {
            assert_eq!(rebuild_timeout(), Some(Duration::from_secs(120)))
        });

        // Garbage falls back to the CEILING, never to "no ceiling" — a typo
        // must not silently restore hang-forever.
        with_env(Some("banana"), || {
            assert_eq!(
                rebuild_timeout(),
                Some(Duration::from_secs(DEFAULT_REBUILD_TIMEOUT_SECS))
            )
        });
    }

    /// The load-bearing one: a command that never exits is KILLED and
    /// reported, not waited on forever.
    #[test]
    fn a_hanging_command_is_killed_and_reported() {
        let mut c = Command::new("sleep");
        c.arg("600");
        let start = Instant::now();
        let err = run_command_timed(&mut c, Some(Duration::from_secs(2)))
            .expect_err("a hanging command must fail, not block");
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "must not have waited it out"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("was killed"),
            "error must say it killed the process: {msg}"
        );
        assert!(
            msg.contains("FLEET_REBUILD_TIMEOUT_SECS"),
            "error must say how to raise it"
        );
    }

    /// The bail text must point at the signal that actually discriminates.
    ///
    /// The first version told the reader to check %cpu. That advice is WRONG:
    /// the `nix build` client sits near 0% CPU on a perfectly healthy build
    /// because the nix-daemon builds in separate processes. Verified live —
    /// a monitor sampled cpu=0.0 for 30 straight minutes on a build that was
    /// producing derivations the whole time. Following that guidance would
    /// make someone kill a working rebuild.
    #[test]
    fn the_bail_text_names_log_progress_not_cpu() {
        let mut c = Command::new("sleep");
        c.arg("600");
        let err = run_command_timed(&mut c, Some(Duration::from_secs(2))).expect_err("must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("wc -l"),
            "must give the log-progress check: {msg}"
        );
        assert!(
            msg.contains("NOT cpu%"),
            "must explicitly warn cpu% is not the signal: {msg}"
        );
    }

    #[test]
    fn a_fast_command_still_succeeds() {
        let mut c = Command::new("true");
        assert!(run_command_timed(&mut c, Some(Duration::from_secs(30))).is_ok());
    }

    fn plain_error(err: &anyhow::Error) -> String {
        let level = crate::output::Level::Required;
        crate::output::tests::strip_ansi(&crate::output::render_error(
            err,
            crate::output::wants_backtrace(level, None),
        ))
    }

    /// The operator's 2026-09-29 failure, as a test: at the DEFAULT level a
    /// failed command must end with its own error lines, then one line naming
    /// it and its exit code, and no backtrace.
    fn assert_cause_printed(tee: StderrTee) {
        let mut c = Command::new("sh");
        c.args([
            "-c",
            "printf 'building\\r\\033[K[1/2 built]\\n' >&2; \
             echo 'unrelated noise' >&2; \
             echo \"error: builder for '/nix/store/x.drv' failed with exit code 1\" >&2; \
             echo '       last 1 log lines: boom' >&2; \
             exit 3",
        ]);
        let err = run_command_teed(&mut c, Some(Duration::from_secs(30)), tee)
            .expect_err("exit 3 must fail");
        let shown = plain_error(&err);
        assert_eq!(
            shown,
            "  error: builder for '/nix/store/x.drv' failed with exit code 1\n         \
             last 1 log lines: boom\n\
             [ERROR] `sh` failed with exit code 3",
            "{tee:?}"
        );
    }

    #[test]
    fn a_failed_commands_stderr_tail_is_printed_at_the_default_level_via_a_pipe() {
        assert_cause_printed(StderrTee::Pipe);
    }

    #[test]
    fn a_failed_commands_stderr_tail_is_printed_at_the_default_level_via_a_pty() {
        assert_cause_printed(StderrTee::Pty);
    }

    #[test]
    fn with_no_error_line_the_cause_is_the_last_lines() {
        let mut c = Command::new("sh");
        c.args(["-c", "echo 'something broke' >&2; exit 1"]);
        let err = run_command_teed(&mut c, Some(Duration::from_secs(30)), StderrTee::Pipe)
            .expect_err("must fail");
        assert_eq!(
            plain_error(&err),
            "  something broke\n[ERROR] `sh` failed with exit code 1"
        );
    }

    #[test]
    fn a_command_is_named_without_sudo_flags_or_option_values() {
        let mut c = Command::new("sudo");
        c.args([
            "--preserve-env=HOME,USER",
            "/run/current-system/sw/bin/darwin-rebuild",
            "switch",
            "--flake",
            ".#ryn",
            "--option",
            "access-tokens",
            "github.com=SECRET",
        ]);
        assert_eq!(command_name(&c), "darwin-rebuild switch");
    }

    #[test]
    fn a_failing_command_still_reports_its_exit_code() {
        let mut c = Command::new("false");
        assert!(run_command_timed(&mut c, Some(Duration::from_secs(30))).is_err());
    }
}
