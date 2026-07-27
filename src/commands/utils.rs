use anyhow::{Context, Result};
use colored::Colorize;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn log_info(msg: &str) {
    println!("{} {}", "[INFO]".blue().bold(), msg);
}

pub fn log_success(msg: &str) {
    println!("{} {}", "[OK]".green().bold(), msg);
}

pub fn log_warning(msg: &str) {
    println!("{} {}", "[WARN]".yellow().bold(), msg);
}

pub fn log_error(msg: &str) {
    eprintln!("{} {}", "[ERROR]".red().bold(), msg);
}

pub fn run_command(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("Failed to execute: {:?}", cmd))?;

    if !status.success() {
        anyhow::bail!("Command failed with exit code: {:?}", status.code());
    }

    Ok(())
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
                log_warning(&format!(
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
/// minutes at 0.0% CPU with no builder children and its GitHub sockets in
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
    let Some(timeout) = timeout else {
        return run_command(cmd);
    };

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("Failed to execute: {cmd:?}"))?;

    let pid = child.id();
    let start = Instant::now();

    loop {
        match child.try_wait().context("waiting on child")? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => {
                anyhow::bail!("Command failed with exit code: {:?}", status.code())
            }
            None => {}
        }

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
                 Confirm before retrying — a wedged build sits at 0.0% CPU with no\n\
                 builder children:\n\
                   ps -o pid,%cpu,command -p $(pgrep -f 'darwinConfigurations.*system')\n\
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

pub fn ssh_cmd_with_config(
    user: &str,
    host: &str,
    ssh: &crate::config::ResolvedSsh,
) -> Command {
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
        assert!(start.elapsed() < Duration::from_secs(30), "must not have waited it out");
        let msg = format!("{err}");
        assert!(msg.contains("was killed"), "error must say it killed the process: {msg}");
        assert!(msg.contains("FLEET_REBUILD_TIMEOUT_SECS"), "error must say how to raise it");
    }

    #[test]
    fn a_fast_command_still_succeeds() {
        let mut c = Command::new("true");
        assert!(run_command_timed(&mut c, Some(Duration::from_secs(30))).is_ok());
    }

    #[test]
    fn a_failing_command_still_reports_its_exit_code() {
        let mut c = Command::new("false");
        assert!(run_command_timed(&mut c, Some(Duration::from_secs(30))).is_err());
    }
}
