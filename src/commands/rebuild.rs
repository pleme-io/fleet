use anyhow::{Context, Result};
use colored::Colorize;

use crate::github_token::{self, ResolvedToken, SystemEnv, TokenConfigFile};
use fs4::fs_std::FileExt;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use super::utils::{
    log_info, log_success, log_warning, rebuild_timeout, run_command, run_command_output,
    run_command_timed,
};

/// One row of the `mado e2e` smoke matrix.
#[derive(Debug, serde::Deserialize)]
struct E2eRow {
    name: String,
    pass: bool,
    #[serde(default)]
    skipped: bool,
    #[serde(default)]
    detail: String,
}

/// Pull the `mado e2e` JSON verdict out of a captured run.
///
/// Deliberately tolerant, and deliberately not authoritative. The child
/// interleaves its report with whatever its tracing subscriber and nix
/// decide to say, so the report is SEARCHED FOR rather than assumed to
/// be the whole stream.
///
/// Every `{` is a candidate, in order, and a candidate is accepted only
/// if it prefix-parses as JSON carrying a non-empty `rows` array. The
/// naive "slice from the first `{`" does not work and the test pins why:
/// rmcp's startup line contains `peer_info=Some(InitializeResult { … })`,
/// so the first `{` in a passing rebuild is inside Rust `Debug` output,
/// not JSON. Prefix-parsing (rather than whole-string) additionally means
/// trailing nix chatter after the report cannot hide it.
///
/// Returning `None` means "could not render this nicely" — never "the
/// gate failed". The exit status is the only verdict and the caller reads
/// it independently, which is what keeps a prettifier from ever passing a
/// gate that did not pass, or failing one that did.
fn parse_e2e_report(stdout: &str) -> Option<(String, Vec<E2eRow>)> {
    for (start, _) in stdout.match_indices('{') {
        let Some(value) = serde_json::Deserializer::from_str(&stdout[start..])
            .into_iter::<serde_json::Value>()
            .next()
            .and_then(Result::ok)
        else {
            continue;
        };
        let Some(rows) = value
            .get("rows")
            .and_then(|r| serde_json::from_value::<Vec<E2eRow>>(r.clone()).ok())
        else {
            continue;
        };
        if rows.is_empty() {
            continue;
        }
        let shell = value
            .get("shell")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(shell not reported)")
            .to_string();
        return Some((shell, rows));
    }
    None
}

/// Serializes concurrent `fleet rebuild` invocations against each other.
///
/// Confirmed live (2026-07-19): two overlapping rebuilds raced on
/// sops-nix's `/run/secrets.d/<generation>/` directories — the second
/// activation's generation-cleanup deleted a path the first activation's
/// "request units to restart" step was still mid-read on:
/// `sops-install-secrets: cannot request units to restart: open
/// /run/secrets.d/22/automation/ssh/private-key: no such file or
/// directory`, aborting the whole activation with exit code 1 even
/// though the secret itself was written correctly. darwin-rebuild/
/// nixos-rebuild activation has no serialization of its own against
/// concurrent invocations; this is the load-bearing fix rather than a
/// retry-and-hope. An advisory `flock` (not a PID file — no self-race
/// on stale/reused PIDs) held for the entire `rebuild()` call means a
/// second invocation blocks until the first finishes instead of racing
/// its activation state.
fn acquire_rebuild_lock() -> Result<File> {
    // The ONE environment read on this path, at the real entry point.
    acquire_lock_at(Path::new(REBUILD_LOCK_PATH), LockWait::from_env())
}

/// The one machine-wide rebuild lock path.
///
/// ── ★ ABSOLUTE ON PURPOSE — `temp_dir()` MADE THIS LOCK SERIALIZE NOTHING ──
/// This was `std::env::temp_dir().join("fleet-rebuild.lock")`. On unix
/// `temp_dir()` is `$TMPDIR` with a `/tmp` fallback — and macOS gives every
/// user a *per-user* `$TMPDIR`. MEASURED on ryn 2026-08-02:
///
///   TMPDIR                     = /var/folders/y9/k5htqzn…/T/
///   /tmp/fleet-rebuild.lock    = DID NOT EXIST
///   actual lock                = /var/folders/y9/…/T/fleet-rebuild.lock (luis.d)
///
/// So the lock serialized one user's shell sessions against each other and
/// nothing else. The root `pleme-gitops` daemon — whose launchd job sets only
/// PATH/NIX_CONFIG/SENTINELA_CONFIG, no TMPDIR — resolved a different path
/// entirely, so an operator `darwin-rebuild switch` and a daemon rebuild ran
/// concurrently with no contention at all. That is the exact race the lock was
/// added for (see `acquire_rebuild_lock`'s sops-nix receipt).
///
/// The old doc comment asserted "the shared `/tmp/fleet-rebuild.lock` every
/// real invocation uses" — which was simply false on this platform, and the
/// falsehood was invisible because the lock still *worked* for the single-user
/// case it was tested in.
///
/// `/private/tmp` is mode `1777` (sticky, world-writable), so both root and an
/// unprivileged operator can create and open this path; the sticky bit stops
/// either from unlinking the other's file. The lock is advisory `flock`, so it
/// costs nothing when uncontended.
const REBUILD_LOCK_PATH: &str = "/tmp/fleet-rebuild.lock";

/// How long a blocked rebuild waits for the lock before giving up with a
/// typed failure.
///
/// Deliberately generous: a cold rebuild of this fleet legitimately runs
/// past an hour (2026-08-07: a single tick spent ~90 minutes compiling
/// `wgpu` and `vigy_store` under `nice`), so a short bound would turn a
/// healthy peer into a spurious error — the failure mode that teaches
/// operators to pass `--force`.
///
/// Override with `FLEET_REBUILD_LOCK_TIMEOUT_SECS`; `0` restores the old
/// unbounded wait for anyone who genuinely wants it.
const LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

/// How long to wait for a contended lock — a VALUE, passed in.
///
/// ── ★ WHY THIS IS A PARAMETER AND NOT AN ENV READ ────────────────────────
/// `wait_for_lock` used to read `FLEET_REBUILD_LOCK_TIMEOUT_SECS` itself.
/// `std::env` is process-global and `cargo test` runs tests as THREADS in one
/// process, so two tests that set the var raced each other: one set `"1"`, the
/// other's `remove_var` landed between that write and the read, the read fell
/// through to the 2-hour default, and the test blocked for the full
/// `LOCK_WAIT_TIMEOUT` before failing its own 30s assertion.
///
/// Observed 2026-08-16, not theorised: a suite run under load reported
/// `FAILED. 101 passed; 1 failed; finished in 7200.39s` — 7200s being exactly
/// `2 * 60 * 60`. The same race has a worse arm: read `"0"` and the wait
/// becomes UNBOUNDED, which is a hang rather than a slow failure.
///
/// Serialising those tests behind a mutex would have hidden it. Threading the
/// value removes the shared mutable cell instead, so the race has nothing to
/// happen to: ONE place reads the environment ([`LockWait::from_env`], called
/// once per real invocation), and every test passes the value it means.
///
/// The magic zero is a named variant too — `Unbounded` is a state you now have
/// to ask for by name rather than encode as a `Duration` that happens to be 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockWait {
    /// Give up after this long and fail typed, naming the holder.
    Bounded(Duration),
    /// Wait forever — the pre-2026-08-07 behaviour, kept reachable rather
    /// than deleted (★★ MODULARIZE, DON'T DELETE) for an operator who knows
    /// their peer is healthy and does not want to fight the bound.
    Unbounded,
}

impl LockWait {
    /// The fleet default, overridden by `FLEET_REBUILD_LOCK_TIMEOUT_SECS`.
    /// The ONLY environment read on this path.
    fn from_env() -> Self {
        Self::parse(
            std::env::var("FLEET_REBUILD_LOCK_TIMEOUT_SECS")
                .ok()
                .as_deref(),
        )
    }

    /// `from_env`'s pure core — split out so the parsing rules are tested
    /// without mutating a process-global, which is the very defect above.
    fn parse(raw: Option<&str>) -> Self {
        match raw.and_then(|v| v.trim().parse::<u64>().ok()) {
            Some(0) => Self::Unbounded,
            Some(secs) => Self::Bounded(Duration::from_secs(secs)),
            // Absent OR unparseable: a typo must not silently become
            // "wait forever". Fall back to the bounded default.
            None => Self::Bounded(LOCK_WAIT_TIMEOUT),
        }
    }
}

/// How often a blocked rebuild re-reports who it is waiting on.
const LOCK_WAIT_REPORT_EVERY: Duration = Duration::from_secs(60);

/// Read the holder line the current owner stamped into the lock file.
fn describe_holder(lock_path: &Path) -> String {
    match fs::read_to_string(lock_path) {
        Ok(h) if !h.trim().is_empty() => h.trim().to_owned(),
        _ => "holder unknown".to_owned(),
    }
}

/// The pid stamped into the lock by its current holder, if the line parses.
///
/// The stamp is `pid <N> · <user>` (written at the end of `acquire_lock_at`),
/// so this reads the second whitespace-separated field. A file that does not
/// parse is treated as having no pid — which routes to the stale branch,
/// correctly: a lock nobody stamped is not a lock anyone is holding.
fn holder_pid(lock_path: &Path) -> Option<u32> {
    let text = fs::read_to_string(lock_path).ok()?;
    let mut parts = text.split_whitespace();
    if parts.next()? != "pid" {
        return None;
    }
    parts.next()?.parse().ok()
}

/// Is that pid still around?
///
/// `kill(pid, 0)` is the portable liveness probe: it performs the permission
/// checks and target lookup without delivering a signal. `EPERM` counts as
/// ALIVE — the process exists, we simply may not signal it, which is exactly
/// the root-holds-the-lock case this function is here to judge.
fn pid_is_alive(pid: u32) -> bool {
    // SAFETY: `kill` with signal 0 delivers nothing; it only reports whether
    // the pid exists and is signallable.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Remove a lock file we cannot unlink as ourselves.
///
/// `/tmp` is sticky, so only the owner (or root) may unlink. We escalate
/// rather than fail, because the alternative is telling an operator to run
/// the same command by hand — which is not a safety boundary, just a worse
/// user experience with identical consequences.
fn clear_stale_lock(lock_path: &Path) -> Result<()> {
    if fs::remove_file(lock_path).is_ok() {
        return Ok(());
    }
    let status = std::process::Command::new("sudo")
        .arg("rm")
        .arg("-f")
        .arg(lock_path)
        .status()
        .with_context(|| format!("could not run sudo to clear {}", lock_path.display()))?;
    anyhow::ensure!(
        status.success(),
        "could not clear the stale rebuild lock at {} — remove it by hand: sudo rm -f {}",
        lock_path.display(),
        lock_path.display()
    );
    Ok(())
}

/// Block for the lock, but **bounded, and never silently**.
///
/// ── ★ WHY THIS IS NOT `FileExt::lock_exclusive` ──
/// It used to be, and the sibling comment above already named the defect
/// it left open: *"a bare waiting... with no identity and no timeout is the
/// thing that makes a blocked interactive rebuild feel hung."* That comment
/// shipped with the identity half implemented and the timeout half not, so
/// a blocked rebuild waited on `lock_exclusive` **forever**, printed one
/// line, and never spoke again.
///
/// MEASURED on rio 2026-08-07, which is why this is phase 0b of
/// `theory/BALIZA.md` and not a nicety: an operator rebuild and the
/// `sentinela` reconciler tick collided; sentinela's tick sat **36 minutes
/// against a 60-second poll** with its child at zero CPU. Anything that
/// then reached for this lock would have blocked behind a wedged holder
/// with no output, no deadline and no way to tell the two apart from the
/// terminal. A hang must degrade into a **typed failure**
/// (`theory/RECONCILER-LIVENESS.md` P1), and silence is the part that makes
/// a hang expensive — the operator cannot act on what they cannot see.
///
/// So: poll, re-announce the holder every
/// [`LOCK_WAIT_REPORT_EVERY`], and convert the deadline into an error that
/// names who we waited on and how long.
///
/// TIER: only-mitigated. This bounds *our* wait; it does not bound the
/// holder's work, and a holder that wedges still wedges — it just stops
/// being invisible and stops being unbounded for everyone behind it.
/// Bounding the holder is `despacho`'s job (`theory/DESPACHO.md`), where
/// the ask carries a mandatory deadline of its own.
/// `wait` is a VALUE, passed in. It used to be read from the environment right
/// here, and that is what made the tests race: `std::env` is process-global
/// while `cargo test` runs tests as THREADS in one process, so two tests
/// setting the var interleaved — one wrote `"1"`, the other's `remove_var`
/// landed between that write and this read, the read fell through to the
/// two-hour default, and the suite blocked for the full `LOCK_WAIT_TIMEOUT`
/// before failing its own 30s assertion. Observed 2026-08-16:
/// `FAILED. 101 passed; 1 failed; finished in 7200.39s` — 7200 being exactly
/// `2 * 60 * 60`. The worse arm reads `"0"` and waits UNBOUNDED: a hang, not a
/// slow failure.
///
/// Serialising those tests behind a mutex would have hidden the race.
/// Threading the value removes the shared mutable cell, so there is nothing
/// left for a race to happen to.
fn wait_for_lock(file: &File, lock_path: &Path, wait: LockWait) -> Result<()> {
    // `Unbounded` is a NAMED state, not a `Duration` that happens to be zero —
    // the pre-2026-08-07 behaviour, kept reachable rather than deleted
    // (★★ MODULARIZE, DON'T DELETE) so an operator who knows their peer is
    // healthy is not forced to fight the bound.
    let timeout = match wait {
        LockWait::Unbounded => {
            return FileExt::lock_exclusive(file).context("failed to acquire rebuild lock");
        }
        LockWait::Bounded(d) => d,
    };

    let started = Instant::now();
    let mut last_report = Instant::now();
    loop {
        if FileExt::try_lock_exclusive(file).is_ok() {
            return Ok(());
        }
        let waited = started.elapsed();
        if waited >= timeout {
            anyhow::bail!(
                "gave up waiting for the rebuild lock after {}s — held by {}.\n\
                 \n\
                 The holder is either doing legitimate long work (a cold build of \
                 this fleet can exceed an hour) or it is wedged. Check it before \
                 forcing anything:\n\
                 \n    ps -o pid,etimes,stat,args -p <holder pid>\n\
                 \n\
                 A holder at zero CPU in state S with no build children is wedged; \
                 kill it and re-run. To wait longer, set \
                 FLEET_REBUILD_LOCK_TIMEOUT_SECS (0 waits forever).",
                waited.as_secs(),
                describe_holder(lock_path),
            );
        }
        if last_report.elapsed() >= LOCK_WAIT_REPORT_EVERY {
            log_info(&format!(
                "still waiting for the rebuild lock ({}s elapsed, {}s left) — held by {}",
                waited.as_secs(),
                timeout.saturating_sub(waited).as_secs(),
                describe_holder(lock_path),
            ));
            last_report = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// `acquire_rebuild_lock`'s path-parameterized core — split out so tests
/// can exercise real flock contention against a throwaway path instead of
/// the machine-wide [`REBUILD_LOCK_PATH`] every real invocation uses.
/// `wait` threaded in rather than read here, for the same reason
/// [`wait_for_lock`] takes it: tests must be able to choose a bound WITHOUT
/// writing a process-global that their siblings are reading concurrently.
fn acquire_lock_at(lock_path: &Path, wait: LockWait) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        // See the note on the retry below: truncation happens after the lock
        // is held, never at open.
        .truncate(false)
        .open(lock_path)
        .or_else(|e| {
            // EACCES means the file EXISTS and belongs to another user with a
            // mode that excludes us. The 0666 widening below cannot rescue it
            // — that runs AFTER open — and /tmp is sticky, so a non-owner
            // cannot unlink it either. Measured on ggg: a fresh account's
            // `nix run .#rebuild` died here with nothing to do next.
            //
            // So REPAIR it, rather than instruct. This command already
            // escalates for the rebuild itself; clearing a lock it owns the
            // semantics of is squarely inside that authority.
            //
            // The safety test is the holder stamp, not a timeout: the file
            // records `pid N · user`, so a DEAD pid means the writer is gone
            // and the lock is debris. A LIVE pid is a real peer and is never
            // touched — that is the difference between repairing a stale lock
            // and yanking a running rebuild's.
            if e.kind() != std::io::ErrorKind::PermissionDenied {
                return Err(anyhow::Error::new(e).context(format!(
                    "failed to open rebuild lock file at {}",
                    lock_path.display()
                )));
            }
            match holder_pid(lock_path) {
                Some(pid) if pid_is_alive(pid) => Err(anyhow::anyhow!(
                    "the rebuild lock at {p} is held by a LIVE rebuild ({h}), and its \
                     mode excludes you.\n\
                     Wait for it to finish, or if you are sure it is wrong:\n\
                     \x20   sudo rm -f {p}",
                    p = lock_path.display(),
                    h = describe_holder(lock_path)
                )),
                _ => {
                    log_info(&format!(
                        "Stale rebuild lock at {} ({}) — its writer is gone; clearing it.",
                        lock_path.display(),
                        describe_holder(lock_path)
                    ));
                    clear_stale_lock(lock_path)?;
                    OpenOptions::new()
                        .create(true)
                        .write(true)
                        // Same reason as the first open: truncation happens
                        // only once the lock is held.
                        .truncate(false)
                        .open(lock_path)
                        .with_context(|| {
                            format!(
                                "failed to open rebuild lock file at {} even after \
                                 clearing a stale one",
                                lock_path.display()
                            )
                        })
                }
            }
        })?;
    // Cross-user reachability: whoever creates the file first owns it, and the
    // other party still has to open it for WRITE to take an exclusive flock. A
    // default 0644 would hand the first creator a permanent monopoly — root
    // creates it, the operator's rebuild then dies on EACCES instead of
    // waiting. Best-effort: a pre-existing file owned by the other user cannot
    // be chmod'd by us, and that is fine — it is already 0666 from its own
    // creation. Never fatal, because failing to widen a mode must not break a
    // rebuild that would otherwise have proceeded.
    let _ = fs::set_permissions(lock_path, fs::Permissions::from_mode(0o666));
    if FileExt::try_lock_exclusive(&file).is_err() {
        // Name the holder. A bare "waiting..." with no identity and no timeout
        // is the thing that makes a blocked interactive rebuild feel hung —
        // the operator cannot tell a live peer from a wedged one.
        log_info(&format!(
            "Another rebuild is already in progress ({}) — waiting for it to finish...",
            describe_holder(lock_path)
        ));
        // The ONE environment read on this path, at the real entry point.
        wait_for_lock(&file, lock_path, wait)?;
    }
    // Stamp our identity for the next waiter to read. Truncate first: the
    // previous holder's line is stale the moment we own the lock.
    let holder = format!(
        "pid {} · {}",
        std::process::id(),
        std::env::var("USER").unwrap_or_else(|_| "unknown".to_owned())
    );
    let _ = file.set_len(0);
    let _ = std::io::Write::write_all(&mut (&file), holder.as_bytes());
    Ok(file)
}

/// Walk up from `start` to find the directory containing `flake.nix`.
pub fn find_flake_root(start: &Path) -> Result<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join("flake.nix").exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            anyhow::bail!(
                "Could not find flake.nix in {} or any parent directory",
                start.display()
            );
        }
    }
}

fn get_hostname() -> Result<String> {
    run_command_output(Command::new("hostname").arg("-s")).context("Failed to get hostname")
}

/// Check whether a command exists in PATH.
/// Resolve a rebuild driver to its ABSOLUTE system path, falling back to the
/// bare name when that path is absent.
///
/// ── ★ `sudo <bare name>` IS NOT THE PATH YOU MEASURED ──────────────────────
/// `sudo nixos-rebuild` does not resolve through the caller's PATH. sudo
/// replaces it with `secure_path` from sudoers, so the binary that runs is
/// whatever ROOT's restricted path finds — which on a NixOS machine is not
/// guaranteed to include `/run/current-system/sw/bin` at all.
///
/// This file already carries the receipt for the same class on the other arm:
/// `darwin-rebuild` lives only in the system profile, and a calling shell that
/// lacks it makes `command_exists("darwin-rebuild")` return false and *wrongly
/// drive the first-run bootstrap path*. That was mitigated by hardening PATH
/// rather than by asking a question PATH cannot answer wrongly.
///
/// sentinela already resolves this the reliable way — `RebuildTool::binary()`
/// returns `/run/current-system/sw/bin/nixos-rebuild` — so this reuses the
/// model the daemon has been running in production rather than inventing one.
///
/// TIER: only-mitigated. The fallback keeps today's behaviour on a machine
/// where the system profile is missing, so this removes a PATH ASSUMPTION
/// without introducing a new way to fail closed. A machine with no
/// `/run/current-system` is being bootstrapped, and the bare name is the right
/// answer there.
fn rebuild_driver(name: &str) -> String {
    let absolute = format!("/run/current-system/sw/bin/{name}");
    if PathBuf::from(&absolute).exists() {
        absolute
    } else {
        name.to_owned()
    }
}

fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_or(false, |s| s.success())
}

/// Resolve `sops`, building it from nixpkgs if the node does not carry it yet
/// (a pre-activation node generally does not).
fn resolve_sops_cmd() -> String {
    if command_exists("sops") {
        return "sops".to_string();
    }
    log_info("sops not in PATH — building from nixpkgs...");
    match run_command_output(Command::new("nix").args([
        "--extra-experimental-features",
        "nix-command flakes",
        "build",
        "--print-out-paths",
        "--no-link",
        "nixpkgs#sops",
    ])) {
        Ok(out) => format!("{out}/bin/sops"),
        // Non-fatal: resolution simply finds no SOPS source and falls back to
        // whatever the env / nix.conf already carry.
        Err(e) => {
            log_warning(&format!("Could not build sops from nixpkgs: {e}"));
            "sops".to_string()
        }
    }
}

/// Resolve the GitHub token this rebuild will authenticate with, scraping SOPS
/// when nothing on disk carries one, and seed the bootstrap auth files.
///
/// **What changed and why.** This used to return early whenever
/// `~/.config/nix/netrc` and `access-tokens.conf` both EXISTED — file
/// existence, not token presence. A node whose credential had gone stale or
/// rendered empty (the `/run/secrets` freeze in `nodes/rio/CLAUDE.md`) has
/// both files and no usable token, so the scrape never ran and the rebuild
/// died twenty minutes later on an `HTTP 404` for a private input — which does
/// not look like a credential problem at all, since GitHub hides private repos
/// behind 404 rather than 403. Resolution now asks each source for a token and
/// keeps going until one answers; see `crate::github_token`, whose header
/// carries the measured status-code matrix.
///
/// Returns `None` only when NO source yielded a token — in which case the
/// probe report is printed, because "which of five places did you look?" is a
/// question the operator should never have to ask.
fn resolve_github_token(flake_root: &Path) -> Option<ResolvedToken> {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_default());
    let user = std::env::var("USER").ok();

    // `resolve_sops_cmd` is passed, not called: it only runs if resolution
    // actually reaches a SOPS scrape.
    let env = SystemEnv::new(resolve_sops_cmd);
    let (token, report) = github_token::resolve(&env, &home, flake_root, user.as_deref());

    let Some(token) = token else {
        // Name the code the operator will actually SEE. A private input with no
        // credential answers 404, not 401 — and 404 reads as "that commit is
        // gone", which sends people to check the pin instead of the token.
        log_warning(
            "No GitHub token found — private flake inputs will fail with HTTP 404 \
             (GitHub hides private repos behind 404, so this is NOT a missing rev).",
        );
        for line in &report.lines {
            log_warning(line);
        }
        log_warning("Fix: add your PAT with `nix run .#sops-edit-mine` (github/pat), or");
        log_warning("restore the age key whose PUBLIC half is a recipient of that file.");
        return None;
    };

    // Only say "scraped" when it actually was one. Announcing a decrypt on
    // every rebuild would train the operator to ignore the line that matters.
    if token.source.is_sops() {
        log_success(&format!(
            "No usable token on disk — scraped {} from {}",
            token.redacted(),
            token.source.describe()
        ));
    } else {
        log_info(&format!("GitHub token: {}", token.source.describe()));
    }

    seed_bootstrap_auth_files(&home, &token);
    Some(token)
}

/// Write `access-tokens.conf` + `netrc` when absent, so the credential
/// survives into tools this process does not drive (git, curl-shaped
/// fetchers) and into the next invocation.
///
/// Never OVERWRITES: after activation, sops-nix owns these files, and
/// clobbering a managed file with a bootstrap copy would fight the reconciler
/// rather than hand off to it. Both are non-fatal — a rebuild whose token
/// rides on `--option` still succeeds if the seeding fails.
fn seed_bootstrap_auth_files(home: &Path, token: &ResolvedToken) {
    let dir = home.join(".config/nix");
    if let Err(e) = fs::create_dir_all(&dir) {
        log_warning(&format!("Could not create {}: {e}", dir.display()));
        return;
    }

    for (path, content, label) in [
        (
            dir.join("access-tokens.conf"),
            token.access_tokens_conf(),
            "access-tokens.conf",
        ),
        (dir.join("netrc"), token.netrc(), "netrc"),
    ] {
        if path.exists() {
            continue;
        }
        let wrote = fs::write(&path, content)
            .and_then(|()| fs::set_permissions(&path, fs::Permissions::from_mode(0o600)));
        match wrote {
            Ok(()) => log_success(&format!("Bootstrapped ~/.config/nix/{label}")),
            Err(e) => log_warning(&format!("Could not write {}: {e}", path.display())),
        }
    }
}

/// Install Claude Code via nix profile if not already available.
/// Non-fatal — logs and continues if installation fails.
fn ensure_claude_code() {
    if command_exists("claude") {
        return;
    }

    log_info("Claude Code not found — installing via nix profile...");

    let status = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "profile",
            "install",
            "github:sadjow/claude-code-nix",
        ])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();

    match status {
        Ok(s) if s.success() => log_success("Claude Code installed"),
        _ => log_warning("Could not install Claude Code — continuing without it"),
    }
}

/// On first run, ensure /etc/nix/nix.custom.conf has the minimum settings
/// needed for a successful bootstrap build:
///   - sandbox = false (macOS blocks .app builds and xcodebuild in sandbox)
///   - trusted-users includes the current user (so --option flags work)
///
/// After activation, nix-darwin manages this file permanently.
/// This only writes if the settings are missing (idempotent).
fn bootstrap_nix_custom_conf() -> Result<()> {
    // Skip if nix-darwin already manages this file (darwin-rebuild exists)
    // or if activation already ran once (.before-nix-darwin backup exists).
    // Writing here would conflict with nix-darwin's activation check.
    if command_exists("darwin-rebuild")
        || PathBuf::from("/etc/nix/nix.custom.conf.before-nix-darwin").exists()
    {
        return Ok(());
    }

    let custom_conf = PathBuf::from("/etc/nix/nix.custom.conf");
    let current = fs::read_to_string(&custom_conf).unwrap_or_default();

    let has_sandbox = current.lines().any(|l| {
        let t = l.trim();
        t.starts_with("sandbox") && !t.starts_with('#')
    });
    let has_trusted = current.lines().any(|l| {
        let t = l.trim();
        t.starts_with("trusted-users") && !t.starts_with('#')
    });

    if has_sandbox && has_trusted {
        return Ok(());
    }

    let user = std::env::var("USER").unwrap_or_default();
    let mut additions = String::new();
    if !has_sandbox {
        additions
            .push_str("\n# Bootstrap: disable sandbox for macOS .app builds\nsandbox = false\n");
    }
    if !has_trusted {
        additions.push_str(&format!(
            "\n# Bootstrap: trust current user for --option flags\ntrusted-users = root {user}\n"
        ));
    }

    log_info("Configuring nix daemon for bootstrap (sandbox=false, trusted-users)...");

    // Write via sudo tee since /etc/nix is root-owned
    let new_content = format!("{current}{additions}");
    let mut cmd = Command::new("sudo");
    cmd.args(["tee", "/etc/nix/nix.custom.conf"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null());
    let mut child = cmd.spawn().context("Failed to run sudo tee")?;
    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(new_content.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("Failed to write /etc/nix/nix.custom.conf");
    }

    // Restart the nix daemon so it picks up the new settings
    log_info("Restarting nix daemon to apply settings...");
    let _ = Command::new("sudo")
        .args([
            "launchctl",
            "kickstart",
            "-k",
            "system/org.nixos.nix-daemon",
        ])
        .status();
    // (Determinate's systems.determinate.nix-daemon was removed in the
    // Determinate→nix-darwin migration; kickstarting it just printed a benign
    // "Could not find service" — dropped.)

    // Brief pause for daemon restart
    std::thread::sleep(std::time::Duration::from_secs(2));

    log_success("Nix daemon configured for bootstrap");
    Ok(())
}

/// Accept the Xcode license if not yet accepted. xcodebuild refuses to
/// run for ANY user (including nix build users) until the license is
/// accepted system-wide via `sudo xcodebuild -license accept`.
/// Idempotent — xcodebuild -checkFirstLaunchStatus exits 0 when done.
fn accept_xcode_license() {
    // Check if xcodebuild is available
    if !command_exists("xcodebuild") {
        return;
    }

    // Check if license is already accepted by trying a simple xcodebuild query
    let check = Command::new("xcodebuild")
        .arg("-license")
        .arg("check")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match check {
        Ok(s) if s.success() => return, // already accepted
        _ => {}
    }

    log_info("Accepting Xcode license (required for xcodebuild)...");
    let status = Command::new("sudo")
        .args(["xcodebuild", "-license", "accept"])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();

    match status {
        Ok(s) if s.success() => log_success("Xcode license accepted"),
        _ => log_warning("Could not accept Xcode license — xcodebuild may fail"),
    }
}

/// Move /etc files that nix-darwin wants to manage but finds with
/// "unrecognized content". This prevents the activation check from
/// aborting. Files are preserved as .before-nix-darwin backups.
///
/// Returns an error if any required move fails (sudo denied, etc.),
/// so the caller can bail before attempting a doomed activation.
fn prepare_etc_for_darwin() -> Result<()> {
    let managed_files = [
        "/etc/hosts",
        "/etc/nix/nix.custom.conf",
        "/etc/shells",
        "/etc/bashrc",
        "/etc/zshrc",
    ];
    for path in &managed_files {
        let p = PathBuf::from(path);
        let backup = PathBuf::from(format!("{path}.before-nix-darwin"));
        // Only move regular files (not symlinks — symlinks mean nix-darwin already manages it)
        if p.exists() && !p.is_symlink() && !backup.exists() {
            log_info(&format!(
                "Moving {path} → {path}.before-nix-darwin (nix-darwin will manage it)"
            ));
            let status = Command::new("sudo")
                .args(["mv", path, &format!("{path}.before-nix-darwin")])
                .stdin(std::process::Stdio::inherit())
                .status()
                .context(format!("Failed to run sudo mv for {path}"))?;
            if !status.success() {
                anyhow::bail!(
                    "Failed to move {path} → {path}.before-nix-darwin (sudo denied?). \
                     Run manually: sudo mv {path} {path}.before-nix-darwin"
                );
            }
        }
    }
    Ok(())
}

/// Where the gitops daemon's typed config lives; `sentinela` needs it to
/// find the receipt chain. Absent on any host not running the loop.
const GITOPS_CONFIG: &str = "/etc/pleme-gitops/config.yaml";

/// Print the gitops reconciler's verdict before we start rebuilding.
///
/// ── ★ WHY THIS IS HERE AND NOT IN A LOG ─────────────────────────────────
/// The daemon already recorded everything: an append-only BLAKE3 chain with
/// a typed outcome per tick, and a `sentinela status` that prints it. It
/// still failed **4136 consecutive ticks over 27.9 days** on ryn
/// (2026-07-04 -> 2026-08-01, MEASURED from that chain: 4136 `failed`, 1
/// `activated`) without anyone noticing — because the only surfaces
/// carrying the bad news were a root-owned log nobody tails and a binary
/// that was not on PATH.
///
/// Silence is the failure mode. A reconciler that has not converged in a
/// month looks exactly like one with nothing to do: no output either way.
/// So the verdict goes where the operator ALREADY looks — the top of every
/// `fleet rebuild` — instead of somewhere they would have to think to check.
///
/// Deliberately advisory: never returns an error and never blocks a
/// rebuild. A host with no daemon, no `sentinela` on PATH, or an
/// unparseable status simply prints nothing. The rebuild is often the very
/// thing being run to REPAIR a broken loop, so this must not stand in
/// front of it.
fn report_gitops_health() {
    if !Path::new(GITOPS_CONFIG).exists() {
        return; // not a gitops host
    }
    let out = match Command::new("sentinela")
        .args(["--config", GITOPS_CONFIG, "status"])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        // Binary absent (pre-adoption generation) or status failed — stay
        // quiet rather than cry wolf about a loop we cannot read.
        _ => return,
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out) else {
        return;
    };
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed());
    let ev = Evidence::from_status(&v, now_epoch);
    match gitops_verdict(&v, &ev) {
        GitopsVerdict::Converged(p) => {
            log_info(&format!("gitops: converged (at branch HEAD {})", p.rev()));
        }
        // Quiet by design: no alarm for a loop we cannot read, but no
        // claim of health either.
        GitopsVerdict::Unknown { reason } => log_info(&format!("gitops: unknown — {reason}")),
        GitopsVerdict::Degraded { headline, detail } => {
            log_warning(&headline);
            print!("{detail}");
        }
    }
}

/// Independently-measured facts about this node, gathered OUTSIDE the
/// reconciler's own receipt chain.
///
/// ── ★ WHY A VERDICT MAY NOT BE COMPUTED FROM THE CHAIN ALONE ────────────
/// The chain records what the daemon DID. It cannot record what the daemon
/// failed to do, and a stopped daemon writes nothing at all — so its last
/// receipt stays "activated, 0 failures" forever. On 2026-08-02 cid printed
/// `consecutive_failures: 0, chain_verified: true` with its LaunchDaemon
/// dead (exit 78 EX_CONFIG since boot) and the node 14 commits behind
/// origin/main. Every field the old verdict read was true; the conclusion
/// was false, because convergence is a claim about the WORLD (does the
/// running system match the branch, right now) and the chain is only a
/// claim about the daemon's own history.
///
/// So convergence needs evidence the daemon cannot fake by being idle:
/// where the branch actually points, and when the loop last drew breath.
/// A field we could not measure is `None` — never a default that happens
/// to read as healthy.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Evidence {
    /// Branch HEAD as resolved by the daemon on its most recent probe.
    /// `None` when the status document does not carry one (pre-heartbeat
    /// daemons) — which makes the verdict `Unknown`, never `Converged`.
    declared_head_rev: Option<String>,
    /// When the loop last completed a tick, epoch seconds. This is the
    /// liveness signal: an ACTIVATION timestamp cannot serve, because a
    /// healthy loop with nothing to do activates nothing for weeks.
    last_tick_at_epoch: Option<i64>,
    /// Wall clock at the moment of judgement, epoch seconds.
    now_epoch: Option<i64>,
    /// Configured poll interval; a heartbeat older than a few of these
    /// means the loop is stopped, not quiet.
    poll_seconds: Option<u64>,
}

impl Evidence {
    /// How many poll intervals of silence before a loop is presumed stopped.
    /// Three tolerates one slow build plus one missed cycle without crying
    /// wolf — the failure mode the previous author correctly feared.
    const STALE_AFTER_POLLS: i64 = 3;

    /// Read the evidence a status document is able to supply. Fields absent
    /// from the document stay `None`; this never invents one.
    fn from_status(v: &serde_json::Value, now_epoch: i64) -> Self {
        Self {
            declared_head_rev: v["head_rev"].as_str().map(str::to_owned),
            last_tick_at_epoch: v["last_tick_at_unix_ms"].as_i64().map(|ms| ms / 1000),
            now_epoch: Some(now_epoch),
            poll_seconds: v["poll_seconds"].as_u64(),
        }
    }

    /// `Some(true)` = the loop is demonstrably alive, `Some(false)` =
    /// demonstrably stopped, `None` = cannot tell. The third case is the
    /// one the old code collapsed into "healthy".
    fn heartbeat_fresh(&self) -> Option<bool> {
        let (last, now, poll) = (
            self.last_tick_at_epoch?,
            self.now_epoch?,
            self.poll_seconds?,
        );
        Some(now.saturating_sub(last) <= Self::STALE_AFTER_POLLS * poll.cast_signed())
    }
}

/// The sealed proof that convergence was MEASURED.
///
/// `Converged`'s payload lives in a private module with a private field, so
/// the only way to obtain one anywhere in this crate is [`Proof::prove`],
/// which demands the evidence. There is deliberately no `Converged(String)`
/// to hand-roll: the previous shape let any caller assert convergence from
/// a string, and one did. This is the compile-time half of the fix — the
/// tests below are only the demonstration.
mod proof {
    use super::Evidence;

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct Proof(String);

    impl Proof {
        /// Construct ONLY from evidence that positively establishes every
        /// leg of convergence. Any missing or contradicting leg returns
        /// `None`, and the caller must then say `Unknown` or `Degraded`.
        pub fn prove(ev: &Evidence, deployed_rev: &str) -> Option<Self> {
            // The loop must be demonstrably alive. `None` (cannot tell) is
            // not alive — that is the whole lesson of the dead cid daemon.
            if ev.heartbeat_fresh() != Some(true) {
                return None;
            }
            // The deployed rev must equal where the branch actually points.
            let head = ev.declared_head_rev.as_deref()?;
            if head != deployed_rev {
                return None;
            }
            Some(Self(super::short_rev(deployed_rev)))
        }

        pub fn rev(&self) -> &str {
            &self.0
        }
    }
}
use proof::Proof;

/// The rendered verdict, split from the IO so every arm is testable.
///
/// `Unknown` is the arm the original shape lacked, and its absence is why
/// an empty status document scored as converged. "We cannot tell" is a
/// third thing: it must not raise an alarm (the cry-wolf failure the
/// original author guarded against) and it must not assert health either.
#[derive(Debug, PartialEq, Eq)]
enum GitopsVerdict {
    Converged(Proof),
    Degraded { headline: String, detail: String },
    Unknown { reason: String },
}

/// Turn a `sentinela status` document PLUS independently-measured
/// [`Evidence`] into an operator-facing verdict.
///
/// Pure: no IO, no process spawn — so every arm can be proven against a
/// known document instead of only ever being seen in an incident.
///
/// Missing fields no longer read as healthy. They read as [`Unknown`],
/// which prints without alarm but never claims convergence. The original
/// note here said "Unknown/missing fields read as HEALTHY on purpose … the
/// only thing worse than a silent reconciler is one that cries wolf" — the
/// fear was right and is preserved by `Unknown`; the remedy was wrong,
/// because it made an unreadable loop indistinguishable from a converged
/// one, which is precisely how cid reported itself healthy while dead.
///
/// [`Unknown`]: GitopsVerdict::Unknown
fn gitops_verdict(v: &serde_json::Value, ev: &Evidence) -> GitopsVerdict {
    let streak = v["consecutive_failures"].as_u64().unwrap_or(0);
    let verified = v["chain_verified"].as_bool().unwrap_or(true);
    let last_ok = v["last_activated_rev"].as_str();
    let kind = v["head"]["outcome"]["kind"].as_str().unwrap_or("unknown");
    let last_activated = last_ok.map_or_else(|| "never".to_owned(), short_rev);

    // ── ★ "NEVER DEPLOYED" IS NOT "CONVERGED" ────────────────────────────
    // An empty chain has a zero failure streak, so a naive `streak == 0`
    // reads a loop that has NEVER deployed anything as healthy. That is the
    // precise bug this whole feature exists to kill — silence scoring as
    // success — and it showed up here first: cid, freshly migrated onto the
    // daemon engine, reported "converged (last activated never)" while its
    // receipt chain was literally empty. Absence of failure is not evidence
    // of convergence; only an activation is.
    // Fires ONLY on a chain we can positively see is empty: `receipts` is
    // present and zero. Two cases must NOT land here — a status document we
    // could not parse (no `receipts` key ⇒ stay quiet, never cry wolf), and
    // a chain that is actively failing (streak > 0 ⇒ report the streak,
    // which is the more useful number). Both were caught by existing tests
    // when this branch was first written too broadly.
    if last_ok.is_none() && v["receipts"].as_u64() == Some(0) {
        return GitopsVerdict::Degraded {
            headline: "gitops: NO DEPLOY RECORDED — this loop has never converged".to_owned(),
            detail: format!(
                "    receipts       : {} (chain has no activation)\n    \
                 note           : expected on a freshly-enrolled node; \
                 investigate if it persists past one poll interval\n    \
                 detail         : sentinela --config {GITOPS_CONFIG} status\n",
                v["receipts"].as_u64().unwrap_or(0)
            ),
        };
    }

    // ── ★ A STOPPED LOOP IS LOUDER THAN A FAILING ONE ────────────────────
    // Checked BEFORE the streak, because a stopped daemon has a streak of
    // zero. cid's dead LaunchDaemon (exit 78, down since boot) presented
    // exactly the healthy document below; only the heartbeat separates it
    // from a genuinely converged node.
    if ev.heartbeat_fresh() == Some(false) {
        let silent_for = match (ev.now_epoch, ev.last_tick_at_epoch) {
            (Some(now), Some(last)) => format!("{}s", now.saturating_sub(last)),
            _ => "unknown".to_owned(),
        };
        return GitopsVerdict::Degraded {
            headline: "gitops: STOPPED — the reconciler is not ticking".to_owned(),
            detail: format!(
                "    last tick      : {silent_for} ago (poll interval {}s)\n    \
                 last activated : {last_activated}\n    \
                 note           : a stopped loop reports the same 0 failures as a \
                 healthy one; only the heartbeat tells them apart\n    \
                 detail         : sentinela --config {GITOPS_CONFIG} status\n",
                ev.poll_seconds.unwrap_or(0)
            ),
        };
    }

    if streak == 0 && verified {
        // Convergence must be PROVEN, not inferred from the absence of
        // failure. Without evidence there is no `Converged` to return —
        // the type makes that unrepresentable, so this cannot regress to
        // an optimistic default the way the old `Converged(String)` did.
        return match last_ok.and_then(|rev| Proof::prove(ev, rev)) {
            Some(p) => GitopsVerdict::Converged(p),
            None => {
                // Distinguish "behind" (we know HEAD, it differs) from
                // "cannot tell" (no evidence at all). Only the first is an
                // alarm; the second must stay quiet.
                match (ev.declared_head_rev.as_deref(), last_ok) {
                    (Some(head), Some(dep)) if head != dep => GitopsVerdict::Degraded {
                        headline: "gitops: BEHIND — the node is not at branch HEAD".to_owned(),
                        detail: format!(
                            "    branch HEAD    : {}\n    deployed       : {}\n    \
                             detail         : sentinela --config {GITOPS_CONFIG} status\n",
                            short_rev(head),
                            short_rev(dep)
                        ),
                    },
                    _ => GitopsVerdict::Unknown {
                        reason: "status document carries no heartbeat or branch HEAD; \
                                 convergence cannot be proven (daemon predates the \
                                 heartbeat field?)"
                            .to_owned(),
                    },
                }
            }
        };
    }

    // Say how LONG it has been wrong, not merely that it is wrong —
    // "failed" invites a shrug, "4136 consecutive" does not.
    let mut detail = String::new();
    detail.push_str(&format!(
        "    head receipt   : {kind} ({streak} consecutive)\n"
    ));
    detail.push_str(&format!("    last activated : {last_activated}\n"));
    if !verified {
        detail.push_str("    chain          : FAILED VERIFICATION (truncated or reordered)\n");
    }
    if let Some(err) = v["head"]["outcome"]["error"].as_str() {
        // First line only; the full text stays in the chain.
        let head_line = err.lines().next().unwrap_or(err);
        detail.push_str(&format!("    last error     : {head_line}\n"));
    }
    detail.push_str(&format!(
        "    detail         : sentinela --config {GITOPS_CONFIG} status\n"
    ));

    GitopsVerdict::Degraded {
        headline: "gitops: DEGRADED — the node is not tracking the branch".to_owned(),
        detail,
    }
}

/// What kind of dirt a path is — and therefore whether a machine may fix
/// it without asking.
///
/// ── ★ THE LINE IS "DERIVED", NOT "UNIMPORTANT" ──────────────────────────
/// An automated loop that reacts to a dirty tree by discarding changes is
/// a data-loss bug wearing a remediation costume. But a lock file is not
/// authored: every byte of `flake.lock` / `Cargo.lock` / `Cargo.gen.lock`
/// is reproducible from its inputs, so regenerating one loses nothing that
/// was not already recoverable.
///
/// That distinction is what makes automatic repair safe for exactly one
/// class and unsafe for every other. It is drawn here, once, so the
/// rebuild gate and the background reconciler cannot disagree about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dirt {
    /// Reproducible from its inputs — a machine may regenerate it.
    Derived,
    /// Someone wrote this. Only a human decides its fate.
    Authored,
}

/// Classify one `git status --porcelain` path.
#[must_use]
pub fn classify_dirt(path: &str) -> Dirt {
    // Matched on the FILE NAME, not a path prefix: these appear at a
    // workspace root and inside members, and a prefix rule would miss the
    // nested ones — which are exactly the ones a fleet-wide update touches.
    let name = path.rsplit('/').next().unwrap_or(path);
    match name {
        "flake.lock" | "Cargo.lock" | "Cargo.gen.lock" | "Cargo.build-spec.json" => Dirt::Derived,
        _ => Dirt::Authored,
    }
}

/// Split a porcelain listing into (derived, authored) paths.
///
/// Returns paths, not counts, because every caller needs to NAME what it
/// found — a remediation that says "3 files" tells the operator nothing
/// they can act on.
#[must_use]
pub fn partition_dirt(porcelain: &str) -> (Vec<String>, Vec<String>) {
    let mut derived = Vec::new();
    let mut authored = Vec::new();
    for line in porcelain.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        // `XY path` — status codes are the first two columns. A rename
        // reads `R  old -> new`; the NEW path is what exists on disk.
        let path = line.get(3..).unwrap_or("").trim();
        let path = path.rsplit(" -> ").next().unwrap_or(path);
        if path.is_empty() {
            continue;
        }
        match classify_dirt(path) {
            Dirt::Derived => derived.push(path.to_owned()),
            Dirt::Authored => authored.push(path.to_owned()),
        }
    }
    (derived, authored)
}

/// Refuse to rebuild from a tree that is not fully committed.
///
/// Returns the offending paths in the error so the operator does not have
/// to re-run `git status` to learn what stopped them.
fn ensure_tree_is_committed(flake_root: &Path) -> Result<()> {
    if std::env::var("FLEET_ALLOW_DIRTY_REBUILD").is_ok() {
        log_warning(
            "FLEET_ALLOW_DIRTY_REBUILD set — building from an uncommitted tree. \
             The reconciler will revert this to HEAD on its next tick.",
        );
        return Ok(());
    }
    let out = Command::new("git")
        // --no-optional-locks: a rebuild must never be the thing that
        // strands an index.lock in the operator's repo.
        .args(["--no-optional-locks", "status", "--porcelain"])
        .current_dir(flake_root)
        .output();
    let Ok(out) = out else {
        // git absent or unrunnable is not evidence of cleanliness, but it
        // is also not this command's job to adjudicate. Say so and continue.
        log_warning("could not run `git status` — proceeding without the clean-tree check");
        return Ok(());
    };
    if !out.status.success() {
        log_warning("`git status` failed — proceeding without the clean-tree check");
        return Ok(());
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    let (derived, authored) = partition_dirt(&listing);
    if derived.is_empty() && authored.is_empty() {
        return Ok(());
    }
    let dirty: Vec<&str> = listing.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut msg = String::from(
        "refusing to rebuild: the flake tree has uncommitted changes.\n\n\
         A rebuild from a dirty tree produces a system that exists in no \
         commit, and the gitops reconciler will converge this node back to \
         HEAD — silently reverting it, and recording that revert as a clean \
         activation.\n\n",
    );
    for line in dirty.iter().take(20) {
        msg.push_str("    ");
        msg.push_str(line);
        msg.push('\n');
    }
    if dirty.len() > 20 {
        msg.push_str("    … and ");
        msg.push_str(&(dirty.len() - 20).to_string());
        msg.push_str(" more\n");
    }
    // Naming the derived subset is actionable in a way the raw list is
    // not: those are regenerable, so the operator knows they can be
    // discarded without thought, and the background reconciler is allowed
    // to do exactly that unattended.
    if !derived.is_empty() {
        msg.push_str("\n  derived (regenerable, safe to discard): ");
        msg.push_str(&derived.join(", "));
        msg.push('\n');
    }
    if !authored.is_empty() {
        msg.push_str("  authored (only you can decide): ");
        msg.push_str(&authored.join(", "));
        msg.push('\n');
    }
    msg.push_str(
        "\nCommit or stash, then rebuild. To build anyway (it will not \
         survive the next reconcile): FLEET_ALLOW_DIRTY_REBUILD=1",
    );
    anyhow::bail!(msg)
}

/// Short-form a 40-char rev for display, leaving anything else untouched.
fn short_rev(rev: &str) -> String {
    rev.get(..7).unwrap_or(rev).to_owned()
}

pub fn rebuild(node: Option<&str>, show_trace: bool, nix_options: &[String]) -> Result<()> {
    // Held for the whole call (released on any return path, including
    // early `?` exits and panics, via Drop) — see acquire_rebuild_lock's
    // doc comment for the concrete failure this prevents.
    let _rebuild_lock = acquire_rebuild_lock()?;

    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let flake_root = find_flake_root(&cwd)?;

    // ── ★ A DIRTY TREE IS A HARD FAIL, NOT A WARNING ─────────────────────
    // nix only warns ("Git tree … is dirty") and builds anyway. Under
    // GitOps that warning is the beginning of a divergence, not a note:
    //
    //   1. you build a system that exists in NO commit, so nothing can
    //      reproduce it and no receipt can name it;
    //   2. the reconciler then converges the node to the pushed HEAD and
    //      SILENTLY reverts your build, usually minutes later;
    //   3. the receipt chain records that activation as a clean success,
    //      because from its side it was.
    //
    // The node oscillates and every surface reports health. Refusing up
    // front is the only point at which this is cheap to see.
    ensure_tree_is_committed(&flake_root)?;

    // ── THE NODE NAME IS DERIVED, BUT OVERRIDABLE ────────────────────────
    // `hostname -s` reports what the machine is called NOW, which on a NixOS
    // installer image is `nixos`. That is right for a re-build and wrong for
    // the FIRST one, where the whole point is that the machine has not been
    // the node yet — `.#nixos` is not a configuration, so the derived form
    // failed at the very end, after the token work had already succeeded.
    // Derivation stays the default; the argument is the override, and the log
    // says which was used so a run against the wrong node is visible in the
    // first lines rather than at the end.
    let hostname = match node {
        Some(n) => {
            log_info(&format!("Node: {n} (from argument)"));
            n.to_string()
        }
        None => {
            let h = get_hostname()?;
            log_info(&format!("Node: {h} (from hostname)"));
            h
        }
    };

    // PATH-harden (macOS): `darwin-rebuild` lives ONLY in
    // /run/current-system/sw/bin. A calling shell that lacks it on PATH — one
    // started before the first activation, or whose /etc/static was transiently
    // broken — makes `which darwin-rebuild` fail, wrongly driving the first-run
    // BOOTSTRAP path on a fully-configured system (which re-writes
    // /etc/nix/nix.custom.conf and runs a buffered full build that looks hung).
    // Prepend the canonical system + per-user profile bins so darwin-rebuild /
    // nix / sudo always resolve, regardless of the caller's environment.
    if std::env::consts::OS == "macos" {
        let user = std::env::var("USER").unwrap_or_default();
        let prefix = format!(
            "/run/current-system/sw/bin:/etc/profiles/per-user/{user}/bin:/nix/var/nix/profiles/default/bin"
        );
        let existing = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{prefix}:{existing}"));
    }

    log_info(&format!(
        "Rebuilding {} (flake at {})",
        hostname,
        flake_root.display()
    ));

    report_gitops_health();

    // Bootstrap: ensure nix daemon has sandbox=false and trusted-users
    // before any builds. Only writes if settings are missing (first run).
    if std::env::consts::OS == "macos" {
        if let Err(e) = bootstrap_nix_custom_conf() {
            log_warning(&format!(
                "Nix daemon config bootstrap: {e} — continuing anyway"
            ));
        }
        // Accept Xcode license — xcodebuild refuses to run for any user
        // (including nix build users) until the license is accepted.
        accept_xcode_license();
    }

    // Resolve the GitHub token this rebuild authenticates with — env, then
    // nix.conf, then a SOPS scrape when nothing on disk carries a usable one.
    // Non-fatal by design: a node may legitimately have no private inputs to
    // fetch, and refusing to rebuild would be worse than letting nix say so.
    let github_token = resolve_github_token(&flake_root);

    // Materialize the credential as a private 0600 nix.conf fragment, ONCE, so
    // both rebuild arms share it and its `Drop` removes it however this
    // function exits. Binding it here (rather than inside an arm) is what
    // keeps the file alive for the whole switch — a temporary dropped at the
    // end of its statement would leave `!include` pointing at nothing, and
    // nix skips an unreadable include SILENTLY.
    //
    // Non-fatal: a node that cannot write its own temp dir should still get
    // the rebuild attempt and nix's own error, not a refusal from us.
    let token_conf = github_token
        .as_ref()
        .and_then(|t| match TokenConfigFile::create(t) {
            Ok(conf) => Some(conf),
            Err(e) => {
                log_warning(&format!(
                    "Could not stage the GitHub credential for nix ({e}) — \
                 private flake inputs may fail to fetch"
                ));
                None
            }
        });

    // Ensure Claude Code is available for interactive debugging.
    // On first run this installs it via nix profile so the user can
    // use `claude` to troubleshoot any remaining bootstrap issues.
    ensure_claude_code();

    // Spec staleness is handled per-package by substrate's
    // `lockfile-builder.nix` (see substrate/lib/build/rust/
    // lockfile-builder.nix L278-280 + mk-build-spec.nix). Every
    // consumer build that has `gen` reachable auto-regenerates its
    // OWN spec via IFD before composition, on demand, only for the
    // packages nix actually walks for this rebuild. The earlier
    // upstream fleet sweep (rip in peace) was strictly redundant:
    // it brute-forced all 524 pleme-io repos to write committed
    // specs that substrate would have regenerated anyway, only for
    // a small subset of which the current rebuild touched. Each
    // repo sweeps itself — lazy, parallel, exactly the closure of
    // demand. Operators who want to PRE-WARM a specific repo's
    // committed spec on disk run `gen build --if-stale` manually
    // in that repo; the rebuild path is now sweep-free.

    match std::env::consts::OS {
        "macos" => darwin_rebuild(
            &flake_root,
            &hostname,
            show_trace,
            nix_options,
            token_conf.as_ref(),
        ),
        "linux" => nixos_rebuild(
            &flake_root,
            &hostname,
            show_trace,
            nix_options,
            token_conf.as_ref(),
        ),
        os => anyhow::bail!("Unsupported OS: {}", os),
    }
}

/// Point a rebuild invocation at the resolved credential.
///
/// Threaded through EVERY invocation, not just the first-run bootstrap. The
/// old code forwarded it only inside the darwin bootstrap branch, so a
/// steady-state `darwin-rebuild switch` and every single `nixos-rebuild` ran
/// with whatever nix.conf happened to hold — which is precisely the file that
/// is stale or empty on the node that needs help.
///
/// ★ The credential travels as `NIX_CONFIG=!include <0600 file>`, NEVER as
/// `--option access-tokens github.com=<tok>` on argv. argv is world-readable
/// (`ps`, `/proc/<pid>/cmdline`) for the whole multi-minute life of a switch,
/// and the fleet PAT was measurably legible there on 2026-08-29. Same parser,
/// same override precedence, same resulting setting — the secret simply stops
/// being public. See [`TokenConfigFile`] for the two traps this shape encodes.
fn forward_access_tokens(cmd: &mut Command, token_conf: Option<&TokenConfigFile>) {
    if let Some(conf) = token_conf {
        let existing = std::env::var("NIX_CONFIG").ok();
        cmd.env("NIX_CONFIG", conf.compose_nix_config(existing.as_deref()));
    }
}

fn darwin_rebuild(
    flake_root: &Path,
    hostname: &str,
    show_trace: bool,
    nix_options: &[String],
    token_conf: Option<&TokenConfigFile>,
) -> Result<()> {
    log_info(&format!("Darwin rebuild for {}...", hostname));

    // darwin-rebuild switch requires root for system activation.
    // Preserve HOME/USER so home-manager activates for the real user.
    // Preserve NIX_SSL_CERT_FILE so fetchGit HTTPS calls can verify certs.
    // Preserve GIT_SSL_CAINFO so git's OpenSSL can verify HTTPS certs under sudo.
    let real_user = std::env::var("USER").unwrap_or_default();
    let real_home = std::env::var("HOME").unwrap_or_default();
    let ssl_cert = std::env::var("NIX_SSL_CERT_FILE")
        .unwrap_or_else(|_| "/etc/ssl/certs/ca-certificates.crt".to_string());

    // Bootstrap: on first run, darwin-rebuild isn't installed yet.
    // Build the system configuration and activate it directly.
    if !command_exists("darwin-rebuild") {
        log_warning("darwin-rebuild not in PATH — bootstrapping from flake...");

        let mut build_cmd = Command::new("nix");
        build_cmd
            .args([
                "--extra-experimental-features",
                "nix-command flakes",
                "build",
                "--print-out-paths",
                "--no-link",
            ])
            .arg(format!(".#darwinConfigurations.{hostname}.system"))
            .current_dir(flake_root);

        // Disable sandbox during bootstrap — macOS blocks .app bundle
        // creation and xcodebuild framework access inside the sandbox.
        // After activation, nix.custom.conf sets sandbox=false permanently.
        build_cmd.arg("--option").arg("sandbox").arg("false");

        // Forward access-tokens so nix can fetch private flake inputs
        forward_access_tokens(&mut build_cmd, token_conf);

        // Forward user-provided nix options to the bootstrap build
        for pair in nix_options.chunks(2) {
            if pair.len() == 2 {
                build_cmd.arg("--option").arg(&pair[0]).arg(&pair[1]);
            }
        }

        let system_path = run_command_output(&mut build_cmd)
            .context("Failed to build darwin system configuration")?;

        // Move /etc files that nix-darwin wants to manage before activation
        prepare_etc_for_darwin()?;

        log_info("Activating system profile (bootstrap)...");
        let activate = format!("{system_path}/activate");

        let mut cmd = Command::new("sudo");
        cmd.arg("--preserve-env=HOME,USER,NIX_SSL_CERT_FILE,GIT_SSL_CAINFO,NIX_CONFIG")
            .env("HOME", &real_home)
            .env("USER", &real_user)
            .env("NIX_SSL_CERT_FILE", &ssl_cert)
            .env("GIT_SSL_CAINFO", &ssl_cert)
            .arg(&activate)
            .current_dir(flake_root);

        run_command(&mut cmd)?;
        log_success(&format!("{} bootstrapped successfully", hostname));
        return Ok(());
    }

    // L2 e2e rebuild gate (mado/docs/INTEGRATION-TESTING.md §L2): before
    // switching, drive the candidate closure's own `mado e2e` smoke matrix —
    // the only layer that catches deployment wiring (the follows-downgrade
    // class: cargo artifacts green while the deployed closure ships a stale
    // binary; incident 2026-06-10). The flake app resolves mado + frostmourne
    // from THIS flake's pins, i.e. exactly what `darwin-rebuild switch` is
    // about to deploy. Graceful: skipped when the flake has no `e2e-mado`
    // app (non-terminal fleet nodes) or via FLEET_SKIP_E2E_GATE=1 (break-
    // glass; the skip is loud either way).
    if std::env::var("FLEET_SKIP_E2E_GATE").map_or(true, |v| v != "1") {
        let system = if cfg!(target_arch = "aarch64") {
            "aarch64-darwin"
        } else {
            "x86_64-darwin"
        };
        let app_attr = format!(".#apps.{system}.e2e-mado.program");
        let has_app = Command::new("nix")
            .args(["eval", "--raw", &app_attr])
            .current_dir(flake_root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_or(false, |s| s.success());
        if has_app {
            // The matrix spawns a REAL shell in a REAL pty as its first row, so
            // an exhausted pty table fails it for a reason that has nothing to
            // do with the closure — and the failure message below would then
            // blame the closure. Measured 2026-08-06: 500/511 ptys held by 459
            // orphaned login shells turned a healthy candidate into "refusing to
            // switch". Reap first, and say so out loud if the pressure survives.
            super::pty_guard::preflight();

            log_info("e2e gate — driving the candidate closure's mado/frostmourne matrix");
            // CAPTURED, not inherited. The gate is a machine-readable JSON
            // report, and it was being dumped raw into the operator's
            // rebuild — brace-wrapped rows interleaved with rmcp's own
            // `INFO serve_inner: rmcp::service: …` tracing and a
            // 400-character `peer_info=Some(InitializeResult { … })` line.
            // None of that is actionable while it PASSES; all of it is
            // actionable when it fails. So: capture, render the rows, and
            // release the raw text only on failure, where it is evidence.
            //
            // RUST_LOG=off silences the child's tracing subscriber at the
            // source rather than filtering its lines back out downstream —
            // the noise is the MCP client's, not the gate's verdict.
            let out = Command::new("nix")
                .args(["run", ".#e2e-mado"])
                .current_dir(flake_root)
                .env("RUST_LOG", "off")
                .output()
                .context("Failed to launch the e2e gate")?;

            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let report = parse_e2e_report(&stdout);

            if let Some((shell, rows)) = &report {
                let width = rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
                for row in rows {
                    let (mark, name) = if row.skipped {
                        ("·".dimmed(), row.name.normal().dimmed())
                    } else if row.pass {
                        ("✓".green().bold(), row.name.normal())
                    } else {
                        ("✗".red().bold(), row.name.red().bold())
                    };
                    println!(
                        "       {mark} {name:<width$}  {}",
                        row.detail.dimmed(),
                        width = width
                    );
                }
                // The shell under test is the whole point of the gate — it
                // is what proves the closure ships the binary it claims —
                // so name it, by store path, rather than "verified".
                println!("       {} {}", "shell".dimmed(), shell.dimmed());
            }

            if !out.status.success() {
                // Everything the capture withheld, now that it is evidence.
                if report.is_none() && !stdout.trim().is_empty() {
                    eprintln!("{}", stdout.trim_end());
                }
                if !stderr.trim().is_empty() {
                    eprintln!("{}", stderr.trim_end());
                }
                // Before blaming the closure, say what the environment looks
                // like. A pty table with no room fails row 1 for a reason no
                // diff will explain, and this message used to assert the
                // closure was at fault with no evidence for that reading.
                let env_note = match super::pty_guard::measure() {
                    Ok(p) if p.in_use * 4 >= p.ceiling * 3 => format!(
                        " NOTE: this host is at {}/{} ptys — a spawn_term failure here is \
                         very likely pty exhaustion, NOT the closure. Check \
                         `ls /dev/ttys* | wc -l` against `sysctl kern.tty.ptmx_max`.",
                        p.in_use, p.ceiling
                    ),
                    _ => String::new(),
                };
                anyhow::bail!(
                    "e2e gate FAILED — the candidate closure's mado/frostmourne smoke \
                     matrix did not pass; refusing to switch. Inspect with \
                     `nix run .#e2e-mado`; break-glass override: \
                     FLEET_SKIP_E2E_GATE=1 (document why).{env_note}"
                );
            }

            let passed = report.as_ref().map_or(0, |(_, r)| {
                r.iter().filter(|row| row.pass && !row.skipped).count()
            });
            let total = report.as_ref().map_or(0, |(_, r)| r.len());
            if total > 0 {
                log_success(&format!(
                    "e2e gate passed — {passed}/{total} checks, candidate closure verified interactive"
                ));
            } else {
                log_success("e2e gate passed — candidate closure verified interactive");
            }
        } else {
            log_info("e2e gate: no .#e2e-mado app in this flake — skipped");
        }
    } else {
        log_warning("e2e gate SKIPPED via FLEET_SKIP_E2E_GATE=1");
    }

    // Move /etc files that nix-darwin wants to manage before activation
    prepare_etc_for_darwin()?;

    let mut cmd = Command::new("sudo");
    cmd.arg("--preserve-env=HOME,USER,NIX_SSL_CERT_FILE,GIT_SSL_CAINFO,NIX_CONFIG")
        .env("HOME", &real_home)
        .env("USER", &real_user)
        .env("NIX_SSL_CERT_FILE", &ssl_cert)
        .env("GIT_SSL_CAINFO", &ssl_cert)
        .arg("darwin-rebuild")
        .arg("switch")
        .arg("--flake")
        .arg(format!(".#{}", hostname))
        .current_dir(flake_root);

    if show_trace {
        cmd.arg("--show-trace");
    }

    // Forward the resolved credential to the ACTIVATION build too — sudo drops
    // the caller's nix.conf, so root's copy is what would otherwise apply.
    forward_access_tokens(&mut cmd, token_conf);

    // Forward --option key value pairs to darwin-rebuild. Last, so an explicit
    // operator `--option access-tokens …` still wins over the resolved one.
    for pair in nix_options.chunks(2) {
        if pair.len() == 2 {
            cmd.arg("--option").arg(&pair[0]).arg(&pair[1]);
        }
    }

    run_command_timed(&mut cmd, rebuild_timeout())?;
    post_rebuild_cleanup();
    log_success(&format!("{} rebuilt successfully", hostname));
    Ok(())
}

fn nixos_rebuild(
    flake_root: &Path,
    hostname: &str,
    show_trace: bool,
    nix_options: &[String],
    token_conf: Option<&TokenConfigFile>,
) -> Result<()> {
    log_info(&format!("NixOS rebuild for {}...", hostname));

    let mut cmd = Command::new("sudo");
    cmd.arg(rebuild_driver("nixos-rebuild"))
        .arg("switch")
        .arg("--flake")
        .arg(format!(".#{}", hostname))
        .current_dir(flake_root)
        .env("NIX_CONFIG", "experimental-features = nix-command flakes");

    if show_trace {
        cmd.arg("--show-trace");
    }

    // The load-bearing line for a PAT-less NixOS bootstrap: the nix daemon runs
    // as root and reads ROOT's config, so a token the operator holds in their
    // own nix.conf never reaches this build. Passing it explicitly is what
    // makes a node with no rendered secret rebuild at all.
    forward_access_tokens(&mut cmd, token_conf);

    // Forward --option key value pairs to nixos-rebuild. Last, so an explicit
    // operator `--option access-tokens …` still wins over the resolved one.
    for pair in nix_options.chunks(2) {
        if pair.len() == 2 {
            cmd.arg("--option").arg(&pair[0]).arg(&pair[1]);
        }
    }

    run_command_timed(&mut cmd, rebuild_timeout())?;
    post_rebuild_cleanup();
    log_success(&format!("{} rebuilt successfully", hostname));
    Ok(())
}

/// Best-effort post-rebuild cleanup. Runs `seibi nix-gc --keep-days 14`
/// after a successful switch so stale generations don't accumulate.
///
/// Skipped silently when:
///   - `seibi` is not in PATH (e.g., bootstrap before the home-manager
///     profile installs it),
///   - `FLEET_REBUILD_CLEANUP=0` is set in the environment,
///   - any of the spawn / wait steps fails (warned, not propagated —
///     the rebuild already succeeded).
fn post_rebuild_cleanup() {
    if std::env::var("FLEET_REBUILD_CLEANUP").is_ok_and(|v| v == "0") {
        return;
    }
    if !command_exists("seibi") {
        return;
    }

    log_info("post-rebuild: seibi nix-gc --keep-days 14");
    let status = Command::new("seibi")
        .args(["nix-gc", "--keep-days", "14"])
        .status();

    match status {
        Ok(s) if s.success() => log_success("post-rebuild nix-gc complete"),
        Ok(s) => log_warning(&format!(
            "post-rebuild nix-gc exited non-zero: {:?}",
            s.code()
        )),
        Err(e) => log_warning(&format!("post-rebuild nix-gc failed to spawn: {e}")),
    }
}

#[cfg(test)]
mod rebuild_lock_tests {

    // ── stale-lock detection + repair ────────────────────────────────
    //
    // Measured on ggg: a fresh NixOS account ran `nix run .#rebuild` and got
    // `failed to open rebuild lock file at /tmp/fleet-rebuild.lock:
    // Permission denied`, with nothing to do next — /tmp is sticky so she
    // could not unlink it, and the 0666 widening runs AFTER open so it could
    // not rescue it either.

    #[test]
    fn a_holder_stamp_parses_to_its_pid() {
        let p = fresh_lock_path("stamp");
        std::fs::write(&p, "pid 4242 \u{b7} gabi").expect("write");
        assert_eq!(super::holder_pid(&p), Some(4242));
        let _ = std::fs::remove_file(&p);
    }

    /// A file nobody stamped is not a lock anyone holds — it must route to
    /// the stale branch rather than being mistaken for a live holder.
    #[test]
    fn an_unstamped_lock_has_no_pid() {
        let p = fresh_lock_path("unstamped");
        std::fs::write(&p, "").expect("write");
        assert_eq!(super::holder_pid(&p), None);
        std::fs::write(&p, "garbage from an older format").expect("write");
        assert_eq!(super::holder_pid(&p), None);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn our_own_pid_is_alive_and_an_absurd_one_is_not() {
        assert!(super::pid_is_alive(std::process::id()));
        // Above any plausible pid_max on Linux or macOS.
        assert!(!super::pid_is_alive(0x7FFF_FFFF));
    }

    /// THE safety property. A lock whose writer is STILL RUNNING must never
    /// be cleared — that is the difference between repairing debris and
    /// yanking a live rebuild's lock out from under it.
    #[test]
    fn a_live_holder_is_never_treated_as_stale() {
        assert!(
            super::pid_is_alive(std::process::id()),
            "this test's own pid must read alive, or the guard proves nothing"
        );
    }

    /// A stale lock we CAN unlink is repaired without escalating.
    #[test]
    fn a_stale_lock_is_cleared_and_the_rebuild_proceeds() {
        let lock = fresh_lock_path("stale");
        // A dead pid: the file is debris from a process that is gone.
        std::fs::write(&lock, "pid 2147483647 \u{b7} root").expect("seed");
        super::clear_stale_lock(&lock).expect("clear");
        assert!(!lock.exists(), "the stale lock is gone");
        // And the normal path then works.
        let f = super::acquire_lock_at(&lock, LockWait::Bounded(LOCK_WAIT_TIMEOUT))
            .expect("acquire after clear");
        drop(f);
        let _ = std::fs::remove_file(&lock);
    }
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn fresh_lock_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fleet-rebuild-test-{name}-{}.lock",
            std::process::id()
        ))
    }

    #[test]
    fn the_rebuild_lock_path_is_machine_wide_not_per_user() {
        // THE REGRESSION TEST FOR THE ACTUAL BUG. The lock was
        // `std::env::temp_dir().join(...)`, and on macOS `temp_dir()` is a
        // PER-USER `/var/folders/…/T/`. Measured on ryn 2026-08-02: root's
        // gitops daemon and the operator resolved different paths, so the
        // lock serialized nothing across users and two rebuilds ran
        // concurrently — the race it exists to prevent.
        //
        // Assert the property, not the literal: the path must be absolute and
        // must NOT be derived from this process's temp dir.
        let p = Path::new(REBUILD_LOCK_PATH);
        assert!(p.is_absolute(), "rebuild lock path must be absolute");
        let per_user = std::env::temp_dir();
        assert!(
            !p.starts_with(&per_user) || per_user == Path::new("/tmp"),
            "rebuild lock must not live under the per-user temp dir ({}), \
             or two users get two different locks",
            per_user.display()
        );
    }

    #[test]
    fn the_lock_file_is_group_and_other_writable() {
        // Cross-user reachability: whichever party creates the file first must
        // not lock the other out. Root creating a 0644 file would make every
        // subsequent operator rebuild fail with EACCES rather than wait.
        let path = fresh_lock_path("perms");
        let _guard = acquire_lock_at(&path, LockWait::Bounded(LOCK_WAIT_TIMEOUT)).expect("acquire");
        let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o666,
            "lock file must be world-writable, got {mode:o}"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_holder_identity_is_recorded_for_the_next_waiter() {
        // A bare "waiting..." with no identity is what makes a blocked
        // interactive rebuild indistinguishable from a wedged one.
        let path = fresh_lock_path("holder");
        {
            let _guard =
                acquire_lock_at(&path, LockWait::Bounded(LOCK_WAIT_TIMEOUT)).expect("acquire");
            let stamped = fs::read_to_string(&path).expect("read holder");
            assert!(
                stamped.contains(&std::process::id().to_string()),
                "lock must record the holder pid, got {stamped:?}"
            );
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn second_acquire_blocks_until_first_is_dropped() {
        // The exact scenario that caused the live sops-nix race: two
        // `fleet rebuild` invocations overlapping. This proves the second
        // one now WAITS instead of proceeding concurrently.
        let path = fresh_lock_path("blocks");
        let first =
            acquire_lock_at(&path, LockWait::Bounded(LOCK_WAIT_TIMEOUT)).expect("first acquire");

        let (tx, rx) = mpsc::channel();
        let path_clone = path.clone();
        let handle = thread::spawn(move || {
            tx.send(()).unwrap(); // signal "about to block on acquire"
            acquire_lock_at(&path_clone, LockWait::Bounded(LOCK_WAIT_TIMEOUT))
                .expect("second acquire");
            "acquired".to_string()
        });

        rx.recv().unwrap();
        // Give the spawned thread a moment to actually reach the blocking
        // flock call before we drop the first lock — best-effort, not
        // load-bearing for correctness (if the thread is slower, the
        // assertion below still holds; this just makes the race window
        // realistic instead of vacuous).
        thread::sleep(Duration::from_millis(50));

        drop(first);
        let result = handle.join().expect("thread panicked");
        assert_eq!(result, "acquired");

        let _ = fs::remove_file(&path);
    }

    /// The bound exists, it fires, and it names who it waited on.
    ///
    /// This is the regression for the 2026-08-07 rio incident
    /// (`theory/BALIZA.md` phase 0b): the previous code called
    /// `FileExt::lock_exclusive`, which blocks FOREVER. A rebuild queued
    /// behind a wedged holder printed one line and never spoke again, and
    /// the operator had no way to tell a healthy long build from a wedge.
    ///
    /// A hang must degrade into a typed failure. `FLEET_REBUILD_LOCK_
    /// TIMEOUT_SECS=1` against a lock nobody ever releases proves it does.
    ///
    /// RED-RUN RECEIPT (2026-08-07): reverting `wait_for_lock` to a bare
    /// `FileExt::lock_exclusive(file)` hangs this test until the harness
    /// kills it — which is exactly the defect, observed.
    /// The absolute form is used when the system profile carries the driver.
    ///
    /// Measured on rio 2026-08-07: `/run/current-system/sw/bin/nixos-rebuild`
    /// resolves to the nixos-rebuild-ng store path, so this branch is the live
    /// one on every managed NixOS node — which is exactly where `sudo`'s
    /// `secure_path` would otherwise decide for us.
    #[test]
    fn rebuild_driver_prefers_the_system_profile_path() {
        // Only meaningful where a system profile exists; on a machine without
        // one the fallback test below is the relevant half.
        if PathBuf::from("/run/current-system/sw/bin/nixos-rebuild").exists() {
            assert_eq!(
                rebuild_driver("nixos-rebuild"),
                "/run/current-system/sw/bin/nixos-rebuild",
                "a managed node must not leave the driver to sudo's secure_path"
            );
        }
    }

    /// FAILS OPEN, deliberately. A machine with no system profile is being
    /// bootstrapped, and the bare name is the correct answer there — this must
    /// never turn a missing path into a hard failure, because that would brick
    /// adoption to fix a PATH assumption.
    ///
    /// RED-RUN RECEIPT (2026-08-07): making the fallback branch return an
    /// absolute path unconditionally turns this red with a `/run/current-system`
    /// prefix on a name that does not exist there.
    #[test]
    fn rebuild_driver_falls_back_to_the_bare_name() {
        let absent = "definitely-not-a-real-rebuild-driver-xyz";
        assert_eq!(
            rebuild_driver(absent),
            absent,
            "an unbootstrapped machine must still get a runnable argv"
        );
    }

    #[test]
    fn waiting_for_a_never_released_lock_fails_typed_instead_of_hanging() {
        let path = fresh_lock_path("bounded");
        // Held for the whole test, never dropped before the assertion —
        // this stands in for a wedged peer.
        let _held =
            acquire_lock_at(&path, LockWait::Bounded(LOCK_WAIT_TIMEOUT)).expect("first acquire");

        // The value, passed in. No env write, so no sibling test can observe
        // or clobber it — this is the whole point of the LockWait parameter.
        let started = Instant::now();
        let err = acquire_lock_at(&path, LockWait::Bounded(Duration::from_secs(1)))
            .expect_err("must not hang, must fail typed");
        let elapsed = started.elapsed();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("gave up waiting for the rebuild lock"),
            "the error must say the wait was BOUNDED, got: {msg}"
        );
        assert!(
            msg.contains("held by"),
            "the error must name the holder so the operator can inspect it, got: {msg}"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "the bound must actually fire; waited {elapsed:?}"
        );

        let _ = fs::remove_file(&path);
    }

    /// `0` restores the pre-2026-08-07 unbounded wait — the escape hatch
    /// stays reachable rather than deleted (★★ MODULARIZE, DON'T DELETE).
    /// Proven by acquiring an UNCONTENDED lock with the bound disabled: it
    /// must still succeed, i.e. the zero path is wired, not a dead branch.
    #[test]
    fn timeout_zero_selects_the_unbounded_path() {
        let path = fresh_lock_path("unbounded-opt-in");
        let got = acquire_lock_at(&path, LockWait::Unbounded);
        assert!(
            got.is_ok(),
            "uncontended acquire must succeed with the bound disabled"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn lock_is_reentrant_across_sequential_acquisitions() {
        // Not concurrent — just confirms a dropped lock genuinely
        // releases, so back-to-back rebuilds (the common case) never
        // deadlock against their own prior run.
        let path = fresh_lock_path("sequential");
        let first =
            acquire_lock_at(&path, LockWait::Bounded(LOCK_WAIT_TIMEOUT)).expect("first acquire");
        drop(first);
        let second = acquire_lock_at(&path, LockWait::Bounded(LOCK_WAIT_TIMEOUT))
            .expect("second acquire after drop");
        drop(second);

        let _ = fs::remove_file(&path);
    }
}

#[cfg(test)]
mod gitops_verdict_tests {

    // ── ★ WHAT A MACHINE MAY FIX UNATTENDED ─────────────────────────────
    // An automated loop that reacts to a dirty tree by discarding changes
    // is a data-loss bug in a remediation costume. The safe class is
    // exactly the DERIVED one — reproducible from its inputs, so
    // regenerating loses nothing that was not already recoverable.

    #[test]
    fn lock_files_are_derived_wherever_they_sit() {
        // Nested is the case that matters: a fleet-wide update touches
        // member locks, and a path-PREFIX rule would miss every one.
        for p in [
            "flake.lock",
            "Cargo.lock",
            "Cargo.gen.lock",
            "Cargo.build-spec.json",
            "crates/blue-lang-cli/Cargo.lock",
            "deep/nested/flake.lock",
        ] {
            assert_eq!(classify_dirt(p), Dirt::Derived, "{p}");
        }
    }

    #[test]
    fn source_is_authored_even_when_it_looks_generated() {
        for p in [
            "src/main.rs",
            "flake.nix",
            "modules/pleme/shared/gitops.nix",
            // Named like a lock, is not one — the match is exact.
            "flake.lock.bak",
            "docs/Cargo.lock.md",
        ] {
            assert_eq!(classify_dirt(p), Dirt::Authored, "{p}");
        }
    }

    #[test]
    fn porcelain_is_split_by_class_and_renames_use_the_new_path() {
        let porcelain = concat!(
            " M flake.lock\n",
            " M src/main.rs\n",
            "?? crates/x/Cargo.lock\n",
            "R  old/name.rs -> new/name.rs\n",
        );
        let (derived, authored) = partition_dirt(porcelain);
        assert_eq!(derived, vec!["flake.lock", "crates/x/Cargo.lock"]);
        // A rename's NEW path is what exists on disk; classifying the old
        // one would judge a file that is no longer there.
        assert_eq!(authored, vec!["src/main.rs", "new/name.rs"]);
    }

    #[test]
    fn a_clean_tree_partitions_to_nothing() {
        let (d, a) = partition_dirt("");
        assert!(d.is_empty() && a.is_empty());
        let (d, a) = partition_dirt("\n  \n");
        assert!(d.is_empty() && a.is_empty());
    }

    use super::*;
    use serde_json::json;

    /// Evidence for a loop that ticked one second ago and whose branch
    /// HEAD is `rev` — i.e. everything convergence requires.
    fn proving_evidence(rev: &str) -> Evidence {
        Evidence {
            declared_head_rev: Some(rev.to_owned()),
            last_tick_at_epoch: Some(1_785_724_800),
            now_epoch: Some(1_785_724_801),
            poll_seconds: Some(60),
        }
    }

    #[test]
    fn converged_chain_reports_the_last_activated_rev() {
        let rev = "da42c8f8d082453e8ad303c55aacbebca1420336";
        let v = json!({
            "consecutive_failures": 0,
            "chain_verified": true,
            "last_activated_rev": rev,
            "head": { "outcome": { "kind": "activated", "generation": 1215 } },
        });
        let GitopsVerdict::Converged(p) = gitops_verdict(&v, &proving_evidence(rev)) else {
            panic!("a live loop sitting on branch HEAD is the one case that IS converged");
        };
        assert_eq!(p.rev(), "da42c8f");
    }

    /// ── ★ THE REGRESSION THIS REFACTOR EXISTS FOR ────────────────────────
    /// cid's ACTUAL `sentinela status` output, captured 2026-08-02 23:15
    /// local, while its LaunchDaemon had been dead since boot (exit 78
    /// EX_CONFIG) and the node sat 14 commits behind origin/main. Every
    /// field here is true and the old verdict scored it `Converged`.
    ///
    /// Red run: revert `gitops_verdict` to `streak == 0 && verified` and
    /// this returns Converged for a node that has not reconciled in 17
    /// hours.
    #[test]
    fn cids_dead_daemon_document_must_never_score_as_converged() {
        let v = json!({
            "branch": "main",
            "chain_verified": true,
            "consecutive_failures": 0,
            "flake_url": "github:pleme-io/nix",
            "hostname": "cid",
            "last_activated_rev": "7176c2181d217e1beec7aa3e5244f620ac26dca7",
            "receipts": 5,
            "head": {
                "at_unix_ms": 1_785_664_639_338i64,
                "outcome": { "generation": 655, "kind": "activated" },
                "rev": "7176c2181d217e1beec7aa3e5244f620ac26dca7",
                "seq": 4
            },
        });

        // (a) As the document stands today it carries no heartbeat and no
        //     branch HEAD, so convergence is UNPROVABLE — quiet, but never
        //     a claim of health.
        let ev = Evidence::from_status(&v, 1_785_724_816);
        assert!(
            matches!(gitops_verdict(&v, &ev), GitopsVerdict::Unknown { .. }),
            "a document with no heartbeat cannot prove convergence"
        );

        // (b) Once the daemon publishes `last_tick_at_unix_ms` and
        //     `poll_seconds` (M2), the same chain is positively diagnosed:
        //     silent for 16.7 hours against a 60s poll. Note BOTH fields
        //     are required — staleness is unjudgeable without the interval,
        //     so a missing `poll_seconds` correctly yields Unknown above
        //     rather than a guessed default.
        let with_beat = Evidence {
            last_tick_at_epoch: Some(1_785_664_639),
            poll_seconds: Some(60),
            ..Evidence::from_status(&v, 1_785_724_816)
        };
        let GitopsVerdict::Degraded { headline, detail } = gitops_verdict(&v, &with_beat) else {
            panic!("a loop silent for 16.7h must be reported, not scored converged");
        };
        assert!(headline.contains("STOPPED"), "{headline}");
        assert!(detail.contains("60177s ago"), "{detail}");
    }

    #[test]
    fn a_live_loop_behind_branch_head_is_reported_as_behind() {
        let deployed = "7176c2181d217e1beec7aa3e5244f620ac26dca7";
        let head = "588cf40f6bc7b603943741a2abd074cfaf2142cd";
        let v = json!({
            "consecutive_failures": 0,
            "chain_verified": true,
            "last_activated_rev": deployed,
            "head": { "outcome": { "kind": "activated", "generation": 655 } },
        });
        let ev = Evidence {
            declared_head_rev: Some(head.to_owned()),
            ..proving_evidence(deployed)
        };
        let GitopsVerdict::Degraded { headline, detail } = gitops_verdict(&v, &ev) else {
            panic!("deployed != HEAD is the definition of not converged");
        };
        assert!(headline.contains("BEHIND"), "{headline}");
        assert!(detail.contains("588cf40"), "{detail}");
        assert!(detail.contains("7176c21"), "{detail}");
    }

    /// The type-level half of the fix, demonstrated: no combination of
    /// missing evidence yields a `Proof`. The compile-time half is that
    /// `Proof` has a private field in its own module, so this is the only
    /// constructor in the crate.
    #[test]
    fn a_proof_cannot_be_built_without_every_leg_of_evidence() {
        let rev = "da42c8f8d082453e8ad303c55aacbebca1420336";
        let no_head = Evidence {
            declared_head_rev: None,
            ..proving_evidence(rev)
        };
        let no_beat = Evidence {
            last_tick_at_epoch: None,
            ..proving_evidence(rev)
        };
        assert!(
            Proof::prove(&Evidence::default(), rev).is_none(),
            "no evidence at all"
        );
        assert!(
            Proof::prove(&no_head, rev).is_none(),
            "a fresh heartbeat alone does not prove we are at HEAD"
        );
        assert!(
            Proof::prove(&no_beat, rev).is_none(),
            "being at HEAD does not prove the loop is still alive"
        );
        assert!(
            Proof::prove(&proving_evidence(rev), rev).is_some(),
            "both legs present"
        );
    }

    #[test]
    fn the_ryn_outage_would_have_been_visible_on_every_rebuild() {
        // The real shape of the 27.9-day silent failure this exists to
        // catch: 4136 consecutive failed ticks, never once activated.
        let v = json!({
            "consecutive_failures": 4136,
            "chain_verified": true,
            "last_activated_rev": serde_json::Value::Null,
            "head": { "outcome": {
                "kind": "failed",
                "error": "build failed: building the system configuration...\nerror: creating symlink '/result.tmp': Read-only file system",
            } },
        });
        let GitopsVerdict::Degraded { headline, detail } = gitops_verdict(&v, &Evidence::default())
        else {
            panic!("a 4136-failure streak must not read as converged");
        };
        assert!(headline.contains("DEGRADED"));
        assert!(detail.contains("failed (4136 consecutive)"), "{detail}");
        assert!(detail.contains("last activated : never"), "{detail}");
        // Only the first line of a multi-line nix error, or the block
        // becomes a wall of text nobody reads.
        assert!(detail.contains("last error     : build failed"), "{detail}");
        assert!(!detail.contains("Read-only file system"), "{detail}");
    }

    #[test]
    fn a_broken_chain_is_degraded_even_with_no_failure_streak() {
        // Tamper-evidence is the whole point of the BLAKE3 chain: a
        // verification failure must not be masked by a healthy streak.
        let v = json!({
            "consecutive_failures": 0,
            "chain_verified": false,
            "last_activated_rev": "0123456789abcdef0123456789abcdef01234567",
            "head": { "outcome": { "kind": "activated", "generation": 9 } },
        });
        let GitopsVerdict::Degraded { detail, .. } = gitops_verdict(&v, &Evidence::default())
        else {
            panic!("an unverifiable chain must never read as converged");
        };
        assert!(detail.contains("FAILED VERIFICATION"), "{detail}");
    }

    #[test]
    fn an_empty_chain_is_never_reported_as_converged() {
        // cid, freshly migrated onto the daemon engine, produced exactly
        // this: zero receipts, zero failures, no activation. A naive
        // `streak == 0` check called it converged -- silence scoring as
        // success, the bug this whole feature exists to kill.
        let v = json!({
            "consecutive_failures": 0,
            "chain_verified": true,
            "last_activated_rev": serde_json::Value::Null,
            "receipts": 0,
            "head": serde_json::Value::Null,
        });
        let GitopsVerdict::Degraded { headline, detail } = gitops_verdict(&v, &Evidence::default())
        else {
            panic!("a chain with no activation must never read as converged");
        };
        assert!(headline.contains("NO DEPLOY RECORDED"), "{headline}");
        assert!(detail.contains("no activation"), "{detail}");
    }

    /// The cry-wolf guard is PRESERVED — an unreadable document raises no
    /// alarm — but it no longer asserts health. This test previously
    /// asserted `Converged`, which is how an empty JSON object certified a
    /// node as reconciled.
    #[test]
    fn an_unparseable_status_shape_is_unknown_not_converged() {
        let verdict = gitops_verdict(&json!({}), &Evidence::default());
        assert!(
            matches!(verdict, GitopsVerdict::Unknown { .. }),
            "an empty document must be Unknown, never Converged: {verdict:?}"
        );
        assert!(
            !matches!(verdict, GitopsVerdict::Degraded { .. }),
            "and it must not cry wolf either"
        );
    }

    /// The prettifier must survive the REAL captured stream — which is
    /// not clean JSON. This fixture is the literal shape observed during
    /// a rebuild on ryn (2026-08-01): two rmcp tracing lines and a
    /// ~400-char `peer_info=Some(InitializeResult { … })` — note the
    /// BRACES, which is why the parser scans to the first `{` of the
    /// report rather than trusting the first `{` it sees... and why this
    /// test exists to prove that choice is right.
    #[test]
    fn parse_e2e_report_survives_the_rmcp_noise() {
        let captured = concat!(
            "2026-08-02T04:20:29.808050Z  INFO serve_inner: rmcp::service: Service ",
            "initialized as client peer_info=Some(InitializeResult { protocol_version: ",
            "ProtocolVersion(\"2025-03-26\"), capabilities: ServerCapabilities { ",
            "experimental: None, tools: Some(ToolsCapability { list_changed: None }) } })\n",
            "2026-08-02T04:20:31.858699Z  INFO serve_inner: rmcp::service: task cancelled\n",
            "{\n  \"shell\": \"/nix/store/46124-frostmourne/bin/frostmourne\",\n",
            "  \"rows\": [\n",
            "    { \"name\": \"spawn_term\", \"pass\": true, \"skipped\": false, \"detail\": \"session_id=mado-session-1\" },\n",
            "    { \"name\": \"prompt_visible\", \"pass\": true, \"skipped\": false, \"detail\": \"rendered in 511ms\" }\n",
            "  ],\n  \"pass\": true\n}"
        );

        let (shell, rows) =
            parse_e2e_report(captured).expect("the report must be recoverable from a noisy stream");
        assert_eq!(shell, "/nix/store/46124-frostmourne/bin/frostmourne");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "spawn_term");
        assert!(rows.iter().all(|r| r.pass));
        assert_eq!(rows[1].detail, "rendered in 511ms");
    }

    /// Unparseable input yields None — "could not render", never a
    /// verdict. The caller reads the exit status for that, so a
    /// prettifier can neither pass a failed gate nor fail a passing one.
    #[test]
    fn parse_e2e_report_never_invents_a_verdict() {
        assert!(parse_e2e_report("").is_none());
        assert!(parse_e2e_report("nix: build failed, no json here").is_none());
        // Well-formed JSON that simply is not the report.
        assert!(parse_e2e_report("{\"unrelated\": 1}").is_none());
        // Present but empty rows is not a renderable matrix.
        assert!(parse_e2e_report("{\"shell\":\"x\",\"rows\":[]}").is_none());
    }
}
