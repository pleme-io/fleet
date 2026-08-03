use anyhow::{Context, Result};
use colored::Colorize;
use fs4::fs_std::FileExt;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    acquire_lock_at(&std::env::temp_dir().join("fleet-rebuild.lock"))
}

/// `acquire_rebuild_lock`'s path-parameterized core — split out so tests
/// can exercise real flock contention against a throwaway path instead of
/// the shared `/tmp/fleet-rebuild.lock` every real invocation uses.
fn acquire_lock_at(lock_path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(lock_path)
        .with_context(|| format!("failed to open rebuild lock file at {}", lock_path.display()))?;
    if FileExt::try_lock_exclusive(&file).is_err() {
        log_info("Another rebuild is already in progress — waiting for it to finish...");
        FileExt::lock_exclusive(&file).context("failed to acquire rebuild lock")?;
    }
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
    run_command_output(Command::new("hostname").arg("-s"))
        .context("Failed to get hostname")
}

/// Check whether a command exists in PATH.
fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_or(false, |s| s.success())
}

/// On first run, Nix needs GitHub auth to fetch private flake inputs.
/// If `~/.config/nix/netrc` doesn't exist but the SOPS age key does,
/// decrypt the GitHub token from secrets.yaml and write temporary auth
/// files so the first `nix build` can succeed. After activation,
/// sops-nix takes over managing these files.
fn bootstrap_nix_auth(flake_root: &Path) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_default();
    let netrc_path = PathBuf::from(&home).join(".config/nix/netrc");
    let access_tokens_path = PathBuf::from(&home).join(".config/nix/access-tokens.conf");
    let age_key_path = PathBuf::from(&home).join(".config/sops/age/keys.txt");

    // Already have auth files — nothing to do
    if netrc_path.exists() && access_tokens_path.exists() {
        return Ok(());
    }

    // Need the age key to decrypt secrets
    if !age_key_path.exists() {
        log_warning("No SOPS age key — cannot bootstrap GitHub auth (private flake inputs may fail)");
        return Ok(());
    }

    let secrets_yaml = flake_root.join("secrets.yaml");
    if !secrets_yaml.exists() {
        return Ok(());
    }

    // Resolve sops CLI — use from PATH or build from nixpkgs
    let sops_cmd = if command_exists("sops") {
        "sops".to_string()
    } else {
        log_info("sops not in PATH — building from nixpkgs...");
        let out = run_command_output(
            Command::new("nix")
                .args([
                    "--extra-experimental-features",
                    "nix-command flakes",
                    "build",
                    "--print-out-paths",
                    "--no-link",
                    "nixpkgs#sops",
                ]),
        )
        .context("Failed to build sops from nixpkgs")?;
        format!("{out}/bin/sops")
    };

    // Decrypt just the GitHub token
    let token_output = Command::new(&sops_cmd)
        .args(["--decrypt", "--extract", "[\"github\"][\"ghcr-token\"]"])
        .arg(&secrets_yaml)
        .env("SOPS_AGE_KEY_FILE", &age_key_path)
        .output()
        .context("Failed to run sops")?;

    if !token_output.status.success() {
        let stderr = String::from_utf8_lossy(&token_output.stderr);
        log_warning(&format!("Could not decrypt GitHub token: {}", stderr.trim()));
        return Ok(());
    }

    let token = String::from_utf8(token_output.stdout)
        .context("GitHub token is not valid UTF-8")?
        .trim()
        .to_string();

    if token.is_empty() {
        log_warning("Decrypted GitHub token is empty — skipping auth bootstrap");
        return Ok(());
    }

    // Write temporary auth files
    let nix_config_dir = PathBuf::from(&home).join(".config/nix");
    fs::create_dir_all(&nix_config_dir)?;

    if !access_tokens_path.exists() {
        fs::write(
            &access_tokens_path,
            format!("access-tokens = github.com={token}\n"),
        )?;
        fs::set_permissions(&access_tokens_path, fs::Permissions::from_mode(0o600))?;
        log_success("Bootstrapped ~/.config/nix/access-tokens.conf");
    }

    if !netrc_path.exists() {
        fs::write(
            &netrc_path,
            format!(
                "machine api.github.com\nlogin x-access-token\npassword {token}\n\n\
                 machine github.com\nlogin x-access-token\npassword {token}\n"
            ),
        )?;
        fs::set_permissions(&netrc_path, fs::Permissions::from_mode(0o600))?;
        log_success("Bootstrapped ~/.config/nix/netrc");
    }

    Ok(())
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
        additions.push_str("\n# Bootstrap: disable sandbox for macOS .app builds\nsandbox = false\n");
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
        .args(["launchctl", "kickstart", "-k", "system/org.nixos.nix-daemon"])
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
    detail.push_str(&format!("    head receipt   : {kind} ({streak} consecutive)\n"));
    detail.push_str(&format!("    last activated : {last_activated}\n"));
    if !verified {
        detail.push_str("    chain          : FAILED VERIFICATION (truncated or reordered)\n");
    }
    if let Some(err) = v["head"]["outcome"]["error"].as_str() {
        // First line only; the full text stays in the chain.
        let head_line = err.lines().next().unwrap_or(err);
        detail.push_str(&format!("    last error     : {head_line}\n"));
    }
    detail.push_str(&format!("    detail         : sentinela --config {GITOPS_CONFIG} status\n"));

    GitopsVerdict::Degraded {
        headline: "gitops: DEGRADED — the node is not tracking the branch".to_owned(),
        detail,
    }
}

/// Short-form a 40-char rev for display, leaving anything else untouched.
fn short_rev(rev: &str) -> String {
    rev.get(..7).unwrap_or(rev).to_owned()
}

pub fn rebuild(show_trace: bool, nix_options: &[String]) -> Result<()> {
    // Held for the whole call (released on any return path, including
    // early `?` exits and panics, via Drop) — see acquire_rebuild_lock's
    // doc comment for the concrete failure this prevents.
    let _rebuild_lock = acquire_rebuild_lock()?;

    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let flake_root = find_flake_root(&cwd)?;
    let hostname = get_hostname()?;

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
            log_warning(&format!("Nix daemon config bootstrap: {e} — continuing anyway"));
        }
        // Accept Xcode license — xcodebuild refuses to run for any user
        // (including nix build users) until the license is accepted.
        accept_xcode_license();
    }

    // Bootstrap: decrypt GitHub token from SOPS so Nix can fetch private inputs.
    // Only runs when auth files are missing (first run). After activation,
    // sops-nix manages these files permanently.
    if let Err(e) = bootstrap_nix_auth(&flake_root) {
        log_warning(&format!("Auth bootstrap: {e} — continuing anyway"));
    }

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
        "macos" => darwin_rebuild(&flake_root, &hostname, show_trace, nix_options),
        "linux" => nixos_rebuild(&flake_root, &hostname, show_trace, nix_options),
        os => anyhow::bail!("Unsupported OS: {}", os),
    }
}

fn darwin_rebuild(
    flake_root: &Path,
    hostname: &str,
    show_trace: bool,
    nix_options: &[String],
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

    // Read access-tokens from bootstrapped config so nix can fetch private inputs.
    let access_tokens_path = PathBuf::from(&real_home).join(".config/nix/access-tokens.conf");
    let access_tokens = if access_tokens_path.exists() {
        fs::read_to_string(&access_tokens_path)
            .ok()
            .and_then(|content| {
                content
                    .trim()
                    .strip_prefix("access-tokens = ")
                    .map(|v| v.to_string())
            })
    } else {
        None
    };

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
        if let Some(ref tokens) = access_tokens {
            build_cmd.arg("--option").arg("access-tokens").arg(tokens);
        }

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
        cmd.arg("--preserve-env=HOME,USER,NIX_SSL_CERT_FILE,GIT_SSL_CAINFO")
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
                anyhow::bail!(
                    "e2e gate FAILED — the candidate closure's mado/frostmourne smoke \
                     matrix did not pass; refusing to switch. Inspect with \
                     `nix run .#e2e-mado`; break-glass override: \
                     FLEET_SKIP_E2E_GATE=1 (document why)."
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
    cmd.arg("--preserve-env=HOME,USER,NIX_SSL_CERT_FILE,GIT_SSL_CAINFO")
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

    // Forward --option key value pairs to darwin-rebuild
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
) -> Result<()> {
    log_info(&format!("NixOS rebuild for {}...", hostname));

    let mut cmd = Command::new("sudo");
    cmd.arg("nixos-rebuild")
        .arg("switch")
        .arg("--flake")
        .arg(format!(".#{}", hostname))
        .current_dir(flake_root)
        .env("NIX_CONFIG", "experimental-features = nix-command flakes");

    if show_trace {
        cmd.arg("--show-trace");
    }

    // Forward --option key value pairs to nixos-rebuild
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
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn fresh_lock_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("fleet-rebuild-test-{name}-{}.lock", std::process::id()))
    }

    #[test]
    fn second_acquire_blocks_until_first_is_dropped() {
        // The exact scenario that caused the live sops-nix race: two
        // `fleet rebuild` invocations overlapping. This proves the second
        // one now WAITS instead of proceeding concurrently.
        let path = fresh_lock_path("blocks");
        let first = acquire_lock_at(&path).expect("first acquire");

        let (tx, rx) = mpsc::channel();
        let path_clone = path.clone();
        let handle = thread::spawn(move || {
            tx.send(()).unwrap(); // signal "about to block on acquire"
            acquire_lock_at(&path_clone).expect("second acquire");
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

    #[test]
    fn lock_is_reentrant_across_sequential_acquisitions() {
        // Not concurrent — just confirms a dropped lock genuinely
        // releases, so back-to-back rebuilds (the common case) never
        // deadlock against their own prior run.
        let path = fresh_lock_path("sequential");
        let first = acquire_lock_at(&path).expect("first acquire");
        drop(first);
        let second = acquire_lock_at(&path).expect("second acquire after drop");
        drop(second);

        let _ = fs::remove_file(&path);
    }
}

#[cfg(test)]
mod gitops_verdict_tests {
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

        let (shell, rows) = parse_e2e_report(captured)
            .expect("the report must be recoverable from a noisy stream");
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
