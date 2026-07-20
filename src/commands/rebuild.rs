use anyhow::{Context, Result};
use fs4::fs_std::FileExt;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::utils::{log_info, log_success, log_warning, run_command, run_command_output};

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
            log_info("Running e2e gate against the candidate closure (.#e2e-mado)...");
            let status = Command::new("nix")
                .args(["run", ".#e2e-mado"])
                .current_dir(flake_root)
                .status()
                .context("Failed to launch the e2e gate")?;
            if !status.success() {
                anyhow::bail!(
                    "e2e gate FAILED — the candidate closure's mado/frostmourne smoke matrix                      did not pass; refusing to switch. Inspect with `nix run .#e2e-mado`;                      break-glass override: FLEET_SKIP_E2E_GATE=1 (document why)."
                );
            }
            log_success("e2e gate passed — candidate closure verified interactive");
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

    run_command(&mut cmd)?;
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

    run_command(&mut cmd)?;
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
