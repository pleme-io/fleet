use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::utils::{log_info, log_success, log_warning, run_command, run_command_output};

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
    // Also try Determinate Nix daemon
    let _ = Command::new("sudo")
        .args([
            "launchctl",
            "kickstart",
            "-k",
            "system/systems.determinate.nix-daemon",
        ])
        .status();

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
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let flake_root = find_flake_root(&cwd)?;
    let hostname = get_hostname()?;

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
    log_success(&format!("{} rebuilt successfully", hostname));
    Ok(())
}
