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

pub fn rebuild(show_trace: bool, nix_options: &[String]) -> Result<()> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let flake_root = find_flake_root(&cwd)?;
    let hostname = get_hostname()?;

    log_info(&format!(
        "Rebuilding {} (flake at {})",
        hostname,
        flake_root.display()
    ));

    // Bootstrap: decrypt GitHub token from SOPS so Nix can fetch private inputs.
    // Only runs when auth files are missing (first run). After activation,
    // sops-nix manages these files permanently.
    if let Err(e) = bootstrap_nix_auth(&flake_root) {
        log_warning(&format!("Auth bootstrap: {e} — continuing anyway"));
    }

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

    // Bootstrap: on first run, darwin-rebuild isn't installed yet.
    // Build the system configuration and activate it directly.
    if !command_exists("darwin-rebuild") {
        log_warning("darwin-rebuild not in PATH — bootstrapping from flake...");

        let system_path = run_command_output(
            Command::new("nix")
                .args([
                    "--extra-experimental-features",
                    "nix-command flakes",
                    "build",
                    "--print-out-paths",
                    "--no-link",
                ])
                .arg(format!(".#darwinConfigurations.{hostname}.system"))
                .current_dir(flake_root),
        )
        .context("Failed to build darwin system configuration")?;

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
