use anyhow::{Context, Result};
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

pub fn rebuild(show_trace: bool, nix_options: &[String]) -> Result<()> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let flake_root = find_flake_root(&cwd)?;
    let hostname = get_hostname()?;

    log_info(&format!(
        "Rebuilding {} (flake at {})",
        hostname,
        flake_root.display()
    ));

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
