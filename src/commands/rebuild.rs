use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::utils::{log_info, log_success, run_command, run_command_output};

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

pub fn rebuild(show_trace: bool) -> Result<()> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let flake_root = find_flake_root(&cwd)?;
    let hostname = get_hostname()?;

    log_info(&format!(
        "Rebuilding {} (flake at {})",
        hostname,
        flake_root.display()
    ));

    match std::env::consts::OS {
        "macos" => darwin_rebuild(&flake_root, &hostname, show_trace),
        "linux" => nixos_rebuild(&flake_root, &hostname, show_trace),
        os => anyhow::bail!("Unsupported OS: {}", os),
    }
}

fn darwin_rebuild(flake_root: &Path, hostname: &str, show_trace: bool) -> Result<()> {
    log_info(&format!("Darwin rebuild for {}...", hostname));

    let mut cmd = Command::new("darwin-rebuild");
    cmd.arg("switch")
        .arg("--flake")
        .arg(format!(".#{}", hostname))
        .current_dir(flake_root);

    if show_trace {
        cmd.arg("--show-trace");
    }

    run_command(&mut cmd)?;
    log_success(&format!("{} rebuilt successfully", hostname));
    Ok(())
}

fn nixos_rebuild(flake_root: &Path, hostname: &str, show_trace: bool) -> Result<()> {
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

    run_command(&mut cmd)?;
    log_success(&format!("{} rebuilt successfully", hostname));
    Ok(())
}
