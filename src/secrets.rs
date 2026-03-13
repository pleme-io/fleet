use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use crate::commands::utils::{log_info, log_success, log_warning};
use crate::config::{FleetConfig, SecretDef};

/// Expand ~ to $HOME in a path string (public for use in list display).
pub fn expand_home_pub(path: &str) -> PathBuf {
    expand_home(path)
}

/// Expand ~ to $HOME in a path string.
fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

/// Parse an octal mode string (e.g. "0600") to a u32.
fn parse_mode(mode: &str) -> Result<u32> {
    u32::from_str_radix(mode.trim_start_matches('0'), 8)
        .with_context(|| format!("Invalid file mode: {}", mode))
}

/// Provision a single secret from its provider.
/// `op_cmd` is the resolved path to the 1Password CLI (may be a nix store path).
fn provision_secret(name: &str, secret: &SecretDef, op_cmd: Option<&str>) -> Result<()> {
    let target = expand_home(&secret.path);

    match secret.provider.as_str() {
        "onepassword" => {
            let op = op_cmd.context(
                "1Password CLI (op) is required but could not be found or built",
            )?;

            log_info(&format!(
                "Provisioning secret '{}' from 1Password...",
                name
            ));

            let output = Command::new(op)
                .arg("read")
                .arg(&secret.item)
                .output()
                .context("Failed to run 'op' CLI — is 1Password CLI installed and signed in?")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                bail!(
                    "1Password read failed for '{}': {}",
                    secret.item,
                    stderr.trim()
                );
            }

            // Ensure parent directory exists
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
            }

            // Write the secret
            fs::write(&target, &output.stdout)
                .with_context(|| format!("Failed to write secret to {}", target.display()))?;

            // Set permissions
            let mode = parse_mode(&secret.mode)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))
                .with_context(|| format!("Failed to set permissions on {}", target.display()))?;

            log_success(&format!(
                "Secret '{}' provisioned -> {}",
                name,
                target.display()
            ));
        }
        other => {
            bail!(
                "Unknown secret provider '{}' for secret '{}' (supported: onepassword)",
                other,
                name
            );
        }
    }

    Ok(())
}

/// Provision all secrets that are configured to run before the given command,
/// but only if their target file does not already exist.
pub fn provision_for_command(config: &FleetConfig, command_name: &str) -> Result<()> {
    // Resolve `op` once (may build from nixpkgs on first run).
    let mut op_cmd: Option<String> = None;
    let mut op_resolved = false;

    for (name, secret) in &config.secrets {
        if secret
            .provision_before
            .iter()
            .any(|cmd| cmd == command_name)
        {
            let target = expand_home(&secret.path);
            if target.exists() {
                continue;
            }

            // Lazily resolve the op CLI (only when we actually need it)
            if secret.provider == "onepassword" && !op_resolved {
                op_cmd = resolve_op_cmd();
                op_resolved = true;

                if op_cmd.is_none() {
                    log_warning("1Password CLI unavailable and could not be built — secrets will be skipped");
                }
            }

            if secret.provider == "onepassword" && op_cmd.is_none() {
                log_warning(&format!(
                    "Secret '{}' needs 1Password CLI — skipping",
                    name
                ));
                continue;
            }

            provision_secret(name, secret, op_cmd.as_deref())?;
        }
    }
    Ok(())
}

/// Remove the local file for a named secret.
pub fn clean_secret(config: &FleetConfig, name: &str) -> Result<()> {
    match config.secrets.get(name) {
        Some(secret) => {
            let target = expand_home(&secret.path);
            if target.exists() {
                fs::remove_file(&target)
                    .with_context(|| format!("Failed to remove {}", target.display()))?;
                log_success(&format!("Secret '{}' removed: {}", name, target.display()));
            } else {
                log_info(&format!("Secret '{}' not present at {}", name, target.display()));
            }
            Ok(())
        }
        None => bail!("No secret named '{}' in fleet.yaml", name),
    }
}

/// Provision a specific named secret (unconditionally, even if file exists).
pub fn sync_secret(config: &FleetConfig, name: &str) -> Result<()> {
    match config.secrets.get(name) {
        Some(secret) => {
            let op_cmd = if secret.provider == "onepassword" {
                resolve_op_cmd()
            } else {
                None
            };
            provision_secret(name, secret, op_cmd.as_deref())
        }
        None => bail!("No secret named '{}' in fleet.yaml", name),
    }
}

/// Provision all configured secrets (unconditionally).
pub fn sync_all(config: &FleetConfig) -> Result<()> {
    let op_cmd = resolve_op_cmd();
    for (name, secret) in &config.secrets {
        provision_secret(name, secret, op_cmd.as_deref())?;
    }
    Ok(())
}

fn which_op() -> Option<()> {
    Command::new("op")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()
        .filter(|s| s.success())
        .map(|_| ())
}

/// Resolve the `op` command — returns "op" if already in PATH, otherwise
/// builds it from nixpkgs on the fly and returns the store path binary.
/// This handles first-run bootstrap on nodes where `op` isn't installed yet.
fn resolve_op_cmd() -> Option<String> {
    if which_op().is_some() {
        return Some("op".to_string());
    }

    log_warning("1Password CLI (op) not in PATH — installing via nix...");

    let output = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            "--print-out-paths",
            "--no-link",
            "nixpkgs#_1password-cli",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let store_path = String::from_utf8(output.stdout).ok()?.trim().to_string();
    let op_bin = format!("{store_path}/bin/op");

    if std::path::Path::new(&op_bin).exists() {
        log_success("1Password CLI built successfully");
        Some(op_bin)
    } else {
        None
    }
}
