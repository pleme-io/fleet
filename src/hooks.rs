use anyhow::{bail, Result};
use std::process::Command;

use crate::commands::utils::{log_info, log_warning};
use crate::config::FleetConfig;
use crate::registry::Node;

/// Run the pre-hook for a command, if configured. Aborts on failure.
pub fn run_pre(
    config: &FleetConfig,
    command_name: &str,
    node_name: &str,
    node: &Node,
) -> Result<()> {
    if let Some(hook) = config.hooks.get(command_name) {
        if let Some(ref script) = hook.pre {
            log_info(&format!(
                "Running pre-{} hook for {}",
                command_name, node_name
            ));
            let status = Command::new("sh")
                .arg("-c")
                .arg(script)
                .env("FLEET_NODE", node_name)
                .env("FLEET_HOST", &node.hostname)
                .env("FLEET_USER", &node.ssh_user)
                .status()?;
            if !status.success() {
                bail!(
                    "Pre-{} hook failed for {} (exit {})",
                    command_name,
                    node_name,
                    status.code().unwrap_or(-1)
                );
            }
        }
    }
    Ok(())
}

/// Run the post-hook for a command, if configured. Warns on failure but does not abort.
pub fn run_post(
    config: &FleetConfig,
    command_name: &str,
    node_name: &str,
    node: &Node,
) {
    if let Some(hook) = config.hooks.get(command_name) {
        if let Some(ref script) = hook.post {
            log_info(&format!(
                "Running post-{} hook for {}",
                command_name, node_name
            ));
            match Command::new("sh")
                .arg("-c")
                .arg(script)
                .env("FLEET_NODE", node_name)
                .env("FLEET_HOST", &node.hostname)
                .env("FLEET_USER", &node.ssh_user)
                .status()
            {
                Ok(status) if !status.success() => {
                    log_warning(&format!(
                        "Post-{} hook failed for {} (exit {})",
                        command_name,
                        node_name,
                        status.code().unwrap_or(-1)
                    ));
                }
                Err(e) => {
                    log_warning(&format!(
                        "Post-{} hook error for {}: {}",
                        command_name, node_name, e
                    ));
                }
                _ => {}
            }
        }
    }
}
