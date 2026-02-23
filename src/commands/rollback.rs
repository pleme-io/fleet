use anyhow::Result;

use crate::config::FleetConfig;
use crate::targeting::ResolvedTargets;
use super::utils::*;

pub fn run(targets: &ResolvedTargets, config: &FleetConfig) -> Result<()> {
    let names: Vec<&str> = targets.names();
    if !confirm(&format!("Rollback {}? (y/N)", names.join(", ")))? {
        log_info("Aborted");
        return Ok(());
    }

    for (name, node) in &targets.nodes {
        log_info(&format!("{} Rolling back...", node_label(name)));
        let ssh = config.resolve_ssh(name);
        match ssh_run_with_config(
            &node.ssh_user,
            &node.hostname,
            &ssh,
            "nixos-rebuild switch --rollback",
        ) {
            Ok(_) => log_success(&format!("{} Rolled back", node_label(name))),
            Err(e) => log_error(&format!("{} Rollback failed: {}", node_label(name), e)),
        }
    }

    Ok(())
}
