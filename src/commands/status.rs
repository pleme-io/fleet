use anyhow::Result;

use crate::config::FleetConfig;
use crate::targeting::ResolvedTargets;
use super::utils::*;

pub fn run(targets: &ResolvedTargets, config: &FleetConfig) -> Result<()> {
    log_info("Gathering node status...\n");

    for (name, node) in &targets.nodes {
        let label = node_label(name);
        let ssh = config.resolve_ssh(name);

        let generation = ssh_run_with_config(
            &node.ssh_user,
            &node.hostname,
            &ssh,
            "readlink /run/current-system | grep -oP 'system-\\K[0-9]+'",
        )
        .unwrap_or_else(|_| "?".to_string());

        let uptime = ssh_run_with_config(&node.ssh_user, &node.hostname, &ssh, "uptime -p")
            .unwrap_or_else(|_| "?".to_string());

        let kernel = ssh_run_with_config(&node.ssh_user, &node.hostname, &ssh, "uname -r")
            .unwrap_or_else(|_| "?".to_string());

        let nixos_version = ssh_run_with_config(
            &node.ssh_user,
            &node.hostname,
            &ssh,
            "cat /run/current-system/nixos-version 2>/dev/null || echo unknown",
        )
        .unwrap_or_else(|_| "?".to_string());

        println!("{} gen={} kernel={} nixos={} {}", label, generation, kernel, nixos_version, uptime);
    }

    Ok(())
}
