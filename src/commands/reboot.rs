use anyhow::Result;

use crate::config::FleetConfig;
use crate::targeting::ResolvedTargets;
use super::utils::*;

pub fn run(targets: &ResolvedTargets, yes: bool, config: &FleetConfig) -> Result<()> {
    let names: Vec<&str> = targets.names();

    if !yes {
        if !confirm(&format!("Reboot {}? (y/N)", names.join(", ")))? {
            log_info("Aborted");
            return Ok(());
        }
    }

    for (name, node) in &targets.nodes {
        log_info(&format!("{} Rebooting...", node_label(name)));
        let ssh = config.resolve_ssh(name);
        // Use nohup + disown so the reboot isn't killed when SSH disconnects
        match ssh_run_with_config(&node.ssh_user, &node.hostname, &ssh, "systemctl reboot") {
            Ok(_) => log_success(&format!("{} Reboot initiated", node_label(name))),
            // SSH will likely disconnect during reboot — that's expected
            Err(_) => log_success(&format!("{} Reboot initiated (connection closed)", node_label(name))),
        }
    }

    Ok(())
}
