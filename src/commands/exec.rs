use anyhow::Result;

use crate::config::FleetConfig;
use crate::targeting::ResolvedTargets;
use super::utils::*;

pub fn run(targets: &ResolvedTargets, cmd: &[String], config: &FleetConfig) -> Result<()> {
    let remote_cmd = cmd.join(" ");
    log_info(&format!("Executing: {}", remote_cmd));

    let mut had_error = false;

    for (name, node) in &targets.nodes {
        let ssh = config.resolve_ssh(name);
        match ssh_run_with_config(&node.ssh_user, &node.hostname, &ssh, &remote_cmd) {
            Ok(output) => {
                for line in output.lines() {
                    println!("{} {}", node_label(name), line);
                }
            }
            Err(e) => {
                log_error(&format!("{} {}", node_label(name), e));
                had_error = true;
            }
        }
    }

    if had_error {
        anyhow::bail!("Some nodes failed");
    }

    Ok(())
}
