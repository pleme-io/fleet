use anyhow::{bail, Result};
use std::os::unix::process::CommandExt;

use crate::config::FleetConfig;
use crate::targeting::ResolvedTargets;
use super::utils::*;

pub fn run(targets: &ResolvedTargets, config: &FleetConfig) -> Result<()> {
    if !targets.is_single() {
        bail!("ssh requires exactly one target node");
    }

    let (name, node) = &targets.nodes[0];
    log_info(&format!("Connecting to {} ({})", name, node.hostname));

    let ssh = config.resolve_ssh(name);
    let err = ssh_cmd_with_config(&node.ssh_user, &node.hostname, &ssh).exec();

    // exec() only returns on error
    bail!("Failed to exec ssh: {}", err)
}
