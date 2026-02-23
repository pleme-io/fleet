use anyhow::Result;
use colored::Colorize;
use std::process::Command;

use crate::config::FleetConfig;
use crate::targeting::ResolvedTargets;
use super::utils::*;

pub fn run(targets: &ResolvedTargets, config: &FleetConfig) -> Result<()> {
    log_info("Checking SSH connectivity...\n");

    let mut reachable = 0;
    let mut unreachable = 0;

    for (name, node) in &targets.nodes {
        let ssh = config.resolve_ssh(name);
        let mut cmd = Command::new("ssh");
        cmd.arg("-o")
            .arg(format!("ConnectTimeout={}", ssh.connect_timeout));
        cmd.arg("-o").arg("BatchMode=yes");
        cmd.arg("-o")
            .arg(format!("StrictHostKeyChecking={}", ssh.strict_host_key));
        for (k, v) in &ssh.options {
            cmd.arg("-o").arg(format!("{}={}", k, v));
        }
        cmd.arg(format!("{}@{}", node.ssh_user, node.hostname));
        cmd.arg("true");

        let status = cmd.output();

        match status {
            Ok(output) if output.status.success() => {
                println!("{} {}", node_label(name), "reachable".green());
                reachable += 1;
            }
            _ => {
                println!("{} {}", node_label(name), "unreachable".red());
                unreachable += 1;
            }
        }
    }

    println!("\n{}/{} nodes reachable", reachable, reachable + unreachable);

    if unreachable > 0 {
        anyhow::bail!("{} node(s) unreachable", unreachable);
    }

    Ok(())
}
