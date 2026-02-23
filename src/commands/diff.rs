use anyhow::Result;
use std::process::Command;

use crate::config::FleetConfig;
use crate::targeting::ResolvedTargets;
use super::utils::*;

pub fn run(targets: &ResolvedTargets, config: &FleetConfig) -> Result<()> {
    let flake = flake_dir();

    for (name, node) in &targets.nodes {
        log_info(&format!("Computing diff for {}", name));

        // Build the new closure locally
        let drv = format!(
            "{flake}#nixosConfigurations.{name}.config.system.build.toplevel"
        );
        let new_path = run_command_output(
            Command::new("nix").arg("build").arg(&drv).arg("--print-out-paths").arg("--no-link"),
        )?;

        // Get current system path from remote
        let ssh = config.resolve_ssh(name);
        let current_path = match ssh_run_with_config(
            &node.ssh_user,
            &node.hostname,
            &ssh,
            "readlink /run/current-system",
        ) {
            Ok(path) => path,
            Err(e) => {
                log_warning(&format!("{} Failed to read current system: {}", node_label(name), e));
                continue;
            }
        };

        // Show diff
        println!("{}", node_label(name));
        let mut cmd = Command::new("nix");
        cmd.arg("store")
            .arg("diff-closures")
            .arg(current_path.trim())
            .arg(new_path.trim());
        if let Err(e) = run_command(&mut cmd) {
            log_warning(&format!("{} diff failed: {}", node_label(name), e));
        }
        println!();
    }

    Ok(())
}
