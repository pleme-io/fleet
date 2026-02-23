use anyhow::Result;
use std::process::Command;

use crate::targeting::ResolvedTargets;
use super::utils::*;

pub fn run(targets: &ResolvedTargets, show_trace: bool) -> Result<()> {
    let flake = flake_dir();

    if targets.is_single() {
        let (name, _node) = &targets.nodes[0];
        log_info(&format!("Building {} (nix build)", name));

        let mut cmd = Command::new("nix");
        cmd.arg("build");
        cmd.arg(format!(
            "{flake}#nixosConfigurations.{name}.config.system.build.toplevel"
        ));
        if show_trace {
            cmd.arg("--show-trace");
        }
        run_command(&mut cmd)?;
        log_success(&format!("{} built successfully", name));
    } else {
        let names = targets.names();
        let on = names.join(",");
        log_info(&format!("Fleet build: {} (colmena build)", on));

        let mut cmd = Command::new("colmena");
        cmd.arg("build");
        cmd.arg("--on").arg(&on);
        if show_trace {
            cmd.arg("--show-trace");
        }
        cmd.current_dir(&flake);
        run_command(&mut cmd)?;
        log_success("Fleet build complete");
    }

    Ok(())
}
