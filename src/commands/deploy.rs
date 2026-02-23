use anyhow::Result;
use std::process::Command;

use crate::targeting::ResolvedTargets;
use super::utils::*;

pub fn run(targets: &ResolvedTargets, dry_run: bool, show_trace: bool) -> Result<()> {
    let flake = flake_dir();

    if targets.is_single() {
        let (name, _node) = &targets.nodes[0];
        deploy_single(&flake, name, dry_run, show_trace)
    } else {
        deploy_fleet(&flake, targets, dry_run, show_trace)
    }
}

fn deploy_single(flake: &str, name: &str, dry_run: bool, show_trace: bool) -> Result<()> {
    if dry_run {
        log_info(&format!("Dry-run deploy to {} (deploy-rs)", name));
    } else {
        log_info(&format!("Deploying to {} (deploy-rs, magic rollback)", name));
    }

    let mut cmd = Command::new("deploy");
    if dry_run {
        cmd.arg("--dry-activate");
    }
    cmd.arg(format!("{flake}#{name}"));
    if show_trace {
        cmd.arg("--show-trace");
    }

    run_command(&mut cmd)?;

    if dry_run {
        log_success(&format!("{} dry-run complete", name));
    } else {
        log_success(&format!("{} deployed successfully", name));
    }
    Ok(())
}

fn deploy_fleet(flake: &str, targets: &ResolvedTargets, dry_run: bool, show_trace: bool) -> Result<()> {
    let names = targets.names();
    let on = names.join(",");

    if dry_run {
        log_info(&format!("Dry-run fleet build: {} (colmena)", on));
        let mut cmd = Command::new("colmena");
        cmd.arg("build");
        cmd.arg("--on").arg(&on);
        if show_trace {
            cmd.arg("--show-trace");
        }
        cmd.current_dir(flake);
        run_command(&mut cmd)?;
        log_success("Fleet dry-run build complete");
    } else {
        log_info(&format!("Fleet deploy: {} (colmena apply)", on));
        let mut cmd = Command::new("colmena");
        cmd.arg("apply");
        cmd.arg("--on").arg(&on);
        if show_trace {
            cmd.arg("--show-trace");
        }
        cmd.current_dir(flake);
        run_command(&mut cmd)?;
        log_success("Fleet deploy complete");
    }

    Ok(())
}
