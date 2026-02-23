use anyhow::{bail, Result};
use colored::Colorize;
use std::process::Command;

use crate::config::{ActionDef, FleetConfig, StepDef};
use crate::dag;
use crate::flow;
use crate::registry::NodeRegistry;
use crate::targeting;

use super::utils::*;

pub fn list(config: &FleetConfig) -> Result<()> {
    if config.flows.is_empty() {
        println!("No flows defined in fleet.yaml");
        return Ok(());
    }

    println!("{:<24} {}", "FLOW".bold(), "DESCRIPTION".bold());
    println!("{}", "-".repeat(60));

    let mut entries: Vec<_> = config.flows.iter().collect();
    entries.sort_by_key(|(name, _)| (*name).clone());

    for (name, flow_def) in entries {
        println!("{:<24} {}", name, flow_def.description);
    }

    Ok(())
}

pub fn run(
    config: &FleetConfig,
    registry: &NodeRegistry,
    name: &str,
    cli_targets: &[String],
    cli_all: bool,
    dry_run: bool,
) -> Result<()> {
    let flow_def = config
        .flows
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("Unknown flow: '{}'", name))?;

    let validated = flow::validate(flow_def)?;
    let levels = dag::topo_levels(flow_def.steps.len(), &validated.deps);

    // Check all steps were scheduled (if not, there's an undetected cycle)
    let scheduled: usize = levels.iter().map(|l| l.len()).sum();
    if scheduled != flow_def.steps.len() {
        bail!("Flow '{}' has a dependency cycle", name);
    }

    if dry_run {
        print_execution_plan(flow_def, &levels);
        return Ok(());
    }

    log_info(&format!("Running flow: {} — {}", name, flow_def.description));
    println!();

    for (level_idx, level) in levels.iter().enumerate() {
        for &step_idx in level {
            let step = &flow_def.steps[step_idx];

            println!(
                "{} Step {}/{}: {}",
                ">>>".blue().bold(),
                level_idx + 1,
                level.len(),
                step.id.bold()
            );

            // Evaluate condition
            if let Some(ref cond) = step.condition {
                let status = Command::new("sh")
                    .arg("-c")
                    .arg(&cond.command)
                    .status();
                match status {
                    Ok(s) if s.success() => {}
                    _ => {
                        log_info(&format!("Condition not met, skipping step '{}'", step.id));
                        continue;
                    }
                }
            }

            // Resolve targets for this step
            let step_targets = if step.targets.is_empty() {
                cli_targets.to_vec()
            } else {
                step.targets.clone()
            };

            dispatch_action(config, registry, step, &step_targets, cli_all)?;
            println!();
        }
    }

    log_success(&format!("Flow '{}' complete", name));
    Ok(())
}

fn dispatch_action(
    config: &FleetConfig,
    registry: &NodeRegistry,
    step: &StepDef,
    targets: &[String],
    cli_all: bool,
) -> Result<()> {
    match &step.action {
        ActionDef::Build { show_trace } => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::build::run(&resolved, *show_trace)
        }
        ActionDef::Deploy { show_trace, dry_run } => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::deploy::run(&resolved, *dry_run, *show_trace)
        }
        ActionDef::Diff => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::diff::run(&resolved, config)
        }
        ActionDef::Status => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::status::run(&resolved, config)
        }
        ActionDef::Ping => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::ping::run(&resolved, config)
        }
        ActionDef::Rollback => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::rollback::run(&resolved, config)
        }
        ActionDef::Reboot => {
            // Auto-confirm in flows
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::reboot::run(&resolved, true, config)
        }
        ActionDef::Exec { command } => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::exec::run(&resolved, command, config)
        }
        ActionDef::Shell { command } => {
            log_info(&format!("Running: {}", command));
            run_command(&mut Command::new("sh").arg("-c").arg(command))
        }
        ActionDef::DarwinRebuild { show_trace } => {
            let flake = flake_dir();
            log_info("Running darwin-rebuild...");
            let mut cmd = Command::new("nix");
            cmd.arg("run").arg(format!("{}#darwin-rebuild", flake));
            if *show_trace {
                cmd.arg("--").arg("--show-trace");
            }
            run_command(&mut cmd)
        }
        ActionDef::HomeManagerRebuild { show_trace } => {
            let flake = flake_dir();
            log_info("Running home-manager-rebuild...");
            let mut cmd = Command::new("nix");
            cmd.arg("run").arg(format!("{}#home-manager-rebuild", flake));
            if *show_trace {
                cmd.arg("--").arg("--show-trace");
            }
            run_command(&mut cmd)
        }
        ActionDef::FlakeUpdate { inputs } => {
            let flake = flake_dir();
            log_info("Running flake update...");
            let mut cmd = Command::new("nix");
            cmd.arg("flake").arg("update");
            for input in inputs {
                cmd.arg(input);
            }
            cmd.arg("--flake").arg(&flake);
            run_command(&mut cmd)
        }
    }
}

fn resolve_step_targets(
    registry: &NodeRegistry,
    targets: &[String],
    cli_all: bool,
) -> Result<targeting::ResolvedTargets> {
    let all = cli_all || targets.is_empty();
    targeting::resolve(registry, targets, all)
}

fn print_execution_plan(flow_def: &crate::config::FlowDef, levels: &[Vec<usize>]) {
    println!("{}", "Execution plan (dry-run):".bold());
    println!();

    for (level_idx, level) in levels.iter().enumerate() {
        println!("  {} {}:", "Level".blue(), level_idx + 1);
        for &step_idx in level {
            let step = &flow_def.steps[step_idx];
            let action_type = match &step.action {
                ActionDef::Deploy { .. } => "deploy",
                ActionDef::Build { .. } => "build",
                ActionDef::Diff => "diff",
                ActionDef::Status => "status",
                ActionDef::Ping => "ping",
                ActionDef::Rollback => "rollback",
                ActionDef::Reboot => "reboot",
                ActionDef::Exec { .. } => "exec",
                ActionDef::Shell { .. } => "shell",
                ActionDef::DarwinRebuild { .. } => "darwin-rebuild",
                ActionDef::HomeManagerRebuild { .. } => "home-manager-rebuild",
                ActionDef::FlakeUpdate { .. } => "flake-update",
            };
            let targets_str = if step.targets.is_empty() {
                "(inherit CLI targets)".to_string()
            } else {
                step.targets.join(", ")
            };
            println!(
                "    {} [{}] targets: {}",
                step.id.bold(),
                action_type.cyan(),
                targets_str
            );
            if !step.depends_on.is_empty() {
                println!("      depends_on: {}", step.depends_on.join(", "));
            }
            if step.condition.is_some() {
                println!("      has condition");
            }
        }
    }
}
