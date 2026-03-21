use anyhow::{bail, Result};
use colored::Colorize;
use std::collections::HashMap;
use std::process::Command;

use crate::config::{ActionDef, FleetConfig, StepDef, StepResult};
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

    // Accumulate outputs from all completed steps, keyed by step ID
    let mut all_outputs: HashMap<String, HashMap<String, serde_json::Value>> = HashMap::new();

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

            let result = dispatch_action(config, registry, step, &step_targets, cli_all, &all_outputs)?;

            // Store outputs for downstream interpolation
            if !result.outputs.is_empty() {
                all_outputs.insert(step.id.clone(), result.outputs);
            }

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
    all_outputs: &HashMap<String, HashMap<String, serde_json::Value>>,
) -> Result<StepResult> {
    match &step.action {
        ActionDef::Build { show_trace } => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::build::run(&resolved, *show_trace)?;
            Ok(StepResult::default())
        }
        ActionDef::Deploy { show_trace, dry_run } => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::deploy::run(&resolved, *dry_run, *show_trace, false)?;
            Ok(StepResult::default())
        }
        ActionDef::Diff => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::diff::run(&resolved, config)?;
            Ok(StepResult::default())
        }
        ActionDef::Status => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::status::run(&resolved, config)?;
            Ok(StepResult::default())
        }
        ActionDef::Ping => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::ping::run(&resolved, config)?;
            Ok(StepResult::default())
        }
        ActionDef::Rollback => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::rollback::run(&resolved, config)?;
            Ok(StepResult::default())
        }
        ActionDef::Reboot => {
            // Auto-confirm in flows
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::reboot::run(&resolved, true, config)?;
            Ok(StepResult::default())
        }
        ActionDef::Exec { command } => {
            let resolved = resolve_step_targets(registry, targets, cli_all)?;
            super::exec::run(&resolved, command, config)?;
            Ok(StepResult::default())
        }
        ActionDef::Shell { command } => {
            log_info(&format!("Running: {}", command));
            run_command(&mut Command::new("sh").arg("-c").arg(command))?;
            Ok(StepResult::default())
        }
        ActionDef::DarwinRebuild { show_trace } => {
            let flake = flake_dir();
            log_info("Running darwin-rebuild...");
            let mut cmd = Command::new("nix");
            cmd.arg("run").arg(format!("{}#darwin-rebuild", flake));
            if *show_trace {
                cmd.arg("--").arg("--show-trace");
            }
            run_command(&mut cmd)?;
            Ok(StepResult::default())
        }
        ActionDef::HomeManagerRebuild { show_trace } => {
            let flake = flake_dir();
            log_info("Running home-manager-rebuild...");
            let mut cmd = Command::new("nix");
            cmd.arg("run").arg(format!("{}#home-manager-rebuild", flake));
            if *show_trace {
                cmd.arg("--").arg("--show-trace");
            }
            run_command(&mut cmd)?;
            Ok(StepResult::default())
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
            run_command(&mut cmd)?;
            Ok(StepResult::default())
        }
        ActionDef::Pangea {
            file,
            template,
            namespace,
            operation,
            env,
        } => {
            // Resolve ${step_id.output_name} references in the env map
            let resolved_env = resolve_step_env(env, all_outputs);
            super::pangea::run(
                file,
                template.as_deref(),
                namespace,
                operation,
                &resolved_env,
            )
        }
    }
}

/// Resolve `${step_id.output_name}` references in environment variable values.
///
/// Pattern: `${permissions.node_role_arn}` looks up step "permissions", output "node_role_arn".
/// Values that don't match the pattern are passed through unchanged.
fn resolve_step_env(
    env: &HashMap<String, String>,
    all_outputs: &HashMap<String, HashMap<String, serde_json::Value>>,
) -> HashMap<String, String> {
    let mut resolved = HashMap::new();
    for (key, value) in env {
        resolved.insert(key.clone(), resolve_template(value, all_outputs));
    }
    resolved
}

/// Resolve a single template string, replacing all `${step_id.output_name}` patterns.
fn resolve_template(
    template: &str,
    all_outputs: &HashMap<String, HashMap<String, serde_json::Value>>,
) -> String {
    let mut result = template.to_string();
    // Find all ${...} patterns
    while let Some(start) = result.find("${") {
        let rest = &result[start + 2..];
        let Some(end) = rest.find('}') else {
            break;
        };
        let reference = &rest[..end];
        let replacement = if let Some((step_id, output_name)) = reference.split_once('.') {
            all_outputs
                .get(step_id)
                .and_then(|outputs| outputs.get(output_name))
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        result = format!("{}{}{}", &result[..start], replacement, &rest[end + 1..]);
    }
    result
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
                ActionDef::Pangea { .. } => "pangea",
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
            // Show Pangea-specific details
            if let ActionDef::Pangea { file, namespace, operation, env, .. } = &step.action {
                let op_str = match operation {
                    crate::config::PangeaOperation::Plan => "plan",
                    crate::config::PangeaOperation::Apply => "apply",
                    crate::config::PangeaOperation::Destroy => "destroy",
                    crate::config::PangeaOperation::Output => "output",
                };
                println!("      pangea: {} {} --namespace {}", op_str, file, namespace);
                if !env.is_empty() {
                    for (k, v) in env {
                        println!("      env: {}={}", k, v);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn test_pangea_operation_serde() {
        let yaml = r#"
type: pangea
file: k3s_permissions.rb
namespace: development
operation: apply
"#;
        let action: ActionDef = serde_yaml_ng::from_str(yaml).unwrap();
        match action {
            ActionDef::Pangea {
                file,
                namespace,
                operation,
                ..
            } => {
                assert_eq!(file, "k3s_permissions.rb");
                assert_eq!(namespace, "development");
                assert!(matches!(operation, PangeaOperation::Apply));
            }
            _ => panic!("Expected Pangea variant"),
        }
    }

    #[test]
    fn test_pangea_operation_plan_serde() {
        let yaml = r#"
type: pangea
file: network.rb
namespace: production
operation: plan
"#;
        let action: ActionDef = serde_yaml_ng::from_str(yaml).unwrap();
        match action {
            ActionDef::Pangea { operation, .. } => {
                assert!(matches!(operation, PangeaOperation::Plan));
            }
            _ => panic!("Expected Pangea variant"),
        }
    }

    #[test]
    fn test_pangea_operation_destroy_serde() {
        let yaml = r#"
type: pangea
file: infra.rb
namespace: staging
operation: destroy
"#;
        let action: ActionDef = serde_yaml_ng::from_str(yaml).unwrap();
        match action {
            ActionDef::Pangea { operation, namespace, .. } => {
                assert!(matches!(operation, PangeaOperation::Destroy));
                assert_eq!(namespace, "staging");
            }
            _ => panic!("Expected Pangea variant"),
        }
    }

    #[test]
    fn test_pangea_with_env() {
        let yaml = r#"
type: pangea
file: k3s_network.rb
namespace: development
operation: apply
env:
  ROLE_ARN: "${permissions.node_role_arn}"
  PROFILE: "${permissions.instance_profile_name}"
"#;
        let action: ActionDef = serde_yaml_ng::from_str(yaml).unwrap();
        match action {
            ActionDef::Pangea { env, .. } => {
                assert_eq!(env.len(), 2);
                assert_eq!(
                    env.get("ROLE_ARN").unwrap(),
                    "${permissions.node_role_arn}"
                );
            }
            _ => panic!("Expected Pangea variant"),
        }
    }

    #[test]
    fn test_resolve_template_simple() {
        let mut all_outputs = HashMap::new();
        let mut step_outputs = HashMap::new();
        step_outputs.insert(
            "node_role_arn".to_string(),
            serde_json::Value::String("arn:aws:iam::123:role/test".to_string()),
        );
        all_outputs.insert("permissions".to_string(), step_outputs);

        let result = resolve_template("${permissions.node_role_arn}", &all_outputs);
        assert_eq!(result, "arn:aws:iam::123:role/test");
    }

    #[test]
    fn test_resolve_template_multiple() {
        let mut all_outputs = HashMap::new();
        let mut step_outputs = HashMap::new();
        step_outputs.insert(
            "arn".to_string(),
            serde_json::Value::String("arn:123".to_string()),
        );
        step_outputs.insert(
            "name".to_string(),
            serde_json::Value::String("my-profile".to_string()),
        );
        all_outputs.insert("step1".to_string(), step_outputs);

        let result = resolve_template("role=${step1.arn},profile=${step1.name}", &all_outputs);
        assert_eq!(result, "role=arn:123,profile=my-profile");
    }

    #[test]
    fn test_resolve_template_missing_output() {
        let all_outputs = HashMap::new();
        let result = resolve_template("${missing.output}", &all_outputs);
        assert_eq!(result, "");
    }

    #[test]
    fn test_resolve_template_no_refs() {
        let all_outputs = HashMap::new();
        let result = resolve_template("plain-value", &all_outputs);
        assert_eq!(result, "plain-value");
    }

    #[test]
    fn test_resolve_template_numeric_value() {
        let mut all_outputs = HashMap::new();
        let mut step_outputs = HashMap::new();
        step_outputs.insert(
            "count".to_string(),
            serde_json::json!(42),
        );
        all_outputs.insert("infra".to_string(), step_outputs);

        let result = resolve_template("${infra.count}", &all_outputs);
        assert_eq!(result, "42");
    }

    #[test]
    fn test_fleet_yaml_with_pangea_flow() {
        let yaml = r#"
flows:
  deploy:
    description: "Deploy K3s permissions"
    steps:
      - id: permissions
        action:
          type: pangea
          file: k3s_permissions.rb
          namespace: development
          operation: apply
      - id: network
        action:
          type: pangea
          file: k3s_network.rb
          namespace: development
          operation: apply
          env:
            ROLE_ARN: "${permissions.node_role_arn}"
        depends_on: [permissions]
"#;
        let config: FleetConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let flow = config.flows.get("deploy").unwrap();
        assert_eq!(flow.steps.len(), 2);
        assert_eq!(flow.steps[0].id, "permissions");
        assert_eq!(flow.steps[1].id, "network");
        assert_eq!(flow.steps[1].depends_on, vec!["permissions"]);

        // Verify DAG validation passes
        let validated = crate::flow::validate(flow).unwrap();
        let levels = crate::dag::topo_levels(flow.steps.len(), &validated.deps);
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0], vec![0]); // permissions first
        assert_eq!(levels[1], vec![1]); // network second
    }

    #[test]
    fn test_pangea_flow_cycle_detection() {
        let yaml = r#"
flows:
  bad:
    description: "Cyclic flow"
    steps:
      - id: a
        action:
          type: pangea
          file: a.rb
          namespace: dev
          operation: plan
        depends_on: [b]
      - id: b
        action:
          type: pangea
          file: b.rb
          namespace: dev
          operation: plan
        depends_on: [a]
"#;
        let config: FleetConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let flow = config.flows.get("bad").unwrap();
        let result = crate::flow::validate(flow);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Cycle"));
    }

    #[test]
    fn test_resolve_step_env() {
        let mut env = HashMap::new();
        env.insert("ARN".to_string(), "${step1.role_arn}".to_string());
        env.insert("STATIC".to_string(), "hello".to_string());

        let mut all_outputs = HashMap::new();
        let mut step1_outputs = HashMap::new();
        step1_outputs.insert(
            "role_arn".to_string(),
            serde_json::Value::String("arn:aws:iam::123:role/node".to_string()),
        );
        all_outputs.insert("step1".to_string(), step1_outputs);

        let resolved = resolve_step_env(&env, &all_outputs);
        assert_eq!(resolved.get("ARN").unwrap(), "arn:aws:iam::123:role/node");
        assert_eq!(resolved.get("STATIC").unwrap(), "hello");
    }
}
