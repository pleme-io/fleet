use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::config::{PangeaOperation, StepResult};

use super::utils::*;

/// Run a Pangea operation on a template file.
pub fn run(
    file: &str,
    template: Option<&str>,
    namespace: &str,
    operation: &PangeaOperation,
    env: &HashMap<String, String>,
) -> Result<StepResult> {
    let op_str = match operation {
        PangeaOperation::Plan => "plan",
        PangeaOperation::Apply => "apply",
        PangeaOperation::Destroy => "destroy",
        PangeaOperation::Output => "output",
        PangeaOperation::Synth => "synth",
    };

    log_info(&format!(
        "pangea {} {} --namespace {}",
        op_str, file, namespace
    ));

    let mut cmd = Command::new("pangea");
    cmd.arg(op_str).arg(file).arg("--namespace").arg(namespace);

    // Inject resolved environment variables
    for (k, v) in env {
        cmd.env(k, v);
    }

    run_command(&mut cmd)?;

    // After apply, capture outputs via tofu output -json
    let outputs = if matches!(operation, PangeaOperation::Apply) {
        capture_outputs(file, template, namespace)?
    } else {
        HashMap::new()
    };

    Ok(StepResult { outputs })
}

/// Capture Terraform/OpenTofu outputs from the Pangea workspace directory.
///
/// Pangea stores state in `~/.pangea/workspaces/{namespace}/{template_name}/`.
/// We run `tofu output -json` there to get structured outputs.
fn capture_outputs(
    file: &str,
    template: Option<&str>,
    namespace: &str,
) -> Result<HashMap<String, serde_json::Value>> {
    let template_name = template.unwrap_or_else(|| {
        Path::new(file)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(file)
    });

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let workspace_dir = format!(
        "{}/.pangea/workspaces/{}/{}",
        home, namespace, template_name
    );

    if !Path::new(&workspace_dir).exists() {
        log_warning(&format!(
            "Workspace dir not found: {} — skipping output capture",
            workspace_dir
        ));
        return Ok(HashMap::new());
    }

    let mut cmd = Command::new("tofu");
    cmd.arg("output").arg("-json").current_dir(&workspace_dir);

    let output = match cmd.output() {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            log_warning(&format!("tofu output failed: {}", stderr.trim()));
            return Ok(HashMap::new());
        }
        Err(e) => {
            log_warning(&format!("Failed to run tofu: {}", e));
            return Ok(HashMap::new());
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(HashMap::new());
    }

    // tofu output -json returns: { "output_name": { "value": ..., "type": ... }, ... }
    let raw: HashMap<String, serde_json::Value> = serde_json::from_str(&stdout)
        .with_context(|| "Failed to parse tofu output JSON")?;

    // Extract just the "value" field from each output
    let mut outputs = HashMap::new();
    for (key, obj) in &raw {
        if let Some(value) = obj.get("value") {
            outputs.insert(key.clone(), value.clone());
        }
    }

    if !outputs.is_empty() {
        log_info(&format!("Captured {} output(s)", outputs.len()));
    }

    Ok(outputs)
}
