use anyhow::Result;
use std::collections::HashMap;
use std::process::Command;

use crate::config::{PitrForgeCommand, StepResult};

use super::utils::*;

/// Run a pitr-forge operation.
pub fn run(
    command: &PitrForgeCommand,
    tenant: Option<&str>,
    environment: Option<&str>,
    restore_time: Option<&str>,
    app_version: Option<&str>,
    config: Option<&str>,
    output_json: Option<&str>,
    skip_teardown: bool,
    env: &HashMap<String, String>,
) -> Result<StepResult> {
    let cmd_str = match command {
        PitrForgeCommand::Verify => "verify",
        PitrForgeCommand::Drill => "drill",
        PitrForgeCommand::Restore => "restore",
        PitrForgeCommand::Status => "status",
        PitrForgeCommand::Teardown => "teardown",
        PitrForgeCommand::Test => "test",
        PitrForgeCommand::Combine => "combine",
    };

    log_info(&format!("pitr-forge {cmd_str}"));

    let mut cmd = Command::new("pitr-forge");
    cmd.arg(cmd_str);

    // Add flags based on command type
    if let Some(t) = tenant {
        cmd.arg("--tenant").arg(t);
    }
    if let Some(e) = environment {
        cmd.arg("--env").arg(e);
    }
    if let Some(rt) = restore_time {
        cmd.arg("--restore-time").arg(rt);
    }
    if let Some(av) = app_version {
        cmd.arg("--app-version").arg(av);
    }
    if let Some(c) = config {
        cmd.arg("--config").arg(c);
    }
    if skip_teardown {
        cmd.arg("--skip-teardown");
    }

    // For test command, --json is the output_json path
    if matches!(command, PitrForgeCommand::Test) {
        if let Some(json_path) = output_json {
            cmd.arg("--json").arg(json_path);
        }
    }

    // Inject resolved environment variables
    for (k, v) in env {
        cmd.env(k, v);
    }

    run_command(&mut cmd)?;

    // After drill/restore, capture outputs from the JSON results file
    let outputs = if let Some(json_path) = output_json {
        if matches!(command, PitrForgeCommand::Drill | PitrForgeCommand::Restore) {
            capture_drill_outputs(json_path)?
        } else {
            HashMap::new()
        }
    } else {
        HashMap::new()
    };

    Ok(StepResult { outputs })
}

/// Capture key outputs from a pitr-forge drill results JSON file.
///
/// Extracts: overall_status, measured_rto_secs, total_ms, tenant, environment,
/// gate_count_passed, gate_count_failed.
fn capture_drill_outputs(json_path: &str) -> Result<HashMap<String, serde_json::Value>> {
    let data = match std::fs::read_to_string(json_path) {
        Ok(d) => d,
        Err(e) => {
            log_warning(&format!(
                "Cannot read pitr-forge output '{}': {}",
                json_path, e
            ));
            return Ok(HashMap::new());
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            log_warning(&format!(
                "Cannot parse pitr-forge output '{}': {}",
                json_path, e
            ));
            return Ok(HashMap::new());
        }
    };

    let mut outputs = HashMap::new();

    if let Some(status) = json.get("overall_status") {
        outputs.insert("overall_status".to_string(), status.clone());
    }
    if let Some(rto) = json
        .get("recovery_objectives")
        .and_then(|ro| ro.get("measured_rto_secs"))
    {
        outputs.insert("measured_rto_secs".to_string(), rto.clone());
    }
    if let Some(total) = json
        .get("phase_timings")
        .and_then(|pt| pt.get("total_ms"))
    {
        outputs.insert("total_ms".to_string(), total.clone());
    }
    if let Some(tenant) = json.get("tenant") {
        outputs.insert("tenant".to_string(), tenant.clone());
    }
    if let Some(env) = json.get("environment") {
        outputs.insert("environment".to_string(), env.clone());
    }

    // Count gates
    if let Some(gates) = json.get("gate_results").and_then(|g| g.as_array()) {
        let passed = gates.iter().filter(|g| g.get("passed") == Some(&serde_json::json!(true))).count();
        let failed = gates.len() - passed;
        outputs.insert(
            "gate_count_passed".to_string(),
            serde_json::json!(passed),
        );
        outputs.insert(
            "gate_count_failed".to_string(),
            serde_json::json!(failed),
        );
    }

    if !outputs.is_empty() {
        log_info(&format!("Captured {} pitr-forge output(s)", outputs.len()));
    }

    Ok(outputs)
}
