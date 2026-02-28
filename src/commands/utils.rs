use anyhow::{Context, Result};
use colored::Colorize;
use std::io::{self, Write};
use std::process::{Command, Stdio};

pub fn log_info(msg: &str) {
    println!("{} {}", "[INFO]".blue().bold(), msg);
}

pub fn log_success(msg: &str) {
    println!("{} {}", "[OK]".green().bold(), msg);
}

pub fn log_warning(msg: &str) {
    println!("{} {}", "[WARN]".yellow().bold(), msg);
}

pub fn log_error(msg: &str) {
    eprintln!("{} {}", "[ERROR]".red().bold(), msg);
}

pub fn run_command(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("Failed to execute: {:?}", cmd))?;

    if !status.success() {
        anyhow::bail!("Command failed with exit code: {:?}", status.code());
    }

    Ok(())
}

pub fn run_command_output(cmd: &mut Command) -> Result<String> {
    let output = cmd
        .output()
        .with_context(|| format!("Failed to execute: {:?}", cmd))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Command failed: {}", stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn ssh_cmd_with_config(
    user: &str,
    host: &str,
    ssh: &crate::config::ResolvedSsh,
) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o")
        .arg(format!("ConnectTimeout={}", ssh.connect_timeout));
    cmd.arg("-o")
        .arg(format!("StrictHostKeyChecking={}", ssh.strict_host_key));
    for (k, v) in &ssh.options {
        cmd.arg("-o").arg(format!("{}={}", k, v));
    }
    cmd.arg(format!("{}@{}", user, host));
    cmd
}

pub fn ssh_run_with_config(
    user: &str,
    host: &str,
    ssh: &crate::config::ResolvedSsh,
    remote_cmd: &str,
) -> Result<String> {
    let mut cmd = ssh_cmd_with_config(user, host, ssh);
    cmd.arg(remote_cmd);
    run_command_output(&mut cmd)
}

pub fn node_label(name: &str) -> String {
    format!("[{}]", name).cyan().bold().to_string()
}

pub fn confirm(msg: &str) -> Result<bool> {
    print!("{} {} ", "[?]".yellow().bold(), msg);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let answer = input.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

pub fn flake_dir() -> String {
    // Prefer local detection: walk up to find flake.nix
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(root) = super::rebuild::find_flake_root(&cwd) {
            return root.to_string_lossy().to_string();
        }
    }
    // Fall back to env var for backwards compatibility (nix wrapper sets this)
    std::env::var("FLEET_FLAKE_DIR").unwrap_or_else(|_| ".".to_string())
}
