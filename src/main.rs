use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod config;
mod dag;
mod flow;
mod hooks;
mod registry;
mod targeting;

#[derive(Parser)]
#[command(name = "fleet")]
#[command(about = "Node lifecycle CLI for NixOS fleet management", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Deploy NixOS configurations to nodes
    Deploy {
        /// Target nodes (names or @tag)
        targets: Vec<String>,

        /// Deploy to all nodes
        #[arg(long)]
        all: bool,

        /// Dry run (build but don't activate)
        #[arg(long)]
        dry_run: bool,

        /// Show nix evaluation trace
        #[arg(long)]
        show_trace: bool,
    },

    /// Build NixOS configurations without activating
    Build {
        /// Target nodes (names or @tag)
        targets: Vec<String>,

        /// Build all nodes
        #[arg(long)]
        all: bool,

        /// Show nix evaluation trace
        #[arg(long)]
        show_trace: bool,
    },

    /// Show closure diff between current and new configuration
    Diff {
        /// Target nodes (names or @tag)
        targets: Vec<String>,

        /// Diff all nodes
        #[arg(long)]
        all: bool,
    },

    /// Execute a command on remote nodes via SSH
    Exec {
        /// Target nodes (names or @tag)
        targets: Vec<String>,

        /// Execute on all nodes
        #[arg(long)]
        all: bool,

        /// Command to execute (after --)
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },

    /// Show status of remote nodes (generation, uptime, kernel)
    Status {
        /// Target nodes (names or @tag)
        targets: Vec<String>,

        /// Show status of all nodes (default if no targets given)
        #[arg(long)]
        all: bool,
    },

    /// Rollback nodes to previous NixOS generation
    Rollback {
        /// Target nodes (names or @tag)
        targets: Vec<String>,

        /// Rollback all nodes
        #[arg(long)]
        all: bool,
    },

    /// Reboot remote nodes
    Reboot {
        /// Target nodes (names or @tag)
        targets: Vec<String>,

        /// Reboot all nodes
        #[arg(long)]
        all: bool,

        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Open interactive SSH session to a node
    Ssh {
        /// Node name
        node: String,
    },

    /// Show node registry information
    Info {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Check SSH connectivity to nodes
    Ping {
        /// Target nodes (names or @tag)
        targets: Vec<String>,

        /// Ping all nodes (default if no targets given)
        #[arg(long)]
        all: bool,
    },

    /// Run or list named DAG workflows
    Flow {
        #[command(subcommand)]
        action: FlowAction,
    },
}

#[derive(Subcommand)]
enum FlowAction {
    /// List available flows
    List,

    /// Run a named flow
    Run {
        /// Flow name
        name: String,

        /// Target nodes (names or @tag) — used by steps without explicit targets
        targets: Vec<String>,

        /// Target all nodes
        #[arg(long)]
        all: bool,

        /// Print execution plan without running
        #[arg(long)]
        dry_run: bool,
    },
}

fn load_config() -> config::FleetConfig {
    let dir = std::env::var("FLEET_FLAKE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    config::FleetConfig::load(&dir).unwrap_or_default()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config();

    match cli.command {
        Commands::Deploy {
            targets,
            all,
            dry_run,
            show_trace,
        } => {
            let reg = registry::load_registry()?;
            let resolved = targeting::resolve(&reg, &targets, all)?;
            for (name, node) in &resolved.nodes {
                hooks::run_pre(&config, "deploy", name, node)?;
            }
            commands::deploy::run(&resolved, dry_run, show_trace)?;
            for (name, node) in &resolved.nodes {
                hooks::run_post(&config, "deploy", name, node);
            }
        }

        Commands::Build {
            targets,
            all,
            show_trace,
        } => {
            let reg = registry::load_registry()?;
            let resolved = targeting::resolve(&reg, &targets, all)?;
            for (name, node) in &resolved.nodes {
                hooks::run_pre(&config, "build", name, node)?;
            }
            commands::build::run(&resolved, show_trace)?;
            for (name, node) in &resolved.nodes {
                hooks::run_post(&config, "build", name, node);
            }
        }

        Commands::Diff { targets, all } => {
            let reg = registry::load_registry()?;
            let resolved = targeting::resolve(&reg, &targets, all)?;
            for (name, node) in &resolved.nodes {
                hooks::run_pre(&config, "diff", name, node)?;
            }
            commands::diff::run(&resolved, &config)?;
            for (name, node) in &resolved.nodes {
                hooks::run_post(&config, "diff", name, node);
            }
        }

        Commands::Exec { targets, all, cmd } => {
            let reg = registry::load_registry()?;
            let resolved = targeting::resolve(&reg, &targets, all)?;
            for (name, node) in &resolved.nodes {
                hooks::run_pre(&config, "exec", name, node)?;
            }
            commands::exec::run(&resolved, &cmd, &config)?;
            for (name, node) in &resolved.nodes {
                hooks::run_post(&config, "exec", name, node);
            }
        }

        Commands::Status { targets, all } => {
            let reg = registry::load_registry()?;
            let all = all || targets.is_empty();
            let resolved = targeting::resolve(&reg, &targets, all)?;
            commands::status::run(&resolved, &config)?;
        }

        Commands::Rollback { targets, all } => {
            let reg = registry::load_registry()?;
            let resolved = targeting::resolve(&reg, &targets, all)?;
            for (name, node) in &resolved.nodes {
                hooks::run_pre(&config, "rollback", name, node)?;
            }
            commands::rollback::run(&resolved, &config)?;
            for (name, node) in &resolved.nodes {
                hooks::run_post(&config, "rollback", name, node);
            }
        }

        Commands::Reboot { targets, all, yes } => {
            let reg = registry::load_registry()?;
            let resolved = targeting::resolve(&reg, &targets, all)?;
            for (name, node) in &resolved.nodes {
                hooks::run_pre(&config, "reboot", name, node)?;
            }
            commands::reboot::run(&resolved, yes, &config)?;
            for (name, node) in &resolved.nodes {
                hooks::run_post(&config, "reboot", name, node);
            }
        }

        Commands::Ssh { node } => {
            let reg = registry::load_registry()?;
            let resolved = targeting::resolve(&reg, &[node], false)?;
            commands::ssh::run(&resolved, &config)?;
        }

        Commands::Info { json } => {
            let reg = registry::load_registry()?;
            commands::info::run(&reg, json)?;
        }

        Commands::Ping { targets, all } => {
            let reg = registry::load_registry()?;
            let all = all || targets.is_empty();
            let resolved = targeting::resolve(&reg, &targets, all)?;
            commands::ping::run(&resolved, &config)?;
        }

        Commands::Flow { action } => match action {
            FlowAction::List => {
                commands::flow::list(&config)?;
            }
            FlowAction::Run {
                name,
                targets,
                all,
                dry_run,
            } => {
                let reg = registry::load_registry()?;
                commands::flow::run(&config, &reg, &name, &targets, all, dry_run)?;
            }
        },
    }

    Ok(())
}
