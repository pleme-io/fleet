use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod config;
mod dag;
mod fetch_recovery;
mod flow;
mod github_token;
mod hooks;
mod registry;
mod secrets;
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

        /// Skip deploy-rs flake checks
        #[arg(long)]
        skip_checks: bool,
    },

    /// Report whether this node is converged with its branch — the typed
    /// document an MCP tool or a log reader consumes. Reads what the
    /// reconciler PUBLISHED (heartbeat + receipt chain), so it works on a
    /// node that is unreachable and on one whose daemon is dead.
    Convergence {
        /// Emit the typed JSON document.
        #[arg(long)]
        json: bool,
    },

    /// Serve the convergence document over MCP (stdio).
    Mcp,

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

    /// Rebuild local system (auto-detects Darwin/NixOS from hostname)
    Rebuild {
        /// Node to build as. Defaults to `hostname -s`.
        ///
        /// PASS THIS ON A FIRST BOOTSTRAP. A fresh NixOS install calls itself
        /// `nixos`, and `.#nixos` is not a configuration — so the derived name
        /// only works once the machine has already been the node at least
        /// once. `fleet rebuild rio` adopts this machine AS rio.
        node: Option<String>,

        /// Show nix evaluation trace
        #[arg(long)]
        show_trace: bool,

        /// Pass --option key value to darwin-rebuild/nixos-rebuild (repeatable)
        #[arg(long = "nix-option", num_args = 2, value_names = ["KEY", "VALUE"], action = clap::ArgAction::Append)]
        nix_options: Vec<String>,
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

    /// Manage secrets (provision from 1Password, clean local files)
    Secrets {
        #[command(subcommand)]
        action: SecretsAction,
    },

    /// Make nix able to fetch private pleme-io flake inputs.
    ///
    /// Resolves a GitHub token (env -> nix.conf -> SOPS) and writes it where
    /// nix will read it, idempotently. Cheap enough to call from a directory
    /// hook: a healthy machine costs one stat plus one read and writes
    /// nothing.
    ///
    /// `pleme-io/fleet` is PUBLIC, so this is reachable with no credential:
    ///   nix run github:pleme-io/fleet -- nix-credential
    /// which is what lets it run BEFORE a private flake is evaluated.
    NixCredential {
        /// Report only; write nothing. Non-zero exit when nothing resolves.
        #[arg(long)]
        check: bool,

        /// Print only when something changed (the shell-hook mode).
        #[arg(long)]
        quiet: bool,

        /// Target /root/.config/nix instead of your own — sudo drops HOME,
        /// so root's config is what a sudo'd rebuild actually reads.
        #[arg(long)]
        root: bool,
    },

    /// Ensure every flake input is present locally, sourcing from a fleet
    /// builder when the upstream throttles THIS host's egress.
    ///
    /// GitHub throttles archive generation per egress IP, separately from the
    /// documented API quota and regardless of a valid token — measured on cid
    /// 2026-08-17 at 4653/5000 requests remaining. nix's own retry (observed
    /// backing off 143923 ms) cannot help, because waiting is not the problem.
    /// A builder on a different egress can fetch the identical content, and
    /// flake.lock's narHash is what makes "identical" checkable rather than
    /// assumed.
    WarmInputs {
        /// Print what would be run without fetching or copying.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum SecretsAction {
    /// Provision secrets from configured providers (all or by name)
    Sync {
        /// Secret name (provisions all if omitted)
        name: Option<String>,
    },

    /// Remove local secret files (all or by name)
    Clean {
        /// Secret name (cleans all if omitted)
        name: Option<String>,
    },

    /// List configured secrets and their status
    List,
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
    // Prefer local detection: walk up to find flake.nix
    let dir = std::env::current_dir()
        .ok()
        .and_then(|cwd| commands::rebuild::find_flake_root(&cwd).ok())
        .or_else(|| std::env::var("FLEET_FLAKE_DIR").map(PathBuf::from).ok())
        .unwrap_or_else(|| PathBuf::from("."));
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
            skip_checks,
        } => {
            secrets::provision_for_command(&config, "deploy")?;
            let reg = registry::load_registry()?;
            let resolved = targeting::resolve(&reg, &targets, all)?;
            for (name, node) in &resolved.nodes {
                hooks::run_pre(&config, "deploy", name, node)?;
            }
            commands::deploy::run(&resolved, dry_run, show_trace, skip_checks)?;
            for (name, node) in &resolved.nodes {
                hooks::run_post(&config, "deploy", name, node);
            }
        }

        Commands::WarmInputs { dry_run } => {
            let root = commands::rebuild::find_flake_root(&std::env::current_dir()?)?;
            commands::warm_inputs::warm_inputs(&root, dry_run)?;
        }
        Commands::Convergence { json } => {
            commands::convergence::convergence(json)?;
        }
        Commands::Mcp => {
            commands::mcp::mcp()?;
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

        Commands::Rebuild {
            node,
            show_trace,
            nix_options,
        } => {
            secrets::provision_for_command(&config, "rebuild")?;
            commands::rebuild::rebuild(node.as_deref(), show_trace, &nix_options)?;
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

        Commands::NixCredential { check, quiet, root } => {
            commands::nix_credential::run(check, quiet, root)?;
        }

        Commands::Secrets { action } => match action {
            SecretsAction::Sync { name } => match name {
                Some(n) => secrets::sync_secret(&config, &n)?,
                None => secrets::sync_all(&config)?,
            },
            SecretsAction::Clean { name } => match name {
                Some(n) => secrets::clean_secret(&config, &n)?,
                None => {
                    for secret_name in config.secrets.keys() {
                        secrets::clean_secret(&config, secret_name)?;
                    }
                }
            },
            SecretsAction::List => {
                if config.secrets.is_empty() {
                    println!("No secrets configured in fleet.yaml");
                } else {
                    for (name, secret) in &config.secrets {
                        let target = secrets::expand_home_pub(&secret.path);
                        let status = if target.exists() {
                            "present".to_string()
                        } else {
                            "missing".to_string()
                        };
                        println!(
                            "  {} ({}) -> {} [{}]",
                            name,
                            secret.provider,
                            target.display(),
                            status
                        );
                    }
                }
            }
        },

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
                // Registry is optional — Pangea-only flows don't need node targets
                let reg = registry::load_registry().unwrap_or_default();
                commands::flow::run(&config, &reg, &name, &targets, all, dry_run)?;
            }
        },
    }

    Ok(())
}
