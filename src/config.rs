use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FleetConfig {
    pub ssh: SshConfig,
    pub deploy: DeployConfig,
    pub nodes: HashMap<String, NodeOverride>,
    pub hooks: HashMap<String, HookPair>,
    pub flows: HashMap<String, FlowDef>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct SshConfig {
    pub connect_timeout: u32,
    pub strict_host_key: String,
    pub options: HashMap<String, String>,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            connect_timeout: 5,
            strict_host_key: "accept-new".to_string(),
            options: HashMap::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct DeployConfig {
    pub show_trace: bool,
    pub magic_rollback: bool,
}

impl Default for DeployConfig {
    fn default() -> Self {
        Self {
            show_trace: false,
            magic_rollback: true,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct NodeOverride {
    pub ssh: SshOverride,
    pub deploy: DeployOverride,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SshOverride {
    pub connect_timeout: Option<u32>,
    pub strict_host_key: Option<String>,
    pub options: HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DeployOverride {
    pub show_trace: Option<bool>,
    pub magic_rollback: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct HookPair {
    pub pre: Option<String>,
    pub post: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FlowDef {
    #[serde(default)]
    pub description: String,
    pub steps: Vec<StepDef>,
}

#[derive(Debug, Deserialize)]
pub struct StepDef {
    pub id: String,
    pub action: ActionDef,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub condition: Option<ConditionDef>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ActionDef {
    Deploy {
        #[serde(default)]
        show_trace: bool,
        #[serde(default)]
        dry_run: bool,
    },
    Build {
        #[serde(default)]
        show_trace: bool,
    },
    Diff,
    Status,
    Ping,
    Rollback,
    Reboot,
    Exec {
        command: Vec<String>,
    },
    Shell {
        command: String,
    },
    /// Run `nix run .#darwin-rebuild` (for macOS nodes like cid)
    DarwinRebuild {
        #[serde(default)]
        show_trace: bool,
    },
    /// Run `nix run .#home-manager-rebuild` (standalone HM rebuild)
    HomeManagerRebuild {
        #[serde(default)]
        show_trace: bool,
    },
    /// Run `nix flake update` (with optional input names)
    FlakeUpdate {
        #[serde(default)]
        inputs: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
pub struct ConditionDef {
    pub command: String,
}

/// Resolved SSH config for a specific node (all merging done).
pub struct ResolvedSsh {
    pub connect_timeout: u32,
    pub strict_host_key: String,
    pub options: HashMap<String, String>,
}

/// Resolved deploy config for a specific node (all merging done).
#[allow(dead_code)]
pub struct ResolvedDeploy {
    pub show_trace: bool,
    pub magic_rollback: bool,
}

impl FleetConfig {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("fleet.yaml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(&path)?;
        let config: FleetConfig = serde_yaml_ng::from_str(&contents)?;
        Ok(config)
    }

    pub fn resolve_ssh(&self, node_name: &str) -> ResolvedSsh {
        let mut resolved = ResolvedSsh {
            connect_timeout: self.ssh.connect_timeout,
            strict_host_key: self.ssh.strict_host_key.clone(),
            options: self.ssh.options.clone(),
        };

        if let Some(ovr) = self.nodes.get(node_name) {
            if let Some(t) = ovr.ssh.connect_timeout {
                resolved.connect_timeout = t;
            }
            if let Some(ref s) = ovr.ssh.strict_host_key {
                resolved.strict_host_key = s.clone();
            }
            for (k, v) in &ovr.ssh.options {
                resolved.options.insert(k.clone(), v.clone());
            }
        }

        resolved
    }

    #[allow(dead_code)]
    pub fn resolve_deploy(&self, node_name: &str) -> ResolvedDeploy {
        let mut resolved = ResolvedDeploy {
            show_trace: self.deploy.show_trace,
            magic_rollback: self.deploy.magic_rollback,
        };

        if let Some(ovr) = self.nodes.get(node_name) {
            if let Some(v) = ovr.deploy.show_trace {
                resolved.show_trace = v;
            }
            if let Some(v) = ovr.deploy.magic_rollback {
                resolved.magic_rollback = v;
            }
        }

        resolved
    }
}
