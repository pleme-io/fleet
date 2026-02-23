use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct Node {
    pub system: String,
    pub hostname: String,
    #[serde(rename = "sshUser")]
    pub ssh_user: String,
    pub tags: Vec<String>,
}

pub type NodeRegistry = HashMap<String, Node>;

pub fn load_registry() -> Result<NodeRegistry> {
    let json = std::env::var("FLEET_NODES")
        .context("FLEET_NODES not set. Run via 'nix run .#fleet'")?;
    serde_json::from_str(&json).context("Failed to parse FLEET_NODES")
}
