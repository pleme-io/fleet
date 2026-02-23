use anyhow::{bail, Result};
use crate::registry::{Node, NodeRegistry};

pub struct ResolvedTargets {
    pub nodes: Vec<(String, Node)>,
}

impl ResolvedTargets {
    pub fn is_single(&self) -> bool {
        self.nodes.len() == 1
    }

    pub fn names(&self) -> Vec<&str> {
        self.nodes.iter().map(|(n, _)| n.as_str()).collect()
    }
}

pub fn resolve(registry: &NodeRegistry, targets: &[String], all: bool) -> Result<ResolvedTargets> {
    let mut result: Vec<(String, Node)> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if all {
        let mut entries: Vec<_> = registry.iter().collect();
        entries.sort_by_key(|(name, _)| (*name).clone());
        for (name, node) in entries {
            result.push((name.clone(), node.clone()));
        }
        return Ok(ResolvedTargets { nodes: result });
    }

    if targets.is_empty() {
        bail!("No targets specified. Use node names, @tag, or --all");
    }

    for target in targets {
        if let Some(tag) = target.strip_prefix('@') {
            let mut matched: Vec<_> = registry
                .iter()
                .filter(|(_, node)| node.tags.contains(&tag.to_string()))
                .collect();
            matched.sort_by_key(|(name, _)| (*name).clone());
            for (name, node) in matched {
                if seen.insert(name.clone()) {
                    result.push((name.clone(), node.clone()));
                }
            }
        } else {
            let node = registry
                .get(target)
                .ok_or_else(|| anyhow::anyhow!("Unknown node: {}", target))?;
            if seen.insert(target.clone()) {
                result.push((target.clone(), node.clone()));
            }
        }
    }

    if result.is_empty() {
        bail!("No nodes matched the given targets");
    }

    Ok(ResolvedTargets { nodes: result })
}
