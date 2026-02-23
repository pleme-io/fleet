use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::config::FlowDef;

/// A validated flow with step indices resolved from string IDs.
pub struct ValidatedFlow {
    /// For each step index, the list of dependency step indices.
    pub deps: Vec<Vec<usize>>,
}

/// Validate a flow definition: check for duplicate IDs, unknown deps, and cycles.
pub fn validate(flow: &FlowDef) -> Result<ValidatedFlow> {
    let mut id_to_idx: HashMap<&str, usize> = HashMap::new();

    // Check for duplicate step IDs
    for (i, step) in flow.steps.iter().enumerate() {
        if let Some(prev) = id_to_idx.insert(&step.id, i) {
            bail!(
                "Duplicate step ID '{}' (steps {} and {})",
                step.id,
                prev,
                i
            );
        }
    }

    // Resolve depends_on to indices, check for unknown deps
    let mut deps: Vec<Vec<usize>> = Vec::with_capacity(flow.steps.len());
    for step in &flow.steps {
        let mut step_deps = Vec::new();
        for dep_id in &step.depends_on {
            match id_to_idx.get(dep_id.as_str()) {
                Some(&idx) => step_deps.push(idx),
                None => bail!(
                    "Step '{}' depends on unknown step '{}'",
                    step.id,
                    dep_id
                ),
            }
        }
        deps.push(step_deps);
    }

    // Cycle detection via DFS coloring
    detect_cycle(flow, &deps)?;

    Ok(ValidatedFlow { deps })
}

/// DFS coloring: White=0, Gray=1, Black=2. Gray→Gray edge = cycle.
fn detect_cycle(flow: &FlowDef, deps: &[Vec<usize>]) -> Result<()> {
    let n = flow.steps.len();
    let mut color = vec![0u8; n]; // 0=white, 1=gray, 2=black
    let mut path: Vec<usize> = Vec::new();

    // Build adjacency list (step → steps that depend on it)
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (step, step_deps) in deps.iter().enumerate() {
        for &dep in step_deps {
            adj[dep].push(step);
        }
    }

    for start in 0..n {
        if color[start] == 0 {
            dfs_visit(start, &adj, &mut color, &mut path, flow)?;
        }
    }

    Ok(())
}

fn dfs_visit(
    node: usize,
    adj: &[Vec<usize>],
    color: &mut [u8],
    path: &mut Vec<usize>,
    flow: &FlowDef,
) -> Result<()> {
    color[node] = 1; // gray
    path.push(node);

    for &next in &adj[node] {
        if color[next] == 1 {
            // Found cycle — build readable error
            let cycle_start = path.iter().position(|&x| x == next).unwrap();
            let cycle_names: Vec<&str> = path[cycle_start..]
                .iter()
                .map(|&i| flow.steps[i].id.as_str())
                .collect();
            bail!(
                "Cycle detected: {} → {}",
                cycle_names.join(" → "),
                flow.steps[next].id
            );
        }
        if color[next] == 0 {
            dfs_visit(next, adj, color, path, flow)?;
        }
    }

    path.pop();
    color[node] = 2; // black
    Ok(())
}
