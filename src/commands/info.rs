use anyhow::Result;
use colored::Colorize;

use crate::registry::NodeRegistry;

pub fn run(registry: &NodeRegistry, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(registry)?);
        return Ok(());
    }

    // Table output
    println!(
        "{:<12} {:<24} {:<8} {:<16} {}",
        "NAME".bold(),
        "HOSTNAME".bold(),
        "USER".bold(),
        "SYSTEM".bold(),
        "TAGS".bold(),
    );
    println!("{}", "-".repeat(80));

    let mut entries: Vec<_> = registry.iter().collect();
    entries.sort_by_key(|(name, _)| (*name).clone());

    for (name, node) in entries {
        println!(
            "{:<12} {:<24} {:<8} {:<16} {}",
            name,
            node.hostname,
            node.ssh_user,
            node.system,
            node.tags.join(", "),
        );
    }

    Ok(())
}
