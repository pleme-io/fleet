//! `fleet warm-inputs` — make every flake input present locally, sourcing from
//! a fleet builder when the upstream refuses us.
//!
//! # Why this is a verb and not a retry
//!
//! Measured 2026-08-17 on cid: a `nix flake update` moved
//! `fenix/rust-analyzer-src`, and GitHub's archive endpoint 429'd the new rev
//! **while core API quota showed 4653/5000 remaining** — a per-egress-IP
//! throttle on archive generation, unaffected by holding a valid token. Two
//! full rebuilds died on it, each after nix had already backed off 143923 ms
//! and exhausted its own attempts. The same prefetch on `rio` succeeded
//! instantly, and `nix copy --from ssh://rio` brought the path over in 43s.
//!
//! So the remedy is not more waiting, and it is not pinning the input back
//! (which the fleet gate's own error text forbids). It is to fetch from a host
//! the throttle does not apply to, and to accept the result only if its hash
//! equals the pin already in `flake.lock`.
//!
//! # Scope, deliberately capped
//!
//! The classification this leans on parses nix's stderr PROSE
//! ([`crate::fetch_recovery::classify_fetch_failure`]), which is a leak, not a
//! design: a typed builder surface would return a typed error and make the
//! parse unnecessary. That surface is the naturalize-into-sui work, and this
//! module is the honest floor until it lands. The operator VERB survives that
//! change — only these internals get replaced — which is why it is worth
//! having now rather than a throwaway.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

use super::utils::{log_info, log_success, log_warning};
use crate::fetch_recovery::{
    classify_fetch_failure, parse_build_machines, parse_prefetch_json, pinned_nar_hash,
    FetchFailure, RecoveryPlan, WarmOutcome,
};

/// How many recover-then-retry rounds to run before giving up.
///
/// Bounded on purpose (★★ reconciler liveness: bound every tick): each round
/// must make progress by warming one input, so an unbounded loop against a
/// permanently-throttled upstream would spin instead of reporting.
const MAX_ROUNDS: usize = 8;

const MACHINES_PATH: &str = "/etc/nix/machines";

pub fn warm_inputs(flake_root: &Path, dry_run: bool) -> Result<()> {
    let lock = std::fs::read_to_string(flake_root.join("flake.lock"))
        .context("no flake.lock here — run this from a flake root")?;
    let machines = std::fs::read_to_string(MACHINES_PATH).unwrap_or_default();
    let builders = parse_build_machines(&machines);

    if builders.is_empty() {
        log_warning(&format!(
            "no ssh builders in {MACHINES_PATH} — a throttled input cannot be \
             recovered from another egress on this host"
        ));
    } else {
        let names: Vec<&str> = builders.iter().map(|b| b.host.as_str()).collect();
        log_info(&format!("fetch sources, best egress first: {}", names.join(", ")));
    }

    for round in 1..=MAX_ROUNDS {
        match attempt(flake_root, &lock, &builders, dry_run)? {
            WarmOutcome::AlreadyWarm => {
                log_success("every flake input is present locally");
                return Ok(());
            }
            WarmOutcome::Recovered {
                input,
                builder,
                store_path,
            } => {
                log_success(&format!(
                    "round {round}: {input} recovered from {builder} (hash matches flake.lock) \
                     -> {store_path}"
                ));
                // Loop: a second throttled input is common after a lock bump,
                // and each round warms exactly one.
            }
            WarmOutcome::Declined { failure, reason } => {
                anyhow::bail!(
                    "cannot warm {}: {}\n  url: {}",
                    failure.input(),
                    reason,
                    match &failure {
                        FetchFailure::Throttled { url, .. }
                        | FetchFailure::Unauthorized { url, .. } => url.clone(),
                    }
                );
            }
            WarmOutcome::NotAFetchProblem { stderr_head } => {
                // Do NOT dress a build/eval error as a fetch problem; say so.
                anyhow::bail!(
                    "the flake failed for a reason that is not a source fetch — \
                     nothing to warm:\n{stderr_head}"
                );
            }
        }
    }
    anyhow::bail!(
        "gave up after {MAX_ROUNDS} rounds — inputs are still not all local. \
         Each round warms one input, so this means more than {MAX_ROUNDS} \
         inputs are unfetchable, or one is failing repeatedly."
    )
}

/// One round: try locally, and if a source fetch is what failed, recover it.
fn attempt(
    flake_root: &Path,
    lock: &str,
    builders: &[crate::fetch_recovery::Builder],
    dry_run: bool,
) -> Result<WarmOutcome> {
    let out = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "flake",
            "archive",
            "--json",
        ])
        .current_dir(flake_root)
        .output()
        .context("failed to launch `nix flake archive`")?;

    if out.status.success() {
        return Ok(WarmOutcome::AlreadyWarm);
    }

    let stderr = String::from_utf8_lossy(&out.stderr);
    let Some(failure) = classify_fetch_failure(&stderr) else {
        return Ok(WarmOutcome::NotAFetchProblem {
            stderr_head: stderr.lines().take(12).collect::<Vec<_>>().join("\n"),
        });
    };

    let input = failure.input().clone();
    let expected = pinned_nar_hash(lock, &input);

    // Try each builder in turn. A builder sharing our egress is last, and if it
    // is throttled too its prefetch simply fails and we move on — correctness
    // never rests on the egress guess.
    let mut last_decline = None;
    for builder in builders {
        let plan = match RecoveryPlan::for_failure(
            &failure,
            Some(builder.host.as_str()),
            expected.as_deref(),
        ) {
            Ok(p) => p,
            Err(reason) => {
                last_decline = Some(reason);
                break; // NotAThrottle / NoPinnedHash are builder-independent.
            }
        };

        if dry_run {
            log_info(&format!(
                "would run on {}: {}",
                plan.builder,
                plan.prefetch_argv().join(" ")
            ));
            log_info(&format!(
                "would then: {}",
                plan.copy_argv("<storePath>").join(" ")
            ));
            return Ok(WarmOutcome::AlreadyWarm);
        }

        log_info(&format!("{} throttled locally; asking {}", input, plan.builder));
        let Some(result) = prefetch_on(&plan) else {
            log_warning(&format!(
                "{} could not fetch {} either — trying the next source",
                plan.builder, input
            ));
            continue;
        };

        // The check that makes an alternate source safe rather than trusted.
        plan.verify(&result.nar_hash)
            .map_err(|m| anyhow::anyhow!("{m}"))?;

        let copy = plan.copy_argv(&result.store_path);
        let status = Command::new(&copy[0])
            .args(&copy[1..])
            .status()
            .context("failed to launch `nix copy`")?;
        if !status.success() {
            log_warning(&format!(
                "nix copy from {} failed — trying the next source",
                plan.builder
            ));
            continue;
        }

        return Ok(WarmOutcome::Recovered {
            input,
            builder: plan.builder,
            store_path: result.store_path,
        });
    }

    Ok(WarmOutcome::Declined {
        failure,
        reason: last_decline.unwrap_or(crate::fetch_recovery::DeclineReason::NoBuilder),
    })
}

/// Run the prefetch on the builder over ssh, returning its parsed result.
fn prefetch_on(plan: &RecoveryPlan) -> Option<crate::fetch_recovery::PrefetchResult> {
    let argv = plan.prefetch_argv();
    let out = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg(&plan.builder)
        .arg(argv.join(" "))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_prefetch_json(&String::from_utf8_lossy(&out.stdout))
}
