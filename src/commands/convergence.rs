//! `fleet convergence` — the one typed answer to "is this node at HEAD, and
//! when did it last reconcile?"
//!
//! ── ★ WHY IT READS FILES AND DOES NOT REACH ANY NODE ────────────────────
//! The obvious design is to fan out over SSH and ask each host. Two facts
//! kill it, and both were measured rather than imagined:
//!
//!   1. A node is not always reachable BY US and is still converging fine.
//!      ryn moves onto a customer VPN and drops off tailscale; `fleet
//!      status` fans out over SSH with GNU-only `grep -oP`, so it cannot
//!      report a Darwin node at all. An observer that must reach IN reports
//!      "unknown" for a healthy machine and calls it an outage.
//!   2. The interesting case is a node whose reconciler is DEAD, and a dead
//!      process answers no query. Anything socket-based — kanshou included —
//!      goes silent exactly when the news matters, because the socket dies
//!      with the process it was reporting on.
//!
//! So the reconciler PUBLISHES and the reader consumes what survived: the
//! heartbeat (rewritten every tick, so its age is the liveness signal) and
//! the receipt chain (what was last activated). Both outlive the daemon.
//! Pull-mode already made reachability irrelevant to CONVERGING; this makes
//! it irrelevant to OBSERVING, which is the same property applied twice.
//!
//! The emitted document is the MCP payload. A server wrapping this is a
//! transport, not a second source of truth — there is exactly one place
//! that decides what "converged" means, and it is [`super::rebuild`]'s
//! evidence-gated verdict.

use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// One node's convergence document. Every field is either MEASURED or
/// `None` — there is no arm that reports a default as though it were read.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct NodeConvergence {
    /// The node this document describes.
    pub node: String,
    /// Which reconciler published it.
    pub engine: &'static str,
    /// The verdict, as a word an operator and a monitor can both branch on.
    pub verdict: &'static str,
    /// Why, in one line. Present for every non-converged verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Rev the running system was built from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployed_rev: Option<String>,
    /// Branch HEAD as the reconciler last observed it. `None` when the last
    /// tick never got far enough to look.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_rev: Option<String>,
    /// Seconds since the last tick. THE liveness number: an activation
    /// timestamp cannot serve, because a converged loop activates nothing
    /// for weeks and so looks identical to a dead one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_tick_age_secs: Option<u64>,
    /// What that tick did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_tick_outcome: Option<String>,
    /// Consecutive failed ticks, from the receipt chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consecutive_failures: Option<u64>,
}

/// Verdict vocabulary. Deliberately small and deliberately including
/// `unknown`: a reader that cannot tell must say so, never round to healthy.
pub const CONVERGED: &str = "converged";
pub const BEHIND: &str = "behind";
pub const STOPPED: &str = "stopped";
pub const FAILING: &str = "failing";
pub const UNKNOWN: &str = "unknown";
pub const NOT_ENROLLED: &str = "notEnrolled";

/// Same budget as `fleet rebuild`'s verdict, `sentinela status --gate` and
/// seki's `gitops` segment. Four surfaces, one definition of "stale" — if
/// they disagreed, an operator would learn to trust whichever was quietest.
const STALE_AFTER_POLLS: u64 = 3;

/// Decide a verdict from already-read values. Pure, so every arm is
/// provable without a node, a clock, or a filesystem.
#[must_use]
pub fn classify(
    deployed: Option<&str>,
    head: Option<&str>,
    tick_age_secs: Option<u64>,
    poll_seconds: Option<u64>,
    failures: Option<u64>,
) -> (&'static str, Option<String>) {
    // Two DIFFERENT unknowns, and saying the wrong one is the same defect
    // this whole surface exists to remove: an earlier draft reported "no
    // heartbeat published" while printing that heartbeat's age two lines
    // later, which is a diagnostic that contradicts its own evidence.
    let (age, poll) = match (tick_age_secs, poll_seconds) {
        (Some(a), Some(p)) => (a, p),
        (None, _) => {
            return (
                UNKNOWN,
                Some("no heartbeat published — liveness cannot be determined".to_owned()),
            );
        }
        (Some(a), None) => {
            return (
                UNKNOWN,
                Some(format!(
                    "heartbeat is {a}s old but the reconciler published no poll interval, \
                     so staleness cannot be judged"
                )),
            );
        }
    };
    if age > STALE_AFTER_POLLS * poll {
        return (
            STOPPED,
            Some(format!(
                "no tick for {age}s against a {poll}s poll — the loop is stopped, not idle"
            )),
        );
    }
    if let Some(n) = failures.filter(|n| *n > 0) {
        return (FAILING, Some(format!("{n} consecutive failed ticks")));
    }
    match (deployed, head) {
        (Some(d), Some(h)) if d != h => (
            BEHIND,
            Some(format!(
                "deployed {} but branch HEAD is {}",
                short(d),
                short(h)
            )),
        ),
        // Alive, not failing, and demonstrably at HEAD. This is the ONLY
        // path to `converged`, and it requires the head probe — absence of
        // bad news is not evidence of convergence.
        (Some(_), Some(_)) => (CONVERGED, None),
        _ => (
            UNKNOWN,
            Some("the reconciler published no branch HEAD; cannot prove convergence".to_owned()),
        ),
    }
}

fn short(rev: &str) -> String {
    rev.get(..7).unwrap_or(rev).to_owned()
}

/// Build this node's document from the reconciler's published state.
pub fn local(state_dir: &Path, node: String, now_epoch: u64) -> NodeConvergence {
    if !state_dir.is_dir() {
        return NodeConvergence {
            node,
            engine: "none",
            verdict: NOT_ENROLLED,
            reason: Some("no reconciler state directory on this host".to_owned()),
            deployed_rev: None,
            head_rev: None,
            last_tick_age_secs: None,
            last_tick_outcome: None,
            consecutive_failures: None,
        };
    }
    let beat = read_json(&state_dir.join("heartbeat.json"));
    let tick_at_ms = beat.as_ref().and_then(|v| v["at_unix_ms"].as_u64());
    let outcome = beat
        .as_ref()
        .and_then(|v| v["outcome"].as_str())
        .map(str::to_owned);
    let head_rev = beat
        .as_ref()
        .and_then(|v| v["head_rev"].as_str())
        .map(str::to_owned);
    let age = tick_at_ms.map(|ms| now_epoch.saturating_sub(ms / 1000));

    let (deployed_rev, failures) = read_chain_tail(&state_dir.join("receipts.json"));
    // The poll interval is published by the daemon alongside its config; a
    // reader that guessed one would manufacture a staleness verdict out of
    // a number nobody wrote down.
    let poll = beat.as_ref().and_then(|v| v["poll_seconds"].as_u64());

    let (verdict, reason) = classify(
        deployed_rev.as_deref(),
        head_rev.as_deref(),
        age,
        poll,
        failures,
    );
    NodeConvergence {
        node,
        engine: "sentinela",
        verdict,
        reason,
        deployed_rev,
        head_rev,
        last_tick_age_secs: age,
        last_tick_outcome: outcome,
        consecutive_failures: failures,
    }
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// `(last_activated_rev, consecutive_failures)` from the chain's TAIL.
///
/// Tail-read on purpose: the chain reached 31 MB on ryn, and this runs on
/// the `fleet rebuild` path where parsing it whole is a real cost paid for
/// two fields near the end.
fn read_chain_tail(path: &Path) -> (Option<String>, Option<u64>) {
    const TAIL: u64 = 64 * 1024;
    let Ok(meta) = std::fs::metadata(path) else {
        return (None, None);
    };
    let raw = if meta.len() > TAIL {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let Ok(mut f) = std::fs::File::open(path) else {
            return (None, None);
        };
        if f.seek(SeekFrom::End(-(TAIL as i64))).is_err() {
            return (None, None);
        }
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_err() {
            return (None, None);
        }
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return (None, None),
        }
    };
    // Line-oriented rather than document-parsed: it survives a tail cut
    // mid-document, which a YAML parser would not.
    let mut streak = 0u64;
    let mut activated: Option<String> = None;
    let mut pending_rev: Option<String> = None;
    for line in raw.lines().rev() {
        let t = line.trim();
        if let Some(k) = t.strip_prefix("kind:") {
            if k.trim() == "activated" {
                activated = pending_rev.clone();
                break;
            }
            streak += 1;
        } else if let Some(r) = t.strip_prefix("rev:") {
            pending_rev = Some(r.trim().to_owned());
        }
    }
    (activated, Some(streak))
}

/// Where the Darwin reconciler publishes. Matches `pleme.gitops.stateDir`.
fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/log/pleme-gitops")
}

pub fn convergence(json: bool) -> Result<()> {
    let node = super::utils::run_command_output(std::process::Command::new("hostname").arg("-s"))
        .unwrap_or_else(|_| "unknown".to_owned());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let doc = local(&default_state_dir(), node, now);

    if json {
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }
    println!("node      : {}", doc.node);
    println!("engine    : {}", doc.engine);
    println!("verdict   : {}", doc.verdict);
    if let Some(r) = &doc.reason {
        println!("reason    : {r}");
    }
    if let Some(d) = &doc.deployed_rev {
        println!("deployed  : {}", short(d));
    }
    if let Some(h) = &doc.head_rev {
        println!("branch    : {}", short(h));
    }
    if let Some(a) = doc.last_tick_age_secs {
        println!(
            "last tick : {a}s ago ({})",
            doc.last_tick_outcome.as_deref().unwrap_or("?")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLL: u64 = 60;
    const REV: &str = "7176c2181d217e1beec7aa3e5244f620ac26dca7";
    const HEAD: &str = "588cf40f6bc7b603943741a2abd074cfaf2142cd";

    /// cid, 2026-08-02: silent 16.7h against a 60s poll while every other
    /// surface reported it healthy.
    #[test]
    fn a_stopped_loop_is_stopped_even_with_a_clean_chain() {
        let (v, why) = classify(Some(REV), Some(REV), Some(60177), Some(POLL), Some(0));
        assert_eq!(v, STOPPED);
        assert!(why.unwrap().contains("stopped, not idle"));
    }

    #[test]
    fn a_live_loop_off_head_is_behind() {
        let (v, why) = classify(Some(REV), Some(HEAD), Some(30), Some(POLL), Some(0));
        assert_eq!(v, BEHIND);
        let why = why.unwrap();
        assert!(why.contains("7176c21") && why.contains("588cf40"), "{why}");
    }

    /// The ryn shape: alive, at HEAD by rev, but every tick failing.
    /// Failures outrank the rev comparison — a loop that cannot build is
    /// not converged no matter what it last activated.
    #[test]
    fn failures_outrank_a_matching_rev() {
        let (v, why) = classify(Some(REV), Some(REV), Some(30), Some(POLL), Some(4136));
        assert_eq!(v, FAILING);
        assert!(why.unwrap().contains("4136"));
    }

    /// ★ The rule every surface in this fleet now shares: absent evidence
    /// is `unknown`, never `converged`.
    #[test]
    fn absent_evidence_is_unknown_never_converged() {
        assert_eq!(
            classify(Some(REV), Some(REV), None, Some(POLL), Some(0)).0,
            UNKNOWN
        );
        let (v, why) = classify(Some(REV), Some(REV), Some(30), None, Some(0));
        assert_eq!(v, UNKNOWN);
        // ...and it must say WHICH unknown. Reporting "no heartbeat" here
        // would contradict the age this very document prints.
        assert!(why.unwrap().contains("no poll interval"));
        // Alive and not failing, but the daemon published no branch HEAD:
        // we cannot prove it is at HEAD, so we do not claim it.
        assert_eq!(
            classify(Some(REV), None, Some(30), Some(POLL), Some(0)).0,
            UNKNOWN
        );
    }

    /// The one path to `converged`, so the vocabulary is not write-only.
    #[test]
    fn alive_at_head_and_not_failing_is_converged() {
        let (v, why) = classify(Some(REV), Some(REV), Some(30), Some(POLL), Some(0));
        assert_eq!(v, CONVERGED);
        assert!(why.is_none(), "a converged node needs no excuse");
    }

    /// A host with no reconciler is NOT a broken one. Conflating them makes
    /// every laptop in the fleet look like an outage.
    #[test]
    fn a_host_with_no_state_dir_is_not_enrolled_not_broken() {
        let doc = local(
            Path::new("/nonexistent/pleme-gitops"),
            "laptop".to_owned(),
            0,
        );
        assert_eq!(doc.verdict, NOT_ENROLLED);
        assert_eq!(doc.engine, "none");
    }

    /// The staleness boundary, pinned both sides — shared verbatim with
    /// three other surfaces.
    #[test]
    fn the_staleness_boundary_is_three_poll_intervals() {
        let budget = STALE_AFTER_POLLS * POLL;
        assert_eq!(
            classify(Some(REV), Some(REV), Some(budget), Some(POLL), Some(0)).0,
            CONVERGED
        );
        assert_eq!(
            classify(Some(REV), Some(REV), Some(budget + 1), Some(POLL), Some(0)).0,
            STOPPED
        );
    }
}
