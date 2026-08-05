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
use serde::{Deserialize, Serialize};
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
/// Alive on schedule and doing no convergence work — the state that used to
/// hide inside `unknown`. The rule, and the rio incident that produced it,
/// are on [`classify`].
pub const INEFFECTIVE: &str = "ineffective";

/// Whether the pulse reports a tick that FINISHED or one still running.
///
/// Mirrors sentinela's `Phase`, which its own author documents as *"a TYPE,
/// not a sentinel value in `outcome`: consumers `match` on it"*. This reader
/// did not match on it — it inferred in-flight-ness from the outcome STRING
/// against [`IN_FLIGHT_OUTCOMES`], a list whose only member sentinela
/// actually publishes is `building`. Reading the typed field is both correct
/// today and durable against a new pending verb.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TickPhase {
    /// The tick finished; `outcome` names what it did.
    ///
    /// The default on purpose, and for sentinela's own stated reason: a
    /// heartbeat written before this field existed reported a completed
    /// tick, because a completed tick was the only kind of pulse there was.
    #[default]
    Resolved,
    /// The tick is inside a build that had not returned when the pulse was
    /// written; `outcome` names the PENDING action, not a completed one.
    InFlight,
    /// A phase string this reader does not know, from a newer sentinela.
    ///
    /// Kept as a THIRD case rather than folded into `Resolved`: the
    /// ineffective rule below turns on "the tick finished", and a phase we
    /// cannot read is not evidence that it did. Folding it into `Resolved`
    /// would let an unknown-but-benign future phase be reported as a broken
    /// loop, which is the cry-wolf error wearing a new hat.
    Unrecognised,
}

impl TickPhase {
    /// Map the published string, tolerating both absence and a value from a
    /// newer sentinela. Deliberately NOT `#[serde(other)]`: serde only
    /// permits that on internally/adjacently tagged enums, so a plain
    /// string-valued enum would hard-fail the WHOLE document on an
    /// unrecognised phase — turning a degraded node into an unreadable one.
    fn from_wire(raw: Option<&str>) -> Self {
        match raw {
            None | Some("resolved") => Self::Resolved,
            Some("in_flight") => Self::InFlight,
            Some(_) => Self::Unrecognised,
        }
    }
}

/// The heartbeat as sentinela publishes it, mirrored rather than imported.
///
/// EVERY field is optional and defaulted, which is not tidiness: this reader
/// must read a pulse written by whatever sentinela is on the node, including
/// one older than this binary. A reader that hard-fails on a missing field
/// reports a degraded node as an unreadable one — strictly worse than the
/// degradation it exists to surface.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Heartbeat {
    /// When the tick completed, unix-millis. `None` only on a malformed pulse.
    at_unix_ms: Option<u64>,
    /// The `TickOutcome` variant name — what the loop did (or, in flight,
    /// what it is doing).
    outcome: Option<String>,
    /// Raw phase string; interpreted by [`TickPhase::from_wire`] so an
    /// unrecognised value degrades this one field instead of the document.
    phase: Option<String>,
    /// Branch HEAD as THIS tick observed it. `None` on exactly the three
    /// sentinela outcomes that never obtained one — see the ineffective rule.
    head_rev: Option<String>,
    /// The loop's poll interval. Without it staleness cannot be judged.
    poll_seconds: Option<u64>,
}

/// Same budget as `fleet rebuild`'s verdict, `sentinela status --gate` and
/// seki's `gitops` segment. Four surfaces, one definition of "stale" — if
/// they disagreed, an operator would learn to trust whichever was quietest.
const STALE_AFTER_POLLS: u64 = 3;

/// Outcomes that mean a tick is STILL RUNNING rather than finished.
///
/// ── ★ A LONG TICK IS NOT A STOPPED LOOP ─────────────────────────────────
/// Measured on cid, 2026-08-03: sentinela alive (pid 15215), last tick
/// `building` 273s earlier, poll 60s — and this function said
/// "the loop is stopped, not idle". It was building, which is the loop
/// working. A nix build routinely exceeds 3 polls; the heartbeat cannot
/// be written again until the tick that is doing the building returns.
///
/// This is the design's own failure mode, inverted. The point of the
/// verdict was that absent evidence is never rounded to healthy; a rule
/// that cries `stopped` through every legitimate build teaches the
/// operator to ignore it, which costs the same as rounding up.
///
/// So staleness is judged against what the reconciler said it was DOING:
/// a terminal outcome must be followed by another tick within the poll
/// budget; a non-terminal one is allowed the build budget below.
const IN_FLIGHT_OUTCOMES: &[&str] = &["building", "applying", "fetching", "switching"];

/// How long a tick may stay in a non-terminal outcome before it is a hang
/// rather than a build.
///
/// 45 minutes: chosen to exceed a cold full-system rebuild on the slowest
/// enrolled node, because the cost of the two errors is asymmetric — a
/// false `stopped` is noise the operator learns to filter, a late `stopped`
/// costs the difference between 45 minutes and however long until someone
/// looks. Deliberately NOT derived from the poll interval: how long a build
/// takes has nothing to do with how often the loop wakes.
const IN_FLIGHT_BUDGET_SECS: u64 = 45 * 60;

/// Decide a verdict from already-read values. Pure, so every arm is
/// provable without a node, a clock, or a filesystem.
///
/// ── ★ A FRESH PULSE PROVES ALIVE, NOT EFFECTIVE ─────────────────────────
/// Measured on rio, 2026-08-05: sentinela published
/// `{"outcome":"probeError","phase":"resolved","head_rev":null,
/// "poll_seconds":60}` every 60 seconds for over an hour. systemd said
/// `active (running)`, `NRestarts=0`, `systemctl --failed` was empty, and
/// the pulse was never once stale. The node had not reconciled a single
/// time — it had never even resolved the branch head.
///
/// This function did not round that up to `converged` (the rev comparison
/// requires a head, and there was none). It returned `unknown` — *"the
/// reconciler published no branch HEAD; cannot prove convergence"* — which
/// is a MISSING-EVIDENCE sentence for a node whose evidence was present and
/// damning. `unknown` is reserved for "we cannot tell"; a loop that told us,
/// on schedule, that it did nothing is a thing we CAN tell.
///
/// The failure had no other detector either. `failing` is sourced from the
/// receipt chain, and `probeError`/`unresolvable` carry no `Rev`, so they
/// structurally cannot write a receipt — an infinitely-probe-erroring loop
/// is invisible to the chain by construction, not by accident.
///
/// So the rule, and it is derived from sentinela's type rather than from a
/// list of verbs: `TickOutcome::observed_head` returns `None` for exactly
/// `CoolingDown`, `Unresolvable` and `ProbeError`. A FINISHED tick with no
/// head is therefore, exhaustively, a tick that did no convergence work —
/// and a future sentinela verb of the same shape is caught the day it ships,
/// with no edit here.
#[must_use]
pub fn classify(
    deployed: Option<&str>,
    head: Option<&str>,
    tick_age_secs: Option<u64>,
    poll_seconds: Option<u64>,
    failures: Option<u64>,
    last_outcome: Option<&str>,
    phase: TickPhase,
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
    // What the reconciler said it was doing decides which budget applies.
    // The typed phase is authoritative; the outcome-name list stays as a
    // fallback for a pulse from a sentinela older than the `phase` field,
    // which is the one case where the string is all there is.
    let in_flight = phase == TickPhase::InFlight
        || last_outcome.is_some_and(|o| IN_FLIGHT_OUTCOMES.contains(&o));
    let budget = if in_flight {
        IN_FLIGHT_BUDGET_SECS
    } else {
        STALE_AFTER_POLLS * poll
    };
    if age > budget {
        return (
            STOPPED,
            Some(if in_flight {
                format!(
                    "tick has been `{}` for {age}s, past the {IN_FLIGHT_BUDGET_SECS}s build                      budget — a build this long is a hang, not progress",
                    last_outcome.unwrap_or("?")
                )
            } else {
                format!("no tick for {age}s against a {poll}s poll — the loop is stopped, not idle")
            }),
        );
    }
    // An in-flight tick is WORKING, and must not be reported as converged
    // just because nothing has failed yet: the build it is running may be
    // the one that moves the node to HEAD. Saying `converged` here would
    // claim a result that has not happened.
    if in_flight {
        return (
            UNKNOWN,
            Some(format!(
                "tick in progress (`{}`, {age}s) — the outcome is not known yet",
                last_outcome.unwrap_or("?")
            )),
        );
    }
    // ── ★ THE MIDDLE STATE: ALIVE, ON SCHEDULE, AND DOING NOTHING ───────
    // Ordered BEFORE `failing` on purpose. `failing` means the loop got far
    // enough to attempt a build or a switch and wrote a receipt about it;
    // this means it never got that far at all, which is the more fundamental
    // breakage and the one with no other detector. Nothing is lost by the
    // ordering — the streak, when the chain has one, is folded into the
    // reason below, so one verdict carries both facts.
    //
    // Requires `Resolved` specifically, not `!= InFlight`: an unrecognised
    // phase is not evidence the tick finished, and claiming a broken loop on
    // a phase we cannot read would be the cry-wolf error. That case falls
    // through to `unknown`, which is what it honestly is.
    if phase == TickPhase::Resolved && head.is_none() {
        let verb = last_outcome.unwrap_or("?");
        let history = match deployed {
            None => "and has never activated a rev".to_owned(),
            Some(d) => format!("having last activated {}", short(d)),
        };
        let streak = match failures.filter(|n| *n > 0) {
            Some(n) => format!(" · {n} consecutive failed receipts"),
            None => String::new(),
        };
        return (
            INEFFECTIVE,
            Some(format!(
                "tick finished `{verb}` without resolving a branch HEAD: the loop is alive \
                 ({age}s ago against a {poll}s poll) but did no convergence work, {history}\
                 {streak}. Evidence covers the LAST tick only — the pulse carries no \
                 ineffective-since stamp, so how long this has run cannot be read from it"
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
        // A head, but nothing ever activated: enrolled and not yet arrived.
        // Distinct from `ineffective` — this loop IS resolving heads, so it
        // is working; it simply has no activation to show yet.
        (None, Some(h)) => (
            UNKNOWN,
            Some(format!(
                "the reconciler observed branch HEAD {} but the receipt chain records no \
                 activation; this node has never deployed",
                short(h)
            )),
        ),
        // Head-less and the phase did not say the tick finished, so the
        // ineffective rule above deliberately declined to fire. We cannot
        // tell a still-running tick from a fruitless one: say so.
        _ => (
            UNKNOWN,
            Some(format!(
                "the reconciler published no branch HEAD, and this reader does not recognise \
                 the phase it published, so whether the tick even finished cannot be \
                 determined (outcome `{}`)",
                last_outcome.unwrap_or("?")
            )),
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
    let beat = read_heartbeat(&state_dir.join("heartbeat.json"));
    let age = beat
        .at_unix_ms
        .map(|ms| now_epoch.saturating_sub(ms / 1000));
    let phase = TickPhase::from_wire(beat.phase.as_deref());

    let (deployed_rev, failures) = read_chain_tail(&state_dir.join("receipts.json"));

    let (verdict, reason) = classify(
        deployed_rev.as_deref(),
        beat.head_rev.as_deref(),
        age,
        // The poll interval is published by the daemon alongside its config;
        // a reader that guessed one would manufacture a staleness verdict
        // out of a number nobody wrote down.
        beat.poll_seconds,
        failures,
        beat.outcome.as_deref(),
        phase,
    );
    let head_rev = beat.head_rev;
    let outcome = beat.outcome;
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

/// Read the pulse, degrading to an all-`None` [`Heartbeat`] rather than
/// erroring. An absent or corrupt file is itself evidence — it lands as
/// "no heartbeat published", which [`classify`] already reports as `unknown`
/// with the correct sentence.
fn read_heartbeat(path: &Path) -> Heartbeat {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
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

/// Where the reconciler publishes. Matches `pleme.gitops.stateDir`.
/// Public so the MCP tool reads the same path rather than repeating it —
/// two spellings of one location is how a reader ends up reporting on a
/// directory nothing writes to.
pub const DEFAULT_STATE_DIR: &str = "/var/log/pleme-gitops";

fn default_state_dir() -> PathBuf {
    PathBuf::from(DEFAULT_STATE_DIR)
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

    /// A finished tick, which is what every pre-`phase` heartbeat reported
    /// and what most of these cases are about. Spelled out so the ONE case
    /// that turns on the phase reads as deliberate rather than incidental.
    const DONE: TickPhase = TickPhase::Resolved;

    /// cid, 2026-08-02: silent 16.7h against a 60s poll while every other
    /// surface reported it healthy.
    #[test]
    fn a_stopped_loop_is_stopped_even_with_a_clean_chain() {
        let (v, why) = classify(
            Some(REV),
            Some(REV),
            Some(60177),
            Some(POLL),
            Some(0),
            Some("converged"),
            DONE,
        );
        assert_eq!(v, STOPPED);
        assert!(why.unwrap().contains("stopped, not idle"));
    }

    #[test]
    fn a_live_loop_off_head_is_behind() {
        let (v, why) = classify(
            Some(REV),
            Some(HEAD),
            Some(30),
            Some(POLL),
            Some(0),
            Some("converged"),
            DONE,
        );
        assert_eq!(v, BEHIND);
        let why = why.unwrap();
        assert!(why.contains("7176c21") && why.contains("588cf40"), "{why}");
    }

    /// The ryn shape: alive, at HEAD by rev, but every tick failing.
    /// Failures outrank the rev comparison — a loop that cannot build is
    /// not converged no matter what it last activated.
    #[test]
    fn failures_outrank_a_matching_rev() {
        let (v, why) = classify(
            Some(REV),
            Some(REV),
            Some(30),
            Some(POLL),
            Some(4136),
            Some("converged"),
            DONE,
        );
        assert_eq!(v, FAILING);
        assert!(why.unwrap().contains("4136"));
    }

    /// ★ The rule every surface in this fleet now shares: absent evidence
    /// is `unknown`, never `converged`.
    #[test]
    fn absent_evidence_is_unknown_never_converged() {
        assert_eq!(
            classify(
                Some(REV),
                Some(REV),
                None,
                Some(POLL),
                Some(0),
                Some("converged"),
                DONE
            )
            .0,
            UNKNOWN
        );
        let (v, why) = classify(
            Some(REV),
            Some(REV),
            Some(30),
            None,
            Some(0),
            Some("converged"),
            DONE,
        );
        assert_eq!(v, UNKNOWN);
        // ...and it must say WHICH unknown. Reporting "no heartbeat" here
        // would contradict the age this very document prints.
        assert!(why.unwrap().contains("no poll interval"));
    }

    /// The one path to `converged`, so the vocabulary is not write-only.
    #[test]
    fn alive_at_head_and_not_failing_is_converged() {
        let (v, why) = classify(
            Some(REV),
            Some(REV),
            Some(30),
            Some(POLL),
            Some(0),
            Some("converged"),
            DONE,
        );
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
    /// ── ★ THE cid FALSE POSITIVE, 2026-08-03 ────────────────────────
    /// sentinela alive (pid 15215), last tick `building` 273s earlier
    /// against a 60s poll. The rule said "the loop is stopped, not idle".
    /// It was building — the loop working. Reported as `stopped`, this
    /// trains the operator to ignore the verdict, which costs exactly what
    /// rounding up to `converged` costs.
    #[test]
    fn a_build_running_past_three_polls_is_not_a_stopped_loop() {
        let (v, why) = classify(
            Some(REV),
            Some(HEAD),
            Some(273),
            Some(60),
            Some(0),
            Some("building"),
            DONE,
        );
        assert_ne!(v, STOPPED, "a running build is not a stopped loop: {why:?}");
    }

    /// ...and it is not `converged` either. The build in flight may be the
    /// one that moves this node to HEAD; claiming a result before it lands
    /// is the original defect wearing the opposite sign.
    #[test]
    fn a_tick_in_flight_is_unknown_never_converged() {
        let (v, why) = classify(
            Some(REV),
            Some(REV),
            Some(273),
            Some(60),
            Some(0),
            Some("building"),
            DONE,
        );
        assert_eq!(v, UNKNOWN, "in-flight must not claim a result: {why:?}");
        assert!(why.expect("reason").contains("in progress"));
    }

    /// The budget is not infinite — a build stuck for hours IS a hang, and
    /// the whole point is that it still gets caught.
    #[test]
    fn a_build_past_the_build_budget_is_stopped() {
        let (v, why) = classify(
            Some(REV),
            Some(HEAD),
            Some(IN_FLIGHT_BUDGET_SECS + 1),
            Some(60),
            Some(0),
            Some("building"),
            DONE,
        );
        assert_eq!(v, STOPPED, "a hung build must still be caught");
        assert!(why.expect("reason").contains("hang"));
    }

    /// The negative control: widening the budget must NOT weaken the
    /// ordinary case. A terminal outcome still goes stale at 3 polls, so
    /// the fix cannot be "stop reporting stopped".
    #[test]
    fn a_terminal_outcome_still_goes_stale_at_three_polls() {
        let (v, _) = classify(
            Some(REV),
            Some(HEAD),
            Some(STALE_AFTER_POLLS * POLL + 1),
            Some(POLL),
            Some(0),
            Some("converged"),
            DONE,
        );
        assert_eq!(v, STOPPED, "a finished tick that never recurred is stopped");
    }

    /// An unrecognised outcome gets the STRICT budget. A new sentinela
    /// verb this table does not know must not silently buy itself 45
    /// minutes of immunity — unknown means treat-as-terminal, which fails
    /// loud rather than quiet.
    #[test]
    fn an_unrecognised_outcome_gets_the_strict_budget() {
        let (v, _) = classify(
            Some(REV),
            Some(HEAD),
            Some(STALE_AFTER_POLLS * POLL + 1),
            Some(POLL),
            Some(0),
            Some("frobnicating"),
            DONE,
        );
        assert_eq!(v, STOPPED);
    }

    #[test]
    fn the_staleness_boundary_is_three_poll_intervals() {
        let budget = STALE_AFTER_POLLS * POLL;
        assert_eq!(
            classify(
                Some(REV),
                Some(REV),
                Some(budget),
                Some(POLL),
                Some(0),
                Some("converged"),
                DONE
            )
            .0,
            CONVERGED
        );
        assert_eq!(
            classify(
                Some(REV),
                Some(REV),
                Some(budget + 1),
                Some(POLL),
                Some(0),
                Some("converged"),
                DONE
            )
            .0,
            STOPPED
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // ★ THE INEFFECTIVE LOOP — rio, 2026-08-05
    //
    // A fresh heartbeat proves the loop is ALIVE. It says nothing about
    // whether the loop is EFFECTIVE, and for over an hour on rio those two
    // facts pointed opposite ways while every surface read the first one.
    // ────────────────────────────────────────────────────────────────────

    /// Write a state dir and read it back the way the MCP tool does, so
    /// these cases exercise the PARSER too — the rio pulse's `head_rev:
    /// null` and `phase: "resolved"` both have to survive deserialization
    /// for the verdict to be reached at all.
    fn read_back(name: &str, heartbeat: &str, receipts: Option<&str>, now: u64) -> NodeConvergence {
        let dir = std::env::temp_dir().join(format!("fleet-convergence-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp state dir");
        std::fs::write(dir.join("heartbeat.json"), heartbeat).expect("write heartbeat");
        if let Some(r) = receipts {
            std::fs::write(dir.join("receipts.json"), r).expect("write receipts");
        }
        let doc = local(&dir, "rio".to_owned(), now);
        let _ = std::fs::remove_dir_all(&dir);
        doc
    }

    /// rio's ACTUAL published pulse, verbatim but for the timestamp.
    fn rio_heartbeat(now: u64) -> String {
        format!(
            "{{\"at_unix_ms\":{},\"outcome\":\"probeError\",\"phase\":\"resolved\",\
             \"head_rev\":null,\"poll_seconds\":60}}",
            (now - 12) * 1000
        )
    }

    /// ★★ THE GATE. rio, 2026-08-05: this exact document, republished every
    /// 60s for over an hour, while systemd reported `active (running)`,
    /// `NRestarts=0` and an empty `systemctl --failed`. The node had not
    /// reconciled once — it had never resolved the branch head.
    ///
    /// Before this change the reader returned `unknown` with the sentence
    /// *"the reconciler published no branch HEAD; cannot prove
    /// convergence"* — true, but framed as MISSING evidence for a node
    /// whose evidence was present and damning, and indistinguishable from
    /// a node whose daemon had simply not published yet.
    #[test]
    fn rios_pulsing_loop_that_never_resolved_a_head_is_not_converged() {
        let now = 1_754_400_000;
        let doc = read_back("rio-live", &rio_heartbeat(now), None, now);

        // The load-bearing assertion: a fresh pulse is not a health claim.
        assert_ne!(
            doc.verdict, CONVERGED,
            "a loop that never resolved a head must never read as converged: {doc:?}"
        );
        // ...and it is not merely unreadable, either. Reporting `unknown`
        // here understates a KNOWN bad state, which is the round-DOWN error:
        // an operator filters ambiguity, so a real outage dressed as one
        // gets filtered with it.
        assert_eq!(doc.verdict, INEFFECTIVE, "{doc:?}");

        // The pulse was FRESH the whole time — that is the trap this closes.
        assert_eq!(doc.last_tick_age_secs, Some(12));
        assert_ne!(doc.verdict, STOPPED, "the daemon was alive and pulsing");

        // The document must carry the evidence, not just the verdict.
        assert_eq!(doc.last_tick_outcome.as_deref(), Some("probeError"));
        assert_eq!(doc.head_rev, None, "sentinela published head_rev: null");
        let why = doc.reason.expect("an ineffective verdict owes a reason");
        assert!(why.contains("probeError"), "{why}");
        assert!(why.contains("no convergence work"), "{why}");
        // Honest about its own reach: one pulse is one sample.
        assert!(why.contains("LAST tick only"), "{why}");
    }

    /// The two ineffective loops are NOT the same incident and must not
    /// read the same. A node that has never activated anything was never
    /// working; a node that activated an hour ago has REGRESSED. Same
    /// verdict, different reason — the operator needs the difference to
    /// know whether to look at bootstrap or at what just changed.
    ///
    /// Driven through [`classify`] rather than a chain file on purpose:
    /// `deployed` is the input that carries this distinction, and pinning
    /// it here keeps the case independent of how the receipt chain happens
    /// to be laid out on disk.
    #[test]
    fn never_activated_reads_differently_from_regressed() {
        let virgin = classify(
            None,
            None,
            Some(12),
            Some(POLL),
            Some(0),
            Some("probeError"),
            DONE,
        );
        assert_eq!(virgin.0, INEFFECTIVE);
        let why = virgin.1.expect("reason");
        assert!(why.contains("never activated a rev"), "{why}");

        let regressed = classify(
            Some(REV),
            None,
            Some(12),
            Some(POLL),
            Some(0),
            Some("probeError"),
            DONE,
        );
        assert_eq!(regressed.0, INEFFECTIVE);
        let why = regressed.1.expect("reason");
        assert!(why.contains("last activated 7176c21"), "{why}");
        assert!(
            !why.contains("never activated"),
            "a node that HAS deployed must not be described as never having: {why}"
        );
    }

    /// A failure streak from the chain is FOLDED IN rather than lost.
    /// `ineffective` outranks `failing` — never resolving a head is the
    /// more fundamental breakage, and the one with no other detector — so
    /// the streak has to travel in the reason or the ordering would cost
    /// the operator a fact.
    #[test]
    fn an_ineffective_verdict_still_carries_the_failure_streak() {
        let (v, why) = classify(
            Some(REV),
            None,
            Some(12),
            Some(POLL),
            Some(7),
            Some("probeError"),
            DONE,
        );
        assert_eq!(v, INEFFECTIVE);
        assert!(
            why.expect("reason")
                .contains("7 consecutive failed receipts"),
            "the streak must survive the precedence choice"
        );
    }

    /// The three states are three, not two. Same node, same reader, three
    /// pulses — the middle one is the whole point of this change and used
    /// to be indistinguishable from the third.
    #[test]
    fn alive_and_effective_alive_and_ineffective_and_dead_are_three_verdicts() {
        let working = classify(
            Some(REV),
            Some(REV),
            Some(30),
            Some(POLL),
            Some(0),
            Some("unchanged"),
            DONE,
        )
        .0;
        let pulsing = classify(
            Some(REV),
            None,
            Some(30),
            Some(POLL),
            Some(0),
            Some("probeError"),
            DONE,
        )
        .0;
        let dead = classify(
            Some(REV),
            Some(REV),
            Some(60177),
            Some(POLL),
            Some(0),
            Some("unchanged"),
            DONE,
        )
        .0;
        assert_eq!((working, pulsing, dead), (CONVERGED, INEFFECTIVE, STOPPED));
    }

    /// ★ THE CRY-WOLF GUARD, and the reason the rule keys on the HEAD
    /// rather than on a list of failure verbs. sentinela's `unchanged` is
    /// the healthy steady state — the overwhelming majority of all pulses
    /// in the fleet — and it publishes a head. A reader that flipped those
    /// to `ineffective` would be wrong on almost every node at once, which
    /// costs exactly what rounding up costs.
    #[test]
    fn the_healthy_steady_state_is_untouched_by_the_ineffective_rule() {
        for outcome in ["unchanged", "deployed", "deployedBehind"] {
            let (v, _) = classify(
                Some(REV),
                Some(REV),
                Some(30),
                Some(POLL),
                Some(0),
                Some(outcome),
                DONE,
            );
            assert_eq!(v, CONVERGED, "`{outcome}` resolved a head and is at it");
        }
    }

    /// A tick still RUNNING has not failed to resolve a head — it has not
    /// finished looking. The doctrine's own words: a tick still running
    /// returns `unknown` rather than claiming a result that has not
    /// happened yet. That must keep holding now that a second rule also
    /// looks at a missing head.
    #[test]
    fn an_in_flight_tick_is_unknown_not_ineffective() {
        let (v, why) = classify(
            Some(REV),
            None,
            Some(30),
            Some(POLL),
            Some(0),
            Some("building"),
            TickPhase::InFlight,
        );
        assert_eq!(v, UNKNOWN, "a running tick has not failed at anything");
        assert!(why.expect("reason").contains("in progress"));
    }

    /// ★ THE OTHER CRY-WOLF GUARD. A phase string from a newer sentinela
    /// is not evidence the tick finished, so it cannot support a claim that
    /// the tick finished fruitlessly. Round DOWN to `unknown` — and say
    /// which unknown, so the next reader knows to teach this table the new
    /// phase rather than to go looking at the node.
    #[test]
    fn an_unrecognised_phase_never_claims_ineffective() {
        let (v, why) = classify(
            Some(REV),
            None,
            Some(30),
            Some(POLL),
            Some(0),
            Some("someNewVerb"),
            TickPhase::from_wire(Some("draining")),
        );
        assert_eq!(v, UNKNOWN, "an unreadable phase is not proof of failure");
        assert!(why
            .expect("reason")
            .contains("does not recognise the phase"));
    }

    /// Staleness still outranks everything. An ineffective loop that then
    /// went silent is STOPPED — the more urgent fact — not ineffective.
    #[test]
    fn a_silent_ineffective_loop_is_stopped_not_ineffective() {
        let (v, _) = classify(
            Some(REV),
            None,
            Some(STALE_AFTER_POLLS * POLL + 1),
            Some(POLL),
            Some(0),
            Some("probeError"),
            DONE,
        );
        assert_eq!(v, STOPPED);
    }

    /// A head observed but nothing ever activated is a THIRD thing again:
    /// the loop is working, the node just has not arrived. It must not be
    /// swept into `ineffective`, and the old shared sentence ("published no
    /// branch HEAD") was simply false here — it published one.
    #[test]
    fn a_working_loop_that_has_never_deployed_is_unknown_not_ineffective() {
        let (v, why) = classify(
            None,
            Some(HEAD),
            Some(30),
            Some(POLL),
            Some(0),
            Some("unchanged"),
            DONE,
        );
        assert_eq!(v, UNKNOWN);
        let why = why.expect("reason");
        assert!(why.contains("never deployed"), "{why}");
        assert!(
            why.contains("588cf40"),
            "the head it DID observe belongs in the reason: {why}"
        );
    }

    /// ★ An older sentinela's pulse must still be READ. `phase` and
    /// `head_rev` postdate the first heartbeat format; a reader that
    /// hard-failed on their absence would turn a degraded node into an
    /// unreadable one, which is worse than the degradation it reports on.
    /// The default matches sentinela's own: no `phase` means the tick
    /// finished, because a finished tick was the only pulse there was.
    #[test]
    fn a_heartbeat_from_an_older_sentinela_still_reads() {
        let now = 1_754_400_000;
        let doc = read_back(
            "rio-legacy",
            &format!(
                "{{\"at_unix_ms\":{},\"outcome\":\"unchanged\",\"poll_seconds\":60}}",
                (now - 20) * 1000
            ),
            None,
            now,
        );
        // Parsed, not swallowed: the age and outcome came off the wire.
        assert_eq!(doc.last_tick_age_secs, Some(20));
        assert_eq!(doc.last_tick_outcome.as_deref(), Some("unchanged"));
        // No head_rev field at all — the same shape as rio's explicit null,
        // and it must land on the same verdict rather than an error.
        assert_eq!(doc.verdict, INEFFECTIVE, "{doc:?}");
    }

    /// A corrupt pulse is not a crash and not a health claim.
    #[test]
    fn an_unparseable_heartbeat_is_unknown_not_a_panic() {
        let now = 1_754_400_000;
        let doc = read_back("rio-corrupt", "{not json at all", None, now);
        assert_eq!(doc.verdict, UNKNOWN);
        assert!(doc
            .reason
            .expect("reason")
            .contains("no heartbeat published"));
    }

    /// The typed phase is what decides in-flight-ness now; the outcome-name
    /// list survives only for pulses older than the field. Pinned so a
    /// future cleanup does not delete the fallback and silently re-break
    /// the cid 2026-08-03 case.
    #[test]
    fn the_phase_wire_mapping_is_total() {
        assert_eq!(TickPhase::from_wire(None), TickPhase::Resolved);
        assert_eq!(TickPhase::from_wire(Some("resolved")), TickPhase::Resolved);
        assert_eq!(TickPhase::from_wire(Some("in_flight")), TickPhase::InFlight);
        assert_eq!(
            TickPhase::from_wire(Some("something_new")),
            TickPhase::Unrecognised
        );
    }
}
