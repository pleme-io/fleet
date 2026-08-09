//! Pre-flight for the L2 e2e gate: can this host still allocate a pty?
//!
//! WHY THIS EXISTS (incident 2026-08-06). A `nix run .#rebuild` on cid died with
//!
//!     error: opening pseudoterminal master: Device not configured
//!     Error: e2e gate FAILED — the candidate closure's mado/frostmourne smoke
//!     matrix did not pass; refusing to switch.
//!
//! Nothing was wrong with the closure. macOS had run out of pseudoterminals —
//! 500 of a `kern.tty.ptmx_max` of 511, held by 459 ORPHANED login shells
//! (`comm == "-sh"`, `ppid == 1`), leaked by agent sessions over three days.
//! `mado e2e` spawns a real shell in a pty as matrix row 1, so it could not get
//! one, the row failed, and the gate blamed the artifact.
//!
//! THE DEFECT WAS THE ATTRIBUTION, not the failure. A host resource condition
//! rendered as "this closure is broken; refusing to switch" sends the operator
//! to read a diff that has nothing wrong with it. The floor this module sets:
//! the gate never runs blind into an exhausted pty table, and if it is exhausted
//! the operator is told THAT, in those words, before anything is blamed.
//!
//! SCOPE, deliberately narrow. This reaps a shell only when ALL of:
//!   * `comm` is exactly `-sh`   — a login shell, argv[0] dash-prefixed
//!   * `ppid == 1`               — reparented to launchd; its session is GONE
//!   * `uid == getuid()`         — ours to reap
//!   * pty pressure is already past `REAP_THRESHOLD`
//! A shell with a live parent is somebody's in-flight session and is never
//! touched, at any pressure. Below the threshold this module does nothing at
//! all — it is not a periodic cleaner, it is a guard on one gate.
//!
//! It also does NOT fix the leak, and must not be read as having done so. The
//! producer is whatever spawned those shells; this keeps the leak from
//! presenting as a false regression while that is chased separately.

use anyhow::{Context, Result};
use std::process::Command;

use super::utils::{log_info, log_warning};

/// Fraction of the pty ceiling past which we reap before running the gate.
///
/// Not 1.0: the gate needs several ptys of headroom itself, and a host at 95%
/// is one agent burst from failing mid-matrix — which reproduces the incident
/// with a smaller number. Not 0.1 either: reaping is a kill, and a quiet host
/// should see this module do nothing.
const REAP_THRESHOLD: f64 = 0.75;

/// macOS' hard ceiling when `kern.tty.ptmx_max` cannot be read. The observed
/// default on the fleet's darwin hosts; used only so a failed sysctl degrades
/// to a conservative number rather than disabling the guard.
const FALLBACK_CEILING: usize = 511;

/// How many ptys exist, against how many may.
#[derive(Debug, Clone, Copy)]
pub struct PtyPressure {
    pub in_use: usize,
    pub ceiling: usize,
}

impl PtyPressure {
    fn saturation(&self) -> f64 {
        if self.ceiling == 0 {
            return 0.0;
        }
        self.in_use as f64 / self.ceiling as f64
    }

    fn pct(&self) -> u32 {
        (self.saturation() * 100.0).round() as u32
    }
}

/// Count allocated ptys and read the ceiling.
///
/// `in_use` counts `/dev/ttysNNN` nodes. Measured on the incident host: 500
/// nodes at exhaustion, 27 after reaping 459 shells — the nodes are torn down
/// with their owner, so the count tracks live allocation rather than a
/// high-water mark.
pub fn measure() -> Result<PtyPressure> {
    let in_use = std::fs::read_dir("/dev")
        .context("read /dev to count allocated ptys")?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("ttys"))
        })
        .count();

    let ceiling = Command::new("sysctl")
        .args(["-n", "kern.tty.ptmx_max"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(FALLBACK_CEILING);

    Ok(PtyPressure { in_use, ceiling })
}

/// A process that is only ever an orphaned login shell — see the module header
/// for the four conditions that must all hold before one is constructed.
#[derive(Debug, Clone, Copy)]
struct OrphanShell(i32);

/// Enumerate orphaned login shells owned by this user.
///
/// `ps` rather than a `sysctl(KERN_PROC_ALL)` FFI walk: the selection is four
/// integer/string comparisons, and the typed thing here is the PREDICATE, not
/// the enumeration. `comm` is matched EXACTLY against `-sh` — matching `-sh` as
/// a substring against a full argv is a known false-positive source (it hits
/// Chrome's `--shared-files` and `--seatbelt`), which is why this reads the
/// `comm` column alone.
fn find_orphan_login_shells() -> Result<Vec<OrphanShell>> {
    let out = Command::new("ps")
        .args(["-Ao", "pid=,ppid=,uid=,comm="])
        .output()
        .context("enumerate processes with ps")?;
    if !out.status.success() {
        anyhow::bail!("ps exited {}", out.status);
    }
    Ok(select_orphans(
        &String::from_utf8_lossy(&out.stdout),
        users_uid(),
    ))
}

/// The predicate, split out from the subprocess so it can be tested against the
/// cases that must NOT match — which is the only interesting half. Every line
/// this returns names a process that will be sent SIGKILL.
fn select_orphans(ps_output: &str, uid: u32) -> Vec<OrphanShell> {
    let mut found = Vec::new();
    for line in ps_output.lines() {
        let mut f = line.split_whitespace();
        let (Some(pid), Some(ppid), Some(puid), Some(comm)) =
            (f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        // `comm` is the LAST field and must be exactly "-sh". A trailing field
        // means we were handed an argv, not a comm — and matching "-sh" inside
        // an argv is a measured false-positive source (Chrome's
        // `--shared-files`, `--seatbelt`). Refuse rather than guess.
        if comm != "-sh" || f.next().is_some() {
            continue;
        }
        // ppid 1 == reparented to launchd, i.e. the session that owned it is
        // gone. A shell with ANY live parent is somebody's in-flight work.
        //
        // Non-vacuity receipt: deleting this check turns
        // `never_reaps_a_shell_with_a_live_parent` and
        // `selects_only_orphaned_login_shells_of_this_user` RED, and nothing
        // else. Verified by doing exactly that, 2026-08-06.
        if ppid != "1" {
            continue;
        }
        if puid.parse::<u32>().ok() != Some(uid) {
            continue;
        }
        if let Ok(pid) = pid.parse::<i32>() {
            found.push(OrphanShell(pid));
        }
    }
    found
}

fn users_uid() -> u32 {
    // SAFETY: getuid() takes no arguments, cannot fail, and has no side effects.
    unsafe { libc::getuid() }
}

/// Reap the given shells. TERM first, then KILL the survivors.
///
/// The two-phase order is not politeness — a login shell IGNORES SIGTERM, so
/// TERM alone leaves every one of them holding its pty. Measured on the
/// incident host: 459 shells, 0 gone after TERM, all gone after KILL.
fn reap(shells: &[OrphanShell]) -> usize {
    for sig in [libc::SIGTERM, libc::SIGKILL] {
        for OrphanShell(pid) in shells {
            // SAFETY: kill() on a pid we selected ourselves; a dead pid returns
            // ESRCH, which is the expected outcome for anything TERM did take.
            unsafe {
                libc::kill(*pid, sig);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    shells.len()
}

/// Run before the e2e gate. Never fails the rebuild — a guard that can itself
/// block the thing it guards is a worse failure than the one it prevents.
pub fn preflight() {
    let Ok(before) = measure() else {
        // Unmeasurable is not the same as fine, and is not worth a rebuild.
        log_warning("pty pre-flight: could not count ptys — running the gate unguarded");
        return;
    };

    if before.saturation() < REAP_THRESHOLD {
        return;
    }

    log_warning(&format!(
        "pty pressure {}/{} ({}%) — reaping orphaned login shells before the e2e gate",
        before.in_use,
        before.ceiling,
        before.pct()
    ));

    let orphans = match find_orphan_login_shells() {
        Ok(o) => o,
        Err(e) => {
            log_warning(&format!(
                "pty pre-flight: could not enumerate processes ({e:#})"
            ));
            return;
        }
    };

    if orphans.is_empty() {
        log_warning(
            "pty pre-flight: no ORPHANED login shells to reap — the ptys belong to live \
             sessions. If the gate now fails to spawn a shell, that is this host being out \
             of ptys, NOT the candidate closure.",
        );
        return;
    }

    let killed = reap(&orphans);
    let after = measure().unwrap_or(before);
    log_info(&format!(
        "pty pre-flight: reaped {} orphaned login shell(s) — ptys {} -> {} of {}",
        killed, before.in_use, after.in_use, after.ceiling
    ));

    if after.saturation() >= REAP_THRESHOLD {
        log_warning(&format!(
            "pty pressure still {}% after reaping — the leak is LIVE and has a producer \
             this guard cannot see. If the e2e gate fails to spawn a shell, read it as pty \
             exhaustion on this host, not as a broken closure.",
            after.pct()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturation_is_a_ratio_of_ceiling() {
        let p = PtyPressure {
            in_use: 500,
            ceiling: 511,
        };
        assert!(p.saturation() > REAP_THRESHOLD);
        assert_eq!(p.pct(), 98);
    }

    #[test]
    fn a_quiet_host_is_below_the_threshold() {
        // The post-reap measurement from the incident host.
        let p = PtyPressure {
            in_use: 27,
            ceiling: 511,
        };
        assert!(p.saturation() < REAP_THRESHOLD);
    }

    /// A zero ceiling must not divide by zero and must not read as saturated —
    /// an unreadable sysctl should never cause a reap.
    #[test]
    fn zero_ceiling_is_not_saturated() {
        let p = PtyPressure {
            in_use: 10,
            ceiling: 0,
        };
        assert_eq!(p.saturation(), 0.0);
        assert!(p.saturation() < REAP_THRESHOLD);
    }

    /// The line shapes that must NEVER be reaped, each one a way this guard
    /// could kill something it does not own. Written from the 2026-08-06
    /// incident host's actual `ps` output.
    const PS_FIXTURE: &str = "\
34917     1 501 -sh
36108     1 501 -sh
90863 84137 501 -sh
41758     1 502 -sh
 1193     1 501 tobira
22835 21209 501 claude
 4572     1 501 /nix/store/xxx-bash-5.3p3/bin/bash
 7781     1 501 Google Chrome Helper --shared-files --seatbelt -sh
";

    #[test]
    fn selects_only_orphaned_login_shells_of_this_user() {
        let picked: Vec<i32> = select_orphans(PS_FIXTURE, 501)
            .iter()
            .map(|OrphanShell(p)| *p)
            .collect();
        assert_eq!(picked, vec![34917, 36108]);
    }

    /// A shell with a LIVE parent is an in-flight session. Reaping one is the
    /// worst thing this module could do, so it gets its own assertion.
    #[test]
    fn never_reaps_a_shell_with_a_live_parent() {
        let picked = select_orphans("90863 84137 501 -sh\n", 501);
        assert!(
            picked.is_empty(),
            "a live-parent shell must never be selected"
        );
    }

    /// Another user's orphan is not ours to kill.
    #[test]
    fn never_reaps_another_users_shell() {
        let picked = select_orphans("41758     1 502 -sh\n", 501);
        assert!(picked.is_empty());
    }

    /// The documented false positive: `-sh` appearing inside an argv. If the
    /// column discipline ever slips, this is what it kills.
    #[test]
    fn never_matches_dash_sh_inside_an_argv() {
        let picked = select_orphans(
            "7781     1 501 Google Chrome Helper --shared-files --seatbelt -sh\n",
            501,
        );
        assert!(picked.is_empty());
    }

    /// The host this runs on must be measurable at all — a guard whose
    /// measurement silently returns 0 would report a healthy host forever.
    #[test]
    fn measure_reads_a_real_ceiling() {
        let p = measure().expect("ptys are countable on a unix host");
        assert!(p.ceiling > 0, "ceiling must be positive, got {}", p.ceiling);
    }
}
