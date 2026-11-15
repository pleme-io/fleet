use std::collections::BTreeSet;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub pid: i32,
    pub ppid: i32,
    pub pgid: i32,
    pub zombie: bool,
    pub comm: String,
}

pub fn parse_ps(out: &str) -> Vec<Proc> {
    out.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let pid = f.next()?.parse().ok()?;
            let ppid = f.next()?.parse().ok()?;
            let pgid = f.next()?.parse().ok()?;
            let stat = f.next()?;
            let comm = f.collect::<Vec<_>>().join(" ");
            Some(Proc {
                pid,
                ppid,
                pgid,
                zombie: stat.starts_with('Z'),
                comm,
            })
        })
        .collect()
}

pub fn snapshot() -> Option<Vec<Proc>> {
    let out = Command::new("ps")
        .args(["-Ao", "pid=,ppid=,pgid=,stat=,comm="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| parse_ps(&String::from_utf8_lossy(&out.stdout)))
}

pub fn widen(procs: &[Proc], known: &mut BTreeSet<i32>) {
    loop {
        let before = known.len();
        for p in procs {
            if p.pid > 1 && (known.contains(&p.ppid) || known.contains(&p.pgid)) {
                known.insert(p.pid);
            }
        }
        if known.len() == before {
            return;
        }
    }
}

pub fn living(procs: &[Proc], known: &BTreeSet<i32>) -> Vec<Proc> {
    procs
        .iter()
        .filter(|p| !p.zombie && known.contains(&p.pid))
        .cloned()
        .collect()
}

fn basename(comm: &str) -> &str {
    comm.rsplit('/').next().unwrap_or(comm)
}

pub fn builders_busy(procs: &[Proc]) -> bool {
    let daemons: BTreeSet<i32> = procs
        .iter()
        .filter(|p| basename(&p.comm) == "nix-daemon")
        .map(|p| p.pid)
        .collect();
    procs
        .iter()
        .any(|p| !p.zombie && daemons.contains(&p.ppid) && basename(&p.comm) != "nix-daemon")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    Sent,
    Gone,
    Denied,
}

#[allow(unsafe_code)]
fn signal(pid: i32, sig: libc::c_int) -> Delivery {
    // SAFETY: kill(2) on a pid enumerated from our own child's tree.
    if unsafe { libc::kill(pid, sig) } == 0 {
        return Delivery::Sent;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM) => Delivery::Denied,
        _ => Delivery::Gone,
    }
}

fn signal_all(pids: &[i32], sig: libc::c_int, name: &str) {
    let denied: Vec<String> = pids
        .iter()
        .filter(|&&pid| signal(pid, sig) == Delivery::Denied)
        .map(|pid| pid.to_string())
        .collect();
    if denied.is_empty() {
        return;
    }
    let _ = Command::new("sudo")
        .args(["-n", "kill", "-s", name, "--"])
        .args(&denied)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn sweep(
    known: &mut BTreeSet<i32>,
    sig: libc::c_int,
    name: &str,
    within: Duration,
) -> Option<Vec<Proc>> {
    let deadline = Instant::now() + within;
    let mut signalled: BTreeSet<i32> = BTreeSet::new();
    loop {
        let procs = snapshot()?;
        widen(&procs, known);
        let alive = living(&procs, known);
        if alive.is_empty() || Instant::now() >= deadline {
            return Some(alive);
        }
        let fresh: Vec<i32> = alive
            .iter()
            .map(|p| p.pid)
            .filter(|pid| signalled.insert(*pid))
            .collect();
        signal_all(&fresh, sig, name);
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    Clean,
    Survivors(Vec<Proc>),
    Blind,
}

pub fn terminate(root: i32, grace: Duration) -> Ended {
    let mut known = BTreeSet::from([root]);
    let first = sweep(&mut known, libc::SIGTERM, "TERM", grace);
    let last = match first {
        Some(alive) if alive.is_empty() => Some(alive),
        _ => sweep(&mut known, libc::SIGKILL, "KILL", Duration::from_secs(5)),
    };
    match last {
        None => {
            signal_all(&[-root], libc::SIGKILL, "KILL");
            Ended::Blind
        }
        Some(alive) if alive.is_empty() => Ended::Clean,
        Some(alive) => Ended::Survivors(alive),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: i32, ppid: i32, pgid: i32, comm: &str) -> Proc {
        Proc {
            pid,
            ppid,
            pgid,
            zombie: false,
            comm: comm.to_owned(),
        }
    }

    #[test]
    fn parse_reads_every_column_and_keeps_spaces_in_comm() {
        let out = "  10     1    10 Ss   /usr/bin/sudo\n  11    10    11 Z    /Applications/Google Chrome.app/x\nbogus\n";
        let got = parse_ps(out);
        assert_eq!(
            got,
            vec![
                p(10, 1, 10, "/usr/bin/sudo"),
                Proc {
                    zombie: true,
                    ..p(11, 10, 11, "/Applications/Google Chrome.app/x")
                }
            ]
        );
    }

    #[test]
    fn widen_follows_children_reparented_children_and_group_mates() {
        let procs = vec![
            p(100, 50, 100, "sudo"),
            p(101, 100, 101, "darwin-rebuild"),
            p(102, 101, 101, "nix"),
            p(103, 1, 101, "orphan-in-group"),
            p(104, 1, 104, "stranger"),
            p(105, 50, 50, "parent-sibling"),
            p(1, 0, 1, "launchd"),
        ];
        let mut known = BTreeSet::from([100]);
        widen(&procs, &mut known);
        assert_eq!(known, BTreeSet::from([100, 101, 102, 103]));
    }

    #[test]
    fn widen_never_takes_init() {
        let procs = vec![p(1, 0, 7, "launchd"), p(7, 1, 7, "root")];
        let mut known = BTreeSet::from([7]);
        widen(&procs, &mut known);
        assert_eq!(known, BTreeSet::from([7]));
    }

    #[test]
    fn living_drops_zombies_and_strangers() {
        let procs = vec![
            p(5, 1, 5, "a"),
            Proc {
                zombie: true,
                ..p(6, 5, 5, "b")
            },
            p(7, 1, 7, "c"),
        ];
        let known = BTreeSet::from([5, 6]);
        assert_eq!(living(&procs, &known), vec![p(5, 1, 5, "a")]);
    }

    #[test]
    fn builders_busy_is_a_non_daemon_child_of_a_daemon() {
        let idle = vec![
            p(10, 1, 10, "/nix/store/x/bin/nix-daemon"),
            p(11, 10, 11, "nix-daemon"),
        ];
        assert!(!builders_busy(&idle));
        let mut busy = idle.clone();
        busy.push(p(12, 11, 12, "/nix/store/y/bin/bash"));
        assert!(builders_busy(&busy));
        let mut stray = idle;
        stray.push(p(13, 99, 13, "bash"));
        assert!(!builders_busy(&stray));
        assert!(!builders_busy(&[
            p(10, 1, 10, "nix-daemon"),
            Proc {
                zombie: true,
                ..p(12, 10, 12, "bash")
            }
        ]));
    }
}
