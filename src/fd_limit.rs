use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFiles {
    pub soft: u64,
    pub hard: u64,
}

pub fn current() -> io::Result<OpenFiles> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(OpenFiles {
        soft: lim.rlim_cur,
        hard: lim.rlim_max,
    })
}

#[cfg(target_os = "macos")]
fn per_process_ceiling() -> u64 {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == 0 && value > 0 {
        value as u64
    } else {
        10_240
    }
}

#[cfg(not(target_os = "macos"))]
fn per_process_ceiling() -> u64 {
    u64::MAX
}

pub fn target_soft(now: OpenFiles, ceiling: u64) -> u64 {
    now.soft.max(now.hard.min(ceiling))
}

pub fn raise_to_hard() -> io::Result<OpenFiles> {
    let now = current()?;
    let soft = target_soft(now, per_process_ceiling());
    if soft == now.soft {
        return Ok(now);
    }
    let lim = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: now.hard as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    current()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn set_soft(soft: u64) {
        let now = current().unwrap();
        let lim = libc::rlimit {
            rlim_cur: soft as libc::rlim_t,
            rlim_max: now.hard as libc::rlim_t,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) }, 0);
    }

    fn child_soft() -> u64 {
        let out = Command::new("/bin/sh")
            .args(["-c", "ulimit -S -n"])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().parse().unwrap()
    }

    #[test]
    fn a_low_session_limit_is_raised_before_any_child_runs() {
        set_soft(256);
        assert_eq!(child_soft(), 256);
        let raised = raise_to_hard().unwrap();
        assert!(raised.soft > 256, "soft stayed at {}", raised.soft);
        assert!(raised.soft <= raised.hard);
        assert_eq!(child_soft(), raised.soft);
        assert_eq!(raise_to_hard().unwrap(), raised);
    }

    #[test]
    fn the_target_never_passes_the_hard_limit_or_the_kernel_ceiling() {
        let unlimited = libc::RLIM_INFINITY;
        assert_eq!(target_soft(OpenFiles { soft: 256, hard: 4096 }, u64::MAX), 4096);
        assert_eq!(target_soft(OpenFiles { soft: 256, hard: unlimited }, 1 << 24), 1 << 24);
        assert_eq!(target_soft(OpenFiles { soft: 1 << 20, hard: 1 << 24 }, 10_240), 1 << 20);
    }
}
