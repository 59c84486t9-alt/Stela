//! The file-creation mask and the descriptor-flag gate: what of the
//! process's descriptor table the hosted kernel keeps beside the host's.
//!
//! - `umask(newmask)` and `umask_extended(newmask, xsecurity)` set the
//!   mask to `newmask & ALLPERMS` and return the mask they replace
//!   (`bsd/kern/kern_descrip.c` `umask1`). The host kernel sets it; the
//!   hosted kernel records each mask it sets, so 26A434's `getumask` reads
//!   it without changing it, as the arm64 kernel reads `fd_cmask`.
//! - The x86-64 host has no `pipe2` or `dup3`: [`super::additions`] gives a
//!   new descriptor its flags after the host creates it, through
//!   `fcntl(F_SETFD)` and, for close-on-fork, a guard added and removed at
//!   once (`change_fdguard_np`), during which the descriptor is
//!   close-on-exec and refuses duplication. The gate makes that atomic for
//!   every call that could observe it: the forwarded duplications
//!   (`dup`, `dup2`, `fcntl` `F_DUPFD`, `F_DUPFD_CLOEXEC`) and `F_SETFD`,
//!   which a guarded descriptor answers with a guard exception, and
//!   `fork`, `posix_spawn` and `execve`, which copy the descriptor table.
//! - `__pthread_chdir` and `__pthread_fchdir` give the calling thread its
//!   own working directory, or (`fd` -1) return it to the process's. The
//!   hosted kernel records which a thread has, so a 26A434 `*at` call the
//!   host lacks can start a relative lookup at a directory descriptor by
//!   moving the thread's directory there and back ([`at_directory`]).
use super::{Call, Kernel, Outcome};
use crate::hosted::darwin::{F_SETFD, O_CLOEXEC};
use crate::hosted::forward;
use crate::hosted::threads::{lock, try_lock};
use anyhow::Result;
use std::sync::{Mutex, MutexGuard};

pub(super) const CALLS: &[&str] = &[
    "umask",
    "umask_extended",
    "__pthread_chdir",
    "__pthread_fchdir",
];

/// `ALLPERMS`: the mode bits a mask keeps.
const ALL_PERMISSIONS: u64 = 0o7777;
/// The `fcntl` commands the gate orders: `F_SETFD`, `F_DUPFD` and
/// `F_DUPFD_CLOEXEC`.
const F_DUPFD: u32 = 0;
const F_DUPFD_CLOEXEC: u32 = 67;

/// The process's file-creation mask and descriptor-flag gate.
pub(crate) struct Files {
    mask: Mutex<u64>,
    gate: Mutex<()>,
}

impl Files {
    /// The mask the host process started with: replaced and restored
    /// before any guest thread runs.
    pub(crate) fn inherit() -> Self {
        // SAFETY: `umask` only exchanges the process's mask.
        let mask = unsafe {
            let mask = libc::umask(0o022);
            libc::umask(mask);
            mask
        };
        Self {
            mask: Mutex::new(u64::from(mask)),
            gate: Mutex::new(()),
        }
    }

    /// The mask the guest last set or the process inherited.
    pub(crate) fn mask(&self) -> u64 {
        *lock(&self.mask)
    }

    /// Hold the descriptor-flag gate.
    pub(crate) fn gate(&self) -> MutexGuard<'_, ()> {
        lock(&self.gate)
    }

    /// The gate and the mask, held across a host `fork` so that the child
    /// finds neither held by a thread it does not have.
    pub(crate) fn hold_for_fork(&self) -> Option<(MutexGuard<'_, ()>, MutexGuard<'_, u64>)> {
        Some((try_lock(&self.gate)?, try_lock(&self.mask)?))
    }
}

/// Whether `call` holds the gate: a forwarded call that would observe a
/// descriptor mid-flag change.
pub(super) fn gated(call: &Call) -> bool {
    match call.entry.name {
        "sys_dup" | "sys_dup2" => true,
        "sys_fcntl" | "sys_fcntl_nocancel" => {
            matches!(call.argument(1) as u32, F_DUPFD | F_SETFD | F_DUPFD_CLOEXEC)
        }
        _ => false,
    }
}

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    Ok(match call.entry.name {
        "umask" | "umask_extended" => {
            // The security descriptor is paged in before the mask is held:
            // no thread waits for the execution lock holding it.
            kernel.page_in_arguments(call.arguments())?;
            let mut mask = lock(&kernel.process.files.mask);
            let returned = forward::bsd(call.entry.number, call.arguments());
            if returned.carry {
                Some(Outcome::Error(returned.rax))
            } else {
                *mask = call.argument(0) & ALL_PERMISSIONS;
                Some(Outcome::value(returned.rax))
            }
        }
        "__pthread_chdir" | "__pthread_fchdir" => {
            let outcome = super::forward(kernel, call)?;
            if let Outcome::Return(..) = outcome {
                // `__pthread_fchdir(-1)` returns the thread to the
                // process's directory.
                kernel.thread_directory =
                    call.entry.name == "__pthread_chdir" || call.argument(0) as u32 as i32 != -1;
            }
            Some(outcome)
        }
        _ => None,
    })
}

/// The host call `name` of the pinned catalog: X0, or the errno.
fn host(name: &str, arguments: &[u64]) -> std::result::Result<u64, u64> {
    let returned = forward::bsd(super::number_of(name), arguments);
    if returned.carry {
        Err(returned.rax)
    } else {
        Ok(returned.rax)
    }
}

/// Why [`at_directory`] cannot run a lookup.
pub(super) const UNRESTORABLE: &str = "the thread's own working directory (__pthread_chdir) \
     cannot be reopened to restore it after a lookup from a directory descriptor";

/// Run `lookup` on the calling host thread with its working directory at
/// the directory descriptor `fd`, where `nameiat` starts a relative
/// lookup, then give the thread back its own directory (`thread_directory`)
/// or the process's.
/// `Err(Some(errno))`: `fd` is not a searchable directory, as the lookup
/// would fail; `Err(None)`: the thread's directory cannot be restored.
pub(super) fn at_directory<T>(
    thread_directory: bool,
    fd: i32,
    lookup: impl FnOnce() -> T,
) -> std::result::Result<T, Option<u64>> {
    const O_SEARCH: u64 = 0x4000_0000 | 0x0010_0000;
    let own = if thread_directory {
        let here = c".";
        match host(
            "open",
            &[here.as_ptr() as u64, O_SEARCH | u64::from(O_CLOEXEC)],
        ) {
            Ok(own) => Some(own),
            Err(_) => return Err(None),
        }
    } else {
        None
    };
    let restore = || {
        let back = own.unwrap_or(u64::MAX);
        let restored = host("__pthread_fchdir", &[back]).is_ok();
        if let Some(own) = own {
            let _ = host("sys_close", &[own]);
        }
        restored
    };
    if let Err(errno) = host("__pthread_fchdir", &[i64::from(fd) as u64]) {
        // The thread's directory is unchanged.
        if let Some(own) = own {
            let _ = host("sys_close", &[own]);
        }
        return Err(Some(errno));
    }
    let result = lookup();
    if restore() { Ok(result) } else { Err(None) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_inherited_mask_is_the_one_children_see() {
        let files = Files::inherit();
        let shell = std::process::Command::new("/bin/sh")
            .args(["-c", "umask"])
            .output()
            .unwrap();
        let printed = String::from_utf8(shell.stdout).unwrap();
        assert_eq!(
            u64::from_str_radix(printed.trim(), 8).unwrap(),
            files.mask()
        );
        assert!(files.hold_for_fork().is_some());
        let _gate = files.gate();
        assert!(files.hold_for_fork().is_none());
    }
}
