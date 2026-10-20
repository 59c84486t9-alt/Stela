//! The kernel's system-wide facilities as a process meets them: the
//! answers the arm64 kernel gives whatever the caller, its credential and
//! entitlement checks, and the calls those checks then hand to the machine.
//!
//! Each contract is the 26A434 handler's (its `sysent` row and code),
//! which keeps the pinned xnu-12377 source's except where noted:
//!
//! - `swapon` and the system-call rejection calls (`debug_syscall_reject`,
//!   `debug_syscall_reject_config`, compiled only into development kernels)
//!   fail with ENOTSUP.
//! - `__mach_bridge_remote_time` returns zero: the arm64 kernel is the
//!   receiving side of a bridge clock (`CONFIG_MACH_BRIDGE_RECV_TIME`), and
//!   with no bridge (a Mac mini has no T2) it never received a timestamp
//!   pair (`bt_init_flag` clear).
//! - `objc_bp_assist_cfg_np` configures the branch predictor's
//!   `objc_msgSend` assist on every CPU in 26A434 (a stub failing with
//!   KERN_FAILURE in xnu-12377): only `initproc` may, so any other process
//!   gets EACCES.
//! - `kas_info`, `stack_snapshot_with_config`, `microstackshot` and
//!   `grab_pgo_data` describe the kernel itself and first check that the
//!   effective user is the superuser: anyone else gets EPERM. The
//!   superuser's request would describe the arm64 kernel's text, threads
//!   or profile, which this machine does not run, so it stops the run.
//! - The calls in [`ENTITLED`] first check a private entitlement of the
//!   calling task (or, for `pid_suspend`, `pid_resume`,
//!   `pid_shutdown_sockets` and `funmount`, use one to widen a check).
//!   They are the host kernel's own calls of the same xnu, so they are
//!   forwarded and its checks give their answers; but the host checks the
//!   hosted runtime's entitlements, not the guest's, so a guest holding
//!   the entitlement stops the run.
//! - `ptrace` traces host processes, which hosted guests are: denying
//!   attachment, being traced by the parent, attaching to, continuing,
//!   killing and detaching from another process are the host kernel's,
//!   whose checks are the same xnu's. Single-stepping (`PT_STEP`) would set
//!   the x86 trap flag of the target's host thread rather than step its
//!   guest code, so it stops the run.
use super::{Call, Kernel, Outcome, forward};
use anyhow::{Result, bail};

const EPERM: u64 = 1;
const EACCES: u64 = 13;
const ENOTSUP: u64 = 45;

/// `PT_STEP`.
const PT_STEP: i32 = 9;

pub(super) const CALLS: &[&str] = &[
    "ptrace",
    "swapon",
    "debug_syscall_reject",
    "sys_debug_syscall_reject_config",
    "__mach_bridge_remote_time",
    "objc_bp_assist_cfg_np",
    "kas_info",
    "stack_snapshot_with_config",
    "microstackshot",
    "grab_pgo_data",
    "sys_panic_with_data",
    "tracker_action",
    "sys_record_system_event",
    "sys_coalition_policy_set",
    "sys_coalition_policy_get",
    "graftdmg",
    "ungraftdmg",
    "oslog_coproc_reg",
    "oslog_coproc",
    "pid_suspend",
    "pid_resume",
    "pid_shutdown_sockets",
    "funmount",
    "pivot_root",
];

/// The superuser-only calls that describe the kernel itself.
const KERNEL_DESCRIPTIONS: &[&str] = &[
    "kas_info",
    "stack_snapshot_with_config",
    "microstackshot",
    "grab_pgo_data",
];

/// The forwarded calls an entitlement of the caller admits or widens,
/// with that entitlement.
pub(super) const ENTITLED: &[(&str, &str)] = &[
    (
        "sys_panic_with_data",
        "com.apple.private.allow-ext_paniclog",
    ),
    ("tracker_action", "com.apple.private.ip-domain-table"),
    (
        "sys_record_system_event",
        "com.apple.private.record_system_event",
    ),
    (
        "sys_coalition_policy_set",
        "com.apple.private.coalition-policy",
    ),
    (
        "sys_coalition_policy_get",
        "com.apple.private.coalition-policy",
    ),
    ("graftdmg", "com.apple.private.vfs.graftdmg"),
    ("ungraftdmg", "com.apple.private.vfs.graftdmg"),
    ("oslog_coproc_reg", "com.apple.private.coprocessor-logging"),
    ("oslog_coproc", "com.apple.private.coprocessor-logging"),
    (
        "pid_suspend",
        "com.apple.private.process.suspend-resume.any",
    ),
    ("pid_resume", "com.apple.private.process.suspend-resume.any"),
    (
        "pid_shutdown_sockets",
        "com.apple.private.process.suspend-resume.any",
    ),
    ("funmount", "com.apple.private.vfs.role-account-unmount"),
    ("pivot_root", "com.apple.private.vfs.pivot-root"),
];

/// Whether the caller's effective user is the superuser (`suser`,
/// `kauth_cred_issuser`: the credential's `cr_uid`).
fn superuser() -> bool {
    // SAFETY: no arguments; it cannot fail.
    unsafe { libc::geteuid() == 0 }
}

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    let name = call.entry.name;
    Ok(Some(match name {
        "swapon" | "debug_syscall_reject" | "sys_debug_syscall_reject_config" => {
            Outcome::Error(ENOTSUP)
        }
        "__mach_bridge_remote_time" => Outcome::value(0),
        "objc_bp_assist_cfg_np" => Outcome::Error(EACCES),
        "ptrace" if call.argument(0) as i32 == PT_STEP => bail!(
            "ptrace(PT_STEP, {}) would single-step the target's x86 host thread, not its guest \
             code",
            call.argument(1) as i32
        ),
        "ptrace" => forward(kernel, call)?,
        _ if KERNEL_DESCRIPTIONS.contains(&name) => {
            if !superuser() {
                return Ok(Some(Outcome::Error(EPERM)));
            }
            bail!(
                "{name} by the superuser describes the arm64 kernel itself (its text, threads or \
                 profile), which this machine does not run (arguments {:x?})",
                call.arguments()
            )
        }
        _ => {
            let Some(&(_, entitlement)) = ENTITLED.iter().find(|&&(entry, _)| entry == name) else {
                return Ok(None);
            };
            if guest_entitled(kernel, entitlement) {
                bail!(
                    "{name}: the guest holds {entitlement}, which the arm64 kernel checks, but the \
                     host kernel checks the hosted runtime's own entitlements"
                );
            }
            forward(kernel, call)?
        }
    }))
}

/// Whether the executable's signature grants `entitlement`.
fn guest_entitled(kernel: &Kernel, entitlement: &str) -> bool {
    crate::hosted::threads::lock(&kernel.process.executable)
        .signature
        .as_ref()
        .is_some_and(|signature| signature.entitled(entitlement))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entitled_call_is_served_once() {
        for (name, entitlement) in ENTITLED {
            assert!(CALLS.contains(name), "{name}");
            assert!(entitlement.starts_with("com.apple.private."));
        }
        let mut names: Vec<_> = CALLS.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), CALLS.len());
        assert!(KERNEL_DESCRIPTIONS.iter().all(|name| CALLS.contains(name)));
    }
}
