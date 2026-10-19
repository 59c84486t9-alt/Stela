//! The `mach_vm` MIG routines (`osfmk/mach/mach_vm.defs`) a hosted process
//! sends to its own task port: the virtual memory of its own address
//! space, which the arm64 kernel manages in 16 KiB pages and the x86 host
//! in 4 KiB pages. [`super::server`] serves `mach_vm_map`, `mach_vm`'s
//! deferred reclamation buffer and the other subsystems' routines, and
//! asks [`serve`] for the rest; a routine neither serves stops the run
//! naming it.
use super::super::Kernel;
use super::server::{Reply, Request};
use anyhow::Result;

/// The routines [`serve`] answers or forwards, with the named limit of a
/// routine served only in part.
pub(crate) const SERVED: &[(&str, Option<&str>)] = &[];

/// Answer `routine` sent to this task, or `None` when it is not served
/// here. `complex` is the request's `MACH_MSGH_BITS_COMPLEX`.
pub(super) fn serve(
    _kernel: &mut Kernel,
    _routine: &str,
    _complex: bool,
    _request: &Request,
) -> Result<Option<Reply>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_served_routine_is_a_mach_vm_routine() {
        for (routine, limit) in SERVED {
            assert!(
                crate::mach::mig::subsystems()
                    .iter()
                    .filter(|subsystem| subsystem.name == "mach_vm")
                    .flat_map(|subsystem| (subsystem.base..subsystem.end)
                        .filter_map(crate::mach::mig::routine))
                    .any(|entry| entry.name == *routine),
                "{routine}"
            );
            assert!(limit.is_none_or(|limit| !limit.is_empty()));
        }
    }
}
