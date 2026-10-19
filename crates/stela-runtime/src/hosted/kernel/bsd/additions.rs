//! System calls the 26A434 kernel (xnu-13432, unpublished) adds at numbers
//! the pinned xnu-12377 catalog reserves, found by the census of the
//! guest's `SVC #0x80` sites ([`crate::hosted::requirements`]). The x86-64
//! host kernel has none of them, so each is composed from host calls with
//! the arm64 kernel's contract, or stops the run naming it.
use super::{Kernel, Outcome, Pe};
use crate::darwin::BsdReturnType;
use crate::hosted::forward;
use anyhow::{Result, bail};

/// Each addition's number and its libsystem_kernel stub's call name.
pub(crate) const ADDITIONS: &[(u16, &str)] = &[
    (148, "pipe2"),
    (149, "dup3"),
    (214, "fchflagsat"),
    (215, "getumask"),
    (246, "aio_readv"),
    (247, "aio_writev"),
    (249, "fsctlat"),
    (352, "guarded_ftruncate_np"),
    (519, "register_uexc_handler"),
];

/// The additions [`call`] services.
pub(crate) const CALLS: &[&str] = &[];

/// Additions serviced with a named limit: what of the arm64 kernel's
/// contract the hosted kernel does not provide.
pub(crate) const LIMITS: &[(&str, &str)] = &[];

/// Why an addition [`call`] does not service stops the run.
pub(crate) const UNIMPLEMENTED: &str =
    "a 26A434 addition at a number the pinned catalog reserves: not implemented";

/// The addition at `number`, if any.
pub(crate) fn addition(number: u16) -> Option<&'static str> {
    ADDITIONS
        .iter()
        .find(|&&(entry, _)| entry == number)
        .map(|&(_, name)| name)
}

/// Service the addition `name` with its argument registers: its return
/// type and outcome.
pub(super) fn call(
    _kernel: &mut Kernel,
    _pe: &mut Pe,
    number: u16,
    name: &'static str,
    arguments: &[u64; forward::MAX_ARGUMENTS],
) -> Result<(BsdReturnType, Outcome)> {
    bail!(
        "BSD system call {name} ({number}) is not implemented by the hosted kernel: \
         {UNIMPLEMENTED} (arguments {arguments:x?})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additions_lie_at_reserved_catalog_numbers() {
        for &(number, name) in ADDITIONS {
            assert!(
                crate::darwin::catalog::entry(number)
                    .is_none_or(|entry| entry.prototype().is_none()),
                "{name} ({number})"
            );
        }
        assert!(
            CALLS
                .iter()
                .all(|call| ADDITIONS.iter().any(|&(_, name)| name == *call))
        );
        assert!(LIMITS.iter().all(|(call, _)| CALLS.contains(call)));
        assert_eq!(addition(148), Some("pipe2"));
        assert_eq!(addition(147), None);
    }
}
