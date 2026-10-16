//! The absent-task-region branch of Darwin's shared-region query.
//!
//! Public XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
//! bsd/vm/vm_unix.c and osfmk/mach/dyld_pager.h. This profile does not claim
//! the private macOS 27 kernel contract or model an existing shared region.

use super::{
    BsdCompletion, BsdPrototype, BsdReturnType, BsdServiceEvent, PendingBsdCall, classify_bsd_call,
};
use crate::blocks::ThreadState;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use anyhow::{Result, ensure};
use stela_compiler::block::SynchronousTrap;

pub const PROFILE_ID: &str = "darwin-arm64-absent-shared-region-v1";
pub const SYSCALL_NUMBER: u16 = 294;

/// The LP64 DYLD_VM_END_MWL command precedes the task-region lookup in XNU.
const DYLD_VM_END_MWL: u64 = u64::MAX;
const DARWIN_EINVAL: u32 = 22;
const PROTOTYPE: BsdPrototype = BsdPrototype {
    argument_count: 1,
    return_type: BsdReturnType::Int,
};

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    classify_bsd_call(state, trap).is_ok_and(|selector| selector.number == SYSCALL_NUMBER)
}

/// Service BSD294 for a process that owns no guest shared-region attachment.
///
/// The caller must establish that absence from its actual process ownership;
/// host shared-cache mappings cannot satisfy this ARM guest condition. XNU
/// returns EINVAL before accessing the destination, including a NULL pointer.
/// There is consequently no guest-memory read, copyout or mapping transition.
/// The map-with-linking command requires process policy state and remains
/// pending. Existing empty/mapped regions require a separate reviewed profile.
pub fn service_absent(state: &mut ThreadState, trap: &SynchronousTrap) -> BsdServiceEvent {
    let mut event = BsdServiceEvent {
        trap: *trap,
        request: None,
        completion: None,
        declined: None,
    };
    let result = (|| -> Result<BsdCompletion> {
        let pending = PendingBsdCall::from_trap(state, trap, PROTOTYPE)?;
        let request = *pending.request();
        event.request = Some(request);
        ensure!(
            request.number == SYSCALL_NUMBER,
            "BSD service {} is not implemented by the absent shared-region profile",
            request.number
        );
        let [address] = request.arguments() else {
            unreachable!("the validated shared-region prototype contains one argument")
        };
        ensure!(
            *address != DYLD_VM_END_MWL,
            "disabling map_with_linking requires owned process policy state"
        );
        let completion = BsdCompletion::Error {
            errno: DARWIN_EINVAL,
        };
        pending.complete(state, completion)?;
        Ok(completion)
    })();
    match result {
        Ok(completion) => event.completion = Some(completion),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

#[cfg(test)]
mod tests;
