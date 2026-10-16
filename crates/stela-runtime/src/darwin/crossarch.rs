//! Explicit unavailable cross-architecture service from public XNU
//! f6217f891ac0bb64f3d375211650a4c1ff8ca1ea, bsd/kern/kern_crossarch.c,
//! bsd/sys/crossarch.h and bsd/kern/syscalls.master. Namespace zero returns
//! ENOTSUP; larger uint32 namespaces return EINVAL. This profile provides no
//! cross-architecture execution or host Rosetta access.

use super::{
    BsdCompletion, BsdPrototype, BsdReturnType, BsdServiceEvent, PendingBsdCall, classify_bsd_call,
};
use crate::blocks::ThreadState;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use anyhow::{Result, ensure};
use stela_compiler::block::SynchronousTrap;

pub const PROFILE_ID: &str = "darwin-crossarch-unavailable-v1";
pub const SYSCALL_NUMBER: u16 = 38;
pub const DARWIN_EINVAL: u32 = 22;
pub const DARWIN_ENOTSUP: u32 = 45;

const MAX_VALID_NAMESPACE: u32 = 0;
const PROTOTYPE: BsdPrototype = BsdPrototype {
    argument_count: 1,
    return_type: BsdReturnType::Int,
};

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    classify_bsd_call(state, trap).is_ok_and(|selector| selector.number == SYSCALL_NUMBER)
}

/// Complete the declared unavailable-service result without reading guest
/// memory or querying host state. Unknown or invalid calls remain pending.
pub fn service(state: &mut ThreadState, trap: &SynchronousTrap) -> BsdServiceEvent {
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
            "BSD service {} is not implemented by the cross-architecture profile",
            request.number
        );
        let namespace = request.arguments()[0] as u32;
        let errno = if namespace > MAX_VALID_NAMESPACE {
            DARWIN_EINVAL
        } else {
            DARWIN_ENOTSUP
        };
        let completion = BsdCompletion::Error { errno };
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
