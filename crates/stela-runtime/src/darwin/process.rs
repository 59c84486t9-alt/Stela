//! `getpid`, answered with the guest process ID.

use super::{
    BsdCompletion, BsdPrototype, BsdRequest, BsdReturnType, BsdServiceEvent, PendingBsdCall,
    classify_bsd_call,
};
use crate::{blocks::ThreadState, process::Context};
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use anyhow::{Result, ensure};
use stela_compiler::block::SynchronousTrap;

pub const SYSCALL_NUMBER: u16 = 20;
const PROTOTYPE: BsdPrototype = BsdPrototype {
    argument_count: 0,
    return_type: BsdReturnType::Int,
};

pub(crate) fn completion(request: &BsdRequest, process: &Context) -> Result<BsdCompletion> {
    ensure!(
        request.number == SYSCALL_NUMBER && request.prototype() == PROTOTYPE,
        "request is not the process identity prototype"
    );
    // ARM entry zeros both retval slots; getpid writes only the first.
    Ok(BsdCompletion::Success {
        values: [process.pid(), 0],
    })
}

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    classify_bsd_call(state, trap).is_ok_and(|selector| selector.number == SYSCALL_NUMBER)
}

/// The runtime binds this immutable process owner through the current thread
/// before dispatch. A different call or incoherent pending trap has no effects.
pub fn service(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    process: &Context,
) -> BsdServiceEvent {
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
            "BSD service {} is not implemented by the process identity profile",
            request.number
        );
        let completion = completion(&request, process)?;
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
