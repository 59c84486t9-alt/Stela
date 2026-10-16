//! `getentropy` from host entropy (XNU `bsd/dev/random/randomdev.c`).
//! Oversized requests return EINVAL; a host failure returns EIO.

use super::{
    BsdCompletion, BsdPrototype, BsdReturnType, BsdServiceEvent, PendingBsdCall, classify_bsd_call,
    copyout,
};
use crate::{blocks::ThreadState, memory::OwnedMemory};
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::ToString};
use anyhow::{Result, ensure};
use std::io;
use stela_compiler::block::SynchronousTrap;

pub const PROFILE_ID: &str = "darwin-host-owned-getentropy-v1";
pub const SYSCALL_NUMBER: u16 = 500;
pub const MAX_BYTES: usize = 256;

const DARWIN_EIO: u32 = 5;
const DARWIN_EFAULT: u32 = 14;
const DARWIN_EINVAL: u32 = 22;
const PROTOTYPE: BsdPrototype = BsdPrototype {
    argument_count: 2,
    return_type: BsdReturnType::Int,
};

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    classify_bsd_call(state, trap).is_ok_and(|selector| selector.number == SYSCALL_NUMBER)
}

/// Obtain fresh kernel entropy before validating and publishing the complete
/// destination. Source-defined store prefixes survive supported copyout faults;
/// ambiguous pair-fault shapes explicitly decline before publication. This
/// service accepts only serialized, non-shareable OwnedMemory.
pub fn service(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    memory: &mut OwnedMemory,
) -> BsdServiceEvent {
    service_with_source(state, trap, memory, host_entropy)
}

fn service_with_source(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    memory: &mut OwnedMemory,
    source: impl FnOnce(&mut [u8]) -> io::Result<()>,
) -> BsdServiceEvent {
    let mut event = BsdServiceEvent {
        trap: *trap,
        request: None,
        completion: None,
        declined: None,
    };
    let result = (|| -> Result<BsdCompletion> {
        ensure!(memory.is_usable(), "guest address space is unusable");
        let pending = PendingBsdCall::from_trap(state, trap, PROTOTYPE)?;
        let request = *pending.request();
        event.request = Some(request);
        ensure!(
            request.number == SYSCALL_NUMBER,
            "BSD service {} is not implemented by the entropy profile",
            request.number
        );
        let [address, size] = request.arguments() else {
            unreachable!("the validated entropy prototype contains two arguments")
        };
        let errno = if *size > MAX_BYTES as u64 {
            Some(DARWIN_EINVAL)
        } else {
            let mut buffer = [0; MAX_BYTES];
            let bytes = &mut buffer[..*size as usize];
            if source(bytes).is_err() {
                Some(DARWIN_EIO)
            } else {
                match copyout::copyout(memory, *address, bytes)? {
                    copyout::Completion::Copied => None,
                    copyout::Completion::Fault { .. } => Some(DARWIN_EFAULT),
                }
            }
        };
        let completion = errno.map_or(BsdCompletion::Success { values: [0, 0] }, |errno| {
            BsdCompletion::Error { errno }
        });
        pending.complete(state, completion)?;
        Ok(completion)
    })();
    match result {
        Ok(completion) => event.completion = Some(completion),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

fn host_entropy(bytes: &mut [u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        // SAFETY: the complete writable buffer is local Rust-owned storage and
        // bounded by MAX_BYTES. No guest pointer is passed to the host syscall.
        let result = unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "host getentropy provider is unavailable",
    ))
}

#[cfg(test)]
mod tests;
