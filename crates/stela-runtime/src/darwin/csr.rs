//! System-integrity (CSR) policy queries against a fixed guest policy
//! (XNU `bsd/kern/kern_csr.c`). The host's policy is never consulted.

use super::{
    BsdCompletion, BsdPrototype, BsdReturnType, BsdServiceEvent, PendingBsdCall, classify_bsd_call,
};
use crate::{
    blocks::ThreadState,
    memory::{DIRECT_RAM_USER_END, OwnedMemory},
};
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use anyhow::{Result, ensure};
use serde::Serialize;
use stela_compiler::block::SynchronousTrap;

pub const PROFILE_ID: &str = "darwin-arm64-immutable-csr-policy-v1";
pub const SYSCALL_NUMBER: u16 = 483;
pub const CHECK: u32 = 0;
pub const GET_ACTIVE_CONFIG: u32 = 1;

const ALLOW_UNTRUSTED_KEXTS: u32 = 1 << 0;
const ALLOW_UNRESTRICTED_FS: u32 = 1 << 1;
const ALLOW_TASK_FOR_PID: u32 = 1 << 2;
const ALLOW_KERNEL_DEBUGGER: u32 = 1 << 3;
const ALLOW_APPLE_INTERNAL: u32 = 1 << 4;
const ALLOW_UNRESTRICTED_DTRACE: u32 = 1 << 5;
const ALLOW_UNRESTRICTED_NVRAM: u32 = 1 << 6;
const ALLOW_DEVICE_CONFIGURATION: u32 = 1 << 7;
const ALLOW_ANY_RECOVERY_OS: u32 = 1 << 8;
const ALLOW_UNAPPROVED_KEXTS: u32 = 1 << 9;
const ALLOW_EXECUTABLE_POLICY_OVERRIDE: u32 = 1 << 10;
const ALLOW_UNAUTHENTICATED_ROOT: u32 = 1 << 11;
const ALLOW_RESEARCH_GUESTS: u32 = 1 << 12;
const VALID_FLAGS: u32 = ALLOW_UNTRUSTED_KEXTS
    | ALLOW_UNRESTRICTED_FS
    | ALLOW_TASK_FOR_PID
    | ALLOW_KERNEL_DEBUGGER
    | ALLOW_APPLE_INTERNAL
    | ALLOW_UNRESTRICTED_DTRACE
    | ALLOW_UNRESTRICTED_NVRAM
    | ALLOW_DEVICE_CONFIGURATION
    | ALLOW_ANY_RECOVERY_OS
    | ALLOW_UNAPPROVED_KEXTS
    | ALLOW_EXECUTABLE_POLICY_OVERRIDE
    | ALLOW_UNAUTHENTICATED_ROOT
    | ALLOW_RESEARCH_GUESTS;
const CONFIG_BYTES: usize = size_of::<u32>();
const DARWIN_EPERM: u32 = 1;
const DARWIN_EFAULT: u32 = 14;
const DARWIN_EINVAL: u32 = 22;
const DARWIN_ENOSYS: u32 = 78;
const PROTOTYPE: BsdPrototype = BsdPrototype {
    argument_count: 3,
    return_type: BsdReturnType::Int,
};

/// A caller-declared guest configuration, rather than inferred boot policy.
/// Active configuration and the effective CHECK mask intentionally differ:
/// ARM XNU allows kernel debugging when untrusted kexts or AppleInternal is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ArmSecurityPolicy {
    active_configuration: u32,
}

impl ArmSecurityPolicy {
    pub fn new(active_configuration: u32) -> Result<Self> {
        ensure!(
            active_configuration & !VALID_FLAGS == 0,
            "CSR policy contains flags outside the pinned ARM contract"
        );
        Ok(Self {
            active_configuration,
        })
    }

    pub fn active_configuration(&self) -> u32 {
        self.active_configuration
    }

    pub fn permits(&self, requested: u32) -> bool {
        let mut effective = self.active_configuration;
        if effective & (ALLOW_UNTRUSTED_KEXTS | ALLOW_APPLE_INTERNAL) != 0 {
            effective |= ALLOW_KERNEL_DEBUGGER;
        }
        effective & requested == requested
    }
}

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    classify_bsd_call(state, trap).is_ok_and(|selector| selector.number == SYSCALL_NUMBER)
}

/// Service a query over serialized owned guest memory. Unknown operations use
/// the syscall's ENOSYS result; calls for other services remain pending.
/// Copyout checks the user address range first, then preserves the completed
/// byte prefix if a later destination byte is unmapped or not writable.
pub fn service(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    memory: &mut OwnedMemory,
    policy: &ArmSecurityPolicy,
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
            "BSD service {} is not implemented by the CSR profile",
            request.number
        );
        let [operation, address, size] = request.arguments() else {
            unreachable!("the validated CSR prototype contains three arguments")
        };
        let errno = match *operation as u32 {
            CHECK | GET_ACTIVE_CONFIG if *address == 0 || *size != CONFIG_BYTES as u64 => {
                Some(DARWIN_EINVAL)
            }
            CHECK => match memory.read_snapshot(*address, CONFIG_BYTES) {
                Ok(bytes) => {
                    let requested =
                        u32::from_le_bytes(bytes.try_into().expect("four-byte CSR mask"));
                    (!policy.permits(requested)).then_some(DARWIN_EPERM)
                }
                Err(_) => Some(DARWIN_EFAULT),
            },
            GET_ACTIVE_CONFIG => copy_active_configuration(memory, *address, policy),
            _ => Some(DARWIN_ENOSYS),
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

fn copy_active_configuration(
    memory: &mut OwnedMemory,
    address: u64,
    policy: &ArmSecurityPolicy,
) -> Option<u32> {
    // Pinned ARM copyio.c validates the complete numeric user range before
    // BCOPY_IMPL performs a forward byte copy for lengths below sixteen.
    // OwnedMemory supplies this serialized profile's lower-VA47 user bound;
    // forbidden top-byte tags are outside it and therefore fail the range check.
    if address
        .checked_add(CONFIG_BYTES as u64)
        .is_none_or(|end| end > DIRECT_RAM_USER_END)
    {
        return Some(DARWIN_EFAULT);
    }
    for (offset, byte) in policy.active_configuration.to_le_bytes().iter().enumerate() {
        if memory
            .write(address + offset as u64, core::slice::from_ref(byte))
            .is_err()
        {
            return Some(DARWIN_EFAULT);
        }
    }
    None
}

#[cfg(test)]
mod tests;
