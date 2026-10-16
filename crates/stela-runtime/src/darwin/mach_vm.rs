//! Owned ordinary-data Mach VM protection for the explicit ARM64 process profile.
//!
//! Contract: public XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
//! mach_kernelrpc.c, vm_user.c, vm_sanitize.c and vm_map.c. This is not a
//! host-port forwarding service or the complete private macOS VM policy.

use crate::{
    blocks::{BlockRuntime, ThreadState},
    darwin::{GUEST_PAGE_BYTES, SYSCALL_SELECTOR_REGISTER, validate_trap},
    mach::{Event, HostPorts, PendingCall},
    memory::{DIRECT_RAM_USER_END, OwnedMemory, ProtectionError},
};
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use anyhow::{Result, ensure};
use stela_compiler::block::SynchronousTrap;

pub mod map;

pub const PROFILE_ID: &str = "darwin-arm64-owned-data-mach-vm-protect-v1";
pub const PROTECT_TRAP: u32 = 14;
pub const KERN_SUCCESS: i32 = 0;
pub const KERN_INVALID_ADDRESS: i32 = 1;
pub const KERN_PROTECTION_FAILURE: i32 = 2;
pub const KERN_INVALID_ARGUMENT: i32 = 4;
pub const MACH_SEND_INVALID_DEST: i32 = 0x10000003;

const PROTECTION_READ: u32 = 1;
const PROTECTION_WRITE: u32 = 2;
const PROTECTION_EXECUTE: u32 = 4;
const PROTECTION_COPY: u32 = 16;
const ALLOWED_PROTECTION: u32 =
    PROTECTION_READ | PROTECTION_WRITE | PROTECTION_EXECUTE | PROTECTION_COPY;
const ARGUMENT_COUNT: usize = 5;
const GUEST_PAGE_MASK: u64 = GUEST_PAGE_BYTES - 1;

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    validate_trap(state, trap).is_ok()
        && state.registers.x[SYSCALL_SELECTOR_REGISTER] as u32 as i32 == -(PROTECT_TRAP as i32)
}

/// Protect only mapped ordinary data owned by this address space. Valid policy
/// requests outside this profile remain stopped, with no fabricated completion.
pub fn service(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    ports: &HostPorts,
    memory: &mut OwnedMemory,
    runtime: &BlockRuntime,
) -> Event {
    let mut event = Event {
        trap: *trap,
        request: None,
        result: None,
        declined: None,
    };
    let result = (|| -> Result<i32> {
        ensure!(memory.is_usable(), "guest address space is unusable");
        ensure!(
            ports.address_space() == runtime.address_space(),
            "Mach ports belong to another guest address space"
        );
        let pending = PendingCall::from_trap(state, trap, ARGUMENT_COUNT)?;
        let request = pending.request();
        event.request = Some(request.clone());
        ensure!(
            request.number == PROTECT_TRAP,
            "not a Mach VM protection trap"
        );
        let [task, address, size, set_maximum, protection]: [u64; ARGUMENT_COUNT] =
            request.arguments.as_slice().try_into()?;
        let owned_task = ports.has_task_send(task as u32);
        let result = protect(
            owned_task,
            address,
            size,
            set_maximum as u32 != 0,
            protection as u32,
            |start, bytes, readable, writable| {
                ensure!(
                    !runtime.source_overlaps(start, bytes),
                    "data protection overlaps a registered code snapshot"
                );
                match memory.protect_data(start, bytes, readable, writable) {
                    Ok(()) => Ok(KERN_SUCCESS),
                    Err(ProtectionError::UnmappedRange) => Ok(KERN_INVALID_ADDRESS),
                    Err(ProtectionError::MaximumProtection) => Ok(KERN_PROTECTION_FAILURE),
                    Err(ProtectionError::InvalidRange) => Ok(KERN_INVALID_ARGUMENT),
                    Err(error) => Err(error.into()),
                }
            },
        )?;
        pending.complete(state, result)?;
        Ok(result)
    })();
    match result {
        Ok(result) => event.result = Some(result),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

fn protect(
    owned_task: bool,
    address: u64,
    size: u64,
    set_maximum: bool,
    protection: u32,
    apply: impl FnOnce(u64, u64, bool, bool) -> Result<i32>,
) -> Result<i32> {
    // XNU resolves the task control port before inspecting the VM request.
    if !owned_task {
        return Ok(MACH_SEND_INVALID_DEST);
    }
    if size == 0 {
        return Ok(KERN_SUCCESS);
    }
    if protection & !ALLOWED_PROTECTION != 0 {
        return Ok(KERN_INVALID_ARGUMENT);
    }
    let (start, end) = match normalized_range(address, size) {
        Ok(range) => range,
        Err(result) => return Ok(result),
    };
    if start >= DIRECT_RAM_USER_END || end > DIRECT_RAM_USER_END {
        return Ok(KERN_INVALID_ADDRESS);
    }
    ensure!(
        protection & (PROTECTION_EXECUTE | PROTECTION_COPY) == 0,
        "execute/copy protection requires a reviewed publication or copy policy"
    );
    ensure!(
        !set_maximum,
        "maximum-rights changes require an owned per-range maximum protection service"
    );
    let readable = protection & PROTECTION_READ != 0;
    let writable = protection & PROTECTION_WRITE != 0;
    ensure!(
        !writable || readable,
        "write-only Mach protection is unsupported by the direct-mapping profile"
    );
    apply(start, end - start, readable, writable)
}

fn normalized_range(address: u64, size: u64) -> core::result::Result<(u64, u64), i32> {
    let start = address & !GUEST_PAGE_MASK;
    let raw_end = address.checked_add(size).ok_or(KERN_INVALID_ARGUMENT)?;
    let end = raw_end.wrapping_add(GUEST_PAGE_MASK) & !GUEST_PAGE_MASK;
    if end > start {
        return Ok((start, end));
    }
    // Protect-specific source compatibility rewrites some rounding overflow to
    // INVALID_ADDRESS. Preserve its wrapping unsigned arithmetic explicitly.
    let bytes = end.wrapping_sub(start);
    if bytes == 0 || start.checked_add(bytes).is_some() {
        Err(KERN_INVALID_ADDRESS)
    } else {
        Err(KERN_INVALID_ARGUMENT)
    }
}

#[cfg(test)]
mod tests;
