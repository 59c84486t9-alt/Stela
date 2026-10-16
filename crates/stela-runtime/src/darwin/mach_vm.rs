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
mod tests {
    use super::*;
    use std::cell::Cell;

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    fn stopped(arguments: [u64; ARGUMENT_COUNT], flags: u32) -> (ThreadState, SynchronousTrap) {
        use stela_compiler::{GuestAddress, GuestState, block::TrapKind};
        let trap = SynchronousTrap {
            kind: TrapKind::SupervisorCall,
            immediate: 0x80,
            instruction_pc: GuestAddress(0x1000),
            exception_return_pc: GuestAddress(0x1004),
        };
        let mut registers = GuestState {
            x: std::array::from_fn(|index| 0xdeadc0de12340000 + index as u64),
            sp: 0xfeed0000,
            nzcv: flags << 28,
            reserved: 0xa5a5,
            v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
            fpcr: 17,
            fpsr: 29,
        };
        registers.x[..ARGUMENT_COUNT].copy_from_slice(&arguments);
        registers.x[SYSCALL_SELECTOR_REGISTER] = u64::MAX - u64::from(PROTECT_TRAP) + 1;
        (
            ThreadState {
                registers,
                pc: trap.instruction_pc,
            },
            trap,
        )
    }

    #[test]
    fn invalid_task_and_zero_size_precede_other_validation() -> Result<()> {
        let called = Cell::new(false);
        let apply = |_, _, _, _| {
            called.set(true);
            Ok(KERN_SUCCESS)
        };
        assert_eq!(
            protect(false, u64::MAX, 0, true, u32::MAX, apply)?,
            MACH_SEND_INVALID_DEST
        );
        assert_eq!(
            protect(true, u64::MAX, 0, true, u32::MAX, apply)?,
            KERN_SUCCESS
        );
        assert!(!called.get());
        Ok(())
    }

    #[test]
    fn normalization_matches_pinned_protect_compatibility_samples() {
        for (address, size, result) in [
            (1, u64::MAX - 1, Err(KERN_INVALID_ADDRESS)),
            (0, u64::MAX, Err(KERN_INVALID_ADDRESS)),
            (
                GUEST_PAGE_BYTES,
                u64::MAX - GUEST_PAGE_BYTES,
                Err(KERN_INVALID_ARGUMENT),
            ),
            (u64::MAX, 1, Err(KERN_INVALID_ARGUMENT)),
            (
                GUEST_PAGE_BYTES + 1,
                1,
                Ok((GUEST_PAGE_BYTES, 2 * GUEST_PAGE_BYTES)),
            ),
            (
                2 * GUEST_PAGE_BYTES - 1,
                2,
                Ok((GUEST_PAGE_BYTES, 3 * GUEST_PAGE_BYTES)),
            ),
        ] {
            assert_eq!(
                normalized_range(address, size),
                result,
                "{address:#x}+{size:#x}"
            );
        }
    }

    #[test]
    fn ordinary_protection_rounds_both_ends_and_preserves_exact_rights() -> Result<()> {
        for protection in [0, PROTECTION_READ, PROTECTION_READ | PROTECTION_WRITE] {
            let mut seen = None;
            let result = protect(
                true,
                GUEST_PAGE_BYTES + 1,
                GUEST_PAGE_BYTES,
                false,
                protection,
                |start, bytes, readable, writable| {
                    seen = Some((start, bytes, readable, writable));
                    Ok(KERN_SUCCESS)
                },
            )?;
            assert_eq!(result, KERN_SUCCESS);
            assert_eq!(
                seen,
                Some((
                    GUEST_PAGE_BYTES,
                    2 * GUEST_PAGE_BYTES,
                    protection & PROTECTION_READ != 0,
                    protection & PROTECTION_WRITE != 0,
                ))
            );
        }
        Ok(())
    }

    #[test]
    fn valid_unimplemented_policies_decline_without_backend_effects() {
        for (maximum, protection) in [
            (true, PROTECTION_READ),
            (false, PROTECTION_WRITE),
            (false, PROTECTION_EXECUTE),
            (false, PROTECTION_COPY),
        ] {
            let called = Cell::new(false);
            let result = protect(
                true,
                GUEST_PAGE_BYTES,
                1,
                maximum,
                protection,
                |_, _, _, _| {
                    called.set(true);
                    Ok(KERN_SUCCESS)
                },
            );
            assert!(result.is_err());
            assert!(!called.get());
        }
    }

    #[test]
    fn invalid_masks_and_address_ranges_complete_without_backend_effects() -> Result<()> {
        for (address, size, protection, expected) in [
            (GUEST_PAGE_BYTES, 1, 8, KERN_INVALID_ARGUMENT),
            (GUEST_PAGE_BYTES, 1, 512, KERN_INVALID_ARGUMENT),
            (
                DIRECT_RAM_USER_END,
                1,
                PROTECTION_READ,
                KERN_INVALID_ADDRESS,
            ),
            (
                DIRECT_RAM_USER_END - 1,
                2,
                PROTECTION_READ,
                KERN_INVALID_ADDRESS,
            ),
            (u64::MAX, 1, PROTECTION_READ, KERN_INVALID_ARGUMENT),
        ] {
            let called = Cell::new(false);
            assert_eq!(
                protect(true, address, size, false, protection, |_, _, _, _| {
                    called.set(true);
                    Ok(KERN_SUCCESS)
                })?,
                expected
            );
            assert!(!called.get());
        }
        Ok(())
    }

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    #[test]
    fn owned_task_resolution_and_completion_preserve_complete_thread_state() -> Result<()> {
        let mut ports = HostPorts::new(17)?;
        let task = ports.request(&crate::mach::Request {
            number: crate::mach::TASK_SELF_TRAP,
            arguments: Vec::new(),
        })? as u32;
        let thread = ports.request(&crate::mach::Request {
            number: crate::mach::THREAD_SELF_TRAP,
            arguments: Vec::new(),
        })? as u32;
        let mut memory = OwnedMemory::map(Vec::new())?;
        let runtime = BlockRuntime::new(17, std::path::PathBuf::new());
        for flags in 0..16 {
            for (arguments, result) in [
                (
                    [u64::from(task) | (1 << 48), u64::MAX, 0, u64::MAX, u64::MAX],
                    KERN_SUCCESS,
                ),
                ([u64::from(thread), 0, 0, 0, 0], MACH_SEND_INVALID_DEST),
                ([0, u64::MAX, 0, 0, 0], MACH_SEND_INVALID_DEST),
                (
                    [
                        u64::from(task),
                        GUEST_PAGE_BYTES,
                        1,
                        1 << 32,
                        u64::from(PROTECTION_READ) | (1 << 32),
                    ],
                    KERN_INVALID_ADDRESS,
                ),
                (
                    [u64::from(task), GUEST_PAGE_BYTES, 1, 0, 512],
                    KERN_INVALID_ARGUMENT,
                ),
            ] {
                let (mut state, trap) = stopped(arguments, flags);
                assert!(handles(&state, &trap));
                let mut expected = state.clone();
                expected.registers.x[0] = result as i64 as u64;
                expected.pc = trap.exception_return_pc;
                let event = service(&mut state, &trap, &ports, &mut memory, &runtime);
                assert_eq!(event.result, Some(result));
                assert!(event.declined.is_none());
                assert_eq!(state.pc, expected.pc);
                assert_eq!(state.registers, expected.registers);
            }
        }
        Ok(())
    }

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    #[test]
    fn actual_owned_protection_changes_access_and_declines_preserve_state() -> Result<()> {
        use crate::memory::MemoryRegionSpec;
        const BASE: u64 = 0x6c0000000000;
        let mut memory = OwnedMemory::map(vec![MemoryRegionSpec {
            guest_address: BASE,
            virtual_bytes: 2 * GUEST_PAGE_BYTES,
            initial_bytes: vec![0x5a; 2 * GUEST_PAGE_BYTES as usize],
            readable: true,
            writable: true,
            executable: false,
        }])?;
        let mut ports = HostPorts::new(18)?;
        let task = ports.request(&crate::mach::Request {
            number: crate::mach::TASK_SELF_TRAP,
            arguments: Vec::new(),
        })? as u32;
        let runtime = BlockRuntime::new(18, std::path::PathBuf::new());
        let (mut state, trap) = stopped(
            [
                u64::from(task),
                BASE + 1,
                GUEST_PAGE_BYTES,
                0,
                u64::from(PROTECTION_READ),
            ],
            15,
        );
        assert_eq!(
            service(&mut state, &trap, &ports, &mut memory, &runtime).result,
            Some(KERN_SUCCESS)
        );
        assert!(memory.write(BASE, &[1]).is_err());
        assert!(memory.write(BASE + GUEST_PAGE_BYTES, &[1]).is_err());
        assert_eq!(memory.read_snapshot(BASE, 1)?, vec![0x5a]);
        for (maximum, protection) in [
            (1, PROTECTION_READ),
            (0, PROTECTION_WRITE),
            (0, PROTECTION_COPY),
            (0, PROTECTION_EXECUTE),
        ] {
            let (mut state, trap) = stopped(
                [u64::from(task), BASE, 1, maximum, u64::from(protection)],
                15,
            );
            let before = state.clone();
            let views = memory.regions().to_vec();
            let event = service(&mut state, &trap, &ports, &mut memory, &runtime);
            assert!(event.result.is_none());
            assert!(event.declined.is_some());
            assert_eq!(state.pc, before.pc);
            assert_eq!(state.registers, before.registers);
            assert_eq!(memory.regions(), views);
        }
        Ok(())
    }
}
