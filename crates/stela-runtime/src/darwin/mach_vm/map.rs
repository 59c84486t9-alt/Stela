//! Anonymous Mach VM allocation. As in XNU, the address is copied in, the
//! mapping published, then the address copied out; a copyout failure keeps the
//! allocation.

use super::{
    GUEST_PAGE_MASK, KERN_INVALID_ADDRESS, KERN_INVALID_ARGUMENT, KERN_SUCCESS,
    MACH_SEND_INVALID_DEST, PROTECTION_EXECUTE, PROTECTION_READ, PROTECTION_WRITE,
};
use crate::{
    blocks::{BlockRuntime, ThreadState},
    darwin::{SYSCALL_SELECTOR_REGISTER, copyout, validate_trap},
    mach::{HostPorts, PendingCall, Request},
    memory::{
        AllocateDataError, AllocateDataRequest, DIRECT_RAM_USER_END, DataAllocation,
        DataInheritance, DataPermissions, DataPlacement, OwnedMemory,
    },
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString};
use anyhow::{Result, ensure};
use serde::Serialize;
use stela_compiler::block::SynchronousTrap;

pub const PROFILE_ID: &str = "darwin-arm64-owned-anonymous-mach-vm-map-v1";
pub const MAP_TRAP: u32 = 15;
pub const KERN_NO_SPACE: i32 = 3;
pub const KERN_MEMORY_ERROR: i32 = 10;

const ARGUMENT_COUNT: usize = 6;
const ADDRESS_BYTES: usize = size_of::<u64>();
const PROTECTION_ALL: u32 = PROTECTION_READ | PROTECTION_WRITE | PROTECTION_EXECUTE;
const PROTECTION_IS_MASK: u32 = 0x40;

const FLAGS_ANYWHERE: u32 = 0x00000001;
const FLAGS_PURGABLE: u32 = 0x00000002;
const FLAGS_4GB_CHUNK: u32 = 0x00000004;
const FLAGS_RANDOM_ADDRESS: u32 = 0x00000008;
const FLAGS_NO_CACHE: u32 = 0x00000010;
const FLAGS_PERMANENT: u32 = 0x00000080;
const FLAGS_TPRO: u32 = 0x00001000;
const FLAGS_OVERWRITE: u32 = 0x00004000;
const FLAGS_SUPERPAGE_MASK: u32 = 0x00070000;
const FLAGS_RETURN_DATA_ADDRESS: u32 = 0x00100000;
const FLAGS_RETURN_4K_DATA_ADDRESS: u32 = 0x00800000;
const FLAGS_ALIAS_MASK: u32 = 0xff000000;
const FLAGS_ALIAS_SHIFT: u32 = 24;
const FLAGS_USER_MAP: u32 = FLAGS_ANYWHERE
    | FLAGS_PURGABLE
    | FLAGS_4GB_CHUNK
    | FLAGS_RANDOM_ADDRESS
    | FLAGS_NO_CACHE
    | FLAGS_PERMANENT
    | FLAGS_TPRO
    | FLAGS_OVERWRITE
    | FLAGS_SUPERPAGE_MASK
    | FLAGS_RETURN_DATA_ADDRESS
    | FLAGS_RETURN_4K_DATA_ADDRESS
    | FLAGS_ALIAS_MASK;
const FLAGS_IMPLEMENTED: u32 = FLAGS_ANYWHERE | FLAGS_ALIAS_MASK;

#[derive(Debug, Serialize)]
pub struct Event {
    pub trap: SynchronousTrap,
    pub request: Option<Request>,
    pub result: Option<i32>,
    pub declined: Option<String>,
    pub allocation: Option<DataAllocation>,
    pub copyout_bytes: usize,
}

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    validate_trap(state, trap).is_ok()
        && state.registers.x[SYSCALL_SELECTOR_REGISTER] as u32 as i32 == -(MAP_TRAP as i32)
}

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
        allocation: None,
        copyout_bytes: 0,
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
        ensure!(request.number == MAP_TRAP, "not a Mach VM map trap");
        let arguments: [u64; ARGUMENT_COUNT] = request.arguments.as_slice().try_into()?;
        let [task, ..] = arguments;
        let owned_task = ports.has_task_send(task as u32);
        let result = if owned_task {
            map_and_copyout(arguments, memory, runtime, &mut event)?
        } else {
            MACH_SEND_INVALID_DEST
        };
        pending.complete(state, result)?;
        Ok(result)
    })();
    match result {
        Ok(result) => event.result = Some(result),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

fn map_and_copyout(
    arguments: [u64; ARGUMENT_COUNT],
    memory: &mut OwnedMemory,
    runtime: &BlockRuntime,
    event: &mut Event,
) -> Result<i32> {
    let [_, address_pointer, ..] = arguments;
    // Partial copyin only touches a private kernel-side buffer. No allocation
    // occurs unless every byte of the initial address was read successfully.
    let initial_address = match memory.read_snapshot(address_pointer, ADDRESS_BYTES) {
        Ok(bytes) => u64::from_le_bytes(bytes.try_into().expect("eight-byte address snapshot")),
        Err(_) => return Ok(KERN_MEMORY_ERROR),
    };
    let request = match plan(arguments, initial_address)? {
        Plan::Complete(result) => return Ok(result),
        Plan::Allocate(request) => request,
    };
    let pending = match memory.begin_data_allocation(request) {
        Ok(pending) => pending,
        Err(AllocateDataError::AddressUnavailable) => return Ok(KERN_NO_SPACE),
        Err(error) => return Err(error.into()),
    };
    let candidate = pending.allocation();
    ensure!(
        !runtime.source_overlaps(candidate.guest_address, candidate.mapped_bytes),
        "anonymous allocation overlaps a registered code snapshot"
    );
    let allocation = pending.publish()?;
    event.allocation = Some(allocation);
    match copyout::copyout(
        memory,
        address_pointer,
        &allocation.guest_address.to_le_bytes(),
    )? {
        copyout::Completion::Copied => {
            event.copyout_bytes = ADDRESS_BYTES;
            Ok(KERN_SUCCESS)
        }
        copyout::Completion::Fault { completed } => {
            event.copyout_bytes = completed;
            Ok(KERN_MEMORY_ERROR)
        }
    }
}

enum Plan {
    Complete(i32),
    Allocate(AllocateDataRequest),
}

fn plan(arguments: [u64; ARGUMENT_COUNT], initial_address: u64) -> Result<Plan> {
    let [_, _, size, mask, flags, protection] = arguments;
    let flags = flags as u32;
    let protection = protection as u32;
    if flags & !FLAGS_USER_MAP != 0 || protection & !(PROTECTION_ALL | PROTECTION_IS_MASK) != 0 {
        return Ok(Plan::Complete(KERN_INVALID_ARGUMENT));
    }
    if size == 0 {
        return Ok(Plan::Complete(KERN_INVALID_ARGUMENT));
    }
    let start = initial_address & !GUEST_PAGE_MASK;
    let anywhere = flags & FLAGS_ANYWHERE != 0;
    // Fixed mapping realigns start before adding size. Anywhere mapping rounds
    // size independently of its hint; neither uses protect's normalization.
    let raw_end = if anywhere {
        Some(size)
    } else {
        start.checked_add(size)
    };
    let end = match raw_end.and_then(|end| end.checked_add(GUEST_PAGE_MASK)) {
        Some(end) => end & !GUEST_PAGE_MASK,
        None => return Ok(Plan::Complete(KERN_INVALID_ARGUMENT)),
    };
    let bytes = if anywhere { end } else { end - start };
    // Unimplemented policies can fail before placement in XNU. Do not infer
    // their result from the ordinary allocator's fixed-mask or bounds rules.
    ensure!(
        flags & !FLAGS_IMPLEMENTED == 0,
        "Mach mapping flags require an unimplemented VM policy"
    );
    ensure!(
        protection & (PROTECTION_EXECUTE | PROTECTION_IS_MASK) == 0,
        "executable/masked protection requires a reviewed publication policy"
    );
    let current = DataPermissions {
        readable: protection & PROTECTION_READ != 0,
        writable: protection & PROTECTION_WRITE != 0,
        executable: false,
    };
    ensure!(
        !current.writable || current.readable,
        "write-only Mach mapping is unsupported by the direct-mapping profile"
    );
    if !anywhere && start & mask != 0 {
        return Ok(Plan::Complete(KERN_NO_SPACE));
    }
    if anywhere && (start >= DIRECT_RAM_USER_END || bytes >= DIRECT_RAM_USER_END) {
        return Ok(Plan::Complete(KERN_NO_SPACE));
    }
    if !anywhere && (start >= DIRECT_RAM_USER_END || end > DIRECT_RAM_USER_END) {
        return Ok(Plan::Complete(KERN_INVALID_ADDRESS));
    }
    Ok(Plan::Allocate(AllocateDataRequest {
        placement: if anywhere {
            DataPlacement::Anywhere { hint: start }
        } else {
            DataPlacement::Fixed(start)
        },
        bytes,
        alignment_mask: mask | GUEST_PAGE_MASK,
        current,
        maximum: DataPermissions {
            readable: true,
            writable: true,
            executable: true,
        },
        alias_tag: ((flags & FLAGS_ALIAS_MASK) >> FLAGS_ALIAS_SHIFT) as u8,
        inheritance: DataInheritance::Copy,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::GUEST_PAGE_BYTES;

    const READ_WRITE: u64 = (PROTECTION_READ | PROTECTION_WRITE) as u64;
    const ALIAS_TAG: u8 = 60;
    const BASE: u64 = 0x100000000;
    const UNKNOWN_FLAG: u64 = 0x100;
    const TASK_NAME: u64 = 257;
    const ADDRESS_POINTER: u64 = 0x9000000f428;
    const OBSERVED_BYTES: u64 = 8 * GUEST_PAGE_BYTES;

    fn arguments(size: u64, mask: u64, flags: u64, protection: u64) -> [u64; ARGUMENT_COUNT] {
        [TASK_NAME, ADDRESS_POINTER, size, mask, flags, protection]
    }

    fn completion(arguments: [u64; ARGUMENT_COUNT], initial: u64) -> i32 {
        match plan(arguments, initial).unwrap() {
            Plan::Complete(result) => result,
            Plan::Allocate(_) => panic!("expected a completed validation error"),
        }
    }

    #[test]
    fn observed_request_preserves_alias_maximum_and_implicit_inheritance() -> Result<()> {
        let flags = u64::from(FLAGS_ANYWHERE) | (u64::from(ALIAS_TAG) << FLAGS_ALIAS_SHIFT);
        let Plan::Allocate(request) = plan(
            arguments(OBSERVED_BYTES, GUEST_PAGE_MASK, flags, READ_WRITE),
            BASE,
        )?
        else {
            panic!("valid observed request declined");
        };
        assert!(matches!(
            request.placement,
            DataPlacement::Anywhere { hint: BASE }
        ));
        assert_eq!(request.bytes, OBSERVED_BYTES);
        assert_eq!(request.alignment_mask, GUEST_PAGE_MASK);
        assert_eq!(request.alias_tag, ALIAS_TAG);
        assert!(
            request.current.readable && request.current.writable && !request.current.executable
        );
        assert!(request.maximum.readable && request.maximum.writable && request.maximum.executable);
        assert!(matches!(request.inheritance, DataInheritance::Copy));
        Ok(())
    }

    #[test]
    fn low32_flags_and_protection_do_not_truncate_size_or_mask() -> Result<()> {
        let Plan::Allocate(request) = plan(
            arguments(
                GUEST_PAGE_BYTES + 1,
                1 << 40,
                (1 << 48) | u64::from(FLAGS_ANYWHERE),
                (1 << 48) | READ_WRITE,
            ),
            BASE + 1,
        )?
        else {
            panic!("low32 truncation failed")
        };
        assert!(matches!(
            request.placement,
            DataPlacement::Anywhere { hint: BASE }
        ));
        assert_eq!(request.bytes, 2 * GUEST_PAGE_BYTES);
        assert_eq!(request.alignment_mask, (1 << 40) | GUEST_PAGE_MASK);
        assert_eq!(
            completion(
                arguments(1 << 63, 0, u64::from(FLAGS_ANYWHERE), READ_WRITE),
                BASE
            ),
            KERN_NO_SPACE
        );
        Ok(())
    }

    #[test]
    fn fixed_start_is_realigned_before_adding_size_and_mask_precedes_bounds() -> Result<()> {
        let Plan::Allocate(request) = plan(
            arguments(GUEST_PAGE_BYTES, 0, 0, READ_WRITE),
            BASE + GUEST_PAGE_MASK,
        )?
        else {
            panic!("unaligned fixed request failed");
        };
        assert!(matches!(request.placement, DataPlacement::Fixed(BASE)));
        assert_eq!(request.bytes, GUEST_PAGE_BYTES);
        assert_eq!(
            completion(
                arguments(1, DIRECT_RAM_USER_END, 0, READ_WRITE),
                DIRECT_RAM_USER_END
            ),
            KERN_NO_SPACE
        );
        assert_eq!(
            completion(arguments(1, 0, 0, READ_WRITE), DIRECT_RAM_USER_END),
            KERN_INVALID_ADDRESS
        );
        Ok(())
    }

    #[test]
    fn invalid_flags_protections_zero_and_overflow_complete_without_allocation() {
        for (size, mask, flags, protection, initial) in [
            (0, 0, 0, READ_WRITE, BASE),
            (1, 0, UNKNOWN_FLAG, READ_WRITE, BASE),
            (1, 0, 0, 0x10, BASE),
            (u64::MAX, 0, u64::from(FLAGS_ANYWHERE), READ_WRITE, BASE),
            (u64::MAX, 0, 0, READ_WRITE, BASE),
        ] {
            assert_eq!(
                completion(arguments(size, mask, flags, protection), initial),
                KERN_INVALID_ARGUMENT
            );
        }
    }

    #[test]
    fn valid_unimplemented_mapping_policies_explicitly_decline() {
        for (flags, protection) in [
            (FLAGS_PURGABLE, READ_WRITE),
            (FLAGS_TPRO, READ_WRITE),
            (FLAGS_OVERWRITE, READ_WRITE),
            (FLAGS_RETURN_DATA_ADDRESS, READ_WRITE),
            (0, u64::from(PROTECTION_EXECUTE)),
            (0, u64::from(PROTECTION_IS_MASK)),
            (0, u64::from(PROTECTION_WRITE)),
        ] {
            assert!(plan(arguments(1, 0, u64::from(flags), protection), BASE).is_err());
        }
        for initial in [GUEST_PAGE_BYTES, DIRECT_RAM_USER_END] {
            assert!(
                plan(
                    arguments(1, initial, u64::from(FLAGS_SUPERPAGE_MASK), READ_WRITE),
                    initial
                )
                .is_err()
            );
        }
    }
}
