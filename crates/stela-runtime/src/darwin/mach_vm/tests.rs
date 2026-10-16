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
