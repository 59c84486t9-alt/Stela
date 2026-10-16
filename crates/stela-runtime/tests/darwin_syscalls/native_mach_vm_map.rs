//! Mach VM anonymous mapping.
#![cfg(target_os = "macos")]

use super::*;
use stela_runtime::{
    darwin::{ExecutionServices, GUEST_PAGE_BYTES, ServiceRunOutcome, mach_vm, run_services},
    mach::{HostPorts, Request, TASK_SELF_TRAP},
    memory::DataInheritance,
};

const SVC_DARWIN: u32 = 0xd4001001;
const RET_X30: u32 = 0xd65f03c0;
const INSTRUCTION_BYTES: u64 = 4;
const SELECTOR_REGISTER: usize = 16;
const ARGUMENT_COUNT: usize = 6;
const NZCV_COMBINATIONS: u32 = 16;
const ADDRESS_BYTES: usize = size_of::<u64>();
const OWNED_RAM_BYTES: usize = 2 * GUEST_PAGE_BYTES as usize;
const ALLOCATION_BYTES: u64 = 8 * GUEST_PAGE_BYTES;
const ALLOCATION_HINT: u64 = 0x100000000;
const GUEST_PAGE_MASK: u64 = GUEST_PAGE_BYTES - 1;
const FLAGS_ANYWHERE: u64 = 1;
const FLAGS_TPRO: u64 = 0x1000;
const UNKNOWN_FLAG: u64 = 0x100;
const ALIAS_TAG: u8 = 60;
const ALIAS_SHIFT: u32 = 24;
const FLAGS_ALIAS: u64 = (ALIAS_TAG as u64) << ALIAS_SHIFT;
const READ_WRITE: u64 = 3;
const WRITE_ONLY: u64 = 2;

fn ports(runtime: &BlockRuntime) -> Result<(HostPorts, u64)> {
    let mut ports = HostPorts::new(runtime.address_space())?;
    let task = ports.request(&Request {
        number: TASK_SELF_TRAP,
        arguments: Vec::new(),
    })? as u32;
    Ok((ports, u64::from(task)))
}

fn request(flags: u32, task: u64, address_pointer: u64) -> ThreadState {
    let mut state = thread(flags, address_pointer);
    state.registers.x[..ARGUMENT_COUNT].copy_from_slice(&[
        task,
        address_pointer,
        ALLOCATION_BYTES,
        GUEST_PAGE_MASK,
        FLAGS_ANYWHERE | FLAGS_ALIAS,
        READ_WRITE,
    ]);
    state.registers.x[SELECTOR_REGISTER] = u64::MAX - u64::from(mach_vm::map::MAP_TRAP) + 1;
    state
}

fn run(
    runtime: &mut BlockRuntime,
    state: &mut ThreadState,
    memory: &mut OwnedMemory,
    ports: &mut HostPorts,
    enabled: bool,
    budget: usize,
) -> Result<ServiceRunOutcome> {
    // SAFETY: SVC/RET code with no RAM access; the backend owns the allocation
    // and copyout.
    unsafe {
        run_services(
            runtime,
            state,
            Some(GuestAddress(STOP)),
            budget,
            memory,
            ExecutionServices {
                mach_vm_map: enabled,
                mach_ports: Some(ports),
                ..ExecutionServices::default()
            },
        )
    }
}

#[test]
fn native_observed_request_preserves_full_state_ram_and_allocation_metadata() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut ports, task) = ports(&runtime)?;
    for flags in 0..NZCV_COMBINATIONS {
        let (mut memory, address) = vm_buffer(true)?;
        memory.write(address, &ALLOCATION_HINT.to_le_bytes())?;
        let mut expected_ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
        let mut state = request(flags, task | (1 << 48), address);
        state.registers.x[4] |= 1 << 48;
        state.registers.x[5] |= 1 << 48;
        let mut expected = state.clone();
        expected.pc = GuestAddress(STOP);
        expected.registers.x[0] = mach_vm::KERN_SUCCESS as u64;
        let outcome = run(&mut runtime, &mut state, &mut memory, &mut ports, true, 2)?;
        assert_eq!(outcome.execution.reason, StopReason::StopAddress);
        assert_state(&state, &expected);
        assert_eq!(outcome.mach_vm_map_services.len(), 1);
        let event = &outcome.mach_vm_map_services[0];
        assert_eq!(event.result, Some(mach_vm::KERN_SUCCESS));
        assert!(event.declined.is_none());
        assert_eq!(event.copyout_bytes, ADDRESS_BYTES);
        assert_eq!(
            event.request.as_ref().unwrap().arguments.len(),
            ARGUMENT_COUNT
        );
        let allocation = event.allocation.unwrap();
        assert!(allocation.guest_address >= ALLOCATION_HINT);
        assert_eq!(allocation.guest_address & GUEST_PAGE_MASK, 0);
        assert_eq!(allocation.virtual_bytes, ALLOCATION_BYTES);
        assert_eq!(allocation.alias_tag, ALIAS_TAG);
        assert_eq!(allocation.inheritance, DataInheritance::Copy);
        assert!(
            allocation.maximum.readable
                && allocation.maximum.writable
                && allocation.maximum.executable
        );
        assert_eq!(
            memory.data_allocation_at(allocation.guest_address),
            Some(allocation)
        );
        let region = memory
            .regions()
            .iter()
            .find(|region| region.guest_address == allocation.guest_address)
            .unwrap();
        assert!(region.readable && region.writable && !region.executable);
        assert_eq!(
            memory.read_snapshot(allocation.guest_address, ALLOCATION_BYTES as usize)?,
            vec![0; ALLOCATION_BYTES as usize]
        );
        expected_ram[..ADDRESS_BYTES].copy_from_slice(&allocation.guest_address.to_le_bytes());
        assert_eq!(
            memory.read_snapshot(address, OWNED_RAM_BYTES)?,
            expected_ram
        );
    }
    Ok(())
}

#[test]
fn invalid_requests_and_disabled_or_unsupported_profiles_preserve_owned_memory() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut ports, task) = ports(&runtime)?;
    let (mut memory, address) = vm_buffer(true)?;
    memory.write(address, &ALLOCATION_HINT.to_le_bytes())?;
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    let views = memory.regions().to_vec();
    for flags in 0..NZCV_COMBINATIONS {
        for case in 0..7 {
            let mut state = request(flags, task, address);
            let result = match case {
                0 => {
                    state.registers.x[0] = 0;
                    state.registers.x[1] = u64::MAX;
                    Some(mach_vm::MACH_SEND_INVALID_DEST)
                }
                1 => {
                    state.registers.x[1] = u64::MAX;
                    Some(mach_vm::map::KERN_MEMORY_ERROR)
                }
                2 => {
                    state.registers.x[2] = 0;
                    Some(mach_vm::KERN_INVALID_ARGUMENT)
                }
                3 => {
                    state.registers.x[4] |= UNKNOWN_FLAG;
                    Some(mach_vm::KERN_INVALID_ARGUMENT)
                }
                4 => None,
                5 => {
                    state.registers.x[4] |= FLAGS_TPRO;
                    None
                }
                _ => {
                    state.registers.x[5] = WRITE_ONLY;
                    None
                }
            };
            let before = state.clone();
            let outcome = run(
                &mut runtime,
                &mut state,
                &mut memory,
                &mut ports,
                case != 4,
                2,
            )?;
            let mut expected = before.clone();
            if let Some(result) = result {
                expected.registers.x[0] = result as i64 as u64;
                expected.pc = GuestAddress(STOP);
                assert_eq!(outcome.execution.reason, StopReason::StopAddress);
                assert_eq!(outcome.mach_vm_map_services[0].result, Some(result));
            } else {
                assert!(matches!(
                    outcome.execution.reason,
                    StopReason::SynchronousTrap { .. }
                ));
                if case == 4 {
                    assert!(outcome.mach_vm_map_services.is_empty());
                } else {
                    assert!(outcome.mach_vm_map_services[0].result.is_none());
                    assert!(outcome.mach_vm_map_services[0].declined.is_some());
                }
            }
            assert_state(&state, &expected);
            assert_eq!(memory.regions(), views);
            assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
        }
    }
    Ok(())
}

#[test]
fn failed_copyout_retains_published_allocation_and_every_reached_byte_prefix() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut ports, task) = ports(&runtime)?;
    for prefix in 0..ADDRESS_BYTES {
        let (mut memory, address) = vm_buffer(true)?;
        let pointer = address + GUEST_PAGE_BYTES - prefix as u64;
        let initial_hint = ALLOCATION_HINT | GUEST_PAGE_MASK;
        memory.write(pointer, &initial_hint.to_le_bytes())?;
        memory.protect_data(address + GUEST_PAGE_BYTES, GUEST_PAGE_BYTES, true, false)?;
        let mut expected_ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
        let mut state = request(prefix as u32, task, pointer);
        let mut expected = state.clone();
        expected.pc = GuestAddress(STOP);
        expected.registers.x[0] = mach_vm::map::KERN_MEMORY_ERROR as u64;
        let outcome = run(&mut runtime, &mut state, &mut memory, &mut ports, true, 2)?;
        assert_eq!(outcome.execution.reason, StopReason::StopAddress);
        assert_state(&state, &expected);
        let event = &outcome.mach_vm_map_services[0];
        assert_eq!(event.result, Some(mach_vm::map::KERN_MEMORY_ERROR));
        assert_eq!(event.copyout_bytes, prefix);
        let allocation = event.allocation.unwrap();
        assert_eq!(
            memory.data_allocation_at(allocation.guest_address),
            Some(allocation)
        );
        assert_eq!(
            memory.read_snapshot(allocation.guest_address, ALLOCATION_BYTES as usize)?,
            vec![0; ALLOCATION_BYTES as usize]
        );
        let offset = (pointer - address) as usize;
        expected_ram[offset..offset + prefix]
            .copy_from_slice(&allocation.guest_address.to_le_bytes()[..prefix]);
        assert_eq!(
            memory.read_snapshot(address, OWNED_RAM_BYTES)?,
            expected_ram
        );
        assert!(memory.write(address + GUEST_PAGE_BYTES, &[1]).is_err());
    }
    Ok(())
}

#[test]
fn code_collision_drops_unpublished_mapping_then_budget_and_cache_resume_once() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut ports, task) = ports(&runtime)?;
    let (mut memory, address) = vm_buffer(true)?;
    let fixed = NEXT_BUFFER.fetch_add(ALLOCATION_BYTES, Ordering::Relaxed);
    memory.write(address, &fixed.to_le_bytes())?;
    runtime.register_code(GuestAddress(fixed), RET_X30.to_le_bytes().to_vec())?;
    let mut state = request(15, task, address);
    state.registers.x[4] = FLAGS_ALIAS;
    let before = state.clone();
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    let views = memory.regions().to_vec();
    let collision = run(&mut runtime, &mut state, &mut memory, &mut ports, true, 2)?;
    assert!(matches!(
        collision.execution.reason,
        StopReason::SynchronousTrap { .. }
    ));
    assert_state(&state, &before);
    assert!(collision.mach_vm_map_services[0].allocation.is_none());
    assert!(
        collision.mach_vm_map_services[0]
            .declined
            .as_deref()
            .unwrap()
            .contains("registered code snapshot")
    );
    assert_eq!(memory.regions(), views);
    assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
    assert!(memory.data_allocation_at(fixed).is_none());
    assert!(runtime.unregister_code(GuestAddress(fixed)));
    let first = run(&mut runtime, &mut state, &mut memory, &mut ports, true, 1)?;
    assert_eq!(first.execution.reason, StopReason::BudgetExhausted);
    assert_eq!(state.pc, GuestAddress(BASE + INSTRUCTION_BYTES));
    assert_eq!(
        first.mach_vm_map_services[0]
            .allocation
            .unwrap()
            .guest_address,
        fixed
    );
    let resumed = run(&mut runtime, &mut state, &mut memory, &mut ports, true, 1)?;
    assert_eq!(resumed.execution.reason, StopReason::StopAddress);
    assert!(resumed.mach_vm_map_services.is_empty());
    memory.write(fixed, &[0x5a])?;
    drop(runtime);
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    memory.write(address, &ALLOCATION_HINT.to_le_bytes())?;
    let mut state = request(0, task, address);
    let cold = run(&mut runtime, &mut state, &mut memory, &mut ports, true, 2)?;
    assert_eq!(cold.execution.reason, StopReason::StopAddress);
    assert!(cold.execution.disk_cache_hits > 0);
    assert_eq!(cold.mach_vm_map_services.len(), 1);
    assert_ne!(
        cold.mach_vm_map_services[0]
            .allocation
            .unwrap()
            .guest_address,
        fixed
    );
    assert_eq!(memory.read_snapshot(fixed, 1)?, vec![0x5a]);
    Ok(())
}
