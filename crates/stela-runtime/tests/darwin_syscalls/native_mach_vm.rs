//! Mach VM protection.
#![cfg(target_os = "macos")]

use super::*;
use stela_runtime::{
    darwin::{ExecutionServices, ServiceRunOutcome, mach_vm, run_services},
    mach::{HostPorts, Request, TASK_SELF_TRAP},
};

const SVC_DARWIN: u32 = 0xd4001001;
const RET_X30: u32 = 0xd65f03c0;
const INSTRUCTION_BYTES: u64 = 4;
const NZCV_COMBINATIONS: u32 = 16;
const OWNED_RAM_BYTES: usize = 32768;
const READ: u64 = 1;
const WRITE: u64 = 2;
const EXECUTE: u64 = 4;
const COPY: u64 = 16;
const UNKNOWN_PROTECTION: u64 = 8;
const READ_WRITE: u64 = READ | WRITE;
const ARGUMENT_COUNT: usize = 5;
const SELECTOR_REGISTER: usize = 16;

fn ports(runtime: &BlockRuntime) -> Result<(HostPorts, u64)> {
    let mut ports = HostPorts::new(runtime.address_space())?;
    let task = ports.request(&Request {
        number: TASK_SELF_TRAP,
        arguments: Vec::new(),
    })? as u32;
    Ok((ports, u64::from(task)))
}

fn request(flags: u32, task: u64, address: u64, size: u64, protection: u64) -> ThreadState {
    let mut state = thread(flags, address);
    state.registers.x[..ARGUMENT_COUNT].copy_from_slice(&[task, address, size, 0, protection]);
    state.registers.x[SELECTOR_REGISTER] = u64::MAX - u64::from(mach_vm::PROTECT_TRAP) + 1;
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
    // SAFETY: own immutable SVC/RET code accesses no RAM. The serialized service
    // owns every affected mapping and excludes execution during host reprotection.
    unsafe {
        run_services(
            runtime,
            state,
            Some(GuestAddress(STOP)),
            budget,
            memory,
            ExecutionServices {
                mach_vm: enabled,
                mach_ports: Some(ports),
                ..ExecutionServices::default()
            },
        )
    }
}

#[test]
fn native_completion_preserves_full_state_and_owned_bytes_for_all_flags() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut ports, task) = ports(&runtime)?;
    for flags in 0..NZCV_COMBINATIONS {
        for case in 0..5 {
            let (mut memory, address) = vm_buffer(case != 2)?;
            let before_ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
            let (target, size, protection, result) = match case {
                0 => (address + 1, 1, READ, mach_vm::KERN_SUCCESS),
                1 => (u64::MAX, 0, u64::MAX, mach_vm::KERN_SUCCESS),
                2 => (address, 1, READ_WRITE, mach_vm::KERN_PROTECTION_FAILURE),
                3 => (
                    address + OWNED_RAM_BYTES as u64,
                    1,
                    READ,
                    mach_vm::KERN_INVALID_ADDRESS,
                ),
                _ => (
                    address,
                    1,
                    UNKNOWN_PROTECTION,
                    mach_vm::KERN_INVALID_ARGUMENT,
                ),
            };
            let mut state = request(flags, task, target, size, protection);
            let mut expected = state.clone();
            expected.pc = GuestAddress(STOP);
            expected.registers.x[0] = result as i64 as u64;
            let outcome = run(&mut runtime, &mut state, &mut memory, &mut ports, true, 2)?;
            assert_eq!(outcome.execution.reason, StopReason::StopAddress);
            assert_eq!(outcome.mach_vm_services.len(), 1);
            assert_eq!(outcome.mach_vm_services[0].result, Some(result));
            assert!(outcome.mach_vm_services[0].declined.is_none());
            assert_state(&state, &expected);
            assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, before_ram);
        }
    }
    Ok(())
}

#[test]
fn disabled_profile_and_unsupported_requests_remain_at_exact_pending_trap() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut ports, task) = ports(&runtime)?;
    let (mut memory, address) = vm_buffer(true)?;
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    let views = memory.regions().to_vec();
    for (enabled, maximum, protection) in [
        (false, 0, READ),
        (true, 1, READ),
        (true, 0, WRITE),
        (true, 0, EXECUTE),
        (true, 0, COPY),
    ] {
        let mut state = request(15, task, address, 1, protection);
        state.registers.x[3] = maximum;
        let before = state.clone();
        let outcome = run(
            &mut runtime,
            &mut state,
            &mut memory,
            &mut ports,
            enabled,
            2,
        )?;
        assert!(matches!(
            outcome.execution.reason,
            StopReason::SynchronousTrap { .. }
        ));
        assert_state(&state, &before);
        assert_eq!(memory.regions(), views);
        assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
        if enabled {
            assert_eq!(outcome.mach_vm_services.len(), 1);
            assert!(outcome.mach_vm_services[0].result.is_none());
            assert!(outcome.mach_vm_services[0].declined.is_some());
        } else {
            assert!(outcome.mach_vm_services.is_empty());
        }
    }
    Ok(())
}

#[test]
fn budget_resume_and_disk_cache_keep_actual_protection_state() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut ports, task) = ports(&runtime)?;
    let (mut memory, address) = vm_buffer(true)?;
    let mut state = request(15, task, address, 1, READ);
    let first = run(&mut runtime, &mut state, &mut memory, &mut ports, true, 1)?;
    assert_eq!(first.execution.reason, StopReason::BudgetExhausted);
    assert_eq!(state.pc, GuestAddress(BASE + INSTRUCTION_BYTES));
    assert_eq!(first.mach_vm_services.len(), 1);
    assert!(memory.write(address, &[1]).is_err());
    let resumed = run(&mut runtime, &mut state, &mut memory, &mut ports, true, 1)?;
    assert_eq!(resumed.execution.reason, StopReason::StopAddress);
    assert!(resumed.mach_vm_services.is_empty());
    let mut restore = request(0, task, address, 1, READ_WRITE);
    let warm = run(&mut runtime, &mut restore, &mut memory, &mut ports, true, 2)?;
    assert_eq!(warm.execution.reason, StopReason::StopAddress);
    assert!(warm.execution.memory_cache_hits > 0);
    memory.write(address, &[0x5a])?;
    drop(runtime);
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let mut again = request(5, task, address, 1, READ);
    let cold = run(&mut runtime, &mut again, &mut memory, &mut ports, true, 2)?;
    assert_eq!(cold.execution.reason, StopReason::StopAddress);
    assert!(cold.execution.disk_cache_hits > 0);
    assert!(memory.write(address, &[1]).is_err());
    assert_eq!(memory.read_snapshot(address, 1)?, vec![0x5a]);
    Ok(())
}

#[test]
fn registered_code_overlap_declines_before_permissions_change() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut ports, task) = ports(&runtime)?;
    let (mut memory, address) = vm_buffer(true)?;
    runtime.register_code(GuestAddress(address), RET_X30.to_le_bytes().to_vec())?;
    let mut state = request(15, task, address, 1, READ);
    let before = state.clone();
    let views = memory.regions().to_vec();
    let outcome = run(&mut runtime, &mut state, &mut memory, &mut ports, true, 2)?;
    assert!(matches!(
        outcome.execution.reason,
        StopReason::SynchronousTrap { .. }
    ));
    assert_state(&state, &before);
    assert_eq!(memory.regions(), views);
    memory.write(address, &[0x5a])?;
    assert_eq!(outcome.mach_vm_services.len(), 1);
    assert!(outcome.mach_vm_services[0].result.is_none());
    assert!(
        outcome.mach_vm_services[0]
            .declined
            .as_deref()
            .unwrap()
            .contains("registered code snapshot")
    );
    Ok(())
}
