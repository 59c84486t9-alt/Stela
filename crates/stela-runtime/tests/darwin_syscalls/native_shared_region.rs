//! The absent shared-region query.

use super::*;
use stela_runtime::darwin::{ExecutionServices, ServiceRunOutcome, run_services, shared_region};

const MOV_X16_SHARED_REGION: u32 = 0xd28024d0;
const SVC_DARWIN: u32 = 0xd4001001;
const RET_X30: u32 = 0xd65f03c0;
const SVC_IMMEDIATE: u16 = 0x80;
const SELECTOR_REGISTER: usize = 16;
const INSTRUCTION_BYTES: u64 = 4;
const NZCV_COMBINATIONS: u32 = 16;
const OWNED_RAM_BYTES: usize = 32768;
const DARWIN_EINVAL: u32 = 22;
const DYLD_VM_END_MWL: u64 = u64::MAX;

fn request(flags: u32, indirect: bool, address: u64, upper: u32) -> ThreadState {
    let mut state = thread(flags, address);
    let selector = (u64::from(upper) << 32) | u64::from(shared_region::SYSCALL_NUMBER);
    state.registers.x[SELECTOR_REGISTER] = if indirect { 0 } else { selector };
    if indirect {
        state.registers.x[0] = selector;
    }
    state.registers.x[usize::from(indirect)] = address;
    state
}

fn run(
    runtime: &mut BlockRuntime,
    state: &mut ThreadState,
    memory: &mut OwnedMemory,
    budget: usize,
    enabled: bool,
    stop: u64,
) -> Result<ServiceRunOutcome> {
    // SAFETY: immutable SVC/RET fixtures access no guest data. This raw process
    // owns no guest shared-region attachment; private RAM does not attach one.
    // The serialized absence service consumes only a numeric destination.
    unsafe {
        run_services(
            runtime,
            state,
            Some(GuestAddress(stop)),
            budget,
            memory,
            ExecutionServices {
                absent_shared_region: enabled,
                ..ExecutionServices::default()
            },
        )
    }
}

fn expected_error(state: &ThreadState, pc: u64) -> ThreadState {
    let mut expected = state.clone();
    expected.pc = GuestAddress(pc);
    expected.registers.x[0] = u64::from(DARWIN_EINVAL);
    expected.registers.x[1] = 0;
    expected.registers.nzcv |= CARRY;
    expected
}

fn assert_pending(outcome: &ServiceRunOutcome, pc: u64) {
    assert_eq!(
        outcome.execution.reason,
        StopReason::SynchronousTrap {
            trap: SynchronousTrap {
                kind: TrapKind::SupervisorCall,
                immediate: SVC_IMMEDIATE,
                instruction_pc: GuestAddress(pc),
                exception_return_pc: GuestAddress(pc + INSTRUCTION_BYTES),
            }
        }
    );
    assert_eq!(outcome.execution.blocks_executed, 1);
}

#[test]
fn native_absence_preserves_full_state_and_destination_for_direct_indirect_all_flags() -> Result<()>
{
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut memory, address) = vm_buffer(true)?;
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    let views = memory.regions().to_vec();
    for indirect in [false, true] {
        for flags in 0..NZCV_COMBINATIONS {
            for upper in [0, 0xfeedface] {
                for destination in [0, 1, address + 3, u64::from(u32::MAX), u64::MAX - 1] {
                    let mut state = request(flags, indirect, destination, upper);
                    let expected = expected_error(&state, STOP);
                    let outcome = run(&mut runtime, &mut state, &mut memory, 2, true, STOP)?;
                    assert_eq!(outcome.execution.reason, StopReason::StopAddress);
                    assert_eq!(outcome.execution.blocks_executed, 2);
                    assert_eq!(outcome.shared_region_services.len(), 1);
                    let event = &outcome.shared_region_services[0];
                    let request = event.request.unwrap();
                    assert_eq!(request.number, shared_region::SYSCALL_NUMBER);
                    assert_eq!(request.indirect, indirect);
                    assert_eq!(request.arguments(), &[destination]);
                    assert_eq!(request.prototype().argument_count, 1);
                    assert_eq!(request.prototype().return_type, BsdReturnType::Int);
                    assert_eq!(
                        event.completion,
                        Some(BsdCompletion::Error {
                            errno: DARWIN_EINVAL
                        })
                    );
                    assert!(event.declined.is_none());
                    assert!(outcome.services.is_empty());
                    assert!(outcome.mach_services.is_empty());
                    assert!(outcome.thread_services.is_empty());
                    assert!(outcome.crossarch_services.is_empty());
                    assert!(outcome.csr_services.is_empty());
                    assert!(outcome.entropy_services.is_empty());
                    assert!(outcome.mach_vm_services.is_empty());
                    assert_state(&state, &expected);
                    assert_eq!(memory.regions(), views);
                    assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
                }
            }
        }
    }
    let mut selector_runtime = vm_runtime(
        cache.path(),
        BASE,
        &[MOV_X16_SHARED_REGION, SVC_DARWIN, RET_X30],
    )?;
    let mut state = request(15, false, address + 3, 0);
    state.registers.x[SELECTOR_REGISTER] = 0xfeedface12345678;
    let mut expected = expected_error(&state, STOP);
    expected.registers.x[SELECTOR_REGISTER] = u64::from(shared_region::SYSCALL_NUMBER);
    let outcome = run(
        &mut selector_runtime,
        &mut state,
        &mut memory,
        2,
        true,
        STOP,
    )?;
    assert_eq!(outcome.execution.reason, StopReason::StopAddress);
    assert_eq!(outcome.execution.blocks_executed, 2);
    assert_eq!(outcome.shared_region_services.len(), 1);
    let event = &outcome.shared_region_services[0];
    assert_eq!(
        event.trap.instruction_pc,
        GuestAddress(BASE + INSTRUCTION_BYTES)
    );
    assert_eq!(event.request.unwrap().arguments(), &[address + 3]);
    assert_eq!(
        event.completion,
        Some(BsdCompletion::Error {
            errno: DARWIN_EINVAL
        })
    );
    assert!(event.declined.is_none());
    assert_state(&state, &expected);
    assert_eq!(memory.regions(), views);
    assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
    Ok(())
}

#[test]
fn default_opt_out_and_unknown_services_remain_at_exact_pending_trap() -> Result<()> {
    assert!(!ExecutionServices::default().absent_shared_region);
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut memory, address) = vm_buffer(true)?;
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    for indirect in [false, true] {
        for flags in 0..NZCV_COMBINATIONS {
            for (enabled, number) in [
                (false, shared_region::SYSCALL_NUMBER),
                (true, shared_region::SYSCALL_NUMBER - 1),
                (true, shared_region::SYSCALL_NUMBER + 1),
            ] {
                let mut state = request(flags, indirect, address, 0);
                state.registers.x[if indirect { 0 } else { SELECTOR_REGISTER }] = u64::from(number);
                let before = state.clone();
                let outcome = run(&mut runtime, &mut state, &mut memory, 2, enabled, STOP)?;
                assert_pending(&outcome, BASE);
                assert!(outcome.shared_region_services.is_empty());
                assert_state(&state, &before);
                assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
            }
        }
    }
    Ok(())
}

#[test]
fn map_with_linking_sentinel_declines_without_state_or_memory_effects() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut memory, address) = vm_buffer(true)?;
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    let views = memory.regions().to_vec();
    for indirect in [false, true] {
        for flags in 0..NZCV_COMBINATIONS {
            let mut state = request(flags, indirect, DYLD_VM_END_MWL, 0);
            let before = state.clone();
            let outcome = run(&mut runtime, &mut state, &mut memory, 2, true, STOP)?;
            assert_pending(&outcome, BASE);
            assert_eq!(outcome.shared_region_services.len(), 1);
            let event = &outcome.shared_region_services[0];
            assert_eq!(event.request.unwrap().arguments(), &[DYLD_VM_END_MWL]);
            assert!(event.completion.is_none());
            assert!(
                event
                    .declined
                    .as_deref()
                    .unwrap()
                    .contains("map_with_linking")
            );
            assert_state(&state, &before);
            assert_eq!(memory.regions(), views);
            assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
        }
    }
    Ok(())
}

#[test]
fn stop_budget_resume_and_cache_preserve_actual_absence_results() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let words = [SVC_DARWIN, SVC_DARWIN, RET_X30];
    let mut runtime = vm_runtime(cache.path(), BASE, &words)?;
    for offset in [0, INSTRUCTION_BYTES, 2 * INSTRUCTION_BYTES] {
        runtime.prepare(GuestAddress(BASE + offset))?;
    }
    let (mut memory, address) = vm_buffer(true)?;
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    let initial = request(0, false, address + 3, 0);
    let mut state = initial.clone();
    let zero = run(&mut runtime, &mut state, &mut memory, 0, true, STOP)?;
    assert_eq!(zero.execution.reason, StopReason::BudgetExhausted);
    assert_eq!(zero.execution.blocks_executed, 0);
    assert!(zero.shared_region_services.is_empty());
    assert_state(&state, &initial);
    let first = run(&mut runtime, &mut state, &mut memory, 1, true, STOP)?;
    assert_eq!(first.execution.reason, StopReason::BudgetExhausted);
    assert_eq!(first.execution.blocks_executed, 1);
    assert_eq!(first.shared_region_services.len(), 1);
    let after_first = expected_error(&initial, BASE + INSTRUCTION_BYTES);
    assert_state(&state, &after_first);
    // The second actual SVC receives the preceding errno as its destination.
    let second = run(&mut runtime, &mut state, &mut memory, 2, true, STOP)?;
    assert_eq!(second.execution.reason, StopReason::StopAddress);
    assert_eq!(second.execution.blocks_executed, 2);
    assert_eq!(second.shared_region_services.len(), 1);
    assert_eq!(
        second.shared_region_services[0]
            .request
            .unwrap()
            .arguments(),
        &[u64::from(DARWIN_EINVAL)]
    );
    let expected = expected_error(&initial, STOP);
    assert_state(&state, &expected);
    assert_eq!(
        first.execution.compiled_blocks + second.execution.compiled_blocks,
        0
    );
    assert_eq!(
        first.execution.disk_cache_hits + second.execution.disk_cache_hits,
        3
    );
    state = initial.clone();
    let stopped = run(
        &mut runtime,
        &mut state,
        &mut memory,
        1,
        true,
        BASE + INSTRUCTION_BYTES,
    )?;
    assert_eq!(stopped.execution.reason, StopReason::StopAddress);
    assert_eq!(stopped.execution.blocks_executed, 1);
    assert_eq!(stopped.shared_region_services.len(), 1);
    assert_state(&state, &after_first);
    state = initial.clone();
    let warm = run(&mut runtime, &mut state, &mut memory, 3, true, STOP)?;
    assert_eq!(warm.execution.reason, StopReason::StopAddress);
    assert_eq!(warm.execution.memory_cache_hits, 3);
    assert_eq!(warm.shared_region_services.len(), 2);
    assert_state(&state, &expected);
    drop(runtime);
    let mut fresh = vm_runtime(cache.path(), BASE, &words)?;
    state = initial;
    let cached = run(&mut fresh, &mut state, &mut memory, 3, true, STOP)?;
    assert_eq!(cached.execution.reason, StopReason::StopAddress);
    assert_eq!(cached.execution.disk_cache_hits, 3);
    assert_eq!(cached.execution.compiled_blocks, 0);
    assert_eq!(cached.shared_region_services.len(), 2);
    assert_state(&state, &expected);
    assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
    Ok(())
}
