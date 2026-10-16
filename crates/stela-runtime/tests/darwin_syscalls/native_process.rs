//! `getpid` through the thread's process.
#![cfg(target_os = "macos")]

use super::*;
use std::rc::Rc;
use stela_runtime::{
    darwin::{ExecutionServices, ServiceRunOutcome, process as process_service, run_services},
    memory::DIRECT_RAM_USER_END,
    process::{self, Context as ProcessContext},
    thread::{Context, VmMaximum},
};

const MOV_X16_GETPID: u32 = 0xd2800290;
const SVC_DARWIN: u32 = 0xd4001001;
const RET_X30: u32 = 0xd65f03c0;
const INSTRUCTION_BYTES: u64 = 4;
const SELECTOR_REGISTER: usize = 16;
const NZCV_COMBINATIONS: u32 = 16;
const OWNED_RAM_BYTES: usize = 32768;
const DECLARED_PROCESS_ID: u32 = 42;

fn request(flags: u32, indirect: bool, address: u64, upper: u32) -> ThreadState {
    let mut state = thread(flags, address);
    let selector = (u64::from(upper) << u32::BITS) | u64::from(process_service::SYSCALL_NUMBER);
    state.registers.x[SELECTOR_REGISTER] = if indirect { 0 } else { selector };
    if indirect {
        state.registers.x[0] = selector;
    }
    state
}

fn run(
    runtime: &mut BlockRuntime,
    state: &mut ThreadState,
    memory: &mut OwnedMemory,
    context: Option<&mut Context>,
    budget: usize,
    stop: u64,
) -> Result<ServiceRunOutcome> {
    // SAFETY: SVC/RET code with no data access. The process ID comes from the
    // thread's own process, RAM is unchanged, and no guest pointer reaches the
    // service.
    unsafe {
        run_services(
            runtime,
            state,
            Some(GuestAddress(stop)),
            budget,
            memory,
            ExecutionServices {
                thread: context,
                ..ExecutionServices::default()
            },
        )
    }
}

#[test]
fn native_queries_preserve_full_state_ram_and_shared_process_owner() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut memory, address) = vm_buffer(true)?;
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    let regions = memory.regions().to_vec();
    for pid in [1, DECLARED_PROCESS_ID, process::MAX_PROCESS_ID] {
        let process = Rc::new(ProcessContext::new(runtime.address_space(), pid)?);
        let mut context =
            Context::native_in_process(Rc::clone(&process), VmMaximum::new(DIRECT_RAM_USER_END)?)?;
        assert!(std::ptr::eq(context.process().unwrap(), process.as_ref()));
        let before = serde_json::to_value(context.snapshot())?;
        for indirect in [false, true] {
            for flags in 0..NZCV_COMBINATIONS {
                for upper in [0, 0xfeedface] {
                    let mut state = request(flags, indirect, address, upper);
                    let mut expected = state.clone();
                    expected.pc = GuestAddress(STOP);
                    expected.registers.x[0] = u64::from(pid);
                    expected.registers.x[1] = 0;
                    expected.registers.nzcv &= !CARRY;
                    let outcome = run(
                        &mut runtime,
                        &mut state,
                        &mut memory,
                        Some(&mut context),
                        2,
                        STOP,
                    )?;
                    assert_eq!(outcome.execution.reason, StopReason::StopAddress);
                    assert_eq!(outcome.process_services.len(), 1);
                    let event = &outcome.process_services[0];
                    assert!(event.declined.is_none());
                    assert_eq!(
                        event.completion,
                        Some(BsdCompletion::Success { values: [pid, 0] })
                    );
                    assert!(event.request.unwrap().arguments().is_empty());
                    assert_eq!(event.request.unwrap().indirect, indirect);
                    assert_state(&state, &expected);
                    assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
                    assert_eq!(memory.regions(), regions);
                    assert_eq!(serde_json::to_value(context.snapshot())?, before);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn original_getpid_request_window_uses_the_declared_owner_and_precise_return_pc() -> Result<()> {
    // Bytes at offsets 0x518c-0x5194 of the dyld slice (900280d2011000d4).
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[MOV_X16_GETPID, SVC_DARWIN, RET_X30])?;
    let (mut memory, address) = vm_buffer(true)?;
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    let process = Rc::new(ProcessContext::new(
        runtime.address_space(),
        DECLARED_PROCESS_ID,
    )?);
    let mut context = Context::native_in_process(process, VmMaximum::new(DIRECT_RAM_USER_END)?)?;
    for flags in 0..NZCV_COMBINATIONS {
        let mut state = request(flags, false, address, 0xfeedface);
        state.registers.x[SELECTOR_REGISTER] = u64::MAX;
        let mut expected = state.clone();
        expected.pc = GuestAddress(BASE + 2 * INSTRUCTION_BYTES);
        expected.registers.x[SELECTOR_REGISTER] = u64::from(process_service::SYSCALL_NUMBER);
        expected.registers.x[0] = u64::from(DECLARED_PROCESS_ID);
        expected.registers.x[1] = 0;
        expected.registers.nzcv &= !CARRY;
        let outcome = run(
            &mut runtime,
            &mut state,
            &mut memory,
            Some(&mut context),
            1,
            expected.pc.0,
        )?;
        assert_eq!(outcome.execution.reason, StopReason::StopAddress);
        assert_eq!(outcome.process_services.len(), 1);
        assert_eq!(
            outcome.process_services[0].trap.instruction_pc,
            GuestAddress(BASE + INSTRUCTION_BYTES)
        );
        assert_state(&state, &expected);
        assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
    }
    Ok(())
}

#[test]
fn legacy_or_absent_thread_process_identity_stays_pending_without_ram_effects() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let (mut memory, address) = vm_buffer(true)?;
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    let mut legacy = Context::native(
        runtime.address_space(),
        VmMaximum::new(DIRECT_RAM_USER_END)?,
    )?;
    assert!(legacy.process().is_none());
    for enabled in [false, true] {
        for flags in 0..NZCV_COMBINATIONS {
            let mut state = request(flags, false, address, 0);
            let before = state.clone();
            let outcome = run(
                &mut runtime,
                &mut state,
                &mut memory,
                enabled.then_some(&mut legacy),
                2,
                STOP,
            )?;
            assert!(matches!(
                outcome.execution.reason,
                StopReason::SynchronousTrap { .. }
            ));
            assert!(outcome.process_services.is_empty());
            assert_state(&state, &before);
            assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
        }
    }
    Ok(())
}

#[test]
fn foreign_process_address_space_declines_before_execution_or_memory_effects() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
    let process = Rc::new(ProcessContext::new(
        runtime.address_space() + 1,
        DECLARED_PROCESS_ID,
    )?);
    let mut context = Context::native_in_process(process, VmMaximum::new(DIRECT_RAM_USER_END)?)?;
    let (mut memory, address) = vm_buffer(true)?;
    let ram = memory.read_snapshot(address, OWNED_RAM_BYTES)?;
    let mut state = request(15, false, address, 0);
    let before = state.clone();
    assert!(
        run(
            &mut runtime,
            &mut state,
            &mut memory,
            Some(&mut context),
            2,
            STOP
        )
        .is_err()
    );
    assert_state(&state, &before);
    assert_eq!(memory.read_snapshot(address, OWNED_RAM_BYTES)?, ram);
    Ok(())
}

#[test]
fn process_snapshot_is_opt_in_and_same_owner_can_be_shared_by_thread_contexts() -> Result<()> {
    let maximum = VmMaximum::new(DIRECT_RAM_USER_END)?;
    let process = Rc::new(ProcessContext::new(1, DECLARED_PROCESS_ID)?);
    let first = Context::native_in_process(Rc::clone(&process), maximum)?;
    let second = Context::native_in_process(Rc::clone(&process), maximum)?;
    assert!(std::ptr::eq(
        first.process().unwrap(),
        second.process().unwrap()
    ));
    assert_eq!(first.address_space(), process.address_space());
    let legacy = Context::native(process.address_space(), maximum)?;
    let old_json = serde_json::to_value(legacy.snapshot())?;
    assert!(old_json.get("process").is_none());
    let mut new_json = serde_json::to_value(first.snapshot())?;
    let process_json = new_json.as_object_mut().unwrap().remove("process").unwrap();
    assert_eq!(
        process_json,
        serde_json::json!({
            "profile_id":process::PROFILE_ID,
            "address_space":process.address_space(),
            "process_id":DECLARED_PROCESS_ID,
        })
    );
    assert_eq!(new_json, old_json);
    Ok(())
}
