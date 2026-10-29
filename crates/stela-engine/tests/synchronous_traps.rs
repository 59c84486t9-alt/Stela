//! Trap exits stop at the trapping instruction.
#![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
use anyhow::Result;
use std::path::Path;
use stela_compiler::{
    GuestAddress, GuestState,
    block::{SynchronousTrap, TrapKind},
};
use stela_engine::blocks::{BlockRuntime, RunOutcome, StopReason, ThreadState};

const BASE: u64 = 0x1000;
const STOP: u64 = 0xdead0000;
const ADD_ONE: u32 = 0x91000400;
const ADD_FOUR: u32 = 0x91001000;
const RET: u32 = 0xd65f03c0;

fn words(input: &[u32]) -> Vec<u8> {
    input.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn traps() -> [(u32, TrapKind, u16); 2] {
    [
        (0xd4001001, TrapKind::SupervisorCall, 0x80),
        (0xd43fffe0, TrapKind::SoftwareBreakpoint, 0xffff),
    ]
}

fn record(kind: TrapKind, immediate: u16, pc: u64) -> SynchronousTrap {
    SynchronousTrap {
        kind,
        immediate,
        instruction_pc: GuestAddress(pc),
        exception_return_pc: GuestAddress(match kind {
            TrapKind::SupervisorCall => pc + 4,
            TrapKind::SoftwareBreakpoint => pc,
        }),
    }
}

fn runtime(cache: &Path, program: &[u32]) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new(1, cache.to_path_buf());
    runtime.register_code(GuestAddress(BASE), words(program))?;
    Ok(runtime)
}

fn state(value: u64, flags: u32) -> ThreadState {
    let mut registers = GuestState {
        sp: 0x12340000,
        nzcv: flags << 28,
        reserved: 0xa5c39e71,
        ..GuestState::default()
    };
    for index in 0..31 {
        registers.x[index] = 0xdeadbeef12345678u64
            .wrapping_mul(index as u64 + 1)
            .rotate_left(flags);
    }
    registers.v = std::array::from_fn(|index| {
        [
            0x0123456789abcdefu64.rotate_left(index as u32),
            0xfedcba9876543210u64.rotate_right(index as u32),
        ]
    });
    registers.fpcr = 0xa5c39e71 ^ flags;
    registers.fpsr = 0x5a3c618e ^ flags;
    registers.x[0] = value;
    registers.x[30] = STOP;
    ThreadState {
        pc: GuestAddress(BASE),
        registers,
    }
}

fn assert_trap(outcome: &RunOutcome, expected: SynchronousTrap) {
    assert_eq!(
        outcome.reason,
        StopReason::SynchronousTrap { trap: expected }
    );
    assert_eq!(outcome.blocks_executed, 1);
    assert_eq!(outcome.last_exit, Some((expected.instruction_pc.0, 5)));
    let json = serde_json::to_value(&outcome.reason).unwrap();
    assert_eq!(json["kind"], "synchronous_trap");
    assert_eq!(json["trap"]["instruction_pc"], expected.instruction_pc.0);
    assert_eq!(
        json["trap"]["exception_return_pc"],
        expected.exception_return_pc.0
    );
}

#[test]
fn pretrap_register_flags_and_ram_effects_survive_without_executing_the_suffix() -> Result<()> {
    for (instruction, kind, immediate) in traps() {
        let cache = tempfile::tempdir()?;
        let mut runtime = runtime(
            cache.path(),
            &[
                ADD_ONE,
                0xf1000c02, // SUBS X2, X0, #3
                0xf9000020, // STR X0, [X1]
                instruction,
                ADD_FOUR,
                0, // Unsupported trailing code must not be consumed or executed.
            ],
        )?;
        let mut memory = Box::new(0u64);
        for flags in 0..16 {
            *memory = 0xdeadbeef;
            let mut thread = state(41, flags);
            thread.registers.x[1] = (&mut *memory as *mut u64) as u64;
            let mut expected = thread.registers.clone();
            expected.x[0] = 42;
            expected.x[2] = 39;
            expected.nzcv = 0x20000000; // Positive nonzero subtraction, no borrow.
            // SAFETY: the code stores only to the exclusively owned Box; the
            // trap is an ABI exit, so SVC and BRK never reach the host.
            let outcome = unsafe { runtime.run(&mut thread, None, 1)? };
            assert_trap(&outcome, record(kind, immediate, BASE + 12));
            assert_eq!(thread.pc, GuestAddress(BASE + 12));
            assert_eq!(thread.registers, expected);
            assert_eq!(*memory, 42);
        }
    }
    Ok(())
}

#[test]
fn traps_report_the_same_record_through_cold_hot_and_disk_aot_paths() -> Result<()> {
    for (instruction, kind, immediate) in traps() {
        let cache = tempfile::tempdir()?;
        let program = [ADD_ONE, instruction, ADD_FOUR, RET];
        let mut first = runtime(cache.path(), &program)?;
        for (compiled, hot) in [(1, 0), (0, 1)] {
            let mut thread = state(10, 15);
            // SAFETY: owned terminating code without memory access, ending in a
            // trap.
            let outcome = unsafe { first.run(&mut thread, None, 8)? };
            assert_trap(&outcome, record(kind, immediate, BASE + 4));
            assert_eq!(
                (
                    outcome.compiled_blocks,
                    outcome.disk_cache_hits,
                    outcome.memory_cache_hits
                ),
                (compiled, 0, hot)
            );
            assert_eq!(thread.registers.x[0], 11);
            assert_eq!(thread.registers.nzcv, 0xf0000000);
            let manifest = first.loaded_manifest(GuestAddress(BASE)).unwrap();
            assert_eq!(manifest.source_map.len(), 2);
            assert_eq!(
                manifest.identity.source_sha256,
                stela_formats::sha256(&words(&program[..2]))
            );
        }
        drop(first);
        let mut fresh = runtime(cache.path(), &program)?;
        let mut thread = state(100, 3);
        // SAFETY: new owner revalidates the same memory-free AOT source/ABI.
        let disk = unsafe { fresh.run(&mut thread, None, 8)? };
        assert_trap(&disk, record(kind, immediate, BASE + 4));
        assert_eq!(
            (
                disk.compiled_blocks,
                disk.disk_cache_hits,
                disk.memory_cache_hits
            ),
            (0, 1, 0)
        );
        assert_eq!(thread.registers.x[0], 101);
    }
    Ok(())
}

#[test]
fn only_explicit_caller_resume_advances_past_a_trap() -> Result<()> {
    for (instruction, kind, immediate) in traps() {
        let cache = tempfile::tempdir()?;
        let mut runtime = runtime(cache.path(), &[ADD_ONE, instruction, ADD_FOUR, RET])?;
        let mut thread = state(10, 6);
        // SAFETY: own memory-free program stops at a native trap boundary.
        let stopped = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 1)? };
        let trap = record(kind, immediate, BASE + 4);
        assert_trap(&stopped, trap);
        assert_eq!(thread.registers.x[0], 11);
        if kind == TrapKind::SoftwareBreakpoint {
            thread.pc = trap.exception_return_pc;
            // SAFETY: retrying BRK reports the same trap without prior additions.
            let retry = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 1)? };
            assert_trap(&retry, trap);
            assert_eq!(thread.registers.x[0], 11);
            thread.pc = GuestAddress(trap.instruction_pc.0 + 4);
        } else {
            thread.pc = trap.exception_return_pc;
        }
        // SAFETY: the caller chose the remaining ADD/RET continuation.
        let resumed = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 1)? };
        assert_eq!(resumed.reason, StopReason::StopAddress);
        assert_eq!(resumed.blocks_executed, 1);
        assert_eq!(resumed.last_exit, Some((STOP, 4)));
        assert_eq!(thread.registers.x[0], 15);
        assert_eq!(thread.pc, GuestAddress(STOP));
    }
    Ok(())
}

#[test]
fn executed_trap_precedes_coincident_budget_and_stop_address_boundaries() -> Result<()> {
    for (instruction, kind, immediate) in traps() {
        let cache = tempfile::tempdir()?;
        let mut runtime = runtime(cache.path(), &[ADD_ONE, instruction, ADD_FOUR, RET])?;
        for stop in [BASE + 4, BASE + 8] {
            let mut thread = state(10, 1);
            // SAFETY: own memory-free block traps before the configured boundary.
            let result = unsafe { runtime.run(&mut thread, Some(GuestAddress(stop)), 1)? };
            assert_trap(&result, record(kind, immediate, BASE + 4));
            assert_eq!(thread.registers.x[0], 11);
        }
    }
    Ok(())
}

#[test]
fn zero_budget_and_initial_stop_address_do_not_execute_a_trap() -> Result<()> {
    for (instruction, _, _) in traps() {
        let cache = tempfile::tempdir()?;
        let mut runtime = runtime(cache.path(), &[instruction])?;
        for (stop, reason) in [
            (None, StopReason::BudgetExhausted),
            (Some(GuestAddress(BASE)), StopReason::StopAddress),
        ] {
            let mut thread = state(17, 9);
            let initial = thread.clone();
            // SAFETY: pre-dispatch checks must execute no registered instructions.
            let result = unsafe { runtime.run(&mut thread, stop, 0)? };
            assert_eq!(result.reason, reason);
            assert_eq!(result.blocks_executed, 0);
            assert_eq!(
                (
                    result.compiled_blocks,
                    result.disk_cache_hits,
                    result.memory_cache_hits
                ),
                (0, 0, 0)
            );
            assert_eq!(result.last_exit, None);
            assert_eq!(thread.pc, initial.pc);
            assert_eq!(thread.registers, initial.registers);
            assert!(runtime.loaded_manifest(GuestAddress(BASE)).is_none());
        }
    }
    Ok(())
}

#[test]
fn ordinary_returns_keep_the_existing_block_exit_contract() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path(), &[ADD_ONE, RET])?;
    let mut thread = state(41, 10);
    // SAFETY: own memory-free constant addition and ordinary return.
    let result = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 1)? };
    assert_eq!(result.reason, StopReason::StopAddress);
    assert_eq!(result.blocks_executed, 1);
    assert_eq!(result.last_exit, Some((STOP, 4)));
    assert_eq!(thread.registers.x[0], 42);
    assert_eq!(thread.registers.nzcv, 0xa0000000);
    Ok(())
}
