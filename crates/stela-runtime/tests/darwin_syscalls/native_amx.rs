//! AMX instructions in translated guest blocks: the per-thread state, native
//! kernels and the model, and explicit stops.
#![cfg(target_os = "macos")]

use super::*;
use stela_compiler::{
    TargetCpu,
    amx::{AmxOperation, AmxRegisters, model},
    block::BlockProfile,
};
use stela_runtime::{
    amx::Failure,
    memory::DIRECT_RAM_USER_END,
    thread::{Context, VmMaximum},
};

const RET_X30: u32 = 0xd65f03c0;
const ADDRESS_SPACE_ID: u64 = 0x414d58;
/// Each AMX word ends a block.
const BUDGET: usize = 64;

fn word(operation: AmxOperation, register: u8) -> u32 {
    operation.word(register)
}

fn amx_runtime(cache: &std::path::Path, words: &[u32], target: TargetCpu) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new_for_target(
        ADDRESS_SPACE_ID,
        cache.into(),
        BlockProfile::DarwinArm64ThreadV1,
        target,
    );
    runtime.register_code(
        GuestAddress(BASE),
        words.iter().flat_map(|word| word.to_le_bytes()).collect(),
    )?;
    Ok(runtime)
}

/// A copy of guest memory that originally lived at `base`.
struct Host<'a> {
    base: u64,
    bytes: &'a mut [u8],
}

impl model::AmxMemory for Host<'_> {
    fn read(&mut self, address: u64, destination: &mut [u8]) -> Result<(), model::MemoryFault> {
        let start = (address - self.base) as usize;
        destination.copy_from_slice(&self.bytes[start..start + destination.len()]);
        Ok(())
    }
    fn write(&mut self, address: u64, source: &[u8]) -> Result<(), model::MemoryFault> {
        let start = (address - self.base) as usize;
        self.bytes[start..start + source.len()].copy_from_slice(source);
        Ok(())
    }
}

/// set; ldx; ldy; fma32 (matrix, native when admitted); fma32 (lane-masked,
/// model); four stz; clr; ret. The stored Z rows and the final state match the
/// model run over the same operands.
#[test]
fn guest_blocks_run_amx_with_thread_state_on_every_target() -> Result<()> {
    let program = [
        word(AmxOperation::Set, 0),
        word(AmxOperation::LoadX, 0),
        word(AmxOperation::LoadY, 1),
        word(AmxOperation::Fma32, 2),
        word(AmxOperation::Fma32, 3),
        word(AmxOperation::StoreZ, 4),
        word(AmxOperation::StoreZ, 5),
        word(AmxOperation::StoreZ, 6),
        word(AmxOperation::StoreZ, 7),
        word(AmxOperation::Clear, 0),
        RET_X30,
    ];
    for target in [TargetCpu::Baseline, TargetCpu::detect()] {
        let cache = tempfile::tempdir()?;
        let mut runtime = amx_runtime(cache.path(), &program, target)?;
        let context = Context::native(ADDRESS_SPACE_ID, VmMaximum::new(DIRECT_RAM_USER_END)?)?;
        // X: 1.0 + i/16; Y: 2.0 - j/32, in two pairs of 64-byte rows.
        let mut memory = vec![0u8; 512];
        for lane in 0..16 {
            let x = 1.0f32 + lane as f32 / 16.0;
            let y = 2.0f32 - lane as f32 / 32.0;
            memory[lane * 4..lane * 4 + 4].copy_from_slice(&x.to_le_bytes());
            memory[64 + lane * 4..64 + lane * 4 + 4].copy_from_slice(&y.to_le_bytes());
        }
        let base = memory.as_ptr() as u64;
        let mut state = thread(0, 0);
        state.registers.x[0] = base;
        state.registers.x[1] = base + 64;
        // Z row group 1 with every lane; then group 2 with only X lane 3
        // (mask mode 1), which the kernels leave to the model.
        state.registers.x[2] = 1 << 20;
        state.registers.x[3] = (2 << 20) | (1 << 46) | (3 << 41);
        let store = |row: u64| base + 128 + 64 * (row - 1);
        for (register, row) in [(4, 1), (5, 2), (6, 5), (7, 6)] {
            state.registers.x[register] = store(row) | (row << 56);
        }
        // The model over a copy of the same memory.
        let mut expected_memory = memory.clone();
        let mut expected = AmxRegisters::zeroed();
        let mut host = Host {
            base,
            bytes: &mut expected_memory,
        };
        for (operation, register) in [
            (AmxOperation::LoadX, 0),
            (AmxOperation::LoadY, 1),
            (AmxOperation::Fma32, 2),
            (AmxOperation::Fma32, 3),
            (AmxOperation::StoreZ, 4),
            (AmxOperation::StoreZ, 5),
            (AmxOperation::StoreZ, 6),
            (AmxOperation::StoreZ, 7),
        ] {
            model::execute(
                &mut expected,
                operation,
                state.registers.x[register],
                &mut host,
            )
            .unwrap();
        }
        let before = state.registers.clone();
        // SAFETY: AMX transfers touch only `memory`; RET leaves for STOP.
        let outcome = unsafe {
            runtime.run_with_thread(
                &mut state,
                Some(GuestAddress(STOP)),
                BUDGET,
                &context,
                None,
                None,
            )?
        };
        assert_eq!(outcome.reason, StopReason::StopAddress);
        assert_eq!(outcome.amx_operations, 10);
        let native = usize::from(target.supports(TargetCpu::Fma));
        assert_eq!(outcome.amx_native_operations, native);
        assert_eq!(memory, expected_memory);
        // Stored rows hold real products: z[j*4+1][i] = x[i] * y[j].
        let z = f32::from_le_bytes(memory[128 + 4..128 + 8].try_into()?);
        assert_eq!(z, (1.0 + 1.0 / 16.0) * 2.0);
        // AMX writes no guest register; clr released the thread's state.
        assert_eq!(state.registers, before);
        assert!(!context.amx().enabled());
    }
    Ok(())
}

#[test]
fn amx_stops_are_explicit_and_keep_the_instruction_pending() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let fma = word(AmxOperation::Fma64, 0);
    let mut runtime = amx_runtime(cache.path(), &[fma, RET_X30], TargetCpu::detect())?;
    let mut state = thread(0, 0);
    let before = state.clone();
    // Without a thread context the instruction stays pending.
    // SAFETY: no instruction reaches memory.
    let missing = unsafe { runtime.run(&mut state, Some(GuestAddress(STOP)), BUDGET)? };
    let StopReason::AmxRequired { instruction } = missing.reason else {
        bail!(
            "AMX exit did not request its thread context: {:?}",
            missing.reason
        );
    };
    assert_eq!(instruction.word, fma);
    assert_eq!(state.pc, GuestAddress(BASE));
    // With a context but without `set`, the instruction is refused.
    let context = Context::native(ADDRESS_SPACE_ID, VmMaximum::new(DIRECT_RAM_USER_END)?)?;
    let disabled = unsafe {
        runtime.run_with_thread(
            &mut state,
            Some(GuestAddress(STOP)),
            BUDGET,
            &context,
            None,
            None,
        )?
    };
    assert_eq!(
        disabled.reason,
        StopReason::AmxFailure {
            instruction,
            failure: Failure::Disabled
        }
    );
    assert_state(&state, &before);
    // An address outside direct RAM is refused before any effect.
    let load = word(AmxOperation::LoadZ, 0);
    let mut runtime = amx_runtime(
        cache.path(),
        &[word(AmxOperation::Set, 0), load, RET_X30],
        TargetCpu::detect(),
    )?;
    state.registers.x[0] = DIRECT_RAM_USER_END;
    let fault = unsafe {
        runtime.run_with_thread(
            &mut state,
            Some(GuestAddress(STOP)),
            BUDGET,
            &context,
            None,
            None,
        )?
    };
    let StopReason::AmxFailure {
        instruction,
        failure,
    } = fault.reason
    else {
        bail!("out-of-range AMX load completed");
    };
    assert_eq!(instruction.word, load);
    assert_eq!(
        failure,
        Failure::Memory {
            address: DIRECT_RAM_USER_END,
            write: false
        }
    );
    assert_eq!(state.pc, GuestAddress(BASE + 4));
    assert_eq!(context.amx().registers(), Some(&AmxRegisters::zeroed()));
    Ok(())
}

/// Profiles without a thread owner keep AMX words unsupported.
#[test]
fn profiles_without_thread_state_refuse_amx() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new_with_profile(
        ADDRESS_SPACE_ID,
        cache.path().into(),
        BlockProfile::Ordinary,
    );
    runtime.register_code(
        GuestAddress(BASE),
        [word(AmxOperation::Set, 0), RET_X30]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect(),
    )?;
    let mut state = thread(0, 0);
    // SAFETY: the unsupported word is refused before execution.
    let outcome = unsafe { runtime.run(&mut state, Some(GuestAddress(STOP)), BUDGET)? };
    ensure!(
        matches!(outcome.reason, StopReason::Unsupported { .. }),
        "ordinary profile admitted AMX: {:?}",
        outcome.reason
    );
    Ok(())
}
