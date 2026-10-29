//! PAuth helpers, profiles, key ownership and state preservation.
#![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
use anyhow::Result;
use std::path::Path;
use stela_compiler::{
    GuestAddress, GuestState,
    block::{BlockProfile, Features, PointerAuthenticationOperation},
};
use stela_engine::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    pauth::{Context, Keys},
};

const BASE: u64 = 0x1000;
const STOP: u64 = 0x1400;
const PACIBSP: u32 = 0xd503237f;
const AUTIBSP: u32 = 0xd50323ff;
const RETAB: u32 = 0xd65f0fff;
const RET: u32 = 0xd65f03c0;
const ADD: u32 = 0x91000400;
const PROFILE: BlockProfile = BlockProfile::new(Features::POINTER_AUTHENTICATION);

fn context(address_space: u64) -> Context {
    Context::new(
        address_space,
        Keys::from_ib_words(0x1122334455667788, 0x99aabbccddeeff00),
    )
}
fn runtime(cache: &Path, program: &[u32]) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new_with_profile(1, cache.to_path_buf(), PROFILE);
    runtime.register_code(
        GuestAddress(BASE),
        program.iter().flat_map(|w| w.to_le_bytes()).collect(),
    )?;
    Ok(runtime)
}
fn thread(flags: u32) -> ThreadState {
    let mut registers = GuestState {
        x: std::array::from_fn(|i| 0x0123456789abcdefu64.rotate_left(i as u32)),
        sp: 0x2000,
        nzcv: flags << 28,
        reserved: 0xa5c39e71,
        v: std::array::from_fn(|i| {
            [
                0x123456789abcdef0u64.rotate_left(i as u32),
                0xfedcba9876543210u64.rotate_right(i as u32),
            ]
        }),
        fpcr: 0x03c00000,
        fpsr: 0x0800001f,
    };
    registers.x[30] = STOP;
    ThreadState {
        pc: GuestAddress(BASE),
        registers,
    }
}

#[test]
fn sign_authenticate_and_return_share_aot_hot_and_new_runtime_cache_without_keys() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let program = [PACIBSP, ADD, AUTIBSP, RET];
    let mut vm = runtime(cache.path(), &program)?;
    let discovery = vm.discover(&[GuestAddress(BASE)], 16)?;
    assert_eq!(discovery.blocks.len(), 3);
    assert!(discovery.issues.is_empty());
    assert!(!discovery.native_executed && !discovery.native_pages_loaded);
    let keys = context(1);
    for phase in 0..3 {
        if phase == 2 {
            vm = runtime(cache.path(), &program)?;
        }
        for flags in 0..16 {
            let mut state = thread(flags);
            let mut expected = state.registers.clone();
            expected.x[0] = expected.x[0].wrapping_add(1);
            // SAFETY: register and helper operations only, with no guest RAM
            // access.
            let result =
                unsafe { vm.run_with_pauth(&mut state, Some(GuestAddress(STOP)), 8, &keys)? };
            assert_eq!(result.reason, StopReason::StopAddress);
            assert_eq!(result.blocks_executed, 3);
            assert_eq!(result.compiled_blocks, 0);
            assert_eq!(
                result.disk_cache_hits,
                if flags == 0 && phase != 1 { 3 } else { 0 }
            );
            assert_eq!(result.pointer_authentication_events.len(), 2);
            assert_eq!(result.pointer_authentication_events[0].authenticated, None);
            assert_eq!(
                result.pointer_authentication_events[1].authenticated,
                Some(true)
            );
            assert_eq!(state.pc, GuestAddress(STOP));
            assert_eq!(state.registers, expected);
        }
    }
    let manifest = vm.loaded_manifest(GuestAddress(BASE)).unwrap();
    assert_eq!(manifest.identity.abi, PROFILE.abi());
    let serialized = serde_json::to_string(manifest)?;
    assert!(!serialized.contains("1122334455667788") && !serialized.contains("99aabbccddeeff00"));
    assert!(!format!("{keys:?}").contains("1122334455667788"));
    Ok(())
}

#[test]
fn ordinary_profile_declines_and_missing_context_preserves_committed_prefix() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let program = [ADD, PACIBSP, RET];
    let mut ordinary = BlockRuntime::new(1, cache.path().to_path_buf());
    ordinary.register_code(
        GuestAddress(BASE),
        program.iter().flat_map(|w| w.to_le_bytes()).collect(),
    )?;
    let mut state = thread(15);
    let before = state.registers.clone();
    let outcome = unsafe { ordinary.run(&mut state, None, 4)? };
    assert!(matches!(outcome.reason, StopReason::Unsupported { .. }));
    assert_eq!(outcome.blocks_executed, 0);
    assert_eq!(state.registers, before);
    let mut vm = runtime(cache.path(), &program)?;
    let result = unsafe { vm.run(&mut state, None, 4)? };
    assert!(matches!(
        result.reason,
        StopReason::PointerAuthenticationRequired { .. }
    ));
    assert_eq!(result.blocks_executed, 1);
    assert_eq!(state.pc, GuestAddress(BASE + 4));
    let mut expected = before;
    expected.x[0] = expected.x[0].wrapping_add(1);
    assert_eq!(state.registers, expected);
    assert!(result.pointer_authentication_events.is_empty());
    Ok(())
}

#[test]
fn foreign_process_context_is_rejected_before_any_native_execution_or_publication() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut vm = runtime(cache.path(), &[ADD, PACIBSP])?;
    let mut state = thread(5);
    let before = state.registers.clone();
    assert!(unsafe { vm.run_with_pauth(&mut state, None, 4, &context(2)) }.is_err());
    assert_eq!(state.pc, GuestAddress(BASE));
    assert_eq!(state.registers, before);
    assert_eq!(std::fs::read_dir(cache.path())?.count(), 0);
    Ok(())
}

#[test]
fn classic_aut_failure_writes_poison_and_continues_without_immediate_fpac_trap() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut vm = runtime(cache.path(), &[AUTIBSP, RET])?;
    let keys = context(1);
    let mut state = thread(10);
    state.registers.x[30] = keys.sign_ib(STOP, state.registers.sp)? ^ (1 << 48);
    let before = state.registers.clone();
    let result = unsafe { vm.run_with_pauth(&mut state, Some(GuestAddress(BASE + 4)), 1, &keys)? };
    assert_eq!(result.reason, StopReason::StopAddress);
    assert_eq!(state.pc, GuestAddress(BASE + 4));
    assert_eq!(
        result.pointer_authentication_events[0].authenticated,
        Some(false)
    );
    let mut expected = before;
    expected.x[30] = STOP | (2 << 61);
    assert_eq!(state.registers, expected);
    assert_eq!(result.blocks_executed, 1);
    Ok(())
}

#[test]
fn retab_keeps_signed_lr_and_failed_target_precedes_budget_and_stop_address() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut vm = runtime(cache.path(), &[RETAB])?;
    let keys = context(1);
    for corrupt in [false, true] {
        let mut state = thread(3);
        state.registers.x[30] =
            keys.sign_ib(STOP, state.registers.sp)? ^ if corrupt { 1 << 48 } else { 0 };
        let before = state.registers.clone();
        let target = if corrupt { STOP | (2 << 61) } else { STOP };
        let result =
            unsafe { vm.run_with_pauth(&mut state, Some(GuestAddress(target)), 1, &keys)? };
        assert_eq!(state.registers, before);
        assert_eq!(state.pc, GuestAddress(target));
        assert_eq!(result.blocks_executed, 1);
        assert_eq!(result.last_exit, Some((BASE, 6)));
        assert_eq!(
            result.pointer_authentication_events[0]
                .instruction
                .operation,
            PointerAuthenticationOperation::ReturnIbSp
        );
        assert_eq!(
            result.pointer_authentication_events[0].authenticated,
            Some(!corrupt)
        );
        if corrupt {
            assert!(matches!(
                result.reason,
                StopReason::PointerAuthenticationPoisonedReturn { .. }
            ));
        } else {
            assert_eq!(result.reason, StopReason::StopAddress);
        }
    }
    Ok(())
}

#[test]
fn zero_budget_or_existing_stop_does_not_sign_or_authenticate() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut vm = runtime(cache.path(), &[PACIBSP])?;
    for (stop, budget) in [(None, 0), (Some(GuestAddress(BASE)), 3)] {
        let mut state = thread(0);
        let before = state.registers.clone();
        let result = unsafe { vm.run_with_pauth(&mut state, stop, budget, &context(1))? };
        assert_eq!(result.blocks_executed, 0);
        assert!(result.pointer_authentication_events.is_empty());
        assert_eq!(state.registers, before);
    }
    Ok(())
}

#[test]
fn poisoned_return_cannot_fetch_registered_code_or_be_accepted_as_a_resumption_stop() -> Result<()>
{
    let cache = tempfile::tempdir()?;
    let mut vm = runtime(cache.path(), &[RETAB])?;
    let keys = context(1);
    let mut state = thread(8);
    state.registers.x[30] = keys.sign_ib(STOP, state.registers.sp)? ^ (1 << 48);
    let first = unsafe { vm.run_with_pauth(&mut state, None, 1, &keys)? };
    assert!(matches!(
        first.reason,
        StopReason::PointerAuthenticationPoisonedReturn { .. }
    ));
    let poison = state.pc;
    vm.register_code(
        poison,
        [ADD, RET].iter().flat_map(|w| w.to_le_bytes()).collect(),
    )?;
    let before = state.registers.clone();
    for stop in [None, Some(poison)] {
        let result = unsafe { vm.run_with_pauth(&mut state, stop, 3, &keys)? };
        assert_eq!(
            result.reason,
            StopReason::NoncanonicalInstructionTarget { address: poison }
        );
        assert_eq!(result.blocks_executed, 0);
        assert!(result.pointer_authentication_events.is_empty());
        assert_eq!(state.pc, poison);
        assert_eq!(state.registers, before);
    }
    let no_fetch = unsafe { vm.run_with_pauth(&mut state, Some(poison), 0, &keys)? };
    assert_eq!(no_fetch.reason, StopReason::BudgetExhausted);
    assert_eq!(no_fetch.blocks_executed, 0);
    Ok(())
}

mod modern;

mod memory;
