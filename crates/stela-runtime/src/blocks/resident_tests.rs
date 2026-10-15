//! Original-block accounting, canonical state and cache ownership for resident loops.
use super::*;

const BASE: GuestAddress = GuestAddress(0x1000);
const FALLTHROUGH: GuestAddress = GuestAddress(BASE.0 + 8);
const STOP: GuestAddress = GuestAddress(0x2000);
const SUBS_X0_ONE: u32 = 0xf100_0400;
const SUBS_W0_ONE: u32 = 0x7100_0400;
const B_NE_SELF: u32 = 0x54ff_ffe1;
const MOV_X0_99: u32 = 0xd280_0c60;
const RET_X30: u32 = 0xd65f_03c0;
const ARM_CARRY: u32 = 1 << 29;
const ARM_ZERO: u32 = 1 << 30;

fn thread(count: u64) -> ThreadState {
    let mut registers = GuestState {
        x: std::array::from_fn(|index| 0x1234_5678_9abc_def0u64.rotate_left(index as u32)),
        sp: 0x3000,
        nzcv: 0xf000_0000,
        reserved: 0xa5c3_9e71,
        v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
        fpcr: 0x03c0_0000,
        fpsr: 0x0800_001f,
    };
    registers.x[0] = count;
    registers.x[30] = STOP.0;
    ThreadState {
        registers,
        pc: BASE,
    }
}

fn runtime(path: &std::path::Path, words: &[u32]) -> Result<BlockRuntime> {
    let mut runtime =
        BlockRuntime::new_with_profile(1, path.to_path_buf(), BlockProfile::OrdinaryResidentV1);
    runtime.register_code(
        BASE,
        words.iter().flat_map(|word| word.to_le_bytes()).collect(),
    )?;
    Ok(runtime)
}

#[test]
fn resident_budget_counts_original_blocks_and_prioritizes_actual_edge() -> Result<()> {
    for (subtract, upper) in [(SUBS_X0_ONE, 0), (SUBS_W0_ONE, 0x1234_5678_0000_0000)] {
        for count in 1..=5 {
            for budget in 0..=7 {
                let cache = tempfile::tempdir()?;
                let mut runtime = runtime(cache.path(), &[subtract, B_NE_SELF])?;
                let mut state = thread(upper | count);
                let mut expected = state.registers.clone();
                let consumed = (count as usize).min(budget);
                if consumed != 0 {
                    expected.x[0] = count - consumed as u64;
                    expected.nzcv = ARM_CARRY | if expected.x[0] == 0 { ARM_ZERO } else { 0 };
                }
                // SAFETY: owned nonfaulting SUBS/conditional loop is bounded by
                // the exact invocation counter; no guest data or host calls.
                let outcome = unsafe { runtime.run(&mut state, Some(FALLTHROUGH), budget)? };
                assert_eq!(state.registers, expected);
                assert_eq!(outcome.blocks_executed, consumed);
                if consumed == count as usize {
                    assert_eq!(state.pc, FALLTHROUGH);
                    assert_eq!(outcome.reason, StopReason::StopAddress);
                } else {
                    assert_eq!(state.pc, BASE);
                    assert_eq!(outcome.reason, StopReason::BudgetExhausted);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn zero_budget_does_not_prepare_or_execute_a_resident_artifact() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path(), &[SUBS_X0_ONE, B_NE_SELF])?;
    let mut state = thread(5);
    let expected = state.registers.clone();
    // SAFETY: zero budget performs no native invocation or instruction fetch.
    let outcome = unsafe { runtime.run(&mut state, None, 0)? };
    assert_eq!(state.registers, expected);
    assert_eq!(state.pc, BASE);
    assert_eq!(outcome.blocks_executed, 0);
    assert_eq!(outcome.compiled_blocks, 0);
    assert!(runtime.loaded_manifest(BASE).is_none());
    Ok(())
}

#[test]
fn ordinary_fallback_preserves_flags_and_consumes_one_block() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path(), &[MOV_X0_99, RET_X30])?;
    let mut state = thread(5);
    let mut expected = state.registers.clone();
    expected.x[0] = 99;
    // SAFETY: owned MOV/RET fixture has no data access and returns finitely.
    let outcome = unsafe { runtime.run(&mut state, Some(STOP), 1)? };
    assert_eq!(state.registers, expected);
    assert_eq!(state.pc, STOP);
    assert_eq!(outcome.blocks_executed, 1);
    assert_eq!(outcome.reason, StopReason::StopAddress);
    assert_eq!(
        runtime.loaded_manifest(BASE).unwrap().identity.abi,
        stela_compiler::block::loop_budget::RESIDENT_BLOCK_ABI
    );
    Ok(())
}

#[test]
fn source_replacement_discards_the_loaded_resident_loop() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path(), &[SUBS_X0_ONE, B_NE_SELF])?;
    let mut state = thread(5);
    // SAFETY: same bounded nonfaulting source and exact budget as above.
    unsafe { runtime.run(&mut state, None, 2)? };
    assert_eq!(state.registers.x[0], 3);
    runtime.register_code(
        BASE,
        [MOV_X0_99, RET_X30]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    )?;
    assert!(runtime.loaded_manifest(BASE).is_none());
    let mut expected = state.registers.clone();
    expected.x[0] = 99;
    // SAFETY: replacement source is a finite owned MOV/RET without data access.
    let outcome = unsafe { runtime.run(&mut state, Some(STOP), 1)? };
    assert_eq!(state.registers, expected);
    assert_eq!(state.pc, STOP);
    assert_eq!(outcome.blocks_executed, 1);
    Ok(())
}

const TST_W8_ONE: u32 = 0x7200_011f;
const CSEL_W11_W9_ZERO_NE: u32 = 0x1a9f_112b;
const EOR_W8_W11_W8_LSR_ONE: u32 = 0x4a48_0568;
const EOR_W8_W8_W8: u32 = 0x4a08_0108;
const SUBS_W10_ONE: u32 = 0x7100_054a;
const B_NE_FOUR_WORDS_BACK: u32 = 0x54ff_ff81;
const CRC_POLYNOMIAL: u32 = 0xedb8_8320;
const CRC_INITIAL: u32 = 0xabcd_ef01;
const CRC_BITS: usize = u8::BITS as usize;
const CRC_LOOP: [u32; 5] = [
    TST_W8_ONE,
    CSEL_W11_W9_ZERO_NE,
    EOR_W8_W11_W8_LSR_ONE,
    SUBS_W10_ONE,
    B_NE_FOUR_WORDS_BACK,
];

fn ordinary(path: &std::path::Path, words: &[u32]) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new_for_target(
        1,
        path.to_path_buf(),
        BlockProfile::Ordinary,
        stela_compiler::TargetCpu::Baseline,
    );
    runtime.register_code(
        BASE,
        words.iter().flat_map(|word| word.to_le_bytes()).collect(),
    )?;
    Ok(runtime)
}

fn crc_thread() -> (ThreadState, GuestState) {
    let mut state = thread(0);
    state.registers.x[8] = 0x1234_5678_0000_0000 | u64::from(CRC_INITIAL);
    state.registers.x[9] = 0x9876_5432_0000_0000 | u64::from(CRC_POLYNOMIAL);
    state.registers.x[10] = 0xffff_ffff_0000_0000 | CRC_BITS as u64;
    let mut expected = state.registers.clone();
    let mut crc = CRC_INITIAL;
    let mut selected = 0;
    for _ in 0..CRC_BITS {
        selected = if crc & 1 != 0 { CRC_POLYNOMIAL } else { 0 };
        crc = (crc >> 1) ^ selected;
    }
    expected.x[8] = u64::from(crc);
    expected.x[10] = 0;
    expected.x[11] = u64::from(selected);
    expected.nzcv = ARM_CARRY | ARM_ZERO;
    (state, expected)
}

#[test]
fn ordinary_runtime_selects_mixed_artifact_abis_and_reuses_their_exact_cache() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let words: Vec<_> = CRC_LOOP.into_iter().chain([RET_X30]).collect();
    let return_pc = GuestAddress(BASE.0 + (CRC_LOOP.len() * std::mem::size_of::<u32>()) as u64);
    let mut runtime = ordinary(cache.path(), &words)?;
    for loaded in [false, true] {
        let (mut state, expected) = crc_thread();
        // SAFETY: owned scalar loop and RET are nonfaulting; the original-block
        // budget and stop sentinel bind the complete finite mixed-ABI run.
        let outcome = unsafe { runtime.run(&mut state, Some(STOP), CRC_BITS + 1)? };
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, STOP);
        assert_eq!(outcome.reason, StopReason::StopAddress);
        assert_eq!(outcome.blocks_executed, CRC_BITS + 1);
        assert_eq!(outcome.compiled_blocks, if loaded { 0 } else { 2 });
        assert_eq!(outcome.memory_cache_hits, if loaded { 2 } else { 0 });
        assert_eq!(
            runtime.loaded_manifest(BASE).unwrap().identity.abi,
            BlockProfile::OrdinaryResidentV1.abi()
        );
        assert_eq!(
            runtime.loaded_manifest(return_pc).unwrap().identity.abi,
            BlockProfile::Ordinary.abi()
        );
    }
    let mut disk_runtime = ordinary(cache.path(), &words)?;
    let (mut state, expected) = crc_thread();
    // SAFETY: same immutable source and owned finite scalar state as above.
    let outcome = unsafe { disk_runtime.run(&mut state, Some(STOP), CRC_BITS + 1)? };
    assert_eq!(state.registers, expected);
    assert_eq!(outcome.blocks_executed, CRC_BITS + 1);
    assert_eq!(outcome.compiled_blocks, 0);
    assert_eq!(outcome.disk_cache_hits, 2);
    Ok(())
}

#[test]
fn ordinary_source_replacement_switches_abis_and_zero_budget_stays_cold() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = ordinary(cache.path(), &[SUBS_X0_ONE, B_NE_SELF])?;
    let mut state = thread(5);
    // SAFETY: owned bounded subtraction loop has no guest data access.
    let outcome = unsafe { runtime.run(&mut state, None, 2)? };
    assert_eq!(outcome.blocks_executed, 2);
    assert_eq!(state.registers.x[0], 3);
    assert_eq!(
        runtime.loaded_manifest(BASE).unwrap().identity.abi,
        BlockProfile::OrdinaryResidentV1.abi()
    );
    runtime.register_code(
        BASE,
        [MOV_X0_99, RET_X30]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    )?;
    assert!(runtime.loaded_manifest(BASE).is_none());
    state.pc = BASE;
    let mut expected = state.registers.clone();
    expected.x[0] = 99;
    // SAFETY: replacement is a finite owned MOV/RET with canonical state.
    let outcome = unsafe { runtime.run(&mut state, Some(STOP), 1)? };
    assert_eq!(outcome.blocks_executed, 1);
    assert_eq!(state.registers, expected);
    assert_eq!(
        runtime.loaded_manifest(BASE).unwrap().identity.abi,
        BlockProfile::Ordinary.abi()
    );
    runtime.register_code(
        BASE,
        [SUBS_X0_ONE, B_NE_SELF]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    )?;
    state = thread(1);
    let before = state.registers.clone();
    // SAFETY: zero budget performs no preparation, mapping or native call.
    let outcome = unsafe { runtime.run(&mut state, None, 0)? };
    assert_eq!(state.registers, before);
    assert_eq!(state.pc, BASE);
    assert_eq!(outcome.blocks_executed, 0);
    assert!(runtime.loaded_manifest(BASE).is_none());
    // SAFETY: restored source is the same finite owned loop.
    let outcome = unsafe { runtime.run(&mut state, Some(FALLTHROUGH), 1)? };
    assert_eq!(outcome.blocks_executed, 1);
    assert_eq!(outcome.reason, StopReason::StopAddress);
    assert_eq!(
        runtime.loaded_manifest(BASE).unwrap().identity.abi,
        BlockProfile::OrdinaryResidentV1.abi()
    );
    Ok(())
}

#[test]
fn ordinary_clobbered_host_flags_decline_residency_but_preserve_guest_flags() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let source = [
        TST_W8_ONE,
        EOR_W8_W8_W8,
        CSEL_W11_W9_ZERO_NE,
        SUBS_X0_ONE,
        B_NE_FOUR_WORDS_BACK,
    ];
    let mut runtime = ordinary(cache.path(), &source)?;
    let mut state = thread(2);
    state.registers.x[8] = 1;
    state.registers.x[9] = u64::from(CRC_POLYNOMIAL);
    let mut expected = state.registers.clone();
    expected.x[0] = 1;
    expected.x[8] = 0;
    expected.x[11] = u64::from(CRC_POLYNOMIAL);
    expected.nzcv = ARM_CARRY;
    // SAFETY: one owned nonfaulting scalar block; CSEL observes the guest TST
    // even though the intervening guest EOR overwrites native flags.
    let outcome = unsafe { runtime.run(&mut state, None, 1)? };
    assert_eq!(state.registers, expected);
    assert_eq!(state.pc, BASE);
    assert_eq!(outcome.blocks_executed, 1);
    assert_eq!(
        runtime.loaded_manifest(BASE).unwrap().identity.abi,
        BlockProfile::Ordinary.abi()
    );
    Ok(())
}
