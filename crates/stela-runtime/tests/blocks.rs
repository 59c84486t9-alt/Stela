//! Native, serialized block-dispatch acceptance tests using only owned ARM code.
#![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
use anyhow::Result;
use stela_compiler::{GuestAddress, GuestState};
use stela_runtime::blocks::{BlockRuntime, StopReason, ThreadState};
use std::path::{Path, PathBuf};

const BASE: u64 = 0x1000;
const STOP: u64 = 0xdead_0000;
const RET: u32 = 0xd65f03c0;
const NOP: u32 = 0xd503201f;
const ADD_ONE: u32 = 0x91000400; // ADD X0, X0, #1

fn words(input: &[u32]) -> Vec<u8> {
    input.iter().flat_map(|word| word.to_le_bytes()).collect()
}
fn state(pc: u64, value: u64) -> ThreadState {
    let mut registers = GuestState::default();
    registers.x[0] = value;
    registers.x[30] = STOP;
    ThreadState {
        registers,
        pc: GuestAddress(pc),
    }
}
fn transfer(pc: u64, target: u64, call: bool) -> u32 {
    let displacement = (target as i64 - pc as i64) / 4;
    assert_eq!((target as i64 - pc as i64) % 4, 0);
    assert!((-(1 << 25)..(1 << 25)).contains(&displacement));
    (if call { 0x94000000 } else { 0x14000000 }) | (displacement as u32 & 0x03ffffff)
}
fn mov(destination: u32, source: u32) -> u32 {
    0xaa0003e0 | source << 16 | destination
}

#[test]
fn simd_family_chain_uses_shared_block_lowering_and_cpu_bound_disk_cache() -> Result<()> {
    use stela_compiler::aarch64::simd::saturating::FPSR_QC;
    use stela_compiler::{TargetCpu, block::BlockProfile};
    let cache = tempfile::tempdir()?;
    let program = words(&[
        0x4f0b5420, // SHL V0.16B,V1.16B,#3
        0x6f09a402, // USHLL2 V2.8H,V0.16B,#1
        0x4f0f8c42, // RSHRN2 V2.16B,V2.8H,#1: alias, preserve low half
        0x5f402483, // SRSHR D3,D4,#64
        0x7f4024c5, // URSHR D5,D6,#64
        0x6f404507, // SRI V7.2D,V8.2D,#64: preserve both old lanes
        0x6eab6d49, // UMIN V9.4S,V10.4S,V11.4S
        0x6eb0a92c, // UMAXV S12,V9.4S
        0x4e20598d, // CNT V13.16B,V12.16B
        0x4eedbdae, // ADDP V14.2D,V13.2D,V13.2D
        0x4e604a0f, // CLS V15.8H,V16.8H
        0x5e207a30, // SQABS B16,B17: active MIN sets QC, clears upper bits
        0x6e320e52, // UQADD V18.16B,V18.16B,V18.16B: zero sum retains QC
        0x6ea12a93, // SQXTUN2 V19.4S,V20.2D: signed wide bounds, preserve low half
        0x4eb7c2d5, // SMULL2 V21.2D,V22.4S,V23.4S
        0x4eb612b5, // SADDW2 V21.2D,V21.2D,V22.4S: full wide left alias
        0x6eb772d8, // UABDL2 V24.2D,V22.4S,V23.4S
        0x4eb79ed9, // MUL V25.4S,V22.4S,V23.4S
        0x6e3716da, // URHADD V26.16B,V22.16B,V23.16B
        0x6e202b5b, // UADDLP V27.8H,V26.16B
        0x4ea02adc, // SADDLP V28.2D,V22.4S
        0x6eb842bd, // RADDHN2 V29.4S,V21.2D,V24.2D
        0x0e212b7e, // XTN V30.8B,V27.8H
        0x6e213b5f, // SHLL2 V31.8H,V26.16B,#8
        0x1e2603d8, // FMOV W24,S30: raw low bits and W upper clearing
        0x9eaf0311, // FMOV V17.D[1],X24: preserve low half
        0x1ee04234, // FMOV H20,H17: raw scalar payload, clear upper bits
        0x1eee1017, // FMOV H23,#1.0
        0x6f00c656, // MVNI V22.4S,#0x12,MSL#8
        0x2f00b5f6, // BIC V22.4H,#0x0f,LSL#8: Q=0 clears high half
        RET,
    ]);
    let mut initial = state(BASE, 19);
    initial.registers.nzcv = 0xf0000000;
    initial.registers.fpcr = 0x03c00000;
    initial.registers.fpsr = 0x1f;
    let source: [u8; 16] = std::array::from_fn(|i| (i * 17 + 3) as u8);
    let limbs = |bytes: [u8; 16]| {
        let value = u128::from_le_bytes(bytes);
        [value as u64, (value >> 64) as u64]
    };
    initial.registers.v[1] = limbs(source);
    initial.registers.v[4] = [u64::MAX, 0x12345678];
    initial.registers.v[6] = [u64::MAX, 0x87654321];
    initial.registers.v[7] = [0x0123456789abcdef, 0xfedcba9876543210];
    initial.registers.v[10] = [0x00000001ffffffff, 0x0000000080000000];
    initial.registers.v[11] = [0x0000000200000000, 0xffffffff7fffffff];
    initial.registers.v[16] = [u64::MAX; 2];
    initial.registers.v[17] = [0x80, u64::MAX];
    initial.registers.v[19] = [0x0123456789abcdef, u64::MAX];
    initial.registers.v[20] = [u64::MAX, 0x100000000];
    initial.registers.v[22] = [0x00000003fffffffe, 0x80000000ffffffff];
    initial.registers.v[23] = [0xfffffffd00000005, 0xffffffff00000002];
    initial.registers.v[29] = [0x0123456789abcdef, u64::MAX];
    let mut expected = initial.registers.clone();
    let shifted = source.map(|byte| byte.wrapping_shl(3));
    expected.v[0] = limbs(shifted);
    let mut narrowed = [0; 16];
    for i in 0..4 {
        narrowed[i * 2..i * 2 + 2].copy_from_slice(&(u16::from(shifted[8 + i]) * 2).to_le_bytes());
    }
    narrowed[8..].copy_from_slice(&shifted[8..]);
    expected.v[2] = limbs(narrowed);
    expected.v[3] = [0; 2];
    expected.v[5] = [1, 0];
    expected.v[9] = [0x0000000100000000, 0x000000007fffffff];
    expected.v[12] = [0x7fffffff, 0];
    expected.v[13] = [0x07080808, 0];
    expected.v[14] = [0x07080808; 2];
    expected.v[15] = [0x000f000f000f000f; 2];
    expected.v[16] = [0x7f, 0];
    expected.v[19] = [0x0123456789abcdef, 0xffffffff00000000];
    expected.fpsr |= FPSR_QC;
    expected.v[21] = [u64::MAX - 2, 0];
    expected.v[24] = [0xfffffffd, 0x7fffffff];
    expected.v[25] = [0xfffffff7fffffff6, 0x80000000fffffffe];
    let input_bytes = |v: [u64; 2]| (u128::from(v[0]) | (u128::from(v[1]) << 64)).to_le_bytes();
    let a = input_bytes(initial.registers.v[22]);
    let b = input_bytes(initial.registers.v[23]);
    let averaged: [u8; 16] =
        std::array::from_fn(|i| ((u16::from(a[i]) + u16::from(b[i]) + 1) >> 1) as u8);
    let pairs: [u16; 8] =
        std::array::from_fn(|i| u16::from(averaged[i * 2]) + u16::from(averaged[i * 2 + 1]));
    expected.v[26] = limbs(averaged);
    expected.v[27] = limbs(std::array::from_fn(|i| pairs[i / 2].to_le_bytes()[i % 2]));
    expected.v[28] = [1, 0xffffffff7fffffff];
    expected.v[29] = [0x0123456789abcdef, 1];
    expected.v[30] = limbs(std::array::from_fn(
        |i| if i < 8 { pairs[i] as u8 } else { 0 },
    ));
    expected.v[31] = limbs(std::array::from_fn(|i| {
        if i % 2 == 0 { 0 } else { averaged[8 + i / 2] }
    }));
    expected.x[24] = 2;
    expected.v[17] = [0x80, 2];
    expected.v[20] = [0x80, 0];
    expected.v[23] = [0x3c00, 0];
    expected.v[22] = [0xf0ffe000f0ffe000, 0];
    let mut targets = vec![TargetCpu::Baseline, TargetCpu::detect()];
    targets.dedup();
    for target in targets {
        for (phase, disk) in [false, true, true].into_iter().enumerate() {
            let mut runtime = BlockRuntime::new_for_target(
                802,
                cache.path().into(),
                BlockProfile::Ordinary,
                target,
            );
            runtime.register_code(GuestAddress(BASE), program.clone())?;
            let mut thread = initial.clone();
            if phase == 2 {
                thread.registers.fpsr |= FPSR_QC;
            }
            // SAFETY: owned, finite register-only code; no guest RAM accesses.
            let result = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 1)? };
            assert_eq!(result.reason, StopReason::StopAddress);
            assert_eq!(thread.pc, GuestAddress(STOP));
            assert_eq!(thread.registers, expected);
            assert_eq!(result.compiled_blocks, usize::from(!disk));
            assert_eq!(result.disk_cache_hits, usize::from(disk));
        }
    }
    Ok(())
}

#[test]
fn nested_direct_and_indirect_calls_preserve_architectural_link_registers() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(17, cache.path().to_path_buf());
    let mut main = vec![NOP; 13];
    main[..4].copy_from_slice(&[
        mov(19, 30),
        transfer(BASE + 4, BASE + 0x20, true),
        mov(30, 19),
        RET,
    ]);
    main[8..].copy_from_slice(&[
        mov(20, 30),
        0xd63f0120, // BLR X9
        0x91000800, // ADD X0, X0, #2
        mov(30, 20),
        RET,
    ]);
    runtime.register_code(GuestAddress(BASE), words(&main))?;
    runtime.register_code(GuestAddress(0x2000), words(&[0x91000c00, RET]))?;
    let mut thread = state(BASE, 7);
    thread.registers.x[9] = 0x2000;
    // SAFETY: all code is owned, memory-free and terminating; execution is serialized.
    let result = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 10)? };
    assert_eq!(result.reason, StopReason::StopAddress);
    assert_eq!(result.blocks_executed, 5);
    assert_eq!(result.compiled_blocks, 5);
    assert_eq!(thread.pc, GuestAddress(STOP));
    assert_eq!(thread.registers.x[0], 12);
    assert_eq!(thread.registers.x[19], STOP);
    assert_eq!(thread.registers.x[20], BASE + 8);
    assert_eq!(thread.registers.x[30], STOP);
    Ok(())
}

#[test]
fn finite_budget_suspends_loop_at_real_guest_pc_and_resumes_from_cached_block() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(18, cache.path().to_path_buf());
    runtime.register_code(GuestAddress(BASE), words(&[0xf1000400, 0x54ffffe1, RET]))?;
    let mut thread = state(BASE, 3);
    // SAFETY: this memory-free decrement loop is bounded by the dispatch budget.
    let first = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    assert_eq!(first.reason, StopReason::BudgetExhausted);
    assert_eq!(first.blocks_executed, 2);
    assert_eq!(first.compiled_blocks, 1);
    assert_eq!(first.memory_cache_hits, 1);
    assert_eq!(thread.pc, GuestAddress(BASE));
    assert_eq!(thread.registers.x[0], 1);
    // SAFETY: the same owned code now reaches its return within two blocks.
    let resumed = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    assert_eq!(resumed.reason, StopReason::StopAddress);
    assert_eq!(resumed.blocks_executed, 2);
    assert_eq!(resumed.memory_cache_hits, 1);
    assert_eq!(thread.registers.x[0], 0);
    assert_eq!(thread.pc, GuestAddress(STOP));
    Ok(())
}

#[test]
fn straight_line_window_limit_falls_through_without_losing_an_instruction() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(19, cache.path().to_path_buf());
    let mut program = vec![ADD_ONE; 257];
    program.push(RET);
    runtime.register_code(GuestAddress(BASE), words(&program))?;
    let mut thread = state(BASE, 0);
    // SAFETY: finite, memory-free additions with an explicit guest return sentinel.
    let first = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 1)? };
    assert_eq!(first.reason, StopReason::BudgetExhausted);
    assert_eq!(thread.pc, GuestAddress(BASE + 256 * 4));
    assert_eq!(thread.registers.x[0], 256);
    // SAFETY: only one addition and RET remain.
    let second = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 1)? };
    assert_eq!(second.reason, StopReason::StopAddress);
    assert_eq!(second.blocks_executed, 1);
    assert_eq!(thread.registers.x[0], 257);
    assert_eq!(thread.pc, GuestAddress(STOP));
    Ok(())
}

#[test]
fn unsupported_callee_is_lazy_and_preserves_completed_caller_effects() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(20, cache.path().to_path_buf());
    runtime.register_code(
        GuestAddress(BASE),
        words(&[ADD_ONE, transfer(BASE + 4, 0x2000, true)]),
    )?;
    runtime.register_code(GuestAddress(0x2000), words(&[0]))?;
    let mut thread = state(BASE, 40);
    // SAFETY: the supported caller is memory-free; unknown callee code must not run.
    let result = unsafe { runtime.run(&mut thread, None, 10)? };
    assert!(matches!(result.reason, StopReason::Unsupported { .. }));
    assert_eq!(result.blocks_executed, 1);
    assert_eq!(result.compiled_blocks, 1);
    assert_eq!(thread.pc, GuestAddress(0x2000));
    assert_eq!(thread.registers.x[0], 41);
    assert_eq!(thread.registers.x[30], BASE + 8);
    Ok(())
}

#[test]
fn indirect_unmapped_and_unaligned_targets_stop_without_host_jumps() -> Result<()> {
    for (target, expected) in [
        (0x9000, StopReason::UnmappedTarget),
        (BASE + 1, StopReason::UnalignedTarget),
    ] {
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new(21, cache.path().to_path_buf());
        runtime.register_code(GuestAddress(BASE), words(&[0xd61f0120]))?; // BR X9
        let mut thread = state(BASE, 55);
        thread.registers.x[9] = target;
        // SAFETY: BR returns a guest PC to dispatch; it must never jump there on the host.
        let result = unsafe { runtime.run(&mut thread, None, 10)? };
        assert_eq!(result.reason, expected);
        assert_eq!(result.blocks_executed, 1);
        assert_eq!(thread.pc, GuestAddress(target));
        assert_eq!(thread.registers.x[0], 55);
    }
    Ok(())
}

#[test]
fn registration_replacement_removal_and_reregistration_invalidate_loaded_blocks() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(22, cache.path().to_path_buf());
    let original = words(&[0xd2800020, RET]); // MOV X0, #1
    let first_generation = runtime.register_code(GuestAddress(BASE), original.clone())?;
    let mut thread = state(BASE, 0);
    // SAFETY: own memory-free constant-return code.
    unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    assert_eq!(thread.registers.x[0], 1);
    let second_generation = runtime.register_code(GuestAddress(BASE), words(&[0xd2800040, RET]))?;
    assert!(second_generation > first_generation);
    thread = state(BASE, 0);
    // SAFETY: replacement is another owned constant-return program.
    let replaced = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    assert_eq!(replaced.reason, StopReason::StopAddress);
    assert_eq!(replaced.compiled_blocks, 1);
    assert_eq!(replaced.memory_cache_hits, 0);
    assert_eq!(thread.registers.x[0], 2);
    assert!(runtime.unregister_code(GuestAddress(BASE)));
    assert!(!runtime.unregister_code(GuestAddress(BASE)));
    thread = state(BASE, 99);
    // SAFETY: no code may execute after its region was removed.
    let removed = unsafe { runtime.run(&mut thread, None, 1)? };
    assert_eq!(removed.reason, StopReason::UnmappedTarget);
    assert_eq!(removed.blocks_executed, 0);
    assert_eq!(thread.registers.x[0], 99);
    assert!(runtime.register_code(GuestAddress(BASE), original)? > second_generation);
    // SAFETY: original owned code has been explicitly registered anew.
    let restored = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    assert_eq!(restored.reason, StopReason::StopAddress);
    assert_eq!(restored.memory_cache_hits, 0);
    assert_eq!(restored.disk_cache_hits, 1);
    assert_eq!(thread.registers.x[0], 1);
    Ok(())
}

#[test]
fn warm_execution_uses_rx_memory_and_new_runtime_revalidates_disk_cache() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let program = words(&[ADD_ONE, RET]);
    let mut runtime = BlockRuntime::new(23, cache.path().to_path_buf());
    runtime.register_code(GuestAddress(BASE), program.clone())?;
    let mut thread = state(BASE, 1);
    // SAFETY: own finite memory-free code, serialized through this runtime.
    let cold = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    assert_eq!(cold.compiled_blocks, 1);
    thread = state(BASE, 7);
    // SAFETY: the same immutable executable copy remains valid.
    let warm = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    assert_eq!(warm.compiled_blocks, 0);
    assert_eq!(warm.disk_cache_hits, 0);
    assert_eq!(warm.memory_cache_hits, 1);
    assert_eq!(thread.registers.x[0], 8);
    let mut other = BlockRuntime::new(23, cache.path().to_path_buf());
    other.register_code(GuestAddress(BASE), program)?;
    thread = state(BASE, 12);
    // SAFETY: loading must revalidate the persisted native bytes before executing.
    let disk = unsafe { other.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    assert_eq!(disk.compiled_blocks, 0);
    assert_eq!(disk.disk_cache_hits, 1);
    assert_eq!(disk.memory_cache_hits, 0);
    assert_eq!(thread.registers.x[0], 13);
    Ok(())
}

fn named_files(root: &Path, name: &str) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            result.extend(named_files(&path, name)?);
        } else if path.file_name().and_then(|s| s.to_str()) == Some(name) {
            result.push(path);
        }
    }
    Ok(result)
}

#[test]
fn disk_corruption_cannot_replace_a_loaded_copy_and_is_rejected_on_reload() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let program = words(&[ADD_ONE, RET]);
    let mut runtime = BlockRuntime::new(24, cache.path().to_path_buf());
    runtime.register_code(GuestAddress(BASE), program.clone())?;
    let mut thread = state(BASE, 0);
    // SAFETY: own memory-free code, first load before corrupting its disk artifact.
    unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    let files = named_files(cache.path(), "native.bin")?;
    assert_eq!(files.len(), 1);
    std::fs::write(&files[0], [0xcc])?;
    thread = state(BASE, 10);
    // SAFETY: loaded RX memory is independent of later untrusted disk edits.
    let warm = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    assert_eq!(warm.memory_cache_hits, 1);
    assert_eq!(thread.registers.x[0], 11);
    let mut other = BlockRuntime::new(24, cache.path().to_path_buf());
    other.register_code(GuestAddress(BASE), program)?;
    thread = state(BASE, 20);
    // SAFETY: corruption must be rejected before any new mapping or execution.
    assert!(unsafe { other.run(&mut thread, Some(GuestAddress(STOP)), 2) }.is_err());
    assert_eq!(thread.pc, GuestAddress(BASE));
    assert_eq!(thread.registers.x[0], 20);
    Ok(())
}

#[test]
fn rejects_overlapping_regions_and_never_pads_partial_final_instruction() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(25, cache.path().to_path_buf());
    let mut program = words(&[ADD_ONE]);
    program.extend([0xc0, 0x03, 0x5f]); // Three bytes of RET, deliberately incomplete.
    runtime.register_code(GuestAddress(BASE), program)?;
    assert!(
        runtime
            .register_code(GuestAddress(BASE + 4), words(&[RET]))
            .is_err()
    );
    assert!(
        runtime
            .register_code(GuestAddress(BASE - 4), words(&[NOP, RET]))
            .is_err()
    );
    let mut thread = state(BASE, 40);
    // SAFETY: the complete addition is memory-free; truncated RET must never execute.
    let result = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 10)? };
    assert_eq!(result.reason, StopReason::TruncatedInstruction);
    assert_eq!(result.blocks_executed, 1);
    assert_eq!(thread.pc, GuestAddress(BASE + 4));
    assert_eq!(thread.registers.x[0], 41);
    assert_eq!(thread.registers.x[30], STOP);
    Ok(())
}

#[test]
fn direct_ram_effects_survive_call_and_return_dispatch_boundaries() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(26, cache.path().to_path_buf());
    runtime.register_code(
        GuestAddress(BASE),
        words(&[
            mov(19, 30),
            ADD_ONE,
            0xf9000020, // STR X0, [X1]
            transfer(BASE + 12, 0x2000, true),
            mov(30, 19),
            RET,
        ]),
    )?;
    runtime.register_code(
        GuestAddress(0x2000),
        words(&[
            0xf9400020, // LDR X0, [X1]
            ADD_ONE, 0xf9000020, // STR X0, [X1]
            RET,
        ]),
    )?;
    let mut cell = Box::new(0u64);
    let mut thread = state(BASE, 40);
    thread.registers.x[1] = (&raw mut *cell) as u64;
    // SAFETY: X1 points to one exclusively owned aligned u64 for the whole run.
    // Code accesses exactly that cell and neither aliases Rust/runtime state nor
    // escapes it; no Rust reference to the cell is active during execution.
    let result = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 4)? };
    assert_eq!(result.reason, StopReason::StopAddress);
    assert_eq!(result.blocks_executed, 3);
    assert_eq!(thread.registers.x[0], 42);
    assert_eq!(*cell, 42);
    assert_eq!(thread.pc, GuestAddress(STOP));
    Ok(())
}

#[test]
fn discovery_follows_both_conditional_edges_calls_continuations_and_loops_without_linear_scanning()
-> Result<()> {
    use stela_compiler::block::{DynamicEdgeKind, SuccessorKind};
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(91, cache.path().into());
    runtime.register_code(
        GuestAddress(BASE),
        words(&[
            transfer(BASE, 0x2000, true),
            transfer(BASE + 4, 0x3000, false),
            0,
        ]),
    )?;
    runtime.register_code(
        GuestAddress(0x2000),
        words(&[0x54000040, RET, transfer(0x2008, 0x2000, false), 0]),
    )?;
    runtime.register_code(GuestAddress(0x3000), words(&[RET, 0]))?;
    let report = runtime.discover(&[GuestAddress(BASE)], 32)?;
    assert_eq!(
        report.blocks.iter().map(|b| b.entry.0).collect::<Vec<_>>(),
        [BASE, 0x2000, BASE + 4, 0x2008, 0x2004, 0x3000]
    );
    assert_eq!(report.compiled_blocks, 6);
    assert_eq!(report.attempted_entries, 6);
    assert!(report.issues.is_empty());
    assert!(report.pending_entries.is_empty());
    assert!(report.static_worklist_exhausted);
    assert_eq!(
        report.blocks[0]
            .analysis
            .static_successors
            .iter()
            .map(|e| e.kind)
            .collect::<Vec<_>>(),
        [SuccessorKind::CallTarget, SuccessorKind::CallContinuation]
    );
    assert_eq!(report.deferred_dynamic_edges.len(), 2);
    assert!(
        report
            .deferred_dynamic_edges
            .iter()
            .all(|e| e.edge.kind == DynamicEdgeKind::Return)
    );
    assert!(report.dynamic_targets_unresolved);
    assert!(
        !report.native_executed && !report.native_pages_loaded && !report.complete_code_discovered
    );
    for block in &report.blocks {
        assert!(runtime.loaded_manifest(block.entry).is_none());
    }
    Ok(())
}

#[test]
fn discovery_prepares_faulting_guest_memory_code_but_does_not_map_or_execute_it() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(92, cache.path().into());
    // LDR X0,[X1]; RET would dereference an unspecified guest pointer if invoked.
    runtime.register_code(GuestAddress(BASE), words(&[0xf9400020, RET]))?;
    let prepared = runtime.prepare(GuestAddress(BASE))?;
    assert_eq!(prepared.analysis.source_bytes, 8);
    assert!(!prepared.prepared.cache_hit);
    assert!(runtime.loaded_manifest(GuestAddress(BASE)).is_none());
    let report = runtime.discover(&[GuestAddress(BASE)], 1)?;
    assert_eq!(report.disk_cache_hits, 1);
    assert!(!report.native_executed && !report.native_pages_loaded);
    assert!(runtime.loaded_manifest(GuestAddress(BASE)).is_none());
    Ok(())
}

#[test]
fn discovery_distinguishes_indirect_calls_returns_and_traps_without_inventing_targets() -> Result<()>
{
    use stela_compiler::block::DynamicEdgeKind;
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(93, cache.path().into());
    runtime.register_code(GuestAddress(BASE), words(&[0xd63f0120, RET, 0]))?; // BLR X9; RET; unreachable data.
    runtime.register_code(GuestAddress(0x2000), words(&[0xd61f0140, 0]))?; // BR X10.
    runtime.register_code(GuestAddress(0x3000), words(&[0xd4001001, 0]))?;
    let report = runtime.discover(
        &[
            GuestAddress(0x3000),
            GuestAddress(0x2000),
            GuestAddress(BASE),
        ],
        20,
    )?;
    assert_eq!(
        report.roots.iter().map(|p| p.0).collect::<Vec<_>>(),
        [BASE, 0x2000, 0x3000]
    );
    assert_eq!(report.blocks.len(), 4);
    assert!(report.issues.is_empty());
    assert_eq!(
        report
            .deferred_dynamic_edges
            .iter()
            .map(|e| (e.edge.kind, e.edge.register))
            .collect::<Vec<_>>(),
        [
            (DynamicEdgeKind::Call, 9),
            (DynamicEdgeKind::Branch, 10),
            (DynamicEdgeKind::Return, 30)
        ]
    );
    let trap = report.blocks.iter().find(|b| b.entry.0 == 0x3000).unwrap();
    assert!(trap.analysis.trap.is_some());
    assert!(trap.analysis.static_successors.is_empty());
    Ok(())
}

#[test]
fn discovery_reports_exact_unsupported_pc_missing_and_truncated_sources_with_bounded_work()
-> Result<()> {
    use stela_runtime::blocks::DiscoveryProblem;
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(94, cache.path().into());
    runtime.register_code(GuestAddress(BASE), words(&[NOP, 0, RET]))?;
    let mut partial = words(&[NOP]);
    partial.extend([1, 2]);
    runtime.register_code(GuestAddress(0x2000), partial)?;
    let report = runtime.discover(
        &[
            GuestAddress(BASE),
            GuestAddress(0x2004),
            GuestAddress(0x9000),
        ],
        10,
    )?;
    assert!(report.blocks.is_empty());
    assert_eq!(report.issues.len(), 3);
    assert!(
        matches!(&report.issues[0].problem,DiscoveryProblem::Unsupported{failure_pc,..} if failure_pc.0==BASE+4)
    );
    assert_eq!(
        report.issues[1].problem,
        DiscoveryProblem::TruncatedInstruction
    );
    assert_eq!(report.issues[2].problem, DiscoveryProblem::UnmappedTarget);
    assert!(!report.static_worklist_exhausted);
    assert_eq!(report.attempted_entries, 3);
    assert!(runtime.loaded_manifest(GuestAddress(BASE)).is_none());
    assert!(runtime.discover(&[], 1).is_err());
    assert!(
        runtime
            .discover(&[GuestAddress(BASE), GuestAddress(BASE)], 1)
            .is_err()
    );
    assert!(runtime.discover(&[GuestAddress(BASE + 1)], 1).is_err());
    assert!(runtime.discover(&[GuestAddress(BASE)], 4097).is_err());
    let zero = runtime.discover(&[GuestAddress(BASE)], 0)?;
    assert_eq!(zero.attempted_entries, 0);
    assert_eq!(zero.pending_entries, [GuestAddress(BASE)]);
    Ok(())
}

#[test]
fn prepared_aot_artifact_is_reused_by_jit_and_source_replacement_changes_identity() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(95, cache.path().into());
    let original = words(&[ADD_ONE, RET]);
    runtime.register_code(GuestAddress(BASE), original.clone())?;
    let prepared = runtime.prepare(GuestAddress(BASE))?;
    let key = prepared.prepared.key;
    let generation = prepared.generation;
    assert!(!prepared.prepared.cache_hit);
    assert!(runtime.loaded_manifest(GuestAddress(BASE)).is_none());
    let mut thread = state(BASE, 9);
    // SAFETY: independently owned memory-free code and an explicit return sentinel.
    let ran = unsafe { runtime.run(&mut thread, Some(GuestAddress(STOP)), 2)? };
    assert_eq!(ran.compiled_blocks, 0);
    assert_eq!(ran.disk_cache_hits, 1);
    assert_eq!(thread.registers.x[0], 10);
    assert_eq!(
        runtime
            .loaded_manifest(GuestAddress(BASE))
            .unwrap()
            .identity,
        prepared.prepared.manifest.identity
    );
    runtime.register_code(GuestAddress(BASE), words(&[0x91000800, RET]))?;
    assert!(runtime.loaded_manifest(GuestAddress(BASE)).is_none());
    let replaced = runtime.prepare(GuestAddress(BASE))?;
    assert!(replaced.generation > generation);
    assert_ne!(replaced.prepared.key, key);
    assert!(!replaced.prepared.cache_hit);
    assert!(runtime.unregister_code(GuestAddress(BASE)));
    assert!(runtime.prepare(GuestAddress(BASE)).is_err());
    runtime.register_code(GuestAddress(BASE), original)?;
    let restored = runtime.prepare(GuestAddress(BASE))?;
    assert!(restored.prepared.cache_hit);
    assert_eq!(restored.prepared.key, key);
    Ok(())
}

#[test]
fn discovery_budget_leaves_deterministic_candidates_and_new_runtime_uses_same_disk_artifacts()
-> Result<()> {
    let cache = tempfile::tempdir()?;
    let code = words(&[0x54000040, RET, RET]);
    let mut runtime = BlockRuntime::new(96, cache.path().into());
    runtime.register_code(GuestAddress(BASE), code.clone())?;
    let first = runtime.discover(&[GuestAddress(BASE)], 1)?;
    assert_eq!(
        first.pending_entries,
        [GuestAddress(BASE + 8), GuestAddress(BASE + 4)]
    );
    assert_eq!(first.compiled_blocks, 1);
    assert!(!first.static_worklist_exhausted);
    let mut second = BlockRuntime::new(96, cache.path().into());
    second.register_code(GuestAddress(BASE), code)?;
    let warm = second.discover(&[GuestAddress(BASE)], 10)?;
    assert_eq!(
        warm.blocks.iter().map(|b| b.entry.0).collect::<Vec<_>>(),
        [BASE, BASE + 8, BASE + 4]
    );
    assert_eq!(warm.disk_cache_hits, 1);
    assert_eq!(warm.compiled_blocks, 2);
    assert!(warm.static_worklist_exhausted);
    assert_eq!(
        first.blocks[0].prepared.manifest.identity,
        warm.blocks[0].prepared.manifest.identity
    );
    assert_eq!(
        first.blocks[0].prepared.manifest.native_sha256,
        warm.blocks[0].prepared.manifest.native_sha256
    );
    Ok(())
}
