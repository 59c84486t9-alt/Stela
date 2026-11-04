use super::super::chain::{DIRECT_EXIT_BYTES, DYNAMIC_EXIT_BYTES};
use super::*;
use crate::block::{SynchronousTrap, TrapKind};
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn ordinary_adjacent_nzcv_uses_native_condition_on_fast_extract_targets() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan},
    };

    // CMP W13,W1; B.HS from the zlib deflate match search.
    let pc = GuestAddress(0x100003fe0);
    let words = [0x6b01_01bfu32, 0x5400_0062];
    let compile = |words: &[u32], pc, target| {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let options = Options::new(BlockProfile::ORDINARY, target);
        CompilationPlan::new(&source, pc, &options)
            .unwrap()
            .compile()
            .unwrap()
            .native
    };
    let extract = |code: &[u8]| {
        code.windows(5)
            .any(|window| window == [0xc4, 0xe2, 0x7a, 0xf5, 0xc1])
    };
    let fast = TargetCpu::X86_64_V2.with_bmi2().with_fast_pdep();
    let pair = compile(&words, pc, fast);
    let branch = pair.source_map[1];
    assert_eq!(
        pair.source_map,
        [(pc, 0), (GuestAddress(pc.0 + 4), branch.1)]
    );
    assert!(extract(&pair.x86_64_code[..branch.1]));
    // Subtraction's CMC gives Arm carry, so HS branches with host JB.
    assert!(pair.x86_64_code[branch.1..].starts_with(&[0x0f, 0x82]));

    let hi = compile(&[words[0], words[1] & !15 | 8], pc, fast);
    // HI needs both !borrow and !zero. Restore x86 borrow for JA.
    assert!(hi.x86_64_code[hi.source_map[1].1..].starts_with(&[0xf5, 0x0f, 0x87]));
    for target in [
        TargetCpu::Baseline,
        TargetCpu::X86_64_V2.with_bmi2(),
        TargetCpu::X86_64_V2.with_fast_pdep(),
        fast.with_data_independent_timing(),
    ] {
        assert!(!extract(&compile(&words, pc, target).x86_64_code));
    }
    assert!(!extract(&compile(&words[..1], pc, fast).x86_64_code));
    let independent = compile(&words[1..], branch.0, fast);
    assert_eq!(independent.source_map, [(branch.0, 0)]);
    assert_eq!(independent.x86_64_code[0], 0xf6); // TEST the saved NZCV byte.
}

#[test]
fn ordinary_compare_reads_both_settled_load_results() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan},
    };

    // LDRB W6,[X4]; LDRB W7,[X11]; CMP W6,W7; B.NE from zlib.
    let words = [0x3940_0086u32, 0x3940_0167, 0x6b07_00df, 0x5400_0dc1];
    let pc = GuestAddress(0x100003e14);
    let compile = |words: &[u32], pc, target| {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        CompilationPlan::new(&source, pc, &Options::new(BlockProfile::ORDINARY, target))
            .unwrap()
            .compile()
            .unwrap()
            .native
    };
    let baseline = TargetCpu::Baseline;
    let fast = TargetCpu::X86_64_V2.with_bmi2().with_fast_pdep();
    for target in [baseline, fast] {
        let grouped = compile(&words, pc, target);
        let map = &grouped.source_map;
        assert_eq!(
            map.iter().map(|row| row.0).collect::<Vec<_>>(),
            [
                pc,
                GuestAddress(pc.0 + 4),
                GuestAddress(pc.0 + 8),
                GuestAddress(pc.0 + 12),
            ]
        );
        let code = &grouped.x86_64_code;
        assert!(code[..map[1].1].ends_with(&[0x48, 0x89, 0x8f, 0x30, 0, 0, 0]));
        assert!(code[map[1].1..map[2].1].ends_with(&[0x48, 0x89, 0x87, 0x38, 0, 0, 0]));
        assert!(code[map[2].1..].starts_with(&[0x39, 0xc1]));
        let independent = compile(&words[1..], map[1].0, target);
        assert!(!independent.x86_64_code[independent.source_map[1].1..].starts_with(&[0x39, 0xc1]));
    }

    for fallback in [
        compile(&words, pc, baseline.with_data_independent_timing()),
        compile(&[words[0], 0x3940_0087, words[2], words[3]], pc, baseline), // Shared base.
        compile(&[words[0], 0x3940_00c7, words[2], words[3]], pc, baseline), // Dependent base.
        compile(
            &[words[0], words[1], words[2] | (1 << 10), words[3]],
            pc,
            baseline,
        ),
    ] {
        assert!(!fallback.x86_64_code[fallback.source_map[2].1..].starts_with(&[0x39, 0xc1]));
    }
}

#[test]
fn indexed_load_store_pair_shares_checked_address_with_distinct_fault_rows() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan, Features, RecoverySiteKind},
        x86_64::MemoryChecks,
    };
    let words = [0xb877_6907u32, 0xb837_6911]; // LDR W7,[X8,X23]; STR W17,[X8,X23]
    let pc = GuestAddress(0x100008014);
    let compile = |words: &[u32], pc, profile, target, checks| {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let options = Options::new(profile, target).with_memory_checks(checks);
        CompilationPlan::new(&source, pc, &options)
            .unwrap()
            .compile()
            .unwrap()
    };
    let target = TargetCpu::Baseline;
    let direct = MemoryChecks::DEFAULT;
    let ordinary = BlockProfile::ORDINARY;
    let system = BlockProfile::new(Features::SYSTEM_MODE);
    let dit = target.with_data_independent_timing();
    for profile in [ordinary, system] {
        let grouped = compile(&words, pc, profile, target, direct);
        let old = compile(&words, pc, profile, dit, direct);
        assert!(grouped.native.x86_64_code.len() < old.native.x86_64_code.len());
        let second = grouped.native.source_map[1];
        assert_eq!(second.0, GuestAddress(pc.0 + 4));
        let standalone = compile(&words[1..], second.0, profile, target, direct);
        assert_eq!(standalone.native.source_map, [(second.0, 0)]);
        assert!(
            !grouped.native.x86_64_code[second.1..]
                .starts_with(&standalone.native.x86_64_code[..3])
        );
        if profile == system {
            let rows = &grouped.fault_recovery;
            let accesses: Vec<_> = rows
                .iter()
                .filter(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
                .collect();
            assert_eq!(accesses.len(), 2);
            assert_eq!(accesses[0].retirement.instruction_pc(), pc);
            assert_eq!(accesses[0].retirement.retired_before(), 0);
            assert!(accesses[0].end <= second.1);
            assert_eq!(accesses[1].retirement.instruction_pc(), second.0);
            assert_eq!(accesses[1].retirement.retired_before(), 1);
            assert!(accesses[1].start >= second.1);
            let failures: Vec<_> = rows
                .iter()
                .filter(|row| row.site.kind() == RecoverySiteKind::GuestCheck)
                .collect();
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].retirement.instruction_pc(), pc);
            let mut mask = Code::pinned();
            super::super::unreachable_if(&mut mask.asm(), Cond::A);
            let preceding = &grouped.native.x86_64_code[..accesses[0].start];
            assert!(preceding.ends_with(&mask[..]));
        }
    }

    // Replacing the index with the load result invalidates the pair.
    let alias = [words[0] & !31 | 23, words[1]];
    let grouped = compile(&alias, pc, ordinary, target, direct);
    let fallback = compile(&alias, pc, ordinary, dit, direct);
    assert_eq!(
        grouped.native.x86_64_code.len(),
        fallback.native.x86_64_code.len()
    );
    for checks in [
        MemoryChecks::system(true, false, true, true),
        direct.with_translation(0x1000),
    ] {
        let grouped = compile(&words, pc, system, target, checks);
        let fallback = compile(&words, pc, system, dit, checks);
        assert_eq!(grouped.native.x86_64_code, fallback.native.x86_64_code);
    }
}

#[test]
fn pinned_carry_run_commits_flags_once_before_the_next_guest_fault() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan, Features, RecoverySiteKind},
    };

    let start = GuestAddress(0xef290);
    let words = [
        0xba0e_0317u32, // ADCS X23,X24,X14
        0xba0f_0338,    // ADCS X24,X25,X15
        0xba10_0359,    // ADCS X25,X26,X16
        0xba11_039a,    // ADCS X26,X28,X17
        0xf940_0349,    // LDR X9,[X26]
    ];
    let compile = |words: &[u32], pc, target| {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let profile = BlockProfile::new(Features::SYSTEM_MODE);
        CompilationPlan::new(&source, pc, &Options::new(profile, target))
            .unwrap()
            .compile()
            .unwrap()
    };
    let target = TargetCpu::Baseline;
    let grouped = compile(&words, start, target);
    let dit = compile(&words, start, target.with_data_independent_timing());
    let store = nzcv_store(true);
    let stores_flags = |native: &NativeBlock, row: usize| {
        let offset = native.source_map[row].1;
        let end = native
            .source_map
            .get(row + 1)
            .map_or(native.x86_64_code.len(), |row| row.1);
        native.x86_64_code[offset..end]
            .windows(store.len())
            .any(|bytes| bytes == store)
    };
    assert_eq!(grouped.native.source_map.len(), words.len());
    for row in 0..4 {
        assert_eq!(
            grouped.native.source_map[row].0,
            GuestAddress(start.0 + row as u64 * 4)
        );
        assert_eq!(stores_flags(&grouped.native, row), row == 3);
        assert!(stores_flags(&dit.native, row));
    }
    let access = grouped
        .fault_recovery
        .iter()
        .find(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
        .unwrap();
    assert_eq!(
        access.retirement.instruction_pc(),
        GuestAddress(start.0 + 16)
    );
    assert_eq!(access.retirement.retired_before(), 4);
    assert!(access.start >= grouped.native.source_map[4].1);
    assert!(access.bindings.is_empty());

    // Prefix clipping materializes the last flag result actually reached.
    for len in 1..=4 {
        let clipped = compile(&words[..len], start, target);
        assert_eq!(clipped.native.source_map.len(), len);
        assert!(stores_flags(&clipped.native, len - 1));
    }
    let independent = compile(&words[3..], GuestAddress(start.0 + 12), target);
    assert!(stores_flags(&independent.native, 0));

    let bounded = compile(&[words[0]; 9], start, target);
    for row in 0..9 {
        assert_eq!(stores_flags(&bounded.native, row), row >= 7);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn pinned_carry_run_matches_dit_for_mixed_widths_and_borrow() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan, Features},
        context::ExecutionContext,
        x86_64::{asm::vector_extensions::execution::Native, pinned::entered},
    };
    let compile = |words: &[u32], target| {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let profile = BlockProfile::new(Features::SYSTEM_MODE);
        let body = CompilationPlan::new(
            &source,
            GuestAddress(0x100000),
            &Options::new(profile, target),
        )
        .unwrap()
        .compile()
        .unwrap();
        Native::new(&entered(&body.native.x86_64_code))
    };
    let target = TargetCpu::Baseline;
    let dit = target.with_data_independent_timing();
    for final_subtract in [0, 1 << 30] {
        let words = [
            0xfa0e_02e8u32,               // SBCS X8,X23,X14 (read incoming guest carry)
            0x7a08_0288,                  // SBCS W8,W20,W8 (right aliases pinned destination)
            0xba08_0210,                  // ADCS X16,X16,X8 (consume zero-extended W8)
            0x3a1f_0201 | final_subtract, // ADCS/SBCS W1,W16,WZR
        ];
        let grouped = compile(&words, target);
        let fallback = compile(&words, dit);
        for source in [0, 1, u64::MAX, 0x8000_0000_8000_0000] {
            for nzcv in [0, 0x2000_0000, 0xf000_0000] {
                let mut original = crate::GuestState {
                    sp: 0x1234,
                    nzcv,
                    ..Default::default()
                };
                for (index, register) in original.x.iter_mut().enumerate() {
                    *register = 0xfedc_ba98_7654_3210u64.wrapping_mul(index as u64 + 1);
                }
                original.x[23] = source;
                let mut result = original.clone();
                grouped.run(&mut result, &mut ExecutionContext::default());
                fallback.run(&mut original, &mut ExecutionContext::default());
                assert_eq!(result, original);
            }
        }
    }
}

#[test]
fn pinned_carry_follows_live_flags_and_keeps_the_next_fault_boundary() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan, Features, RecoverySiteKind},
    };
    let start = GuestAddress(0xeee3c);
    let words = [
        0xab06_0273u32, // ADDS X19,X19,X6
        0xba07_0294,    // ADCS X20,X20,X7
        0xf940_0289,    // LDR X9,[X20]
    ];
    let compile = |words: &[u32], pc, target| {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let profile = BlockProfile::new(Features::SYSTEM_MODE);
        CompilationPlan::new(&source, pc, &Options::new(profile, target))
            .unwrap()
            .compile()
            .unwrap()
    };
    let target = TargetCpu::Baseline;
    let grouped = compile(&words, start, target);
    let dit = compile(&words, start, target.with_data_independent_timing());
    let second = GuestAddress(start.0 + 4);
    let independent = compile(&words[1..], second, target);
    let mut scratch = Code::pinned();
    super::super::flag_word::carry(&mut scratch.asm(), 29);
    let reads_carry = |native: &NativeBlock, row: usize| {
        let start = native.source_map[row].1;
        let end = native.source_map[row + 1].1;
        native.x86_64_code[start..end]
            .windows(scratch.len())
            .any(|bytes| bytes == &scratch[..])
    };
    assert!(!reads_carry(&grouped.native, 1));
    assert!(reads_carry(&dit.native, 1));
    assert!(reads_carry(&independent.native, 0));
    assert_eq!(grouped.native.source_map.len(), words.len());
    assert_eq!(grouped.native.source_map[1].0, second);
    assert_eq!(grouped.native.source_map[2].0, GuestAddress(start.0 + 8));
    let access = grouped
        .fault_recovery
        .iter()
        .find(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
        .unwrap();
    assert_eq!(
        access.retirement.instruction_pc(),
        grouped.native.source_map[2].0
    );
    assert_eq!(access.retirement.retired_before(), 2);
    assert!(access.start >= grouped.native.source_map[2].1);
    assert!(access.bindings.is_empty());
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn pinned_carry_matches_fallback_for_widths_aliases_and_zero_registers() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan, Features},
        context::ExecutionContext,
        x86_64::{asm::vector_extensions::execution::Native, pinned::entered},
    };
    let compile = |words: [u32; 2], target| {
        let source: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let profile = BlockProfile::new(Features::SYSTEM_MODE);
        let options = Options::new(profile, target);
        let body = CompilationPlan::new(&source, GuestAddress(0x100000), &options)
            .unwrap()
            .compile()
            .unwrap();
        Native::new(&entered(&body.native.x86_64_code))
    };
    let target = TargetCpu::Baseline;
    let dit = target.with_data_independent_timing();
    for wide in [0, 1 << 31] {
        for producer in [0x2b03_004f, 0x6b03_004f] {
            for kind in [0, 1 << 29, 1 << 30, 3 << 29] {
                for (destination, left, right) in [
                    (8, 20, 8),
                    (19, 19, 19),
                    (1, 31, 0),
                    (0, 0, 31),
                    (31, 2, 8),
                    (7, 31, 31),
                    (17, 16, 1),
                ] {
                    let consumer = 0x1a00_0000 | kind | right << 16 | left << 5 | destination;
                    let words = [wide | producer, wide | consumer];
                    let grouped = compile(words, target);
                    let fallback = compile(words, dit);
                    for pair in [
                        [0, 1],
                        [1, 0],
                        [u64::MAX, 1],
                        [0x8000_0000_8000_0000, u64::MAX],
                    ] {
                        let mut original = crate::GuestState {
                            sp: 0x1234,
                            nzcv: 0x9000_0000,
                            ..Default::default()
                        };
                        for (index, register) in original.x.iter_mut().enumerate() {
                            *register = 0xfedc_ba98_7654_3210u64.wrapping_mul(index as u64 + 1);
                        }
                        original.x[2..4].copy_from_slice(&pair);
                        let mut result = original.clone();
                        grouped.run(&mut result, &mut ExecutionContext::default());
                        fallback.run(&mut original, &mut ExecutionContext::default());
                        assert_eq!(
                            result, original,
                            "encodings {words:08x?}, inputs {pair:016x?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn pinned_scalar_span_settles_before_the_next_access() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan, Features, RecoverySiteKind},
    };

    let words = [
        0x8b06_02d5u32, // ADD X21,X22,X6
        0x8b06_0259,    // ADD X25,X18,X6
        0xd100_0eb2,    // SUB X18,X21,#3
        0xd100_0f26,    // SUB X6,X25,#3
        0x3940_0cd3,    // LDRB W19,[X6,#3]
    ];
    let start = GuestAddress(0x1000045d4);
    let compile = |words: &[u32], start, target| {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let profile = BlockProfile::new(Features::SYSTEM_MODE);
        CompilationPlan::new(&source, start, &Options::new(profile, target))
            .unwrap()
            .compile()
            .unwrap()
    };
    let target = TargetCpu::Baseline;
    let dit = target.with_data_independent_timing();
    let grouped = compile(&words, start, target);
    let fallback = compile(&words, start, dit);
    assert_eq!(grouped.native.source_map.len(), words.len());
    for (index, (pc, _)) in grouped.native.source_map.iter().enumerate() {
        assert_eq!(pc.0, start.0 + index as u64 * 4);
    }
    assert!(
        grouped
            .native
            .source_map
            .windows(2)
            .all(|rows| rows[0].1 < rows[1].1)
    );
    assert!(grouped.native.source_map[4].1 < fallback.native.source_map[4].1);
    let access = grouped
        .fault_recovery
        .iter()
        .find(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
        .unwrap();
    assert_eq!(
        access.retirement.instruction_pc(),
        grouped.native.source_map[4].0
    );
    assert_eq!(access.retirement.retired_before(), 4);
    assert!(access.start >= grouped.native.source_map[4].1);
    assert!(access.bindings.is_empty());
    let mut scratch = Code::default();
    let load_x6 = super::super::register_load(&mut scratch, Register::X(6), true).unwrap();
    assert!(!grouped.native.x86_64_code[grouped.native.source_map[4].1..].starts_with(load_x6));

    // A shortened prefix, or an independent entry at its second row,
    // has fewer than two beneficial values and retains its direct body.
    for (input, pc) in [
        (&words[..2], start),
        (&words[1..4], GuestAddress(start.0 + 4)),
    ] {
        let compiled = compile(input, pc, target);
        assert_eq!(
            compiled.native.x86_64_code,
            compile(input, pc, dit).native.x86_64_code
        );
    }

    // Execute an X/W mix through the real pinned ABI with stale high input
    // bits, unchanged flags and unmodified permanently pinned values.
    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    {
        use crate::x86_64::asm::vector_extensions::execution::Native;
        let mut mixed = [words[0] & !(1 << 31), words[1], words[2], words[3]];
        let native = compile(&mixed, start, target).native;
        let original = compile(&mixed, start, dit).native;
        assert!(native.x86_64_code.len() < original.x86_64_code.len());
        let body = Native::new(&super::super::pinned::entered(&native.x86_64_code));
        let mut initial = crate::GuestState {
            nzcv: 0x9000_0000,
            sp: 0x1234,
            ..Default::default()
        };
        for (index, register) in initial.x.iter_mut().enumerate() {
            *register = 0xfedc_ba98_7654_3210u64.wrapping_mul(index as u64 + 1);
        }
        let mut expected = initial.clone();
        expected.x[21] = initial.x[22].wrapping_add(initial.x[6]) as u32 as u64;
        expected.x[25] = initial.x[18].wrapping_add(initial.x[6]);
        expected.x[18] = expected.x[21].wrapping_sub(3);
        expected.x[6] = expected.x[25].wrapping_sub(3);
        body.run(
            &mut initial,
            &mut crate::context::ExecutionContext::default(),
        );
        assert_eq!(initial, expected);

        // A flag-setting row must split the proposal instead of exposing
        // an incompletely settled value to another recipe.
        mixed[2] |= 1 << 29;
        let split = compile(&mixed, start, target).native;
        assert_eq!(split.source_map.len(), mixed.len());
        assert_eq!(split.source_map[2], original.source_map[2]);
    }
}

#[test]
fn bitfields_and_pc_relative_addresses_feed_the_next_frame_reader() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan, Features, RecoverySiteKind},
    };
    let compile = |words: &[u32], pc, profile, target| {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        CompilationPlan::new(&source, pc, &Options::new(profile, target))
            .unwrap()
            .compile()
            .unwrap()
    };
    let target = TargetCpu::Baseline;
    let ordinary = BlockProfile::ORDINARY;
    let system = BlockProfile::new(Features::SYSTEM_MODE);
    let lz4 = GuestAddress(0x10000800c);
    let lz4_words = [0xd372_fce7, 0x927e_2cf7]; // LSR X7,X7,#50; AND X23,X7,#0x3ffc
    let mut scratch = Code::default();
    let load_x7 = super::super::register_load(&mut scratch, Register::X(7), false).unwrap();
    let grouped = compile(&lz4_words, lz4, ordinary, target);
    let second = grouped.native.source_map[1];
    assert_eq!(second.0, GuestAddress(lz4.0 + 4));
    assert!(!grouped.native.x86_64_code[second.1..].starts_with(load_x7));
    let independent = compile(&lz4_words[1..], second.0, ordinary, target);
    assert!(independent.native.x86_64_code.starts_with(load_x7));
    let dit = compile(
        &lz4_words,
        lz4,
        ordinary,
        target.with_data_independent_timing(),
    );
    assert!(dit.native.x86_64_code[dit.native.source_map[1].1..].starts_with(load_x7));

    let sqlite = GuestAddress(0x10000fee0);
    let sqlite_words = [0x106f_9c89, 0x7868_7929]; // ADR X9,...; LDRH W9,[X9,X8,LSL #1]
    for profile in [ordinary, system] {
        let load_x9 = super::super::register_load(
            &mut scratch,
            Register::X(9),
            profile.has(Features::SYSTEM_MODE),
        )
        .unwrap();
        let grouped = compile(&sqlite_words, sqlite, profile, target);
        let second = grouped.native.source_map[1];
        assert_eq!(second.0, GuestAddress(sqlite.0 + 4));
        assert!(!grouped.native.x86_64_code[second.1..].starts_with(load_x9));
        let independent = compile(&sqlite_words[1..], second.0, profile, target);
        assert!(independent.native.x86_64_code.starts_with(load_x9));
        if profile.has(Features::SYSTEM_MODE) {
            let access = grouped
                .fault_recovery
                .iter()
                .find(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
                .unwrap();
            assert_eq!(access.retirement.instruction_pc(), second.0);
            assert_eq!(access.retirement.retired_before(), 1);
            assert!(access.start >= second.1);
        }
    }
}

#[test]
fn vector_store_reuses_load_across_integer_rows_and_keeps_recovery() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan, Features, RecoverySiteKind},
    };
    let words = [
        0x3dc0_0280u32, // LDR Q0,[X20]
        0x8b02_0288,    // ADD X8,X20,X2
        0x9240_0ce7,    // AND X7,X7,#0xf
        0x8b02_0133,    // ADD X19,X9,X2
        0x7100_3cff,    // CMP W7,#15
        0x3d80_0120,    // STR Q0,[X9]
        0x7840_2514,    // LDRH W20,[X8],#2
        0xcb14_0262,    // SUB X2,X19,X20
        0x5400_00a0,    // B.EQ
    ];
    let start = GuestAddress(0x100008e04);
    let store = GuestAddress(start.0 + 20);
    let compile = |words: &[u32], pc, profile, target| {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        CompilationPlan::new(&source, pc, &Options::new(profile, target))
            .unwrap()
            .compile()
            .unwrap()
    };
    let reloads = |block: &NativeBlock, index: usize| {
        let offset = block.source_map[index].1;
        let end = block
            .source_map
            .get(index + 1)
            .map_or(block.x86_64_code.len(), |row| row.1);
        block.x86_64_code[offset..end]
            .windows(8)
            .any(|bytes| bytes == [0xf3, 0x0f, 0x6f, 0x87, 8, 1, 0, 0])
    };
    let baseline = TargetCpu::Baseline;
    for profile in [
        BlockProfile::ORDINARY,
        BlockProfile::new(Features::SYSTEM_MODE),
    ] {
        let grouped = compile(&words, start, profile, baseline);
        assert_eq!(grouped.native.source_map.len(), words.len());
        assert_eq!(grouped.native.source_map[5].0, store);
        assert!(!reloads(&grouped.native, 5));

        let dit = compile(
            &words,
            start,
            profile,
            baseline.with_data_independent_timing(),
        );
        assert!(reloads(&dit.native, 5));
        let standalone = compile(&words[5..], store, profile, baseline);
        assert!(reloads(&standalone.native, 0));
        if profile.has(Features::SYSTEM_MODE) {
            let access = grouped
                .fault_recovery
                .iter()
                .find(|entry| {
                    entry.site.kind() == RecoverySiteKind::GuestAccess
                        && entry.retirement.instruction_pc() == store
                })
                .unwrap();
            assert_eq!(access.retirement.retired_before(), 5);
            assert!(access.start >= grouped.native.source_map[5].1);
            assert!(access.end <= grouped.native.source_map[6].1);
        }
    }

    // A vector writer between the original load and store replaces XMM0.
    let clobbered = compile(
        &[words[0], 0x4f00_e401, words[2], words[5]],
        start,
        BlockProfile::ORDINARY,
        baseline,
    );
    assert!(reloads(&clobbered.native, 3));
}

#[test]
fn reverse_dword_runs_share_one_mask_with_independent_source_rows() {
    use crate::{Lifter, TargetCpu, aarch64::Decoder};

    let entry = GuestAddress(0x259f5c);
    let end = GuestAddress(entry.0 + 16);
    let instructions: Vec<_> = [0x6e20_0884, 0x6e20_08a5, 0x6e20_08c6, 0x6e20_08e7]
        .into_iter()
        .enumerate()
        .map(|(index, word)| {
            Decoder
                .lift(GuestAddress(entry.0 + index as u64 * 4), word)
                .unwrap()
        })
        .collect();
    let ordinary =
        |source: &[Instruction], target| emit_ordinary_for_target(source, None, end, target);
    let grouped = ordinary(&instructions, TargetCpu::Ssse3);
    let baseline = ordinary(&instructions, TargetCpu::Baseline);
    let dit = ordinary(
        &instructions,
        TargetCpu::Ssse3.with_data_independent_timing(),
    );
    let shuffles = |code: &NativeBlock| {
        code.x86_64_code
            .windows(3)
            .filter(|word| *word == [0x0f, 0x38, 0x00])
            .count()
    };
    assert_eq!(shuffles(&grouped), 4);
    assert_eq!(shuffles(&baseline), 0);
    assert_eq!(shuffles(&dit), 8);
    assert!(grouped.x86_64_code.len() < baseline.x86_64_code.len());
    assert!(baseline.x86_64_code.len() < dit.x86_64_code.len());
    for code in [&grouped, &baseline, &dit] {
        assert_eq!(code.source_map.len(), 4);
        assert!(code.source_map.windows(2).all(|rows| rows[0].1 < rows[1].1));
        for (row, instruction) in code.source_map.iter().zip(&instructions) {
            assert_eq!(row.0, instruction.pc);
        }
    }
    let singleton = ordinary(&instructions[1..2], TargetCpu::Ssse3);
    assert_eq!(singleton.source_map, [(instructions[1].pc, 0)]);
    assert_eq!(shuffles(&singleton), 0);
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn reverse_dword_runs_commit_aliased_vectors_in_guest_order() {
    use crate::{GuestState, Lifter, TargetCpu, aarch64::Decoder, x86_64::native};

    let entry = GuestAddress(0x1000);
    let end = GuestAddress(entry.0 + 16);
    let operations = [(4, 4), (4, 4), (4, 5), (6, 4)];
    let instructions: Vec<_> = operations
        .iter()
        .enumerate()
        .map(|(index, &(destination, source))| {
            Decoder
                .lift(
                    GuestAddress(entry.0 + index as u64 * 4),
                    0x6e20_0800 | (source << 5) | destination,
                )
                .unwrap()
        })
        .collect();
    for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
        if target.supports(TargetCpu::Ssse3) && !std::arch::is_x86_feature_detected!("ssse3") {
            continue;
        }
        let code = emit_ordinary_for_target(&instructions, None, end, target);
        let mut state = GuestState {
            v: core::array::from_fn(|i| {
                let value = (i as u64).wrapping_mul(0x0e7c_61ab_da86_a105);
                [value, value.rotate_left(29)]
            }),
            nzcv: 0xb000_0000,
            fpsr: 0x800_0010,
            ..GuestState::default()
        };
        let mut expected = state.clone();
        for (destination, source) in operations {
            expected.v[destination as usize] = expected.v[source as usize].map(|half| {
                u64::from((half as u32).swap_bytes())
                    | (u64::from(((half >> 32) as u32).swap_bytes()) << 32)
            });
        }
        assert_eq!(native::run(&code.x86_64_code, &mut state), end.0);
        assert_eq!(state, expected);
    }
}

#[test]
fn hosted_result_chain_keeps_both_zlib_compare_inputs() {
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, CompilationPlan},
    };

    let compile = |words: &[u32], entry, target| {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        CompilationPlan::new(
            &source,
            GuestAddress(entry),
            &Options::new(BlockProfile::ORDINARY, target),
        )
        .unwrap()
        .compile()
        .unwrap()
        .native
    };
    let entry = 0x100003df0;
    // MOV W5,W1; ADD X4,X8,X5; ADD X6,X4,W12,SXTW;
    // LDRB W7,[X6]; CMP W7,W3; B.NE.
    let address = [
        0x2a01_03e5,
        0x8b05_0104,
        0x8b2c_c086,
        0x3940_00c7,
        0x6b03_00ff,
        0x5400_0ea1,
    ];
    let native = compile(&address, entry, TargetCpu::Baseline);
    let bytes = &native.x86_64_code;
    assert_eq!(native.source_map.len(), address.len());
    for (index, (pc, _)) in native.source_map.iter().enumerate() {
        assert_eq!(*pc, GuestAddress(entry + index as u64 * 4));
    }
    assert!(bytes[native.source_map[1].1..].starts_with(&[0x48, 0x03, 0x87, 0x40]));
    assert!(bytes[native.source_map[3].1..].starts_with(&[0x0f, 0xb6, 0x00]));
    assert!(bytes[native.source_map[4].1..].starts_with(&[0x3b, 0x87, 0x18]));
    let compare = compile(&address[4..], entry + 16, TargetCpu::Baseline);
    assert!(compare.x86_64_code.starts_with(&[0x48, 0x8b, 0x87, 0x38]));

    // AND W1,W1,W14; LDRH W1,[X9,W1,UXTW #1]; CMP W13,W1; B.HS.
    let indexed = [0x0a0e_0021, 0x7861_5921, 0x6b01_01bf, 0x5400_0062];
    let entry = 0x100003fd8;
    let native = compile(&indexed, entry, TargetCpu::Baseline);
    let dit = compile(
        &indexed,
        entry,
        TargetCpu::Baseline.with_data_independent_timing(),
    );
    assert_eq!(native.source_map.len(), indexed.len());
    let held_compare = [0x39, 0x87, 0x68]; // CMP [frame+X13],EAX.
    assert!(native.x86_64_code[native.source_map[2].1..].starts_with(&held_compare));
    assert!(!dit.x86_64_code[dit.source_map[2].1..].starts_with(&held_compare));
}

#[test]
fn system_address_pair_keeps_source_rows_and_the_following_fault_boundary() {
    use crate::{Lifter, TargetCpu, aarch64::Decoder, block::RecoverySiteKind};

    let entry = GuestAddress(0x1030);
    let add_pc = GuestAddress(entry.0 + 4);
    let load_pc = GuestAddress(entry.0 + 8);
    let fallthrough = GuestAddress(entry.0 + 12);
    let checks = super::super::MemoryChecks::DEFAULT;
    for (register, opcode) in [(0, [0x49, 0xbf]), (20, [0x48, 0xb8])] {
        let instructions = [
            Decoder.lift(entry, 0xb000_0000 | register).unwrap(),
            Decoder
                .lift(add_pc, 0x9140_2000 | register << 5 | register)
                .unwrap(),
            Decoder.lift(load_pc, 0xf940_0002 | register << 5).unwrap(),
        ]; // adrp; add #8, lsl #12; ldr x2,[register]
        let system = |input: &[Instruction], next, target| {
            emit_system_mode(
                input,
                None,
                next,
                target,
                checks,
                super::super::NativeSystem::NONE,
            )
        };
        let (native, recovery) = system(&instructions, fallthrough, TargetCpu::Baseline);
        let (dit, _) = system(
            &instructions,
            fallthrough,
            TargetCpu::Baseline.with_data_independent_timing(),
        );
        let expected_end = if register == 0 { 11 } else { 18 };
        assert_eq!(
            native.source_map,
            [(entry, 0), (add_pc, 1), (load_pc, expected_end)]
        );
        assert_eq!(native.x86_64_code[0], 0x90);
        assert_eq!(native.x86_64_code[1..3], opcode);
        assert_eq!(native.x86_64_code[3..11], 0xa000_u64.to_le_bytes());
        assert!(dit.source_map[1].1 > 1);
        assert!(native.x86_64_code.len() < dit.x86_64_code.len());
        assert!(!recovery.is_empty());
        assert!(recovery.iter().all(|row| row.start >= expected_end));
        let access = recovery
            .iter()
            .find(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
            .unwrap();
        assert_eq!(access.retirement.instruction_pc(), load_pc);
        assert_eq!(access.retirement.retired_before(), 2);

        let (truncated, _) = system(&instructions[..1], add_pc, TargetCpu::Baseline);
        assert_eq!(truncated.source_map, [(entry, 0)]);
        assert_eq!(truncated.x86_64_code[2..10], 0x2000_u64.to_le_bytes());
        let (standalone, _) = system(&instructions[1..2], load_pc, TargetCpu::Baseline);
        assert_eq!(standalone.source_map, [(add_pc, 0)]);
        assert_ne!(standalone.x86_64_code[0], 0x90);
    }
}

#[test]
fn system_address_pair_requires_an_adjacent_flagless_x64_overwrite() {
    use crate::{Lifter, TargetCpu, aarch64::Decoder};

    let entry = GuestAddress(0x1000);
    let first = Decoder.lift(entry, 0xb000_0000).unwrap();
    for (pc, word) in [
        (0x1008, 0x9100_2000), // Gap.
        (0x1004, 0x1100_2000), // W destination.
        (0x1004, 0xb100_2000), // Flag-setting ADD.
        (0x1004, 0xd100_2000), // SUB.
        (0x1004, 0x9100_2001), // Different destination.
        (0x1004, 0x9100_2020), // Different source.
    ] {
        let second = Decoder.lift(GuestAddress(pc), word).unwrap();
        let (native, _) = emit_system_mode(
            &[first.clone(), second],
            None,
            GuestAddress(pc + 4),
            TargetCpu::Baseline,
            super::super::MemoryChecks::DEFAULT,
            super::super::NativeSystem::NONE,
        );
        assert_eq!(native.source_map, [(entry, 0), (GuestAddress(pc), 10)]);
        assert_eq!(native.x86_64_code[2..10], 0x2000_u64.to_le_bytes());
    }
}

/// A reload removed before a check takes the check's jump along.
#[test]
fn removed_instructions_move_the_check_failures_after_them() {
    use super::super::asm::{Cond, Gpr, Mem, Size};
    let mut code = Code::new();
    code.check_failure(Cond::E);
    let start = code.len();
    code.asm()
        .mov_load(Size::Qword, Gpr::Rax, Mem::base(Gpr::Rdi, 0));
    let end = code.len();
    code.check_failure(Cond::Ne);
    code.remove_instruction(start..end);
    code.place_failures();
    assert_eq!(
        code[..],
        [
            0x0f, 0x84, 6, 0, 0, 0, 0x0f, 0x85, 2, 0, 0, 0, 0x0f, 0x0b, 0x0f, 0x0b
        ],
    );
}

/// A conditional exit's branch skips its fallthrough exit, and each of
/// its instructions counts.
#[test]
fn conditional_exits_branch_over_the_fallthrough_exit() {
    let mut code = Code::new();
    conditional_exit(
        &mut code,
        Some(Cond::Ne),
        GuestAddress(0x2000),
        GuestAddress(0x1004),
    );
    let fallthrough = super::super::chain::direct_exit(GuestAddress(0x1004), ExitKind::Fallthrough);
    let taken = super::super::chain::direct_exit(GuestAddress(0x2000), ExitKind::Direct);
    assert_eq!(code[..6], [0x0f, 0x85, 20, 0, 0, 0]);
    assert_eq!(code[6..26], fallthrough);
    assert_eq!(code[26..], taken);
    assert_eq!(code.instructions(), 15);
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn grouped_sha256_schedule_removes_only_the_intermediate_frame_round_trip() {
    use crate::{
        GuestState, Lifter, TargetCpu,
        aarch64::Decoder,
        x86_64::{native, pinned},
    };

    let pc = GuestAddress(0x1000);
    let words = [
        0x5e28_28a4_u32,
        0x4ea0_1c02,
        0x5e10_4020,
        0x5e10_5041,
        0x5e07_60c4,
    ];
    let instructions: Vec<_> = words
        .into_iter()
        .enumerate()
        .map(|(i, word)| {
            Decoder
                .lift(GuestAddress(pc.0 + i as u64 * 4), word)
                .unwrap()
        })
        .collect();
    let checks = super::super::MemoryChecks::DEFAULT;
    for target in [
        TargetCpu::Baseline,
        TargetCpu::Ssse3,
        TargetCpu::Sha,
        TargetCpu::Ssse3.with_sha(),
    ] {
        let system = |input: &[Instruction]| {
            let pc = GuestAddress(input.last().unwrap().pc.0 + 4);
            let terminal = (
                pc,
                Terminator::Register {
                    source: Register::X(30),
                    kind: ExitKind::Return,
                },
            );
            let next = GuestAddress(pc.0 + 4);
            let (block, faults) = emit_system_mode(
                input,
                Some(&terminal),
                next,
                target,
                checks,
                super::super::NativeSystem::NONE,
            );
            assert!(faults.is_empty());
            (block, terminal, next)
        };
        let body_bytes = |input: &[Instruction]| system(input).0.source_map.last().unwrap().1;
        let separate_bytes = body_bytes(&instructions[..1])
            + body_bytes(&instructions[1..4])
            + body_bytes(&instructions[4..]);
        assert_eq!(body_bytes(&instructions) + 16, separate_bytes);

        if (target.supports(TargetCpu::Sha) && !std::arch::is_x86_feature_detected!("sha"))
            || (target.supports(TargetCpu::Ssse3) && !std::arch::is_x86_feature_detected!("ssse3"))
        {
            continue;
        }
        for input in [
            &instructions[..],
            &instructions[..4],
            &instructions[1..],
            &instructions[4..],
        ] {
            let (grouped, terminal, next) = system(input);
            let plain = emit_for_target(input, Some(&terminal), next, target, checks);
            let rows =
                |code: &NativeBlock| code.source_map.iter().map(|row| row.0).collect::<Vec<_>>();
            assert_eq!(rows(&grouped), rows(&plain));
            assert!(
                grouped
                    .source_map
                    .windows(2)
                    .all(|pair| pair[0].1 < pair[1].1)
            );
            let entered = pinned::entered(&grouped.x86_64_code);
            let mut state = GuestState {
                x: core::array::from_fn(|index| u64::MAX ^ index as u64),
                v: core::array::from_fn(|index| {
                    let word = (index as u64).wrapping_mul(0x1234_5678_8765_4321);
                    [word, !word.rotate_left(11)]
                }),
                nzcv: 0xa000_0000,
                fpsr: 0x800_0000,
                ..GuestState::default()
            };
            let mut expected = state.clone();
            let exit = native::run(&plain.x86_64_code, &mut expected);
            assert_eq!(native::run(&entered, &mut state), exit);
            assert_eq!(state, expected);
        }
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn grouped_sha256_rounds_preserve_three_rows_and_both_state_halves() {
    use crate::{
        GuestState, Lifter, TargetCpu,
        aarch64::Decoder,
        x86_64::{native, pinned},
    };

    let pc = GuestAddress(0x1000);
    let checks = super::super::MemoryChecks::DEFAULT;
    for (a, b, temporary, wk) in [(0, 1, 2, 16), (31, 30, 29, 29), (6, 7, 8, 7)] {
        let instructions: Vec<_> = [
            0x4ea0_1c00 | temporary | a << 5 | a << 16,
            0x5e00_4000 | a | b << 5 | wk << 16,
            0x5e00_5000 | b | temporary << 5 | wk << 16,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, word)| {
            Decoder
                .lift(GuestAddress(pc.0 + index as u64 * 4), word)
                .unwrap()
        })
        .collect();
        for target in [TargetCpu::Baseline, TargetCpu::Sha] {
            for (input, separate_hashes) in [
                (&instructions[..], 2),
                (&instructions[..2], 1),
                (&instructions[1..], 2),
                (&instructions[2..], 1),
            ] {
                let return_pc = GuestAddress(input.last().unwrap().pc.0 + 4);
                let terminal = (
                    return_pc,
                    Terminator::Register {
                        source: Register::X(30),
                        kind: ExitKind::Return,
                    },
                );
                let next = GuestAddress(return_pc.0 + 4);
                let (grouped, faults) = emit_system_mode(
                    input,
                    Some(&terminal),
                    next,
                    target,
                    checks,
                    super::super::NativeSystem::NONE,
                );
                let plain = emit_for_target(input, Some(&terminal), next, target, checks);
                let rows = |block: &NativeBlock| {
                    block.source_map.iter().map(|row| row.0).collect::<Vec<_>>()
                };
                assert_eq!(rows(&grouped), rows(&plain));
                assert!(
                    grouped
                        .source_map
                        .windows(2)
                        .all(|rows| rows[0].1 < rows[1].1)
                );
                assert!(faults.is_empty());
                let rounds = |code: &[u8]| {
                    code.windows(3)
                        .filter(|bytes| *bytes == [0x0f, 0x38, 0xcb])
                        .count()
                };
                if target.supports(TargetCpu::Sha) {
                    let grouped_rounds = if input.len() == 3 {
                        2
                    } else {
                        2 * separate_hashes
                    };
                    assert_eq!(rounds(&grouped.x86_64_code), grouped_rounds);
                    assert_eq!(rounds(&plain.x86_64_code), 2 * separate_hashes);
                } else {
                    assert_eq!(rounds(&grouped.x86_64_code), 0);
                    assert_eq!(rounds(&plain.x86_64_code), 0);
                }
                if input.len() == 3 {
                    assert!(grouped.source_map[3].1 < plain.source_map[3].1);
                }
                if target.supports(TargetCpu::Sha) && !std::arch::is_x86_feature_detected!("sha") {
                    continue;
                }
                let entered = pinned::entered(&grouped.x86_64_code);
                for seed in [0, 1, u64::MAX] {
                    let mut state = GuestState {
                        x: core::array::from_fn(|index| seed ^ index as u64),
                        v: core::array::from_fn(|index| {
                            let x = (index as u64).wrapping_mul(0x1234_5678_8765_4321);
                            [x ^ seed, x.rotate_left(17) ^ !seed]
                        }),
                        nzcv: 0xa000_0000,
                        fpsr: 0x800_0000,
                        ..GuestState::default()
                    };
                    let mut expected = state.clone();
                    let exit = native::run(&plain.x86_64_code, &mut expected);
                    assert_eq!(native::run(&entered, &mut state), exit);
                    assert_eq!(state, expected);
                }
            }
        }
    }
}

#[test]
fn hosted_trailing_zero_pair_preserves_instruction_boundaries() {
    use crate::{Lifter, TargetCpu, aarch64::Decoder};

    let entry = GuestAddress(0x1000);
    for words in [[0xdac0_0020_u32, 0xdac0_1000], [0x5ac0_0020, 0x5ac0_1000]] {
        let instructions = [
            Decoder.lift(entry, words[0]).unwrap(),
            Decoder.lift(GuestAddress(entry.0 + 4), words[1]).unwrap(),
        ];
        let end = GuestAddress(entry.0 + 8);
        for target in [TargetCpu::Baseline, TargetCpu::Baseline.with_bmi1()] {
            let ordinary = emit_ordinary_for_target(&instructions, None, end, target);
            let separate = emit_for_target(
                &instructions,
                None,
                end,
                target,
                super::super::MemoryChecks::DEFAULT,
            );
            assert_eq!(ordinary.source_map, [(entry, 0), (instructions[1].pc, 1)]);
            assert_eq!(ordinary.x86_64_code[0], 0x90);
            assert!(ordinary.x86_64_code.len() < separate.x86_64_code.len());
            let tzcnt = if words[0] >> 31 == 1 {
                &[0xf3, 0x48, 0x0f, 0xbc][..]
            } else {
                &[0xf3, 0x0f, 0xbc][..]
            };
            assert_eq!(
                ordinary
                    .x86_64_code
                    .windows(tzcnt.len())
                    .any(|window| window == tzcnt),
                target.supports(TargetCpu::Bmi1)
            );
        }
        let dit = TargetCpu::Baseline.with_data_independent_timing();
        assert_eq!(
            emit_ordinary_for_target(&instructions, None, end, dit).x86_64_code,
            emit_for_target(
                &instructions,
                None,
                end,
                dit,
                super::super::MemoryChecks::DEFAULT,
            )
            .x86_64_code
        );
        let (system, _) = emit_system_mode(
            &instructions,
            None,
            end,
            TargetCpu::Baseline,
            super::super::MemoryChecks::DEFAULT,
            super::super::NativeSystem::NONE,
        );
        assert!(system.source_map[1].1 > 1);
    }

    // A different width, source or destination leaves the original pair.
    let first = Decoder.lift(entry, 0xdac0_0020).unwrap();
    for word in [0x5ac0_1000, 0xdac0_1020, 0xdac0_1001] {
        let second = Decoder.lift(GuestAddress(entry.0 + 4), word).unwrap();
        let instructions = [first.clone(), second];
        assert_eq!(
            emit_ordinary_for_target(
                &instructions,
                None,
                GuestAddress(entry.0 + 8),
                TargetCpu::Baseline
            )
            .x86_64_code,
            emit(&instructions, None, GuestAddress(entry.0 + 8)).x86_64_code
        );
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn hosted_trailing_zero_pair_matches_both_scalar_widths_and_aliases() {
    use crate::{GuestState, Lifter, TargetCpu, aarch64::Decoder, x86_64::native};

    let entry = GuestAddress(0x1000);
    let end = GuestAddress(entry.0 + 8);
    for (reverse, count) in [(0xdac0_0000, 0xdac0_1000), (0x5ac0_0000, 0x5ac0_1000)] {
        for source in [0, 1, 31] {
            let instructions = [
                Decoder.lift(entry, reverse | source << 5).unwrap(),
                Decoder.lift(GuestAddress(entry.0 + 4), count).unwrap(),
            ];
            for target in [TargetCpu::Baseline, TargetCpu::Baseline.with_bmi1()] {
                if !TargetCpu::detect().supports(target) {
                    continue;
                }
                let block = emit_ordinary_for_target(&instructions, None, end, target);
                assert_eq!(block.source_map[1].1, 1);
                for input in [0, 1, 0x1234_5678_0000_0000, 1 << 31, 1 << 63, u64::MAX] {
                    let mut state = GuestState::default();
                    state.x[0] = input;
                    state.x[1] = input;
                    state.nzcv = 0xa000_0000;
                    let mut expected = state.clone();
                    let input = if source == 31 { 0 } else { input };
                    expected.x[0] = u64::from(if reverse >> 31 == 1 {
                        input.trailing_zeros()
                    } else {
                        (input as u32).trailing_zeros()
                    });
                    assert_eq!(native::run(&block.x86_64_code, &mut state), end.0);
                    assert_eq!(state, expected);
                }
            }
        }
    }
}

/// add x10, x10, #4; cmp x10, #0x600; b.ne: the CMP takes X10 from
/// RAX where the ADD stored it, and the branch tests the NZCV word the
/// CMP left in EAX, so neither reloads from the frame.
#[test]
fn values_left_in_rax_are_not_reloaded() {
    use crate::{Lifter, aarch64::Decoder};
    const LOAD_X10: [u8; 7] = [0x48, 0x8b, 0x87, 0x50, 0, 0, 0];
    const LOAD_NZCV: [u8; 6] = [0x8b, 0x87, 0, 1, 0, 0];
    let pc = GuestAddress(0x1000);
    let instructions: Vec<_> = [0x9100_114a_u32, 0xf118_015f]
        .into_iter()
        .enumerate()
        .map(|(index, word)| {
            Decoder
                .lift(GuestAddress(pc.0 + 4 * index as u64), word)
                .unwrap()
        })
        .collect();
    let branch = GuestAddress(pc.0 + 8);
    let terminal = (
        branch,
        Terminator::Branch(Operation::BranchCondition {
            target: pc,
            condition: 1,
        }),
    );
    let native = emit(&instructions, Some(&terminal), GuestAddress(branch.0 + 4));
    let code = &native.x86_64_code;
    let count = |pattern: &[u8]| {
        code.windows(pattern.len())
            .filter(|w| *w == pattern)
            .count()
    };
    assert_eq!(count(&LOAD_X10), 1);
    assert_eq!(count(&LOAD_NZCV), 0);
    let compare = native.source_map[1].1;
    assert_eq!(&code[compare..compare + 3], &[0x48, 0x81, 0xf8]); // CMP RAX,imm32.
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn pinned_compare_reuses_the_preceding_unshifted_right_operand() {
    use crate::{GuestState, Lifter, TargetCpu, aarch64::Decoder, x86_64::native};

    let pc = GuestAddress(0x1000);
    let compare = GuestAddress(pc.0 + 4);
    let branch = GuestAddress(pc.0 + 8);
    let next = GuestAddress(pc.0 + 12);
    let terminal = (
        branch,
        Terminator::Branch(Operation::BranchCondition {
            target: pc,
            condition: 3, // LO: borrow.
        }),
    );
    for (sf, mask) in [(0, u64::from(u32::MAX)), (1 << 31, u64::MAX)] {
        for left in [1, 9] {
            let instructions = [
                Decoder.lift(pc, sf | 0x1100_0694).unwrap(), // ADD R20,R20,#1
                Decoder.lift(compare, sf | 0x6b14_001f | left << 5).unwrap(), // CMP Rleft,R20
            ];
            let system = |input: &[Instruction], target| {
                emit_system_mode(
                    input,
                    Some(&terminal),
                    next,
                    target,
                    super::super::MemoryChecks::DEFAULT,
                    super::super::NativeSystem::NONE,
                )
                .0
            };
            let native = system(&instructions, TargetCpu::Baseline);
            let dit = system(
                &instructions,
                TargetCpu::Baseline.with_data_independent_timing(),
            );
            let standalone = system(&instructions[1..], TargetCpu::Baseline);
            let code = &native.x86_64_code;
            let at = native.source_map[1].1;
            let opcode = if sf == 0 { at } else { at + 1 };
            let cmp = if left == 1 {
                &[0x39, 0xc5][..] // CMP EBP/RBP,EAX/RAX.
            } else {
                &[0x39, 0x47, 72][..] // CMP [frame+X9],EAX/RAX.
            };
            assert_eq!(&code[opcode..opcode + cmp.len()], cmp);
            assert!(
                !dit.x86_64_code[dit.source_map[1].1..].starts_with(&code[at..opcode + cmp.len()])
            );
            assert!(
                !standalone
                    .x86_64_code
                    .starts_with(&code[at..opcode + cmp.len()])
            );
            assert_eq!(
                native
                    .source_map
                    .iter()
                    .map(|row| row.0)
                    .collect::<Vec<_>>(),
                [pc, compare, branch]
            );

            let entered = super::super::pinned::entered(code);
            let sign = (mask >> 1) + 1;
            for (a, before) in [
                (1, 0),
                (0, 0),
                (mask, 0),
                (sign - 1, mask - 1),
                (0, sign - 1),
            ] {
                let mut state = GuestState::default();
                state.x[left as usize] = a;
                state.x[20] = before | !mask;
                let mut expected = state.clone();
                let b = before.wrapping_add(1) & mask;
                let difference = a.wrapping_sub(b) & mask;
                expected.x[20] = b;
                expected.nzcv = (u32::from(difference & sign != 0) << 31)
                    | (u32::from(difference == 0) << 30)
                    | (u32::from(a >= b) << 29)
                    | (u32::from((a ^ b) & (a ^ difference) & sign != 0) << 28);
                assert_eq!(
                    native::run(&entered, &mut state),
                    if a < b { pc.0 } else { next.0 }
                );
                assert_eq!(state, expected);
            }
        }
    }
}

#[test]
fn ordinary_integer_operations_read_frame_operands_directly() {
    use crate::{Lifter, aarch64::Decoder};
    let pc = GuestAddress(0x1000);
    // MOV W5,W1; AND W1,W1,W14; CMP W13,W1; CMP W13,#7; ADD X6,X4,W12,SXTW.
    let instructions: Vec<_> = [
        0x2a01_03e5_u32,
        0x0a0e_0021,
        0x6b01_01bf,
        0x7100_1dbf,
        0x8b2c_c086,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, word)| {
        Decoder
            .lift(GuestAddress(pc.0 + 4 * index as u64), word)
            .unwrap()
    })
    .collect();
    let native = emit(&instructions, None, GuestAddress(0x1014));
    let code = &native.x86_64_code;
    let map = &native.source_map;
    assert_eq!(
        &code[..map[1].1],
        &[0x8b, 0x87, 8, 0, 0, 0, 0x48, 0x89, 0x87, 40, 0, 0, 0],
    ); // MOV EAX,[RDI+8]; MOV [RDI+40],RAX.
    assert_eq!(
        &code[map[1].1 + 7..map[1].1 + 13],
        &[0x23, 0x87, 112, 0, 0, 0]
    );
    // CMP [RDI+104],EAX using the preceding AND result.
    assert_eq!(&code[map[2].1..map[2].1 + 6], &[0x39, 0x87, 104, 0, 0, 0]);
    let standalone = emit(&instructions[2..3], None, GuestAddress(0x100c));
    // CMP EAX,[RDI+8] without a producer.
    assert_eq!(&standalone.x86_64_code[7..13], &[0x3b, 0x87, 8, 0, 0, 0]);
    assert_eq!(
        &code[map[3].1..map[3].1 + 7],
        &[0x83, 0xbf, 104, 0, 0, 0, 7]
    );
    assert_eq!(
        &code[map[4].1 + 7..map[4].1 + 14],
        &[0x48, 0x63, 0x8f, 96, 0, 0, 0],
    ); // MOVSXD RCX,[RDI+96].
}

#[test]
fn pinned_scalar_loads_forward_through_the_block() {
    use crate::{Lifter, aarch64::Decoder, block::RecoverySiteKind};
    const FRAME_LOAD: [u8; 4] = [0x48, 0x8b, 0x47, 0x50];
    let pc = GuestAddress(0x1000);
    let second = GuestAddress(0x1004);
    let branch = GuestAddress(0x1008);
    // LDR X10,[X10]; LDR X10,[X10,X2]; CBZ X10,entry.
    let instructions = [
        Decoder.lift(pc, 0xf940_014a).unwrap(),
        Decoder.lift(second, 0xf862_694a).unwrap(),
    ];
    let terminal = (
        branch,
        Terminator::Branch(Operation::BranchZero {
            source: Register::X(10),
            width: crate::aarch64::Width::X64,
            nonzero: false,
            target: pc,
        }),
    );
    let (native, recovery) = emit_system_mode(
        &instructions,
        Some(&terminal),
        GuestAddress(0x100c),
        crate::TargetCpu::Baseline,
        super::super::MemoryChecks::DEFAULT,
        super::super::NativeSystem::NONE,
    );
    let code = &native.x86_64_code;
    assert_eq!(native.source_map.len(), 3);
    let [(pc1, at1), (pc2, at2), (pc3, at3)] = native.source_map.as_slice() else {
        unreachable!()
    };
    assert_eq!([*pc1, *pc2, *pc3], [pc, second, branch]);
    assert!(at1 < at2 && at2 < at3);
    assert_eq!(
        code.windows(FRAME_LOAD.len())
            .filter(|w| *w == FRAME_LOAD)
            .count(),
        1
    );
    assert_eq!(&code[*at3..*at3 + 3], &[0x48, 0x85, 0xc0]); // TEST RAX,RAX
    let accesses: Vec<_> = recovery
        .iter()
        .filter(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
        .collect();
    assert_eq!(accesses.len(), 2);
    for (index, access) in accesses.into_iter().enumerate() {
        let (pc, start) = native.source_map[index];
        assert!(start <= access.start && access.end <= native.source_map[index + 1].1);
        let position = access.retirement.position().unwrap();
        assert_eq!(position.pc, pc);
        assert_eq!(usize::from(position.retired_instructions), index);
    }
}

/// ldr x0, [sp, #8]; ldr x1, [sp, #16]; sub sp, sp, #8; ldr x2, [sp]:
/// the second access relies on the first one's SP alignment check, and
/// the third checks SP again after its move by 8.
#[test]
fn sp_alignment_is_checked_once_while_it_holds() {
    use crate::{Lifter, aarch64::Decoder};
    let pc = GuestAddress(0x1000);
    let instructions: Vec<_> = [0xf940_07e0_u32, 0xf940_0be1, 0xd100_23ff, 0xf940_03e2]
        .into_iter()
        .enumerate()
        .map(|(index, word)| {
            Decoder
                .lift(GuestAddress(pc.0 + 4 * index as u64), word)
                .unwrap()
        })
        .collect();
    let code = emit(&instructions, None, GuestAddress(pc.0 + 16)).x86_64_code;
    let check = super::super::STACK_ALIGNMENT_CHECK;
    let checks = code.windows(check.len()).filter(|w| *w == check).count();
    assert_eq!(checks, 2);
}

/// A block whose numerical slow paths are out of line, with runs that
/// check FPCR and FPSR once and inputs taken from XMM0 where the
/// previous instruction left them, runs on the host exactly as its
/// instructions do one at a time with the inline layout: in every
/// sticky-path state and outside it, through zero-product resumes and
/// helper exits in mid-run.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn out_of_line_slow_paths_run_as_the_inline_layout() {
    use crate::{GuestState, Lifter, aarch64::Decoder};
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            bytes: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x20;
    const PAGE: usize = 4096;
    #[repr(C)]
    #[derive(Debug, PartialEq, Eq)]
    struct Exit {
        pc: u64,
        kind: u64,
    }
    /// Guest memory at X1.
    type Memory = [u64; 16];
    fn run(code: &[u8], state: &mut GuestState, memory: &mut Memory) -> Exit {
        let bytes = code.len().next_multiple_of(PAGE);
        state.x[1] = memory.as_mut_ptr() as u64;
        // SAFETY: private anonymous memory, RX after the copy, unmapped
        // after the call; the block touches only `state`, `memory`
        // through X1 and its own stack slots.
        let exit = unsafe {
            let page = mmap(core::ptr::null_mut(), bytes, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
            assert_eq!(mprotect(page, bytes, 5), 0);
            let entry: unsafe extern "sysv64" fn(*mut GuestState) -> Exit =
                core::mem::transmute(page);
            let exit = entry(state);
            assert_eq!(munmap(page, bytes), 0);
            exit
        };
        state.x[1] = 0;
        exit
    }
    const WORDS: [u32; 45] = [
        0xbd40_0021, // ldr s1,[x1]
        0x1e21_0802, // fmul s2,s0,s1
        0x1e20_2843, // fadd s3,s2,s0
        0x1e20_08e4, // fmul s4,s7,s0
        0x1e24_3865, // fsub s5,s3,s4
        0xbd00_0425, // str s5,[x1,#4]
        0xfd40_0430, // ldr d16,[x1,#8]
        0x1f50_4a26, // fmadd d6,d17,d16,d18
        0x3d80_1826, // str q6,[x1,#96]
        0x1e61_c0d3, // fsqrt d19,d6
        0x3dc0_0435, // ldr q21,[x1,#16]
        0x4e36_d6b4, // fadd v20.4s,v21.4s,v22.4s
        0x6e79_df17, // fmul v23.2d,v24.2d,v25.2d
        0x9100_0400, // add x0,x0,#1
        0x1e21_08a8, // fmul s8,s5,s1
        0x1e20_1909, // fdiv s9,s8,s0
        0x1e71_8a0a, // fnmul d10,d16,d17
        0x4e36_ceba, // fmla v26.4s,v21.4s,v22.4s
        0x3d80_083a, // str q26,[x1,#32]
        0xfd00_182a, // str d10,[x1,#48]
        0x6f00_e41b, // movi v27.2d,#0
        0x0e35_d77c, // fadd v28.2s,v27.2s,v21.2s
        0x3d80_103c, // str q28,[x1,#64]
        0x1e3c_2b9e, // fadd s30,s28,s28
        0x3d80_143e, // str q30,[x1,#80]
        0x3dc0_042c, // ldr q12,[x1,#16]
        0x6e31_a98d, // uminv b13,v12.16b
        0x1e26_01a2, // fmov w2,s13
        0x6e70_a98e, // umaxv h14,v12.8h
        0x0e02_3dc3, // umov w3,v14.h[0]
        0x6e36_8d8f, // cmeq v15.16b,v12.16b,v22.16b
        0x4e01_2de4, // smov x4,v15.b[0]
        0x4eb6_85f0, // add v16.4s,v15.4s,v22.4s
        0x4e08_3e05, // umov x5,v16.d[0]
        0x3dc0_0431, // ldr q17,[x1,#16]
        0x0e01_3e26, // umov w6,v17.b[0]
        0x3dc0_0432, // ldr q18,[x1,#16]
        0x0e02_3e47, // umov w7,v18.h[0]
        0x3dc0_0433, // ldr q19,[x1,#16]
        0x9e66_0268, // fmov x8,d19
        0x3dc0_0435, // ldr q21,[x1,#16]
        0x6e36_8d94, // cmeq v20.16b,v12.16b,v22.16b
        0x1e26_0289, // fmov w9,s20
        0x4eb6_8697, // add v23.4s,v20.4s,v22.4s
        0x3d80_1c37, // str q23,[x1,#112]
    ];
    const IXC: u32 = 1 << 4;
    const NEP: u32 = 1 << 2;
    const ROUND_UP: u32 = 1 << 22;
    const ROUND_TO_ZERO: u32 = 3 << 22;
    const FZ: u32 = 1 << 24;
    const DN: u32 = 1 << 25;
    const UPPER_GARBAGE: u64 = 0xa5a5_5a5a_c3c3_3c3c;
    let pc = GuestAddress(0x1000);
    let instructions: Vec<_> = WORDS
        .iter()
        .enumerate()
        .map(|(index, &word)| {
            Decoder
                .lift(GuestAddress(pc.0 + 4 * index as u64), word)
                .unwrap()
        })
        .collect();
    let fallthrough = GuestAddress(pc.0 + 4 * WORDS.len() as u64);
    let single = |s: f32| u64::from(s.to_bits()) | UPPER_GARBAGE << 32;
    let lanes = |values: [f32; 4]| {
        let bits = values.map(|value| u64::from(value.to_bits()));
        [bits[0] | bits[1] << 32, bits[2] | bits[3] << 32]
    };
    let initial = |s7: f32, s1: f32, d18: f64| {
        let mut state = GuestState::default();
        for (index, vector) in state.v.iter_mut().enumerate() {
            *vector = [UPPER_GARBAGE.rotate_left(index as u32), UPPER_GARBAGE];
        }
        state.v[0][0] = single(1.1);
        state.v[7][0] = single(s7);
        for (index, value) in [(17, 2.7f64), (18, d18)] {
            state.v[index][0] = value.to_bits();
        }
        state.v[22] = lanes([0.7, 5.5, -1.9, 7e3]);
        state.v[24] = [1.7f64.to_bits(), (-0.3f64).to_bits()];
        state.v[25] = [2.9f64.to_bits(), 1e10f64.to_bits()];
        let mut memory: Memory = [UPPER_GARBAGE; 16];
        memory[0] = single(s1);
        memory[1] = 1.3f64.to_bits();
        [memory[2], memory[3]] = lanes([1.5, -2.25, 3.1, 1e-3]);
        (state, memory)
    };
    for target in [crate::TargetCpu::Baseline, crate::TargetCpu::detect()] {
        let block = emit_for_target(
            &instructions,
            None,
            fallthrough,
            target,
            super::super::MemoryChecks::DEFAULT,
        );
        // Normal values complete; an exact zero product resumes; a subnormal one takes the
        // helper mid-run, as does the root of a negative or an infinite
        // addend; an infinite input takes it at once.
        for (s7, s1, d18) in [
            (2.0, 3.3, 0.9),
            (0.0, 3.3, 0.9),
            (-0.0, 3.3, 0.9),
            (1e-40, 3.3, 0.9),
            (0.0, 3.3, -100.0),
            (0.0, 3.3, f64::INFINITY),
            (0.0, f32::INFINITY, 0.9),
        ] {
            for (fpcr, fpsr) in [
                (0, IXC),
                (0, 0),
                (ROUND_TO_ZERO, IXC),
                (ROUND_UP, 0),
                (NEP, IXC),
                (DN, IXC),
                (FZ, IXC),
            ] {
                let (mut state, mut memory) = initial(s7, s1, d18);
                state.fpcr = fpcr;
                state.fpsr = fpsr;
                let (mut expected, mut expected_memory) = (state.clone(), memory);
                let mut expected_exit = None;
                // The state and memory before each instruction.
                let mut before = vec![];
                for instruction in &instructions {
                    before.push((instruction.pc.0, expected.clone(), expected_memory));
                    let next = GuestAddress(instruction.pc.0 + 4);
                    let mut code = Code::new();
                    match &instruction.operation {
                        Operation::FloatingPoint(operand) => super::super::simd::emit_numerical(
                            &mut code,
                            operand,
                            instruction.pc,
                            target,
                        ),
                        _ => super::super::emit_instruction(
                            &mut code,
                            instruction,
                            &mut vec![],
                            target,
                            super::super::MemoryChecks::DEFAULT,
                        ),
                    }
                    direct_exit(&mut code, next, ExitKind::Fallthrough);
                    let exit = run(&code, &mut expected, &mut expected_memory);
                    if exit.pc != next.0 || exit.kind != ExitKind::Fallthrough as u64 {
                        expected_exit = Some(exit);
                        break;
                    }
                }
                let expected_exit = expected_exit.unwrap_or(Exit {
                    pc: fallthrough.0,
                    kind: ExitKind::Fallthrough as u64,
                });
                let exit = run(&block.x86_64_code, &mut state, &mut memory);
                let case = (target, s7, s1, d18, fpcr, fpsr);
                // With FPSR.IXC clear, the first full path of a run may
                // set it; the run's later instructions then take full
                // paths too, where one at a time they take sticky ones.
                // A full path sends a zero input to the helper, where
                // a sticky product resumes.
                if exit != expected_exit && fpcr == 0 && fpsr & IXC == 0 {
                    assert_eq!(exit.kind, ExitKind::FloatingPoint as u64, "{case:?}");
                    assert!(exit.pc < expected_exit.pc, "{case:?}");
                    let (_, at_exit, memory_at_exit) =
                        before.iter().find(|(pc, ..)| *pc == exit.pc).unwrap();
                    assert_eq!(&state, at_exit, "{case:?}");
                    assert_eq!(&memory, memory_at_exit, "{case:?}");
                    continue;
                }
                assert_eq!(exit, expected_exit, "{case:?}");
                assert_eq!(state, expected, "{case:?}");
                assert_eq!(memory, expected_memory, "{case:?}");
            }
        }
    }
}

#[test]
fn clock_exit_requests_runtime_service_without_counter_or_guest_writes() {
    use crate::block::{ClockInstruction, ClockOperation};
    for operation in [
        ClockOperation::InstructionSynchronization,
        ClockOperation::ReadVirtualCounter { destination: 0 },
        ClockOperation::ReadVirtualCounter { destination: 31 },
    ] {
        let pc = GuestAddress(0x123456789000);
        let request = ClockInstruction {
            operation,
            instruction_pc: pc,
            next_pc: GuestAddress(pc.0 + 4),
        };
        let native = emit(
            &[],
            Some(&(pc, Terminator::Clock(request))),
            request.next_pc,
        );
        let mut expected = vec![0x48, 0xb8];
        expected.extend(pc.0.to_le_bytes());
        expected.extend([0xba, 7, 0, 0, 0, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc]);
        // No RDTSC, host helper address, guessed counter, destination write
        // or placeholder ISB: only the checked runtime service may complete.
        assert_eq!(native.x86_64_code, expected);
        assert_eq!(native.source_map, [(pc, 0)]);
    }
}

#[test]
fn pac_helper_exit_has_no_guest_writes_or_embedded_service_address() {
    use crate::block::{PointerAuthentication, decode_pointer_authentication};
    let fixed_words = [
        0xd503211f, 0xd503215f, 0xd503219f, 0xd50321df, 0xd503231f, 0xd503233f, 0xd503235f,
        0xd503237f, 0xd503239f, 0xd50323bf, 0xd50323df, 0xd50323ff, 0xd50320ff, 0xd65f0bff,
        0xd65f0fff, 0xdac143f1, 0xdac147f1,
    ];
    let integer_words = (0..8).flat_map(|op| {
        [
            0xdac10000 | (op << 10) | (16 << 5) | 17,
            0xdac123e0 | (op << 10) | 17,
        ]
    });
    let words: Vec<_> = fixed_words.into_iter().chain(integer_words).collect();
    assert_eq!(words.len(), 33);
    for word in words {
        let operation = decode_pointer_authentication(GuestAddress(0x1000), word)
            .unwrap()
            .unwrap()
            .operation;
        let pc = GuestAddress(0x123456789000);
        let request = PointerAuthentication {
            operation,
            instruction_pc: pc,
            next_pc: GuestAddress(pc.0 + 4),
        };
        let native = emit(
            &[],
            Some(&(pc, Terminator::PointerAuthentication(request))),
            request.next_pc,
        );
        let mut expected = vec![0x48, 0xb8];
        expected.extend(pc.0.to_le_bytes());
        expected.extend([0xba, 6, 0, 0, 0, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc]);
        // Only the SysV return registers RAX/RDX are touched, including for
        // RETAB: the runtime must keep signed LR while authenticating target.
        assert_eq!(native.x86_64_code, expected);
        assert_eq!(native.source_map, [(pc, 0)]);
    }
}

#[test]
fn ordinary_native_prefix_is_preserved_before_pac_boundary() {
    use crate::{
        Lifter,
        aarch64::Decoder,
        block::{PointerAuthentication, PointerAuthenticationOperation},
    };
    let base = GuestAddress(0x4000);
    let instruction = Decoder.lift(base, 0xd2800020).unwrap();
    let pc = GuestAddress(base.0 + 4);
    let ordinary = emit(core::slice::from_ref(&instruction), None, pc);
    let request = PointerAuthentication {
        operation: PointerAuthenticationOperation::SignIbSp,
        instruction_pc: pc,
        next_pc: GuestAddress(pc.0 + 4),
    };
    let native = emit(
        &[instruction],
        Some(&(pc, Terminator::PointerAuthentication(request))),
        request.next_pc,
    );
    assert_eq!(
        &native.x86_64_code[..ordinary.x86_64_code.len() - DIRECT_EXIT_BYTES],
        &ordinary.x86_64_code[..ordinary.x86_64_code.len() - DIRECT_EXIT_BYTES]
    );
    assert_eq!(native.source_map.len(), 2);
    assert_eq!(native.source_map[1].0, pc);
    assert_eq!(
        &native.x86_64_code[native.x86_64_code.len() - DYNAMIC_EXIT_BYTES..],
        &[0xba, 6, 0, 0, 0, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc]
    );
}

#[test]
fn trap_exit_uses_instruction_pc_and_only_native_return_scratch_registers() {
    for kind in [TrapKind::SupervisorCall, TrapKind::SoftwareBreakpoint] {
        let pc = GuestAddress(0x123456789000);
        let trap = SynchronousTrap {
            kind,
            immediate: 0x80,
            instruction_pc: pc,
            exception_return_pc: if kind == TrapKind::SupervisorCall {
                GuestAddress(pc.0 + 4)
            } else {
                pc
            },
        };
        let native = emit(
            &[],
            Some(&(pc, Terminator::Trap(trap))),
            GuestAddress(pc.0 + 4),
        );
        let mut expected = vec![0x48, 0xb8]; // movabs rax,instruction_pc
        expected.extend(pc.0.to_le_bytes());
        expected.extend([0xba, 5, 0, 0, 0, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc]); // mov edx,Trap; ret
        assert_eq!(native.x86_64_code, expected);
        assert_eq!(native.source_map, [(pc, 0)]);
    }
}

/// Region census of real code, run by hand:
/// `STELA_CENSUS=PATH:FILE_OFFSET:BYTES:BASE` names a raw image, the
/// executable range to sweep and the guest address of file offset 0
/// (all hexadecimal). It sweeps maximal straight-line runs the decoder
/// lifts, replays the region selection of [`emit_selected`] on each,
/// with its cost gates, and prints the summed allocator statistics, the
/// share of instructions each emission path takes, and the categories
/// of the instructions that end a region or run outside one.
/// `STELA_CENSUS_SYSTEM=1` replays system mode, whose accesses check
/// the guest range (`guest_range`), instead of the process profiles.
#[test]
#[ignore = "manual: opt-in"]
fn region_census_of_real_code() {
    use crate::Lifter;
    use std::collections::BTreeMap;
    let spec = std::env::var("STELA_CENSUS").expect("STELA_CENSUS=PATH:OFFSET:BYTES:BASE");
    let system = std::env::var_os("STELA_CENSUS_SYSTEM").is_some();
    let parts: Vec<&str> = spec.split(':').collect();
    let hex = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
    let image = std::fs::read(parts[0]).unwrap();
    let (offset, bytes, base) = (hex(parts[1]), hex(parts[2]), hex(parts[3]));
    let text = &image[offset as usize..(offset + bytes) as usize];
    let category = |op: &Operation| {
        let name = std::format!("{op:?}");
        let end = name.find(['(', ' ', '{']).unwrap_or(name.len());
        std::string::String::from(&name[..end])
    };
    let mut stats = super::super::region::AllocationStats::default();
    let add = |total: &mut super::super::region::AllocationStats,
               s: &super::super::region::AllocationStats| {
        total.state_loads += s.state_loads;
        total.pressure_stores += s.pressure_stores;
        total.exit_stores += s.exit_stores;
        total.lifetime_stores += s.lifetime_stores;
        total.commits += s.commits;
        total.native_instructions += s.native_instructions;
        total.load_boundary_stores += s.load_boundary_stores;
        total.clean_loads += s.clean_loads;
        total.pair_loads += s.pair_loads;
        total.stores += s.stores;
        total.flag_loads += s.flag_loads;
        total.flag_stores += s.flag_stores;
    };
    let (mut allocated, mut clean, mut rejected, mut plain, mut runs) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    let (mut region_bytes, mut plain_bytes) = (0usize, 0usize);
    let mut outside: BTreeMap<std::string::String, usize> = BTreeMap::new();
    let mut breakers: BTreeMap<std::string::String, usize> = BTreeMap::new();
    let mut run: Vec<Instruction> = vec![];
    let mut flush = |run: &mut Vec<Instruction>| {
        if run.is_empty() {
            return;
        }
        runs += 1;
        let mut ranges = [false; MAX_BLOCK_INSTRUCTIONS];
        if system {
            super::super::guest_range::checks(run, &mut ranges[..run.len()]);
        }
        let checks_at = |index: usize| super::super::MemoryChecks {
            guest_range: ranges[index],
            ..super::super::MemoryChecks::DEFAULT
        };
        let mut cursor = 0;
        while cursor < run.len() {
            let rest = &run[cursor..];
            // Replays the system-mode selection with its cost gates: a
            // rejected chunk is emitted as baseline and skipped whole.
            let baseline = |count: usize| {
                let mut code = Code::new();
                let mut fixups = vec![];
                for (index, instruction) in rest[..count].iter().enumerate() {
                    super::super::emit_instruction(
                        &mut code,
                        instruction,
                        &mut fixups,
                        crate::TargetCpu::Baseline,
                        checks_at(cursor + index),
                    );
                }
                (code, fixups.is_empty())
            };
            let allocated_region = super::super::region::emit_allocated_prefix(rest)
                .ok()
                .flatten()
                .filter(|region| {
                    let (code, no_fixups) = baseline(region.consumed_instructions);
                    no_fixups && super::super::region::admits_allocated(region, &code)
                });
            let clean_region = || {
                super::super::region::emit_clean_load_prefix_with(
                    rest,
                    super::super::MemoryChecks::DEFAULT,
                    system,
                    system.then(|| &ranges[cursor..]),
                )
                .ok()
                .filter(|region| region.consumed_instructions != 0)
            };
            if let Some(region) = allocated_region {
                allocated += region.consumed_instructions;
                region_bytes += region.code.len();
                add(&mut stats, &region.stats);
                cursor += region.consumed_instructions;
            } else if let Some(region) = clean_region() {
                let (code, _) = baseline(region.consumed_instructions);
                if super::super::region::admits_ordinary(&region, &code) {
                    clean += region.consumed_instructions;
                    region_bytes += region.code.len();
                    add(&mut stats, &region.stats);
                } else {
                    rejected += region.consumed_instructions;
                    plain_bytes += code.len();
                }
                cursor += region.consumed_instructions;
            } else {
                let instruction = &run[cursor];
                let detail = match &instruction.operation {
                    Operation::Memory {
                        transfer,
                        bytes,
                        mode,
                        base,
                        ..
                    }
                    | Operation::MemoryPair {
                        transfer,
                        bytes,
                        mode,
                        base,
                        ..
                    } => std::format!(
                        "{} {transfer:?} {bytes} {mode:?} {}",
                        category(&instruction.operation),
                        if *base == Register::Sp { "sp" } else { "x" }
                    ),
                    operation => category(operation),
                };
                *outside.entry(detail).or_default() += 1;
                let mut code = Code::new();
                let mut fixups = vec![];
                if let Operation::FloatingPoint(operand) = &instruction.operation {
                    super::super::simd::emit_numerical(
                        &mut code,
                        operand,
                        instruction.pc,
                        crate::TargetCpu::Baseline,
                    );
                } else if super::super::validate_target_with(
                    instruction,
                    crate::TargetCpu::Baseline,
                    checks_at(cursor),
                )
                .is_ok()
                {
                    super::super::emit_instruction(
                        &mut code,
                        instruction,
                        &mut fixups,
                        crate::TargetCpu::Baseline,
                        checks_at(cursor),
                    );
                }
                plain_bytes += code.len();
                plain += 1;
                cursor += 1;
                continue;
            }
            if let Some(next) = run.get(cursor) {
                *breakers.entry(category(&next.operation)).or_default() += 1;
            }
        }
        run.clear();
    };
    for (index, word) in text.as_chunks::<4>().0.iter().enumerate() {
        let pc = GuestAddress(base + offset + 4 * index as u64);
        match crate::aarch64::Decoder.lift(pc, u32::from_le_bytes(*word)) {
            Ok(instruction)
                if !category(&instruction.operation).starts_with("Branch")
                    && category(&instruction.operation) != "Return" =>
            {
                run.push(instruction);
                if run.len() == crate::block::MAX_BLOCK_INSTRUCTIONS {
                    flush(&mut run);
                }
            }
            _ => flush(&mut run),
        }
    }
    flush(&mut run);
    let top = |map: &BTreeMap<std::string::String, usize>| {
        let mut v: Vec<_> = map.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        v.into_iter()
            .take(40)
            .map(|(k, n)| std::format!("{k} {n}"))
            .collect::<Vec<_>>()
    };
    std::println!(
        "runs {runs} allocated {allocated} clean {clean} rejected {rejected} plain {plain}"
    );
    std::println!("region bytes {region_bytes} plain bytes {plain_bytes}");
    std::println!("{stats:?}");
    std::println!("outside {:?}", top(&outside));
    std::println!("breakers {:?}", top(&breakers));
}

#[test]
fn frame_compare_and_test_branches_do_not_load_a_scratch_register() {
    use crate::aarch64::Width;
    let target = GuestAddress(0x2000);
    for (operation, expected, condition) in [
        (
            Operation::BranchZero {
                target,
                source: Register::X(20),
                width: Width::W32,
                nonzero: false,
            },
            &[0x83, 0xbf, 160, 0, 0, 0, 0][..],
            Cond::E,
        ),
        (
            Operation::BranchZero {
                target,
                source: Register::X(20),
                width: Width::X64,
                nonzero: true,
            },
            &[0x48, 0x83, 0xbf, 160, 0, 0, 0, 0][..],
            Cond::Ne,
        ),
        (
            Operation::BranchBit {
                target,
                source: Register::X(20),
                bit: 63,
                nonzero: true,
            },
            &[0xf6, 0x87, 167, 0, 0, 0, 0x80][..],
            Cond::Ne,
        ),
    ] {
        let mut code = Code::pinned();
        assert_eq!(
            branch_condition(&mut code, &operation, super::super::Rax::Unknown),
            Some(condition)
        );
        assert_eq!(&code[..], expected);
        assert_eq!(code.instructions(), 1);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn pinned_select_consumes_the_preceding_compare_flags() {
    use crate::{
        GuestState,
        block::{BlockProfile, Features},
        x86_64::{native, pinned},
    };
    // CMP X0, #1; CSEL X1, X2, X3, HI; RET.
    let source: Vec<_> = [0xf100_041fu32, 0x9a83_8041, 0xd65f_03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let code = crate::testing::block_with(
        &source,
        GuestAddress(0x1000),
        BlockProfile::new(Features::SYSTEM_MODE),
    )
    .unwrap()
    .native;
    let select = &code.x86_64_code[code.source_map[1].1..code.source_map[2].1];
    // CMC converts Arm carry into the x86 borrow for the HI predicate.
    assert_eq!(select[0], 0xf5);
    let entry = pinned::entered(&code.x86_64_code);
    for (operand, selected, nzcv) in [
        (0, 33, 0x8000_0000),
        (1, 33, 0x6000_0000),
        (2, 22, 0x2000_0000),
    ] {
        let mut state = GuestState::default();
        state.x[0] = operand;
        state.x[2] = 22;
        state.x[3] = 33;
        state.x[30] = 0x2000;
        assert_eq!(native::run(&entry, &mut state), 0x2000);
        assert_eq!(state.x[1], selected);
        assert_eq!(state.nzcv, nzcv);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn pinned_conditional_increment_consumes_the_preceding_compare_flags() {
    use crate::{
        GuestState,
        block::{BlockProfile, Features},
        x86_64::{native, pinned},
    };
    // CMP X0, #1; CSET W2, EQ; RET.
    let cset = 0x1a9f_17e2;
    // CMP X0, #1; CSINC W8, W2, W8, HI; RET.
    let csinc = 0x1a88_8448;
    for (select, prefix) in [
        (cset, &[0x0f, 0x94, 0xc0][..]),                            // SETE AL
        (csinc, &[0x44, 0x8b, 0xc6, 0x45, 0x8d, 0x40, 0x01, 0xf5]), // MOV, LEA, CMC
    ] {
        let source: Vec<_> = [0xf100_041fu32, select, 0xd65f_03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let code = crate::testing::block_with(
            &source,
            GuestAddress(0x1000),
            BlockProfile::new(Features::SYSTEM_MODE),
        )
        .unwrap()
        .native;
        let selected = &code.x86_64_code[code.source_map[1].1..code.source_map[2].1];
        assert!(selected.starts_with(prefix), "{selected:02x?}");
        let entry = pinned::entered(&code.x86_64_code);
        for (compared, equal, higher, nzcv) in [
            (0, 0, false, 0x8000_0000),
            (1, 1, false, 0x6000_0000),
            (2, 0, true, 0x2000_0000),
        ] {
            let mut state = GuestState::default();
            state.x[0] = compared;
            state.x[2] = 0xaabb_ccdd_0000_0016;
            state.x[8] = u64::MAX;
            state.x[30] = 0x2000;
            let mut expected = state.x;
            if select == cset {
                expected[2] = equal;
            } else {
                expected[8] = if higher { 22 } else { 0 };
            }
            assert_eq!(native::run(&entry, &mut state), 0x2000);
            assert_eq!(state.x, expected);
            assert_eq!(state.nzcv, nzcv);
        }
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn pinned_conditional_compare_consumes_the_preceding_flags() {
    use crate::{
        GuestState, Lifter, TargetCpu,
        aarch64::{Decoder, conditional_select::decode_compare},
        x86_64::{native, pinned},
    };

    let pc = GuestAddress(0x1000);
    let compare_pc = GuestAddress(pc.0 + 4);
    let end = GuestAddress(pc.0 + 8);
    for wide in [0, 1] {
        for producer_subtract in [0, 1] {
            // CMP or CMN of X0/W0 and X4/W4.
            let producer = 0x2b04_001f | wide << 31 | producer_subtract << 30;
            for subtract in [0, 1] {
                for right in [2 << 16, (1 << 11) | (31 << 16)] {
                    for condition in 0..16 {
                        // CCMP or CCMN of X1/W1 and X2/W2 or immediate 31.
                        let compare =
                            0x3a40_0025 | wide << 31 | subtract << 30 | right | condition << 12;
                        let instructions = [
                            Decoder.lift(pc, producer).unwrap(),
                            Decoder.lift(compare_pc, compare).unwrap(),
                        ];
                        let (system, _) = emit_system_mode(
                            &instructions,
                            None,
                            end,
                            TargetCpu::Baseline,
                            super::super::MemoryChecks::DEFAULT,
                            super::super::NativeSystem::NONE,
                        );
                        assert_eq!(system.source_map[0], (pc, 0));
                        let (at, offset) = system.source_map[1];
                        assert_eq!(at, compare_pc);
                        let (single, _) = emit_system_mode(
                            &instructions[1..],
                            None,
                            end,
                            TargetCpu::Baseline,
                            super::super::MemoryChecks::DEFAULT,
                            super::super::NativeSystem::NONE,
                        );
                        let bytes = &system.x86_64_code[offset..];
                        if condition < 14 {
                            assert!(bytes.len() < single.x86_64_code.len(), "{compare:08x}");
                            let predicate_at = usize::from(matches!(condition, 8 | 9));
                            assert_eq!(bytes[predicate_at..predicate_at + 2], [0x41, 0x0f]);
                        } else {
                            assert_eq!(bytes, single.x86_64_code);
                        }

                        let dit = TargetCpu::Baseline.with_data_independent_timing();
                        let (system_dit, _) = emit_system_mode(
                            &instructions,
                            None,
                            end,
                            dit,
                            super::super::MemoryChecks::DEFAULT,
                            super::super::NativeSystem::NONE,
                        );
                        let mut baseline = Code::pinned();
                        baseline.set_constant_time(true);
                        super::super::conditional_select::emit_compare(
                            &mut baseline,
                            &decode_compare(compare).unwrap(),
                            false,
                        );
                        assert!(
                            system_dit.x86_64_code[system_dit.source_map[1].1..]
                                .starts_with(&baseline)
                        );

                        let frame = emit(&instructions, None, end);
                        let entered = pinned::entered(&system.x86_64_code);
                        for (left, right) in [
                            (0, 0),
                            (1, 0),
                            (0, 1),
                            (1 << 31, 1),
                            (1 << 63, 1),
                            (u64::MAX, 1),
                            (u64::MAX, u64::MAX),
                        ] {
                            let mut initial = GuestState::default();
                            initial.x[0] = left;
                            initial.x[1] = left ^ 1;
                            initial.x[2] = right;
                            initial.x[4] = right;
                            initial.nzcv = 0xf000_0000;
                            let mut expected = initial.clone();
                            assert_eq!(native::run(&frame.x86_64_code, &mut expected), end.0);
                            assert_eq!(native::run(&entered, &mut initial), end.0);
                            assert_eq!(initial, expected, "{producer:08x} {compare:08x}");
                        }
                    }
                }
            }
        }
    }
}
