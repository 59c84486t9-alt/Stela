use super::super::chain::{DIRECT_EXIT_BYTES, DYNAMIC_EXIT_BYTES};
use super::*;
use crate::block::{SynchronousTrap, TrapKind};
use alloc::vec;
use alloc::vec::Vec;

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
    assert_eq!(
        &code[map[2].1 + 7..map[2].1 + 13],
        &[0x3b, 0x87, 8, 0, 0, 0]
    );
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
        let ranges = if system {
            super::super::guest_range::checks(run)
        } else {
            vec![false; run.len()]
        };
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
