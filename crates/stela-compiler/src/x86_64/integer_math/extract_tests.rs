use super::*;
use crate::{
    Lifter, Options,
    aarch64::Decoder,
    block::{BlockProfile, CompilationPlan, CompiledBlock, Features},
};

// EXTR X16,X17,X16,#63 from the archived OpenSSL RSA workload.
const OPENSSL: (GuestAddress, u32) = (GuestAddress(0xef008), 0x93d0_fe30);

fn compile(pc: GuestAddress, word: u32, target: TargetCpu, profile: BlockProfile) -> CompiledBlock {
    CompilationPlan::new(&word.to_le_bytes(), pc, &Options::new(profile, target))
        .unwrap()
        .compile()
        .unwrap()
}

#[test]
fn extract_commits_shrd_without_a_result_move() {
    let (pc, word) = OPENSSL;
    let Operation::IntegerMath(operand) = Decoder.lift(pc, word).unwrap().operation else {
        panic!("decoded EXTR");
    };
    let system = BlockProfile::new(Features::SYSTEM_MODE);
    for (profile, new_code, old_bytes, new_bytes, new_count) in [
        (BlockProfile::ORDINARY, Code::new as fn() -> Code, 29, 26, 4),
        (system, Code::pinned as fn() -> Code, 17, 5, 1),
    ] {
        let mut old = new_code();
        let mut asm = old.asm();
        load_with(&mut asm, operand.left);
        right_operand_with(&mut asm, operand.right, Width::X64, Shift::Lsl, 0);
        asm.shrd_imm(Size::Qword, Rcx, Rax, 63);
        asm.mov(Size::Qword, Rax, Rcx);
        store_with(&mut asm, operand.destination);
        assert_eq!((old.len(), old.instructions()), (old_bytes, 5));

        for target in [
            TargetCpu::Baseline,
            TargetCpu::Ssse3,
            TargetCpu::Sse41,
            TargetCpu::X86_64_V3,
            TargetCpu::X86_64_V3.with_data_independent_timing(),
        ] {
            let mut result = new_code();
            emit(&mut result, &operand, target);
            assert_eq!(
                (result.len(), result.instructions()),
                (new_bytes, new_count)
            );
            let actual = compile(pc, word, target, profile);
            assert_eq!(actual.native.source_map, [(pc, 0)]);
            assert!(actual.native.x86_64_code.starts_with(&result));
            assert!(actual.fault_recovery.is_empty());
        }
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn extract_matches_arm_concatenation_in_frame_and_pinned_code() {
    use crate::{
        GuestState,
        x86_64::{native::run, pinned},
    };

    // ROR X3,X14,#33 from the archived xxHash workload is an EXTR alias.
    let xxhash = (GuestAddress(0x10000b450), 0x93ce_85c3);
    let check = |pc: GuestAddress, word: u32| {
        let wide = word >> 31 != 0;
        let bits = if wide { 64 } else { 32 };
        let mask = u64::MAX >> (64 - bits);
        let shift = (word >> 10) & 63;
        let (high, low, dst) = ((word >> 5) & 31, (word >> 16) & 31, word & 31);
        let system = BlockProfile::new(Features::SYSTEM_MODE);
        for profile in [BlockProfile::ORDINARY, system] {
            for target in [
                TargetCpu::Baseline,
                TargetCpu::X86_64_V3.with_data_independent_timing(),
            ] {
                let block = compile(pc, word, target, profile);
                let code = if profile == system {
                    pinned::entered(&block.native.x86_64_code)
                } else {
                    block.native.x86_64_code
                };
                let mut state = GuestState {
                    x: core::array::from_fn(|r| 0xdead_beef_1357_2468u64.rotate_right(r as u32)),
                    sp: 0x1234_5678_9000,
                    nzcv: 0xb000_0000,
                    ..Default::default()
                };
                let read = |r| state.x.get(r as usize).copied().unwrap_or(0) & mask;
                let joined = (u128::from(read(high)) << bits) | u128::from(read(low));
                let mut expected = state.clone();
                if dst != 31 {
                    expected.x[dst as usize] = (joined >> shift) as u64 & mask;
                }
                assert_eq!(run(&code, &mut state), pc.0 + 4);
                assert_eq!(state, expected, "{word:08x}, {profile:?}, {target:?}");
            }
        }
    };
    check(OPENSSL.0, OPENSSL.1);
    check(xxhash.0, xxhash.1);
    for wide in [false, true] {
        let form = 0x1380_0000 | if wide { (1 << 31) | (1 << 22) } else { 0 };
        for shift in [0, 1, if wide { 63 } else { 31 }] {
            for (high, low, dst) in [
                (16, 17, 16),
                (17, 16, 16),
                (17, 16, 0),
                (1, 16, 19),
                (17, 1, 19),
                (31, 16, 16),
                (17, 31, 17),
                (17, 16, 31),
            ] {
                let word = form | (low << 16) | (shift << 10) | (high << 5) | dst;
                check(OPENSSL.0, word);
            }
        }
    }
}
