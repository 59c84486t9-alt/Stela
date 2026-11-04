use super::*;
use crate::{
    Lifter, Options,
    aarch64::Decoder,
    block::{BlockProfile, CompilationPlan, CompiledBlock},
};

const PC: GuestAddress = GuestAddress(0x1f534c);
// UDIV X20,X21,X1; MSUB X20,X20,X1,X21 from the OpenSSL RSA workload.
const OPENSSL: [u32; 2] = [0x9ac1_0ab4, 0x9b01_d694];

fn lift(words: [u32; 2]) -> [Instruction; 2] {
    core::array::from_fn(|index| {
        Decoder
            .lift(GuestAddress(PC.0 + 4 * index as u64), words[index])
            .unwrap()
    })
}

fn compile(words: &[u32], pc: GuestAddress, target: TargetCpu) -> CompiledBlock {
    let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    CompilationPlan::new(&source, pc, &Options::new(BlockProfile::ORDINARY, target))
        .unwrap()
        .compile()
        .unwrap()
}

#[test]
fn divide_remainder_emits_two_rows_and_one_remainder_store() {
    for target in [
        TargetCpu::Baseline,
        TargetCpu::Ssse3,
        TargetCpu::Sse41,
        TargetCpu::X86_64_V3,
    ] {
        for (wide, signed, old_bytes, new_bytes, old_count, new_count) in [
            (true, false, 80, 52, 16, 11),
            (false, false, 77, 51, 17, 12),
            (true, true, 98, 72, 20, 16),
            (false, true, 92, 68, 21, 17),
        ] {
            let words = [
                OPENSSL[0] & !(1 << 31) | (u32::from(wide) << 31) | (u32::from(signed) << 10),
                OPENSSL[1] & !(1 << 31) | (u32::from(wide) << 31),
            ];
            let instructions = lift(words);
            let [
                Operation::IntegerMath(division),
                Operation::IntegerMath(product),
            ] = instructions.clone().map(|row| row.operation)
            else {
                panic!("decoded division and MSUB");
            };
            let mut old = Code::new();
            emit(&mut old, &division, target);
            emit(&mut old, &product, target);
            assert_eq!((old.len(), old.instructions()), (old_bytes, old_count));
            let mut grouped = Code::new();
            let mut map = Vec::new();
            assert!(emit_divide_remainder(&mut grouped, &mut map, &instructions));
            assert_eq!(
                (grouped.len(), grouped.instructions()),
                (new_bytes, new_count)
            );
            assert_eq!(&grouped[map[1].1..], &[0x48, 0x89, 0x97, 0xa0, 0, 0, 0]);
            let block = compile(&words, PC, target);
            assert_eq!(block.native.source_map, map);
            assert!(block.native.x86_64_code.starts_with(&grouped));
            let dit = compile(&words, PC, target.with_data_independent_timing());
            assert!(dit.native.x86_64_code.starts_with(&old));
        }
    }
}

#[test]
fn divide_remainder_refuses_aliased_inputs_and_unmatched_rows() {
    let [a, b] = OPENSSL;
    for words in [
        [a & !31 | 21, b & !(31 << 5) | (21 << 5)], // Quotient overwrites the dividend.
        [a & !31 | 1, b & !(31 << 5) | (1 << 5)],   // Quotient overwrites the divisor.
        [a, b ^ (1 << 31)],                         // Different result width.
        [a, b ^ (1 << 15)],                         // MADD.
        [a, b ^ (1 << 10)],                         // A different accumulator.
        [a, b | 31],                                // Discarded remainder.
    ] {
        let mut code = Code::new();
        let mut map = Vec::new();
        assert!(!emit_divide_remainder(&mut code, &mut map, &lift(words)));
        assert!(code.is_empty() && map.is_empty());
    }
    let mut separated = lift(OPENSSL);
    separated[1].pc.0 += 4;
    assert!(!emit_divide_remainder(
        &mut Code::new(),
        &mut Vec::new(),
        &separated
    ));
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn divide_remainder_matches_arm_at_each_row_and_independent_entry() {
    use crate::{GuestState, x86_64::native::run};

    let inputs = [
        0,
        1,
        3,
        0x8000_0000,
        0x8000_0000_0000_0000,
        0xffff_ffff_ffff_fffd,
        u64::MAX,
    ];
    for wide in [false, true] {
        for signed in [false, true] {
            for swapped in [false, true] {
                for [dividend, divisor, quotient, remainder] in [
                    [0, 1, 2, 2],
                    [0, 1, 2, 0],
                    [0, 1, 2, 1],
                    [0, 1, 2, 3],
                    [0, 0, 2, 30],
                    [31, 1, 2, 3],
                    [0, 31, 2, 3],
                ] {
                    let form = u32::from(wide) << 31;
                    let divide = 0x1ac0_0800
                        | form
                        | (u32::from(signed) << 10)
                        | (divisor << 16)
                        | (dividend << 5)
                        | quotient;
                    let (left, right) = if swapped {
                        (divisor, quotient)
                    } else {
                        (quotient, divisor)
                    };
                    let msub = 0x1b00_8000
                        | form
                        | (right << 16)
                        | (dividend << 10)
                        | (left << 5)
                        | remainder;
                    let compiled = compile(&[divide, msub], PC, TargetCpu::Baseline);
                    let msub_pc = GuestAddress(PC.0 + 4);
                    let msub_at = compiled.native.source_map[1].1;
                    assert_eq!(compiled.native.source_map, [(PC, 0), (msub_pc, msub_at)]);
                    let alone = compile(&[msub], msub_pc, TargetCpu::Baseline);
                    assert_eq!(alone.native.source_map, [(msub_pc, 0)]);
                    let mask = if wide { u64::MAX } else { u32::MAX.into() };
                    let signed_value = |v: u64| {
                        if wide {
                            i128::from(v as i64)
                        } else {
                            i128::from(v as i32)
                        }
                    };
                    for a in inputs {
                        for b in inputs {
                            let mut state = GuestState {
                                x: [0xabab_cdcd_efef_0101; 31],
                                nzcv: 0xb,
                                ..Default::default()
                            };
                            if dividend != 31 {
                                state.x[dividend as usize] = a;
                            }
                            if divisor != 31 {
                                state.x[divisor as usize] = b;
                            }
                            let read =
                                |r| state.x.get(r as usize).copied().unwrap_or_default() & mask;
                            let (a, b) = (read(dividend), read(divisor));
                            let q = if b == 0 {
                                0
                            } else if signed {
                                (signed_value(a) / signed_value(b)) as u64 & mask
                            } else {
                                a / b
                            };
                            let r = a.wrapping_sub(q.wrapping_mul(b)) & mask;
                            let mut first = state.clone();
                            first.x[quotient as usize] = q;
                            let mut expected = first.clone();
                            expected.x[remainder as usize] = r;
                            let mut intermediate = state.clone();
                            run(&compiled.native.x86_64_code[..msub_at], &mut intermediate);
                            assert_eq!(intermediate, first, "{divide:08x}, {msub:08x}");
                            assert_eq!(run(&compiled.native.x86_64_code, &mut state), PC.0 + 8);
                            assert_eq!(state, expected, "{divide:08x}, {msub:08x}");
                            assert_eq!(run(&alone.native.x86_64_code, &mut intermediate), PC.0 + 8);
                            assert_eq!(intermediate, expected, "independent {msub:08x}");
                        }
                    }
                }
            }
        }
    }
}
