//! S/D FADD, FSUB, FMUL, FDIV, FABD, FMULX and FNMUL over subnormal,
//! tiny, overflowing and special inputs
//! against the Arm reference, compiled as blocks for every tier this host
//! has: every inline completion matches the reference in every V register
//! and FPSR, every exit leaves the state unchanged, and with FZ, FIZ, AH
//! and the trap enables clear, every lane set without a NaN input or an
//! invalid operation (or a minimum normal quotient) completes
//! inline, its subnormal inputs and results, UFC, OFC and DZC included.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        self, BinaryOperation, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ,
        FPCR_NEP, FPCR_ROUNDING_SHIFT, Format, INVALID,
    },
    block::{BlockProfile, CompilationPlan},
    x86_64::native::run,
};
use alloc::{vec, vec::Vec};

const PC: GuestAddress = GuestAddress(0x1000_0000);
const RETURN: u64 = 0x4000;
const D: u32 = 3;
const N: u32 = 4;
const M: u32 = 17;

fn targets() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    [
        TargetCpu::Baseline,
        TargetCpu::Sse41,
        TargetCpu::X86_64_V2,
        TargetCpu::X86_64_V3,
        TargetCpu::X86_64_V4,
        TargetCpu::X86_64_V4.with_data_independent_timing(),
        host,
    ]
    .into_iter()
    .filter(|target| host.supports(*target))
    .collect()
}

fn compile(word: u32, target: TargetCpu) -> Vec<u8> {
    let source = [word, 0xd65f_03c0].map(u32::to_le_bytes).concat();
    CompilationPlan::new(&source, PC, &Options::new(BlockProfile::ORDINARY, target))
        .unwrap()
        .compile()
        .unwrap()
        .native
        .x86_64_code
}

fn controls() -> [u32; 10] {
    [
        0,
        1 << FPCR_ROUNDING_SHIFT,
        2 << FPCR_ROUNDING_SHIFT,
        3 << FPCR_ROUNDING_SHIFT,
        FPCR_DN,
        FPCR_NEP,
        FPCR_FZ,
        FPCR_FIZ,
        FPCR_AH,
        FPCR_EXCEPTION_ENABLE_MASK,
    ]
}

/// FPCR whose operations complete inline for every lane without a NaN
/// input or an invalid operation.
fn rounded(fpcr: u32) -> bool {
    fpcr & (FPCR_FZ | FPCR_FIZ | FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK) == 0
}

/// Zeros, subnormals, the minimum normal and values whose products and
/// quotients fall below it, normals, values near the maximum, infinities
/// and NaNs, both signs.
fn floats(format: Format) -> Vec<u64> {
    let fraction_bits = format.fraction_bits();
    let infinity = format.exponent_mask();
    let quiet = 1u64 << (fraction_bits - 1);
    let bias = u64::from(format.exponent_bias());
    let one = bias << fraction_bits;
    let half = (bias - 1) << fraction_bits;
    let minimum = 1u64 << fraction_bits;
    let mut values = vec![
        0,
        1,
        minimum - 3,
        minimum,
        minimum | 5,
        3 * minimum,
        2 * minimum - 1,
        half,
        one,
        one + 1,
        3 * one / 2,
        (bias + 3) << fraction_bits | 0x1234,
        infinity - 1,
        infinity,
        infinity | quiet,
        infinity | 1,
    ];
    let positive = values.len();
    for index in 0..positive {
        values.push(values[index] | format.sign_mask());
    }
    values
}

fn is_nan(format: Format, bits: u64) -> bool {
    bits & !format.sign_mask() > format.exponent_mask()
}

fn lane(vector: [u64; 2], format: Format, index: usize) -> u64 {
    if format == Format::Double {
        vector[index]
    } else {
        vector[index / 2] >> (32 * (index % 2)) & 0xffff_ffff
    }
}

fn set_lane(vector: &mut [u64; 2], format: Format, index: usize, bits: u64) {
    if format == Format::Double {
        vector[index] = bits;
    } else {
        let shift = 32 * (index % 2);
        vector[index / 2] = vector[index / 2] & !(0xffff_ffff << shift) | bits << shift;
    }
}

fn shapes(format: Format) -> &'static [u32] {
    if format == Format::Double {
        &[0, 2]
    } else {
        &[0, 2, 4]
    }
}

/// The scalar (`lanes` zero) or vector word of `operation`, if it has one.
fn binary_word(operation: BinaryOperation, format: Format, lanes: u32) -> Option<u32> {
    let double = u32::from(format == Format::Double);
    let registers = M << 16 | N << 5 | D | double << 22;
    if lanes == 0 {
        let base = match operation {
            BinaryOperation::Add => 0x1e20_2800,
            BinaryOperation::Subtract => 0x1e20_3800,
            BinaryOperation::Multiply => 0x1e20_0800,
            BinaryOperation::Divide => 0x1e20_1800,
            BinaryOperation::NegatedMultiply => 0x1e20_8800,
            BinaryOperation::AbsoluteDifference => 0x7ea0_d400,
            BinaryOperation::MultiplyExtended => 0x5e20_dc00,
        };
        return Some(base | registers);
    }
    let base = match operation {
        BinaryOperation::Add => 0x0e20_d400,
        BinaryOperation::Subtract => 0x0ea0_d400,
        BinaryOperation::Multiply => 0x2e20_dc00,
        BinaryOperation::Divide => 0x2e20_fc00,
        BinaryOperation::AbsoluteDifference => 0x2ea0_d400,
        BinaryOperation::MultiplyExtended => 0x0e20_dc00,
        BinaryOperation::NegatedMultiply => return None,
    };
    Some(base | u32::from(lanes * format.bits() == 128) << 30 | registers)
}

/// Whether a lane may exit: a NaN input, an operation that raises the
/// host's invalid (FMULX's infinity times zero, two on Arm), or a minimum
/// normal quotient.
fn exits(operation: BinaryOperation, format: Format, fpcr: u32, left: u64, right: u64) -> bool {
    let magnitude = |bits: u64| bits & !format.sign_mask();
    let special = |a: u64, b: u64| magnitude(a) == 0 && magnitude(b) == format.exponent_mask();
    is_nan(format, left)
        || is_nan(format, right)
        || (operation == BinaryOperation::MultiplyExtended
            && (special(left, right) || special(right, left)))
        || floating::evaluate(format, operation, fpcr, left, right).is_ok_and(|outcome| {
            // The host may find a quotient's tininess after rounding: a
            // minimum normal quotient takes the helper.
            outcome.exceptions & INVALID != 0
                || operation == BinaryOperation::Divide
                    && outcome.bits & !format.sign_mask() == 1 << format.fraction_bits()
        })
}

#[test]
fn binary_operations_complete_subnormal_and_tiny_lanes_inline() {
    use BinaryOperation::*;
    let mut runs = 0;
    let mut inline = 0;
    for target in targets() {
        for format in [Format::Single, Format::Double] {
            let all = floats(format);
            for &lanes in shapes(format) {
                for operation in [
                    Add,
                    Subtract,
                    Multiply,
                    Divide,
                    AbsoluteDifference,
                    MultiplyExtended,
                    NegatedMultiply,
                ] {
                    let Some(word) = binary_word(operation, format, lanes) else {
                        continue;
                    };
                    let code = compile(word, target);
                    for start in 0..all.len() {
                        let mut n = [0x5a5a_a5a5_3c3c_c3c3u64, 0x0123_4567_09ab_cdef];
                        let mut m = [0x7654_3210_1edc_ba98u64, 0x13c3_3c3c_a5a5_5a5a];
                        if lanes != 0 {
                            n = [0; 2];
                            m = [0; 2];
                        }
                        for index in 0..lanes.max(1) as usize {
                            set_lane(&mut n, format, index, all[(start + index) % all.len()]);
                            set_lane(
                                &mut m,
                                format,
                                index,
                                all[(start * 7 + index * 3 + 5) % all.len()],
                            );
                        }
                        for fpcr in controls() {
                            let mut initial = GuestState {
                                fpcr,
                                fpsr: 0x0800_0000,
                                ..GuestState::default()
                            };
                            initial.x[30] = RETURN;
                            initial.v[N as usize] = n;
                            initial.v[M as usize] = m;
                            initial.v[D as usize] = [0xdead_beef_0bad_f00d, 0xfeed_face_cafe_d00d];
                            let label =
                                alloc::format!("{word:08x} {n:x?} {m:x?} {fpcr:#x} {target:?}");
                            let must_inline = rounded(fpcr)
                                && !target.data_independent_timing()
                                && (0..lanes.max(1) as usize).all(|index| {
                                    !exits(
                                        operation,
                                        format,
                                        fpcr,
                                        lane(n, format, index),
                                        lane(m, format, index),
                                    )
                                });
                            let mut actual = initial.clone();
                            let exit = run(&code, &mut actual);
                            runs += 1;
                            if exit == PC.0 {
                                assert_eq!(actual, initial, "{label}");
                                assert!(!must_inline, "exited: {label}");
                                continue;
                            }
                            assert_eq!(exit, RETURN, "{label}");
                            inline += 1;
                            let mut expected = initial.clone();
                            let mut result = if lanes == 0 && fpcr & FPCR_NEP != 0 {
                                n
                            } else {
                                [0; 2]
                            };
                            for index in 0..lanes.max(1) as usize {
                                let outcome = floating::evaluate(
                                    format,
                                    operation,
                                    fpcr,
                                    lane(n, format, index),
                                    lane(m, format, index),
                                )
                                .expect("completed with traps");
                                expected.fpsr |= outcome.exceptions;
                                set_lane(&mut result, format, index, outcome.bits);
                            }
                            expected.v[D as usize] = result;
                            assert_eq!(actual, expected, "{label}");
                        }
                    }
                }
            }
        }
    }
    assert!(inline > runs / 3, "{inline} of {runs} inline");
}
