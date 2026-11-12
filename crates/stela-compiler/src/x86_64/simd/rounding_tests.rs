//! S/D FRINTN, FRINTA, FRINTP, FRINTM, FRINTZ, FRINTI and FRINTX over every
//! input class against the Arm reference, compiled as blocks for every tier
//! this host has: every inline completion matches the reference in every V
//! register and FPSR, every exit leaves the state unchanged, and on SSE4.1
//! hosts with AH and the trap enables clear every lane set without a NaN
//! completes inline, infinities and subnormals (flushed under FZ or FIZ)
//! included.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_NEP,
        FPCR_ROUNDING_SHIFT, Format,
        rounding::{self, RoundingOperation},
    },
    block::{BlockProfile, CompilationPlan},
    x86_64::native::run,
};
use alloc::{vec, vec::Vec};

const PC: GuestAddress = GuestAddress(0x1000_0000);
const RETURN: u64 = 0x4000;
const D: u32 = 3;
const N: u32 = 4;

fn targets() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    [
        TargetCpu::Baseline,
        TargetCpu::Sse41,
        TargetCpu::X86_64_V2,
        TargetCpu::X86_64_V3,
        TargetCpu::X86_64_V4,
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

/// Zeros, subnormals, fractions and ties, integers, values past the last
/// fraction bit, the largest finite value, infinities and NaNs, both signs.
fn floats(format: Format) -> Vec<u64> {
    let fraction_bits = format.fraction_bits();
    let bias = u64::from(format.exponent_bias());
    let one = bias << fraction_bits;
    let half = (bias - 1) << fraction_bits;
    let infinity = format.exponent_mask();
    let mut values = vec![
        0,
        1,
        (1 << fraction_bits) - 1,
        1 << fraction_bits,
        half,
        half + 1,
        one,
        one | 1 << (fraction_bits - 1),                         // 1.5
        (bias + 1) << fraction_bits | 1 << (fraction_bits - 2), // 2.5
        (bias + u64::from(fraction_bits)) << fraction_bits | 1,
        infinity - 1,
        infinity,
        infinity | 1 << (fraction_bits - 1),
        infinity | 1,
    ];
    let positive = values.len();
    for index in 0..positive {
        values.push(values[index] | format.sign_mask());
    }
    values
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

/// The word of `operation` for `format` with `lanes` (zero: scalar).
fn word(operation: RoundingOperation, format: Format, lanes: u32) -> u32 {
    let double = u32::from(format == Format::Double);
    let registers = N << 5 | D;
    if lanes == 0 {
        let rmode = match operation {
            RoundingOperation::NearestEven => 0,
            RoundingOperation::TowardPositive => 1,
            RoundingOperation::TowardNegative => 2,
            RoundingOperation::TowardZero => 3,
            RoundingOperation::NearestAway => 4,
            RoundingOperation::CurrentExact => 6,
            _ => 7,
        };
        return 0x1e24_4000 | double << 22 | rmode << 15 | registers;
    }
    let base = match operation {
        RoundingOperation::NearestEven => 0x0e21_8800,
        RoundingOperation::TowardNegative => 0x0e21_9800,
        RoundingOperation::TowardPositive => 0x0ea1_8800,
        RoundingOperation::TowardZero => 0x0ea1_9800,
        RoundingOperation::NearestAway => 0x2e21_8800,
        RoundingOperation::CurrentExact => 0x2e21_9800,
        _ => 0x2ea1_9800,
    };
    let q = u32::from(lanes * format.bits() == 128);
    base | q << 30 | double << 22 | registers
}

#[test]
fn special_lanes_round_inline() {
    let operations = [
        RoundingOperation::NearestEven,
        RoundingOperation::NearestAway,
        RoundingOperation::TowardPositive,
        RoundingOperation::TowardNegative,
        RoundingOperation::TowardZero,
        RoundingOperation::Current,
        RoundingOperation::CurrentExact,
    ];
    let controls = [
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
    ];
    let mut runs = 0;
    let mut inline = 0;
    for target in targets() {
        let checked = target.supports(TargetCpu::Sse41);
        for operation in operations {
            for format in [Format::Single, Format::Double] {
                let shapes: &[u32] = if format == Format::Double {
                    &[0, 2]
                } else {
                    &[0, 2, 4]
                };
                for &lanes in shapes {
                    let code = compile(word(operation, format, lanes), target);
                    let all = floats(format);
                    let count = lanes.max(1) as usize;
                    for start in 0..all.len() {
                        let mut n = [0x0123_4567_89ab_cdef, 0x0fed_cba9_8765_4321];
                        for index in 0..count {
                            set_lane(&mut n, format, index, all[(start + index * 5) % all.len()]);
                        }
                        let nan = (0..count).any(|index| {
                            lane(n, format, index) & !format.sign_mask() > format.exponent_mask()
                        });
                        for fpcr in controls {
                            let mut initial = GuestState {
                                fpcr,
                                fpsr: 0x0800_0000,
                                ..GuestState::default()
                            };
                            initial.x[30] = RETURN;
                            initial.v[N as usize] = n;
                            initial.v[D as usize] = [0xdead_beef_0bad_f00d, 0xfeed_face_cafe_d00d];
                            let label = alloc::format!(
                                "{operation:?} {format:?} {lanes} {n:x?} {fpcr:#x} {target:?}"
                            );
                            let must_inline = checked
                                && !nan
                                && fpcr & (FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK) == 0;
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
                                initial.v[D as usize]
                            } else {
                                [0; 2]
                            };
                            for index in 0..count {
                                let outcome = rounding::evaluate(
                                    format,
                                    operation,
                                    fpcr,
                                    lane(n, format, index),
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
