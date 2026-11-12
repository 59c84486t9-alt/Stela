//! S/D FDIV with zero divisors and S/D FCMEQ/FCMGE/FCMGT/FACGE/FACGT and
//! the comparisons with zero over every input class, against the Arm
//! reference, compiled as blocks for every tier this host has: every inline
//! completion matches the reference in every V register and FPSR, every
//! exit leaves the state unchanged, a finite normal dividend over a zero
//! divisor completes with DZC, and every comparison completes without an
//! exit where AH and the trap enables are clear.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        self, BinaryOperation, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ,
        FPCR_NEP, FPCR_ROUNDING_SHIFT, Format, comparison::Predicate,
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

fn controls() -> [u32; 8] {
    [
        0,
        2 << FPCR_ROUNDING_SHIFT,
        FPCR_FZ,
        FPCR_FIZ,
        FPCR_DN,
        FPCR_FZ | FPCR_NEP,
        FPCR_AH,
        FPCR_EXCEPTION_ENABLE_MASK,
    ]
}

/// Zeros, subnormals, normals, infinities, quiet and signalling NaNs (both
/// signs).
fn floats(format: Format) -> Vec<u64> {
    let fraction_bits = format.fraction_bits();
    let infinity = format.exponent_mask();
    let quiet = 1u64 << (fraction_bits - 1);
    let one = u64::from(format.exponent_bias()) << fraction_bits;
    let mut values = vec![
        0,
        1,
        quiet,
        1 << fraction_bits,
        one,
        one + 1,
        3 * one / 2,
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

/// The comparison word (`zero`: against #0) and whether it is one.
fn compare_word(predicate: Predicate, zero: bool, format: Format, lanes: u32) -> u32 {
    let double = u32::from(format == Format::Double);
    let base = match (predicate, zero) {
        (Predicate::Equal, false) => 0x0e20_e400,
        (Predicate::GreaterEqual, false) => 0x2e20_e400,
        (Predicate::Greater, false) => 0x2ea0_e400,
        (Predicate::AbsoluteGreaterEqual, false) => 0x2e20_ec00,
        (Predicate::AbsoluteGreater, false) => 0x2ea0_ec00,
        (Predicate::Equal, true) => 0x0ea0_d800,
        (Predicate::GreaterEqual, true) => 0x2ea0_c800,
        (Predicate::Greater, true) => 0x0ea0_c800,
        (Predicate::LessEqual, true) => 0x2ea0_d800,
        (Predicate::Less, true) => 0x0ea0_e800,
        _ => unreachable!("listed forms"),
    };
    let shape = if lanes == 0 {
        0x5000_0000
    } else {
        u32::from(lanes * format.bits() == 128) << 30
    };
    let registers = if zero {
        N << 5 | D
    } else {
        M << 16 | N << 5 | D
    };
    base | shape | double << 22 | registers
}

fn divide_word(format: Format, lanes: u32) -> u32 {
    let double = u32::from(format == Format::Double);
    let registers = M << 16 | N << 5 | D;
    if lanes == 0 {
        return 0x1e20_1800 | double << 22 | registers;
    }
    0x2e20_fc00 | u32::from(lanes * format.bits() == 128) << 30 | double << 22 | registers
}

#[allow(clippy::too_many_arguments)]
fn check(
    word: u32,
    target: TargetCpu,
    format: Format,
    lanes: u32,
    initial: &GuestState,
    reference: impl Fn(u64, u64) -> Option<floating::Outcome>,
    merge: Option<[u64; 2]>,
    must_inline: bool,
    runs: &mut usize,
) {
    let code = compile(word, target);
    let mut actual = initial.clone();
    let exit = run(&code, &mut actual);
    *runs += 1;
    let label = alloc::format!(
        "{word:08x} {:x?} {:x?} {:#x} {target:?}",
        initial.v[N as usize],
        initial.v[M as usize],
        initial.fpcr
    );
    if exit == PC.0 {
        assert_eq!(&actual, initial, "{label}");
        assert!(!must_inline, "exited: {label}");
        return;
    }
    assert_eq!(exit, RETURN, "{label}");
    let mut expected = initial.clone();
    let mut result = merge.unwrap_or([0; 2]);
    for index in 0..lanes.max(1) as usize {
        let outcome = reference(
            lane(initial.v[N as usize], format, index),
            lane(initial.v[M as usize], format, index),
        )
        .expect("completed with traps");
        expected.fpsr |= outcome.exceptions;
        set_lane(&mut result, format, index, outcome.bits);
    }
    expected.v[D as usize] = result;
    assert_eq!(actual, expected, "{label}");
}

fn shapes(format: Format) -> &'static [u32] {
    if format == Format::Double {
        &[0, 2]
    } else {
        &[0, 2, 4]
    }
}

#[test]
fn zero_divisors_complete_with_divide_by_zero() {
    let mut runs = 0;
    for target in targets() {
        for format in [Format::Single, Format::Double] {
            let one = u64::from(format.exponent_bias()) << format.fraction_bits();
            let sign = format.sign_mask();
            let dividends = [one, (3 * one / 2) | sign, 0, sign];
            for &lanes in shapes(format) {
                let word = divide_word(format, lanes);
                for (start, _) in dividends.iter().enumerate() {
                    let mut n = [0; 2];
                    let mut m = [0; 2];
                    for index in 0..lanes.max(1) as usize {
                        set_lane(&mut n, format, index, dividends[(start + index) % 4]);
                        // Zero divisors of both signs, and normal ones.
                        let divisor = [0, sign, one, 0][(start + 2 * index) % 4];
                        set_lane(&mut m, format, index, divisor);
                    }
                    let zero_over_zero = (0..lanes.max(1) as usize).any(|index| {
                        lane(n, format, index) & !sign == 0 && lane(m, format, index) & !sign == 0
                    });
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
                        let merge = (lanes == 0 && fpcr & FPCR_NEP != 0).then_some(n);
                        let must_inline = !zero_over_zero
                            && fpcr & FPCR_EXCEPTION_ENABLE_MASK == 0
                            && !target.data_independent_timing();
                        check(
                            word,
                            target,
                            format,
                            lanes,
                            &initial,
                            |left, right| {
                                floating::evaluate(
                                    format,
                                    BinaryOperation::Divide,
                                    fpcr,
                                    left,
                                    right,
                                )
                                .ok()
                            },
                            merge,
                            must_inline,
                            &mut runs,
                        );
                    }
                }
            }
        }
    }
    assert!(runs > 0);
}

#[test]
fn float_comparisons_complete_inline() {
    use Predicate::*;
    let mut runs = 0;
    let forms = [
        (Equal, false),
        (GreaterEqual, false),
        (Greater, false),
        (AbsoluteGreaterEqual, false),
        (AbsoluteGreater, false),
        (Equal, true),
        (GreaterEqual, true),
        (Greater, true),
        (LessEqual, true),
        (Less, true),
    ];
    for target in targets() {
        for format in [Format::Single, Format::Double] {
            let all = floats(format);
            for &lanes in shapes(format) {
                for (predicate, zero) in forms {
                    let word = compare_word(predicate, zero, format, lanes);
                    for start in 0..all.len() {
                        let mut n = [0x5a5a_a5a5_3c3c_c3c3u64, 0x0123_4567_89ab_cdef];
                        let mut m = [0x7654_3210_fedc_ba98u64, 0xc3c3_3c3c_a5a5_5a5a];
                        for index in 0..lanes.max(1) as usize {
                            set_lane(&mut n, format, index, all[(start + index) % all.len()]);
                            set_lane(
                                &mut m,
                                format,
                                index,
                                all[(start * 5 + index + 3) % all.len()],
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
                            let merge = (lanes == 0 && !zero && fpcr & FPCR_NEP != 0).then_some(m);
                            let must_inline = fpcr & (FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK) == 0;
                            check(
                                word,
                                target,
                                format,
                                lanes,
                                &initial,
                                |left, right| {
                                    let right = if zero { 0 } else { right };
                                    floating::comparison::predicate(
                                        format, predicate, fpcr, left, right,
                                    )
                                    .ok()
                                },
                                merge,
                                must_inline,
                                &mut runs,
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(runs > 0);
}
