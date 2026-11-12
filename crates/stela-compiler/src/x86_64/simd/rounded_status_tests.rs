//! S/D FADD, FSUB, FMUL, FDIV, FABD, FMULX, FNMUL and (with FMA3) FMLA,
//! FMLS and FMADD over subnormal, tiny, overflowing and special inputs
//! against the Arm reference, compiled as blocks for every tier this host
//! has: every inline completion matches the reference in every V register
//! and FPSR, every exit leaves the state unchanged, and with FZ, FIZ, AH
//! and the trap enables clear (FZ and FIZ flushing inputs inline), every
//! binary lane set completes inline, NaN
//! propagation, invalid operations, subnormal inputs and results, UFC, OFC
//! and DZC included, but for FMULX's infinity times zero and a minimum
//! normal quotient; FMA lanes complete likewise but for a quiet NaN
//! addend with a NaN product and a minimum normal result. Under FZ a
//! result Arm flushes to zero takes the helper.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        self, BinaryOperation, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ,
        FPCR_NEP, FPCR_ROUNDING_SHIFT, Format, fused::FusedOperation,
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
const A: u32 = 12;

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

/// FPCR whose operations complete inline but for the lanes [`exits`]
/// and the fused test list.
fn rounded(fpcr: u32) -> bool {
    fpcr & (FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK) == 0
}

/// Under FZ, whether Arm flushes the result (UFC) or the host's result
/// with the inputs flushed is the minimum normal: those lanes take the
/// helper.
fn flushed_output(format: Format, fpcr: u32, exceptions: u32, unflushed: u64) -> bool {
    let magnitude = unflushed & !format.sign_mask();
    fpcr & FPCR_FZ != 0
        && (exceptions & floating::UNDERFLOW != 0 || magnitude == 1 << format.fraction_bits())
}

/// FPCR with FZ's input flushing but no output flushing.
fn input_flushing(fpcr: u32) -> u32 {
    if fpcr & FPCR_FZ != 0 {
        fpcr & !FPCR_FZ | FPCR_FIZ
    } else {
        fpcr
    }
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

/// Whether a lane may exit: FMULX's infinity times zero (two on Arm, for
/// which the host raises invalid), or a minimum normal quotient (the host
/// may find its tininess after rounding).
fn exits(operation: BinaryOperation, format: Format, fpcr: u32, left: u64, right: u64) -> bool {
    let magnitude = |bits: u64| bits & !format.sign_mask();
    let special = |a: u64, b: u64| magnitude(a) == 0 && magnitude(b) == format.exponent_mask();
    (operation == BinaryOperation::MultiplyExtended
        && (special(left, right) || special(right, left)))
        || operation == BinaryOperation::Divide
            && floating::evaluate(format, operation, fpcr, left, right)
                .is_ok_and(|outcome| magnitude(outcome.bits) == 1 << format.fraction_bits())
        || floating::evaluate(format, operation, fpcr, left, right).is_ok_and(|outcome| {
            floating::evaluate(format, operation, input_flushing(fpcr), left, right).is_ok_and(
                |unflushed| flushed_output(format, fpcr, outcome.exceptions, unflushed.bits),
            )
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

#[derive(Clone, Copy, Debug)]
enum Form {
    /// FMLA (false) or FMLS (true) by vector, lanes.
    Vector(bool, u32),
    /// FMLA by element 1 of Vm, lanes.
    Element(u32),
    /// FMADD.
    Scalar,
}

fn fused_word(form: Form, format: Format) -> u32 {
    let double = u32::from(format == Format::Double);
    let q = |lanes: u32| u32::from(lanes * format.bits() == 128);
    match form {
        Form::Vector(subtract, lanes) => {
            0x0e20_cc00
                | q(lanes) << 30
                | u32::from(subtract) << 23
                | double << 22
                | M << 16
                | N << 5
                | D
        }
        Form::Element(lanes) => {
            // Element 1: H:L = 0:1 for S, H = 1 for D.
            let index = if double == 1 { 1 << 11 } else { 1 << 21 };
            0x0f80_1000 | q(lanes) << 30 | double << 22 | index | M << 16 | N << 5 | D
        }
        Form::Scalar => 0x1f00_0000 | double << 22 | M << 16 | A << 10 | N << 5 | D,
    }
}

/// The lanes of `form` as (operation, addend, left, right) per lane.
fn fused_lanes(
    form: Form,
    format: Format,
    state: &GuestState,
) -> Vec<(FusedOperation, u64, u64, u64)> {
    let (operation, lanes) = match form {
        Form::Vector(true, lanes) => (FusedOperation::Subtract, lanes),
        Form::Vector(false, lanes) | Form::Element(lanes) => (FusedOperation::Add, lanes),
        Form::Scalar => (FusedOperation::Add, 1),
    };
    let addend = match form {
        Form::Scalar => state.v[A as usize],
        _ => state.v[D as usize],
    };
    (0..lanes as usize)
        .map(|index| {
            let right = match form {
                Form::Element(_) => lane(state.v[M as usize], format, 1),
                _ => lane(state.v[M as usize], format, index),
            };
            (
                operation,
                lane(addend, format, index),
                lane(state.v[N as usize], format, index),
                right,
            )
        })
        .collect()
}

#[test]
fn fused_operations_complete_subnormal_and_tiny_lanes_inline() {
    let mut runs = 0;
    let mut inline = 0;
    for target in targets() {
        let fma = target.supports(TargetCpu::Fma) && !target.data_independent_timing();
        for format in [Format::Single, Format::Double] {
            let all = floats(format);
            let lanes = if format == Format::Double { 2 } else { 4 };
            let forms = [
                Form::Vector(false, lanes),
                Form::Vector(true, lanes),
                Form::Vector(false, 2),
                Form::Element(lanes),
                Form::Scalar,
            ];
            for form in forms {
                let code = compile(fused_word(form, format), target);
                for start in 0..all.len() {
                    let mut vectors = [[0u64; 2]; 3];
                    let count = match form {
                        Form::Vector(_, count) | Form::Element(count) => count,
                        Form::Scalar => 1,
                    };
                    for index in 0..count as usize {
                        for (which, vector) in vectors.iter_mut().enumerate() {
                            let position =
                                start * (which + 1) + index * (2 * which + 1) + which * 4;
                            set_lane(vector, format, index, all[position % all.len()]);
                        }
                    }
                    if matches!(form, Form::Element(_)) {
                        // Element 1 of Vm takes every class in turn.
                        set_lane(&mut vectors[2], format, 1, all[(start * 3 + 1) % all.len()]);
                    }
                    for fpcr in controls() {
                        let mut initial = GuestState {
                            fpcr,
                            fpsr: 0x0800_0000,
                            ..GuestState::default()
                        };
                        initial.x[30] = RETURN;
                        initial.v[D as usize] = vectors[0];
                        initial.v[A as usize] = vectors[0];
                        initial.v[N as usize] = vectors[1];
                        initial.v[M as usize] = vectors[2];
                        let label =
                            alloc::format!("{form:?} {format:?} {vectors:x?} {fpcr:#x} {target:?}");
                        let lanes = fused_lanes(form, format, &initial);
                        // A quiet NaN addend with a NaN product (Arm's
                        // default NaN for infinity times zero) and a minimum
                        // normal result (the host may find its tininess
                        // after rounding) take the helper.
                        let must_inline = fma
                            && rounded(fpcr)
                            && lanes.iter().all(|&(operation, addend, left, right)| {
                                let magnitude = |bits: u64| bits & !format.sign_mask();
                                let infinity = format.exponent_mask();
                                let quiet = 1 << (format.fraction_bits() - 1);
                                let invalid_product = is_nan(format, left)
                                    || is_nan(format, right)
                                    || magnitude(left) == 0 && magnitude(right) == infinity
                                    || magnitude(left) == infinity && magnitude(right) == 0;
                                !(is_nan(format, addend) && addend & quiet != 0 && invalid_product)
                                    && floating::fused::evaluate(
                                        format, operation, fpcr, addend, left, right,
                                    )
                                    .is_ok_and(|outcome| {
                                        magnitude(outcome.bits) != 1 << format.fraction_bits()
                                    })
                                    && !flushed_output(
                                        format,
                                        fpcr,
                                        floating::fused::evaluate(
                                            format, operation, fpcr, addend, left, right,
                                        )
                                        .map_or(0, |outcome| outcome.exceptions),
                                        floating::fused::evaluate(
                                            format,
                                            operation,
                                            input_flushing(fpcr),
                                            addend,
                                            left,
                                            right,
                                        )
                                        .map_or(0, |outcome| outcome.bits),
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
                        let mut result = if matches!(form, Form::Scalar) && fpcr & FPCR_NEP != 0 {
                            initial.v[A as usize]
                        } else {
                            [0; 2]
                        };
                        for (index, &(operation, addend, left, right)) in lanes.iter().enumerate() {
                            let outcome = floating::fused::evaluate(
                                format, operation, fpcr, addend, left, right,
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
    assert!(inline > runs / 8, "{inline} of {runs} inline");
}

/// An inexact result that rounds up to the minimum normal is tiny before
/// rounding for Arm (UFC with AH clear), but a host's FMA and CVTSD2SS may
/// find it tiny after rounding and raise no underflow. FDIV, FMSUB and
/// FCVT D to S take the helper for that one value on every tier
/// (intentionally: one result value), leaving the state unchanged.
#[test]
fn minimum_normal_results_take_the_helper() {
    let below = 0x00ff_ffffu64; // 2^-125 (1 - 2^-24)
    let two = 0x4000_0000u64;
    let minimum = 0x0080_0000u64;
    let cases: [(u32, [u64; 3]); 3] = [
        // FDIV S3, S4, S17: 2^-126 - 2^-150 rounds to 2^-126.
        (0x1e20_1800 | M << 16 | N << 5 | D, [below, two, 0]),
        // FMSUB S3, S4, S17, S12: 2^-126 - 2^-252 rounds to 2^-126.
        (
            0x1f00_8000 | M << 16 | A << 10 | N << 5 | D,
            [minimum, minimum, minimum],
        ),
        // FCVT S3, D4 of a Double just below 2^-126.
        (0x1e62_4000 | N << 5 | D, [0x380f_ffff_ffff_ffff, 0, 0]),
    ];
    for target in targets() {
        for &(word, [n, m, a]) in &cases {
            let code = compile(word, target);
            let mut initial = GuestState::default();
            initial.x[30] = RETURN;
            initial.v[N as usize] = [n, 0];
            initial.v[M as usize] = [m, 0];
            initial.v[A as usize] = [a, 0];
            let mut actual = initial.clone();
            assert_eq!(run(&code, &mut actual), PC.0, "{word:08x} {target:?}");
            assert_eq!(actual, initial, "{word:08x} {target:?}");
        }
    }
    // The helper's result: the minimum normal with UFC and IXC.
    let outcome =
        floating::evaluate(Format::Single, BinaryOperation::Divide, 0, below, two).unwrap();
    assert_eq!(outcome.bits, minimum);
    assert_eq!(outcome.exceptions, floating::UNDERFLOW | floating::INEXACT);
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Binary(BinaryOperation),
    Fused(FusedOperation),
}

/// A word, its operation, and whether it is a vector of every lane (else
/// lane 0 alone).
type Case = (u32, Kind, bool);

/// Run `word` with Vn, Vm and Va (and Vd, the vector addend) holding
/// `left`, `right` and `addend` in every lane or lane 0. Returns the exit,
/// the initial, actual and expected states.
fn run_lanes(
    target: TargetCpu,
    (word, kind, vector): Case,
    format: Format,
    fpcr: u32,
    [left, right, addend]: [u64; 3],
) -> (u64, GuestState, GuestState, GuestState) {
    let lanes = if !vector {
        1
    } else if format == Format::Double {
        2
    } else {
        4
    };
    let mut initial = GuestState {
        fpcr,
        ..GuestState::default()
    };
    initial.x[30] = RETURN;
    for index in 0..lanes {
        set_lane(&mut initial.v[N as usize], format, index, left);
        set_lane(&mut initial.v[M as usize], format, index, right);
        set_lane(&mut initial.v[A as usize], format, index, addend);
        set_lane(&mut initial.v[D as usize], format, index, addend);
    }
    let outcome = match kind {
        Kind::Fused(operation) => {
            floating::fused::evaluate(format, operation, fpcr, addend, left, right)
        }
        Kind::Binary(operation) => floating::evaluate(format, operation, fpcr, left, right),
    }
    .unwrap();
    let mut expected = initial.clone();
    expected.fpsr |= outcome.exceptions;
    let mut result = [0u64; 2];
    for index in 0..lanes {
        set_lane(&mut result, format, index, outcome.bits);
    }
    expected.v[D as usize] = result;
    let mut actual = initial.clone();
    let exit = run(&compile(word, target), &mut actual);
    (exit, initial, actual, expected)
}

/// Arm negates the product operand Vn of FMLS, FMSUB and FNMADD and the
/// addend of FNMADD and FNMSUB before FPProcessNaNs, so a NaN there
/// propagates with its sign flipped (quieted, or the default NaN under DN),
/// in the order addend, Vn, Vm with signaling NaNs first. On an FMA tier
/// every NaN lane completes inline but for a quiet NaN addend with a NaN
/// product, which takes the helper.
#[test]
fn fused_nan_operands_keep_arm_negation_signs() {
    for target in targets() {
        if !target.supports(TargetCpu::Fma) || target.data_independent_timing() {
            continue;
        }
        for format in [Format::Single, Format::Double] {
            let fraction_bits = format.fraction_bits();
            let infinity = format.exponent_mask();
            let quiet = 1u64 << (fraction_bits - 1);
            let sign = format.sign_mask();
            let nans = [
                infinity | quiet | 5,
                infinity | 7,
                sign | infinity | quiet | 9,
                sign | infinity | 3,
            ];
            let ordinary = u64::from(format.exponent_bias()) << fraction_bits | quiet;
            let double = u32::from(format == Format::Double);
            let scalar = |base: u32| base | double << 22 | M << 16 | A << 10 | N << 5 | D;
            let cases: [Case; 5] = [
                (scalar(0x1f00_0000), Kind::Fused(FusedOperation::Add), false),
                (
                    scalar(0x1f00_8000),
                    Kind::Fused(FusedOperation::Subtract),
                    false,
                ),
                (
                    scalar(0x1f20_0000),
                    Kind::Fused(FusedOperation::NegatedAdd),
                    false,
                ),
                (
                    scalar(0x1f20_8000),
                    Kind::Fused(FusedOperation::NegatedSubtract),
                    false,
                ),
                (
                    fused_word(Form::Vector(true, 128 / format.bits()), format),
                    Kind::Fused(FusedOperation::Subtract),
                    true,
                ),
            ];
            for case in cases {
                for fpcr in [0, FPCR_DN] {
                    for (first, &nan) in nans.iter().enumerate() {
                        for position in 0..3 {
                            // One NaN, then a second NaN in the next position.
                            for second in [None, Some(nans[(first + 1) % 4])] {
                                let mut inputs = [ordinary; 3];
                                inputs[position] = nan;
                                if let Some(other) = second {
                                    inputs[(position + 1) % 3] = other;
                                }
                                let [left, right, addend] = inputs;
                                let (exit, initial, actual, expected) =
                                    run_lanes(target, case, format, fpcr, inputs);
                                let label = alloc::format!(
                                    "{case:x?} {format:?} {inputs:x?} {fpcr:#x} {target:?}"
                                );
                                let helper = addend & quiet != 0
                                    && is_nan(format, addend)
                                    && (is_nan(format, left) || is_nan(format, right));
                                if helper {
                                    assert_eq!(exit, PC.0, "{label}");
                                    assert_eq!(actual, initial, "{label}");
                                    continue;
                                }
                                assert_eq!(exit, RETURN, "{label}");
                                assert_eq!(actual, expected, "{label}");
                            }
                        }
                    }
                }
            }
            // The flipped sign itself, apart from the reference: FMSUB of a
            // positive quiet NaN Vn gives the negative NaN.
            let (exit, _, actual, _) =
                run_lanes(target, cases[1], format, 0, [nans[0], ordinary, ordinary]);
            assert_eq!(exit, RETURN);
            assert_eq!(lane(actual.v[D as usize], format, 0), nans[0] | sign);
        }
    }
}

/// FZ (with IDC) and FIZ (without) flush subnormal inputs inline, ahead of
/// NaN and division-by-zero handling; under FIZ an inexact subnormal result stays
/// inline with UFC, while under FZ a result Arm flushes takes the helper,
/// leaving the state unchanged.
#[test]
fn flushed_inputs_complete_inline_and_flushed_results_exit() {
    const SUBNORMAL: u64 = 0x0000_0003;
    const MINIMUM_ODD: u64 = 0x0080_0001;
    const HALF: u64 = 0x3f00_0000;
    const ONE: u64 = 0x3f80_0000;
    const QUIET_NAN: u64 = 0x7fc0_0001;
    let registers = M << 16 | N << 5 | D;
    let add = (
        1 << 30 | 0x0e20_d400 | registers,
        Kind::Binary(BinaryOperation::Add),
        true,
    );
    let divide = (
        1 << 30 | 0x2e20_fc00 | registers,
        Kind::Binary(BinaryOperation::Divide),
        true,
    );
    let multiply = (
        0x1e20_0800 | registers,
        Kind::Binary(BinaryOperation::Multiply),
        false,
    );
    let fmla = (
        fused_word(Form::Vector(false, 4), Format::Single),
        Kind::Fused(FusedOperation::Add),
        true,
    );
    // (case, fpcr, [left, right, addend], completes inline).
    let table: [(Case, u32, [u64; 3], bool); 8] = [
        (add, FPCR_FZ, [SUBNORMAL, ONE, 0], true),
        (add, FPCR_FIZ, [ONE, SUBNORMAL | 1 << 31, 0], true),
        // 1 / flushed 0: the infinity with DZC and IDC.
        (divide, FPCR_FZ, [ONE, SUBNORMAL, 0], true),
        // A NaN beside a flushed input: the NaN, with IDC.
        (add, FPCR_FZ, [QUIET_NAN, SUBNORMAL, 0], true),
        // An inexact subnormal product: UFC under FIZ, flushed under FZ.
        (multiply, FPCR_FIZ, [MINIMUM_ODD, HALF, 0], true),
        (multiply, FPCR_FZ, [MINIMUM_ODD, HALF, 0], false),
        // A flushed addend beside a normal product.
        (fmla, FPCR_FZ, [ONE, HALF, SUBNORMAL], true),
        // A product Arm flushes to zero.
        (fmla, FPCR_FZ, [MINIMUM_ODD, HALF, 0], false),
    ];
    for target in targets() {
        let fma = target.supports(TargetCpu::Fma) && !target.data_independent_timing();
        for (row, &(case, fpcr, inputs, inline)) in table.iter().enumerate() {
            if matches!(case.1, Kind::Fused(_)) && !fma {
                continue;
            }
            let label = alloc::format!("row {row} {:08x} {fpcr:#x} {target:?}", case.0);
            let (exit, initial, actual, expected) =
                run_lanes(target, case, Format::Single, fpcr, inputs);
            if !inline {
                assert_eq!(exit, PC.0, "{label}");
                assert_eq!(actual, initial, "{label}");
                continue;
            }
            assert_eq!(exit, RETURN, "{label}");
            let subnormal = inputs.iter().any(|&bits| bits & 0x7fff_ffff == SUBNORMAL);
            assert_eq!(
                actual.fpsr & floating::INPUT_DENORMAL != 0,
                subnormal && fpcr & FPCR_FZ != 0,
                "{label}"
            );
            assert_eq!(actual, expected, "{label}");
        }
    }
}
