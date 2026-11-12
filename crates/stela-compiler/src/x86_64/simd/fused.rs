//! Fused multiply-add: FMA3 when available, otherwise an exact-product SSE2 path.
use super::super::isa::ShiftOpcode;
use super::numerical::{
    ArithmeticOpcode, ColdSplit, Condition, Entry, FPSR_UNDERFLOW, FusedOpcode,
    INPUT_MINIMUM_EXPONENT, Input, MXCSR_UNDERFLOW, NanRegisters, RESULT_MINIMUM_EXPONENT,
    Rounding, ZeroProduct, active_lanes, branch, capture_environment_status,
    clear_environment_status, clear_scalar, commit_flush_status, commit_inexact,
    commit_invalid_lanes, commit_rounded_status, emit_fma, emit_opcode, environment,
    environment_directed, float_lanes, flush_subnormal_lanes, jump, merge_nans,
    minimum_normal_lanes, prepare_vector_input_range, prepare_vector_result_range, quiet_lanes,
    read_inputs, read_numerical_right, read_numerical_vector, reject_exceptional_lanes,
    reject_other_status, reject_product_status, resolve, restore_environment,
    restore_environment_with_product, save_product_status, scalar_ordered_range, select_input_nans,
    small_lanes, special_lanes, sticky_inexact, sticky_result_check, subnormal_lanes, test_control,
    vector_ordered_range, zero_product_check,
};
use super::{Host, commit, packed};
use crate::x86_64::asm::{Alu, Code, FloatOp, Gpr, Mem, Rm, Size};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_NEP, Format},
        simd::{arithmetic::Shape, fused::Operand},
    },
    block::ExitKind,
};
use alloc::vec;
use alloc::vec::Vec;
mod half;
#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests;
mod wide_half;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const SIGN_MASK: u8 = 2;
const ADDEND: u8 = 6;
const ORIGINAL_ADDEND: u8 = 7;
/// The zero classifier's scratch: the scalar-only original addend's register.
const ZERO_RANGE_SCRATCH: u8 = ORIGINAL_ADDEND;
/// [`flush_subnormal_lanes`]' scratch, free before the input guards.
const FLUSH_SCRATCH: [u8; 4] = [2, 3, 4, 5];
/// [`select_input_nans`]' registers, which alias no source.
const NAN_REGISTERS: NanRegisters = NanRegisters {
    selected: 2,
    inputs: 3,
    invalid: 4,
    mask: 5,
    temporary: 7,
};
/// [`minimum_normal_lanes`]' scratch after [`merge_nans`].
const MINIMUM_SCRATCH: [u8; 2] = [2, 3];
/// [`small_lanes`]' scratch after [`merge_nans`], leaving its lanes where
/// [`minimum_normal_lanes`] does.
const SMALL_SCRATCH: [u8; 3] = [2, 3, 5];
/// The unordered compare predicate.
const UNORDERED: u8 = 3;
/// PSHUFD selector moving the high qword to the low.
const HIGH_QWORD: u8 = 0xee;
/// [`operand_special_lanes`]' result.
const SPECIAL_LANES: u8 = 2;

/// Flip the sign of the multiplicand and addend that FMLS, FMSUB, FNMADD
/// and FNMSUB negate (Arm's FPNeg, which flips a NaN's sign too); a
/// second call restores them. Clobbers NAN_REGISTERS.temporary.
fn negate_operands(code: &mut Code, operand: &Operand) {
    let negated = [
        (operand.operation.negate_left(), LEFT),
        (operand.operation.negate_addend(), ADDEND),
    ];
    if !negated.iter().any(|&(negate, _)| negate) {
        return;
    }
    let sign = NAN_REGISTERS.temporary;
    packed(code, Host::EqualDword, sign, sign);
    let shift = if operand.format == Format::Single {
        ShiftOpcode::LeftDword
    } else {
        ShiftOpcode::LeftQword
    };
    shift.emit(code, sign, (operand.format.bits() - 1) as u8);
    for (negate, source) in negated {
        if negate {
            packed(code, Host::Xor, source, sign);
        }
    }
}

fn emit_checked_fma(code: &mut Code, operand: &Operand, target: TargetCpu) {
    emit_fma(
        code,
        operand.format,
        operand.shape,
        FusedOpcode::from(operand.operation),
        target,
    );
}

fn prepare_right(code: &mut Code, operand: &Operand) {
    read_numerical_right(
        code,
        operand.format,
        operand.shape,
        operand.right,
        operand.right_lane,
    );
    if operand.shape == Shape::Vector64 && operand.right_lane.is_some() {
        // Inactive lanes multiply zeros, so an infinite element raises no
        // host invalid there.
        packed(code, Host::MoveQword, RIGHT, RIGHT);
    }
}

fn prepare_negation(code: &mut Code, operand: &Operand) -> u8 {
    let merge = if operand.shape == Shape::Scalar && operand.operation.negate_addend() {
        packed(code, Host::MoveAligned, ORIGINAL_ADDEND, ADDEND);
        ORIGINAL_ADDEND
    } else {
        ADDEND
    };
    if operand.operation.negate_addend() || operand.operation.negate_left() {
        packed(code, Host::EqualDword, SIGN_MASK, SIGN_MASK);
        let shift = if operand.format == Format::Single {
            ShiftOpcode::LeftDword
        } else {
            ShiftOpcode::LeftQword
        };
        shift.emit(code, SIGN_MASK, (operand.format.bits() - 1) as u8);
        if operand.operation.negate_left() {
            packed(code, Host::Xor, LEFT, SIGN_MASK);
        }
        if operand.operation.negate_addend() {
            packed(code, Host::Xor, ADDEND, SIGN_MASK);
        }
    }
    merge
}

/// With FMA3, S/D forms return their [`ColdSplit`].
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
    entry: Entry,
) -> Option<ColdSplit> {
    if operand.format == Format::Half {
        half::emit(code, operand, pc, target);
        return None;
    }
    let native_fma = target.supports(TargetCpu::Fma);
    let (mut helper, sticky) = if native_fma {
        let StickyPath {
            full,
            helper,
            done,
            mut crossing,
            cold,
            inline_end,
        } = sticky_path(code, operand, target, entry);
        let full_start = code.len();
        for &patch in &full {
            resolve(code, patch, full_start);
        }
        crossing.extend(full);
        (helper, Some((done, full_start, crossing, cold, inline_end)))
    } else {
        (Vec::new(), None)
    };
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    read_numerical_vector(code, operand.shape, operand.left, LEFT);
    read_numerical_vector(code, operand.shape, operand.addend, ADDEND);
    prepare_right(code, operand);
    // FZ or FIZ with AH clear flush subnormal inputs to their signed zeros
    // (FZ raising IDC, committed with the result); AH=1 keeps the helper.
    code.asm().alu(Alu::Xor, Size::Dword, Gpr::R11, Gpr::R11);
    if !native_fma {
        code.asm().alu(Alu::Xor, Size::Dword, Gpr::R10, Gpr::R10);
    }
    // With FMA3 and FZ, FIZ and AH clear, subnormal inputs and tiny,
    // overflowing and infinite results are exact: the host's single
    // unflushed rounding in Arm's mode is FPMulAdd's, and its status FPSR's
    // ([`commit_rounded_status`]). NaN lanes follow FPProcessNaNs3 over
    // the addend and the multiplicands, after FMLS, FMSUB and FNMADD negate
    // theirs ([`select_input_nans`]), and an invalid operation gives the
    // default NaN with IOC ([`merge_nans`]), also beside a quiet NaN
    // addend, where Arm does not propagate the addend. A minimum normal
    // result takes the helper. Without FMA3, lanes with an infinite or NaN
    // operand (AH clear) complete apart from the exact-product path's
    // ([`clear_special_lanes`], [`special_results`]).
    test_control(code, FPCR_AH);
    let alternative = branch(code, Condition::NotZero);
    test_control(code, FPCR_FZ | FPCR_FIZ);
    let unflushed = branch(code, Condition::Zero);
    for source in [LEFT, RIGHT, ADDEND] {
        flush_subnormal_lanes(code, operand.format, operand.shape, source, FLUSH_SCRATCH);
    }
    let flushed = code.len();
    resolve(code, unflushed, flushed);
    let rounded = native_fma.then(|| {
        environment(code);
        negate_operands(code, operand);
        select_input_nans(
            code,
            operand.format,
            operand.shape,
            &[ADDEND, LEFT, RIGHT],
            NAN_REGISTERS,
        );
        invalid_products_beside_quiet_nans(code, operand.format);
        code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax);
        // The product's status is not the guest's.
        clear_environment_status(code);
        negate_operands(code, operand);
        // The original Vn, for FZ's flush.
        code.asm().movq_from_xmm(Gpr::R8, LEFT);
        super::shuffle(code, NAN_REGISTERS.temporary, LEFT, HIGH_QWORD);
        code.asm().movq_from_xmm(Gpr::R9, NAN_REGISTERS.temporary);
        emit_checked_fma(code, operand, target);
        merge_nans(code, operand.format, operand.shape, LEFT, NAN_REGISTERS);
        // Under FZ, a result Arm flushes completes inline.
        test_control(code, FPCR_FZ);
        let unflushing = branch(code, Condition::Zero);
        flush_tiny_fused_results(code, operand, target);
        let flushed = jump(code);
        let minimum = code.len();
        resolve(code, unflushing, minimum);
        minimum_normal_lanes(code, operand.format, LEFT, MINIMUM_SCRATCH);
        Host::DwordSignMask.register(
            code,
            Gpr::Rcx as u8,
            MINIMUM_SCRATCH[0],
            TargetCpu::Baseline,
        );
        code.asm().alu(Alu::Or, Size::Dword, Gpr::Rax, Gpr::Rcx);
        let classified = code.len();
        resolve(code, flushed, classified);
        restore_environment(code);
        helper.push(reject_exceptional_lanes(
            code,
            operand.format,
            operand.shape,
        ));
        commit_flush_status(code);
        commit_invalid_lanes(code, operand.format, operand.shape, NAN_REGISTERS.invalid);
        commit_rounded_status(code);
        jump(code)
    });
    if !native_fma {
        clear_special_lanes(code, operand);
    }
    let strict = code.len();
    resolve(code, alternative, strict);
    if operand.shape != Shape::Scalar {
        prepare_vector_input_range(code, operand.format);
    }
    // A zero input or lane is exact on both sides: FPMulAdd and the host's
    // FMA follow IEEE 754's signed-zero sums under the installed rounding
    // (an exact zero sum is +0, -0 rounding toward minus infinity, and a sum
    // of two zeros of one sign keeps it), a zero product adds exactly, and
    // a zero is not subnormal, so FZ and FIZ flush nothing, and neither side
    // raises status for it. An infinite input is exact too: its result is an
    // infinity in every rounding mode, without status, unless it meets a zero
    // factor or an opposite infinity, which raise the host's invalid (the
    // separate product's too) and go to the helper; a finite product that
    // overflowed raised overflow. The SSE2 product's own status rejects any
    // rounding before the sum.
    for source in [LEFT, RIGHT, ADDEND] {
        if operand.shape == Shape::Scalar {
            helper.push(scalar_ordered_range(
                code,
                operand.format,
                source,
                INPUT_MINIMUM_EXPONENT,
            ));
        } else {
            vector_ordered_range(
                code,
                operand.format,
                operand.shape,
                source,
                ZERO_RANGE_SCRATCH,
            );
            helper.push(branch(code, Condition::NotZero));
        }
    }
    let merge = if native_fma {
        ADDEND
    } else {
        prepare_negation(code, operand)
    };
    environment(code);
    if native_fma {
        emit_checked_fma(code, operand, target);
        restore_environment(code);
    } else {
        emit_opcode(
            code,
            operand.format,
            operand.shape,
            ArithmeticOpcode::Multiply,
            RIGHT,
        );
        save_product_status(code);
        emit_opcode(
            code,
            operand.format,
            operand.shape,
            ArithmeticOpcode::Add,
            ADDEND,
        );
        restore_environment_with_product(code);
        // All host status and stack state are restored before either side exit.
        helper.push(reject_product_status(code));
    }
    helper.push(reject_other_status(code));
    if !native_fma {
        flush_exact_tiny_results(code, operand);
    }
    let success = if operand.shape == Shape::Scalar {
        // An exact zero result raised no status; a nonzero one rounded to
        // zero raised underflow, which went to the helper above.
        helper.push(scalar_ordered_range(
            code,
            operand.format,
            LEFT,
            RESULT_MINIMUM_EXPONENT,
        ));
        jump(code)
    } else {
        prepare_vector_result_range(code);
        // A zero result is exact: one that underflowed raised the host's
        // underflow status, which went to the helper above.
        vector_ordered_range(
            code,
            operand.format,
            operand.shape,
            LEFT,
            ZERO_RANGE_SCRATCH,
        );
        branch(code, Condition::Zero)
    };
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, success, success_start);
    commit_inexact(code);
    commit_flush_status(code);
    if !native_fma {
        special_results(code, operand, merge);
    }
    if let Some(rounded) = rounded {
        let tail = code.len();
        resolve(code, rounded, tail);
    }
    if operand.shape == Shape::Scalar {
        // Register MOVSS/MOVSD replaces only the result lane of A.
        if operand.format == Format::Single {
            Host::MoveScalarSingle
        } else {
            Host::MoveScalarDouble
        }
        .register(code, merge, LEFT, crate::TargetCpu::Baseline);
        test_control(code, FPCR_NEP);
        let merging = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, merge);
        let commit_start = code.len();
        resolve(code, merging, commit_start);
        commit(code, operand.destination, merge);
        // XMM0 holds the destination wherever the emission ends.
        packed(code, Host::MoveAligned, LEFT, merge);
    } else {
        if operand.shape == Shape::Vector64 {
            packed(code, Host::MoveQword, LEFT, LEFT);
        }
        commit(code, operand.destination, LEFT);
    }
    let (done, full, crossing, cold, inline_end) = sticky?;
    let end = code.len();
    resolve(code, done, end);
    Some(ColdSplit {
        cold,
        inline_end,
        full,
        crossing,
        result: operand.destination,
    })
}

/// With FMA3, FPCR.FZ set and AH clear, after [`merge_nans`] in the
/// private environment: Arm flushes a result whose exact value is nonzero
/// and below the minimum normal in magnitude to the zero of its sign, with
/// UFC alone. A lane can be tiny only if the host's result is nonzero and
/// at most the minimum normal, or it rounded to zero, raising the host's
/// underflow; then the operation runs again rounding up (U) and down (D)
/// from the original Vn, kept in R8 and R9: the exact value is tiny exactly
/// when the smaller of |U| and |D| is below the minimum normal and the
/// larger nonzero, and its sign is U's. Tiny lanes add UFC to R11D, take
/// that signed zero, and give up their host status: the operation runs a
/// last time in the control's rounding with their operands zero, for the
/// other lanes' status. Leaves the result in LEFT and EAX zero; clobbers
/// RIGHT, ADDEND's flushed lanes (a scalar's merge keeps its upper lanes),
/// XMM2, XMM3, XMM5, XMM7 and ECX.
fn flush_tiny_fused_results(code: &mut Code, operand: &Operand, target: TargetCpu) {
    const LESS: u8 = 1;
    const NOT_EQUAL: u8 = 4;
    const ORDERED: u8 = 7;
    const UP: u8 = 2;
    const DOWN: u8 = 3;
    const RESULT: u8 = 5;
    const VN: u8 = 7;
    let (format, shape) = (operand.format, operand.shape);
    let lanes = float_lanes(format, Shape::Vector128);
    let (left_shift, right_shift) = if format == Format::Double {
        (ShiftOpcode::LeftQword, ShiftOpcode::RightQword)
    } else {
        (ShiftOpcode::LeftDword, ShiftOpcode::RightDword)
    };
    let restore_vn = |code: &mut Code, xmm: u8, scratch: u8| {
        packed(code, Host::MoveGprQword, xmm, Gpr::R8 as u8);
        packed(code, Host::MoveGprQword, scratch, Gpr::R9 as u8);
        packed(code, Host::UnpackLowQword, xmm, scratch);
    };
    small_lanes(code, format, LEFT, SMALL_SCRATCH);
    active_lanes(code, shape, format, DOWN);
    packed(code, Host::And, SMALL_SCRATCH[0], DOWN);
    Host::DwordSignMask.register(code, Gpr::Rax as u8, SMALL_SCRATCH[0], TargetCpu::Baseline);
    capture_environment_status(code);
    code.asm()
        .alu_imm32(Alu::And, Size::Dword, Gpr::Rcx, MXCSR_UNDERFLOW as i32);
    code.asm().alu(Alu::Or, Size::Dword, Gpr::Rax, Gpr::Rcx);
    let exact = branch(code, Condition::Zero);
    packed(code, Host::MoveAligned, RESULT, LEFT);
    for (rounding, destination) in [(Rounding::Positive, UP), (Rounding::Negative, DOWN)] {
        restore_vn(code, LEFT, destination);
        environment_directed(code, rounding);
        emit_checked_fma(code, operand, target);
        packed(code, Host::MoveAligned, destination, LEFT);
    }
    // LEFT: U's sign; VN: the magnitude mask.
    packed(code, Host::EqualDword, LEFT, LEFT);
    left_shift.emit(code, LEFT, (format.bits() - 1) as u8);
    packed(code, Host::And, LEFT, UP);
    packed(code, Host::EqualDword, VN, VN);
    right_shift.emit(code, VN, 1);
    packed(code, Host::And, UP, VN);
    packed(code, Host::And, DOWN, VN);
    packed(code, Host::MoveAligned, VN, UP);
    code.asm().float(FloatOp::Max, lanes, VN, Rm::Xmm(DOWN));
    code.asm().float(FloatOp::Min, lanes, UP, Rm::Xmm(DOWN));
    // UP: tiny lanes, ordered, active.
    code.asm().mov_imm64(Gpr::Rax, 1 << format.fraction_bits());
    packed(code, Host::MoveGprQword, DOWN, Gpr::Rax as u8);
    if format == Format::Single {
        super::shuffle(code, DOWN, DOWN, 0);
    } else {
        packed(code, Host::UnpackLowQword, DOWN, DOWN);
    }
    code.asm().float_compare(lanes, UP, Rm::Xmm(DOWN), LESS);
    packed(code, Host::Xor, DOWN, DOWN);
    code.asm()
        .float_compare(lanes, VN, Rm::Xmm(DOWN), NOT_EQUAL);
    packed(code, Host::And, UP, VN);
    packed(code, Host::MoveAligned, DOWN, RESULT);
    code.asm()
        .float_compare(lanes, DOWN, Rm::Xmm(DOWN), ORDERED);
    packed(code, Host::And, UP, DOWN);
    active_lanes(code, shape, format, DOWN);
    packed(code, Host::And, UP, DOWN);
    // DOWN: the result, the tiny lanes' signed zeros.
    packed(code, Host::And, LEFT, UP);
    packed(code, Host::MoveAligned, DOWN, UP);
    packed(code, Host::AndNot, DOWN, RESULT);
    packed(code, Host::Or, DOWN, LEFT);
    Host::DwordSignMask.register(code, Gpr::Rax as u8, UP, TargetCpu::Baseline);
    code.asm().test(Size::Dword, Gpr::Rax, Gpr::Rax);
    let kept = branch(code, Condition::Zero);
    code.asm()
        .alu_imm8(Alu::Or, Size::Dword, Gpr::R11, FPSR_UNDERFLOW as i8);
    let flushed = code.len();
    resolve(code, kept, flushed);
    restore_vn(code, LEFT, RESULT);
    for source in [LEFT, RIGHT, ADDEND] {
        packed(code, Host::MoveAligned, RESULT, UP);
        packed(code, Host::AndNot, RESULT, source);
        packed(code, Host::MoveAligned, source, RESULT);
    }
    clear_environment_status(code);
    emit_checked_fma(code, operand, target);
    packed(code, Host::MoveAligned, LEFT, DOWN);
    let end = code.len();
    resolve(code, exact, end);
    code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax);
}

/// Without FMA3, with FPCR.FZ set and AH clear, after the exact-product
/// path: its sum of an exact product is exact when tiny, so the tiny
/// lanes are its subnormal results, which raised no host status; Arm
/// flushes them to the zero of their sign with UFC, in R11D. Clobbers
/// RIGHT, XMM2, XMM3 and EAX.
fn flush_exact_tiny_results(code: &mut Code, operand: &Operand) {
    const TINY: u8 = 2;
    const SCRATCH: u8 = 3;
    let (format, shape) = (operand.format, operand.shape);
    test_control(code, FPCR_FZ);
    let unflushing = branch(code, Condition::Zero);
    test_control(code, FPCR_AH);
    let alternative = branch(code, Condition::NotZero);
    subnormal_lanes(code, format, TINY, LEFT, [SCRATCH, RIGHT]);
    active_lanes(code, shape, format, SCRATCH);
    packed(code, Host::And, TINY, SCRATCH);
    Host::DwordSignMask.register(code, Gpr::Rax as u8, TINY, TargetCpu::Baseline);
    code.asm().test(Size::Dword, Gpr::Rax, Gpr::Rax);
    let none = branch(code, Condition::Zero);
    code.asm()
        .alu_imm8(Alu::Or, Size::Dword, Gpr::R11, FPSR_UNDERFLOW as i8);
    // Clear the tiny lanes' magnitudes.
    packed(code, Host::EqualDword, SCRATCH, SCRATCH);
    if format == Format::Double {
        ShiftOpcode::RightQword.emit(code, SCRATCH, 1);
    } else {
        ShiftOpcode::RightDword.emit(code, SCRATCH, 1);
    }
    packed(code, Host::And, SCRATCH, TINY);
    packed(code, Host::AndNot, SCRATCH, LEFT);
    packed(code, Host::MoveAligned, LEFT, SCRATCH);
    let end = code.len();
    for patch in [unflushing, alternative, none] {
        resolve(code, patch, end);
    }
}

/// After [`select_input_nans`] over the negated operands, in the private
/// environment: Arm gives an infinity times a zero beside a quiet NaN
/// addend the default NaN with IOC, not the addend. Those lanes' addends
/// become zeros and leave the NaN-input lanes, so that the host's invalid
/// product gives [`merge_nans`]' default NaN with IOC. A NaN factor's lane
/// keeps FPProcessNaNs3's selection. Clobbers NAN_REGISTERS.mask and
/// NAN_REGISTERS.temporary.
fn invalid_products_beside_quiet_nans(code: &mut Code, format: Format) {
    let [product, quiet] = [NAN_REGISTERS.mask, NAN_REGISTERS.temporary];
    let lanes = float_lanes(format, Shape::Vector128);
    packed(code, Host::MoveAligned, product, LEFT);
    code.asm()
        .float(FloatOp::Mul, lanes, product, Rm::Xmm(RIGHT));
    code.asm()
        .float_compare(lanes, product, Rm::Xmm(product), UNORDERED);
    quiet_lanes(code, format, quiet, ADDEND);
    packed(code, Host::And, product, quiet);
    packed(code, Host::MoveAligned, quiet, ADDEND);
    code.asm()
        .float_compare(lanes, quiet, Rm::Xmm(quiet), UNORDERED);
    packed(code, Host::And, product, quiet);
    // Not a NaN factor's product: an infinity times a zero.
    for factor in [LEFT, RIGHT] {
        packed(code, Host::MoveAligned, quiet, factor);
        code.asm()
            .float_compare(lanes, quiet, Rm::Xmm(quiet), UNORDERED);
        packed(code, Host::AndNot, quiet, product);
        packed(code, Host::MoveAligned, product, quiet);
    }
    let inputs = NAN_REGISTERS.inputs;
    packed(code, Host::And, product, inputs);
    packed(code, Host::MoveAligned, quiet, product);
    packed(code, Host::AndNot, quiet, ADDEND);
    packed(code, Host::MoveAligned, ADDEND, quiet);
    packed(code, Host::AndNot, product, inputs);
    packed(code, Host::MoveAligned, inputs, product);
}

/// The exact-product path's lanes with an infinite or NaN operand, in
/// SPECIAL_LANES ([`special_lanes`]); clobbers XMM3, XMM4 and EAX.
fn operand_special_lanes(code: &mut Code, format: Format, shape: Shape) {
    const SCRATCH: u8 = 3;
    const OTHER: u8 = 4;
    special_lanes(code, format, SPECIAL_LANES, LEFT, SCRATCH);
    for source in [RIGHT, ADDEND] {
        special_lanes(code, format, OTHER, source, SCRATCH);
        packed(code, Host::Or, SPECIAL_LANES, OTHER);
    }
    active_lanes(code, shape, format, OTHER);
    packed(code, Host::And, SPECIAL_LANES, OTHER);
}

/// Without FMA3, with FPCR.AH clear, after the input flush: the operands
/// of each lane with an infinite or NaN operand become zeros, which the
/// exact-product path completes exactly and without status, and R10D
/// becomes nonzero for [`special_results`]. Clobbers XMM2 to XMM4 and EAX.
fn clear_special_lanes(code: &mut Code, operand: &Operand) {
    const KEPT: u8 = 3;
    operand_special_lanes(code, operand.format, operand.shape);
    Host::DwordSignMask.register(code, Gpr::Rax as u8, SPECIAL_LANES, TargetCpu::Baseline);
    code.asm().alu(Alu::Or, Size::Dword, Gpr::R10, Gpr::Rax);
    code.asm().test(Size::Dword, Gpr::Rax, Gpr::Rax);
    let ordinary = branch(code, Condition::Zero);
    for source in [LEFT, RIGHT, ADDEND] {
        packed(code, Host::MoveAligned, KEPT, SPECIAL_LANES);
        packed(code, Host::AndNot, KEPT, source);
        packed(code, Host::MoveAligned, source, KEPT);
    }
    let end = code.len();
    resolve(code, ordinary, end);
}

/// Without FMA3, after the exact-product path completed the other lanes
/// into LEFT (and before the commit), when [`clear_special_lanes`] found
/// lanes with an infinite or NaN operand: their results, which round
/// nothing. From the operands read again (flushed again under FZ or FIZ,
/// their IDC committed already) and negated as the operation does, a
/// separate host product and sum give FPMulAdd's infinity or invalid
/// operation once a lane whose factors are both finite has a zero product
/// (its exact product cannot change an infinite or NaN addend, but its host
/// product could overflow). NaN lanes follow FPProcessNaNs3 and an invalid
/// operation gives the default NaN with IOC ([`select_input_nans`],
/// [`invalid_products_beside_quiet_nans`], [`merge_nans`]). The other
/// lanes add the exact-product result to a zero product of its sign, which
/// keeps it exactly. Only IOC reaches FPSR. Keeps `merge` and leaves the
/// result in LEFT; clobbers XMM1 to XMM7 but `merge`, RAX and RCX.
fn special_results(code: &mut Code, operand: &Operand, merge: u8) {
    const SAVED_BYTES: i8 = 32;
    const RESULT_SLOT: i32 = 0;
    const MERGE_SLOT: i32 = 16;
    const FACTORS: u8 = SPECIAL_LANES;
    const SCRATCH: u8 = 3;
    const OTHER: u8 = 4;
    const RESULT: u8 = 5;
    const SPECIAL: u8 = 7;
    let (format, shape) = (operand.format, operand.shape);
    code.asm().test(Size::Dword, Gpr::R10, Gpr::R10);
    let ordinary = branch(code, Condition::Zero);
    code.asm()
        .alu_imm8(Alu::Sub, Size::Qword, Gpr::Rsp, SAVED_BYTES);
    Host::StoreUnaligned.emit(
        code,
        LEFT,
        Mem::base(Gpr::Rsp, RESULT_SLOT),
        TargetCpu::Baseline,
    );
    Host::StoreUnaligned.emit(
        code,
        merge,
        Mem::base(Gpr::Rsp, MERGE_SLOT),
        TargetCpu::Baseline,
    );
    read_numerical_vector(code, shape, operand.left, LEFT);
    read_numerical_vector(code, shape, operand.addend, ADDEND);
    prepare_right(code, operand);
    test_control(code, FPCR_FZ | FPCR_FIZ);
    let unflushed = branch(code, Condition::Zero);
    for source in [LEFT, RIGHT, ADDEND] {
        flush_subnormal_lanes(code, format, shape, source, FLUSH_SCRATCH);
    }
    let flushed = code.len();
    resolve(code, unflushed, flushed);
    negate_operands(code, operand);
    special_lanes(code, format, FACTORS, LEFT, SCRATCH);
    special_lanes(code, format, OTHER, RIGHT, SCRATCH);
    packed(code, Host::Or, FACTORS, OTHER);
    special_lanes(code, format, SPECIAL, ADDEND, SCRATCH);
    packed(code, Host::Or, SPECIAL, FACTORS);
    Host::LoadUnaligned.emit(
        code,
        RESULT,
        Mem::base(Gpr::Rsp, RESULT_SLOT),
        TargetCpu::Baseline,
    );
    // Vn is zero where neither factor is special.
    packed(code, Host::And, LEFT, FACTORS);
    // Elsewhere Vm is the exact-product result's signed zero, and the
    // addend that result.
    packed(code, Host::EqualDword, SCRATCH, SCRATCH);
    if format == Format::Single {
        ShiftOpcode::LeftDword
    } else {
        ShiftOpcode::LeftQword
    }
    .emit(code, SCRATCH, (format.bits() - 1) as u8);
    packed(code, Host::And, SCRATCH, RESULT);
    for (source, ordinary_value) in [(RIGHT, SCRATCH), (ADDEND, RESULT)] {
        packed(code, Host::And, source, SPECIAL);
        packed(code, Host::MoveAligned, OTHER, SPECIAL);
        packed(code, Host::AndNot, OTHER, ordinary_value);
        packed(code, Host::Or, source, OTHER);
    }
    environment(code);
    select_input_nans(code, format, shape, &[ADDEND, LEFT, RIGHT], NAN_REGISTERS);
    invalid_products_beside_quiet_nans(code, format);
    emit_opcode(code, format, shape, ArithmeticOpcode::Multiply, RIGHT);
    emit_opcode(code, format, shape, ArithmeticOpcode::Add, ADDEND);
    merge_nans(code, format, shape, LEFT, NAN_REGISTERS);
    restore_environment(code);
    commit_invalid_lanes(code, format, shape, NAN_REGISTERS.invalid);
    Host::LoadUnaligned.emit(
        code,
        merge,
        Mem::base(Gpr::Rsp, MERGE_SLOT),
        TargetCpu::Baseline,
    );
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, SAVED_BYTES);
    let end = code.len();
    resolve(code, ordinary, end);
}

/// The sticky-inexact path (`numerical::sticky_inexact`) for a host with
/// FMA3, whose single rounding is the guest's: the operation in the entry
/// MXCSR, its result classification and the commit, which clears scalar
/// upper bits as NEP is zero there. A rejected zero takes the out-of-line
/// zero-product check, and other rejected results the full path. Returns the branches to the full path, to the helper
/// and past the full path, and those between the sticky path and the rest
/// ([`ColdSplit`]).
struct StickyPath {
    full: Vec<usize>,
    helper: Vec<usize>,
    done: usize,
    crossing: Vec<usize>,
    cold: crate::x86_64::asm::Checkpoint,
    inline_end: crate::x86_64::asm::Checkpoint,
}

fn sticky_path(code: &mut Code, operand: &Operand, target: TargetCpu, entry: Entry) -> StickyPath {
    let full = sticky_inexact(code, entry);
    // A zeroing load of the destination LEFT leaves a scalar result's
    // upper bits clear.
    let left = if operand.shape == Shape::Scalar {
        Input::Scalar(operand.format)
    } else {
        Input::Vector(operand.shape)
    };
    let vector = Input::Vector(operand.shape);
    let mut inputs = vec![(left, operand.left, LEFT), (vector, operand.addend, ADDEND)];
    if operand.right_lane.is_none() {
        inputs.push((vector, operand.right, RIGHT));
    }
    read_inputs(code, entry.xmm0, target, &inputs);
    if operand.right_lane.is_some() {
        prepare_right(code, operand);
    }
    emit_checked_fma(code, operand, target);
    let rejected = sticky_result_check(code, operand.format, operand.shape, LEFT, false, target);
    let resume = code.len();
    if operand.shape == Shape::Vector64 {
        packed(code, Host::MoveQword, LEFT, LEFT);
    }
    commit(code, operand.destination, LEFT);
    let inline_end = code.checkpoint();
    let done = jump(code);
    let cold = code.checkpoint();
    let check = code.len();
    resolve(code, rejected, check);
    let mut crossing = vec![rejected];
    // An infinite result may be exact: the full path tells, from its inputs
    // and the host's status, rather than the helper.
    let mut full = full;
    full.extend(zero_product_check(
        code,
        &ZeroProduct {
            format: operand.format,
            shape: operand.shape,
            right: RIGHT,
            left: operand.left,
            addend: Some(ADDEND),
        },
        resume,
        &mut crossing,
    ));
    StickyPath {
        full,
        helper: vec![],
        done,
        crossing,
        cold,
        inline_end,
    }
}
