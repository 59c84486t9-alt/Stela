//! FSQRT: SSE2 for every S/D input with FPCR.AH clear and for positive
//! normals otherwise, F16C or integer roots for H, software fallback
//! otherwise.
use super::super::isa::ShiftOpcode;
use super::numerical::{
    ColdSplit, Condition, Entry, INPUT_MINIMUM_EXPONENT, Input, Rounding, branch, clear_scalar,
    commit_inexact, environment_round, positive_exponent_range, prepare_vector_input_range,
    read_inputs, read_numerical_vector, reject_other_status, resolve, restore_environment,
    sticky_inexact, sticky_result_check, test_control, vector_positive_exponent_range,
};
use super::numerical::{
    NanRegisters, commit_flush_status, commit_invalid_lanes, commit_rounded_status, environment,
    flush_subnormal_lanes, helper_section, jump, merge_nans, select_input_nans,
};
use super::{Host, commit, packed, read_vector};
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::{Alu, Code, Gpr, ShiftOp, Size};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{
            FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_NEP, FPCR_ROUNDING_SHIFT,
            Format,
        },
        simd::{arithmetic::Shape, sqrt::Operand},
    },
};
use Gpr::Rax;
use alloc::vec::Vec;

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const TEMP: u8 = 2;
const ZERO: u8 = 3;
const HALF_BIAS: u8 = 4;
const ROUNDING_BIAS: u8 = 5;
const SAVED_HALF: u8 = 6;
const ROUNDING_PARITY: u8 = 7;
const FIRST_LANE: u8 = 0;
const CONVERT_USING_MXCSR: u8 = 1 << 2;
const FPCR_LOW_ROUNDING_BIT: u32 = 1 << FPCR_ROUNDING_SHIFT;
const FPCR_HIGH_ROUNDING_BIT: u32 = 1 << (FPCR_ROUNDING_SHIFT + 1);
const HALF_FRACTION_SHIFT: u8 =
    (Format::Single.fraction_bits() - Format::Half.fraction_bits()) as u8;
const HALF_DISCARDED_MASK: u32 = (1 << HALF_FRACTION_SHIFT) - 1;
const HALF_TO_SINGLE_BIAS: u32 = (Format::Single.exponent_bias() - Format::Half.exponent_bias())
    << Format::Single.fraction_bits();
const HALF_BIAS_POSITION: u8 = HALF_TO_SINGLE_BIAS.trailing_zeros() as u8;
const HALF_BIAS_DIGITS: u8 = (HALF_TO_SINGLE_BIAS >> HALF_BIAS_POSITION).ilog2() as u8 + 1;
const UPPER_HALF_BYTES: u8 = (u64::BITS / u8::BITS) as u8;

/// Read the source; S and D take [`rounded_root`] first, whose jump to the
/// commit this returns.
fn source_guard(code: &mut Code, operand: &Operand, helper: &mut Vec<usize>) -> Option<usize> {
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    read_numerical_vector(code, operand.shape, operand.source, SOURCE);
    let rounded = (operand.format != Format::Half).then(|| rounded_root(code, operand));
    if operand.shape == Shape::Scalar {
        positive_exponent_range(code, operand.format, SOURCE, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
    } else {
        prepare_vector_input_range(code, operand.format);
        vector_positive_exponent_range(code, operand.format, operand.shape, SOURCE);
        helper.push(branch(code, Condition::NotZero));
    }
    rounded
}

/// [`rounded_root`]'s NaN registers, apart from RESULT and SOURCE.
const NAN_REGISTERS: NanRegisters = NanRegisters {
    selected: 2,
    inputs: 3,
    invalid: 4,
    mask: 5,
    temporary: 7,
};
const FLUSH_SCRATCH: [u8; 4] = [2, 3, 4, 5];

/// S/D FSQRT with FPCR.AH clear, for every input: FZ or FIZ flush
/// subnormal inputs first (FZ raising IDC), and the host's root in Arm's
/// rounding mode is the guest's, exact for zeros (keeping the sign) and
/// +infinity, rounded once for the rest; its inexact status is IXC (a root
/// never underflows or overflows). A NaN input propagates by Arm's rules
/// and a negative one gives the default NaN with IOC
/// ([`select_input_nans`], [`merge_nans`]). Leaves the result in RESULT
/// and returns the jump to the commit; AH continues past it.
fn rounded_root(code: &mut Code, operand: &Operand) -> usize {
    let (format, shape) = (operand.format, operand.shape);
    code.asm().alu(Alu::Xor, Size::Dword, Gpr::R11, Gpr::R11);
    test_control(code, FPCR_AH);
    let alternative = branch(code, Condition::NotZero);
    test_control(code, FPCR_FZ | FPCR_FIZ);
    let unflushed = branch(code, Condition::Zero);
    flush_subnormal_lanes(code, format, shape, SOURCE, FLUSH_SCRATCH);
    let flushed = code.len();
    resolve(code, unflushed, flushed);
    if shape == Shape::Scalar {
        // Legacy scalar SQRT preserves destination upper bits for NEP.
        read_vector(code, operand.destination, RESULT);
    }
    environment(code);
    select_input_nans(code, format, shape, &[SOURCE], NAN_REGISTERS);
    square_root(code, format, shape, SOURCE);
    merge_nans(code, format, shape, RESULT, NAN_REGISTERS);
    restore_environment(code);
    commit_flush_status(code);
    commit_invalid_lanes(code, format, shape, NAN_REGISTERS.invalid);
    commit_rounded_status(code);
    let done = jump(code);
    let alternative_start = code.len();
    resolve(code, alternative, alternative_start);
    done
}

fn square_root(code: &mut Code, format: Format, shape: Shape, source: u8) {
    let opcode = match (format, shape) {
        (Format::Single, Shape::Scalar) => Host::SquareRootScalarSingle,
        (Format::Double, Shape::Scalar) => Host::SquareRootScalarDouble,
        (Format::Single, _) => Host::SquareRootPackedSingle,
        (Format::Double, _) => Host::SquareRootPackedDouble,
        (Format::Half, _) => unreachable!("half roots use exact Single widening"),
    };
    packed(code, opcode, RESULT, source);
}

/// Select positive-result narrowing bias once for both four-lane H groups.
/// Nearest-even adds half-minus-one plus parity. Positive rounding
/// adds the entire discarded mask; negative/zero rounding simply truncates.
fn half_constants(code: &mut Code) {
    packed(code, Host::Xor, ZERO, ZERO);
    packed(code, Host::EqualDword, HALF_BIAS, HALF_BIAS);
    ShiftOpcode::RightDword.emit(code, HALF_BIAS, u32::BITS as u8 - HALF_BIAS_DIGITS);
    ShiftOpcode::LeftDword.emit(code, HALF_BIAS, HALF_BIAS_POSITION);
    packed(code, Host::Xor, ROUNDING_BIAS, ROUNDING_BIAS);
    packed(code, Host::Xor, ROUNDING_PARITY, ROUNDING_PARITY);
    test_control(code, FPCR_HIGH_ROUNDING_BIT);
    let truncating = branch(code, Condition::NotZero);
    packed(code, Host::EqualDword, ROUNDING_BIAS, ROUNDING_BIAS);
    ShiftOpcode::RightDword.emit(code, ROUNDING_BIAS, u32::BITS as u8 - HALF_FRACTION_SHIFT);
    test_control(code, FPCR_LOW_ROUNDING_BIT);
    let positive = branch(code, Condition::NotZero);
    ShiftOpcode::RightDword.emit(code, ROUNDING_BIAS, 1);
    packed(code, Host::EqualDword, ROUNDING_PARITY, ROUNDING_PARITY);
    ShiftOpcode::RightDword.emit(code, ROUNDING_PARITY, u32::BITS as u8 - 1);
    let selected = code.len();
    for patch in [truncating, positive] {
        resolve(code, patch, selected);
    }
}

/// All active inputs were positive normal H. Integer field construction is exact.
fn widen_half(code: &mut Code, upper: bool) {
    packed(code, Host::MoveAligned, RESULT, SOURCE);
    if upper {
        ShiftOpcode::RightBytes.emit(code, RESULT, UPPER_HALF_BYTES);
    }
    packed(code, Host::UnpackLowWord, RESULT, ZERO);
    ShiftOpcode::LeftDword.emit(code, RESULT, HALF_FRACTION_SHIFT);
    packed(code, Host::AddDword, RESULT, HALF_BIAS);
}

/// Rounding single-precision sqrt and then rounding to half gives the same
/// result as direct half-precision sqrt, with single PE exactly matching half
/// inexact. Results are positive normal halves of at most 256, so signed dword
/// packing is exact.
fn half_fields(code: &mut Code) {
    packed(code, Host::SubDword, RESULT, HALF_BIAS);
    packed(code, Host::MoveAligned, TEMP, RESULT);
    ShiftOpcode::RightDword.emit(code, TEMP, HALF_FRACTION_SHIFT);
    packed(code, Host::And, TEMP, ROUNDING_PARITY);
    packed(code, Host::AddDword, TEMP, ROUNDING_BIAS);
    packed(code, Host::AddDword, RESULT, TEMP);
    ShiftOpcode::RightDword.emit(code, RESULT, HALF_FRACTION_SHIFT);
}

/// The scalar integer recipe avoids vector constant preparation and packing.
/// BT captures kept parity before ADC adds half-minus-one plus that bit.
fn scalar_half_root(code: &mut Code) {
    let mut asm = code.asm();
    asm.movd_from_xmm(Rax, SOURCE);
    asm.movzx(Size::Dword, Rax, Size::Word, Rax);
    asm.shift_imm(ShiftOp::Shl, Size::Dword, Rax, HALF_FRACTION_SHIFT);
    asm.alu_accumulator_imm32(Alu::Add, Size::Dword, HALF_TO_SINGLE_BIAS as i32);
    asm.movd_to_xmm(RESULT, Rax);
    square_root(code, Format::Single, Shape::Scalar, RESULT);
    let mut asm = code.asm();
    asm.movd_from_xmm(Rax, RESULT);
    asm.alu_accumulator_imm32(Alu::Sub, Size::Dword, HALF_TO_SINGLE_BIAS as i32);
    test_control(code, FPCR_HIGH_ROUNDING_BIT);
    let truncating = branch(code, Condition::NotZero);
    test_control(code, FPCR_LOW_ROUNDING_BIT);
    let positive = branch(code, Condition::NotZero);
    let mut asm = code.asm();
    asm.bit_imm(BitTest::Bt, Size::Dword, Rax, HALF_FRACTION_SHIFT);
    asm.alu_accumulator_imm32(Alu::Adc, Size::Dword, (HALF_DISCARDED_MASK >> 1) as i32);
    let nearest_done = jump(code);
    let positive_start = code.len();
    resolve(code, positive, positive_start);
    code.asm()
        .alu_accumulator_imm32(Alu::Add, Size::Dword, HALF_DISCARDED_MASK as i32);
    let shift_start = code.len();
    for patch in [truncating, nearest_done] {
        resolve(code, patch, shift_start);
    }
    let mut asm = code.asm();
    asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, HALF_FRACTION_SHIFT);
    asm.movd_to_xmm(RESULT, Rax);
}

fn vector_half_root(code: &mut Code, shape: Shape) {
    half_constants(code);
    widen_half(code, false);
    square_root(code, Format::Single, shape, RESULT);
    half_fields(code);
    if shape == Shape::Vector128 {
        packed(code, Host::MoveAligned, SAVED_HALF, RESULT);
        widen_half(code, true);
        square_root(code, Format::Single, Shape::Vector128, RESULT);
        half_fields(code);
        packed(code, Host::PackSignedDwordToWord, SAVED_HALF, RESULT);
        packed(code, Host::MoveAligned, RESULT, SAVED_HALF);
    } else {
        packed(code, Host::PackSignedDwordToWord, RESULT, RESULT);
    }
}

fn narrow_half(code: &mut Code, destination: u8, source: u8, target: TargetCpu) {
    // VCVTPS2PH encodes source in ModRM.reg and destination in ModRM.r/m,
    // reversing the register field roles of ordinary two-operand SIMD ops.
    Host::ConvertSingleToHalf.register_imm(code, source, destination, CONVERT_USING_MXCSR, target);
}

fn checked_half_root(code: &mut Code, shape: Shape, target: TargetCpu) {
    if shape == Shape::Scalar {
        clear_scalar(code, Format::Half, SOURCE);
    }
    Host::ConvertHalfToSingle.register(code, RESULT, SOURCE, target);
    // Exact hardware widening makes inactive scalar lanes +0, so packed SQRT
    // is safe here. Integer widening's manufactured inactive fields differ.
    square_root(code, Format::Single, Shape::Vector128, RESULT);
    if shape == Shape::Vector128 {
        narrow_half(code, SAVED_HALF, RESULT, target);
        ShiftOpcode::RightBytes.emit(code, SOURCE, UPPER_HALF_BYTES);
        Host::ConvertHalfToSingle.register(code, RESULT, SOURCE, target);
        square_root(code, Format::Single, Shape::Vector128, RESULT);
        narrow_half(code, RESULT, RESULT, target);
        packed(code, Host::UnpackLowQword, SAVED_HALF, RESULT);
        packed(code, Host::MoveAligned, RESULT, SAVED_HALF);
    } else {
        narrow_half(code, RESULT, RESULT, target);
    }
}

fn commit_result(code: &mut Code, operand: &Operand) {
    if operand.shape == Shape::Scalar {
        if operand.format == Format::Half {
            // Rebuild the half-precision scalar result in Vd after the
            // arithmetic and packing, which handles source aliases and V31.
            code.asm().movd_from_xmm(Rax, RESULT);
            read_vector(code, operand.destination, RESULT);
            code.asm().pinsrw(RESULT, Rax, FIRST_LANE);
        }
        test_control(code, FPCR_NEP);
        let merging = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, RESULT);
        let committed = code.len();
        resolve(code, merging, committed);
    } else if operand.shape == Shape::Vector64 {
        clear_scalar(code, Format::Double, RESULT);
    }
    commit(code, operand.destination, RESULT);
}

/// S/D forms return their [`ColdSplit`].
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
    entry: Entry,
) -> Option<ColdSplit> {
    let checked_half = operand.format == Format::Half && target.supports(TargetCpu::F16c);
    if checked_half {
        // F16C requires usable AVX. Pay this prefix per body before legacy
        // guards, avoiding a transition from arbitrary caller upper YMM state.
        code.asm().vzeroupper();
    }
    let mut helper = Vec::new();
    // The sticky-inexact path (`numerical::sticky_inexact`) for S and D: the
    // root of a negative input is NaN and of +infinity infinite, which take
    // the full path ([`rounded_root`]); every other root is exact IEEE on
    // both sides.
    let mut sticky = None;
    if operand.format != Format::Half {
        let mut crossing = sticky_inexact(code, entry);
        // NEP is zero on this path: scalar upper bits clear, as the root
        // of a zeroing load into RESULT leaves them.
        let (input, source) = if operand.shape == Shape::Scalar {
            (Input::Scalar(operand.format), RESULT)
        } else {
            (Input::Vector(operand.shape), SOURCE)
        };
        read_inputs(code, entry.xmm0, target, &[(input, operand.source, source)]);
        square_root(code, operand.format, operand.shape, source);
        let rejected =
            sticky_result_check(code, operand.format, operand.shape, RESULT, true, target);
        if operand.shape == Shape::Vector64 {
            clear_scalar(code, Format::Double, RESULT);
        }
        commit(code, operand.destination, RESULT);
        let inline_end = code.checkpoint();
        let done = jump(code);
        let cold = code.checkpoint();
        let full_start = code.len();
        crossing.push(rejected);
        for &patch in &crossing {
            resolve(code, patch, full_start);
        }
        sticky = Some((done, full_start, crossing, cold, inline_end));
    }
    let rounded = source_guard(code, operand, &mut helper);
    if operand.shape == Shape::Scalar && operand.format != Format::Half {
        // Legacy scalar SQRT preserves destination upper bits for NEP.
        read_vector(code, operand.destination, RESULT);
    }
    environment_round(code, Rounding::Fpcr);
    if operand.format == Format::Half {
        if checked_half {
            checked_half_root(code, operand.shape, target);
        } else if operand.shape == Shape::Scalar {
            scalar_half_root(code);
        } else {
            vector_half_root(code, operand.shape);
        }
    } else {
        square_root(code, operand.format, operand.shape, SOURCE);
    }
    restore_environment(code);
    helper.push(reject_other_status(code));
    helper_section(code, &helper, pc);
    commit_inexact(code);
    if let Some(rounded) = rounded {
        let commit_start = code.len();
        resolve(code, rounded, commit_start);
    }
    commit_result(code, operand);
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
