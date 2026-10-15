//! Integral rounding: compact integer baseline and checked, nontrapping ROUND.
pub(in crate::x86_64) mod kernel;
use super::super::isa::ShiftOpcode;
use super::numerical::{
    ArithmeticOpcode, Condition, EXPONENT_VECTOR, branch, clear_scalar, prepare_vector_input_range,
    read_numerical_vector, resolve, test_control, vector_exponent_range,
};
use super::{Host, commit, packed, read_vector};
use crate::{
    GuestAddress, GuestState, TargetCpu,
    aarch64::{
        floating::{
            FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, FPCR_ROUNDING_SHIFT, Format, INEXACT,
            rounding::RoundingOperation,
        },
        simd::{arithmetic::Shape, rounding::Operand},
    },
    block::ExitKind,
};

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const TEMP: u8 = 2;
const RESIDUAL: u8 = 3;
const MASK: u8 = 4;
const CONSTANT: u8 = 5;
const SAVED_HALF: u8 = 6;
const ORIGINAL_HALF: u8 = 7;
const SIGN_BITS: u32 = 1;
const ACCUMULATOR_GPR: u8 = 0;
const FIRST_LANE: u8 = 0;
const BROADCAST_LOW_DWORD: u8 = 0;
const SINGLE_LOW_MASK: u32 = 0x03;
const SINGLE_FULL_MASK: u32 = 0x0f;
const DOUBLE_FULL_MASK: u32 = 0x05;
const BITS_PER_BYTE: u32 = u8::BITS;
const REGISTER_DIRECT: u8 = 0xc0;
const REGISTER_SHIFT: u8 = 3;
const SSE_ESCAPE: u8 = 0x0f;
const JMP_RELATIVE: u8 = 0xe9;
const MOVD_TO_EAX: &[u8] = &[0x66, 0x0f, 0x7e];
const MOVD_FROM_EAX: &[u8] = &[0x66, 0x0f, 0x6e];
const MOVQ_TO_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
const PINSRW_FROM_EAX: &[u8] = &[0x66, 0x0f, 0xc4];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const SHR_RCX: &[u8] = &[0x48, 0xc1, 0xe9];
const AND_ECX: &[u8] = &[0x81, 0xe1];
const CMP_ECX: &[u8] = &[0x81, 0xf9];
const MOV_R8D_ECX: &[u8] = &[0x41, 0x89, 0xc8];
const DEC_R8D: &[u8] = &[0x41, 0xff, 0xc8];
const CMP_R8D: &[u8] = &[0x41, 0x81, 0xf8];
const MOV_R9_RDX: &[u8] = &[0x49, 0x89, 0xd1];
const MOV_R9_RAX: &[u8] = &[0x49, 0x89, 0xc1];
const SHL_R9: &[u8] = &[0x49, 0xc1, 0xe1];
const MOV_R8D: &[u8] = &[0x41, 0xb8];
const MOVABS_R8: &[u8] = &[0x49, 0xb8];
const SUB_R8D_ECX: &[u8] = &[0x41, 0x29, 0xc8];
const MOV_ECX_R8D: &[u8] = &[0x44, 0x89, 0xc1];
const SHL_R8_CL: &[u8] = &[0x49, 0xd3, 0xe0];
const MOV_R9_R8: &[u8] = &[0x4d, 0x89, 0xc1];
const DEC_R9: &[u8] = &[0x49, 0xff, 0xc9];
const SHR_R8_1: &[u8] = &[0x49, 0xd1, 0xe8];
const DEC_R8: &[u8] = &[0x49, 0xff, 0xc8];
const BT_RAX_RCX: &[u8] = &[0x48, 0x0f, 0xa3, 0xc8];
const ADC_R8_ZERO: &[u8] = &[0x49, 0x83, 0xd0, 0];
const XOR_R8D_R8D: &[u8] = &[0x45, 0x31, 0xc0];
const BT_RDX: &[u8] = &[0x48, 0x0f, 0xba, 0xe2];
const BT_RAX: &[u8] = &[0x48, 0x0f, 0xba, 0xe0];
const BTR_R9: &[u8] = &[0x49, 0x0f, 0xba, 0xf1];
const CMOVB_R8_R9: &[u8] = &[0x4d, 0x0f, 0x42, 0xc1];
const CMOVAE_R8_R9: &[u8] = &[0x4d, 0x0f, 0x43, 0xc1];
const ADD_RAX_R8: &[u8] = &[0x4c, 0x01, 0xc0];
const OR_RAX_R8: &[u8] = &[0x4c, 0x09, 0xc0];
const OR_RAX_R9: &[u8] = &[0x4c, 0x09, 0xc8];
const XOR_RAX_R9: &[u8] = &[0x4c, 0x31, 0xc8];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const OR_EAX_IMMEDIATE: u8 = 0x0d;
const SHR_RAX: &[u8] = &[0x48, 0xc1, 0xe8];
const SHL_RAX: &[u8] = &[0x48, 0xc1, 0xe0];
const CMP_R9_R8: &[u8] = &[0x4d, 0x39, 0xc1];
const CMP_RAX_RDX: &[u8] = &[0x48, 0x39, 0xd0];
const SETNE_R8B: &[u8] = &[0x41, 0x0f, 0x95, 0xc0];
const MOVZX_R8D_R8B: &[u8] = &[0x45, 0x0f, 0xb6, 0xc0];
const OR_R10D_R8D: &[u8] = &[0x45, 0x09, 0xc2];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const SETNE_R10B: &[u8] = &[0x41, 0x0f, 0x95, 0xc2];
const SHL_R10D: &[u8] = &[0x41, 0xc1, 0xe2];
const OR_STATE_R10D: &[u8] = &[0x44, 0x09, 0x97];
const MOV_R11D: &[u8] = &[0x41, 0xbb];
const DEC_R11D: &[u8] = &[0x41, 0xff, 0xcb];
const PSLLDQ_XMM2: &[u8] = &[0x66, 0x0f, 0x73, 0xfa];
const MOVLHPS_XMM0_XMM2: &[u8] = &[0x0f, 0x16, 0xc2];
const MOVSS_XMM6_XMM0: &[u8] = &[0xf3, 0x0f, 0x10, 0xf0];
const MOVSD_XMM6_XMM0: &[u8] = &[0xf2, 0x0f, 0x10, 0xf0];
const MOVABS_RAX: &[u8] = &[0x48, 0xb8];
const CMP_EAX_IMMEDIATE: u8 = 0x3d;
const PRECISION_SUPPRESSED: u8 = 1 << 3;
const ROUND_NEAREST: u8 = 0;
const ROUND_NEGATIVE: u8 = 1;
const ROUND_POSITIVE: u8 = 2;
const ROUND_ZERO: u8 = 3;
const FPCR_LOW_ROUNDING_BIT: u32 = 1 << FPCR_ROUNDING_SHIFT;
const FPCR_HIGH_ROUNDING_BIT: u32 = 1 << (FPCR_ROUNDING_SHIFT + 1);
const INEXACT_SHIFT: u8 = INEXACT.trailing_zeros() as u8;
const COMPARE_LESS_EQUAL: u8 = 2;
const COMPARE_OPCODE: u8 = 0xc2;
const SCALAR_SINGLE_PREFIX: u8 = 0xf3;
const SCALAR_DOUBLE_PREFIX: u8 = 0xf2;
const PACKED_DOUBLE_PREFIX: u8 = 0x66;
const ADJACENT_DWORDS: u8 = 0xb1;

#[derive(Clone, Copy)]
enum Direction {
    NearestEven,
    NearestAway,
    Positive,
    Negative,
    Zero,
}

fn jump(code: &mut Vec<u8>) -> usize {
    code.push(JMP_RELATIVE);
    let patch = code.len();
    code.extend(0i32.to_le_bytes());
    patch
}

fn immediate(code: &mut Vec<u8>, instruction: &[u8], value: u32) {
    code.extend(instruction);
    code.extend(value.to_le_bytes());
}

fn exponent_mask(format: Format) -> u32 {
    (1 << (format.bits() - format.fraction_bits() - SIGN_BITS)) - 1
}

fn bias(format: Format) -> u32 {
    exponent_mask(format) >> 1
}

fn sign_bit(format: Format) -> u8 {
    (format.bits() - SIGN_BITS) as u8
}

fn lanes(operand: &Operand) -> u32 {
    match operand.shape {
        Shape::Scalar => 1,
        Shape::Vector64 => u64::BITS / operand.format.bits(),
        Shape::Vector128 => u128::BITS / operand.format.bits(),
    }
}

fn fixed_direction(operation: RoundingOperation) -> Option<Direction> {
    Some(match operation {
        RoundingOperation::NearestEven => Direction::NearestEven,
        RoundingOperation::NearestAway => Direction::NearestAway,
        RoundingOperation::TowardPositive => Direction::Positive,
        RoundingOperation::TowardNegative => Direction::Negative,
        RoundingOperation::TowardZero
        | RoundingOperation::Signed32Zero
        | RoundingOperation::Signed64Zero => Direction::Zero,
        _ => return None,
    })
}

/// Dynamic FPCR is read at execution time, without installing host control.
fn current_direction(code: &mut Vec<u8>, mut emit: impl FnMut(&mut Vec<u8>, Direction)) {
    test_control(code, FPCR_HIGH_ROUNDING_BIT);
    let high = branch(code, Condition::NotZero);
    test_control(code, FPCR_LOW_ROUNDING_BIT);
    let positive = branch(code, Condition::NotZero);
    emit(code, Direction::NearestEven);
    let nearest_done = jump(code);
    let positive_start = code.len();
    resolve(code, positive, positive_start);
    emit(code, Direction::Positive);
    let positive_done = jump(code);
    let high_start = code.len();
    resolve(code, high, high_start);
    test_control(code, FPCR_LOW_ROUNDING_BIT);
    let zero = branch(code, Condition::NotZero);
    emit(code, Direction::Negative);
    let negative_done = jump(code);
    let zero_start = code.len();
    resolve(code, zero, zero_start);
    emit(code, Direction::Zero);
    let done = code.len();
    for patch in [nearest_done, positive_done, negative_done] {
        resolve(code, patch, done);
    }
}

fn direction(
    code: &mut Vec<u8>,
    operation: RoundingOperation,
    mut emit: impl FnMut(&mut Vec<u8>, Direction),
) {
    if let Some(fixed) = fixed_direction(operation) {
        emit(code, fixed);
    } else {
        current_direction(code, emit);
    }
}

fn read_lane(code: &mut Vec<u8>, format: Format, xmm: u8) {
    code.extend(if format == Format::Double {
        MOVQ_TO_RAX
    } else {
        MOVD_TO_EAX
    });
    code.push(REGISTER_DIRECT | (xmm << REGISTER_SHIFT));
    if format == Format::Half {
        code.push(AND_EAX_IMMEDIATE);
        code.extend(u32::from(u16::MAX).to_le_bytes());
    }
}

fn source_class(code: &mut Vec<u8>, format: Format, helper: &mut Vec<usize>) {
    code.extend(MOV_RDX_RAX);
    code.extend(MOV_RCX_RAX);
    code.extend(SHR_RCX);
    code.push(format.fraction_bits() as u8);
    immediate(code, AND_ECX, exponent_mask(format));
    code.extend(MOV_R8D_ECX);
    code.extend(DEC_R8D);
    immediate(code, CMP_R8D, exponent_mask(format) - 1);
    let normal = branch(code, Condition::Below);
    code.extend(MOV_R9_RDX);
    code.extend(SHL_R9);
    code.push((u64::BITS - (format.bits() - SIGN_BITS)) as u8);
    helper.push(branch(code, Condition::NotZero)); // only signed zero survives the nonnormal case
    let accepted = code.len();
    resolve(code, normal, accepted);
}

fn fractional_bias(code: &mut Vec<u8>, format: Format, rounding: Direction) {
    match rounding {
        Direction::NearestEven => {
            code.extend(SHR_R8_1);
            code.extend(DEC_R8);
            code.extend(BT_RAX_RCX);
            code.extend(ADC_R8_ZERO);
        }
        Direction::NearestAway => code.extend(SHR_R8_1),
        Direction::Positive | Direction::Negative => {
            code.extend(XOR_R8D_R8D);
            code.extend(BT_RDX);
            code.push(sign_bit(format));
            code.extend(if matches!(rounding, Direction::Positive) {
                CMOVAE_R8_R9
            } else {
                CMOVB_R8_R9
            });
        }
        Direction::Zero => code.extend(XOR_R8D_R8D),
    }
}

fn or_one(code: &mut Vec<u8>, format: Format) {
    let one = u64::from(bias(format)) << format.fraction_bits();
    if format == Format::Double {
        code.extend(MOVABS_R8);
        code.extend(one.to_le_bytes());
        code.extend(OR_RAX_R8);
    } else {
        code.push(OR_EAX_IMMEDIATE);
        code.extend((one as u32).to_le_bytes());
    }
}

fn small_increment(code: &mut Vec<u8>, format: Format, rounding: Direction, done: &mut Vec<usize>) {
    match rounding {
        Direction::NearestEven | Direction::NearestAway => {
            immediate(code, CMP_ECX, bias(format) - 1);
            done.push(branch(code, Condition::Below));
            if matches!(rounding, Direction::NearestEven) {
                code.extend(MOV_R9_RDX);
                code.extend(SHL_R9);
                code.push((u64::BITS - format.fraction_bits()) as u8);
                done.push(branch(code, Condition::Zero));
            }
            or_one(code, format);
        }
        Direction::Positive | Direction::Negative => {
            code.extend(BT_RDX);
            code.push(sign_bit(format));
            done.push(branch(
                code,
                if matches!(rounding, Direction::Positive) {
                    Condition::Below
                } else {
                    Condition::AboveOrEqual
                },
            ));
            or_one(code, format);
        }
        Direction::Zero => (),
    }
}

fn bounded(code: &mut Vec<u8>, format: Format, width: u32, helper: &mut Vec<usize>) {
    code.extend(MOV_R9_RAX);
    code.extend(BTR_R9);
    code.push(sign_bit(format));
    code.extend(MOVABS_R8);
    code.extend((u64::from(bias(format) + width - 1) << format.fraction_bits()).to_le_bytes());
    code.extend(CMP_R9_R8);
    helper.push(branch(code, Condition::Above));
    let smaller = branch(code, Condition::Below);
    code.extend(BT_RAX);
    code.push(sign_bit(format));
    helper.push(branch(code, Condition::AboveOrEqual)); // equality is valid only at the negative limit
    let accepted = code.len();
    resolve(code, smaller, accepted);
}

fn integer_lane(code: &mut Vec<u8>, operand: &Operand, helper: &mut Vec<usize>) {
    let format = operand.format;
    read_lane(code, format, SOURCE);
    source_class(code, format, helper);
    let mut done = Vec::new();
    immediate(code, CMP_ECX, bias(format));
    let small = branch(code, Condition::Below);
    immediate(code, CMP_ECX, bias(format) + format.fraction_bits());
    done.push(branch(code, Condition::AboveOrEqual));
    immediate(code, MOV_R8D, bias(format) + format.fraction_bits());
    code.extend(SUB_R8D_ECX);
    code.extend(MOV_ECX_R8D);
    immediate(code, MOV_R8D, 1);
    code.extend(SHL_R8_CL);
    code.extend(MOV_R9_R8);
    code.extend(DEC_R9);
    direction(code, operand.operation, |code, rounding| {
        fractional_bias(code, format, rounding)
    });
    code.extend(ADD_RAX_R8);
    code.extend(OR_RAX_R9);
    code.extend(XOR_RAX_R9);
    done.push(jump(code));
    let small_start = code.len();
    resolve(code, small, small_start);
    if format == Format::Double {
        code.extend(SHR_RAX);
        code.push(sign_bit(format));
        code.extend(SHL_RAX);
        code.push(sign_bit(format));
    } else {
        code.push(AND_EAX_IMMEDIATE);
        code.extend((1u32 << sign_bit(format)).to_le_bytes());
    }
    code.extend(MOV_R9_RDX);
    code.extend(SHL_R9);
    code.push((u64::BITS - (format.bits() - SIGN_BITS)) as u8);
    done.push(branch(code, Condition::Zero));
    direction(code, operand.operation, |code, rounding| {
        small_increment(code, format, rounding, &mut done)
    });
    let rounded = code.len();
    for patch in done {
        resolve(code, patch, rounded);
    }
    if let Some(width) = operand.operation.signed_width() {
        bounded(code, format, width, helper);
    }
    if operand.operation.exact() {
        code.extend(CMP_RAX_RDX);
        code.extend(SETNE_R8B);
        code.extend(MOVZX_R8D_R8B);
        code.extend(OR_R10D_R8D);
    }
}

fn insert_lane(code: &mut Vec<u8>, operand: &Operand) {
    match operand.format {
        Format::Half => {
            code.extend(PINSRW_FROM_EAX);
            code.push(REGISTER_DIRECT);
            code.push((lanes(operand) - 1) as u8);
        }
        Format::Single => {
            code.extend(MOVD_FROM_EAX);
            code.push(REGISTER_DIRECT | (TEMP << REGISTER_SHIFT));
            code.extend(PSLLDQ_XMM2);
            code.push(((lanes(operand) - 1) * (Format::Single.bits() / BITS_PER_BYTE)) as u8);
            packed(code, Host::Or, RESULT, TEMP);
        }
        Format::Double => {
            packed(code, Host::MoveGprQword, TEMP, ACCUMULATOR_GPR);
            code.extend(MOVLHPS_XMM0_XMM2);
        }
    }
}

fn integer_rounding(code: &mut Vec<u8>, operand: &Operand, helper: &mut Vec<usize>) {
    if operand.operation.exact() {
        code.extend(XOR_R10D_R10D);
    }
    if operand.shape == Shape::Scalar {
        integer_lane(code, operand, helper);
        if operand.format == Format::Double {
            packed(code, Host::MoveGprQword, RESULT, ACCUMULATOR_GPR);
        } else {
            code.extend(MOVD_FROM_EAX);
            code.push(REGISTER_DIRECT);
        }
    } else {
        packed(code, Host::Xor, RESULT, RESULT);
        immediate(code, MOV_R11D, lanes(operand));
        let repeat = code.len();
        integer_lane(code, operand, helper);
        let lane_bytes = (operand.format.bits() / BITS_PER_BYTE) as u8;
        ShiftOpcode::RightBytes.emit(code, SOURCE, lane_bytes);
        ShiftOpcode::RightBytes.emit(code, RESULT, lane_bytes);
        insert_lane(code, operand);
        code.extend(DEC_R11D);
        let repeat_branch = branch(code, Condition::NotZero);
        resolve(code, repeat_branch, repeat);
    }
}

fn packed_left(format: Format) -> ShiftOpcode {
    match format {
        Format::Half => ShiftOpcode::LeftWord,
        Format::Single => ShiftOpcode::LeftDword,
        Format::Double => ShiftOpcode::LeftQword,
    }
}

fn packed_right(format: Format) -> ShiftOpcode {
    match format {
        Format::Half => ShiftOpcode::RightWord,
        Format::Single => ShiftOpcode::RightDword,
        Format::Double => ShiftOpcode::RightQword,
    }
}

fn checked_source(code: &mut Vec<u8>, operand: &Operand, helper: &mut Vec<usize>) {
    let format = operand.format;
    prepare_vector_input_range(code, format);
    vector_exponent_range(code, format, operand.shape, SOURCE);
    packed(code, Host::MoveAligned, ORIGINAL_HALF, SOURCE);
    packed_left(format).emit(code, ORIGINAL_HALF, SIGN_BITS as u8);
    packed_right(format).emit(code, ORIGINAL_HALF, SIGN_BITS as u8);
    packed(code, Host::Xor, RESIDUAL, RESIDUAL);
    packed(
        code,
        if format == Format::Half {
            Host::EqualWord
        } else {
            Host::EqualDword
        },
        ORIGINAL_HALF,
        RESIDUAL,
    );
    if format == Format::Double {
        super::shuffle(code, SAVED_HALF, ORIGINAL_HALF, ADJACENT_DWORDS);
        packed(code, Host::And, ORIGINAL_HALF, SAVED_HALF);
    }
    packed(code, Host::Or, EXPONENT_VECTOR, ORIGINAL_HALF);
    let mask = if format == Format::Half {
        Host::ByteSignMask.register(code, 0, EXPONENT_VECTOR, TargetCpu::Baseline);
        (1u32 << (lanes(operand) * (format.bits() / BITS_PER_BYTE))) - 1
    } else {
        Host::DwordSignMask.register(code, 0, EXPONENT_VECTOR, TargetCpu::Baseline);
        match (format, operand.shape) {
            (_, Shape::Scalar) => 1,
            (Format::Single, Shape::Vector64) => SINGLE_LOW_MASK,
            (Format::Single, Shape::Vector128) => SINGLE_FULL_MASK,
            (Format::Double, Shape::Vector128) => DOUBLE_FULL_MASK,
            _ => unreachable!("decoded checked round arrangement"),
        }
    };
    code.push(AND_EAX_IMMEDIATE);
    code.extend(mask.to_le_bytes());
    code.push(CMP_EAX_IMMEDIATE);
    code.extend(mask.to_le_bytes());
    helper.push(branch(code, Condition::NotZero));
}

fn round_instruction(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    rounding: Direction,
    target: TargetCpu,
) {
    let opcode = match (format, shape) {
        (Format::Single, Shape::Scalar) => Host::RoundScalarSingle,
        (Format::Double, Shape::Scalar) => Host::RoundScalarDouble,
        (Format::Single, _) => Host::RoundPackedSingle,
        (Format::Double, _) => Host::RoundPackedDouble,
        _ => unreachable!("half rounds after exact widening"),
    };
    let mode = match rounding {
        Direction::NearestEven => ROUND_NEAREST,
        Direction::Positive => ROUND_POSITIVE,
        Direction::Negative => ROUND_NEGATIVE,
        Direction::Zero => ROUND_ZERO,
        Direction::NearestAway => unreachable!("ties-away uses an exact residual"),
    };
    opcode.register(code, RESULT, SOURCE, target);
    code.push(PRECISION_SUPPRESSED | mode);
}

fn fp_prefix(code: &mut Vec<u8>, format: Format, shape: Shape) {
    if shape == Shape::Scalar {
        code.push(if format == Format::Double {
            SCALAR_DOUBLE_PREFIX
        } else {
            SCALAR_SINGLE_PREFIX
        });
    } else if format == Format::Double {
        code.push(PACKED_DOUBLE_PREFIX);
    }
}

fn fp_arithmetic(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    opcode: ArithmeticOpcode,
    destination: u8,
    source: u8,
) {
    fp_prefix(code, format, shape);
    code.extend([
        SSE_ESCAPE,
        opcode as u8,
        REGISTER_DIRECT | (destination << REGISTER_SHIFT) | source,
    ]);
}

fn splat(code: &mut Vec<u8>, format: Format, vector: u8, bits: u64) {
    code.extend(MOVABS_RAX);
    code.extend(bits.to_le_bytes());
    packed(code, Host::MoveGprQword, vector, ACCUMULATOR_GPR);
    if format == Format::Single {
        super::shuffle(code, vector, vector, BROADCAST_LOW_DWORD);
    } else {
        packed(code, Host::UnpackLowQword, vector, vector);
    }
}

fn magnitude_mask(code: &mut Vec<u8>, format: Format, vector: u8) {
    packed(code, Host::EqualDword, vector, vector);
    packed_right(format).emit(code, vector, SIGN_BITS as u8);
}

fn ties_away(code: &mut Vec<u8>, format: Format, shape: Shape, target: TargetCpu) {
    round_instruction(code, format, shape, Direction::Zero, target);
    packed(code, Host::MoveAligned, RESIDUAL, SOURCE);
    fp_arithmetic(
        code,
        format,
        shape,
        ArithmeticOpcode::Subtract,
        RESIDUAL,
        RESULT,
    );
    magnitude_mask(code, format, MASK);
    packed(code, Host::And, RESIDUAL, MASK);
    splat(
        code,
        format,
        CONSTANT,
        u64::from(bias(format) - 1) << format.fraction_bits(),
    );
    // 0.5 <= abs(x-trunc(x)), with an ordered predicate and guarded finite data.
    fp_prefix(code, format, shape);
    code.extend([
        SSE_ESCAPE,
        COMPARE_OPCODE,
        REGISTER_DIRECT | (CONSTANT << REGISTER_SHIFT) | RESIDUAL,
        COMPARE_LESS_EQUAL,
    ]);
    packed(code, Host::EqualDword, MASK, MASK);
    packed_left(format).emit(code, MASK, sign_bit(format));
    packed(code, Host::And, MASK, SOURCE);
    splat(
        code,
        format,
        RESIDUAL,
        u64::from(bias(format)) << format.fraction_bits(),
    );
    packed(code, Host::Or, RESIDUAL, MASK);
    packed(code, Host::And, RESIDUAL, CONSTANT);
    fp_arithmetic(code, format, shape, ArithmeticOpcode::Add, RESULT, RESIDUAL);
    // Exact zero addition/subtraction can choose a host-RC sign. Force the
    // architectural original sign on every result, including signed zero.
    magnitude_mask(code, format, MASK);
    packed(code, Host::And, RESULT, MASK);
    packed(code, Host::EqualDword, CONSTANT, CONSTANT);
    packed(code, Host::Xor, MASK, CONSTANT);
    packed(code, Host::And, MASK, SOURCE);
    packed(code, Host::Or, RESULT, MASK);
}

fn checked_compute(
    code: &mut Vec<u8>,
    operation: RoundingOperation,
    format: Format,
    shape: Shape,
    target: TargetCpu,
) {
    if operation == RoundingOperation::NearestAway {
        ties_away(code, format, shape, target);
    } else {
        direction(code, operation, |code, mode| {
            round_instruction(code, format, shape, mode, target)
        });
    }
}

fn half_bias(code: &mut Vec<u8>, vector: u8) {
    let adjustment = (bias(Format::Single) - bias(Format::Half)) << Format::Single.fraction_bits();
    let position = adjustment.trailing_zeros();
    let digits = (adjustment >> position).ilog2() + 1;
    packed(code, Host::EqualDword, vector, vector);
    ShiftOpcode::RightDword.emit(code, vector, (u32::BITS - digits) as u8);
    ShiftOpcode::LeftDword.emit(code, vector, position as u8);
}

fn widen_half(code: &mut Vec<u8>, upper: bool) {
    let sign_shift = (Format::Single.bits() - Format::Half.bits()) as u8;
    let strip_sign = sign_shift + SIGN_BITS as u8;
    let fraction_shift = (Format::Single.fraction_bits() - Format::Half.fraction_bits()) as u8;
    packed(code, Host::MoveAligned, RESULT, ORIGINAL_HALF);
    if upper {
        ShiftOpcode::RightBytes.emit(code, RESULT, (u64::BITS / BITS_PER_BYTE) as u8);
    }
    packed(code, Host::Xor, CONSTANT, CONSTANT);
    packed(code, Host::UnpackLowWord, RESULT, CONSTANT);
    packed(code, Host::MoveAligned, TEMP, RESULT);
    ShiftOpcode::LeftDword.emit(code, TEMP, sign_shift);
    ShiftOpcode::RightDword.emit(code, TEMP, sign_bit(Format::Single));
    ShiftOpcode::LeftDword.emit(code, TEMP, sign_bit(Format::Single));
    packed(code, Host::MoveAligned, RESIDUAL, RESULT);
    ShiftOpcode::LeftDword.emit(code, RESIDUAL, strip_sign);
    ShiftOpcode::RightDword.emit(code, RESIDUAL, strip_sign);
    packed(code, Host::EqualDword, RESIDUAL, CONSTANT);
    ShiftOpcode::LeftDword.emit(code, RESULT, strip_sign);
    ShiftOpcode::RightDword.emit(code, RESULT, strip_sign - fraction_shift);
    half_bias(code, MASK);
    packed(code, Host::AddDword, RESULT, MASK);
    packed(code, Host::AndNot, RESIDUAL, RESULT); // preserve exact half zeros
    packed(code, Host::Or, RESIDUAL, TEMP);
    packed(code, Host::MoveAligned, SOURCE, RESIDUAL);
}

fn pack_half(code: &mut Vec<u8>, target: TargetCpu) {
    packed(code, Host::MoveAligned, TEMP, RESULT);
    ShiftOpcode::RightDword.emit(code, TEMP, sign_bit(Format::Single));
    ShiftOpcode::LeftDword.emit(code, TEMP, sign_bit(Format::Half));
    packed(code, Host::MoveAligned, RESIDUAL, RESULT);
    ShiftOpcode::LeftDword.emit(code, RESIDUAL, SIGN_BITS as u8);
    ShiftOpcode::RightDword.emit(code, RESIDUAL, SIGN_BITS as u8);
    packed(code, Host::Xor, CONSTANT, CONSTANT);
    packed(code, Host::MoveAligned, MASK, RESIDUAL);
    packed(code, Host::EqualDword, MASK, CONSTANT);
    half_bias(code, CONSTANT);
    packed(code, Host::SubDword, RESIDUAL, CONSTANT);
    ShiftOpcode::RightDword.emit(
        code,
        RESIDUAL,
        (Format::Single.fraction_bits() - Format::Half.fraction_bits()) as u8,
    );
    packed(code, Host::AndNot, MASK, RESIDUAL);
    packed(code, Host::Or, MASK, TEMP);
    Host::PackUnsignedDwordToWord.register(code, MASK, MASK, target);
}

fn checked_half(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    packed(code, Host::MoveAligned, ORIGINAL_HALF, SOURCE);
    widen_half(code, false);
    checked_compute(
        code,
        operand.operation,
        Format::Single,
        Shape::Vector128,
        target,
    );
    pack_half(code, target);
    if operand.shape == Shape::Vector128 {
        packed(code, Host::MoveAligned, SAVED_HALF, MASK);
        widen_half(code, true);
        checked_compute(
            code,
            operand.operation,
            Format::Single,
            Shape::Vector128,
            target,
        );
        pack_half(code, target);
        packed(code, Host::UnpackLowQword, SAVED_HALF, MASK);
        packed(code, Host::MoveAligned, RESULT, SAVED_HALF);
    } else {
        packed(code, Host::MoveAligned, RESULT, MASK);
    }
    packed(code, Host::MoveAligned, SOURCE, ORIGINAL_HALF);
}

fn checked_bounds(code: &mut Vec<u8>, operand: &Operand, helper: &mut Vec<usize>) {
    let Some(width) = operand.operation.signed_width() else {
        return;
    };
    packed(code, Host::MoveAligned, TEMP, RESULT);
    for _ in 0..lanes(operand) {
        read_lane(code, operand.format, TEMP);
        bounded(code, operand.format, width, helper);
        ShiftOpcode::RightBytes.emit(code, TEMP, (operand.format.bits() / BITS_PER_BYTE) as u8);
    }
}

fn checked_inexact(code: &mut Vec<u8>, operand: &Operand) {
    if !operand.operation.exact() {
        return;
    }
    code.extend(XOR_R10D_R10D);
    packed(code, Host::MoveAligned, TEMP, RESULT);
    packed(code, Host::EqualByte, TEMP, SOURCE);
    Host::ByteSignMask.register(code, 0, TEMP, TargetCpu::Baseline);
    let mask = (1u32 << (lanes(operand) * (operand.format.bits() / BITS_PER_BYTE))) - 1;
    code.push(AND_EAX_IMMEDIATE);
    code.extend(mask.to_le_bytes());
    code.push(CMP_EAX_IMMEDIATE);
    code.extend(mask.to_le_bytes());
    code.extend(SETNE_R10B);
}

fn checked_rounding(
    code: &mut Vec<u8>,
    operand: &Operand,
    helper: &mut Vec<usize>,
    target: TargetCpu,
) {
    checked_source(code, operand, helper);
    if operand.format == Format::Half {
        checked_half(code, operand, target);
    } else {
        checked_compute(
            code,
            operand.operation,
            operand.format,
            operand.shape,
            target,
        );
    }
    checked_bounds(code, operand, helper);
    checked_inexact(code, operand);
}

fn helper_section(code: &mut Vec<u8>, helper: &[usize], pc: GuestAddress) {
    let completed = jump(code);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let success = code.len();
    for &patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, completed, success);
}

fn commit_result(code: &mut Vec<u8>, operand: &Operand) {
    if operand.operation.exact() {
        code.extend(SHL_R10D);
        code.push(INEXACT_SHIFT);
        code.extend(OR_STATE_R10D);
        code.extend((std::mem::offset_of!(GuestState, fpsr) as u32).to_le_bytes());
    }
    let result = if operand.shape == Shape::Scalar {
        read_vector(code, operand.destination, SAVED_HALF);
        match operand.format {
            Format::Half => {
                read_lane(code, Format::Half, RESULT);
                code.extend(PINSRW_FROM_EAX);
                code.push(REGISTER_DIRECT | (SAVED_HALF << REGISTER_SHIFT));
                code.push(FIRST_LANE);
            }
            Format::Single => code.extend(MOVSS_XMM6_XMM0),
            Format::Double => code.extend(MOVSD_XMM6_XMM0),
        }
        test_control(code, FPCR_NEP);
        let merging = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, SAVED_HALF);
        let merged = code.len();
        resolve(code, merging, merged);
        SAVED_HALF
    } else {
        if operand.shape == Shape::Vector64 {
            clear_scalar(code, Format::Double, RESULT);
        }
        RESULT
    };
    commit(code, operand.destination, result);
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    let mut helper = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    read_numerical_vector(code, operand.shape, operand.source, SOURCE);
    // Scalar Half widening and packing cost more than compact integer rounding.
    // Packed Half and S/D still benefit from capability-checked ROUND.
    let scalar_half = operand.format == Format::Half && operand.shape == Shape::Scalar;
    if target.supports(TargetCpu::Sse41) && !scalar_half {
        checked_rounding(code, operand, &mut helper, target);
    } else {
        integer_rounding(code, operand, &mut helper);
    }
    helper_section(code, &helper, pc);
    commit_result(code, operand);
}
