//! Integer power-of-two scaling (FSCALE) shared by AdvSIMD and SME.
//! Inputs XMM0/1, result XMM0; clobbers XMM2-5, RAX/RCX/RDX and flags.
//! Only normal inputs and results take this path.
use super::{
    Host,
    numerical::{Condition, branch, prepare_vector_input_range, vector_exponent_range},
    packed,
};
use crate::{
    TargetCpu,
    aarch64::{floating::Format, simd::arithmetic::Shape},
    x86_64::isa::ShiftOpcode,
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const EXPONENT: u8 = 2;
const VALID: u8 = 3;
const MAXIMUM: u8 = 4;
const ZERO: u8 = 5;
const ONE_BIT: u8 = 1;
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const MOVD_XMM4_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xe0];
const REPEAT_LOW_DWORD: u8 = 0;
const PMOVMSKB_EAX_XMM3: &[u8] = &[0x66, 0x0f, 0xd7, 0xc3];
const CMP_EAX_IMMEDIATE: u8 = 0x3d;
const LOW_VECTOR_BYTE_MASK: u32 = 0xff;
const FULL_VECTOR_BYTE_MASK: u32 = 0xffff;
const MOVQ_RAX_XMM2: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xd0];
const MOVQ_RCX_XMM3: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xd9];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const SHR_RDX: &[u8] = &[0x48, 0xc1, 0xea];
const AND_EDX: &[u8] = &[0x81, 0xe2];
const SUB_RDX_ONE: &[u8] = &[0x48, 0x83, 0xea, 1];
const ADD_RDX_ONE: &[u8] = &[0x48, 0x83, 0xc2, 1];
const ADD_RDX_RCX: &[u8] = &[0x48, 0x01, 0xca];
const CMP_RDX: &[u8] = &[0x48, 0x81, 0xfa];
const SHL_RCX: &[u8] = &[0x48, 0xc1, 0xe1];
const ADD_RAX_RCX: &[u8] = &[0x48, 0x01, 0xc8];
const MOVQ_XMM4_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xe0];
const MOVQ_XMM5_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xe8];
const DOUBLE_EXPONENT_SHIFT: u8 = Format::Double.fraction_bits() as u8;
const DOUBLE_EXPONENT_MASK: u32 =
    (Format::Double.exponent_mask() >> Format::Double.fraction_bits()) as u32;
const DOUBLE_MAXIMUM_NORMAL_MINUS_ONE: u32 = DOUBLE_EXPONENT_MASK - 1;

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    format: Format,
    shape: Shape,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    if format == Format::Double && !target.supports(TargetCpu::Sse42) {
        scale_double(code, failures);
        return;
    }
    prepare_vector_input_range(code, format);
    vector_exponent_range(code, format, shape, LEFT);
    failures.push(branch(code, Condition::NotZero));
    let (left_shift, right_shift, add, greater) = match format {
        Format::Half => (
            ShiftOpcode::LeftWord,
            ShiftOpcode::RightWord,
            Host::AddWord,
            Host::GreaterWord,
        ),
        Format::Single => (
            ShiftOpcode::LeftDword,
            ShiftOpcode::RightDword,
            Host::AddDword,
            Host::GreaterDword,
        ),
        Format::Double => (
            ShiftOpcode::LeftQword,
            ShiftOpcode::RightQword,
            Host::AddQword,
            Host::GreaterQword,
        ),
    };
    // Extract the positive exponent with no sign/fraction bits. Addition of a
    // bounded positive exponent to a signed lane can overflow only to negative;
    // the signed range guards therefore reject every unrepresentable sum.
    packed(code, Host::MoveAligned, EXPONENT, LEFT);
    left_shift.emit(code, EXPONENT, ONE_BIT);
    right_shift.emit(code, EXPONENT, (format.fraction_bits() + 1) as u8);
    packed(code, add, EXPONENT, RIGHT);
    packed(code, Host::Xor, ZERO, ZERO);
    packed(code, Host::MoveAligned, VALID, EXPONENT);
    greater.register(code, VALID, ZERO, target);
    let maximum = (format.exponent_mask() >> format.fraction_bits()) as u32;
    let constant = if format == Format::Half {
        maximum | (maximum << u16::BITS)
    } else {
        maximum
    };
    code.push(MOV_EAX_IMMEDIATE);
    code.extend(constant.to_le_bytes());
    if format == Format::Double {
        code.extend(MOVQ_XMM4_RAX);
        packed(code, Host::UnpackLowQword, MAXIMUM, MAXIMUM);
    } else {
        code.extend(MOVD_XMM4_EAX);
        packed(code, Host::ShuffleDword, MAXIMUM, MAXIMUM);
        code.push(REPEAT_LOW_DWORD);
    }
    greater.register(code, MAXIMUM, EXPONENT, target);
    packed(code, Host::And, VALID, MAXIMUM);
    code.extend(PMOVMSKB_EAX_XMM3);
    code.push(CMP_EAX_IMMEDIATE);
    // Q0's upper zero lanes are outside the architectural vector and must not
    // reject an otherwise valid operation.
    let mask = if shape == Shape::Vector64 {
        LOW_VECTOR_BYTE_MASK
    } else {
        FULL_VECTOR_BYTE_MASK
    };
    code.extend(mask.to_le_bytes());
    failures.push(branch(code, Condition::NotZero));
    left_shift.emit(code, RIGHT, format.fraction_bits() as u8);
    packed(code, add, LEFT, RIGHT);
}

fn scale_double(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
    for lane in 0..2 {
        packed(code, Host::MoveAligned, EXPONENT, LEFT);
        packed(code, Host::MoveAligned, VALID, RIGHT);
        if lane != 0 {
            ShiftOpcode::RightBytes.emit(code, EXPONENT, size_of::<u64>() as u8);
            ShiftOpcode::RightBytes.emit(code, VALID, size_of::<u64>() as u8);
        }
        code.extend(MOVQ_RAX_XMM2);
        code.extend(MOVQ_RCX_XMM3);
        code.extend(MOV_RDX_RAX);
        code.extend(SHR_RDX);
        code.push(DOUBLE_EXPONENT_SHIFT);
        code.extend(AND_EDX);
        code.extend(DOUBLE_EXPONENT_MASK.to_le_bytes());
        // (exponent - 1) < 2046 admits exactly normal exponent fields.
        code.extend(SUB_RDX_ONE);
        code.extend(CMP_RDX);
        code.extend(DOUBLE_MAXIMUM_NORMAL_MINUS_ONE.to_le_bytes());
        failures.push(branch(code, Condition::AboveOrEqual));
        code.extend(ADD_RDX_ONE);
        code.extend(ADD_RDX_RCX);
        code.extend(SUB_RDX_ONE);
        code.extend(CMP_RDX);
        code.extend(DOUBLE_MAXIMUM_NORMAL_MINUS_ONE.to_le_bytes());
        failures.push(branch(code, Condition::AboveOrEqual));
        code.extend(SHL_RCX);
        code.push(DOUBLE_EXPONENT_SHIFT);
        code.extend(ADD_RAX_RCX);
        code.extend(if lane == 0 {
            MOVQ_XMM4_RAX
        } else {
            MOVQ_XMM5_RAX
        });
    }
    packed(code, Host::UnpackLowQword, MAXIMUM, ZERO);
    packed(code, Host::MoveAligned, LEFT, MAXIMUM);
}
