//! FMLAL/FMLSL on normal half inputs with one final rounding.
use super::super::isa::ShiftOpcode;
use super::numerical::{
    ArithmeticOpcode, Condition, FusedOpcode, VZEROUPPER, branch, clear_scalar, commit_inexact,
    emit_fma, emit_opcode, environment, prepare_vector_input_range, read_numerical_right,
    read_numerical_vector, reject_other_status, resolve, restore_environment, test_control,
    vector_exponent_range, vector_half_exponent_range, widen_half_to_single,
};
use super::{Host, commit, packed, read_vector, shuffle};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, Format, widening::WideningOperation},
        simd::{arithmetic::Shape, widening::Operand},
    },
    block::ExitKind,
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const SIGN_MASK: u8 = 2;
const WIDEN_SIGN: u8 = 4;
const ZERO: u8 = 5;
const ADDEND: u8 = 6;
const WIDEN_BIAS: u8 = 7;
const EAX: u8 = 0;
const FIRST_LANE: u8 = 0;
const HALF_BYTES: u32 = Format::Half.bits() / u8::BITS;
const HALF_LOW_BYTE_MASK: u32 = (1 << (2 * HALF_BYTES)) - 1;
const HALF_GROUP_BYTE_MASK: u32 = (1 << (4 * HALF_BYTES)) - 1;
const SIGN_BITS: u8 = 1;
const SINGLE_SIGN_SHIFT: u8 = Format::Single.bits() as u8 - SIGN_BITS;
const HALF_TO_SINGLE_BIAS: u32 = (Format::Single.exponent_bias() - Format::Half.exponent_bias())
    << Format::Single.fraction_bits();
const MOV_EAX_IMM32: u8 = 0xb8;
const MOVD_XMM_EAX_PREFIX: &[u8] = &[0x66, 0x0f, 0x6e];
const REGISTER_DIRECT: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;

fn select_part(code: &mut Vec<u8>, operand: &Operand, source: u8, vector: u8) {
    read_vector(code, source, vector);
    let offset = operand.part.source_lane_offset(operand.shape) * HALF_BYTES;
    if offset != 0 {
        ShiftOpcode::RightBytes.emit(code, vector, offset as u8);
    }
}

fn prepare_sources(code: &mut Vec<u8>, operand: &Operand) {
    // Snapshot every guest source before the single eventual destination store.
    select_part(code, operand, operand.left, LEFT);
    if operand.right_lane.is_some() {
        read_numerical_right(
            code,
            Format::Half,
            operand.shape,
            operand.right,
            operand.right_lane,
        );
    } else {
        select_part(code, operand, operand.right, RIGHT);
    }
    read_numerical_vector(code, operand.shape, operand.destination, ADDEND);
}

fn prepare_integer_widening(code: &mut Vec<u8>) {
    packed(code, Host::Xor, ZERO, ZERO);
    code.push(MOV_EAX_IMM32);
    code.extend(HALF_TO_SINGLE_BIAS.to_le_bytes());
    code.extend(MOVD_XMM_EAX_PREFIX);
    code.push(REGISTER_DIRECT | WIDEN_BIAS << MODRM_REGISTER_SHIFT | EAX);
    shuffle(code, WIDEN_BIAS, WIDEN_BIAS, FIRST_LANE);
    for vector in [LEFT, RIGHT] {
        widen_half_to_single(code, vector, vector, WIDEN_SIGN, ZERO, WIDEN_BIAS);
    }
}

fn prepare_checked_widening(code: &mut Vec<u8>, shape: Shape, target: TargetCpu) {
    for vector in [LEFT, RIGHT] {
        if shape == Shape::Vector64 {
            // Exactly two half lanes are active. Clear H2/H3 before VCVTPH2PS
            // so that stale signaling NaNs in Vm cannot raise status.
            clear_scalar(code, Format::Single, vector);
        }
        Host::ConvertHalfToSingle.register(code, vector, vector, target);
    }
}

fn use_fma(operand: &Operand, target: TargetCpu) -> bool {
    target.supports(TargetCpu::Fma)
        && (operand.operation == WideningOperation::Add || operand.shape == Shape::Vector64)
}

fn arithmetic(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    if use_fma(operand, target) {
        let opcode = match operand.operation {
            WideningOperation::Add => FusedOpcode::MultiplyAdd,
            WideningOperation::Subtract => FusedOpcode::NegativeMultiplyAdd,
        };
        emit_fma(code, Format::Single, operand.shape, opcode, target);
    } else {
        if operand.operation == WideningOperation::Subtract {
            // Accepted finite normals make FPNeg an exact sign toggle. Negate
            // the multiplicand before multiplication, never the rounded sum.
            packed(code, Host::EqualDword, SIGN_MASK, SIGN_MASK);
            ShiftOpcode::LeftDword.emit(code, SIGN_MASK, SINGLE_SIGN_SHIFT);
            packed(code, Host::Xor, LEFT, SIGN_MASK);
        }
        // Two finite half significands give at most 22 product bits and their
        // exponents fit a normal single, so MULPS is exact under any rounding
        // mode and ADDPS performs the only rounding.
        emit_opcode(
            code,
            Format::Single,
            operand.shape,
            ArithmeticOpcode::Multiply,
            RIGHT,
        );
        emit_opcode(
            code,
            Format::Single,
            operand.shape,
            ArithmeticOpcode::Add,
            ADDEND,
        );
    }
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    assert!(operand.shape != Shape::Scalar, "FHM requires vector lanes");
    if target.supports(TargetCpu::F16c) || use_fma(operand, target) {
        code.extend(VZEROUPPER);
    }
    let mut helper = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    prepare_sources(code, operand);
    let half_mask = match operand.shape {
        Shape::Vector64 => HALF_LOW_BYTE_MASK,
        Shape::Vector128 => HALF_GROUP_BYTE_MASK,
        Shape::Scalar => unreachable!("FHM requires vector lanes"),
    };
    prepare_vector_input_range(code, Format::Half);
    for source in [LEFT, RIGHT] {
        vector_half_exponent_range(code, source, half_mask);
        helper.push(branch(code, Condition::NotZero));
    }
    prepare_vector_input_range(code, Format::Single);
    vector_exponent_range(code, Format::Single, operand.shape, ADDEND);
    let accepted = branch(code, Condition::Zero);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let accepted_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, accepted, accepted_start);
    if target.supports(TargetCpu::F16c) {
        prepare_checked_widening(code, operand.shape, target);
    } else {
        prepare_integer_widening(code);
    }
    environment(code);
    arithmetic(code, operand, target);
    restore_environment(code);
    // Nonzero sums are at least 2^-72, hence normal Single. Exact cancellation
    // zero has the guest RC sign. Overflow and unexpected status take the full
    // core only after complete caller MXCSR/RSP restoration, before any commit.
    let unexpected = reject_other_status(code);
    resolve(code, unexpected, helper_start);
    commit_inexact(code);
    if operand.shape == Shape::Vector64 {
        packed(code, Host::MoveQword, LEFT, LEFT);
    }
    commit(code, operand.destination, LEFT);
}
