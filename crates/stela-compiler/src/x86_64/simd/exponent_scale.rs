//! Integer power-of-two scaling (FSCALE) shared by AdvSIMD and SME.
//! Inputs XMM0/1, result XMM0; clobbers XMM2-5, RAX/RCX/RDX and flags.
//! Only normal inputs and results take this path.
use super::{
    Host,
    numerical::{Condition, branch, prepare_vector_input_range, vector_exponent_range},
    packed, packed_imm,
};
use crate::x86_64::asm::{Alu, Code, Gpr, ShiftOp, Size};
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
const REPEAT_LOW_DWORD: u8 = 0;
const LOW_VECTOR_BYTE_MASK: u32 = 0xff;
const FULL_VECTOR_BYTE_MASK: u32 = 0xffff;
const DOUBLE_EXPONENT_SHIFT: u8 = Format::Double.fraction_bits() as u8;
const DOUBLE_EXPONENT_MASK: u32 =
    (Format::Double.exponent_mask() >> Format::Double.fraction_bits()) as u32;
const DOUBLE_MAXIMUM_NORMAL_MINUS_ONE: u32 = DOUBLE_EXPONENT_MASK - 1;

pub(in crate::x86_64) fn emit(
    code: &mut Code,
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
    // Extract the exponent field alone. Adding a bounded positive exponent to a
    // signed lane can overflow only to negative, so the signed range checks
    // catch every unrepresentable sum.
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
    code.asm().mov_imm32(Gpr::Rax, constant);
    if format == Format::Double {
        code.asm().movq_to_xmm(MAXIMUM, Gpr::Rax);
        packed(code, Host::UnpackLowQword, MAXIMUM, MAXIMUM);
    } else {
        code.asm().movd_to_xmm(MAXIMUM, Gpr::Rax);
        packed_imm(code, Host::ShuffleDword, MAXIMUM, MAXIMUM, REPEAT_LOW_DWORD);
    }
    greater.register(code, MAXIMUM, EXPONENT, target);
    packed(code, Host::And, VALID, MAXIMUM);
    Host::ByteSignMask.register(code, 0, VALID, TargetCpu::Baseline);
    // Q0's upper zero lanes are outside the architectural vector and must not
    // reject an otherwise valid operation.
    let mask = if shape == Shape::Vector64 {
        LOW_VECTOR_BYTE_MASK
    } else {
        FULL_VECTOR_BYTE_MASK
    };
    code.asm()
        .alu_accumulator_imm32(Alu::Cmp, Size::Dword, mask as i32);
    failures.push(branch(code, Condition::NotZero));
    left_shift.emit(code, RIGHT, format.fraction_bits() as u8);
    packed(code, add, LEFT, RIGHT);
}

fn scale_double(code: &mut Code, failures: &mut Vec<usize>) {
    for lane in 0..2 {
        packed(code, Host::MoveAligned, EXPONENT, LEFT);
        packed(code, Host::MoveAligned, VALID, RIGHT);
        if lane != 0 {
            ShiftOpcode::RightBytes.emit(code, EXPONENT, size_of::<u64>() as u8);
            ShiftOpcode::RightBytes.emit(code, VALID, size_of::<u64>() as u8);
        }
        let mut asm = code.asm();
        asm.movq_from_xmm(Gpr::Rax, EXPONENT);
        asm.movq_from_xmm(Gpr::Rcx, VALID);
        asm.mov(Size::Qword, Gpr::Rdx, Gpr::Rax);
        asm.shift_imm(ShiftOp::Shr, Size::Qword, Gpr::Rdx, DOUBLE_EXPONENT_SHIFT);
        asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rdx, DOUBLE_EXPONENT_MASK as i32);
        // (exponent - 1) < 2046 admits exactly normal exponent fields.
        asm.alu_imm8(Alu::Sub, Size::Qword, Gpr::Rdx, 1);
        asm.alu_imm32(
            Alu::Cmp,
            Size::Qword,
            Gpr::Rdx,
            DOUBLE_MAXIMUM_NORMAL_MINUS_ONE as i32,
        );
        failures.push(branch(code, Condition::AboveOrEqual));
        let mut asm = code.asm();
        asm.alu_imm8(Alu::Add, Size::Qword, Gpr::Rdx, 1);
        asm.alu(Alu::Add, Size::Qword, Gpr::Rdx, Gpr::Rcx);
        asm.alu_imm8(Alu::Sub, Size::Qword, Gpr::Rdx, 1);
        asm.alu_imm32(
            Alu::Cmp,
            Size::Qword,
            Gpr::Rdx,
            DOUBLE_MAXIMUM_NORMAL_MINUS_ONE as i32,
        );
        failures.push(branch(code, Condition::AboveOrEqual));
        let mut asm = code.asm();
        asm.shift_imm(ShiftOp::Shl, Size::Qword, Gpr::Rcx, DOUBLE_EXPONENT_SHIFT);
        asm.alu(Alu::Add, Size::Qword, Gpr::Rax, Gpr::Rcx);
        asm.movq_to_xmm(if lane == 0 { MAXIMUM } else { ZERO }, Gpr::Rax);
    }
    packed(code, Host::UnpackLowQword, MAXIMUM, ZERO);
    packed(code, Host::MoveAligned, LEFT, MAXIMUM);
}
