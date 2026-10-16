//! SVE integer dot products, one 128-bit segment at a time. All sources are
//! staged before each destination chunk is written.

use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength, is_z_register};
use crate::aarch64::sve::dot::{Kind, Operand, Products, RightOperand, Signedness};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};
use crate::x86_64::scalable::{load_z_chunk, store_z_chunk};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const LEFT_HIGH: u8 = 2;
const RIGHT_HIGH: u8 = 3;
const SIGNS: u8 = 4;
const WIDE_HIGH: u8 = 5;
const PAIR_SWAP: u8 = 6;
const ACCUMULATOR: u8 = 7;

const BYTE_BITS: u8 = 8;
const WORD_SIGN_SHIFT: u8 = 31;
const SWAP_ADJACENT_DWORDS: u8 = 0xb1;
const SELECT_EVEN_DWORDS: u8 = 0x88;
const SWAP_QWORDS: u8 = 0x4e;
const REPLICATE_LOW_QWORD: u8 = 0x44;
const REPLICATE_HIGH_QWORD: u8 = 0xee;
const BROADCAST_DWORD: u8 = 0x55;
const INDEXED_WORD_REGISTERS: u8 = 8;
const INDEXED_DOUBLEWORD_REGISTERS: u8 = 16;

fn packed(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn shuffle(code: &mut Vec<u8>, destination: u8, source: u8, control: u8) {
    packed(code, Host::ShuffleDword, destination, source);
    code.push(control);
}

fn index_right(code: &mut Vec<u8>, operand: &Operand) {
    if let RightOperand::Indexed { index, .. } = operand.right {
        let control = if operand.element_size == ElementSize::Word {
            index * BROADCAST_DWORD
        } else if index == 0 {
            REPLICATE_LOW_QWORD
        } else {
            REPLICATE_HIGH_QWORD
        };
        shuffle(code, RIGHT, RIGHT, control);
    }
}

/// Split byte pairs into signed or unsigned word lanes. XMM0/2 receive the
/// even/odd left bytes, XMM1/3 the even/odd right bytes.
fn byte_components(code: &mut Vec<u8>, left_signed: bool, right_signed: bool) {
    packed(code, Host::MoveAligned, LEFT_HIGH, LEFT);
    packed(code, Host::MoveAligned, RIGHT_HIGH, RIGHT);
    for (low, high, signed) in [
        (LEFT, LEFT_HIGH, left_signed),
        (RIGHT, RIGHT_HIGH, right_signed),
    ] {
        Shift::LeftWord.emit(code, low, BYTE_BITS);
        let right_shift = if signed {
            Shift::ArithmeticWord
        } else {
            Shift::RightWord
        };
        right_shift.emit(code, low, BYTE_BITS);
        right_shift.emit(code, high, BYTE_BITS);
    }
}

fn byte_dot(code: &mut Vec<u8>, signedness: Signedness) {
    let left_signed = matches!(signedness, Signedness::Signed | Signedness::SignedUnsigned);
    let right_signed = matches!(signedness, Signedness::Signed | Signedness::UnsignedSigned);
    byte_components(code, left_signed, right_signed);
    packed(code, Host::MultiplyAddWords, LEFT, RIGHT);
    packed(code, Host::MultiplyAddWords, LEFT_HIGH, RIGHT_HIGH);
    packed(code, Host::AddDword, LEFT, LEFT_HIGH);
}

/// Reconstruct each individual 32-bit product before any horizontal sum.
/// The low/high four products finish in XMM0/XMM3. Unsigned halfword products
/// must be zero-extended later; signed pair overflow must never be widened.
fn halfword_products(code: &mut Vec<u8>, signed: bool) {
    packed(code, Host::MoveAligned, LEFT_HIGH, LEFT);
    packed(code, Host::MultiplyLowWord, LEFT, RIGHT);
    packed(
        code,
        if signed {
            Host::MultiplyHighSignedWord
        } else {
            Host::MultiplyHighUnsignedWord
        },
        LEFT_HIGH,
        RIGHT,
    );
    packed(code, Host::MoveAligned, RIGHT_HIGH, LEFT);
    packed(code, Host::UnpackLowWord, LEFT, LEFT_HIGH);
    packed(code, Host::UnpackHighWord, RIGHT_HIGH, LEFT_HIGH);
}

fn sum_halfword_pairs(code: &mut Vec<u8>, target: TargetCpu) {
    if target.supports(TargetCpu::Ssse3) {
        Host::HorizontalAddDword.register(code, LEFT, RIGHT_HIGH, target);
    } else {
        shuffle(code, SIGNS, LEFT, SWAP_ADJACENT_DWORDS);
        packed(code, Host::AddDword, LEFT, SIGNS);
        shuffle(code, SIGNS, RIGHT_HIGH, SWAP_ADJACENT_DWORDS);
        packed(code, Host::AddDword, RIGHT_HIGH, SIGNS);
        shuffle(code, LEFT, LEFT, SELECT_EVEN_DWORDS);
        shuffle(code, RIGHT_HIGH, RIGHT_HIGH, SELECT_EVEN_DWORDS);
        packed(code, Host::UnpackLowQword, LEFT, RIGHT_HIGH);
    }
}

/// Four 32-bit products become one exact 64-bit sum, replicated. For complex
/// subtraction the even and odd products are summed separately first; each
/// signed product fits in 32 bits, but pair sums may not.
fn sum_four_wide(code: &mut Vec<u8>, source: u8, signed: bool, subtract_odd: bool) {
    packed(code, Host::MoveAligned, WIDE_HIGH, source);
    if signed {
        packed(code, Host::MoveAligned, SIGNS, source);
        Shift::ArithmeticDword.emit(code, SIGNS, WORD_SIGN_SHIFT);
    } else {
        packed(code, Host::Xor, SIGNS, SIGNS);
    }
    packed(code, Host::UnpackLowDword, source, SIGNS);
    packed(code, Host::UnpackHighDword, WIDE_HIGH, SIGNS);
    packed(code, Host::AddQword, source, WIDE_HIGH);
    shuffle(code, PAIR_SWAP, source, SWAP_QWORDS);
    packed(
        code,
        if subtract_odd {
            Host::SubQword
        } else {
            Host::AddQword
        },
        source,
        PAIR_SWAP,
    );
}

fn halfword_dot(code: &mut Vec<u8>, signed: bool, wide: bool, target: TargetCpu) {
    if signed && !wide {
        // The PMADDWD overflow case is exactly the required modulo32 result.
        packed(code, Host::MultiplyAddWords, LEFT, RIGHT);
        return;
    }
    halfword_products(code, signed);
    if wide {
        sum_four_wide(code, LEFT, signed, false);
        sum_four_wide(code, RIGHT_HIGH, signed, false);
        packed(code, Host::UnpackLowQword, LEFT, RIGHT_HIGH);
    } else {
        sum_halfword_pairs(code, target);
    }
}

fn complex_byte_dot(code: &mut Vec<u8>, select_imaginary: bool, subtract: bool) {
    byte_components(code, true, true);
    let (real, imaginary) = if select_imaginary {
        (RIGHT_HIGH, RIGHT)
    } else {
        (RIGHT, RIGHT_HIGH)
    };
    packed(code, Host::MultiplyAddWords, LEFT, real);
    packed(code, Host::MultiplyAddWords, LEFT_HIGH, imaginary);
    packed(
        code,
        if subtract {
            Host::SubDword
        } else {
            Host::AddDword
        },
        LEFT,
        LEFT_HIGH,
    );
}

fn complex_halfword_dot(code: &mut Vec<u8>, select_imaginary: bool, subtract: bool) {
    if select_imaginary {
        for opcode in [Host::ShuffleLowWord, Host::ShuffleHighWord] {
            packed(code, opcode, RIGHT, RIGHT);
            code.push(SWAP_ADJACENT_DWORDS);
        }
    }
    halfword_products(code, true);
    sum_four_wide(code, LEFT, true, subtract);
    sum_four_wide(code, RIGHT_HIGH, true, subtract);
    packed(code, Host::UnpackLowQword, LEFT, RIGHT_HIGH);
}

/// Emit the integer dot forms only. Any other operand returns false before
/// appending bytes.
pub(crate) fn emit_integer(
    code: &mut Vec<u8>,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
) -> bool {
    let wide = match operand.element_size {
        ElementSize::Word => false,
        ElementSize::Doubleword => true,
        _ => return false,
    };
    if !is_z_register(operand.destination) || !is_z_register(operand.left) {
        return false;
    }
    let right = match operand.right {
        RightOperand::Vector(register) if is_z_register(register) => register,
        RightOperand::Indexed { register, index }
            if register
                < if wide {
                    INDEXED_DOUBLEWORD_REGISTERS
                } else {
                    INDEXED_WORD_REGISTERS
                }
                && usize::from(index) < VECTOR_CHUNK_BYTES / operand.element_size.bytes() =>
        {
            register
        }
        _ => return false,
    };
    match operand.kind {
        Kind::Integer {
            signedness,
            products,
        } if (wide || products == Products::Two)
            && !matches!(signedness, Signedness::Signed | Signedness::Unsigned) =>
        {
            return false;
        }
        Kind::Integer {
            products: Products::Two,
            ..
        } if wide => return false,
        Kind::Integer { .. } | Kind::Complex { .. } => {}
        Kind::HalfDot | Kind::HalfMultiplyLong { .. } => return false,
    }
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.left, chunk, LEFT, length, target);
        load_z_chunk(code, right, chunk, RIGHT, length, target);
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            ACCUMULATOR,
            length,
            target,
        );
        index_right(code, operand);
        match operand.kind {
            Kind::Integer {
                signedness,
                products: Products::Four,
            } if !wide => byte_dot(code, signedness),
            Kind::Integer { signedness, .. } => {
                halfword_dot(code, signedness == Signedness::Signed, wide, target);
            }
            Kind::Complex { rotation } => {
                let (select_real, _, subtract) = rotation.component_selection();
                if wide {
                    complex_halfword_dot(code, select_real != 0, subtract);
                } else {
                    complex_byte_dot(code, select_real != 0, subtract);
                }
            }
            Kind::HalfDot | Kind::HalfMultiplyLong { .. } => {
                unreachable!("floating dot rejected before emission")
            }
        }
        packed(
            code,
            if wide { Host::AddQword } else { Host::AddDword },
            LEFT,
            ACCUMULATOR,
        );
        store_z_chunk(code, operand.destination, chunk, LEFT, length, target);
    }
    true
}

#[cfg(test)]
mod tests;
