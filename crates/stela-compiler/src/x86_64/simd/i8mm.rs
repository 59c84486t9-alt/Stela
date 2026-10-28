//! Byte dot products and 2x8-by-8x2 matrix multiply-accumulate.
use super::{Host, commit, packed, read_vector, shuffle};
use crate::x86_64::asm::Code;
use crate::{
    TargetCpu,
    aarch64::simd::{
        arithmetic::Shape,
        i8mm::{Kind, Operand},
    },
    x86_64::isa::ShiftOpcode as Shift,
};

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const LEFT_HIGH: u8 = 2;
const RIGHT_HIGH: u8 = 3;
const EXTENSION_MASK: u8 = 4;
const ORIGINAL_LEFT: u8 = 5;
const ORIGINAL_RIGHT: u8 = 6;
// The mask register is dead once operands are widened or the first dot is complete.
const FIRST_HALF_SUM: u8 = EXTENSION_MASK;
const ROW0_COLUMN1_PRODUCTS: u8 = EXTENSION_MASK;
const ROW1_COLUMN1_PRODUCTS: u8 = ORIGINAL_LEFT;
const RESULT: u8 = LEFT;
const OLD_DESTINATION: u8 = RIGHT;
const BYTE_BITS: u8 = 8;
const DOT_GROUP_BROADCAST: u8 = 0x55;
const MATRIX_LEFT_LOW: u8 = 0xa0; // Dwords [0, 0, 2, 2].
const MATRIX_LEFT_HIGH: u8 = 0xf5; // Dwords [1, 1, 3, 3].
const MATRIX_RIGHT_LOW: u8 = 0x88; // Dwords [0, 2, 0, 2].
const MATRIX_RIGHT_HIGH: u8 = 0xdd; // Dwords [1, 3, 1, 3].

/// XMM0/1 hold four byte groups. Separate even/odd bytes into exact signed
/// words (unsigned bytes fit positive signed words), then combine PMADDWD sums.
/// Six shifts avoid materializing the low-byte mask for one guest instruction.
fn dot_sum(code: &mut Code, left_signed: bool, right_signed: bool) {
    packed(code, Host::MoveAligned, LEFT_HIGH, LEFT);
    packed(code, Host::MoveAligned, RIGHT_HIGH, RIGHT);
    for (low, high, signed) in [
        (LEFT, LEFT_HIGH, left_signed),
        (RIGHT, RIGHT_HIGH, right_signed),
    ] {
        Shift::LeftWord.emit(code, low, BYTE_BITS);
        let right = if signed {
            Shift::ArithmeticWord
        } else {
            Shift::RightWord
        };
        right.emit(code, low, BYTE_BITS);
        right.emit(code, high, BYTE_BITS);
    }
    packed(code, Host::MultiplyAddWords, LEFT, RIGHT);
    packed(code, Host::MultiplyAddWords, LEFT_HIGH, RIGHT_HIGH);
    packed(code, Host::AddDword, RESULT, LEFT_HIGH);
}

fn matrix_sse2(code: &mut Code, left_signed: bool, right_signed: bool) {
    // XMM5/6 keep the left and right inputs for both halves.
    shuffle(code, LEFT, ORIGINAL_LEFT, MATRIX_LEFT_LOW);
    shuffle(code, RIGHT, ORIGINAL_RIGHT, MATRIX_RIGHT_LOW);
    dot_sum(code, left_signed, right_signed);
    packed(code, Host::MoveAligned, FIRST_HALF_SUM, RESULT);
    shuffle(code, LEFT, ORIGINAL_LEFT, MATRIX_LEFT_HIGH);
    shuffle(code, RIGHT, ORIGINAL_RIGHT, MATRIX_RIGHT_HIGH);
    dot_sum(code, left_signed, right_signed);
    packed(code, Host::AddDword, RESULT, FIRST_HALF_SUM);
}

fn matrix_ssse3(code: &mut Code, left_signed: bool, right_signed: bool, target: TargetCpu) {
    // Widen the two contiguous rows/columns to words. XMM0/2 are rows 0/1;
    // XMM1/3 are columns 0/1. A single zero mask serves both unsigned inputs.
    packed(code, Host::Xor, EXTENSION_MASK, EXTENSION_MASK);
    for (low, high, signed) in [
        (LEFT, LEFT_HIGH, left_signed),
        (RIGHT, RIGHT_HIGH, right_signed),
    ] {
        packed(code, Host::MoveAligned, high, low);
        if signed {
            packed(code, Host::GreaterByte, EXTENSION_MASK, low);
        }
        packed(code, Host::UnpackLowByte, low, EXTENSION_MASK);
        packed(code, Host::UnpackHighByte, high, EXTENSION_MASK);
        if low == LEFT && signed {
            packed(code, Host::Xor, EXTENSION_MASK, EXTENSION_MASK);
        }
    }
    packed(code, Host::MoveAligned, ROW0_COLUMN1_PRODUCTS, LEFT);
    packed(code, Host::MoveAligned, ROW1_COLUMN1_PRODUCTS, LEFT_HIGH);
    packed(code, Host::MultiplyAddWords, LEFT, RIGHT); // Row 0, column 0.
    packed(code, Host::MultiplyAddWords, LEFT_HIGH, RIGHT); // Row 1, column 0.
    packed(
        code,
        Host::MultiplyAddWords,
        ROW0_COLUMN1_PRODUCTS,
        RIGHT_HIGH,
    );
    packed(
        code,
        Host::MultiplyAddWords,
        ROW1_COLUMN1_PRODUCTS,
        RIGHT_HIGH,
    );
    // First reduce pairs for each row, then produce row-major [00,01,10,11].
    Host::HorizontalAddDword.register(code, LEFT, ROW0_COLUMN1_PRODUCTS, target);
    Host::HorizontalAddDword.register(code, LEFT_HIGH, ROW1_COLUMN1_PRODUCTS, target);
    Host::HorizontalAddDword.register(code, RESULT, LEFT_HIGH, target);
}

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
    let (left_signed, right_signed) = operand.kind.signedness();
    match operand.kind {
        Kind::Matrix(_) if target.supports(TargetCpu::Ssse3) => {
            read_vector(code, operand.left, LEFT);
            read_vector(code, operand.right, RIGHT);
            matrix_ssse3(code, left_signed, right_signed, target);
        }
        Kind::Matrix(_) => {
            read_vector(code, operand.left, ORIGINAL_LEFT);
            read_vector(code, operand.right, ORIGINAL_RIGHT);
            matrix_sse2(code, left_signed, right_signed);
        }
        Kind::Dot(_) => {
            read_vector(code, operand.left, LEFT);
            read_vector(code, operand.right, RIGHT);
            if let Some(index) = operand.index {
                shuffle(code, RIGHT, RIGHT, index * DOT_GROUP_BROADCAST);
            }
            dot_sum(code, left_signed, right_signed);
        }
    }
    read_vector(code, operand.destination, OLD_DESTINATION);
    packed(code, Host::AddDword, RESULT, OLD_DESTINATION);
    if operand.shape == Shape::Vector64 {
        packed(code, Host::MoveQword, RESULT, RESULT);
    }
    commit(code, operand.destination, RESULT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn emitted(word: u32, target: TargetCpu) -> Vec<u8> {
        let operand = crate::aarch64::simd::i8mm::decode(word).unwrap().unwrap();
        let mut code = Code::new();
        emit(&mut code, &operand, target);
        code.into_bytes()
    }

    #[test]
    fn only_checked_matrix_paths_use_horizontal_add() {
        const PHADDD: &[u8] = &[0x66, 0x0f, 0x38, 0x02];
        for word in [0x4e80a400, 0x6e80a400, 0x4e80ac00] {
            let baseline = emitted(word, TargetCpu::Baseline);
            let checked = emitted(word, TargetCpu::Ssse3);
            assert!(!baseline.windows(PHADDD.len()).any(|bytes| bytes == PHADDD));
            assert_eq!(
                checked
                    .windows(PHADDD.len())
                    .filter(|bytes| *bytes == PHADDD)
                    .count(),
                3
            );
            assert!(checked.len() < baseline.len());
        }
        for word in [0x0e809c00, 0x0f80f000, 0x0f00f000] {
            assert_eq!(
                emitted(word, TargetCpu::Baseline),
                emitted(word, TargetCpu::Ssse3)
            );
        }
    }

    #[test]
    fn indexed_q0_uses_full_source_and_clears_upper_destination() {
        const CLEAR_UPPER: &[u8] = &[0xf3, 0x0f, 0x7e, 0xc0];
        for base in [0x0f80f000, 0x0f00f000] {
            for index in 0..4 {
                let word = base | 31 << 16 | 31 << 5 | 31 | (index & 1) << 21 | (index >> 1) << 11;
                let low = emitted(word, TargetCpu::Baseline);
                let full = emitted(word | 1 << 30, TargetCpu::Baseline);
                assert!(
                    low.windows(5).any(|bytes| bytes
                        == [0x66, 0x0f, 0x70, 0xc9, index as u8 * DOT_GROUP_BROADCAST])
                );
                assert!(low.windows(4).any(|bytes| bytes == CLEAR_UPPER));
                assert!(!full.windows(4).any(|bytes| bytes == CLEAR_UPPER));
            }
        }
    }
}
