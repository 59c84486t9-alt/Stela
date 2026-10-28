//! SVE saturating arithmetic and absolute differences with SSE2.
use super::super::scalable::{load_z_chunk, read_predicate_mask, store_z_chunk};
use crate::TargetCpu;
use crate::aarch64::{
    scalable::{ElementSize, Predication, VectorLength},
    sve::integer_saturation::{Arithmetic, Half, Input, Kind, Operand, Signedness},
};
use crate::x86_64::asm::Code;

use super::super::isa::{ShiftOpcode, SimdOpcode as Host};

const REPLICATE_HIGH_DWORDS: u8 = 0xf5;
const SWAP_DWORD_PAIRS: u8 = 0xb1;
const SWAP_QWORDS: u8 = 0x4e;
const SWAP_WORD_PAIRS: u8 = 0xb1;
const MOV_RAX_IMM64: &[u8] = &[0x48, 0xb8];

#[derive(Clone, Copy)]
enum ShiftKind {
    Left,
    Right,
    Arithmetic,
}

const BYTE_SIGN_BITS: u64 = 0x8080_8080_8080_8080;
const BYTE_SHIFT_MASK: u64 = 0x7f7f_7f7f_7f7f_7f7f;
const BYTE_LOW_BITS: u64 = 0x0101_0101_0101_0101;
const HALFWORD_LOW_BITS: u64 = 0x0001_0001_0001_0001;
const WORD_LOW_BITS: u64 = 0x0000_0001_0000_0001;
const QWORD_LOW_BITS: u64 = 1;
const BITS_PER_BYTE: usize = 8;

fn binary(code: &mut Code, opcode: Host, destination: u8, source: u8) {
    // This family's packed recipes deliberately require only the SSE2 baseline.
    opcode.register(code, destination, source, TargetCpu::Baseline);
}
fn copy(code: &mut Code, destination: u8, source: u8) {
    if destination != source {
        binary(code, Host::MoveAligned, destination, source);
    }
}
fn shift_immediate(
    code: &mut Code,
    element: ElementSize,
    operation: ShiftKind,
    register: u8,
    amount: usize,
) {
    let opcode = match (element, operation) {
        (ElementSize::Byte | ElementSize::Halfword, ShiftKind::Left) => ShiftOpcode::LeftWord,
        (ElementSize::Word, ShiftKind::Left) => ShiftOpcode::LeftDword,
        (ElementSize::Doubleword, ShiftKind::Left) => ShiftOpcode::LeftQword,
        (ElementSize::Byte | ElementSize::Halfword, ShiftKind::Right) => ShiftOpcode::RightWord,
        (ElementSize::Word, ShiftKind::Right) => ShiftOpcode::RightDword,
        (ElementSize::Doubleword, ShiftKind::Right) => ShiftOpcode::RightQword,
        (ElementSize::Halfword, ShiftKind::Arithmetic) => ShiftOpcode::ArithmeticWord,
        (ElementSize::Word, ShiftKind::Arithmetic) => ShiftOpcode::ArithmeticDword,
        _ => unreachable!("decoder width or synthesized byte/qword arithmetic shift"),
    };
    opcode.emit(code, register, amount as u8);
}
fn shuffle(code: &mut Code, opcode: Host, register: u8, order: u8) {
    opcode.register(code, register, register, TargetCpu::Baseline);
    code.push(order);
}
fn splat(code: &mut Code, register: u8, pattern: u64) {
    code.extend(MOV_RAX_IMM64);
    code.extend(pattern.to_le_bytes());
    Host::MoveGprQword.register(code, register, 0, TargetCpu::Baseline);
    binary(code, Host::UnpackLowQword, register, register);
}
fn all_ones(code: &mut Code, register: u8) {
    binary(code, Host::EqualDword, register, register);
}
fn arithmetic_opcode(element: ElementSize, subtract: bool) -> Host {
    match (element, subtract) {
        (ElementSize::Byte, false) => Host::AddByte,
        (ElementSize::Halfword, false) => Host::AddWord,
        (ElementSize::Word, false) => Host::AddDword,
        (ElementSize::Doubleword, false) => Host::AddQword,
        (ElementSize::Byte, true) => Host::SubByte,
        (ElementSize::Halfword, true) => Host::SubWord,
        (ElementSize::Word, true) => Host::SubDword,
        (ElementSize::Doubleword, true) => Host::SubQword,
        (ElementSize::Quadword, _) => unreachable!(),
    }
}
/// Expand each lane's sign bit to a complete lane mask. XMM7 is byte scratch.
fn sign_mask(code: &mut Code, destination: u8, source: u8, element: ElementSize) {
    if element == ElementSize::Byte {
        let source = if destination == source {
            copy(code, 7, source);
            7
        } else {
            source
        };
        binary(code, Host::Xor, destination, destination);
        binary(code, Host::GreaterByte, destination, source);
    } else {
        copy(code, destination, source);
        let shift_element = if element == ElementSize::Doubleword {
            ElementSize::Word
        } else {
            element
        };
        shift_immediate(
            code,
            shift_element,
            ShiftKind::Arithmetic,
            destination,
            shift_element.bits() - 1,
        );
        if element == ElementSize::Doubleword {
            shuffle(code, Host::ShuffleDword, destination, REPLICATE_HIGH_DWORDS);
        }
    }
}
/// Shift a packed lane without leaking neighboring bytes; clobbers XMM6/7.
fn half_shift(code: &mut Code, register: u8, element: ElementSize, signed: bool, amount: usize) {
    if element == ElementSize::Byte {
        debug_assert_eq!(amount, 1);
        if signed {
            sign_mask(code, 6, register, element);
        }
        shift_immediate(code, element, ShiftKind::Right, register, amount);
        splat(code, 7, BYTE_SHIFT_MASK);
        binary(code, Host::And, register, 7);
        if signed {
            splat(code, 7, BYTE_SIGN_BITS);
            binary(code, Host::And, 6, 7);
            binary(code, Host::Or, register, 6);
        }
    } else if signed && element == ElementSize::Doubleword {
        sign_mask(code, 6, register, element);
        shift_immediate(code, element, ShiftKind::Right, register, amount);
        shift_immediate(code, element, ShiftKind::Left, 6, element.bits() - amount);
        binary(code, Host::Or, register, 6);
    } else {
        shift_immediate(
            code,
            element,
            if signed {
                ShiftKind::Arithmetic
            } else {
                ShiftKind::Right
            },
            register,
            amount,
        );
    }
}
/// Select replacement XMM5 where mask XMM4 is set, preserving result XMM0 elsewhere.
fn select_saturated(code: &mut Code) {
    binary(code, Host::And, 5, 4);
    binary(code, Host::AndNot, 4, 0);
    binary(code, Host::Or, 5, 4);
    copy(code, 0, 5);
}
/// XMM0=a, XMM1=b. Leaves a in XMM3 and the unsigned carry mask in XMM5.
fn add_with_carry_mask(code: &mut Code, element: ElementSize) {
    copy(code, 3, 0);
    binary(code, arithmetic_opcode(element, false), 0, 1);
    copy(code, 4, 3);
    binary(code, Host::Or, 4, 1);
    copy(code, 5, 3);
    binary(code, Host::And, 5, 1);
    copy(code, 6, 0);
    binary(code, Host::AndNot, 6, 4);
    binary(code, Host::Or, 5, 6);
    sign_mask(code, 5, 5, element);
}
fn saturating(code: &mut Code, element: ElementSize, signedness: Signedness, subtract: bool) {
    let direct = match (element, signedness, subtract) {
        (ElementSize::Byte, Signedness::Signed, false) => Some(Host::AddSignedSaturatingByte),
        (ElementSize::Halfword, Signedness::Signed, false) => Some(Host::AddSignedSaturatingWord),
        (ElementSize::Byte, Signedness::Unsigned, false) => Some(Host::AddUnsignedSaturatingByte),
        (ElementSize::Halfword, Signedness::Unsigned, false) => {
            Some(Host::AddUnsignedSaturatingWord)
        }
        (ElementSize::Byte, Signedness::Signed, true) => Some(Host::SubSignedSaturatingByte),
        (ElementSize::Halfword, Signedness::Signed, true) => Some(Host::SubSignedSaturatingWord),
        (ElementSize::Byte, Signedness::Unsigned, true) => Some(Host::SubUnsignedSaturatingByte),
        (ElementSize::Halfword, Signedness::Unsigned, true) => {
            Some(Host::SubUnsignedSaturatingWord)
        }
        _ => None,
    };
    if let Some(opcode) = direct {
        binary(code, opcode, 0, 1);
        return;
    }
    if signedness == Signedness::Unsigned && !subtract {
        add_with_carry_mask(code, element);
        binary(code, Host::Or, 0, 5);
        return;
    }
    copy(code, 3, 0);
    binary(code, arithmetic_opcode(element, subtract), 0, 1);
    if signedness == Signedness::Signed {
        copy(code, 4, 3);
        binary(code, Host::Xor, 4, 1);
        copy(code, 5, 3);
        binary(code, Host::Xor, 5, 0);
        binary(code, if subtract { Host::And } else { Host::AndNot }, 4, 5);
        sign_mask(code, 4, 4, element);
        sign_mask(code, 5, 3, element);
        all_ones(code, 6);
        shift_immediate(code, element, ShiftKind::Right, 6, 1);
        binary(code, Host::Xor, 5, 6);
        select_saturated(code);
    } else {
        copy(code, 4, 3);
        binary(code, Host::AndNot, 4, 1);
        all_ones(code, 5);
        binary(code, Host::Xor, 5, 3);
        binary(code, Host::Or, 5, 1);
        binary(code, Host::And, 5, 0);
        binary(code, Host::Or, 4, 5);
        sign_mask(code, 4, 4, element);
        binary(code, Host::AndNot, 4, 0);
        copy(code, 0, 4);
    }
}
fn subtract_with_borrow_mask(code: &mut Code, element: ElementSize) {
    copy(code, 3, 0);
    binary(code, arithmetic_opcode(element, true), 0, 1);
    copy(code, 4, 3);
    binary(code, Host::AndNot, 4, 1);
    all_ones(code, 5);
    binary(code, Host::Xor, 5, 3);
    binary(code, Host::Or, 5, 1);
    binary(code, Host::And, 5, 0);
    binary(code, Host::Or, 5, 4);
    sign_mask(code, 5, 5, element);
}
/// Signed destination minus an unsigned magnitude; only negative saturation occurs.
fn mixed_subtract(code: &mut Code, element: ElementSize) {
    subtract_with_borrow_mask(code, element);
    sign_mask(code, 4, 3, element);
    sign_mask(code, 6, 0, element);
    all_ones(code, 7);
    binary(code, Host::Xor, 6, 7);
    copy(code, 7, 4);
    binary(code, Host::Or, 7, 5);
    binary(code, Host::And, 7, 6);
    binary(code, Host::And, 4, 5);
    binary(code, Host::Or, 4, 7);
    if element == ElementSize::Byte {
        splat(code, 5, BYTE_SIGN_BITS);
    } else {
        all_ones(code, 5);
        shift_immediate(code, element, ShiftKind::Left, 5, element.bits() - 1);
    }
    select_saturated(code);
}
fn mixed_add(code: &mut Code, element: ElementSize, signed_destination: bool) {
    add_with_carry_mask(code, element);
    if signed_destination {
        sign_mask(code, 4, 3, element);
        sign_mask(code, 6, 0, element);
        all_ones(code, 7);
        binary(code, Host::Xor, 4, 7);
        copy(code, 7, 4);
        binary(code, Host::Or, 7, 6);
        binary(code, Host::And, 7, 5);
        binary(code, Host::And, 4, 6);
        binary(code, Host::Or, 4, 7);
        if element == ElementSize::Byte {
            splat(code, 5, BYTE_SHIFT_MASK);
        } else {
            all_ones(code, 5);
            shift_immediate(code, element, ShiftKind::Right, 5, 1);
        }
        select_saturated(code);
    } else {
        sign_mask(code, 4, 1, element);
        copy(code, 7, 4);
        binary(code, Host::AndNot, 7, 5);
        copy(code, 6, 5);
        binary(code, Host::AndNot, 6, 4);
        binary(code, Host::Or, 0, 7);
        binary(code, Host::AndNot, 6, 0);
        copy(code, 0, 6);
    }
}
fn halving(
    code: &mut Code,
    element: ElementSize,
    signedness: Signedness,
    subtract: bool,
    round: bool,
) {
    if !subtract && element == ElementSize::Byte {
        if round && signedness == Signedness::Signed {
            splat(code, 7, BYTE_SIGN_BITS);
            binary(code, Host::Xor, 0, 7);
            binary(code, Host::Xor, 1, 7);
            binary(code, Host::AverageByte, 0, 1);
            binary(code, Host::Xor, 0, 7);
            return;
        }
        if !round && signedness == Signedness::Unsigned {
            copy(code, 3, 0);
            binary(code, Host::Xor, 3, 1);
            splat(code, 7, BYTE_LOW_BITS);
            binary(code, Host::And, 3, 7);
            binary(code, Host::AverageByte, 0, 1);
            binary(code, Host::SubByte, 0, 3);
            return;
        }
    }
    if !subtract && round && signedness == Signedness::Unsigned {
        let direct = match element {
            ElementSize::Byte => Some(Host::AverageByte),
            ElementSize::Halfword => Some(Host::AverageWord),
            _ => None,
        };
        if let Some(opcode) = direct {
            binary(code, opcode, 0, 1);
            return;
        }
    }
    if !subtract {
        copy(code, 3, 0);
        binary(code, Host::Xor, 3, 1);
        binary(code, if round { Host::Or } else { Host::And }, 0, 1);
        half_shift(code, 3, element, signedness == Signedness::Signed, 1);
        binary(code, arithmetic_opcode(element, round), 0, 3);
    } else {
        copy(code, 3, 0);
        binary(code, Host::AndNot, 3, 1);
        let low_bits = match element {
            ElementSize::Byte => BYTE_LOW_BITS,
            ElementSize::Halfword => HALFWORD_LOW_BITS,
            ElementSize::Word => WORD_LOW_BITS,
            ElementSize::Doubleword => QWORD_LOW_BITS,
            ElementSize::Quadword => unreachable!(),
        };
        splat(code, 7, low_bits);
        binary(code, Host::And, 3, 7);
        half_shift(code, 0, element, signedness == Signedness::Signed, 1);
        half_shift(code, 1, element, signedness == Signedness::Signed, 1);
        binary(code, arithmetic_opcode(element, true), 0, 1);
        binary(code, arithmetic_opcode(element, true), 0, 3);
    }
}
fn widen_interleaved(
    code: &mut Code,
    register: u8,
    element: ElementSize,
    signedness: Signedness,
    half: Half,
) {
    let amount = element.bits() / 2;
    if half == Half::Bottom {
        shift_immediate(code, element, ShiftKind::Left, register, amount);
    }
    half_shift(
        code,
        register,
        element,
        signedness == Signedness::Signed,
        amount,
    );
}
fn difference(
    code: &mut Code,
    element: ElementSize,
    signedness: Signedness,
    widening: Option<Half>,
) {
    if let Some(half) = widening {
        widen_interleaved(code, 0, element, signedness, half);
        widen_interleaved(code, 1, element, signedness, half);
        binary(code, arithmetic_opcode(element, true), 0, 1);
        sign_mask(code, 3, 0, element);
        binary(code, Host::Xor, 0, 3);
        binary(code, arithmetic_opcode(element, true), 0, 3);
        return;
    }
    if signedness == Signedness::Signed && element == ElementSize::Halfword {
        copy(code, 3, 0);
        binary(code, Host::MaxSignedWord, 0, 1);
        binary(code, Host::MinSignedWord, 1, 3);
        binary(code, Host::SubWord, 0, 1);
        return;
    }
    if signedness == Signedness::Signed {
        if element == ElementSize::Byte {
            splat(code, 7, BYTE_SIGN_BITS);
        } else {
            all_ones(code, 7);
            shift_immediate(code, element, ShiftKind::Left, 7, element.bits() - 1);
        }
        binary(code, Host::Xor, 0, 7);
        binary(code, Host::Xor, 1, 7);
    }
    if matches!(element, ElementSize::Byte | ElementSize::Halfword) {
        copy(code, 3, 0);
        let opcode = if element == ElementSize::Byte {
            Host::SubUnsignedSaturatingByte
        } else {
            Host::SubUnsignedSaturatingWord
        };
        binary(code, opcode, 0, 1);
        binary(code, opcode, 1, 3);
        binary(code, Host::Or, 0, 1);
    } else {
        copy(code, 3, 0);
        binary(code, arithmetic_opcode(element, true), 0, 1);
        copy(code, 4, 3);
        binary(code, Host::AndNot, 4, 1);
        all_ones(code, 5);
        binary(code, Host::Xor, 5, 3);
        binary(code, Host::Or, 5, 1);
        binary(code, Host::And, 5, 0);
        binary(code, Host::Or, 4, 5);
        sign_mask(code, 4, 4, element);
        binary(code, Host::Xor, 0, 4);
        binary(code, arithmetic_opcode(element, true), 0, 4);
    }
}
fn complex_partner(code: &mut Code, element: ElementSize) {
    match element {
        ElementSize::Byte => {
            copy(code, 3, 1);
            shift_immediate(
                code,
                ElementSize::Halfword,
                ShiftKind::Left,
                1,
                BITS_PER_BYTE,
            );
            shift_immediate(
                code,
                ElementSize::Halfword,
                ShiftKind::Right,
                3,
                BITS_PER_BYTE,
            );
            binary(code, Host::Or, 1, 3);
        }
        ElementSize::Halfword => {
            shuffle(code, Host::ShuffleLowWord, 1, SWAP_WORD_PAIRS);
            shuffle(code, Host::ShuffleHighWord, 1, SWAP_WORD_PAIRS);
        }
        ElementSize::Word => shuffle(code, Host::ShuffleDword, 1, SWAP_DWORD_PAIRS),
        ElementSize::Doubleword => shuffle(code, Host::ShuffleDword, 1, SWAP_QWORDS),
        ElementSize::Quadword => unreachable!(),
    }
}
fn repeat_lane(value: u64, element: ElementSize) -> u64 {
    if element == ElementSize::Doubleword {
        return value;
    }
    let mut pattern = 0;
    for shift in (0..u64::BITS as usize).step_by(element.bits()) {
        pattern |= value << shift;
    }
    pattern
}

pub(crate) fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
    let element = operand.element_size;
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.left, chunk, 0, length, target);
        match operand.right {
            Input::Vector(right) => load_z_chunk(code, right, chunk, 1, length, target),
            Input::Immediate(immediate) => {
                splat(code, 1, repeat_lane(u64::from(immediate), element))
            }
            Input::None => {}
        }
        match operand.kind {
            Kind::Saturating {
                signedness,
                arithmetic,
            } => {
                if arithmetic == Arithmetic::ReverseSubtract {
                    copy(code, 3, 0);
                    copy(code, 0, 1);
                    copy(code, 1, 3);
                }
                if matches!(operand.right, Input::Immediate(_)) && signedness == Signedness::Signed
                {
                    if arithmetic == Arithmetic::Add {
                        mixed_add(code, element, true);
                    } else {
                        mixed_subtract(code, element);
                    }
                } else {
                    saturating(code, element, signedness, arithmetic != Arithmetic::Add);
                }
            }
            Kind::MixedSaturatingAdd { signed_destination } => {
                mixed_add(code, element, signed_destination)
            }
            Kind::Halving {
                signedness,
                arithmetic,
                round,
            } => {
                if arithmetic == Arithmetic::ReverseSubtract {
                    copy(code, 3, 0);
                    copy(code, 0, 1);
                    copy(code, 1, 3);
                }
                halving(
                    code,
                    element,
                    signedness,
                    arithmetic != Arithmetic::Add,
                    round,
                );
            }
            Kind::AbsoluteDifference {
                signedness,
                widening,
                accumulate,
            } => {
                difference(code, element, signedness, widening);
                if accumulate {
                    load_z_chunk(code, operand.destination, chunk, 2, length, target);
                    binary(code, arithmetic_opcode(element, false), 0, 2);
                }
            }
            Kind::Absolute | Kind::Negate => {
                copy(code, 1, 0);
                binary(code, Host::Xor, 0, 0);
                saturating(code, element, Signedness::Signed, true);
                if operand.kind == Kind::Absolute {
                    // XMM1 still holds the original lane; clamp the most
                    // negative magnitude.
                    sign_mask(code, 4, 1, element);
                    copy(code, 5, 0);
                    copy(code, 0, 1);
                    select_saturated(code);
                }
            }
            Kind::ComplexAdd { rotate_270 } => {
                complex_partner(code, element);
                saturating(code, element, Signedness::Signed, false);
                copy(code, 2, 0);
                load_z_chunk(code, operand.left, chunk, 0, length, target);
                // Signed saturation preserves XMM1, already holding the rotated source.
                saturating(code, element, Signedness::Signed, true);
                let lane_mask = if element == ElementSize::Doubleword {
                    u64::MAX
                } else {
                    (1u64 << element.bits()) - 1
                };
                let mut alternating = 0u64;
                for lane in 0..(u64::BITS as usize / element.bits()) {
                    if (lane % 2 == 0) != rotate_270 {
                        alternating |= lane_mask << (lane * element.bits());
                    }
                }
                if element == ElementSize::Doubleword {
                    // Each complex pair occupies two qwords, so their masks differ.
                    splat(code, 4, u64::MAX);
                    binary(code, Host::Xor, 5, 5);
                    binary(code, Host::UnpackLowQword, 4, 5);
                    if rotate_270 {
                        all_ones(code, 5);
                        binary(code, Host::Xor, 4, 5);
                    }
                } else {
                    splat(code, 4, alternating);
                }
                binary(code, Host::And, 0, 4);
                binary(code, Host::AndNot, 4, 2);
                binary(code, Host::Or, 0, 4);
            }
        }
        if let Predication::Merging(predicate) = operand.predication {
            load_z_chunk(code, operand.destination, chunk, 2, length, target);
            read_predicate_mask(code, predicate, chunk, element, 3, 4, length, target);
            binary(code, Host::And, 0, 3);
            binary(code, Host::AndNot, 3, 2);
            binary(code, Host::Or, 0, 3);
        }
        store_z_chunk(code, operand.destination, chunk, 0, length, target);
    }
}
