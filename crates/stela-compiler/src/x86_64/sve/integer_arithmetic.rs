//! SVE integer arithmetic. Each source chunk is staged before it is written.
use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, Predication, VectorLength};
use crate::aarch64::sve::integer_arithmetic::{Binary, Kind, Operand, Source};
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::Gpr::{Rax, Rcx, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, Size, Unary};
use crate::x86_64::isa::{ShiftOpcode, SimdOpcode as Host};
use crate::x86_64::scalable::{load_z_chunk, read_predicate_mask, store_z_chunk};

const RESULT: u8 = 0;
const RIGHT: u8 = 1;
const TEMPORARY: u8 = 2;
const MASK: u8 = 4;
const SAVED_LEFT: u8 = 5;
const SAVED_RIGHT: u8 = 6;
const PREVIOUS: u8 = 7;
const CHUNK_BYTES: usize = 16;
const QWORD_BYTES: usize = 8;
const SWAP_DWORDS: u8 = 0xb1;
const SWAP_QWORDS: u8 = 0x4e;
const BROADCAST_HIGH_DWORDS: u8 = 0xf5;
const WORD_SIGN_SHIFT: u8 = (u32::BITS - 1) as u8;
const HALFWORD_SIGN_SHIFT: u8 = (u16::BITS - 1) as u8;
const SELECT_EVEN_DWORDS: u8 = 0x88;
const SELECT_ODD_DWORDS: u8 = 0xdd;

fn packed(code: &mut Code, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn copy(code: &mut Code, destination: u8, source: u8) {
    packed(code, Host::MoveAligned, destination, source);
}

fn zero(code: &mut Code, register: u8) {
    packed(code, Host::Xor, register, register);
}

fn shuffle(code: &mut Code, register: u8, control: u8) {
    code.asm().simd_imm(
        Host::ShuffleDword,
        register,
        Rm::Xmm(register),
        control,
        TargetCpu::Baseline,
    );
}

fn constant(code: &mut Code, destination: u8, value: u64) {
    let mut asm = code.asm();
    asm.mov_imm64(Rax, value);
    asm.simd(Host::MoveGprQword, destination, Rax, TargetCpu::Baseline);
    packed(code, Host::UnpackLowQword, destination, destination);
}

fn repeated(value: u64, element: ElementSize) -> u64 {
    if element == ElementSize::Doubleword {
        return value;
    }
    let value = value & ((1u64 << element.bits()) - 1);
    (0..QWORD_BYTES / element.bytes()).fold(0, |all, lane| all | value << (lane * element.bits()))
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
        (ElementSize::Quadword, _) => unreachable!("validated integer lane width"),
    }
}

fn left_shift(element: ElementSize) -> ShiftOpcode {
    match element {
        ElementSize::Halfword => ShiftOpcode::LeftWord,
        ElementSize::Word => ShiftOpcode::LeftDword,
        ElementSize::Doubleword => ShiftOpcode::LeftQword,
        _ => unreachable!("widening output lane width"),
    }
}

fn right_shift(element: ElementSize) -> ShiftOpcode {
    match element {
        ElementSize::Halfword => ShiftOpcode::RightWord,
        ElementSize::Word => ShiftOpcode::RightDword,
        ElementSize::Doubleword => ShiftOpcode::RightQword,
        _ => unreachable!("widening output lane width"),
    }
}

/// XMM0/XMM1 inputs; XMM0 result. XMM2..6 scratch, XMM7 preserved.
fn minmax(code: &mut Code, element: ElementSize, unsigned: bool, maximum: bool, target: TargetCpu) {
    let direct = match (element, unsigned, maximum) {
        (ElementSize::Byte, true, false) => Some(Host::MinUnsignedByte),
        (ElementSize::Byte, true, true) => Some(Host::MaxUnsignedByte),
        (ElementSize::Halfword, false, false) => Some(Host::MinSignedWord),
        (ElementSize::Halfword, false, true) => Some(Host::MaxSignedWord),
        (ElementSize::Byte, false, false) => Some(Host::MinSignedByte),
        (ElementSize::Byte, false, true) => Some(Host::MaxSignedByte),
        (ElementSize::Halfword, true, false) => Some(Host::MinUnsignedWord),
        (ElementSize::Halfword, true, true) => Some(Host::MaxUnsignedWord),
        (ElementSize::Word, false, false) => Some(Host::MinSignedDword),
        (ElementSize::Word, false, true) => Some(Host::MaxSignedDword),
        (ElementSize::Word, true, false) => Some(Host::MinUnsignedDword),
        (ElementSize::Word, true, true) => Some(Host::MaxUnsignedDword),
        _ => None,
    };
    if let Some(opcode) = direct.filter(|opcode| target.supports(opcode.requires())) {
        opcode.register(code, RESULT, RIGHT, target);
        return;
    }
    copy(code, SAVED_LEFT, RESULT);
    copy(code, SAVED_RIGHT, RIGHT);
    crate::x86_64::simd::greater(code, element.bytes() as u8, unsigned, target);
    let (selected, other) = if maximum {
        (SAVED_LEFT, SAVED_RIGHT)
    } else {
        (SAVED_RIGHT, SAVED_LEFT)
    };
    packed(code, Host::And, selected, RESULT);
    packed(code, Host::AndNot, RESULT, other);
    packed(code, Host::Or, RESULT, selected);
}

/// Caller-staged XMM0/XMM1 arithmetic kernel for SVE/SME group wrappers.
/// XMM0 is the result; XMM0..6, RAX/RCX/RDX and host flags are scratch.
/// XMM7, RDI/R15 and architectural NZCV/FP state remain unchanged.
pub(crate) fn emit_binary_chunk(
    code: &mut Code,
    operation: Binary,
    element: ElementSize,
    target: TargetCpu,
) {
    match operation {
        Binary::Add | Binary::Subtract => packed(
            code,
            arithmetic_opcode(element, operation == Binary::Subtract),
            RESULT,
            RIGHT,
        ),
        Binary::ReverseSubtract => {
            packed(code, arithmetic_opcode(element, true), RIGHT, RESULT);
            copy(code, RESULT, RIGHT);
        }
        Binary::Minimum { unsigned } | Binary::Maximum { unsigned } => minmax(
            code,
            element,
            unsigned,
            matches!(operation, Binary::Maximum { .. }),
            target,
        ),
        Binary::Divide { .. } | Binary::Clamp { .. } => {
            unreachable!("caller owns division guards and clamp's third input")
        }
    }
}

fn unary(code: &mut Code, element: ElementSize, absolute: bool, target: TargetCpu) {
    let direct = match element {
        ElementSize::Byte => Some(Host::AbsByte),
        ElementSize::Halfword => Some(Host::AbsWord),
        ElementSize::Word => Some(Host::AbsDword),
        _ => None,
    };
    if absolute && let Some(opcode) = direct.filter(|opcode| target.supports(opcode.requires())) {
        opcode.register(code, RESULT, RESULT, target);
        return;
    }
    if !absolute {
        zero(code, RIGHT);
        packed(code, arithmetic_opcode(element, true), RIGHT, RESULT);
        copy(code, RESULT, RIGHT);
        return;
    }
    match element {
        ElementSize::Byte => {
            zero(code, RIGHT);
            packed(code, Host::GreaterByte, RIGHT, RESULT);
        }
        ElementSize::Halfword | ElementSize::Word | ElementSize::Doubleword => {
            copy(code, RIGHT, RESULT);
            if element == ElementSize::Doubleword {
                shuffle(code, RIGHT, BROADCAST_HIGH_DWORDS);
            }
            if element == ElementSize::Halfword {
                ShiftOpcode::ArithmeticWord.emit(code, RIGHT, HALFWORD_SIGN_SHIFT);
            } else {
                ShiftOpcode::ArithmeticDword.emit(code, RIGHT, WORD_SIGN_SHIFT);
            }
        }
        ElementSize::Quadword => unreachable!("validated unary integer lane width"),
    }
    packed(code, Host::Xor, RESULT, RIGHT);
    packed(code, arithmetic_opcode(element, true), RESULT, RIGHT);
}

/// Keep every other narrow lane in its containing wide lane, then extend it.
fn widen(
    code: &mut Code,
    register: u8,
    element: ElementSize,
    unsigned: bool,
    top: bool,
    target: TargetCpu,
) {
    let half_bits = (element.bits() / 2) as u8;
    if element == ElementSize::Doubleword && !unsigned {
        shuffle(
            code,
            register,
            if top {
                SELECT_ODD_DWORDS
            } else {
                SELECT_EVEN_DWORDS
            },
        );
        if target.supports(TargetCpu::Sse41) {
            Host::SignExtendDwordToQword.register(code, register, register, target);
        } else {
            copy(code, MASK, register);
            ShiftOpcode::ArithmeticDword.emit(code, MASK, half_bits - 1);
            packed(code, Host::UnpackLowDword, register, MASK);
        }
        return;
    }
    if !top {
        left_shift(element).emit(code, register, half_bits);
    }
    if unsigned {
        right_shift(element).emit(code, register, half_bits);
    } else {
        match element {
            ElementSize::Halfword => ShiftOpcode::ArithmeticWord,
            ElementSize::Word => ShiftOpcode::ArithmeticDword,
            _ => unreachable!("signed qword widening handled above"),
        }
        .emit(code, register, half_bits);
    }
}

fn complex(code: &mut Code, element: ElementSize, rotate_270: bool) {
    if matches!(element, ElementSize::Word | ElementSize::Doubleword) {
        shuffle(
            code,
            RIGHT,
            if element == ElementSize::Word {
                SWAP_DWORDS
            } else {
                SWAP_QWORDS
            },
        );
    } else {
        let wider = if element == ElementSize::Byte {
            ElementSize::Halfword
        } else {
            ElementSize::Word
        };
        copy(code, TEMPORARY, RIGHT);
        left_shift(wider).emit(code, TEMPORARY, element.bits() as u8);
        right_shift(wider).emit(code, RIGHT, element.bits() as u8);
        packed(code, Host::Or, RIGHT, TEMPORARY);
    }
    let lane_mask = if element == ElementSize::Doubleword {
        u64::MAX
    } else {
        (1u64 << element.bits()) - 1
    };
    let mut mask = 0u128;
    for lane in (usize::from(rotate_270)..CHUNK_BYTES / element.bytes()).step_by(2) {
        mask |= u128::from(lane_mask) << (lane * element.bits());
    }
    if element == ElementSize::Doubleword {
        constant(code, MASK, u64::MAX);
        if rotate_270 {
            ShiftOpcode::LeftBytes.emit(code, MASK, QWORD_BYTES as u8);
        } else {
            ShiftOpcode::RightBytes.emit(code, MASK, QWORD_BYTES as u8);
        }
    } else {
        constant(code, MASK, mask as u64);
    }
    packed(code, Host::Xor, RIGHT, MASK);
    packed(code, arithmetic_opcode(element, true), RIGHT, MASK);
    packed(code, arithmetic_opcode(element, false), RESULT, RIGHT);
}

/// One qword pair fits the host ADC result and its carry flag directly.
fn carry_qword(code: &mut Code, subtract: bool, top: bool) {
    code.asm().movq_from_xmm(Rax, PREVIOUS);
    if top {
        ShiftOpcode::RightBytes.emit(code, RIGHT, QWORD_BYTES as u8);
    }
    code.asm().movq_from_xmm(Rcx, RIGHT);
    ShiftOpcode::RightBytes.emit(code, TEMPORARY, QWORD_BYTES as u8);
    code.asm().movq_from_xmm(Rdx, TEMPORARY);
    if subtract {
        code.asm().unary(Unary::Not, Size::Qword, Rcx);
    }
    // BT consumes only the architectural carry-in low bit. Keep ADC and SETC
    // adjacent so intervening host flags cannot alter the published carry.
    let mut asm = code.asm();
    asm.bit_imm(BitTest::Bt, Size::Dword, Rdx, 0);
    asm.alu(Alu::Adc, Size::Qword, Rax, Rcx);
    asm.setcc(Cond::B, Rdx);
    asm.movzx(Size::Dword, Rdx, Size::Byte, Rdx);
    asm.simd(Host::MoveGprQword, RESULT, Rax, TargetCpu::Baseline);
    asm.simd(Host::MoveGprQword, RIGHT, Rdx, TargetCpu::Baseline);
    packed(code, Host::UnpackLowQword, RESULT, RIGHT);
}

/// Paired even result / odd carry; word pairs use packed overflow comparisons.
fn carry(code: &mut Code, element: ElementSize, subtract: bool, top: bool, target: TargetCpu) {
    if element == ElementSize::Doubleword {
        carry_qword(code, subtract, top);
        return;
    }
    let lane_bits = element.bits() as u8;
    let lane_bytes = element.bytes() as u8;
    constant(code, MASK, u64::from(u32::MAX));
    packed(code, Host::And, PREVIOUS, MASK);
    if top {
        ShiftOpcode::RightBytes.emit(code, RIGHT, lane_bytes);
    }
    if subtract {
        packed(code, Host::EqualDword, RESULT, RESULT);
        packed(code, Host::Xor, RIGHT, RESULT);
    }
    packed(code, Host::And, RIGHT, MASK);
    ShiftOpcode::RightBytes.emit(code, TEMPORARY, lane_bytes);
    packed(code, Host::And, TEMPORARY, MASK);
    constant(code, RESULT, 1);
    packed(code, Host::And, TEMPORARY, RESULT);
    copy(code, SAVED_LEFT, PREVIOUS);
    copy(code, SAVED_RIGHT, PREVIOUS);
    copy(code, PREVIOUS, TEMPORARY); // carry-in survives the comparison scratch.
    packed(code, arithmetic_opcode(element, false), SAVED_LEFT, RIGHT);
    copy(code, RESULT, SAVED_RIGHT);
    copy(code, RIGHT, SAVED_LEFT);
    crate::x86_64::simd::greater(code, lane_bytes, true, target);
    copy(code, SAVED_RIGHT, RESULT);
    copy(code, RESULT, SAVED_LEFT);
    packed(
        code,
        arithmetic_opcode(element, false),
        SAVED_LEFT,
        PREVIOUS,
    );
    copy(code, RIGHT, SAVED_LEFT);
    crate::x86_64::simd::greater(code, lane_bytes, true, target);
    packed(code, Host::Or, RESULT, SAVED_RIGHT);
    right_shift(element).emit(code, RESULT, lane_bits - 1);
    ShiftOpcode::LeftBytes.emit(code, RESULT, lane_bytes);
    packed(code, Host::Or, RESULT, SAVED_LEFT);
}

fn extract(code: &mut Code, source: u8, lane: usize, element: ElementSize, to_rcx: bool) {
    copy(code, TEMPORARY, source);
    if lane != 0 {
        ShiftOpcode::RightBytes.emit(code, TEMPORARY, (lane * element.bytes()) as u8);
    }
    let destination = if to_rcx { Rcx } else { Rax };
    let mut asm = code.asm();
    match element {
        ElementSize::Word => asm.movd_from_xmm(destination, TEMPORARY),
        ElementSize::Doubleword => asm.movq_from_xmm(destination, TEMPORARY),
        _ => unreachable!("division width"),
    }
}

/// Scalar IDIV has no packed counterpart. Guard zero, signed overflow and
/// inactive lanes before issuing it; no guest or host arithmetic exception leaks.
fn divide(code: &mut Code, element: ElementSize, unsigned: bool, reverse: bool, predicated: bool) {
    let size = match element {
        ElementSize::Word => Size::Dword,
        ElementSize::Doubleword => Size::Qword,
        _ => unreachable!("division width"),
    };
    zero(code, SAVED_RIGHT);
    for lane in 0..CHUNK_BYTES / element.bytes() {
        let inactive = if predicated {
            extract(code, SAVED_LEFT, lane, element, true);
            let mut asm = code.asm();
            asm.test(Size::Dword, Rcx, Rcx);
            Some(asm.jcc(Cond::E))
        } else {
            None
        };
        extract(
            code,
            if reverse { RESULT } else { RIGHT },
            lane,
            element,
            true,
        );
        let mut asm = code.asm();
        asm.test(size, Rcx, Rcx);
        let zero_divisor = asm.jcc(Cond::E);
        extract(
            code,
            if reverse { RIGHT } else { RESULT },
            lane,
            element,
            false,
        );
        let mut asm = code.asm();
        let mut overflow = None;
        if !unsigned {
            asm.alu_imm8(Alu::Cmp, size, Rcx, -1);
            let ordinary_divisor = asm.jcc(Cond::Ne);
            if element == ElementSize::Word {
                asm.alu_accumulator_imm32(Alu::Cmp, Size::Dword, i32::MIN);
            } else {
                asm.mov_imm64(Rdx, i64::MIN as u64);
                asm.alu(Alu::Cmp, Size::Qword, Rax, Rdx);
            }
            overflow = Some(asm.jcc(Cond::E));
            asm.bind(ordinary_divisor);
        }
        if unsigned {
            asm.alu(Alu::Xor, Size::Dword, Rdx, Rdx);
            asm.unary(Unary::Div, size, Rcx);
        } else {
            asm.sign_extend_accumulator(size);
            asm.unary(Unary::Idiv, size, Rcx);
        }
        let finished = asm.jmp();
        if let Some(patch) = inactive {
            asm.bind(patch);
        }
        asm.bind(zero_divisor);
        asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
        asm.bind(finished);
        if let Some(patch) = overflow {
            asm.bind(patch);
        }
        asm.simd(Host::MoveGprQword, MASK, Rax, TargetCpu::Baseline);
        if lane != 0 {
            ShiftOpcode::LeftBytes.emit(code, MASK, (lane * element.bytes()) as u8);
        }
        packed(code, Host::Or, SAVED_RIGHT, MASK);
    }
    copy(code, RESULT, SAVED_RIGHT);
}

pub fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
    let needs_previous = matches!(operand.predication, Predication::Merging(_))
        || matches!(
            operand.kind,
            Kind::Binary {
                operation: Binary::Clamp { .. },
                ..
            } | Kind::Carry { .. }
                | Kind::ComplexAdd { .. }
        );
    for chunk in 0..length.chunks() {
        if needs_previous {
            load_z_chunk(code, operand.destination, chunk, PREVIOUS, length, target);
        }
        match operand.kind {
            Kind::Binary {
                operation,
                left,
                right,
            } => {
                if needs_previous && left == operand.destination {
                    copy(code, RESULT, PREVIOUS);
                } else {
                    load_z_chunk(code, left, chunk, RESULT, length, target);
                }
                match right {
                    Source::Vector(register) => {
                        if register == left {
                            copy(code, RIGHT, RESULT);
                        } else if needs_previous && register == operand.destination {
                            copy(code, RIGHT, PREVIOUS);
                        } else {
                            load_z_chunk(code, register, chunk, RIGHT, length, target);
                        }
                    }
                    Source::Immediate(value) => {
                        constant(code, RIGHT, repeated(value as u64, operand.element_size))
                    }
                }
                match operation {
                    Binary::Add
                    | Binary::Subtract
                    | Binary::ReverseSubtract
                    | Binary::Minimum { .. }
                    | Binary::Maximum { .. } => {
                        emit_binary_chunk(code, operation, operand.element_size, target);
                    }
                    Binary::Clamp { unsigned } => {
                        copy(code, SAVED_RIGHT, RIGHT);
                        copy(code, RIGHT, PREVIOUS);
                        copy(code, PREVIOUS, SAVED_RIGHT);
                        minmax(code, operand.element_size, unsigned, true, target);
                        copy(code, RIGHT, PREVIOUS);
                        minmax(code, operand.element_size, unsigned, false, target);
                    }
                    Binary::Divide { unsigned, reverse } => {
                        let predicated = if let Predication::Merging(predicate)
                        | Predication::Zeroing(predicate) = operand.predication
                        {
                            read_predicate_mask(
                                code,
                                predicate,
                                chunk,
                                operand.element_size,
                                SAVED_LEFT,
                                SAVED_RIGHT,
                                length,
                                target,
                            );
                            true
                        } else {
                            false
                        };
                        divide(code, operand.element_size, unsigned, reverse, predicated);
                    }
                }
            }
            Kind::Unary { source, absolute } => {
                if needs_previous && source == operand.destination {
                    copy(code, RESULT, PREVIOUS);
                } else {
                    load_z_chunk(code, source, chunk, RESULT, length, target);
                }
                unary(code, operand.element_size, absolute, target);
            }
            Kind::Widening {
                left,
                right,
                unsigned,
                subtract,
                wide_left,
                left_top,
                right_top,
            } => {
                load_z_chunk(code, left, chunk, RESULT, length, target);
                if right == left {
                    copy(code, RIGHT, RESULT);
                } else {
                    load_z_chunk(code, right, chunk, RIGHT, length, target);
                }
                if !wide_left {
                    widen(
                        code,
                        RESULT,
                        operand.element_size,
                        unsigned,
                        left_top,
                        target,
                    );
                }
                widen(
                    code,
                    RIGHT,
                    operand.element_size,
                    unsigned,
                    right_top,
                    target,
                );
                packed(
                    code,
                    arithmetic_opcode(operand.element_size, subtract),
                    RESULT,
                    RIGHT,
                );
            }
            Kind::Carry {
                source,
                carry: carry_register,
                subtract,
                top,
            } => {
                if source == operand.destination {
                    copy(code, RIGHT, PREVIOUS);
                } else {
                    load_z_chunk(code, source, chunk, RIGHT, length, target);
                }
                if carry_register == source {
                    copy(code, TEMPORARY, RIGHT);
                } else if carry_register == operand.destination {
                    copy(code, TEMPORARY, PREVIOUS);
                } else {
                    load_z_chunk(code, carry_register, chunk, TEMPORARY, length, target);
                }
                carry(code, operand.element_size, subtract, top, target);
            }
            Kind::ComplexAdd { source, rotate_270 } => {
                copy(code, RESULT, PREVIOUS);
                if source == operand.destination {
                    copy(code, RIGHT, PREVIOUS);
                } else {
                    load_z_chunk(code, source, chunk, RIGHT, length, target);
                }
                complex(code, operand.element_size, rotate_270);
            }
        }
        if let Predication::Merging(predicate) | Predication::Zeroing(predicate) =
            operand.predication
        {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                operand.element_size,
                SAVED_LEFT,
                SAVED_RIGHT,
                length,
                target,
            );
            packed(code, Host::And, RESULT, SAVED_LEFT);
            if matches!(operand.predication, Predication::Merging(_)) {
                packed(code, Host::AndNot, SAVED_LEFT, PREVIOUS);
                packed(code, Host::Or, RESULT, SAVED_LEFT);
            }
        }
        store_z_chunk(code, operand.destination, chunk, RESULT, length, target);
    }
}
