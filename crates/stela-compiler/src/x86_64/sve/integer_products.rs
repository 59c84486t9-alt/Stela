//! SVE integer multiplies with SSE2. Indexed multipliers select within the same
//! 128-bit chunk, so aliases never read an already written chunk.
use crate::TargetCpu;
use crate::aarch64::Unsupported;
use crate::aarch64::scalable::{ElementSize, Predication, VectorLength};
use crate::aarch64::sve::integer_products::{Kind, Multiplier, Operand, Selection};
use crate::x86_64::asm::Gpr::{Rax, Rcx, Rdx};
use crate::x86_64::asm::{Code, Rm, Size, Unary};
use crate::x86_64::isa::{ShiftOpcode, SimdOpcode as Host};
use crate::x86_64::scalable::{load_z_chunk, read_predicate_mask, store_z_chunk};

mod complex;
mod complex_wrapping;
mod polynomial;
mod saturating;
mod widening;

pub(crate) use saturating::emit_chunk as emit_saturating_chunk;

const RESULT: u8 = 0;
const RIGHT: u8 = 1;
const FIRST_PARTIAL: u8 = 2;
const SECOND_PARTIAL: u8 = 3;
const ACCUMULATOR_OR_CONSTANT: u8 = 4;
const PREDICATE: u8 = 5;
const PREDICATE_SCRATCH: u8 = 6;
const PREVIOUS: u8 = 7;
const Z_REGISTERS: u8 = 32;
const GOVERNING_PREDICATES: u8 = 8;
const CHUNK_BYTES: usize = 16;
const QWORD_BYTES: usize = 8;
const DWORD_BITS: u8 = 32;
const REPEAT_SHUFFLE_LANE: u8 = 0x55;
const REPEAT_LOW_DWORD: u8 = 0x00;
const REPEAT_HIGH_WORD_PAIR: u8 = 0xaa;
const REPEAT_LOW_QWORD: u8 = 0x44;
const REPEAT_HIGH_QWORD: u8 = 0xee;
const SELECT_LOW_PRODUCT_DWORDS: u8 = 0x88;
const WORDS_PER_HALF_CHUNK: u8 = 4;
const BYTE_BITS: u8 = 8;
const DWORD_SIGN_SHIFT: u8 = DWORD_BITS - 1;

fn packed(code: &mut Code, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn shuffle(code: &mut Code, opcode: Host, register: u8, control: u8) {
    code.asm().simd_imm(
        opcode,
        register,
        Rm::Xmm(register),
        control,
        TargetCpu::Baseline,
    );
}

fn multiplier_element(operand: Operand) -> ElementSize {
    let bytes = match operand.kind {
        Kind::Long { .. } | Kind::Polynomial { widening: true, .. } => {
            operand.element_size.bytes() / 2
        }
        Kind::Complex { .. } => operand.element_size.bytes() * 2,
        _ => operand.element_size.bytes(),
    };
    // Complex indexed forms are H/S; an unindexed D complex pair never calls
    // the broadcaster and can retain its component size here.
    ElementSize::from_bytes(bytes).unwrap_or(operand.element_size)
}

fn supported(operand: Operand) -> bool {
    if operand.destination >= Z_REGISTERS || operand.source >= Z_REGISTERS {
        return false;
    }
    if operand.element_size == ElementSize::Quadword {
        return false;
    }
    match operand.predication {
        Predication::Merging(predicate) => {
            if predicate >= GOVERNING_PREDICATES
                || !matches!(
                    operand.kind,
                    Kind::Multiply | Kind::MultiplyHigh { .. } | Kind::Accumulate { .. }
                )
            {
                return false;
            }
        }
        Predication::Zeroing(_) => return false,
        Predication::Unpredicated => {}
    }
    match operand.kind {
        Kind::Complex { .. } => {
            if ![0, 90, 180, 270].contains(&operand.rotation_degrees) {
                return false;
            }
        }
        _ if operand.rotation_degrees != 0 => return false,
        _ => {}
    }
    match operand.kind {
        Kind::Long {
            signed,
            doubling,
            selection,
            ..
        } => {
            if operand.element_size == ElementSize::Byte
                || (doubling && !signed)
                || (!doubling && selection == Selection::Cross)
            {
                return false;
            }
        }
        Kind::Polynomial {
            widening,
            selection,
        } => {
            if selection == Selection::Cross || (!widening && selection != Selection::Bottom) {
                return false;
            }
            if if widening {
                !matches!(
                    operand.element_size,
                    ElementSize::Halfword | ElementSize::Doubleword
                )
            } else {
                operand.element_size != ElementSize::Byte
            } {
                return false;
            }
        }
        _ => {}
    }
    match (operand.kind.accumulating(), operand.accumulator) {
        (true, Some(register)) if register < Z_REGISTERS => {}
        (false, None) => {}
        _ => return false,
    }
    match operand.multiplier {
        Multiplier::Vector {
            register,
            segment_lane,
        } => {
            if segment_lane.is_some() {
                let width_valid = match operand.kind {
                    Kind::Multiply
                    | Kind::Accumulate { .. }
                    | Kind::DoublingHigh { .. }
                    | Kind::RoundedHighAccumulate { .. } => {
                        operand.element_size != ElementSize::Byte
                    }
                    Kind::Long { selection, .. } => {
                        matches!(
                            operand.element_size,
                            ElementSize::Word | ElementSize::Doubleword
                        ) && selection != Selection::Cross
                    }
                    Kind::Complex { .. } => {
                        matches!(
                            operand.element_size,
                            ElementSize::Halfword | ElementSize::Word
                        )
                    }
                    Kind::MultiplyHigh { .. } | Kind::Polynomial { .. } => false,
                };
                if !width_valid || operand.predication != Predication::Unpredicated {
                    return false;
                }
            } else if matches!(operand.kind, Kind::Accumulate { .. })
                && operand.predication == Predication::Unpredicated
            {
                return false;
            }
            let element = multiplier_element(operand);
            register < Z_REGISTERS
                && segment_lane.is_none_or(|lane| usize::from(lane) < CHUNK_BYTES / element.bytes())
        }
        Multiplier::Immediate(_) => {
            operand.kind == Kind::Multiply && operand.predication == Predication::Unpredicated
        }
    }
}

fn immediate(code: &mut Code, value: i8, element: ElementSize) {
    let bits = element.bits();
    let value = value as i64 as u64;
    let repeated = if element == ElementSize::Doubleword {
        value
    } else {
        let lane = value & ((1u64 << bits) - 1);
        (0..QWORD_BYTES / element.bytes())
            .fold(0, |result, index| result | (lane << (index * bits)))
    };
    let mut asm = code.asm();
    asm.mov_imm64(Rax, repeated);
    asm.simd(
        Host::MoveGprQword,
        ACCUMULATOR_OR_CONSTANT,
        Rax,
        TargetCpu::Baseline,
    );
    packed(
        code,
        Host::UnpackLowQword,
        ACCUMULATOR_OR_CONSTANT,
        ACCUMULATOR_OR_CONSTANT,
    );
}

fn broadcast_lane(code: &mut Code, element: ElementSize, lane: u8) {
    match element {
        ElementSize::Byte => {
            // Move the containing word to every word, then select its byte.
            let word = lane / 2;
            let opcode = if word < WORDS_PER_HALF_CHUNK {
                Host::ShuffleLowWord
            } else {
                Host::ShuffleHighWord
            };
            shuffle(
                code,
                opcode,
                RIGHT,
                (word % WORDS_PER_HALF_CHUNK) * REPEAT_SHUFFLE_LANE,
            );
            let control = if word < WORDS_PER_HALF_CHUNK {
                REPEAT_LOW_DWORD
            } else {
                REPEAT_HIGH_WORD_PAIR
            };
            shuffle(code, Host::ShuffleDword, RIGHT, control);
            if !lane.is_multiple_of(2) {
                ShiftOpcode::RightWord.emit(code, RIGHT, BYTE_BITS);
            }
            ShiftOpcode::LeftWord.emit(code, RIGHT, BYTE_BITS);
            packed(code, Host::MoveAligned, FIRST_PARTIAL, RIGHT);
            ShiftOpcode::RightWord.emit(code, FIRST_PARTIAL, BYTE_BITS);
            packed(code, Host::Or, RIGHT, FIRST_PARTIAL);
        }
        ElementSize::Halfword => {
            let opcode = if lane < WORDS_PER_HALF_CHUNK {
                Host::ShuffleLowWord
            } else {
                Host::ShuffleHighWord
            };
            shuffle(
                code,
                opcode,
                RIGHT,
                (lane % WORDS_PER_HALF_CHUNK) * REPEAT_SHUFFLE_LANE,
            );
            let control = if lane < WORDS_PER_HALF_CHUNK {
                REPEAT_LOW_DWORD
            } else {
                REPEAT_HIGH_WORD_PAIR
            };
            shuffle(code, Host::ShuffleDword, RIGHT, control);
        }
        ElementSize::Word => shuffle(code, Host::ShuffleDword, RIGHT, lane * REPEAT_SHUFFLE_LANE),
        ElementSize::Doubleword => {
            let control = if lane == 0 {
                REPEAT_LOW_QWORD
            } else {
                REPEAT_HIGH_QWORD
            };
            shuffle(code, Host::ShuffleDword, RIGHT, control);
        }
        _ => unreachable!("validated product lane size"),
    }
}

/// Low products are identical for signed and unsigned interpretations. SSE2
/// PMULUDQ multiplies even dwords; shifted odd lanes or cross terms supply the
/// remaining low bits without widening guest results or touching host MXCSR.
fn multiply_low(code: &mut Code, element: ElementSize) {
    match element {
        ElementSize::Byte => multiply_low_bytes(code),
        ElementSize::Halfword => packed(code, Host::MultiplyLowWord, RESULT, RIGHT),
        ElementSize::Word => {
            packed(code, Host::MoveAligned, FIRST_PARTIAL, RESULT);
            packed(code, Host::MoveAligned, SECOND_PARTIAL, RIGHT);
            ShiftOpcode::RightQword.emit(code, FIRST_PARTIAL, DWORD_BITS);
            ShiftOpcode::RightQword.emit(code, SECOND_PARTIAL, DWORD_BITS);
            packed(
                code,
                Host::MultiplyUnsignedDword,
                FIRST_PARTIAL,
                SECOND_PARTIAL,
            );
            packed(code, Host::MultiplyUnsignedDword, RESULT, RIGHT);
            shuffle(code, Host::ShuffleDword, RESULT, SELECT_LOW_PRODUCT_DWORDS);
            shuffle(
                code,
                Host::ShuffleDword,
                FIRST_PARTIAL,
                SELECT_LOW_PRODUCT_DWORDS,
            );
            packed(code, Host::UnpackLowDword, RESULT, FIRST_PARTIAL);
        }
        ElementSize::Doubleword => {
            packed(code, Host::MoveAligned, FIRST_PARTIAL, RESULT);
            packed(code, Host::MoveAligned, SECOND_PARTIAL, RIGHT);
            ShiftOpcode::RightQword.emit(code, FIRST_PARTIAL, DWORD_BITS);
            ShiftOpcode::RightQword.emit(code, SECOND_PARTIAL, DWORD_BITS);
            packed(code, Host::MultiplyUnsignedDword, FIRST_PARTIAL, RIGHT);
            packed(code, Host::MultiplyUnsignedDword, SECOND_PARTIAL, RESULT);
            packed(code, Host::AddQword, FIRST_PARTIAL, SECOND_PARTIAL);
            ShiftOpcode::LeftQword.emit(code, FIRST_PARTIAL, DWORD_BITS);
            packed(code, Host::MultiplyUnsignedDword, RESULT, RIGHT);
            packed(code, Host::AddQword, RESULT, FIRST_PARTIAL);
        }
        _ => unreachable!("validated product lane size"),
    }
}

/// The checked dword multiply replaces the complete two-part SSE2 low-product
/// recipe. Keep the baseline kernel shared with callers lacking SSE4.1.
fn multiply_low_for_target(code: &mut Code, element: ElementSize, target: TargetCpu) {
    if element == ElementSize::Word && target.supports(TargetCpu::Sse41) {
        Host::MultiplyLowDword.register(code, RESULT, RIGHT, target);
    } else {
        multiply_low(code, element);
    }
}

fn multiply_low_bytes(code: &mut Code) {
    // Whole-word multiplication already has the correct low byte. Compute the
    // product of the two high bytes separately and replace the contaminated
    // high byte of each whole-word result.
    packed(code, Host::MoveAligned, FIRST_PARTIAL, RESULT);
    packed(code, Host::MoveAligned, SECOND_PARTIAL, RIGHT);
    ShiftOpcode::RightWord.emit(code, FIRST_PARTIAL, BYTE_BITS);
    ShiftOpcode::RightWord.emit(code, SECOND_PARTIAL, BYTE_BITS);
    packed(code, Host::MultiplyLowWord, FIRST_PARTIAL, SECOND_PARTIAL);
    packed(code, Host::MultiplyLowWord, RESULT, RIGHT);
    ShiftOpcode::LeftWord.emit(code, FIRST_PARTIAL, BYTE_BITS);
    packed(code, Host::EqualDword, PREDICATE, PREDICATE);
    ShiftOpcode::RightWord.emit(code, PREDICATE, BYTE_BITS);
    packed(code, Host::And, RESULT, PREDICATE);
    packed(code, Host::Or, RESULT, FIRST_PARTIAL);
}

fn multiply_high_bytes(code: &mut Code, signed: bool) {
    packed(code, Host::MoveAligned, FIRST_PARTIAL, RESULT);
    packed(code, Host::MoveAligned, SECOND_PARTIAL, RIGHT);
    packed(code, Host::Xor, PREDICATE, PREDICATE);
    if signed {
        packed(code, Host::MoveAligned, PREDICATE_SCRATCH, PREDICATE);
        packed(code, Host::GreaterByte, PREDICATE_SCRATCH, RESULT);
        packed(code, Host::UnpackLowByte, RESULT, PREDICATE_SCRATCH);
        packed(code, Host::UnpackHighByte, FIRST_PARTIAL, PREDICATE_SCRATCH);
        packed(code, Host::MoveAligned, PREDICATE_SCRATCH, PREDICATE);
        packed(code, Host::GreaterByte, PREDICATE_SCRATCH, RIGHT);
        packed(code, Host::UnpackLowByte, RIGHT, PREDICATE_SCRATCH);
        packed(
            code,
            Host::UnpackHighByte,
            SECOND_PARTIAL,
            PREDICATE_SCRATCH,
        );
    } else {
        packed(code, Host::UnpackLowByte, RESULT, PREDICATE);
        packed(code, Host::UnpackHighByte, FIRST_PARTIAL, PREDICATE);
        packed(code, Host::UnpackLowByte, RIGHT, PREDICATE);
        packed(code, Host::UnpackHighByte, SECOND_PARTIAL, PREDICATE);
    }
    packed(code, Host::MultiplyLowWord, RESULT, RIGHT);
    packed(code, Host::MultiplyLowWord, FIRST_PARTIAL, SECOND_PARTIAL);
    // The selected byte is now an unsigned word in 0..255, so PACKUSWB is exact
    // even for signed high products: it preserves their two's-complement byte.
    ShiftOpcode::RightWord.emit(code, RESULT, BYTE_BITS);
    ShiftOpcode::RightWord.emit(code, FIRST_PARTIAL, BYTE_BITS);
    packed(code, Host::PackUnsignedWordToByte, RESULT, FIRST_PARTIAL);
}

fn multiply_high_words(code: &mut Code, signed: bool) {
    if signed {
        packed(code, Host::MoveAligned, FIRST_PARTIAL, RESULT);
        packed(code, Host::MoveAligned, SECOND_PARTIAL, RIGHT);
    }
    packed(code, Host::MoveAligned, PREDICATE, RESULT);
    packed(code, Host::MoveAligned, PREDICATE_SCRATCH, RIGHT);
    ShiftOpcode::RightQword.emit(code, PREDICATE, DWORD_BITS);
    ShiftOpcode::RightQword.emit(code, PREDICATE_SCRATCH, DWORD_BITS);
    packed(
        code,
        Host::MultiplyUnsignedDword,
        PREDICATE,
        PREDICATE_SCRATCH,
    );
    packed(code, Host::MultiplyUnsignedDword, RESULT, RIGHT);
    ShiftOpcode::RightQword.emit(code, RESULT, DWORD_BITS);
    ShiftOpcode::RightQword.emit(code, PREDICATE, DWORD_BITS);
    shuffle(code, Host::ShuffleDword, RESULT, SELECT_LOW_PRODUCT_DWORDS);
    shuffle(
        code,
        Host::ShuffleDword,
        PREDICATE,
        SELECT_LOW_PRODUCT_DWORDS,
    );
    packed(code, Host::UnpackLowDword, RESULT, PREDICATE);
    if signed {
        // high_signed(a*b) = high_unsigned(a*b) - (a<0 ? b : 0)
        //                                           - (b<0 ? a : 0).
        packed(code, Host::MoveAligned, PREDICATE, FIRST_PARTIAL);
        ShiftOpcode::ArithmeticDword.emit(code, FIRST_PARTIAL, DWORD_SIGN_SHIFT);
        packed(code, Host::And, FIRST_PARTIAL, SECOND_PARTIAL);
        ShiftOpcode::ArithmeticDword.emit(code, SECOND_PARTIAL, DWORD_SIGN_SHIFT);
        packed(code, Host::And, SECOND_PARTIAL, PREDICATE);
        packed(code, Host::SubDword, RESULT, FIRST_PARTIAL);
        packed(code, Host::SubDword, RESULT, SECOND_PARTIAL);
    }
}

fn multiply_high_doublewords(code: &mut Code, signed: bool) {
    packed(code, Host::MoveAligned, SECOND_PARTIAL, RESULT);
    packed(code, Host::MoveAligned, PREDICATE, RIGHT);
    ShiftOpcode::RightBytes.emit(code, SECOND_PARTIAL, QWORD_BYTES as u8);
    ShiftOpcode::RightBytes.emit(code, PREDICATE, QWORD_BYTES as u8);
    let multiply = if signed { Unary::Imul } else { Unary::Mul };
    let mut asm = code.asm();
    for (left, right, high) in [
        (RESULT, RIGHT, FIRST_PARTIAL),
        (SECOND_PARTIAL, PREDICATE, RESULT),
    ] {
        asm.movq_from_xmm(Rax, left);
        asm.movq_from_xmm(Rcx, right);
        asm.unary(multiply, Size::Qword, Rcx);
        asm.simd(Host::MoveGprQword, high, Rdx, TargetCpu::Baseline);
    }
    packed(code, Host::UnpackLowQword, FIRST_PARTIAL, RESULT);
    packed(code, Host::MoveAligned, RESULT, FIRST_PARTIAL);
}

fn multiply_high(code: &mut Code, element: ElementSize, signed: bool) {
    match element {
        ElementSize::Byte => multiply_high_bytes(code, signed),
        ElementSize::Halfword => {
            let opcode = if signed {
                Host::MultiplyHighSignedWord
            } else {
                Host::MultiplyHighUnsignedWord
            };
            packed(code, opcode, RESULT, RIGHT);
        }
        ElementSize::Word => multiply_high_words(code, signed),
        ElementSize::Doubleword => multiply_high_doublewords(code, signed),
        ElementSize::Quadword => unreachable!("validated product lane size"),
    }
}

fn accumulate(code: &mut Code, element: ElementSize, subtract: bool) {
    let opcode = match (element, subtract) {
        (ElementSize::Byte, false) => Host::AddByte,
        (ElementSize::Halfword, false) => Host::AddWord,
        (ElementSize::Word, false) => Host::AddDword,
        (ElementSize::Doubleword, false) => Host::AddQword,
        (ElementSize::Byte, true) => Host::SubByte,
        (ElementSize::Halfword, true) => Host::SubWord,
        (ElementSize::Word, true) => Host::SubDword,
        (ElementSize::Doubleword, true) => Host::SubQword,
        _ => unreachable!("validated product lane size"),
    };
    if subtract {
        packed(code, opcode, ACCUMULATOR_OR_CONSTANT, RESULT);
        packed(code, Host::MoveAligned, RESULT, ACCUMULATOR_OR_CONSTANT);
    } else {
        packed(code, opcode, RESULT, ACCUMULATOR_OR_CONSTANT);
    }
}

/// Validate emitter operand shape before the caller appends instruction bytes.
pub fn validate(operand: Operand) -> Result<(), Unsupported> {
    if supported(operand) {
        Ok(())
    } else {
        Err(Unsupported)
    }
}

/// Emit ordinary vector effects for an operand accepted by `validate`.
/// The caller owns ISA/mode and MOVPRFX validity checks.
/// This mapping preserves guest NZCV, FPSR.QC, FPCR and RAM; all arithmetic is
/// integer host instructions and leaves host MXCSR untouched. Optional faster
/// kernels are gated by their exact host capabilities.
pub fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
    assert!(supported(operand), "validated integer product operand");
    if let Multiplier::Immediate(value) = operand.multiplier {
        immediate(code, value, operand.element_size);
    }
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.source, chunk, RESULT, length, target);
        match operand.multiplier {
            Multiplier::Vector {
                register,
                segment_lane,
            } => {
                load_z_chunk(code, register, chunk, RIGHT, length, target);
                if let Some(lane) = segment_lane {
                    broadcast_lane(code, multiplier_element(operand), lane);
                }
            }
            Multiplier::Immediate(_) => {
                packed(code, Host::MoveAligned, RIGHT, ACCUMULATOR_OR_CONSTANT);
            }
        }
        if let Some(register) = operand.accumulator {
            load_z_chunk(
                code,
                register,
                chunk,
                ACCUMULATOR_OR_CONSTANT,
                length,
                target,
            );
        }
        if matches!(operand.predication, Predication::Merging(_)) {
            load_z_chunk(code, operand.destination, chunk, PREVIOUS, length, target);
        }
        match operand.kind {
            Kind::Multiply => multiply_low_for_target(code, operand.element_size, target),
            Kind::Accumulate { subtract } => {
                multiply_low_for_target(code, operand.element_size, target);
                accumulate(code, operand.element_size, subtract);
            }
            Kind::MultiplyHigh { signed } => multiply_high(code, operand.element_size, signed),
            Kind::Long {
                signed,
                doubling: false,
                accumulate,
                selection,
            } => {
                widening::emit_chunk(
                    code,
                    operand.element_size,
                    signed,
                    accumulate,
                    selection,
                    target,
                );
            }
            Kind::Long { doubling: true, .. }
            | Kind::DoublingHigh { .. }
            | Kind::RoundedHighAccumulate { .. } => {
                saturating::emit_chunk_for_target(code, operand.kind, operand.element_size, target);
            }
            Kind::Complex { rounded } => {
                complex::emit_chunk(
                    code,
                    operand.element_size,
                    rounded,
                    operand.rotation_degrees,
                    target,
                )
                .expect("validated complex product operand");
            }
            Kind::Polynomial {
                widening,
                selection,
            } => {
                polynomial::emit_chunk(code, operand.element_size, widening, selection, target)
                    .expect("validated polynomial product operand");
            }
        }
        if let Predication::Merging(predicate) = operand.predication {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                operand.element_size,
                PREDICATE,
                PREDICATE_SCRATCH,
                length,
                target,
            );
            packed(code, Host::And, RESULT, PREDICATE);
            packed(code, Host::AndNot, PREDICATE, PREVIOUS);
            packed(code, Host::Or, RESULT, PREDICATE);
        }
        store_z_chunk(code, operand.destination, chunk, RESULT, length, target);
    }
}
