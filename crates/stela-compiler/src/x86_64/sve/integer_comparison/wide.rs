//! Wide-element right-hand sides for SVE comparisons.
use super::{
    BYTE_BITS, ElementSize, Host, Operand, QWORD_BYTES, REPEAT_BYTE_IN_DWORD,
    REPEAT_HALFWORD_IN_DWORD, Relation, Shift, TargetCpu, VectorLength, WORD_SIGN_SHIFT, XMM_BIAS,
    XMM_CHUNK_BYTES, XMM_HIGH_GREATER, XMM_LEFT, XMM_RIGHT, emit_compare_chunk, emit_compare_mask,
    shuffle,
};
use crate::x86_64::asm::Gpr::{R8, Rax, Rcx, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, ShiftOp, Size, Unary};
use crate::x86_64::scalable::load_z_chunk;

const XMM_WIDE_LEFT: u8 = 6;
const XMM_WIDE_RIGHT: u8 = 7;
const LOW_ELEMENT_BIT: u32 = 1;
const REPEAT_LOW_QWORD: u8 = 0x44;
const REPEAT_HIGH_QWORD: u8 = 0xee;
const HALFWORD_BITS: u8 = 16;
const IN_RANGE: u8 = 5;
const OVERRIDE: u8 = 6;
const HIGH_IN_RANGE: u8 = 3;
const HIGH_OVERRIDE: u8 = 4;

// Whole-body measurements cover 16 and 64 bytes. The 32-byte policy follows
// the short case; 128/256 follow the long case. Those speeds remain inferred.
const LONG_VECTOR_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recipe {
    Range,
    BaselinePairs,
    CheckedPairs,
}

fn recipe(operand: Operand, length: VectorLength, target: TargetCpu) -> Recipe {
    let equality = matches!(operand.relation, Relation::Equal | Relation::NotEqual);
    let checked = target.supports(if equality {
        TargetCpu::Sse41
    } else {
        TargetCpu::Sse42
    });
    let long = length.bytes() >= LONG_VECTOR_BYTES;
    match operand.element_size {
        ElementSize::Byte => Recipe::Range,
        ElementSize::Halfword if checked && (!long || (!equality && !operand.unsigned)) => {
            Recipe::CheckedPairs
        }
        ElementSize::Halfword if !checked && equality && !long => Recipe::BaselinePairs,
        ElementSize::Halfword => Recipe::Range,
        ElementSize::Word if checked => Recipe::CheckedPairs,
        ElementSize::Word
            if long
                && operand.unsigned
                && matches!(operand.relation, Relation::Greater | Relation::GreaterEqual) =>
        {
            Recipe::Range
        }
        ElementSize::Word => Recipe::BaselinePairs,
        _ => unreachable!("decoded wide comparison width"),
    }
}

pub(super) fn emit_chunk(
    code: &mut Code,
    operand: Operand,
    right: u8,
    chunk: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    load_z_chunk(code, operand.left, chunk, XMM_WIDE_LEFT, length, target);
    load_z_chunk(code, right, chunk, XMM_WIDE_RIGHT, length, target);
    match recipe(operand, length, target) {
        Recipe::Range => range_chunk(code, operand, target),
        Recipe::BaselinePairs => pair_chunk(code, operand, target, false),
        Recipe::CheckedPairs => pair_chunk(code, operand, target, true),
    }
}

fn widen_left_pair(
    code: &mut Code,
    size: ElementSize,
    offset: usize,
    unsigned: bool,
    target: TargetCpu,
    checked: bool,
) {
    if checked {
        let source = if offset == 0 {
            XMM_WIDE_LEFT
        } else {
            Host::MoveAligned.register(code, XMM_LEFT, XMM_WIDE_LEFT, target);
            Shift::RightBytes.emit(code, XMM_LEFT, offset as u8);
            XMM_LEFT
        };
        let opcode = match (size, unsigned) {
            (ElementSize::Halfword, false) => Host::SignExtendWordToQword,
            (ElementSize::Halfword, true) => Host::ZeroExtendWordToQword,
            (ElementSize::Word, false) => Host::SignExtendDwordToQword,
            (ElementSize::Word, true) => Host::ZeroExtendDwordToQword,
            _ => unreachable!("exact wide pair element size"),
        };
        opcode.register(code, XMM_LEFT, source, target);
        return;
    }
    Host::MoveAligned.register(code, XMM_LEFT, XMM_WIDE_LEFT, TargetCpu::Baseline);
    if offset != 0 {
        Shift::RightBytes.emit(code, XMM_LEFT, offset as u8);
    }
    if unsigned {
        Host::Xor.register(
            code,
            XMM_HIGH_GREATER,
            XMM_HIGH_GREATER,
            TargetCpu::Baseline,
        );
        if size == ElementSize::Halfword {
            Host::UnpackLowWord.register(code, XMM_LEFT, XMM_HIGH_GREATER, TargetCpu::Baseline);
        }
        Host::UnpackLowDword.register(code, XMM_LEFT, XMM_HIGH_GREATER, TargetCpu::Baseline);
    } else {
        if size == ElementSize::Halfword {
            Host::UnpackLowWord.register(code, XMM_LEFT, XMM_LEFT, TargetCpu::Baseline);
            Shift::ArithmeticDword.emit(code, XMM_LEFT, HALFWORD_BITS);
        }
        Host::MoveAligned.register(code, XMM_HIGH_GREATER, XMM_LEFT, TargetCpu::Baseline);
        Shift::ArithmeticDword.emit(code, XMM_HIGH_GREATER, WORD_SIGN_SHIFT);
        Host::UnpackLowDword.register(code, XMM_LEFT, XMM_HIGH_GREATER, TargetCpu::Baseline);
    }
}

fn pair_chunk(code: &mut Code, operand: Operand, target: TargetCpu, checked: bool) {
    code.asm().alu(Alu::Xor, Size::Dword, R8, R8);
    let bytes = operand.element_size.bytes();
    for offset in (0..XMM_CHUNK_BYTES).step_by(bytes * 2) {
        widen_left_pair(
            code,
            operand.element_size,
            offset,
            operand.unsigned,
            target,
            checked,
        );
        shuffle(
            code,
            XMM_RIGHT,
            XMM_WIDE_RIGHT,
            if offset < QWORD_BYTES {
                REPEAT_LOW_QWORD
            } else {
                REPEAT_HIGH_QWORD
            },
        );
        emit_compare_chunk(
            code,
            operand.relation,
            operand.unsigned,
            ElementSize::Doubleword,
            target,
        )
        .expect("wide compare stages allocated doubleword operands");
        let mut asm = code.asm();
        asm.mov(Size::Dword, Rcx, Rax);
        asm.alu_accumulator_imm32(Alu::And, Size::Dword, LOW_ELEMENT_BIT as i32);
        asm.shift_imm(ShiftOp::Shr, Size::Dword, Rcx, BYTE_BITS);
        asm.alu_imm32(Alu::And, Size::Dword, Rcx, LOW_ELEMENT_BIT as i32);
        asm.shift_imm(ShiftOp::Shl, Size::Dword, Rcx, bytes as u8);
        asm.alu(Alu::Or, Size::Dword, Rax, Rcx);
        if offset != 0 {
            asm.shift_imm(ShiftOp::Shl, Size::Dword, Rax, offset as u8);
        }
        asm.alu(Alu::Or, Size::Dword, R8, Rax);
    }
    code.asm().mov(Size::Dword, Rax, R8);
}

fn range_chunk(code: &mut Code, operand: Operand, target: TargetCpu) {
    // Classify each full64 RHS before narrow packed comparison.
    let bits = operand.element_size.bits();
    let ordered = !matches!(operand.relation, Relation::Equal | Relation::NotEqual);
    let less = matches!(operand.relation, Relation::Less | Relation::LessEqual);
    let override_needed = ordered && (!operand.unsigned || less);
    Host::MoveAligned.register(code, XMM_LEFT, XMM_WIDE_LEFT, target);
    for high in [false, true] {
        let (right, range, constant) = if high {
            Host::MoveAligned.register(code, XMM_RIGHT + 1, XMM_WIDE_RIGHT, target);
            Shift::RightBytes.emit(code, XMM_RIGHT + 1, QWORD_BYTES as u8);
            code.asm().movq_from_xmm(Rax, XMM_RIGHT + 1);
            (XMM_RIGHT + 1, HIGH_IN_RANGE, HIGH_OVERRIDE)
        } else {
            code.asm().movq_from_xmm(Rax, XMM_WIDE_RIGHT);
            (XMM_RIGHT, IN_RANGE, OVERRIDE)
        };
        let mut asm = code.asm();
        match (operand.element_size, operand.unsigned) {
            (ElementSize::Byte, false) => asm.movsx(Size::Qword, Rdx, Size::Byte, Rax),
            (ElementSize::Halfword, false) => asm.movsx(Size::Qword, Rdx, Size::Word, Rax),
            (ElementSize::Word, false) => asm.movsxd(Rdx, Rax),
            (ElementSize::Byte, true) => asm.movzx(Size::Dword, Rdx, Size::Byte, Rax),
            (ElementSize::Halfword, true) => asm.movzx(Size::Dword, Rdx, Size::Word, Rax),
            (ElementSize::Word, true) => asm.mov(Size::Dword, Rdx, Rax),
            _ => unreachable!("allocated wide source width"),
        }
        asm.alu(Alu::Cmp, Size::Qword, Rax, Rdx);
        asm.setcc(Cond::E, Rcx);
        if override_needed {
            if operand.unsigned {
                asm.setcc(Cond::Ne, Rdx);
            } else {
                let bound = if less {
                    (1i64 << (bits - 1)) - 1
                } else {
                    -(1i64 << (bits - 1))
                };
                asm.alu_accumulator_imm32(Alu::Cmp, Size::Qword, bound as i32);
                asm.setcc(if less { Cond::G } else { Cond::L }, Rdx);
            }
            asm.movzx(Size::Dword, Rdx, Size::Byte, Rdx);
            asm.unary(Unary::Neg, Size::Qword, Rdx);
            asm.movq_to_xmm(constant, Rdx);
        }
        asm.movzx(Size::Dword, Rcx, Size::Byte, Rcx);
        asm.unary(Unary::Neg, Size::Qword, Rcx);
        asm.movq_to_xmm(range, Rcx);
        match operand.element_size {
            ElementSize::Byte => {
                asm.movzx(Size::Dword, Rax, Size::Byte, Rax);
                asm.imul_imm32(Size::Dword, Rax, Rax, REPEAT_BYTE_IN_DWORD as i32);
            }
            ElementSize::Halfword => {
                asm.movzx(Size::Dword, Rax, Size::Word, Rax);
                asm.imul_imm32(Size::Dword, Rax, Rax, REPEAT_HALFWORD_IN_DWORD as i32);
            }
            ElementSize::Word => {}
            _ => unreachable!("allocated wide source width"),
        }
        asm.movd_to_xmm(right, Rax);
        shuffle(code, right, right, 0);
    }
    Host::UnpackLowQword.register(code, XMM_RIGHT, XMM_RIGHT + 1, target);
    Host::UnpackLowQword.register(code, IN_RANGE, HIGH_IN_RANGE, target);
    if override_needed {
        Host::UnpackLowQword.register(code, OVERRIDE, HIGH_OVERRIDE, target);
    }
    let relation = if operand.relation == Relation::NotEqual {
        Relation::Equal
    } else {
        operand.relation
    };
    let result = emit_compare_mask(
        code,
        relation,
        operand.unsigned,
        operand.element_size,
        target,
    )
    .unwrap();
    Host::And.register(code, result, IN_RANGE, target);
    if override_needed {
        Host::Or.register(code, result, OVERRIDE, target);
    }
    if operand.relation == Relation::NotEqual {
        Host::EqualDword.register(code, XMM_BIAS, XMM_BIAS, target);
        Host::Xor.register(code, result, XMM_BIAS, target);
    }
    code.asm()
        .simd_to_gpr(Host::ByteSignMask, Rax, result, target);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::sve::integer_comparison::decode;

    #[test]
    fn checked_pair_selection_requires_the_comparison_feature() {
        let half_equal = decode(0x2440_2020).unwrap().unwrap();
        let half_greater = decode(0x2440_4030).unwrap().unwrap();
        let word_greater = decode(0x2480_4030).unwrap().unwrap();
        let short = VectorLength::from_bytes(16).unwrap();
        assert_eq!(
            recipe(half_equal, short, TargetCpu::Baseline),
            Recipe::BaselinePairs
        );
        assert_eq!(
            recipe(half_equal, short, TargetCpu::Sse41),
            Recipe::CheckedPairs
        );
        assert_eq!(recipe(half_greater, short, TargetCpu::Sse41), Recipe::Range);
        assert_eq!(
            recipe(half_greater, short, TargetCpu::Sse42),
            Recipe::CheckedPairs
        );
        assert_eq!(
            recipe(word_greater, short, TargetCpu::Sse41),
            Recipe::BaselinePairs
        );
        assert_eq!(
            recipe(word_greater, short, TargetCpu::Sse42),
            Recipe::CheckedPairs
        );
    }

    #[test]
    fn long_mapping_keeps_measured_unsigned_word_less_latency_choice() {
        let word_hi = decode(0x2480_c030).unwrap().unwrap();
        let word_lo = decode(0x2480_e020).unwrap().unwrap();
        let half_equal = decode(0x2440_2020).unwrap().unwrap();
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            assert_eq!(
                recipe(word_lo, length, TargetCpu::Baseline),
                Recipe::BaselinePairs
            );
            assert_eq!(
                recipe(word_hi, length, TargetCpu::Baseline),
                if bytes < LONG_VECTOR_BYTES {
                    Recipe::BaselinePairs
                } else {
                    Recipe::Range
                }
            );
            assert_eq!(
                recipe(half_equal, length, TargetCpu::Sse42),
                if bytes < LONG_VECTOR_BYTES {
                    Recipe::CheckedPairs
                } else {
                    Recipe::Range
                }
            );
        }
    }
}
