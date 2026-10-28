//! Wide-element right-hand sides for SVE comparisons.
use super::{
    AND_EAX_IMMEDIATE, BYTE_BITS, ElementSize, Host, MOV_EAX_R8D, MOV_EDX_EAX, MOVD_XMM_EAX,
    MOVQ_XMM_RAX, MOVZX_EAX_AL, MOVZX_ECX_CL, Operand, QWORD_BYTES, REPEAT_BYTE_IN_DWORD,
    REPEAT_HALFWORD_IN_DWORD, Relation, SHL_EAX, SHL_ECX, SHR_ECX, Shift, TargetCpu, VectorLength,
    WORD_SIGN_SHIFT, XMM_BIAS, XMM_CHUNK_BYTES, XMM_HIGH_GREATER, XMM_LEFT, XMM_RIGHT,
    emit_compare_chunk, emit_compare_mask, register_fields, shuffle,
};
use crate::x86_64::asm::Code;
use crate::x86_64::scalable::load_z_chunk;

const XMM_WIDE_LEFT: u8 = 6;
const XMM_WIDE_RIGHT: u8 = 7;
const LOW_ELEMENT_BIT: u32 = 1;
const REPEAT_LOW_QWORD: u8 = 0x44;
const REPEAT_HIGH_QWORD: u8 = 0xee;
const XOR_R8D_R8D: &[u8] = &[0x45, 0x31, 0xc0];
const OR_R8D_EAX: &[u8] = &[0x41, 0x09, 0xc0];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const AND_ECX_IMMEDIATE: &[u8] = &[0x81, 0xe1];
const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];
const HALFWORD_BITS: u8 = 16;
const MOVSX_RDX_AL: &[u8] = &[0x48, 0x0f, 0xbe, 0xd0];
const MOVSX_RDX_AX: &[u8] = &[0x48, 0x0f, 0xbf, 0xd0];
const MOVSXD_RDX_EAX: &[u8] = &[0x48, 0x63, 0xd0];
const MOVZX_EDX_AL: &[u8] = &[0x0f, 0xb6, 0xd0];
const MOVZX_EDX_AX: &[u8] = &[0x0f, 0xb7, 0xd0];
const MOVQ_RAX_XMM: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
const CMP_RAX_RDX: &[u8] = &[0x48, 0x39, 0xd0];
const SETE_CL: &[u8] = &[0x0f, 0x94, 0xc1];
const MOVZX_EDX_DL: &[u8] = &[0x0f, 0xb6, 0xd2];
const NEG_RDX: &[u8] = &[0x48, 0xf7, 0xda];
const NEG_RCX: &[u8] = &[0x48, 0xf7, 0xd9];
const CMP_RAX_SIGNED_IMMEDIATE: &[u8] = &[0x48, 0x3d];
const SETL_DL: &[u8] = &[0x0f, 0x9c, 0xc2];
const SETG_DL: &[u8] = &[0x0f, 0x9f, 0xc2];
const SETNE_DL: &[u8] = &[0x0f, 0x95, 0xc2];
const MOVZX_EAX_AX: &[u8] = &[0x0f, 0xb7, 0xc0];
const IMUL_EAX_EAX_IMMEDIATE: &[u8] = &[0x69, 0xc0];
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
    code.extend_from_slice(XOR_R8D_R8D);
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
        code.extend_from_slice(MOV_ECX_EAX);
        code.push(AND_EAX_IMMEDIATE);
        code.extend(LOW_ELEMENT_BIT.to_le_bytes());
        code.extend_from_slice(SHR_ECX);
        code.push(BYTE_BITS);
        code.extend_from_slice(AND_ECX_IMMEDIATE);
        code.extend(LOW_ELEMENT_BIT.to_le_bytes());
        code.extend_from_slice(SHL_ECX);
        code.push(bytes as u8);
        code.extend_from_slice(OR_EAX_ECX);
        if offset != 0 {
            code.extend_from_slice(SHL_EAX);
            code.push(offset as u8);
        }
        code.extend_from_slice(OR_R8D_EAX);
    }
    code.extend_from_slice(MOV_EAX_R8D);
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
            register_fields(code, MOVQ_RAX_XMM, XMM_RIGHT + 1, 0);
            (XMM_RIGHT + 1, HIGH_IN_RANGE, HIGH_OVERRIDE)
        } else {
            register_fields(code, MOVQ_RAX_XMM, XMM_WIDE_RIGHT, 0);
            (XMM_RIGHT, IN_RANGE, OVERRIDE)
        };
        code.extend_from_slice(match (operand.element_size, operand.unsigned) {
            (ElementSize::Byte, false) => MOVSX_RDX_AL,
            (ElementSize::Halfword, false) => MOVSX_RDX_AX,
            (ElementSize::Word, false) => MOVSXD_RDX_EAX,
            (ElementSize::Byte, true) => MOVZX_EDX_AL,
            (ElementSize::Halfword, true) => MOVZX_EDX_AX,
            (ElementSize::Word, true) => MOV_EDX_EAX,
            _ => unreachable!("allocated wide source width"),
        });
        code.extend_from_slice(CMP_RAX_RDX);
        code.extend_from_slice(SETE_CL);
        if override_needed {
            if operand.unsigned {
                code.extend_from_slice(SETNE_DL);
            } else {
                code.extend_from_slice(CMP_RAX_SIGNED_IMMEDIATE);
                let bound = if less {
                    (1i64 << (bits - 1)) - 1
                } else {
                    -(1i64 << (bits - 1))
                };
                code.extend((bound as i32).to_le_bytes());
                code.extend_from_slice(if less { SETG_DL } else { SETL_DL });
            }
            code.extend_from_slice(MOVZX_EDX_DL);
            code.extend_from_slice(NEG_RDX);
            register_fields(code, MOVQ_XMM_RAX, constant, 2);
        }
        code.extend_from_slice(MOVZX_ECX_CL);
        code.extend_from_slice(NEG_RCX);
        register_fields(code, MOVQ_XMM_RAX, range, 1);
        match operand.element_size {
            ElementSize::Byte => {
                code.extend_from_slice(MOVZX_EAX_AL);
                code.extend_from_slice(IMUL_EAX_EAX_IMMEDIATE);
                code.extend(REPEAT_BYTE_IN_DWORD.to_le_bytes());
            }
            ElementSize::Halfword => {
                code.extend_from_slice(MOVZX_EAX_AX);
                code.extend_from_slice(IMUL_EAX_EAX_IMMEDIATE);
                code.extend(REPEAT_HALFWORD_IN_DWORD.to_le_bytes());
            }
            ElementSize::Word => {}
            _ => unreachable!("allocated wide source width"),
        }
        register_fields(code, MOVD_XMM_EAX, right, 0);
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
    Host::ByteSignMask.register(code, 0, result, target);
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
