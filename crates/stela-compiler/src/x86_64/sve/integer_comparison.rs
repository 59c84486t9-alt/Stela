//! SVE integer comparisons into predicates.
use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, VectorLength};
use crate::aarch64::sve::integer_comparison::{Operand, Relation, Right};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};
use alloc::vec::Vec;

const XMM_LEFT: u8 = 0;
const XMM_RIGHT: u8 = 1;
const XMM_HIGH_GREATER: u8 = 2;
const XMM_HIGH_EQUAL: u8 = 3;
const XMM_BIAS: u8 = 4;
const MOD_REGISTER: u8 = 0xc0;
const REGISTER_SHIFT: u8 = 3;
const REPEAT_BYTE_IN_DWORD: u32 = 0x0101_0101;
const REPEAT_HALFWORD_IN_DWORD: u32 = 0x0001_0001;
const MOVD_XMM_EAX: &[u8] = &[0x66, 0x0f, 0x6e];
const XMM_CHUNK_BYTES: usize = 16;
const BYTE_SIGN_SHIFT: u8 = 7;
const HALFWORD_SIGN_SHIFT: u8 = 15;
const WORD_SIGN_SHIFT: u8 = 31;
const DOUBLEWORD_SIGN_SHIFT: u8 = 63;
const REPLICATE_HIGH_WORDS: u8 = 0xf5;
const REPLICATE_LOW_WORDS: u8 = 0xa0;
const SWAP_ADJACENT_WORDS: u8 = 0xb1;
const XOR_EAX_IMMEDIATE: u8 = 0x35;
const TRUTH_BYTE_MASK: u32 = 0xffff;

const PREDICATE_RESULT_STACK_BYTES: u8 = 32;
const PREDICATE_BITS_PER_VECTOR_CHUNK: usize = 16;
const VECTOR_CHUNKS_PER_PREDICATE_QWORD: usize = 4;
const PREDICATE_RESULT_CHUNK_BYTES: usize = 2;
const QWORD_BYTES: usize = 8;
const BYTE_BITS: u8 = 8;
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const MOV_RAX_SIGNED_IMMEDIATE: &[u8] = &[0x48, 0xc7, 0xc0];
const MOVQ_XMM_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e];
const MOV_R8D_EAX: &[u8] = &[0x41, 0x89, 0xc0];
const MOV_EAX_R8D: &[u8] = &[0x44, 0x89, 0xc0];
const MOV_EDX_EAX: &[u8] = &[0x89, 0xc2];
const AND_EAX_EDX: &[u8] = &[0x21, 0xd0];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const SHR_ECX: &[u8] = &[0xc1, 0xe9];
const SHL_ECX: &[u8] = &[0xc1, 0xe1];
const SHL_EAX: &[u8] = &[0xc1, 0xe0];
const SHR_RAX: &[u8] = &[0x48, 0xc1, 0xe8];
const SUB_RSP_IMMEDIATE: &[u8] = &[0x48, 0x83, 0xec];
const ADD_RSP_IMMEDIATE: &[u8] = &[0x48, 0x83, 0xc4];
const STORE_STACK_AX: &[u8] = &[0x66, 0x89, 0x44, 0x24];
const LOAD_STACK_RAX: &[u8] = &[0x48, 0x8b, 0x44, 0x24];
const LOAD_STACK_EAX: &[u8] = &[0x8b, 0x44, 0x24];
const LOAD_STACK_WORD_EAX: &[u8] = &[0x0f, 0xb7, 0x44, 0x24];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const MOVABS_RCX_IMMEDIATE: &[u8] = &[0x48, 0xb9];
const AND_RDX_RCX: &[u8] = &[0x48, 0x21, 0xca];
const XOR_R9D_R9D: &[u8] = &[0x45, 0x31, 0xc9];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const MOV_R11D_IMMEDIATE: &[u8] = &[0x41, 0xbb];
const OR_R10_RAX: &[u8] = &[0x49, 0x09, 0xc2];
const TEST_RDX_RDX: &[u8] = &[0x48, 0x85, 0xd2];
const TEST_R9D_IMMEDIATE: &[u8] = &[0x41, 0xf7, 0xc1];
const BSF_RCX_RDX: &[u8] = &[0x48, 0x0f, 0xbc, 0xca];
const BSR_RCX_RDX: &[u8] = &[0x48, 0x0f, 0xbd, 0xca];
const BT_RAX_RCX: &[u8] = &[0x48, 0x0f, 0xa3, 0xc8];
const SETC_CL: &[u8] = &[0x0f, 0x92, 0xc1];
const MOVZX_ECX_CL: &[u8] = &[0x0f, 0xb6, 0xc9];
const OR_R9D_ECX: &[u8] = &[0x41, 0x09, 0xc9];
const OR_R9D_ONE: &[u8] = &[0x41, 0x83, 0xc9, 1];
const SETNC_R11B: &[u8] = &[0x41, 0x0f, 0x93, 0xc3];
const TEST_R10_R10: &[u8] = &[0x4d, 0x85, 0xd2];
const SETZ_AL: &[u8] = &[0x0f, 0x94, 0xc0];
const MOVZX_EAX_AL: &[u8] = &[0x0f, 0xb6, 0xc0];
const AND_R9D_IMMEDIATE: &[u8] = &[0x41, 0x81, 0xe1];
const SHL_R11D: &[u8] = &[0x41, 0xc1, 0xe3];
const OR_EAX_R9D: &[u8] = &[0x44, 0x09, 0xc8];
const OR_EAX_R11D: &[u8] = &[0x44, 0x09, 0xd8];
const STORE_STATE_EAX: &[u8] = &[0x89, 0x87];
const JZ_REL32: &[u8] = &[0x0f, 0x84];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const NZCV_N_SHIFT: u8 = 31;
const NZCV_Z_SHIFT: u8 = 30;
const NZCV_C_SHIFT: u8 = 29;
const FIRST_ACTIVE_SEEN: u32 = 1;
const INITIAL_CARRY: u32 = 1;
const XMM_IMMEDIATE: u8 = 5;

mod wide;

fn register_fields(code: &mut Vec<u8>, opcode: &[u8], reg: u8, rm: u8) {
    code.extend_from_slice(opcode);
    code.push(MOD_REGISTER | (reg << REGISTER_SHIFT) | rm);
}

fn shuffle(code: &mut Vec<u8>, destination: u8, source: u8, control: u8) {
    Host::ShuffleDword.register(code, destination, source, TargetCpu::Baseline);
    code.push(control);
}

fn sign_bias(code: &mut Vec<u8>, size: ElementSize) {
    Host::EqualDword.register(code, XMM_BIAS, XMM_BIAS, TargetCpu::Baseline);
    let (opcode, amount) = match size {
        ElementSize::Byte => (Shift::LeftWord, BYTE_SIGN_SHIFT),
        ElementSize::Halfword => (Shift::LeftWord, HALFWORD_SIGN_SHIFT),
        ElementSize::Word => (Shift::LeftDword, WORD_SIGN_SHIFT),
        ElementSize::Doubleword => (Shift::LeftQword, DOUBLEWORD_SIGN_SHIFT),
        ElementSize::Quadword => unreachable!("validated comparison element size"),
    };
    opcode.emit(code, XMM_BIAS, amount);
    if size == ElementSize::Byte {
        Host::PackSignedWordToByte.register(code, XMM_BIAS, XMM_BIAS, TargetCpu::Baseline);
    }
}

fn equal_doublewords(code: &mut Vec<u8>, left: u8, right: u8) {
    Host::EqualDword.register(code, left, right, TargetCpu::Baseline);
    shuffle(code, XMM_HIGH_GREATER, left, SWAP_ADJACENT_WORDS);
    Host::And.register(code, left, XMM_HIGH_GREATER, TargetCpu::Baseline);
}

fn greater_doublewords(code: &mut Vec<u8>, left: u8, right: u8) {
    Host::MoveAligned.register(code, XMM_HIGH_GREATER, left, TargetCpu::Baseline);
    Host::GreaterDword.register(code, XMM_HIGH_GREATER, right, TargetCpu::Baseline);
    shuffle(
        code,
        XMM_HIGH_GREATER,
        XMM_HIGH_GREATER,
        REPLICATE_HIGH_WORDS,
    );
    Host::MoveAligned.register(code, XMM_HIGH_EQUAL, left, TargetCpu::Baseline);
    Host::EqualDword.register(code, XMM_HIGH_EQUAL, right, TargetCpu::Baseline);
    shuffle(code, XMM_HIGH_EQUAL, XMM_HIGH_EQUAL, REPLICATE_HIGH_WORDS);
    sign_bias(code, ElementSize::Word);
    Host::Xor.register(code, left, XMM_BIAS, TargetCpu::Baseline);
    Host::Xor.register(code, right, XMM_BIAS, TargetCpu::Baseline);
    Host::GreaterDword.register(code, left, right, TargetCpu::Baseline);
    shuffle(code, left, left, REPLICATE_LOW_WORDS);
    Host::And.register(code, left, XMM_HIGH_EQUAL, TargetCpu::Baseline);
    Host::Or.register(code, left, XMM_HIGH_GREATER, TargetCpu::Baseline);
}

fn compare_lanes(
    code: &mut Vec<u8>,
    relation: Relation,
    unsigned: bool,
    size: ElementSize,
    target: TargetCpu,
) -> Result<(u8, bool), ()> {
    if size == ElementSize::Quadword {
        return Err(());
    }
    let equality = matches!(relation, Relation::Equal | Relation::NotEqual);
    let reverse = matches!(relation, Relation::GreaterEqual | Relation::Less);
    let invert = matches!(
        relation,
        Relation::NotEqual | Relation::GreaterEqual | Relation::LessEqual
    );
    let (left, right) = if reverse {
        (XMM_RIGHT, XMM_LEFT)
    } else {
        (XMM_LEFT, XMM_RIGHT)
    };
    if unsigned && !equality {
        sign_bias(code, size);
        Host::Xor.register(code, left, XMM_BIAS, TargetCpu::Baseline);
        Host::Xor.register(code, right, XMM_BIAS, TargetCpu::Baseline);
    }
    let opcode = match (size, equality) {
        (ElementSize::Byte, true) => Some(Host::EqualByte),
        (ElementSize::Halfword, true) => Some(Host::EqualWord),
        (ElementSize::Word, true) => Some(Host::EqualDword),
        (ElementSize::Doubleword, true) if target.supports(TargetCpu::Sse41) => {
            Some(Host::EqualQword)
        }
        (ElementSize::Byte, false) => Some(Host::GreaterByte),
        (ElementSize::Halfword, false) => Some(Host::GreaterWord),
        (ElementSize::Word, false) => Some(Host::GreaterDword),
        (ElementSize::Doubleword, false) if target.supports(TargetCpu::Sse42) => {
            Some(Host::GreaterQword)
        }
        (ElementSize::Doubleword, true) => {
            equal_doublewords(code, left, right);
            None
        }
        (ElementSize::Doubleword, false) => {
            greater_doublewords(code, left, right);
            None
        }
        (ElementSize::Quadword, _) => unreachable!("validated comparison element size"),
    };
    if let Some(opcode) = opcode {
        opcode.register(code, left, right, target);
    }
    Ok((left, invert))
}

/// Compare staged XMM0/XMM1 lanes and return the XMM register holding FF/00 lanes.
/// Clobbers XMM0..XMM4; preserves all GPRs, host flags and MXCSR. Callers that
/// select source values must preserve their originals outside this scratch set.
pub(crate) fn emit_compare_mask(
    code: &mut Vec<u8>,
    relation: Relation,
    unsigned: bool,
    size: ElementSize,
    target: TargetCpu,
) -> Result<u8, ()> {
    let (result, invert) = compare_lanes(code, relation, unsigned, size, target)?;
    if invert {
        Host::EqualDword.register(code, XMM_BIAS, XMM_BIAS, TargetCpu::Baseline);
        Host::Xor.register(code, result, XMM_BIAS, TargetCpu::Baseline);
    }
    Ok(result)
}

/// Compare staged XMM0/XMM1 lanes and return sixteen truth-byte bits in EAX.
/// Clobbers XMM0..XMM4, EAX and host flags; preserves RDI/R15 and host MXCSR.
/// Governing masks, packed lane-start bits, NZCV and state commits belong to the
/// outer instruction emitter. Immediate/wide operands must be prepared there.
pub(crate) fn emit_compare_chunk(
    code: &mut Vec<u8>,
    relation: Relation,
    unsigned: bool,
    size: ElementSize,
    target: TargetCpu,
) -> Result<(), ()> {
    let (result, invert) = compare_lanes(code, relation, unsigned, size, target)?;
    Host::ByteSignMask.register(code, 0, result, TargetCpu::Baseline);
    if invert {
        code.push(XOR_EAX_IMMEDIATE);
        code.extend_from_slice(&TRUTH_BYTE_MASK.to_le_bytes());
    }
    Ok(())
}

fn branch(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend_from_slice(opcode);
    let position = code.len();
    code.extend(0i32.to_le_bytes());
    position
}

fn finish_branch(code: &mut [u8], position: usize) {
    let displacement = (code.len() - position - size_of::<i32>()) as i32;
    code[position..position + size_of::<i32>()].copy_from_slice(&displacement.to_le_bytes());
}

fn splat_immediate(code: &mut Vec<u8>, value: i16, size: ElementSize) {
    if size == ElementSize::Doubleword {
        if value < 0 {
            code.extend_from_slice(MOV_RAX_SIGNED_IMMEDIATE);
            code.extend(i32::from(value).to_le_bytes());
        } else {
            code.push(MOV_EAX_IMMEDIATE);
            code.extend((value as u32).to_le_bytes());
        }
        register_fields(code, MOVQ_XMM_RAX, XMM_IMMEDIATE, 0);
        Host::UnpackLowQword.register(code, XMM_IMMEDIATE, XMM_IMMEDIATE, TargetCpu::Baseline);
    } else {
        let bits = match size {
            ElementSize::Byte => u32::from(value as u8) * REPEAT_BYTE_IN_DWORD,
            ElementSize::Halfword => u32::from(value as u16) * REPEAT_HALFWORD_IN_DWORD,
            ElementSize::Word => value as u32,
            _ => unreachable!("decoded comparison element size"),
        };
        code.push(MOV_EAX_IMMEDIATE);
        code.extend(bits.to_le_bytes());
        register_fields(code, MOVD_XMM_EAX, XMM_IMMEDIATE, 0);
        shuffle(code, XMM_IMMEDIATE, XMM_IMMEDIATE, 0);
    }
}

fn load_result_chunk(code: &mut Vec<u8>, chunk: usize, predicate_bytes: usize) {
    let offset = chunk * QWORD_BYTES;
    code.extend_from_slice(match (predicate_bytes - offset).min(QWORD_BYTES) {
        2 => LOAD_STACK_WORD_EAX,
        4 => LOAD_STACK_EAX,
        8 => LOAD_STACK_RAX,
        _ => unreachable!("validated packed predicate chunk size"),
    });
    code.push(offset as u8);
}

fn accumulate_predtest(code: &mut Vec<u8>) {
    // RDX is the effective governing64-bit mask; RAX is the governed result.
    // R9 holds N plus a first-active-seen marker, R10 any result and R11 !last.
    code.extend_from_slice(OR_R10_RAX);
    code.extend_from_slice(TEST_RDX_RDX);
    let empty = branch(code, JZ_REL32);
    code.extend_from_slice(TEST_R9D_IMMEDIATE);
    code.extend(FIRST_ACTIVE_SEEN.to_le_bytes());
    let seen = branch(code, JNZ_REL32);
    code.extend_from_slice(BSF_RCX_RDX);
    code.extend_from_slice(BT_RAX_RCX);
    code.extend_from_slice(SETC_CL);
    code.extend_from_slice(MOVZX_ECX_CL);
    code.extend_from_slice(SHL_ECX);
    code.push(NZCV_N_SHIFT);
    code.extend_from_slice(OR_R9D_ECX);
    code.extend_from_slice(OR_R9D_ONE);
    finish_branch(code, seen);
    code.extend_from_slice(BSR_RCX_RDX);
    code.extend_from_slice(BT_RAX_RCX);
    code.extend_from_slice(SETNC_R11B);
    finish_branch(code, empty);
}

/// Comparison results are staged on the stack until every governing bit and
/// PredTest input is consumed, so Pd == Pg sees the original predicate
/// throughout.
pub(crate) fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    use crate::x86_64::scalable::{load_z_chunk, read_predicate_chunk, write_predicate_chunk};
    let single_chunk = length.chunks() == 1;
    if !single_chunk {
        code.extend_from_slice(SUB_RSP_IMMEDIATE);
        code.push(PREDICATE_RESULT_STACK_BYTES);
    }
    code.extend_from_slice(XOR_R9D_R9D);
    code.extend_from_slice(XOR_R10D_R10D);
    code.extend_from_slice(MOV_R11D_IMMEDIATE);
    code.extend(INITIAL_CARRY.to_le_bytes());
    if let Right::Immediate(value) = operand.right {
        splat_immediate(code, value, operand.element_size);
    }
    let leading: u32 = (0..PREDICATE_BITS_PER_VECTOR_CHUNK)
        .step_by(operand.element_size.bytes())
        .map(|bit| 1 << bit)
        .sum();
    for chunk in 0..length.chunks() {
        match operand.right {
            Right::WideVector(right) => {
                wide::emit_chunk(code, operand, right, chunk, length, target);
            }
            Right::Vector(right) => {
                load_z_chunk(code, operand.left, chunk, XMM_LEFT, length, target);
                load_z_chunk(code, right, chunk, XMM_RIGHT, length, target);
                emit_compare_chunk(
                    code,
                    operand.relation,
                    operand.unsigned,
                    operand.element_size,
                    target,
                )
                .expect("decoded comparison element size");
            }
            Right::Immediate(_) => {
                load_z_chunk(code, operand.left, chunk, XMM_LEFT, length, target);
                Host::MoveAligned.register(code, XMM_RIGHT, XMM_IMMEDIATE, TargetCpu::Baseline);
                emit_compare_chunk(
                    code,
                    operand.relation,
                    operand.unsigned,
                    operand.element_size,
                    target,
                )
                .expect("decoded comparison element size");
            }
        }
        code.extend_from_slice(MOV_R8D_EAX);
        read_predicate_chunk(
            code,
            operand.governing,
            chunk / VECTOR_CHUNKS_PER_PREDICATE_QWORD,
            length,
        );
        let shift = (chunk % VECTOR_CHUNKS_PER_PREDICATE_QWORD) * PREDICATE_BITS_PER_VECTOR_CHUNK;
        if shift != 0 {
            code.extend_from_slice(SHR_RAX);
            code.push(shift as u8);
        }
        code.push(AND_EAX_IMMEDIATE);
        code.extend(leading.to_le_bytes());
        code.extend_from_slice(MOV_EDX_EAX);
        code.extend_from_slice(MOV_EAX_R8D);
        code.extend_from_slice(AND_EAX_EDX);
        if single_chunk {
            code.extend_from_slice(MOV_R8D_EAX);
            accumulate_predtest(code);
        } else {
            code.extend_from_slice(STORE_STACK_AX);
            code.push((chunk * PREDICATE_RESULT_CHUNK_BYTES) as u8);
        }
    }
    if !single_chunk {
        let packed_leading: u64 = (0..QWORD_BYTES * BYTE_BITS as usize)
            .step_by(operand.element_size.bytes())
            .map(|bit| 1u64 << bit)
            .sum();
        for chunk in 0..length.predicate_bytes().div_ceil(QWORD_BYTES) {
            read_predicate_chunk(code, operand.governing, chunk, length);
            code.extend_from_slice(MOV_RDX_RAX);
            code.extend_from_slice(MOVABS_RCX_IMMEDIATE);
            code.extend(packed_leading.to_le_bytes());
            code.extend_from_slice(AND_RDX_RCX);
            load_result_chunk(code, chunk, length.predicate_bytes());
            accumulate_predtest(code);
        }
    }
    code.extend_from_slice(TEST_R10_R10);
    code.extend_from_slice(SETZ_AL);
    code.extend_from_slice(MOVZX_EAX_AL);
    code.extend_from_slice(SHL_EAX);
    code.push(NZCV_Z_SHIFT);
    code.extend_from_slice(AND_R9D_IMMEDIATE);
    code.extend((1u32 << NZCV_N_SHIFT).to_le_bytes());
    code.extend_from_slice(SHL_R11D);
    code.push(NZCV_C_SHIFT);
    code.extend_from_slice(OR_EAX_R9D);
    code.extend_from_slice(OR_EAX_R11D);
    code.extend_from_slice(STORE_STATE_EAX);
    code.extend((core::mem::offset_of!(crate::GuestState, nzcv) as u32).to_le_bytes());
    for chunk in 0..length.predicate_bytes().div_ceil(QWORD_BYTES) {
        if single_chunk {
            code.extend_from_slice(MOV_EAX_R8D);
        } else {
            load_result_chunk(code, chunk, length.predicate_bytes());
        }
        write_predicate_chunk(code, operand.destination, chunk, length);
    }
    if !single_chunk {
        code.extend_from_slice(ADD_RSP_IMMEDIATE);
        code.push(PREDICATE_RESULT_STACK_BYTES);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn optional_doubleword_opcodes_require_exact_tier() {
        for (relation, required, optional) in [
            (
                Relation::Equal,
                TargetCpu::Sse41,
                Host::EqualQword.encoding(),
            ),
            (
                Relation::Greater,
                TargetCpu::Sse42,
                Host::GreaterQword.encoding(),
            ),
        ] {
            let mut baseline = Vec::new();
            emit_compare_chunk(
                &mut baseline,
                relation,
                false,
                ElementSize::Doubleword,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert!(
                !baseline
                    .windows(optional.len())
                    .any(|bytes| bytes == optional)
            );
            let mut checked = Vec::new();
            emit_compare_chunk(
                &mut checked,
                relation,
                false,
                ElementSize::Doubleword,
                required,
            )
            .unwrap();
            assert!(
                checked
                    .windows(optional.len())
                    .any(|bytes| bytes == optional)
            );
            assert!(checked.len() < baseline.len());
        }
    }

    #[test]
    fn reserved_element_width_does_not_emit_prefix() {
        let mut code = vec![0x90];
        assert_eq!(
            emit_compare_chunk(
                &mut code,
                Relation::Equal,
                false,
                ElementSize::Quadword,
                TargetCpu::Sse42
            ),
            Err(())
        );
        assert_eq!(code, [0x90]);
    }
}
