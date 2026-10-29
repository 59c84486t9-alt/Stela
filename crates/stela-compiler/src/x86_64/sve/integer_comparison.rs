//! SVE integer comparisons into predicates.
use crate::TargetCpu;
use crate::aarch64::Unsupported;
use crate::aarch64::scalable::{ElementSize, VectorLength};
use crate::aarch64::sve::integer_comparison::{Operand, Relation, Right};
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdi, Rdx, Rsp};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, Rm, ShiftOp, Size};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};

const XMM_LEFT: u8 = 0;
const XMM_RIGHT: u8 = 1;
const XMM_HIGH_GREATER: u8 = 2;
const XMM_HIGH_EQUAL: u8 = 3;
const XMM_BIAS: u8 = 4;
const REPEAT_BYTE_IN_DWORD: u32 = 0x0101_0101;
const REPEAT_HALFWORD_IN_DWORD: u32 = 0x0001_0001;
const XMM_CHUNK_BYTES: usize = 16;
const BYTE_SIGN_SHIFT: u8 = 7;
const HALFWORD_SIGN_SHIFT: u8 = 15;
const WORD_SIGN_SHIFT: u8 = 31;
const DOUBLEWORD_SIGN_SHIFT: u8 = 63;
const REPLICATE_HIGH_WORDS: u8 = 0xf5;
const REPLICATE_LOW_WORDS: u8 = 0xa0;
const SWAP_ADJACENT_WORDS: u8 = 0xb1;
const TRUTH_BYTE_MASK: u32 = 0xffff;

const PREDICATE_RESULT_STACK_BYTES: u8 = 32;
const PREDICATE_BITS_PER_VECTOR_CHUNK: usize = 16;
const VECTOR_CHUNKS_PER_PREDICATE_QWORD: usize = 4;
const PREDICATE_RESULT_CHUNK_BYTES: usize = 2;
const QWORD_BYTES: usize = 8;
const BYTE_BITS: u8 = 8;
const NZCV_N_SHIFT: u8 = 31;
const NZCV_Z_SHIFT: u8 = 30;
const NZCV_C_SHIFT: u8 = 29;
const FIRST_ACTIVE_SEEN: u32 = 1;
const INITIAL_CARRY: u32 = 1;
const XMM_IMMEDIATE: u8 = 5;

mod wide;

fn shuffle(code: &mut Code, destination: u8, source: u8, control: u8) {
    code.asm().simd_imm(
        Host::ShuffleDword,
        destination,
        Rm::Xmm(source),
        control,
        TargetCpu::Baseline,
    );
}

fn sign_bias(code: &mut Code, size: ElementSize) {
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

fn equal_doublewords(code: &mut Code, left: u8, right: u8) {
    Host::EqualDword.register(code, left, right, TargetCpu::Baseline);
    shuffle(code, XMM_HIGH_GREATER, left, SWAP_ADJACENT_WORDS);
    Host::And.register(code, left, XMM_HIGH_GREATER, TargetCpu::Baseline);
}

fn greater_doublewords(code: &mut Code, left: u8, right: u8) {
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
    code: &mut Code,
    relation: Relation,
    unsigned: bool,
    size: ElementSize,
    target: TargetCpu,
) -> Result<(u8, bool), Unsupported> {
    if size == ElementSize::Quadword {
        return Err(Unsupported);
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
    code: &mut Code,
    relation: Relation,
    unsigned: bool,
    size: ElementSize,
    target: TargetCpu,
) -> Result<u8, Unsupported> {
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
    code: &mut Code,
    relation: Relation,
    unsigned: bool,
    size: ElementSize,
    target: TargetCpu,
) -> Result<(), Unsupported> {
    let (result, invert) = compare_lanes(code, relation, unsigned, size, target)?;
    Host::ByteSignMask.register(code, 0, result, TargetCpu::Baseline);
    if invert {
        code.asm()
            .alu_accumulator_imm32(Alu::Xor, Size::Dword, TRUTH_BYTE_MASK as i32);
    }
    Ok(())
}

fn splat_immediate(code: &mut Code, value: i16, size: ElementSize) {
    if size == ElementSize::Doubleword {
        if value < 0 {
            code.asm().mov_rm_imm32(Size::Qword, Rax, i32::from(value));
        } else {
            code.asm().mov_imm32(Rax, value as u32);
        }
        code.asm().movq_to_xmm(XMM_IMMEDIATE, Rax);
        Host::UnpackLowQword.register(code, XMM_IMMEDIATE, XMM_IMMEDIATE, TargetCpu::Baseline);
    } else {
        let bits = match size {
            ElementSize::Byte => u32::from(value as u8) * REPEAT_BYTE_IN_DWORD,
            ElementSize::Halfword => u32::from(value as u16) * REPEAT_HALFWORD_IN_DWORD,
            ElementSize::Word => value as u32,
            _ => unreachable!("decoded comparison element size"),
        };
        code.asm().mov_imm32(Rax, bits);
        code.asm().movd_to_xmm(XMM_IMMEDIATE, Rax);
        shuffle(code, XMM_IMMEDIATE, XMM_IMMEDIATE, 0);
    }
}

fn load_result_chunk(code: &mut Code, chunk: usize, predicate_bytes: usize) {
    let offset = chunk * QWORD_BYTES;
    let source = Mem::base_disp8(Rsp, offset as i8);
    let mut asm = code.asm();
    match (predicate_bytes - offset).min(QWORD_BYTES) {
        2 => asm.movzx(Size::Dword, Rax, Size::Word, source),
        4 => asm.mov_load(Size::Dword, Rax, source),
        8 => asm.mov_load(Size::Qword, Rax, source),
        _ => unreachable!("validated packed predicate chunk size"),
    }
}

fn accumulate_predtest(code: &mut Code) {
    // RDX is the effective governing64-bit mask; RAX is the governed result.
    // R9 holds N plus a first-active-seen marker, R10 any result and R11 !last.
    let mut asm = code.asm();
    asm.alu(Alu::Or, Size::Qword, R10, Rax);
    asm.test(Size::Qword, Rdx, Rdx);
    let empty = asm.jcc(Cond::E);
    asm.test_imm(Size::Dword, R9, FIRST_ACTIVE_SEEN as i32);
    let seen = asm.jcc(Cond::Ne);
    asm.bsf(Size::Qword, Rcx, Rdx);
    asm.bit(BitTest::Bt, Size::Qword, Rax, Rcx);
    asm.setcc(Cond::B, Rcx);
    asm.movzx(Size::Dword, Rcx, Size::Byte, Rcx);
    asm.shift_imm(ShiftOp::Shl, Size::Dword, Rcx, NZCV_N_SHIFT);
    asm.alu(Alu::Or, Size::Dword, R9, Rcx);
    asm.alu_imm8(Alu::Or, Size::Dword, R9, 1);
    asm.bind(seen);
    asm.bsr(Size::Qword, Rcx, Rdx);
    asm.bit(BitTest::Bt, Size::Qword, Rax, Rcx);
    asm.setcc(Cond::Ae, R11);
    asm.bind(empty);
}

/// Comparison results are staged on the stack until every governing bit and
/// PredTest input is consumed, so Pd == Pg sees the original predicate
/// throughout.
pub(crate) fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
    use crate::x86_64::scalable::{load_z_chunk, read_predicate_chunk, write_predicate_chunk};
    let single_chunk = length.chunks() == 1;
    if !single_chunk {
        code.asm().alu_imm8(
            Alu::Sub,
            Size::Qword,
            Rsp,
            PREDICATE_RESULT_STACK_BYTES as i8,
        );
    }
    let mut asm = code.asm();
    asm.alu(Alu::Xor, Size::Dword, R9, R9);
    asm.alu(Alu::Xor, Size::Dword, R10, R10);
    asm.mov_imm32(R11, INITIAL_CARRY);
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
        code.asm().mov(Size::Dword, R8, Rax);
        read_predicate_chunk(
            code,
            operand.governing,
            chunk / VECTOR_CHUNKS_PER_PREDICATE_QWORD,
            length,
        );
        let shift = (chunk % VECTOR_CHUNKS_PER_PREDICATE_QWORD) * PREDICATE_BITS_PER_VECTOR_CHUNK;
        if shift != 0 {
            code.asm()
                .shift_imm(ShiftOp::Shr, Size::Qword, Rax, shift as u8);
        }
        let mut asm = code.asm();
        asm.alu_accumulator_imm32(Alu::And, Size::Dword, leading as i32);
        asm.mov(Size::Dword, Rdx, Rax);
        asm.mov(Size::Dword, Rax, R8);
        asm.alu(Alu::And, Size::Dword, Rax, Rdx);
        if single_chunk {
            code.asm().mov(Size::Dword, R8, Rax);
            accumulate_predtest(code);
        } else {
            code.asm().mov_store(
                Size::Word,
                Mem::base_disp8(Rsp, (chunk * PREDICATE_RESULT_CHUNK_BYTES) as i8),
                Rax,
            );
        }
    }
    if !single_chunk {
        let packed_leading: u64 = (0..QWORD_BYTES * BYTE_BITS as usize)
            .step_by(operand.element_size.bytes())
            .map(|bit| 1u64 << bit)
            .sum();
        for chunk in 0..length.predicate_bytes().div_ceil(QWORD_BYTES) {
            read_predicate_chunk(code, operand.governing, chunk, length);
            let mut asm = code.asm();
            asm.mov(Size::Qword, Rdx, Rax);
            asm.mov_imm64(Rcx, packed_leading);
            asm.alu(Alu::And, Size::Qword, Rdx, Rcx);
            load_result_chunk(code, chunk, length.predicate_bytes());
            accumulate_predtest(code);
        }
    }
    let mut asm = code.asm();
    asm.test(Size::Qword, R10, R10);
    asm.setcc(Cond::E, Rax);
    asm.movzx(Size::Dword, Rax, Size::Byte, Rax);
    asm.shift_imm(ShiftOp::Shl, Size::Dword, Rax, NZCV_Z_SHIFT);
    asm.alu_imm32(Alu::And, Size::Dword, R9, (1u32 << NZCV_N_SHIFT) as i32);
    asm.shift_imm(ShiftOp::Shl, Size::Dword, R11, NZCV_C_SHIFT);
    asm.alu(Alu::Or, Size::Dword, Rax, R9);
    asm.alu(Alu::Or, Size::Dword, Rax, R11);
    asm.mov_store(
        Size::Dword,
        Mem::base_disp32(Rdi, (core::mem::offset_of!(crate::GuestState, nzcv)) as i32),
        Rax,
    );
    for chunk in 0..length.predicate_bytes().div_ceil(QWORD_BYTES) {
        if single_chunk {
            code.asm().mov(Size::Dword, Rax, R8);
        } else {
            load_result_chunk(code, chunk, length.predicate_bytes());
        }
        write_predicate_chunk(code, operand.destination, chunk, length);
    }
    if !single_chunk {
        code.asm().alu_imm8(
            Alu::Add,
            Size::Qword,
            Rsp,
            PREDICATE_RESULT_STACK_BYTES as i8,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let mut baseline = Code::new();
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
            let mut checked = Code::new();
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
        let mut code = Code::new();
        code.asm().nop();
        assert_eq!(
            emit_compare_chunk(
                &mut code,
                Relation::Equal,
                false,
                ElementSize::Quadword,
                TargetCpu::Sse42
            ),
            Err(Unsupported)
        );
        assert_eq!(code, [0x90]);
    }
}
