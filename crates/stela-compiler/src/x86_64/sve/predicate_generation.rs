//! Packed predicate generation with checked scalar BMI1 recipes; no guest RAM access.
use super::predicate;
use crate::{
    GuestState, TargetCpu,
    aarch64::{
        Register, Shift, Width,
        scalable::{ElementSize, MAX_VECTOR_BYTES, VectorLength},
        sve::predicate_generation::{BasicOperand, Destination, Operand},
    },
    x86_64::{
        load, right_operand,
        scalable::{read_predicate_chunk, write_predicate_chunk, zero_predicate},
    },
};

const CHUNK_BITS: usize = u64::BITS as usize;
const CHUNK_BYTES: usize = std::mem::size_of::<u64>();
const REL32_BYTES: usize = std::mem::size_of::<i32>();
const NZCV_OFFSET: u32 = std::mem::offset_of!(GuestState, nzcv) as u32;
const N_FLAG: u32 = 1 << 31;
const Z_FLAG: u32 = 1 << 30;
const C_FLAG: u32 = 1 << 29;
const V_FLAG: u32 = 1 << 28;
const COUNTER_INVERT_BIT: u64 = 1 << 15;
const MOV_EAX_IMM32: u8 = 0xb8;
const MOV_RAX_SIGN_EXTENDED_IMM32: &[u8] = &[0x48, 0xc7, 0xc0];
const PATTERN_POW2: u8 = 0;
const PATTERN_MUL4: u8 = 29;
const PATTERN_MUL3: u8 = 30;
const PATTERN_ALL: u8 = 31;
const MOVABS_RAX: &[u8] = &[0x48, 0xb8];
const MOVABS_R11: &[u8] = &[0x49, 0xbb];
const MOV_R11_RAX: &[u8] = &[0x49, 0x89, 0xc3];
const MOV_R9_R11: &[u8] = &[0x4d, 0x89, 0xd9];
const BLSI_R9_R11: &[u8] = &[0xc4, 0xc2, 0xb0, 0xf3, 0xdb];
const NEG_R9: &[u8] = &[0x49, 0xf7, 0xd9];
const AND_R9_R11: &[u8] = &[0x4d, 0x21, 0xd9];
const AND_R9_R10: &[u8] = &[0x4d, 0x21, 0xd1];
const CMP_R11_ONE: &[u8] = &[0x49, 0x83, 0xfb, 1];
const SBB_RCX_RCX: &[u8] = &[0x48, 0x19, 0xc9];
const AND_R10_RCX: &[u8] = &[0x49, 0x21, 0xca];
const OR_RAX_R9: &[u8] = &[0x4c, 0x09, 0xc8];
const ALL_R10: &[u8] = &[0x49, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff];
const ALL_R9: &[u8] = &[0x49, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff];
const AND_RAX_R11: &[u8] = &[0x4c, 0x21, 0xd8];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const TEST_RAX_RAX: &[u8] = &[0x48, 0x85, 0xc0];
const BSR_RCX_RAX: &[u8] = &[0x48, 0x0f, 0xbd, 0xc8];
const LEA_R10D_RCX_DISP32: &[u8] = &[0x44, 0x8d, 0x91];
const CMP_R10D_IMM32: &[u8] = &[0x41, 0x81, 0xfa];
const MOV_ECX_R10D: &[u8] = &[0x44, 0x89, 0xd1];
const SUB_ECX_IMM32: &[u8] = &[0x81, 0xe9];
const SHL_R11_CL: &[u8] = &[0x49, 0xd3, 0xe3];
const NEG_R11: &[u8] = &[0x49, 0xf7, 0xdb];
const AND_RAX_R9: &[u8] = &[0x4c, 0x21, 0xc8];
const CMP_RAX_ONE: &[u8] = &[0x48, 0x83, 0xf8, 1];
const AND_R9_RCX: &[u8] = &[0x49, 0x21, 0xc9];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const MOV_STATE_IMM32: &[u8] = &[0xc7, 0x87];
const MOV_STATE_EAX: &[u8] = &[0x89, 0x87];
const MOV_EDX_STATE: &[u8] = &[0x8b, 0x97];
const CMP_RAX_RCX: &[u8] = &[0x48, 0x39, 0xc8];
const CMP_EAX_ECX: &[u8] = &[0x39, 0xc8];
const SETE_AL: &[u8] = &[0x0f, 0x94, 0xc0];
const SETNE_AL: &[u8] = &[0x0f, 0x95, 0xc0];
const MOVZX_EAX_AL: &[u8] = &[0x0f, 0xb6, 0xc0];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const XOR_ECX_ONE: &[u8] = &[0x83, 0xf1, 1];
const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
const SHL_ECX_IMM8: &[u8] = &[0xc1, 0xe1];
const AND_EDX_IMM32: &[u8] = &[0x81, 0xe2];
const OR_EAX_EDX: &[u8] = &[0x09, 0xd0];
const MOV_R11D_EDX: &[u8] = &[0x41, 0x89, 0xd3];
const SHR_R11D_IMM8: &[u8] = &[0x41, 0xc1, 0xeb];
const XOR_R11D_ONE: &[u8] = &[0x41, 0x83, 0xf3, 1];
const AND_ECX_R11D: &[u8] = &[0x44, 0x21, 0xd9];
const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];
const MOVQ_XMM_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e];
const MOVQ_RAX_XMM: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const AND_R11D_ONE: &[u8] = &[0x41, 0x83, 0xe3, 1];
const JZ: &[u8] = &[0x0f, 0x84];
const JBE: &[u8] = &[0x0f, 0x86];
const JAE: &[u8] = &[0x0f, 0x83];
const JMP: &[u8] = &[0xe9];

pub(crate) fn emit(code: &mut Vec<u8>, operand: &Operand, length: VectorLength, target: TargetCpu) {
    match operand {
        Operand::Basic(basic) => emit_basic(code, basic, length, target),
        Operand::Break(operand) => breaks::emit_break(code, *operand, length, target),
        Operand::While(operand) => whiles::emit_while(code, operand, length, write_counted),
    }
}

fn chunks(length: VectorLength) -> usize {
    length.predicate_bytes().div_ceil(CHUNK_BYTES)
}
fn constant(code: &mut Vec<u8>, value: u64) {
    if value == 0 {
        code.extend(XOR_EAX_EAX);
    } else if let Ok(value) = u32::try_from(value) {
        code.push(MOV_EAX_IMM32);
        code.extend(value.to_le_bytes());
    } else if let Ok(value) = i32::try_from(value as i64) {
        code.extend(MOV_RAX_SIGN_EXTENDED_IMM32);
        code.extend(value.to_le_bytes());
    } else {
        code.extend(MOVABS_RAX);
        code.extend(value.to_le_bytes());
    }
}
fn marker_mask(element: ElementSize) -> u64 {
    predicate::leading_bits(element)
}
fn stage(code: &mut Vec<u8>, xmm: u8) {
    assert!(xmm < 8);
    code.extend(MOVQ_XMM_RAX);
    code.push(MODRM_REGISTER | xmm << MODRM_REGISTER_SHIFT);
}
fn restore(code: &mut Vec<u8>, xmm: u8) {
    assert!(xmm < 8);
    code.extend(MOVQ_RAX_XMM);
    code.push(MODRM_REGISTER | xmm << MODRM_REGISTER_SHIFT);
}
fn restore_guard(code: &mut Vec<u8>, xmm: u8) {
    restore(code, xmm);
    code.extend(MOV_R11_RAX);
}
fn jump(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let at = code.len();
    code.extend([0; REL32_BYTES]);
    at
}
fn bind(code: &mut [u8], at: usize) {
    let displacement = i32::try_from(code.len() - at - REL32_BYTES).unwrap();
    code[at..at + REL32_BYTES].copy_from_slice(&displacement.to_le_bytes());
}
fn commit_staged(code: &mut Vec<u8>, destination: u8, length: VectorLength) {
    for chunk in 0..chunks(length) {
        restore(code, chunk as u8);
        write_predicate_chunk(code, destination, chunk, length);
    }
}
fn test_staged(code: &mut Vec<u8>, element: ElementSize, length: VectorLength) {
    predicate::begin_predtest(code);
    for chunk in 0..chunks(length) {
        restore_guard(code, 4 + chunk as u8);
        restore(code, chunk as u8);
        predicate::accumulate_predtest(code, element);
    }
    predicate::finish_predtest(code);
}
fn immediate_flags(code: &mut Vec<u8>, flags: u32) {
    code.extend(MOV_STATE_IMM32);
    code.extend(NZCV_OFFSET.to_le_bytes());
    code.extend(flags.to_le_bytes());
}
fn pattern_count(pattern: u8, elements: usize) -> usize {
    let count = match pattern {
        PATTERN_POW2 => 1 << elements.ilog2(),
        1..=8 => usize::from(pattern),
        9..=13 => 1 << (pattern - 5),
        PATTERN_MUL4 => elements / 4 * 4,
        PATTERN_MUL3 => elements / 3 * 3,
        PATTERN_ALL => elements,
        _ => 0,
    };
    if count <= elements { count } else { 0 }
}
fn emit_basic(code: &mut Vec<u8>, operand: &BasicOperand, length: VectorLength, target: TargetCpu) {
    match *operand {
        BasicOperand::False { destination } => zero_predicate(code, destination, length),
        BasicOperand::True {
            destination,
            element,
            pattern,
            set_flags,
        } => {
            let count = pattern_count(pattern, length.lanes(element));
            for chunk in 0..chunks(length) {
                let value = (0..count)
                    .map(|lane| lane * element.bytes())
                    .filter(|bit| bit / CHUNK_BITS == chunk)
                    .fold(0, |mask, bit| mask | (1u64 << (bit % CHUNK_BITS)));
                constant(code, value);
                write_predicate_chunk(code, destination, chunk, length);
            }
            if set_flags {
                immediate_flags(code, if count == 0 { Z_FLAG | C_FLAG } else { N_FLAG });
            }
        }
        BasicOperand::TrueCounter {
            destination,
            element,
        } => {
            if chunks(length) > 1 {
                zero_predicate(code, destination, length);
            }
            constant(code, COUNTER_INVERT_BIT | element.bytes() as u64);
            write_predicate_chunk(code, destination, 0, length);
        }
        BasicOperand::Test { governing, source } => {
            predicate::begin_predtest(code);
            for chunk in 0..chunks(length) {
                read_predicate_chunk(code, governing, chunk, length);
                code.extend(MOV_R11_RAX);
                read_predicate_chunk(code, source, chunk, length);
                predicate::accumulate_predtest(code, ElementSize::Byte);
            }
            predicate::finish_predtest(code);
        }
        BasicOperand::First {
            destination,
            governing,
        } => emit_first(code, destination, governing, length, target),
        BasicOperand::Next {
            destination,
            governing,
            element,
        } => emit_next(code, destination, governing, element, length),
        BasicOperand::ConditionalTerminate {
            first,
            second,
            width,
            equal,
        } => emit_terminate(code, first, second, width, equal),
    }
}
fn emit_first(
    code: &mut Vec<u8>,
    destination: u8,
    governing: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    code.extend(ALL_R10);
    for chunk in 0..chunks(length) {
        read_predicate_chunk(code, governing, chunk, length);
        stage(code, 4 + chunk as u8);
        code.extend(MOV_R11_RAX);
        // Shorter profiles retain the baseline recipe: some measured short
        // cohorts regressed with BMI1, while the maximum profile improved.
        if target.supports(TargetCpu::Bmi1) && length.bytes() == MAX_VECTOR_BYTES {
            code.extend(BLSI_R9_R11);
        } else {
            code.extend(MOV_R9_R11);
            code.extend(NEG_R9);
            code.extend(AND_R9_R11);
        }
        code.extend(AND_R9_R10);
        code.extend(CMP_R11_ONE);
        code.extend(SBB_RCX_RCX);
        code.extend(AND_R10_RCX);
        read_predicate_chunk(code, destination, chunk, length);
        code.extend(OR_RAX_R9);
        stage(code, chunk as u8);
    }
    commit_staged(code, destination, length);
    test_staged(code, ElementSize::Byte, length);
}
fn emit_next(
    code: &mut Vec<u8>,
    destination: u8,
    governing: u8,
    element: ElementSize,
    length: VectorLength,
) {
    code.extend(XOR_R10D_R10D);
    for chunk in 0..chunks(length) {
        read_predicate_chunk(code, governing, chunk, length);
        stage(code, 4 + chunk as u8);
        read_predicate_chunk(code, destination, chunk, length);
        code.extend(MOVABS_R11);
        code.extend(marker_mask(element).to_le_bytes());
        code.extend(AND_RAX_R11);
        code.extend(TEST_RAX_RAX);
        let empty = jump(code, JZ);
        code.extend(BSR_RCX_RAX);
        code.extend(LEA_R10D_RCX_DISP32);
        code.extend(((chunk * CHUNK_BITS + element.bytes()) as u32).to_le_bytes());
        bind(code, empty);
    }
    code.extend(ALL_R9);
    for chunk in 0..chunks(length) {
        restore(code, 4 + chunk as u8);
        code.extend(MOVABS_R11);
        code.extend(marker_mask(element).to_le_bytes());
        code.extend(AND_RAX_R11);
        code.extend(CMP_R10D_IMM32);
        code.extend(((chunk * CHUNK_BITS) as u32).to_le_bytes());
        let keep = jump(code, JBE);
        code.extend(CMP_R10D_IMM32);
        code.extend((((chunk + 1) * CHUNK_BITS) as u32).to_le_bytes());
        let empty = jump(code, JAE);
        code.extend(MOV_ECX_R10D);
        code.extend(SUB_ECX_IMM32);
        code.extend(((chunk * CHUNK_BITS) as u32).to_le_bytes());
        code.extend(MOVABS_R11);
        code.extend(u64::MAX.to_le_bytes());
        code.extend(SHL_R11_CL);
        code.extend(AND_RAX_R11);
        bind(code, keep);
        code.extend(MOV_R11_RAX);
        code.extend(NEG_R11);
        code.extend(AND_RAX_R11);
        code.extend(AND_RAX_R9);
        code.extend(CMP_RAX_ONE);
        code.extend(SBB_RCX_RCX);
        code.extend(AND_R9_RCX);
        let ready = jump(code, JMP);
        bind(code, empty);
        code.extend(XOR_EAX_EAX);
        bind(code, ready);
        stage(code, chunk as u8);
    }
    commit_staged(code, destination, length);
    test_staged(code, element, length);
}
fn emit_terminate(
    code: &mut Vec<u8>,
    first: Register,
    second: Register,
    width: Width,
    equal: bool,
) {
    load(code, first);
    right_operand(code, second, width, Shift::Lsl, 0);
    code.extend(if width == Width::X64 {
        CMP_RAX_RCX
    } else {
        CMP_EAX_ECX
    });
    code.extend(if equal { SETE_AL } else { SETNE_AL });
    code.extend(MOVZX_EAX_AL);
    code.extend(MOV_ECX_EAX);
    code.extend(XOR_ECX_ONE);
    code.extend(SHL_EAX_IMM8);
    code.push(N_FLAG.trailing_zeros() as u8);
    code.extend(MOV_EDX_STATE);
    code.extend(NZCV_OFFSET.to_le_bytes());
    code.extend(AND_EDX_IMM32);
    code.extend((Z_FLAG | C_FLAG).to_le_bytes());
    code.extend(OR_EAX_EDX);
    code.extend(MOV_R11D_EDX);
    code.extend(SHR_R11D_IMM8);
    code.push(C_FLAG.trailing_zeros() as u8);
    // Z survives independently; isolate C before forming !C.
    code.extend(AND_R11D_ONE);
    code.extend(XOR_R11D_ONE);
    code.extend(AND_ECX_R11D);
    code.extend(SHL_ECX_IMM8);
    code.push(V_FLAG.trailing_zeros() as u8);
    code.extend(OR_EAX_ECX);
    code.extend(MOV_STATE_EAX);
    code.extend(NZCV_OFFSET.to_le_bytes());
}

const MOV_R9D_R8D: &[u8] = &[0x45, 0x89, 0xc1];
const MOV_R9D_IMM32: &[u8] = &[0x41, 0xb9];
const SUB_R9D_R8D: &[u8] = &[0x45, 0x29, 0xc1];
const SHL_R9D_IMM8: &[u8] = &[0x41, 0xc1, 0xe1];
const CMP_R9D_IMM32: &[u8] = &[0x41, 0x81, 0xf9];
const MOV_ECX_R9D: &[u8] = &[0x44, 0x89, 0xc9];
const SHL_RAX_CL: &[u8] = &[0x48, 0xd3, 0xe0];
const DEC_RAX: &[u8] = &[0x48, 0xff, 0xc8];
const NOT_RAX: &[u8] = &[0x48, 0xf7, 0xd0];

/// Emit a complete P/PP prefix or suffix from the clamped R8D element count.
/// R8 survives; packed physical chunks need not align to a pair's global64 bits.
fn write_counted(
    code: &mut Vec<u8>,
    destination: Destination,
    element: ElementSize,
    length: VectorLength,
    suffix: bool,
    capacity: u32,
) {
    let (first, vectors) = match destination {
        Destination::Predicate(register) => (register, 1),
        Destination::Pair(register) => (register, 2),
        Destination::Counter { .. } => unreachable!("counter uses architectural encoding"),
    };
    if suffix {
        code.extend(MOV_R9D_IMM32);
        code.extend(capacity.to_le_bytes());
        code.extend(SUB_R9D_R8D);
    } else {
        code.extend(MOV_R9D_R8D);
    }
    let shift = element.bytes().trailing_zeros() as u8;
    if shift != 0 {
        code.extend(SHL_R9D_IMM8);
        code.push(shift);
    }
    for vector in 0..vectors {
        for chunk in 0..chunks(length) {
            let start = vector * length.bytes() + chunk * CHUNK_BITS;
            let width = (length.bytes() - chunk * CHUNK_BITS).min(CHUNK_BITS);
            code.extend(CMP_R9D_IMM32);
            code.extend((start as u32).to_le_bytes());
            let low = jump(code, JBE);
            code.extend(CMP_R9D_IMM32);
            code.extend(((start + width) as u32).to_le_bytes());
            let high = jump(code, JAE);
            code.extend(MOV_ECX_R9D);
            code.extend(SUB_ECX_IMM32);
            code.extend((start as u32).to_le_bytes());
            constant(code, 1);
            code.extend(SHL_RAX_CL);
            code.extend(DEC_RAX);
            if suffix {
                code.extend(NOT_RAX);
            }
            let partial = jump(code, JMP);
            bind(code, low);
            constant(code, if suffix { u64::MAX } else { 0 });
            let low_ready = jump(code, JMP);
            bind(code, high);
            constant(code, if suffix { 0 } else { u64::MAX });
            bind(code, partial);
            bind(code, low_ready);
            code.extend(MOVABS_R11);
            code.extend(marker_mask(element).to_le_bytes());
            code.extend(AND_RAX_R11);
            write_predicate_chunk(code, first + vector as u8, chunk, length);
        }
    }
}

mod breaks {
    //! Packed predicate breaks with alias-safe SSE2 staging and checked BMI1 cores.
    //!
    //! Only packed P storage is read/written. RDI/R15 and the host stack survive.
    //! Results use XMM0..3; flagged non-Next forms keep original Pg in XMM4..7.
    use crate::aarch64::scalable::{ElementSize, VectorLength};
    use crate::aarch64::sve::predicate_generation::{Boundary, BreakKind, BreakOperand};
    use crate::x86_64::scalable::{read_predicate_chunk, write_predicate_chunk};
    use crate::x86_64::sve::predicate;

    use crate::TargetCpu;

    const BLSMSK_RAX_R9: &[u8] = &[0xc4, 0xc2, 0xf8, 0xf3, 0xd1];
    const BLSI_RAX_R9: &[u8] = &[0xc4, 0xc2, 0xf8, 0xf3, 0xd9];
    const DEC_RAX: &[u8] = &[0x48, 0xff, 0xc8];
    const QWORD_BYTES: usize = std::mem::size_of::<u64>();
    const BITS_PER_BYTE: usize = u8::BITS as usize;
    const ORIGINAL_GUARD_XMM_BASE: usize = 4;
    const MOV_R8_RAX: &[u8] = &[0x49, 0x89, 0xc0];
    const MOV_R9_RAX: &[u8] = &[0x49, 0x89, 0xc1];
    const MOV_R11_RAX: &[u8] = &[0x49, 0x89, 0xc3];
    const MOV_R11_R9: &[u8] = &[0x4d, 0x89, 0xcb];
    const MOV_R10_SIGN_EXTENDED_IMM32: &[u8] = &[0x49, 0xc7, 0xc2];
    const MOV_R11_SIGN_EXTENDED_IMM32: &[u8] = &[0x49, 0xc7, 0xc3];
    const MOVABS_R11_IMM64: &[u8] = &[0x49, 0xbb];
    const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
    const TEST_RAX_RAX: &[u8] = &[0x48, 0x85, 0xc0];
    const BSR_RCX_RAX: &[u8] = &[0x48, 0x0f, 0xbd, 0xc8];
    const BT_RAX_RCX: &[u8] = &[0x48, 0x0f, 0xa3, 0xc8];
    const SBB_R10_R10: &[u8] = &[0x4d, 0x19, 0xd2];
    const LEA_RAX_R9_MINUS_ONE: &[u8] = &[0x49, 0x8d, 0x41, 0xff];
    const XOR_RAX_R9: &[u8] = &[0x4c, 0x31, 0xc8];
    const NOT_R11: &[u8] = &[0x49, 0xf7, 0xd3];
    const NOT_R8: &[u8] = &[0x49, 0xf7, 0xd0];
    const AND_RAX_R11: &[u8] = &[0x4c, 0x21, 0xd8];
    const AND_RAX_R8: &[u8] = &[0x4c, 0x21, 0xc0];
    const AND_RAX_R10: &[u8] = &[0x4c, 0x21, 0xd0];
    const OR_RAX_R11: &[u8] = &[0x4c, 0x09, 0xd8];
    const CMP_R9_ONE: &[u8] = &[0x49, 0x83, 0xf9, 0x01];
    const SBB_R11_R11: &[u8] = &[0x4d, 0x19, 0xdb];
    const AND_R10_R11: &[u8] = &[0x4d, 0x21, 0xda];
    const MOVQ_XMM_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e];
    const MOVQ_RAX_XMM: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
    const MODRM_REGISTER: u8 = 0xc0;
    const MODRM_REGISTER_SHIFT: usize = 3;
    const JZ_REL32: &[u8] = &[0x0f, 0x84];
    const JMP_REL32: &[u8] = &[0xe9];
    const ALL_BITS: i32 = -1;

    fn stage(code: &mut Vec<u8>, xmm: usize) {
        code.extend(MOVQ_XMM_RAX);
        code.push(MODRM_REGISTER | (xmm << MODRM_REGISTER_SHIFT) as u8);
    }

    fn restore(code: &mut Vec<u8>, xmm: usize) {
        code.extend(MOVQ_RAX_XMM);
        code.push(MODRM_REGISTER | (xmm << MODRM_REGISTER_SHIFT) as u8);
    }

    fn jump(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
        code.extend(opcode);
        let displacement = code.len();
        code.extend(0_i32.to_le_bytes());
        displacement
    }

    fn patch(code: &mut [u8], displacement: usize, destination: usize) {
        let after = displacement + std::mem::size_of::<i32>();
        let relative = i32::try_from(destination as isize - after as isize)
            .expect("predicate-break local branch must fit rel32");
        code[displacement..after].copy_from_slice(&relative.to_le_bytes());
    }

    /// R10=-1 iff Pn at the last active Pg bit is one; otherwise R10=0.
    /// Read all selection inputs before any result is committed. BSR is never
    /// consumed on zero. Scalable storage reads preserve RCX and R10.
    fn last_active(code: &mut Vec<u8>, guard: u8, source: u8, length: VectorLength) {
        let chunks = length.predicate_bytes().div_ceil(QWORD_BYTES);
        code.extend(XOR_R10D_R10D);
        let mut completed = Vec::with_capacity(chunks);
        for chunk in (0..chunks).rev() {
            read_predicate_chunk(code, guard, chunk, length);
            code.extend(TEST_RAX_RAX);
            let absent = jump(code, JZ_REL32);
            code.extend(BSR_RCX_RAX);
            read_predicate_chunk(code, source, chunk, length);
            code.extend(BT_RAX_RCX);
            code.extend(SBB_R10_R10);
            completed.push(jump(code, JMP_REL32));
            let next = code.len();
            patch(code, absent, next);
        }
        let done = code.len();
        for displacement in completed {
            patch(code, displacement, done);
        }
    }

    fn all_chunk_bits(code: &mut Vec<u8>, chunk: usize, length: VectorLength) {
        let bytes = (length.predicate_bytes() - chunk * QWORD_BYTES).min(QWORD_BYTES);
        if bytes == QWORD_BYTES {
            code.extend(MOV_R11_SIGN_EXTENDED_IMM32);
            code.extend(ALL_BITS.to_le_bytes());
        } else {
            // Full physical tail width matters to BRKNS's C flag.
            let bits = bytes * BITS_PER_BYTE;
            code.extend(MOVABS_R11_IMM64);
            code.extend(((1_u64 << bits) - 1).to_le_bytes());
        }
    }

    pub(crate) fn emit_break(
        code: &mut Vec<u8>,
        operand: BreakOperand,
        length: VectorLength,
        target: TargetCpu,
    ) {
        let chunks = length.predicate_bytes().div_ceil(QWORD_BYTES);
        debug_assert!(chunks <= ORIGINAL_GUARD_XMM_BASE);
        let (boundary, merging, breaking) = match operand.kind {
            BreakKind::Break { boundary, merging } => {
                code.extend(MOV_R10_SIGN_EXTENDED_IMM32);
                code.extend(ALL_BITS.to_le_bytes());
                (Some(boundary), merging, operand.source)
            }
            BreakKind::Previous { boundary, source } => {
                last_active(code, operand.guard, operand.source, length);
                (Some(boundary), false, source)
            }
            BreakKind::Next => {
                last_active(code, operand.guard, operand.source, length);
                (None, false, operand.destination)
            }
        };
        for chunk in 0..chunks {
            if let Some(boundary) = boundary {
                read_predicate_chunk(code, operand.guard, chunk, length);
                if operand.set_flags {
                    stage(code, ORIGINAL_GUARD_XMM_BASE + chunk);
                }
                code.extend(MOV_R8_RAX);
                read_predicate_chunk(code, breaking, chunk, length);
                code.extend(AND_RAX_R8);
                code.extend(MOV_R9_RAX);
                match boundary {
                    Boundary::After if target.supports(TargetCpu::Bmi1) => {
                        code.extend(BLSMSK_RAX_R9)
                    }
                    Boundary::Before if target.supports(TargetCpu::Bmi1) => {
                        code.extend(BLSI_RAX_R9);
                        code.extend(DEC_RAX);
                    }
                    Boundary::After => {
                        code.extend(LEA_RAX_R9_MINUS_ONE);
                        code.extend(XOR_RAX_R9);
                    }
                    Boundary::Before => {
                        code.extend(LEA_RAX_R9_MINUS_ONE);
                        code.extend(MOV_R11_R9);
                        code.extend(NOT_R11);
                        code.extend(AND_RAX_R11);
                    }
                }
                code.extend(AND_RAX_R8);
                code.extend(AND_RAX_R10);
                if merging {
                    code.extend(MOV_R11_RAX);
                    read_predicate_chunk(code, operand.destination, chunk, length);
                    code.extend(NOT_R8);
                    code.extend(AND_RAX_R8);
                    code.extend(OR_RAX_R11);
                }
                stage(code, chunk);
                code.extend(CMP_R9_ONE);
                code.extend(SBB_R11_R11);
                code.extend(AND_R10_R11);
            } else {
                read_predicate_chunk(code, operand.destination, chunk, length);
                code.extend(AND_RAX_R10);
                stage(code, chunk);
            }
        }
        // Every input and alias has been consumed before the first write.
        for chunk in 0..chunks {
            restore(code, chunk);
            write_predicate_chunk(code, operand.destination, chunk, length);
        }
        if operand.set_flags {
            predicate::begin_predtest(code);
            for chunk in 0..chunks {
                if boundary.is_some() {
                    restore(code, ORIGINAL_GUARD_XMM_BASE + chunk);
                    code.extend(MOV_R11_RAX);
                } else {
                    all_chunk_bits(code, chunk, length);
                }
                restore(code, chunk);
                predicate::accumulate_predtest(code, ElementSize::Byte);
            }
            predicate::finish_predtest(code);
        }
    }
}

mod whiles {
    //! Baseline WHILE count and PN emission. Parent owns the P/PP chunk writer.
    //!
    //! Count is retained in R8D across state helpers; RAX/RCX/RDX are scratch.
    //! No callee-saved register is used. Scalar inputs are read before guest writes.
    use crate::{
        GuestState,
        aarch64::{
            Register, Width,
            scalable::{ElementSize, VectorLength},
            sve::predicate_generation::{Comparison, Destination, WhileOperand},
        },
        x86_64::{
            offset,
            scalable::{write_predicate_chunk, zero_predicate},
        },
    };

    const GPR_BYTES: usize = std::mem::size_of::<u64>();
    const NZCV_OFFSET: u32 = std::mem::offset_of!(GuestState, nzcv) as u32;
    const NZCV_STATE_SHIFT: u8 = 28;
    const N_NIBBLE: u32 = 8;
    const C_NIBBLE: u32 = 2;
    const ASCENDING_PARTIAL_FLAGS: u32 = N_NIBBLE | C_NIBBLE;
    const N_NIBBLE_SHIFT: u8 = 3;
    const Z_NIBBLE_SHIFT: u8 = 2;
    const PN_INVERT_BIT: u32 = 1 << 15;
    const PN_COUNT_SCALE_SHIFT: u32 = 1;
    const REL32_BYTES: usize = std::mem::size_of::<i32>();
    const TWO_BYTE_OPCODE: u8 = 0x0f;
    const JMP_REL32: u8 = 0xe9;

    const MOV_EAX_STATE: &[u8] = &[0x8b, 0x87];
    const MOV_RAX_STATE: &[u8] = &[0x48, 0x8b, 0x87];
    const MOVSXD_RAX_STATE: &[u8] = &[0x48, 0x63, 0x87];
    const MOV_ECX_STATE: &[u8] = &[0x8b, 0x8f];
    const MOV_RCX_STATE: &[u8] = &[0x48, 0x8b, 0x8f];
    const MOVSXD_RCX_STATE: &[u8] = &[0x48, 0x63, 0x8f];
    const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
    const XOR_ECX_ECX: &[u8] = &[0x31, 0xc9];
    const XOR_R8D_R8D: &[u8] = &[0x45, 0x31, 0xc0];
    const MOV_EAX_IMM32: u8 = 0xb8;
    const MOV_EDX_IMM32: u8 = 0xba;
    const MOV_R8D_IMM32: &[u8] = &[0x41, 0xb8];
    const MOVABS_RDX_IMM64: &[u8] = &[0x48, 0xba];
    const MOV_RAX_RCX: &[u8] = &[0x48, 0x89, 0xc8];
    const MOV_EAX_R8D: &[u8] = &[0x44, 0x89, 0xc0];
    const MOV_R8D_EAX: &[u8] = &[0x41, 0x89, 0xc0];
    const CMP_RAX_RCX: &[u8] = &[0x48, 0x39, 0xc8];
    const CMP_RCX_RAX: &[u8] = &[0x48, 0x39, 0xc1];
    const CMP_RCX_RDX: &[u8] = &[0x48, 0x39, 0xd1];
    const CMP_RAX_RDX: &[u8] = &[0x48, 0x39, 0xd0];
    const CMP_ECX_IMM32: &[u8] = &[0x81, 0xf9];
    const CMP_RCX_NEGATIVE_ONE: &[u8] = &[0x48, 0x83, 0xf9, 0xff];
    const CMP_R8D_IMM32: &[u8] = &[0x41, 0x81, 0xf8];
    const TEST_RAX_RAX: &[u8] = &[0x48, 0x85, 0xc0];
    const TEST_RCX_RCX: &[u8] = &[0x48, 0x85, 0xc9];
    const TEST_R8D_R8D: &[u8] = &[0x45, 0x85, 0xc0];
    const SUB_RAX_RCX: &[u8] = &[0x48, 0x29, 0xc8];
    const SUB_RCX_RAX: &[u8] = &[0x48, 0x29, 0xc1];
    const SUB_EAX_R8D: &[u8] = &[0x44, 0x29, 0xc0];
    const NEG_RAX: &[u8] = &[0x48, 0xf7, 0xd8];
    const CMOVA_RAX_RDX: &[u8] = &[0x48, TWO_BYTE_OPCODE, 0x47, 0xc2];
    const CMOVE_R8D_EDX: &[u8] = &[0x44, TWO_BYTE_OPCODE, 0x44, 0xc2];
    const LEA_R8D_RAX_PLUS_ONE: &[u8] = &[0x44, 0x8d, 0x40, 1];
    const JAE_REL8: u8 = 0x73;
    const SHR_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe8];
    const SHL_EAX_IMM8: &[u8] = &[0xc1, 0xe0];
    const SHL_ECX_IMM8: &[u8] = &[0xc1, 0xe1];
    const SHL_EDX_IMM8: &[u8] = &[0xc1, 0xe2];
    const SETE_CL: &[u8] = &[TWO_BYTE_OPCODE, 0x94, 0xc1];
    const SETE_DL: &[u8] = &[TWO_BYTE_OPCODE, 0x94, 0xc2];
    const MOVZX_ECX_CL: &[u8] = &[TWO_BYTE_OPCODE, 0xb6, 0xc9];
    const MOVZX_EDX_DL: &[u8] = &[TWO_BYTE_OPCODE, 0xb6, 0xd2];
    const LEA_EAX_RDX_TIMES_THREE: &[u8] = &[0x8d, 0x04, 0x52];
    const ADD_EAX_EAX: &[u8] = &[0x01, 0xc0];
    const ADD_ECX_ECX: &[u8] = &[0x01, 0xc9];
    const SUB_EAX_ECX: &[u8] = &[0x29, 0xc8];
    const SUB_EAX_EDX: &[u8] = &[0x29, 0xd0];
    const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];
    const OR_EAX_IMM32: u8 = 0x0d;
    const MOV_STATE_EAX: &[u8] = &[0x89, 0x87];

    #[repr(u8)]
    #[derive(Clone, Copy)]
    enum JumpCondition {
        Below = 0x82,
        Equal = 0x84,
        BelowEqual = 0x86,
        Above = 0x87,
        Less = 0x8c,
        GreaterEqual = 0x8d,
        LessEqual = 0x8e,
        Greater = 0x8f,
        AboveEqual = 0x83,
    }

    fn conditional_jump(code: &mut Vec<u8>, condition: JumpCondition) -> usize {
        code.extend([TWO_BYTE_OPCODE, condition as u8]);
        relative_jump_slot(code)
    }

    fn jump(code: &mut Vec<u8>) -> usize {
        code.push(JMP_REL32);
        relative_jump_slot(code)
    }

    fn relative_jump_slot(code: &mut Vec<u8>) -> usize {
        let slot = code.len();
        code.extend(0i32.to_le_bytes());
        slot
    }

    fn bind_jump(code: &mut [u8], slot: usize) {
        let displacement =
            i32::try_from(code.len() - slot - REL32_BYTES).expect("one WHILE mapping fits rel32");
        code[slot..slot + REL32_BYTES].copy_from_slice(&displacement.to_le_bytes());
    }

    fn immediate(code: &mut Vec<u8>, instruction: &[u8], value: u32) {
        code.extend(instruction);
        code.extend(value.to_le_bytes());
    }

    fn scalar(code: &mut Vec<u8>, source: Register, width: Width, signed: bool, first: bool) {
        if source == Register::Zero {
            code.extend(if first { XOR_EAX_EAX } else { XOR_ECX_ECX });
            return;
        }
        debug_assert!(matches!(source, Register::X(_)));
        let instruction = match (first, width, signed) {
            (true, Width::X64, _) => MOV_RAX_STATE,
            (false, Width::X64, _) => MOV_RCX_STATE,
            (true, Width::W32, false) => MOV_EAX_STATE,
            (false, Width::W32, false) => MOV_ECX_STATE,
            (true, Width::W32, true) => MOVSXD_RAX_STATE,
            (false, Width::W32, true) => MOVSXD_RCX_STATE,
        };
        immediate(
            code,
            instruction,
            offset(source).expect("WHILE scalar source is GPR"),
        );
    }

    fn descending(comparison: Comparison) -> bool {
        matches!(
            comparison,
            Comparison::SignedGe
                | Comparison::SignedGt
                | Comparison::UnsignedGe
                | Comparison::UnsignedGt
        )
    }

    fn signed(comparison: Comparison) -> bool {
        matches!(
            comparison,
            Comparison::SignedLt
                | Comparison::SignedLe
                | Comparison::SignedGe
                | Comparison::SignedGt
        )
    }

    fn inclusive(comparison: Comparison) -> bool {
        matches!(
            comparison,
            Comparison::SignedLe
                | Comparison::SignedGe
                | Comparison::UnsignedLe
                | Comparison::UnsignedGe
        )
    }

    fn failed_condition(comparison: Comparison) -> JumpCondition {
        match comparison {
            Comparison::SignedLt => JumpCondition::GreaterEqual,
            Comparison::SignedLe => JumpCondition::Greater,
            Comparison::SignedGe => JumpCondition::Less,
            Comparison::SignedGt => JumpCondition::LessEqual,
            Comparison::UnsignedLt => JumpCondition::AboveEqual,
            Comparison::UnsignedLe => JumpCondition::Above,
            Comparison::UnsignedGe => JumpCondition::Below,
            Comparison::UnsignedGt => JumpCondition::BelowEqual,
            _ => unreachable!("address distance has its own count mapping"),
        }
    }

    /// Compare RCX to the inclusive bound covering the entire modular domain.
    fn endpoint_compare(code: &mut Vec<u8>, comparison: Comparison, width: Width) {
        if comparison == Comparison::UnsignedGe {
            code.extend(TEST_RCX_RCX);
        } else if comparison == Comparison::UnsignedLe && width == Width::X64 {
            code.extend(CMP_RCX_NEGATIVE_ONE);
        } else if width == Width::W32 {
            let endpoint = match comparison {
                Comparison::SignedLe => i32::MAX as u32,
                Comparison::SignedGe => i32::MIN as u32,
                Comparison::UnsignedLe => u32::MAX,
                _ => unreachable!("inclusive comparison"),
            };
            immediate(code, CMP_ECX_IMM32, endpoint);
        } else {
            let endpoint = if comparison == Comparison::SignedLe {
                i64::MAX as u64
            } else {
                i64::MIN as u64
            };
            code.extend(MOVABS_RDX_IMM64);
            code.extend(endpoint.to_le_bytes());
            code.extend(CMP_RCX_RDX);
        }
    }

    fn clamped_distance(code: &mut Vec<u8>, capacity: u32, add_one: bool) {
        // The unsigned distance can be UINT64_MAX even for signed64 operands.
        // Clamp BEFORE increment, so inclusive full-domain distance cannot overflow.
        immediate(code, &[MOV_EDX_IMM32], capacity - u32::from(add_one));
        code.extend(CMP_RAX_RDX);
        code.extend(CMOVA_RAX_RDX);
        code.extend(if add_one {
            LEA_R8D_RAX_PLUS_ONE
        } else {
            MOV_R8D_EAX
        });
    }

    fn comparison_count(code: &mut Vec<u8>, operand: &WhileOperand, capacity: u32) {
        let add_one = inclusive(operand.comparison);
        if operand.first == operand.limit {
            if !add_one {
                code.extend(XOR_R8D_R8D);
            } else {
                // Equal inputs produce one active element except at the inclusive
                // domain endpoint, where comparison remains true across scalar wrap.
                scalar(
                    code,
                    operand.limit,
                    operand.width,
                    signed(operand.comparison),
                    false,
                );
                immediate(code, MOV_R8D_IMM32, 1);
                endpoint_compare(code, operand.comparison, operand.width);
                immediate(code, &[MOV_EDX_IMM32], capacity);
                code.extend(CMOVE_R8D_EDX);
            }
            return;
        }
        scalar(
            code,
            operand.first,
            operand.width,
            signed(operand.comparison),
            true,
        );
        scalar(
            code,
            operand.limit,
            operand.width,
            signed(operand.comparison),
            false,
        );
        let endpoint = if add_one {
            immediate(code, MOV_R8D_IMM32, capacity);
            endpoint_compare(code, operand.comparison, operand.width);
            Some(conditional_jump(code, JumpCondition::Equal))
        } else {
            None
        };
        code.extend(XOR_R8D_R8D);
        code.extend(CMP_RAX_RCX);
        let failed = conditional_jump(code, failed_condition(operand.comparison));
        if descending(operand.comparison) {
            code.extend(SUB_RAX_RCX);
        } else {
            code.extend(SUB_RCX_RAX);
            code.extend(MOV_RAX_RCX);
        }
        clamped_distance(code, capacity, add_one);
        bind_jump(code, failed);
        if let Some(endpoint) = endpoint {
            bind_jump(code, endpoint);
        }
    }

    fn address_count(code: &mut Vec<u8>, operand: &WhileOperand, capacity: u32) {
        immediate(code, MOV_R8D_IMM32, capacity);
        if operand.first == operand.limit {
            return;
        }
        scalar(code, operand.first, Width::X64, false, true);
        scalar(code, operand.limit, Width::X64, false, false);
        let backward = if operand.comparison == Comparison::WriteReadDistance {
            code.extend(CMP_RCX_RAX);
            let backward = conditional_jump(code, JumpCondition::BelowEqual);
            code.extend(SUB_RCX_RAX);
            code.extend(MOV_RAX_RCX);
            Some(backward)
        } else {
            // A borrowed unsigned subtraction followed by NEG recovers abs(a-b),
            // including differences above INT64_MAX; signed ABS would be incorrect.
            code.extend(SUB_RAX_RCX);
            code.extend([JAE_REL8, NEG_RAX.len() as u8]);
            code.extend(NEG_RAX);
            None
        };
        let divisor_shift = operand.element.bytes().trailing_zeros() as u8;
        if divisor_shift != 0 {
            code.extend(SHR_RAX_IMM8);
            code.push(divisor_shift);
        }
        code.extend(TEST_RAX_RAX);
        let unrestricted = conditional_jump(code, JumpCondition::Equal);
        clamped_distance(code, capacity, false);
        bind_jump(code, unrestricted);
        if let Some(backward) = backward {
            bind_jump(code, backward);
        }
    }

    fn count_flags(code: &mut Vec<u8>, capacity: u32, suffix: bool) {
        immediate(code, CMP_R8D_IMM32, capacity);
        code.extend(SETE_CL);
        code.extend(TEST_R8D_R8D);
        code.extend(SETE_DL);
        code.extend(MOVZX_ECX_CL);
        code.extend(MOVZX_EDX_DL);
        if suffix {
            // nibble = 8*full + 6*none; partial suffix has nibble0.
            code.extend(LEA_EAX_RDX_TIMES_THREE);
            code.extend(ADD_EAX_EAX);
            code.extend(SHL_ECX_IMM8);
            code.push(N_NIBBLE_SHIFT);
            code.extend(OR_EAX_ECX);
        } else {
            // nibble = 10 - 4*none - 2*full.
            immediate(code, &[MOV_EAX_IMM32], ASCENDING_PARTIAL_FLAGS);
            code.extend(SHL_EDX_IMM8);
            code.push(Z_NIBBLE_SHIFT);
            code.extend(SUB_EAX_EDX);
            code.extend(ADD_ECX_ECX);
            code.extend(SUB_EAX_ECX);
        }
        code.extend(SHL_EAX_IMM8);
        code.push(NZCV_STATE_SHIFT);
        immediate(code, MOV_STATE_EAX, NZCV_OFFSET);
    }

    fn counter(
        code: &mut Vec<u8>,
        destination: u8,
        element: ElementSize,
        length: VectorLength,
        capacity: u32,
        suffix: bool,
    ) {
        let single_chunk = length.predicate_bytes() <= GPR_BYTES;
        if single_chunk {
            code.extend(XOR_EAX_EAX);
        } else {
            zero_predicate(code, destination, length);
        }
        code.extend(TEST_R8D_R8D);
        let empty = conditional_jump(code, JumpCondition::Equal);
        let tag = element.bytes() as u32;
        let shift = (element.bytes().trailing_zeros() + PN_COUNT_SCALE_SHIFT) as u8;
        if suffix {
            immediate(code, &[MOV_EAX_IMM32], capacity);
            code.extend(SUB_EAX_R8D);
            code.extend(SHL_EAX_IMM8);
            code.push(shift);
            immediate(code, &[OR_EAX_IMM32], PN_INVERT_BIT | tag);
        } else {
            immediate(code, CMP_R8D_IMM32, capacity);
            let full = conditional_jump(code, JumpCondition::Equal);
            code.extend(MOV_EAX_R8D);
            code.extend(SHL_EAX_IMM8);
            code.push(shift);
            immediate(code, &[OR_EAX_IMM32], tag);
            let encoded = jump(code);
            bind_jump(code, full);
            immediate(code, &[MOV_EAX_IMM32], PN_INVERT_BIT | tag);
            bind_jump(code, encoded);
        }
        if single_chunk {
            bind_jump(code, empty);
            write_predicate_chunk(code, destination, 0, length);
        } else {
            write_predicate_chunk(code, destination, 0, length);
            bind_jump(code, empty);
        }
    }

    /// Parent callback emits the complete prefix/suffix P or PP write from R8D.
    /// It must preserve R8D. `capacity` spans both destinations for a pair.
    pub(super) fn emit_while(
        code: &mut Vec<u8>,
        operand: &WhileOperand,
        length: VectorLength,
        write_counted: impl FnOnce(&mut Vec<u8>, Destination, ElementSize, VectorLength, bool, u32),
    ) {
        debug_assert!(operand.element.bytes() <= GPR_BYTES);
        let vectors = match operand.destination {
            Destination::Predicate(_) => 1,
            Destination::Pair(_) => 2,
            Destination::Counter { vectors, .. } => usize::from(vectors),
        };
        let capacity = (length.lanes(operand.element) * vectors) as u32;
        let suffix = descending(operand.comparison);
        if matches!(
            operand.comparison,
            Comparison::ReadWriteDistance | Comparison::WriteReadDistance
        ) {
            address_count(code, operand, capacity);
        } else {
            comparison_count(code, operand, capacity);
        }
        count_flags(code, capacity, suffix);
        if let Destination::Counter { register, .. } = operand.destination {
            counter(code, register, operand.element, length, capacity, suffix);
        } else {
            write_counted(
                code,
                operand.destination,
                operand.element,
                length,
                suffix,
                capacity,
            );
        }
    }
}
