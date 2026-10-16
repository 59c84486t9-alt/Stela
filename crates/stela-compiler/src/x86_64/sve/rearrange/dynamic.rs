//! SVE TBL, SPLICE and INDEX.
//!
//! Scratch: RAX/RCX/RDX, XMM0-7 and a stack frame; large SPLICE copies also use
//! R8-R11/RSI and REP MOVSB (RDI is restored; SysV guarantees DF=0).

use crate::aarch64::Register;
use crate::aarch64::scalable::{ElementSize, MAX_VECTOR_BYTES, VECTOR_CHUNK_BYTES, VectorLength};
use crate::aarch64::sve::rearrange::{IndexOperand, Operand};
use crate::x86_64::isa::SimdOpcode as Host;
use crate::x86_64::scalable::{load_z_chunk, read_predicate_chunk, store_z_chunk};
use crate::{GuestState, TargetCpu};
use alloc::vec::Vec;

const RAX: u8 = 0;
const RCX: u8 = 1;
const RSP: u8 = 4;
const NO_INDEX: u8 = RSP;
const REGISTER_SHIFT: u8 = 3;
const SCALE_SHIFT: u8 = 6;
const MODRM_DISP32_SIB: u8 = 0x84;
const SIB_RSP_NO_INDEX: u8 = 0x24;
const MODRM_DISP32_RDI: u8 = 0x87;
const MODRM_REGISTER: u8 = 0xc0;
const REX_QWORD: u8 = 0x48;
const WORD_PREFIX: u8 = 0x66;
const MOVZX_BYTE: &[u8] = &[0x0f, 0xb6];
const MOVZX_WORD: &[u8] = &[0x0f, 0xb7];
const MOV_LOAD: u8 = 0x8b;
const MOV_STORE_BYTE: u8 = 0x88;
const MOV_STORE: u8 = 0x89;
const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];
const CMP_RAX_IMM32: &[u8] = &[0x48, 0x3d];
const MOV_RAX_IMM32: &[u8] = &[0x48, 0xc7, 0xc0];
const MOV_RCX_IMM32: &[u8] = &[0x48, 0xc7, 0xc1];
const MOVABS_RCX_IMM64: &[u8] = &[0x48, 0xb9];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const XOR_ECX_ECX: &[u8] = &[0x31, 0xc9];
const ADD_RAX_RCX: &[u8] = &[0x48, 0x01, 0xc8];
const SUB_RAX_RCX: &[u8] = &[0x48, 0x29, 0xc8];
const ADD_RAX_IMM32: &[u8] = &[0x48, 0x05];
const ADD_RCX_IMM32: &[u8] = &[0x48, 0x81, 0xc1];
const NEG_RAX: &[u8] = &[0x48, 0xf7, 0xd8];
const SHL_RCX_IMM8: &[u8] = &[0x48, 0xc1, 0xe1];
const AND_RAX_RCX: &[u8] = &[0x48, 0x21, 0xc8];
const TEST_RAX_RAX: &[u8] = &[0x48, 0x85, 0xc0];
const BSF_RCX_RAX: &[u8] = &[0x48, 0x0f, 0xbc, 0xc8];
const BSR_RAX_RAX: &[u8] = &[0x48, 0x0f, 0xbd, 0xc0];
const JUMP_REL32: &[u8] = &[0xe9];
const JAE_REL32: &[u8] = &[0x0f, 0x83];
const JBE_REL32: &[u8] = &[0x0f, 0x86];
const JE_REL32: &[u8] = &[0x0f, 0x84];
const JNE_REL32: &[u8] = &[0x0f, 0x85];
const REL32_BYTES: usize = core::mem::size_of::<i32>();
const QWORD_BYTES: usize = core::mem::size_of::<u64>();
const PREDICATE_CHUNK_BITS: usize = u64::BITS as usize;
const FIRST: u8 = 0;
const SECOND: u8 = 1;
const TABLE_CHUNK: u8 = 2;
const RELATIVE_INDEX: u8 = 3;
const IN_RANGE: u8 = 4;
const MATCHED: u8 = 5;
const CHUNK_BASE: u8 = 6;
const MAX_INDEX: u8 = 7;
const FIRST_DWORD: u8 = 0;
const MOV_EAX_IMM32: u8 = 0xb8;
const MOVD_XMM_EAX: &[u8] = &[0x66, 0x0f, 0x6e];
const BYTE_BROADCAST_MULTIPLIER: u32 = 0x0101_0101;
const TABLE_CHUNK_LAST_INDEX: u8 = VECTOR_CHUNK_BYTES as u8 - 1;
const BYTE_INDEX_VALUES: usize = u8::MAX as usize + 1;
// Measured whole-table cutoff; larger whole tables retain the scalar mapping.
const BYTE_TABLE_SHUFFLE_LIMIT_BYTES: usize = 64;
const Z_REGISTER_MASK: u8 = 31;

const REX_EXTENDED_BASE: u8 = 0x41;
const REX_QWORD_EXTENDED_BASE: u8 = 0x49;
const LEA_R8_STACK_RAX: &[u8] = &[0x4c, 0x8d, 0x04, 0x04];
const LEA_R9_STACK: &[u8] = &[0x4c, 0x8d, 0x8c, 0x24];
const LEA_R10_STACK: &[u8] = &[0x4c, 0x8d, 0x94, 0x24];
const LEA_R11_STACK: &[u8] = &[0x4c, 0x8d, 0x9c, 0x24];
const LEA_RDI_STACK: &[u8] = &[0x48, 0x8d, 0xbc, 0x24];
const LEA_RSI_STACK: &[u8] = &[0x48, 0x8d, 0xb4, 0x24];
const LEA_RSI_STACK_RAX: &[u8] = &[0x48, 0x8d, 0x34, 0x04];
const MOV_R8_RDI: &[u8] = &[0x49, 0x89, 0xf8];
const MOV_RDI_R8: &[u8] = &[0x4c, 0x89, 0xc7];
const REP_MOVSB: &[u8] = &[0xf3, 0xa4];
const SUB_RCX_RAX: &[u8] = &[0x48, 0x29, 0xc1];
const TEST_RCX_RCX: &[u8] = &[0x48, 0x85, 0xc9];
const SUB_RCX_IMM8: &[u8] = &[0x48, 0x83, 0xe9];
const ADD_R8_IMM8: &[u8] = &[0x49, 0x83, 0xc0];
const ADD_R9_IMM8: &[u8] = &[0x49, 0x83, 0xc1];
const ADD_R10_IMM8: &[u8] = &[0x49, 0x83, 0xc2];
const CMP_R10_R11: &[u8] = &[0x4d, 0x39, 0xda];
const JB_REL32: &[u8] = &[0x0f, 0x82];
const R8_BASE: u8 = 0;
const R9_BASE: u8 = 1;
const R10_BASE: u8 = 2;

fn stack_adjust(code: &mut Vec<u8>, bytes: usize, allocate: bool) {
    assert!(bytes.is_multiple_of(VECTOR_CHUNK_BYTES));
    code.extend(if allocate {
        SUB_RSP_IMM32
    } else {
        ADD_RSP_IMM32
    });
    code.extend(i32::try_from(bytes).unwrap().to_le_bytes());
}

fn branch(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend([0; REL32_BYTES]);
    displacement
}

fn bind(code: &mut [u8], displacement: usize) {
    let target = code.len();
    let relative = i32::try_from(target as isize - (displacement + REL32_BYTES) as isize).unwrap();
    code[displacement..displacement + REL32_BYTES].copy_from_slice(&relative.to_le_bytes());
}

/// Scalar stack load. Index is RAX/RCX or NO_INDEX; scale is element byte size.
fn load_stack(
    code: &mut Vec<u8>,
    destination: u8,
    displacement: usize,
    index: u8,
    scale: usize,
    bytes: usize,
) {
    assert!(matches!(destination, RAX | RCX));
    assert!(matches!(index, RAX | RCX | NO_INDEX));
    assert!(matches!(scale, 1 | 2 | 4 | 8));
    match bytes {
        1 => code.extend(MOVZX_BYTE),
        2 => code.extend(MOVZX_WORD),
        4 => code.push(MOV_LOAD),
        QWORD_BYTES => code.extend([REX_QWORD, MOV_LOAD]),
        _ => unreachable!("dynamic rearrangement has scalar B/H/S/D lanes"),
    }
    code.push(MODRM_DISP32_SIB | (destination << REGISTER_SHIFT));
    code.push(((scale.trailing_zeros() as u8) << SCALE_SHIFT) | (index << REGISTER_SHIFT) | RSP);
    code.extend(i32::try_from(displacement).unwrap().to_le_bytes());
}

fn store_stack(code: &mut Vec<u8>, source: u8, displacement: usize, bytes: usize) {
    assert!(matches!(source, RAX | RCX));
    match bytes {
        1 => code.push(MOV_STORE_BYTE),
        2 => code.extend([WORD_PREFIX, MOV_STORE]),
        4 => code.push(MOV_STORE),
        QWORD_BYTES => code.extend([REX_QWORD, MOV_STORE]),
        _ => unreachable!("dynamic rearrangement has scalar B/H/S/D lanes"),
    }
    code.extend([
        MODRM_DISP32_SIB | (source << REGISTER_SHIFT),
        SIB_RSP_NO_INDEX,
    ]);
    code.extend(i32::try_from(displacement).unwrap().to_le_bytes());
}

fn xmm_stack(code: &mut Vec<u8>, opcode: Host, xmm: u8, offset: usize, target: TargetCpu) {
    opcode.append(code, target);
    code.extend([MODRM_DISP32_SIB | (xmm << REGISTER_SHIFT), SIB_RSP_NO_INDEX]);
    code.extend(i32::try_from(offset).unwrap().to_le_bytes());
}

fn snapshot_z(
    code: &mut Vec<u8>,
    register: u8,
    offset: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    for chunk in 0..length.chunks() {
        load_z_chunk(code, register, chunk, FIRST, length, target);
        xmm_stack(
            code,
            Host::StoreUnaligned,
            FIRST,
            offset + chunk * VECTOR_CHUNK_BYTES,
            target,
        );
    }
}

fn commit_z(
    code: &mut Vec<u8>,
    register: u8,
    offset: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    for chunk in 0..length.chunks() {
        xmm_stack(
            code,
            Host::LoadUnaligned,
            FIRST,
            offset + chunk * VECTOR_CHUNK_BYTES,
            target,
        );
        store_z_chunk(code, register, chunk, FIRST, length, target);
    }
}

#[derive(Clone, Copy)]
struct Table {
    destination: u8,
    source: u8,
    indexes: u8,
    register_count: u8,
    extension: bool,
    segment: bool,
    element_size: ElementSize,
}

struct TableFrame {
    table_bytes: usize,
    indexes: usize,
    output: usize,
    bytes: usize,
}

impl TableFrame {
    fn snapshot(code: &mut Vec<u8>, op: Table, length: VectorLength, target: TargetCpu) -> Self {
        assert!(matches!(op.register_count, 1 | 2));
        assert!(!op.segment || op.register_count == 1);
        let table_bytes = usize::from(op.register_count) * length.bytes();
        let indexes = table_bytes;
        let output = indexes + length.bytes();
        let bytes = output + length.bytes();
        stack_adjust(code, bytes, true);
        for table in 0..op.register_count {
            snapshot_z(
                code,
                (op.source + table) & Z_REGISTER_MASK,
                usize::from(table) * length.bytes(),
                length,
                target,
            );
        }
        snapshot_z(code, op.indexes, indexes, length, target);
        if op.extension {
            snapshot_z(code, op.destination, output, length, target);
        }
        Self {
            table_bytes,
            indexes,
            output,
            bytes,
        }
    }

    fn finish(self, code: &mut Vec<u8>, destination: u8, length: VectorLength, target: TargetCpu) {
        commit_z(code, destination, self.output, length, target);
        stack_adjust(code, self.bytes, false);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TableRecipe {
    ScalarGather,
    ByteShuffle,
}

fn table_recipe(
    element_size: ElementSize,
    segment: bool,
    length: VectorLength,
    target: TargetCpu,
) -> TableRecipe {
    if element_size == ElementSize::Byte
        && target.supports(TargetCpu::Ssse3)
        && (segment || length.bytes() <= BYTE_TABLE_SHUFFLE_LIMIT_BYTES)
    {
        TableRecipe::ByteShuffle
    } else {
        TableRecipe::ScalarGather
    }
}

/// Scalar table gathers branch on and address stack bytes with guest index
/// values, which requires a profile declaring DIT clear.
pub(super) fn requires_explicit_dit_zero(
    operand: Operand,
    length: VectorLength,
    target: TargetCpu,
) -> bool {
    match operand {
        Operand::Table {
            element_size,
            segment,
            ..
        } => table_recipe(element_size, segment, length, target) == TableRecipe::ScalarGather,
        _ => false,
    }
}

fn emit_table(code: &mut Vec<u8>, op: Table, length: VectorLength, target: TargetCpu) {
    match table_recipe(op.element_size, op.segment, length, target) {
        TableRecipe::ByteShuffle => emit_table_ssse3(code, op, length, target),
        TableRecipe::ScalarGather => emit_table_unrolled(code, op, length, target),
    }
}

/// SSE2 baseline: a full unsigned bounds check of B/H/S/D indices before a
/// bounded gather.
fn emit_table_unrolled(code: &mut Vec<u8>, op: Table, length: VectorLength, target: TargetCpu) {
    let width = op.element_size.bytes();
    assert!(width <= QWORD_BYTES);
    let frame = TableFrame::snapshot(code, op, length, target);
    let table_bytes = if op.segment {
        VECTOR_CHUNK_BYTES
    } else {
        frame.table_bytes
    };
    for offset in (0..length.bytes()).step_by(width) {
        let base = if op.segment {
            offset / VECTOR_CHUNK_BYTES * VECTOR_CHUNK_BYTES
        } else {
            0
        };
        load_stack(code, RAX, frame.indexes + offset, NO_INDEX, 1, width);
        code.extend(CMP_RAX_IMM32);
        code.extend(i32::try_from(table_bytes / width).unwrap().to_le_bytes());
        let out_of_range = branch(code, JAE_REL32);
        load_stack(code, RCX, base, RAX, width, width);
        store_stack(code, RCX, frame.output + offset, width);
        let next = branch(code, JUMP_REL32);
        bind(code, out_of_range);
        if !op.extension {
            code.extend(XOR_ECX_ECX);
            store_stack(code, RCX, frame.output + offset, width);
        }
        bind(code, next);
    }
    frame.finish(code, op.destination, length, target);
}

fn broadcast_byte(code: &mut Vec<u8>, value: u8, destination: u8, target: TargetCpu) {
    code.push(MOV_EAX_IMM32);
    code.extend((u32::from(value) * BYTE_BROADCAST_MULTIPLIER).to_le_bytes());
    code.extend(MOVD_XMM_EAX);
    code.push(MODRM_REGISTER | (destination << REGISTER_SHIFT));
    Host::ShuffleDword.register(code, destination, destination, target);
    code.push(FIRST_DWORD);
}

/// PSHUFB with every index masked to below 16, so indices 16-127 cannot wrap
/// and two-table TBL at a 256-bit vector length cannot reach the upper table
/// through byte indices. The scalar baseline handles full-width H/S/D indices.
fn emit_table_ssse3(code: &mut Vec<u8>, op: Table, length: VectorLength, target: TargetCpu) {
    assert_eq!(op.element_size, ElementSize::Byte);
    assert!(target.supports(TargetCpu::Ssse3));
    let frame = TableFrame::snapshot(code, op, length, target);
    broadcast_byte(code, TABLE_CHUNK_LAST_INDEX, MAX_INDEX, target);
    for chunk in 0..length.chunks() {
        xmm_stack(
            code,
            Host::LoadUnaligned,
            SECOND,
            frame.indexes + chunk * VECTOR_CHUNK_BYTES,
            target,
        );
        Host::Xor.register(code, FIRST, FIRST, target);
        Host::Xor.register(code, MATCHED, MATCHED, target);
        let table_chunks = if op.segment {
            1
        } else {
            frame.table_bytes.min(BYTE_INDEX_VALUES) / VECTOR_CHUNK_BYTES
        };
        for table_chunk in 0..table_chunks {
            let table_offset = if op.segment {
                chunk * VECTOR_CHUNK_BYTES
            } else {
                table_chunk * VECTOR_CHUNK_BYTES
            };
            xmm_stack(code, Host::LoadUnaligned, TABLE_CHUNK, table_offset, target);
            Host::MoveAligned.register(code, RELATIVE_INDEX, SECOND, target);
            if !op.segment && table_chunk != 0 {
                broadcast_byte(
                    code,
                    (table_chunk * VECTOR_CHUNK_BYTES) as u8,
                    CHUNK_BASE,
                    target,
                );
                Host::SubByte.register(code, RELATIVE_INDEX, CHUNK_BASE, target);
            }
            Host::MoveAligned.register(code, IN_RANGE, RELATIVE_INDEX, target);
            Host::MinUnsignedByte.register(code, IN_RANGE, MAX_INDEX, target);
            Host::EqualByte.register(code, IN_RANGE, RELATIVE_INDEX, target);
            Host::ByteShuffle.register(code, TABLE_CHUNK, RELATIVE_INDEX, target);
            Host::And.register(code, TABLE_CHUNK, IN_RANGE, target);
            Host::Or.register(code, FIRST, TABLE_CHUNK, target);
            if op.extension {
                Host::Or.register(code, MATCHED, IN_RANGE, target);
            }
        }
        if op.extension {
            xmm_stack(
                code,
                Host::LoadUnaligned,
                TABLE_CHUNK,
                frame.output + chunk * VECTOR_CHUNK_BYTES,
                target,
            );
            Host::AndNot.register(code, MATCHED, TABLE_CHUNK, target);
            Host::Or.register(code, FIRST, MATCHED, target);
        }
        xmm_stack(
            code,
            Host::StoreUnaligned,
            FIRST,
            frame.output + chunk * VECTOR_CHUNK_BYTES,
            target,
        );
    }
    frame.finish(code, op.destination, length, target);
}

#[derive(Clone, Copy)]
struct Splice {
    destination: u8,
    source: u8,
    second: u8,
    governing: u8,
    element_size: ElementSize,
}

fn address(code: &mut Vec<u8>, opcode: &[u8], displacement: usize) {
    code.extend(opcode);
    code.extend(i32::try_from(displacement).unwrap().to_le_bytes());
}

fn pointer_load(code: &mut Vec<u8>, bytes: usize, base: u8) {
    code.push(if bytes == QWORD_BYTES {
        REX_QWORD_EXTENDED_BASE
    } else {
        REX_EXTENDED_BASE
    });
    code.extend(match bytes {
        1 => MOVZX_BYTE,
        2 => MOVZX_WORD,
        4 | QWORD_BYTES => &[MOV_LOAD],
        _ => unreachable!("SPLICE lane width"),
    });
    code.push(base);
}

fn pointer_store(code: &mut Vec<u8>, bytes: usize) {
    if bytes == 2 {
        code.push(WORD_PREFIX);
    }
    code.push(if bytes == QWORD_BYTES {
        REX_QWORD_EXTENDED_BASE
    } else {
        REX_EXTENDED_BASE
    });
    code.push(if bytes == 1 {
        MOV_STORE_BYTE
    } else {
        MOV_STORE
    });
    code.push(R10_BASE);
}

fn backward(code: &mut Vec<u8>, opcode: &[u8], target: usize) {
    let displacement = branch(code, opcode);
    let relative = i32::try_from(target as isize - (displacement + REL32_BYTES) as isize).unwrap();
    code[displacement..displacement + REL32_BYTES].copy_from_slice(&relative.to_le_bytes());
}

fn copy_splice_rep(
    code: &mut Vec<u8>,
    second: usize,
    output: usize,
    first: usize,
    end: usize,
    bytes: usize,
) {
    code.extend(MOV_R8_RDI);
    address(code, LEA_RDI_STACK, output);
    load_stack(code, RAX, first, NO_INDEX, 1, QWORD_BYTES);
    code.extend(LEA_RSI_STACK_RAX);
    load_stack(code, RCX, end, NO_INDEX, 1, QWORD_BYTES);
    code.extend(REP_MOVSB);
    code.extend(MOV_RCX_IMM32);
    code.extend(i32::try_from(bytes).unwrap().to_le_bytes());
    load_stack(code, RAX, end, NO_INDEX, 1, QWORD_BYTES);
    code.extend(SUB_RCX_RAX);
    address(code, LEA_RSI_STACK, second);
    code.extend(REP_MOVSB);
    code.extend(MOV_RDI_R8);
}

fn copy_splice_counted(
    code: &mut Vec<u8>,
    second: usize,
    output: usize,
    first: usize,
    end: usize,
    bytes: usize,
    width: usize,
) {
    load_stack(code, RAX, first, NO_INDEX, 1, QWORD_BYTES);
    code.extend(LEA_R8_STACK_RAX);
    address(code, LEA_R9_STACK, second);
    address(code, LEA_R10_STACK, output);
    address(code, LEA_R11_STACK, output + bytes);
    load_stack(code, RCX, end, NO_INDEX, 1, QWORD_BYTES);
    code.extend(TEST_RCX_RCX);
    let empty = branch(code, JE_REL32);
    let prefix_loop = code.len();
    pointer_load(code, width, R8_BASE);
    pointer_store(code, width);
    code.extend(ADD_R8_IMM8);
    code.push(width as u8);
    code.extend(ADD_R10_IMM8);
    code.push(width as u8);
    code.extend(SUB_RCX_IMM8);
    code.push(width as u8);
    backward(code, JNE_REL32, prefix_loop);
    bind(code, empty);
    code.extend(CMP_R10_R11);
    let full = branch(code, JE_REL32);
    let suffix_loop = code.len();
    pointer_load(code, width, R9_BASE);
    pointer_store(code, width);
    code.extend(ADD_R9_IMM8);
    code.push(width as u8);
    code.extend(ADD_R10_IMM8);
    code.push(width as u8);
    code.extend(CMP_R10_R11);
    backward(code, JB_REL32, suffix_loop);
    bind(code, full);
}

/// SSE2 baseline SPLICE copies the contiguous first..last active hull, including
/// inactive holes, then fills from operand2. Empty predicates copy operand2.
fn emit_splice(code: &mut Vec<u8>, op: Splice, length: VectorLength, target: TargetCpu) {
    let width = op.element_size.bytes();
    assert!(width <= QWORD_BYTES);
    let second = length.bytes();
    let output = second + length.bytes();
    let first = output + length.bytes();
    let end = first + QWORD_BYTES;
    let frame_bytes = first + VECTOR_CHUNK_BYTES;
    stack_adjust(code, frame_bytes, true);
    snapshot_z(code, op.source, 0, length, target);
    snapshot_z(code, op.second, second, length, target);
    code.extend(MOV_RAX_IMM32);
    code.extend(i32::try_from(length.bytes()).unwrap().to_le_bytes());
    store_stack(code, RAX, first, QWORD_BYTES);
    code.extend(XOR_EAX_EAX);
    store_stack(code, RAX, end, QWORD_BYTES);
    let mut leading_bits = 0u64;
    for bit in (0..PREDICATE_CHUNK_BITS).step_by(width) {
        leading_bits |= 1u64 << bit;
    }
    for chunk in 0..length.predicate_bytes().div_ceil(QWORD_BYTES) {
        read_predicate_chunk(code, op.governing, chunk, length);
        if width != 1 {
            code.extend(MOVABS_RCX_IMM64);
            code.extend(leading_bits.to_le_bytes());
            code.extend(AND_RAX_RCX);
        }
        code.extend(TEST_RAX_RAX);
        let inactive = branch(code, JE_REL32);
        code.extend(BSF_RCX_RAX);
        code.extend(BSR_RAX_RAX);
        code.extend(ADD_RAX_IMM32);
        code.extend(
            i32::try_from(chunk * PREDICATE_CHUNK_BITS + width)
                .unwrap()
                .to_le_bytes(),
        );
        store_stack(code, RAX, end, QWORD_BYTES);
        load_stack(code, RAX, first, NO_INDEX, 1, QWORD_BYTES);
        code.extend(CMP_RAX_IMM32);
        code.extend(i32::try_from(length.bytes()).unwrap().to_le_bytes());
        let already_found = branch(code, JNE_REL32);
        code.extend(ADD_RCX_IMM32);
        code.extend(
            i32::try_from(chunk * PREDICATE_CHUNK_BITS)
                .unwrap()
                .to_le_bytes(),
        );
        store_stack(code, RCX, first, QWORD_BYTES);
        bind(code, already_found);
        bind(code, inactive);
    }
    load_stack(code, RAX, end, NO_INDEX, 1, QWORD_BYTES);
    code.extend(TEST_RAX_RAX);
    let nonempty = branch(code, JNE_REL32);
    store_stack(code, RAX, first, QWORD_BYTES); // Empty: first=end=0.
    bind(code, nonempty);
    load_stack(code, RCX, first, NO_INDEX, 1, QWORD_BYTES);
    code.extend(SUB_RAX_RCX);
    store_stack(code, RAX, end, QWORD_BYTES); // End slot now holds hull byte length.
    if length.bytes() == MAX_VECTOR_BYTES {
        if width <= ElementSize::Halfword.bytes() {
            copy_splice_rep(code, second, output, first, end, length.bytes());
        } else {
            copy_splice_counted(code, second, output, first, end, length.bytes(), width);
        }
    } else {
        for offset in (0..length.bytes()).step_by(width) {
            load_stack(code, RAX, end, NO_INDEX, 1, QWORD_BYTES);
            code.extend(CMP_RAX_IMM32);
            code.extend(i32::try_from(offset).unwrap().to_le_bytes());
            let from_second = branch(code, JBE_REL32);
            load_stack(code, RCX, first, NO_INDEX, 1, QWORD_BYTES);
            load_stack(code, RAX, offset, RCX, 1, width);
            let selected = branch(code, JUMP_REL32);
            bind(code, from_second);
            code.extend(NEG_RAX);
            load_stack(code, RAX, second + offset, RAX, 1, width);
            bind(code, selected);
            store_stack(code, RAX, output + offset, width);
        }
    }
    commit_z(code, op.destination, output, length, target);
    stack_adjust(code, frame_bytes, false);
}

fn read_index_operand(code: &mut Vec<u8>, operand: IndexOperand, destination: u8) {
    assert!(matches!(destination, RAX | RCX));
    match operand {
        IndexOperand::Immediate(value) => {
            code.extend(if destination == RAX {
                MOV_RAX_IMM32
            } else {
                MOV_RCX_IMM32
            });
            code.extend(i32::from(value).to_le_bytes());
        }
        IndexOperand::Register(Register::Zero) => code.extend(if destination == RAX {
            XOR_EAX_EAX
        } else {
            XOR_ECX_ECX
        }),
        IndexOperand::Register(Register::X(register)) => {
            assert!(register < 31);
            code.extend([
                REX_QWORD,
                MOV_LOAD,
                MODRM_DISP32_RDI | (destination << REGISTER_SHIFT),
            ]);
            code.extend(
                ((core::mem::offset_of!(GuestState, x) + usize::from(register) * QWORD_BYTES)
                    as u32)
                    .to_le_bytes(),
            );
        }
        IndexOperand::Register(Register::Sp) => unreachable!("INDEX register31 is ZR, never SP"),
    }
}

#[derive(Clone, Copy)]
struct Index {
    destination: u8,
    start: IndexOperand,
    step: IndexOperand,
    element_size: ElementSize,
}

/// SSE2 packed ramp: synthesize only the first16 bytes, broadcast the
/// modulo-width chunk step, then use PADD B/H/S/D for each additional chunk.
fn emit_index(code: &mut Vec<u8>, op: Index, length: VectorLength, target: TargetCpu) {
    let width = op.element_size.bytes();
    assert!(width <= QWORD_BYTES);
    stack_adjust(code, VECTOR_CHUNK_BYTES, true);
    read_index_operand(code, op.start, RAX);
    read_index_operand(code, op.step, RCX);
    for offset in (0..VECTOR_CHUNK_BYTES).step_by(width) {
        store_stack(code, RAX, offset, width);
        if offset + width < VECTOR_CHUNK_BYTES {
            code.extend(ADD_RAX_RCX);
        }
    }
    xmm_stack(code, Host::LoadUnaligned, FIRST, 0, target);
    if length.chunks() > 1 {
        code.extend(SHL_RCX_IMM8);
        code.push((VECTOR_CHUNK_BYTES / width).trailing_zeros() as u8);
        Host::MoveGprQword.register(code, SECOND, RCX, target);
        match op.element_size {
            ElementSize::Byte => {
                Host::UnpackLowByte.register(code, SECOND, SECOND, target);
                Host::UnpackLowWord.register(code, SECOND, SECOND, target);
                Host::ShuffleDword.register(code, SECOND, SECOND, target);
                code.push(FIRST_DWORD);
            }
            ElementSize::Halfword => {
                Host::UnpackLowWord.register(code, SECOND, SECOND, target);
                Host::ShuffleDword.register(code, SECOND, SECOND, target);
                code.push(FIRST_DWORD);
            }
            ElementSize::Word => {
                Host::ShuffleDword.register(code, SECOND, SECOND, target);
                code.push(FIRST_DWORD);
            }
            ElementSize::Doubleword => Host::UnpackLowQword.register(code, SECOND, SECOND, target),
            ElementSize::Quadword => unreachable!("INDEX has no128-bit element allocation"),
        }
    }
    let add = match op.element_size {
        ElementSize::Byte => Host::AddByte,
        ElementSize::Halfword => Host::AddWord,
        ElementSize::Word => Host::AddDword,
        ElementSize::Doubleword => Host::AddQword,
        ElementSize::Quadword => unreachable!("INDEX has no128-bit element allocation"),
    };
    for chunk in 0..length.chunks() {
        store_z_chunk(code, op.destination, chunk, FIRST, length, target);
        if chunk + 1 < length.chunks() {
            add.register(code, FIRST, SECOND, target);
        }
    }
    stack_adjust(code, VECTOR_CHUNK_BYTES, false);
}

/// Complete validated Table/Splice/Index operands. The family dispatcher owns
/// allocation and streaming-profile checks before calling this module.
pub(crate) fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    match operand {
        Operand::Table {
            destination,
            source,
            indexes,
            register_count,
            extension,
            segment,
            element_size,
        } => emit_table(
            code,
            Table {
                destination,
                source,
                indexes,
                register_count,
                extension,
                segment,
                element_size,
            },
            length,
            target,
        ),
        Operand::Splice {
            destination,
            source,
            second,
            governing,
            element_size,
        } => emit_splice(
            code,
            Splice {
                destination,
                source,
                second,
                governing,
                element_size,
            },
            length,
            target,
        ),
        Operand::Index {
            destination,
            start,
            step,
            element_size,
        } => emit_index(
            code,
            Index {
                destination,
                start,
                step,
                element_size,
            },
            length,
            target,
        ),
        _ => unreachable!("dynamic rearrangement dispatch accepts only Table, Splice and Index"),
    }
}
