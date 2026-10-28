//! SVE TBL, SPLICE and INDEX.
//!
//! Scratch: RAX/RCX/RDX, XMM0-7 and a stack frame; large SPLICE copies also use
//! R8-R11/RSI and REP MOVSB (RDI is restored; SysV guarantees DF=0).
use crate::x86_64::asm::Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdi, Rsi, Rsp};
use crate::x86_64::asm::{Alu, Code, Cond, Disp, Gpr, Mem, Rm, ShiftOp, Size, Unary, resolve};

use crate::aarch64::Register;
use crate::aarch64::scalable::{ElementSize, MAX_VECTOR_BYTES, VECTOR_CHUNK_BYTES, VectorLength};
use crate::aarch64::sve::rearrange::{IndexOperand, Operand};
use crate::x86_64::isa::SimdOpcode as Host;
use crate::x86_64::scalable::{load_z_chunk, read_predicate_chunk, store_z_chunk};
use crate::{GuestState, TargetCpu};

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
const BYTE_BROADCAST_MULTIPLIER: u32 = 0x0101_0101;
const TABLE_CHUNK_LAST_INDEX: u8 = VECTOR_CHUNK_BYTES as u8 - 1;
const BYTE_INDEX_VALUES: usize = u8::MAX as usize + 1;
// Measured whole-table cutoff; larger whole tables retain the scalar mapping.
const BYTE_TABLE_SHUFFLE_LIMIT_BYTES: usize = 64;
const Z_REGISTER_MASK: u8 = 31;

fn stack_adjust(code: &mut Code, bytes: usize, allocate: bool) {
    assert!(bytes.is_multiple_of(VECTOR_CHUNK_BYTES));
    let op = if allocate { Alu::Sub } else { Alu::Add };
    code.asm()
        .alu_imm32(op, Size::Qword, Rsp, i32::try_from(bytes).unwrap());
}

/// `[rsp + index * scale + displacement]` with a 32-bit displacement field.
fn stack_slot(displacement: usize, index: Option<Gpr>, scale: usize) -> Mem {
    let displacement = i32::try_from(displacement).unwrap();
    match index {
        None => Mem::base_disp32(Rsp, displacement),
        Some(index) => Mem::indexed(Rsp, index, scale as u8, displacement).with_width(Disp::Dword),
    }
}

/// The operand size of a B/H/S/D lane.
fn lane_size(bytes: usize) -> Size {
    match bytes {
        1 => Size::Byte,
        2 => Size::Word,
        4 => Size::Dword,
        QWORD_BYTES => Size::Qword,
        _ => unreachable!("dynamic rearrangement has scalar B/H/S/D lanes"),
    }
}

/// Zero-extending lane load into RAX/RCX.
fn load_lane(code: &mut Code, destination: Gpr, source: Mem, bytes: usize) {
    let mut asm = code.asm();
    match lane_size(bytes) {
        Size::Dword => asm.mov_load(Size::Dword, destination, source),
        Size::Qword => asm.mov_load(Size::Qword, destination, source),
        narrow => asm.movzx(Size::Dword, destination, narrow, source),
    }
}

/// Scalar stack load. Index is RAX/RCX or none; scale is element byte size.
fn load_stack(
    code: &mut Code,
    destination: Gpr,
    displacement: usize,
    index: Option<Gpr>,
    scale: usize,
    bytes: usize,
) {
    assert!(matches!(destination, Rax | Rcx));
    assert!(matches!(index, Some(Rax | Rcx) | None));
    assert!(matches!(scale, 1 | 2 | 4 | 8));
    load_lane(
        code,
        destination,
        stack_slot(displacement, index, scale),
        bytes,
    );
}

fn store_stack(code: &mut Code, source: Gpr, displacement: usize, bytes: usize) {
    assert!(matches!(source, Rax | Rcx));
    code.asm()
        .mov_store(lane_size(bytes), stack_slot(displacement, None, 1), source);
}

fn xmm_stack(code: &mut Code, opcode: Host, xmm: u8, offset: usize, target: TargetCpu) {
    code.asm()
        .simd(opcode, xmm, stack_slot(offset, None, 1), target);
}

fn snapshot_z(
    code: &mut Code,
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

fn commit_z(code: &mut Code, register: u8, offset: usize, length: VectorLength, target: TargetCpu) {
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
    fn snapshot(code: &mut Code, op: Table, length: VectorLength, target: TargetCpu) -> Self {
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

    fn finish(self, code: &mut Code, destination: u8, length: VectorLength, target: TargetCpu) {
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

fn emit_table(code: &mut Code, op: Table, length: VectorLength, target: TargetCpu) {
    match table_recipe(op.element_size, op.segment, length, target) {
        TableRecipe::ByteShuffle => emit_table_ssse3(code, op, length, target),
        TableRecipe::ScalarGather => emit_table_unrolled(code, op, length, target),
    }
}

/// SSE2 baseline: a full unsigned bounds check of B/H/S/D indices before a
/// bounded gather.
fn emit_table_unrolled(code: &mut Code, op: Table, length: VectorLength, target: TargetCpu) {
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
        load_stack(code, Rax, frame.indexes + offset, None, 1, width);
        let mut asm = code.asm();
        asm.alu_accumulator_imm32(
            Alu::Cmp,
            Size::Qword,
            i32::try_from(table_bytes / width).unwrap(),
        );
        let out_of_range = asm.jcc(Cond::Ae);
        load_stack(code, Rcx, base, Some(Rax), width, width);
        store_stack(code, Rcx, frame.output + offset, width);
        let next = code.asm().jmp();
        code.asm().bind(out_of_range);
        if !op.extension {
            code.asm().alu(Alu::Xor, Size::Dword, Rcx, Rcx);
            store_stack(code, Rcx, frame.output + offset, width);
        }
        code.asm().bind(next);
    }
    frame.finish(code, op.destination, length, target);
}

fn broadcast_byte(code: &mut Code, value: u8, destination: u8, target: TargetCpu) {
    code.asm()
        .mov_imm32(Rax, u32::from(value) * BYTE_BROADCAST_MULTIPLIER);
    code.asm().movd_to_xmm(destination, Rax);
    code.asm().simd_imm(
        Host::ShuffleDword,
        destination,
        Rm::Xmm(destination),
        FIRST_DWORD,
        target,
    );
}

/// PSHUFB with every index masked to below 16, so indices 16-127 cannot wrap
/// and two-table TBL at a 256-bit vector length cannot reach the upper table
/// through byte indices. The scalar baseline handles full-width H/S/D indices.
fn emit_table_ssse3(code: &mut Code, op: Table, length: VectorLength, target: TargetCpu) {
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

fn address(code: &mut Code, destination: Gpr, displacement: usize) {
    code.asm()
        .lea(Size::Qword, destination, stack_slot(displacement, None, 1));
}

fn pointer_load(code: &mut Code, bytes: usize, base: Gpr) {
    load_lane(code, Rax, Mem::base(base, 0), bytes);
}

fn pointer_store(code: &mut Code, bytes: usize) {
    code.asm()
        .mov_store(lane_size(bytes), Mem::base(R10, 0), Rax);
}

fn backward(code: &mut Code, condition: Cond, target: usize) {
    let branch = code.asm().jcc(condition);
    resolve(code, branch, target);
}

fn copy_splice_rep(
    code: &mut Code,
    second: usize,
    output: usize,
    first: usize,
    end: usize,
    bytes: usize,
) {
    code.asm().mov(Size::Qword, R8, Rdi);
    address(code, Rdi, output);
    load_stack(code, Rax, first, None, 1, QWORD_BYTES);
    code.asm()
        .lea(Size::Qword, Rsi, Mem::indexed(Rsp, Rax, 1, 0));
    load_stack(code, Rcx, end, None, 1, QWORD_BYTES);
    let mut asm = code.asm();
    asm.rep_movsb();
    asm.mov_rm_imm32(Size::Qword, Rcx, i32::try_from(bytes).unwrap());
    load_stack(code, Rax, end, None, 1, QWORD_BYTES);
    code.asm().alu(Alu::Sub, Size::Qword, Rcx, Rax);
    address(code, Rsi, second);
    let mut asm = code.asm();
    asm.rep_movsb();
    asm.mov(Size::Qword, Rdi, R8);
}

fn copy_splice_counted(
    code: &mut Code,
    second: usize,
    output: usize,
    first: usize,
    end: usize,
    bytes: usize,
    width: usize,
) {
    load_stack(code, Rax, first, None, 1, QWORD_BYTES);
    code.asm()
        .lea(Size::Qword, R8, Mem::indexed(Rsp, Rax, 1, 0));
    address(code, R9, second);
    address(code, R10, output);
    address(code, R11, output + bytes);
    load_stack(code, Rcx, end, None, 1, QWORD_BYTES);
    let mut asm = code.asm();
    asm.test(Size::Qword, Rcx, Rcx);
    let empty = asm.jcc(Cond::E);
    let prefix_loop = code.len();
    pointer_load(code, width, R8);
    pointer_store(code, width);
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Add, Size::Qword, R8, width as i8);
    asm.alu_imm8(Alu::Add, Size::Qword, R10, width as i8);
    asm.alu_imm8(Alu::Sub, Size::Qword, Rcx, width as i8);
    backward(code, Cond::Ne, prefix_loop);
    let mut asm = code.asm();
    asm.bind(empty);
    asm.alu(Alu::Cmp, Size::Qword, R10, R11);
    let full = asm.jcc(Cond::E);
    let suffix_loop = code.len();
    pointer_load(code, width, R9);
    pointer_store(code, width);
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Add, Size::Qword, R9, width as i8);
    asm.alu_imm8(Alu::Add, Size::Qword, R10, width as i8);
    asm.alu(Alu::Cmp, Size::Qword, R10, R11);
    backward(code, Cond::B, suffix_loop);
    code.asm().bind(full);
}

/// SSE2 baseline SPLICE copies the contiguous first..last active hull, including
/// inactive holes, then fills from operand2. Empty predicates copy operand2.
fn emit_splice(code: &mut Code, op: Splice, length: VectorLength, target: TargetCpu) {
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
    code.asm()
        .mov_rm_imm32(Size::Qword, Rax, i32::try_from(length.bytes()).unwrap());
    store_stack(code, Rax, first, QWORD_BYTES);
    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
    store_stack(code, Rax, end, QWORD_BYTES);
    let mut leading_bits = 0u64;
    for bit in (0..PREDICATE_CHUNK_BITS).step_by(width) {
        leading_bits |= 1u64 << bit;
    }
    for chunk in 0..length.predicate_bytes().div_ceil(QWORD_BYTES) {
        read_predicate_chunk(code, op.governing, chunk, length);
        let mut asm = code.asm();
        if width != 1 {
            asm.mov_imm64(Rcx, leading_bits);
            asm.alu(Alu::And, Size::Qword, Rax, Rcx);
        }
        asm.test(Size::Qword, Rax, Rax);
        let inactive = asm.jcc(Cond::E);
        asm.bsf(Size::Qword, Rcx, Rax);
        asm.bsr(Size::Qword, Rax, Rax);
        asm.alu_accumulator_imm32(
            Alu::Add,
            Size::Qword,
            i32::try_from(chunk * PREDICATE_CHUNK_BITS + width).unwrap(),
        );
        store_stack(code, Rax, end, QWORD_BYTES);
        load_stack(code, Rax, first, None, 1, QWORD_BYTES);
        let mut asm = code.asm();
        asm.alu_accumulator_imm32(
            Alu::Cmp,
            Size::Qword,
            i32::try_from(length.bytes()).unwrap(),
        );
        let already_found = asm.jcc(Cond::Ne);
        asm.alu_imm32(
            Alu::Add,
            Size::Qword,
            Rcx,
            i32::try_from(chunk * PREDICATE_CHUNK_BITS).unwrap(),
        );
        store_stack(code, Rcx, first, QWORD_BYTES);
        let mut asm = code.asm();
        asm.bind(already_found);
        asm.bind(inactive);
    }
    load_stack(code, Rax, end, None, 1, QWORD_BYTES);
    let mut asm = code.asm();
    asm.test(Size::Qword, Rax, Rax);
    let nonempty = asm.jcc(Cond::Ne);
    store_stack(code, Rax, first, QWORD_BYTES); // Empty: first=end=0.
    code.asm().bind(nonempty);
    load_stack(code, Rcx, first, None, 1, QWORD_BYTES);
    code.asm().alu(Alu::Sub, Size::Qword, Rax, Rcx);
    store_stack(code, Rax, end, QWORD_BYTES); // End slot now holds hull byte length.
    if length.bytes() == MAX_VECTOR_BYTES {
        if width <= ElementSize::Halfword.bytes() {
            copy_splice_rep(code, second, output, first, end, length.bytes());
        } else {
            copy_splice_counted(code, second, output, first, end, length.bytes(), width);
        }
    } else {
        for offset in (0..length.bytes()).step_by(width) {
            load_stack(code, Rax, end, None, 1, QWORD_BYTES);
            let mut asm = code.asm();
            asm.alu_accumulator_imm32(Alu::Cmp, Size::Qword, i32::try_from(offset).unwrap());
            let from_second = asm.jcc(Cond::Be);
            load_stack(code, Rcx, first, None, 1, QWORD_BYTES);
            load_stack(code, Rax, offset, Some(Rcx), 1, width);
            let selected = code.asm().jmp();
            let mut asm = code.asm();
            asm.bind(from_second);
            asm.unary(Unary::Neg, Size::Qword, Rax);
            load_stack(code, Rax, second + offset, Some(Rax), 1, width);
            code.asm().bind(selected);
            store_stack(code, Rax, output + offset, width);
        }
    }
    commit_z(code, op.destination, output, length, target);
    stack_adjust(code, frame_bytes, false);
}

fn read_index_operand(code: &mut Code, operand: IndexOperand, destination: Gpr) {
    assert!(matches!(destination, Rax | Rcx));
    let mut asm = code.asm();
    match operand {
        IndexOperand::Immediate(value) => {
            asm.mov_rm_imm32(Size::Qword, destination, i32::from(value));
        }
        IndexOperand::Register(Register::Zero) => {
            asm.alu(Alu::Xor, Size::Dword, destination, destination);
        }
        IndexOperand::Register(Register::X(register)) => {
            assert!(register < 31);
            let offset = core::mem::offset_of!(GuestState, x) + usize::from(register) * QWORD_BYTES;
            asm.mov_load(
                Size::Qword,
                destination,
                Mem::base_disp32(Rdi, offset as i32),
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
fn emit_index(code: &mut Code, op: Index, length: VectorLength, target: TargetCpu) {
    let width = op.element_size.bytes();
    assert!(width <= QWORD_BYTES);
    stack_adjust(code, VECTOR_CHUNK_BYTES, true);
    read_index_operand(code, op.start, Rax);
    read_index_operand(code, op.step, Rcx);
    for offset in (0..VECTOR_CHUNK_BYTES).step_by(width) {
        store_stack(code, Rax, offset, width);
        if offset + width < VECTOR_CHUNK_BYTES {
            code.asm().alu(Alu::Add, Size::Qword, Rax, Rcx);
        }
    }
    xmm_stack(code, Host::LoadUnaligned, FIRST, 0, target);
    if length.chunks() > 1 {
        let mut asm = code.asm();
        asm.shift_imm(
            ShiftOp::Shl,
            Size::Qword,
            Rcx,
            (VECTOR_CHUNK_BYTES / width).trailing_zeros() as u8,
        );
        asm.simd(Host::MoveGprQword, SECOND, Rcx, target);
        match op.element_size {
            ElementSize::Byte => {
                Host::UnpackLowByte.register(code, SECOND, SECOND, target);
                Host::UnpackLowWord.register(code, SECOND, SECOND, target);
                code.asm().simd_imm(
                    Host::ShuffleDword,
                    SECOND,
                    Rm::Xmm(SECOND),
                    FIRST_DWORD,
                    target,
                );
            }
            ElementSize::Halfword => {
                Host::UnpackLowWord.register(code, SECOND, SECOND, target);
                code.asm().simd_imm(
                    Host::ShuffleDword,
                    SECOND,
                    Rm::Xmm(SECOND),
                    FIRST_DWORD,
                    target,
                );
            }
            ElementSize::Word => {
                code.asm().simd_imm(
                    Host::ShuffleDword,
                    SECOND,
                    Rm::Xmm(SECOND),
                    FIRST_DWORD,
                    target,
                );
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
pub(crate) fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
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
