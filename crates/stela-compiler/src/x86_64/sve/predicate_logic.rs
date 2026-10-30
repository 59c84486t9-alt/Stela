//! Predicate Boolean operations and permutes.
use super::super::scalable;
use super::predicate;
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::Gpr::{R8, R11, Rax, Rcx, Rdi, Rdx, Rsp};
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, ShiftOp, Size, Unary};
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, VectorLength},
        sve::predicate_logic::{Boolean, Kind, Operand, Permutation},
    },
};

const CHUNK_BITS: usize = 64;
const CHUNK_BYTES: usize = 8;
const SOURCE_SLOT_BYTES: usize = 32;
const SNAPSHOT_BYTES: u8 = 64;
const HALF_CHUNK_BITS: usize = 32;
const SPREAD_STAGES: [(u8, u64); 5] = [
    (16, 0x0000_ffff_0000_ffff),
    (8, 0x00ff_00ff_00ff_00ff),
    (4, 0x0f0f_0f0f_0f0f_0f0f),
    (2, 0x3333_3333_3333_3333),
    (1, 0x5555_5555_5555_5555),
];

pub(crate) fn emit(code: &mut Code, operand: &Operand, length: VectorLength, target: TargetCpu) {
    match operand.kind {
        Kind::Boolean {
            operation,
            flags,
            governor,
            left,
            right,
        } => {
            if flags {
                predicate::begin_predtest(code);
            }
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                scalable::read_predicate_chunk(code, left, chunk, length);
                code.asm().mov(Size::Qword, Rcx, Rax);
                scalable::read_predicate_chunk(code, right, chunk, length);
                match operation {
                    Boolean::And => code.asm().alu(Alu::And, Size::Qword, Rax, Rcx),
                    Boolean::BitClear => {
                        let mut asm = code.asm();
                        asm.unary(Unary::Not, Size::Qword, Rax);
                        asm.alu(Alu::And, Size::Qword, Rax, Rcx);
                    }
                    Boolean::ExclusiveOr => code.asm().alu(Alu::Xor, Size::Qword, Rax, Rcx),
                    Boolean::Nand => {
                        let mut asm = code.asm();
                        asm.alu(Alu::And, Size::Qword, Rax, Rcx);
                        asm.unary(Unary::Not, Size::Qword, Rax);
                    }
                    Boolean::Nor => {
                        let mut asm = code.asm();
                        asm.alu(Alu::Or, Size::Qword, Rax, Rcx);
                        asm.unary(Unary::Not, Size::Qword, Rax);
                    }
                    Boolean::OrNot => {
                        let mut asm = code.asm();
                        asm.unary(Unary::Not, Size::Qword, Rax);
                        asm.alu(Alu::Or, Size::Qword, Rax, Rcx);
                    }
                    Boolean::Or => code.asm().alu(Alu::Or, Size::Qword, Rax, Rcx),
                }
                code.asm().mov(Size::Qword, Rcx, Rax);
                scalable::read_predicate_chunk(code, governor, chunk, length);
                let mut asm = code.asm();
                asm.mov(Size::Qword, R11, Rax);
                asm.alu(Alu::And, Size::Qword, Rax, Rcx);
                if flags {
                    predicate::accumulate_predtest(code, ElementSize::Byte);
                }
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            if flags {
                predicate::finish_predtest(code);
            }
        }
        Kind::Select {
            governor,
            left,
            right,
        } => {
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                scalable::read_predicate_chunk(code, left, chunk, length);
                code.asm().mov(Size::Qword, Rcx, Rax);
                scalable::read_predicate_chunk(code, right, chunk, length);
                let mut asm = code.asm();
                asm.mov(Size::Qword, R11, Rax);
                asm.alu(Alu::Xor, Size::Qword, Rax, Rcx);
                asm.mov(Size::Qword, Rcx, Rax);
                scalable::read_predicate_chunk(code, governor, chunk, length);
                let mut asm = code.asm();
                asm.alu(Alu::And, Size::Qword, Rax, Rcx);
                asm.alu(Alu::Xor, Size::Qword, Rax, R11);
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
        }
        Kind::SelectIndexed {
            element,
            source,
            selector,
            index_register,
            immediate,
        } => {
            code.asm()
                .alu_imm8(Alu::Sub, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
            snapshot(code, selector, 0, length);
            code.asm().mov_load(
                Size::Dword,
                Rcx,
                Mem::base_disp32(
                    Rdi,
                    (core::mem::offset_of!(crate::GuestState, x)
                        + usize::from(index_register) * CHUNK_BYTES) as i32,
                ),
            );
            if immediate != 0 {
                code.asm()
                    .alu_imm8(Alu::Add, Size::Dword, Rcx, immediate as i8);
            }
            code.asm().alu_imm32(
                Alu::And,
                Size::Dword,
                Rcx,
                (length.bytes() / element.bytes() - 1) as i32,
            );
            if element != ElementSize::Byte {
                code.asm().shift_imm(
                    ShiftOp::Shl,
                    Size::Dword,
                    Rcx,
                    element.bytes().ilog2() as u8,
                );
            }
            let mut asm = code.asm();
            asm.bit(BitTest::Bt, Size::Qword, Mem::base(Rsp, 0), Rcx);
            asm.alu(Alu::Sbb, Size::Qword, R8, R8);
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                scalable::read_predicate_chunk(code, source, chunk, length);
                code.asm().alu(Alu::And, Size::Qword, Rax, R8);
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            code.asm()
                .alu_imm8(Alu::Add, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
        }
        Kind::ExtractCounter {
            element,
            source,
            part,
            pair,
        } => {
            scalable::read_predicate_chunk(code, source, 0, length);
            predicate::prepare_counter(code, length);
            let outputs = if pair { 2 } else { 1 };
            for output in 0..outputs {
                for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                    let offset = (usize::from(part) * outputs + output) * length.bytes()
                        + chunk * CHUNK_BITS;
                    predicate::emit_prepared_counter_chunk(code, offset / CHUNK_BITS, length);
                    shift(code, ShiftOp::Shr, Rax, offset % CHUNK_BITS);
                    and_mask(code, predicate::leading_bits(element));
                    scalable::write_predicate_chunk(
                        code,
                        (operand.destination + output as u8) % 16,
                        chunk,
                        length,
                    );
                }
            }
        }
        Kind::MoveVector {
            element,
            source,
            part,
        } => {
            code.asm()
                .alu_imm8(Alu::Sub, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
            let needed = length.predicate_bytes().div_ceil(16);
            for chunk in 0..needed {
                scalable::load_z_chunk(code, source, chunk, 0, length, target);
                code.asm()
                    .movdqu_store(Mem::base_disp32(Rsp, (chunk * 16) as i32), 0);
            }
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                let bit = length.bytes() / element.bytes() * usize::from(part)
                    + chunk * CHUNK_BITS / element.bytes();
                load_bits(code, 0, bit);
                dilate(code, element.bytes());
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            code.asm()
                .alu_imm8(Alu::Add, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
        }
        Kind::Permute {
            operation,
            element,
            left,
            right,
        } => {
            code.asm()
                .alu_imm8(Alu::Sub, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
            snapshot(code, left, 0, length);
            snapshot(code, right, SOURCE_SLOT_BYTES, length);
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                permutation(code, operation, element, chunk, length);
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            code.asm()
                .alu_imm8(Alu::Add, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
        }
        Kind::Unpack { high, source } => {
            code.asm()
                .alu_imm8(Alu::Sub, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
            snapshot(code, source, 0, length);
            for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
                load_bits(
                    code,
                    0,
                    usize::from(high) * length.bytes() / 2 + chunk * HALF_CHUNK_BITS,
                );
                spread(code, 1, length.bytes().min(CHUNK_BITS));
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            code.asm()
                .alu_imm8(Alu::Add, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
        }
        Kind::Reverse { element, source } => {
            code.asm()
                .alu_imm8(Alu::Sub, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
            snapshot(code, source, 0, length);
            let chunks = length.predicate_bytes().div_ceil(CHUNK_BYTES);
            for chunk in 0..chunks {
                load_snapshot(code, (chunks - 1 - chunk) * CHUNK_BYTES);
                for distance in [1, 2, 4].into_iter().filter(|&d| d >= element.bytes()) {
                    code.asm().mov(Size::Qword, Rdx, Rax);
                    shift(code, ShiftOp::Shr, Rdx, distance);
                    and_mask(code, low_group_mask(distance));
                    shift(code, ShiftOp::Shl, Rax, distance);
                    // RDX already contains the opposite half; mask it via R11.
                    let mut asm = code.asm();
                    asm.alu(Alu::And, Size::Qword, Rdx, R11);
                    asm.alu(Alu::Or, Size::Qword, Rax, Rdx);
                }
                code.asm().bswap(Size::Qword, Rax);
                if length.bytes() < CHUNK_BITS {
                    shift(code, ShiftOp::Shr, Rax, CHUNK_BITS - length.bytes());
                }
                scalable::write_predicate_chunk(code, operand.destination, chunk, length);
            }
            code.asm()
                .alu_imm8(Alu::Add, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
        }
    }
}

fn snapshot(code: &mut Code, source: u8, slot: usize, length: VectorLength) {
    for chunk in 0..length.predicate_bytes().div_ceil(CHUNK_BYTES) {
        scalable::read_predicate_chunk(code, source, chunk, length);
        store_snapshot(code, slot + chunk * CHUNK_BYTES);
    }
}
fn store_snapshot(code: &mut Code, offset: usize) {
    code.asm()
        .mov_store(Size::Qword, Mem::base_disp32(Rsp, offset as i32), Rax);
}
fn load_snapshot(code: &mut Code, offset: usize) {
    code.asm()
        .mov_load(Size::Qword, Rax, Mem::base_disp32(Rsp, offset as i32));
}
fn load_bits(code: &mut Code, slot: usize, bit: usize) {
    load_snapshot(code, slot + (bit / CHUNK_BITS) * CHUNK_BYTES);
    shift(code, ShiftOp::Shr, Rax, bit % CHUNK_BITS);
}
fn shift(code: &mut Code, op: ShiftOp, register: Gpr, bits: usize) {
    if bits != 0 {
        code.asm().shift_imm(op, Size::Qword, register, bits as u8);
    }
}
fn and_mask(code: &mut Code, mask: u64) {
    let mut asm = code.asm();
    asm.mov_imm64(R11, mask);
    asm.alu(Alu::And, Size::Qword, Rax, R11);
}
fn low_group_mask(group: usize) -> u64 {
    (0..CHUNK_BITS)
        .filter(|bit| (bit / group).is_multiple_of(2))
        .fold(0, |mask, bit| mask | (1 << bit))
}
fn spread(code: &mut Code, group: usize, output_bits: usize) {
    if output_bits < CHUNK_BITS {
        code.asm().alu_accumulator_imm32(
            Alu::And,
            Size::Dword,
            ((1u32 << (output_bits / 2)) - 1) as i32,
        );
    } else {
        code.asm().mov(Size::Dword, Rax, Rax);
    }
    for (distance, mask) in SPREAD_STAGES.into_iter().filter(|&(distance, _)| {
        usize::from(distance) >= group && usize::from(distance) < output_bits / 2
    }) {
        code.asm().mov(Size::Qword, Rdx, Rax);
        shift(code, ShiftOp::Shl, Rdx, usize::from(distance));
        code.asm().alu(Alu::Or, Size::Qword, Rax, Rdx);
        and_mask(code, mask);
    }
}
fn compact(code: &mut Code, group: usize, odd: bool) {
    shift(code, ShiftOp::Shr, Rax, usize::from(odd) * group);
    and_mask(code, low_group_mask(group));
    for distance in [1, 2, 4, 8, 16]
        .into_iter()
        .filter(|&distance| distance >= group)
    {
        code.asm().mov(Size::Qword, Rdx, Rax);
        shift(code, ShiftOp::Shr, Rdx, distance);
        code.asm().alu(Alu::Or, Size::Qword, Rax, Rdx);
        and_mask(code, low_group_mask(distance * 2));
    }
    code.asm().mov(Size::Dword, Rax, Rax);
}
fn permutation(
    code: &mut Code,
    operation: Permutation,
    element: ElementSize,
    chunk: usize,
    length: VectorLength,
) {
    let group = element.bytes();
    match operation {
        Permutation::Zip { high } => {
            let bit = usize::from(high) * length.bytes() / 2 + chunk * HALF_CHUNK_BITS;
            load_bits(code, 0, bit);
            spread(code, group, length.bytes().min(CHUNK_BITS));
            code.asm().mov(Size::Qword, Rcx, Rax);
            load_bits(code, SOURCE_SLOT_BYTES, bit);
            spread(code, group, length.bytes().min(CHUNK_BITS));
            shift(code, ShiftOp::Shl, Rax, group);
            code.asm().alu(Alu::Or, Size::Qword, Rax, Rcx);
        }
        Permutation::Transpose { odd } => {
            load_snapshot(code, chunk * CHUNK_BYTES);
            shift(code, ShiftOp::Shr, Rax, usize::from(odd) * group);
            and_mask(code, low_group_mask(group));
            code.asm().mov(Size::Qword, Rcx, Rax);
            load_snapshot(code, SOURCE_SLOT_BYTES + chunk * CHUNK_BYTES);
            shift(code, ShiftOp::Shr, Rax, usize::from(odd) * group);
            and_mask(code, low_group_mask(group));
            shift(code, ShiftOp::Shl, Rax, group);
            code.asm().alu(Alu::Or, Size::Qword, Rax, Rcx);
        }
        Permutation::Unzip { odd } => {
            if length.bytes() <= CHUNK_BITS {
                load_snapshot(code, 0);
                compact(code, group, odd);
                code.asm().mov(Size::Qword, Rcx, Rax);
                load_snapshot(code, SOURCE_SLOT_BYTES);
                compact(code, group, odd);
                shift(code, ShiftOp::Shl, Rax, length.bytes() / 2);
                code.asm().alu(Alu::Or, Size::Qword, Rax, Rcx);
            } else {
                let half = length.bytes() / 2;
                let bit = chunk * CHUNK_BITS;
                let slot = if bit < half { 0 } else { SOURCE_SLOT_BYTES };
                let source_chunk = (bit % half) / HALF_CHUNK_BITS;
                load_snapshot(code, slot + source_chunk * CHUNK_BYTES);
                compact(code, group, odd);
                code.asm().mov(Size::Qword, Rcx, Rax);
                load_snapshot(code, slot + (source_chunk + 1) * CHUNK_BYTES);
                compact(code, group, odd);
                shift(code, ShiftOp::Shl, Rax, HALF_CHUNK_BITS);
                code.asm().alu(Alu::Or, Size::Qword, Rax, Rcx);
            }
        }
    }
}

fn dilate(code: &mut Code, stride: usize) {
    if stride == 1 {
        return;
    }
    let input_bits = CHUNK_BITS / stride;
    // The first dilation mask discards unused low32 bits; this clears the
    // only higher bits that could otherwise overlap its groups.
    code.asm().mov(Size::Dword, Rax, Rax);
    let mut block = input_bits / 2;
    while block != 0 {
        code.asm().mov(Size::Qword, Rdx, Rax);
        shift(code, ShiftOp::Shl, Rdx, (stride - 1) * block);
        code.asm().alu(Alu::Or, Size::Qword, Rax, Rdx);
        let mask = (0..CHUNK_BITS)
            .filter(|bit| bit % (block * stride) < block)
            .fold(0, |mask, bit| mask | (1 << bit));
        and_mask(code, mask);
        block /= 2;
    }
}
