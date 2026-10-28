//! SVE extraction and broadcast (SSE2) and insertion (SSSE3).
use crate::x86_64::asm::Gpr::{R8, Rax, Rcx, Rsp};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, Rm, Size};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VECTOR_REGISTER_COUNT, VectorLength},
        sve::rearrange_extract::{Destination, Kind, LastPosition, Operand},
    },
    x86_64::{
        isa::{ShiftOpcode as Shift, SimdOpcode as Host},
        load,
        scalable::{clear_z_upper, load_z_chunk, read_predicate_chunk, store_z_chunk},
        store,
    },
};
use alloc::vec::Vec;

const VALUE_XMM: u8 = 0;
const INSERT_XMM: u8 = 1;
const PREVIOUS_XMM: u8 = 2;
const ZERO_XMM: u8 = 3;
const LOW_DWORD_CONTROL: u8 = 0;
const PREDICATE_CHUNK_BITS: usize = u64::BITS as usize;
const PREDICATE_CHUNK_BYTES: usize = core::mem::size_of::<u64>();
const STAGING_FRAME_BYTES: u8 = VECTOR_CHUNK_BYTES as u8;
const CHUNK_OFFSET_MASK: u8 = (VECTOR_CHUNK_BYTES - 1) as u8;
const GOVERNING_PREDICATE_COUNT: u8 = 8;
const INDEXED_SOURCE_BYTES: usize = 64;

fn packed(code: &mut Code, opcode: Host, destination: u8, source: u8, target: TargetCpu) {
    opcode.register(code, destination, source, target);
}

fn narrow_general(code: &mut Code, element: ElementSize) {
    let mut asm = code.asm();
    match element {
        ElementSize::Byte => asm.movzx(Size::Dword, Rax, Size::Byte, Rax),
        ElementSize::Halfword => asm.movzx(Size::Dword, Rax, Size::Word, Rax),
        ElementSize::Word => asm.mov(Size::Dword, Rax, Rax),
        ElementSize::Doubleword => {}
        ElementSize::Quadword => unreachable!("general extraction has at most 64 bits"),
    }
}

fn move_rax(code: &mut Code, register: u8, target: TargetCpu) {
    code.asm().simd(Host::MoveGprQword, register, Rax, target);
}

fn broadcast(code: &mut Code, element: ElementSize, target: TargetCpu) {
    match element {
        ElementSize::Byte => {
            packed(code, Host::UnpackLowByte, VALUE_XMM, VALUE_XMM, target);
            packed(code, Host::UnpackLowWord, VALUE_XMM, VALUE_XMM, target);
        }
        ElementSize::Halfword => {
            packed(code, Host::UnpackLowWord, VALUE_XMM, VALUE_XMM, target);
        }
        ElementSize::Word => {}
        ElementSize::Doubleword => {
            packed(code, Host::UnpackLowQword, VALUE_XMM, VALUE_XMM, target);
            return;
        }
        ElementSize::Quadword => return,
    }
    code.asm().simd_imm(
        Host::ShuffleDword,
        VALUE_XMM,
        Rm::Xmm(VALUE_XMM),
        LOW_DWORD_CONTROL,
        target,
    );
}

fn broadcast_last(code: &mut Code, element: ElementSize, target: TargetCpu) {
    if element == ElementSize::Byte && target.supports(TargetCpu::Ssse3) {
        packed(code, Host::Xor, ZERO_XMM, ZERO_XMM, target);
        packed(code, Host::ByteShuffle, VALUE_XMM, ZERO_XMM, target);
    } else {
        broadcast(code, element, target);
    }
}

fn store_broadcast(code: &mut Code, destination: u8, length: VectorLength, target: TargetCpu) {
    for chunk in 0..length.chunks() {
        store_z_chunk(code, destination, chunk, VALUE_XMM, length, target);
    }
}

fn predicate_start_mask(element: ElementSize) -> u64 {
    let mut mask = 0;
    for bit in (0..PREDICATE_CHUNK_BITS).step_by(element.bytes()) {
        mask |= 1u64 << bit;
    }
    mask
}

fn emit_last(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
    let Kind::Last {
        source,
        predicate,
        position,
        conditional,
    } = operand.kind
    else {
        unreachable!("extraction recipe requires LAST operands");
    };
    if operand.destination == Destination::General(Register::Zero) {
        // Shared instruction permission checks still precede this recipe.
        code.asm().nop();
        return;
    }
    let mut found = Vec::new();
    let mut finished = Vec::new();
    let chunks = length.predicate_bytes().div_ceil(PREDICATE_CHUNK_BYTES);
    for chunk in (0..chunks).rev() {
        read_predicate_chunk(code, predicate, chunk, length);
        if operand.element_size != ElementSize::Byte {
            let mut asm = code.asm();
            asm.mov_imm64(Rcx, predicate_start_mask(operand.element_size));
            asm.alu(Alu::And, Size::Qword, Rax, Rcx);
        }
        let mut asm = code.asm();
        asm.test(Size::Qword, Rax, Rax);
        let empty = asm.jcc(Cond::E);
        asm.bsr(Size::Qword, R8, Rax);
        if chunk != 0 {
            asm.alu_imm32(
                Alu::Or,
                Size::Dword,
                R8,
                (chunk * PREDICATE_CHUNK_BITS) as i32,
            );
        }
        found.push(asm.jmp());
        asm.bind(empty);
    }
    let mut scalar_fallback = None;
    let mut unconditional_fallback = None;
    if conditional {
        match operand.destination {
            Destination::Vector(_) => finished.push(code.asm().jmp()),
            Destination::General(destination) => {
                load(code, destination);
                narrow_general(code, operand.element_size);
                store(code, destination);
                finished.push(code.asm().jmp());
            }
            Destination::Scalar(destination) => {
                load_z_chunk(code, destination, 0, VALUE_XMM, length, target);
                let mut asm = code.asm();
                asm.alu(Alu::Xor, Size::Dword, R8, R8);
                scalar_fallback = Some(asm.jmp());
            }
        }
    } else {
        let offset = if position == LastPosition::LastActive {
            length.bytes() - operand.element_size.bytes()
        } else {
            0
        };
        let mut asm = code.asm();
        asm.mov_imm32(R8, offset as u32);
        unconditional_fallback = Some(asm.jmp());
    }
    let mut asm = code.asm();
    for branch in found {
        asm.bind(branch);
    }
    if position == LastPosition::AfterLastActive {
        asm.alu_imm8(
            Alu::Add,
            Size::Dword,
            R8,
            operand.element_size.bytes() as i8,
        );
        asm.alu_imm32(Alu::And, Size::Dword, R8, (length.bytes() - 1) as i32);
    }
    if let Some(branch) = unconditional_fallback {
        asm.bind(branch);
    }
    let mut loaded = Vec::new();
    for chunk in (1..length.chunks()).rev() {
        let mut asm = code.asm();
        asm.alu_imm32(
            Alu::Cmp,
            Size::Dword,
            R8,
            (chunk * VECTOR_CHUNK_BYTES) as i32,
        );
        let lower = asm.jcc(Cond::B);
        load_z_chunk(code, source, chunk, VALUE_XMM, length, target);
        let mut asm = code.asm();
        loaded.push(asm.jmp());
        asm.bind(lower);
    }
    load_z_chunk(code, source, 0, VALUE_XMM, length, target);
    let mut asm = code.asm();
    for branch in loaded.into_iter().chain(scalar_fallback) {
        asm.bind(branch);
    }
    asm.alu_imm8(Alu::And, Size::Dword, R8, CHUNK_OFFSET_MASK as i8);
    // Only the selected 16-byte chunk is staged, in the same bounded frame for
    // every path.
    asm.alu_imm8(Alu::Sub, Size::Qword, Rsp, STAGING_FRAME_BYTES as i8);
    asm.movdqu_store(Mem::base(Rsp, 0), 0);
    let lane = Mem::indexed(Rsp, R8, 1, 0);
    match operand.element_size {
        ElementSize::Byte => asm.movzx(Size::Dword, Rax, Size::Byte, lane),
        ElementSize::Halfword => asm.movzx(Size::Dword, Rax, Size::Word, lane),
        ElementSize::Word => asm.mov_load(Size::Dword, Rax, lane),
        ElementSize::Doubleword => asm.mov_load(Size::Qword, Rax, lane),
        ElementSize::Quadword => unreachable!("LAST excludes 128-bit elements"),
    }
    asm.alu_imm8(Alu::Add, Size::Qword, Rsp, STAGING_FRAME_BYTES as i8);
    match operand.destination {
        Destination::General(destination) => store(code, destination),
        Destination::Scalar(destination) => {
            move_rax(code, VALUE_XMM, target);
            store_z_chunk(code, destination, 0, VALUE_XMM, length, target);
            clear_z_upper(code, destination, ZERO_XMM, length, target);
        }
        Destination::Vector(destination) => {
            move_rax(code, VALUE_XMM, target);
            broadcast_last(code, operand.element_size, target);
            store_broadcast(code, destination, length, target);
        }
    }
    let mut asm = code.asm();
    for branch in finished {
        asm.bind(branch);
    }
}

fn emit_insert(
    code: &mut Code,
    destination: u8,
    element: ElementSize,
    length: VectorLength,
    target: TargetCpu,
) {
    let width = element.bytes() as u8;
    let carry = VECTOR_CHUNK_BYTES as u8 - width;
    for chunk in (1..length.chunks()).rev() {
        load_z_chunk(code, destination, chunk, VALUE_XMM, length, target);
        load_z_chunk(code, destination, chunk - 1, PREVIOUS_XMM, length, target);
        if target.supports(TargetCpu::Ssse3) {
            code.asm().simd_imm(
                Host::AlignBytes,
                VALUE_XMM,
                Rm::Xmm(PREVIOUS_XMM),
                carry,
                target,
            );
        } else {
            Shift::LeftBytes.emit(code, VALUE_XMM, width);
            Shift::RightBytes.emit(code, PREVIOUS_XMM, carry);
            packed(code, Host::Or, VALUE_XMM, PREVIOUS_XMM, target);
        }
        store_z_chunk(code, destination, chunk, VALUE_XMM, length, target);
    }
    load_z_chunk(code, destination, 0, VALUE_XMM, length, target);
    Shift::LeftBytes.emit(code, VALUE_XMM, width);
    packed(code, Host::Or, VALUE_XMM, INSERT_XMM, target);
    store_z_chunk(code, destination, 0, VALUE_XMM, length, target);
}

fn valid(operand: Operand) -> bool {
    let vector = |register| register < VECTOR_REGISTER_COUNT;
    let general =
        |register| !matches!(register, Register::X(index) if index >= VECTOR_REGISTER_COUNT - 1);
    match operand.destination {
        Destination::General(register) if !general(register) || register == Register::Sp => {
            return false;
        }
        Destination::Scalar(register) | Destination::Vector(register) if !vector(register) => {
            return false;
        }
        _ => {}
    }
    if operand.element_size == ElementSize::Quadword
        && !matches!(operand.kind, Kind::DuplicateElement { .. })
    {
        return false;
    }
    match operand.kind {
        Kind::Last {
            source,
            predicate,
            conditional,
            ..
        } => {
            vector(source)
                && predicate < GOVERNING_PREDICATE_COUNT
                && (conditional || !matches!(operand.destination, Destination::Vector(_)))
        }
        Kind::DuplicateImmediate(_) => matches!(operand.destination, Destination::Vector(_)),
        Kind::DuplicateGeneral(register) => {
            general(register)
                && register != Register::Zero
                && matches!(operand.destination, Destination::Vector(_))
        }
        Kind::DuplicateElement { source, index } => {
            vector(source)
                && usize::from(index) < INDEXED_SOURCE_BYTES / operand.element_size.bytes()
                && matches!(operand.destination, Destination::Vector(_))
        }
        Kind::InsertGeneral(register) => {
            general(register)
                && register != Register::Sp
                && matches!(operand.destination, Destination::Vector(_))
        }
        Kind::InsertScalar(source) => {
            vector(source) && matches!(operand.destination, Destination::Vector(_))
        }
    }
}

/// Emit a decoded register-only operation after shared streaming permission checks.
/// Uses caller-saved RAX/RCX/RDX/R8 and XMM0..3, preserving RDI/R15 and MXCSR.
pub fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
    assert!(
        valid(operand),
        "extraction emitter requires validated operands"
    );
    if matches!(operand.kind, Kind::Last { .. }) {
        emit_last(code, operand, length, target);
        return;
    }
    let Destination::Vector(destination) = operand.destination else {
        unreachable!("validated broadcast/insertion destination");
    };
    match operand.kind {
        Kind::DuplicateImmediate(immediate) => {
            let mut asm = code.asm();
            if operand.element_size == ElementSize::Doubleword {
                asm.mov_rm_imm32(Size::Qword, Rax, i32::from(immediate));
            } else {
                asm.mov_imm32(Rax, i32::from(immediate) as u32);
            }
            move_rax(code, VALUE_XMM, target);
        }
        Kind::DuplicateGeneral(source) => {
            load(code, source);
            move_rax(code, VALUE_XMM, target);
        }
        Kind::DuplicateElement { source, index } => {
            let offset = usize::from(index) * operand.element_size.bytes();
            if offset < length.bytes() {
                load_z_chunk(
                    code,
                    source,
                    offset / VECTOR_CHUNK_BYTES,
                    VALUE_XMM,
                    length,
                    target,
                );
                if !offset.is_multiple_of(VECTOR_CHUNK_BYTES) {
                    Shift::RightBytes.emit(code, VALUE_XMM, (offset % VECTOR_CHUNK_BYTES) as u8);
                }
            } else {
                packed(code, Host::Xor, VALUE_XMM, VALUE_XMM, target);
            }
        }
        Kind::InsertGeneral(source) => {
            load(code, source);
            narrow_general(code, operand.element_size);
            move_rax(code, INSERT_XMM, target);
            emit_insert(code, destination, operand.element_size, length, target);
            return;
        }
        Kind::InsertScalar(source) => {
            load_z_chunk(code, source, 0, INSERT_XMM, length, target);
            let shift = (VECTOR_CHUNK_BYTES - operand.element_size.bytes()) as u8;
            Shift::LeftBytes.emit(code, INSERT_XMM, shift);
            Shift::RightBytes.emit(code, INSERT_XMM, shift);
            emit_insert(code, destination, operand.element_size, length, target);
            return;
        }
        Kind::Last { .. } => unreachable!("extraction handled above"),
    }
    broadcast(code, operand.element_size, target);
    store_broadcast(code, destination, length, target);
}
