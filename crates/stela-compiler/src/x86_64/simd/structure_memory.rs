//! Structured loads and stores, with an element-by-element path across page
//! boundaries.
use super::{commit, vector_offset};
use crate::TargetCpu;
use crate::aarch64::simd::structure_memory::{
    Access, Direction, Layout, LoadCommit, Operand, PostIndex,
};
use crate::aarch64::{AddressMode, Register};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, Size};
use crate::x86_64::simd::encode::guest;

mod multiple;
mod single;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const STACK_ALIGNMENT_BYTES: u8 = 16;

/// The operand size of a `bytes`-byte element.
fn size(bytes: u8) -> Size {
    match bytes {
        BYTE_BYTES => Size::Byte,
        HALFWORD_BYTES => Size::Word,
        DWORD_BYTES => Size::Dword,
        QWORD_BYTES => Size::Qword,
        _ => unreachable!("decoder validates scalar structure width"),
    }
}

/// `[rax + displacement]`, the element at `displacement` in the footprint.
fn element(displacement: u8) -> Mem {
    Mem::base(Gpr::Rax, displacement.into())
}

pub(super) fn emit(
    code: &mut Code,
    operand: &Operand,
    target: TargetCpu,
    checks: super::super::MemoryChecks,
) {
    // This reuses the incoming-SP check before any guest RAM access.
    // SCTLR_ELx.A checks each element: all are aligned when the first is.
    super::super::memory_address(
        code,
        checks,
        operand.base,
        0,
        AddressMode::Offset,
        operand.element_bytes,
        super::super::Access::of(
            operand.direction == Direction::Store,
            operand.transferred_bytes().into(),
        ),
    );
    match operand.post_index {
        PostIndex::None => {}
        PostIndex::TransferredBytes => {
            code.asm().lea(
                Size::Qword,
                Gpr::Rdx,
                Mem::base_disp32(Gpr::Rax, operand.transferred_bytes().into()),
            );
        }
        PostIndex::Register(index) => {
            scalar_state_transfer(
                code,
                false,
                QWORD_BYTES,
                super::super::offset(Register::X(index)).expect("post-index is X0..X30"),
            );
            // The address plus the post-index register.
            code.asm().lea(
                Size::Qword,
                Gpr::Rdx,
                Mem::indexed(Gpr::Rax, Gpr::Rcx, 1, 0),
            );
        }
    }
    // A checked SP is 16-byte aligned; an unchecked one is an ordinary base.
    let aligned_sp = operand.base == Register::Sp && checks.stack_alignment;
    if operand.transferred_bytes() == BYTE_BYTES
        || (aligned_sp && operand.transferred_bytes() <= STACK_ALIGNMENT_BYTES)
    {
        packed(code, operand, target);
    } else {
        // N <= 64: bit12 changes exactly when this footprint crosses a 4KiB
        // boundary, including wrapping addresses. No memory is read by the guard.
        let mut asm = code.asm();
        asm.lea(
            Size::Dword,
            Gpr::R10,
            Mem::base_disp8(Gpr::Rax, (operand.transferred_bytes() - 1) as i8),
        );
        asm.alu(Alu::Xor, Size::Dword, Gpr::R10, Gpr::Rax);
        asm.test_imm(
            Size::Dword,
            Gpr::R10,
            super::super::memory_store::PROTECTION_GRANULE_BYTES as i32,
        );
        let crossing_jump = asm.jcc(Cond::Ne).offset();
        packed(code, operand, target);
        let complete_jump = code.asm().jmp().offset();
        patch_jump(code, crossing_jump);
        ordered(code, operand, aligned_sp);
        patch_jump(code, complete_jump);
    }
    if operand.post_index != PostIndex::None {
        super::super::memory_writeback(code, operand.base, AddressMode::PostIndex);
    }
}

fn packed(code: &mut Code, operand: &Operand, target: TargetCpu) {
    match operand.layout {
        Layout::Multiple { .. } => multiple::packed(code, operand, target),
        Layout::Lane { .. } | Layout::Replicate { .. } => single::packed(code, operand, target),
    }
}

/// Source-width accesses and immediate successful assignments. RDX/RDI survive;
/// RAX advances through the footprint, RCX/R10/XMM0 are scratch.
fn ordered(code: &mut Code, operand: &Operand, aligned_sp: bool) {
    let count = operand.transferred_bytes() / operand.element_bytes;
    for (ordinal, access) in operand.accesses().enumerate() {
        transfer_access(code, operand, access, 0, false, aligned_sp);
        if ordinal + 1 != usize::from(count) {
            code.asm().alu_imm8(
                Alu::Add,
                Size::Qword,
                Gpr::Rax,
                operand.element_bytes as i8,
            );
        }
    }
}

/// The whole footprint is within one granule, so elements are accessed at fixed
/// displacements without per-element store guards.
fn ordered_in_granule(code: &mut Code, operand: &Operand) {
    for access in operand.accesses() {
        transfer_access(code, operand, access, access.byte_offset, true, false);
    }
}

fn transfer_access(
    code: &mut Code,
    operand: &Operand,
    access: Access,
    displacement: u8,
    in_granule: bool,
    aligned_sp: bool,
) {
    match (operand.direction, access.commit) {
        (Direction::Load, LoadCommit::Lane { index, clear_upper }) => {
            element_load(code, operand.element_bytes, displacement);
            scalar_state_transfer(
                code,
                true,
                operand.element_bytes,
                vector_offset(access.vector) + u32::from(index * operand.element_bytes),
            );
            if clear_upper {
                code.asm().mov_rm_imm32(
                    Size::Qword,
                    guest(vector_offset(access.vector) + u32::from(QWORD_BYTES)),
                    0,
                );
            }
        }
        (Direction::Load, LoadCommit::Replicate { vector_bytes }) => {
            element_load(code, operand.element_bytes, displacement);
            single::broadcast(code, operand.element_bytes, vector_bytes);
            commit(code, access.vector, 0);
        }
        (Direction::Store, LoadCommit::Lane { index, .. }) => {
            scalar_state_transfer(
                code,
                false,
                operand.element_bytes,
                vector_offset(access.vector) + u32::from(index * operand.element_bytes),
            );
            if in_granule {
                element_store(code, operand.element_bytes, displacement);
            } else {
                super::super::memory_store::emit(
                    code,
                    operand.element_bytes,
                    0,
                    super::super::memory_store::Source::Rcx,
                    aligned_sp,
                );
            }
        }
        (Direction::Store, LoadCommit::Replicate { .. }) => {
            unreachable!("replicate encodings are load-only")
        }
    }
}

/// Exact-width RAM read into zero-extended RCX; no guest state commit yet.
fn element_load(code: &mut Code, bytes: u8, displacement: u8) {
    let mut asm = code.asm();
    match bytes {
        BYTE_BYTES | HALFWORD_BYTES => {
            asm.movzx(Size::Dword, Gpr::Rcx, size(bytes), element(displacement));
        }
        _ => asm.mov_load(size(bytes), Gpr::Rcx, element(displacement)),
    }
}

/// Exact scalar RCX store, used only after the whole-footprint granule proof.
fn element_store(code: &mut Code, bytes: u8, displacement: u8) {
    code.asm()
        .mov_store(size(bytes), element(displacement), Gpr::Rcx);
}

/// true writes RCX to the selected state lane; false reads it into RCX.
fn scalar_state_transfer(code: &mut Code, load: bool, bytes: u8, state_offset: u32) {
    let lane = guest(state_offset);
    let mut asm = code.asm();
    if load {
        asm.mov_store(size(bytes), lane, Gpr::Rcx);
    } else if bytes <= HALFWORD_BYTES {
        asm.movzx(Size::Dword, Gpr::Rcx, size(bytes), lane);
    } else {
        asm.mov_load(size(bytes), Gpr::Rcx, lane);
    }
}

fn patch_jump(code: &mut [u8], offset: usize) {
    let displacement = i32::try_from(code.len() - offset - size_of::<i32>())
        .expect("bounded structure-transfer body");
    code[offset..offset + size_of::<i32>()].copy_from_slice(&displacement.to_le_bytes());
}
