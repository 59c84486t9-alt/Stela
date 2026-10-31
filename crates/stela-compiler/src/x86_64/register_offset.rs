//! Register-offset loads and stores to private RAM.
use super::{
    Access, AddressMode, MemoryTransfer, Register, Shift, Width, memory_address, memory_store,
    offset, right_operand,
};
use crate::aarch64::register_offset::{IndexExtend, Operand};
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, ShiftOp, Size};

pub(super) fn emit(code: &mut Code, operand: &Operand, checks: super::MemoryChecks) {
    address(
        code,
        checks,
        IndexedAddress::new(operand.base, operand.index, operand.extend, operand.shift),
        operand.bytes,
        operand.transfer == MemoryTransfer::Store,
    );
    transfer(code, operand);
}

/// A decoded base, index extension and scale.
#[derive(Clone, Copy)]
pub(super) struct IndexedAddress {
    base: Register,
    index: Register,
    extend: IndexExtend,
    shift: u8,
}

impl IndexedAddress {
    pub(super) const fn new(
        base: Register,
        index: Register,
        extend: IndexExtend,
        shift: u8,
    ) -> Self {
        Self {
            base,
            index,
            extend,
            shift,
        }
    }
}

/// Shared integer/SIMD address calculation, without guest register writeback.
/// RAX is the result; RCX/RDX and host flags are scratch. SP is checked first,
/// and SCTLR_ELx.A checks the result against the access's `bytes`.
pub(super) fn address(
    code: &mut Code,
    checks: super::MemoryChecks,
    address: IndexedAddress,
    bytes: u8,
    write: bool,
) {
    let IndexedAddress {
        base,
        index,
        extend,
        shift,
    } = address;
    // Validate incoming SP before offset addition, even if the effective
    // address would be aligned. No guest register is committed before access.
    // Only the final address is checked against the guest's ranges.
    let base_checks = super::MemoryChecks {
        guest_range: false,
        ..checks
    };
    let access = Access::of(write, bytes.into());
    memory_address(
        code,
        base_checks,
        crate::x86_64::ImmediateAddress {
            base,
            displacement: 0,
            mode: AddressMode::Offset,
        },
        1,
        access,
    );
    index_add(code, index, extend, shift);
    super::address_checks(code, checks, bytes, access);
}

/// The largest shift a SIB scale applies (times eight).
const MAX_SCALE_SHIFT: u8 = 3;

/// The index register, extended and shifted, added to the base in RAX
/// modulo 2^64. A W index is read with its extension from its frame slot;
/// a ZR index adds nothing. RCX and host flags are scratch.
pub(crate) fn index_add(code: &mut Code, index: Register, extend: IndexExtend, shift: u8) {
    let Some(slot) = offset(index) else {
        return;
    };
    let state = Mem::base_disp32(Gpr::Rdi, slot as i32);
    let mut asm = code.asm();
    match extend {
        IndexExtend::Uxtw => asm.mov_load(Size::Dword, Gpr::Rcx, state),
        IndexExtend::Sxtw => asm.movsxd(Gpr::Rcx, state),
        IndexExtend::Lsl | IndexExtend::Sxtx if shift == 0 => {
            asm.alu_load(Alu::Add, Size::Qword, Gpr::Rax, state);
            return;
        }
        IndexExtend::Lsl | IndexExtend::Sxtx => asm.mov_load(Size::Qword, Gpr::Rcx, state),
    }
    let scale = if shift > MAX_SCALE_SHIFT {
        asm.shift_imm(ShiftOp::Shl, Size::Qword, Gpr::Rcx, shift);
        0
    } else {
        shift
    };
    // RAX + RCX * 2^scale, the SIB scale applying the shift.
    asm.lea(
        Size::Qword,
        Gpr::Rax,
        Mem::indexed(Gpr::Rax, Gpr::Rcx, 1 << scale, 0),
    );
}

fn transfer(code: &mut Code, operand: &Operand) {
    match operand.transfer {
        MemoryTransfer::Store => {
            right_operand(code, operand.data, Width::X64, Shift::Lsl, 0);
            memory_store::emit(code, operand.bytes, 0, memory_store::Source::Rcx);
        }
        MemoryTransfer::Load { signed, width } => {
            let size = Size::of(width == Width::X64);
            let address = Mem::base(Gpr::Rax, 0);
            let mut asm = code.asm();
            asm.guest_access(|asm| match (operand.bytes, signed) {
                (1, false) => asm.movzx(size, Gpr::Rcx, Size::Byte, address),
                (2, false) => asm.movzx(size, Gpr::Rcx, Size::Word, address),
                (1, true) => asm.movsx(size, Gpr::Rcx, Size::Byte, address),
                (2, true) => asm.movsx(size, Gpr::Rcx, Size::Word, address),
                (4, true) => {
                    debug_assert!(size == Size::Qword);
                    asm.movsxd(Gpr::Rcx, address);
                }
                (4 | 8, false) => asm.mov_load(size, Gpr::Rcx, address),
                _ => unreachable!("decoder validates signed register-offset size"),
            });
            // A load to ZR still accesses memory and can fault.
            if let Some(displacement) = offset(operand.data) {
                asm.mov_store(
                    Size::Qword,
                    Mem::base_disp32(Gpr::Rdi, displacement as i32),
                    Gpr::Rcx,
                );
            }
        }
    }
    // This addressing class never performs base writeback.
    debug_assert!(operand.base != Register::Zero);
}
