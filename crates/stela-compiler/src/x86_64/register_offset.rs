//! Register-offset loads and stores to private RAM.
use super::{
    Access, AddressMode, MemoryTransfer, Register, Shift, Width, memory_address, memory_store,
    right_operand,
};
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, ShiftOp, Size};
use crate::{
    GuestAddress,
    aarch64::{
        Instruction, Operation,
        register_offset::{IndexExtend, Operand},
    },
};
use alloc::vec::Vec;

pub(super) fn emit(code: &mut Code, operand: &Operand, checks: super::MemoryChecks) {
    address(
        code,
        checks,
        IndexedAddress::of(operand),
        operand.bytes,
        operand.transfer == MemoryTransfer::Store,
    );
    let scratch = if code.is_pinned() || !code.constant_time() {
        Gpr::Rax
    } else {
        Gpr::Rcx
    };
    transfer(code, operand, scratch);
}

/// An adjacent load and store may keep their exact effective address, but
/// both accesses and the first load's architectural result stay separate.
pub(super) fn emit_load_store(
    code: &mut Code,
    source_map: &mut Vec<(GuestAddress, usize)>,
    instructions: &[Instruction],
    checks: super::MemoryChecks,
) -> bool {
    debug_assert!(!checks.checks_every_access() && !code.constant_time());
    let Some([load, store]) = instructions.first_chunk() else {
        return false;
    };
    let (Operation::MemoryRegisterOffset(first), Operation::MemoryRegisterOffset(second)) =
        (load.operation, store.operation)
    else {
        return false;
    };
    let address = IndexedAddress::of(&first);
    if !matches!(first.transfer, MemoryTransfer::Load { .. })
        || second.transfer != MemoryTransfer::Store
        || first.bytes != second.bytes
        || address != IndexedAddress::of(&second)
        || (code.is_pinned() && !checks.guest_range)
        || matches!(first.base, Register::Sp)
        || matches!(first.index, Register::Zero)
        || first.data == first.base
        || first.data == first.index
        || load.pc.0.checked_add(4) != Some(store.pc.0)
    {
        return false;
    }
    source_map.push((load.pc, code.len()));
    code.set_instruction(source_map.len() - 1);
    emit_address(
        code,
        checks,
        address,
        first.bytes,
        Access::of(false, first.bytes.into()),
        true,
    );
    transfer(code, &first, Gpr::Rcx);
    source_map.push((store.pc, code.len()));
    code.set_instruction(source_map.len() - 1);
    transfer(code, &second, Gpr::Rcx);
    true
}

/// A decoded base, index extension and scale.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct IndexedAddress {
    base: Register,
    index: Register,
    extend: IndexExtend,
    shift: u8,
}

impl IndexedAddress {
    const fn of(operand: &Operand) -> Self {
        Self::new(operand.base, operand.index, operand.extend, operand.shift)
    }

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
    emit_address(
        code,
        checks,
        address,
        bytes,
        Access::of(write, bytes.into()),
        false,
    );
}

fn emit_address(
    code: &mut Code,
    checks: super::MemoryChecks,
    address: IndexedAddress,
    bytes: u8,
    access: Access,
    shared: bool,
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
    if let (Some(host), false) = (
        code.host(base),
        checks.alignment || checks.checks_every_access(),
    ) {
        if base == Register::Sp && checks.stack_alignment && !checks.stack_checked {
            code.asm().test_imm(Size::Byte, host, 15);
            code.check_failure(crate::x86_64::asm::Cond::Ne);
        }
        code.asm().mov(Size::Qword, Gpr::Rax, host);
        index_add(code, index, extend, shift);
        if checks.guest_range {
            checks.range.emit_base(code, Gpr::Rax);
            if shared {
                // Retain the first #UD site and make both operands depend
                // on its range result even if its branch is mispredicted.
                super::unreachable_if(&mut code.asm(), super::asm::Cond::A);
            }
        }
        return;
    }
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
    let mut asm = code.asm();
    let Some(state) = asm.guest(index) else {
        return;
    };
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

fn transfer(code: &mut Code, operand: &Operand, load_scratch: Gpr) {
    match operand.transfer {
        MemoryTransfer::Store => {
            let source = match code.host(operand.data) {
                Some(host) => memory_store::Source::Host(host),
                None => {
                    right_operand(code, operand.data, Width::X64, Shift::Lsl, 0);
                    memory_store::Source::Rcx
                }
            };
            memory_store::emit(code, operand.bytes, 0, source);
        }
        MemoryTransfer::Load { signed, width } => {
            let size = Size::of(width == Width::X64);
            let address = Mem::base(Gpr::Rax, 0);
            // The result may replace the address in RAX. This leaves it
            // available to the next instruction, with no base writeback.
            let host = code.host(operand.data).unwrap_or(load_scratch);
            let mut asm = code.asm();
            asm.guest_access(|asm| match (operand.bytes, signed) {
                (1, false) => asm.movzx(size, host, Size::Byte, address),
                (2, false) => asm.movzx(size, host, Size::Word, address),
                (1, true) => asm.movsx(size, host, Size::Byte, address),
                (2, true) => asm.movsx(size, host, Size::Word, address),
                (4, true) => {
                    debug_assert!(size == Size::Qword);
                    asm.movsxd(host, address);
                }
                (4 | 8, false) => asm.mov_load(size, host, address),
                _ => unreachable!("decoder validates signed register-offset size"),
            });
            // A load to ZR still accesses memory and can fault.
            if host == load_scratch
                && let Some(data) = asm.guest(operand.data)
            {
                asm.mov_store(Size::Qword, data, host);
            }
        }
    }
    // This addressing class never performs base writeback.
    debug_assert!(operand.base != Register::Zero);
}
