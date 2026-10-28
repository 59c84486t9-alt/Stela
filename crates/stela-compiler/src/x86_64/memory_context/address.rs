//! SP alignment checks and address arithmetic for checked accesses.
use super::fault;
use crate::x86_64::asm::{Code, Cond, Gpr, Mem, Patch, Size};
use crate::x86_64::load;
use crate::{
    aarch64::{AddressMode, Register, register_offset::IndexExtend},
    context::memory::{MemoryStatus, address::AddressAddChecks},
};

const STACK_ALIGNMENT_MASK: u8 = 15;

/// Check SP before the offset is applied. The caller resolves the returned
/// branch to its cleanup. On failure RAX holds the faulting SP. Clobbers RAX/RCX/RDX
/// and flags.
pub(crate) fn check_sp(code: &mut Code, base: Register, pc: u64) -> Option<Patch> {
    if base != Register::Sp {
        return None;
    }
    load(code, Register::Sp);
    let mut asm = code.asm();
    asm.test_accumulator_imm(Size::Byte, STACK_ALIGNMENT_MASK.into());
    let aligned = asm.jcc(Cond::E);
    fault(code, MemoryStatus::StackAlignment, pc);
    let mut asm = code.asm();
    let failed = asm.jmp();
    asm.bind(aligned);
    Some(failed)
}

/// Return only after scratch cleanup. The checked outer CALL wrapper owns R15.
/// The runtime inspects the fault view before interpreting native block returns.
pub(crate) fn return_if_failed(code: &mut Code) {
    let mut asm = code.asm();
    asm.test(Size::Dword, Gpr::Rax, Gpr::Rax);
    let succeeded = asm.jcc8(Cond::E);
    asm.ret();
    asm.bind(succeeded);
}

/// Unchecked arithmetic AFTER check_sp ([`crate::x86_64::address_add`]).
/// Snapshot pending writeback before callbacks; commit only on full success.
pub(crate) fn immediate(code: &mut Code, base: Register, displacement: i32, mode: AddressMode) {
    load(code, base);
    crate::x86_64::address_add(code, displacement, mode);
}

/// AddressAdd at the access level's resolved specialization, after the SP check
/// and store staging. RAX is the access address; pre- and post-index forms also
/// leave the pending writeback in RDX. Post-index keeps the original access
/// address and marks only the writeback.
pub(crate) fn immediate_with_checks(
    code: &mut Code,
    base: Register,
    displacement: i32,
    mode: AddressMode,
    checks: AddressAddChecks,
) {
    // Marking a zero offset is idempotent, even on an already marked base.
    if checks == AddressAddChecks::Disabled || displacement == 0 {
        immediate(code, base, displacement, mode);
        return;
    }
    load(code, base);
    let mut asm = code.asm();
    asm.mov(Size::Qword, Gpr::Rdx, Gpr::Rax);
    if mode == AddressMode::PostIndex {
        asm.mov(Size::Qword, Gpr::R8, Gpr::Rax);
    }
    // A nonzero displacement: disp8 when it fits, else disp32.
    asm.lea(Size::Qword, Gpr::Rax, Mem::base(Gpr::Rax, displacement));
    // The CPA recipe preserves RDX and, without multiplication, R8.
    // RAX/RCX/R9/R10/R11 and flags are scratch.
    crate::x86_64::pointer_checks::emit(code, false);
    let mut asm = code.asm();
    if mode != AddressMode::Offset {
        asm.mov(Size::Qword, Gpr::Rdx, Gpr::Rax);
    }
    if mode == AddressMode::PostIndex {
        asm.mov(Size::Qword, Gpr::Rax, Gpr::R8);
    }
}

/// Unchecked arithmetic AFTER check_sp. RAX=EA; no base writeback. Operands are
/// the existing validated decoder types, including W extension and ZR index.
pub(crate) fn register_offset(
    code: &mut Code,
    base: Register,
    index: Register,
    extend: IndexExtend,
    shift: u8,
) {
    load(code, base);
    crate::x86_64::register_offset::index_add(code, index, extend, shift);
}

/// AddressAdd for an extended or shifted register offset. RAX is the effective
/// address and RDX keeps the base. There is no writeback.
pub(crate) fn register_offset_with_checks(
    code: &mut Code,
    base: Register,
    index: Register,
    extend: IndexExtend,
    shift: u8,
    checks: AddressAddChecks,
) {
    if checks == AddressAddChecks::Disabled {
        register_offset(code, base, index, extend, shift);
        return;
    }
    load(code, base);
    if index == Register::Zero {
        return;
    }
    code.asm().mov(Size::Qword, Gpr::Rdx, Gpr::Rax);
    crate::x86_64::register_offset::index_add(code, index, extend, shift);
    crate::x86_64::pointer_checks::emit(code, false);
}
