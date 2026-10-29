//! LSE atomics. RDX holds the checked guest address on entry.
use super::{load, offset, store};
use crate::aarch64::{
    Register,
    atomic::{Kind, Operand},
};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, Size};

mod compare_exchange;
mod compare_exchange_pair;
mod read_modify_write;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const ATOMIC_GRANULE_BYTES: u8 = 16;
const DOUBLEWORD_PAIR_BYTES: u8 = 2 * QWORD_BYTES;
const ATOMIC_GRANULE_MASK: u8 = ATOMIC_GRANULE_BYTES - 1;
/// `[rdx]`, the checked guest address.
const ADDRESS: Mem = Mem::base(Gpr::Rdx, 0);

/// The operand size of a `bytes`-wide access.
fn size(bytes: u8) -> Size {
    match bytes {
        BYTE_BYTES => Size::Byte,
        HALFWORD_BYTES => Size::Word,
        DWORD_BYTES => Size::Dword,
        QWORD_BYTES => Size::Qword,
        _ => unreachable!("decoder validates atomic widths"),
    }
}

/// A CASP of two doublewords needs CMPXCHG16B, unless it is a plain access
/// ([`super::plain_ordering`]).
pub(super) fn requires_cx16(
    operand: &Operand,
    target: crate::TargetCpu,
    checks: super::MemoryChecks,
) -> bool {
    matches!(operand.kind, Kind::CompareExchangePair { .. })
        && operand.bytes == DOUBLEWORD_PAIR_BYTES
        && !super::plain_ordering(target, checks)
}

/// Locked x86 updates, or for a single agent ([`super::plain_ordering`]) a
/// plain load, the update and a plain store. The plain recipes load first,
/// so a translation, Access flag or read-permission fault reports WnR 0 and
/// a store to read-only memory WnR 1, as Arm requires of an atomic that
/// reads and writes (ESR_ELx.WnR); a locked x86 update faults as a write.
pub(super) fn emit(
    code: &mut Code,
    operand: &Operand,
    target: crate::TargetCpu,
    checks: super::MemoryChecks,
) {
    let plain = super::plain_ordering(target, checks);
    address(code, operand.base, operand.bytes, checks);
    match operand.kind {
        Kind::CompareExchange { .. } => compare_exchange::emit(code, operand, plain),
        Kind::CompareExchangePair { .. } => {
            compare_exchange_pair::emit(code, operand, target, plain)
        }
        Kind::ReadModifyWrite { .. } => read_modify_write::emit(code, operand, plain),
    }
}

/// SP is checked first. LSE2 accesses must fit the selected aligned 16-byte granule.
/// RAX/RCX are scratch, RDX receives the address, and guest state is untouched.
pub(super) fn address(code: &mut Code, base: Register, bytes: u8, checks: super::MemoryChecks) {
    let access = super::Access::write(bytes.into()).atomic();
    address_offset(code, base, bytes, 0, checks, true, access);
}

/// Check SP before adding the displacement. SCTLR_ELx.A and then, with
/// `granule`, the single-copy-atomic boundary apply to the effective address;
/// a known-aligned SP needs no run-time boundary test. Without the SP
/// alignment check, SP is an ordinary base.
pub(super) fn address_offset(
    code: &mut Code,
    base: Register,
    bytes: u8,
    displacement: i32,
    checks: super::MemoryChecks,
    granule: bool,
    access: super::Access,
) {
    load(code, base);
    let aligned_sp = base == Register::Sp && checks.stack_alignment;
    if aligned_sp {
        let mut asm = code.asm();
        asm.test_accumulator_imm(Size::Byte, ATOMIC_GRANULE_MASK.into());
        let aligned = asm.jcc8(Cond::E);
        asm.guest_check();
        asm.bind(aligned);
    }
    if displacement != 0 {
        code.asm()
            .alu_accumulator_imm32(Alu::Add, Size::Qword, displacement);
    }
    super::address_checks(code, checks, bytes, access);
    if granule && bytes != BYTE_BYTES {
        let mut asm = code.asm();
        if !aligned_sp {
            asm.mov(Size::Dword, Gpr::Rcx, Gpr::Rax);
            asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rcx, ATOMIC_GRANULE_MASK as i8);
            asm.alu_byte_imm(Alu::Cmp, Gpr::Rcx, ATOMIC_GRANULE_BYTES - bytes);
            let within = asm.jcc8(Cond::Be);
            asm.guest_check();
            asm.bind(within);
        } else if displacement.rem_euclid(i32::from(ATOMIC_GRANULE_BYTES))
            > i32::from(ATOMIC_GRANULE_BYTES - bytes)
        {
            asm.guest_check();
        }
    }
    code.asm().mov(Size::Qword, Gpr::Rdx, Gpr::Rax);
}

/// The guest `register` at `bytes`, zero-extended, into `destination`.
fn input(code: &mut Code, bytes: u8, register: Register, destination: Gpr) {
    let mut asm = code.asm();
    let Some(displacement) = offset(register) else {
        asm.alu(Alu::Xor, Size::Dword, destination, destination);
        return;
    };
    let state = Mem::base_disp32(Gpr::Rdi, displacement as i32);
    match bytes {
        BYTE_BYTES | HALFWORD_BYTES => {
            asm.movzx(Size::Dword, destination, size(bytes), state);
        }
        _ => asm.mov_load(size(bytes), destination, state),
    }
}

pub(super) fn input_rax(code: &mut Code, bytes: u8, register: Register) {
    input(code, bytes, register, Gpr::Rax);
}

pub(super) fn input_rcx(code: &mut Code, bytes: u8, register: Register) {
    input(code, bytes, register, Gpr::Rcx);
}

/// [`input_rcx`] without changing the host flags: ZR is a MOV of zero.
pub(super) fn input_rcx_keeping_flags(code: &mut Code, bytes: u8, register: Register) {
    if register == Register::Zero {
        code.asm().mov_imm32(Gpr::Rcx, 0);
    } else {
        input_rcx(code, bytes, register);
    }
}

/// [`input_rax`] without changing the host flags: ZR is a MOV of zero.
pub(super) fn input_rax_keeping_flags(code: &mut Code, bytes: u8, register: Register) {
    if register == Register::Zero {
        code.asm().mov_imm32(Gpr::Rax, 0);
    } else {
        input_rax(code, bytes, register);
    }
}

pub(super) fn read_rax(code: &mut Code, bytes: u8) {
    read(code, bytes, Gpr::Rax);
}

/// [RDX] at `bytes` into R8, zero-extended.
pub(super) fn read_r8(code: &mut Code, bytes: u8) {
    read(code, bytes, Gpr::R8);
}

fn read(code: &mut Code, bytes: u8, destination: Gpr) {
    let mut asm = code.asm();
    match bytes {
        BYTE_BYTES | HALFWORD_BYTES => {
            asm.guest_access(|asm| asm.movzx(Size::Dword, destination, size(bytes), ADDRESS));
        }
        _ => asm.guest_access(|asm| asm.mov_load(size(bytes), destination, ADDRESS)),
    }
}

/// MOV of RCX's low `bytes` to [RDX].
pub(super) fn store_rcx(code: &mut Code, bytes: u8) {
    code.asm()
        .guest_access(|asm| asm.mov_store(size(bytes), ADDRESS, Gpr::Rcx));
}

/// Input staging and exact-width updates keep the complete old value zero-extended.
pub(super) fn commit_rax(code: &mut Code, bytes: u8, destination: Register) {
    debug_assert!(matches!(
        bytes,
        BYTE_BYTES | HALFWORD_BYTES | DWORD_BYTES | QWORD_BYTES
    ));
    store(code, destination);
}

/// `lock cmpxchg [rdx], source` at `bytes`.
pub(super) fn locked_compare_exchange(code: &mut Code, bytes: u8, source: Gpr) {
    let mut asm = code.asm();
    asm.guest_access(|asm| {
        asm.lock();
        asm.cmpxchg(size(bytes), ADDRESS, source)
    });
}
