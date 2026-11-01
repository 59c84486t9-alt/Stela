//! Direct stores to private RAM. A store crossing a page is one host store: x86
//! takes its fault before writing either page, and Arm leaves the locations of
//! an aborted store UNKNOWN. The protection granule is assumed to be at least
//! 4 KiB.
use crate::x86_64::asm::{Code, Gpr, Mem, Size};
pub(crate) mod checked_pair;
pub(crate) mod checked_scalar;
use super::{AddressMode, Register};

pub(super) const PROTECTION_GRANULE_BYTES: u32 = 4096;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const VECTOR_BYTES: u8 = 16;

#[derive(Clone, Copy)]
pub(super) enum Source {
    Rcx,
    R8,
    /// A register that holds a guest register ([`super::pinned`]).
    Host(Gpr),
    Xmm(u8),
}

pub(super) fn aligned_immediate(
    base: Register,
    displacement: i32,
    mode: AddressMode,
    bytes: u8,
) -> bool {
    base == Register::Sp && (mode == AddressMode::PostIndex || displacement % i32::from(bytes) == 0)
}

pub(super) fn aligned_register_offset(
    base: Register,
    index: Register,
    shift: u8,
    bytes: u8,
) -> bool {
    base == Register::Sp && (index == Register::Zero || u32::from(shift) >= bytes.trailing_zeros())
}

/// RAX is the address; displacement is zero or the second pair element's size.
/// Every register and XMM source survives.
pub(super) fn emit(code: &mut Code, bytes: u8, displacement: u8, source: Source) {
    debug_assert!(displacement == 0 || displacement == bytes);
    emit_to(code, bytes, Mem::base(Gpr::Rax, i32::from(displacement)), source);
}

/// The store at `target`.
pub(super) fn emit_to(code: &mut Code, bytes: u8, target: Mem, source: Source) {
    debug_assert!(bytes.is_power_of_two() && bytes <= VECTOR_BYTES);
    let mut asm = code.asm();
    asm.guest_access(|asm| match source {
        Source::Xmm(xmm) => match bytes {
            DWORD_BYTES => asm.movd_from_xmm(target, xmm),
            QWORD_BYTES => asm.movq_store(xmm, target),
            VECTOR_BYTES => asm.movdqu_store(target, xmm),
            _ => unreachable!("narrow vectors are staged through RCX"),
        },
        Source::Rcx | Source::R8 | Source::Host(_) => {
            debug_assert!(bytes <= QWORD_BYTES);
            let size = match bytes {
                1 => Size::Byte,
                HALFWORD_BYTES => Size::Word,
                DWORD_BYTES => Size::Dword,
                _ => Size::Qword,
            };
            let register = match source {
                Source::R8 => Gpr::R8,
                Source::Host(host) => host,
                _ => Gpr::Rcx,
            };
            asm.mov_store(size, target, register);
        }
    });
}
