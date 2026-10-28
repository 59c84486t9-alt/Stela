//! Direct stores to private RAM, keeping the completed prefix when a later page
//! faults. The protection granule is assumed to be at least 4 KiB.
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, ShiftOp, Size};
use alloc::vec::Vec;
pub(crate) mod checked_pair;
pub(crate) mod checked_scalar;
use super::{AddressMode, Register, isa::SimdOpcode};

pub(super) const PROTECTION_GRANULE_BYTES: u32 = 4096;
const BYTE_BITS: u8 = 8;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const VECTOR_BYTES: u8 = 16;
/// Wide stores stage their sources in XMM0/XMM1. XMM2 is never a retained
/// input at this boundary; a full-width shuffle also avoids a merge dependency.
const HIGH_QWORD_SCRATCH_XMM: u8 = 2;
const DUPLICATE_HIGH_QWORD: u8 = 0xee;

#[derive(Clone, Copy)]
pub(super) enum Source {
    Rcx,
    R8,
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
/// RDX (pending writeback), R8 (second integer value), RDI and guest state survive.
/// RCX, R10 and XMM2 are scratch on the crossing path. The selected XMM0/XMM1
/// source remains whole, including where the block retains XMM0 for a later
/// instruction.
pub(super) fn emit(code: &mut Code, bytes: u8, displacement: u8, source: Source, aligned: bool) {
    emit_marking(code, bytes, displacement, source, aligned, &mut None);
}

/// [`emit`], pushing the end of each instruction to `ends` when given.
fn emit_marking(
    code: &mut Code,
    bytes: u8,
    displacement: u8,
    source: Source,
    aligned: bool,
    ends: &mut Option<Vec<usize>>,
) {
    debug_assert!(bytes.is_power_of_two() && bytes <= VECTOR_BYTES);
    debug_assert!(displacement == 0 || displacement == bytes);
    if bytes == 1 || aligned {
        fast(code, bytes, displacement, source);
        mark(code, ends);
        return;
    }
    // An access crossing a 4 KiB boundary flips address bit 12. Comparing
    // against the pair's base may conservatively include the second element.
    let mut asm = code.asm();
    asm.lea(
        Size::Dword,
        Gpr::R10,
        Mem::base_disp8(Gpr::Rax, (displacement + bytes - 1) as i8),
    );
    mark(code, ends);
    code.asm().alu(Alu::Xor, Size::Dword, Gpr::R10, Gpr::Rax);
    mark(code, ends);
    code.asm()
        .test_imm(Size::Dword, Gpr::R10, PROTECTION_GRANULE_BYTES as i32);
    mark(code, ends);
    let fast_jump = code.asm().jcc(Cond::E);
    mark(code, ends);
    prefix_store(code, bytes, displacement, source, ends);
    let done_jump = code.asm().jmp();
    mark(code, ends);
    code.asm().bind(fast_jump);
    fast(code, bytes, displacement, source);
    mark(code, ends);
    code.asm().bind(done_jump);
}

/// Push the code's length, the end of the instruction just emitted, to `ends`.
fn mark(code: &Code, ends: &mut Option<Vec<usize>>) {
    if let Some(ends) = ends {
        ends.push(code.len());
    }
}

/// Golden-byte and instruction-boundary oracle for an unaligned scalar store.
/// Production regions copy the shared emitter's typed span and count.
#[cfg(test)]
pub(super) fn crossing_store(bytes: u8) -> Option<(Vec<u8>, Vec<usize>)> {
    if !matches!(bytes, HALFWORD_BYTES | DWORD_BYTES | QWORD_BYTES) {
        return None;
    }
    let mut code = Code::new();
    // LEA, XOR, TEST and JZ; every byte's shift but the first and its byte
    // store; JMP; then the fast path's one store.
    let mut ends = Some(Vec::new());
    emit_marking(&mut code, bytes, 0, Source::Rcx, false, &mut ends);
    Some((code.into_bytes(), ends.unwrap_or_default()))
}

fn fast(code: &mut Code, bytes: u8, displacement: u8, source: Source) {
    let target = Mem::base(Gpr::Rax, i32::from(displacement));
    let mut asm = code.asm();
    match source {
        Source::Xmm(xmm) => match bytes {
            DWORD_BYTES => asm.movd_from_xmm(target, xmm),
            QWORD_BYTES => asm.movq_store(xmm, target),
            VECTOR_BYTES => asm.movdqu_store(target, xmm),
            _ => unreachable!("narrow vectors are staged through RCX"),
        },
        Source::Rcx | Source::R8 => {
            debug_assert!(bytes <= QWORD_BYTES);
            let size = match bytes {
                1 => Size::Byte,
                HALFWORD_BYTES => Size::Word,
                DWORD_BYTES => Size::Dword,
                _ => Size::Qword,
            };
            let register = if matches!(source, Source::R8) {
                Gpr::R8
            } else {
                Gpr::Rcx
            };
            asm.mov_store(size, target, register);
        }
    }
}

fn prefix_store(
    code: &mut Code,
    bytes: u8,
    displacement: u8,
    source: Source,
    ends: &mut Option<Vec<usize>>,
) {
    match source {
        Source::Rcx => {}
        Source::R8 => {
            code.asm().mov(Size::Qword, Gpr::Rcx, Gpr::R8);
            mark(code, ends);
        }
        Source::Xmm(xmm) => {
            extract_qword(code, xmm);
            mark(code, ends);
        }
    }
    for byte in 0..bytes {
        if byte == QWORD_BYTES {
            let Source::Xmm(xmm) = source else {
                unreachable!("only vectors exceed a qword")
            };
            assert_ne!(
                xmm, HIGH_QWORD_SCRATCH_XMM,
                "store input aliases its scratch"
            );
            SimdOpcode::ShuffleDword.register_imm(
                code,
                HIGH_QWORD_SCRATCH_XMM,
                xmm,
                DUPLICATE_HIGH_QWORD,
                crate::TargetCpu::Baseline,
            );
            mark(code, ends);
            extract_qword(code, HIGH_QWORD_SCRATCH_XMM);
            mark(code, ends);
        } else if byte != 0 {
            code.asm()
                .shift_imm(ShiftOp::Shr, Size::Qword, Gpr::Rcx, BYTE_BITS);
            mark(code, ends);
        }
        fast(code, 1, displacement + byte, Source::Rcx);
        mark(code, ends);
    }
}

/// RCX = the low qword of `xmm`.
fn extract_qword(code: &mut Code, xmm: u8) {
    code.asm().movq_from_xmm(Gpr::Rcx, xmm);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The crossing recipe's ends are its instruction boundaries.
    #[test]
    fn crossing_store_ends_are_instruction_boundaries() {
        let (code, ends) = crossing_store(HALFWORD_BYTES).unwrap();
        assert_eq!(
            code,
            [
                0x44, 0x8d, 0x50, 0x01, // lea r10d, [rax+1]
                0x41, 0x31, 0xc2, // xor r10d, eax
                0x41, 0xf7, 0xc2, 0x00, 0x10, 0x00, 0x00, // test r10d, 0x1000
                0x0f, 0x84, 0x0e, 0x00, 0x00, 0x00, // jz fast
                0x88, 0x08, // mov [rax], cl
                0x48, 0xc1, 0xe9, 0x08, // shr rcx, 8
                0x88, 0x48, 0x01, // mov [rax+1], cl
                0xe9, 0x03, 0x00, 0x00, 0x00, // jmp done
                0x66, 0x89, 0x08, // fast: mov [rax], cx
            ]
        );
        assert_eq!(ends, [4, 7, 14, 20, 22, 26, 29, 34, 37]);
        for bytes in [DWORD_BYTES, QWORD_BYTES] {
            let (code, ends) = crossing_store(bytes).unwrap();
            assert_eq!(ends.len(), 4 + 2 * usize::from(bytes) - 1 + 2);
            assert!(ends.windows(2).all(|pair| pair[0] < pair[1]));
            assert_eq!(*ends.last().unwrap(), code.len());
        }
        assert!(crossing_store(1).is_none());
        assert!(crossing_store(VECTOR_BYTES).is_none());
    }
}
