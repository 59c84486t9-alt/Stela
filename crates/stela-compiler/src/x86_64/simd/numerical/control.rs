//! Translate FPCR rounding controls into a private MXCSR.
use crate::x86_64::asm::{Alu, Code, Gpr, ShiftOp, Size};

use crate::{GuestState, aarch64::floating::FPCR_ROUNDING_SHIFT};

const MXCSR_POSITIVE_ROUNDING_SHIFT: u8 = 14;
const MXCSR_NEGATIVE_ROUNDING_SHIFT: u8 = 13;
const MXCSR_POSITIVE_ROUNDING: u32 = 1 << MXCSR_POSITIVE_ROUNDING_SHIFT;
const MXCSR_NEGATIVE_ROUNDING: u32 = 1 << MXCSR_NEGATIVE_ROUNDING_SHIFT;
const FPCR_POSITIVE_TO_MXCSR_SHIFT: u8 = FPCR_ROUNDING_SHIFT as u8 - MXCSR_POSITIVE_ROUNDING_SHIFT;
const FPCR_NEGATIVE_TO_MXCSR_SHIFT: u8 =
    FPCR_ROUNDING_SHIFT as u8 + 1 - MXCSR_NEGATIVE_ROUNDING_SHIFT;

/// Read raw guest FPCR and leave only positioned host RC bits in EAX.
/// Clobbers ECX and host flags; preserves every XMM, RDI/R15 and guest state.
/// Operation-specific AH/rounding policy and MXCSR installation remain callers'
/// responsibilities. This helper neither installs nor reads host MXCSR.
pub(in crate::x86_64) fn rounding_control(code: &mut Code) {
    use Gpr::{Rax, Rcx};
    let mut asm = code.asm();
    asm.mov_load(
        Size::Dword,
        Rax,
        super::state(core::mem::offset_of!(GuestState, fpcr)),
    );
    asm.mov(Size::Dword, Rcx, Rax);
    asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, FPCR_POSITIVE_TO_MXCSR_SHIFT);
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, MXCSR_POSITIVE_ROUNDING as i32);
    asm.shift_imm(ShiftOp::Shr, Size::Dword, Rcx, FPCR_NEGATIVE_TO_MXCSR_SHIFT);
    asm.alu_imm32(Alu::And, Size::Dword, Rcx, MXCSR_NEGATIVE_ROUNDING as i32);
    asm.alu(Alu::Or, Size::Dword, Rax, Rcx);
}
