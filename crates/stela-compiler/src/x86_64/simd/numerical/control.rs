//! Translate FPCR rounding controls into a private MXCSR.
use crate::x86_64::asm::Code;

use crate::{GuestState, aarch64::floating::FPCR_ROUNDING_SHIFT};

const MXCSR_POSITIVE_ROUNDING_SHIFT: u8 = 14;
const MXCSR_NEGATIVE_ROUNDING_SHIFT: u8 = 13;
const MXCSR_POSITIVE_ROUNDING: u32 = 1 << MXCSR_POSITIVE_ROUNDING_SHIFT;
const MXCSR_NEGATIVE_ROUNDING: u32 = 1 << MXCSR_NEGATIVE_ROUNDING_SHIFT;
const FPCR_POSITIVE_TO_MXCSR_SHIFT: u8 = FPCR_ROUNDING_SHIFT as u8 - MXCSR_POSITIVE_ROUNDING_SHIFT;
const FPCR_NEGATIVE_TO_MXCSR_SHIFT: u8 =
    FPCR_ROUNDING_SHIFT as u8 + 1 - MXCSR_NEGATIVE_ROUNDING_SHIFT;
const MOV_EAX_STATE: &[u8] = &[0x8b, 0x87];
const MOV_ECX_EAX: &[u8] = &[0x89, 0xc1];
const SHR_EAX_IMMEDIATE: &[u8] = &[0xc1, 0xe8];
const SHR_ECX_IMMEDIATE: &[u8] = &[0xc1, 0xe9];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const AND_ECX_IMMEDIATE: &[u8] = &[0x81, 0xe1];
const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];

/// Read raw guest FPCR and leave only positioned host RC bits in EAX.
/// Clobbers ECX and host flags; preserves every XMM, RDI/R15 and guest state.
/// Operation-specific AH/rounding policy and MXCSR installation remain callers'
/// responsibilities. This helper neither installs nor reads host MXCSR.
pub(in crate::x86_64) fn rounding_control(code: &mut Code) {
    code.extend(MOV_EAX_STATE);
    code.extend((core::mem::offset_of!(GuestState, fpcr) as u32).to_le_bytes());
    code.extend(MOV_ECX_EAX);
    code.extend(SHR_EAX_IMMEDIATE);
    code.push(FPCR_POSITIVE_TO_MXCSR_SHIFT);
    code.push(AND_EAX_IMMEDIATE);
    code.extend(MXCSR_POSITIVE_ROUNDING.to_le_bytes());
    code.extend(SHR_ECX_IMMEDIATE);
    code.push(FPCR_NEGATIVE_TO_MXCSR_SHIFT);
    code.extend(AND_ECX_IMMEDIATE);
    code.extend(MXCSR_NEGATIVE_ROUNDING.to_le_bytes());
    code.extend(OR_EAX_ECX);
}
