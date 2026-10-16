//! Effective controls passed to numerical helpers during streaming execution.
//!
//! Raw FPCR storage is preserved. Arm's FPProcessException suppresses numerical
//! traps in ordinary SME streaming mode, while cumulative FPSR still updates.
use crate::aarch64::floating::{FPCR_AHP, FPCR_EXCEPTION_ENABLE_MASK};

/// Adapt retained enables to FPProcessException's streaming trap condition.
/// Full A64 execution retains the ordinary numerical exception-enable policy.
pub const fn effective_fpcr(fpcr: u32, streaming: bool, full_a64: bool) -> u32 {
    if streaming && !full_a64 {
        fpcr & !FPCR_EXCEPTION_ENABLE_MASK
    } else {
        fpcr
    }
}

/// FPConvertSVE ignores alternative half precision independently of FPCR.AH.
pub const fn conversion_fpcr(fpcr: u32, streaming: bool, full_a64: bool) -> u32 {
    effective_fpcr(fpcr, streaming, full_a64) & !FPCR_AHP
}

#[cfg(test)]
mod tests;
