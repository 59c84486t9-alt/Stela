//! DRPS.
use super::halted::Status;
use crate::system::access::ExceptionLevel;
use crate::system::pstate::{DAIF_MASK, NZCV_MASK};
use crate::system::state::{
    PSTATE_EL1H, PSTATE_EL1T, PSTATE_IL_MASK, PSTATE_MODE_MASK, PSTATE_SS_MASK,
};
use stela_compiler::aarch64::system::exception::{self, Operation};

const BASE_SAVED_MASK: u64 =
    NZCV_MASK | DAIF_MASK | PSTATE_MODE_MASK | PSTATE_IL_MASK | PSTATE_SS_MASK;
const ARBITRARY_MASK: u64 = NZCV_MASK | PSTATE_SS_MASK | DAIF_MASK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unsupported {
    Encoding,
    SourceLevel,
    SavedMode,
    SavedBits,
    SavedIllegalState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    SynchronizeContext,
    RestoreActualSavedPstate,
    ClearShouldAdvanceSs,
    WriteArbitraryPstate,
    WriteDlrDspsrArbitrary,
    UpdateEdscrFields,
    CompleteHaltedInjection,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    word: u32,
    source_spsr: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Preparation {
    DecodeUndefined,
    Plan(Plan),
}

/// `saved` is a diagnostic read of the EL1 bank. The consumer re-checks the
/// controls, the base subset, the source and the saved state before any effect;
/// RestoreActualSavedPstate reads the bank at its step after synchronization.
pub(crate) fn prepare(
    word: u32,
    status: Status,
    current_el: ExceptionLevel,
    saved: u64,
) -> Result<Preparation, Unsupported> {
    if exception::decode(word) != Some(Operation::DebugReturn) {
        return Err(Unsupported::Encoding);
    }
    if !status.halted() || current_el == ExceptionLevel::El0 {
        return Ok(Preparation::DecodeUndefined);
    }
    if current_el != ExceptionLevel::El1 {
        return Err(Unsupported::SourceLevel);
    }
    if !matches!(saved & PSTATE_MODE_MASK, PSTATE_EL1T | PSTATE_EL1H) {
        return Err(Unsupported::SavedMode);
    }
    if saved & !BASE_SAVED_MASK != 0 {
        return Err(Unsupported::SavedBits);
    }
    if saved & PSTATE_IL_MASK != 0 {
        return Err(Unsupported::SavedIllegalState);
    }
    Ok(Preparation::Plan(Plan {
        word,
        source_spsr: saved,
    }))
}

impl Plan {
    pub(crate) fn word(&self) -> u32 {
        self.word
    }
    pub(crate) fn steps(&self) -> [Step; 7] {
        [
            Step::SynchronizeContext,
            Step::RestoreActualSavedPstate,
            Step::ClearShouldAdvanceSs,
            Step::WriteArbitraryPstate,
            Step::WriteDlrDspsrArbitrary,
            Step::UpdateEdscrFields,
            Step::CompleteHaltedInjection,
        ]
    }
}

/// The ARBITRARY bits are chosen as zero after SetPSTATEFromPSR; the rest of
/// the state is as restored.
pub(crate) fn arbitrary_pstate(restored: u64) -> u64 {
    restored & !ARBITRARY_MASK
}

#[cfg(test)]
mod tests;
