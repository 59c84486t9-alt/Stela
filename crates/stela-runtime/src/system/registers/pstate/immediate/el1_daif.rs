//! Source-bound A64 EL1 DAIF plan; no entry, async, source or retirement grant.
//! The EL0 UMA/trap decision requires its real access owner and is not inferred.

use super::{SourceError, request};
use crate::system::{
    access::ExceptionLevel,
    pstate::{DAIF_MASK, DAIF_SHIFT},
    registers::pstate::Effect,
    state::{PSTATE_IL_MASK, SystemState},
};
use stela_compiler::{GuestAddress, GuestState, block::system::SystemInstruction};

const DAIF_IMMEDIATE_OP1: u8 = 3;
const DAIF_SET_OP2: u8 = 6;
const DAIF_CLEAR_OP2: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrepareError {
    Source(SourceError),
    NotDaif,
    IllegalExecutionState,
    AccessContextRequired,
}

/// Private fields retain the decoded source intent, not a copied CPU or permit.
/// The checked consumer retains original source/control/domain/async loans and
/// revalidates those actual owners before applying this plan to the same state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedEl1Daif {
    effect: Effect,
    instruction: SystemInstruction,
}

impl PreparedEl1Daif {
    pub(crate) fn prepare(
        instruction: SystemInstruction,
        source_pc: GuestAddress,
        source_word: u32,
        system: &SystemState,
    ) -> Result<Self, PrepareError> {
        let selected = request(instruction, source_pc, source_word)
            .map_err(PrepareError::Source)?
            .encoding;
        if selected.op1() != DAIF_IMMEDIATE_OP1
            || !matches!(selected.op2(), DAIF_SET_OP2 | DAIF_CLEAR_OP2)
        {
            return Err(PrepareError::NotDaif);
        }
        Self::check_state(system)?;
        // CheckDAIFAccess's UMA/EL2 routing is conditional on actual EL0. The
        // sole SystemState supports A64 modes only; this plan admits only EL1.
        let mask = u64::from(selected.crm()) << DAIF_SHIFT;
        let value = if selected.op2() == DAIF_SET_OP2 {
            mask
        } else {
            0
        };
        Ok(Self {
            effect: Effect::Daif { mask, value },
            instruction,
        })
    }

    fn check_state(system: &SystemState) -> Result<(), PrepareError> {
        if system.pstate_misc() & PSTATE_IL_MASK != 0 {
            return Err(PrepareError::IllegalExecutionState);
        }
        if system.current_el() != ExceptionLevel::El1 {
            return Err(PrepareError::AccessContextRequired);
        }
        Ok(())
    }

    /// Validate and normalize the current DAIF state before any mutation. The
    /// canonical consumer retains the same exclusive System/register borrow,
    /// source/control/outer/async loans and this exact staged value across its
    /// fallible retirement transition, then applies it once under Retiring.
    pub(crate) fn stage(
        self,
        system: &SystemState,
        registers: &GuestState,
    ) -> Result<StagedEl1Daif, StageError> {
        Self::check_state(system).map_err(StageError::State)?;
        let Effect::Daif { mask, value } = self.effect else {
            return Err(StageError::InvalidEffect);
        };
        if mask & !DAIF_MASK != 0 {
            return Err(StageError::InvalidMask);
        }
        if value & !mask != 0 {
            return Err(StageError::InvalidValue);
        }
        Ok(StagedEl1Daif {
            instruction: self.instruction,
            value: ((system.pstate(registers) & !mask) | value) & DAIF_MASK,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageError {
    State(PrepareError),
    InvalidEffect,
    InvalidMask,
    InvalidValue,
}

/// An unapplied state value, never an actual source/control/entry permit. The
/// canonical private session binds this exact value to its original descriptor
/// and retained owners; it must not accept a caller's saved replacement stage.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StagedEl1Daif {
    instruction: SystemInstruction,
    value: u64,
}
impl StagedEl1Daif {
    pub(crate) const fn instruction(&self) -> SystemInstruction {
        self.instruction
    }
    pub(crate) const fn value(&self) -> u64 {
        self.value
    }
    /// The token has a private canonical constructor, retains the original
    /// mutable state, and is validated against this exact source/staged value
    /// before start_retirement. No fallible step follows the first mutation.
    pub(crate) fn apply(
        self,
        mut loan: crate::blocks::retirement::checked::el1_system::El1SystemEffectLoan<'_>,
    ) -> GuestAddress {
        loan.write_daif_authorized(self.value);
        self.instruction.next_pc
    }
}

#[cfg(test)]
mod tests;
