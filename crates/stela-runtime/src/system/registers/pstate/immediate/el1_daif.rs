//! MSR DAIFSet/DAIFClr at EL1.

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

/// The decoded source intent. The consumer re-validates its owners before
/// applying the plan.
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
        // CheckDAIFAccess's UMA and EL2 routing apply only at EL0; this plan
        // admits EL1 only.
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

    /// Validate and normalize the current DAIF state before any change. The
    /// consumer holds the system and register borrow, its other borrows and the
    /// staged value across the retirement transition, then applies it once.
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

/// An unapplied state value. The session binds it to its descriptor and owners
/// and never accepts a saved replacement.
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
    /// The token is constructed only by the consumer, holds the mutable state
    /// and is validated against this source and value before retirement starts.
    /// Nothing fallible follows the first change.
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
