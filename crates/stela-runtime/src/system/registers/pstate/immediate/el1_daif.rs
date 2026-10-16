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
mod tests {
    use super::*;
    use crate::system::{
        pstate::DAIF_MASK,
        state::{El1Registers, PSTATE_EL0T, PSTATE_EL1H, PSTATE_EL1T},
    };
    use stela_compiler::block::system::decode_system_instruction;

    const BASE: GuestAddress = GuestAddress(0x1000);
    const DAIF_SET: u32 = 0xd503_40df;
    const DAIF_CLEAR: u32 = 0xd503_40ff;
    const CRM_SHIFT: u32 = 8;
    const MAX_OPERAND: u32 = 15;
    const FLAGS: u32 = 0xa123_4567;

    fn system(mode: u64, daif: u64) -> SystemState {
        SystemState::new(mode | daif, 0x1234, El1Registers::new(1, 2, 3, 4, 5)).unwrap()
    }

    fn instruction(word: u32) -> SystemInstruction {
        decode_system_instruction(BASE, word).unwrap().unwrap()
    }

    #[test]
    fn every_el1_operand_and_direction_preserves_cpu_and_other_owned_state() {
        for mode in [PSTATE_EL1T, PSTATE_EL1H] {
            for initial in [0, DAIF_MASK] {
                for base in [DAIF_SET, DAIF_CLEAR] {
                    for operand in 0..=MAX_OPERAND {
                        let word = base | (operand << CRM_SHIFT);
                        let system = system(mode, initial);
                        let registers = GuestState {
                            nzcv: FLAGS,
                            reserved: u32::MAX,
                            sp: 0xfedc,
                            ..GuestState::default()
                        };
                        let before = registers.clone();
                        let mask = u64::from(operand) << DAIF_SHIFT;
                        let updated = if base == DAIF_SET {
                            initial | mask
                        } else {
                            initial & !mask
                        };
                        let plan = PreparedEl1Daif::prepare(instruction(word), BASE, word, &system)
                            .unwrap();
                        let staged = plan.stage(&system, &registers).unwrap();
                        assert_eq!(staged.instruction(), instruction(word));
                        assert_eq!(staged.value(), updated);
                        assert_eq!(registers, before);
                        assert_eq!(system, self::system(mode, initial));
                    }
                }
            }
        }
    }

    #[test]
    fn forged_source_il_and_el0_never_prepare_an_effect() {
        let word = DAIF_SET | (MAX_OPERAND << CRM_SHIFT);
        let instruction = instruction(word);
        let valid = system(PSTATE_EL1H, 0);
        assert_eq!(
            PreparedEl1Daif::prepare(instruction, BASE, word ^ (1 << CRM_SHIFT), &valid),
            Err(PrepareError::Source(SourceError::WrongSource))
        );
        assert_eq!(
            PreparedEl1Daif::prepare(
                instruction,
                BASE,
                word,
                &system(PSTATE_EL1H | PSTATE_IL_MASK, 0)
            ),
            Err(PrepareError::IllegalExecutionState)
        );
        assert_eq!(
            PreparedEl1Daif::prepare(instruction, BASE, word, &system(PSTATE_EL0T, 0)),
            Err(PrepareError::AccessContextRequired)
        );
    }

    #[test]
    fn actual_state_is_rechecked_before_staging_a_prepared_plan() {
        let valid = system(PSTATE_EL1H, 0);
        let plan =
            PreparedEl1Daif::prepare(instruction(DAIF_CLEAR), BASE, DAIF_CLEAR, &valid).unwrap();
        for mode in [PSTATE_EL0T, PSTATE_EL1H | PSTATE_IL_MASK] {
            let changed = system(mode, DAIF_MASK);
            let registers = GuestState::default();
            let before = (changed.clone(), registers.clone());
            assert!(plan.stage(&changed, &registers).is_err());
            assert_eq!((changed, registers), before);
        }
    }
}
