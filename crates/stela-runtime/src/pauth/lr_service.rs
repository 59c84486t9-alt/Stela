//! Read-only FEAT_PAuth_LR operand and key access. Results are applied only by
//! the retiring owner, after its source, PC and trap checks.

use super::{
    Context,
    features::{LinkRegisterPauthCapability, UnsupportedInstructionProfile},
    lr_context::{self, InstructionKey, LinkRegisterContext},
    lr_instruction::{self, Instruction, Staged},
};
use crate::system::{
    access::ExceptionLevel,
    process_memory::{
        SCTLR_ENIA, SCTLR_ENIB,
        extended_controls::{ExtendedControlLoan, SCTLR2_ENPACM, SCTLR2_ENPACM0},
    },
    state::{PacmStateFeature, SystemState},
};
use stela_compiler::{GuestAddress, GuestState, block::PointerAuthenticationOperation};

/// A decoded current control fact, not an execution grant or caller permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeySelection {
    Bypass,
    UseKey,
}

/// The selected raw control value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacmControlValue {
    Zero,
    One,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Profile(UnsupportedInstructionProfile),
    Context(lr_context::Error),
    Stage(lr_instruction::StageError),
    UnsupportedCurrentEl,
    MissingPacmStorage,
}

/// Borrowed access for an executing caller. Not Clone or Copy, with no mutable
/// getters or saved state.
pub(crate) struct BorrowedLinkRegisterService<'run> {
    capability: LinkRegisterPauthCapability<'run>,
    context: &'run Context,
    controls: ExtendedControlLoan<'run>,
    registers: &'run GuestState,
    instruction_pc: GuestAddress,
    system: &'run SystemState,
}

impl<'run> BorrowedLinkRegisterService<'run> {
    /// Takes the bank and source read borrow. Namespace equality is a
    /// consistency check of the keys only.
    pub(crate) fn new(
        controls: ExtendedControlLoan<'run>,
        context: &'run Context,
        registers: &'run GuestState,
        instruction_pc: GuestAddress,
        system: &'run SystemState,
    ) -> Result<Self, Error> {
        if system.pacm_state_feature() != PacmStateFeature::Full {
            return Err(Error::MissingPacmStorage);
        }
        let snapshot = controls.snapshot();
        let capability =
            LinkRegisterPauthCapability::from_profile(snapshot).map_err(Error::Profile)?;
        let crypto =
            LinkRegisterContext::new(snapshot, controls.address_space(), &capability, context)
                .map_err(Error::Context)?;
        if !crypto.snapshot().same_snapshot(snapshot) {
            return Err(Error::Context(lr_context::Error::WrongSnapshot));
        }
        Ok(Self {
            capability,
            context,
            controls,
            registers,
            instruction_pc,
            system,
        })
    }

    /// Read the current registers and the settled source PC. Decoding,
    /// authorization and all state commits happen elsewhere.
    pub(crate) fn stage(&self, instruction: Instruction) -> Result<Staged, Error> {
        lr_instruction::stage(
            instruction,
            self.instruction_pc.0,
            &self.registers.x,
            self.registers.sp,
        )
        .map_err(Error::Stage)
    }

    /// Conditional forms read PACM from the system state; None leaves other
    /// operations on their normal path.
    pub(crate) fn stage_conditional(
        &self,
        operation: PointerAuthenticationOperation,
    ) -> Result<Option<super::conditional::Operands>, Error> {
        super::conditional::stage(
            operation,
            self.instruction_pc.0,
            &self.registers.x,
            self.registers.sp,
            self.system.pacm(),
        )
        .map_err(Error::Stage)
    }

    /// Test-only observation.
    #[cfg(test)]
    pub(crate) fn pstate(&self) -> u64 {
        self.system.pstate(self.registers)
    }

    pub(crate) fn key_selection(&self, key: InstructionKey) -> KeySelection {
        let mask = match key {
            InstructionKey::A => SCTLR_ENIA,
            InstructionKey::B => SCTLR_ENIB,
        };
        if self.controls.sctlr_el1() & mask == 0 {
            KeySelection::Bypass
        } else {
            KeySelection::UseKey
        }
    }

    pub(crate) fn pacm_control_value(&self) -> Result<PacmControlValue, Error> {
        let mask = match self.system.current_el() {
            ExceptionLevel::El0 => SCTLR2_ENPACM0,
            ExceptionLevel::El1 => SCTLR2_ENPACM,
            _ => return Err(Error::UnsupportedCurrentEl),
        };
        Ok(if self.controls.sctlr2_el1() & mask == 0 {
            PacmControlValue::Zero
        } else {
            PacmControlValue::One
        })
    }

    /// Original raw layout controls for the parent's exact layout qualifier.
    /// Returning these values neither selects a layout nor changes a bank.
    pub(crate) fn tcr_controls(&self) -> (u64, u64) {
        (self.controls.tcr_el1(), self.controls.tcr2_el1())
    }

    /// Unconditional pure key service; this does not apply key-enable selection,
    /// prove TCR layout, perform a guest operation or grant retirement.
    pub(crate) fn crypto(&self) -> Result<LinkRegisterContext<'_, 'run>, Error> {
        LinkRegisterContext::new(
            self.capability.snapshot(),
            self.controls.address_space(),
            &self.capability,
            self.context,
        )
        .map_err(Error::Context)
    }
}
