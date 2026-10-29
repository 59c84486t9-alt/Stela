//! Validated guest retirement at a native recovery boundary.
use super::FaultRecoveryError;
use crate::{
    GuestAddress,
    aarch64::{AddressMode, Instruction, MemoryTransfer, Operation},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetirementPhase {
    Before,
    AfterFallthrough,
}

/// A precise boundary; terminal/branch/RET windows may only use Before.
/// AfterFallthrough has no implicit meaning for a control transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetirementPoint {
    instruction_pc: GuestAddress,
    retired_before: u16,
    phase: RetirementPhase,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredPosition {
    pub pc: GuestAddress,
    pub retired_instructions: u16,
}
impl RetirementPoint {
    pub fn before(
        instruction_pc: GuestAddress,
        retired_before: u16,
    ) -> Result<Self, FaultRecoveryError> {
        let point = Self {
            instruction_pc,
            retired_before,
            phase: RetirementPhase::Before,
        };
        point.position()?;
        Ok(point)
    }
    /// Prove the listed instruction's sequential control-flow shape.
    /// The producer must separately prove all architectural results are complete
    /// and recoverable at its exact native boundary. For memory, this witness
    /// conveys no endianness, RAM, helper or access-effect authority: admission
    /// and the retained compilation/profile/code proof must bind those conditions.
    /// Adding another family requires its continuation and completion proof.
    pub fn after_fallthrough(
        instruction: &Instruction,
        retired_before: u16,
    ) -> Result<Self, FaultRecoveryError> {
        if !matches!(
            instruction.operation,
            Operation::Nop
                | Operation::PcRelative(_)
                | Operation::MoveWide { .. }
                | Operation::AddSub { .. }
                | Operation::AddSubRegister { .. }
                | Operation::LogicalRegister { .. }
                | Operation::LogicalImmediate { .. }
                | Operation::Memory {
                    transfer: MemoryTransfer::Load { .. },
                    mode: AddressMode::Offset,
                    ..
                }
        ) {
            return Err(FaultRecoveryError::UnprovenFallthrough { pc: instruction.pc });
        }
        let point = Self {
            instruction_pc: instruction.pc,
            retired_before,
            phase: RetirementPhase::AfterFallthrough,
        };
        point.position()?;
        Ok(point)
    }
    /// Reconstruct persisted metadata from the matching retained source
    /// instruction, after its source hash, address and entry extent are checked.
    /// A serialized phase byte alone never qualifies AfterFallthrough.
    /// Reconstructing this shape witness supplies no memory-effect authority;
    /// the retained compilation/profile/code proof remains required.
    pub fn from_instruction(
        instruction: &Instruction,
        retired_before: u16,
        phase: RetirementPhase,
    ) -> Result<Self, FaultRecoveryError> {
        match phase {
            RetirementPhase::Before => Self::before(instruction.pc, retired_before),
            RetirementPhase::AfterFallthrough => {
                Self::after_fallthrough(instruction, retired_before)
            }
        }
    }
    /// Move a previously qualified point with its code's guest-PC relocation.
    /// The operation's sequential-continuation proof and phase are preserved.
    pub fn relocated(self, instruction_pc: GuestAddress) -> Result<Self, FaultRecoveryError> {
        let point = Self {
            instruction_pc,
            ..self
        };
        point.position()?;
        Ok(point)
    }
    pub const fn instruction_pc(self) -> GuestAddress {
        self.instruction_pc
    }
    pub const fn retired_before(self) -> u16 {
        self.retired_before
    }
    pub const fn phase(self) -> RetirementPhase {
        self.phase
    }
    pub fn rebased(self, retired_base: u16) -> Result<Self, FaultRecoveryError> {
        let retired_before = self.retired_before.checked_add(retired_base).ok_or(
            FaultRecoveryError::RetirementOverflow {
                pc: self.instruction_pc,
            },
        )?;
        let point = Self {
            retired_before,
            ..self
        };
        point.position()?;
        Ok(point)
    }
    pub fn position(self) -> Result<RecoveredPosition, FaultRecoveryError> {
        if usize::from(self.retired_before) > super::super::MAX_BLOCK_INSTRUCTIONS {
            return Err(FaultRecoveryError::InvalidRetiredCount {
                count: self.retired_before,
            });
        }
        if self.instruction_pc.0 & 3 != 0 {
            return Err(FaultRecoveryError::InvalidInstructionAddress {
                pc: self.instruction_pc,
            });
        }
        match self.phase {
            RetirementPhase::Before => Ok(RecoveredPosition {
                pc: self.instruction_pc,
                retired_instructions: self.retired_before,
            }),
            RetirementPhase::AfterFallthrough => Ok(RecoveredPosition {
                pc: GuestAddress(self.instruction_pc.0.checked_add(4).ok_or(
                    FaultRecoveryError::RetirementOverflow {
                        pc: self.instruction_pc,
                    },
                )?),
                retired_instructions: self
                    .retired_before
                    .checked_add(1)
                    .filter(|count| usize::from(*count) <= super::super::MAX_BLOCK_INSTRUCTIONS)
                    .ok_or(FaultRecoveryError::RetirementOverflow {
                        pc: self.instruction_pc,
                    })?,
            }),
        }
    }
}
