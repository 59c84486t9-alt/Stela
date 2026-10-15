//! CPA arithmetic in the same immutable checked context plan as ordinary RAM.

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{Instruction, Operation},
    context::{memory::MemoryRequirements, pointer::PointerArithmeticRequirement},
    extended::Decoded,
};

pub(crate) enum CheckedOperation {
    Ordinary(Decoded),
    Pointer {
        operand: crate::aarch64::checked_pointer::Operand,
        requirement: PointerArithmeticRequirement,
    },
}

impl CheckedOperation {
    pub(super) fn new(
        instruction: Instruction,
        profile: super::CheckedMemoryProfile,
    ) -> Result<Self, CompileError> {
        if let Operation::CheckedPointer(operand) = instruction.operation {
            let requirement = profile.pointer_arithmetic().ok_or_else(|| {
                CompileError(
                    "CPA arithmetic requires an explicit feature/mode specialization".into(),
                )
            })?;
            return Ok(Self::Pointer {
                operand,
                requirement,
            });
        }
        Decoded::checked_ordinary(instruction, profile).map(Self::Ordinary)
    }

    pub(super) fn requirements(&self) -> MemoryRequirements {
        match self {
            Self::Ordinary(decoded) => decoded.memory_requirements(),
            Self::Pointer { requirement, .. } => MemoryRequirements {
                required_pointer_arithmetic: Some(*requirement),
                ..Default::default()
            },
        }
    }

    pub(crate) fn emit(
        &self,
        code: &mut Vec<u8>,
        pc: GuestAddress,
        target: TargetCpu,
        fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
    ) -> Result<(), CompileError> {
        match self {
            Self::Ordinary(decoded) => decoded.emit_checked_ordinary(code, pc, target, fixups),
            Self::Pointer {
                operand,
                requirement,
            } => {
                crate::x86_64::checked_pointer::emit(code, operand, requirement.checks());
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[path = "pointer/tests.rs"]
mod tests;
