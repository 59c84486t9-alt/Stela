//! Source-derived checked GPR memory plans under the existing block parser.
use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu, context::memory::MemoryRequirements,
    extended::Decoded,
};

pub const ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID: &str =
    "el0-le-lse2-a0-cpa2off-mte0-spe0-normal-wb-gpr-memory-v3";
/// Immutable specialization selected from the actual process-control owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckedMemoryProfile {
    SpAlignmentEnabled,
    SpAlignmentDisabled,
}
impl CheckedMemoryProfile {
    pub const fn abi(self) -> &'static str {
        match self {
            Self::SpAlignmentEnabled => {
                "x86_64-sysv-guest-state-v3-context-block-exit-checked-gpr-memory-sa0-on-normal-wb-v3"
            }
            Self::SpAlignmentDisabled => {
                "x86_64-sysv-guest-state-v3-context-block-exit-checked-gpr-memory-sa0-off-normal-wb-v3"
            }
        }
    }
    pub const fn id(self) -> &'static str {
        match self {
            Self::SpAlignmentEnabled => "checked-gpr-memory-sa0-on-normal-wb-v3",
            Self::SpAlignmentDisabled => "checked-gpr-memory-sa0-off-normal-wb-v3",
        }
    }
    pub const fn sp_requirement(self) -> crate::context::memory::SpAlignmentRequirement {
        match self {
            Self::SpAlignmentEnabled => crate::context::memory::SpAlignmentRequirement::Enabled,
            Self::SpAlignmentDisabled => crate::context::memory::SpAlignmentRequirement::Disabled,
        }
    }
}

/// Constructed only from this module's parent's one decoded consumed vector.
/// Native output and effects are derived from these same immutable typed values.
pub(super) struct CheckedPlan {
    decoded: Vec<(GuestAddress, Decoded)>,
    requirements: MemoryRequirements,
}
impl CheckedPlan {
    pub(super) fn new(
        instructions: &[crate::aarch64::Instruction],
        terminal: Option<&(GuestAddress, super::Terminator)>,
        profile: CheckedMemoryProfile,
    ) -> Result<Self, CompileError> {
        if let Some((_, terminal)) = terminal {
            match terminal {
                super::Terminator::Branch(_)
                | super::Terminator::DirectCall(_)
                | super::Terminator::Register { .. }
                | super::Terminator::Trap(_) => {}
                super::Terminator::FloatingPoint(_)
                | super::Terminator::PointerAuthentication(_)
                | super::Terminator::Clock(_)
                | super::Terminator::ThreadRegister(_)
                | super::Terminator::System(_) => {
                    return Err(CompileError(
                        "terminal service is not admitted by checked GPR memory profile".into(),
                    ));
                }
            }
        }
        let mut requirements = MemoryRequirements::default();
        let mut decoded = Vec::with_capacity(instructions.len());
        for instruction in instructions {
            let operation = Decoded::checked_ordinary(instruction.clone(), profile)?;
            requirements = requirements
                .merge(operation.memory_requirements())
                .ok_or_else(|| CompileError("incompatible checked memory requirements".into()))?;
            decoded.push((instruction.pc, operation));
        }
        Ok(Self {
            decoded,
            requirements,
        })
    }
    pub(super) fn requirements(&self) -> MemoryRequirements {
        self.requirements
    }
    pub(super) fn emit(
        &self,
        terminal: Option<&(GuestAddress, super::Terminator)>,
        fallthrough: GuestAddress,
        target: TargetCpu,
    ) -> Result<NativeBlock, CompileError> {
        crate::x86_64::block::checked_memory::emit(&self.decoded, terminal, fallthrough, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_plan_rejects_unqualified_exclusive_widths_and_pairs() {
        const RET: u32 = 0xd65f_03c0;
        // Canonical scalar loads B/H/X and pair loads W/X, all valid allocated
        // encodings. The source decoder accepts them; this entry recipe declines.
        for word in [
            0x085f_7d2au32,
            0x485f_7d2a,
            0xc85f_7d2a,
            0x887f_2d2a,
            0xc87f_2d2a,
        ] {
            assert!(matches!(
                crate::aarch64::exclusive::decode(word),
                Some(Ok(_))
            ));
            let source: Vec<u8> = [word, RET].into_iter().flat_map(u32::to_le_bytes).collect();
            for recipe in [
                CheckedMemoryProfile::SpAlignmentEnabled,
                CheckedMemoryProfile::SpAlignmentDisabled,
            ] {
                let error = crate::block::CompilationPlan::new(
                    &source,
                    GuestAddress(0x1000),
                    crate::block::BlockProfile::CheckedMemory(recipe),
                    TargetCpu::Baseline,
                )
                .err()
                .expect("unqualified valid exclusive must decline");
                assert!(error.to_string().contains("outside checked scalar32 scope"));
            }
        }
    }
}
