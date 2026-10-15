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
    pub const fn process_helpers_abi(self) -> &'static str {
        match self {
            Self::SpAlignmentEnabled => {
                "x86_64-sysv-guest-state-v3-context-block-exit-checked-gpr-memory-sa0-on-normal-wb-pauth-clock-thread-v1"
            }
            Self::SpAlignmentDisabled => {
                "x86_64-sysv-guest-state-v3-context-block-exit-checked-gpr-memory-sa0-off-normal-wb-pauth-clock-thread-v1"
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
        process_helpers: bool,
    ) -> Result<Self, CompileError> {
        if let Some((_, terminal)) = terminal {
            match terminal {
                super::Terminator::Branch(_)
                | super::Terminator::DirectCall(_)
                | super::Terminator::Register { .. }
                | super::Terminator::Trap(_) => {}
                super::Terminator::PointerAuthentication(instruction)
                    if process_helpers
                        && !matches!(
                            instruction.operation,
                            super::PointerAuthenticationOperation::Load(_)
                        ) => {}
                super::Terminator::Clock(_) | super::Terminator::ThreadRegister(_)
                    if process_helpers => {}
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
    fn checked_process_helpers_use_distinct_immutable_abi_and_exact_terminals() {
        use crate::block::{BlockProfile, CompilationPlan};
        let base = GuestAddress(0x1000);
        for recipe in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            let selected = BlockProfile::CheckedMemoryPauthClockThread(recipe);
            assert_ne!(selected.abi(), BlockProfile::CheckedMemory(recipe).abi());
            assert_ne!(
                selected.abi(),
                BlockProfile::AppleArm64eSoftwarePauthClockThreadV1.abi()
            );
            assert!(selected.supports_pointer_authentication());
            assert!(selected.supports_clock());
            assert!(selected.supports_thread_registers());
            assert!(!selected.supports_system());
            for terminal in [0xd503237fu32, 0xd53be040, 0xd5033fdf, 0xd53bd061] {
                // Original MOV X3,#0x44 prefix must survive before the helper.
                let source: Vec<_> = [0xd2800883u32, terminal, 0xd65f03c0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect();
                let plan =
                    CompilationPlan::new(&source, base, selected, crate::TargetCpu::Baseline)
                        .unwrap();
                assert_eq!(plan.source_bytes(), 8);
                assert!(plan.memory_requirements().is_some());
                let compiled = plan.compile().unwrap();
                assert_eq!(compiled.native.source_map.len(), 2);
                assert_eq!(compiled.native.source_map[1].0, GuestAddress(base.0 + 4));
                assert!(
                    CompilationPlan::new(
                        &source,
                        base,
                        BlockProfile::CheckedMemory(recipe),
                        crate::TargetCpu::Baseline
                    )
                    .is_err()
                );
            }
            // Authenticated data loads still need the canonical helper reader.
            let load = 0xf8200400u32.to_le_bytes();
            assert!(
                CompilationPlan::new(&load, base, selected, crate::TargetCpu::Baseline).is_err()
            );
        }
    }
    #[test]
    fn checked_exclusive_widths_preserve_source_quantity_and_host_requirements() {
        use crate::context::memory::{flags, host_caps, profile_requirements};
        const RET: u32 = 0xd65f_03c0;
        // Existing source decoder/emitter shapes, all with non-SP base X9.
        for (word, element_bytes, members, required_caps) in [
            (0x085f_7d2a_u32, 1, 1, 0),
            (0x485f_7d2a, 2, 1, host_caps::ATOMIC_LOAD16),
            (0x885f_7d2a, 4, 1, host_caps::ATOMIC_LOAD16),
            (0xc85f_7d2a, 8, 1, host_caps::ATOMIC_LOAD16),
            (0x887f_2d2a, 4, 2, host_caps::ATOMIC_LOAD16),
            (0xc87f_2d2a, 8, 2, host_caps::ATOMIC_LOAD16),
        ] {
            let operand = crate::aarch64::exclusive::decode(word).unwrap().unwrap();
            let crate::aarch64::exclusive::Operand::Transfer {
                element_bytes: actual,
                data,
                ..
            } = operand
            else {
                panic!("expected transfer");
            };
            assert_eq!(actual, element_bytes);
            assert_eq!(
                match data {
                    crate::aarch64::exclusive::Data::Scalar(_) => 1,
                    crate::aarch64::exclusive::Data::Pair(registers) => registers.len(),
                },
                members
            );
            let source: Vec<u8> = [word, RET].into_iter().flat_map(u32::to_le_bytes).collect();
            for recipe in [
                CheckedMemoryProfile::SpAlignmentEnabled,
                CheckedMemoryProfile::SpAlignmentDisabled,
            ] {
                let plan = crate::block::CompilationPlan::new(
                    &source,
                    GuestAddress(0x1000),
                    crate::block::BlockProfile::CheckedMemory(recipe),
                    TargetCpu::Baseline,
                )
                .unwrap();
                let requirements = plan
                    .memory_requirements()
                    .expect("checked body requirements");
                assert_eq!(requirements.required_host_caps, required_caps);
                assert_eq!(
                    requirements.required_flags,
                    flags::EXCLUSIVE | flags::TAG_CHECKED
                );
                assert_eq!(
                    requirements.required_profile,
                    profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES
                );
                // Actual emission must preserve the same consumed plan and source map.
                let native = plan.compile().unwrap();
                assert!(!native.native.x86_64_code.is_empty());
                assert_eq!(native.native.source_map.len(), 2);
            }
        }
    }
}
