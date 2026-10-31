//! Checked GPR memory access plans.
use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu, context::memory::MemoryRequirements,
};
use alloc::vec::Vec;

mod address;
pub use address::CheckedAddressProfile;
mod pointer;
pub(crate) use pointer::CheckedOperation;

pub const ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID: &str =
    "el0-le-lse2-a0-cpa2off-mte0-spe0-normal-wb-gpr-memory-v4";
pub const CHECKED_POINTER_PROCESS_MEMORY_PROFILE_ID: &str =
    "el0-le-lse2-a0-cpa-qualified-mte0-spe0-normal-wb-memory-v5";
/// Checked-memory specialization, selected from the process controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckedMemoryProfile {
    SpAlignmentEnabled,
    SpAlignmentDisabled,
    AddressChecks(CheckedAddressProfile),
}
impl CheckedMemoryProfile {
    /// Select the compiler's address checks. The runtime validates the access
    /// level and controls before the block runs.
    pub const fn with_address_checks(
        self,
        ordinary_access_el: crate::context::memory::address::AccessEl,
        unprivileged_access_el: crate::context::memory::address::AccessEl,
        checks: crate::context::memory::address::EffectiveAddressChecks,
    ) -> Self {
        Self::AddressChecks(CheckedAddressProfile::new(
            self.sp_requirement(),
            ordinary_access_el,
            unprivileged_access_el,
            checks,
        ))
    }

    /// Require FEAT_CPA and bind the arithmetic effects at the profile's
    /// current EL. The AddressAdd and arithmetic checks must agree.
    pub fn with_pointer_arithmetic(
        self,
        checks: crate::context::pointer::EffectivePointerChecks,
    ) -> Option<Self> {
        match self {
            Self::AddressChecks(profile) => profile
                .with_pointer_arithmetic(checks)
                .map(Self::AddressChecks),
            _ => None,
        }
    }

    pub(crate) fn pointer_arithmetic(
        self,
    ) -> Option<crate::context::pointer::PointerArithmeticRequirement> {
        match self {
            Self::AddressChecks(profile) => profile.pointer_arithmetic(),
            _ => None,
        }
    }

    pub const fn process_memory_profile_id(self) -> &'static str {
        match self {
            Self::AddressChecks(_) => CHECKED_POINTER_PROCESS_MEMORY_PROFILE_ID,
            _ => ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID,
        }
    }

    /// The profile's name in a checked block's ABI identity.
    pub const fn id(self) -> &'static str {
        match self {
            Self::AddressChecks(_) => "checked-memory-address-v5",
            Self::SpAlignmentEnabled => "checked-gpr-memory-sa0-on-normal-wb-v4",
            Self::SpAlignmentDisabled => "checked-gpr-memory-sa0-off-normal-wb-v4",
        }
    }
    pub const fn sp_requirement(self) -> crate::context::memory::SpAlignmentRequirement {
        match self {
            Self::AddressChecks(profile) => profile.sp_requirement(),
            Self::SpAlignmentEnabled => crate::context::memory::SpAlignmentRequirement::Enabled,
            Self::SpAlignmentDisabled => crate::context::memory::SpAlignmentRequirement::Disabled,
        }
    }

    pub(crate) const fn address_checks(
        self,
        unprivileged: bool,
    ) -> crate::context::memory::address::AddressAddChecks {
        match self {
            Self::AddressChecks(profile) => profile.checks(unprivileged),
            _ => crate::context::memory::address::AddressAddChecks::Disabled,
        }
    }

    pub(crate) fn address_requirements(
        self,
        unprivileged: bool,
    ) -> crate::context::memory::address::AddressCheckRequirements {
        match self {
            Self::AddressChecks(profile) => profile.requirements(unprivileged),
            _ => Default::default(),
        }
    }

    pub(crate) fn direct_address_requirements(
        self,
    ) -> crate::context::memory::address::AddressCheckRequirements {
        match self {
            Self::AddressChecks(profile) => profile.direct_requirements(),
            _ => Default::default(),
        }
    }
}

/// Constructed only from this module's parent's one decoded consumed vector.
/// Native output and effects are derived from these same immutable typed values.
pub(super) struct CheckedPlan {
    decoded: Vec<(GuestAddress, CheckedOperation)>,
    requirements: MemoryRequirements,
    register_regions: bool,
}
impl CheckedPlan {
    pub(super) fn new(
        instructions: &[crate::aarch64::Instruction],
        terminal: Option<&(GuestAddress, super::Terminator)>,
        profile: CheckedMemoryProfile,
        outer: super::BlockProfile,
    ) -> Result<Self, CompileError> {
        let process_helpers = outer.has(super::Features::PROCESS_HELPERS);
        let system_helpers = outer.has(super::Features::FULL_SYSTEM);
        if system_helpers
            && !matches!(
                profile,
                CheckedMemoryProfile::SpAlignmentEnabled
                    | CheckedMemoryProfile::SpAlignmentDisabled
            )
        {
            return Err(CompileError::new(
                crate::CompileErrorKind::UnqualifiedSharedMemoryProfile,
            ));
        }
        if let Some((_, terminal)) = terminal {
            match terminal {
                super::Terminator::Branch(_)
                | super::Terminator::DirectCall(_)
                | super::Terminator::Register { .. }
                | super::Terminator::Trap(_) => {}
                super::Terminator::System(_)
                | super::Terminator::PointerAuthentication(_)
                | super::Terminator::Amx(_)
                | super::Terminator::FloatingPoint { .. }
                    if system_helpers => {}
                super::Terminator::PointerAuthentication(instruction)
                    if process_helpers
                        && !matches!(
                            instruction.operation,
                            super::PointerAuthenticationOperation::Load(_)
                        ) => {}
                super::Terminator::Clock(_) | super::Terminator::ThreadRegister(_)
                    if process_helpers => {}
                super::Terminator::FloatingPoint { .. }
                | super::Terminator::PointerAuthentication(_)
                | super::Terminator::Clock(_)
                | super::Terminator::ThreadRegister(_)
                | super::Terminator::System(_)
                | super::Terminator::Amx(_) => {
                    return Err(CompileError::new(
                        crate::CompileErrorKind::UnadmittedMemoryTerminal,
                    ));
                }
            }
        }
        let mut requirements = MemoryRequirements::default();
        let mut decoded = Vec::with_capacity(instructions.len());
        for instruction in instructions {
            let operation = CheckedOperation::new(instruction.clone(), profile)?;
            requirements = requirements
                .merge(operation.requirements())
                .ok_or_else(|| {
                    CompileError::new(crate::CompileErrorKind::IncompatibleMemoryRequirements)
                })?;
            decoded.push((instruction.pc, operation));
        }
        Ok(Self {
            decoded,
            requirements,
            register_regions: system_helpers,
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
        profile: Option<&mut super::profile::CompileProfile>,
    ) -> Result<NativeBlock, CompileError> {
        crate::x86_64::block::checked_memory::emit(
            &self.decoded,
            terminal,
            fallthrough,
            target,
            self.register_regions,
            profile,
        )
    }
}

#[cfg(test)]
mod tests;
