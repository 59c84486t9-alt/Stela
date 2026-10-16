//! Source-derived checked GPR memory plans under the existing block parser.
use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu, context::memory::MemoryRequirements,
};
use alloc::vec::Vec;

mod address;
pub use address::CheckedAddressProfile;
mod pointer;
pub(crate) use pointer::CheckedOperation;

pub const ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID: &str =
    "el0-le-lse2-a0-cpa2off-mte0-spe0-normal-wb-gpr-memory-v3";
pub const CHECKED_POINTER_PROCESS_MEMORY_PROFILE_ID: &str =
    "el0-le-lse2-a0-cpa-qualified-mte0-spe0-normal-wb-memory-v4";
/// Immutable specialization selected from the actual process-control owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckedMemoryProfile {
    SpAlignmentEnabled,
    SpAlignmentDisabled,
    /// One ordinary unsigned 64-bit load, non-SP base and no writeback.
    /// The state pointer is private staging; authoritative state commits only
    /// after the canonical M0 parent's checked completion and finalization.
    M0DeviceRamRead64Staged,
    AddressChecks(CheckedAddressProfile),
}
impl CheckedMemoryProfile {
    /// Select compiler effects only; the actual owner validates source access EL,
    /// controls and implementation choice before the native prefix can run.
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

    /// Require CPA availability and bind the exact arithmetic effects at the
    /// profile's original current EL. AddressAdd and arithmetic must agree.
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

    pub const fn abi(self) -> &'static str {
        match self {
            Self::M0DeviceRamRead64Staged => {
                "x86_64-sysv-guest-state-v3-context-block-exit-el1-m0-device-ram-read64-staged-v1"
            }
            Self::AddressChecks(_) => {
                "x86_64-sysv-guest-state-v3-context-block-exit-checked-memory-address-v4"
            }
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
            Self::M0DeviceRamRead64Staged => {
                "unadmitted-el1-m0-device-ram-read64-process-helpers-v1"
            }
            Self::AddressChecks(_) => {
                "x86_64-sysv-guest-state-v3-context-block-exit-checked-memory-address-pauth-clock-thread-v2"
            }
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
            Self::M0DeviceRamRead64Staged => "el1-m0-device-ram-read64-staged-v1",
            Self::AddressChecks(_) => "checked-memory-address-v4",
            Self::SpAlignmentEnabled => "checked-gpr-memory-sa0-on-normal-wb-v3",
            Self::SpAlignmentDisabled => "checked-gpr-memory-sa0-off-normal-wb-v3",
        }
    }
    pub const fn sp_requirement(self) -> crate::context::memory::SpAlignmentRequirement {
        match self {
            Self::M0DeviceRamRead64Staged => crate::context::memory::SpAlignmentRequirement::Any,
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
}
impl CheckedPlan {
    pub(super) fn new(
        instructions: &[crate::aarch64::Instruction],
        terminal: Option<&(GuestAddress, super::Terminator)>,
        profile: CheckedMemoryProfile,
        process_helpers: bool,
    ) -> Result<Self, CompileError> {
        if process_helpers && profile == CheckedMemoryProfile::M0DeviceRamRead64Staged {
            return Err(CompileError(
                "M0 staged read excludes process helpers".into(),
            ));
        }
        if profile == CheckedMemoryProfile::M0DeviceRamRead64Staged
            && (instructions.len() != 1 || terminal.is_some())
        {
            return Err(CompileError(
                "M0 staged read requires exactly one ordinary source load and no terminator".into(),
            ));
        }
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
            let operation = CheckedOperation::new(instruction.clone(), profile)?;
            requirements = requirements
                .merge(operation.requirements())
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
mod tests;
