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
            return Err(CompileError(
                "shared system memory specialization is unqualified".into(),
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
                | super::Terminator::FloatingPoint
                    if system_helpers => {}
                super::Terminator::PointerAuthentication(instruction)
                    if process_helpers
                        && !matches!(
                            instruction.operation,
                            super::PointerAuthenticationOperation::Load(_)
                        ) => {}
                super::Terminator::Clock(_) | super::Terminator::ThreadRegister(_)
                    if process_helpers => {}
                super::Terminator::FloatingPoint
                | super::Terminator::PointerAuthentication(_)
                | super::Terminator::Clock(_)
                | super::Terminator::ThreadRegister(_)
                | super::Terminator::System(_)
                | super::Terminator::Amx(_) => {
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
mod tests {
    use super::*;
    use crate::block::Features;
    use alloc::vec::Vec;
    #[test]
    fn checked_process_helpers_use_distinct_immutable_abi_and_exact_terminals() {
        use crate::block::{BlockProfile, CompilationPlan};
        let base = GuestAddress(0x1000);
        for recipe in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            let selected = BlockProfile::new(Features::PROCESS_HELPERS).with_checked_memory(recipe);
            assert_ne!(
                selected.abi(),
                BlockProfile::ORDINARY.with_checked_memory(recipe).abi()
            );
            assert_ne!(
                selected.abi(),
                BlockProfile::new(Features::PROCESS_HELPERS.union(Features::AMX)).abi()
            );
            assert!(selected.has(Features::POINTER_AUTHENTICATION));
            assert!(selected.has(Features::CLOCK));
            assert!(selected.has(Features::THREAD_REGISTERS));
            assert!(!selected.has(Features::SYSTEM));
            for terminal in [0xd503237fu32, 0xd53be040, 0xd5033fdf, 0xd53bd061] {
                // Original MOV X3,#0x44 prefix must survive before the helper.
                let source: Vec<_> = [0xd2800883u32, terminal, 0xd65f03c0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect();
                let plan = CompilationPlan::new(
                    &source,
                    base,
                    &crate::Options::new(selected, crate::TargetCpu::Baseline),
                )
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
                        &crate::Options::new(
                            BlockProfile::ORDINARY.with_checked_memory(recipe),
                            crate::TargetCpu::Baseline
                        )
                    )
                    .is_err()
                );
            }
            // Authenticated data loads still need the helper reader.
            let load = 0xf8200400u32.to_le_bytes();
            assert!(
                CompilationPlan::new(
                    &load,
                    base,
                    &crate::Options::new(selected, crate::TargetCpu::Baseline)
                )
                .is_err()
            );
        }
    }
    #[test]
    fn checked_fixed_simd_load_store_routes_through_exact_plan_requirements() {
        use crate::context::memory::{SpAlignmentRequirement, flags, host_caps};
        for profile in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            for (word, write) in [(0xfd47_b520u32, false), (0xfc19_83a0, true)] {
                let source: Vec<_> = [word, 0xd65f_03c0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect();
                let plan = crate::block::CompilationPlan::new(
                    &source,
                    GuestAddress(0x1000),
                    &crate::Options::new(
                        crate::block::BlockProfile::new(Features::PROCESS_HELPERS)
                            .with_checked_memory(profile),
                        TargetCpu::Baseline,
                    ),
                )
                .unwrap();
                let required = plan.memory_requirements().unwrap();
                assert_eq!(required.required_flags & flags::ASIMD, flags::ASIMD);
                assert_eq!(
                    required.required_flags & flags::WRITE,
                    if write { flags::WRITE } else { 0 }
                );
                assert_eq!(required.required_sp_alignment, SpAlignmentRequirement::Any);
                assert_eq!(
                    required.required_host_caps,
                    if write { 0 } else { host_caps::ATOMIC_LOAD16 }
                );
                let native = plan.compile().unwrap();
                assert_eq!(native.native.source_map.len(), 2);
            }
        }
    }
    #[test]
    fn shared_literal_forms_use_the_checked_scalar_service_and_exact_source_map() {
        use crate::context::memory::{SpAlignmentRequirement, flags, host_caps};
        const RET: u32 = 0xd65f03c0;
        for form in [0x18000000u32, 0x58000000, 0x98000000] {
            for destination in [0, 10, 30, 31] {
                for specialization in [
                    CheckedMemoryProfile::SpAlignmentEnabled,
                    CheckedMemoryProfile::SpAlignmentDisabled,
                ] {
                    for target in [TargetCpu::X86_64_V2, TargetCpu::AtomicLoad16] {
                        let word = form | (8 << 5) | destination;
                        let source: Vec<_> =
                            [word, RET].into_iter().flat_map(u32::to_le_bytes).collect();
                        let plan = crate::block::CompilationPlan::new(
                            &source,
                            GuestAddress(0x1000),
                            &crate::Options::new(
                                crate::block::BlockProfile::new(Features::SYSTEM_MODE)
                                    .with_checked_memory(specialization),
                                target,
                            ),
                        )
                        .unwrap();
                        let required = plan.memory_requirements().unwrap();
                        assert_eq!(
                            required.required_flags
                                & (flags::TAG_CHECKED | flags::WRITE | flags::ASIMD),
                            0
                        );
                        assert_eq!(required.required_sp_alignment, SpAlignmentRequirement::Any);
                        assert_eq!(
                            required.required_host_caps,
                            if target.supports(TargetCpu::AtomicLoad16) {
                                host_caps::ATOMIC_LOAD16
                            } else {
                                host_caps::CX16
                            }
                        );
                        let emitted = plan.compile().unwrap();
                        assert!(emitted.fault_recovery.is_empty());
                        assert_eq!(
                            emitted
                                .native
                                .source_map
                                .iter()
                                .map(|(pc, _)| pc.0)
                                .collect::<Vec<_>>(),
                            [0x1000, 0x1004]
                        );
                        // Exact guest address is materialized, never host RIP.
                        let mut constant = alloc::vec![0x48, 0xb8];
                        constant.extend(0x1020u64.to_le_bytes());
                        assert!(
                            emitted
                                .native
                                .x86_64_code
                                .windows(constant.len())
                                .any(|window| window == constant)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn shared_simd_literal_forms_retain_checked_asimd_requirements_and_source_maps() {
        use crate::context::memory::{SpAlignmentRequirement, flags, host_caps};
        for (form, bytes) in [(0x1c00_0000u32, 4u64), (0x5c00_0000, 8), (0x9c00_0000, 16)] {
            for destination in 0..32 {
                for (pc, immediate) in [(0x1000u64, -1i32), (0x1004, 0), (0x1000, 1)] {
                    for profile in [
                        CheckedMemoryProfile::SpAlignmentEnabled,
                        CheckedMemoryProfile::SpAlignmentDisabled,
                    ] {
                        for target in [TargetCpu::X86_64_V2, TargetCpu::AtomicLoad16] {
                            let word = form | ((immediate as u32 & 0x7ffff) << 5) | destination;
                            let source: Vec<_> = [word, 0xd65f_03c0]
                                .into_iter()
                                .flat_map(u32::to_le_bytes)
                                .collect();
                            let plan = crate::block::CompilationPlan::new(
                                &source,
                                GuestAddress(pc),
                                &crate::Options::new(
                                    crate::block::BlockProfile::new(Features::SYSTEM_MODE)
                                        .with_checked_memory(profile),
                                    target,
                                ),
                            )
                            .unwrap();
                            let requirements = plan.memory_requirements().unwrap();
                            let address = pc.wrapping_add_signed(i64::from(immediate) * 4);
                            assert_eq!(requirements.required_flags, flags::ASIMD);
                            assert_eq!(
                                requirements.required_sp_alignment,
                                SpAlignmentRequirement::Any
                            );
                            assert!(requirements.required_address_checks.is_empty());
                            assert_eq!(
                                requirements.required_host_caps,
                                if bytes < 16 && !address.is_multiple_of(bytes) {
                                    if target.supports(TargetCpu::AtomicLoad16) {
                                        host_caps::ATOMIC_LOAD16
                                    } else {
                                        host_caps::CX16
                                    }
                                } else {
                                    0
                                }
                            );
                            let emitted = plan.compile().unwrap();
                            assert!(emitted.fault_recovery.is_empty());
                            assert_eq!(
                                emitted
                                    .native
                                    .source_map
                                    .iter()
                                    .map(|(pc, _)| pc.0)
                                    .collect::<Vec<_>>(),
                                [pc, pc + 4]
                            );
                            let mut constant = alloc::vec![0x48, 0xb8];
                            constant.extend(address.to_le_bytes());
                            assert!(
                                emitted
                                    .native
                                    .x86_64_code
                                    .windows(constant.len())
                                    .any(|window| window == constant)
                            );
                        }
                    }
                }
            }
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
                    &crate::Options::new(
                        crate::block::BlockProfile::ORDINARY.with_checked_memory(recipe),
                        TargetCpu::Baseline,
                    ),
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
    #[test]
    fn memory_context_v2_has_distinct_profile_identity_and_fixed_layout() {
        assert_eq!(crate::context::memory::MEMORY_CONTEXT_VERSION, 2);
        assert_eq!(crate::context::memory::MEMORY_CONTEXT_BYTES, 64);
        assert_eq!(crate::context::memory::MEMORY_REQUEST_BYTES, 32);
        assert_eq!(
            CheckedMemoryProfile::SpAlignmentEnabled.id(),
            "checked-gpr-memory-sa0-on-normal-wb-v4"
        );
        assert_eq!(
            CheckedMemoryProfile::SpAlignmentDisabled.id(),
            "checked-gpr-memory-sa0-off-normal-wb-v4"
        );
    }
}
