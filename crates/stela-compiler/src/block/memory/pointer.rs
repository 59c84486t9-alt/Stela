//! FEAT_CPA arithmetic within checked memory plans.

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{Instruction, Operation},
    context::{memory::MemoryRequirements, pointer::PointerArithmeticRequirement},
    extended::Decoded,
};
use alloc::vec::Vec;

pub(crate) enum CheckedOperation {
    Ordinary(Decoded),
    Pointer {
        operand: crate::aarch64::checked_pointer::Operand,
        requirement: PointerArithmeticRequirement,
    },
}

impl CheckedOperation {
    pub(crate) fn profile_success_traffic(
        &self,
    ) -> Option<(
        crate::block::profile::RegisterRecipe,
        crate::block::profile::RegisterTraffic,
    )> {
        use crate::block::profile::{RegisterRecipe, RegisterTraffic};
        match self {
            Self::Ordinary(Decoded::MemoryScalar(operand)) => Some((
                RegisterRecipe::ScalarCallback,
                operand.profile_success_traffic(),
            )),
            Self::Ordinary(Decoded::MemoryPair(operand)) => Some((
                RegisterRecipe::PairCallback,
                operand.profile_success_traffic(),
            )),
            Self::Ordinary(Decoded::PrefetchHint) => {
                Some((RegisterRecipe::Prefetch, RegisterTraffic::default()))
            }
            _ => None,
        }
    }

    /// Only already-admitted register operations may enter a nonfaulting
    /// region. Typed checked accesses and CPA operations remain boundaries.
    pub(crate) fn ordinary_instruction(&self) -> Option<&Instruction> {
        match self {
            Self::Ordinary(Decoded::Ordinary(instruction)) => Some(instruction),
            _ => None,
        }
    }

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
mod tests {
    use crate::{
        GuestAddress, TargetCpu,
        block::{BlockProfile, CheckedMemoryProfile, CompilationPlan},
        context::{
            memory::address::{AccessEl, AddressAddChecks, EffectiveAddressChecks},
            pointer::{EffectivePointerChecks, PointerArithmeticRequirement},
        },
    };
    use alloc::vec::Vec;

    const SOURCE_PC: GuestAddress = GuestAddress(0x4000);
    const INSTRUCTION_BYTES: usize = size_of::<u32>();
    const RET_X30: u32 = 0xd65f_03c0;
    const NOP: u32 = 0xd503_201f;
    const LDR_X0_X9_8: u32 = 0xf940_0520;
    const STR_X0_X9_8: u32 = 0xf900_0520;
    const ADDPT_X0_X1_X2: u32 = 0x9a02_2020;
    const SUBPT_X0_X1_X2: u32 = 0xda02_2020;
    const MADDPT_X0_X1_X2_X3: u32 = 0x9b62_0c20;
    const MSUBPT_X0_X1_X2_X3: u32 = 0x9b62_8c20;
    const DESTINATION_MASK: u32 = 0x1f;
    const ZERO_REGISTER: u32 = 0x1f;
    const LDP_X0_X0_X9_16: u32 = 0xa941_0120;
    const MODES: [EffectivePointerChecks; 3] = [
        EffectivePointerChecks::Unchecked,
        EffectivePointerChecks::Addition,
        EffectivePointerChecks::AdditionAndMultiplication,
    ];
    const FORMS: [u32; 4] = [
        ADDPT_X0_X1_X2,
        SUBPT_X0_X1_X2,
        MADDPT_X0_X1_X2_X3,
        MSUBPT_X0_X1_X2_X3,
    ];

    fn source(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }
    fn profile(mode: EffectivePointerChecks) -> CheckedMemoryProfile {
        let address = match mode {
            EffectivePointerChecks::Unchecked => AddressAddChecks::Disabled,
            _ => AddressAddChecks::Enabled,
        };
        CheckedMemoryProfile::SpAlignmentDisabled
            .with_address_checks(
                AccessEl::El0,
                AccessEl::El0,
                EffectiveAddressChecks::new(address, address),
            )
            .with_pointer_arithmetic(mode)
            .unwrap()
    }

    #[test]
    fn all_four_forms_share_one_memory_plan_and_retain_feature_mode_and_source() {
        for word in FORMS {
            for mode in MODES {
                let bytes = source(&[LDR_X0_X9_8, word, STR_X0_X9_8, RET_X30]);
                let plan = CompilationPlan::new(
                    &bytes,
                    SOURCE_PC,
                    BlockProfile::CheckedMemory(profile(mode)),
                    TargetCpu::Baseline,
                )
                .unwrap();
                let requirements = plan.memory_requirements().unwrap();
                assert_eq!(
                    requirements.required_pointer_arithmetic,
                    Some(PointerArithmeticRequirement::new(AccessEl::El0, mode))
                );
                assert!(!requirements.required_address_checks.is_empty());
                let compiled = plan.compile().unwrap();
                assert_eq!(compiled.source_bytes, bytes.len());
                assert_eq!(
                    compiled.native.source_map.len(),
                    bytes.len() / INSTRUCTION_BYTES
                );
                for (index, (pc, _)) in compiled.native.source_map.iter().enumerate() {
                    assert_eq!(pc.0, SOURCE_PC.0 + (index * INSTRUCTION_BYTES) as u64);
                }
            }
        }
    }

    #[test]
    fn arithmetic_cannot_infer_feature_from_memory_profile_or_discarded_result() {
        for word in FORMS {
            for profile in [
                CheckedMemoryProfile::SpAlignmentDisabled,
                CheckedMemoryProfile::SpAlignmentDisabled.with_address_checks(
                    AccessEl::El0,
                    AccessEl::El0,
                    EffectiveAddressChecks::new(
                        AddressAddChecks::Disabled,
                        AddressAddChecks::Disabled,
                    ),
                ),
            ] {
                let bytes = source(&[word, RET_X30]);
                assert!(
                    CompilationPlan::new(
                        &bytes,
                        SOURCE_PC,
                        BlockProfile::CheckedMemory(profile),
                        TargetCpu::Baseline
                    )
                    .is_err()
                );
            }
        }
        let discarded = (MADDPT_X0_X1_X2_X3 & !DESTINATION_MASK) | ZERO_REGISTER;
        let bytes = source(&[discarded, RET_X30]);
        let plan = CompilationPlan::new(
            &bytes,
            SOURCE_PC,
            BlockProfile::CheckedMemory(profile(EffectivePointerChecks::Unchecked)),
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(
            plan.memory_requirements()
                .unwrap()
                .required_pointer_arithmetic,
            Some(PointerArithmeticRequirement::new(
                AccessEl::El0,
                EffectivePointerChecks::Unchecked
            ))
        );
        assert!(plan.compile().is_ok());
    }

    #[test]
    fn incompatible_arithmetic_and_address_effects_cannot_form_a_profile() {
        let unchecked = CheckedMemoryProfile::SpAlignmentDisabled.with_address_checks(
            AccessEl::El0,
            AccessEl::El0,
            EffectiveAddressChecks::new(AddressAddChecks::Disabled, AddressAddChecks::Enabled),
        );
        assert!(
            unchecked
                .with_pointer_arithmetic(EffectivePointerChecks::Addition)
                .is_none()
        );
        assert!(
            CheckedMemoryProfile::SpAlignmentDisabled
                .with_pointer_arithmetic(EffectivePointerChecks::Unchecked)
                .is_none()
        );
    }

    #[test]
    fn combined_profile_keeps_exact_raw_nop_provenance() {
        let profile = BlockProfile::CheckedMemory(profile(EffectivePointerChecks::Addition));
        assert!(
            CompilationPlan::new(
                &source(&[NOP, ADDPT_X0_X1_X2, RET_X30]),
                SOURCE_PC,
                profile,
                TargetCpu::Baseline
            )
            .is_ok()
        );
        assert!(
            CompilationPlan::new(
                &source(&[LDP_X0_X0_X9_16, ADDPT_X0_X1_X2, RET_X30]),
                SOURCE_PC,
                profile,
                TargetCpu::Baseline
            )
            .is_err()
        );
    }
}
