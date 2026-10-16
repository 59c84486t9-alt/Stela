//! Leaf compilation with an execution context and a scalable specialization.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
pub mod block;
pub mod debug_movement;

mod prefix;

use alloc::collections::BTreeMap;

use crate::{
    CompileError, GuestAddress, Lifter, NativeBlock, TargetCpu,
    aarch64::{
        Decoder, Instruction, Operation,
        scalable::{
            ElementSize, ScalableMode, VectorLength,
            execution::{
                GuestMemoryQuantity, InstructionExecutionRequirements, ScalableAccessCheck,
                ScalableAccessRequirements, ScalableExecutionRequirements,
            },
            features::{FeatureRequirement, ScalableFeature, ScalableFeatures},
            profile::ScalableControls,
        },
        sme::{
            integer_dots, integer_matrix, integer_vector, length, lut_v2, memory as sme_memory,
            movement, tables,
        },
        sve::{
            address, dot, floating_copy, integer_arithmetic, integer_bits, integer_comparison,
            integer_logic::{self, CopySource, Kind},
            integer_predicate_move, integer_products, integer_saturation, memory_load,
            memory_multi, memory_store, memory_structure, predicate_generation, predicate_logic,
            rearrange, rearrange_extract, rearrange_widen, reductions, shifts, shifts_narrow, sign,
            tables as sve_tables,
        },
    },
    context::{ExecutionContext, ScalableStateView, memory::MemoryRequirements},
    x86_64,
};

pub const PROFILE_ID: &str = "apple-sme2-streaming-v1";
pub const DECLARED_PROFILE_ID: &str = "sme-streaming-v2";
const INSTRUCTION_BYTES: usize = size_of::<u32>();
const PUSH_R15: &[u8] = &[0x41, 0x57];
const MOV_R15_RSI: &[u8] = &[0x49, 0x89, 0xf7];
const CALL_REL32: u8 = 0xe8;
const POP_R15: &[u8] = &[0x41, 0x5f];
const RET: u8 = 0xc3;
const CALL_BYTES: usize = 1 + size_of::<i32>();
const CALL_END: usize = PUSH_R15.len() + MOV_R15_RSI.len() + CALL_BYTES;
pub const CONTEXT_WRAPPER_BYTES: usize = CALL_END + POP_R15.len() + 1;

/// Guest features and controls are immutable specialization identity.
/// Host capability selection remains a separate TargetCpu value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScalableProfile {
    length: VectorLength,
    mode: ScalableMode,
    kind: ScalableProfileKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ScalableProfileKind {
    V1,
    V2 {
        features: ScalableFeatures,
        controls: ScalableControls,
    },
}

impl ScalableProfile {
    /// The fixed SME2 profile, keeping its artifact identity.
    pub const fn new(length: VectorLength, mode: ScalableMode) -> Self {
        Self {
            length,
            mode,
            kind: ScalableProfileKind::V1,
        }
    }

    /// Declare guest features and controls explicitly; no hardware is inferred
    /// and no feature dependency is added. Version 2 requires PSTATE.DIT clear,
    /// which the caller validates.
    pub fn new_with_features(
        length: VectorLength,
        mode: ScalableMode,
        features: ScalableFeatures,
        controls: ScalableControls,
    ) -> Result<Self, CompileError> {
        if !features.contains(ScalableFeature::Sme) {
            return Err(CompileError("scalable profile requires FEAT_SME".into()));
        }
        if features.contains(ScalableFeature::Sme2p1) && !features.contains(ScalableFeature::Sme2) {
            return Err(CompileError("FEAT_SME2p1 requires FEAT_SME2".into()));
        }
        if controls.fpmr_enabled() && !features.contains(ScalableFeature::Fpmr) {
            return Err(CompileError("FPMR access enable requires FEAT_FPMR".into()));
        }
        if controls.zt0_enabled() && !features.contains(ScalableFeature::Sme2) {
            return Err(CompileError("ZT0 enable requires FEAT_SME2".into()));
        }
        if length > controls.max_vector_length() {
            return Err(CompileError(
                "current streaming vector length exceeds declared maximum".into(),
            ));
        }
        Ok(Self {
            length,
            mode,
            kind: ScalableProfileKind::V2 { features, controls },
        })
    }

    pub const fn id(self) -> &'static str {
        match self.kind {
            ScalableProfileKind::V1 => PROFILE_ID,
            ScalableProfileKind::V2 { .. } => DECLARED_PROFILE_ID,
        }
    }

    pub const fn vector_length(self) -> VectorLength {
        self.length
    }

    pub const fn mode(self) -> ScalableMode {
        self.mode
    }

    pub const fn features(self) -> ScalableFeatures {
        match self.kind {
            ScalableProfileKind::V1 => {
                ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2)
            }
            ScalableProfileKind::V2 { features, .. } => features,
        }
    }

    /// Decline unavailable guest instructions before emission or execution.
    pub fn require_features(
        self,
        requirement: FeatureRequirement,
        pc: GuestAddress,
    ) -> Result<(), CompileError> {
        let available = self.features();
        if requirement.is_satisfied_by(available) {
            return Ok(());
        }
        let available_names = available.names();
        let missing: Vec<_> = requirement
            .all_features()
            .names()
            .into_iter()
            .filter(|name| !available_names.contains(name))
            .collect();
        let alternatives = requirement.any_features().names();
        let mut reasons = Vec::new();
        if !missing.is_empty() {
            reasons.push(format!("requires {}", missing.join(", ")));
        }
        if !alternatives.is_empty()
            && !FeatureRequirement::any(requirement.any_features()).is_satisfied_by(available)
        {
            reasons.push(format!("requires one of {}", alternatives.join(", ")));
        }
        Err(CompileError(format!(
            "unavailable guest features at {:#x}: {}",
            pc.0,
            reasons.join("; ")
        )))
    }

    /// Only version 2 manifests list declared features; version 1 artifacts
    /// keep their fixed profile ID.
    pub const fn declared_features(self) -> Option<ScalableFeatures> {
        match self.kind {
            ScalableProfileKind::V1 => None,
            ScalableProfileKind::V2 { features, .. } => Some(features),
        }
    }

    pub const fn controls(self) -> ScalableControls {
        match self.kind {
            ScalableProfileKind::V1 => ScalableControls::new(self.length, false),
            ScalableProfileKind::V2 { controls, .. } => controls,
        }
    }

    /// V2 mappings require DIT=0. DIT is not stored in the borrowed context;
    /// the execution caller validates this requirement before entering native code.
    pub const fn required_dit(self) -> Option<bool> {
        match self.kind {
            ScalableProfileKind::V1 => None,
            ScalableProfileKind::V2 { .. } => Some(false),
        }
    }

    /// Validate borrowed metadata before native entry. Ownership, bounds and
    /// guest-RAM separation remain requirements of the unsafe execution caller.
    /// This view does not contain DIT; the caller must also check required_dit().
    pub fn validate_view(
        self,
        context: &ExecutionContext,
        view: &ScalableStateView,
    ) -> Result<(), CompileError> {
        let valid = context.has_supported_header()
            && core::ptr::eq(context.scalable.cast_const(), view)
            && usize::from(view.svl_bytes) == self.length.bytes()
            && view.reserved == [0; 6]
            && view.svcr == self.mode.svcr()
            && (!self.mode.streaming()
                || ((!view.z_upper.is_null() || self.length.chunks() == 1)
                    && !view.predicates.is_null()
                    && !view.ffr.is_null()))
            && (!self.mode.za_enabled()
                || (!view.za.is_null()
                    && match self.kind {
                        ScalableProfileKind::V1 => !view.zt0.is_null(),
                        ScalableProfileKind::V2 { controls, .. } => {
                            !controls.zt0_enabled() || !view.zt0.is_null()
                        }
                    }));
        if valid {
            Ok(())
        } else {
            Err(CompileError(
                "extended execution context/profile mismatch".into(),
            ))
        }
    }
}

pub(crate) enum Decoded {
    Exclusive(crate::x86_64::exclusive::CheckedOperand),
    MemoryScalar(crate::x86_64::memory_store::checked_scalar::Operand),
    MemoryPair(crate::x86_64::memory_store::checked_pair::Operand),
    MemoryFixed(crate::x86_64::CheckedFixedMemoryOperand),
    Ordinary(Instruction),
    Address(address::Operand),
    IntegerDot(dot::Operand),
    IntegerBits(integer_bits::Operand),
    IntegerLogic(integer_logic::Operand),
    IntegerPredicateMove(integer_predicate_move::Operand),
    IntegerProducts(integer_products::Operand),
    IntegerSaturation(integer_saturation::Operand),
    Rearrange(rearrange::Operand),
    RearrangeExtract(rearrange_extract::Operand),
    RearrangeWiden(rearrange_widen::Operand),
    Reductions(reductions::Operand),
    Shifts(shifts::Operand),
    ShiftsNarrow(shifts_narrow::Operand),
    Sign(sign::Operand),
    FloatingCopy(floating_copy::Operand),
    IntegerArithmetic(integer_arithmetic::Operand),
    IntegerComparison(integer_comparison::Operand),
    PredicateGeneration(predicate_generation::Operand),
    PredicateLogic(predicate_logic::Operand),
    Length(length::Operand),
    MemoryLoad(memory_load::Operand),
    SmeMemory(sme_memory::Operand),
    MemoryMulti(memory_multi::Operand),
    MemoryStore(memory_store::Operand),
    MemoryStructure(memory_structure::Operand),
    SmeTables(tables::Operand),
    SveTables(sve_tables::Operand),
    SmeLutV2(lut_v2::Operand),
    SmeMovement(movement::Operand),
    SmeIntegerVector(integer_vector::Operand),
    SmeIntegerDots(integer_dots::Operand),
    SmeIntegerMatrix(integer_matrix::Operand),
}

impl Decoded {
    fn execution_access_requirements(&self) -> ScalableAccessRequirements {
        match self {
            Self::Exclusive(_) => ScalableAccessRequirements::Unqualified,
            Self::MemoryScalar(_) | Self::MemoryPair(_) | Self::MemoryFixed(_) => {
                ScalableAccessRequirements::Unqualified
            }
            Self::MemoryLoad(_) => {
                ScalableAccessRequirements::Known(Box::new([ScalableAccessCheck::SveEnabled]))
            }
            Self::MemoryMulti(operand) => memory_multi::execution_access_requirements(operand),
            Self::MemoryStore(operand) => memory_store::execution_access_requirements(operand),
            Self::MemoryStructure(operand) => {
                memory_structure::execution_access_requirements(operand)
            }
            Self::SmeMemory(operand) => operand.execution_access_requirements(),
            Self::Ordinary(instruction) => match instruction.operation {
                Operation::MoveWide { .. }
                | Operation::AddSub { .. }
                | Operation::Return
                | Operation::Nop => ScalableAccessRequirements::Known(Box::new([])),
                _ => ScalableAccessRequirements::Unqualified,
            },
            Self::Address(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerDot(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerBits(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerLogic(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerPredicateMove(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerProducts(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerSaturation(_) => ScalableAccessRequirements::Unqualified,
            Self::Rearrange(_) => ScalableAccessRequirements::Unqualified,
            Self::RearrangeExtract(_) => ScalableAccessRequirements::Unqualified,
            Self::RearrangeWiden(_) => ScalableAccessRequirements::Unqualified,
            Self::Reductions(_) => ScalableAccessRequirements::Unqualified,
            Self::Shifts(_) => ScalableAccessRequirements::Unqualified,
            Self::ShiftsNarrow(_) => ScalableAccessRequirements::Unqualified,
            Self::Sign(_) => ScalableAccessRequirements::Unqualified,
            Self::FloatingCopy(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerArithmetic(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerComparison(_) => ScalableAccessRequirements::Unqualified,
            Self::PredicateGeneration(_) => ScalableAccessRequirements::Unqualified,
            Self::PredicateLogic(_) => ScalableAccessRequirements::Unqualified,
            Self::Length(_) => ScalableAccessRequirements::Unqualified,
            Self::SmeLutV2(_) => ScalableAccessRequirements::Known(Box::new([
                ScalableAccessCheck::StreamingSveEnabled,
                ScalableAccessCheck::SmeZt0Enabled,
            ])),
            Self::SmeTables(_) => ScalableAccessRequirements::Unqualified,
            Self::SveTables(_) => ScalableAccessRequirements::Unqualified,
            Self::SmeMovement(_) => ScalableAccessRequirements::Unqualified,
            Self::SmeIntegerVector(_) => ScalableAccessRequirements::Unqualified,
            Self::SmeIntegerDots(_) => ScalableAccessRequirements::Unqualified,
            Self::SmeIntegerMatrix(_) => ScalableAccessRequirements::Unqualified,
        }
    }

    const fn guest_memory_quantity(&self) -> GuestMemoryQuantity {
        match self {
            Self::Exclusive(_) => GuestMemoryQuantity::Unqualified,
            Self::MemoryScalar(_) | Self::MemoryPair(_) | Self::MemoryFixed(_) => {
                GuestMemoryQuantity::Unqualified
            }
            Self::MemoryLoad(operand) => GuestMemoryQuantity::Maximum(operand.memory_element),
            Self::MemoryMulti(operand) => memory_multi::guest_memory_quantity(operand),
            Self::MemoryStore(operand) => memory_store::guest_memory_quantity(operand),
            Self::MemoryStructure(operand) => memory_structure::guest_memory_quantity(operand),
            Self::SmeMemory(operand) => operand.guest_memory_quantity(),
            Self::Ordinary(instruction) => match instruction.operation {
                Operation::MoveWide { .. }
                | Operation::AddSub { .. }
                | Operation::Return
                | Operation::Nop => GuestMemoryQuantity::None,
                _ => GuestMemoryQuantity::Unqualified,
            },
            Self::Address(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerDot(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerBits(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerLogic(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerPredicateMove(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerProducts(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerSaturation(_) => GuestMemoryQuantity::Unqualified,
            Self::Rearrange(_) => GuestMemoryQuantity::Unqualified,
            Self::RearrangeExtract(_) => GuestMemoryQuantity::Unqualified,
            Self::RearrangeWiden(_) => GuestMemoryQuantity::Unqualified,
            Self::Reductions(_) => GuestMemoryQuantity::Unqualified,
            Self::Shifts(_) => GuestMemoryQuantity::Unqualified,
            Self::ShiftsNarrow(_) => GuestMemoryQuantity::Unqualified,
            Self::Sign(_) => GuestMemoryQuantity::Unqualified,
            Self::FloatingCopy(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerArithmetic(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerComparison(_) => GuestMemoryQuantity::Unqualified,
            Self::PredicateGeneration(_) => GuestMemoryQuantity::Unqualified,
            Self::PredicateLogic(_) => GuestMemoryQuantity::Unqualified,
            Self::Length(_) => GuestMemoryQuantity::Unqualified,
            Self::SmeLutV2(_) => GuestMemoryQuantity::None,
            Self::SmeTables(_) => GuestMemoryQuantity::Unqualified,
            Self::SveTables(_) => GuestMemoryQuantity::None,
            Self::SmeMovement(_) => GuestMemoryQuantity::Unqualified,
            Self::SmeIntegerVector(_) => GuestMemoryQuantity::Unqualified,
            Self::SmeIntegerDots(_) => GuestMemoryQuantity::Unqualified,
            Self::SmeIntegerMatrix(_) => GuestMemoryQuantity::Unqualified,
        }
    }

    pub(crate) fn memory_requirements(&self) -> crate::context::memory::MemoryRequirements {
        match self {
            Self::MemoryScalar(operand) => {
                crate::x86_64::memory_store::checked_scalar::requirements(operand)
            }
            Self::MemoryPair(operand) => {
                crate::x86_64::memory_store::checked_pair::requirements(operand)
            }
            Self::MemoryFixed(operand) => operand.requirements(),
            Self::Exclusive(operand) => crate::x86_64::exclusive::requirements(operand),
            Self::MemoryLoad(operand) => x86_64::sve::memory_load::requirements(*operand),
            Self::SmeMemory(operand) => x86_64::sme::memory::requirements(operand),
            Self::MemoryMulti(operand) => x86_64::sve::memory_multi::requirements(operand),
            Self::MemoryStore(operand) => x86_64::sve::memory_store::requirements(operand),
            Self::MemoryStructure(operand) => x86_64::sve::memory_structure::requirements(*operand),
            Self::Ordinary(_) => Default::default(),
            Self::Address(_) => Default::default(),
            Self::IntegerDot(_) => Default::default(),
            Self::IntegerBits(_) => Default::default(),
            Self::IntegerLogic(_) => Default::default(),
            Self::IntegerPredicateMove(_) => Default::default(),
            Self::IntegerProducts(_) => Default::default(),
            Self::IntegerSaturation(_) => Default::default(),
            Self::Rearrange(_) => Default::default(),
            Self::RearrangeExtract(_) => Default::default(),
            Self::RearrangeWiden(_) => Default::default(),
            Self::Reductions(_) => Default::default(),
            Self::Shifts(_) => Default::default(),
            Self::ShiftsNarrow(_) => Default::default(),
            Self::Sign(_) => Default::default(),
            Self::FloatingCopy(_) => Default::default(),
            Self::IntegerArithmetic(_) => Default::default(),
            Self::IntegerComparison(_) => Default::default(),
            Self::PredicateGeneration(_) => Default::default(),
            Self::PredicateLogic(_) => Default::default(),
            Self::Length(_) => Default::default(),
            Self::SmeLutV2(_) => Default::default(),
            Self::SmeTables(_) => Default::default(),
            Self::SveTables(_) => Default::default(),
            Self::SmeMovement(_) => Default::default(),
            Self::SmeIntegerVector(_) => Default::default(),
            Self::SmeIntegerDots(_) => Default::default(),
            Self::SmeIntegerMatrix(_) => Default::default(),
        }
    }

    /// Each family adapter re-checks the original word. Encodings without a
    /// policy are refused.
    fn prefix_requirement(
        &self,
        original_word: u32,
    ) -> Result<Option<crate::aarch64::sve::prefix::PrefixRequirement>, ()> {
        match self {
            Self::Exclusive(_)
            | Self::MemoryScalar(_)
            | Self::MemoryPair(_)
            | Self::MemoryFixed(_) => Ok(None),
            Self::MemoryLoad(_)
            | Self::MemoryMulti(_)
            | Self::MemoryStore(_)
            | Self::MemoryStructure(_)
            | Self::SmeMemory(_) => Ok(None),
            Self::Ordinary(_) => Ok(None),
            Self::Address(_) => Ok(None),
            Self::IntegerDot(_) => Ok(None),
            Self::IntegerBits(_) => Ok(None),
            Self::IntegerLogic(operand) => operand.prefix_requirement(original_word),
            Self::IntegerPredicateMove(_) => Ok(None),
            Self::IntegerProducts(operand) => operand.prefix_requirement(original_word),
            Self::IntegerSaturation(operand) => operand.prefix_requirement(original_word),
            Self::Rearrange(operand) => operand.prefix_requirement(original_word),
            Self::RearrangeExtract(operand) => operand.prefix_requirement(original_word),
            Self::RearrangeWiden(operand) => operand.prefix_requirement(original_word),
            Self::Reductions(operand) => operand.prefix_requirement(original_word),
            Self::Shifts(_) => Ok(None),
            Self::ShiftsNarrow(_) => Ok(None),
            Self::Sign(_) => Ok(None),
            Self::FloatingCopy(_) => Ok(None),
            Self::IntegerArithmetic(operand) => operand.prefix_requirement(original_word),
            Self::IntegerComparison(_) => Ok(None),
            Self::PredicateGeneration(_) => Ok(None),
            Self::PredicateLogic(_) => Ok(None),
            Self::Length(_) => Ok(None),
            Self::SmeLutV2(_) => Ok(None),
            Self::SmeTables(_) => Ok(None),
            Self::SveTables(_) => Ok(None),
            Self::SmeMovement(_) => Ok(None),
            Self::SmeIntegerVector(_) => Ok(None),
            Self::SmeIntegerDots(_) => Ok(None),
            Self::SmeIntegerMatrix(_) => Ok(None),
        }
    }

    /// Pairs may currently use only register-only followers that compile
    /// completely inline. A service, numerical or memory exit would need
    /// restart support.
    fn require_total_inline_prefix(&self, pc: GuestAddress) -> Result<(), CompileError> {
        match self {
            Self::IntegerLogic(_)
            | Self::IntegerProducts(_)
            | Self::IntegerSaturation(_)
            | Self::Rearrange(_)
            | Self::RearrangeExtract(_)
            | Self::RearrangeWiden(_)
            | Self::Reductions(_)
            | Self::IntegerArithmetic(_) => Ok(()),
            Self::Exclusive(_)
            | Self::MemoryScalar(_)
            | Self::MemoryPair(_)
            | Self::MemoryFixed(_)
            | Self::MemoryLoad(_)
            | Self::MemoryMulti(_)
            | Self::MemoryStore(_)
            | Self::MemoryStructure(_)
            | Self::SmeMemory(_)
            | Self::Ordinary(_)
            | Self::Address(_)
            | Self::IntegerDot(_)
            | Self::IntegerBits(_)
            | Self::IntegerPredicateMove(_)
            | Self::Shifts(_)
            | Self::ShiftsNarrow(_)
            | Self::Sign(_)
            | Self::FloatingCopy(_)
            | Self::IntegerComparison(_)
            | Self::PredicateGeneration(_)
            | Self::PredicateLogic(_)
            | Self::Length(_)
            | Self::SmeLutV2(_)
            | Self::SmeTables(_)
            | Self::SveTables(_)
            | Self::SmeMovement(_)
            | Self::SmeIntegerVector(_)
            | Self::SmeIntegerDots(_)
            | Self::SmeIntegerMatrix(_) => Err(CompileError(format!(
                "MOVPRFX pair validation: follower pair/effect requirements are not reviewed at {:#x}",
                pc.0
            ))),
        }
    }
}

impl Decoded {
    /// Reuse the already decoded ordinary block instruction. Effects receive a
    /// typed checked variant; unmigrated writers never fall back to direct RAM.
    pub(crate) fn checked_ordinary(
        instruction: Instruction,
        profile: crate::block::CheckedMemoryProfile,
    ) -> Result<Self, CompileError> {
        if profile == crate::block::CheckedMemoryProfile::M0DeviceRamRead64Staged
            && !matches!(&instruction.operation, Operation::Memory { .. })
        {
            return Err(CompileError(format!(
                "operation outside staged M0 ordinary read64 profile at {:#x}",
                instruction.pc.0
            )));
        }
        if let Operation::Exclusive(operand) = instruction.operation {
            // The existing typed adapter validates every decoded exclusive shape,
            // including constrained register roles, and derives its exact checked
            // quantity, ordering and host requirements. No raw memory fallback.
            return Ok(Self::Exclusive(
                crate::x86_64::exclusive::CheckedOperand::new(operand, profile)?,
            ));
        }
        if let Some(operand) = crate::x86_64::memory_store::checked_scalar::Operand::from_operation(
            &instruction.operation,
            profile,
        ) {
            return Ok(Self::MemoryScalar(operand));
        }
        if let Some(operand) = crate::x86_64::memory_store::checked_pair::Operand::from_operation(
            &instruction.operation,
            profile,
        ) {
            return Ok(Self::MemoryPair(operand));
        }
        if let Some(operand) = crate::x86_64::CheckedFixedMemoryOperand::from_operation(
            &instruction.operation,
            profile,
        ) {
            return Ok(Self::MemoryFixed(operand));
        }
        if !ordinary_permitted(&instruction.operation) {
            return Err(CompileError(format!(
                "operation outside checked GPR memory profile at {:#x}",
                instruction.pc.0
            )));
        }
        Ok(Self::Ordinary(instruction))
    }
    pub(crate) fn emit_checked_ordinary(
        &self,
        code: &mut Vec<u8>,
        pc: GuestAddress,
        target: TargetCpu,
        fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
    ) -> Result<(), CompileError> {
        match self {
            Self::Ordinary(instruction) => {
                if instruction.pc != pc {
                    return Err(CompileError("checked instruction PC differs".into()));
                }
                x86_64::emit_instruction(code, instruction, fixups, target);
            }
            Self::MemoryScalar(operand) => {
                crate::x86_64::memory_store::checked_scalar::emit_context(code, operand, pc.0)
            }
            Self::MemoryPair(operand) => {
                crate::x86_64::memory_store::checked_pair::emit_context(code, operand, pc.0)
            }
            Self::MemoryFixed(operand) => operand.emit_context(code, pc.0),
            Self::Exclusive(operand) => {
                crate::x86_64::exclusive::emit_context(code, operand, pc.0)?
            }
            Self::MemoryLoad(_)
            | Self::SmeMemory(_)
            | Self::MemoryMulti(_)
            | Self::MemoryStore(_)
            | Self::MemoryStructure(_)
            | Self::Address(_)
            | Self::SmeLutV2(_)
            | Self::SmeTables(_)
            | Self::SveTables(_)
            | Self::SmeMovement(_)
            | Self::IntegerBits(_)
            | Self::IntegerPredicateMove(_)
            | Self::Rearrange(_)
            | Self::Reductions(_)
            | Self::Shifts(_)
            | Self::ShiftsNarrow(_)
            | Self::IntegerComparison(_)
            | Self::PredicateGeneration(_)
            | Self::PredicateLogic(_)
            | Self::SmeIntegerVector(_)
            | Self::IntegerDot(_)
            | Self::IntegerLogic(_)
            | Self::IntegerProducts(_)
            | Self::IntegerSaturation(_)
            | Self::RearrangeExtract(_)
            | Self::RearrangeWiden(_)
            | Self::Sign(_)
            | Self::FloatingCopy(_)
            | Self::IntegerArithmetic(_)
            | Self::Length(_)
            | Self::SmeIntegerDots(_)
            | Self::SmeIntegerMatrix(_) => {
                return Err(CompileError(
                    "unrequested scalable operation in checked GPR memory profile".into(),
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn ordinary_permitted(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Bitfield(_)
            | Operation::PcRelative(_)
            | Operation::ConditionalSelect(_)
            | Operation::ConditionalCompare(_)
            | Operation::Crc(_)
            | Operation::Flags(_)
            | Operation::IntegerMath(_)
            | Operation::IntegerMinMax(_)
            | Operation::IntegerUnary(_)
            | Operation::AddSubRegister { .. }
            | Operation::AddSubCarry { .. }
            | Operation::AddSubExtended { .. }
            | Operation::LogicalRegister { .. }
            | Operation::LogicalImmediate { .. }
            | Operation::Branch { .. }
            | Operation::BranchCondition { .. }
            | Operation::BranchZero { .. }
            | Operation::BranchBit { .. }
            | Operation::MoveWide { .. }
            | Operation::AddSub { .. }
            | Operation::Synchronization(_)
            | Operation::Nop
            | Operation::Return
    )
}

fn require_features(
    profile: ScalableProfile,
    clauses: &mut Vec<FeatureRequirement>,
    requirement: FeatureRequirement,
    pc: GuestAddress,
) -> Result<(), CompileError> {
    profile.require_features(requirement, pc)?;
    clauses.push(requirement);
    Ok(())
}

// The existing contextual compiler uses this adapter; the leaf collector retains
// clauses from the same operand decoder without decoding source a second time.
fn decode(
    pc: GuestAddress,
    word: u32,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<Decoded, CompileError> {
    decode_recording_features(pc, word, profile, target, &mut Vec::new())
}

fn decode_recording_features(
    pc: GuestAddress,
    word: u32,
    profile: ScalableProfile,
    target: TargetCpu,
    clauses: &mut Vec<FeatureRequirement>,
) -> Result<Decoded, CompileError> {
    if let Some(operand) = sme_memory::decode(word) {
        let (streaming, za, sme2, zt0) = match operand {
            sme_memory::Operand::Vectors(_) => (true, false, true, false),
            sme_memory::Operand::Tile(_) => (true, true, false, false),
            sme_memory::Operand::ZaVector(_) => (false, true, false, false),
            sme_memory::Operand::Zt(_) => (false, true, true, true),
        };
        if streaming && !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        if za && !profile.mode.za_enabled() {
            return Err(CompileError(format!(
                "ZA enabled state required at {:#x}",
                pc.0
            )));
        }
        if zt0 && !profile.controls().zt0_enabled() {
            return Err(CompileError(format!("ZT0 enable required at {:#x}", pc.0)));
        }
        let required = if sme2 {
            ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2)
        } else {
            ScalableFeatures::of(ScalableFeature::Sme)
        };
        require_features(profile, clauses, FeatureRequirement::all(required), pc)?;
        x86_64::sme::memory::validate_target(&operand, target)
            .map_err(|reason| CompileError(format!("{reason} at {:#x}", pc.0)))?;
        return Ok(Decoded::SmeMemory(operand));
    }
    if let Some(decoded) = integer_vector::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved multi-vector integer encoding at {:#x}",
                pc.0
            ))
        })?;
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme2)),
            pc,
        )?;
        // This profile supplies streaming SME lengths, not ordinary SVE state.
        // The six SVE-category narrows enter through their SME2 alternative.
        if !profile.mode().streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::SmeIntegerVector(operand));
    }

    if let Some(decoded) = memory_load::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!("reserved streaming load encoding at {:#x}", pc.0))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::MemoryLoad(operand));
    }
    if let Some(decoded) = memory_multi::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming multi-vector memory encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(
                ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
            ),
            pc,
        )?;
        return Ok(Decoded::MemoryMulti(operand));
    }
    if let Some(decoded) = memory_store::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!("reserved streaming store encoding at {:#x}", pc.0))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        let mut features = ScalableFeatures::of(ScalableFeature::Sme);
        if matches!(operand, memory_store::Operand::Store(store)
            if store.memory_element == ElementSize::Quadword)
        {
            features = features.with(ScalableFeature::Sme2p1);
        }
        require_features(profile, clauses, FeatureRequirement::all(features), pc)?;
        return Ok(Decoded::MemoryStore(operand));
    }
    if let Some(decoded) = memory_structure::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming structured load encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        let mut required = ScalableFeatures::of(ScalableFeature::Sme);
        // Q allocation accepts SVE2p1 or SME2p1 architecturally. This compiler
        // entry owns SME streaming profiles, so it uses the SME2p1 alternative.
        if operand.requires_sve2p1_or_sme2p1() {
            required = required.with(ScalableFeature::Sme2p1);
        }
        require_features(profile, clauses, FeatureRequirement::all(required), pc)?;
        return Ok(Decoded::MemoryStructure(operand));
    }
    if let Some(decoded) = address::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming length/count encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        let mut features = ScalableFeatures::of(ScalableFeature::Sme);
        if matches!(
            operand.kind,
            address::Kind::Count(address::Count::Counter { .. })
        ) {
            features = features.with(ScalableFeature::Sme2);
        }
        require_features(profile, clauses, FeatureRequirement::all(features), pc)?;
        return Ok(Decoded::Address(operand));
    }
    if let Some(decoded) = dot::decode_integer(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer dot encoding at {:#x}",
                pc.0
            ))
        })?;
        if operand.requires_i8mm() && profile.declared_features().is_none() {
            return Err(CompileError(format!(
                "guest I8MM is outside the streaming profile at {:#x}",
                pc.0
            )));
        }
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        let mut required = ScalableFeatures::of(ScalableFeature::Sme);
        if operand.requires_i8mm() {
            required = required.with(ScalableFeature::I8mm);
        }
        if matches!(
            operand.kind,
            dot::Kind::Integer {
                products: dot::Products::Two,
                ..
            }
        ) {
            required = required.with(ScalableFeature::Sme2);
        }
        require_features(profile, clauses, FeatureRequirement::all(required), pc)?;
        return Ok(Decoded::IntegerDot(operand));
    }
    if let Some(decoded) = integer_predicate_move::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming predicate-to-vector encoding at {:#x}",
                pc.0
            ))
        })?;
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme2p1)),
            pc,
        )?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::IntegerPredicateMove(operand));
    }
    if let Some(decoded) = integer_bits::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer-bit encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        if x86_64::sve::integer_bits::requires_declared_dit_zero(operand, profile.length)
            && profile.required_dit() != Some(false)
        {
            return Err(CompileError(format!(
                "BSR leading counts require a declared DIT=0 profile at {:#x}",
                pc.0,
            )));
        }
        return Ok(Decoded::IntegerBits(operand));
    }
    if let Some(decoded) = integer_logic::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        if matches!(operand.kind, Kind::Copy(CopySource::Vector(_))) {
            return Err(CompileError(format!(
                "MOVPRFX pair validation required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::IntegerLogic(operand));
    }
    if let Some(decoded) = integer_comparison::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer comparison encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::IntegerComparison(operand));
    }
    if let Some(decoded) = integer_arithmetic::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer arithmetic encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::IntegerArithmetic(operand));
    }
    if let Some(decoded) = integer_saturation::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer saturation encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::IntegerSaturation(operand));
    }
    if let Some(decoded) = rearrange_widen::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming rearrangement encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::RearrangeWiden(operand));
    }
    if let Some(decoded) = shifts::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer shift encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        if x86_64::sve::shifts::requires_declared_dit_zero(operand, profile.vector_length())
            && profile.required_dit() != Some(false)
        {
            return Err(CompileError(format!(
                "selected streaming integer shift mapping requires declared DIT=0 at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::Shifts(operand));
    }
    if let Some(decoded) = shifts_narrow::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming width-conversion encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::ShiftsNarrow(operand));
    }
    if let Some(decoded) = sign::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!("reserved streaming sign encoding at {:#x}", pc.0))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::Sign(operand));
    }
    if let Some(decoded) = integer_products::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer product encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        x86_64::sve::integer_products::validate(operand).map_err(|()| {
            CompileError(format!(
                "invalid streaming integer product operand at {:#x}",
                pc.0
            ))
        })?;
        return Ok(Decoded::IntegerProducts(operand));
    }
    if let Some(operand) = integer_dots::decode(word) {
        let mut features = ScalableFeatures::of(ScalableFeature::Sme2);
        if operand.accumulator == ElementSize::Doubleword {
            features = features.with(ScalableFeature::SmeI16I64);
        }
        require_features(profile, clauses, FeatureRequirement::all(features), pc)?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        if !profile.mode.za_enabled() {
            return Err(CompileError(format!("ZA enable required at {:#x}", pc.0)));
        }
        return Ok(Decoded::SmeIntegerDots(operand));
    }
    if let Some(decoded) = sve_tables::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!("reserved streaming LUT encoding at {:#x}", pc.0))
        })?;
        profile.require_features(
            FeatureRequirement::all(
                ScalableFeatures::of(ScalableFeature::Sme2).with(ScalableFeature::Lut),
            ),
            pc,
        )?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        if profile.length.bits() < operand.minimum_vl_bits()
            || profile.controls().max_vector_length().bits() < operand.minimum_vl_bits()
        {
            return Err(CompileError(format!(
                "LUT requires a larger current/maximum vector length at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::SveTables(operand));
    }
    if let Some(decoded) = rearrange_extract::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming extraction encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::RearrangeExtract(operand));
    }
    if let Some(decoded) = floating_copy::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming floating copy encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::FloatingCopy(operand));
    }
    if let Some(decoded) = predicate_generation::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming predicate generation encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        let mut features = ScalableFeatures::of(ScalableFeature::Sme);
        if operand.requires_sme2() {
            features = features.with(ScalableFeature::Sme2);
        }
        require_features(profile, clauses, FeatureRequirement::all(features), pc)?;
        return Ok(Decoded::PredicateGeneration(operand));
    }
    if let Some(decoded) = predicate_logic::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming predicate logic encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        let mut features = ScalableFeatures::of(ScalableFeature::Sme);
        match operand.kind {
            predicate_logic::Kind::MoveVector { .. } => {
                features = features.with(ScalableFeature::Sme2p1);
            }
            predicate_logic::Kind::ExtractCounter { .. } => {
                features = features.with(ScalableFeature::Sme2);
            }
            _ => {}
        }
        require_features(profile, clauses, FeatureRequirement::all(features), pc)?;
        return Ok(Decoded::PredicateLogic(operand));
    }
    if let Some(decoded) = reductions::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer reduction encoding at {:#x}",
                pc.0
            ))
        })?;
        if operand.output == reductions::Output::Quadword {
            require_features(
                profile,
                clauses,
                FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme2p1)),
                pc,
            )?;
        }
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::Reductions(operand));
    }
    if let Some(decoded) = rearrange::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming rearrangement encoding at {:#x}",
                pc.0
            ))
        })?;
        if matches!(
            operand,
            rearrange::Operand::Interleave { segment: true, .. }
                | rearrange::Operand::Extract { segment: true, .. }
                | rearrange::Operand::Table { segment: true, .. }
                | rearrange::Operand::DuplicateSegment { .. }
        ) {
            require_features(
                profile,
                clauses,
                FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme2p1)),
                pc,
            )?;
        }
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        if x86_64::sve::rearrange::requires_explicit_dit_zero(operand, profile.length, target)
            && profile.required_dit() != Some(false)
        {
            return Err(CompileError(format!(
                "scalar table lookup requires explicitly declared DIT=0 at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::Rearrange(operand));
    }
    if let Some(operand) = movement::decode(word) {
        let requirements = operand.requirements;
        if requirements.halted {
            return Err(CompileError(format!(
                "halted debug execution required at {:#x}",
                pc.0
            )));
        }
        let feature = match requirements.feature {
            movement::Feature::Sme => ScalableFeature::Sme,
            movement::Feature::Sme2 => ScalableFeature::Sme2,
            movement::Feature::Sme2p1 => ScalableFeature::Sme2p1,
        };
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(feature)),
            pc,
        )?;
        if requirements.za && !profile.mode.za_enabled() {
            return Err(CompileError(format!("ZA state required at {:#x}", pc.0)));
        }
        if requirements.streaming && !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        if requirements.zt0 && !profile.controls().zt0_enabled() {
            return Err(CompileError(format!(
                "ZT0 enabled state required at {:#x}",
                pc.0
            )));
        }
        if profile.controls().max_vector_length().bits()
            < usize::from(requirements.minimum_implemented_svl_bits)
        {
            return Err(CompileError(format!(
                "maximum streaming vector length is too small at {:#x}",
                pc.0
            )));
        }
        if profile.length.bits() < usize::from(requirements.minimum_current_svl_bits) {
            return Err(CompileError(format!(
                "current streaming vector length is too small at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::SmeMovement(operand));
    }
    if let Some(operand) = lut_v2::decode(word) {
        let mut required =
            ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::SmeLutV2);
        if operand.requires_sme2p1() {
            required = required.with(ScalableFeature::Sme2p1);
        }
        require_features(profile, clauses, FeatureRequirement::all(required), pc)?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        if !profile.mode.za_enabled() || !profile.controls().zt0_enabled() {
            return Err(CompileError(format!(
                "SME LUTv2 requires ZA and enabled ZT0 at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::SmeLutV2(operand));
    }
    if let Some(operand) = tables::decode(word) {
        if x86_64::sme::tables::requires_dit_zero(&operand, profile.length, target)
            && profile.required_dit() != Some(false)
        {
            return Err(CompileError(format!(
                "scalar SME lookup requires a declared DIT=0 profile at {:#x}",
                pc.0
            )));
        }
        let mut features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
        if operand.feature == tables::Feature::Sme2p1 {
            features = features.with(ScalableFeature::Sme2p1);
        }
        require_features(profile, clauses, FeatureRequirement::all(features), pc)?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        let minimum = operand.minimum_svl_bits();
        if profile.length.bits() < minimum
            || profile.controls().max_vector_length().bits() < minimum
        {
            return Err(CompileError(format!(
                "SME table operands require SVL >= {minimum} bits at {:#x}",
                pc.0
            )));
        }
        if operand.requires_zt0()
            && (!profile.mode.za_enabled() || !profile.controls().zt0_enabled())
        {
            return Err(CompileError(format!(
                "SME lookup requires ZA and enabled ZT0 at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::SmeTables(operand));
    }
    if let Some(operand) = integer_matrix::decode(word) {
        let mut required = ScalableFeatures::of(ScalableFeature::Sme);
        if operand.requires_sme2() {
            required = required.with(ScalableFeature::Sme2);
        }
        if operand.requires_i16i64() {
            required = required.with(ScalableFeature::SmeI16I64);
        }
        require_features(profile, clauses, FeatureRequirement::all(required), pc)?;
        if !profile.mode().streaming() || !profile.mode().za_enabled() {
            return Err(CompileError(format!(
                "streaming mode and ZA required for integer matrix operation at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::SmeIntegerMatrix(operand));
    }
    if let Some(operand) = length::decode(word) {
        require_features(
            profile,
            clauses,
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::Length(operand));
    }
    let instruction = Decoder
        .lift(pc, word)
        .map_err(|reason| CompileError(format!("unsupported ARM64 semantics: {reason:?}")))?;
    if !ordinary_permitted(&instruction.operation) {
        return Err(CompileError(format!(
            "operation outside extended integer profile at {:#x}: {:#010x}",
            pc.0, word
        )));
    }
    x86_64::validate_target(&instruction, target)
        .map_err(|reason| CompileError(format!("x86 emission failed: {reason:?}")))?;
    Ok(Decoded::Ordinary(instruction))
}

pub(crate) fn context_wrapper() -> Vec<u8> {
    let mut code = Vec::with_capacity(CONTEXT_WRAPPER_BYTES);
    code.extend(PUSH_R15);
    code.extend(MOV_R15_RSI);
    code.push(CALL_REL32);
    code.extend(((CONTEXT_WRAPPER_BYTES - CALL_END) as i32).to_le_bytes());
    code.extend(POP_R15);
    code.push(RET);
    code
}

fn emit_decoded(
    code: &mut Vec<u8>,
    pc: GuestAddress,
    instruction: Decoded,
    profile: ScalableProfile,
    target: TargetCpu,
    fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
) -> Result<(), CompileError> {
    match instruction {
        Decoded::Exclusive(_) => {
            return Err(CompileError(
                "exclusive service was not requested by scalable profile".into(),
            ));
        }
        Decoded::MemoryScalar(_) => {
            return Err(CompileError(
                "checked scalar service was not requested by scalable profile".into(),
            ));
        }
        Decoded::MemoryPair(_) | Decoded::MemoryFixed(_) => {
            return Err(CompileError(
                "checked fixed-width memory service was not requested by scalable profile".into(),
            ));
        }
        Decoded::Address(operand) => {
            x86_64::sve::address::emit(code, &operand, profile.length, target);
        }
        Decoded::Ordinary(instruction) => {
            x86_64::emit_instruction(code, &instruction, fixups, target);
        }
        Decoded::IntegerDot(operand) => {
            if !x86_64::sve::dot::emit_integer(code, &operand, profile.length, target) {
                return Err(CompileError(format!(
                    "unsupported streaming integer dot operands at {:#x}",
                    pc.0
                )));
            }
        }
        Decoded::IntegerPredicateMove(operand) => {
            x86_64::sve::integer_predicate_move::emit(code, operand, profile.length, target);
        }
        Decoded::IntegerBits(operand) => {
            x86_64::sve::integer_bits::emit(code, operand, profile.length, target);
        }
        Decoded::IntegerLogic(operand) => {
            x86_64::sve::integer_logic::emit(code, operand, profile.length, target);
        }
        Decoded::IntegerComparison(operand) => {
            x86_64::sve::integer_comparison::emit(code, operand, profile.length, target);
        }
        Decoded::IntegerArithmetic(operand) => {
            x86_64::sve::integer_arithmetic::emit(code, operand, profile.length, target);
        }
        Decoded::IntegerSaturation(operand) => {
            x86_64::sve::integer_saturation::emit(code, operand, profile.length, target);
        }
        Decoded::RearrangeWiden(operand) => {
            x86_64::sve::rearrange_widen::emit(code, operand, profile.length, target);
        }
        Decoded::Shifts(operand) => {
            x86_64::sve::shifts::emit(code, operand, profile.length, target);
        }
        Decoded::ShiftsNarrow(operand) => {
            x86_64::sve::shifts_narrow::emit(code, operand, profile.length, target);
        }
        Decoded::Sign(operand) => {
            x86_64::sve::sign::emit(code, &operand, profile.length, target);
        }
        Decoded::IntegerProducts(operand) => {
            x86_64::sve::integer_products::emit(code, operand, profile.length, target);
        }
        Decoded::SmeIntegerDots(operand) => {
            x86_64::sme::integer_dots::emit(code, &operand, profile.length, target);
        }
        Decoded::RearrangeExtract(operand) => {
            x86_64::sve::rearrange_extract::emit(code, operand, profile.length, target);
        }
        Decoded::FloatingCopy(operand) => {
            x86_64::sve::floating_copy::emit(code, operand, profile.length, target);
        }
        Decoded::PredicateGeneration(operand) => {
            x86_64::sve::predicate_generation::emit(code, &operand, profile.length, target);
        }
        Decoded::PredicateLogic(operand) => {
            x86_64::sve::predicate_logic::emit(code, &operand, profile.length, target);
        }
        Decoded::Reductions(operand) => {
            x86_64::sve::reductions::emit(code, operand, profile.length, target);
        }
        Decoded::Rearrange(operand) => {
            x86_64::sve::rearrange::emit(code, operand, profile.length, target);
        }
        Decoded::SmeIntegerVector(operand) => {
            x86_64::sme::integer_vector::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::SmeMovement(operand) => {
            x86_64::sme::movement::emit(code, &operand, profile.length, target)
                .map_err(|reason| CompileError(format!("{reason} at {:#x}", pc.0)))?;
        }
        Decoded::SmeLutV2(operand) => {
            x86_64::sme::tables::emit_lut_v2(code, &operand, profile.length, target);
        }
        Decoded::SmeTables(operand) => {
            x86_64::sme::tables::emit(code, &operand, profile.length, target);
        }
        Decoded::SveTables(operand) => {
            x86_64::sve::tables::emit(code, &operand, profile.length, target);
        }
        Decoded::SmeIntegerMatrix(operand) => {
            x86_64::sme::integer_matrix::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::SmeMemory(operand) => {
            x86_64::sme::memory::emit(code, &operand, profile.length, target, pc.0)
                .map_err(|reason| CompileError(format!("{reason} at {:#x}", pc.0)))?;
        }
        Decoded::MemoryLoad(operand) => {
            x86_64::sve::memory_load::emit(code, operand, profile.length, target, pc.0);
        }
        Decoded::MemoryMulti(operand) => {
            x86_64::sve::memory_multi::emit(code, &operand, profile.length, target, pc.0);
        }
        Decoded::MemoryStore(operand) => {
            x86_64::sve::memory_store::emit(code, &operand, profile.length, target, pc.0);
        }
        Decoded::MemoryStructure(operand) => {
            x86_64::sve::memory_structure::emit(code, &operand, profile.length, target, pc.0);
        }
        Decoded::Length(operand) => {
            x86_64::sme::length::emit(code, &operand, profile.length);
        }
    }
    Ok(())
}

struct DecodedLeafInstruction {
    pc: GuestAddress,
    instruction: Decoded,
    feature_clauses: Vec<FeatureRequirement>,
}

fn decode_leaf(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<Vec<DecodedLeafInstruction>, CompileError> {
    if source.is_empty()
        || !source.len().is_multiple_of(INSTRUCTION_BYTES)
        || !base.0.is_multiple_of(INSTRUCTION_BYTES as u64)
    {
        return Err(CompileError(
            "input and guest base must be nonempty/aligned to 4 bytes".into(),
        ));
    }
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < source.len() {
        if let Some(pair) = prefix::decode_pair(source, offset, base, profile, target)? {
            instructions.push(DecodedLeafInstruction {
                pc: pair.prefix_pc,
                instruction: Decoded::IntegerLogic(pair.prefix),
                feature_clauses: vec![pair.prefix_features],
            });
            instructions.push(DecodedLeafInstruction {
                pc: pair.follower_pc,
                instruction: pair.follower,
                feature_clauses: pair.follower_features,
            });
            offset += prefix::PAIR_BYTES;
            continue;
        }
        let pc = GuestAddress(
            base.0
                .checked_add(offset as u64)
                .ok_or_else(|| CompileError("guest address overflow".into()))?,
        );
        let word = u32::from_le_bytes(
            source[offset..offset + INSTRUCTION_BYTES]
                .try_into()
                .expect("checked leaf instruction alignment"),
        );
        let mut feature_clauses = Vec::new();
        let instruction =
            decode_recording_features(pc, word, profile, target, &mut feature_clauses)?;
        instructions.push(DecodedLeafInstruction {
            pc,
            instruction,
            feature_clauses,
        });
        offset += INSTRUCTION_BYTES;
    }
    if !matches!(
        instructions.last(),
        Some(DecodedLeafInstruction {
            instruction: Decoded::Ordinary(Instruction {
                operation: Operation::Return,
                ..
            }),
            ..
        })
    ) {
        return Err(CompileError("leaf region must end in RET X30".into()));
    }
    for DecodedLeafInstruction {
        pc,
        instruction: decoded,
        ..
    } in &instructions
    {
        let Decoded::Ordinary(instruction) = decoded else {
            continue;
        };
        let target = match &instruction.operation {
            Operation::Branch { target }
            | Operation::BranchCondition { target, .. }
            | Operation::BranchZero { target, .. }
            | Operation::BranchBit { target, .. } => Some(*target),
            _ => None,
        };
        if let Some(target) = target
            && instructions
                .binary_search_by_key(&target.0, |instruction| instruction.pc.0)
                .is_err()
        {
            return Err(CompileError(format!(
                "unresolved direct target {:#x} from {:#x}",
                target.0, pc.0
            )));
        }
    }
    Ok(instructions)
}

/// Derive the whole body's service requirements with the same parser used to
/// compile it. Leaves with no memory access return empty requirements.
pub fn memory_requirements(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<MemoryRequirements, CompileError> {
    leaf_memory_requirements(&decode_leaf(source, base, profile, target)?)
}

fn leaf_memory_requirements(
    instructions: &[DecodedLeafInstruction],
) -> Result<MemoryRequirements, CompileError> {
    instructions
        .iter()
        .try_fold(MemoryRequirements::default(), |requirements, decoded| {
            requirements
                .merge(decoded.instruction.memory_requirements())
                .ok_or_else(|| {
                    CompileError(format!(
                        "conflicting memory control requirements at {:#x}",
                        decoded.pc.0
                    ))
                })
        })
}

/// All outputs derive from one validated source vector. No caller-supplied
/// execution metadata or service requirements are accepted.
pub struct PreparedLeafCode {
    pub native: NativeBlock,
    pub memory_requirements: MemoryRequirements,
    pub execution_requirements: ScalableExecutionRequirements,
}

pub fn prepare_leaf(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<PreparedLeafCode, CompileError> {
    let instructions = decode_leaf(source, base, profile, target)?;
    let memory_requirements = leaf_memory_requirements(&instructions)?;
    let execution_requirements = ScalableExecutionRequirements::new(
        instructions
            .iter()
            .map(|decoded| {
                InstructionExecutionRequirements::new(
                    decoded.pc,
                    decoded.feature_clauses.clone(),
                    decoded.instruction.execution_access_requirements(),
                    decoded.instruction.guest_memory_quantity(),
                )
            })
            .collect(),
    );
    let native = emit_leaf(instructions, profile, target)?;
    Ok(PreparedLeafCode {
        native,
        memory_requirements,
        execution_requirements,
    })
}

/// Compile a two-argument context leaf ending in RET X30. The runtime validates
/// this profile against its state before calling it.
pub fn compile_for_profile(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    emit_leaf(decode_leaf(source, base, profile, target)?, profile, target)
}

fn emit_leaf(
    instructions: Vec<DecodedLeafInstruction>,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    let mut code = context_wrapper();
    let mut source_map = Vec::with_capacity(instructions.len());
    let mut fixups = Vec::new();
    for DecodedLeafInstruction {
        pc, instruction, ..
    } in instructions
    {
        source_map.push((pc, code.len()));
        emit_decoded(&mut code, pc, instruction, profile, target, &mut fixups)?;
    }
    let offsets: BTreeMap<_, _> = source_map
        .iter()
        .map(|(pc, offset)| (pc.0, *offset))
        .collect();
    for (pc, target, displacement) in fixups {
        let destination = offsets.get(&target.0).ok_or_else(|| {
            CompileError(format!(
                "unresolved direct target {:#x} from {:#x}",
                target.0, pc.0
            ))
        })?;
        let relative =
            i32::try_from(*destination as i128 - (displacement + size_of::<i32>()) as i128)
                .map_err(|_| CompileError("native branch displacement overflow".into()))?;
        code[displacement..displacement + size_of::<i32>()]
            .copy_from_slice(&relative.to_le_bytes());
    }
    Ok(NativeBlock {
        x86_64_code: code,
        source_map,
    })
}

#[cfg(test)]
mod tests;
