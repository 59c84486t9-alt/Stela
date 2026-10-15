//! Context-backed leaf compilation with immutable scalable specialization.
//!
//! Declared scalable mappings and existing pure GPR/control mappings are
//! admitted after guest feature and execution-mode checks. Unsupported
//! effects remain explicit declines.

pub mod block;

mod prefix;

use std::collections::BTreeMap;

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
    /// Preserve the original fixed SME2 profile and its artifact identity.
    pub const fn new(length: VectorLength, mode: ScalableMode) -> Self {
        Self {
            length,
            mode,
            kind: ScalableProfileKind::V1,
        }
    }

    /// Declare guest availability and controls explicitly, without inferring
    /// Apple hardware capabilities or silently adding feature dependencies.
    /// V2 requires PSTATE.DIT=0; the execution caller must validate that state.
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

    /// Only V2 manifests carry a declared feature list. V1 artifacts retain
    /// their original shape and fixed profile ID.
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
            && std::ptr::eq(context.scalable.cast_const(), view)
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
            Self::MemoryScalar(_) => ScalableAccessRequirements::Unqualified,
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
            Self::MemoryScalar(_) => GuestMemoryQuantity::Unqualified,
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

    /// Original canonical word is rechecked by each frozen family adapter.
    /// None remains unaudited; no unreviewed effect class receives a default permit.
    fn prefix_requirement(
        &self,
        original_word: u32,
    ) -> Result<Option<crate::aarch64::sve::prefix::PrefixRequirement>, ()> {
        match self {
            Self::Exclusive(_) | Self::MemoryScalar(_) => Ok(None),
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

    /// Pair execution currently permits only reviewed total register-only mappings.
    /// Metadata alone never authorizes a service, numerical or memory restart edge.
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

const CHECKED_EXCLUSIVE_SCALAR_BYTES: u8 = size_of::<u32>() as u8;

impl Decoded {
    /// Reuse the already decoded ordinary block instruction. Effects receive a
    /// typed checked variant; unmigrated writers never fall back to direct RAM.
    pub(crate) fn checked_ordinary(
        instruction: Instruction,
        profile: crate::block::CheckedMemoryProfile,
    ) -> Result<Self, CompileError> {
        if let Operation::Exclusive(operand) = instruction.operation {
            use crate::aarch64::exclusive::{Data, Operand};
            if !matches!(
                operand,
                Operand::Clear
                    | Operand::Transfer {
                        element_bytes: CHECKED_EXCLUSIVE_SCALAR_BYTES,
                        data: Data::Scalar(_),
                        ..
                    }
            ) {
                return Err(CompileError(format!(
                    "exclusive width/pair outside checked scalar32 scope at {:#x}",
                    instruction.pc.0
                )));
            }
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

/// Derive complete-body service requirements from the same validated leaf
/// parser used by compilation. Pure leaves return explicit empty requirements.
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

/// Compile an extended two-argument leaf ending in RET X30. The runtime must
/// validate this exact profile against its owned view before unsafe invocation.
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
#[path = "extended/integer_dots_tests.rs"]
mod integer_dots_tests;

#[cfg(test)]
mod movement_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_bits_register_exact_bodies_and_source_maps() {
        const CANONICAL_WORDS: [u32; 7] = [
            0x0418_a020, // CLS
            0x0419_a020, // CLZ
            0x041a_a020, // CNT
            0x0527_8020, // RBIT
            0x0564_8020, // REVB
            0x05a5_8020, // REVH
            0x05e6_8020, // REVW
        ];
        for word in CANONICAL_WORDS {
            let operand = integer_bits::decode(word).unwrap().unwrap();
            assert_eq!(
                crate::aarch64::sve::decode(word),
                Some(Ok(crate::aarch64::sve::Operand::IntegerBits(operand)))
            );
            for bytes in [16, 32, 64, 128, 256] {
                for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Sse41] {
                    let native = compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, true),
                        target,
                    )
                    .unwrap();
                    let mut body = Vec::new();
                    x86_64::sve::integer_bits::emit(
                        &mut body,
                        operand,
                        VectorLength::from_bytes(bytes).unwrap(),
                        target,
                    );
                    let return_offset = CONTEXT_WRAPPER_BYTES + body.len();
                    assert_eq!(
                        native.source_map,
                        [
                            (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                            (GuestAddress(0x1004), return_offset)
                        ]
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES..return_offset],
                        body
                    );
                    assert_eq!(&native.x86_64_code[return_offset..], &[RET]);
                }
            }
            let length = VectorLength::from_bytes(16).unwrap();
            for streaming in [false, true] {
                for za in [false, true] {
                    // Base SME is sufficient; no accidental SME2 requirement.
                    let selected = ScalableProfile::new_with_features(
                        length,
                        ScalableMode::new(streaming, za),
                        ScalableFeatures::of(ScalableFeature::Sme),
                        ScalableControls::new(length, false),
                    )
                    .unwrap();
                    let result = compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        selected,
                        TargetCpu::Baseline,
                    );
                    if streaming {
                        assert!(result.is_ok());
                    } else {
                        assert!(result.unwrap_err().0.contains("streaming mode required"));
                    }
                }
            }
        }
    }

    #[test]
    fn integer_bits_reserved_zeroing_and_prefix_inputs_remain_explicit() {
        const RESERVED_REVERSE_WORDS: [u32; 6] = [
            0x0524_8020,
            0x0525_8020,
            0x0565_8020,
            0x0526_8020,
            0x0566_8020,
            0x05a6_8020,
        ];
        for word in RESERVED_REVERSE_WORDS {
            assert!(
                compile_for_profile(
                    &words(&[NOP, word, RET_X30]),
                    GuestAddress(0),
                    profile(16, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("reserved streaming integer-bit")
            );
        }
        const ZEROING_WORDS: [u32; 7] = [
            0x0408_a020,
            0x0409_a020,
            0x040a_a020,
            0x0527_a020,
            0x0564_a020,
            0x05a5_a020,
            0x05e6_a020,
        ];
        for word in ZEROING_WORDS {
            assert!(
                compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0),
                    profile(16, true),
                    TargetCpu::Baseline
                )
                .is_err()
            );
        }
        const CLS_Z0_B_P0_Z1_B: u32 = 0x0418_a020;
        assert!(
            compile_for_profile(
                &words(&[MOVPRFX_Z0_Z1, CLS_Z0_B_P0_Z1_B, RET_X30]),
                GuestAddress(0),
                profile(16, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("MOVPRFX pair validation")
        );
        assert!(crate::compile(&words(&[CLS_Z0_B_P0_Z1_B, RET_X30]), GuestAddress(0)).is_err());
    }
    #[test]
    fn integer_bits_bsr_recipes_require_declared_dit_zero() {
        const SIZE_SHIFT: u32 = 22;
        const LEADING_COUNT_WORDS: [u32; 2] = [0x0418_a020, 0x0419_a020];
        const VECTOR_BYTES: [usize; 5] = [16, 32, 64, 128, 256];
        // Independent audited B/H/S/D decisions by ascending supported SVL.
        const EXPECTED_DIT_REQUIREMENTS: [[bool; 5]; 4] = [
            [false; 5],
            [false; 5],
            [false, false, false, false, true],
            [true; 5],
        ];
        for canonical in LEADING_COUNT_WORDS {
            for (size, expected_by_length) in EXPECTED_DIT_REQUIREMENTS.into_iter().enumerate() {
                let word = canonical | ((size as u32) << SIZE_SHIFT);
                let operand = integer_bits::decode(word).unwrap().unwrap();
                for (length_index, bytes) in VECTOR_BYTES.into_iter().enumerate() {
                    let length = VectorLength::from_bytes(bytes).unwrap();
                    let requires_declared_dit_zero = expected_by_length[length_index];
                    assert_eq!(
                        x86_64::sve::integer_bits::requires_declared_dit_zero(operand, length),
                        requires_declared_dit_zero
                    );
                    let declared = ScalableProfile::new_with_features(
                        length,
                        ScalableMode::new(true, false),
                        ScalableFeatures::of(ScalableFeature::Sme),
                        ScalableControls::new(length, false),
                    )
                    .unwrap();
                    assert_eq!(declared.required_dit(), Some(false));
                    for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Sse41] {
                        let positive = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0),
                            declared,
                            target,
                        )
                        .unwrap();
                        let mut body = Vec::new();
                        x86_64::sve::integer_bits::emit(&mut body, operand, length, target);
                        assert_eq!(
                            &positive.x86_64_code[CONTEXT_WRAPPER_BYTES..][..body.len()],
                            body
                        );
                        let legacy = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0),
                            profile(bytes, true),
                            target,
                        );
                        if requires_declared_dit_zero {
                            assert!(legacy.unwrap_err().0.contains("declared DIT=0"));
                        } else {
                            assert_eq!(legacy.unwrap().x86_64_code, positive.x86_64_code);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn feature_admission_declines_with_exact_pc_and_missing_clause_names() {
        let length = VectorLength::from_bytes(16).unwrap();
        let features = ScalableFeatures::of(ScalableFeature::Sme);
        let profile = ScalableProfile::new_with_features(
            length,
            ScalableMode::new(true, false),
            features,
            ScalableControls::new(length, false),
        )
        .unwrap();
        let required = ScalableFeatures::of(ScalableFeature::Sme2);
        let alternatives =
            ScalableFeatures::of(ScalableFeature::SmeF16F16).with(ScalableFeature::SmeF8F16);
        let pc = GuestAddress(0x1234);
        let error = profile
            .require_features(FeatureRequirement::all_and_any(required, alternatives), pc)
            .unwrap_err();
        assert_eq!(
            error.0,
            "unavailable guest features at 0x1234: requires FEAT_SME2; requires one of FEAT_SME_F16F16, FEAT_SME_F8F16"
        );
        assert!(
            profile
                .require_features(FeatureRequirement::all(features), pc)
                .is_ok()
        );
        assert!(
            profile
                .require_features(FeatureRequirement::default(), pc)
                .is_ok()
        );
        assert!(
            ScalableProfile::new(length, ScalableMode::default())
                .require_features(FeatureRequirement::all(required), pc)
                .is_ok()
        );
    }

    #[test]
    fn declared_sme1_za_storage_does_not_require_zt0_or_streaming_banks() {
        let length = VectorLength::from_bytes(64).unwrap();
        let mode = ScalableMode::new(false, true);
        let sme = ScalableFeatures::of(ScalableFeature::Sme);
        let mut za = [0_u8; 64 * 64];
        let mut view = ScalableStateView {
            svl_bytes: length.bytes() as u16,
            reserved: [0; 6],
            svcr: mode.svcr(),
            tpidr2_el0: 0,
            fpmr: 0,
            z_upper: std::ptr::null_mut(),
            predicates: std::ptr::null_mut(),
            ffr: std::ptr::null_mut(),
            za: za.as_mut_ptr(),
            zt0: std::ptr::null_mut(),
        };
        let context = ExecutionContext {
            scalable: &mut view,
            ..ExecutionContext::default()
        };
        let profile = ScalableProfile::new_with_features(
            length,
            mode,
            sme,
            ScalableControls::new(length, false),
        )
        .unwrap();
        assert!(profile.validate_view(&context, &view).is_ok());
        assert_eq!(profile.required_dit(), Some(false));
        let zt0_profile = ScalableProfile::new_with_features(
            length,
            mode,
            sme.with(ScalableFeature::Sme2),
            ScalableControls::new(length, true),
        )
        .unwrap();
        assert!(zt0_profile.validate_view(&context, &view).is_err());
        let original = ScalableProfile::new(length, mode);
        assert!(original.validate_view(&context, &view).is_err());
        assert_eq!(original.required_dit(), None);
        let mut zt0 = [0_u8; crate::aarch64::scalable::LOOKUP_TABLE_BYTES];
        view.zt0 = zt0.as_mut_ptr();
        assert!(zt0_profile.validate_view(&context, &view).is_ok());
        assert!(original.validate_view(&context, &view).is_ok());
        view.za = std::ptr::null_mut();
        assert!(profile.validate_view(&context, &view).is_err());
        assert!(zt0_profile.validate_view(&context, &view).is_err());
    }

    #[test]
    fn declared_profile_requires_explicit_dependencies_and_controls() {
        let length = VectorLength::from_bytes(64).unwrap();
        let controls = ScalableControls::new(length, false);
        let sme = ScalableFeatures::of(ScalableFeature::Sme);
        let mode = ScalableMode::new(true, false);
        assert!(
            ScalableProfile::new_with_features(length, mode, ScalableFeatures::empty(), controls)
                .is_err()
        );
        assert!(
            ScalableProfile::new_with_features(
                length,
                mode,
                sme.with(ScalableFeature::Sme2p1),
                controls
            )
            .is_err()
        );
        assert!(
            ScalableProfile::new_with_features(
                length,
                mode,
                sme,
                ScalableControls::new(length, true)
            )
            .is_err()
        );
        assert!(
            ScalableProfile::new_with_features(
                length,
                mode,
                sme,
                ScalableControls::new(VectorLength::from_bytes(32).unwrap(), false)
            )
            .is_err()
        );
        let profile = ScalableProfile::new_with_features(length, mode, sme, controls).unwrap();
        assert_eq!(profile.id(), DECLARED_PROFILE_ID);
        assert_eq!(profile.features(), sme);
        assert_eq!(profile.declared_features(), Some(sme));
        assert_eq!(profile.controls(), controls);
    }

    #[test]
    fn declared_profile_identity_includes_features_and_controls() {
        let length = VectorLength::from_bytes(32).unwrap();
        let mode = ScalableMode::new(true, true);
        let features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
        let controls = ScalableControls::new(length, false);
        let original =
            ScalableProfile::new_with_features(length, mode, features, controls).unwrap();
        for (other_features, other_controls) in [
            (features.with(ScalableFeature::Sme2p1), controls),
            (
                features,
                ScalableControls::new(VectorLength::from_bytes(64).unwrap(), false),
            ),
            (features, ScalableControls::new(length, true)),
        ] {
            assert_ne!(
                original,
                ScalableProfile::new_with_features(length, mode, other_features, other_controls)
                    .unwrap()
            );
        }
    }

    #[test]
    fn original_profile_retains_fixed_identity_and_manifest_shape() {
        let length = VectorLength::from_bytes(64).unwrap();
        let mode = ScalableMode::new(false, true);
        let original = ScalableProfile::new(length, mode);
        assert_eq!(original.id(), PROFILE_ID);
        assert_eq!(original.vector_length(), length);
        assert_eq!(original.mode(), mode);
        assert_eq!(original.declared_features(), None);
        assert_eq!(original.features().names(), ["FEAT_SME", "FEAT_SME2"]);
        assert_eq!(original.controls(), ScalableControls::new(length, false));
        assert_ne!(
            original,
            ScalableProfile::new_with_features(
                length,
                mode,
                original.features(),
                original.controls()
            )
            .unwrap()
        );
    }

    #[test]
    fn declared_profiles_keep_base_sme_families_available() {
        const BASE_SME_WORDS: [u32; 6] = [
            0x041a_0040, // AND predicated.
            0x0461_5820, // ADDSPL.
            0x0416_a020, // ABS predicated.
            0x045c_bfff, // FABS predicated.
            0x4500_f820, // SABA.
            0x4482_003f, // Four-product SDOT.
        ];
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            let profile = ScalableProfile::new_with_features(
                length,
                ScalableMode::new(true, false),
                ScalableFeatures::of(ScalableFeature::Sme),
                ScalableControls::new(length, false),
            )
            .unwrap();
            for word in BASE_SME_WORDS {
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0x1234),
                        profile,
                        TargetCpu::Baseline,
                    )
                    .is_ok()
                );
            }
        }
    }

    #[test]
    fn declared_dot_features_preserve_v1_scope_and_check_optional_requirements() {
        const TWO_PRODUCT_SDOT: u32 = 0x4402_c820;
        const MIXED_DOT_WORDS: [u32; 3] = [0x4482_7820, 0x44a2_1820, 0x44a2_1c20];
        let length = VectorLength::from_bytes(16).unwrap();
        let mode = ScalableMode::new(true, false);
        let sme = ScalableFeatures::of(ScalableFeature::Sme);
        let declared = |features| {
            ScalableProfile::new_with_features(
                length,
                mode,
                features,
                ScalableControls::new(length, false),
            )
            .unwrap()
        };
        let compile = |word, profile| {
            compile_for_profile(
                &words(&[word, RET_X30]),
                GuestAddress(0x1234),
                profile,
                TargetCpu::Baseline,
            )
        };
        let missing = compile(TWO_PRODUCT_SDOT, declared(sme)).unwrap_err();
        assert!(missing.0.contains("0x1234") && missing.0.contains("requires FEAT_SME2"));
        assert!(compile(TWO_PRODUCT_SDOT, declared(sme.with(ScalableFeature::Sme2))).is_ok());
        assert!(compile(TWO_PRODUCT_SDOT, ScalableProfile::new(length, mode)).is_ok());
        for word in MIXED_DOT_WORDS {
            let legacy = compile(word, ScalableProfile::new(length, mode)).unwrap_err();
            assert!(legacy.0.contains("I8MM is outside") && legacy.0.contains("0x1234"));
            let missing = compile(word, declared(sme.with(ScalableFeature::Sme2))).unwrap_err();
            assert!(missing.0.contains("requires FEAT_I8MM") && missing.0.contains("0x1234"));
            assert!(compile(word, declared(sme.with(ScalableFeature::I8mm))).is_ok());
        }
    }

    const RET_X30: u32 = 0xd65f_03c0;
    const NOP: u32 = 0xd503_201f;
    const AND_Z0_Z1_Z2: u32 = 0x0422_3020;
    const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
    const RDSVL_X0_ONE: u32 = 0x04bf_5820;

    #[test]
    fn integer_matrix_admission_checks_features_mode_and_source_maps() {
        const MATRIX_WORDS: [u32; 6] = [
            0xc1a0_1c10, // ADD ZA.S pair.
            0xc100_0000, // SMLALL ZA.S indexed byte products.
            0xc180_0000, // SMLALL ZA.D indexed halfword products.
            0xa080_0000, // SMOPA ZA.S byte outer products.
            0xa0c0_0000, // SMOPA ZA.D halfword outer products.
            0x8080_0008, // BMOPA ZA.S XNOR outer products.
        ];
        for word in MATRIX_WORDS {
            let operand = integer_matrix::decode(word).unwrap();
            let source = words(&[word, RET_X30]);
            assert!(crate::compile(&source, GuestAddress(0)).is_err());
            let legacy = ScalableProfile::new(
                VectorLength::from_bytes(16).unwrap(),
                ScalableMode::new(true, true),
            );
            let legacy_result =
                compile_for_profile(&source, GuestAddress(0), legacy, TargetCpu::Baseline);
            assert_eq!(legacy_result.is_ok(), !operand.requires_i16i64());
            if operand.requires_i16i64() {
                assert!(legacy_result.unwrap_err().0.contains("FEAT_SME_I16I64"));
            }
            for bytes in [16, 32, 64, 128, 256] {
                let length = VectorLength::from_bytes(bytes).unwrap();
                for sme2 in [false, true] {
                    for i16i64 in [false, true] {
                        let mut features = ScalableFeatures::of(ScalableFeature::Sme);
                        if sme2 {
                            features = features.with(ScalableFeature::Sme2);
                        }
                        if i16i64 {
                            features = features.with(ScalableFeature::SmeI16I64);
                        }
                        for streaming in [false, true] {
                            for za in [false, true] {
                                let profile = ScalableProfile::new_with_features(
                                    length,
                                    ScalableMode::new(streaming, za),
                                    features,
                                    ScalableControls::new(length, false),
                                )
                                .unwrap();
                                let result = compile_for_profile(
                                    &source,
                                    GuestAddress(0),
                                    profile,
                                    TargetCpu::Baseline,
                                );
                                let permitted = streaming
                                    && za
                                    && (!operand.requires_sme2() || sme2)
                                    && (!operand.requires_i16i64() || i16i64);
                                assert_eq!(
                                    result.is_ok(),
                                    permitted,
                                    "word={word:#x} bytes={bytes} sme2={sme2} i16i64={i16i64} sm={streaming} za={za}"
                                );
                                if let Ok(native) = result {
                                    let mut body = Vec::new();
                                    x86_64::sme::integer_matrix::emit(
                                        &mut body,
                                        &operand,
                                        length,
                                        TargetCpu::Baseline,
                                    );
                                    let map = &native.source_map;
                                    assert_eq!(map.len(), 2);
                                    assert_eq!(map[0], (GuestAddress(0), CONTEXT_WRAPPER_BYTES));
                                    assert_eq!(
                                        map[1],
                                        (GuestAddress(4), CONTEXT_WRAPPER_BYTES + body.len())
                                    );
                                    assert_eq!(&native.x86_64_code[map[0].1..map[1].1], body);
                                    assert_eq!(&native.x86_64_code[map[1].1..], &[RET]);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    fn profile(bytes: usize, streaming: bool) -> ScalableProfile {
        ScalableProfile::new(
            VectorLength::from_bytes(bytes).unwrap(),
            ScalableMode::new(streaming, false),
        )
    }

    fn words(input: &[u32]) -> Vec<u8> {
        input.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn integer_dot_admission_requires_streaming_without_requiring_za() {
        const SDOT_Z0_S_Z1_B_Z2_B: u32 = 0x4482_0020;
        const CDOT_RESERVED_BYTE: u32 = 0x4400_1000;
        let source = words(&[SDOT_Z0_S_Z1_B_Z2_B, RET_X30]);
        assert!(crate::compile(&source, GuestAddress(0)).is_err());
        assert!(matches!(
            crate::aarch64::sve::decode(SDOT_Z0_S_Z1_B_Z2_B),
            Some(Ok(crate::aarch64::sve::Operand::Dot(_)))
        ));
        for bytes in [16, 32, 64, 128, 256] {
            for streaming in [false, true] {
                for za in [false, true] {
                    let profile = ScalableProfile::new(
                        VectorLength::from_bytes(bytes).unwrap(),
                        ScalableMode::new(streaming, za),
                    );
                    let result =
                        compile_for_profile(&source, GuestAddress(0), profile, TargetCpu::Baseline);
                    if streaming {
                        assert!(result.is_ok());
                    } else {
                        assert!(result.unwrap_err().0.contains("streaming mode required"));
                    }
                }
            }
            assert!(
                compile_for_profile(
                    &words(&[CDOT_RESERVED_BYTE, RET_X30]),
                    GuestAddress(0),
                    profile(bytes, true),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("reserved streaming integer dot")
            );
        }
    }

    #[test]
    fn integer_dot_registration_keeps_half_numerical_and_prefix_inputs_explicit() {
        const HALF_NUMERICAL_WORDS: [u32; 10] = [
            0x6420_8000,
            0x6420_4000,
            0x64a0_8000,
            0x64a0_8400,
            0x64a0_a000,
            0x64a0_a400,
            0x64a0_4000,
            0x64a0_4400,
            0x64a0_6000,
            0x64a0_6400,
        ];
        const SDOT_Z0_S_Z1_B_Z2_B: u32 = 0x4482_0020;
        for word in HALF_NUMERICAL_WORDS {
            assert!(dot::decode(word).unwrap().is_ok());
            assert_eq!(crate::aarch64::sve::decode(word), None);
            assert!(
                compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0),
                    profile(32, true),
                    TargetCpu::Baseline,
                )
                .is_err()
            );
        }
        assert!(
            compile_for_profile(
                &words(&[MOVPRFX_Z0_Z1, SDOT_Z0_S_Z1_B_Z2_B, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("MOVPRFX pair validation")
        );
    }

    #[test]
    fn mixed_signedness_dot_requires_an_explicit_guest_i8mm_profile() {
        const MIXED_SIGNEDNESS_WORDS: [u32; 3] = [0x44a0_1c00, 0x4480_7800, 0x44a0_1800];
        for word in MIXED_SIGNEDNESS_WORDS {
            assert!(dot::decode_integer(word).unwrap().unwrap().requires_i8mm());
            for bytes in [16, 32, 64, 128, 256] {
                for za in [false, true] {
                    for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                        let profile = ScalableProfile::new(
                            VectorLength::from_bytes(bytes).unwrap(),
                            ScalableMode::new(true, za),
                        );
                        assert!(
                            compile_for_profile(
                                &words(&[word, RET_X30]),
                                GuestAddress(0),
                                profile,
                                target,
                            )
                            .unwrap_err()
                            .0
                            .contains("guest I8MM is outside the streaming profile")
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn multi_vector_integer_access_and_legacy_abi_boundaries() {
        const ADD_PAIR: u32 = 0xc120_a300;
        const SQCVT_PAIR: u32 = 0xc123_e000;
        const SVE_SQCVTN_PAIR: u32 = 0x4531_4000;
        const SRSHL_PAIR: u32 = 0xc120_a220;
        const RESERVED_QUARTET_SHIFT: u32 = 0xc120_d800;
        let features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
        let declared = |bytes, streaming| {
            let length = VectorLength::from_bytes(bytes).unwrap();
            ScalableProfile::new_with_features(
                length,
                ScalableMode::new(streaming, false),
                features,
                ScalableControls::new(length, false),
            )
            .unwrap()
        };
        for word in [ADD_PAIR, SQCVT_PAIR, SVE_SQCVTN_PAIR, SRSHL_PAIR] {
            let source = words(&[word, RET_X30]);
            assert!(crate::compile(&source, GuestAddress(0)).is_err());
            let compatible = compile_for_profile(
                &source,
                GuestAddress(0),
                profile(16, true),
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(
                compatible.source_map[0],
                (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
            );
            for bytes in [16, 32, 64, 128, 256] {
                for streaming in [false, true] {
                    let result = compile_for_profile(
                        &source,
                        GuestAddress(0),
                        declared(bytes, streaming),
                        TargetCpu::Baseline,
                    );
                    if streaming {
                        let native = result.unwrap();
                        assert_eq!(
                            native.source_map[0],
                            (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                        );
                        assert_eq!(native.source_map[1].0, GuestAddress(4));
                    } else {
                        assert!(result.unwrap_err().0.contains("streaming mode required"));
                    }
                }
            }
        }
        assert!(
            compile_for_profile(
                &words(&[RESERVED_QUARTET_SHIFT, RET_X30]),
                GuestAddress(0),
                declared(16, true),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("reserved multi-vector integer")
        );
        let sme_only = ScalableProfile::new_with_features(
            VectorLength::from_bytes(16).unwrap(),
            ScalableMode::new(true, false),
            ScalableFeatures::of(ScalableFeature::Sme),
            ScalableControls::new(VectorLength::from_bytes(16).unwrap(), false),
        )
        .unwrap();
        for word in [ADD_PAIR, SQCVT_PAIR, SVE_SQCVTN_PAIR, SRSHL_PAIR] {
            assert!(
                compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0),
                    sme_only,
                    TargetCpu::Baseline,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn ordinary_payload_and_maps_preserve_original_bytes() {
        let source = words(&[NOP, 0xd280_00e0, RET_X30]);
        let old = crate::compile(&source, GuestAddress(0x1000)).unwrap();
        let new = compile_for_profile(
            &source,
            GuestAddress(0x1000),
            profile(32, true),
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(&new.x86_64_code[CONTEXT_WRAPPER_BYTES..], old.x86_64_code);
        assert_eq!(
            new.source_map,
            old.source_map
                .iter()
                .map(|(pc, offset)| (*pc, offset + CONTEXT_WRAPPER_BYTES))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            context_wrapper(),
            [
                0x41, 0x57, 0x49, 0x89, 0xf7, 0xe8, 3, 0, 0, 0, 0x41, 0x5f, 0xc3
            ]
        );
    }

    #[test]
    fn variable_length_modes_and_prefix_boundary_are_explicit() {
        for bytes in [16, 32, 64, 128, 256] {
            let source = words(&[AND_Z0_Z1_Z2, RDSVL_X0_ONE, RET_X30]);
            assert!(
                compile_for_profile(
                    &source,
                    GuestAddress(0),
                    profile(bytes, true),
                    TargetCpu::Baseline
                )
                .is_ok()
            );
            assert!(
                compile_for_profile(
                    &source,
                    GuestAddress(0),
                    profile(bytes, false),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("streaming mode required")
            );
            assert!(
                compile_for_profile(
                    &words(&[RDSVL_X0_ONE, RET_X30]),
                    GuestAddress(0),
                    profile(bytes, false),
                    TargetCpu::Baseline
                )
                .is_ok()
            );
        }
        assert!(
            compile_for_profile(
                &words(&[MOVPRFX_Z0_Z1, AND_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("MOVPRFX pair validation")
        );
        for word in [0xf940_0020, 0x4e22_8420, 0x1e22_2820] {
            assert!(
                compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0),
                    profile(32, true),
                    TargetCpu::Baseline
                )
                .is_err()
            );
        }
    }

    #[test]
    fn sign_operations_require_streaming_without_za() {
        const FABS_HALF: u32 = 0x045c_a020;
        const FNEG_DOUBLE: u32 = 0x04dd_bfff;
        const RESERVED_SIGN_SIZE: u32 = 0x041c_a020;
        for bytes in [16, 32, 64, 128, 256] {
            for svcr in 0..=3 {
                let profile = ScalableProfile::new(
                    VectorLength::from_bytes(bytes).unwrap(),
                    ScalableMode::from_svcr(svcr).unwrap(),
                );
                let source = words(&[FABS_HALF, FNEG_DOUBLE, RET_X30]);
                let result =
                    compile_for_profile(&source, GuestAddress(0), profile, TargetCpu::Baseline);
                if profile.mode().streaming() {
                    let native = result.unwrap();
                    assert_eq!(
                        native.source_map[0],
                        (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                    );
                    assert_eq!(native.source_map[1].0, GuestAddress(4));
                    assert!(native.source_map[1].1 > native.source_map[0].1);
                } else {
                    assert!(result.unwrap_err().0.contains("streaming mode required"));
                }
            }
        }
        assert!(crate::compile(&words(&[FABS_HALF, RET_X30]), GuestAddress(0)).is_err());
        assert!(
            compile_for_profile(
                &words(&[RESERVED_SIGN_SIZE, RET_X30]),
                GuestAddress(0),
                profile(16, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("reserved streaming sign")
        );
    }

    #[test]
    fn branches_resolve_across_scalable_instruction_bodies() {
        const BRANCH_PLUS_EIGHT: u32 = 0x1400_0002;
        let native = compile_for_profile(
            &words(&[BRANCH_PLUS_EIGHT, AND_Z0_Z1_Z2, RET_X30]),
            GuestAddress(0),
            profile(32, true),
            TargetCpu::Baseline,
        )
        .unwrap();
        let branch = native.source_map[0].1;
        assert_eq!(native.x86_64_code[branch], 0xe9);
        let displacement = i32::from_le_bytes(
            native.x86_64_code[branch + 1..branch + 5]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            (branch + 5) as i64 + i64::from(displacement),
            native.source_map[2].1 as i64
        );
    }
    #[test]
    fn integer_comparison_preflight_rejects_non_streaming_reserved_and_prefix_inputs() {
        const CMPEQ_BYTE: u32 = 0x2400_2020;
        const CMPEQ_WIDE_RESERVED_DOUBLEWORD: u32 = 0x24c0_2020;
        const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
        for (input, streaming, reason) in [
            (vec![CMPEQ_BYTE, RET_X30], false, "streaming mode required"),
            (
                vec![CMPEQ_WIDE_RESERVED_DOUBLEWORD, RET_X30],
                true,
                "reserved streaming integer comparison",
            ),
            (vec![MOVPRFX_Z0_Z1, CMPEQ_BYTE, RET_X30], true, "MOVPRFX"),
        ] {
            let error = compile_for_profile(
                &words(&input),
                GuestAddress(0),
                profile(32, streaming),
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(error.0.contains(reason), "{error:?}");
        }
    }

    #[test]
    fn integer_comparison_accepts_declared_sme_without_sme2() {
        const CMPEQ_BYTE: u32 = 0x2400_2020;
        let length = VectorLength::from_bytes(32).unwrap();
        let mode = ScalableMode::new(true, true);
        let declared = ScalableProfile::new_with_features(
            length,
            mode,
            ScalableFeatures::of(ScalableFeature::Sme),
            ScalableControls::new(length, false),
        )
        .unwrap();
        let source = words(&[CMPEQ_BYTE, RET_X30]);
        let fixed = compile_for_profile(
            &source,
            GuestAddress(0),
            ScalableProfile::new(length, mode),
            TargetCpu::Baseline,
        )
        .unwrap();
        let explicit =
            compile_for_profile(&source, GuestAddress(0), declared, TargetCpu::Baseline).unwrap();
        assert_eq!(fixed.x86_64_code, explicit.x86_64_code);
        assert_eq!(fixed.source_map, explicit.source_map);
    }

    #[test]
    fn integer_arithmetic_maps_all_families_with_exact_body_boundaries() {
        const CANONICAL_WORDS: [u32; 48] = [
            0x0416_a000, // abs_z_p_z_m
            0x4500_d000, // adclb_z_zzz_
            0x4500_d400, // adclt_z_zzz_
            0x0400_0000, // add_z_p_zz_
            0x2520_c000, // add_z_zi_
            0x0420_0000, // add_z_zz_
            0x4500_d800, // cadd_z_zz_
            0x0417_a000, // neg_z_p_z_m
            0x4540_0000, // saddlb_z_zz_
            0x4540_8000, // saddlbt_z_zz_
            0x4540_0400, // saddlt_z_zz_
            0x4540_4000, // saddwb_z_zz_
            0x4540_4400, // saddwt_z_zz_
            0x4580_d000, // sbclb_z_zzz_
            0x4580_d400, // sbclt_z_zzz_
            0x4400_c000, // sclamp_z_zz_
            0x0494_0000, // sdiv_z_p_zz_
            0x0496_0000, // sdivr_z_p_zz_
            0x0408_0000, // smax_z_p_zz_
            0x2528_c000, // smax_z_zi_
            0x040a_0000, // smin_z_p_zz_
            0x252a_c000, // smin_z_zi_
            0x4540_1000, // ssublb_z_zz_
            0x4540_8800, // ssublbt_z_zz_
            0x4540_1400, // ssublt_z_zz_
            0x4540_8c00, // ssubltb_z_zz_
            0x4540_5000, // ssubwb_z_zz_
            0x4540_5400, // ssubwt_z_zz_
            0x0401_0000, // sub_z_p_zz_
            0x2521_c000, // sub_z_zi_
            0x0420_0400, // sub_z_zz_
            0x0403_0000, // subr_z_p_zz_
            0x2523_c000, // subr_z_zi_
            0x4540_0800, // uaddlb_z_zz_
            0x4540_0c00, // uaddlt_z_zz_
            0x4540_4800, // uaddwb_z_zz_
            0x4540_4c00, // uaddwt_z_zz_
            0x4400_c400, // uclamp_z_zz_
            0x0495_0000, // udiv_z_p_zz_
            0x0497_0000, // udivr_z_p_zz_
            0x0409_0000, // umax_z_p_zz_
            0x2529_c000, // umax_z_zi_
            0x040b_0000, // umin_z_p_zz_
            0x252b_c000, // umin_z_zi_
            0x4540_1800, // usublb_z_zz_
            0x4540_1c00, // usublt_z_zz_
            0x4540_5800, // usubwb_z_zz_
            0x4540_5c00, // usubwt_z_zz_
        ];
        const DESTINATION_MASK: u32 = 31;
        const SOURCE_MASK: u32 = 31 << 5;
        const SOURCE_REGISTER: u32 = 5;
        for canonical in CANONICAL_WORDS {
            // Distinct operands, destination/source alias, and ordinary Z31.
            for register in [0, SOURCE_REGISTER, 31] {
                let word = (canonical & !(DESTINATION_MASK | SOURCE_MASK))
                    | register
                    | (SOURCE_REGISTER << 5);
                let operand = integer_arithmetic::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::IntegerArithmetic(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                        let native = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0x1000),
                            profile(bytes, true),
                            target,
                        )
                        .unwrap();
                        let mut expected = Vec::new();
                        x86_64::sve::integer_arithmetic::emit(
                            &mut expected,
                            operand,
                            VectorLength::from_bytes(bytes).unwrap(),
                            target,
                        );
                        assert_eq!(
                            native.source_map[0],
                            (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES)
                        );
                        assert_eq!(
                            native.source_map[1],
                            (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                        );
                        assert_eq!(
                            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                            context_wrapper()
                        );
                        assert_eq!(
                            &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                            expected
                        );
                        assert_eq!(native.x86_64_code[native.source_map[1].1..], [RET]);
                    }
                }
            }
        }
    }

    #[test]
    fn integer_arithmetic_preflight_rejects_mode_reserved_and_prefix_inputs() {
        const ADD_Z0_Z1_Z2: u32 = 0x0422_0020;
        const SDIV_RESERVED_BYTE: u32 = 0x0414_0000;
        const UDIV_RESERVED_HALFWORD: u32 = 0x0455_0000;
        const SADDLB_RESERVED_BYTE: u32 = 0x4500_0000;
        const ADD_RESERVED_BYTE_SHIFT8: u32 = 0x2520_e000;
        for word in [
            SDIV_RESERVED_BYTE,
            UDIV_RESERVED_HALFWORD,
            SADDLB_RESERVED_BYTE,
            ADD_RESERVED_BYTE_SHIFT8,
        ] {
            assert!(
                compile_for_profile(
                    &words(&[NOP, word, RET_X30]),
                    GuestAddress(0),
                    profile(32, true),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("reserved streaming integer arithmetic")
            );
        }
        for bytes in [16, 32, 64, 128, 256] {
            assert!(
                compile_for_profile(
                    &words(&[ADD_Z0_Z1_Z2, RET_X30]),
                    GuestAddress(0),
                    profile(bytes, false),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("streaming mode required")
            );
        }
        assert!(
            compile_for_profile(
                &words(&[MOVPRFX_Z0_Z1, ADD_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("MOVPRFX pair validation")
        );
        assert!(crate::compile(&words(&[ADD_Z0_Z1_Z2, RET_X30]), GuestAddress(0)).is_err());
    }
    #[test]
    fn integer_saturation_maps_all_forms_with_exact_body_boundaries() {
        const CANONICAL_WORDS: [u32; 39] = [
            0x4500_f800, // saba_z_zzz_
            0x4540_c000, // sabalb_z_zzz_
            0x4540_c400, // sabalt_z_zzz_
            0x040c_0000, // sabd_z_p_zz_
            0x4540_3000, // sabdlb_z_zz_
            0x4540_3400, // sabdlt_z_zz_
            0x4410_8000, // shadd_z_p_zz_
            0x4412_8000, // shsub_z_p_zz_
            0x4416_8000, // shsubr_z_p_zz_
            0x4408_a000, // sqabs_z_p_z_m
            0x4418_8000, // sqadd_z_p_zz_
            0x2524_c000, // sqadd_z_zi_
            0x0420_1000, // sqadd_z_zz_
            0x4501_d800, // sqcadd_z_zz_
            0x4409_a000, // sqneg_z_p_z_m
            0x441a_8000, // sqsub_z_p_zz_
            0x2526_c000, // sqsub_z_zi_
            0x0420_1800, // sqsub_z_zz_
            0x441e_8000, // sqsubr_z_p_zz_
            0x4414_8000, // srhadd_z_p_zz_
            0x441c_8000, // suqadd_z_p_zz_
            0x4500_fc00, // uaba_z_zzz_
            0x4540_c800, // uabalb_z_zzz_
            0x4540_cc00, // uabalt_z_zzz_
            0x040d_0000, // uabd_z_p_zz_
            0x4540_3800, // uabdlb_z_zz_
            0x4540_3c00, // uabdlt_z_zz_
            0x4411_8000, // uhadd_z_p_zz_
            0x4413_8000, // uhsub_z_p_zz_
            0x4417_8000, // uhsubr_z_p_zz_
            0x4419_8000, // uqadd_z_p_zz_
            0x2525_c000, // uqadd_z_zi_
            0x0420_1400, // uqadd_z_zz_
            0x441b_8000, // uqsub_z_p_zz_
            0x2527_c000, // uqsub_z_zi_
            0x0420_1c00, // uqsub_z_zz_
            0x441f_8000, // uqsubr_z_p_zz_
            0x4415_8000, // urhadd_z_p_zz_
            0x441d_8000, // usqadd_z_p_zz_
        ];
        const REGISTER_MASK: u32 = 31;
        const SOURCE_SHIFT: u32 = 5;
        const SOURCE_REGISTER: u32 = 5;
        for canonical in CANONICAL_WORDS {
            for register in [0, SOURCE_REGISTER, REGISTER_MASK] {
                let word = (canonical & !(REGISTER_MASK | (REGISTER_MASK << SOURCE_SHIFT)))
                    | register
                    | (SOURCE_REGISTER << SOURCE_SHIFT);
                let operand = integer_saturation::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::IntegerSaturation(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                        let native = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0x1000),
                            profile(bytes, true),
                            target,
                        )
                        .unwrap();
                        let mut expected = Vec::new();
                        x86_64::sve::integer_saturation::emit(
                            &mut expected,
                            operand,
                            VectorLength::from_bytes(bytes).unwrap(),
                            target,
                        );
                        assert_eq!(
                            native.source_map[0],
                            (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES)
                        );
                        assert_eq!(
                            native.source_map[1],
                            (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                        );
                        assert_eq!(
                            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                            context_wrapper()
                        );
                        assert_eq!(
                            &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                            expected
                        );
                        assert_eq!(native.x86_64_code[native.source_map[1].1..], [RET]);
                    }
                }
            }
        }
    }

    #[test]
    fn integer_saturation_preflight_rejects_reserved_mode_and_prefix_inputs() {
        const SQADD_Z0_Z1_Z2: u32 = 0x0422_1020;
        const SQADD_RESERVED_BYTE_SHIFT8: u32 = 0x2524_e000;
        const SABDLB_RESERVED_BYTE: u32 = 0x4500_3000;
        const MOVPRFX_PREDICATED_Z0_Z1: u32 = 0x0410_2020;
        for word in [SQADD_RESERVED_BYTE_SHIFT8, SABDLB_RESERVED_BYTE] {
            assert!(
                compile_for_profile(
                    &words(&[NOP, word, RET_X30]),
                    GuestAddress(0),
                    profile(32, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("reserved streaming integer saturation")
            );
        }
        for bytes in [16, 32, 64, 128, 256] {
            assert!(
                compile_for_profile(
                    &words(&[SQADD_Z0_Z1_Z2, RET_X30]),
                    GuestAddress(0),
                    profile(bytes, false),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("streaming mode required")
            );
        }
        for prefix in [MOVPRFX_Z0_Z1, MOVPRFX_PREDICATED_Z0_Z1] {
            assert!(
                compile_for_profile(
                    &words(&[prefix, SQADD_Z0_Z1_Z2, RET_X30]),
                    GuestAddress(0),
                    profile(32, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("MOVPRFX pair validation")
            );
        }
        assert!(crate::compile(&words(&[SQADD_Z0_Z1_Z2, RET_X30]), GuestAddress(0)).is_err());
    }

    #[test]
    fn integer_products_maps_every_form_to_exact_body_boundaries() {
        const CANONICAL_WORDS: [u32; 101] = [
            0x4403_20bf, // cmla_z_zzz_
            0x44a3_60bf, // cmla_z_zzzi_h
            0x44e3_60bf, // cmla_z_zzzi_s
            0x0403_de7f, // mad_z_p_zzz_
            0x0403_5cbf, // mla_z_p_zzz_
            0x44e3_08bf, // mla_z_zzzi_d
            0x4423_08bf, // mla_z_zzzi_h
            0x44a3_08bf, // mla_z_zzzi_s
            0x0403_7cbf, // mls_z_p_zzz_
            0x44e3_0cbf, // mls_z_zzzi_d
            0x4423_0cbf, // mls_z_zzzi_h
            0x44a3_0cbf, // mls_z_zzzi_s
            0x0403_fe7f, // msb_z_p_zzz_
            0x0410_1c7f, // mul_z_p_zz_
            0x2530_d01f, // mul_z_zi_
            0x0423_60bf, // mul_z_zz_
            0x44e3_f8bf, // mul_z_zzi_d
            0x4423_f8bf, // mul_z_zzi_h
            0x44a3_f8bf, // mul_z_zzi_s
            0x0423_64bf, // pmul_z_zz_
            0x4543_68bf, // pmullb_z_zz_
            0x4543_6cbf, // pmullt_z_zz_
            0x4443_40bf, // smlalb_z_zzz_
            0x44e3_80bf, // smlalb_z_zzzi_d
            0x44a3_80bf, // smlalb_z_zzzi_s
            0x4443_44bf, // smlalt_z_zzz_
            0x44e3_84bf, // smlalt_z_zzzi_d
            0x44a3_84bf, // smlalt_z_zzzi_s
            0x4443_50bf, // smlslb_z_zzz_
            0x44e3_a0bf, // smlslb_z_zzzi_d
            0x44a3_a0bf, // smlslb_z_zzzi_s
            0x4443_54bf, // smlslt_z_zzz_
            0x44e3_a4bf, // smlslt_z_zzzi_d
            0x44a3_a4bf, // smlslt_z_zzzi_s
            0x0412_1c7f, // smulh_z_p_zz_
            0x0423_68bf, // smulh_z_zz_
            0x4543_70bf, // smullb_z_zz_
            0x44e3_c0bf, // smullb_z_zzi_d
            0x44a3_c0bf, // smullb_z_zzi_s
            0x4543_74bf, // smullt_z_zz_
            0x44e3_c4bf, // smullt_z_zzi_d
            0x44a3_c4bf, // smullt_z_zzi_s
            0x4443_60bf, // sqdmlalb_z_zzz_
            0x44e3_20bf, // sqdmlalb_z_zzzi_d
            0x44a3_20bf, // sqdmlalb_z_zzzi_s
            0x4443_08bf, // sqdmlalbt_z_zzz_
            0x4443_64bf, // sqdmlalt_z_zzz_
            0x44e3_24bf, // sqdmlalt_z_zzzi_d
            0x44a3_24bf, // sqdmlalt_z_zzzi_s
            0x4443_68bf, // sqdmlslb_z_zzz_
            0x44e3_30bf, // sqdmlslb_z_zzzi_d
            0x44a3_30bf, // sqdmlslb_z_zzzi_s
            0x4443_0cbf, // sqdmlslbt_z_zzz_
            0x4443_6cbf, // sqdmlslt_z_zzz_
            0x44e3_34bf, // sqdmlslt_z_zzzi_d
            0x44a3_34bf, // sqdmlslt_z_zzzi_s
            0x0423_70bf, // sqdmulh_z_zz_
            0x44e3_f0bf, // sqdmulh_z_zzi_d
            0x4423_f0bf, // sqdmulh_z_zzi_h
            0x44a3_f0bf, // sqdmulh_z_zzi_s
            0x4543_60bf, // sqdmullb_z_zz_
            0x44e3_e0bf, // sqdmullb_z_zzi_d
            0x44a3_e0bf, // sqdmullb_z_zzi_s
            0x4543_64bf, // sqdmullt_z_zz_
            0x44e3_e4bf, // sqdmullt_z_zzi_d
            0x44a3_e4bf, // sqdmullt_z_zzi_s
            0x4403_30bf, // sqrdcmlah_z_zzz_
            0x44a3_70bf, // sqrdcmlah_z_zzzi_h
            0x44e3_70bf, // sqrdcmlah_z_zzzi_s
            0x4403_70bf, // sqrdmlah_z_zzz_
            0x44e3_10bf, // sqrdmlah_z_zzzi_d
            0x4423_10bf, // sqrdmlah_z_zzzi_h
            0x44a3_10bf, // sqrdmlah_z_zzzi_s
            0x4403_74bf, // sqrdmlsh_z_zzz_
            0x44e3_14bf, // sqrdmlsh_z_zzzi_d
            0x4423_14bf, // sqrdmlsh_z_zzzi_h
            0x44a3_14bf, // sqrdmlsh_z_zzzi_s
            0x0423_74bf, // sqrdmulh_z_zz_
            0x44e3_f4bf, // sqrdmulh_z_zzi_d
            0x4423_f4bf, // sqrdmulh_z_zzi_h
            0x44a3_f4bf, // sqrdmulh_z_zzi_s
            0x4443_48bf, // umlalb_z_zzz_
            0x44e3_90bf, // umlalb_z_zzzi_d
            0x44a3_90bf, // umlalb_z_zzzi_s
            0x4443_4cbf, // umlalt_z_zzz_
            0x44e3_94bf, // umlalt_z_zzzi_d
            0x44a3_94bf, // umlalt_z_zzzi_s
            0x4443_58bf, // umlslb_z_zzz_
            0x44e3_b0bf, // umlslb_z_zzzi_d
            0x44a3_b0bf, // umlslb_z_zzzi_s
            0x4443_5cbf, // umlslt_z_zzz_
            0x44e3_b4bf, // umlslt_z_zzzi_d
            0x44a3_b4bf, // umlslt_z_zzzi_s
            0x0413_1c7f, // umulh_z_p_zz_
            0x0423_6cbf, // umulh_z_zz_
            0x4543_78bf, // umullb_z_zz_
            0x44e3_d0bf, // umullb_z_zzi_d
            0x44a3_d0bf, // umullb_z_zzi_s
            0x4543_7cbf, // umullt_z_zz_
            0x44e3_d4bf, // umullt_z_zzi_d
            0x44a3_d4bf, // umullt_z_zzi_s
        ];
        for word in CANONICAL_WORDS {
            let operand = integer_products::decode(word).unwrap().unwrap();
            assert_eq!(
                crate::aarch64::sve::decode(word),
                Some(Ok(crate::aarch64::sve::Operand::IntegerProducts(operand)))
            );
            for bytes in [16, 32, 64, 128, 256] {
                for (target, declared) in [
                    (TargetCpu::Baseline, false),
                    (TargetCpu::Sse42, false),
                    (TargetCpu::Baseline, true),
                    (TargetCpu::Sse42, true),
                ] {
                    let selected_profile = if declared {
                        ScalableProfile::new_with_features(
                            VectorLength::from_bytes(bytes).unwrap(),
                            ScalableMode::new(true, false),
                            ScalableFeatures::of(ScalableFeature::Sme),
                            ScalableControls::new(VectorLength::from_bytes(bytes).unwrap(), false),
                        )
                        .unwrap()
                    } else {
                        profile(bytes, true)
                    };
                    let native = compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        selected_profile,
                        target,
                    )
                    .unwrap();
                    let mut expected = Vec::new();
                    x86_64::sve::integer_products::emit(
                        &mut expected,
                        operand,
                        VectorLength::from_bytes(bytes).unwrap(),
                        target,
                    );
                    assert_eq!(
                        native.source_map,
                        [
                            (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                            (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                        ]
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                        expected
                    );
                    assert_eq!(&native.x86_64_code[native.source_map[1].1..], &[RET]);
                }
            }
        }
    }

    #[test]
    fn integer_products_preflight_rejects_reserved_modes_and_prefix_pairs() {
        const MUL_Z0_Z1_Z2: u32 = 0x0422_6020;
        const SMULLB_RESERVED_BYTE: u32 = 0x4500_7000;
        const PMULLB_RESERVED_WORD: u32 = 0x4580_6800;
        for word in [SMULLB_RESERVED_BYTE, PMULLB_RESERVED_WORD] {
            assert!(
                compile_for_profile(
                    &words(&[NOP, word, RET_X30]),
                    GuestAddress(0),
                    profile(32, true),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("reserved streaming integer product")
            );
        }
        assert!(
            compile_for_profile(
                &words(&[MUL_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(32, false),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("streaming mode required")
        );
        assert!(
            compile_for_profile(
                &words(&[MOVPRFX_Z0_Z1, MUL_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
            .contains("MOVPRFX pair validation")
        );
    }
    #[test]
    fn floating_copies_require_streaming_without_za() {
        const FCPY_HALF_P15_Z31: u32 = 0x055f_ce1f;
        const FDUP_DOUBLE_Z31: u32 = 0x25f9_ce1f;
        const RESERVED_FCPY_SIZE: u32 = 0x051f_ce1f;
        for bytes in [16, 32, 64, 128, 256] {
            for svcr in 0..=3 {
                let profile = ScalableProfile::new(
                    VectorLength::from_bytes(bytes).unwrap(),
                    ScalableMode::from_svcr(svcr).unwrap(),
                );
                let source = words(&[FCPY_HALF_P15_Z31, FDUP_DOUBLE_Z31, RET_X30]);
                let result =
                    compile_for_profile(&source, GuestAddress(0), profile, TargetCpu::Baseline);
                if profile.mode().streaming() {
                    let native = result.unwrap();
                    assert_eq!(
                        native.source_map[0],
                        (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                    );
                    assert_eq!(native.source_map[1].0, GuestAddress(4));
                    assert!(native.source_map[1].1 > native.source_map[0].1);
                } else {
                    assert!(result.unwrap_err().0.contains("streaming mode required"));
                }
            }
        }
        assert!(crate::compile(&words(&[FCPY_HALF_P15_Z31, RET_X30]), GuestAddress(0)).is_err());
        assert!(
            compile_for_profile(
                &words(&[RESERVED_FCPY_SIZE, RET_X30]),
                GuestAddress(0),
                profile(16, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("reserved streaming floating copy")
        );
    }
    #[test]
    fn address_counts_require_streaming_but_sme_length_does_not() {
        const ADDVL_X0_ONE: u32 = 0x0420_5020;
        const RDVL_X0_ONE: u32 = 0x04bf_5020;
        const CNTP_X0_P0: u32 = 0x2520_8000;
        const CNTP_X0_PN0: u32 = 0x2520_8200;
        const SQINCW_X0_W0: u32 = 0x04a0_f000;
        const UQDECW_Z0: u32 = 0x04a0_cc00;
        for bytes in [16, 32, 64, 128, 256] {
            for word in [
                ADDVL_X0_ONE,
                RDVL_X0_ONE,
                CNTP_X0_P0,
                CNTP_X0_PN0,
                SQINCW_X0_W0,
                UQDECW_Z0,
            ] {
                for za in [false, true] {
                    let selected = ScalableProfile::new(
                        VectorLength::from_bytes(bytes).unwrap(),
                        ScalableMode::new(true, za),
                    );
                    assert!(
                        compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0),
                            selected,
                            TargetCpu::Baseline
                        )
                        .is_ok()
                    );
                    let inactive = ScalableProfile::new(
                        VectorLength::from_bytes(bytes).unwrap(),
                        ScalableMode::new(false, za),
                    );
                    assert!(
                        compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0),
                            inactive,
                            TargetCpu::Baseline
                        )
                        .unwrap_err()
                        .0
                        .contains("streaming mode required")
                    );
                }
                assert!(crate::compile(&words(&[word, RET_X30]), GuestAddress(0)).is_err());
            }
            assert!(
                compile_for_profile(
                    &words(&[RDSVL_X0_ONE, RET_X30]),
                    GuestAddress(0),
                    profile(bytes, false),
                    TargetCpu::Baseline
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn address_vector_reserved_width_declines_before_mode_checks() {
        const RESERVED_BYTE_VECTOR_WORDS: [u32; 12] = [
            0x0430_c000,
            0x0430_c400,
            0x0420_c000,
            0x0420_c400,
            0x0420_c800,
            0x0420_cc00,
            0x252c_8000,
            0x252d_8000,
            0x2528_8000,
            0x2529_8000,
            0x252a_8000,
            0x252b_8000,
        ];
        for word in RESERVED_BYTE_VECTOR_WORDS {
            for streaming in [false, true] {
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        profile(16, streaming),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("reserved")
                );
            }
        }
    }

    #[test]
    fn address_counter_requires_declared_sme2() {
        const ADDVL_X0_ONE: u32 = 0x0420_5020;
        const CNTP_X0_PN0: u32 = 0x2520_8200;
        let length = VectorLength::from_bytes(16).unwrap();
        let selected = ScalableProfile::new_with_features(
            length,
            ScalableMode::new(true, false),
            ScalableFeatures::of(ScalableFeature::Sme),
            ScalableControls::new(length, false),
        )
        .unwrap();
        assert!(
            compile_for_profile(
                &words(&[ADDVL_X0_ONE, RET_X30]),
                GuestAddress(0),
                selected,
                TargetCpu::Baseline
            )
            .is_ok()
        );
        assert!(
            compile_for_profile(
                &words(&[CNTP_X0_PN0, RET_X30]),
                GuestAddress(0),
                selected,
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("FEAT_SME2")
        );
    }
    fn declared_dit_zero_profile(bytes: usize) -> ScalableProfile {
        let length = VectorLength::from_bytes(bytes).unwrap();
        ScalableProfile::new_with_features(
            length,
            ScalableMode::new(true, false),
            ScalableFeatures::of(ScalableFeature::Sme),
            ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
        )
        .unwrap()
    }

    #[test]
    fn integer_shifts_register_exact_bodies_and_source_maps() {
        const CANONICAL_WORDS: [u32; 43] = [
            0x040081e0, // ASR
            0x04188040, // ASR
            0x04108040, // ASR
            0x042f9020, // ASR
            0x04228020, // ASR
            0x040481e0, // ASRD
            0x04148040, // ASRR
            0x04038100, // LSL
            0x041b8040, // LSL
            0x04138040, // LSL
            0x04289c20, // LSL
            0x04228c20, // LSL
            0x04178040, // LSLR
            0x040181e0, // LSR
            0x04198040, // LSR
            0x04118040, // LSR
            0x042f9420, // LSR
            0x04228420, // LSR
            0x04158040, // LSRR
            0x4508f420, // SLI
            0x440a8040, // SQRSHL
            0x440e8040, // SQRSHLR
            0x04068100, // SQSHL
            0x44088040, // SQSHL
            0x440c8040, // SQSHLR
            0x040f8100, // SQSHLU
            0x450ff020, // SRI
            0x44028040, // SRSHL
            0x44068040, // SRSHLR
            0x040c81e0, // SRSHR
            0x450fe820, // SRSRA
            0x450fe020, // SSRA
            0x440b8040, // UQRSHL
            0x440f8040, // UQRSHLR
            0x04078100, // UQSHL
            0x44098040, // UQSHL
            0x440d8040, // UQSHLR
            0x44038040, // URSHL
            0x44078040, // URSHLR
            0x040d81e0, // URSHR
            0x450fec20, // URSRA
            0x450fe420, // USRA
            0x042f3440, // XAR
        ];
        for word in CANONICAL_WORDS {
            let operand = shifts::decode(word).unwrap().unwrap();
            assert_eq!(
                crate::aarch64::sve::decode(word),
                Some(Ok(crate::aarch64::sve::Operand::Shifts(operand)))
            );
            for bytes in [16, 32, 64, 128, 256] {
                for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
                    let native = compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        declared_dit_zero_profile(bytes),
                        target,
                    )
                    .unwrap();
                    let mut body = Vec::new();
                    x86_64::sve::shifts::emit(
                        &mut body,
                        operand,
                        VectorLength::from_bytes(bytes).unwrap(),
                        target,
                    );
                    let return_offset = CONTEXT_WRAPPER_BYTES + body.len();
                    assert_eq!(
                        native.source_map,
                        [
                            (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                            (GuestAddress(0x1004), return_offset)
                        ]
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES..return_offset],
                        body
                    );
                    assert_eq!(&native.x86_64_code[return_offset..], &[RET]);
                }
            }
            let length = VectorLength::from_bytes(16).unwrap();
            let base_sme = ScalableProfile::new_with_features(
                length,
                ScalableMode::new(true, false),
                ScalableFeatures::of(ScalableFeature::Sme),
                ScalableControls::new(length, false),
            )
            .unwrap();
            assert!(
                compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0),
                    base_sme,
                    TargetCpu::Baseline
                )
                .is_ok()
            );
            for streaming in [false, true] {
                for za in [false, true] {
                    let selected = ScalableProfile::new(
                        VectorLength::from_bytes(16).unwrap(),
                        ScalableMode::new(streaming, za),
                    );
                    let result = compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        selected,
                        TargetCpu::Baseline,
                    );
                    if streaming && x86_64::sve::shifts::requires_declared_dit_zero(operand, length)
                    {
                        assert!(result.unwrap_err().0.contains("requires declared DIT=0"));
                    } else if streaming {
                        assert!(result.is_ok());
                    } else {
                        assert!(result.unwrap_err().0.contains("streaming mode required"));
                    }
                }
            }
        }
    }

    #[test]
    fn integer_shift_dit_policy_preserves_canonical_width_boundaries() {
        // Expected decisions come from the source-bound June per-form audit,
        // including forward/reverse rounding identity and byte packed exceptions.
        const AUDITED_WORDS: &[(u32, bool, bool)] = &[
            (0x0400_81e0, true, false),  // asr_z_p_zi_
            (0x0400_83e0, true, false),  // asr_z_p_zi_
            (0x0440_83e0, true, false),  // asr_z_p_zi_
            (0x04c0_83e0, true, false),  // asr_z_p_zi_
            (0x0418_8040, true, true),   // asr_z_p_zw_
            (0x0458_8040, true, true),   // asr_z_p_zw_
            (0x0498_8040, true, true),   // asr_z_p_zw_
            (0x0410_8040, true, true),   // asr_z_p_zz_
            (0x0450_8040, true, true),   // asr_z_p_zz_
            (0x0490_8040, true, true),   // asr_z_p_zz_
            (0x04d0_8040, true, true),   // asr_z_p_zz_
            (0x042f_9020, true, false),  // asr_z_zi_
            (0x043f_9020, true, false),  // asr_z_zi_
            (0x047f_9020, true, false),  // asr_z_zi_
            (0x04ff_9020, true, false),  // asr_z_zi_
            (0x0422_8020, true, true),   // asr_z_zw_
            (0x0462_8020, true, true),   // asr_z_zw_
            (0x04a2_8020, true, true),   // asr_z_zw_
            (0x0404_81e0, true, false),  // asrd_z_p_zi_
            (0x0404_83e0, true, false),  // asrd_z_p_zi_
            (0x0444_83e0, true, false),  // asrd_z_p_zi_
            (0x04c4_83e0, true, false),  // asrd_z_p_zi_
            (0x0414_8040, true, true),   // asrr_z_p_zz_
            (0x0454_8040, true, true),   // asrr_z_p_zz_
            (0x0494_8040, true, true),   // asrr_z_p_zz_
            (0x04d4_8040, true, true),   // asrr_z_p_zz_
            (0x0403_8100, true, false),  // lsl_z_p_zi_
            (0x0403_8200, true, false),  // lsl_z_p_zi_
            (0x0443_8000, true, false),  // lsl_z_p_zi_
            (0x0483_8000, true, false),  // lsl_z_p_zi_
            (0x041b_8040, true, true),   // lsl_z_p_zw_
            (0x045b_8040, true, true),   // lsl_z_p_zw_
            (0x049b_8040, true, true),   // lsl_z_p_zw_
            (0x0413_8040, true, false),  // lsl_z_p_zz_
            (0x0453_8040, true, true),   // lsl_z_p_zz_
            (0x0493_8040, true, true),   // lsl_z_p_zz_
            (0x04d3_8040, true, true),   // lsl_z_p_zz_
            (0x0428_9c20, true, false),  // lsl_z_zi_
            (0x0430_9c20, true, false),  // lsl_z_zi_
            (0x0460_9c20, true, false),  // lsl_z_zi_
            (0x04a0_9c20, true, false),  // lsl_z_zi_
            (0x0422_8c20, true, true),   // lsl_z_zw_
            (0x0462_8c20, true, true),   // lsl_z_zw_
            (0x04a2_8c20, true, true),   // lsl_z_zw_
            (0x0417_8040, true, false),  // lslr_z_p_zz_
            (0x0457_8040, true, true),   // lslr_z_p_zz_
            (0x0497_8040, true, true),   // lslr_z_p_zz_
            (0x04d7_8040, true, true),   // lslr_z_p_zz_
            (0x0401_81e0, true, false),  // lsr_z_p_zi_
            (0x0401_83e0, true, false),  // lsr_z_p_zi_
            (0x0441_83e0, true, false),  // lsr_z_p_zi_
            (0x04c1_83e0, true, false),  // lsr_z_p_zi_
            (0x0419_8040, true, true),   // lsr_z_p_zw_
            (0x0459_8040, true, true),   // lsr_z_p_zw_
            (0x0499_8040, true, true),   // lsr_z_p_zw_
            (0x0411_8040, true, false),  // lsr_z_p_zz_
            (0x0451_8040, true, true),   // lsr_z_p_zz_
            (0x0491_8040, true, true),   // lsr_z_p_zz_
            (0x04d1_8040, true, true),   // lsr_z_p_zz_
            (0x042f_9420, true, false),  // lsr_z_zi_
            (0x043f_9420, true, false),  // lsr_z_zi_
            (0x047f_9420, true, false),  // lsr_z_zi_
            (0x04ff_9420, true, false),  // lsr_z_zi_
            (0x0422_8420, true, true),   // lsr_z_zw_
            (0x0462_8420, true, true),   // lsr_z_zw_
            (0x04a2_8420, true, true),   // lsr_z_zw_
            (0x0415_8040, true, false),  // lsrr_z_p_zz_
            (0x0455_8040, true, true),   // lsrr_z_p_zz_
            (0x0495_8040, true, true),   // lsrr_z_p_zz_
            (0x04d5_8040, true, true),   // lsrr_z_p_zz_
            (0x4508_f420, true, false),  // sli_z_zzi_
            (0x4510_f420, true, false),  // sli_z_zzi_
            (0x4540_f420, true, false),  // sli_z_zzi_
            (0x4580_f420, true, false),  // sli_z_zzi_
            (0x440a_8040, false, false), // sqrshl_z_p_zz_
            (0x444a_8040, false, false), // sqrshl_z_p_zz_
            (0x448a_8040, false, false), // sqrshl_z_p_zz_
            (0x44ca_8040, false, false), // sqrshl_z_p_zz_
            (0x440e_8040, false, false), // sqrshlr_z_p_zz_
            (0x444e_8040, false, false), // sqrshlr_z_p_zz_
            (0x448e_8040, false, false), // sqrshlr_z_p_zz_
            (0x44ce_8040, false, false), // sqrshlr_z_p_zz_
            (0x0406_8100, false, false), // sqshl_z_p_zi_
            (0x0406_8200, false, false), // sqshl_z_p_zi_
            (0x0446_8000, false, false), // sqshl_z_p_zi_
            (0x0486_8000, false, false), // sqshl_z_p_zi_
            (0x4408_8040, false, false), // sqshl_z_p_zz_
            (0x4448_8040, false, false), // sqshl_z_p_zz_
            (0x4488_8040, false, false), // sqshl_z_p_zz_
            (0x44c8_8040, false, false), // sqshl_z_p_zz_
            (0x440c_8040, false, false), // sqshlr_z_p_zz_
            (0x444c_8040, false, false), // sqshlr_z_p_zz_
            (0x448c_8040, false, false), // sqshlr_z_p_zz_
            (0x44cc_8040, false, false), // sqshlr_z_p_zz_
            (0x040f_8100, false, false), // sqshlu_z_p_zi_
            (0x040f_8200, false, false), // sqshlu_z_p_zi_
            (0x044f_8000, false, false), // sqshlu_z_p_zi_
            (0x048f_8000, false, false), // sqshlu_z_p_zi_
            (0x450f_f020, true, false),  // sri_z_zzi_
            (0x451f_f020, true, false),  // sri_z_zzi_
            (0x455f_f020, true, false),  // sri_z_zzi_
            (0x45df_f020, true, false),  // sri_z_zzi_
            (0x4402_8040, true, true),   // srshl_z_p_zz_
            (0x4442_8040, true, true),   // srshl_z_p_zz_
            (0x4482_8040, true, true),   // srshl_z_p_zz_
            (0x44c2_8040, true, true),   // srshl_z_p_zz_
            (0x4406_8040, false, false), // srshlr_z_p_zz_
            (0x4446_8040, false, false), // srshlr_z_p_zz_
            (0x4486_8040, false, false), // srshlr_z_p_zz_
            (0x44c6_8040, false, false), // srshlr_z_p_zz_
            (0x040c_81e0, true, false),  // srshr_z_p_zi_
            (0x040c_83e0, true, false),  // srshr_z_p_zi_
            (0x044c_83e0, true, false),  // srshr_z_p_zi_
            (0x04cc_83e0, true, false),  // srshr_z_p_zi_
            (0x450f_e820, true, false),  // srsra_z_zi_
            (0x451f_e820, true, false),  // srsra_z_zi_
            (0x455f_e820, true, false),  // srsra_z_zi_
            (0x45df_e820, true, false),  // srsra_z_zi_
            (0x450f_e020, true, false),  // ssra_z_zi_
            (0x451f_e020, true, false),  // ssra_z_zi_
            (0x455f_e020, true, false),  // ssra_z_zi_
            (0x45df_e020, true, false),  // ssra_z_zi_
            (0x440b_8040, false, false), // uqrshl_z_p_zz_
            (0x444b_8040, false, false), // uqrshl_z_p_zz_
            (0x448b_8040, false, false), // uqrshl_z_p_zz_
            (0x44cb_8040, false, false), // uqrshl_z_p_zz_
            (0x440f_8040, false, false), // uqrshlr_z_p_zz_
            (0x444f_8040, false, false), // uqrshlr_z_p_zz_
            (0x448f_8040, false, false), // uqrshlr_z_p_zz_
            (0x44cf_8040, false, false), // uqrshlr_z_p_zz_
            (0x0407_8100, false, false), // uqshl_z_p_zi_
            (0x0407_8200, false, false), // uqshl_z_p_zi_
            (0x0447_8000, false, false), // uqshl_z_p_zi_
            (0x0487_8000, false, false), // uqshl_z_p_zi_
            (0x4409_8040, false, false), // uqshl_z_p_zz_
            (0x4449_8040, false, false), // uqshl_z_p_zz_
            (0x4489_8040, false, false), // uqshl_z_p_zz_
            (0x44c9_8040, false, false), // uqshl_z_p_zz_
            (0x440d_8040, false, false), // uqshlr_z_p_zz_
            (0x444d_8040, false, false), // uqshlr_z_p_zz_
            (0x448d_8040, false, false), // uqshlr_z_p_zz_
            (0x44cd_8040, false, false), // uqshlr_z_p_zz_
            (0x4403_8040, true, true),   // urshl_z_p_zz_
            (0x4443_8040, true, true),   // urshl_z_p_zz_
            (0x4483_8040, true, true),   // urshl_z_p_zz_
            (0x44c3_8040, true, true),   // urshl_z_p_zz_
            (0x4407_8040, false, false), // urshlr_z_p_zz_
            (0x4447_8040, false, false), // urshlr_z_p_zz_
            (0x4487_8040, false, false), // urshlr_z_p_zz_
            (0x44c7_8040, false, false), // urshlr_z_p_zz_
            (0x040d_81e0, true, false),  // urshr_z_p_zi_
            (0x040d_83e0, true, false),  // urshr_z_p_zi_
            (0x044d_83e0, true, false),  // urshr_z_p_zi_
            (0x04cd_83e0, true, false),  // urshr_z_p_zi_
            (0x450f_ec20, true, false),  // ursra_z_zi_
            (0x451f_ec20, true, false),  // ursra_z_zi_
            (0x455f_ec20, true, false),  // ursra_z_zi_
            (0x45df_ec20, true, false),  // ursra_z_zi_
            (0x450f_e420, true, false),  // usra_z_zi_
            (0x451f_e420, true, false),  // usra_z_zi_
            (0x455f_e420, true, false),  // usra_z_zi_
            (0x45df_e420, true, false),  // usra_z_zi_
            (0x042f_3440, true, false),  // xar_z_zzi_
            (0x043f_3440, true, false),  // xar_z_zzi_
            (0x047f_3440, true, false),  // xar_z_zzi_
            (0x04ff_3440, true, false),  // xar_z_zzi_
        ];
        for &(word, noted, requires_dit_zero) in AUDITED_WORDS {
            let operand = shifts::decode(word).unwrap().unwrap();
            assert_eq!(operand.has_dit_guarantee, noted, "{word:#x}");
            for bytes in [16, 32, 64, 128, 256] {
                let length = VectorLength::from_bytes(bytes).unwrap();
                assert_eq!(
                    x86_64::sve::shifts::requires_declared_dit_zero(operand, length),
                    requires_dit_zero,
                    "{word:#x} at {bytes} bytes",
                );
                let source = words(&[NOP, word, RET_X30]);
                let legacy = compile_for_profile(
                    &source,
                    GuestAddress(0),
                    profile(bytes, true),
                    TargetCpu::Baseline,
                );
                if requires_dit_zero {
                    assert!(legacy.unwrap_err().0.contains("requires declared DIT=0"));
                } else {
                    assert!(legacy.is_ok());
                }
                assert!(
                    compile_for_profile(
                        &source,
                        GuestAddress(0),
                        declared_dit_zero_profile(bytes),
                        TargetCpu::Baseline,
                    )
                    .is_ok()
                );
            }
        }
    }

    #[test]
    fn integer_shifts_reserved_and_prefix_inputs_remain_explicit() {
        const LSL_RESERVED_SIZE: u32 = 0x0403_8000;
        const ASR_RESERVED_DOUBLEWORDS: u32 = 0x04d8_8000;
        const LSL_Z0_B_P0_Z0_B_ZERO: u32 = 0x0403_8100;
        for word in [LSL_RESERVED_SIZE, ASR_RESERVED_DOUBLEWORDS] {
            assert!(
                compile_for_profile(
                    &words(&[NOP, word, RET_X30]),
                    GuestAddress(0),
                    profile(16, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("reserved streaming integer shift")
            );
        }
        assert!(
            compile_for_profile(
                &words(&[MOVPRFX_Z0_Z1, LSL_Z0_B_P0_Z0_B_ZERO, RET_X30]),
                GuestAddress(0),
                profile(16, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("MOVPRFX pair validation")
        );
        assert!(
            crate::compile(&words(&[LSL_Z0_B_P0_Z0_B_ZERO, RET_X30]), GuestAddress(0)).is_err()
        );
    }
    #[test]
    fn width_conversions_register_exact_bodies_and_source_maps() {
        const CANONICAL_WORDS: [u32; 26] = [
            0x452f1820, // RSHRNB
            0x452f1c20, // RSHRNT
            0x452f1020, // SHRNB
            0x452f1420, // SHRNT
            0x452f2820, // SQRSHRNB
            0x452f2c20, // SQRSHRNT
            0x452f0820, // SQRSHRUNB
            0x452f0c20, // SQRSHRUNT
            0x452f2020, // SQSHRNB
            0x452f2420, // SQSHRNT
            0x452f0020, // SQSHRUNB
            0x452f0420, // SQSHRUNT
            0x45284020, // SQXTNB
            0x45284420, // SQXTNT
            0x45285020, // SQXTUNB
            0x45285420, // SQXTUNT
            0x4508a020, // SSHLLB
            0x4508a420, // SSHLLT
            0x452f3820, // UQRSHRNB
            0x452f3c20, // UQRSHRNT
            0x452f3020, // UQSHRNB
            0x452f3420, // UQSHRNT
            0x45284820, // UQXTNB
            0x45284c20, // UQXTNT
            0x4508a820, // USHLLB
            0x4508ac20, // USHLLT
        ];
        for word in CANONICAL_WORDS {
            let operand = shifts_narrow::decode(word).unwrap().unwrap();
            assert_eq!(
                crate::aarch64::sve::decode(word),
                Some(Ok(crate::aarch64::sve::Operand::ShiftsNarrow(operand)))
            );
            for bytes in [16, 32, 64, 128, 256] {
                for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
                    let native = compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        profile(bytes, true),
                        target,
                    )
                    .unwrap();
                    let mut body = Vec::new();
                    x86_64::sve::shifts_narrow::emit(
                        &mut body,
                        operand,
                        VectorLength::from_bytes(bytes).unwrap(),
                        target,
                    );
                    let return_offset = CONTEXT_WRAPPER_BYTES + body.len();
                    assert_eq!(
                        native.source_map,
                        [
                            (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                            (GuestAddress(0x1004), return_offset)
                        ]
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES..return_offset],
                        body
                    );
                    assert_eq!(&native.x86_64_code[return_offset..], &[RET]);
                }
            }
            for streaming in [false, true] {
                for za in [false, true] {
                    let selected = ScalableProfile::new(
                        VectorLength::from_bytes(16).unwrap(),
                        ScalableMode::new(streaming, za),
                    );
                    let result = compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        selected,
                        TargetCpu::Baseline,
                    );
                    if streaming {
                        assert!(result.is_ok());
                    } else {
                        assert!(result.unwrap_err().0.contains("streaming mode required"));
                    }
                }
            }
        }
    }

    #[test]
    fn width_conversion_reserved_and_prefix_inputs_remain_explicit() {
        const SSHLLB_RESERVED_SIZE: u32 = 0x4500_a000;
        const SQXTNB_RESERVED_SIZE: u32 = 0x4520_4000;
        const SSHLLB_Z0_H_Z1_B: u32 = 0x4508_a020;
        for word in [SSHLLB_RESERVED_SIZE, SQXTNB_RESERVED_SIZE] {
            assert!(
                compile_for_profile(
                    &words(&[NOP, word, RET_X30]),
                    GuestAddress(0),
                    profile(16, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("reserved streaming width-conversion")
            );
        }
        assert!(
            compile_for_profile(
                &words(&[MOVPRFX_Z0_Z1, SSHLLB_Z0_H_Z1_B, RET_X30]),
                GuestAddress(0),
                profile(16, true),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .0
            .contains("MOVPRFX pair validation")
        );
        assert!(crate::compile(&words(&[SSHLLB_Z0_H_Z1_B, RET_X30]), GuestAddress(0)).is_err());
    }
    const TABLE_LOOKUP: u32 = 0xc0cc0000;
    const TABLE_SELECT: u32 = 0xc1208000;
    const TABLE_ZIP_PAIR_Q: u32 = 0xc120d400;
    const TABLE_ZIP_QUAD_Q: u32 = 0xc137e000;

    fn table_profile(
        bytes: usize,
        mode: ScalableMode,
        features: ScalableFeatures,
        zt0_enabled: bool,
    ) -> ScalableProfile {
        ScalableProfile::new_with_features(
            VectorLength::from_bytes(bytes).unwrap(),
            mode,
            features,
            ScalableControls::new(VectorLength::from_bytes(256).unwrap(), zt0_enabled),
        )
        .unwrap()
    }

    fn table_features() -> ScalableFeatures {
        ScalableFeatures::of(ScalableFeature::Sme)
            .with(ScalableFeature::Sme2)
            .with(ScalableFeature::Sme2p1)
    }

    #[test]
    fn fixed_table_routes_retain_compatible_legacy_profiles() {
        let legacy = ScalableProfile::new(
            VectorLength::from_bytes(64).unwrap(),
            ScalableMode::new(true, false),
        );
        for word in [TABLE_SELECT, TABLE_ZIP_PAIR_Q, TABLE_ZIP_QUAD_Q, 0xc165e000] {
            assert!(
                compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0x1000),
                    legacy,
                    TargetCpu::Baseline
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn scalar_lookup_policy_tracks_the_selected_recipe() {
        use crate::aarch64::scalable::ElementSize;
        let mut operand = tables::decode(TABLE_LOOKUP).unwrap();
        let short = VectorLength::from_bytes(16).unwrap();
        let long = VectorLength::from_bytes(64).unwrap();
        operand.element = ElementSize::Word;
        assert!(x86_64::sme::tables::requires_dit_zero(
            &operand,
            short,
            TargetCpu::Baseline
        ));
        assert!(x86_64::sme::tables::requires_dit_zero(
            &operand,
            short,
            TargetCpu::Ssse3
        ));
        assert!(!x86_64::sme::tables::requires_dit_zero(
            &operand,
            long,
            TargetCpu::Ssse3
        ));
        operand.element = ElementSize::Halfword;
        assert!(x86_64::sme::tables::requires_dit_zero(
            &operand,
            short,
            TargetCpu::Baseline
        ));
        assert!(!x86_64::sme::tables::requires_dit_zero(
            &operand,
            long,
            TargetCpu::Baseline
        ));
        assert!(!x86_64::sme::tables::requires_dit_zero(
            &operand,
            short,
            TargetCpu::Ssse3
        ));
        operand.element = ElementSize::Byte;
        assert!(!x86_64::sme::tables::requires_dit_zero(
            &operand,
            short,
            TargetCpu::Baseline
        ));
        let legacy = ScalableProfile::new(short, ScalableMode::new(true, true));
        let scalar_word = TABLE_LOOKUP | (2 << 12);
        let error = compile_for_profile(
            &words(&[scalar_word, RET_X30]),
            GuestAddress(0x1000),
            legacy,
            TargetCpu::Baseline,
        )
        .unwrap_err();
        assert!(error.0.contains("scalar SME lookup"));
    }

    #[test]
    fn table_lookup_requires_za_and_enabled_zt0() {
        for (za_enabled, zt0_enabled) in [(false, false), (false, true), (true, false)] {
            let profile = table_profile(
                16,
                ScalableMode::new(true, za_enabled),
                table_features(),
                zt0_enabled,
            );
            let error = compile_for_profile(
                &words(&[TABLE_LOOKUP, RET_X30]),
                GuestAddress(0x1000),
                profile,
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(error.0.contains("ZA and enabled ZT0"));
        }
        let profile = table_profile(16, ScalableMode::new(true, true), table_features(), true);
        assert!(
            compile_for_profile(
                &words(&[TABLE_LOOKUP, RET_X30]),
                GuestAddress(0x1000),
                profile,
                TargetCpu::Baseline
            )
            .is_ok()
        );
    }

    #[test]
    fn table_strided_lookups_require_sme2p1() {
        let feature_base = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
        let base = table_profile(16, ScalableMode::new(true, true), feature_base, true);
        let complete = table_profile(16, ScalableMode::new(true, true), table_features(), true);
        for word in [0xc09c4000, 0xc09c8000, 0xc09a4000, 0xc09a9000] {
            let input = words(&[word, RET_X30]);
            let error =
                compile_for_profile(&input, GuestAddress(0x1000), base, TargetCpu::Baseline)
                    .unwrap_err();
            assert!(error.0.contains("FEAT_SME2p1"));
            assert!(
                compile_for_profile(&input, GuestAddress(0x1000), complete, TargetCpu::Baseline)
                    .is_ok()
            );
        }
    }

    #[test]
    fn table_permutations_validate_current_length_despite_larger_maximum() {
        for (word, too_short, minimum) in [(TABLE_ZIP_PAIR_Q, 16, 32), (TABLE_ZIP_QUAD_Q, 32, 64)] {
            let input = words(&[word, RET_X30]);
            let short = table_profile(
                too_short,
                ScalableMode::new(true, false),
                table_features(),
                false,
            );
            let error =
                compile_for_profile(&input, GuestAddress(0x1000), short, TargetCpu::Baseline)
                    .unwrap_err();
            assert!(error.0.contains("require SVL"));
            let valid = table_profile(
                minimum,
                ScalableMode::new(true, false),
                table_features(),
                false,
            );
            assert!(
                compile_for_profile(&input, GuestAddress(0x1000), valid, TargetCpu::Baseline)
                    .is_ok()
            );
        }
    }

    #[test]
    fn every_table_family_routes_through_the_shared_context_entry() {
        let profile = table_profile(64, ScalableMode::new(true, true), table_features(), true);
        for word in [
            0xc08c4000, 0xc09c4000, 0xc08c8000, 0xc09c8000, 0xc0cc0000, 0xc08a4000, 0xc09a4000,
            0xc08a9000, 0xc09a9000, 0xc0ca0000, 0xc1208000, 0xc1218000, 0xc165e000, 0xc175e000,
            0xc165e001, 0xc175e001, 0xc136e002, 0xc137e002, 0xc120d001, 0xc120d401, 0xc136e000,
            0xc137e000, 0xc120d000, 0xc120d400,
        ] {
            let result = compile_for_profile(
                &words(&[word, RET_X30]),
                GuestAddress(0x1000),
                profile,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(result.source_map.len(), 2);
            assert_eq!(
                result.source_map[0],
                (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES)
            );
            assert_eq!(result.source_map[1].0, GuestAddress(0x1004));
            assert!(result.source_map[1].1 > result.source_map[0].1);
        }
    }

    #[test]
    fn table_admission_requires_sme2_and_streaming() {
        let sme_only = table_profile(
            16,
            ScalableMode::new(true, false),
            ScalableFeatures::of(ScalableFeature::Sme),
            false,
        );
        let error = compile_for_profile(
            &words(&[TABLE_SELECT, RET_X30]),
            GuestAddress(0x1000),
            sme_only,
            TargetCpu::Baseline,
        )
        .unwrap_err();
        assert!(error.0.contains("FEAT_SME2"));
        let non_streaming =
            table_profile(16, ScalableMode::new(false, false), table_features(), false);
        let error = compile_for_profile(
            &words(&[TABLE_SELECT, RET_X30]),
            GuestAddress(0x1000),
            non_streaming,
            TargetCpu::Baseline,
        )
        .unwrap_err();
        assert!(error.0.contains("streaming mode required"));
    }
}

#[cfg(test)]
mod rearrange_extract_tests;

#[cfg(test)]
mod predicate_generation_tests;

#[cfg(test)]
#[path = "extended/predicate_logic_tests.rs"]
mod predicate_logic_tests;

#[cfg(test)]
#[path = "extended/rearrange_tests.rs"]
mod rearrange_tests;

#[cfg(test)]
#[path = "extended/reductions_tests.rs"]
mod reductions_tests;

#[cfg(test)]
#[path = "extended/sme2p1_tests.rs"]
mod sme2p1_tests;

#[cfg(test)]
#[path = "extended/predicate_move_tests.rs"]
mod predicate_move_tests;

#[cfg(test)]
mod prefix_pair_tests {
    use super::*;

    const BASE: GuestAddress = GuestAddress(0x1000);
    const UNPREDICATED_PREFIX: u32 = 0x0420_bc20;
    const ZEROING_PREFIX: u32 = 0x0410_2020;
    const MERGING_PREFIX: u32 = 0x0411_2020;
    const AND_DESTRUCTIVE: u32 = 0x041a_0040;
    const RET: u32 = 0xd65f_03c0;

    #[test]
    fn both_prefix_forms_compile_as_two_individual_source_map_intervals() {
        for bytes in [16, 32, 64, 128, 256] {
            let profile = ScalableProfile::new(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::new(true, false),
            );
            for prefix in [UNPREDICATED_PREFIX, ZEROING_PREFIX, MERGING_PREFIX] {
                let source: Vec<_> = [prefix, AND_DESTRUCTIVE, RET]
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect();
                let native =
                    compile_for_profile(&source, BASE, profile, TargetCpu::Baseline).unwrap();
                assert_eq!(
                    native
                        .source_map
                        .iter()
                        .map(|(pc, _)| *pc)
                        .collect::<Vec<_>>(),
                    [
                        BASE,
                        GuestAddress(BASE.0 + INSTRUCTION_BYTES as u64),
                        GuestAddress(BASE.0 + prefix::PAIR_BYTES as u64)
                    ]
                );
                assert_eq!(native.source_map[0].1, CONTEXT_WRAPPER_BYTES);
                assert!(
                    native
                        .source_map
                        .windows(2)
                        .all(|pair| pair[0].1 < pair[1].1)
                );
            }
        }
    }
    #[test]
    fn prepared_prefix_records_both_source_clauses_and_preserves_refusals() {
        use crate::aarch64::scalable::execution::{
            GuestMemoryQuantity, ScalableAccessRequirements,
        };
        let profile = ScalableProfile::new(
            VectorLength::from_bytes(16).unwrap(),
            ScalableMode::new(true, false),
        );
        let source: Vec<_> = [UNPREDICATED_PREFIX, AND_DESTRUCTIVE, RET]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let prepared = prepare_leaf(&source, BASE, profile, TargetCpu::Baseline).unwrap();
        let ordinary = compile_for_profile(&source, BASE, profile, TargetCpu::Baseline).unwrap();
        assert_eq!(prepared.native.x86_64_code, ordinary.x86_64_code);
        assert_eq!(prepared.native.source_map, ordinary.source_map);
        let instructions = prepared.execution_requirements.instructions();
        assert_eq!(instructions.len(), 3);
        let clause = FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme));
        for (index, instruction) in instructions[..2].iter().enumerate() {
            assert_eq!(
                instruction.pc(),
                GuestAddress(BASE.0 + (index * INSTRUCTION_BYTES) as u64)
            );
            assert_eq!(instruction.feature_clauses(), &[clause]);
            assert_eq!(
                instruction.access(),
                &ScalableAccessRequirements::Unqualified
            );
            assert_eq!(
                instruction.guest_memory_quantity(),
                GuestMemoryQuantity::Unqualified
            );
        }
        assert!(instructions[2].feature_clauses().is_empty());
        assert_eq!(
            instructions[2].guest_memory_quantity(),
            GuestMemoryQuantity::None
        );
        let refused: Vec<_> = [UNPREDICATED_PREFIX, RET]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let error = match prepare_leaf(&refused, BASE, profile, TargetCpu::Baseline) {
            Err(error) => error,
            Ok(_) => panic!("unreviewed MOVPRFX pair accepted"),
        };
        assert!(error.0.contains("MOVPRFX pair validation"));
    }
}

#[cfg(test)]
#[path = "extended/memory_load_tests.rs"]
mod memory_load_tests;

#[cfg(test)]
#[path = "extended/memory_multi_tests.rs"]
mod memory_multi_tests;

#[cfg(test)]
#[path = "extended/memory_store_tests.rs"]
mod memory_store_tests;

#[cfg(test)]
#[path = "extended/memory_structure_tests.rs"]
mod memory_structure_tests;

#[cfg(test)]
#[path = "extended/sme_memory_tests.rs"]
mod sme_memory_tests;
