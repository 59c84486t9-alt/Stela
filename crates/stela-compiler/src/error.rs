//! Typed compilation failures and their guest instruction context.
pub use crate::x86_64::RegionError;
pub use crate::x86_64::sme::memory::Error as SmeMemoryError;
pub use crate::x86_64::sme::movement::Error as SmeMovementError;
use crate::{
    GuestAddress, UnsupportedReason,
    aarch64::{
        scalable::features::{FeatureRequirement, ScalableFeatures},
        sve::prefix::PrefixViolation,
    },
    block::BlockProfile,
};
use alloc::boxed::Box;

/// Guest source associated with a compilation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionContext {
    pub address: GuestAddress,
    pub encoding: Option<u32>,
}

/// A compilation failure with structured cause and optional source instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub kind: CompileErrorKind,
    pub instruction: Option<InstructionContext>,
}
impl CompileError {
    pub const fn new(kind: CompileErrorKind) -> Self {
        Self {
            kind,
            instruction: None,
        }
    }
    pub fn at(mut self, address: GuestAddress) -> Self {
        let encoding = self
            .instruction
            .filter(|source| source.address == address)
            .and_then(|source| source.encoding);
        self.instruction = Some(InstructionContext { address, encoding });
        self
    }
    pub fn at_instruction(mut self, address: GuestAddress, encoding: u32) -> Self {
        self.instruction = Some(InstructionContext {
            address,
            encoding: Some(encoding),
        });
        self
    }
}
impl From<UnsupportedReason> for CompileError {
    fn from(reason: UnsupportedReason) -> Self {
        let instruction = match &reason {
            UnsupportedReason::Instruction { address, encoding } => Some(InstructionContext {
                address: *address,
                encoding: Some(*encoding),
            }),
            UnsupportedReason::HostCapabilityRequired { address, .. }
            | UnsupportedReason::NumericalRuntimeRequired { address }
            | UnsupportedReason::PrivilegedOperation { address }
            | UnsupportedReason::PointerAuthentication { address }
            | UnsupportedReason::UnresolvedIndirectTarget { address }
            | UnsupportedReason::UnresolvedDirectTarget { address, .. } => {
                Some(InstructionContext {
                    address: *address,
                    encoding: None,
                })
            }
            UnsupportedReason::RuntimeGeneratedCode => None,
        };
        Self {
            kind: CompileErrorKind::Unsupported(reason),
            instruction,
        }
    }
}
impl From<RegionError> for CompileError {
    fn from(error: RegionError) -> Self {
        Self::new(CompileErrorKind::Region(error))
    }
}
impl From<SmeMemoryError> for CompileError {
    fn from(error: SmeMemoryError) -> Self {
        Self::new(CompileErrorKind::SmeMemory(error))
    }
}
impl From<SmeMovementError> for CompileError {
    fn from(error: SmeMovementError) -> Self {
        Self::new(CompileErrorKind::SmeMovement(error))
    }
}
impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.kind.fmt(f)?;
        if let Some(source) = self.instruction {
            write!(f, " at {:#x}", source.address.0)?;
            if let Some(word) = source.encoding {
                write!(f, " ({word:#010x})")?;
            }
        }
        Ok(())
    }
}
impl core::error::Error for CompileError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self.kind {
            CompileErrorKind::Region(error) => Some(error),
            CompileErrorKind::SmeMemory(error) => Some(error),
            CompileErrorKind::SmeMovement(error) => Some(error),
            CompileErrorKind::MovprfxFollowerUnsupported(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

/// The bounded encoding families admitted by the scalable decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingFamily {
    MultiVectorInteger,
    StreamingLut,
    StreamingIntegerDot,
    StreamingIntegerReduction,
    StreamingInteger,
    StreamingLengthCount,
    StreamingMultiVectorMemory,
    StreamingPredicateGeneration,
    StreamingPredicateLogic,
    StreamingPredicateToVector,
    StreamingRearrangement,
    StreamingStore,
    StreamingStructuredLoad,
    StreamingExtraction,
    StreamingFloatingCopy,
    StreamingIntegerArithmetic,
    StreamingIntegerComparison,
    StreamingIntegerProduct,
    StreamingIntegerSaturation,
    StreamingIntegerShift,
    StreamingIntegerBit,
    StreamingLoad,
    StreamingSign,
    StreamingWidthConversion,
}
impl core::fmt::Display for EncodingFamily {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MultiVectorInteger => f.write_str("multi-vector integer"),
            Self::StreamingLut => f.write_str("streaming LUT"),
            Self::StreamingIntegerDot => f.write_str("streaming integer dot"),
            Self::StreamingIntegerReduction => f.write_str("streaming integer reduction"),
            Self::StreamingInteger => f.write_str("streaming integer"),
            Self::StreamingLengthCount => f.write_str("streaming length/count"),
            Self::StreamingMultiVectorMemory => f.write_str("streaming multi-vector memory"),
            Self::StreamingPredicateGeneration => f.write_str("streaming predicate generation"),
            Self::StreamingPredicateLogic => f.write_str("streaming predicate logic"),
            Self::StreamingPredicateToVector => f.write_str("streaming predicate-to-vector"),
            Self::StreamingRearrangement => f.write_str("streaming rearrangement"),
            Self::StreamingStore => f.write_str("streaming store"),
            Self::StreamingStructuredLoad => f.write_str("streaming structured load"),
            Self::StreamingExtraction => f.write_str("streaming extraction"),
            Self::StreamingFloatingCopy => f.write_str("streaming floating copy"),
            Self::StreamingIntegerArithmetic => f.write_str("streaming integer arithmetic"),
            Self::StreamingIntegerComparison => f.write_str("streaming integer comparison"),
            Self::StreamingIntegerProduct => f.write_str("streaming integer product"),
            Self::StreamingIntegerSaturation => f.write_str("streaming integer saturation"),
            Self::StreamingIntegerShift => f.write_str("streaming integer shift"),
            Self::StreamingIntegerBit => f.write_str("streaming integer-bit"),
            Self::StreamingLoad => f.write_str("streaming load"),
            Self::StreamingSign => f.write_str("streaming sign"),
            Self::StreamingWidthConversion => f.write_str("streaming width-conversion"),
        }
    }
}

/// The condition that prevented compilation. Values remain available to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileErrorKind {
    CpaSpecializationRequired,
    HalfHostCapabilityUnavailable,
    InvalidHalfOutputFormat,
    ReservedCoreBinary,
    InvalidNumericalOutputs,
    InvalidNumericalOutputCount,
    UnexpectedRegisterBranch,
    UnexpectedMemoryBranch,
    DebugMovementStateRequired,
    InvalidDebugMovement,
    UnallocatedMovement,
    ExecutionContextMismatch,
    VectorLengthExceedsMaximum,
    Zt0RequiresSme2,
    FpmrRequiresFeature,
    Sme2p1RequiresSme2,
    ScalableRequiresSme,
    MovprfxFollowerMismatch,
    GuestAddressOverflow,
    SourceExtentOverflow,
    MisalignedInstructionAddress,
    IncompleteSourceInstruction,
    SourceOffsetOverflow,
    InvalidContextSourceLayout,
    UnrequestedScalableOperation,
    InstructionAddressMismatch,
    ConstrainedExclusiveOperands,
    InvalidExclusiveTransfer,
    InvalidExclusiveStatusRegister,
    FixedAddressContractRequired,
    InvalidOrderedOperand,
    InvalidDmbOperand,
    InvalidLseOperand,
    AmbiguousSystemInstruction,
    ReservedScalableNumerical,
    FullA64RequiresSmeFa64,
    FpmrAccessDisabled,
    NumericalDescriptorMismatch,
    IncompatibleMemoryRequirements,
    UnadmittedMemoryTerminal,
    UnqualifiedSharedMemoryProfile,
    NativeBranchOverflow,
    FixedMemoryServiceNotRequested,
    ScalarMemoryServiceNotRequested,
    ExclusiveServiceNotRequested,
    MissingLeafReturn,
    InvalidSourceLayout,
    StreamingModeRequired,
    ZaEnabledStateRequired,
    ZaEnableRequired,
    ZaStateRequired,
    Zt0EnableRequired,
    Zt0EnabledStateRequired,
    LutVectorLengthRequired,
    MovprfxPairRequired,
    LutV2StateRequired,
    LutStateRequired,
    CurrentVectorLengthTooSmall,
    MaximumVectorLengthTooSmall,
    StreamingI8mmUnsupported,
    HaltedDebugRequired,
    IntegerMatrixStateRequired,
    LeadingCountsRequireDitClear,
    SmeLookupRequiresDitClear,
    TableLookupRequiresDitClear,
    IntegerShiftRequiresDitClear,
    InvalidStreamingIntegerProduct,
    Region(RegionError),
    SmeTableVectorLength {
        minimum_bits: usize,
    },
    Unsupported(UnsupportedReason),
    SmeMemory(SmeMemoryError),
    SmeMovement(SmeMovementError),
    ReservedEncoding {
        family: EncodingFamily,
    },
    ProfileRequiresScalable {
        profile: BlockProfile,
        required: bool,
    },
    MemoryChecksUnsupported {
        profile: BlockProfile,
    },
    NativeZeroBlockUnsupported {
        profile: BlockProfile,
    },
    InvalidZeroBlockSize {
        bytes: u16,
    },
    NativeCacheCleanUnsupported {
        profile: BlockProfile,
    },
    ProfileNotImplemented {
        profile: BlockProfile,
    },
    StreamingDotOperands,
    UnresolvedDirectTarget {
        target: GuestAddress,
    },
    ConflictingMemoryRequirements,
    NumericalModeUnavailable,
    UnresearchedAmxImmediate {
        operation: u32,
        field: u32,
    },
    MovprfxEffectsUnreviewed,
    OutsideCheckedMemoryProfile,
    ContextServiceUnimplemented,
    ContextMemoryUnimplemented,
    MovprfxFollowerMissing,
    MovprfxFollowerIsPrefix,
    MovprfxFollowerUnsupported(Box<CompileError>),
    MovprfxMetadataUnreviewed,
    MovprfxViolation(PrefixViolation),
    GuestFeaturesUnavailable {
        available: ScalableFeatures,
        required: FeatureRequirement,
    },
    OutsideContextIntegerProfile,
    TooManyInstructions {
        maximum: usize,
    },
    UnadmittedNopProvenance,
    OutsideRestrictedSystemProfile,
}
impl CompileErrorKind {
    /// Stable diagnostic identifier for serialized reports.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::CpaSpecializationRequired => "cpa_specialization_required",
            Self::HalfHostCapabilityUnavailable => "half_host_capability_unavailable",
            Self::InvalidHalfOutputFormat => "invalid_half_output_format",
            Self::ReservedCoreBinary => "reserved_core_binary",
            Self::InvalidNumericalOutputs => "invalid_numerical_outputs",
            Self::InvalidNumericalOutputCount => "invalid_numerical_output_count",
            Self::UnexpectedRegisterBranch => "unexpected_register_branch",
            Self::UnexpectedMemoryBranch => "unexpected_memory_branch",
            Self::DebugMovementStateRequired => "debug_movement_state_required",
            Self::InvalidDebugMovement => "invalid_debug_movement",
            Self::UnallocatedMovement => "unallocated_movement",
            Self::ExecutionContextMismatch => "execution_context_mismatch",
            Self::VectorLengthExceedsMaximum => "vector_length_exceeds_maximum",
            Self::Zt0RequiresSme2 => "zt0_requires_sme2",
            Self::FpmrRequiresFeature => "fpmr_requires_feature",
            Self::Sme2p1RequiresSme2 => "sme2p1_requires_sme2",
            Self::ScalableRequiresSme => "scalable_requires_sme",
            Self::MovprfxFollowerMismatch => "movprfx_follower_mismatch",
            Self::GuestAddressOverflow => "guest_address_overflow",
            Self::SourceExtentOverflow => "source_extent_overflow",
            Self::MisalignedInstructionAddress => "misaligned_instruction_address",
            Self::IncompleteSourceInstruction => "incomplete_source_instruction",
            Self::SourceOffsetOverflow => "source_offset_overflow",
            Self::InvalidContextSourceLayout => "invalid_context_source_layout",
            Self::UnrequestedScalableOperation => "unrequested_scalable_operation",
            Self::InstructionAddressMismatch => "instruction_address_mismatch",
            Self::ConstrainedExclusiveOperands => "constrained_exclusive_operands",
            Self::InvalidExclusiveTransfer => "invalid_exclusive_transfer",
            Self::InvalidExclusiveStatusRegister => "invalid_exclusive_status_register",
            Self::FixedAddressContractRequired => "fixed_address_contract_required",
            Self::InvalidOrderedOperand => "invalid_ordered_operand",
            Self::InvalidDmbOperand => "invalid_dmb_operand",
            Self::InvalidLseOperand => "invalid_lse_operand",
            Self::AmbiguousSystemInstruction => "ambiguous_system_instruction",
            Self::ReservedScalableNumerical => "reserved_scalable_numerical",
            Self::FullA64RequiresSmeFa64 => "full_a64_requires_sme_fa64",
            Self::FpmrAccessDisabled => "fpmr_access_disabled",
            Self::NumericalDescriptorMismatch => "numerical_descriptor_mismatch",
            Self::IncompatibleMemoryRequirements => "incompatible_memory_requirements",
            Self::UnadmittedMemoryTerminal => "unadmitted_memory_terminal",
            Self::UnqualifiedSharedMemoryProfile => "unqualified_shared_memory_profile",
            Self::NativeBranchOverflow => "native_branch_overflow",
            Self::FixedMemoryServiceNotRequested => "fixed_memory_service_not_requested",
            Self::ScalarMemoryServiceNotRequested => "scalar_memory_service_not_requested",
            Self::ExclusiveServiceNotRequested => "exclusive_service_not_requested",
            Self::MissingLeafReturn => "missing_leaf_return",
            Self::InvalidSourceLayout => "invalid_source_layout",
            Self::StreamingModeRequired => "streaming_mode_required",
            Self::ZaEnabledStateRequired => "za_enabled_state_required",
            Self::ZaEnableRequired => "za_enable_required",
            Self::ZaStateRequired => "za_state_required",
            Self::Zt0EnableRequired => "zt0_enable_required",
            Self::Zt0EnabledStateRequired => "zt0_enabled_state_required",
            Self::LutVectorLengthRequired => "lut_vector_length_required",
            Self::MovprfxPairRequired => "movprfx_pair_required",
            Self::LutV2StateRequired => "lut_v2_state_required",
            Self::LutStateRequired => "lut_state_required",
            Self::CurrentVectorLengthTooSmall => "current_vector_length_too_small",
            Self::MaximumVectorLengthTooSmall => "maximum_vector_length_too_small",
            Self::StreamingI8mmUnsupported => "streaming_i8mm_unsupported",
            Self::HaltedDebugRequired => "halted_debug_required",
            Self::IntegerMatrixStateRequired => "integer_matrix_state_required",
            Self::LeadingCountsRequireDitClear => "leading_counts_require_dit_clear",
            Self::SmeLookupRequiresDitClear => "sme_lookup_requires_dit_clear",
            Self::TableLookupRequiresDitClear => "table_lookup_requires_dit_clear",
            Self::IntegerShiftRequiresDitClear => "integer_shift_requires_dit_clear",
            Self::InvalidStreamingIntegerProduct => "invalid_streaming_integer_product",
            Self::Region(..) => "region",
            Self::SmeTableVectorLength { .. } => "sme_table_vector_length",
            Self::Unsupported(..) => "unsupported",
            Self::SmeMemory(..) => "sme_memory",
            Self::SmeMovement(..) => "sme_movement",
            Self::ReservedEncoding { .. } => "reserved_encoding",
            Self::ProfileRequiresScalable { .. } => "profile_requires_scalable",
            Self::MemoryChecksUnsupported { .. } => "memory_checks_unsupported",
            Self::NativeZeroBlockUnsupported { .. } => "native_zero_block_unsupported",
            Self::InvalidZeroBlockSize { .. } => "invalid_zero_block_size",
            Self::NativeCacheCleanUnsupported { .. } => "native_cache_clean_unsupported",
            Self::ProfileNotImplemented { .. } => "profile_not_implemented",
            Self::StreamingDotOperands => "streaming_dot_operands",
            Self::UnresolvedDirectTarget { .. } => "unresolved_direct_target",
            Self::ConflictingMemoryRequirements => "conflicting_memory_requirements",
            Self::NumericalModeUnavailable => "numerical_mode_unavailable",
            Self::UnresearchedAmxImmediate { .. } => "unresearched_amx_immediate",
            Self::MovprfxEffectsUnreviewed => "movprfx_effects_unreviewed",
            Self::OutsideCheckedMemoryProfile => "outside_checked_memory_profile",
            Self::ContextServiceUnimplemented => "context_service_unimplemented",
            Self::ContextMemoryUnimplemented => "context_memory_unimplemented",
            Self::MovprfxFollowerMissing => "movprfx_follower_missing",
            Self::MovprfxFollowerIsPrefix => "movprfx_follower_is_prefix",
            Self::MovprfxFollowerUnsupported(..) => "movprfx_follower_unsupported",
            Self::MovprfxMetadataUnreviewed => "movprfx_metadata_unreviewed",
            Self::MovprfxViolation(..) => "movprfx_violation",
            Self::GuestFeaturesUnavailable { .. } => "guest_features_unavailable",
            Self::OutsideContextIntegerProfile => "outside_context_integer_profile",
            Self::TooManyInstructions { .. } => "too_many_instructions",
            Self::UnadmittedNopProvenance => "unadmitted_nop_provenance",
            Self::OutsideRestrictedSystemProfile => "outside_restricted_system_profile",
        }
    }
}

impl serde::Serialize for CompileErrorKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        struct Message<'a>(&'a CompileErrorKind);
        impl serde::Serialize for Message<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self.0)
            }
        }
        let mut record = serializer.serialize_struct("CompileErrorKind", 2)?;
        record.serialize_field("code", self.code())?;
        record.serialize_field("message", &Message(self))?;
        record.end()
    }
}
impl core::fmt::Display for CompileErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CpaSpecializationRequired => {
                f.write_str("CPA arithmetic requires an explicit feature/mode specialization")
            }
            Self::HalfHostCapabilityUnavailable => {
                f.write_str("Half candidate host capability unavailable")
            }
            Self::InvalidHalfOutputFormat => f.write_str("Half numerical outputs must be Single"),
            Self::ReservedCoreBinary => f.write_str("reserved core binary allocation"),
            Self::InvalidNumericalOutputs => {
                f.write_str("invalid or overlapping numerical outputs")
            }
            Self::InvalidNumericalOutputCount => {
                f.write_str("numerical frame requires one to four outputs")
            }
            Self::UnexpectedRegisterBranch => {
                f.write_str("checked register span unexpectedly branches")
            }
            Self::UnexpectedMemoryBranch => f.write_str("checked GPR prefix unexpectedly branches"),
            Self::DebugMovementStateRequired => {
                f.write_str("halted MOVT specialization requires active ZA and enabled ZT0")
            }
            Self::InvalidDebugMovement => {
                f.write_str("debug movement accepts only the two MOVT GPR/ZT0 forms")
            }
            Self::UnallocatedMovement => f.write_str("not an allocated movement instruction"),
            Self::ExecutionContextMismatch => {
                f.write_str("extended execution context/profile mismatch")
            }
            Self::VectorLengthExceedsMaximum => {
                f.write_str("current streaming vector length exceeds declared maximum")
            }
            Self::Zt0RequiresSme2 => f.write_str("ZT0 enable requires FEAT_SME2"),
            Self::FpmrRequiresFeature => f.write_str("FPMR access enable requires FEAT_FPMR"),
            Self::Sme2p1RequiresSme2 => f.write_str("FEAT_SME2p1 requires FEAT_SME2"),
            Self::ScalableRequiresSme => f.write_str("scalable profile requires FEAT_SME"),
            Self::MovprfxFollowerMismatch => {
                f.write_str("MOVPRFX follower source/operand mismatch")
            }
            Self::GuestAddressOverflow => f.write_str("guest address overflow"),
            Self::SourceExtentOverflow => f.write_str("MOVPRFX pair source extent overflow"),
            Self::MisalignedInstructionAddress => {
                f.write_str("instruction PC must be aligned to 4 bytes")
            }
            Self::IncompleteSourceInstruction => f.write_str("incomplete source instruction"),
            Self::SourceOffsetOverflow => f.write_str("MOVPRFX source offset overflow"),
            Self::InvalidContextSourceLayout => {
                f.write_str("context block input must be aligned, nonempty and bounded")
            }
            Self::UnrequestedScalableOperation => {
                f.write_str("unrequested scalable operation in checked GPR memory profile")
            }
            Self::InstructionAddressMismatch => f.write_str("checked instruction PC differs"),
            Self::ConstrainedExclusiveOperands => f.write_str(
                "constrained exclusive operands require a generic undefined-instruction boundary",
            ),
            Self::InvalidExclusiveTransfer => f.write_str("invalid exclusive transfer operands"),
            Self::InvalidExclusiveStatusRegister => {
                f.write_str("invalid exclusive status register")
            }
            Self::FixedAddressContractRequired => {
                f.write_str("checked shared operations require the fixed address contract")
            }
            Self::InvalidOrderedOperand => f.write_str("invalid checked ordered operand"),
            Self::InvalidDmbOperand => f.write_str("invalid checked DMB operand"),
            Self::InvalidLseOperand => f.write_str("invalid checked LSE operand"),
            Self::AmbiguousSystemInstruction => f.write_str("ambiguous system instruction family"),
            Self::ReservedScalableNumerical => f.write_str("reserved scalable numerical encoding"),
            Self::FullA64RequiresSmeFa64 => {
                f.write_str("effective FullA64 requires declared FEAT_SME_FA64")
            }
            Self::FpmrAccessDisabled => {
                f.write_str("indirect FPMR access is not enabled in the declared guest profile")
            }
            Self::NumericalDescriptorMismatch => {
                f.write_str("scalable numerical source/descriptor mismatch")
            }
            Self::IncompatibleMemoryRequirements => {
                f.write_str("incompatible checked memory requirements")
            }
            Self::UnadmittedMemoryTerminal => {
                f.write_str("terminal service is not admitted by checked GPR memory profile")
            }
            Self::UnqualifiedSharedMemoryProfile => {
                f.write_str("shared system memory specialization is unqualified")
            }
            Self::NativeBranchOverflow => f.write_str("native branch displacement overflow"),
            Self::FixedMemoryServiceNotRequested => f.write_str(
                "checked fixed-width memory service was not requested by scalable profile",
            ),
            Self::ScalarMemoryServiceNotRequested => {
                f.write_str("checked scalar service was not requested by scalable profile")
            }
            Self::ExclusiveServiceNotRequested => {
                f.write_str("exclusive service was not requested by scalable profile")
            }
            Self::MissingLeafReturn => f.write_str("leaf region must end in RET X30"),
            Self::InvalidSourceLayout => {
                f.write_str("input and guest base must be nonempty/aligned to 4 bytes")
            }
            Self::StreamingModeRequired => f.write_str("streaming mode required"),
            Self::ZaEnabledStateRequired => f.write_str("ZA enabled state required"),
            Self::ZaEnableRequired => f.write_str("ZA enable required"),
            Self::ZaStateRequired => f.write_str("ZA state required"),
            Self::Zt0EnableRequired => f.write_str("ZT0 enable required"),
            Self::Zt0EnabledStateRequired => f.write_str("ZT0 enabled state required"),
            Self::LutVectorLengthRequired => {
                f.write_str("LUT requires a larger current/maximum vector length")
            }
            Self::MovprfxPairRequired => f.write_str("MOVPRFX pair validation required"),
            Self::LutV2StateRequired => f.write_str("SME LUTv2 requires ZA and enabled ZT0"),
            Self::LutStateRequired => f.write_str("SME lookup requires ZA and enabled ZT0"),
            Self::CurrentVectorLengthTooSmall => {
                f.write_str("current streaming vector length is too small")
            }
            Self::MaximumVectorLengthTooSmall => {
                f.write_str("maximum streaming vector length is too small")
            }
            Self::StreamingI8mmUnsupported => {
                f.write_str("guest I8MM is outside the streaming profile")
            }
            Self::HaltedDebugRequired => f.write_str("halted debug execution required"),
            Self::IntegerMatrixStateRequired => {
                f.write_str("streaming mode and ZA required for integer matrix operation")
            }
            Self::LeadingCountsRequireDitClear => {
                f.write_str("BSR leading counts require a declared DIT=0 profile")
            }
            Self::SmeLookupRequiresDitClear => {
                f.write_str("scalar SME lookup requires a declared DIT=0 profile")
            }
            Self::TableLookupRequiresDitClear => {
                f.write_str("scalar table lookup requires explicitly declared DIT=0")
            }
            Self::IntegerShiftRequiresDitClear => {
                f.write_str("selected streaming integer shift mapping requires declared DIT=0")
            }
            Self::InvalidStreamingIntegerProduct => {
                f.write_str("invalid streaming integer product operand")
            }
            Self::Region(error) => write!(f, "resident loop emission failed: {error}"),
            Self::SmeTableVectorLength { minimum_bits } => {
                write!(f, "SME table operands require SVL >= {minimum_bits} bits")
            }
            Self::Unsupported(reason) => write!(f, "unsupported ARM64 semantics: {reason:?}"),
            Self::SmeMemory(error) => error.fmt(f),
            Self::SmeMovement(error) => error.fmt(f),
            Self::ReservedEncoding { family } => write!(f, "reserved {family} encoding"),
            Self::ProfileRequiresScalable { profile, required } => write!(
                f,
                "{profile:?} {} a scalable specialization",
                if *required { "requires" } else { "takes no" }
            ),
            Self::MemoryChecksUnsupported { profile } => {
                write!(f, "{profile:?} makes only the default memory checks")
            }
            Self::NativeZeroBlockUnsupported { profile } => {
                write!(f, "{profile:?} keeps DC ZVA's System exit")
            }
            Self::InvalidZeroBlockSize { bytes } => {
                write!(f, "a {bytes}-byte DC ZVA block is not a DCZID_EL0.BS size")
            }
            Self::NativeCacheCleanUnsupported { profile } => {
                write!(f, "{profile:?} keeps the DC clean operations' System exit")
            }
            Self::ProfileNotImplemented { profile } => {
                write!(f, "no emitter implements {profile:?}")
            }
            Self::StreamingDotOperands => f.write_str("unsupported streaming integer dot operands"),
            Self::UnresolvedDirectTarget { target } => {
                write!(f, "unresolved direct target {:#x}", target.0)
            }
            Self::ConflictingMemoryRequirements => {
                f.write_str("conflicting memory control requirements")
            }
            Self::NumericalModeUnavailable => f.write_str("scalable numerical mode unavailable"),
            Self::UnresearchedAmxImmediate { operation, field } => write!(
                f,
                "AMX operation {operation} immediate {field} has no researched behavior"
            ),
            Self::MovprfxEffectsUnreviewed => f.write_str(
                "MOVPRFX pair validation: follower pair/effect requirements are not reviewed",
            ),
            Self::OutsideCheckedMemoryProfile => {
                f.write_str("operation outside checked GPR memory profile")
            }
            Self::ContextServiceUnimplemented => {
                f.write_str("context block service is not integrated")
            }
            Self::ContextMemoryUnimplemented => {
                f.write_str("context block memory entry is not integrated")
            }
            Self::MovprfxFollowerMissing => {
                f.write_str("MOVPRFX pair validation: follower missing from source window")
            }
            Self::MovprfxFollowerIsPrefix => {
                f.write_str("MOVPRFX pair validation: follower is another prefix")
            }
            Self::MovprfxFollowerUnsupported(error) => {
                write!(f, "MOVPRFX pair validation: unsupported follower: {error}")
            }
            Self::MovprfxMetadataUnreviewed => {
                f.write_str("MOVPRFX pair validation: follower metadata not reviewed")
            }
            Self::MovprfxViolation(violation) => {
                write!(f, "MOVPRFX pair validation failed: {violation:?}")
            }
            Self::GuestFeaturesUnavailable {
                available,
                required,
            } => {
                let available_bits = *available;
                let available = available.names();
                let missing: alloc::vec::Vec<_> = required
                    .all_features()
                    .names()
                    .into_iter()
                    .filter(|name| !available.contains(name))
                    .collect();
                f.write_str("unavailable guest features")?;
                if !missing.is_empty() {
                    write!(f, ": requires {}", missing.join(", "))?;
                }
                let alternatives = required.any_features();
                if alternatives != ScalableFeatures::empty()
                    && !FeatureRequirement::any(alternatives).is_satisfied_by(available_bits)
                {
                    write!(f, "; requires one of {}", alternatives.names().join(", "))?;
                }
                Ok(())
            }
            Self::OutsideContextIntegerProfile => {
                f.write_str("operation outside extended integer profile")
            }
            Self::TooManyInstructions { maximum } => {
                write!(f, "block input exceeds {maximum} instructions")
            }
            Self::UnadmittedNopProvenance => {
                f.write_str("unadmitted NOP provenance in checked memory profile")
            }
            Self::OutsideRestrictedSystemProfile => {
                f.write_str("operation outside restricted System prefix profile")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_error_keeps_the_declined_word_and_address() {
        let base = GuestAddress(0x1000);
        let source: alloc::vec::Vec<_> = [0xd503201fu32, 0, 0xd65f03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let options = crate::Options::new(BlockProfile::ORDINARY, crate::TargetCpu::Baseline);
        let error = crate::compile(&source, base, &options).unwrap_err();
        assert_eq!(
            error.instruction,
            Some(InstructionContext {
                address: GuestAddress(0x1004),
                encoding: Some(0)
            })
        );
        assert_eq!(
            error.kind,
            CompileErrorKind::Unsupported(UnsupportedReason::Instruction {
                address: GuestAddress(0x1004),
                encoding: 0
            })
        );
        assert_eq!(error.kind.code(), "unsupported");
        let analysis = crate::block::analyze(&source, base).unwrap_err();
        assert_eq!(analysis.pc, GuestAddress(0x1004));
        assert_eq!(analysis.encoding, Some(0));
        assert_eq!(analysis.kind, error.kind);
    }

    #[test]
    fn adding_address_context_preserves_the_same_instruction_word() {
        let pc = GuestAddress(0x1000);
        let error = CompileError::from(UnsupportedReason::Instruction {
            address: pc,
            encoding: 0xdeadbeef,
        })
        .at(pc);
        assert_eq!(error.instruction.unwrap().encoding, Some(0xdeadbeef));
    }

    #[test]
    fn sme_capability_failure_remains_typed_through_the_public_boundary() {
        let cause = SmeMemoryError {
            required: crate::TargetCpu::Sse41,
            available: crate::TargetCpu::Baseline,
        };
        let error = CompileError::from(cause).at(GuestAddress(0x1000));
        assert_eq!(error.kind, CompileErrorKind::SmeMemory(cause));
        assert!(core::error::Error::source(&error).is_some());
    }
}
