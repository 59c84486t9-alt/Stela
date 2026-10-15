//! Context-backed leaf compilation with immutable scalable specialization.
//!
//! The profile admits streaming integer logic, arithmetic, saturation and dot
//! products, SME length arithmetic, floating sign operations and existing pure
//! GPR/control mappings. Other effects remain explicit declines.

use std::collections::BTreeMap;

use crate::{
    CompileError, GuestAddress, Lifter, NativeBlock, TargetCpu,
    aarch64::{
        Decoder, Instruction, Operation,
        scalable::{
            ElementSize, ScalableMode, VectorLength,
            features::{FeatureRequirement, ScalableFeature, ScalableFeatures},
            profile::ScalableControls,
        },
        sme::{integer_dots, length},
        sve::{
            dot, integer_arithmetic,
            integer_logic::{self, CopySource, Kind},
            integer_products, integer_saturation, rearrange_extract, sign,
        },
    },
    context::{ExecutionContext, ScalableStateView},
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

enum Decoded {
    Ordinary(Instruction),
    IntegerDot(dot::Operand),
    IntegerLogic(integer_logic::Operand),
    IntegerProducts(integer_products::Operand),
    IntegerSaturation(integer_saturation::Operand),
    RearrangeExtract(rearrange_extract::Operand),
    Sign(sign::Operand),
    IntegerArithmetic(integer_arithmetic::Operand),
    Length(length::Operand),
    SmeIntegerDots(integer_dots::Operand),
}

fn ordinary_permitted(operation: &Operation) -> bool {
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

fn decode(
    pc: GuestAddress,
    word: u32,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<Decoded, CompileError> {
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
        profile.require_features(FeatureRequirement::all(required), pc)?;
        return Ok(Decoded::IntegerDot(operand));
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
        profile.require_features(
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::IntegerLogic(operand));
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
        profile.require_features(
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
        profile.require_features(
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::IntegerSaturation(operand));
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
        profile.require_features(
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
        profile.require_features(
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
        profile.require_features(FeatureRequirement::all(features), pc)?;
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
        profile.require_features(
            FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme)),
            pc,
        )?;
        return Ok(Decoded::RearrangeExtract(operand));
    }
    if let Some(operand) = length::decode(word) {
        profile.require_features(
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

fn context_wrapper() -> Vec<u8> {
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
        Decoded::IntegerLogic(operand) => {
            x86_64::sve::integer_logic::emit(code, operand, profile.length, target);
        }
        Decoded::IntegerArithmetic(operand) => {
            x86_64::sve::integer_arithmetic::emit(code, operand, profile.length, target);
        }
        Decoded::IntegerSaturation(operand) => {
            x86_64::sve::integer_saturation::emit(code, operand, profile.length, target);
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
        Decoded::Length(operand) => {
            x86_64::sme::length::emit(code, &operand, profile.length);
        }
    }
    Ok(())
}

/// Compile an extended two-argument leaf ending in RET X30. The runtime must
/// validate this exact profile against its owned view before unsafe invocation.
pub fn compile_for_profile(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    if source.is_empty()
        || !source.len().is_multiple_of(INSTRUCTION_BYTES)
        || !base.0.is_multiple_of(INSTRUCTION_BYTES as u64)
    {
        return Err(CompileError(
            "input and guest base must be nonempty/aligned to 4 bytes".into(),
        ));
    }
    let instructions: Vec<_> = source
        .as_chunks::<INSTRUCTION_BYTES>()
        .0
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let pc = base
                .0
                .checked_add((index as u64) * INSTRUCTION_BYTES as u64)
                .map(GuestAddress)
                .ok_or_else(|| CompileError("guest address overflow".into()))?;
            Ok((pc, decode(pc, u32::from_le_bytes(*bytes), profile, target)?))
        })
        .collect::<Result<_, CompileError>>()?;
    if !matches!(
        instructions.last(),
        Some((
            _,
            Decoded::Ordinary(Instruction {
                operation: Operation::Return,
                ..
            })
        ))
    ) {
        return Err(CompileError("leaf region must end in RET X30".into()));
    }
    let mut code = context_wrapper();
    let mut source_map = Vec::with_capacity(instructions.len());
    let mut fixups = Vec::new();
    for (pc, instruction) in instructions {
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
mod tests {
    use super::*;

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
}

#[cfg(test)]
mod rearrange_extract_tests;
