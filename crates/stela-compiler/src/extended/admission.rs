//! Decoding one instruction and admitting it under a scalable profile.
use crate::aarch64::Unsupported;
use alloc::{format, vec::Vec};

use super::{Decoded, ScalableProfile, ordinary_permitted};
use crate::{
    CompileError, GuestAddress, Lifter, TargetCpu,
    aarch64::{
        Decoder,
        scalable::{
            ElementSize,
            features::{FeatureRequirement, ScalableFeature, ScalableFeatures},
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
    x86_64,
};

pub(super) fn require_features(
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
pub(super) fn decode(
    pc: GuestAddress,
    word: u32,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<Decoded, CompileError> {
    decode_recording_features(pc, word, profile, target, &mut Vec::new())
}

/// Profile checks for one scalable instruction. Every admitted feature
/// requirement is recorded in `clauses`.
struct Admission<'a> {
    pc: GuestAddress,
    profile: ScalableProfile,
    clauses: &'a mut Vec<FeatureRequirement>,
}

impl Admission<'_> {
    fn error(&self, reason: &str) -> CompileError {
        CompileError(format!("{reason} at {:#x}", self.pc.0))
    }

    fn ensure(&self, condition: bool, reason: &str) -> Result<(), CompileError> {
        if condition {
            Ok(())
        } else {
            Err(self.error(reason))
        }
    }

    fn operand<T>(
        &self,
        decoded: Result<T, Unsupported>,
        encoding: &str,
    ) -> Result<T, CompileError> {
        decoded.map_err(|Unsupported| self.error(&format!("reserved {encoding} encoding")))
    }

    fn require(&mut self, features: ScalableFeatures) -> Result<(), CompileError> {
        require_features(
            self.profile,
            self.clauses,
            FeatureRequirement::all(features),
            self.pc,
        )
    }

    fn streaming(&self) -> Result<(), CompileError> {
        self.ensure(self.profile.mode().streaming(), "streaming mode required")
    }

    /// The common streaming SVE admission: a valid operand, streaming mode and SME.
    fn streaming_sme<T>(
        &mut self,
        decoded: Result<T, Unsupported>,
        encoding: &str,
    ) -> Result<T, CompileError> {
        let operand = self.operand(decoded, encoding)?;
        self.streaming()?;
        self.require(ScalableFeatures::of(ScalableFeature::Sme))?;
        Ok(operand)
    }

    fn declared_dit_zero(&self, required: bool, reason: &str) -> Result<(), CompileError> {
        self.ensure(
            !required || self.profile.required_dit() == Some(false),
            reason,
        )
    }
}

pub(super) fn decode_recording_features(
    pc: GuestAddress,
    word: u32,
    profile: ScalableProfile,
    target: TargetCpu,
    clauses: &mut Vec<FeatureRequirement>,
) -> Result<Decoded, CompileError> {
    use ScalableFeature as F;
    let sme = ScalableFeatures::of(F::Sme);
    let mut check = Admission {
        pc,
        profile,
        clauses,
    };
    if let Some(operand) = sme_memory::decode(word) {
        let (streaming, za, sme2, zt0) = match operand {
            sme_memory::Operand::Vectors(_) => (true, false, true, false),
            sme_memory::Operand::Tile(_) => (true, true, false, false),
            sme_memory::Operand::ZaVector(_) => (false, true, false, false),
            sme_memory::Operand::Zt(_) => (false, true, true, true),
        };
        check.ensure(
            !streaming || profile.mode().streaming(),
            "streaming mode required",
        )?;
        check.ensure(
            !za || profile.mode().za_enabled(),
            "ZA enabled state required",
        )?;
        check.ensure(
            !zt0 || profile.controls().zt0_enabled(),
            "ZT0 enable required",
        )?;
        check.require(if sme2 { sme.with(F::Sme2) } else { sme })?;
        x86_64::sme::memory::validate_target(&operand, target)
            .map_err(|reason| CompileError(format!("{reason} at {:#x}", pc.0)))?;
        return Ok(Decoded::SmeMemory(operand));
    }
    if let Some(decoded) = integer_vector::decode(word) {
        let operand = check.operand(decoded, "multi-vector integer")?;
        check.require(ScalableFeatures::of(F::Sme2))?;
        // This profile supplies streaming SME lengths, not ordinary SVE state.
        // The six SVE-category narrows enter through their SME2 alternative.
        check.streaming()?;
        return Ok(Decoded::SmeIntegerVector(operand));
    }
    if let Some(decoded) = memory_load::decode(word) {
        return Ok(Decoded::MemoryLoad(
            check.streaming_sme(decoded, "streaming load")?,
        ));
    }
    if let Some(decoded) = memory_multi::decode(word) {
        let operand = check.operand(decoded, "streaming multi-vector memory")?;
        check.streaming()?;
        check.require(sme.with(F::Sme2))?;
        return Ok(Decoded::MemoryMulti(operand));
    }
    if let Some(decoded) = memory_store::decode(word) {
        let operand = check.operand(decoded, "streaming store")?;
        check.streaming()?;
        let quadword = matches!(operand, memory_store::Operand::Store(store)
            if store.memory_element == ElementSize::Quadword);
        check.require(if quadword { sme.with(F::Sme2p1) } else { sme })?;
        return Ok(Decoded::MemoryStore(operand));
    }
    if let Some(decoded) = memory_structure::decode(word) {
        let operand = check.operand(decoded, "streaming structured load")?;
        check.streaming()?;
        // Q allocation accepts SVE2p1 or SME2p1 architecturally. This compiler
        // entry owns SME streaming profiles, so it uses the SME2p1 alternative.
        let quadword = operand.requires_sve2p1_or_sme2p1();
        check.require(if quadword { sme.with(F::Sme2p1) } else { sme })?;
        return Ok(Decoded::MemoryStructure(operand));
    }
    if let Some(decoded) = address::decode(word) {
        let operand = check.operand(decoded, "streaming length/count")?;
        check.streaming()?;
        let counter = matches!(
            operand.kind,
            address::Kind::Count(address::Count::Counter { .. })
        );
        check.require(if counter { sme.with(F::Sme2) } else { sme })?;
        return Ok(Decoded::Address(operand));
    }
    if let Some(decoded) = dot::decode_integer(word) {
        let operand = check.operand(decoded, "streaming integer dot")?;
        check.ensure(
            !operand.requires_i8mm() || profile.declared_features().is_some(),
            "guest I8MM is outside the streaming profile",
        )?;
        check.streaming()?;
        let mut required = sme;
        if operand.requires_i8mm() {
            required = required.with(F::I8mm);
        }
        if matches!(
            operand.kind,
            dot::Kind::Integer {
                products: dot::Products::Two,
                ..
            }
        ) {
            required = required.with(F::Sme2);
        }
        check.require(required)?;
        return Ok(Decoded::IntegerDot(operand));
    }
    if let Some(decoded) = integer_predicate_move::decode(word) {
        let operand = check.operand(decoded, "streaming predicate-to-vector")?;
        check.require(ScalableFeatures::of(F::Sme2p1))?;
        check.streaming()?;
        return Ok(Decoded::IntegerPredicateMove(operand));
    }
    if let Some(decoded) = integer_bits::decode(word) {
        let operand = check.streaming_sme(decoded, "streaming integer-bit")?;
        check.declared_dit_zero(
            x86_64::sve::integer_bits::requires_declared_dit_zero(operand, profile.vector_length()),
            "BSR leading counts require a declared DIT=0 profile",
        )?;
        return Ok(Decoded::IntegerBits(operand));
    }
    if let Some(decoded) = integer_logic::decode(word) {
        let operand = check.operand(decoded, "streaming integer")?;
        check.streaming()?;
        check.ensure(
            !matches!(operand.kind, Kind::Copy(CopySource::Vector(_))),
            "MOVPRFX pair validation required",
        )?;
        check.require(sme)?;
        return Ok(Decoded::IntegerLogic(operand));
    }
    if let Some(decoded) = integer_comparison::decode(word) {
        let operand = check.streaming_sme(decoded, "streaming integer comparison")?;
        return Ok(Decoded::IntegerComparison(operand));
    }
    if let Some(decoded) = integer_arithmetic::decode(word) {
        let operand = check.streaming_sme(decoded, "streaming integer arithmetic")?;
        return Ok(Decoded::IntegerArithmetic(operand));
    }
    if let Some(decoded) = integer_saturation::decode(word) {
        let operand = check.streaming_sme(decoded, "streaming integer saturation")?;
        return Ok(Decoded::IntegerSaturation(operand));
    }
    if let Some(decoded) = rearrange_widen::decode(word) {
        let operand = check.streaming_sme(decoded, "streaming rearrangement")?;
        return Ok(Decoded::RearrangeWiden(operand));
    }
    if let Some(decoded) = shifts::decode(word) {
        let operand = check.streaming_sme(decoded, "streaming integer shift")?;
        check.declared_dit_zero(
            x86_64::sve::shifts::requires_declared_dit_zero(operand, profile.vector_length()),
            "selected streaming integer shift mapping requires declared DIT=0",
        )?;
        return Ok(Decoded::Shifts(operand));
    }
    if let Some(decoded) = shifts_narrow::decode(word) {
        let operand = check.streaming_sme(decoded, "streaming width-conversion")?;
        return Ok(Decoded::ShiftsNarrow(operand));
    }
    if let Some(decoded) = sign::decode(word) {
        return Ok(Decoded::Sign(
            check.streaming_sme(decoded, "streaming sign")?,
        ));
    }
    if let Some(decoded) = integer_products::decode(word) {
        let operand = check.streaming_sme(decoded, "streaming integer product")?;
        x86_64::sve::integer_products::validate(operand)
            .map_err(|Unsupported| check.error("invalid streaming integer product operand"))?;
        return Ok(Decoded::IntegerProducts(operand));
    }
    if let Some(operand) = integer_dots::decode(word) {
        let wide = operand.accumulator == ElementSize::Doubleword;
        let features = ScalableFeatures::of(F::Sme2);
        check.require(if wide {
            features.with(F::SmeI16I64)
        } else {
            features
        })?;
        check.streaming()?;
        check.ensure(profile.mode().za_enabled(), "ZA enable required")?;
        return Ok(Decoded::SmeIntegerDots(operand));
    }
    if let Some(decoded) = sve_tables::decode(word) {
        let operand = check.operand(decoded, "streaming LUT")?;
        profile.require_features(
            FeatureRequirement::all(ScalableFeatures::of(F::Sme2).with(F::Lut)),
            pc,
        )?;
        check.streaming()?;
        let minimum = operand.minimum_vl_bits();
        check.ensure(
            profile.vector_length().bits() >= minimum
                && profile.controls().max_vector_length().bits() >= minimum,
            "LUT requires a larger current/maximum vector length",
        )?;
        return Ok(Decoded::SveTables(operand));
    }
    if let Some(decoded) = rearrange_extract::decode(word) {
        let operand = check.streaming_sme(decoded, "streaming extraction")?;
        return Ok(Decoded::RearrangeExtract(operand));
    }
    if let Some(decoded) = floating_copy::decode(word) {
        let operand = check.streaming_sme(decoded, "streaming floating copy")?;
        return Ok(Decoded::FloatingCopy(operand));
    }
    if let Some(decoded) = predicate_generation::decode(word) {
        let operand = check.operand(decoded, "streaming predicate generation")?;
        check.streaming()?;
        check.require(if operand.requires_sme2() {
            sme.with(F::Sme2)
        } else {
            sme
        })?;
        return Ok(Decoded::PredicateGeneration(operand));
    }
    if let Some(decoded) = predicate_logic::decode(word) {
        let operand = check.operand(decoded, "streaming predicate logic")?;
        check.streaming()?;
        check.require(match operand.kind {
            predicate_logic::Kind::MoveVector { .. } => sme.with(F::Sme2p1),
            predicate_logic::Kind::ExtractCounter { .. } => sme.with(F::Sme2),
            _ => sme,
        })?;
        return Ok(Decoded::PredicateLogic(operand));
    }
    if let Some(decoded) = reductions::decode(word) {
        let operand = check.operand(decoded, "streaming integer reduction")?;
        if operand.output == reductions::Output::Quadword {
            check.require(ScalableFeatures::of(F::Sme2p1))?;
        }
        check.streaming()?;
        check.require(sme)?;
        return Ok(Decoded::Reductions(operand));
    }
    if let Some(decoded) = rearrange::decode(word) {
        let operand = check.operand(decoded, "streaming rearrangement")?;
        if matches!(
            operand,
            rearrange::Operand::Interleave { segment: true, .. }
                | rearrange::Operand::Extract { segment: true, .. }
                | rearrange::Operand::Table { segment: true, .. }
                | rearrange::Operand::DuplicateSegment { .. }
        ) {
            check.require(ScalableFeatures::of(F::Sme2p1))?;
        }
        check.streaming()?;
        check.require(sme)?;
        check.declared_dit_zero(
            x86_64::sve::rearrange::requires_explicit_dit_zero(
                operand,
                profile.vector_length(),
                target,
            ),
            "scalar table lookup requires explicitly declared DIT=0",
        )?;
        return Ok(Decoded::Rearrange(operand));
    }
    if let Some(operand) = movement::decode(word) {
        let requirements = operand.requirements;
        check.ensure(!requirements.halted, "halted debug execution required")?;
        check.require(ScalableFeatures::of(match requirements.feature {
            movement::Feature::Sme => F::Sme,
            movement::Feature::Sme2 => F::Sme2,
            movement::Feature::Sme2p1 => F::Sme2p1,
        }))?;
        check.ensure(
            !requirements.za || profile.mode().za_enabled(),
            "ZA state required",
        )?;
        check.ensure(
            !requirements.streaming || profile.mode().streaming(),
            "streaming mode required",
        )?;
        check.ensure(
            !requirements.zt0 || profile.controls().zt0_enabled(),
            "ZT0 enabled state required",
        )?;
        check.ensure(
            profile.controls().max_vector_length().bits()
                >= usize::from(requirements.minimum_implemented_svl_bits),
            "maximum streaming vector length is too small",
        )?;
        check.ensure(
            profile.vector_length().bits() >= usize::from(requirements.minimum_current_svl_bits),
            "current streaming vector length is too small",
        )?;
        return Ok(Decoded::SmeMovement(operand));
    }
    if let Some(operand) = lut_v2::decode(word) {
        let required = sme.with(F::SmeLutV2);
        check.require(if operand.requires_sme2p1() {
            required.with(F::Sme2p1)
        } else {
            required
        })?;
        check.streaming()?;
        check.ensure(
            profile.mode().za_enabled() && profile.controls().zt0_enabled(),
            "SME LUTv2 requires ZA and enabled ZT0",
        )?;
        return Ok(Decoded::SmeLutV2(operand));
    }
    if let Some(operand) = tables::decode(word) {
        check.declared_dit_zero(
            x86_64::sme::tables::requires_dit_zero(&operand, profile.vector_length(), target),
            "scalar SME lookup requires a declared DIT=0 profile",
        )?;
        let features = sme.with(F::Sme2);
        check.require(if operand.feature == tables::Feature::Sme2p1 {
            features.with(F::Sme2p1)
        } else {
            features
        })?;
        check.streaming()?;
        let minimum = operand.minimum_svl_bits();
        check.ensure(
            profile.vector_length().bits() >= minimum
                && profile.controls().max_vector_length().bits() >= minimum,
            &format!("SME table operands require SVL >= {minimum} bits"),
        )?;
        check.ensure(
            !operand.requires_zt0()
                || (profile.mode().za_enabled() && profile.controls().zt0_enabled()),
            "SME lookup requires ZA and enabled ZT0",
        )?;
        return Ok(Decoded::SmeTables(operand));
    }
    if let Some(operand) = integer_matrix::decode(word) {
        let mut required = sme;
        if operand.requires_sme2() {
            required = required.with(F::Sme2);
        }
        if operand.requires_i16i64() {
            required = required.with(F::SmeI16I64);
        }
        check.require(required)?;
        check.ensure(
            profile.mode().streaming() && profile.mode().za_enabled(),
            "streaming mode and ZA required for integer matrix operation",
        )?;
        return Ok(Decoded::SmeIntegerMatrix(operand));
    }
    if let Some(operand) = length::decode(word) {
        check.require(sme)?;
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
