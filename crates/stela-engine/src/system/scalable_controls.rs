//! CPACR_EL1 and SMCR_EL1 for an EL0/EL1 machine. Every checked native entry
//! re-evaluates its requirements against them.
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
mod features;
pub mod fp;

use fp::FpControlOwner;

use super::{
    access::ExceptionLevel,
    identification::Register as IdRegister,
    identification_snapshot::{self, Origin, Snapshot},
    pstate::DIT_MASK,
    state::{PSTATE_IL_MASK, PSTATE_SS_MASK, SystemState},
};
use crate::scalable::ScalableState;
use stela_compiler::aarch64::system::registers::Encoding;
use stela_compiler::{
    GuestAddress, GuestState,
    aarch64::scalable::{
        ScalableMode, VectorLength,
        execution::{
            ScalableAccessCheck as Check, ScalableAccessRequirements, ScalableExecutionRequirements,
        },
        features::{ScalableFeature, ScalableFeatures},
    },
    context::memory::MemoryImplementationProfile,
    scalable_context::ScalableProfile,
};

const ZEN_SHIFT: u32 = 16;
const FPEN_SHIFT: u32 = 20;
const SMEN_SHIFT: u32 = 24;
const ENABLE_MASK: u64 = 3;
const SMCR_LEN_MASK: u64 = 0xf;
const SMCR_RAZ_WI_MASK: u64 = 0x1f0;
const SMCR_EZT0_MASK: u64 = 1 << 30;
const SMCR_FA64_MASK: u64 = 1 << 31;
const VECTOR_GRANULE_BYTES: usize = 16;
const FP_EC: u8 = 0x07;
const SVE_EC: u8 = 0x19;
const SME_EC: u8 = 0x1d;
const A64_FP_ISS: u32 = 0x1e << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    CpacrEl1,
    SmcrEl1,
}
impl Register {
    pub const fn encoding(self) -> Encoding {
        match self {
            Self::CpacrEl1 => Encoding::new(3, 0, 1, 0, 2),
            Self::SmcrEl1 => Encoding::new(3, 0, 1, 2, 6),
        }
    }
    pub fn decode(encoding: Encoding) -> Option<Self> {
        [Self::CpacrEl1, Self::SmcrEl1]
            .into_iter()
            .find(|r| r.encoding() == encoding)
    }
}

/// Initial readbacks, never reset guesses. LEN is programmed, not SVL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Readbacks {
    pub cpacr_el1: u64,
    pub smcr_el1: u64,
}

/// Explicit implementation facts for a fresh software CPU. This does not
/// reconstruct hardware support from a sampled RDSVL or current state length.
#[derive(Debug)]
pub struct Implementation {
    source_atomicity: SourceAtomicity,
    lengths: Box<[VectorLength]>,
    memory: MemoryImplementationProfile,
}
impl Implementation {
    pub fn declared(
        lengths: &[VectorLength],
        memory: MemoryImplementationProfile,
    ) -> Result<Self, Error> {
        if lengths.is_empty() || lengths.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::InvalidSupportedLengths);
        }
        if memory != MemoryImplementationProfile::ScalableTagChecks {
            return Err(Error::UnsupportedImplementationProfile);
        }
        Ok(Self {
            source_atomicity: SourceAtomicity::Unspecified,
            lengths: lengths.into(),
            memory,
        })
    }
    /// Declare the source CPU's ImpDefInt atomic granule as exactly 16 bytes.
    /// Host NATIVE_ACCESS capability does not establish this architectural fact.
    pub fn declared_sca16(
        lengths: &[VectorLength],
        memory: MemoryImplementationProfile,
    ) -> Result<Self, Error> {
        let mut implementation = Self::declared(lengths, memory)?;
        implementation.source_atomicity = SourceAtomicity::FixedSca16;
        Ok(implementation)
    }

    fn maximum(&self) -> VectorLength {
        *self.lengths.last().expect("nonempty checked support")
    }
    fn select(&self, smcr: u64) -> VectorLength {
        let requested = ((smcr & SMCR_LEN_MASK) as usize + 1) * VECTOR_GRANULE_BYTES;
        self.lengths
            .iter()
            .rev()
            .copied()
            .find(|length| length.bytes() <= requested)
            .unwrap_or(self.lengths[0])
    }
}

/// The source's architectural atomicity, declared independently of host access
/// sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceAtomicity {
    Unspecified,
    FixedSca16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessTrap {
    pub pc: GuestAddress,
    pub target: ExceptionLevel,
    pub exception_class: u8,
    pub iss: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Identification(identification_snapshot::Unsupported),
    IdField {
        register: IdRegister,
        name: &'static str,
        value: u8,
    },
    IncoherentIdentification(&'static str),
    UnsupportedControlConsumer(&'static str),
    InvalidSupportedLengths,
    UnsupportedImplementationProfile,
    CapturedImplementationUnavailable,
    IllegalExecutionState,
    SingleStepUnavailable,
    Undefined,
    MissingSme,
    MissingNonStreamingLengthControl,
    UnsupportedStreamingSpecialization {
        pc: GuestAddress,
    },
    UnqualifiedSource {
        pc: GuestAddress,
    },
    MissingInstructionFeature {
        pc: GuestAddress,
    },
    Trap(AccessTrap),
    /// Admission decline only. A later source instruction has not executed its
    /// prefix; the caller must not deliver this as an already reached fault.
    PreflightTrap(AccessTrap),
    SpecializationMismatch,
    StateLengthMismatch,
    StateFeatureMismatch,
    InitialRazReadback,
    LengthChangeUnavailable,
    GenerationExhausted,
}

/// Facts valid inside `with_checked_execution`'s borrow.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveContext {
    source_atomicity: SourceAtomicity,
    length: VectorLength,
    mode: ScalableMode,
    features: ScalableFeatures,
    zt0_enabled: bool,
    implementation: MemoryImplementationProfile,
}
impl EffectiveContext {
    pub const fn source_atomicity(self) -> SourceAtomicity {
        self.source_atomicity
    }
    pub const fn vector_length(self) -> VectorLength {
        self.length
    }
    pub const fn mode(self) -> ScalableMode {
        self.mode
    }
    pub const fn features(self) -> ScalableFeatures {
        self.features
    }
    pub const fn zt0_enabled(self) -> bool {
        self.zt0_enabled
    }
    pub const fn implementation_profile(self) -> MemoryImplementationProfile {
        self.implementation
    }
}

pub struct ScalableControlOwner<'id> {
    fp: FpControlOwner<'id>,
    smcr_el1: u64,
    implementation: Implementation,
    generation: u64,
}
impl<'id> ScalableControlOwner<'id> {
    pub fn new_declared_el10(
        ids: &'id Snapshot,
        readbacks: Readbacks,
        implementation: Implementation,
    ) -> Result<Self, Error> {
        let fp = FpControlOwner::new_declared_scalable_el10(ids, readbacks.cpacr_el1)?;
        if features::sme(ids)? == 0 {
            return Err(Error::MissingSme);
        }
        let _ = features::derive(ids)?;
        if readbacks.smcr_el1 & SMCR_RAZ_WI_MASK != 0 {
            return Err(Error::InitialRazReadback);
        }
        Ok(Self {
            fp,
            smcr_el1: readbacks.smcr_el1,
            implementation,
            generation: 0,
        })
    }
    pub const fn identification_snapshot(&self) -> &Snapshot {
        self.fp.identification_snapshot()
    }
    /// The shared CPACR bank, for AdvSIMD/FP consumers.
    pub const fn fp_controls(&self) -> &FpControlOwner<'id> {
        &self.fp
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn readbacks(&self) -> Readbacks {
        Readbacks {
            cpacr_el1: self.fp.cpacr_el1(),
            smcr_el1: self.smcr_el1,
        }
    }
    pub fn current_svl(&self) -> VectorLength {
        self.implementation.select(self.smcr_el1)
    }

    pub fn read(
        &self,
        register: Register,
        state: &SystemState,
        pc: GuestAddress,
    ) -> Result<u64, Error> {
        self.register_access(register, state, pc)?;
        Ok(match register {
            Register::CpacrEl1 => self.fp.cpacr_el1(),
            Register::SmcrEl1 => self.smcr_el1,
        })
    }

    /// No cached permission survives a write: the next body must re-enter the
    /// checked borrow, and a live borrow holds the whole bank immutably.
    /// Reserved fields are writable with preserved readback; only SMCR[8:4] is
    /// RAZ/WI by specification.
    pub fn prepare_write<'a>(
        &'a mut self,
        register: Register,
        value: u64,
        state: &'a SystemState,
        scalable: &'a ScalableState,
        pc: GuestAddress,
    ) -> Result<PreparedWrite<'a, 'id>, Error> {
        self.register_access(register, state, pc)?;
        let value = match register {
            Register::CpacrEl1 => value,
            Register::SmcrEl1 => value & !SMCR_RAZ_WI_MASK,
        };
        if self.current_svl() != scalable.vector_length() {
            return Err(Error::StateLengthMismatch);
        }
        if register == Register::SmcrEl1 && self.implementation.select(value) != self.current_svl()
        {
            return Err(Error::LengthChangeUnavailable);
        }
        let next = self
            .generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        let next_fp = if register == Register::CpacrEl1 {
            self.fp.next_generation()?
        } else {
            self.fp.generation()
        };
        Ok(PreparedWrite {
            owner: self,
            register,
            value,
            next,
            next_fp,
            _state: state,
            _scalable: scalable,
        })
    }

    fn register_access(
        &self,
        register: Register,
        state: &SystemState,
        pc: GuestAddress,
    ) -> Result<(), Error> {
        check_state(state)?;
        if state.current_el() != ExceptionLevel::El1 {
            return Err(Error::Undefined);
        }
        if register == Register::SmcrEl1
            && disabled(self.fp.cpacr_el1(), SMEN_SHIFT, state.current_el())
        {
            return Err(trap(pc, SME_EC, 0));
        }
        Ok(())
    }

    pub fn with_checked_execution<R>(
        &self,
        requirements: &ScalableExecutionRequirements,
        specialization: ScalableProfile,
        state: &SystemState,
        registers: &mut GuestState,
        scalable: &mut ScalableState,
        operation: impl FnOnce(EffectiveContext, &mut GuestState, &mut ScalableState) -> R,
    ) -> Result<R, Error> {
        let effective =
            self.check_execution(requirements, specialization, state, registers, scalable)?;
        Ok(operation(effective, registers, scalable))
    }

    fn check_execution(
        &self,
        requirements: &ScalableExecutionRequirements,
        specialization: ScalableProfile,
        state: &SystemState,
        registers: &GuestState,
        scalable: &ScalableState,
    ) -> Result<EffectiveContext, Error> {
        check_state(state)?;
        if state.pstate_misc() & PSTATE_SS_MASK != 0 {
            return Err(Error::SingleStepUnavailable);
        }
        let available = features::derive(self.fp.identification_snapshot())?;
        // Source-specialization prerequisites are admission conditions, not an
        // architectural CheckStreamingSVEEnabled trap on an unproven branch.
        // Check every prerequisite before evaluating any helper sequence.
        for instruction in requirements.instructions() {
            if matches!(
                instruction.access(),
                ScalableAccessRequirements::StreamingSmeSpecialization(_)
            ) && !(available.contains(ScalableFeature::Sme) && scalable.mode().streaming())
            {
                return Err(Error::UnsupportedStreamingSpecialization {
                    pc: instruction.pc(),
                });
            }
        }
        for instruction in requirements.instructions() {
            if !instruction
                .feature_clauses()
                .iter()
                .all(|clause| clause.is_satisfied_by(available))
            {
                return Err(Error::MissingInstructionFeature {
                    pc: instruction.pc(),
                });
            }
            let checks = match instruction.access() {
                ScalableAccessRequirements::Known(checks)
                | ScalableAccessRequirements::StreamingSmeSpecialization(checks) => checks,
                ScalableAccessRequirements::Unqualified => {
                    return Err(Error::UnqualifiedSource {
                        pc: instruction.pc(),
                    });
                }
            };
            for &check in checks {
                self.check_helper(check, state, scalable.mode(), instruction.pc())
                    .map_err(|error| match error {
                        Error::Trap(trap) => Error::PreflightTrap(trap),
                        other => other,
                    })?;
            }
        }
        let length = self.current_svl();
        if scalable.vector_length() != length {
            return Err(Error::StateLengthMismatch);
        }
        let zt0 = features::sme(self.fp.identification_snapshot())? == 2
            && self.smcr_el1 & SMCR_EZT0_MASK != 0;
        // CPU support and EZT0 do not prove that this state has ZT0 storage.
        if zt0 && scalable.mode().za_enabled() && !scalable.has_zt0_storage() {
            return Err(Error::StateFeatureMismatch);
        }
        if specialization.vector_length() != length
            || specialization.mode() != scalable.mode()
            || specialization.features() != available
            || specialization.controls().max_vector_length() != self.implementation.maximum()
            || specialization.controls().zt0_enabled() != zt0
            || specialization
                .required_dit()
                .is_some_and(|dit| dit != (state.pstate(registers) & DIT_MASK != 0))
        {
            return Err(Error::SpecializationMismatch);
        }
        Ok(EffectiveContext {
            source_atomicity: self.implementation.source_atomicity,
            length,
            mode: scalable.mode(),
            features: available,
            zt0_enabled: zt0,
            implementation: self.implementation.memory,
        })
    }

    fn check_helper(
        &self,
        check: Check,
        state: &SystemState,
        mode: ScalableMode,
        pc: GuestAddress,
    ) -> Result<(), Error> {
        let el = state.current_el();
        match check {
            Check::SmeEnabled => self.check_sme(el, pc),
            Check::StreamingSveEnabled => {
                self.check_sme(el, pc)?;
                if !mode.streaming() {
                    return Err(trap(pc, SME_EC, 2));
                }
                Ok(())
            }
            Check::SmeAndZaEnabled => {
                self.check_sme(el, pc)?;
                if !mode.za_enabled() {
                    return Err(trap(pc, SME_EC, 3));
                }
                Ok(())
            }
            Check::StreamingSveAndZaEnabled => {
                self.check_helper(Check::StreamingSveEnabled, state, mode, pc)?;
                if !mode.za_enabled() {
                    return Err(trap(pc, SME_EC, 3));
                }
                Ok(())
            }
            Check::SmeZt0Enabled => {
                if !mode.za_enabled() {
                    return Err(trap(pc, SME_EC, 3));
                }
                if features::sme(self.fp.identification_snapshot())? != 2 {
                    return Err(Error::StateFeatureMismatch);
                }
                if self.smcr_el1 & SMCR_EZT0_MASK == 0 {
                    return Err(trap(pc, SME_EC, 4));
                }
                Ok(())
            }
            Check::SveEnabled => {
                if mode.streaming() {
                    return self.check_sme(el, pc);
                }
                if !features::sve(self.fp.identification_snapshot())? {
                    return self.check_helper(Check::StreamingSveEnabled, state, mode, pc);
                }
                if disabled(self.fp.cpacr_el1(), ZEN_SHIFT, el) {
                    return Err(trap(pc, SVE_EC, 0));
                }
                self.check_fp(el, pc)?;
                Err(Error::MissingNonStreamingLengthControl)
            }
            Check::NonStreamingSveEnabled => {
                self.check_helper(Check::SveEnabled, state, mode, pc)?;
                if mode.streaming()
                    && !(features::derive(self.fp.identification_snapshot())?
                        .contains(ScalableFeature::SmeFa64)
                        && self.smcr_el1 & SMCR_FA64_MASK != 0)
                {
                    return Err(trap(pc, SME_EC, 1));
                }
                Ok(())
            }
        }
    }
    fn check_sme(&self, el: ExceptionLevel, pc: GuestAddress) -> Result<(), Error> {
        if disabled(self.fp.cpacr_el1(), SMEN_SHIFT, el) {
            return Err(trap(pc, SME_EC, 0));
        }
        self.check_fp(el, pc)
    }
    fn check_fp(&self, el: ExceptionLevel, pc: GuestAddress) -> Result<(), Error> {
        self.fp.check_fp_at_el(el, pc)
    }
}

pub struct PreparedWrite<'a, 'id> {
    owner: &'a mut ScalableControlOwner<'id>,
    register: Register,
    value: u64,
    next: u64,
    next_fp: u64,
    _state: &'a SystemState,
    _scalable: &'a ScalableState,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequalificationRequired {
    pub generation: u64,
}
impl PreparedWrite<'_, '_> {
    pub fn commit(self) -> RequalificationRequired {
        match self.register {
            Register::CpacrEl1 => self.owner.fp.commit_prepared(self.value, self.next_fp),
            Register::SmcrEl1 => self.owner.smcr_el1 = self.value,
        }
        self.owner.generation = self.next;
        RequalificationRequired {
            generation: self.next,
        }
    }
}
fn check_state(state: &SystemState) -> Result<(), Error> {
    if state.pstate_misc() & PSTATE_IL_MASK != 0 {
        return Err(Error::IllegalExecutionState);
    }
    if !matches!(
        state.current_el(),
        ExceptionLevel::El0 | ExceptionLevel::El1
    ) {
        return Err(Error::Undefined);
    }
    Ok(())
}
fn disabled(cpacr: u64, shift: u32, el: ExceptionLevel) -> bool {
    match (cpacr >> shift) & ENABLE_MASK {
        0 | 2 => true,
        1 => el == ExceptionLevel::El0,
        3 => false,
        _ => unreachable!("two-bit field"),
    }
}
fn trap(pc: GuestAddress, exception_class: u8, iss: u32) -> Error {
    Error::Trap(AccessTrap {
        pc,
        target: ExceptionLevel::El1,
        exception_class,
        iss,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::state::{El1Registers, PSTATE_EL0T, PSTATE_EL1H};
    use stela_compiler::{TargetCpu, aarch64::scalable::profile::ScalableControls};

    const PC: GuestAddress = GuestAddress(0x1000);
    const FP_ENABLED: u64 = 3 << FPEN_SHIFT;
    const SME_ENABLED: u64 = 3 << SMEN_SHIFT;
    const SVE_ENABLED: u64 = 3 << ZEN_SHIFT;
    const NOP: u32 = 0xd503_201f;
    const RET: u32 = 0xd65f_03c0;

    fn length(bytes: usize) -> VectorLength {
        VectorLength::from_bytes(bytes).unwrap()
    }
    fn ids(sve: bool) -> Snapshot {
        Snapshot::declared(
            "scalable-owner-pure-tests",
            &[
                (IdRegister::IdAa64Pfr0El1, 0x11 | (u64::from(sve) << 32)),
                (IdRegister::IdAa64Pfr1El1, 2 << 24),
                (IdRegister::IdAa64Smfr0El1, 1 << 56),
                (IdRegister::IdAa64Zfr0El1, 0),
                (IdRegister::IdAa64Isar1El1, 0),
                (IdRegister::IdAa64Isar3El1, 0),
                (IdRegister::IdAa64Dfr0El1, 0),
                (IdRegister::IdAa64Mmfr3El1, 0),
                (IdRegister::IdAa64Mmfr4El1, 0),
            ],
        )
        .unwrap()
    }
    fn state(el0: bool, extra: u64) -> SystemState {
        SystemState::new(
            if el0 { PSTATE_EL0T } else { PSTATE_EL1H } | extra,
            0,
            El1Registers::new(0, 0, 0, 0, 0),
        )
        .unwrap()
    }
    fn make_owner(ids: &Snapshot, cpacr: u64, smcr: u64) -> ScalableControlOwner<'_> {
        ScalableControlOwner::new_declared_el10(
            ids,
            Readbacks {
                cpacr_el1: cpacr,
                smcr_el1: smcr,
            },
            Implementation::declared(
                &[length(16), length(32), length(128)],
                MemoryImplementationProfile::ScalableTagChecks,
            )
            .unwrap(),
        )
        .unwrap()
    }
    /// The scalable execution requirements of the context leaf `source`.
    fn execution_requirements(
        source: &[u8],
        profile: ScalableProfile,
    ) -> stela_compiler::aarch64::scalable::execution::ScalableExecutionRequirements {
        use stela_compiler::block::{BlockProfile, CompilationPlan, Features};
        let options = stela_compiler::Options::new(
            BlockProfile::new(Features::LEAF | Features::CONTEXT),
            TargetCpu::Baseline,
        )
        .with_scalable(profile);
        CompilationPlan::new(source, PC, &options)
            .unwrap()
            .execution_requirements()
            .unwrap()
    }

    fn profile(owner: &ScalableControlOwner<'_>, mode: ScalableMode) -> ScalableProfile {
        ScalableProfile::new_with_features(
            owner.current_svl(),
            mode,
            features::derive(owner.identification_snapshot()).unwrap(),
            ScalableControls::new(
                owner.implementation.maximum(),
                owner.readbacks().smcr_el1 & SMCR_EZT0_MASK != 0,
            ),
        )
        .unwrap()
    }

    #[test]
    fn sparse_supported_lengths_select_down_then_up_without_rewriting_len() {
        let support = Implementation::declared(
            &[length(32), length(128)],
            MemoryImplementationProfile::ScalableTagChecks,
        )
        .unwrap();
        for (len, bytes) in [(0, 32), (1, 32), (2, 32), (6, 32), (7, 128), (15, 128)] {
            assert_eq!(support.select(len).bytes(), bytes);
        }
        assert!(matches!(
            Implementation::declared(
                &[length(32), length(16)],
                MemoryImplementationProfile::ScalableTagChecks
            ),
            Err(Error::InvalidSupportedLengths)
        ));
    }

    #[test]
    fn cpacr_all_enable_values_have_source_el_dependent_behavior() {
        for field in 0_u64..4 {
            for el0 in [false, true] {
                let ids = ids(false);
                let owner = make_owner(&ids, (field << SMEN_SHIFT) | FP_ENABLED, 0);
                let result = owner.check_helper(
                    Check::SmeEnabled,
                    &state(el0, 0),
                    ScalableMode::new(false, false),
                    PC,
                );
                assert_eq!(result.is_ok(), field == 3 || (field == 1 && !el0));
            }
        }
    }

    #[test]
    fn source_orders_smen_before_fp_and_zen_before_fp() {
        let ids = ids(true);
        let owner = make_owner(&ids, 0, 0);
        assert_eq!(
            owner.check_helper(
                Check::SmeEnabled,
                &state(false, 0),
                ScalableMode::new(false, false),
                PC
            ),
            Err(trap(PC, SME_EC, 0))
        );
        assert_eq!(
            owner.check_helper(
                Check::SveEnabled,
                &state(false, 0),
                ScalableMode::new(false, false),
                PC
            ),
            Err(trap(PC, SVE_EC, 0))
        );
        let owner = make_owner(&ids, SME_ENABLED | SVE_ENABLED, 0);
        assert_eq!(
            owner.check_helper(
                Check::SmeEnabled,
                &state(false, 0),
                ScalableMode::new(false, false),
                PC
            ),
            Err(trap(PC, FP_EC, A64_FP_ISS))
        );
    }

    #[test]
    fn sme_only_sve_branch_uses_actual_streaming_and_za_is_helper_specific() {
        let ids = ids(false);
        let owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, 0);
        let state = state(false, 0);
        assert_eq!(
            owner.check_helper(
                Check::SveEnabled,
                &state,
                ScalableMode::new(false, false),
                PC
            ),
            Err(trap(PC, SME_EC, 2))
        );
        assert!(
            owner
                .check_helper(
                    Check::SveEnabled,
                    &state,
                    ScalableMode::new(true, false),
                    PC
                )
                .is_ok()
        );
        assert!(
            owner
                .check_helper(
                    Check::SmeAndZaEnabled,
                    &state,
                    ScalableMode::new(false, true),
                    PC
                )
                .is_ok()
        );
        assert_eq!(
            owner.check_helper(
                Check::StreamingSveAndZaEnabled,
                &state,
                ScalableMode::new(false, true),
                PC
            ),
            Err(trap(PC, SME_EC, 2))
        );
        assert_eq!(
            owner.check_helper(
                Check::SmeZt0Enabled,
                &state,
                ScalableMode::new(false, false),
                PC
            ),
            Err(trap(PC, SME_EC, 3))
        );
        assert_eq!(
            owner.check_helper(
                Check::SmeZt0Enabled,
                &state,
                ScalableMode::new(false, true),
                PC
            ),
            Err(trap(PC, SME_EC, 4))
        );
    }

    #[test]
    fn register_access_is_not_general_sme_instruction_access() {
        let ids = ids(false);
        let owner = make_owner(&ids, SME_ENABLED, 0);
        assert_eq!(owner.read(Register::SmcrEl1, &state(false, 0), PC), Ok(0));
        assert_eq!(
            owner.check_helper(
                Check::SmeEnabled,
                &state(false, 0),
                ScalableMode::new(false, false),
                PC
            ),
            Err(trap(PC, FP_EC, A64_FP_ISS))
        );
        assert_eq!(
            owner.read(Register::CpacrEl1, &state(true, 0), PC),
            Err(Error::Undefined)
        );
        let owner = make_owner(&ids, 0, 0);
        assert_eq!(owner.read(Register::CpacrEl1, &state(false, 0), PC), Ok(0));
        assert_eq!(
            owner.read(Register::SmcrEl1, &state(false, 0), PC),
            Err(trap(PC, SME_EC, 0))
        );
    }

    #[test]
    fn smcr_writes_ignore_only_raz_fields_and_decline_actual_length_changes() {
        let ids = ids(false);
        let mut owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, 0);
        let state = state(false, 0);
        let scalable = ScalableState::new(length(16), true);
        let value = (1u64 << 63) | SMCR_RAZ_WI_MASK | SMCR_EZT0_MASK;
        owner
            .prepare_write(Register::SmcrEl1, value, &state, &scalable, PC)
            .unwrap()
            .commit();
        assert_eq!(owner.readbacks().smcr_el1, value & !SMCR_RAZ_WI_MASK);
        let before = owner.readbacks();
        assert!(matches!(
            owner.prepare_write(Register::SmcrEl1, 1, &state, &scalable, PC),
            Err(Error::LengthChangeUnavailable)
        ));
        assert_eq!(owner.readbacks(), before);
        assert_eq!(owner.generation(), 1);
    }

    #[test]
    fn sole_cpacr_bank_is_shared_with_fp_and_smcr_keeps_its_generation() {
        let ids = ids(false);
        let mut owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, 0);
        assert!(std::ptr::eq(
            owner.identification_snapshot(),
            owner.fp_controls().identification_snapshot()
        ));
        let el1 = state(false, 0);
        let el0 = state(true, 0);
        let scalable = ScalableState::new(length(16), true);
        assert_eq!(owner.fp_controls().check_fp_enabled(&el0, PC), Ok(()));
        let value = (1 << FPEN_SHIFT) | SME_ENABLED;
        owner
            .prepare_write(Register::CpacrEl1, value, &el1, &scalable, PC)
            .unwrap()
            .commit();
        assert_eq!(owner.readbacks().cpacr_el1, value);
        assert_eq!(owner.fp_controls().cpacr_el1(), value);
        assert_eq!(
            owner.fp_controls().check_fp_enabled(&el0, PC),
            Err(trap(PC, FP_EC, A64_FP_ISS))
        );
        assert_eq!(
            owner.check_fp(el0.current_el(), PC),
            Err(trap(PC, FP_EC, A64_FP_ISS))
        );
        assert_eq!(owner.generation(), 1);
        assert_eq!(owner.fp_controls().generation(), 1);
        owner
            .prepare_write(Register::SmcrEl1, 0, &el1, &scalable, PC)
            .unwrap()
            .commit();
        assert_eq!(owner.generation(), 2);
        assert_eq!(owner.fp_controls().generation(), 1);
        assert_eq!(owner.readbacks().cpacr_el1, value);
    }

    #[test]
    fn actual_il_declines_register_effects_and_checked_callback() {
        let ids = ids(false);
        let mut owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, 0);
        let state = state(false, PSTATE_IL_MASK);
        let mut scalable = ScalableState::new(length(16), true);
        let mut registers = GuestState::default();
        let profile = profile(&owner, scalable.mode());
        let source: Vec<u8> = [NOP, RET].into_iter().flat_map(u32::to_le_bytes).collect();
        let requirements = execution_requirements(&source, profile);
        let mut called = false;
        let result = owner.with_checked_execution(
            &requirements,
            profile,
            &state,
            &mut registers,
            &mut scalable,
            |_, _, _| called = true,
        );
        assert_eq!(result, Err(Error::IllegalExecutionState));
        assert!(!called);
        assert_eq!(
            owner.read(Register::CpacrEl1, &state, PC),
            Err(Error::IllegalExecutionState)
        );
        assert!(matches!(
            owner.prepare_write(Register::CpacrEl1, 0, &state, &scalable, PC),
            Err(Error::IllegalExecutionState)
        ));
        assert_eq!(owner.generation(), 0);
    }

    #[test]
    fn checked_callback_uses_same_actual_state_and_named_implementation() {
        let ids = ids(false);
        let owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, 0);
        let state = state(false, 0);
        let mut scalable = ScalableState::new(length(16), true);
        let mut registers = GuestState::default();
        scalable
            .apply_mode(&mut registers, ScalableMode::new(true, false))
            .unwrap();
        let profile = profile(&owner, scalable.mode());
        let source: Vec<u8> = [NOP, RET].into_iter().flat_map(u32::to_le_bytes).collect();
        let requirements = execution_requirements(&source, profile);
        owner
            .with_checked_execution(
                &requirements,
                profile,
                &state,
                &mut registers,
                &mut scalable,
                |effective, registers, scalable| {
                    assert_eq!(
                        effective.implementation_profile(),
                        MemoryImplementationProfile::ScalableTagChecks
                    );
                    assert_eq!(effective.mode(), scalable.mode());
                    assert_eq!(effective.vector_length(), scalable.vector_length());
                    registers.x[3] = 0x1234;
                },
            )
            .unwrap();
        assert_eq!(registers.x[3], 0x1234);
    }

    #[test]
    fn cpu_zt0_presence_does_not_prove_supplied_state_storage() {
        let ids = ids(false);
        let owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, SMCR_EZT0_MASK);
        let state = state(false, 0);
        let mut scalable = ScalableState::new(length(16), false);
        let mut registers = GuestState::default();
        scalable
            .apply_mode(&mut registers, ScalableMode::new(true, true))
            .unwrap();
        let profile = profile(&owner, scalable.mode());
        let source: Vec<u8> = [NOP, RET].into_iter().flat_map(u32::to_le_bytes).collect();
        let requirements = execution_requirements(&source, profile);
        let mut called = false;
        assert_eq!(
            owner.with_checked_execution(
                &requirements,
                profile,
                &state,
                &mut registers,
                &mut scalable,
                |_, _, _| called = true
            ),
            Err(Error::StateFeatureMismatch)
        );
        assert!(!called);
        let mut supported = ScalableState::new(length(16), true);
        supported
            .apply_mode(&mut registers, ScalableMode::new(true, true))
            .unwrap();
        owner
            .with_checked_execution(
                &requirements,
                profile,
                &state,
                &mut registers,
                &mut supported,
                |_, _, _| called = true,
            )
            .unwrap();
        assert!(called);
    }

    #[test]
    fn source_atomicity_requires_its_explicit_cpu_declaration() {
        let unspecified = Implementation::declared(
            &[length(16)],
            MemoryImplementationProfile::ScalableTagChecks,
        )
        .unwrap();
        assert_eq!(unspecified.source_atomicity, SourceAtomicity::Unspecified);
        let explicit = Implementation::declared_sca16(
            &[length(16)],
            MemoryImplementationProfile::ScalableTagChecks,
        )
        .unwrap();
        assert_eq!(explicit.source_atomicity, SourceAtomicity::FixedSca16);
        let ids = ids(false);
        let owner = ScalableControlOwner::new_declared_el10(
            &ids,
            Readbacks {
                cpacr_el1: FP_ENABLED | SME_ENABLED,
                smcr_el1: 0,
            },
            explicit,
        )
        .unwrap();
        let state = state(false, 0);
        let mut registers = GuestState::default();
        let mut scalable = ScalableState::new(length(16), true);
        let profile = profile(&owner, scalable.mode());
        let source: Vec<u8> = [NOP, RET].into_iter().flat_map(u32::to_le_bytes).collect();
        let requirements = execution_requirements(&source, profile);
        assert_eq!(
            owner.with_checked_execution(
                &requirements,
                profile,
                &state,
                &mut registers,
                &mut scalable,
                |effective, _, _| effective.source_atomicity()
            ),
            Ok(SourceAtomicity::FixedSca16)
        );
    }
}
