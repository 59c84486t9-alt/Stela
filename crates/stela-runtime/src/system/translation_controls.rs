//! The EL1 translation controls of a PE: SCTLR, TCR, TTBR0, TTBR1 and MAIR.
//!
//! Each register is stored once; every change publishes through the memory
//! system. Controls take effect immediately, and an ISB is still a real context
//! synchronization and fetch publication.

mod branch_address;
mod context_sync;
pub(crate) use context_sync::PreparedContextSynchronization;
mod effects;
mod el1_source;
mod event_context;
mod fields;
pub(crate) mod m0_data;
pub use effects::*;
pub use fields::{
    AsidBits, BaseEl1FeatureFacts, Endianness, EvidenceBinding, FieldError, PanFeatures,
    PolicyProvenance, Presence,
};

use alloc::sync::Arc;

use super::{
    access,
    state::{PSTATE_IL_MASK, SystemState},
    translation,
};
use crate::memory::{domain::MemorySystem, stage1};
use stela_compiler::GuestState;

const REGISTER_COUNT: usize = 5;
const ZERO_REGISTER: u8 = 31;
const INSTRUCTION_BYTES: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    SctlrEl1,
    TcrEl1,
    Ttbr0El1,
    Ttbr1El1,
    MairEl1,
}

impl Register {
    pub const ALL: [Self; REGISTER_COUNT] = [
        Self::SctlrEl1,
        Self::TcrEl1,
        Self::Ttbr0El1,
        Self::Ttbr1El1,
        Self::MairEl1,
    ];

    pub const fn index(self) -> usize {
        match self {
            Self::SctlrEl1 => 0,
            Self::TcrEl1 => 1,
            Self::Ttbr0El1 => 2,
            Self::Ttbr1El1 => 3,
            Self::MairEl1 => 4,
        }
    }

    const fn family(self) -> translation::Register {
        match self {
            Self::SctlrEl1 => translation::Register::SctlrEl1,
            Self::TcrEl1 => translation::Register::TcrEl1,
            Self::Ttbr0El1 => translation::Register::Ttbr0El1,
            Self::Ttbr1El1 => translation::Register::Ttbr1El1,
            Self::MairEl1 => translation::Register::MairEl1,
        }
    }
}

/// Architectural or declared initial values; there is no default,
/// unknown-as-zero or firmware inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterValues {
    pub sctlr_el1: u64,
    pub tcr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub mair_el1: u64,
}

impl RegisterValues {
    pub const fn get(self, register: Register) -> u64 {
        match register {
            Register::SctlrEl1 => self.sctlr_el1,
            Register::TcrEl1 => self.tcr_el1,
            Register::Ttbr0El1 => self.ttbr0_el1,
            Register::Ttbr1El1 => self.ttbr1_el1,
            Register::MairEl1 => self.mair_el1,
        }
    }

    fn set(&mut self, register: Register, value: u64) {
        match register {
            Register::SctlrEl1 => self.sctlr_el1 = value,
            Register::TcrEl1 => self.tcr_el1 = value,
            Register::Ttbr0El1 => self.ttbr0_el1 = value,
            Register::Ttbr1El1 => self.ttbr1_el1 = value,
            Register::MairEl1 => self.mair_el1 = value,
        }
    }

    /// Source-filtered consumer inputs, not a second bank or a validated MMU.
    /// Canonical stage1 still derives regional geometry/ASID and access faults.
    pub const fn stage1_controls(self) -> stage1::Controls {
        stage1::Controls {
            sctlr_el1: self.sctlr_el1,
            tcr_el1: self.tcr_el1,
            ttbr0_el1: self.ttbr0_el1,
            ttbr1_el1: self.ttbr1_el1,
            mair_el1: self.mair_el1,
        }
    }
}

/// Immutable source, CPU and regime policy. The field facts and the resolver's
/// CPU witness must describe the same CPU.
pub struct ControlProfile {
    policies: [fields::RegisterPolicy; REGISTER_COUNT],
    cpu: stage1::CpuProfile,
    facts: BaseEl1FeatureFacts,
    provenance: PolicyProvenance,
}

impl ControlProfile {
    pub fn base_el1(
        facts: BaseEl1FeatureFacts,
        provenance: PolicyProvenance,
        cpu: stage1::CpuProfile,
    ) -> Result<Self, FieldError> {
        let expected_asid = match facts.asid_bits {
            AsidBits::Eight => stage1::AsidBits::Bits8,
            AsidBits::Sixteen => stage1::AsidBits::Bits16,
        };
        let pan3 = facts.pan == PanFeatures::Pan3;
        if cpu.pa_max.bits() > 48
            || cpu.asid_bits != expected_asid
            || cpu.pauth != (facts.pauth == Presence::Present)
            || cpu.pan != pan3
            || cpu.pan3 != pan3
        {
            return Err(FieldError::IncoherentCpuProfile(
                "field and canonical resolver CPU facts disagree",
            ));
        }
        let policies = [
            fields::RegisterPolicy::base_el1(Register::SctlrEl1, facts, provenance)?,
            fields::RegisterPolicy::base_el1(Register::TcrEl1, facts, provenance)?,
            fields::RegisterPolicy::base_el1(Register::Ttbr0El1, facts, provenance)?,
            fields::RegisterPolicy::base_el1(Register::Ttbr1El1, facts, provenance)?,
            fields::RegisterPolicy::base_el1(Register::MairEl1, facts, provenance)?,
        ];
        Ok(Self {
            policies,
            cpu,
            facts,
            provenance,
        })
    }

    fn consumers(&self, readbacks: RegisterValues) -> RegisterValues {
        let mut result = readbacks;
        for register in Register::ALL {
            result.set(
                register,
                self.policies[register.index()].effective(readbacks.get(register)),
            );
        }
        result
    }
}

/// A read-only derived snapshot; the owner and control generation are
/// re-checked at every entry.
#[derive(Debug, Clone)]
pub struct ControlSnapshot {
    identity: Arc<()>,
    generation: u64,
    readbacks: RegisterValues,
    consumer_inputs: RegisterValues,
    features: BaseEl1FeatureFacts,
    provenance: PolicyProvenance,
}

impl ControlSnapshot {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn readbacks(&self) -> RegisterValues {
        self.readbacks
    }
    pub const fn consumer_inputs(&self) -> RegisterValues {
        self.consumer_inputs
    }

    pub const fn feature_facts(&self) -> BaseEl1FeatureFacts {
        self.features
    }
    pub const fn policy_provenance(&self) -> PolicyProvenance {
        self.provenance
    }

    pub fn same_pe(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}

/// System-register access for a non-secure AArch64 EL0/EL1 machine without EL2
/// or EL3. The current EL always comes from SystemState.
pub struct TranslationControls {
    identity: Arc<()>,
    memory: Arc<MemorySystem>,
    profile: ControlProfile,
    readbacks: RegisterValues,
    generation: u64,
    poisoned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// The illegal-execution-state exception needs the exception owner; nothing
    /// executed before this refusal.
    IllegalExecutionState,
    Undefined,
    NotOwned,
    WrongMemorySystem,
    StaleSource,
    GenerationExhausted,
    Poisoned,
    Field(FieldError),
    Unavailable(&'static str),
    Fetch(FetchFailure),
    Publication {
        register_committed: bool,
        progress: PublicationProgress,
        reason: &'static str,
    },
}

/// A fetch admitted by the bound controls. Preparation re-validates the word
/// and source generation; a copied source buffer cannot bypass fetch
/// permissions or publication.
pub struct FetchedInstruction {
    snapshot: ControlSnapshot,
    pub(super) source: PhysicalFetch,
}

impl FetchedInstruction {
    pub const fn pc(&self) -> u64 {
        self.source.pc
    }
    pub const fn word(&self) -> u32 {
        self.source.word
    }
    pub const fn source_generation(&self) -> u64 {
        self.source.source_generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// MRS completed; System terminal owner commits the destination and next PC.
    Read { rt: u8, value: u64, next_pc: u64 },
    /// Native execution must return: the next instruction, even an ISB, has to
    /// be fetched under the current controls.
    FetchRequired { pc: u64, control_generation: u64 },
}

impl TranslationControls {
    /// Install the initial policy through the memory and publication owner; a
    /// filled bank alone does not admit the machine.
    pub fn install<S: TranslationServices>(
        readbacks: RegisterValues,
        profile: ControlProfile,
        memory: Arc<MemorySystem>,
        state: &SystemState,
        services: &mut S,
    ) -> Result<Self, ControlError> {
        if !Arc::ptr_eq(&memory, services.memory_system()) {
            return Err(ControlError::WrongMemorySystem);
        }
        for register in Register::ALL {
            profile.policies[register.index()]
                .validate_initial(readbacks.get(register))
                .map_err(ControlError::Field)?;
        }
        let mut owner = Self {
            identity: Arc::new(()),
            memory,
            profile,
            readbacks,
            generation: 0,
            poisoned: false,
        };
        let snapshot = owner.current_snapshot();
        let request = PublicationRequest::Initial {
            snapshot,
            cpu: owner.profile.cpu,
            state,
        };
        let prepared = services
            .prepare(request)
            .map_err(ControlError::Unavailable)?;
        if let Err(error) = prepared.commit() {
            owner.poisoned = true;
            return Err(ControlError::Publication {
                register_committed: false,
                progress: error.progress,
                reason: error.reason,
            });
        }
        Ok(owner)
    }

    pub fn snapshot(&self) -> Result<ControlSnapshot, ControlError> {
        if self.poisoned {
            return Err(ControlError::Poisoned);
        }
        Ok(self.current_snapshot())
    }

    fn current_snapshot(&self) -> ControlSnapshot {
        ControlSnapshot {
            identity: Arc::clone(&self.identity),
            generation: self.generation,
            readbacks: self.readbacks,
            consumer_inputs: self.profile.consumers(self.readbacks),
            features: self.profile.facts,
            provenance: self.profile.provenance,
        }
    }

    /// Fetch through the resolver, backing and source owner, which supplies the
    /// fault details.
    pub fn fetch<S: TranslationServices>(
        &self,
        pc: u64,
        state: &SystemState,
        services: &mut S,
    ) -> Result<FetchedInstruction, ControlError> {
        self.check_services(services)?;
        if pc & (INSTRUCTION_BYTES - 1) != 0 {
            return Err(ControlError::Fetch(FetchFailure::InstructionAlignment {
                raw_pc: pc,
                exception_level: state.current_el(),
            }));
        }
        let snapshot = self.current_snapshot();
        let source = services
            .fetch(&snapshot, &self.profile.cpu, state, pc)
            .map_err(ControlError::Fetch)?;
        if source.pc != pc {
            return Err(ControlError::StaleSource);
        }
        Ok(FetchedInstruction { snapshot, source })
    }

    /// Read after a fetched MRS; the guest destination is not written here.
    pub fn read<S: TranslationServices>(
        &mut self,
        fetched: &FetchedInstruction,
        state: &SystemState,
        services: &mut S,
    ) -> Result<Completion, ControlError> {
        self.prepare_read(fetched, state, services)?.commit()
    }

    /// Reserve the MRS publication before retiring; the value and destination
    /// stay fixed under the bank borrow.
    pub fn prepare_read<'a, S: TranslationServices>(
        &'a mut self,
        fetched: &FetchedInstruction,
        state: &'a SystemState,
        services: &'a mut S,
    ) -> Result<PreparedRead<'a, S::Prepared<'a>>, ControlError> {
        check_execution_state(state)?;
        self.check_services(services)?;
        self.check_site(fetched)?;
        services
            .validate_source(&self.current_snapshot(), fetched.source, state)
            .map_err(ControlError::Unavailable)?;
        let (register, rt) = decode_register(fetched.word(), true)?;
        check_el1_access(state)?;
        let prepared = services
            .prepare(PublicationRequest::Read {
                snapshot: self.current_snapshot(),
                source: fetched.source,
                cpu: self.profile.cpu,
                state,
            })
            .map_err(ControlError::Unavailable)?;
        let completion = Completion::Read {
            rt,
            value: self.readbacks.get(register),
            next_pc: next_pc(fetched.pc())?,
        };
        Ok(PreparedRead {
            owner: self,
            prepared,
            completion,
        })
    }

    /// Preflight without guest effects. Xt is read from GuestState (including
    /// XZR), and nothing can be substituted between this request and the
    /// prepared transaction.
    pub fn prepare_write<'a, S: TranslationServices>(
        &'a mut self,
        fetched: &'a FetchedInstruction,
        state: &'a SystemState,
        registers: &'a GuestState,
        services: &'a mut S,
    ) -> Result<PreparedWrite<'a, S::Prepared<'a>>, ControlError> {
        check_execution_state(state)?;
        self.check_services(services)?;
        self.check_site(fetched)?;
        services
            .validate_source(&self.current_snapshot(), fetched.source, state)
            .map_err(ControlError::Unavailable)?;
        let (register, rt) = decode_register(fetched.word(), false)?;
        check_el1_access(state)?;
        let operand = if rt == ZERO_REGISTER {
            0
        } else {
            registers.x[usize::from(rt)]
        };
        let applied = self.profile.policies[register.index()]
            .apply(self.readbacks.get(register), operand)
            .map_err(ControlError::Field)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(ControlError::GenerationExhausted)?;
        let before = self.current_snapshot();
        let mut after_values = self.readbacks;
        after_values.set(register, applied.readback);
        let after = ControlSnapshot {
            identity: Arc::clone(&self.identity),
            generation,
            readbacks: after_values,
            consumer_inputs: self.profile.consumers(after_values),
            features: self.profile.facts,
            provenance: self.profile.provenance,
        };
        let request = ControlChange {
            before,
            after,
            register,
            operand,
            source: fetched.source,
            next_pc: next_pc(fetched.pc())?,
        };
        let prepared = services
            .prepare(PublicationRequest::Write {
                change: request.clone(),
                cpu: self.profile.cpu,
                state,
                registers,
            })
            .map_err(ControlError::Unavailable)?;
        Ok(PreparedWrite {
            owner: self,
            request,
            prepared,
        })
    }

    pub fn prepare_isb<'a, S: TranslationServices>(
        &'a mut self,
        fetched: &'a FetchedInstruction,
        state: &'a SystemState,
        registers: &'a GuestState,
        services: &'a mut S,
    ) -> Result<PreparedIsb<'a, S::Prepared<'a>>, ControlError> {
        check_execution_state(state)?;
        self.check_services(services)?;
        self.check_site(fetched)?;
        services
            .validate_source(&self.current_snapshot(), fetched.source, state)
            .map_err(ControlError::Unavailable)?;
        let operation = stela_compiler::aarch64::system::synchronization::decode(fetched.word())
            .ok_or(ControlError::NotOwned)?;
        if !matches!(operation,
            stela_compiler::aarch64::system::synchronization::Operation::InstructionSynchronization { .. }) {
            return Err(ControlError::NotOwned);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(ControlError::GenerationExhausted)?;
        let before = self.current_snapshot();
        let mut after = before.clone();
        after.generation = next_generation;
        let prepared = services
            .prepare(PublicationRequest::Isb {
                before,
                after,
                source: fetched.source,
                operation,
                cpu: self.profile.cpu,
                state,
                registers,
            })
            .map_err(ControlError::Unavailable)?;
        Ok(PreparedIsb {
            owner: self,
            prepared,
            next_generation,
            next_pc: next_pc(fetched.pc())?,
        })
    }

    fn check_services<S: TranslationServices>(&self, services: &S) -> Result<(), ControlError> {
        if self.poisoned {
            return Err(ControlError::Poisoned);
        }
        if !Arc::ptr_eq(&self.memory, services.memory_system()) {
            return Err(ControlError::WrongMemorySystem);
        }
        Ok(())
    }

    fn check_site(&self, fetched: &FetchedInstruction) -> Result<(), ControlError> {
        if self.poisoned {
            return Err(ControlError::Poisoned);
        }
        if !Arc::ptr_eq(&self.identity, &fetched.snapshot.identity)
            || self.generation != fetched.snapshot.generation
        {
            return Err(ControlError::StaleSource);
        }
        Ok(())
    }
}

pub struct PreparedRead<'a, P: PreparedPublication> {
    owner: &'a mut TranslationControls,
    prepared: P,
    completion: Completion,
}
impl<P: PreparedPublication> PreparedRead<'_, P> {
    pub fn commit(self) -> Result<Completion, ControlError> {
        let Self {
            owner,
            prepared,
            completion,
        } = self;
        if let Err(error) = prepared.commit() {
            owner.poisoned = true;
            return Err(ControlError::Publication {
                register_committed: false,
                progress: error.progress,
                reason: error.reason,
            });
        }
        Ok(completion)
    }
}

pub struct PreparedWrite<'a, P: PreparedPublication> {
    owner: &'a mut TranslationControls,
    request: ControlChange,
    prepared: P,
}

impl<P: PreparedPublication> PreparedWrite<'_, P> {
    pub fn commit(self) -> Result<Completion, ControlError> {
        let Self {
            owner,
            request,
            prepared,
        } = self;
        // The exclusive owner borrow and real service gates exclude observation
        // of a bank/context mismatch at this linearization point.
        owner.readbacks = request.after.readbacks;
        owner.generation = request.after.generation;
        if let Err(error) = prepared.commit() {
            // Keep the committed architectural register and prior prefix. An
            // internally incomplete publication cannot execute or be retried.
            owner.poisoned = true;
            return Err(ControlError::Publication {
                register_committed: true,
                progress: error.progress,
                reason: error.reason,
            });
        }
        Ok(Completion::FetchRequired {
            pc: request.next_pc,
            control_generation: owner.generation,
        })
    }
}

pub struct PreparedIsb<'a, P: PreparedPublication> {
    owner: &'a mut TranslationControls,
    prepared: P,
    next_generation: u64,
    next_pc: u64,
}

impl<P: PreparedPublication> PreparedIsb<'_, P> {
    pub fn commit(self) -> Result<Completion, ControlError> {
        let Self {
            owner,
            prepared,
            next_generation,
            next_pc,
        } = self;
        if let Err(error) = prepared.commit() {
            owner.poisoned = true;
            return Err(ControlError::Publication {
                register_committed: false,
                progress: error.progress,
                reason: error.reason,
            });
        }
        owner.generation = next_generation;
        Ok(Completion::FetchRequired {
            pc: next_pc,
            control_generation: next_generation,
        })
    }
}

/// Refuse entry when PSTATE.IL is set, for native and interpreted execution
/// alike.
fn check_execution_state(state: &SystemState) -> Result<(), ControlError> {
    state
        .check_lower_el_storage()
        .map_err(|_| ControlError::Unavailable("EL1 controls do not own higher-EL storage"))?;
    if state.pstate_misc() & PSTATE_IL_MASK != 0 {
        Err(ControlError::IllegalExecutionState)
    } else {
        Ok(())
    }
}

fn check_el1_access(state: &SystemState) -> Result<(), ControlError> {
    match state.current_el() {
        access::ExceptionLevel::El0 => Err(ControlError::Undefined),
        access::ExceptionLevel::El1 => Ok(()),
        _ => Err(ControlError::Unavailable("EL2/EL3 control access owner")),
    }
}

fn next_pc(pc: u64) -> Result<u64, ControlError> {
    pc.checked_add(INSTRUCTION_BYTES)
        .ok_or(ControlError::Unavailable("instruction PC overflow"))
}

fn decode_register(word: u32, read: bool) -> Result<(Register, u8), ControlError> {
    const MRS_BASE: u32 = 0xd520_0000;
    const MSR_BASE: u32 = 0xd500_0000;
    const ENCODING_SHIFT: u32 = 5;
    const RT_MASK: u32 = 0b1_1111;

    // The current compiler exports the checked Encoding selector, not a raw
    // register decoder. Match the complete word for this bank's five selectors;
    // direction and every fixed bit stay checked. Rt31 remains XZR, never SP.
    let base = if read { MRS_BASE } else { MSR_BASE };
    let instruction = word & !RT_MASK;
    Register::ALL
        .into_iter()
        .find(|register| {
            base | (u32::from(register.family().encoding().selector()) << ENCODING_SHIFT)
                == instruction
        })
        .map(|register| (register, (word & RT_MASK) as u8))
        .ok_or(ControlError::NotOwned)
}

#[cfg(test)]
mod tests {
    //! Translation-control sequencing against a test effects observer.
    use super::*;
    use crate::system::state::{El1Registers, PSTATE_EL1H};
    use std::{cell::Cell, collections::BTreeMap};

    const PC: u64 = 0x1000;
    const ISB_SY: u32 = 0xd503_3fdf;
    const MSR_SCTLR_X1: u32 = 0xd518_1001;
    const MSR_TCR_X1: u32 = 0xd518_2041;
    const MSR_TTBR1_XZR: u32 = 0xd518_203f;
    const MRS_TTBR1_XZR: u32 = 0xd538_203f;
    const DECLARED_TEST_PROVENANCE: EvidenceBinding = EvidenceBinding {
        id: "synthetic-owner-sequencing-test-not-hardware-evidence",
        sha256: [1; 32],
    };

    fn facts() -> BaseEl1FeatureFacts {
        BaseEl1FeatureFacts {
            pauth: Presence::Present,
            pan: PanFeatures::Pan3,
            ssbs: Presence::Absent,
            exs: Presence::Absent,
            asid_bits: AsidBits::Sixteen,
            endianness: Endianness::LittleOnly,
        }
    }
    fn cpu() -> stage1::CpuProfile {
        stage1::CpuProfile {
            pa_max: stage1::PaBits::Bits40,
            asid_bits: stage1::AsidBits::Bits16,
            granules: stage1::GranuleSupport {
                kib4: true,
                kib16: true,
                kib64: false,
                lower_fallback: stage1::Granule::KiB4,
                upper_fallback: stage1::Granule::KiB16,
            },
            pauth: true,
            pan: true,
            pan3: true,
        }
    }
    fn profile() -> ControlProfile {
        ControlProfile::base_el1(
            facts(),
            PolicyProvenance {
                cpu_features: DECLARED_TEST_PROVENANCE,
                implementation_choices: DECLARED_TEST_PROVENANCE,
            },
            cpu(),
        )
        .unwrap()
    }
    fn state() -> SystemState {
        SystemState::new(PSTATE_EL1H, 0x9876, El1Registers::new(1, 2, 3, 4, 5)).unwrap()
    }
    fn values() -> RegisterValues {
        RegisterValues {
            sctlr_el1: 0,
            tcr_el1: 0,
            ttbr0_el1: 0x2345,
            ttbr1_el1: 0x6789,
            mair_el1: 0xff,
        }
    }

    struct Observer {
        memory: Arc<MemorySystem>,
        installed: Option<ControlSnapshot>,
        words: BTreeMap<u64, u32>,
        source_generation: u64,
        unavailable: bool,
        failure: Option<PublicationFailure>,
        events: Vec<&'static str>,
        fetches: usize,
        poisoned: bool,
        memory_system_calls: Cell<usize>,
        prepare_calls: usize,
        source_validation_calls: usize,
    }
    impl Observer {
        fn new(memory: Arc<MemorySystem>, word: u32) -> Self {
            Self {
                memory,
                installed: None,
                words: BTreeMap::from([(PC, word), (PC + 4, ISB_SY)]),
                source_generation: 1,
                unavailable: false,
                failure: None,
                events: Vec::new(),
                fetches: 0,
                poisoned: false,
                memory_system_calls: Cell::new(0),
                prepare_calls: 0,
                source_validation_calls: 0,
            }
        }
        fn callback_counts(&self) -> (usize, usize, usize, usize) {
            (
                self.memory_system_calls.get(),
                self.prepare_calls,
                self.source_validation_calls,
                self.fetches,
            )
        }
        fn current(&self, snapshot: &ControlSnapshot) -> Result<(), &'static str> {
            if self.poisoned {
                return Err("observer poisoned");
            }
            let installed = self.installed.as_ref().ok_or("no installed context")?;
            if !installed.same_pe(snapshot) || installed.generation() != snapshot.generation() {
                return Err("stale owner generation");
            }
            Ok(())
        }
    }
    struct PreparedObserver<'a> {
        observer: &'a mut Observer,
        after: Option<ControlSnapshot>,
        event: &'static str,
    }
    impl PreparedPublication for PreparedObserver<'_> {
        fn commit(self) -> Result<(), PublicationFailure> {
            if let Some(error) = self.observer.failure.take() {
                self.observer.poisoned = true;
                return Err(error);
            }
            if let Some(after) = self.after {
                self.observer.installed = Some(after);
            }
            self.observer.events.push(self.event);
            Ok(())
        }
    }
    impl TranslationServices for Observer {
        type Prepared<'a> = PreparedObserver<'a>;
        fn memory_system(&self) -> &Arc<MemorySystem> {
            self.memory_system_calls
                .set(self.memory_system_calls.get() + 1);
            &self.memory
        }
        fn prepare<'a>(
            &'a mut self,
            request: PublicationRequest<'a>,
        ) -> Result<Self::Prepared<'a>, &'static str> {
            self.prepare_calls += 1;
            if self.unavailable {
                return Err("effect unavailable");
            }
            let (after, event) = match request {
                PublicationRequest::Initial { snapshot, .. } => (Some(snapshot), "initial"),
                PublicationRequest::Read {
                    snapshot,
                    source,
                    state,
                    ..
                } => {
                    self.validate_source(&snapshot, source, state)?;
                    (None, "read")
                }
                PublicationRequest::Write { change, state, .. } => {
                    self.validate_source(&change.before, change.source, state)?;
                    assert!(change.before.same_pe(&change.after));
                    assert_eq!(change.after.generation(), change.before.generation() + 1);
                    (Some(change.after), "write")
                }
                PublicationRequest::Isb {
                    before,
                    after,
                    source,
                    state,
                    operation,
                    ..
                } => {
                    self.validate_source(&before, source, state)?;
                    assert!(matches!(operation, stela_compiler::aarch64::system::synchronization::Operation::InstructionSynchronization { .. }));
                    assert!(before.same_pe(&after));
                    assert_eq!(after.generation(), before.generation() + 1);
                    assert_eq!(after.readbacks(), before.readbacks());
                    (Some(after), "isb")
                }
            };
            Ok(PreparedObserver {
                observer: self,
                after,
                event,
            })
        }
        fn validate_source(
            &mut self,
            snapshot: &ControlSnapshot,
            source: PhysicalFetch,
            _: &SystemState,
        ) -> Result<(), &'static str> {
            self.source_validation_calls += 1;
            self.current(snapshot)?;
            if source.source_generation != self.source_generation
                || self.words.get(&source.pc) != Some(&source.word)
            {
                return Err("stale physical source");
            }
            Ok(())
        }
        fn fetch(
            &mut self,
            snapshot: &ControlSnapshot,
            _: &stage1::CpuProfile,
            _: &SystemState,
            pc: u64,
        ) -> Result<PhysicalFetch, FetchFailure> {
            self.current(snapshot).map_err(FetchFailure::Unavailable)?;
            self.fetches += 1;
            let word = *self
                .words
                .get(&pc)
                .ok_or(FetchFailure::Unavailable("synthetic unmapped fetch"))?;
            // Observes the current policy; this is not an MMU.
            let physical_address = if snapshot.consumer_inputs().sctlr_el1 & 1 != 0 {
                pc + 0x4000
            } else {
                pc
            };
            Ok(PhysicalFetch {
                pc,
                word,
                physical_address,
                source_generation: self.source_generation,
            })
        }
    }
    fn machine(word: u32) -> (TranslationControls, SystemState, Observer) {
        let memory = MemorySystem::new(16, 8).unwrap();
        let mut observer = Observer::new(Arc::clone(&memory), word);
        let state = state();
        let owner =
            TranslationControls::install(values(), profile(), memory, &state, &mut observer)
                .unwrap();
        (owner, state, observer)
    }

    #[test]
    fn exact_source_register_encodings_preserve_direction_and_rt() {
        let pairs = [
            (Register::SctlrEl1, 0xd518_1000, 0xd538_1000),
            (Register::TcrEl1, 0xd518_2040, 0xd538_2040),
            (Register::Ttbr0El1, 0xd518_2000, 0xd538_2000),
            (Register::Ttbr1El1, 0xd518_2020, 0xd538_2020),
            (Register::MairEl1, 0xd518_a200, 0xd538_a200),
        ];
        for (register, write, read) in pairs {
            for rt in 0..=31 {
                assert_eq!(decode_register(write | rt, false), Ok((register, rt as u8)));
                assert_eq!(decode_register(read | rt, true), Ok((register, rt as u8)));
                assert_eq!(
                    decode_register(write | rt, true),
                    Err(ControlError::NotOwned)
                );
            }
        }
    }

    #[test]
    fn profile_rejects_incoherent_canonical_feature_witness() {
        let mut wrong = cpu();
        wrong.pauth = false;
        assert!(matches!(
            ControlProfile::base_el1(
                facts(),
                PolicyProvenance {
                    cpu_features: DECLARED_TEST_PROVENANCE,
                    implementation_choices: DECLARED_TEST_PROVENANCE,
                },
                wrong
            ),
            Err(FieldError::IncoherentCpuProfile(_))
        ));
    }

    #[test]
    fn dormant_intermediate_write_commits_readback_and_invalidates_old_sites() {
        let (mut owner, state, mut observer) = machine(MSR_TCR_X1);
        let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
        let mut registers = GuestState::default();
        registers.x[1] = u64::MAX;
        let result = owner
            .prepare_write(&fetched, &state, &registers, &mut observer)
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(
            result,
            Completion::FetchRequired {
                pc: PC + 4,
                control_generation: 1
            }
        );
        assert_eq!(owner.snapshot().unwrap().readbacks().tcr_el1, u64::MAX);
        assert_eq!(owner.snapshot().unwrap().readbacks().sctlr_el1, 0);
        assert!(matches!(
            owner.prepare_write(&fetched, &state, &registers, &mut observer),
            Err(ControlError::StaleSource)
        ));
        assert_eq!(observer.events, vec!["initial", "write"]);
    }

    #[test]
    fn unavailable_effect_leaves_the_real_bank_and_generation_unchanged() {
        let (mut owner, state, mut observer) = machine(MSR_SCTLR_X1);
        let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
        let before = owner.snapshot().unwrap().readbacks();
        let mut registers = GuestState::default();
        registers.x[1] = 1;
        observer.unavailable = true;
        assert!(matches!(
            owner.prepare_write(&fetched, &state, &registers, &mut observer),
            Err(ControlError::Unavailable(_))
        ));
        assert_eq!(owner.snapshot().unwrap().readbacks(), before);
        assert_eq!(owner.snapshot().unwrap().generation(), 0);
    }

    #[test]
    fn commit_failure_preserves_register_prefix_and_poison_blocks_reentry() {
        let (mut owner, state, mut observer) = machine(MSR_SCTLR_X1);
        let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
        let mut registers = GuestState::default();
        registers.x[1] = 1;
        observer.failure = Some(PublicationFailure {
            progress: PublicationProgress::CodeDependenciesRetired,
            reason: "injected owner failure",
        });
        assert_eq!(
            owner
                .prepare_write(&fetched, &state, &registers, &mut observer)
                .unwrap()
                .commit(),
            Err(ControlError::Publication {
                register_committed: true,
                progress: PublicationProgress::CodeDependenciesRetired,
                reason: "injected owner failure"
            })
        );
        assert_eq!(owner.readbacks.sctlr_el1, 1);
        assert!(matches!(owner.snapshot(), Err(ControlError::Poisoned)));
        assert!(matches!(
            owner.fetch(PC + 4, &state, &mut observer),
            Err(ControlError::Poisoned)
        ));
    }

    #[test]
    fn post_msr_isb_requires_a_fresh_current_policy_fetch_and_authoritative_after_generation() {
        let (mut owner, state, mut observer) = machine(MSR_SCTLR_X1);
        let write = owner.fetch(PC, &state, &mut observer).unwrap();
        let mut registers = GuestState::default();
        registers.x[1] = 1;
        owner
            .prepare_write(&write, &state, &registers, &mut observer)
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(observer.fetches, 1);
        let isb = owner.fetch(PC + 4, &state, &mut observer).unwrap();
        assert_eq!(isb.source.physical_address, PC + 4 + 0x4000);
        assert_eq!(
            owner
                .prepare_isb(&isb, &state, &registers, &mut observer)
                .unwrap()
                .commit()
                .unwrap(),
            Completion::FetchRequired {
                pc: PC + 8,
                control_generation: 2
            }
        );
        assert_eq!(observer.installed.as_ref().unwrap().generation(), 2);
        assert!(matches!(
            owner.prepare_isb(&isb, &state, &registers, &mut observer),
            Err(ControlError::StaleSource)
        ));
        assert_eq!(observer.events, vec!["initial", "write", "isb"]);
    }

    #[test]
    fn stale_physical_source_is_checked_before_el0_undefined() {
        let (mut owner, _, mut observer) = machine(MRS_TTBR1_XZR);
        let el0 = SystemState::new(0, 0, El1Registers::new(1, 2, 3, 4, 5)).unwrap();
        let fetched = owner.fetch(PC, &el0, &mut observer).unwrap();
        observer.source_generation += 1;
        assert_eq!(
            owner.read(&fetched, &el0, &mut observer),
            Err(ControlError::Unavailable("stale physical source"))
        );
        let fetched = owner.fetch(PC, &el0, &mut observer).unwrap();
        assert_eq!(
            owner.read(&fetched, &el0, &mut observer),
            Err(ControlError::Undefined)
        );
    }

    #[test]
    fn xzr_write_is_zero_and_xzr_read_still_checks_and_obtains_value() {
        let (mut owner, state, mut observer) = machine(MSR_TTBR1_XZR);
        let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
        owner
            .prepare_write(&fetched, &state, &GuestState::default(), &mut observer)
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(owner.snapshot().unwrap().readbacks().ttbr1_el1, 0);
        observer.words.insert(PC, MRS_TTBR1_XZR);
        let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
        assert_eq!(
            owner.read(&fetched, &state, &mut observer),
            Ok(Completion::Read {
                rt: 31,
                value: 0,
                next_pc: PC + 4
            })
        );
        assert_eq!(observer.events.last(), Some(&"read"));
    }

    #[test]
    fn foreign_machine_and_foreign_pe_sources_are_never_admitted() {
        let (owner, state, mut observer) = machine(MSR_TCR_X1);
        let mut foreign = Observer::new(MemorySystem::new(16, 8).unwrap(), MSR_TCR_X1);
        assert!(matches!(
            owner.fetch(PC, &state, &mut foreign),
            Err(ControlError::WrongMemorySystem)
        ));
        let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
        let memory = Arc::clone(&observer.memory);
        let mut second_observer = Observer::new(Arc::clone(&memory), MSR_TCR_X1);
        let mut second =
            TranslationControls::install(values(), profile(), memory, &state, &mut second_observer)
                .unwrap();
        assert!(matches!(
            second.prepare_write(
                &fetched,
                &state,
                &GuestState::default(),
                &mut second_observer
            ),
            Err(ControlError::StaleSource)
        ));
    }

    #[test]
    fn misaligned_fetch_reports_typed_pc_provenance_before_translation() {
        let (owner, state, mut observer) = machine(MSR_TCR_X1);
        assert!(
            matches!(owner.fetch(PC+1,&state,&mut observer),Err(ControlError::Fetch(FetchFailure::InstructionAlignment {raw_pc,exception_level:access::ExceptionLevel::El1})) if raw_pc==PC+1)
        );
        assert_eq!(observer.fetches, 0);
    }

    #[test]
    fn subsequent_fetch_decline_preserves_the_completed_msr() {
        let (mut owner, state, mut observer) = machine(MSR_SCTLR_X1);
        let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
        let mut registers = GuestState::default();
        registers.x[1] = 1;
        owner
            .prepare_write(&fetched, &state, &registers, &mut observer)
            .unwrap()
            .commit()
            .unwrap();
        observer.words.remove(&(PC + 4));
        assert!(matches!(
            owner.fetch(PC + 4, &state, &mut observer),
            Err(ControlError::Fetch(FetchFailure::Unavailable(_)))
        ));
        assert_eq!(owner.snapshot().unwrap().readbacks().sctlr_el1, 1);
        assert_eq!(owner.snapshot().unwrap().generation(), 1);
    }

    #[test]
    fn actual_il_declines_all_control_operations_before_any_service_callback() {
        for word in [MRS_TTBR1_XZR, MSR_SCTLR_X1, ISB_SY] {
            let (mut owner, valid_state, mut observer) = machine(word);
            let fetched = owner.fetch(PC, &valid_state, &mut observer).unwrap();
            let illegal = SystemState::new(
                PSTATE_EL1H | PSTATE_IL_MASK,
                0x9876,
                El1Registers::new(1, 2, 3, 4, 5),
            )
            .unwrap();
            let before_state = illegal.clone();
            let before = owner.snapshot().unwrap();
            let mut registers = GuestState::default();
            registers.x.fill(0x9876_5432_10ab_cdef);
            registers.sp = 0x1234_5678;
            registers.nzcv = 0xa000_0000;
            registers.fpcr = 0x400_0000;
            registers.fpsr = 0x0800_0000;
            registers.v.fill([0xdead_beef, 0xbeef_dead]);
            let before_registers = registers.clone();
            // IL must decline even before source/backend failures can call a hook.
            observer.unavailable = true;
            observer.source_generation += 1;
            let callbacks = observer.callback_counts();
            let events = observer.events.clone();
            match word {
                MRS_TTBR1_XZR => assert_eq!(
                    owner.read(&fetched, &illegal, &mut observer),
                    Err(ControlError::IllegalExecutionState),
                ),
                MSR_SCTLR_X1 => assert!(matches!(
                    owner.prepare_write(&fetched, &illegal, &registers, &mut observer),
                    Err(ControlError::IllegalExecutionState),
                )),
                ISB_SY => assert!(matches!(
                    owner.prepare_isb(&fetched, &illegal, &registers, &mut observer),
                    Err(ControlError::IllegalExecutionState),
                )),
                _ => unreachable!("fixed three-operation test cohort"),
            }
            assert_eq!(observer.callback_counts(), callbacks);
            assert_eq!(observer.events, events);
            assert_eq!(illegal, before_state);
            assert_eq!(registers.x, before_registers.x);
            assert_eq!(registers.sp, before_registers.sp);
            assert_eq!(registers.nzcv, before_registers.nzcv);
            assert_eq!(registers.v, before_registers.v);
            assert_eq!(registers.fpcr, before_registers.fpcr);
            assert_eq!(registers.fpsr, before_registers.fpsr);
            let after = owner.snapshot().unwrap();
            assert_eq!(after.generation(), before.generation());
            assert_eq!(after.readbacks(), before.readbacks());
            assert_eq!(after.consumer_inputs(), before.consumer_inputs());
        }
    }

    #[test]
    fn illegal_state_guard_uses_only_the_actual_owned_il_bit() {
        use crate::system::state::PSTATE_SS_MASK;
        let single_step = SystemState::new(
            PSTATE_EL1H | PSTATE_SS_MASK,
            0x9876,
            El1Registers::new(1, 2, 3, 4, 5),
        )
        .unwrap();
        assert_eq!(check_execution_state(&single_step), Ok(()));
        assert_eq!(check_execution_state(&state()), Ok(()));
        // The service owns stepping and debug eligibility.
    }

    fn branch_machine(tcr_el1: u64, pauth: Presence) -> TranslationControls {
        let memory = MemorySystem::new(16, 8).unwrap();
        let mut observer = Observer::new(Arc::clone(&memory), ISB_SY);
        let mut actual_facts = facts();
        actual_facts.pauth = pauth;
        let mut actual_cpu = cpu();
        actual_cpu.pauth = pauth == Presence::Present;
        let profile = ControlProfile::base_el1(
            actual_facts,
            PolicyProvenance {
                cpu_features: DECLARED_TEST_PROVENANCE,
                implementation_choices: DECLARED_TEST_PROVENANCE,
            },
            actual_cpu,
        )
        .unwrap();
        let mut readbacks = values();
        readbacks.tcr_el1 = tcr_el1;
        TranslationControls::install(readbacks, profile, memory, &state(), &mut observer).unwrap()
    }

    #[test]
    fn branch_address_uses_destination_region_and_instruction_tbid() {
        use super::fields::tcr;
        use crate::system::access::ExceptionLevel;
        const LOWER_TAGGED: u64 = 0xab12_3456_789a_bcde;
        const UPPER_TAGGED: u64 = 0xab92_3456_789a_bcde;
        const LOWER: u64 = 0x0012_3456_789a_bcde;
        const UPPER: u64 = 0xff92_3456_789a_bcde;
        for destination in [ExceptionLevel::El0, ExceptionLevel::El1] {
            for (bits, lower, upper) in [
                (0, LOWER_TAGGED, UPPER_TAGGED),
                (tcr::TBI0, LOWER, UPPER_TAGGED),
                (tcr::TBI1, LOWER_TAGGED, UPPER),
                (tcr::TBI0 | tcr::TBI1, LOWER, UPPER),
                (tcr::TBI0 | tcr::TBI1 | tcr::TBID0, LOWER_TAGGED, UPPER),
                (tcr::TBI0 | tcr::TBI1 | tcr::TBID1, LOWER, UPPER_TAGGED),
            ] {
                let owner = branch_machine(bits, Presence::Present);
                assert_eq!(owner.branch_address(LOWER_TAGGED, destination), Ok(lower));
                assert_eq!(owner.branch_address(UPPER_TAGGED, destination), Ok(upper));
            }
            let owner = branch_machine(
                tcr::TBI0 | tcr::TBI1 | tcr::TBID0 | tcr::TBID1,
                Presence::Absent,
            );
            assert_eq!(owner.branch_address(LOWER_TAGGED, destination), Ok(LOWER));
            assert_eq!(owner.branch_address(UPPER_TAGGED, destination), Ok(UPPER));
        }
    }

    #[test]
    fn branch_address_refuses_unowned_regimes_and_poisoned_controls() {
        use crate::system::access::ExceptionLevel;
        let (mut owner, _, _) = machine(ISB_SY);
        for destination in [ExceptionLevel::El2, ExceptionLevel::El3] {
            assert!(matches!(
                owner.branch_address(PC, destination),
                Err(ControlError::Unavailable(_))
            ));
        }
        owner.poisoned = true;
        assert_eq!(
            owner.branch_address(PC, ExceptionLevel::El1),
            Err(ControlError::Poisoned)
        );
    }
}
