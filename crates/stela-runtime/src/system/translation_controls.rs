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
mod tests;
