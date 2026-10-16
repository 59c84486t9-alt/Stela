//! Ordered base A64 NS EL0/EL1 exception effects.
//!
//! Plans are source-state checked before any service call. Service failures
//! expose the committed prefix; callers must not roll back memory or retry the
//! whole instruction. The caller establishes fetch/decode and synchronous fault
//! priority before constructing an event. Fetching the returned PC is subsequent.

pub(crate) mod higher_el;

use super::access::{ExceptionLevel, Profile, Request, SecurityState};
use super::debug::DebugControls;
use super::profile::{EntryProfile, EntryProfileError};
use super::pstate::{DAIF_MASK, NZCV_MASK};
use super::state::{
    El1Registers, PSTATE_EL0T, PSTATE_EL1H, PSTATE_EL1T, PSTATE_IL_MASK, PSTATE_MODE_MASK,
    PSTATE_SS_MASK, StackBank, StateError, SystemState,
};
use stela_compiler::GuestState;

const A64_INSTRUCTION_BYTES: u64 = 4;
const ESR_INSTRUCTION_LENGTH: u64 = 1 << 25;
const ESR_EXCEPTION_CLASS_SHIFT: u32 = 26;
const SVC_EXCEPTION_CLASS: u64 = 0x15;
const SOFTWARE_BREAKPOINT_EXCEPTION_CLASS: u64 = 0x3c;
const VECTOR_ALIGNMENT_MASK: u64 = 0x7ff;
const VECTOR_LOWER_EL_A64: u64 = 0x400;
const VECTOR_CURRENT_EL_SPX: u64 = 0x200;
const VECTOR_IRQ: u64 = 0x80;
const PSTATE_IRQ_MASK: u64 = 1 << 7;
const RETURN_PSTATE_MASK: u64 = NZCV_MASK | DAIF_MASK | PSTATE_IL_MASK | PSTATE_MODE_MASK;
const MAX_REGISTER_OPERAND: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryEvent {
    Undefined {
        instruction_pc: u64,
    },
    SupervisorCall {
        instruction_pc: u64,
        immediate: u16,
    },
    /// A64 BRK is a software breakpoint, independent of MDSCR monitor enable.
    /// Its preferred return is the BRK address, unlike SVC's next address.
    SoftwareBreakpoint {
        instruction_pc: u64,
        immediate: u16,
    },
    SystemAccess {
        instruction_pc: u64,
        request: Request,
    },
    /// The controller has presented an actual physical IRQ at an architectural
    /// boundary. Entry does not acknowledge or deassert that interrupt source.
    Irq {
        next_pc: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryControls {
    pub tcr_el1: u64,
    pub mdscr_el1: u64,
    pub debug: DebugControls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareError {
    Controls(EntryProfileError),
    UnsupportedScope,
    CurrentElMismatch,
    UnsupportedDebugState,
    UnsupportedIllegalExecutionState,
    UnsupportedMteState,
    InvalidRegisterOperand,
    MaskedIrq,
    ReturnAtEl0,
    UnsupportedSavedMode(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredEffects {
    Entry { irq: bool },
    Return,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRequest {
    pub effects: RequiredEffects,
    pub profile: Profile,
    pub source_el: ExceptionLevel,
    pub source_pstate: u64,
    pub source_pc: u64,
    pub controls: EntryControls,
}

/// A failing owner reports whether its own requested effect took place.
/// Unknown completion is not permission to retry an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    None,
    Partial,
    Complete,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectFailure<E> {
    pub error: E,
    pub completion: Completion,
}

/// Authoritative runtime effects, not architectural storage substitutes.
///
/// Preflight may reserve resources but must not change guest architectural
/// state, synchronization state, the exclusive monitor, or the local event.
/// Verify the requested scope/profile and controls against the current authoritative context.
/// Verify source_pc against the runtime PC and immutable original source extent.
/// IRQ preflight additionally verifies a real pending physical IRQ at the
/// precise architectural boundary; it must not acknowledge the controller.
/// A permit is consumed by one execution and may release reservations on drop.
/// Successful callbacks certify their complete effect. Implementations must not
/// supply successful no-ops for unavailable services.
pub trait ExceptionServices {
    type Permit;
    type Error;

    fn preflight(&mut self, request: ServiceRequest) -> Result<Self::Permit, Self::Error>;
    fn synchronize_context(
        &mut self,
        permit: &mut Self::Permit,
        source_el: ExceptionLevel,
    ) -> Result<(), EffectFailure<Self::Error>>;
    fn clear_exclusive_local(
        &mut self,
        permit: &mut Self::Permit,
    ) -> Result<(), EffectFailure<Self::Error>>;
    fn send_event_local(
        &mut self,
        permit: &mut Self::Permit,
    ) -> Result<(), EffectFailure<Self::Error>>;
    /// Apply architectural BranchAddr with the destination's actual address
    /// controls. This is not a target fetch or permission/alignment probe.
    fn branch_address(
        &mut self,
        permit: &mut Self::Permit,
        target: u64,
        destination_el: ExceptionLevel,
    ) -> Result<u64, EffectFailure<Self::Error>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectStage {
    Synchronize,
    ClearExclusive,
    SendEvent,
    BranchAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommittedPrefix {
    None,
    Synchronized,
    RestoredPstate,
    ClearedExclusive,
    SetLocalEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecuteError<E> {
    StalePlan,
    Preflight(E),
    State {
        error: StateError,
        committed: CommittedPrefix,
    },
    Effect {
        stage: EffectStage,
        committed: CommittedPrefix,
        failure: EffectFailure<E>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceState {
    pstate: u64,
    sp_el0: u64,
    sp_el1: u64,
    el1: El1Registers,
    mte: bool,
}

impl SourceState {
    fn capture(system: &SystemState, registers: &GuestState) -> Self {
        Self {
            pstate: system.pstate(registers),
            sp_el0: system.stack_pointer(StackBank::El0, registers),
            sp_el1: system.stack_pointer(StackBank::El1, registers),
            el1: *system.el1_registers(),
            mte: system.mte().is_some(),
        }
    }

    fn matches(self, system: &SystemState, registers: &GuestState) -> bool {
        self == Self::capture(system, registers)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EntryPlan {
    profile: Profile,
    source_pc: u64,
    controls: EntryControls,
    irq: bool,
    source: SourceState,
    source_el: ExceptionLevel,
    target: u64,
    preferred_pc: u64,
    esr: Option<u64>,
    destination_pstate: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReturnPlan {
    profile: Profile,
    source_pc: u64,
    controls: EntryControls,
    source: SourceState,
    target: u64,
    destination_pstate: u64,
    destination_el: ExceptionLevel,
}

fn validate_source(
    features: &EntryProfile,
    profile: Profile,
    controls: EntryControls,
    system: &SystemState,
    registers: &GuestState,
) -> Result<SourceState, PrepareError> {
    system
        .check_lower_el_storage()
        .map_err(|_| PrepareError::UnsupportedScope)?;
    if profile.security != SecurityState::NonSecure
        || profile.el2_enabled
        || profile.el3_present
        || !matches!(
            profile.current_el,
            ExceptionLevel::El0 | ExceptionLevel::El1
        )
    {
        return Err(PrepareError::UnsupportedScope);
    }
    if profile.current_el != system.current_el() {
        return Err(PrepareError::CurrentElMismatch);
    }
    features
        .check_controls(controls.tcr_el1, controls.mdscr_el1)
        .map_err(PrepareError::Controls)?;
    if controls.debug.halted || controls.debug.halting_allowed {
        return Err(PrepareError::UnsupportedDebugState);
    }
    let source = SourceState::capture(system, registers);
    if source.pstate & PSTATE_SS_MASK != 0 {
        return Err(PrepareError::UnsupportedDebugState);
    }
    if source.mte {
        return Err(PrepareError::UnsupportedMteState);
    }
    Ok(source)
}

pub fn prepare_entry(
    features: &EntryProfile,
    profile: Profile,
    controls: EntryControls,
    system: &SystemState,
    registers: &GuestState,
    event: EntryEvent,
) -> Result<EntryPlan, PrepareError> {
    let source = validate_source(features, profile, controls, system, registers)?;
    if source.pstate & PSTATE_IL_MASK != 0 && !matches!(event, EntryEvent::Irq { .. }) {
        return Err(PrepareError::UnsupportedIllegalExecutionState);
    }
    let source_mode = source.pstate & PSTATE_MODE_MASK;
    let vector_base = match source_mode {
        PSTATE_EL0T => VECTOR_LOWER_EL_A64,
        PSTATE_EL1T => 0,
        PSTATE_EL1H => VECTOR_CURRENT_EL_SPX,
        _ => unreachable!("SystemState owns checked A64 modes"),
    };
    let (preferred_pc, esr, event_offset) = match event {
        EntryEvent::Undefined { instruction_pc } => {
            (instruction_pc, Some(ESR_INSTRUCTION_LENGTH), 0)
        }
        EntryEvent::SupervisorCall {
            instruction_pc,
            immediate,
        } => (
            instruction_pc.wrapping_add(A64_INSTRUCTION_BYTES),
            Some(
                (SVC_EXCEPTION_CLASS << ESR_EXCEPTION_CLASS_SHIFT)
                    | ESR_INSTRUCTION_LENGTH
                    | u64::from(immediate),
            ),
            0,
        ),
        EntryEvent::SoftwareBreakpoint {
            instruction_pc,
            immediate,
        } => (
            instruction_pc,
            Some(
                (SOFTWARE_BREAKPOINT_EXCEPTION_CLASS << ESR_EXCEPTION_CLASS_SHIFT)
                    | ESR_INSTRUCTION_LENGTH
                    | u64::from(immediate),
            ),
            0,
        ),
        EntryEvent::SystemAccess {
            instruction_pc,
            request,
        } => {
            if request.rt > MAX_REGISTER_OPERAND {
                return Err(PrepareError::InvalidRegisterOperand);
            }
            (
                instruction_pc,
                Some(u64::from(request.system_access_esr())),
                0,
            )
        }
        EntryEvent::Irq { next_pc } => {
            if source.pstate & PSTATE_IRQ_MASK != 0 {
                return Err(PrepareError::MaskedIrq);
            }
            (next_pc, None, VECTOR_IRQ)
        }
    };
    let source_pc = match event {
        EntryEvent::Undefined { instruction_pc }
        | EntryEvent::SupervisorCall { instruction_pc, .. }
        | EntryEvent::SoftwareBreakpoint { instruction_pc, .. }
        | EntryEvent::SystemAccess { instruction_pc, .. } => instruction_pc,
        EntryEvent::Irq { next_pc } => next_pc,
    };
    Ok(EntryPlan {
        profile,
        source_pc,
        controls,
        irq: matches!(event, EntryEvent::Irq { .. }),
        source,
        source_el: profile.current_el,
        target: (source.el1.vbar() & !VECTOR_ALIGNMENT_MASK)
            .wrapping_add(vector_base + event_offset),
        preferred_pc,
        esr,
        destination_pstate: (source.pstate & NZCV_MASK) | PSTATE_EL1H | DAIF_MASK,
    })
}

pub fn prepare_return(
    instruction_pc: u64,
    features: &EntryProfile,
    profile: Profile,
    controls: EntryControls,
    system: &SystemState,
    registers: &GuestState,
) -> Result<ReturnPlan, PrepareError> {
    let source = validate_source(features, profile, controls, system, registers)?;
    if profile.current_el != ExceptionLevel::El1 {
        return Err(PrepareError::ReturnAtEl0);
    }
    if source.pstate & PSTATE_IL_MASK != 0 {
        return Err(PrepareError::UnsupportedIllegalExecutionState);
    }
    let saved = source.el1.spsr();
    let mode = saved & PSTATE_MODE_MASK;
    let destination_el = match mode {
        PSTATE_EL0T => ExceptionLevel::El0,
        PSTATE_EL1T | PSTATE_EL1H => ExceptionLevel::El1,
        mode => return Err(PrepareError::UnsupportedSavedMode(mode)),
    };
    Ok(ReturnPlan {
        profile,
        source_pc: instruction_pc,
        controls,
        source,
        target: source.el1.elr(),
        // Absent optional fields are ignored. Debug disabled restores SS=0.
        destination_pstate: saved & RETURN_PSTATE_MASK,
        destination_el,
    })
}

impl EntryPlan {
    pub fn execute<S: ExceptionServices>(
        self,
        system: &mut SystemState,
        registers: &mut GuestState,
        services: &mut S,
    ) -> Result<u64, ExecuteError<S::Error>> {
        if !self.source.matches(system, registers) {
            return Err(ExecuteError::StalePlan);
        }
        let permit = services
            .preflight(self.service_request())
            .map_err(ExecuteError::Preflight)?;
        self.execute_preflighted(system, registers, services, permit)
    }

    /// Describe the source-bound effects before the canonical Retiring phase.
    /// The actual consumer retains the resulting service permit across it.
    pub(crate) fn service_request(&self) -> ServiceRequest {
        ServiceRequest {
            effects: RequiredEffects::Entry { irq: self.irq },
            profile: self.profile,
            source_el: self.source_el,
            source_pstate: self.source.pstate,
            source_pc: self.source_pc,
            controls: self.controls,
        }
    }

    pub(crate) const fn target_address(&self) -> u64 {
        self.target
    }

    pub(crate) const fn target_exception_level(&self) -> ExceptionLevel {
        ExceptionLevel::El1
    }

    /// Consume the original preflight permit. Effects can still fail with an
    /// exact committed prefix; this never grants PC or retry authority.
    pub(crate) fn execute_preflighted<S: ExceptionServices>(
        self,
        system: &mut SystemState,
        registers: &mut GuestState,
        services: &mut S,
        mut permit: S::Permit,
    ) -> Result<u64, ExecuteError<S::Error>> {
        if !self.source.matches(system, registers) {
            return Err(ExecuteError::StalePlan);
        }
        services
            .synchronize_context(&mut permit, self.source_el)
            .map_err(|failure| ExecuteError::Effect {
                stage: EffectStage::Synchronize,
                committed: CommittedPrefix::None,
                failure,
            })?;
        // No callback or failure point splits these checked storage writes.
        system
            .transition_pstate(registers, self.destination_pstate)
            .map_err(|error| ExecuteError::State {
                error,
                committed: CommittedPrefix::Synchronized,
            })?;
        let el1 = system.el1_registers_mut();
        if let Some(esr) = self.esr {
            el1.set_esr(esr);
        }
        // FAR is ARBITRARY for these synchronous events; retain its old value.
        // IRQ bypasses ReportException and preserves both ESR and FAR.
        el1.set_spsr(self.source.pstate);
        el1.set_elr(self.preferred_pc);
        Ok(self.target)
    }
}

impl ReturnPlan {
    pub fn execute<S: ExceptionServices>(
        self,
        system: &mut SystemState,
        registers: &mut GuestState,
        services: &mut S,
    ) -> Result<u64, ExecuteError<S::Error>> {
        if !self.source.matches(system, registers) {
            return Err(ExecuteError::StalePlan);
        }
        let permit = services
            .preflight(self.service_request())
            .map_err(ExecuteError::Preflight)?;
        self.execute_preflighted(system, registers, services, permit)
    }

    /// Describe the source-bound effects before the canonical Retiring phase.
    /// The actual consumer retains the resulting service permit across it.
    pub(crate) fn service_request(&self) -> ServiceRequest {
        ServiceRequest {
            effects: RequiredEffects::Return,
            profile: self.profile,
            source_el: ExceptionLevel::El1,
            source_pstate: self.source.pstate,
            source_pc: self.source_pc,
            controls: self.controls,
        }
    }

    pub(crate) const fn target_address(&self) -> u64 {
        self.target
    }

    pub(crate) const fn target_exception_level(&self) -> ExceptionLevel {
        self.destination_el
    }

    /// Consume the original preflight permit. Effects can still fail with an
    /// exact committed prefix; this never grants PC or retry authority.
    pub(crate) fn execute_preflighted<S: ExceptionServices>(
        self,
        system: &mut SystemState,
        registers: &mut GuestState,
        services: &mut S,
        mut permit: S::Permit,
    ) -> Result<u64, ExecuteError<S::Error>> {
        if !self.source.matches(system, registers) {
            return Err(ExecuteError::StalePlan);
        }
        services
            .synchronize_context(&mut permit, ExceptionLevel::El1)
            .map_err(|failure| ExecuteError::Effect {
                stage: EffectStage::Synchronize,
                committed: CommittedPrefix::None,
                failure,
            })?;
        system
            .transition_pstate(registers, self.destination_pstate)
            .map_err(|error| ExecuteError::State {
                error,
                committed: CommittedPrefix::Synchronized,
            })?;
        services
            .clear_exclusive_local(&mut permit)
            .map_err(|failure| ExecuteError::Effect {
                stage: EffectStage::ClearExclusive,
                committed: CommittedPrefix::RestoredPstate,
                failure,
            })?;
        services
            .send_event_local(&mut permit)
            .map_err(|failure| ExecuteError::Effect {
                stage: EffectStage::SendEvent,
                committed: CommittedPrefix::ClearedExclusive,
                failure,
            })?;
        let target = services
            .branch_address(&mut permit, self.target, self.destination_el)
            .map_err(|failure| ExecuteError::Effect {
                stage: EffectStage::BranchAddress,
                committed: CommittedPrefix::SetLocalEvent,
                failure,
            })?;
        // ELR/SPSR become UNKNOWN after ERET. Retention is our explicit policy.
        Ok(target)
    }
}

#[cfg(test)]
mod tests;
