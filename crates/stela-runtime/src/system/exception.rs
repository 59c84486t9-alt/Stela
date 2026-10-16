//! A64 EL0/EL1 exception entry and return.
//!
//! A failed service reports the committed prefix; callers must not roll back
//! memory or retry the instruction.

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

/// Whether PSTATE.I masks IRQs. This says nothing about pending sources and
/// does not deliver or acknowledge an interrupt.
pub(crate) fn irq_masked(system: &SystemState) -> bool {
    system.pstate_misc() & PSTATE_IRQ_MASK != 0
}

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
    /// The interrupt controller presents a physical IRQ at an instruction
    /// boundary. Entry neither acknowledges nor deasserts it.
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

/// Runtime services for exception entry and return.
///
/// Preflight may reserve resources but must not change architectural state,
/// synchronization state, the exclusive monitor or the local event. It checks
/// the scope, profile and controls against the current context, and `source_pc`
/// against the runtime PC and the source extent; IRQ preflight also checks that
/// a physical IRQ is pending at this boundary, without acknowledging it. One
/// execution consumes the reservation, which may release resources on drop. A
/// successful callback means its whole effect happened; unavailable services
/// must not succeed as no-ops.
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
    /// Apply BranchAddr with the destination's address controls. This neither
    /// fetches the target nor checks its permission or alignment.
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

    /// The effects to reserve before retiring.
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

    /// Consume the preflight reservation. Effects can still fail with a known
    /// committed prefix.
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

    /// The effects to reserve before retiring.
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

    /// Consume the preflight reservation. Effects can still fail with a known
    /// committed prefix.
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
        // ELR and SPSR become UNKNOWN after ERET; keeping them is our choice.
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::super::access::{AccessKind, Encoding};
    use super::super::profile::{ScalableEntryAbsence, SystemEntryFeatures};
    use super::*;

    const SP0: u64 = 0x1230;
    const SP1: u64 = 0x4560;
    const FLAGS: u32 = 0xa000_0000;
    const VECTOR_BASE: u64 = 0x8000;
    const SOURCE_PC: u64 = 0x1000;
    const RETURN_PC: u64 = 0x2001;
    const OLD_ESR: u64 = 0x9876;
    const OLD_FAR: u64 = 0x5432;

    fn features() -> EntryProfile {
        EntryProfile::base(
            SystemEntryFeatures::declared_absent(),
            ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
        )
        .unwrap()
    }

    fn controls() -> EntryControls {
        EntryControls {
            tcr_el1: 0,
            mdscr_el1: 0,
            debug: DebugControls::default(),
        }
    }

    fn state(mode: u64) -> (Profile, SystemState, GuestState) {
        let registers = GuestState {
            sp: if mode == PSTATE_EL1H { SP1 } else { SP0 },
            nzcv: FLAGS,
            x: std::array::from_fn(|i| 0x1020_3040_5060_7080u64.wrapping_mul(i as u64 + 1)),
            v: std::array::from_fn(|i| [0x1122_3344_5566_7788u64 ^ i as u64, !i as u64]),
            reserved: 0xa5a5_5a5a,
            fpcr: 0x0240_0000,
            fpsr: 0x0800_009f,
        };
        let system = SystemState::new(
            mode,
            if mode == PSTATE_EL1H { SP0 } else { SP1 },
            El1Registers::new(
                RETURN_PC,
                PSTATE_EL0T,
                OLD_ESR,
                OLD_FAR,
                VECTOR_BASE | 0x123,
            ),
        )
        .unwrap();
        (
            Profile {
                current_el: system.current_el(),
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            system,
            registers,
        )
    }

    #[derive(Debug, Default)]
    struct Services {
        requests: Vec<ServiceRequest>,
        calls: Vec<EffectStage>,
        fail_preflight: bool,
        fail: Option<EffectStage>,
        monitor_cleared: bool,
        event_set: bool,
    }

    impl Services {
        fn call(&mut self, stage: EffectStage) -> Result<(), EffectFailure<&'static str>> {
            self.calls.push(stage);
            if self.fail == Some(stage) {
                Err(EffectFailure {
                    error: "injected",
                    completion: Completion::Partial,
                })
            } else {
                Ok(())
            }
        }
    }

    impl ExceptionServices for Services {
        type Permit = ();
        type Error = &'static str;
        fn preflight(&mut self, request: ServiceRequest) -> Result<(), Self::Error> {
            self.requests.push(request);
            if self.fail_preflight {
                Err("unavailable")
            } else {
                Ok(())
            }
        }
        fn synchronize_context(
            &mut self,
            _: &mut (),
            _: ExceptionLevel,
        ) -> Result<(), EffectFailure<Self::Error>> {
            self.call(EffectStage::Synchronize)
        }
        fn clear_exclusive_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<Self::Error>> {
            self.call(EffectStage::ClearExclusive)?;
            self.monitor_cleared = true;
            Ok(())
        }
        fn send_event_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<Self::Error>> {
            self.call(EffectStage::SendEvent)?;
            self.event_set = true;
            Ok(())
        }
        fn branch_address(
            &mut self,
            _: &mut (),
            target: u64,
            _: ExceptionLevel,
        ) -> Result<u64, EffectFailure<Self::Error>> {
            self.call(EffectStage::BranchAddress)?;
            Ok(target)
        }
    }

    #[test]
    fn every_source_mode_selects_old_stack_vector_and_preserves_other_state() {
        for (mode, offset) in [(PSTATE_EL0T, 0x400), (PSTATE_EL1T, 0), (PSTATE_EL1H, 0x200)] {
            for irq in [false, true] {
                let (profile, mut system, mut registers) = state(mode);
                let mut expected = registers.clone();
                expected.sp = SP1;
                let old_psr = system.pstate(&registers);
                let event = if irq {
                    EntryEvent::Irq { next_pc: SOURCE_PC }
                } else {
                    EntryEvent::Undefined {
                        instruction_pc: SOURCE_PC,
                    }
                };
                let plan =
                    prepare_entry(&features(), profile, controls(), &system, &registers, event)
                        .unwrap();
                let mut services = Services::default();
                let pc = plan
                    .execute(&mut system, &mut registers, &mut services)
                    .unwrap();
                assert_eq!(pc, VECTOR_BASE + offset + if irq { VECTOR_IRQ } else { 0 });
                assert_eq!(registers, expected);
                assert_eq!(system.stack_pointer(StackBank::El0, &registers), SP0);
                assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
                assert_eq!(
                    system.pstate(&registers),
                    u64::from(FLAGS) | DAIF_MASK | PSTATE_EL1H
                );
                assert_eq!(system.el1_registers().spsr(), old_psr);
                assert_eq!(system.el1_registers().elr(), SOURCE_PC);
                assert_eq!(
                    system.el1_registers().esr(),
                    if irq { OLD_ESR } else { 0x0200_0000 }
                );
                assert_eq!(system.el1_registers().far(), OLD_FAR);
                assert_eq!(services.calls, [EffectStage::Synchronize]);
                assert_eq!(services.requests[0].effects, RequiredEffects::Entry { irq });
            }
        }
    }

    #[test]
    fn svc_wraps_pc_and_system_trap_uses_original_selector() {
        let (profile, system, registers) = state(PSTATE_EL0T);
        let svc = prepare_entry(
            &features(),
            profile,
            controls(),
            &system,
            &registers,
            EntryEvent::SupervisorCall {
                instruction_pc: u64::MAX - 3,
                immediate: 0xbeef,
            },
        )
        .unwrap();
        assert_eq!(svc.preferred_pc, 0);
        assert_eq!(svc.esr, Some(0x5600_beef));
        let request = Request::write(Encoding::new(0, 3, 4, 0, 6), 31, 0);
        let trap = prepare_entry(
            &features(),
            profile,
            controls(),
            &system,
            &registers,
            EntryEvent::SystemAccess {
                instruction_pc: SOURCE_PC,
                request,
            },
        )
        .unwrap();
        assert_eq!(trap.preferred_pc, SOURCE_PC);
        assert_eq!(trap.esr, Some(0x620c_d3e0));
        let invalid = Request {
            rt: 32,
            kind: AccessKind::Read,
            ..request
        };
        assert_eq!(
            prepare_entry(
                &features(),
                profile,
                controls(),
                &system,
                &registers,
                EntryEvent::SystemAccess {
                    instruction_pc: SOURCE_PC,
                    request: invalid
                }
            ),
            Err(PrepareError::InvalidRegisterOperand)
        );
    }

    #[test]
    fn unsupported_contexts_and_masked_irq_decline_without_effects() {
        let (profile, mut system, mut registers) = state(PSTATE_EL0T);
        system
            .transition_pstate(&mut registers, PSTATE_IRQ_MASK)
            .unwrap();
        assert_eq!(
            prepare_entry(
                &features(),
                profile,
                controls(),
                &system,
                &registers,
                EntryEvent::Irq { next_pc: SOURCE_PC }
            ),
            Err(PrepareError::MaskedIrq)
        );
        for security in [SecurityState::Secure, SecurityState::Realm] {
            assert_eq!(
                prepare_return(
                    SOURCE_PC,
                    &features(),
                    Profile {
                        security,
                        ..profile
                    },
                    controls(),
                    &system,
                    &registers
                ),
                Err(PrepareError::UnsupportedScope)
            );
        }
        assert_eq!(
            prepare_return(
                SOURCE_PC,
                &features(),
                profile,
                controls(),
                &system,
                &registers
            ),
            Err(PrepareError::ReturnAtEl0)
        );
    }

    #[test]
    fn legal_return_restores_flags_banks_and_il_but_clears_saved_ss() {
        for mode in [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H] {
            let (profile, mut system, mut registers) = state(PSTATE_EL1H);
            let saved = mode | 0x5000_0000 | PSTATE_IL_MASK | PSTATE_SS_MASK | PSTATE_IRQ_MASK;
            system.el1_registers_mut().set_spsr(saved);
            let before = system.el1_registers().to_owned();
            let mut expected = registers.clone();
            expected.sp = if mode == PSTATE_EL1H { SP1 } else { SP0 };
            expected.nzcv = 0x5000_0000;
            let plan = prepare_return(
                SOURCE_PC,
                &features(),
                profile,
                controls(),
                &system,
                &registers,
            )
            .unwrap();
            let mut services = Services::default();
            assert_eq!(
                plan.execute(&mut system, &mut registers, &mut services),
                Ok(RETURN_PC)
            );
            assert_eq!(system.pstate(&registers), saved & !PSTATE_SS_MASK);
            assert_eq!(registers, expected);
            assert_eq!(*system.el1_registers(), before);
            assert_eq!(
                services.calls,
                [
                    EffectStage::Synchronize,
                    EffectStage::ClearExclusive,
                    EffectStage::SendEvent,
                    EffectStage::BranchAddress
                ]
            );
            assert!(services.monitor_cleared && services.event_set);
        }
    }

    #[test]
    fn illegal_saved_modes_are_explicitly_partial_before_mutation() {
        for mode in 0..=PSTATE_MODE_MASK {
            if [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H].contains(&mode) {
                continue;
            }
            let (profile, mut system, registers) = state(PSTATE_EL1H);
            system.el1_registers_mut().set_spsr(mode);
            assert_eq!(
                prepare_return(
                    SOURCE_PC,
                    &features(),
                    profile,
                    controls(),
                    &system,
                    &registers
                ),
                Err(PrepareError::UnsupportedSavedMode(mode))
            );
        }
    }

    #[test]
    fn failed_return_exposes_exact_completed_prefix_without_rollback() {
        let stages = [
            (EffectStage::Synchronize, CommittedPrefix::None),
            (EffectStage::ClearExclusive, CommittedPrefix::RestoredPstate),
            (EffectStage::SendEvent, CommittedPrefix::ClearedExclusive),
            (EffectStage::BranchAddress, CommittedPrefix::SetLocalEvent),
        ];
        for (index, (stage, committed)) in stages.into_iter().enumerate() {
            let (profile, mut system, mut registers) = state(PSTATE_EL1H);
            system
                .el1_registers_mut()
                .set_spsr(PSTATE_EL0T | 0x5000_0000);
            let before = (system.clone(), registers.clone());
            let plan = prepare_return(
                SOURCE_PC,
                &features(),
                profile,
                controls(),
                &system,
                &registers,
            )
            .unwrap();
            let mut services = Services {
                fail: Some(stage),
                ..Services::default()
            };
            assert_eq!(
                plan.execute(&mut system, &mut registers, &mut services),
                Err(ExecuteError::Effect {
                    stage,
                    committed,
                    failure: EffectFailure {
                        error: "injected",
                        completion: Completion::Partial
                    }
                })
            );
            assert_eq!(services.calls.len(), index + 1);
            if stage == EffectStage::Synchronize {
                assert_eq!((system, registers), before);
            } else {
                assert_eq!(system.pstate(&registers), 0x5000_0000);
                assert_eq!(registers.sp, SP0);
                assert_eq!(*system.el1_registers(), *before.0.el1_registers());
                let mut expected = before.1;
                expected.sp = SP0;
                expected.nzcv = 0x5000_0000;
                assert_eq!(registers, expected);
            }
            assert_eq!(services.monitor_cleared, index >= 2);
            assert_eq!(services.event_set, index >= 3);
        }
    }

    #[test]
    fn preflight_failure_and_stale_plan_make_no_architectural_changes() {
        let (profile, mut system, mut registers) = state(PSTATE_EL1H);
        let plan = prepare_return(
            SOURCE_PC,
            &features(),
            profile,
            controls(),
            &system,
            &registers,
        )
        .unwrap();
        let before = (system.clone(), registers.clone());
        let mut services = Services {
            fail_preflight: true,
            ..Services::default()
        };
        assert_eq!(
            plan.execute(&mut system, &mut registers, &mut services),
            Err(ExecuteError::Preflight("unavailable"))
        );
        assert_eq!((system.clone(), registers.clone()), before);
        assert!(services.calls.is_empty());
        let plan = prepare_return(
            SOURCE_PC,
            &features(),
            profile,
            controls(),
            &system,
            &registers,
        )
        .unwrap();
        system.el1_registers_mut().set_elr(0x3000);
        let before = (system.clone(), registers.clone());
        let mut services = Services::default();
        assert_eq!(
            plan.execute(&mut system, &mut registers, &mut services),
            Err(ExecuteError::StalePlan)
        );
        assert_eq!((system, registers), before);
        assert!(services.requests.is_empty());
    }

    #[test]
    fn entry_captures_old_il_daif_and_sync_failure_preserves_them() {
        for fail in [false, true] {
            let (profile, mut system, mut registers) = state(PSTATE_EL1T);
            let old_psr =
                PSTATE_EL1T | PSTATE_IL_MASK | (DAIF_MASK & !PSTATE_IRQ_MASK) | u64::from(FLAGS);
            system.transition_pstate(&mut registers, old_psr).unwrap();
            let before = (system.clone(), registers.clone());
            let plan = prepare_entry(
                &features(),
                profile,
                controls(),
                &system,
                &registers,
                EntryEvent::Irq { next_pc: SOURCE_PC },
            )
            .unwrap();
            let mut services = Services {
                fail: fail.then_some(EffectStage::Synchronize),
                ..Services::default()
            };
            let result = plan.execute(&mut system, &mut registers, &mut services);
            if fail {
                assert!(matches!(
                    result,
                    Err(ExecuteError::Effect {
                        committed: CommittedPrefix::None,
                        ..
                    })
                ));
                assert_eq!((system, registers), before);
            } else {
                assert_eq!(result, Ok(VECTOR_BASE + VECTOR_IRQ));
                assert_eq!(system.el1_registers().spsr(), old_psr);
                assert_eq!(
                    system.pstate(&registers),
                    PSTATE_EL1H | DAIF_MASK | u64::from(FLAGS)
                );
            }
        }
    }

    #[test]
    fn illegal_execution_state_precedes_instruction_generated_events_and_eret() {
        let (profile, mut system, mut registers) = state(PSTATE_EL1H);
        system
            .transition_pstate(&mut registers, PSTATE_EL1H | PSTATE_IL_MASK)
            .unwrap();
        for event in [
            EntryEvent::Undefined {
                instruction_pc: SOURCE_PC,
            },
            EntryEvent::SupervisorCall {
                instruction_pc: SOURCE_PC,
                immediate: 0,
            },
            EntryEvent::SystemAccess {
                instruction_pc: SOURCE_PC,
                request: Request::read(Encoding::new(3, 3, 4, 2, 0), 0),
            },
        ] {
            assert_eq!(
                prepare_entry(&features(), profile, controls(), &system, &registers, event),
                Err(PrepareError::UnsupportedIllegalExecutionState)
            );
        }
        assert_eq!(
            prepare_return(
                SOURCE_PC,
                &features(),
                profile,
                controls(),
                &system,
                &registers
            ),
            Err(PrepareError::UnsupportedIllegalExecutionState)
        );
    }

    #[test]
    fn software_breakpoint_all_flags_immediates_pc_and_effect_sequence() {
        for mode in [PSTATE_EL1T, PSTATE_EL1H] {
            for flags in 0..16u32 {
                for immediate in [0, 1, 0x7fff, 0x8000, u16::MAX] {
                    for instruction_pc in [SOURCE_PC, u64::MAX - 3] {
                        let (profile, mut system, mut registers) = state(mode);
                        registers.nzcv = flags << 28;
                        let old = registers.clone();
                        let source_pstate = system.pstate(&registers);
                        let plan = prepare_entry(
                            &features(),
                            profile,
                            controls(),
                            &system,
                            &registers,
                            EntryEvent::SoftwareBreakpoint {
                                instruction_pc,
                                immediate,
                            },
                        )
                        .unwrap();
                        let mut services = Services::default();
                        let target = plan
                            .execute(&mut system, &mut registers, &mut services)
                            .unwrap();
                        assert_eq!(
                            target,
                            VECTOR_BASE + if mode == PSTATE_EL1H { 0x200 } else { 0 }
                        );
                        assert_eq!(
                            system.el1_registers().esr(),
                            0xf200_0000 | u64::from(immediate)
                        );
                        assert_eq!(system.el1_registers().elr(), instruction_pc);
                        assert_eq!(system.el1_registers().spsr(), source_pstate);
                        assert_eq!(system.el1_registers().far(), OLD_FAR);
                        assert_eq!(
                            system.pstate(&registers),
                            u64::from(flags << 28) | DAIF_MASK | PSTATE_EL1H
                        );
                        assert_eq!(registers.x, old.x);
                        assert_eq!(registers.v, old.v);
                        assert_eq!((registers.fpcr, registers.fpsr), (old.fpcr, old.fpsr));
                        assert_eq!(services.calls, [EffectStage::Synchronize]);
                        assert!(!services.monitor_cleared && !services.event_set);
                        assert_eq!(services.requests.len(), 1);
                        assert_eq!(services.requests[0].source_pc, instruction_pc);
                        assert_eq!(
                            services.requests[0].effects,
                            RequiredEffects::Entry { irq: false }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn software_breakpoint_failure_never_becomes_an_entry_or_local_event() {
        for fail_preflight in [true, false] {
            let (profile, mut system, mut registers) = state(PSTATE_EL1T);
            let before_system = system.clone();
            let before_registers = registers.clone();
            let plan = prepare_entry(
                &features(),
                profile,
                controls(),
                &system,
                &registers,
                EntryEvent::SoftwareBreakpoint {
                    instruction_pc: SOURCE_PC,
                    immediate: 0xbeef,
                },
            )
            .unwrap();
            let mut services = Services {
                fail_preflight,
                fail: Some(EffectStage::Synchronize),
                ..Services::default()
            };
            let error = plan
                .execute(&mut system, &mut registers, &mut services)
                .unwrap_err();
            if fail_preflight {
                assert!(matches!(error, ExecuteError::Preflight("unavailable")));
                assert!(services.calls.is_empty());
            } else {
                assert!(matches!(
                    error,
                    ExecuteError::Effect {
                        stage: EffectStage::Synchronize,
                        committed: CommittedPrefix::None,
                        ..
                    }
                ));
            }
            assert_eq!(system, before_system);
            assert_eq!(registers, before_registers);
            assert!(!services.monitor_cleared && !services.event_set);
        }
    }

    #[test]
    fn entry_preflight_permit_is_consumed_once_without_a_second_preflight() {
        let (profile, mut system, mut registers) = state(PSTATE_EL1H);
        let plan = prepare_entry(
            &features(),
            profile,
            controls(),
            &system,
            &registers,
            EntryEvent::SoftwareBreakpoint {
                instruction_pc: SOURCE_PC,
                immediate: 7,
            },
        )
        .unwrap();
        assert_eq!(plan.target_address(), VECTOR_BASE + VECTOR_CURRENT_EL_SPX);
        assert_eq!(plan.target_exception_level(), ExceptionLevel::El1);
        let mut services = Services::default();
        services.preflight(plan.service_request()).unwrap();
        assert!(services.calls.is_empty());
        let target = plan
            .execute_preflighted(&mut system, &mut registers, &mut services, ())
            .unwrap();
        assert_eq!(target, VECTOR_BASE + VECTOR_CURRENT_EL_SPX);
        assert_eq!(services.requests.len(), 1);
        assert_eq!(services.calls, [EffectStage::Synchronize]);
        assert_eq!(system.el1_registers().elr(), SOURCE_PC);
    }

    #[test]
    fn return_preflight_does_not_hide_stale_state_or_fallible_synchronization() {
        let (profile, mut system, mut registers) = state(PSTATE_EL1H);
        let plan = prepare_return(
            SOURCE_PC,
            &features(),
            profile,
            controls(),
            &system,
            &registers,
        )
        .unwrap();
        assert_eq!(plan.target_address(), RETURN_PC);
        assert_eq!(plan.target_exception_level(), ExceptionLevel::El0);
        let mut services = Services::default();
        services.preflight(plan.service_request()).unwrap();
        system
            .el1_registers_mut()
            .set_elr(RETURN_PC.wrapping_add(A64_INSTRUCTION_BYTES));
        let before = registers.clone();
        assert_eq!(
            plan.execute_preflighted(&mut system, &mut registers, &mut services, ()),
            Err(ExecuteError::StalePlan)
        );
        assert_eq!(registers, before);
        assert!(services.calls.is_empty());
        assert_eq!(services.requests.len(), 1);

        let plan = prepare_return(
            SOURCE_PC,
            &features(),
            profile,
            controls(),
            &system,
            &registers,
        )
        .unwrap();
        let mut services = Services {
            fail: Some(EffectStage::Synchronize),
            ..Services::default()
        };
        services.preflight(plan.service_request()).unwrap();
        assert_eq!(
            plan.execute_preflighted(&mut system, &mut registers, &mut services, ()),
            Err(ExecuteError::Effect {
                stage: EffectStage::Synchronize,
                committed: CommittedPrefix::None,
                failure: EffectFailure {
                    error: "injected",
                    completion: Completion::Partial
                }
            })
        );
        assert_eq!(registers, before);
        assert_eq!(system.current_el(), ExceptionLevel::El1);
        assert_eq!(services.requests.len(), 1);
        assert!(!services.monitor_cleared && !services.event_set);
    }

    #[test]
    fn higher_el_profile_is_declined_before_capturing_base_stack_state() {
        let (mut profile, system, registers) = state(PSTATE_EL1H);
        for current_el in [ExceptionLevel::El2, ExceptionLevel::El3] {
            profile.current_el = current_el;
            assert!(matches!(
                prepare_entry(
                    &features(),
                    profile,
                    controls(),
                    &system,
                    &registers,
                    EntryEvent::Undefined {
                        instruction_pc: SOURCE_PC
                    }
                ),
                Err(PrepareError::UnsupportedScope)
            ));
            assert!(matches!(
                prepare_return(
                    SOURCE_PC,
                    &features(),
                    profile,
                    controls(),
                    &system,
                    &registers
                ),
                Err(PrepareError::UnsupportedScope)
            ));
        }
    }
}
