//! Per-PE events (SEV, SEVL) and WFE/WFI. Waits never park: a WFx completes
//! once its wake condition is checked.

use super::access::{ExceptionLevel, Profile, SecurityState};
use crate::platform::sync::Mutex;
use alloc::sync::{Arc, Weak};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use stela_compiler::GuestState;
use stela_compiler::aarch64::system::synchronization::{self, Operation, WaitKind};

const INSTRUCTION_BYTES: u64 = 4;
const ZERO_REGISTER: u8 = 31;
const ESR_EC_SHIFT: u32 = 26;
const ESR_INSTRUCTION_LENGTH: u32 = 1 << 25;
const ESR_CONDITION_SHIFT: u32 = 20;
const ESR_CONDITION_VALID_ALWAYS: u32 = 0b1_1110;
const ESR_WFX_EXCEPTION_CLASS: u32 = 0x01;
const ISS_TIMED_REGISTER_VALID: u32 = 1 << 2;
const ISS_TIMED_REGISTER_SHIFT: u32 = 5;
const ISS_WFI: u32 = 0;
const ISS_WFE: u32 = 1;
const ISS_WFIT: u32 = 2;
const ISS_WFET: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    Poisoned,
    WrongDomain,
}

#[derive(Debug)]
struct EventRegister {
    event: AtomicBool,
    monitor_bound: AtomicBool,
    live: AtomicBool,
}

impl EventRegister {
    fn signal_local(&self) -> bool {
        if !self.live.load(Ordering::Acquire) {
            return false;
        }
        self.event.store(true, Ordering::Release);
        true
    }
}

/// The registry contains only weak publication handles, not another PE state
/// bank. Registry locking never calls memory, counter or interrupt services.
#[derive(Debug)]
struct EventRegistry {
    endpoints: Mutex<Vec<Weak<EventRegister>>>,
}

#[derive(Debug, Clone)]
pub struct EventDomain {
    identity: Arc<EventRegistry>,
}

impl EventDomain {
    pub fn new() -> Self {
        Self {
            identity: Arc::new(EventRegistry {
                endpoints: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Both initial values are explicit. Dropping the endpoint retires this
    /// PE's event identity.
    pub fn register(
        &self,
        initial_event: bool,
        local_timeout: Option<u64>,
    ) -> Result<EventEndpoint, DomainError> {
        let event = Arc::new(EventRegister {
            event: AtomicBool::new(initial_event),
            monitor_bound: AtomicBool::new(false),
            live: AtomicBool::new(true),
        });
        let mut endpoints = self
            .identity
            .endpoints
            .lock()
            .map_err(|_| DomainError::Poisoned)?;
        endpoints.retain(|endpoint| endpoint.strong_count() != 0);
        endpoints.push(Arc::downgrade(&event));
        Ok(EventEndpoint {
            domain: Arc::clone(&self.identity),
            event,
            local_timeout,
        })
    }

    /// Includes the sender when its endpoint is registered in this domain.
    /// Repeated sends coalesce. New registrations do not inherit past sends.
    pub fn signal_all(&self) -> Result<(), DomainError> {
        let mut endpoints = self
            .identity
            .endpoints
            .lock()
            .map_err(|_| DomainError::Poisoned)?;
        endpoints.retain(|endpoint| endpoint.upgrade().is_some_and(|event| event.signal_local()));
        Ok(())
    }

    fn owns(&self, endpoint: &EventEndpoint) -> bool {
        Arc::ptr_eq(&self.identity, &endpoint.domain)
    }
}

impl Default for EventDomain {
    fn default() -> Self {
        Self::new()
    }
}

/// One authoritative execution handle, deliberately not Clone. Its event bit
/// can be published concurrently; local timeout mutations require `&mut self`.
#[derive(Debug)]
pub struct EventEndpoint {
    domain: Arc<EventRegistry>,
    event: Arc<EventRegister>,
    local_timeout: Option<u64>,
}

impl EventEndpoint {
    /// Retain the same registry when an assigned PE leaves reset later. The
    /// endpoint owns its domain; dropping the boot's original handle does not
    /// create a second registry or lose the existing event recipients.
    pub(crate) fn domain(&self) -> EventDomain {
        EventDomain {
            identity: Arc::clone(&self.domain),
        }
    }

    pub(crate) fn same_domain(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &other.domain)
    }

    pub fn producer(&self) -> EventProducer {
        EventProducer {
            event: Arc::downgrade(&self.event),
        }
    }

    /// SEVL and legal exception return use this same endpoint. This publication
    /// is not an architectural guest memory barrier.
    pub fn signal_local(&self) {
        self.event.event.store(true, Ordering::Release);
    }

    pub fn consume_if_set(&self) -> bool {
        self.event.event.swap(false, Ordering::AcqRel)
    }

    pub fn is_set(&self) -> bool {
        self.event.event.load(Ordering::Acquire)
    }

    pub const fn local_timeout(&self) -> Option<u64> {
        self.local_timeout
    }

    /// Counter reads use the existing architectural virtual-counter provider,
    /// outside all event locks. Pending interrupt includes masked wake sources;
    /// this service neither acknowledges interrupts nor clears reservations.
    pub fn complete<E>(
        &mut self,
        domain: &EventDomain,
        instruction: EventInstruction,
        context: Context,
        pending_interrupt: bool,
        mut counter: impl FnMut() -> Result<u64, E>,
    ) -> Result<Outcome, Error<E>> {
        if !domain.owns(self) {
            return Err(Error::Domain(DomainError::WrongDomain));
        }
        let next_pc = instruction
            .pc
            .checked_add(INSTRUCTION_BYTES)
            .filter(|_| instruction.pc.is_multiple_of(INSTRUCTION_BYTES))
            .ok_or(Error::InvalidInstructionPc)?;
        if instruction.deadline.is_some() && !context.wfxt {
            return Ok(Outcome::Undefined { instruction });
        }
        let retire = |reason| Outcome::Retired { next_pc, reason };
        match instruction.operation {
            Operation::SendEvent { local: true } => {
                self.signal_local();
                return Ok(retire(RetireReason::EventSent));
            }
            Operation::SendEvent { local: false } => {
                domain.signal_all().map_err(Error::Domain)?;
                return Ok(retire(RetireReason::EventSent));
            }
            Operation::Wait { .. } => {}
            _ => unreachable!("EventInstruction admits only event operations"),
        }
        let event_wait = instruction.is_event_wait();
        if event_wait {
            if self.consume_if_set() {
                return Ok(retire(RetireReason::EventConsumed));
            }
        } else if pending_interrupt {
            return Ok(retire(RetireReason::InterruptPending));
        }
        if let Some(deadline) = instruction.deadline
            && self.timeout_expired(deadline.ticks, &mut counter)?
        {
            return Ok(retire(RetireReason::DeadlineExpired));
        }
        if context.traps(event_wait) {
            return Ok(Outcome::Trap(El1Trap {
                instruction,
                preferred_return_pc: instruction.pc,
                esr: instruction.trap_esr(),
            }));
        }
        // WaitForEvent observes a newly set bit without consuming it. This
        // short-circuits its second timeout check, exactly as the source helper.
        if event_wait && self.is_set() {
            return Ok(retire(RetireReason::EventObserved));
        }
        if let Some(deadline) = instruction.deadline
            && self.timeout_expired(deadline.ticks, &mut counter)?
        {
            return Ok(retire(RetireReason::DeadlineExpired));
        }
        Ok(retire(RetireReason::CooperativeResume))
    }

    fn timeout_expired<E>(
        &mut self,
        deadline: u64,
        counter: &mut impl FnMut() -> Result<u64, E>,
    ) -> Result<bool, Error<E>> {
        let now = counter().map_err(Error::Counter)?;
        if now >= deadline {
            Ok(true)
        } else {
            // A later trap or provider failure does not invent a timer reset.
            self.local_timeout = Some(deadline);
            Ok(false)
        }
    }
}

impl Drop for EventEndpoint {
    fn drop(&mut self) {
        // Temporary producer upgrades must not prolong the PE's live identity.
        self.event.live.store(false, Ordering::Release);
    }
}

/// A concrete infallible publication handle suitable under a monitor stripe.
/// Memory owns once-only Exclusive→Open transitions; this handle only coalesces
/// the resulting signals. It cannot keep a retired endpoint alive or retarget.
#[derive(Debug, Clone)]
pub struct EventProducer {
    event: Weak<EventRegister>,
}

impl EventProducer {
    /// False means the PE endpoint has retired, not that an event was consumed.
    pub fn signal_local(&self) -> bool {
        self.event
            .upgrade()
            .is_some_and(|event| event.signal_local())
    }

    pub fn same_endpoint(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.event, &other.event)
    }

    /// Claim the single monitor owner across every memory domain. The claim
    /// does not keep the PE alive: after retirement, publications return false.
    pub fn try_bind_monitor(&self) -> Result<MonitorBinding, MonitorBindError> {
        let event = self
            .event
            .upgrade()
            .ok_or(MonitorBindError::EndpointRetired)?;
        if !event.live.load(Ordering::Acquire) {
            return Err(MonitorBindError::EndpointRetired);
        }
        if event
            .monitor_bound
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(if event.live.load(Ordering::Acquire) {
                MonitorBindError::AlreadyBound
            } else {
                MonitorBindError::EndpointRetired
            });
        }
        if !event.live.load(Ordering::Acquire) {
            event.monitor_bound.store(false, Ordering::Release);
            return Err(MonitorBindError::EndpointRetired);
        }
        Ok(MonitorBinding {
            producer: self.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorBindError {
    EndpointRetired,
    AlreadyBound,
}

/// The claim of the PE endpoint's monitor owner. Memory keeps this guard while
/// any of the owner's global marks survive; it opens marks once and signals
/// through this handle.
#[derive(Debug)]
pub struct MonitorBinding {
    producer: EventProducer,
}

impl MonitorBinding {
    pub fn signal_local(&self) -> bool {
        self.producer.signal_local()
    }

    pub fn same_endpoint(&self, producer: &EventProducer) -> bool {
        self.producer.same_endpoint(producer)
    }
}

impl Drop for MonitorBinding {
    fn drop(&mut self) {
        if let Some(event) = self.producer.event.upgrade() {
            event.monitor_bound.store(false, Ordering::Release);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    UnsupportedProfile,
    TrapDelayUnsupported,
    HaltedUnsupported,
}

/// The supported non-halting, non-secure AArch64 EL0/EL1 profile without TWED,
/// EL2 or EL3. The CPU owner supplies every control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    current_el: ExceptionLevel,
    wfxt: bool,
    n_twe: bool,
    n_twi: bool,
}

impl Context {
    pub fn new(
        profile: Profile,
        wfxt: bool,
        twed: bool,
        halted: bool,
        n_twe: bool,
        n_twi: bool,
    ) -> Result<Self, ContextError> {
        if profile.security != SecurityState::NonSecure
            || profile.el2_enabled
            || profile.el3_present
            || !matches!(
                profile.current_el,
                ExceptionLevel::El0 | ExceptionLevel::El1
            )
        {
            return Err(ContextError::UnsupportedProfile);
        }
        if twed {
            return Err(ContextError::TrapDelayUnsupported);
        }
        if halted {
            return Err(ContextError::HaltedUnsupported);
        }
        Ok(Self {
            current_el: profile.current_el,
            wfxt,
            n_twe,
            n_twi,
        })
    }

    fn traps(self, event_wait: bool) -> bool {
        self.current_el == ExceptionLevel::El0
            && !(if event_wait { self.n_twe } else { self.n_twi })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Deadline {
    register: u8,
    ticks: u64,
}

/// Exact decoded source word plus the once-sampled timed operand. Fields are
/// private so callers cannot substitute a descriptor unrelated to that word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventInstruction {
    word: u32,
    pc: u64,
    operation: Operation,
    deadline: Option<Deadline>,
}

impl EventInstruction {
    pub fn decode(word: u32, pc: u64, registers: &GuestState) -> Option<Self> {
        let operation = synchronization::decode(word)?;
        let deadline = match operation {
            Operation::SendEvent { .. } => None,
            Operation::Wait {
                timeout_register, ..
            } => timeout_register.map(|register| Deadline {
                register,
                ticks: if register == ZERO_REGISTER {
                    0
                } else {
                    registers.x[usize::from(register)]
                },
            }),
            _ => return None,
        };
        Some(Self {
            word,
            pc,
            operation,
            deadline,
        })
    }

    pub const fn word(self) -> u32 {
        self.word
    }
    pub const fn pc(self) -> u64 {
        self.pc
    }

    fn is_event_wait(self) -> bool {
        matches!(
            self.operation,
            Operation::Wait {
                kind: WaitKind::Event,
                ..
            }
        )
    }

    fn trap_esr(self) -> u32 {
        let kind = match (self.is_event_wait(), self.deadline.is_some()) {
            (false, false) => ISS_WFI,
            (true, false) => ISS_WFE,
            (false, true) => ISS_WFIT,
            (true, true) => ISS_WFET,
        };
        let timed_register = self.deadline.map_or(0, |deadline| {
            ISS_TIMED_REGISTER_VALID | (u32::from(deadline.register) << ISS_TIMED_REGISTER_SHIFT)
        });
        (ESR_WFX_EXCEPTION_CLASS << ESR_EC_SHIFT)
            | ESR_INSTRUCTION_LENGTH
            | (ESR_CONDITION_VALID_ALWAYS << ESR_CONDITION_SHIFT)
            | kind
            | timed_register
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetireReason {
    EventSent,
    EventConsumed,
    EventObserved,
    InterruptPending,
    /// The event implementation resumed because an IRQ was presented; the
    /// event register keeps its value.
    PresentedIrqResume,
    DeadlineExpired,
    /// Explicit source-permitted implementation-selected immediate resume.
    CooperativeResume,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct El1Trap {
    pub instruction: EventInstruction,
    pub preferred_return_pc: u64,
    pub esr: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Retired { next_pc: u64, reason: RetireReason },
    Trap(El1Trap),
    Undefined { instruction: EventInstruction },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    Domain(DomainError),
    InvalidInstructionPc,
    Counter(E),
}

#[cfg(test)]
mod tests {
    #[test]
    fn endpoint_retains_one_registry_for_later_cpu_starts() {
        let domain = super::EventDomain::new();
        let first = domain.register(false, None).unwrap();
        drop(domain);
        let retained = first.domain();
        let second = retained.register(false, None).unwrap();
        assert!(first.same_domain(&second));
        retained.signal_all().unwrap();
        assert!(first.consume_if_set());
        assert!(second.consume_if_set());
        let cloned = retained.clone();
        drop(retained);
        cloned.signal_all().unwrap();
        assert!(first.consume_if_set());
        assert!(second.consume_if_set());
    }

    use super::*;
    use std::sync::Barrier;

    const WFE: u32 = 0xd503_205f;
    const WFI: u32 = 0xd503_207f;
    const SEV: u32 = 0xd503_209f;
    const SEVL: u32 = 0xd503_20bf;
    const WFET: u32 = 0xd503_1000;
    const WFIT: u32 = 0xd503_1020;
    const PC: u64 = 0x1000;
    const WFX_ESR: u32 = 0x07e0_0000;

    fn profile(el: ExceptionLevel) -> Profile {
        Profile {
            current_el: el,
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        }
    }

    fn context(trap: bool) -> Context {
        Context::new(
            profile(ExceptionLevel::El0),
            true,
            false,
            false,
            !trap,
            !trap,
        )
        .unwrap()
    }

    fn instruction(word: u32, value: u64) -> EventInstruction {
        let registers = GuestState {
            x: [value; 31],
            ..GuestState::default()
        };
        EventInstruction::decode(word, PC, &registers).unwrap()
    }

    fn no_counter() -> Result<u64, ()> {
        panic!("counter must not be sampled")
    }

    fn retired(outcome: Outcome, reason: RetireReason) {
        assert_eq!(
            outcome,
            Outcome::Retired {
                next_pc: PC + INSTRUCTION_BYTES,
                reason
            }
        );
    }

    #[test]
    fn send_local_all_coalescing_and_registration_are_distinct() {
        let domain = EventDomain::new();
        let mut first = domain.register(false, None).unwrap();
        let second = domain.register(false, None).unwrap();
        for _ in 0..2 {
            retired(
                first
                    .complete(
                        &domain,
                        instruction(SEVL, 0),
                        context(true),
                        false,
                        no_counter,
                    )
                    .unwrap(),
                RetireReason::EventSent,
            );
        }
        assert!(first.consume_if_set());
        assert!(!first.consume_if_set());
        assert!(!second.consume_if_set());
        retired(
            first
                .complete(
                    &domain,
                    instruction(SEV, 0),
                    context(true),
                    false,
                    no_counter,
                )
                .unwrap(),
            RetireReason::EventSent,
        );
        assert!(first.consume_if_set());
        assert!(second.consume_if_set());
        assert!(!domain.register(false, None).unwrap().is_set());
    }

    #[test]
    fn weak_producers_do_not_retain_or_retarget_retired_pes() {
        let domain = EventDomain::new();
        let first = domain.register(false, None).unwrap();
        let producer = first.producer();
        assert!(producer.same_endpoint(&first.producer()));
        assert!(producer.signal_local());
        assert!(first.consume_if_set());
        drop(first);
        assert!(!producer.signal_local());
        let next = domain.register(false, None).unwrap();
        assert!(!producer.same_endpoint(&next.producer()));
        assert!(!producer.signal_local());
        assert!(!next.is_set());
    }

    #[test]
    fn wrong_domain_and_invalid_pc_fail_before_event_effects() {
        let domain = EventDomain::new();
        let other = EventDomain::new();
        let mut endpoint = domain.register(true, Some(77)).unwrap();
        assert_eq!(
            endpoint.complete(
                &other,
                instruction(WFE, 0),
                context(true),
                false,
                no_counter
            ),
            Err(Error::Domain(DomainError::WrongDomain))
        );
        for pc in [PC + 1, u64::MAX - (INSTRUCTION_BYTES - 1)] {
            let invalid = EventInstruction::decode(WFE, pc, &GuestState::default()).unwrap();
            assert_eq!(
                endpoint.complete(&domain, invalid, context(true), false, no_counter),
                Err(Error::InvalidInstructionPc)
            );
        }
        assert!(endpoint.is_set());
        assert_eq!(endpoint.local_timeout(), Some(77));
    }

    #[test]
    fn context_rejects_unimplemented_privilege_delay_and_halt_profiles() {
        for el in [ExceptionLevel::El2, ExceptionLevel::El3] {
            assert_eq!(
                Context::new(profile(el), true, false, false, true, true),
                Err(ContextError::UnsupportedProfile)
            );
        }
        for unsupported in [
            Profile {
                security: SecurityState::Secure,
                ..profile(ExceptionLevel::El0)
            },
            Profile {
                security: SecurityState::Realm,
                ..profile(ExceptionLevel::El0)
            },
            Profile {
                el2_enabled: true,
                ..profile(ExceptionLevel::El0)
            },
            Profile {
                el3_present: true,
                ..profile(ExceptionLevel::El0)
            },
        ] {
            assert_eq!(
                Context::new(unsupported, true, false, false, true, true),
                Err(ContextError::UnsupportedProfile)
            );
        }
        assert_eq!(
            Context::new(profile(ExceptionLevel::El0), true, true, false, true, true),
            Err(ContextError::TrapDelayUnsupported)
        );
        assert_eq!(
            Context::new(profile(ExceptionLevel::El0), true, false, true, true, true),
            Err(ContextError::HaltedUnsupported)
        );
    }

    #[test]
    fn wfe_consumes_before_trap_but_wfi_never_consumes() {
        let domain = EventDomain::new();
        let mut endpoint = domain.register(true, None).unwrap();
        let wait = instruction(WFI, 0);
        assert_eq!(
            endpoint
                .complete(&domain, wait, context(true), false, no_counter)
                .unwrap(),
            Outcome::Trap(El1Trap {
                instruction: wait,
                preferred_return_pc: PC,
                esr: WFX_ESR | ISS_WFI
            })
        );
        assert!(endpoint.is_set());
        retired(
            endpoint
                .complete(
                    &domain,
                    instruction(WFE, 0),
                    context(true),
                    false,
                    no_counter,
                )
                .unwrap(),
            RetireReason::EventConsumed,
        );
        let wait = instruction(WFE, 0);
        assert_eq!(
            endpoint
                .complete(&domain, wait, context(true), false, no_counter)
                .unwrap(),
            Outcome::Trap(El1Trap {
                instruction: wait,
                preferred_return_pc: PC,
                esr: WFX_ESR | ISS_WFE
            })
        );
        endpoint.signal_local();
        retired(
            endpoint
                .complete(
                    &domain,
                    instruction(WFI, 0),
                    context(true),
                    true,
                    no_counter,
                )
                .unwrap(),
            RetireReason::InterruptPending,
        );
        assert!(endpoint.is_set());
    }

    #[test]
    fn timed_short_circuits_and_absent_feature_do_not_invent_effects() {
        let domain = EventDomain::new();
        let mut endpoint = domain.register(true, Some(77)).unwrap();
        retired(
            endpoint
                .complete(
                    &domain,
                    instruction(WFET, u64::MAX),
                    context(true),
                    false,
                    no_counter,
                )
                .unwrap(),
            RetireReason::EventConsumed,
        );
        retired(
            endpoint
                .complete(
                    &domain,
                    instruction(WFIT, u64::MAX),
                    context(true),
                    true,
                    no_counter,
                )
                .unwrap(),
            RetireReason::InterruptPending,
        );
        let absent = Context::new(
            profile(ExceptionLevel::El0),
            false,
            false,
            false,
            false,
            false,
        )
        .unwrap();
        endpoint.signal_local();
        let timed = instruction(WFET, 99);
        assert_eq!(
            endpoint
                .complete(&domain, timed, absent, false, no_counter)
                .unwrap(),
            Outcome::Undefined { instruction: timed }
        );
        assert!(endpoint.is_set());
        assert_eq!(endpoint.local_timeout(), Some(77));
    }

    #[test]
    fn every_timed_register_has_exact_syndrome_and_one_operand_sample() {
        let domain = EventDomain::new();
        for base in [WFET, WFIT] {
            for register in 0..=ZERO_REGISTER {
                let mut endpoint = domain.register(false, None).unwrap();
                let mut registers = GuestState {
                    x: [99; 31],
                    nzcv: u32::MAX,
                    ..GuestState::default()
                };
                let word = base | u32::from(register);
                let timed = EventInstruction::decode(word, PC, &registers).unwrap();
                let before = registers.clone();
                registers.x.fill(0);
                let mut reads = 0;
                let outcome = endpoint
                    .complete(&domain, timed, context(true), false, || {
                        reads += 1;
                        Ok::<_, ()>(0)
                    })
                    .unwrap();
                assert_eq!(timed.word(), word);
                assert_eq!(timed.pc(), PC);
                assert_eq!(reads, 1);
                if register == ZERO_REGISTER {
                    retired(outcome, RetireReason::DeadlineExpired);
                    assert_eq!(endpoint.local_timeout(), None);
                } else {
                    let kind = if base == WFET { ISS_WFET } else { ISS_WFIT };
                    assert_eq!(
                        outcome,
                        Outcome::Trap(El1Trap {
                            instruction: timed,
                            preferred_return_pc: PC,
                            esr: WFX_ESR
                                | kind
                                | ISS_TIMED_REGISTER_VALID
                                | (u32::from(register) << ISS_TIMED_REGISTER_SHIFT)
                        })
                    );
                    assert_eq!(endpoint.local_timeout(), Some(99));
                }
                // The service cannot mutate the source register image it borrowed.
                assert_eq!(before.nzcv, u32::MAX);
                assert_eq!(
                    registers,
                    GuestState {
                        x: [0; 31],
                        ..before
                    }
                );
            }
        }
    }

    #[test]
    fn deadlines_are_unsigned_and_timeout_arming_precedes_traps() {
        let domain = EventDomain::new();
        for (deadline, now, expired) in [
            (0, 0, true),
            (1 << 63, (1 << 63) - 1, false),
            (1 << 63, 1 << 63, true),
            (u64::MAX, 0, false),
            (u64::MAX, u64::MAX, true),
            (0, u64::MAX, true),
        ] {
            let mut endpoint = domain.register(false, Some(77)).unwrap();
            let timed = instruction(WFET, deadline);
            let outcome = endpoint
                .complete(&domain, timed, context(true), false, || Ok::<_, ()>(now))
                .unwrap();
            if expired {
                retired(outcome, RetireReason::DeadlineExpired);
                assert_eq!(endpoint.local_timeout(), Some(77));
            } else {
                assert!(matches!(outcome, Outcome::Trap(_)));
                assert_eq!(endpoint.local_timeout(), Some(deadline));
            }
        }
    }

    #[test]
    fn final_event_observation_preserves_the_new_bit_and_skips_second_counter() {
        let domain = EventDomain::new();
        let mut endpoint = domain.register(false, None).unwrap();
        let producer = endpoint.producer();
        let mut reads = 0;
        let outcome = endpoint
            .complete(
                &domain,
                instruction(WFET, 99),
                context(false),
                false,
                || {
                    reads += 1;
                    assert_eq!(reads, 1);
                    assert!(producer.signal_local());
                    Ok::<_, ()>(0)
                },
            )
            .unwrap();
        retired(outcome, RetireReason::EventObserved);
        assert!(endpoint.consume_if_set());
        assert_eq!(endpoint.local_timeout(), Some(99));
    }

    #[test]
    fn counter_errors_preserve_prior_timeout_and_publication() {
        let domain = EventDomain::new();
        let mut endpoint = domain.register(false, Some(77)).unwrap();
        assert_eq!(
            endpoint.complete(
                &domain,
                instruction(WFIT, 99),
                context(false),
                false,
                || Err("first")
            ),
            Err(Error::Counter("first"))
        );
        assert_eq!(endpoint.local_timeout(), Some(77));
        let producer = endpoint.producer();
        let mut reads = 0;
        assert_eq!(
            endpoint.complete(
                &domain,
                instruction(WFIT, 99),
                context(false),
                false,
                || {
                    reads += 1;
                    if reads == 1 {
                        Ok(0)
                    } else {
                        producer.signal_local();
                        Err("second")
                    }
                }
            ),
            Err(Error::Counter("second"))
        );
        assert_eq!(endpoint.local_timeout(), Some(99));
        assert!(endpoint.is_set());
    }

    #[test]
    fn explicit_cooperative_resume_and_el1_trap_scope() {
        let domain = EventDomain::new();
        let mut endpoint = domain.register(false, None).unwrap();
        for word in [WFE, WFI] {
            retired(
                endpoint
                    .complete(
                        &domain,
                        instruction(word, 0),
                        context(false),
                        false,
                        no_counter,
                    )
                    .unwrap(),
                RetireReason::CooperativeResume,
            );
            let el1 = Context::new(
                profile(ExceptionLevel::El1),
                true,
                false,
                false,
                false,
                false,
            )
            .unwrap();
            retired(
                endpoint
                    .complete(&domain, instruction(word, 0), el1, false, no_counter)
                    .unwrap(),
                RetireReason::CooperativeResume,
            );
        }
        let mut reads = 0;
        retired(
            endpoint
                .complete(&domain, instruction(WFIT, 9), context(false), false, || {
                    reads += 1;
                    Ok::<_, ()>(if reads == 1 { 8 } else { 9 })
                })
                .unwrap(),
            RetireReason::DeadlineExpired,
        );
        assert_eq!(reads, 2);
        assert!(EventInstruction::decode(0xd503_201f, PC, &GuestState::default()).is_none());
    }

    #[test]
    fn racing_signal_and_initial_consume_cannot_lose_an_event() {
        const ROUNDS: usize = 2000;
        let domain = EventDomain::new();
        let endpoint = domain.register(false, None).unwrap();
        let producer = endpoint.producer();
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..ROUNDS {
                    barrier.wait();
                    assert!(producer.signal_local());
                    barrier.wait();
                    barrier.wait();
                }
            });
            for _ in 0..ROUNDS {
                barrier.wait();
                let consumed = endpoint.consume_if_set();
                barrier.wait();
                let retained = endpoint.consume_if_set();
                assert_ne!(consumed, retained);
                barrier.wait();
            }
        });
    }
}
