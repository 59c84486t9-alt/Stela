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

/// One authoritative execution handle, not Clone. Its event bit
/// can be published concurrently; local timeout mutations require `&mut self`.
#[derive(Debug)]
pub struct EventEndpoint {
    domain: Arc<EventRegistry>,
    event: Arc<EventRegister>,
    local_timeout: Option<u64>,
}

impl EventEndpoint {
    /// Keep the same registry when an assigned PE leaves reset later. The
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
mod tests;
