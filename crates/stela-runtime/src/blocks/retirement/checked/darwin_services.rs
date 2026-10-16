//! Darwin service calls completed on the running thread.
use crate::{darwin, mach, thread};
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
use serde::Serialize;
use stela_compiler::block::SynchronousTrap;

// Settlement is reached only by the hosted Darwin process owner.
#[cfg(feature = "std")]
use crate::darwin::{BsdPrototype, BsdReturnType, PendingBsdCall, platform};
#[cfg(feature = "std")]
use anyhow::{Context, Result};
#[cfg(feature = "std")]
use stela_compiler::{GuestAddress, GuestState};

#[derive(Debug, Default)]
// Only the hosted Darwin process path reports these events.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) struct TrapServiceEvents {
    pub mach: Vec<mach::Event>,
    pub mach_effects: Vec<MachEffects>,
    pub thread: Vec<thread::Event>,
    pub process: Vec<darwin::BsdServiceEvent>,
    pub refusals: Vec<ServiceRefusal>,
}
#[derive(Debug, Serialize)]
pub(crate) struct MachEffects {
    trap: SynchronousTrap,
    effects: Vec<mach::ports::Effect>,
}
#[derive(Debug, Serialize)]
pub(crate) struct ServiceRefusal {
    trap: SynchronousTrap,
    detail: String,
}

pub(crate) enum Outcome {
    /// No service effect. The original trap stays pending under this same owner.
    NoEffect,
    #[cfg(feature = "std")]
    Complete(GuestAddress),
    /// A host or ABI operation failed; canonical consumer preserves all effects.
    Indeterminate(anyhow::Error),
}

#[cfg(feature = "std")]
enum Prepared {
    Mach(mach::PendingCall),
    ThreadIdentity(PendingBsdCall),
    ProcessIdentity(PendingBsdCall),
    Platform(platform::PendingCall),
}
#[cfg(feature = "std")]
impl Prepared {
    fn from_registers(
        trap: &SynchronousTrap,
        registers: &GuestState,
        thread: &thread::Context,
    ) -> Result<Option<Self>> {
        let selector = registers.x[darwin::SYSCALL_SELECTOR_REGISTER] as u32 as i32;
        if selector == platform::PLATFORM_CALL_SELECTOR {
            return Ok(Some(Self::Platform(platform::PendingCall::from_registers(
                trap.instruction_pc,
                registers,
                trap,
            )?)));
        }
        if selector < 0 {
            let Some(number) = selector
                .checked_neg()
                .and_then(|value| u32::try_from(value).ok())
            else {
                return Ok(None);
            };
            if !matches!(
                number,
                mach::REPLY_PORT_TRAP
                    | mach::THREAD_SELF_TRAP
                    | mach::TASK_SELF_TRAP
                    | mach::HOST_SELF_TRAP
            ) {
                return Ok(None);
            }
            return Ok(Some(Self::Mach(mach::PendingCall::from_registers(
                trap.instruction_pc,
                registers,
                trap,
                0,
            )?)));
        }
        let selector = darwin::classify_bsd_call_parts(trap.instruction_pc, registers, trap)?;
        let (prototype, identity) = match selector.number {
            thread::THREAD_SELFID_SYSCALL => (
                BsdPrototype {
                    argument_count: 0,
                    return_type: BsdReturnType::Unsigned64,
                },
                true,
            ),
            darwin::process::SYSCALL_NUMBER if thread.process().is_some() => (
                BsdPrototype {
                    argument_count: 0,
                    return_type: BsdReturnType::Int,
                },
                false,
            ),
            _ => return Ok(None),
        };
        let pending =
            PendingBsdCall::from_registers(trap.instruction_pc, registers, trap, prototype)?;
        Ok(Some(if identity {
            Self::ThreadIdentity(pending)
        } else {
            Self::ProcessIdentity(pending)
        }))
    }

    fn complete(
        self,
        trap: &SynchronousTrap,
        registers: &mut GuestState,
        thread: &mut thread::Context,
        events: &mut TrapServiceEvents,
    ) -> Outcome {
        let result: Result<GuestAddress> = match self {
            Self::Mach(pending) => return complete_mach(pending, trap, registers, thread, events),
            Self::ThreadIdentity(pending) => {
                let mut event = thread::IdentityEvent {
                    trap: *trap,
                    request: Some(*pending.request()),
                    completion: None,
                    declined: None,
                };
                let result = thread
                    .identity_completion(pending.request())
                    .and_then(|completion| {
                        let pc = pending.complete_registers(registers, completion)?;
                        event.completion = Some(completion);
                        Ok(pc)
                    });
                if let Err(error) = &result {
                    event.declined = Some(error.to_string());
                }
                events.thread.push(thread::Event::Identity(event));
                result
            }
            Self::ProcessIdentity(pending) => {
                let mut event = darwin::BsdServiceEvent {
                    trap: *trap,
                    request: Some(*pending.request()),
                    completion: None,
                    declined: None,
                };
                let result: Result<GuestAddress> = (|| {
                    let process = thread
                        .process()
                        .context("actual process identity owner disappeared")?;
                    let completion = darwin::process::completion(pending.request(), process)?;
                    let pc = pending.complete_registers(registers, completion)?;
                    event.completion = Some(completion);
                    Ok(pc)
                })();
                if let Err(error) = &result {
                    event.declined = Some(error.to_string());
                }
                events.process.push(event);
                result
            }
            Self::Platform(pending) => {
                let before = thread.thread_specific_data();
                let mut event = thread::PlatformEvent {
                    trap: *trap,
                    request: Some(*pending.request()),
                    completion: None,
                    thread_specific_data_before: before,
                    thread_specific_data_after: before,
                    declined: None,
                };
                let result = thread.complete_platform_registers(pending, registers);
                match &result {
                    Ok(actual) => {
                        event.completion = Some(actual.completion);
                        event.thread_specific_data_before = actual.before;
                        event.thread_specific_data_after = actual.after;
                    }
                    Err(error) => event.declined = Some(error.to_string()),
                }
                events.thread.push(thread::Event::Platform(event));
                result.map(|actual| actual.next_pc)
            }
        };
        match result {
            Ok(pc) => Outcome::Complete(pc),
            Err(error) => Outcome::Indeterminate(error),
        }
    }
}

#[cfg(feature = "std")]
fn complete_mach(
    pending: mach::PendingCall,
    trap: &SynchronousTrap,
    registers: &mut GuestState,
    thread: &mut thread::Context,
    events: &mut TrapServiceEvents,
) -> Outcome {
    use mach::ports::Outcome as PortOutcome;
    let mut event = mach::Event {
        trap: *trap,
        request: Some(pending.request().clone()),
        result: None,
        declined: None,
    };
    let (result, effects) = match thread.ports_mut().bootstrap(pending.request()) {
        PortOutcome::NoEffect { reason } => {
            event.declined = Some(reason);
            events.mach.push(event);
            return Outcome::NoEffect;
        }
        PortOutcome::Complete { value, effects } => (Ok(value), effects),
        PortOutcome::Indeterminate { error, effects } => (Err(anyhow::anyhow!(error)), effects),
        PortOutcome::Copyout { effects, .. } => (
            Err(anyhow::anyhow!(
                "bootstrap returned an inadmissible guest-memory effect"
            )),
            effects,
        ),
    };
    // Preserve actual acquisitions, releases and uncertain cleanup attempts
    // before ABI validation or canonical authority settlement may fail.
    events.mach_effects.push(MachEffects {
        trap: *trap,
        effects,
    });
    match &result {
        Ok(value) => event.result = Some(*value),
        Err(error) => event.declined = Some(error.to_string()),
    }
    events.mach.push(event);
    match result.and_then(|value| pending.complete_registers(registers, value)) {
        Ok(pc) => Outcome::Complete(pc),
        Err(error) => Outcome::Indeterminate(error),
    }
}

#[cfg(feature = "std")]
pub(super) fn complete(
    trap: &SynchronousTrap,
    registers: &mut GuestState,
    thread: &mut thread::Context,
    events: &mut TrapServiceEvents,
) -> Outcome {
    let prepared = match Prepared::from_registers(trap, registers, thread) {
        Ok(Some(prepared)) => prepared,
        Ok(None) => return Outcome::NoEffect,
        Err(error) => {
            events.refusals.push(ServiceRefusal {
                trap: *trap,
                detail: error.to_string(),
            });
            return Outcome::NoEffect;
        }
    };
    // These four identity/platform prototypes and Mach bootstraps cannot return
    // Restart/JustReturn. Future restart requires a typed source-qualified route.
    prepared.complete(trap, registers, thread, events)
}
