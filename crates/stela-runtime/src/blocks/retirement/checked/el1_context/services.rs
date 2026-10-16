//! EL1 exception effects borrowed from the EL1 owner.
use crate::{
    memory::{domain::MemoryThread, policy::MemoryControls},
    system::{
        access::ExceptionLevel,
        events::EventEndpoint,
        exception::{
            Completion, EffectFailure, ExceptionServices, RequiredEffects, ServiceRequest,
        },
        translation_controls::{
            ControlError, PreparedContextSynchronization, PreparedPublication, PublicationProgress,
            TranslationControls,
        },
    },
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Prepared,
    Synchronized,
    ExclusiveCleared,
    EventSent,
    Branched,
}

const MAX_EXCEPTION_EFFECT_RECORDS: usize = 4;

pub(super) struct ExceptionPermit {
    request: ServiceRequest,
    stage: Stage,
}

pub(super) enum ExceptionEffect {
    ContextSynchronized,
    ContextFailed(ControlError),
    ExclusiveCleared,
    ExclusiveFailed(stela_compiler::context::memory::MemoryStatus),
    LocalEventSent,
    BranchAddress { raw: u64, result: u64 },
}

pub(super) struct BorrowedExceptionServices<'controls, 'resource, P: PreparedPublication> {
    publication: Option<PreparedContextSynchronization<'controls, P>>,
    controls: Option<&'controls mut TranslationControls>,
    memory: &'resource mut MemoryThread<MemoryControls>,
    endpoint: &'resource EventEndpoint,
    expected: ServiceRequest,
    target: u64,
    destination: ExceptionLevel,
    preflighted: bool,
    pub(super) effects: Vec<ExceptionEffect>,
}

impl<'controls, 'resource, P: PreparedPublication>
    BorrowedExceptionServices<'controls, 'resource, P>
{
    pub(super) fn new(
        publication: PreparedContextSynchronization<'controls, P>,
        memory: &'resource mut MemoryThread<MemoryControls>,
        endpoint: &'resource EventEndpoint,
        expected: ServiceRequest,
        target: u64,
        destination: ExceptionLevel,
    ) -> Self {
        Self {
            publication: Some(publication),
            controls: None,
            memory,
            endpoint,
            expected,
            target,
            destination,
            preflighted: false,
            effects: Vec::new(),
        }
    }
}

fn same_request(left: ServiceRequest, right: ServiceRequest) -> bool {
    left.effects == right.effects
        && left.profile == right.profile
        && left.source_el == right.source_el
        && left.source_pstate == right.source_pstate
        && left.source_pc == right.source_pc
        && left.controls.tcr_el1 == right.controls.tcr_el1
        && left.controls.mdscr_el1 == right.controls.mdscr_el1
        && left.controls.debug == right.controls.debug
}

fn no_effect(message: impl Into<String>) -> EffectFailure<String> {
    EffectFailure {
        error: message.into(),
        completion: Completion::None,
    }
}

impl<P: PreparedPublication> ExceptionServices for BorrowedExceptionServices<'_, '_, P> {
    type Permit = ExceptionPermit;
    type Error = String;

    fn preflight(&mut self, request: ServiceRequest) -> Result<Self::Permit, String> {
        if self.preflighted || !same_request(request, self.expected) {
            return Err("exception request differs from the original prepared plan".into());
        }
        if matches!(request.effects, RequiredEffects::Entry { irq: true }) {
            return Err("IRQ needs its pending-controller receipt".into());
        }
        self.memory
            .check_event_endpoint(self.endpoint)
            .map_err(|error| format!("original exception monitor/event binding: {error:?}"))?;
        // Reserve diagnostics before any effect; no allocation during the
        // source-ordered synchronization/monitor/event/BranchAddr sequence.
        self.effects
            .try_reserve(MAX_EXCEPTION_EFFECT_RECORDS)
            .map_err(|error| error.to_string())?;
        self.preflighted = true;
        Ok(ExceptionPermit {
            request,
            stage: Stage::Prepared,
        })
    }

    fn synchronize_context(
        &mut self,
        permit: &mut Self::Permit,
        source_el: ExceptionLevel,
    ) -> Result<(), EffectFailure<String>> {
        if permit.stage != Stage::Prepared
            || !same_request(permit.request, self.expected)
            || source_el != self.expected.source_el
        {
            return Err(no_effect(
                "exception synchronization changed its original request",
            ));
        }
        let prepared = self
            .publication
            .take()
            .ok_or_else(|| no_effect("original exception publication already consumed"))?;
        let (controls, result) = prepared.commit();
        self.controls = Some(controls);
        match result {
            Ok(()) => {
                self.effects.push(ExceptionEffect::ContextSynchronized);
                permit.stage = Stage::Synchronized;
                Ok(())
            }
            Err(error) => {
                let completion = match &error {
                    ControlError::Publication {
                        progress: PublicationProgress::None,
                        ..
                    } => Completion::None,
                    ControlError::Publication {
                        progress: PublicationProgress::InstructionExecutionSerialized,
                        ..
                    } => Completion::Complete,
                    ControlError::Publication { .. } => Completion::Partial,
                    _ => Completion::Unknown,
                };
                let detail = format!("exception context publication: {error:?}");
                self.effects.push(ExceptionEffect::ContextFailed(error));
                Err(EffectFailure {
                    error: detail,
                    completion,
                })
            }
        }
    }

    fn clear_exclusive_local(
        &mut self,
        permit: &mut Self::Permit,
    ) -> Result<(), EffectFailure<String>> {
        if permit.request.effects != RequiredEffects::Return || permit.stage != Stage::Synchronized
        {
            return Err(no_effect(
                "exclusive clear is outside the original ERET order",
            ));
        }
        match self.memory.clear_reservation() {
            Ok(()) => {
                self.effects.push(ExceptionEffect::ExclusiveCleared);
                permit.stage = Stage::ExclusiveCleared;
                Ok(())
            }
            Err(error) => {
                self.effects.push(ExceptionEffect::ExclusiveFailed(error));
                Err(EffectFailure {
                    error: format!("original exception exclusive owner: {error:?}"),
                    // Existing API checks health both before and after clear;
                    // its error cannot distinguish those effect boundaries.
                    completion: Completion::Unknown,
                })
            }
        }
    }

    fn send_event_local(&mut self, permit: &mut Self::Permit) -> Result<(), EffectFailure<String>> {
        if permit.stage != Stage::ExclusiveCleared {
            return Err(no_effect(
                "local ERET event precedes original exclusive clear",
            ));
        }
        self.endpoint.signal_local();
        self.effects.push(ExceptionEffect::LocalEventSent);
        permit.stage = Stage::EventSent;
        Ok(())
    }

    fn branch_address(
        &mut self,
        permit: &mut Self::Permit,
        target: u64,
        destination: ExceptionLevel,
    ) -> Result<u64, EffectFailure<String>> {
        if permit.stage != Stage::EventSent
            || target != self.target
            || destination != self.destination
        {
            return Err(no_effect(
                "BranchAddr differs from the original ERET target/order",
            ));
        }
        let controls = self
            .controls
            .as_ref()
            .ok_or_else(|| no_effect("original synchronized controls unavailable"))?;
        let result = controls
            .branch_address(target, destination)
            .map_err(|error| no_effect(format!("destination BranchAddr: {error:?}")))?;
        self.effects.push(ExceptionEffect::BranchAddress {
            raw: target,
            result,
        });
        permit.stage = Stage::Branched;
        Ok(result)
    }
}

impl core::fmt::Debug for ExceptionEffect {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ContextSynchronized => formatter.write_str("ContextSynchronized"),
            Self::ContextFailed(error) => {
                formatter.debug_tuple("ContextFailed").field(error).finish()
            }
            Self::ExclusiveCleared => formatter.write_str("ExclusiveCleared"),
            Self::ExclusiveFailed(error) => formatter
                .debug_tuple("ExclusiveFailed")
                .field(error)
                .finish(),
            Self::LocalEventSent => formatter.write_str("LocalEventSent"),
            Self::BranchAddress { raw, result } => formatter
                .debug_struct("BranchAddress")
                .field("raw", raw)
                .field("result", result)
                .finish(),
        }
    }
}
