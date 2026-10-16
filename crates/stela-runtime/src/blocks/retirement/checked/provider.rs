//! The EL0 backend: checked memory, PAuth, clock and TSD.
mod m0_owner;
mod resources;
pub(crate) use m0_owner::M0Owner;
pub(super) use resources::M0ExecutionChecks;
pub(crate) use resources::{
    El1ContextResources, El1ExecutionResources, El1SystemEffectResources, M0ExecutionResources,
};

use super::NativeObservation;
use super::entry_controls::ProcessEntryControls;
use super::source::{BoundSource, Helper};
use crate::{
    memory::domain::MemoryExecutionLoan,
    system::{execution::Boundary, state::SystemState},
};
use stela_compiler::{GuestAddress, GuestState};

// The hosted EL0 process owner; the freestanding mount has no Darwin process.
#[cfg(feature = "std")]
use super::super::super::{checked_memory, complete_clock, complete_pauth_with_memory};
#[cfg(feature = "std")]
use super::super::software_async::NoAsyncSources;
#[cfg(feature = "std")]
use super::{low128_call, pauth_lr};
#[cfg(feature = "std")]
use crate::{
    blocks::{ClockEvent, PointerAuthenticationEvent, RunOutcome, ThreadRegisterEvent},
    clock,
    memory::{domain::MemoryThread, policy::MemoryControls},
    pauth,
    system::{
        events::EventEndpoint,
        execution::{Dispatcher, EntryBoundary, Failure},
        process_memory::{FixedProcessMemoryControls, PreparedProcessMemory},
        scalable_controls::fp::FpControlOwner,
    },
    thread,
};
#[cfg(feature = "std")]
use stela_compiler::{
    block::PointerAuthenticationOperation,
    context::{ExecutionContext, memory::MemoryRequirements},
};
#[cfg(feature = "std")]
pub(crate) struct CheckedProcessOwner<'pe> {
    address_space: u64,
    controls: &'pe mut FixedProcessMemoryControls,
    execution: &'pe ProcessEntryControls,
    memory: &'pe mut MemoryThread<MemoryControls>,
    endpoint: &'pe EventEndpoint,
    context: &'pe mut ExecutionContext,
    pending: NoAsyncSources<'pe>,
    pauth: &'pe pauth::Context,
    clock: &'pe mut clock::Context,
    thread: &'pe mut thread::Context,
    fp: Option<&'pe FpControlOwner<'pe>>,
}
#[cfg(feature = "std")]
impl<'pe> CheckedProcessOwner<'pe> {
    /// # Safety
    /// Called once by the software machine constructor, before it creates its
    /// execution owner. Every resource belongs to the same PE and namespace and
    /// lives as long as it; `controls` holds the SCTLR/TCR facts, `execution`
    /// the declared debug and optional-feature subset, and `pending` the
    /// complete set of event producers. No raw producer, mutable control alias,
    /// other native entry or source writer may bypass the machine. The clock is
    /// already bound.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks::retirement) unsafe fn fresh_software(
        address_space: u64,
        controls: &'pe mut FixedProcessMemoryControls,
        execution: &'pe ProcessEntryControls,
        memory: &'pe mut MemoryThread<MemoryControls>,
        endpoint: &'pe EventEndpoint,
        context: &'pe mut ExecutionContext,
        pending: NoAsyncSources<'pe>,
        pauth: &'pe pauth::Context,
        clock: &'pe mut clock::Context,
        thread: &'pe mut thread::Context,
        fp: Option<&'pe FpControlOwner<'pe>>,
    ) -> anyhow::Result<Self> {
        let mut owner = Self {
            address_space,
            controls,
            execution,
            memory,
            endpoint,
            context,
            pending,
            pauth,
            clock,
            thread,
            fp,
        };
        owner.check_resources()?;
        Ok(owner)
    }

    fn check_resources(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.memory.address_space() == Some(self.address_space)
                && self.pauth.address_space() == self.address_space
                && self.clock.address_space() == self.address_space
                && self.thread.address_space() == self.address_space,
            "retained namespace differs"
        );
        anyhow::ensure!(
            self.context.has_supported_header(),
            "unsupported context header"
        );
        self.execution.check()?;
        self.pending
            .check_registry()
            .map_err(|error| anyhow::anyhow!("producer registry: {error:?}"))?;
        self.memory
            .check_event_endpoint(self.endpoint)
            .map_err(|error| anyhow::anyhow!("PE monitor: {error:?}"))?;
        self.memory
            .validate_execution(0)
            .map_err(|error| anyhow::anyhow!("memory domain: {error:?}"))?;
        self.clock
            .check_execution_thread(self.memory)
            .map_err(|error| anyhow::anyhow!("clock publication domain: {error:?}"))?;
        Ok(())
    }
    fn qualify_current_resources(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        self.check_resources()?;
        self.execution
            .check_snapshot(self.controls.identification_snapshot(), system)?;
        if self.execution.link_register() {
            anyhow::ensure!(
                bound.trap().is_none(),
                "LR trap/exception lifecycle is not admitted"
            );
        }
        anyhow::ensure!(
            bound.entry.address_space() == self.address_space,
            "source namespace differs"
        );
        if let Some(instruction) = bound.pauth() {
            let ids = self
                .controls
                .identification_snapshot()
                .ok_or_else(|| anyhow::anyhow!("PAuth identification owner unavailable"))?;
            if matches!(
                instruction.operation,
                PointerAuthenticationOperation::LinkRegister(_)
            ) || self.execution.link_register() && pauth_lr::conditional(instruction.operation)
            {
                let _service = pauth_lr::service(
                    &*self.controls,
                    self.pauth,
                    system,
                    registers,
                    instruction,
                    self.memory,
                    outer,
                )?;
            } else {
                super::pauth_policy::qualify(
                    ids,
                    self.controls.sctlr_el1(),
                    self.controls.tcr_el1(),
                    self.pauth,
                    instruction.operation,
                )?;
            }
        }
        if bound.memory_requirements()?.required_flags
            & stela_compiler::context::memory::flags::ASIMD
            != 0
        {
            let fp = self
                .fp
                .ok_or_else(|| anyhow::anyhow!("low128 FP owner unavailable"))?;
            return low128_call::qualify(
                bound,
                &*self.controls,
                fp,
                self.execution.debug_controls(),
                system,
                registers,
                self.memory,
                self.endpoint,
            );
        }
        // The control producer validates the current EL0/PSTATE/TCO state,
        // source generation, domain, required category and SP specialization.
        // The unused token is dropped before the call; it changes nothing.
        self.controls
            .prepare_profile(
                &bound.entry,
                bound.memory_profile()?,
                bound.memory_requirements()?,
                system,
                self.execution.debug_controls(),
                registers,
                self.memory,
                Some(self.endpoint),
            )
            .map_err(|error| anyhow::anyhow!("process controls: {error:?}"))?;
        Ok(())
    }
}

pub(super) mod sealed {
    pub(crate) trait Concrete {}
}
#[cfg(feature = "std")]
impl sealed::Concrete for CheckedProcessOwner<'_> {}

/// Only this module can implement a backend.
pub(crate) trait Owner: sealed::Concrete {
    fn supports_profile(&self, profile: stela_compiler::block::BlockProfile) -> bool {
        profile.checked_memory().is_some()
            || matches!(
                profile,
                stela_compiler::block::BlockProfile::El1DirectBranchV1
                    | stela_compiler::block::BlockProfile::El1M0IntegerV1
            )
    }
    fn qualify_debug_lifecycle(
        &self,
        debug: Option<&crate::system::debug::halted::DebugMachine>,
        _system: &SystemState,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(debug.is_none(), "backend has no lifecycle consumer");
        Ok(())
    }
    fn complete_system(
        &mut self,
        _bound: &BoundSource<'_>,
        _boundary: &Boundary,
        _system: &mut SystemState,
        _registers: &mut GuestState,
        _debug: Option<&mut crate::system::debug::halted::DebugMachine>,
        _outer: &MemoryExecutionLoan,
    ) -> super::privileged::SystemOutcome {
        super::privileged::SystemOutcome::NoEffect(anyhow::anyhow!("System owner unavailable"))
    }

    fn execution_loan(&mut self) -> anyhow::Result<MemoryExecutionLoan>;
    fn prepare_source(
        &mut self,
        _runtime: &mut crate::blocks::BlockRuntime,
        _system: &SystemState,
        _pc: GuestAddress,
        _outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    fn qualify(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()>;
    /// Lend this backend's own fields once. The consumer keeps them through
    /// source and control validation, preparation, the native call,
    /// finalization and PC settlement.
    fn split_m0_resources(&mut self) -> anyhow::Result<M0ExecutionResources<'_>> {
        anyhow::bail!("M0 backend resources are unavailable")
    }

    /// Only the installed EL1 owner lends these fields; other backends refuse
    /// before the call.
    fn split_el1_resources(&mut self) -> anyhow::Result<El1ExecutionResources<'_>> {
        anyhow::bail!("installed branch backend resources are unavailable")
    }

    /// Mutable publication and monitor access, after all native borrows end.
    fn split_el1_system_effect_resources(
        &mut self,
    ) -> anyhow::Result<El1SystemEffectResources<'_>> {
        anyhow::bail!("owner has no original System completion resources")
    }

    fn split_el1_context_resources(&mut self) -> anyhow::Result<El1ContextResources<'_>> {
        anyhow::bail!("EL1 context resources are unavailable")
    }

    fn invoke(
        &mut self,
        bound: &BoundSource<'_>,
        system: &mut SystemState,
        registers: &mut GuestState,
    ) -> anyhow::Result<NativeObservation>;
    fn complete_helper(
        &mut self,
        helper: &Helper,
        system: &SystemState,
        registers: &mut GuestState,
        outer: Option<&MemoryExecutionLoan>,
    ) -> HelperOutcome;
    fn complete_trap(
        &mut self,
        trap: &stela_compiler::block::SynchronousTrap,
        system: &SystemState,
        registers: &mut GuestState,
        events: &mut super::darwin_services::TrapServiceEvents,
    ) -> super::darwin_services::Outcome;
    fn post_retirement(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()>;
}

#[cfg(feature = "std")]
impl Owner for CheckedProcessOwner<'_> {
    fn execution_loan(&mut self) -> anyhow::Result<MemoryExecutionLoan> {
        self.memory
            .execution_loan()
            .map_err(|error| anyhow::anyhow!("domain exclusion: {error:?}"))
    }
    fn qualify(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        self.qualify_current_resources(bound, system, registers, outer)?;
        // Pointer operands may come from the ordinary prefix (including a
        // loaded LR or SP), so they are checked only at the helper, after the
        // prefix settles.
        Ok(())
    }
    fn invoke(
        &mut self,
        bound: &BoundSource<'_>,
        system: &mut SystemState,
        registers: &mut GuestState,
    ) -> anyhow::Result<NativeObservation> {
        if bound.memory_requirements()?.required_flags
            & stela_compiler::context::memory::flags::ASIMD
            != 0
        {
            let fp = self
                .fp
                .ok_or_else(|| anyhow::anyhow!("low128 FP owner unavailable"))?;
            return low128_call::call(
                bound,
                &*self.controls,
                fp,
                self.execution.debug_controls(),
                system,
                registers,
                self.memory,
                self.endpoint,
                self.context,
            );
        }
        let mut dispatcher = ProcessDispatcher {
            address_space: self.address_space,
            controls: &*self.controls,
            debug: self.execution.debug_controls(),
            system,
            memory: self.memory,
            endpoint: self.endpoint,
            bound,
        };
        // SAFETY: the caller holds the native session and the domain borrow;
        // the source, plan, map and context stay borrowed through the call and
        // every finalizer.
        let returned = unsafe {
            checked_memory::call(
                &mut dispatcher,
                &bound.entry,
                bound.source,
                &bound.block.prepared.manifest.source_map,
                bound.memory_profile()?.process_memory_profile_id(),
                bound.memory_requirements()?,
                &bound.block.mapping,
                registers,
                self.context,
            )?
        };
        // Conversion of the raw result into the public type, for reporting.
        Ok(match returned {
            checked_memory::CheckedReturn::Returned(exit) => NativeObservation::Returned {
                next_pc: exit.next_pc,
                kind: exit.kind,
            },
            checked_memory::CheckedReturn::MemoryFault(fault) => {
                NativeObservation::Fault(fault.into())
            }
            checked_memory::CheckedReturn::CpuDeclined(error) => {
                NativeObservation::CpuDeclined(format!("{error:?}"))
            }
            checked_memory::CheckedReturn::EntryDeclined(status) => {
                NativeObservation::EntryDeclined(status)
            }
            checked_memory::CheckedReturn::FinalizationFailed {
                status,
                native_executed,
                original_fault,
                completed_bytes,
                observed_exit,
                native_invoked,
                callback_failure,
                raw_memory,
                raw_returned_carrier,
            } => NativeObservation::FinalizationFailed {
                status,
                native_executed,
                original_fault: original_fault.map(Into::into),
                completed_bytes,
                observed_exit,
                native_invoked: Some(native_invoked),
                callback_failure,
                raw_memory: raw_memory.map(raw_memory_observation),
                raw_returned_carrier,
            },
            checked_memory::CheckedReturn::InvocationFailed {
                detail,
                native_invoked,
                native_executed,
                original_fault,
                raw_memory,
                completed_bytes,
                observed_exit,
                raw_returned_carrier,
            } => NativeObservation::InvocationFailed {
                detail,
                native_invoked,
                native_executed,
                original_fault: original_fault.map(Into::into),
                raw_memory: raw_memory.map(raw_memory_observation),
                completed_bytes,
                observed_exit,
                raw_returned_carrier,
            },
        })
    }

    fn complete_helper(
        &mut self,
        helper: &Helper,
        system: &SystemState,
        registers: &mut GuestState,
        outer: Option<&MemoryExecutionLoan>,
    ) -> HelperOutcome {
        // The consumer has already stored the terminal PC.
        if let Err(error) = self.check_resources() {
            return HelperOutcome::NoEffect(error);
        }
        match helper {
            Helper::Pauth(instruction) => {
                if matches!(
                    instruction.operation,
                    PointerAuthenticationOperation::LinkRegister(_)
                ) || self.execution.link_register()
                    && pauth_lr::conditional(instruction.operation)
                {
                    let prepared = (|| -> anyhow::Result<pauth_lr::Prepared> {
                        let outer = outer
                            .ok_or_else(|| anyhow::anyhow!("LR outer exclusion unavailable"))?;
                        let service = pauth_lr::service(
                            &*self.controls,
                            self.pauth,
                            system,
                            registers,
                            *instruction,
                            self.memory,
                            outer,
                        )?;
                        pauth_lr::prepare(*instruction, &service)
                    })();
                    return match prepared {
                        Ok(pauth_lr::Prepared::Effect(effect)) => HelperOutcome::PreparedPauth {
                            instruction: *instruction,
                            effect,
                        },
                        Ok(pauth_lr::Prepared::AuthenticationFault { code }) => {
                            HelperOutcome::AuthenticationFault {
                                instruction: *instruction,
                                code,
                            }
                        }
                        Err(error) => HelperOutcome::NoEffect(error),
                    };
                }
                if let Err(error) =
                    super::pauth_policy::qualify_pointer(instruction.operation, registers)
                {
                    return HelperOutcome::NoEffect(error);
                }
                if matches!(
                    instruction.operation,
                    PointerAuthenticationOperation::Load(_)
                ) {
                    return HelperOutcome::NoEffect(anyhow::anyhow!(
                        "LDRA has no qualified checked reader"
                    ));
                }
                // FPACCombined failure precedes register/link writes. Classic AUT
                // poison and failed transfer link effects remain architectural.
                // Conservative generic errors
                // remain Indeterminate; no detached error-class proof grants Ready.
                match complete_pauth_with_memory(self.pauth, instruction, registers, None) {
                    Ok((continuation, authenticated)) => HelperOutcome::Complete {
                        continuation,
                        event: HelperEvent::Pauth(PointerAuthenticationEvent {
                            instruction: *instruction,
                            next_pc: continuation,
                            authenticated,
                        }),
                    },
                    Err(error) => HelperOutcome::Indeterminate(error),
                }
            }
            Helper::Clock(instruction) => {
                // Native exclusion was released after PC settled, and
                // publication takes the domain's service borrow.
                match complete_clock(self.clock, instruction, registers) {
                    Ok(counter) => HelperOutcome::Complete {
                        continuation: instruction.next_pc,
                        event: HelperEvent::Clock(ClockEvent {
                            instruction: *instruction,
                            next_pc: instruction.next_pc,
                            counter,
                        }),
                    },
                    // Sampling/publication may have happened; generic Err is
                    // NEVER classified NoEffect merely because Rd is unchanged.
                    Err(error) => HelperOutcome::Indeterminate(error),
                }
            }
            Helper::Thread(instruction) => {
                if instruction.destination >= 32 {
                    return HelperOutcome::NoEffect(anyhow::anyhow!("invalid TSD destination"));
                }
                let value = self.thread.thread_specific_data();
                if instruction.destination != 31 {
                    registers.x[usize::from(instruction.destination)] = value;
                }
                HelperOutcome::Complete {
                    continuation: instruction.next_pc,
                    event: HelperEvent::Thread(ThreadRegisterEvent {
                        instruction: *instruction,
                        next_pc: instruction.next_pc,
                        value,
                    }),
                }
            }
        }
    }
    fn complete_trap(
        &mut self,
        trap: &stela_compiler::block::SynchronousTrap,
        _system: &SystemState,
        registers: &mut GuestState,
        events: &mut super::darwin_services::TrapServiceEvents,
    ) -> super::darwin_services::Outcome {
        if let Err(error) = self.check_resources() {
            return super::darwin_services::Outcome::Indeterminate(error);
        }
        // The consumer settles PC; this backend lends only its thread.
        super::darwin_services::complete(trap, registers, self.thread, events)
    }

    fn post_retirement(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        // Fail if any event producer is registered. A completed helper has
        // changed its operand (for example, signing LR), so re-validate the
        // current resources without treating that output as the input of
        // another helper.
        self.qualify_current_resources(bound, system, registers, outer)
    }
}

/// Short-lived borrows of the system, control and domain resources.
#[cfg(feature = "std")]
struct ProcessDispatcher<'call, 'code> {
    address_space: u64,
    controls: &'call FixedProcessMemoryControls,
    debug: &'call crate::system::debug::DebugControls,
    system: &'call SystemState,
    memory: &'call mut MemoryThread<MemoryControls>,
    endpoint: &'call EventEndpoint,
    bound: &'call BoundSource<'code>,
}
#[cfg(feature = "std")]
impl Dispatcher for ProcessDispatcher<'_, '_> {
    fn address_space(&self) -> u64 {
        self.address_space
    }
    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        registers: &GuestState,
    ) -> Result<(), Failure> {
        if boundary.address_space() != self.address_space
            || boundary.entry() != self.bound.entry.entry()
            || boundary.generation() != self.bound.entry.generation()
            || source != self.bound.source
        {
            return Err(Failure::WrongAddressSpace);
        }
        self.controls
            .prepare_profile(
                boundary,
                self.bound
                    .memory_profile()
                    .map_err(|error| Failure::Backend(error.to_string()))?,
                self.bound
                    .memory_requirements()
                    .map_err(|error| Failure::Backend(error.to_string()))?,
                self.system,
                self.debug,
                registers,
                self.memory,
                Some(self.endpoint),
            )
            .map_err(|error| Failure::Backend(format!("{error:?}")))?;
        Ok(())
    }
    fn prepare_memory_entry<'run>(
        &'run mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        requirements: MemoryRequirements,
        registers: &GuestState,
    ) -> Result<PreparedProcessMemory<'run>, Failure> {
        self.validate_entry(boundary, source, registers)?;
        if requirements
            != self
                .bound
                .memory_requirements()
                .map_err(|error| Failure::Backend(error.to_string()))?
        {
            return Err(Failure::Unsupported("source requirements mismatch"));
        }
        self.controls
            .prepare_profile(
                boundary,
                self.bound
                    .memory_profile()
                    .map_err(|error| Failure::Backend(error.to_string()))?,
                requirements,
                self.system,
                self.debug,
                registers,
                self.memory,
                Some(self.endpoint),
            )
            .map_err(|error| Failure::Backend(format!("{error:?}")))
    }
    fn complete(
        &mut self,
        _boundary: Boundary,
        _registers: &mut GuestState,
    ) -> Result<GuestAddress, Failure> {
        Err(Failure::Unsupported(
            "checked helper consumer owns completion; no loose dispatcher route",
        ))
    }
}

pub(crate) enum HelperOutcome {
    #[cfg(feature = "std")]
    PreparedPauth {
        instruction: stela_compiler::block::PointerAuthentication,
        effect: pauth_lr::PreparedEffect,
    },
    #[cfg(feature = "std")]
    AuthenticationFault {
        instruction: stela_compiler::block::PointerAuthentication,
        code: u8,
    },
    NoEffect(anyhow::Error),
    #[cfg(feature = "std")]
    Complete {
        continuation: GuestAddress,
        event: HelperEvent,
    },
    Indeterminate(anyhow::Error),
}
#[cfg(feature = "std")]
pub(crate) enum HelperEvent {
    Pauth(PointerAuthenticationEvent),
    Clock(ClockEvent),
    Thread(ThreadRegisterEvent),
}
#[cfg(feature = "std")]
impl HelperEvent {
    pub(super) fn poisoned_transfer(
        &self,
    ) -> Option<(stela_compiler::block::PointerAuthentication, GuestAddress)> {
        match self {
            Self::Pauth(event)
                if event.instruction.operation.is_transfer()
                    && event.authenticated == Some(false) =>
            {
                Some((event.instruction, event.next_pc))
            }
            _ => None,
        }
    }
    pub(super) fn record(self, accounting: &mut RunOutcome) {
        match self {
            Self::Pauth(event) => accounting.pointer_authentication_events.push(event),
            Self::Clock(event) => accounting.clock_events.push(event),
            Self::Thread(event) => accounting.thread_register_events.push(event),
        }
    }
}

// This module owns these private concrete resource fields. No generic
// provider or caller callback is involved.
#[cfg(feature = "std")]
impl CheckedProcessOwner<'_> {
    pub(crate) fn observe_retained(
        &self,
        _owner: crate::system::execution::owner::OwnerKey,
        actual: &crate::blocks::ThreadState,
    ) -> anyhow::Result<super::observation::OwnedProcessObservation> {
        anyhow::ensure!(
            self.memory.address_space() == Some(self.address_space)
                && self.clock.address_space() == self.address_space
                && self.thread.address_space() == self.address_space,
            "retained observation namespace differs"
        );
        // Equal namespace numbers do not prove the clock alias still belongs to
        // this thread's domain and backing.
        self.clock
            .check_execution_thread(self.memory)
            .map_err(|error| anyhow::anyhow!("observation clock binding: {error:?}"))?;
        let region = self.clock.region();
        let full_virtual_bytes = usize::try_from(region.virtual_bytes)?;
        anyhow::ensure!(
            region.guest_address == crate::commpage::legacy::GUEST_BASE
                && full_virtual_bytes == crate::commpage::legacy::GUEST_BYTES,
            "retained clock facade extent differs"
        );
        let loan = self
            .memory
            .observation_loan()
            .map_err(|error| anyhow::anyhow!("observation domain exclusion: {error:?}"))?;
        // Snapshot through the existing borrow; `clock.snapshot_bytes()` would
        // take a second, nested service borrow.
        let legacy_clock_bytes = loan
            .snapshot(region.guest_address, full_virtual_bytes)
            .map_err(|error| anyhow::anyhow!("clock facade observation: {error:?}"))?;
        let observation = super::observation::OwnedProcessObservation {
            actual_pc: actual.pc,
            registers: actual.registers.clone(),
            legacy_clock_bytes,
            clock_events: self.clock.events().to_vec(),
            thread: self.thread.snapshot(),
        };
        // Every field has been copied before releasing the service guard. This
        // diagnostic operation never samples/publishes the clock or mutates the
        // register bank, thread rights, PE phase, source or memory generation.
        drop(loan);
        Ok(observation)
    }
}

#[cfg(feature = "std")]
fn raw_memory_observation(
    raw: checked_memory::RawMemoryObservation,
) -> super::RawMemoryObservation {
    super::RawMemoryObservation {
        status_code: raw.status_code,
        address: raw.address,
        pc: raw.pc,
        completed_bytes: raw.completed_bytes,
    }
}
