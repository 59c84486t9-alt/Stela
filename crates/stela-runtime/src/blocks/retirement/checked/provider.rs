//! Concrete fresh-software EL0 checked-memory/PAC/clock/TSD owner. No blanket
//! provider, stored Dispatcher, caller callback, second CPU or copied System.
mod m0_owner;
mod resources;
pub(crate) use m0_owner::M0Owner;
pub(super) use resources::M0ExecutionChecks;
pub(crate) use resources::{El1ContextResources, El1ExecutionResources, M0ExecutionResources};

use super::super::super::{checked_memory, complete_clock, complete_pauth_with_memory};
use super::super::software_async::NoAsyncSources;
use super::NativeObservation;
use super::source::{BoundSource, Helper};
use super::{low128_call, pauth_lr};
use crate::{
    blocks::{ClockEvent, PointerAuthenticationEvent, RunOutcome, ThreadRegisterEvent},
    clock,
    memory::{
        domain::{MemoryExecutionLoan, MemoryThread},
        policy::MemoryControls,
    },
    pauth,
    system::{
        events::EventEndpoint,
        execution::{Boundary, Dispatcher, EntryBoundary, Failure},
        process_memory::{FixedProcessMemoryControls, PreparedProcessMemory},
        scalable_controls::fp::FpControlOwner,
        state::SystemState,
    },
    thread,
};
use stela_compiler::{
    GuestAddress, GuestState,
    block::PointerAuthenticationOperation,
    context::{ExecutionContext, memory::MemoryRequirements},
};

use super::entry_controls::ProcessEntryControls;
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
impl<'pe> CheckedProcessOwner<'pe> {
    /// # Safety
    /// Called once by the actual fresh software machine constructor before it
    /// creates its sole SystemExecutionOwner. Every resource is actual same-PE,
    /// same-namespace and lifetime-held; controls own original SCTLR/TCR facts,
    /// execution owns the actual declared debug/optional-feature subset, and
    /// pending borrows the COMPLETE producer universe. This cannot adopt a live
    /// hardware PE or mint a backend for copied diagnostics. No raw producer,
    /// mutable control alias, alternate native entry or source writer bypasses
    /// the retained machine. Clock publication is already canonically bound.
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
            "actual retained namespace differs"
        );
        anyhow::ensure!(
            self.context.has_supported_header(),
            "unsupported actual context header"
        );
        self.execution.check()?;
        self.pending
            .check_registry()
            .map_err(|error| anyhow::anyhow!("actual producer registry: {error:?}"))?;
        self.memory
            .check_event_endpoint(self.endpoint)
            .map_err(|error| anyhow::anyhow!("actual PE monitor: {error:?}"))?;
        self.memory
            .validate_execution(0)
            .map_err(|error| anyhow::anyhow!("actual memory domain: {error:?}"))?;
        self.clock
            .check_execution_thread(self.memory)
            .map_err(|error| anyhow::anyhow!("actual clock publication domain: {error:?}"))?;
        Ok(())
    }
    fn qualify_current_resources(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        bound.recheck()?;
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
                .ok_or_else(|| anyhow::anyhow!("actual low128 FP owner unavailable"))?;
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
        // The actual CPU/control producer validates current EL0/PSTATE/TCO,
        // source generation/domain, required category and SP specialization.
        // The unused token is dropped before FFI: it changes no policy/effect.
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
            .map_err(|error| anyhow::anyhow!("actual process controls: {error:?}"))?;
        Ok(())
    }
}

pub(super) mod sealed {
    pub(crate) trait Concrete {}
}
impl sealed::Concrete for CheckedProcessOwner<'_> {}

/// Only this source module can implement the canonical consumer's backend.
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
        anyhow::ensure!(debug.is_none(), "backend has no actual lifecycle consumer");
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
    /// One disjoint loan of this concrete backend's ORIGINAL fields. No
    /// caller/resource tuple, context clone or second backend can supply it.
    /// The canonical Active retains this through real source/control mint,
    /// no-read preparation, FFI/finalization and once-only PC settlement.
    fn split_m0_resources(&mut self) -> anyhow::Result<M0ExecutionResources<'_>> {
        anyhow::bail!("actual M0 backend resources are unavailable")
    }

    /// Only the SAME concrete installed owner in its exact B cohort can lend
    /// these original fields. All other sealed owners refuse before FFI.
    fn split_el1_resources(&mut self) -> anyhow::Result<El1ExecutionResources<'_>> {
        anyhow::bail!("actual installed branch backend resources are unavailable")
    }

    /// Actual mutable publication/monitor loan, after all native loans end.
    fn split_el1_context_resources(&mut self) -> anyhow::Result<El1ContextResources<'_>> {
        anyhow::bail!("actual EL1 context resources are unavailable")
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

impl Owner for CheckedProcessOwner<'_> {
    fn execution_loan(&mut self) -> anyhow::Result<MemoryExecutionLoan> {
        self.memory
            .execution_loan()
            .map_err(|error| anyhow::anyhow!("actual domain exclusion: {error:?}"))
    }
    fn qualify(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        self.qualify_current_resources(bound, system, registers, outer)?;
        // Pointer operands may be produced by the ordinary prefix (including
        // loaded LR/SP). They are qualified only at the actual source-validated
        // helper boundary, after the canonical consumer settles that prefix.
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
                .ok_or_else(|| anyhow::anyhow!("actual low128 FP owner unavailable"))?;
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
        // SAFETY: the canonical caller retains NativeActive and the same-domain
        // outer loan; exact source/plan/map/context owners above remain borrowed
        // through call's complete outer Result and every checked finalizer.
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
        // This conversion is descriptive only. Canonical consumer invokes this
        // sealed actual owner synchronously; no API accepts a saved observation
        // as completion/Ready authority. Narrow raw component types stay private.
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
        // Actual terminal PC was already stored by the consumer, which retains
        // it exclusively; this provider receives no PC/authority accessor.
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
                        let outer = outer.ok_or_else(|| {
                            anyhow::anyhow!("actual LR outer exclusion unavailable")
                        })?;
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
                // The canonical consumer released native exclusion only after
                // SystemActive and actual source settlement. Publication itself
                // acquires the same domain's real service_loan. No raw fallback.
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
        // Source settlement and SystemActive belong to canonical Active. This
        // owner lends only its actual thread; no PC or authority accessor escapes.
        super::darwin_services::complete(trap, registers, self.thread, events)
    }

    fn post_retirement(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        // This is an actual exhaustive registry lease, not an empty queue test
        // or successful pending-delivery stub. Any registered producer fails.
        // A completed helper has changed its operand (for example, signing
        // LR). Revalidate current resources without treating that output as
        // the original input to a second helper invocation.
        self.qualify_current_resources(bound, system, registers, outer)
    }
}

/// Ephemeral borrows of SAME actual system/control/domain resources; no state.
struct ProcessDispatcher<'call, 'code> {
    address_space: u64,
    controls: &'call FixedProcessMemoryControls,
    debug: &'call crate::system::debug::DebugControls,
    system: &'call SystemState,
    memory: &'call mut MemoryThread<MemoryControls>,
    endpoint: &'call EventEndpoint,
    bound: &'call BoundSource<'code>,
}
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
        self.bound
            .recheck()
            .map_err(|error| Failure::Backend(error.to_string()))?;
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
    PreparedPauth {
        instruction: stela_compiler::block::PointerAuthentication,
        effect: pauth_lr::PreparedEffect,
    },
    AuthenticationFault {
        instruction: stela_compiler::block::PointerAuthentication,
        code: u8,
    },
    NoEffect(anyhow::Error),
    Complete {
        continuation: GuestAddress,
        event: HelperEvent,
    },
    Indeterminate(anyhow::Error),
}
pub(crate) enum HelperEvent {
    Pauth(PointerAuthenticationEvent),
    Clock(ClockEvent),
    Thread(ThreadRegisterEvent),
}
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

// Append to blocks::retirement::checked::provider, which owns these private
// concrete resource fields. No generic provider or caller callback is involved.
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
            "actual retained observation namespace differs"
        );
        // Numeric namespace equality alone does not prove the actual publication
        // alias retains this thread's actual domain and bound backing association.
        self.clock
            .check_execution_thread(self.memory)
            .map_err(|error| anyhow::anyhow!("actual observation clock binding: {error:?}"))?;
        let region = self.clock.region();
        let full_virtual_bytes = usize::try_from(region.virtual_bytes)?;
        anyhow::ensure!(
            region.guest_address == crate::commpage::legacy::GUEST_BASE
                && full_virtual_bytes == crate::commpage::legacy::GUEST_BYTES,
            "actual retained clock facade extent differs"
        );
        let loan = self
            .memory
            .observation_loan()
            .map_err(|error| anyhow::anyhow!("actual observation domain exclusion: {error:?}"))?;
        // Snapshot through the existing loan: clock.snapshot_bytes() would
        // attempt another service admission and must not be nested here.
        let legacy_clock_bytes = loan
            .snapshot(region.guest_address, full_virtual_bytes)
            .map_err(|error| anyhow::anyhow!("actual clock facade observation: {error:?}"))?;
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
