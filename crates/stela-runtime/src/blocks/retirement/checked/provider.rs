//! Concrete fresh-software EL0 checked-memory/PAC/clock/TSD owner. No blanket
//! provider, stored Dispatcher, caller callback, second CPU or copied System.
use super::super::super::{checked_memory, complete_clock, complete_pauth_with_memory};
use super::super::software_async::NoAsyncSources;
use super::NativeObservation;
use super::low128_call;
use super::source::{BoundSource, Helper};
use crate::{
    blocks::{ClockEvent, PointerAuthenticationEvent, RunOutcome, ThreadRegisterEvent},
    clock,
    memory::{
        domain::{MemoryExecutionLoan, MemoryThread},
        policy::MemoryControls,
    },
    pauth,
    system::{
        debug::DebugControls,
        events::EventEndpoint,
        execution::{Boundary, Dispatcher, EntryBoundary, Failure},
        process_memory::{FixedProcessMemoryControls, PreparedProcessMemory},
        profile::{BaseSpeAbsence, EntryProfile},
        scalable_controls::fp::FpControlOwner,
        state::SystemState,
    },
    thread,
};
use stela_compiler::{
    GuestAddress, GuestState,
    block::{ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID, PointerAuthenticationOperation},
    context::{ExecutionContext, memory::MemoryRequirements},
};

const MDSCR_SOFTWARE_STEP: u64 = 1;
const MDSCR_KERNEL_DEBUG_ENABLE: u64 = 1 << 13;
const MDSCR_MONITOR_DEBUG_ENABLE: u64 = 1 << 15;
const MDSCR_ACTIVE_DEBUG: u64 =
    MDSCR_SOFTWARE_STEP | MDSCR_KERNEL_DEBUG_ENABLE | MDSCR_MONITOR_DEBUG_ENABLE;

/// Actual immutable declaration for a NEW software PE's debug/control subset.
/// EntryProfile has already proved the bounded optional features (including
/// NMI) absent; BaseSpeAbsence covers branch-history effects separately.
pub(crate) struct ProcessEntryControls {
    _features: EntryProfile,
    _spe: BaseSpeAbsence,
    mdscr_el1: u64,
    debug: DebugControls,
}
impl ProcessEntryControls {
    /// # Safety
    /// These are this fresh software PE's sole actual declared debug controls,
    /// not readbacks copied from another mutable CPU. Retain this owner for the
    /// executable PE lifetime. All producers belong to SoftwareAsyncDomain.
    pub(crate) unsafe fn fresh_software(
        features: EntryProfile,
        spe: BaseSpeAbsence,
        mdscr_el1: u64,
        debug: DebugControls,
    ) -> anyhow::Result<Self> {
        let owner = Self {
            _features: features,
            _spe: spe,
            mdscr_el1,
            debug,
        };
        owner.check()?;
        Ok(owner)
    }
    fn check(&self) -> anyhow::Result<()> {
        let debug = self.debug;
        anyhow::ensure!(
            self.mdscr_el1 & MDSCR_ACTIVE_DEBUG == 0
                && !debug.halted
                && !debug.ignore_traps_in_debug
                && !debug.halting_allowed
                && !debug.edscr_tda
                && debug.breakpoint_count == 0
                && debug.watchpoint_count == 0
                && debug.raw_bank == 0
                && debug.effective_bank == 0,
            "unsupported actual debug/step producer state"
        );
        Ok(())
    }
}

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
    ) -> anyhow::Result<()> {
        bound.recheck()?;
        self.check_resources()?;
        anyhow::ensure!(
            bound.entry.address_space() == self.address_space,
            "source namespace differs"
        );
        if let Some(instruction) = bound.pauth() {
            use crate::system::identification::Register;
            use stela_compiler::block::PointerAuthenticationKey as K;
            let ids = self
                .controls
                .identification_snapshot()
                .ok_or_else(|| anyhow::anyhow!("PAuth identification owner unavailable"))?;
            const APA_QARMA5_COMBINED: u64 = 5;
            const APA_SHIFT: u32 = 4;
            const FIELD_MASK: u64 = 15;
            anyhow::ensure!(
                (ids.read(Register::IdAa64Isar1El1)? >> APA_SHIFT) & FIELD_MASK
                    == APA_QARMA5_COMBINED
                    && self.pauth.version() == pauth::Version::FaultingCombined,
                "PAuth key algorithm differs from the actual identification owner"
            );
            const TCR_T0SZ_MASK: u64 = 63;
            const TCR_VA47_T0SZ: u64 = 17;
            const TCR_TBI0: u64 = 1 << 37;
            anyhow::ensure!(
                self.controls.tcr_el1() & (TCR_T0SZ_MASK | TCR_TBI0) == TCR_VA47_T0SZ,
                "PAuth instruction address policy requires actual VA47/iTBI0 controls"
            );
            anyhow::ensure!(
                !matches!(
                    instruction.operation,
                    PointerAuthenticationOperation::Strip { data: true, .. }
                ) && !matches!(instruction.operation.required_key(), Some(K::Da | K::Db)),
                "PAuth data-address policy has no matching actual TCR authority"
            );
            if let Some(key) = instruction.operation.required_key() {
                // June2026 SCTLR_EL1.EnIA/EnIB/EnDA/EnDB, same sole bank as memory.
                const SCTLR_ENIA: u64 = 1 << 31;
                const SCTLR_ENIB: u64 = 1 << 30;
                const SCTLR_ENDA: u64 = 1 << 27;
                const SCTLR_ENDB: u64 = 1 << 13;
                let (key, enable) = match key {
                    K::Ia => (pauth::Key::Ia, SCTLR_ENIA),
                    K::Ib => (pauth::Key::Ib, SCTLR_ENIB),
                    K::Da => (pauth::Key::Da, SCTLR_ENDA),
                    K::Db => (pauth::Key::Db, SCTLR_ENDB),
                };
                anyhow::ensure!(
                    self.controls.sctlr_el1() & enable != 0 && self.pauth.has_key(key),
                    "PAuth disabled controls or unavailable actual key are unsupported"
                );
            }
            anyhow::ensure!(
                !matches!(
                    instruction.operation,
                    PointerAuthenticationOperation::GenericCode(_)
                ),
                "generic authentication identification authority is unsupported"
            );
        }
        if bound.requirements.required_flags & stela_compiler::context::memory::flags::ASIMD != 0 {
            let fp = self
                .fp
                .ok_or_else(|| anyhow::anyhow!("actual low128 FP owner unavailable"))?;
            return low128_call::qualify(
                bound,
                &*self.controls,
                fp,
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
            .prepare(
                &bound.entry,
                bound.requirements,
                system,
                registers,
                self.memory,
                Some(self.endpoint),
            )
            .map_err(|error| anyhow::anyhow!("actual process controls: {error:?}"))?;
        Ok(())
    }
}

mod sealed {
    pub(crate) trait Concrete {}
}
impl sealed::Concrete for CheckedProcessOwner<'_> {}

/// Only this source module can implement the canonical consumer's backend.
pub(crate) trait Owner: sealed::Concrete {
    fn execution_loan(&mut self) -> anyhow::Result<MemoryExecutionLoan>;
    fn qualify(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
    ) -> anyhow::Result<()>;
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
    ) -> HelperOutcome;
    fn complete_trap(
        &mut self,
        trap: &stela_compiler::block::SynchronousTrap,
        system: &SystemState,
        registers: &mut GuestState,
        events: &mut Vec<crate::mach::Event>,
    ) -> anyhow::Result<Option<GuestAddress>>;
    fn post_retirement(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
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
    ) -> anyhow::Result<()> {
        self.qualify_current_resources(bound, system, registers)?;
        if let Some(instruction) = bound.pauth() {
            // Qualify the pointer before any native prefix can replace it.
            // Prefix-dependent PAC operands need a separate source-effect proof.
            anyhow::ensure!(
                instruction.instruction_pc == bound.entry.entry(),
                "PAuth pointer prefix is not qualified by the fixed address policy"
            );
            use stela_compiler::block::PointerAuthenticationOperation as O;
            const LINK_REGISTER: u8 = 30;
            const ZERO_REGISTER: u8 = 31;
            let pointer_register = match instruction.operation {
                O::SignIbSp | O::AuthenticateIbSp | O::ReturnIbSp | O::ReturnIaSp => {
                    Some(LINK_REGISTER)
                }
                O::Sign { destination, .. }
                | O::Authenticate { destination, .. }
                | O::Strip { destination, .. } => Some(destination),
                O::Branch { target, .. } => Some(target),
                O::GenericCode(_) | O::Load(_) => None,
            };
            if let Some(register) = pointer_register {
                let pointer = if register == ZERO_REGISTER {
                    0
                } else {
                    registers.x[usize::from(register)]
                };
                const UPPER_REGION: u64 = 1 << 55;
                anyhow::ensure!(
                    pointer & UPPER_REGION == 0,
                    "upper-region PAuth inputs are unsupported"
                );
                if matches!(instruction.operation, O::SignIbSp | O::Sign { .. }) {
                    const VA47_ADDRESS_MASK: u64 = (1 << 47) - 1;
                    anyhow::ensure!(
                        pointer & !VA47_ADDRESS_MASK == 0,
                        "noncanonical lower signing input is unsupported"
                    );
                }
            }
        }
        Ok(())
    }
    fn invoke(
        &mut self,
        bound: &BoundSource<'_>,
        system: &mut SystemState,
        registers: &mut GuestState,
    ) -> anyhow::Result<NativeObservation> {
        if bound.requirements.required_flags & stela_compiler::context::memory::flags::ASIMD != 0 {
            let fp = self
                .fp
                .ok_or_else(|| anyhow::anyhow!("actual low128 FP owner unavailable"))?;
            return low128_call::call(
                bound,
                &*self.controls,
                fp,
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
                ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID,
                bound.requirements,
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
        _system: &SystemState,
        registers: &mut GuestState,
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
                    PointerAuthenticationOperation::Load(_)
                ) {
                    return HelperOutcome::NoEffect(anyhow::anyhow!(
                        "LDRA has no qualified checked reader"
                    ));
                }
                // Existing helper performs all fallible authentication/signing
                // before its register/link write. Conservative generic errors
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
        events: &mut Vec<crate::mach::Event>,
    ) -> anyhow::Result<Option<GuestAddress>> {
        use crate::{darwin::SYSCALL_SELECTOR_REGISTER, mach};
        let selector = registers.x[SYSCALL_SELECTOR_REGISTER] as u32 as i32;
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
        self.check_resources()?;
        // Source settlement and SystemActive were established by the canonical
        // consumer. This adapter has no actual PC or authority accessor.
        let pending = mach::PendingCall::from_registers(trap.instruction_pc, registers, trap, 0)?;
        let mut event = mach::Event {
            trap: *trap,
            request: Some(pending.request().clone()),
            result: None,
            declined: None,
        };
        let result = self.thread.ports_mut().request(pending.request());
        match &result {
            Ok(value) => event.result = Some(*value),
            Err(error) => event.declined = Some(error.to_string()),
        }
        // Preserve the actual host attempt before any later validation fails.
        events.push(event);
        let value = result?;
        Ok(Some(pending.complete_registers(registers, value)?))
    }
    fn post_retirement(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        registers: &mut GuestState,
    ) -> anyhow::Result<()> {
        // This is an actual exhaustive registry lease, not an empty queue test
        // or successful pending-delivery stub. Any registered producer fails.
        // A completed helper has changed its operand (for example, signing
        // LR). Revalidate current resources without treating that output as
        // the original input to a second helper invocation.
        self.qualify_current_resources(bound, system, registers)
    }
}

/// Ephemeral borrows of SAME actual system/control/domain resources; no state.
struct ProcessDispatcher<'call, 'code> {
    address_space: u64,
    controls: &'call FixedProcessMemoryControls,
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
            .prepare(
                boundary,
                self.bound.requirements,
                self.system,
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
        if requirements != self.bound.requirements {
            return Err(Failure::Unsupported("source requirements mismatch"));
        }
        self.controls
            .prepare(
                boundary,
                requirements,
                self.system,
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
