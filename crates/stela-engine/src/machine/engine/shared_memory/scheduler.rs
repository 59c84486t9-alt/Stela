//! Checked native rounds with stopped, owner-local source services. This is a
//! candidate scheduler, not admission of a boot device/DMA/reset resource graph.
use super::super::{RequirementKind, Step, Stop, processors::Peer, publication};
use super::*;
use stela_compiler::{block::ExitKind, context::memory::MemoryStatus};

fn fault_write(
    access: stela_compiler::context::memory::FaultAccess,
    operation: crate::memory::domain::DataOperation,
    original: crate::memory::backing::AccessKind,
) -> bool {
    use stela_compiler::context::memory::FaultAccess;
    match access {
        FaultAccess::Read => false,
        FaultAccess::Write => true,
        FaultAccess::OriginalSource => {
            operation != crate::memory::domain::DataOperation::Atomic
                && original == crate::memory::backing::AccessKind::Write
        }
    }
}

fn completing<H: Host, D: Devices>(
    machine: &mut Machine<H, D>,
    complete: impl FnOnce(&mut Machine<H, D>) -> Step,
) -> Step {
    let retired = machine.cpu.retired;
    let step = machine.completing(machine.cpu.pc, complete);
    // A refused stopped service has not completed the source instruction.
    // Keep the actual native prefix's retirement; never count a denied word.
    if matches!(step, Err(Stop::Unsupported(_))) {
        machine.cpu.retired = retired;
    }
    step
}

impl<H: Host, T: NativeTransport, D: Devices> Machine<ServiceHost<H, T>, D> {
    /// Publish the assigned physical owners before the first native round.
    pub fn initialize_native_transport(&mut self, owners: Vec<publication::WorkerOwner>) {
        let Some(inventory) = &mut self.native_publication else {
            self.host
                .transport
                .fail_stopped("native initialization requires the actual inventory");
        };
        self.host
            .transport
            .initialize(&mut self.host.local, inventory, owners);
    }

    pub(super) fn hold_native_services(&mut self) -> Result<publication::StoppedWorkers, Stop> {
        let Some(inventory) = &mut self.native_publication else {
            return Err(self.unsupported(RequirementKind::Native(
                "native publication inventory is absent",
            )));
        };
        if let Some(held) = self.host.retained_hold.take() {
            if inventory.require_all_held(&held).is_err() {
                self.host
                    .transport
                    .fail_stopped("retained native hold changed");
            }
            // Stopped source helpers can perform copyout on this BSP between
            // rounds. Idle remote owners have executed no new native frame.
            self.host.local.memory_barrier();
            return Ok(held);
        }
        let held = self
            .host
            .transport
            .hold_all(&mut self.host.local, inventory);
        Ok(self.begin_native_services(held))
    }

    fn begin_native_services(
        &mut self,
        held: publication::StoppedWorkers,
    ) -> publication::StoppedWorkers {
        let inventory = self
            .native_publication
            .as_mut()
            .expect("held native inventory");
        let bindings: Vec<_> = inventory.bindings().collect();
        if inventory.require_all_held(&held).is_err() {
            self.host
                .transport
                .fail_stopped("native source services lack actual held workers");
        }
        let mut services = self.host.take_empty_service_buffer();
        services.reserve(bindings.len());
        for binding in &bindings {
            match inventory.open_services(&held, binding.pe) {
                Ok(service) => services.push(service),
                Err(_) => self
                    .host
                    .transport
                    .fail_stopped("native source Host session admission refused"),
            }
        }
        if self.host.begin_services(services).is_err() {
            self.host
                .transport
                .fail_stopped("native source Host sessions already active");
        }
        // Each actual owner fenced its last stores in WorkerOwner::invalidate
        // before publishing the receipt consumed by hold_all. No guest or
        // device work occurs while these software sessions open. Keep that
        // completed fence instead of sending another command to every owner.
        // Later source/controller writes still use their own checked fences.
        held
    }

    fn retain_native_services(&mut self, held: publication::StoppedWorkers) {
        if self.host.retained_hold.replace(held).is_some() {
            self.host
                .transport
                .fail_stopped("native hold retained twice");
        }
    }

    fn close_native_services(&mut self) {
        let inventory = self
            .native_publication
            .as_mut()
            .expect("held native inventory");
        let mut services = self.host.end_services();
        for service in services.drain(..) {
            if inventory.close_services(service).is_err() {
                self.host
                    .transport
                    .fail_stopped("native Host service did not actually finish");
            }
        }
        self.host.retain_empty_service_buffer(services);
    }

    pub(in crate::machine::engine) fn release_native_services(
        &mut self,
        held: publication::StoppedWorkers,
    ) {
        self.close_native_services();
        self.host.transport.release(
            &mut self.host.local,
            self.native_publication
                .as_mut()
                .expect("held native inventory"),
            held,
        );
    }

    pub(in crate::machine::engine) fn native_source_pe(
        &mut self,
        binding: publication::WorkerBinding,
    ) -> Step {
        if !self.host.select_native_service(binding.worker) {
            return Err(self.unsupported(RequirementKind::Native(
                "source PE has no held physical Host service owner",
            )));
        }
        if binding.pe != self.current {
            if !matches!(self.peers.get(binding.pe), Some(Peer::Parked(_))) {
                return Err(self.unsupported(RequirementKind::Native(
                    "source PE reset/rebind ownership is not active",
                )));
            }
            self.switch_to(binding.pe);
        }
        self.device_lines = None;
        Ok(())
    }

    /// Execute one bounded round on fixed physical workers and settle every
    /// reached source boundary while all actual workers are recovered and held.
    /// No old direct-RAM execution or copied monitor/event state is used.
    ///
    /// # Safety
    /// The full shared_native_run RAM/control/publication contract applies.
    /// External DMA/device jobs and code/MMU writers are excluded or retain the
    /// canonical all-writer authority through this whole call. Host counter and
    /// IRQ delivery are qualified for these assigned workers. Reset/rebind,
    /// Device/MMIO completion, debug/PMU/AMX/scalable resources remain explicit
    /// refusals until their actual platform owners join this candidate. Calling
    /// this method does not enable production SMP or qualify original macOS.
    pub unsafe fn native_round(&mut self) -> Result<usize, Stop> {
        // SAFETY: identical caller contract. One body PER runnable PE, with
        // the complete cohort preserved; a total budget of1 would starve peers.
        unsafe { self.native_round_with_policy(u64::MAX, None, false) }
    }

    /// Execute every online PE in turn on this BSP, through the serial
    /// scheduler and chained native blocks, until `limit` blocks or a stop.
    /// Every assigned physical worker stays held from the first call on, so
    /// no worker executes; Host effects apply to this BSP alone. The PEs keep
    /// their canonical RAM, memory/event and processor owners, and device
    /// accesses consume through them synchronously. Exclusives use the
    /// snapshot monitor, which observes other PEs' writes between slices.
    ///
    /// # Safety
    /// The native_round RAM/control/publication and closed producer contract
    /// applies for the whole serialized run.
    pub unsafe fn run_serialized(&mut self, limit: u64) -> Stop {
        if let Some(pending) = self.pending_native_device_access() {
            return pending;
        }
        // SAFETY: the caller's contract.
        if let Err(stop) = unsafe { self.hold_serialized() } {
            return stop;
        }
        self.run_blocks(limit)
    }

    /// Serialized execution with a soft host-time limit at engine boundaries.
    /// Entered native chains, maintenance and host callbacks may overrun.
    ///
    /// # Safety
    /// The complete [`Self::run_serialized`] contract applies.
    pub unsafe fn run_serialized_with_budget(&mut self, budget: super::super::RunBudget) -> Stop {
        if let Some(failure) = &self.native_failure {
            return Stop::NativeFailure(failure.summary.clone());
        }

        if let Some(pending) = self.pending_native_device_access() {
            return pending;
        }
        // SAFETY: the caller retains the run_serialized ownership contract.
        if let Err(stop) = unsafe { self.hold_serialized() } {
            return stop;
        }
        self.run_blocks_with_budget(budget)
    }

    /// Hold every assigned physical worker for [`Self::run_serialized`], as
    /// its first call does, after which their cores take no more of the
    /// native scheduler's work: they can run machines of their own
    /// ([`Self::enter_parallel`]).
    ///
    /// # Safety
    /// The [`Self::run_serialized`] contract applies from this call on.
    pub unsafe fn hold_serialized(&mut self) -> Result<(), Stop> {
        if self.serial_hold.is_none() {
            let held = self.hold_native_services()?;
            self.close_native_services();
            self.serial_hold = Some(held);
            // The fetch and jump caches and the host's shadow tables start
            // from the running PE's regime.
            self.translations_changed();
        }
        Ok(())
    }

    /// Execute at most `body_budget` bodies, allowing warm epochs only for one
    /// instantiated online PE. Other online PEs retain one-body publications.
    /// `deadline` uses Host::counter, not the adjusted guest clock or raw TSC.
    /// A body/service already entered may overrun this soft observation bound.
    ///
    /// # Safety
    /// The complete native_round ownership/producer/physical-worker contract
    /// applies for the whole epoch, including between its checked bodies.
    pub unsafe fn native_round_bounded(
        &mut self,
        body_budget: u64,
        deadline: Option<NativeEpochDeadline>,
    ) -> Result<usize, Stop> {
        // SAFETY: identical complete epoch contract.
        unsafe { self.native_round_with_policy(body_budget, deadline, true) }
    }

    unsafe fn native_round_with_policy(
        &mut self,
        body_budget: u64,
        deadline: Option<NativeEpochDeadline>,
        allow_epochs: bool,
    ) -> Result<usize, Stop> {
        if body_budget == 0 {
            return Ok(0);
        }
        #[cfg(feature = "native-profile")]
        self.host
            .native_timing(super::super::NativeTimingPhase::Begin);
        let mut scratch = core::mem::take(&mut self.host.round_scratch);
        // SAFETY: this wrapper forwards the caller's full native-round contract.
        // Restore only cleared plain metadata on every ordinary Result return;
        // actual loans, receipts and holds keep their existing linear protocol.
        let result = unsafe {
            self.native_round_with_scratch(&mut scratch, body_budget, deadline, allow_epochs)
        };
        scratch.clear();
        self.host.round_scratch = scratch;
        #[cfg(feature = "native-profile")]
        self.host
            .native_timing(super::super::NativeTimingPhase::End);
        result
    }

    unsafe fn native_round_with_scratch(
        &mut self,
        scratch: &mut super::host::RoundScratch,
        body_budget: u64,
        caller_deadline: Option<NativeEpochDeadline>,
        allow_epochs: bool,
    ) -> Result<usize, Stop> {
        // A recovered bus continuation has already entered its instruction.
        // Newly installed host points apply to future entries; they cannot
        // revoke this retained generation or replay its possible effects.
        if let Some(pending) = self.pending_native_device_access() {
            return Err(pending);
        }
        let Some(inventory) = self.native_publication.as_ref() else {
            return Err(self.unsupported(RequirementKind::Native("native workers are not bound")));
        };
        let bindings = &mut scratch.bindings;
        bindings.extend(inventory.bindings());
        if bindings.len() != self.peers.len()
            || self.peers.iter().enumerate().any(|(pe, peer)| {
                let cpu = match peer {
                    Peer::Running if pe == self.current => &self.cpu,
                    Peer::Parked(parked) => parked.cpu(),
                    Peer::Off => return false,
                    _ => return true,
                };
                !cpu.has_canonical_memory()
            })
        {
            return Err(self.unsupported(RequirementKind::Native(
                "native scheduler requires every assigned PE's actual canonical owner",
            )));
        }
        let held = self.hold_native_services()?;
        // Serial fair-share lag cannot represent concurrently executing cores.
        // This lane observes the qualified common host counter without drift.
        self.clock.follow_host();
        let current = bindings
            .iter()
            .find(|binding| binding.pe == self.current)
            .copied()
            .ok_or_else(|| {
                self.unsupported(RequirementKind::Native(
                    "current PE has no assigned physical worker",
                ))
            })?;
        self.native_source_pe(current)?;
        self.take_starts()?;
        let mut limits = if allow_epochs {
            self.native_epoch_limits(body_budget, caller_deadline)?
        } else {
            native_run::Limits::single()
        };
        for binding in bindings.iter() {
            if matches!(self.peers[binding.pe], Peer::Off) {
                continue;
            }
            self.native_source_pe(*binding)?;
            let now = self.now();
            self.poll_devices(now)?;
            self.take_starts()?;
            if let Some(reset) = self.devices.take_reset() {
                return Err(Stop::Reset(reset));
            }
            if !self.ready(binding.pe, now) {
                continue;
            }
            self.wake()?;
            self.deliver_interrupts();
            if let Some(reset) = self.devices.take_reset() {
                return Err(Stop::Reset(reset));
            }
            self.sync_monitor();
            let debug = self.debug_mode();
            if debug.breakpoints || debug.step || self.cpu.pstate.pacm {
                return Err(self.unsupported(RequirementKind::Native(
                    "native debug/single-step/PACM entry is not joined",
                )));
            }
            if !self.cpu.pc.is_multiple_of(4) {
                let mut exception = crate::machine::cpu::Exception::synchronous(
                    crate::machine::exception::Class::PcAlignment,
                    0,
                    self.cpu.pc,
                );
                exception.fault_address = Some(self.cpu.pc);
                self.take(exception);
            } else if self.cpu.pstate.il {
                self.take(crate::machine::cpu::Exception::undefined(self.cpu.pc));
            }
            for boundary in 0..64 {
                // Observe the actual stopped frame before fetching or servicing
                // its instruction, including a source-side exception boundary.
                if self.breakpoints.binary_search(&self.cpu.pc).is_ok() {
                    self.release_native_services(held);
                    return Err(Stop::Breakpoint(self.cpu.pc));
                }
                if self.traces.binary_search(&self.cpu.pc).is_ok() {
                    self.trace(self.cpu.pc);
                }
                if !self.native_entry_check()? {
                    break;
                }
                if boundary == 63 {
                    // A bounded source-check quantum: retain actual progress
                    // and return to host work before preparing another loan.
                    self.retain_native_services(held);
                    return Ok(0);
                }
            }
        }
        // Preflight/source services may have started another PE or changed PMU
        // eligibility. Never infer permission merely from one runnable frame.
        if !self.epoch_eligible() {
            limits = native_run::Limits::single();
        }
        if limits.max_bodies > 1 {
            // Final line refresh/exception entry may change timer bank, PMU
            // context or board/DMA deadlines. Tighten using fresh/cached facts
            // without invoking another effectful board advance after checks.
            let now = self.now();
            let due = [
                crate::machine::timer::epoch_deadline(&self.cpu, now),
                self.cpu.pmu.as_ref().and_then(|pmu| pmu.deadline()),
                self.devices.dma_deadline(),
                self.device_lines.map(|(_, until, _)| until),
            ]
            .into_iter()
            .flatten()
            .min();
            if let Some(due) = due {
                let deadline = self.clock.host_deadline(due);
                limits.deadline = Some(NativeEpochDeadline(
                    limits
                        .deadline
                        .map_or(deadline, |existing| existing.0.min(deadline)),
                ));
            }
        }
        // Preparation can borrow canonical state while physical owners remain
        // held; close only the software Host sessions before constructing loans.
        #[cfg(feature = "native-profile")]
        self.host
            .native_timing(super::super::NativeTimingPhase::SchedulerReady);
        self.close_native_services();
        let preparation_pc = self.cpu.pc;
        let preparation_el = self.cpu.pstate.el;
        let mut cohort = self
            .native_cohort(bindings, true)
            .map_err(|failure| failure.into_stop(preparation_pc, preparation_el))?;
        // A short caller budget must not credit or execute extra PE frames.
        cohort
            .frames
            .truncate(usize::try_from(body_budget).unwrap_or(usize::MAX));
        for frame in &mut cohort.frames {
            frame.limits = limits;
        }
        #[cfg(feature = "native-profile")]
        cohort
            .host
            .native_timing(super::super::NativeTimingPhase::Prepared);
        let expected = &mut scratch.expected;
        expected.extend(cohort.frames.iter().map(|frame| frame.identity().pe));
        let (reports, held) = {
            let host = cohort.host;
            host.transport
                .execute_held(&mut host.local, cohort.inventory, cohort.frames, held)
        };
        #[cfg(feature = "native-profile")]
        self.host
            .native_timing(super::super::NativeTimingPhase::Recovered);
        let held = self.begin_native_services(held);
        if reports.len() != expected.len() {
            self.host
                .transport
                .fail_stopped("native transport returned an incomplete actual cohort");
        }
        let mut executed_bodies = 0usize;
        let mut pending_accesses = Vec::new();
        let seen = &mut scratch.seen;
        seen.reserve(reports.len());
        for mut report in reports {
            let Some(settlement) = report.settlement.take() else {
                self.host
                    .transport
                    .fail_stopped("native source report has no actual recovered frame authority");
            };
            if !expected.contains(&settlement.binding.pe) || seen.contains(&settlement.binding.pe) {
                self.host
                    .transport
                    .fail_stopped("native source report has duplicate/wrong PE authority");
            }
            seen.push(settlement.binding.pe);
            executed_bodies += settlement.executed_bodies as usize;
            match settlement.source_failure {
                Some(policy::Failure::DeviceRead { .. }) => {
                    self.validate_native_source(&settlement)?;
                    pending_accesses
                        .push(super::RecoveredDeviceAccess::Read(settlement.into_read()));
                }
                Some(policy::Failure::DeviceWrite { .. }) => {
                    self.validate_native_source(&settlement)?;
                    pending_accesses
                        .push(super::RecoveredDeviceAccess::Write(settlement.into_write()));
                }
                _ => self.settle_native_source(settlement)?,
            }
        }
        if !pending_accesses.is_empty() {
            return Err(self.queue_device_accesses(pending_accesses, held));
        }
        self.retain_native_services(held);
        Ok(executed_bodies)
    }

    /// All online owners, rather than just runnable frames, participate in
    /// eligibility: even a waiting peer can wake on a store/reservation event.
    fn epoch_eligible(&self) -> bool {
        self.peers
            .iter()
            .filter(|peer| !matches!(peer, Peer::Off))
            .count()
            == 1
            && self.waiting.is_none()
            && self.breakpoints.is_empty()
            && self.traces.is_empty()
            && !self
                .cpu
                .pmu
                .as_ref()
                .is_some_and(|pmu| pmu.has_instruction_deadline())
    }

    fn native_epoch_limits(
        &mut self,
        budget: u64,
        caller: Option<NativeEpochDeadline>,
    ) -> Result<native_run::Limits, Stop> {
        if budget <= 1 || !self.epoch_eligible() {
            return Ok(native_run::Limits::single());
        }
        // A named periodic observation policy still polls devices whose
        // advance returns None. None never certifies an idle board.
        const OBSERVATIONS_PER_SECOND: u64 = 10_000; // 100 microseconds
        let now = self.now();
        // Eligibility leaves one online, nonwaiting PE: no peer timeout or
        // WFE stream contributes here. Already asserted stable timer levels
        // are polled below, rather than becoming a permanently past cutoff.
        let due = [
            crate::machine::timer::epoch_deadline(&self.cpu, now),
            self.cpu.pmu.as_ref().and_then(|pmu| pmu.deadline()),
            self.devices.deadline(now),
            self.devices.dma_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        // deadline() can itself advance devices. Publish any newly produced
        // starts/reset/interrupts before constructing or lending actual frames.
        self.take_starts()?;
        if let Some(reset) = self.devices.take_reset() {
            return Err(Stop::Reset(reset));
        }
        // The ordinary per-PE poll/wake/interrupt/source-check loop follows
        // this effectful preflight, before any frame is prepared.
        if !self.epoch_eligible() {
            return Ok(native_run::Limits::single());
        }
        let host_now = self.host.counter();
        let quantum = crate::machine::timer::system_frequency(&self.cpu)
            .div_ceil(OBSERVATIONS_PER_SECOND)
            .max(1);
        let deadline = due
            .map(|count| self.clock.host_deadline(count))
            .into_iter()
            .chain(caller.map(|deadline| deadline.0))
            .chain(core::iter::once(host_now.saturating_add(quantum)))
            .min()
            .expect("finite observation quantum");
        if deadline <= host_now {
            return Ok(native_run::Limits::single());
        }
        Ok(native_run::Limits {
            max_bodies: usize::try_from(budget)
                .unwrap_or(usize::MAX)
                .min(MAX_NATIVE_EPOCH_BODIES),
            deadline: Some(NativeEpochDeadline(deadline)),
        })
    }

    /// Check the real fetched word before a frame may cross a physical core.
    /// This uses the canonical descriptor/source owner, including precise access-flag faults.
    fn native_entry_check(&mut self) -> Result<bool, Stop> {
        let controls = Controls::capture(&self.cpu, self.profile.name, &self.profile_missing)
            .map_err(|_| {
                self.unsupported(RequirementKind::Native(
                    "native entry controls are unqualified",
                ))
            })?;
        let memory = self
            .cpu
            .canonical_memory
            .as_ref()
            .expect("validated canonical owner");
        match native_run::source::instruction(memory, &controls, self.cpu.pc) {
            Ok((word, guarded)) => {
                if guarded && self.cpu.pstate.btype != 0 && !self.branch_target_compatible(word) {
                    let exception = self
                        .branch_target_exception(self.cpu.pc, word)
                        .expect("incompatible branch target");
                    self.take(exception);
                    return Ok(true);
                }
                let admitted = self.admit(word);
                if admitted != word {
                    if admitted == 0xd503_201f {
                        completing(self, Self::next)?;
                        self.statistics.blocks += 1;
                    } else if admitted == 0 {
                        self.undefined()?;
                    } else {
                        return Err(self.unsupported(RequirementKind::Native(
                            "unqualified source instruction admission replacement",
                        )));
                    }
                    return Ok(true);
                }
                let checks = self.profile.chip.checks(word);
                let denied = crate::machine::streaming::check(&self.cpu, checks);
                match denied {
                    Err(crate::machine::streaming::Denial::FloatingPoint(el)) => {
                        self.take(
                            crate::machine::cpu::Exception::synchronous(
                                crate::machine::exception::Class::FloatingPointAccess,
                                super::super::TRAPPED_AARCH64,
                                self.cpu.pc,
                            )
                            .to(el),
                        );
                        return Ok(true);
                    }
                    Err(crate::machine::streaming::Denial::Sme { el, smtc }) => {
                        self.take(
                            crate::machine::cpu::Exception::synchronous(
                                crate::machine::exception::Class::SmeAccess,
                                smtc,
                                self.cpu.pc,
                            )
                            .to(el),
                        );
                        return Ok(true);
                    }
                    Err(crate::machine::streaming::Denial::Undefined) => {
                        self.undefined()?;
                        return Ok(true);
                    }
                    Err(crate::machine::streaming::Denial::Unimplemented(detail)) => {
                        return Err(self.unsupported(RequirementKind::Native(detail)));
                    }
                    Ok(()) => {}
                }
                if super::super::is_floating_point(word) {
                    if self.cpu.floating_point_trap().is_some() {
                        let exception = self.floating_point_exception(self.cpu.pc);
                        self.take(exception);
                        return Ok(true);
                    }
                    if self.cpu.svcr() & 1 != 0 {
                        return Err(self.unsupported(RequirementKind::Native(
                            "native streaming FP state is not joined",
                        )));
                    }
                }
                if checks.iter().any(|check| {
                    !matches!(
                        check,
                        stela_contracts::chip::Check::Fp | stela_contracts::chip::Check::FpAdvSimd
                    )
                }) {
                    return Err(self.unsupported(RequirementKind::Native(
                        "native scalable/FPMR source service is not joined",
                    )));
                }
                Ok(false)
            }
            Err(native_run::source::FetchFailure::Fault(fault)) => {
                let pc = self.cpu.pc;
                let exception = self.abort(
                    fault,
                    [
                        crate::machine::exception::Class::InstructionAbortLower,
                        crate::machine::exception::Class::InstructionAbortSame,
                    ],
                    fault.instruction_syndrome(),
                    pc,
                    pc,
                );
                self.take(exception);
                Ok(true)
            }
            Err(native_run::source::FetchFailure::Refused(_)) => Err(self.unsupported(
                RequirementKind::Native("canonical native instruction fetch refused"),
            )),
        }
    }

    fn validate_native_source(&mut self, settlement: &native_run::Settlement) -> Step {
        if !Arc::ptr_eq(&settlement.machine, &self.native_memory_identity)
            || self.native_publication.as_ref().is_none_or(|inventory| {
                inventory
                    .require_recovered(settlement.binding, settlement.generation)
                    .is_err()
            })
        {
            return Err(self.unsupported(RequirementKind::Native(
                "stale/foreign native source settlement",
            )));
        }
        self.native_source_pe(settlement.binding)?;
        if self.cpu.pc != settlement.pc || self.cpu.retired != settlement.retired {
            return Err(self.unsupported(RequirementKind::Native(
                "native source frame changed before stopped settlement",
            )));
        }
        if let Some(super::super::NativeExit::Fault(fault)) = settlement.native {
            let failure = Arc::new(super::super::NativeFailure {
                pc: settlement.pc,
                code: None,
                native_offset: fault.offset,
                address: fault.address,
                origin: fault.origin,
                trap: fault.trap,
                error_code: fault.error_code,
                unsettled_chain: None,
                reason: super::super::NativeFailureReason::InternalSite,
                source_record: None,
            });
            self.native_failure = Some(super::super::recovery::CapturedFailure {
                summary: failure.clone(),
                capture: fault,
            });
            return Err(Stop::NativeFailure(failure));
        }
        if settlement.status.is_err() {
            return Err(self.unsupported(RequirementKind::Native(
                "native target/context/return finalization refused",
            )));
        }
        self.statistics.blocks += settlement.executed_bodies;
        self.sync_monitor();
        Ok(())
    }

    fn settle_native_source(&mut self, settlement: native_run::Settlement) -> Step {
        self.validate_native_source(&settlement)?;
        if let Some(fault) = settlement.memory_fault {
            return match settlement.source_failure {
                Some(policy::Failure::Fault {
                    request,
                    address,
                    access,
                    fault: source_fault,
                    ..
                }) => self.data_abort(
                    address,
                    source_fault,
                    fault_write(fault.access, request.operation, access),
                    false,
                ),
                _ if fault.status == MemoryStatus::Alignment => {
                    let Some(word) = settlement.fault_word else {
                        return Err(self.unsupported(RequirementKind::Native(
                            "checked alignment fault lacks its exact source instruction",
                        )));
                    };
                    if super::super::stack_based(word)
                        && self.stack_alignment_checked()
                        && !self.cpu.state.sp.is_multiple_of(16)
                    {
                        self.take(crate::machine::cpu::Exception::synchronous(
                            crate::machine::exception::Class::SpAlignment,
                            0,
                            self.cpu.pc,
                        ));
                        Ok(())
                    } else {
                        let exclusive =
                            stela_compiler::block::decode_system_mode_instruction(
                                stela_compiler::GuestAddress(self.cpu.pc),
                                word,
                            )
                            .ok()
                            .flatten()
                            .and_then(|instruction| match instruction.operation {
                                super::super::SystemOperation::Exclusive(Ok(
                                    stela_compiler::aarch64::exclusive::Operand::Transfer {
                                        base,
                                        kind,
                                        ..
                                    },
                                )) if self.read_register(base) == fault.address => Some(matches!(
                                    kind,
                                    stela_compiler::aarch64::exclusive::Kind::Store { .. }
                                )),
                                _ => None,
                            });
                        if let Some(write) = exclusive {
                            return self.alignment_fault(fault.address, match fault.access {
                                stela_compiler::context::memory::FaultAccess::Read => false,
                                stela_compiler::context::memory::FaultAccess::Write => true,
                                stela_compiler::context::memory::FaultAccess::OriginalSource => write,
                            });
                        }
                        let accesses = self.data_accesses(self.cpu.pc, word).map_err(|detail| {
                            self.unsupported(RequirementKind::Instruction {
                                word,
                                detail: detail.into(),
                            })
                        })?;
                        let Some((access, _)) = accesses
                            .iter()
                            .find(|(access, _)| access.address == fault.address)
                        else {
                            return Err(self.unsupported(RequirementKind::Native(
                                "checked alignment fault does not match its original source access",
                            )));
                        };
                        let write = match fault.access {
                            stela_compiler::context::memory::FaultAccess::Read => false,
                            stela_compiler::context::memory::FaultAccess::Write => true,
                            stela_compiler::context::memory::FaultAccess::OriginalSource => {
                                access.write && !access.read
                            }
                        };
                        self.alignment_fault(fault.address, write)
                    }
                }
                _ => Err(self.unsupported(match settlement.fault_word {
                    Some(word) => RequirementKind::Instruction {
                        word,
                        detail: alloc::format!(
                            "native source memory service remains unexecuted: {fault:?}; source={:?}",
                            settlement.source_failure
                        ),
                    },
                    None => RequirementKind::Native(
                        "native Device/MMIO or unsupported source memory service remains unexecuted",
                    ),
                })),
            };
        }
        let Some(super::super::NativeExit::Exit { kind, .. }) = settlement.native else {
            return Err(self.unsupported(RequirementKind::Native(
                "native Host fault is terminal, not an ARM memory completion",
            )));
        };
        match ExitKind::try_from(kind) {
            Ok(
                ExitKind::Fallthrough
                | ExitKind::Direct
                | ExitKind::Indirect
                | ExitKind::Call
                | ExitKind::Return,
            ) => Ok(()),
            Ok(ExitKind::System) => {
                self.statistics.system_exits += 1;
                use super::super::{Synchronization, SystemOperation};
                if stela_compiler::block::decode_system_mode_instruction(
                    stela_compiler::GuestAddress(self.cpu.pc),
                    settlement.terminal,
                )
                .is_ok_and(|instruction| {
                    instruction.is_some_and(|instruction| {
                        matches!(
                            instruction.operation,
                            SystemOperation::Synchronization(
                                Synchronization::DataCompletion { .. }
                                    | Synchronization::StoreBypassBarrier { .. }
                            )
                        )
                    })
                }) {
                    // All native owners are actually held after their CPU
                    // fences; fence this PE and BSP helper copyout as well.
                    // External Device/DMA/MCC completion remains unqualified.
                    self.host.memory_barrier();
                }
                completing(self, |machine| {
                    machine.system_instruction(settlement.terminal)
                })
            }
            Ok(ExitKind::FloatingPoint) => {
                let Some(Ok(operation)) =
                    stela_compiler::aarch64::FloatingPointOperation::decode(settlement.terminal)
                else {
                    return Err(self.unsupported(RequirementKind::Native(
                        "numerical source exit is not an FP operation",
                    )));
                };
                self.complete_floating_point(settlement.terminal, &operation)
                    .map_err(|_| {
                        self.unsupported(RequirementKind::Instruction {
                            word: settlement.terminal,
                            detail: alloc::format!(
                                "FPCR {:#x} enables a trapped FP exception",
                                self.cpu.state.fpcr
                            ),
                        })
                    })?;
                completing(self, Self::next)
            }
            Ok(ExitKind::PointerAuthentication) => completing(self, |machine| {
                machine.pointer_authentication(settlement.terminal)
            }),
            _ => Err(self.unsupported(RequirementKind::Instruction {
                word: settlement.terminal,
                detail: alloc::string::String::from(
                    "source boundary is unexecuted; native AMX/trap service is not joined",
                ),
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_fault_access_overrides_original_atomic_or_write_intent() {
        use crate::memory::{backing::AccessKind, domain::DataOperation};
        use stela_compiler::context::memory::FaultAccess;
        for operation in [
            DataOperation::Atomic,
            DataOperation::Exclusive,
            DataOperation::Ordered,
            DataOperation::Ordinary,
        ] {
            assert!(!fault_write(
                FaultAccess::Read,
                operation,
                AccessKind::Write
            ));
            assert!(fault_write(FaultAccess::Write, operation, AccessKind::Read));
            assert_eq!(
                fault_write(FaultAccess::OriginalSource, operation, AccessKind::Write),
                operation != DataOperation::Atomic
            );
            assert!(!fault_write(
                FaultAccess::OriginalSource,
                operation,
                AccessKind::Read
            ));
        }
    }
    #[test]
    fn refused_source_clear_does_not_retire_or_change_the_actual_cpu_prefix() {
        let (mut machine, ram, events) = super::super::tests::machine();
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        let memory = machine.cpu.canonical_memory.as_mut().unwrap();
        // Terminal corrupted-owner finalization is an implementation refusal,
        // never an ARM source fault or a completed CLREX.
        let failed = unsafe { memory.memory.with_checked_view(|view| view.version = 0) };
        assert_eq!(failed, Err(MemoryStatus::Domain));
        let before = (
            machine.cpu.state.clone(),
            machine.cpu.pc,
            machine.cpu.retired,
        );
        const CLREX: u32 = 0xd503305f;
        assert!(matches!(
            completing(&mut machine, |machine| machine.system_instruction(CLREX)),
            Err(Stop::Unsupported(_))
        ));
        assert_eq!(
            (
                machine.cpu.state.clone(),
                machine.cpu.pc,
                machine.cpu.retired
            ),
            before
        );
    }
}
