//! Existing AP mailboxes carrying actual native loans and closed Host effects.
//! The BSP retains the Machine; each physical owner retains its own Host.
use super::executor::Executors;
use crate::apic::Apic;
use alloc::{sync::Arc, vec::Vec};
use stela_runtime::machine::{
    Host,
    engine::{
        self, NativeRun, NativeRunIdentity, NativeRunObservation, NativeTransport,
        ServiceTransport,
        publication::{
            self, HostEffectCommand, HostEffectReceipt, WithPayload, WorkerOwner,
            WorkerPublications,
        },
    },
};
use stela_runtime::memory::RegisteredSystemRam;

/// Bounded recent identities suppress loop diagnostics without retaining code,
/// frames or execution authority. Eviction only permits a diagnostic to repeat.
const RECENT_ARTIFACT_DIAGNOSTICS: usize = 256;

pub(crate) struct FixedWorkers<'a> {
    bsp: Option<WorkerOwner>,
    executors: &'a Executors,
    sender: &'a Apic,
    tsc_hz: u64,
    ram: Arc<RegisteredSystemRam>,
    // Diagnostics retain identities, never execution authority or live loans.
    trace_artifacts: bool,
    recent_artifacts: Vec<NativeRunIdentity>,
    next_artifact_slot: usize,
    recovered_rounds: u64,
    progress_reported: u64,
    reported_services: Vec<(publication::WorkerBinding, &'static str)>,
}
impl<'a> FixedWorkers<'a> {
    pub(crate) fn new(
        executors: &'a Executors,
        sender: &'a Apic,
        tsc_hz: u64,
        ram: Arc<RegisteredSystemRam>,
        trace_artifacts: bool,
    ) -> Self {
        Self {
            bsp: None,
            executors,
            sender,
            tsc_hz,
            ram,
            trace_artifacts,
            recent_artifacts: Vec::new(),
            next_artifact_slot: 0,
            recovered_rounds: 0,
            progress_reported: crate::engine::host::rdtsc(),
            reported_services: Vec::new(),
        }
    }
    fn processor(&self, binding: publication::WorkerBinding) -> &super::executor::Processor {
        self.executors
            .processors()
            .iter()
            .find(|processor| processor.slot() == binding.worker.0)
            .unwrap_or_else(|| fail("assigned native physical worker is absent"))
    }
    fn bsp(&mut self) -> &mut WorkerOwner {
        self.bsp
            .as_mut()
            .unwrap_or_else(|| fail("native BSP owner is not initialized"))
    }
    fn is_bsp(&self, binding: publication::WorkerBinding) -> bool {
        self.bsp
            .as_ref()
            .is_some_and(|owner| owner.binding() == binding)
    }
}
fn fail(reason: &'static str) -> ! {
    crate::output::arguments(format_args!(
        "STELA FATAL native scheduler: {reason}; retaining all live ownership\n"
    ));
    loop {
        // SAFETY: fail stopped; no potentially live native loan is unwound or
        // released merely because a mailbox/effect did not complete.
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}
impl ServiceTransport for FixedWorkers<'_> {
    fn apply(
        &mut self,
        local: &mut dyn Host,
        command: HostEffectCommand,
    ) -> Result<HostEffectReceipt, WithPayload<HostEffectCommand>> {
        let binding = command.binding();
        let generation = command.generation();
        let sequence = command.sequence();
        let effect = command.effect_name();
        let result = if self.is_bsp(binding) {
            self.bsp().apply_host_effect(command, local)
        } else {
            self.processor(command.binding())
                .host_effect(command, self.sender, self.tsc_hz)
        };
        if result.is_ok() && !self.reported_services.contains(&(binding, effect)) {
            // Every real effect still executes and returns its actual receipt.
            // Repeating the same fence diagnostic for every block can flood the
            // serial device during an ordinary guest RAM-initialization loop.
            self.reported_services.push((binding, effect));
            crate::output::arguments(format_args!(
                "NATIVE SERVICE applied pe={} worker={} generation={generation} sequence={sequence} effect={effect}\n",
                binding.pe, binding.worker.0
            ));
        }
        result
    }
    fn fail_stopped(&mut self, reason: &'static str) -> ! {
        fail(reason)
    }
}
// SAFETY: all actual non-'static AP loans below are synchronously joined and
// recovered. Error paths stop without dropping their reachable resources.
// Stop/release use the retained owner token on each fixed physical executor.
unsafe impl NativeTransport for FixedWorkers<'_> {
    fn initialize(
        &mut self,
        local: &mut dyn Host,
        inventory: &mut WorkerPublications,
        owners: Vec<WorkerOwner>,
    ) {
        if self.bsp.is_some() {
            fail("native transport initialized twice");
        }
        for mut owner in owners {
            let published = if local.native_worker() == Some(owner.binding().worker) {
                if self.bsp.is_some() {
                    fail("duplicate native BSP owner");
                }
                let published = owner
                    .publish_initial(local)
                    .unwrap_or_else(|_| fail("actual BSP initialization refused"));
                self.bsp = Some(owner);
                published
            } else {
                self.processor(owner.binding())
                    .initialize(owner, Arc::clone(&self.ram), self.sender, self.tsc_hz)
                    .unwrap_or_else(|_| fail("actual AP initialization refused"))
            };
            inventory
                .accept_initial(published)
                .unwrap_or_else(|_| fail("native initial publication mismatch"));
        }
        if self.bsp.is_none() {
            fail("physical BSP has no assigned native owner");
        }
    }
    fn execute<'a>(
        &mut self,
        local: &mut dyn Host,
        inventory: &mut WorkerPublications,
        frames: Vec<NativeRun<'a>>,
    ) -> Vec<NativeRunObservation> {
        let mut pending = Vec::new();
        let mut bsp = None;
        for frame in frames {
            let identity = frame.identity();
            // Artifact provenance stays attached to every run/cache entry.
            // Full identity formatting and the diagnostic ring scan are opt-in,
            // so warm dispatch does not pay for serial tracing.
            if self.trace_artifacts && !self.recent_artifacts.contains(identity) {
                crate::output::arguments(format_args!("NATIVE SCHEDULER artifact {identity:?}\n"));
                if self.recent_artifacts.len() == RECENT_ARTIFACT_DIAGNOSTICS {
                    self.recent_artifacts[self.next_artifact_slot] = identity.clone();
                    self.next_artifact_slot =
                        (self.next_artifact_slot + 1) % RECENT_ARTIFACT_DIAGNOSTICS;
                } else {
                    self.recent_artifacts.push(identity.clone());
                }
            }
            let loan = engine::dispatch_native_run(inventory, frame)
                .unwrap_or_else(|_| fail("actual native frame dispatch refused"));
            if self.is_bsp(loan.binding()) {
                if bsp.is_some() {
                    fail("duplicate native BSP frame");
                }
                bsp = Some(loan);
            } else {
                // SAFETY: every pending original frame is joined below. No
                // return/error unwinds or forgets a live AP borrow.
                pending.push(
                    unsafe {
                        self.processor(loan.binding())
                            .submit(loan, self.sender, self.tsc_hz)
                    }
                    .unwrap_or_else(|_| fail("actual native AP mailbox refused frame")),
                );
            }
        }
        let mut reports = Vec::new();
        if let Some(loan) = bsp {
            let returned = self
                .bsp()
                .execute(loan, local)
                .unwrap_or_else(|_| fail("actual BSP native entry refused"));
            reports.push(
                engine::recover_native_run(inventory, returned)
                    .unwrap_or_else(|_| fail("actual BSP native recovery refused")),
            );
        }
        for pending in pending {
            let returned = pending
                .finish()
                .unwrap_or_else(|_| fail("actual AP native entry refused"));
            reports.push(
                engine::recover_native_run(inventory, returned)
                    .unwrap_or_else(|_| fail("actual AP native recovery refused")),
            );
        }
        self.recovered_rounds = self.recovered_rounds.saturating_add(1);
        let now = crate::engine::host::rdtsc();
        if now.wrapping_sub(self.progress_reported) >= self.tsc_hz {
            self.progress_reported = now;
            for report in &reports {
                crate::output::arguments(format_args!(
                    "NATIVE PROGRESS recovered_rounds={} pe={} pc={:#x} instructions={} status={:?} compiled={} reused={} cache_bytes={} cache_entries={}\n",
                    self.recovered_rounds,
                    report.identity.pe,
                    report.settled_pc,
                    report.retired,
                    report.status,
                    report.artifact_cache.compiled,
                    report.artifact_cache.reused,
                    report.artifact_cache.retained_bytes,
                    report.artifact_cache.entries
                ));
            }
        }
        reports
    }
    fn hold_all(
        &mut self,
        local: &mut dyn Host,
        inventory: &mut WorkerPublications,
    ) -> publication::StoppedWorkers {
        let members: Vec<_> = inventory.bindings().map(|binding| binding.pe).collect();
        let request = inventory
            .request_stop(&members)
            .unwrap_or_else(|_| fail("native whole-cohort stop refused"));
        for command in inventory
            .native_stop_commands(&request)
            .unwrap_or_else(|_| fail("native unrecovered frame refused stop"))
        {
            let receipt = if self.is_bsp(command.binding()) {
                self.bsp()
                    .invalidate(command, local)
                    .unwrap_or_else(|_| fail("actual BSP stopped invalidation refused"))
            } else {
                self.processor(command.binding())
                    .invalidate(command, self.sender, self.tsc_hz)
                    .unwrap_or_else(|_| fail("actual AP stopped invalidation refused"))
            };
            inventory
                .accept_invalidation(receipt)
                .unwrap_or_else(|_| fail("native stopped invalidation receipt mismatch"));
        }
        inventory
            .hold_stop(request)
            .unwrap_or_else(|_| fail("actual whole native cohort was not held"))
    }
    fn release(
        &mut self,
        _: &mut dyn Host,
        inventory: &mut WorkerPublications,
        held: publication::StoppedWorkers,
    ) {
        for release in inventory
            .release(held)
            .unwrap_or_else(|_| fail("native cohort has unfinished services"))
        {
            let receipt = if self.is_bsp(release.binding()) {
                self.bsp()
                    .release(release)
                    .unwrap_or_else(|_| fail("actual BSP release refused"))
            } else {
                self.processor(release.binding())
                    .release(release, self.sender, self.tsc_hz)
                    .unwrap_or_else(|_| fail("actual AP release refused"))
            };
            inventory
                .accept_release(receipt)
                .unwrap_or_else(|_| fail("actual native release receipt mismatch"));
        }
    }
}
