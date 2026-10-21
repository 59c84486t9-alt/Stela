//! A consuming synchronous borrow of the actual scheduler/native owners.
//! Controller preflight and its final infallible commit surround this access;
//! no post-write pending queue substitutes for actual CPU settlement.
use super::super::{
    DebugMode, MemoryChecks, Mirrors, NativeSystem, PredictionContext, Regime, Statistics, Watch,
    clock, pointer::PointerService,
};
use super::{
    Cpu, Host, Lines, Peer, PreparedProcessorPower, ProcessorChange, ProcessorPowerError,
    Processors, Wait, check_owners, pause_cpu,
};

/// One synchronous device-write access to the actual scheduler and native
/// owners. Only the engine constructs it. Applying one complete batch consumes
/// the access; dropping it after another owner's refusal changes nothing.
/// A device must preflight every native/controller owner first, then apply the
/// CPU batch, then perform only an infallible prepared commit before ACK.
pub struct ProcessorWrite<'a> {
    pub(super) processors: &'a mut Processors,
    pub(super) current: usize,
    pub(super) cpu: &'a mut Cpu,
    pub(super) peers: &'a mut [Peer],
    pub(super) waiting: Option<Wait>,
    pub(super) clock: &'a mut clock::Clock,
    pub(super) slice_end: &'a mut u64,
    pub(super) native: NativeProcessorState<'a>,
}

/// Successful settlement keeps the exclusive actual-owner borrow through the
/// caller's infallible native/controller commit. It cannot apply another batch.
#[must_use = "hold the actual-owner lease until the controller has committed"]
pub struct SettledProcessorWrite<'a> {
    pub(super) owners: ProcessorWrite<'a>,
}

impl SettledProcessorWrite<'_> {
    pub fn paused(&self, pe: usize) -> Option<bool> {
        self.owners.processors.paused(pe)
    }
}

/// Exact owners changed by translations_changed/sync_regime. Every reference
/// belongs to this Machine/native worker, never a global or a copied context.
pub(super) struct NativeProcessorState<'a> {
    pub host: &'a mut dyn Host,
    pub statistics: &'a mut Statistics,
    pub translation_generation: &'a mut u64,
    pub timers: &'a mut Option<Option<u64>>,
    pub floating_point: &'a mut Option<Option<u8>>,
    pub memory_checks: &'a mut Option<MemoryChecks>,
    pub native_system: &'a mut Option<NativeSystem>,
    pub debug: &'a mut Option<DebugMode>,
    pub pointer: &'a mut PointerService,
    pub mirrors: &'a mut Mirrors,
    pub device_lines: &'a mut Option<(Lines, u64)>,
    pub watch: &'a mut Watch,
    pub tag_checks: &'a mut [bool; 2],
    pub prediction_context: &'a mut Option<PredictionContext>,
}

struct NativeSettlement {
    generation: u64,
    translation_changes: u64,
    watch: Watch,
    watch_changed: bool,
    prediction: PredictionContext,
    isolate: bool,
    isolations: u64,
}

impl NativeProcessorState<'_> {
    fn prepare(&self, cpu: &Cpu) -> Result<NativeSettlement, ProcessorPowerError> {
        let watch = Watch {
            pass: self.watch.pass,
            ..Watch::from_ranges(&crate::machine::debug::watched(cpu))
        };
        let watch_changed = watch.ranges != self.watch.ranges;
        let prediction = PredictionContext::of(cpu);
        let isolate = *self.prediction_context != Some(prediction);
        let advance = |value: u64, by, field| {
            value
                .checked_add(by)
                .ok_or(ProcessorPowerError::NativeStateExhausted(field))
        };
        Ok(NativeSettlement {
            generation: advance(
                *self.translation_generation,
                1 + u64::from(watch_changed),
                "translation generation",
            )?,
            translation_changes: advance(
                self.statistics.translation_changes,
                1,
                "translation changes",
            )?,
            watch,
            watch_changed,
            prediction,
            isolate,
            isolations: advance(
                self.statistics.prediction_isolations,
                u64::from(isolate),
                "prediction isolations",
            )?,
        })
    }

    /// The existing translations_changed/sync_regime effects, through the
    /// actual borrowed native owners. No guest cache maintenance is invented.
    fn settle(
        &mut self,
        cpu: &mut Cpu,
        waiting: bool,
        clock: &mut clock::Clock,
        plan: NativeSettlement,
    ) {
        *self.translation_generation = plan.generation - u64::from(plan.watch_changed);
        self.statistics.translation_changes = plan.translation_changes;
        self.host.invalidate_translations();
        *self.timers = None;
        *self.floating_point = None;
        *self.memory_checks = None;
        *self.native_system = None;
        *self.debug = None;
        self.pointer.close();
        *self.mirrors = Mirrors::default();
        *self.device_lines = None;
        let pmu_timed = cpu.pmu.as_ref().map(|monitor| monitor.timed());
        let amu_timed = cpu.amu.as_ref().map(|monitors| monitors.timed());
        if pmu_timed.is_some() || amu_timed.is_some() {
            let now = if pmu_timed == Some(true) || amu_timed == Some(true) {
                clock.read(self.host.counter())
            } else {
                0
            };
            if let Some(monitor) = cpu.pmu.as_mut() {
                monitor.sync(
                    now,
                    cpu.retired,
                    crate::machine::pmu::Context {
                        el: cpu.pstate.el,
                        waiting,
                    },
                );
            }
            if let Some(monitors) = cpu.amu.as_mut() {
                monitors.sync(now, cpu.retired, waiting);
            }
        }
        if plan.watch_changed {
            *self.translation_generation = plan.generation;
            self.host.invalidate_translations();
        }
        *self.watch = plan.watch;
        *self.tag_checks = cpu.tag_checks();
        self.host.set_regime(&Regime {
            controls: cpu.controls(cpu.regime()),
            requester: cpu.requester(),
            watch: plan.watch,
            tag_checks: *self.tag_checks,
        });
        if plan.isolate {
            *self.prediction_context = Some(plan.prediction);
            self.statistics.prediction_isolations = plan.isolations;
            self.host.isolate_predictions();
        }
    }
}

impl<'a> ProcessorWrite<'a> {
    pub fn apply(
        self,
        changes: &[ProcessorChange],
    ) -> Result<SettledProcessorWrite<'a>, ProcessorPowerError> {
        let plan = self.processors.prepare(changes)?;
        self.settle(plan)
    }

    pub(super) fn settle(
        mut self,
        plan: PreparedProcessorPower,
    ) -> Result<SettledProcessorWrite<'a>, ProcessorPowerError> {
        self.processors.check(&plan)?;
        check_owners(self.processors, self.current, self.peers)?;
        let settlement = self.processors.settlement(plan)?;
        let current_changed = settlement
            .changes()
            .iter()
            .any(|change| change.pe == self.current);
        let native = current_changed
            .then(|| self.native.prepare(self.cpu))
            .transpose()?;
        let current_paused = settlement.paused(self.current);
        let changes = settlement.commit();
        if changes.is_empty() {
            return Ok(SettledProcessorWrite { owners: self });
        }
        let host = self.native.host.counter();
        self.clock.end_slice(host, self.native.statistics.blocks);
        let now = self.clock.read(host);
        for change in changes {
            match &mut self.peers[change.pe] {
                Peer::Running => pause_cpu(self.cpu, self.waiting, now, change.paused),
                Peer::Parked(parked) => {
                    pause_cpu(&mut parked.cpu, parked.waiting, now, change.paused)
                }
                Peer::Off => {}
            }
        }
        *self.slice_end = self.native.statistics.blocks;
        if let Some(native) = native {
            self.native.settle(
                self.cpu,
                self.waiting.is_some() || current_paused,
                self.clock,
                native,
            );
        }
        Ok(SettledProcessorWrite { owners: self })
    }
}
