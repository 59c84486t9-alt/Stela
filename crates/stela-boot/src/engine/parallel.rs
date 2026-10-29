//! Every guest PE on its own host core (the default). The boot processor's
//! machine keeps the boot PE and serves resets and DMA; each other PE runs
//! a machine of its own on the AP its worker binding names, from the first
//! time a device starts it. Whichever PE waits for an interrupt serves the
//! host (`service`). The machines share guest
//! RAM, the board's devices and a hub (`stela_engine::machine::engine::
//! parallel`).
use super::{SLICE, WAIT_POLLS_PER_SECOND, host, output};
use crate::{apic::Apic, native_smp::executor::Executors};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use stela_compiler::TargetCpu;
use stela_engine::machine::Cpu;
use stela_engine::machine::CpuProfile;
use stela_engine::machine::Host;
use stela_engine::machine::Machine;
use stela_engine::machine::Stop;
use stela_engine::machine::ctrr;
use stela_engine::machine::engine::Kick;
use stela_engine::machine::engine::SharedDevices;
pub(crate) use stela_engine::machine::engine::SourcePhase;
use stela_engine::machine::engine::publication::WorkerBinding;
pub(crate) use stela_engine::machine::engine::{Counts, RunBudget};
use stela_engine::machine::exception::Pstate;
use stela_runtime::machine::apple::AppleDevices;

/// The native code of the blocks the PEs share, compiled once by whichever
/// runs them first (`translations::share`).
pub(crate) const SHARED_CODE_BYTES: usize = 64 << 20;

/// The board's devices as every PE's machine reaches them.
pub(crate) type Board = SharedDevices<AppleDevices>;

/// Rings the doorbell of the AP that runs each PE.
pub(crate) struct Doorbells {
    /// APIC IDs by PE.
    destinations: Vec<Option<u32>>,
}

impl Doorbells {
    /// `apic` gives the APIC ID of each worker slot.
    pub(crate) fn new(
        pes: usize,
        bindings: &[WorkerBinding],
        apic: impl Fn(usize) -> Option<u32>,
    ) -> Self {
        let mut destinations = alloc::vec![None; pes];
        for binding in bindings {
            if let Some(destination) = destinations.get_mut(binding.pe) {
                *destination = apic(binding.worker.0);
            }
        }
        Self { destinations }
    }
}

impl Kick for Doorbells {
    fn kick(&self, pe: usize) {
        if let Some(&Some(destination)) = self.destinations.get(pe) {
            host::ring(destination);
        }
    }
}

/// What every PE's machine shares with the home machine's settings.
pub(crate) struct Settings {
    pub profile: CpuProfile,
    pub target: TargetCpu,
    pub traces: Vec<u64>,
    pub watches: Vec<(u64, u64)>,
}

/// Give each AP the PE its worker binding names, to run on a machine of its
/// own once a device starts it. `home` already entered parallel and holds
/// the serial workers.
pub(crate) fn spawn<H: Host>(
    home: &Machine<H, Board>,
    bindings: &[WorkerBinding],
    executors: &Executors,
    sender: &Apic,
    tsc_hz: u64,
    settings: &Settings,
) -> Result<(), &'static str> {
    for binding in bindings {
        if binding.pe == home.processor() {
            continue;
        }
        let processor = executors
            .processors()
            .iter()
            .find(|processor| processor.slot() == binding.worker.0)
            .ok_or("a PE's worker has no AP")?;
        let pe = Pe {
            pe: binding.pe,
            devices: home.devices.worker(),
            core_locks: home.cpu.core_locks.clone(),
            profile: settings.profile.clone(),
            target: settings.target,
            traces: settings.traces.clone(),
            watches: settings.watches.clone(),
        };
        processor.spawn(Box::new(move |owner| pe.run(owner)), sender, tsc_hz)?;
    }
    output::arguments(format_args!(
        "PARALLEL {} PEs, each on its own host core\n",
        bindings.len()
    ));
    // Every PE's guest time passes while the serial port takes a long
    // report; idle PEs send it instead.
    output::queue_serial();
    Ok(())
}

/// One PE's machine, before its first start.
struct Pe {
    pe: usize,
    devices: Board,
    core_locks: Arc<ctrr::CoreLocks>,
    profile: CpuProfile,
    target: TargetCpu,
    traces: Vec<u64>,
    watches: Vec<(u64, u64)>,
}

impl Pe {
    fn run(self, owner: &mut host::HostOwner) {
        let Self {
            pe,
            devices,
            core_locks,
            profile,
            target,
            traces,
            watches,
        } = self;
        // This core's driver calls keep the engine's TLB entries.
        let _tagged = super::storage::TaggedRoots::enable();
        let hub = Arc::clone(devices.hub());
        let address = {
            let mut host = owner.host();
            hub.first_start(pe, || host.wait_for_interrupt())
        };
        let cpu = Cpu::of(profile.chip, address, Pstate::reset(2));
        // This core's own allocations, which other PEs' leave alone.
        let own = || crate::ALLOCATOR.own().unwrap_or(0);
        let before = own();
        let mut machine = Machine::new_at(cpu, owner.host(), devices, profile, target, pe)
            .unwrap_or_else(|error| output::fatal(error));
        let observing = !traces.is_empty() || !watches.is_empty();
        if !traces.is_empty() {
            machine.set_traces(&traces);
        }
        if !watches.is_empty() {
            machine.set_watches(&watches);
        }
        drop((traces, watches));
        output::arguments(format_args!(
            "PARALLEL PE {pe} machine takes {} KiB of heap\n",
            own().saturating_sub(before).max(0) >> 10
        ));
        // Waits return to this loop, which publishes the counts.
        machine.set_wait_limit(Some(host::COUNTER_HZ / WAIT_POLLS_PER_SECOND));
        if let Err(stop) = machine.start_parallel(Arc::clone(&hub), core_locks, address) {
            stopped(pe, stop);
        }
        output::arguments(format_args!("PARALLEL PE {pe} starts at {address:#x}\n"));
        loop {
            let limit = machine.statistics.blocks + SLICE;
            let stop = machine.run_with_budget(RunBudget {
                blocks: limit,
                host_ticks: Some(host::COUNTER_HZ / WAIT_POLLS_PER_SECOND),
            });
            // Like the home PE, drain outside guest execution and before a
            // terminal stop. Retention is bounded by TRACE_HITS/WATCH_HITS;
            // output uses the shared bounded serial queue, never an ISR.
            if observing {
                report_diagnostics(&mut machine);
            }
            match stop {
                // A PE that waits for an interrupt serves the host meanwhile.
                stop if machine.yielded_for_interrupt(&stop) => super::service::serve(false),
                Stop::Budget | Stop::Waiting => {}
                stop => stopped(pe, stop),
            }
            hub.publish(pe, machine.counts());
        }
    }
}

/// The home and secondary PEs' records, including the PE that made each hit.
/// Each machine retains at most TRACE_HITS and WATCH_HITS between drains;
/// their last records report any overflow rather than hiding lost hits.
pub(super) fn report_diagnostics<H: Host>(machine: &mut Machine<H, Board>) {
    for hit in machine.take_trace_hits() {
        output::arguments(format_args!(
            "TRACE pc={:#x} pe={} el={} x0-x3={:#x} {:#x} {:#x} {:#x} lr={:#x} dropped={}\n",
            hit.pc,
            hit.pe,
            hit.el,
            hit.arguments[0],
            hit.arguments[1],
            hit.arguments[2],
            hit.arguments[3],
            hit.lr,
            hit.dropped
        ));
    }
    for hit in machine.take_watch_hits() {
        output::arguments(format_args!(
            "WATCH pc={:#x} pe={} {} pa={:#x} bytes={} value={:#x}{} dropped={}\n",
            hit.pc,
            hit.pe,
            if hit.write { "write" } else { "read" },
            hit.physical,
            hit.bytes,
            hit.value,
            if hit.completed { "" } else { " refused" },
            hit.dropped
        ));
    }
}

/// Bounded, explicitly stale observations copied by each owning Machine.
/// Neither the report time nor another PE's publication makes them current.
pub(super) fn report_source_observations<H: Host>(home: &Machine<H, Board>) {
    let hub = home.devices.hub();
    if !hub.source_observations_enabled() {
        return;
    }
    output::arguments(format_args!(
        "PE SOURCE last-materialized=true coherent=false\n"
    ));
    for pe in 0..hub.pes() {
        match hub.source_observation(pe) {
            Some(observed) => {
                let source = observed.source;
                output::arguments(format_args!(
                    "PE SOURCE pe={pe} sequence={} observed_host_counter={:#x} phase={:?} pc={:#x} el={} daif={:#x} sp={:#x} lr={:#x}\n",
                    observed.sequence,
                    source.host_counter,
                    source.phase,
                    source.pc,
                    source.el,
                    source.daif,
                    source.sp,
                    source.lr
                ));
            }
            None => output::arguments(format_args!(
                "PE SOURCE pe={pe} unavailable=no-stable-owner-observation\n"
            )),
        }
    }
    output::arguments(format_args!(
        "PE BROADCAST retained=true coherent-across-pes=false counter_hz={} fields=started/completed/recipients/elapsed/max/polls\n",
        host::COUNTER_HZ
    ));
    for pe in 0..hub.pes() {
        match hub.broadcast_profile(pe) {
            Some(profile) => {
                let [tlb, code, power] = profile.kinds;
                output::arguments(format_args!(
                    "PE BROADCAST pe={pe} tlb={}/{}/{}/{}/{}/{} code={}/{}/{}/{}/{}/{} power={}/{}/{}/{}/{}/{} active={:?} active_start={:#x} dropped={}\n",
                    tlb.started,
                    tlb.completed,
                    tlb.recipients,
                    tlb.elapsed_ticks,
                    tlb.maximum_ticks,
                    tlb.polls,
                    code.started,
                    code.completed,
                    code.recipients,
                    code.elapsed_ticks,
                    code.maximum_ticks,
                    code.polls,
                    power.started,
                    power.completed,
                    power.recipients,
                    power.elapsed_ticks,
                    power.maximum_ticks,
                    power.polls,
                    profile.active,
                    profile.active_start,
                    profile.dropped_updates
                ));
            }
            None => output::arguments(format_args!(
                "PE BROADCAST pe={pe} unavailable=no-stable-observation\n"
            )),
        }
    }
}

/// A PE's machine stopped, which only the home machine may: the board stops.
fn stopped(pe: usize, stop: Stop) -> ! {
    output::arguments(format_args!("PARALLEL PE {pe} stopped: {stop:?}\n"));
    output::fatal("a PE on its own host core stopped")
}

/// Each PE's counts: the home machine's own, and those every other PE's
/// machine last published; one when the PEs run serialized.
pub(crate) fn counts<H: Host>(home: &Machine<H, Board>) -> Vec<Counts> {
    let own = home.counts();
    if !home.runs_parallel() {
        return alloc::vec![own];
    }
    let hub = home.devices.hub();
    (0..hub.pes())
        .map(|pe| {
            if pe == home.processor() {
                own
            } else {
                hub.published(pe)
            }
        })
        .collect()
}
