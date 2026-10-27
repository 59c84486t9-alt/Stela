//! Every guest PE on its own host core (the default). The boot processor's
//! machine keeps the boot PE and serves resets and DMA; each other PE runs
//! a machine of its own on the AP its worker binding names, from the first
//! time a device starts it. Whichever PE waits for an interrupt serves the
//! host (`service`). The machines share guest
//! RAM, the board's devices and a hub (`stela_runtime::machine::engine::
//! parallel`).
use super::{SLICE, WAIT_POLLS_PER_SECOND, host, output};
use crate::{apic::Apic, native_smp::executor::Executors};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use stela_compiler::TargetCpu;
pub(crate) use stela_runtime::machine::engine::Counts;
use stela_runtime::machine::{
    Cpu, CpuProfile, Host, Machine, Stop,
    apple::AppleDevices,
    ctrr,
    engine::{Kick, SharedDevices, publication::WorkerBinding},
    exception::Pstate,
};

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
    pub strict: bool,
    pub profile: CpuProfile,
    pub target: TargetCpu,
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
            strict: settings.strict,
            profile: settings.profile.clone(),
            target: settings.target,
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
    core_locks: Arc<ctrr::Handoff>,
    strict: bool,
    profile: CpuProfile,
    target: TargetCpu,
}

impl Pe {
    fn run(self, owner: &mut host::HostOwner) {
        let Self {
            pe,
            devices,
            core_locks,
            strict,
            profile,
            target,
        } = self;
        let hub = Arc::clone(devices.hub());
        let address = {
            let mut host = owner.host();
            hub.first_start(pe, || host.wait_for_interrupt())
        };
        let cpu = Cpu::of(profile.chip, address, Pstate::reset(2));
        let live = crate::ALLOCATOR.usage().live;
        let mut machine = Machine::new_at(cpu, owner.host(), devices, profile, target, pe)
            .unwrap_or_else(|error| output::fatal(error));
        output::arguments(format_args!(
            "PARALLEL PE {pe} machine takes {} KiB of heap\n",
            crate::ALLOCATOR.usage().live.saturating_sub(live) >> 10
        ));
        machine.set_strict(strict);
        // Waits return to this loop, which publishes the counts.
        machine.set_wait_limit(Some(host::COUNTER_HZ / WAIT_POLLS_PER_SECOND));
        if let Err(stop) = machine.start_parallel(Arc::clone(&hub), core_locks, address) {
            stopped(pe, stop);
        }
        output::arguments(format_args!("PARALLEL PE {pe} starts at {address:#x}\n"));
        loop {
            let limit = machine.statistics.blocks + SLICE;
            match machine.run(limit) {
                Stop::Budget => {}
                // A PE that waits for an interrupt serves the host meanwhile.
                Stop::Waiting if machine.waits_for_interrupt() => super::service::serve(false),
                Stop::Waiting => {}
                stop => stopped(pe, stop),
            }
            hub.publish(pe, machine.counts());
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
