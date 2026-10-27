//! The host's service between guest slices: the restore host, the host's
//! inputs, network and NOR, its power button and the log stores. The guest
//! storage's host transfers need none: its controller submits each one and
//! completes it once the disk has (`ans::host`).
//!
//! Guest time passes while a PE's core serves the host, and another PE may
//! spin on a lock the served PE's guest holds; XNU panics when a spinlock
//! is held past its timeout. With every PE on a host core of its own, a PE
//! that waits for an interrupt serves the host ([`serve`]), as it holds no
//! such lock, and a device that leaves bytes for the host wakes one that
//! sleeps (`Hub::request_service`). The boot PE serves only once no PE has
//! for [`STARVED_MILLIS`], or always when the PEs run serialized.
use super::{host, input, network, nor, output, parallel, power, restore};
use alloc::{format, string::String};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// How long the host may go unserved before the boot PE serves it: a PE's
/// wait returns to its run loop at least this often
/// (`WAIT_POLLS_PER_SECOND`), so with any PE idle it is served first. A
/// device's request with no PE asleep to take it (bytes for the host while
/// every PE runs) waits [`REQUESTED_MILLIS`] at most.
const STARVED_MILLIS: u64 = 50;
const REQUESTED_MILLIS: u64 = 2;

/// Seconds between the service's own reports.
const REPORT_SECONDS: u64 = 10;

/// The host interfaces the service owns for the whole run.
pub(super) struct Service {
    devices: parallel::Board,
    restore: Option<restore::Experiment>,
    input: Option<input::HostInput>,
    network: Option<network::GuestNetwork>,
    nor: Option<nor::HostNor>,
    power: power::HostPowerControl,
    tsc_hz: u64,
    log_flushed: u64,
    reported: u64,
}

impl Service {
    pub(super) fn new(
        devices: parallel::Board,
        restore: Option<restore::Experiment>,
        input: Option<input::HostInput>,
        network: Option<network::GuestNetwork>,
        nor: Option<nor::HostNor>,
        power: power::HostPowerControl,
        tsc_hz: u64,
    ) -> Self {
        let now = host::rdtsc();
        Self {
            devices,
            restore,
            input,
            network,
            nor,
            power,
            tsc_hz,
            log_flushed: now,
            reported: now,
        }
    }

    pub(super) fn power(&self) -> &power::HostPowerControl {
        &self.power
    }

    /// Store what the guest committed since the last service, the caller
    /// waiting: at the stop, before the PC restarts or turns off.
    pub(super) fn stop(&mut self) {
        if let Some(nor) = self.nor.as_mut() {
            let dirty = self.devices.with(nor::HostNor::dirty);
            nor.store(dirty);
            nor.finish();
        }
    }

    /// One service: its quick parts first, then the restore's read ahead
    /// and verification, which a waiting PE leaves to a later service once
    /// an interrupt comes for it (`boot` serves them whole).
    fn serve(&mut self, boot: bool) {
        let Self {
            devices,
            restore,
            input,
            network,
            nor,
            power,
            tsc_hz,
            log_flushed,
            reported,
        } = self;
        let mut lap = Lap(host::rdtsc());
        let now = host::rdtsc();
        if now.wrapping_sub(*log_flushed) >= *tsc_hz {
            output::flush_due();
            *log_flushed = host::rdtsc();
        } else {
            output::advance_logs();
        }
        lap.part(Part::Log);
        if let Some(input) = input {
            let inputs = input.read();
            if !inputs.is_empty() {
                devices.serve(|devices| input.deliver_all(devices, inputs));
            }
            lap.part(Part::Input);
        }
        if let Some(network) = network {
            let frames = devices.with(network::GuestNetwork::queued);
            network.transmit(frames);
            devices.serve(|devices| network.poll(devices));
            lap.part(Part::Network);
        }
        if let Some(nor) = nor {
            let dirty = devices.with(nor::HostNor::dirty);
            nor.store(dirty);
        }
        if power.pressed() {
            devices.serve(|devices| power.press(devices));
        }
        lap.part(Part::Nor);
        let interrupted = || !boot && host::interrupted();
        if let Some(experiment) = restore {
            // The source is read outside the devices' lock, which every
            // PE's device accesses take.
            experiment.pump();
            if !interrupted() {
                experiment.prefetch();
            }
            lap.part(Part::Read);
            if !interrupted() {
                devices.serve(|devices| experiment.poll(devices));
            }
            lap.part(Part::Restore);
        }
        if now.wrapping_sub(*reported) >= REPORT_SECONDS * *tsc_hz {
            if let Some(line) = restore
                .as_ref()
                .and_then(|experiment| experiment.asr_report())
            {
                output::arguments(format_args!("{line}\n"));
            }
            power.disks().report(*tsc_hz);
            *reported = now;
        }
    }
}

/// The parts of a service, timed for [`report`].
#[derive(Clone, Copy)]
enum Part {
    /// The restore source's read ahead.
    Read,
    Restore,
    Input,
    Network,
    /// The NOR's stores and the power button.
    Nor,
    Log,
}

const PARTS: usize = 6;
const NAMES: [&str; PARTS] = ["read", "restore", "input", "network", "nor", "log"];

/// The longest each part took since the last [`report`], in counter ticks.
static LONGEST: [AtomicU64; PARTS] = [const { AtomicU64::new(0) }; PARTS];
/// Services since the last report: by a waiting PE and by the boot PE.
static SERVICES: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

struct Lap(u64);

impl Lap {
    fn part(&mut self, part: Part) {
        let now = host::rdtsc();
        LONGEST[part as usize].fetch_max(now.wrapping_sub(self.0), Ordering::Relaxed);
        self.0 = now;
    }
}

/// The service, which one core at a time holds.
struct Slot {
    held: AtomicBool,
    service: UnsafeCell<Option<Service>>,
}

// SAFETY: only the core that set `held` reaches the service, so the state
// its parts share through `Rc` or `RefCell` is never touched by two cores
// at once; their devices are reached through their controllers' registers
// and locks, from any core.
unsafe impl Sync for Slot {}

static SLOT: Slot = Slot {
    held: AtomicBool::new(false),
    service: UnsafeCell::new(None),
};

/// The counter when the host was last served.
static SERVED: AtomicU64 = AtomicU64::new(0);

/// Run `f` on the service while this core holds it; `None` while another
/// does.
fn hold<R>(f: impl FnOnce(&mut Option<Service>) -> R) -> Option<R> {
    if SLOT
        .held
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return None;
    }
    // SAFETY: `held` gives this core the only reference.
    let result = f(unsafe { &mut *SLOT.service.get() });
    SLOT.held.store(false, Ordering::Release);
    Some(result)
}

/// Give the service its interfaces for the run.
pub(super) fn install(service: Service) {
    let mut service = Some(service);
    while hold(|slot| *slot = service.take()).is_none() {
        core::hint::spin_loop();
    }
}

/// Serve the host unless another core is serving it; `boot` when the boot
/// PE serves it.
pub(super) fn serve(boot: bool) {
    // An interrupt from now on is one the waiting PE should take instead.
    if !boot {
        host::clear_interrupted();
    }
    let served = hold(|slot| {
        let Some(service) = slot else {
            return false;
        };
        service.serve(boot);
        true
    });
    if served == Some(true) {
        SERVED.store(host::rdtsc(), Ordering::Release);
        SERVICES[usize::from(boot)].fetch_add(1, Ordering::Relaxed);
    }
}

/// Whether no PE has served the host for [`STARVED_MILLIS`], or for
/// [`REQUESTED_MILLIS`] with a device's request `requested`.
pub(super) fn starved(tsc_hz: u64, requested: bool) -> bool {
    let millis = if requested {
        REQUESTED_MILLIS
    } else {
        STARVED_MILLIS
    };
    host::rdtsc().wrapping_sub(SERVED.load(Ordering::Acquire)) >= tsc_hz / 1000 * millis
}

/// The service, back from whichever core serves it, for the run's end.
pub(super) fn take() -> Option<Service> {
    loop {
        if let Some(service) = hold(Option::take) {
            return service;
        }
        core::hint::spin_loop();
    }
}

/// The services since the last report and the longest each part took.
pub(super) fn report(tsc_hz: u64) -> String {
    let services = SERVICES
        .each_ref()
        .map(|count| count.swap(0, Ordering::Relaxed));
    let mut line = format!(
        "services waiting={} boot={} longest_us",
        services[0], services[1]
    );
    for (name, longest) in NAMES.iter().zip(&LONGEST) {
        let ticks = longest.swap(0, Ordering::Relaxed);
        line.push_str(&format!(
            " {name}={}",
            u128::from(ticks) * 1_000_000 / u128::from(tsc_hz.max(1))
        ));
    }
    line
}
