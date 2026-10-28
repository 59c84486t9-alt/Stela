//! The host's xHCI controllers after probe: each controller's topology
//! owner ([`xhci::Host`]), looked at between engine slices so hotplug and
//! the resets class drivers queue (`Controller::queue_reset`) are serviced,
//! as Linux's `hub_event` services them. A controller that signals its
//! events wakes the engine and is polled once it has work
//! ([`xhci::Host::due`]); another is polled on a timer. A keyboard or
//! pointer that arrives joins the host input; another new device is
//! reported and its owners kept.
//!
//! The controllers' registers and DMA pages are reached through the
//! loader's identity root, so each poll runs in it (`storage::RestoreRoot`).
use super::storage::RestoreRoot;
use crate::output;
use alloc::{sync::Arc, vec::Vec};
use stela_drivers::{
    bus::dma::RegionAllocator,
    firmware::{Catalog, HandoffProvider},
    input::InputDevice,
    usb::xhci::{self, Found},
};

/// How often controllers without a signal are polled: Linux's root hub
/// status timer runs every 250 ms; a hub's status endpoint interval is at
/// most 255 ms.
const POLL_HZ: u64 = 16;

pub struct HostUsb {
    hosts: Vec<xhci::Host>,
    /// The probe's DMA pages, which enumeration of a new device draws on.
    dma: RegionAllocator,
    firmware: Option<Arc<Catalog>>,
    root: u64,
    /// New devices' class owners that no consumer takes, kept for the boot.
    kept: Vec<Found>,
    interval: u64,
    last: u64,
}

impl HostUsb {
    pub fn new(
        hosts: Vec<xhci::Host>,
        dma: RegionAllocator,
        firmware: Option<Arc<Catalog>>,
        root: u64,
        tsc_hz: u64,
    ) -> Self {
        Self {
            hosts,
            dma,
            firmware,
            root,
            kept: Vec::new(),
            interval: tsc_hz / POLL_HZ,
            last: super::host::rdtsc(),
        }
    }

    /// Poll each signalling controller that has work, and the others when
    /// the interval has passed; the keyboards and pointers that arrived.
    pub fn poll(&mut self) -> Vec<InputDevice> {
        let mut inputs = Vec::new();
        let now = super::host::rdtsc();
        let timed = now.wrapping_sub(self.last) >= self.interval;
        if timed {
            self.last = now;
        }
        let firmware = HandoffProvider::new(self.firmware.as_deref());
        for host in &mut self.hosts {
            if !(if host.signals() { host.due() } else { timed }) {
                continue;
            }
            let mut changes = {
                // SAFETY: the loader root `storage::open` captured, which maps
                // the controller and the DMA pages.
                let _root = unsafe { RestoreRoot::enter(self.root) };
                host.poll(&mut self.dma, &firmware)
            };
            for device in &changes.removed {
                output::arguments(format_args!("USB removed {}\n", device.location));
            }
            let added = &mut changes.added;
            for (location, error) in &added.failures {
                output::arguments(format_args!(
                    "USB FAILED {location}: {}\n",
                    xhci::explain(error)
                ));
            }
            for (location, why) in &added.unused {
                output::arguments(format_args!("USB UNUSED {location}: {why}\n"));
            }
            inputs.extend(added.inputs.drain(..).map(InputDevice::Usb));
            for device in &added.devices {
                output::arguments(format_args!("USB added {}\n", device.location));
            }
            if !added.disks.is_empty() || !added.storage.is_empty() || !added.links.is_empty() {
                output::arguments(format_args!(
                    "USB a disk or network adapter added after boot is kept unused until the next boot\n"
                ));
            }
            if !changes.added.devices.is_empty() {
                self.kept.push(changes.added);
            }
        }
        inputs
    }
}
