//! The host's xHCI controllers after probe: each controller's topology
//! owner ([`xhci::Host`]), looked at between engine slices so hotplug and
//! the resets class drivers queue (`Controller::queue_reset`) are serviced,
//! as Linux's `hub_event` services them. A controller that signals its
//! events wakes the engine and is polled once it has work
//! ([`xhci::Host::due`]); another is polled on a timer. A keyboard or
//! pointer that arrives joins the host input; another new device is
//! reported and its owners kept.
//!
//! USB4 hosts whose firmware runs the connection manager are looked at on
//! the same timer: each firmware event is reported, as Linux's
//! `icm_handle_notification` receives it.
//!
//! The controllers' registers and DMA pages are reached through the
//! loader's identity root, so each poll runs in it (`storage::RestoreRoot`).
use super::storage::RestoreRoot;
use crate::output;
use alloc::{sync::Arc, vec::Vec};
use stela_drivers::{
    bus::{dma::RegionAllocator, thunderbolt::icm},
    firmware::{Catalog, HandoffProvider},
    input::InputDevice,
    probe::native::usb4,
    usb::xhci::{self, Found},
};

/// Firmware events serviced per USB4 host per poll.
const USB4_EVENTS: usize = 16;

/// Report one firmware event of `host`.
pub fn report_usb4(host: &usb4::Host, event: &icm::Event) {
    let location = &host.location;
    match event {
        icm::Event::Notification(message) => {
            match icm::Notification::decode(host.icm.family(), message) {
                Ok(notification) => {
                    output::arguments(format_args!("HOST USB4 {location}: {notification}\n"))
                }
                Err(error) => output::arguments(format_args!(
                    "HOST USB4 {location}: undecodable firmware event {:#x}: {error:?}\n",
                    message.code
                )),
            }
        }
        icm::Event::Discarded(error) => output::arguments(format_args!(
            "HOST USB4 {location}: firmware message discarded: {error:?}\n"
        )),
        icm::Event::DriverReady { request, .. } => output::arguments(format_args!(
            "HOST USB4 {location}: unrequested DRIVER_READY answer {request}\n"
        )),
    }
}

/// How often controllers without a signal are polled: Linux's root hub
/// status timer runs every 250 ms; a hub's status endpoint interval is at
/// most 255 ms.
const POLL_HZ: u64 = 16;

pub struct HostUsb {
    hosts: Vec<xhci::Host>,
    /// USB4 hosts, and whether each one's connection manager still runs.
    usb4: Vec<(usb4::Host, bool)>,
    tsc_per_ms: u64,
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
        usb4: Vec<usb4::Host>,
        dma: RegionAllocator,
        firmware: Option<Arc<Catalog>>,
        root: u64,
        tsc_hz: u64,
    ) -> Self {
        Self {
            hosts,
            usb4: usb4.into_iter().map(|host| (host, true)).collect(),
            tsc_per_ms: (tsc_hz / 1000).max(1),
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
        if timed {
            self.poll_usb4(now);
        }
        let firmware = HandoffProvider::new(self.firmware.as_deref());
        for host in &mut self.hosts {
            let mut changes = {
                // SAFETY: the loader root `storage::open` captured maps the
                // controller and DMA pages used by both readiness and polling.
                let _root = unsafe { RestoreRoot::enter(self.root) };
                if !(if host.signals() { host.due() } else { timed }) {
                    continue;
                }
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
            inputs.extend(
                added
                    .inputs
                    .drain(..)
                    .map(|input| InputDevice::Usb(alloc::boxed::Box::new(input))),
            );
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

    /// Service each running USB4 host's firmware events. A host whose
    /// transport faults is reported once and left stopped.
    fn poll_usb4(&mut self, now: u64) {
        let now_ms = now / self.tsc_per_ms;
        for (host, running) in &mut self.usb4 {
            if !*running {
                continue;
            }
            for _ in 0..USB4_EVENTS {
                let event = {
                    // SAFETY: as for the xHCI controllers below.
                    let _root = unsafe { RestoreRoot::enter(self.root) };
                    host.icm.poll(now_ms)
                };
                match event {
                    Ok(Some(event)) => report_usb4(host, &event),
                    Ok(None) => break,
                    Err(error) => {
                        output::arguments(format_args!(
                            "HOST USB4 {}: connection manager transport stopped: {error:?}\n",
                            host.location
                        ));
                        *running = false;
                        break;
                    }
                }
            }
        }
    }
}
