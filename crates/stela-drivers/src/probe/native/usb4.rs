//! USB4/Thunderbolt hosts, attached as Linux's `nhi_probe` and `nhi_select_cm`
//! attach them when ACPI grants the OS no native USB4 control, which this
//! mount never requests. A host whose firmware runs the connection manager
//! (ICM) keeps it; as Linux does with no authorizing agent, a device that
//! firmware leaves awaiting approval gets no PCIe tunnel. Any other host gets
//! the software connection manager ([`Manager`]).
//!
//! Software hosts come up before the PCI scan ([`bring_up`]), so the scan
//! finds what they tunnel as it finds any other function, and a USB device
//! behind a USB3 tunnel is there when the xHCI controllers attach.
use super::{Bridge, Claimed, Failure, Kind, NativeServices, ServiceError, claim, map};
use crate::{
    Clock,
    bus::{
        mmio::owned::Mapping,
        pci::{Address, ConfigSpace, EcamWindow, Function, hotplug, owned::OwnedConfig, regs},
        thunderbolt::{
            channel::{self, Channel},
            controller::{self, Controller},
            icm,
            manager::Manager,
            ring,
        },
    },
    probe::{Devices, Error, Handoff, Warning},
};
use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::fmt;

/// How long a domain's routers stay silent before it counts as found, and
/// the longest the finding takes.
const QUIET_MS: u64 = 700;
const SETTLE_MS: u64 = 3000;
/// How long the PCIe links of new tunnels get to train and their functions
/// to answer.
const LINK_MS: u64 = 1000;
/// The wait after link training before configuration requests
/// (PCI Express Base 6.0 §6.6.1).
const LINK_RECOVERY_MS: u64 = 100;
/// Between looks at the hosts.
const POLL_US: u64 = 1000;

/// What runs a host's domain.
pub enum Connection {
    /// Its firmware: the ICM transport and the firmware's protocol
    /// parameters, with what arrived before DRIVER_READY was answered.
    Firmware {
        icm: Box<icm::Host<ring::Mmio>>,
        ready: icm::DriverReady,
        early: Vec<icm::Event>,
    },
    /// This mount.
    Software { manager: Manager },
}

/// An attached host, with the claimed function and BAR0 mapping it runs on.
pub struct Host {
    pub location: String,
    pub connection: Connection,
    _owners: (Function<OwnedConfig>, Mapping),
}

/// Why a host was not attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The `IMR_VALID` property says the firmware image is invalid, which
    /// `nhi_imr_valid` refuses.
    InvalidFirmwareImage,
    Clock,
    Ring(ring::Error),
    Controller(controller::Error),
    Icm(icm::Error),
    Channel(channel::Error),
    Platform(ServiceError),
    /// What arrived below a hot-plug bridge has no place.
    Arrival(hotplug::Error),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFirmwareImage => f.write_str("firmware image not valid"),
            Self::Clock => f.write_str("uncalibrated clock"),
            Self::Ring(error) => write!(f, "NHI ring: {error:?}"),
            Self::Controller(error) => write!(f, "NHI preparation: {error:?}"),
            Self::Icm(error) => write!(f, "ICM: {error:?}"),
            Self::Channel(error) => write!(f, "control channel: {error:?}"),
            Self::Platform(error) => write!(f, "connection manager: {error}"),
            Self::Arrival(hotplug::Error::Buses) => {
                f.write_str("tunnelled PCIe device: the bridge has no bus numbers left for it")
            }
            Self::Arrival(hotplug::Error::Windows) => {
                f.write_str("tunnelled PCIe device: the bridge's memory windows cannot hold it")
            }
        }
    }
}

/// Whether the function's ACPI companion says its firmware image is
/// invalid, as `nhi_imr_valid` reads `IMR_VALID`: absent means valid.
#[cfg(feature = "native-acpi")]
fn invalid_image(services: &dyn NativeServices, address: Address, bridges: &[Bridge]) -> bool {
    use crate::platform::acpi::Value;
    services
        .acpi()
        .and_then(|session| super::companion(session, address, bridges))
        .is_some_and(|companion| {
            matches!(companion.property("IMR_VALID"), Ok(Some(Value::Integer(0))))
        })
}

#[cfg(not(feature = "native-acpi"))]
fn invalid_image(_: &dyn NativeServices, _: Address, _: &[Bridge]) -> bool {
    false
}

/// Attach the USB4 host at `address`: prepare its NHI as `nhi_probe` does,
/// enable its bus mastering, then start its connection manager. A firmware
/// one has answered DRIVER_READY on return; a software one is yet to run.
/// `isolated` is [`NativeServices::usb4_platform`]'s.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, `clock` is the
/// handoff's calibrated clock, and `bridges` lists the segment's bridges.
#[expect(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(in crate::probe) unsafe fn attach(
    services: &dyn NativeServices,
    address: Address,
    bridges: &[Bridge],
    clock: Clock,
    isolated: bool,
) -> Result<Host, Failure> {
    let refused =
        |refusal: Refusal, kept: Option<Box<dyn core::any::Any>>| (Error::Usb4(refusal), kept);
    if invalid_image(services, address, bridges) {
        return Err(refused(Refusal::InvalidFirmwareImage, None));
    }
    let Claimed {
        mut function,
        domain,
        bars,
    } = claim(services, address).map_err(|error| (Error::Native(error), None))?;
    let family = icm::Family::of(function.vendor, function.device);
    let location = format!("{address}");
    let mapping = match map(services, address, &bars, 0) {
        Ok(mapping) => mapping,
        Err(error) => {
            return Err((Error::Native(error), Some(Box::new((function, domain)))));
        }
    };
    let window = mapping
        .bytes()
        .and_then(|bytes| Ok((mapping.address(0, bytes)?, bytes)));
    let (window, bytes) = match window {
        Ok(window) => window,
        Err(error) => {
            return Err((
                Error::Native(ServiceError::Mapping(error)),
                Some(Box::new((function, domain, mapping))),
            ));
        }
    };
    // SAFETY: `window` is the whole owned uncached BAR0 mapping, which the
    // host keeps with every reference to these registers.
    let registers = match unsafe { ring::Mmio::new(window, bytes) } {
        Ok(registers) => Arc::new(registers),
        Err(error) => {
            return Err(refused(
                Refusal::Ring(error),
                Some(Box::new((function, domain, mapping))),
            ));
        }
    };
    let now = || {
        clock
            .try_now_us()
            .map(|us| us / 1000)
            .map_err(|_| Refusal::Clock)
    };
    let started = (|| {
        let config = function.config();
        let command = config.read16(regs::COMMAND);
        if command & regs::COMMAND_MEMORY == 0 {
            config.write16(regs::COMMAND, command | regs::COMMAND_MEMORY);
        }
        {
            // SAFETY: the configuration and registers are the claimed
            // function's and its BAR0, and the claimed requester's DMA and
            // interrupts are stopped.
            let mut controller = unsafe { Controller::new(&mut *config, registers.clone()) }
                .map_err(Refusal::Controller)?;
            while controller
                .poll(now()?)
                .map_err(Refusal::Controller)?
                .is_none()
            {
                core::hint::spin_loop();
            }
        }
        // `nhi_probe`'s pci_set_master, now that the domain is attached.
        let command = config.read16(regs::COMMAND);
        config.write16(regs::COMMAND, command | regs::COMMAND_MASTER);
        if family.is_none() {
            let platform = services
                .usb4_platform(&location, isolated)
                .map_err(Refusal::Platform)?;
            // SAFETY: as above; the domain is the claimed requester's own,
            // the prepared NHI has its interrupts masked and rings idle, and
            // no firmware runs a connection manager on it.
            let mut channel = unsafe {
                Channel::new(
                    registers.clone(),
                    services.pages(),
                    domain.clone(),
                    u64::MAX,
                )
            }
            .map_err(Refusal::Channel)?;
            channel.start(now()?).map_err(Refusal::Channel)?;
            let manager = Manager::new(Box::new(channel), platform);
            return Ok(Connection::Software { manager });
        }
        // SAFETY: as above; this mount negotiates no native USB4 control, so
        // its firmware's ICM is the connection manager.
        let mut host = unsafe {
            icm::Host::new(
                &*config,
                registers.clone(),
                services.pages(),
                domain.clone(),
                u64::MAX,
            )
        }
        .map_err(Refusal::Icm)?;
        host.start(now()?).map_err(Refusal::Icm)?;
        let request = host.driver_ready(now()?).map_err(Refusal::Icm)?;
        let mut early = Vec::new();
        loop {
            match host.poll(now()?).map_err(Refusal::Icm)? {
                Some(icm::Event::DriverReady {
                    request: answered,
                    parameters,
                }) if answered == request => {
                    return Ok(Connection::Firmware {
                        icm: Box::new(host),
                        ready: parameters,
                        early,
                    });
                }
                Some(event) => early.push(event),
                None => core::hint::spin_loop(),
            }
        }
    })();
    match started {
        Ok(connection) => Ok(Host {
            location,
            connection,
            _owners: (function, mapping),
        }),
        Err(refusal) => Err(refused(
            refusal,
            Some(Box::new((function, domain, mapping, registers))),
        )),
    }
}

/// A hot-plug bridge, and how to reach what hangs from it.
struct Slot {
    window: EcamWindow,
    address: Address,
}

impl Slot {
    /// Whether something has arrived below it for [`hotplug::adopt`].
    ///
    /// # Safety
    /// As for [`bring_up`].
    unsafe fn arrived(&self) -> bool {
        let Address {
            bus,
            device,
            function,
            ..
        } = self.address;
        // SAFETY: forwarded; the window is mapped, and only probe reaches it.
        let config = unsafe { self.window.config(bus, device, function) };
        // SAFETY: as above.
        hotplug::arrived(&config, |bus, device, function| unsafe {
            self.window.config(bus, device, function)
        })
    }
}

/// What a look over the mapped windows found.
#[derive(Default)]
struct Survey {
    bridges: Vec<Bridge>,
    slots: Vec<Slot>,
    hosts: Vec<Address>,
}

/// # Safety
/// As for [`bring_up`].
unsafe fn survey(handoff: &Handoff) -> Survey {
    let mut found = Survey::default();
    for window in &handoff.ecam {
        if !handoff.is_mapped(&window.range()) {
            continue;
        }
        // SAFETY: mapped as checked; the caller owns the machine.
        for mut function in unsafe { Function::enumerate(window) } {
            let address = function.address;
            if function.class[..2] == [6, 4] {
                found.bridges.push(Bridge {
                    address,
                    secondary: function.config().read8(0x19),
                    aspm: crate::bus::pci::aspm_control(&function),
                });
                if hotplug::hot_plug_capable(&*function.config()) {
                    found.slots.push(Slot {
                        window: *window,
                        address,
                    });
                }
            }
            if Kind::of(&function) == Some(Kind::Usb4)
                && icm::Family::of(function.vendor, function.device).is_none()
            {
                found.hosts.push(address);
            }
        }
    }
    found
}

/// Poll the software connection managers for up to `ms`, until `done` holds.
/// `done` hears whether any of them has work in progress.
fn pump(hosts: &mut [Host], clock: Clock, ms: u64, mut done: impl FnMut(bool) -> bool) {
    let Ok(start) = clock.try_now_us() else {
        return;
    };
    loop {
        let mut busy = false;
        for host in hosts.iter_mut() {
            if let Connection::Software { manager } = &mut host.connection {
                busy |= manager.poll() && !manager.idle();
            }
        }
        let Ok(now) = clock.try_now_us() else {
            return;
        };
        if done(busy) || now.saturating_sub(start) >= ms * 1000 || clock.try_delay(POLL_US).is_err()
        {
            return;
        }
    }
}

/// Start the USB4 hosts no firmware runs a connection manager on, let their
/// domains come up, and number and place the PCIe functions they tunnel. The
/// addresses returned are the hosts dealt with here, attached or not.
///
/// PCIe tunnels of later plug events keep their functions unused: there is no
/// scan to find them, as Linux's pciehp would.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`. The caller owns the
/// machine, and no driver has started.
pub(in crate::probe) unsafe fn bring_up(
    services: &dyn NativeServices,
    handoff: &Handoff,
    devices: &mut Devices,
) -> Vec<Address> {
    // SAFETY: forwarded.
    let Survey {
        bridges,
        slots,
        hosts,
    } = unsafe { survey(handoff) };
    let clock = handoff.clock;
    let isolated = hosts
        .iter()
        .all(|address| services.dma_translated(*address))
        && slots
            .iter()
            .all(|slot| services.dma_subtree_translated(slot.address));
    for &address in &hosts {
        // SAFETY: as for tg3 in probe; the look found every bridge.
        match unsafe { attach(services, address, &bridges, clock, isolated) } {
            Ok(host) => devices.usb4_hosts.push(host),
            Err((error, kept)) => {
                devices.failures.push((address, error));
                devices.owners.extend(kept);
            }
        }
    }
    let attached = &mut devices.usb4_hosts;
    let Ok(start) = clock.try_now_us() else {
        return hosts;
    };
    let mut quiet_since = start;
    pump(attached, clock, SETTLE_MS, |busy| {
        let now = clock.try_now_us().unwrap_or(start);
        if busy {
            quiet_since = now;
        }
        now.saturating_sub(quiet_since) >= QUIET_MS * 1000
    });
    let tunnels: usize = attached
        .iter()
        .map(|host| match &host.connection {
            Connection::Software { manager } => manager.pcie_tunnels(),
            Connection::Firmware { .. } => 0,
        })
        .sum();
    if tunnels == 0 {
        return hosts;
    }
    let waiting = || {
        // SAFETY: forwarded.
        slots.iter().filter(|slot| unsafe { slot.arrived() })
    };
    pump(attached, clock, LINK_MS, |_| waiting().count() >= tunnels);
    pump(attached, clock, LINK_RECOVERY_MS, |_| false);
    let adopting: Vec<&Slot> = waiting().collect();
    for slot in adopting {
        let bridge = slot.address;
        // SAFETY: forwarded; the functions below a bridge are still probe's.
        let adopted = hotplug::adopt(
            bridge.segment,
            (bridge.bus, bridge.device, bridge.function),
            |bus, device, function| unsafe { slot.window.config(bus, device, function) },
        );
        let arrivals = match adopted {
            Ok(arrivals) => arrivals,
            Err(error) => {
                devices
                    .failures
                    .push((bridge, Error::Usb4(Refusal::Arrival(error))));
                continue;
            }
        };
        // Observe every present RID in the owned reserved subtree, including
        // functions adoption cannot place (such as ARI functions above 7).
        // Omitting such a PF could misclassify another function as physical.
        // SAFETY: this is the kept original slot bridge, still exclusively owned.
        let configuration = unsafe {
            slot.window
                .config(bridge.bus, bridge.device, bridge.function)
        };
        let (first, last) = (configuration.read8(0x19), configuration.read8(0x1a));
        if first <= bridge.bus
            || last < first
            || first < slot.window.start_bus
            || last > slot.window.end_bus
        {
            devices.failures.push((
                bridge,
                Error::Native(ServiceError::Refused(
                    "PCI arrival has no owned downstream bus range",
                )),
            ));
            continue;
        }
        let mut functions = Vec::new();
        for bus in first..=last {
            for number in 0..=255u16 {
                let address = Address {
                    segment: bridge.segment,
                    bus,
                    device: (number >> 3) as u8,
                    function: (number & 7) as u8,
                };
                // SAFETY: the original slot owns this complete reserved range;
                // no child driver has started or configuration writer overlaps.
                let configuration =
                    unsafe { slot.window.config(bus, address.device, address.function) };
                if configuration.read16(0) != u16::MAX {
                    functions.push(address);
                }
            }
        }
        let mut read32 = |address: Address, offset: u16| {
            if address.segment != slot.window.segment
                || !(slot.window.start_bus..=slot.window.end_bus).contains(&address.bus)
                || (address != bridge && !functions.contains(&address))
                || address.device >= 32
                || address.function >= 8
                || offset > 4092
                || !offset.is_multiple_of(4)
            {
                return None;
            }
            // SAFETY: bring_up owns this exact complete adopted subtree and
            // its original bridge under the same kept mapped ECAM window.
            let config = unsafe {
                slot.window
                    .config(address.bus, address.device, address.function)
            };
            Some(config.read32(offset))
        };
        // SAFETY: adopt just completed the entire subtree under this owned
        // slot. No child driver has started; all prior PF/VF assignments and
        // the bridge's updated routing remain owned throughout observation.
        if let Err(error) = unsafe {
            services.requesters_arrived(crate::probe::services::ArrivalInventory {
                bridge,
                functions: &functions,
                read32: &mut read32,
            })
        } {
            devices.failures.push((bridge, Error::Native(error)));
        }
        for address in arrivals.payload_mismatches {
            devices.warnings.push((
                address,
                Warning::Message("largest payload below its link's: expect malformed packets"),
            ));
        }
    }
    hosts
}
