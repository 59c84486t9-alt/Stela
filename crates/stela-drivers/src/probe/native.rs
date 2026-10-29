//! PCI functions whose drivers attach through [`NativeServices`]: each takes
//! a stopped requester, its DMA domain and owned BAR mappings from the mount.
//! Among them are the AMD and Intel sensor hubs ([`SensorHub`]).
use super::{Error, NativeServices, ServiceError};
#[cfg(feature = "native-acpi")]
use crate::net::wifi;
use crate::{
    Clock,
    bus::{
        dma::mapping::DmaDomain,
        mmio::owned::{CacheAttribute, Mapping, Protection},
        pci::{
            Address, Bar, Function,
            owned::OwnedConfig,
            requester::{FunctionRole, StoppedRequester},
        },
        vmd,
    },
    input::{ish, sfh},
    net::{
        Link, LinkError, Mac,
        aqtion::{self, Aqtion, MappedRegisters},
        tg3,
    },
    storage::nvme,
};
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::any::Any;

/// A Broadcom Tigon3 adapter over owned BAR0 and APE mappings.
pub type Tg3 = tg3::Packet<tg3::io::Mmio<OwnedConfig>, Clock>;

/// A link driver and the PCI location it was found at.
pub struct Located<L> {
    pub location: String,
    pub link: L,
}

impl<L: Link> Link for Located<L> {
    fn mac(&self) -> Mac {
        self.link.mac()
    }
    fn carrier(&mut self) -> bool {
        self.link.carrier()
    }
    fn signals(&self) -> bool {
        self.link.signals()
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        self.link.transmit(frame)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.link.receive()
    }
}

/// The drivers here that attach through [`NativeServices`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Tg3,
    Aqtion,
    Vmd,
    /// AMD Sensor Fusion Hub v2.
    Sfh,
    /// Intel Integrated Sensor Hub.
    Ish,
    /// An Intel Wi-Fi function, which `iwl_pci_probe` identifies further.
    IntelWifi,
}

impl Kind {
    pub(super) fn of(function: &Function) -> Option<Self> {
        if vmd::Profile::identify(function.vendor, function.device).is_ok() {
            Some(Self::Vmd)
        } else if tg3::candidate(function.vendor, function.device, function.class) {
            Some(Self::Tg3)
        } else if aqtion::Profile::identify(function.vendor, function.device).is_some()
            && function.class == [2, 0, 0]
        {
            Some(Self::Aqtion)
        } else if (function.vendor, function.device) == (0x1022, 0x15e4) {
            Some(Self::Sfh)
        } else if (function.vendor, function.device) == (0x8086, 0x9d35) {
            Some(Self::Ish)
        } else if function.vendor == 0x8086 && function.class[..2] == [2, 0x80] {
            Some(Self::IntelWifi)
        } else {
            None
        }
    }
}

/// A function claimed from the mount, before any device effect.
struct Claimed {
    function: Function<OwnedConfig>,
    domain: Arc<dyn DmaDomain>,
    bars: [Option<Bar>; 6],
}

fn claim(services: &dyn NativeServices, address: Address) -> Result<Claimed, ServiceError> {
    let requester = services.claim_stopped(address)?;
    let (requester, binding) = requester
        .into_dma_binding()
        .map_err(|(error, _)| ServiceError::Claim(error))?;
    let domain = services.domain(binding)?;
    let mut function = requester.into_function();
    let bars = function.bars();
    Ok(Claimed {
        function,
        domain,
        bars,
    })
}

fn map(
    services: &dyn NativeServices,
    address: Address,
    bars: &[Option<Bar>; 6],
    index: usize,
) -> Result<Mapping, ServiceError> {
    match bars[index] {
        Some(bar @ Bar::Memory { .. }) => services.map_bar(address, bar),
        _ => Err(ServiceError::Refused("missing memory BAR")),
    }
}

/// What a failed attach leaves: the error and any owner that must outlive
/// the device because it may hold mappings or DMA.
pub(super) type Failure = (Error, Option<Box<dyn Any>>);

/// Attach a Tigon3 adapter: BAR0 holds the MAC registers, BAR2 the APE.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, and `clock` is the
/// handoff's calibrated clock.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn tg3(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<Located<Tg3>, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let claimed = claim(services, address).map_err(refused)?;
    let mac = map(services, address, &claimed.bars, 0).map_err(refused)?;
    let ape = map(services, address, &claimed.bars, 2).map_err(refused)?;
    let window = |mapping: &Mapping| {
        let bytes = mapping.bytes()?;
        Ok((mapping.address(0, bytes)?, bytes))
    };
    let ((mac_window, mac_bytes), (ape_window, ape_bytes)) = window(&mac)
        .and_then(|mac| Ok((mac, window(&ape)?)))
        .map_err(|error| refused(ServiceError::Mapping(error)))?;
    let windows: Arc<dyn Any> = Arc::new((mac, ape));
    // SAFETY: the mount claimed the stopped function and mapped exactly its
    // BAR0 and BAR2 uncached, and `windows` keeps both mappings alive.
    let registers = unsafe {
        tg3::io::Mmio::from_owned_windows(
            claimed.function,
            mac_window,
            mac_bytes,
            ape_window,
            ape_bytes,
            windows,
        )
    }
    .map_err(|(error, function, windows)| {
        (
            Error::Tg3(error),
            Some(Box::new((function, windows)) as Box<dyn Any>),
        )
    })?;
    // SAFETY: the registers satisfy their ownership contract and `clock` is
    // the calibrated handoff clock.
    let hardware = unsafe { tg3::Hardware::new(registers, clock) };
    // SAFETY: the mount's domain isolates this requester and its pages are
    // kept; the function was stopped when claimed.
    match unsafe { tg3::Packet::attach(hardware, services.pages(), claimed.domain) } {
        Ok(link) => Ok(Located {
            location: alloc::format!("{address}"),
            link,
        }),
        Err((error, link)) => Err((Error::Tg3(error), Some(Box::new(link)))),
    }
}

/// Attach an Aquantia AQtion adapter over its BAR0 registers.
///
/// # Safety
/// As for [`tg3`].
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn aqtion(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<Located<Aqtion>, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let claimed = claim(services, address).map_err(refused)?;
    let registers = map(services, address, &claimed.bars, 0).map_err(refused)?;
    let registers = MappedRegisters::new(registers).map_err(|(error, mapping)| {
        (
            Error::Aqtion(error),
            Some(Box::new(mapping) as Box<dyn Any>),
        )
    })?;
    // SAFETY: the mount claimed the stopped function, mapped its BAR0 and
    // supplied an isolating domain; the probe runs in process context.
    match unsafe {
        Aqtion::attach(
            claimed.function,
            registers,
            clock,
            claimed.domain,
            services.pages(),
        )
    } {
        Ok(link) => Ok(Located {
            location: alloc::format!("{address}"),
            link,
        }),
        Err((error, link)) => Err((Error::Aqtion(error), Some(Box::new(link)))),
    }
}

/// An Intel AX200/AX210 adapter over its owned BAR0, reading its ACPI
/// companion.
#[cfg(feature = "native-acpi")]
pub type IntelWifi = wifi::intel::link::Wifi<
    wifi::intel::boot::NativeBootIo,
    wifi::intel::radio::bios::service::native::NativeBios,
>;

/// Attach an Intel Wi-Fi function: BAR0 holds its CSRs.
///
/// # Safety
/// As for [`tg3`]; `inputs.bios` reads this function's own ACPI companion.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
#[cfg(feature = "native-acpi")]
pub(super) unsafe fn intel_wifi<B: wifi::intel::radio::bios::service::BiosIo>(
    services: &dyn NativeServices,
    address: Address,
    inputs: wifi::intel::link::Inputs<B>,
) -> Result<Located<wifi::intel::link::Wifi<wifi::intel::boot::NativeBootIo, B>>, Failure> {
    use crate::bus::pci::ConfigSpace;
    use wifi::intel::attach::{AttachError, Pci, attach};
    let refused = |error: ServiceError| (Error::Native(error), None);
    let Claimed {
        mut function,
        domain,
        bars,
    } = claim(services, address).map_err(refused)?;
    let registers = map(services, address, &bars, 0).map_err(refused)?;
    let window = registers
        .address(0, 8192)
        .map_err(|error| refused(ServiceError::Mapping(error)))?;
    let vendor = function.vendor;
    let device = function.device;
    let config = function.config();
    let pci = Pci {
        vendor,
        device,
        subsystem_vendor: config.read16(0x2c),
        subsystem_device: config.read16(0x2e),
        revision: config.read8(0x08),
    };
    // iwl_pci_probe: memory decoding and bus mastering, polled.
    function.enable_polled();
    let owner: Arc<dyn Any> = Arc::new((function, registers));
    let kept = |owner: &Arc<dyn Any>| Some(Box::new(owner.clone()) as Box<dyn Any>);
    // SAFETY: the mount claimed the stopped function and mapped its BAR0
    // uncached; `owner` keeps both, and its interrupts are off.
    let io = unsafe {
        wifi::intel::boot::NativeBootIo::from_window(window.cast(), owner.clone(), inputs.clock)
    }
    .map_err(|error| (Error::IntelWifi(AttachError::Boot(error)), kept(&owner)))?;
    // SAFETY: the mount's domain isolates this requester, and the caller's
    // contract covers `inputs`.
    match unsafe { attach(io, pci, domain, inputs) } {
        Ok(link) => Ok(Located {
            location: alloc::format!("{address}"),
            link,
        }),
        Err(error) => Err((Error::IntelWifi(error), kept(&owner))),
    }
}

/// The ACPI companion of the function at `address`, as Linux's
/// `acpi_pci_find_companion` finds it: from the root bridge whose `_SEG` and
/// `_BBN` name its root bus, the child whose `_ADR` names each bridge on the
/// way down, then the function. `bridges` lists each PCI bridge with its
/// secondary bus.
#[cfg(feature = "native-acpi")]
pub(super) fn companion(
    session: &'static crate::platform::acpi::Session,
    address: Address,
    bridges: &[(Address, u8)],
) -> Option<crate::platform::acpi::Handle<'static>> {
    use crate::platform::acpi::{Handle, Value};
    let integer = |handle: Handle<'static>, name: &str| -> Option<u64> {
        handle.child(name).ok()?;
        match handle.evaluate(Some(name), &[]).ok()? {
            Some(Value::Integer(value)) => Some(value),
            _ => None,
        }
    };
    let parent = |handle: Handle<'static>| -> Option<String> {
        let path = handle.path().ok()?;
        path.rsplit_once('.')
            .map(|(parent, _)| String::from(parent))
    };
    let mut chain = alloc::vec![(address, false)];
    let mut bus = address.bus;
    while let Some(&(bridge, _)) = bridges.iter().find(|(bridge, secondary)| {
        bridge.segment == address.segment && *secondary == bus && bridge.bus < bus
    }) {
        chain.push((bridge, true));
        bus = bridge.bus;
    }
    let devices = session.all_devices().ok()?;
    let mut roots = session.devices("PNP0A08").ok()?;
    roots.extend(session.devices("PNP0A03").ok()?);
    let mut current = roots.into_iter().find(|root| {
        integer(*root, "_SEG").unwrap_or(0) == u64::from(address.segment)
            && integer(*root, "_BBN").unwrap_or(0) == u64::from(bus)
    })?;
    for (address, bridge) in chain.into_iter().rev() {
        let path = current.path().ok()?;
        let adr = (u64::from(address.device) << 16) | u64::from(address.function);
        // acpi_find_child_device and find_child_checks: an enabled device
        // without _HID wins; one without _STA or with a _HID only scores
        // lower; a bridge's companion needs children.
        let mut best: Option<(u8, Handle<'static>)> = None;
        for &device in &devices {
            if parent(device).as_deref() != Some(path.as_str())
                || integer(device, "_ADR") != Some(adr)
            {
                continue;
            }
            if bridge {
                let own = device.path().ok()?;
                if !devices
                    .iter()
                    .any(|child| parent(*child).as_deref() == Some(own.as_str()))
                {
                    continue;
                }
            }
            let score = if device.child("_STA").is_err() {
                1
            } else if integer(device, "_STA").is_none_or(|status| status & 2 == 0) {
                continue;
            } else if device.child("_HID").is_ok() {
                1
            } else {
                3
            };
            if best.is_none_or(|(kept, _)| score > kept) {
                best = Some((score, device));
            }
            if score == 3 {
                break;
            }
        }
        current = best?.1;
    }
    Some(current)
}

/// An Intel VMD host's first NVMe controller, the devices behind it no
/// driver here takes, and the hierarchy owner that hands back the parent's
/// owners when the controller retires.
pub struct Vmd {
    pub nvme: Option<nvme::Attached>,
    pub others: Vec<vmd::Child>,
    pub owner: Box<dyn Any>,
}

/// Attach the NVMe controller behind an Intel VMD host: BAR0 holds the
/// children's configuration space, BAR2 and BAR4 their memory windows.
///
/// # Safety
/// As for [`tg3`]; every device behind the host is stopped as well.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn vmd(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<Vmd, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let failed = |error: vmd::Error, owner: Box<dyn Any>| (Error::Vmd(error), Some(owner));
    let requester = services.claim_stopped(address).map_err(refused)?;
    let (requester, binding) = requester
        .into_dma_binding()
        .map_err(|(error, _)| refused(ServiceError::Claim(error)))?;
    let domain = services.domain(binding).map_err(refused)?;
    let mut function = requester.into_function();
    let profile = vmd::Profile::identify(function.vendor, function.device)
        .map_err(|error| (Error::Vmd(error), None))?;
    let bars = function.bars();
    // SAFETY: the mount claimed this function stopped, and sizing its BARs
    // with decode off left it so.
    let requester = unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) }
        .map_err(|(error, function)| {
            (
                Error::Native(ServiceError::Claim(error)),
                Some(Box::new(function) as Box<dyn Any>),
            )
        })?;
    let reserve = |index: usize| match bars[index] {
        Some(bar @ Bar::Memory { .. }) => services.bar_resource(address, bar),
        _ => Err(ServiceError::Refused("missing memory BAR")),
    };
    let cfgbar = reserve(0).map_err(refused)?;
    let membar1 = reserve(2).map_err(refused)?;
    let membar2 = reserve(4).map_err(refused)?;
    let authority = services.authority().map_err(refused)?;
    let map = |resource: &crate::bus::mmio::owned::Resource, window: core::ops::Range<u64>| {
        authority
            .map(
                resource.clone(),
                window.start as usize,
                (window.end - window.start) as usize,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(|error| refused(ServiceError::Mapping(error)))
    };
    let configuration = map(&cfgbar, 0..cfgbar.physical_span().bytes())?;
    let shadow = profile
        .shadow_window()
        .map(|window| map(&membar2, window))
        .transpose()?;
    let resources = vmd::NativeResources {
        requester,
        bars: [cfgbar, membar1, membar2],
        cfgbar: configuration,
        shadow,
        msix: None,
    };
    // SAFETY: the mount reserved and mapped these BARs for this stopped host,
    // and no other owner reaches the hierarchy behind it.
    let registers = unsafe { vmd::NativeRegisters::claim(resources) }
        .map_err(|(error, resources)| failed(error, Box::new(resources)))?;
    let mut host = vmd::Host::initialize(registers).map_err(|(error, registers)| {
        (
            Error::Vmd(error),
            registers.map(|r| Box::new(r) as Box<dyn Any>),
        )
    })?;
    let mut others = match host.scan() {
        Ok(children) => children,
        Err(error) => return Err(failed(error, Box::new(host))),
    };
    let Some(index) = others.iter().position(|child| child.class == [1, 8, 2]) else {
        return Ok(Vmd {
            nvme: None,
            others,
            owner: Box::new(host),
        });
    };
    let child = others.remove(index);
    let bytes = match host.memory_bar_bytes(child.address) {
        Ok(bytes) => bytes,
        Err(error) => return Err(failed(error, Box::new(host))),
    };
    // SAFETY: `bytes` is the child's firmware-assigned BAR0, sized with its
    // decode off, and the stopped hierarchy has no other owner.
    let bar = match unsafe { vmd::nvme::FirmwareBar::claim(&mut host, child.address, bytes) } {
        Ok(bar) => bar,
        Err(error) => return Err(failed(error, Box::new(host))),
    };
    let label = alloc::format!(
        "{address} VMD {:02x}:{:02x}.{}",
        child.address.bus,
        child.address.device,
        child.address.function
    );
    // SAFETY: the mount's domain covers the host's requester and its aliases,
    // its permission issued these mappings, and the hierarchy is stopped.
    match unsafe { vmd::nvme::attach(host, bar, domain, authority, services.pages(), clock, label) }
    {
        Ok((attached, hierarchy)) => Ok(Vmd {
            nvme: Some(attached),
            others,
            owner: Box::new(hierarchy),
        }),
        Err((error, hierarchy)) => Err((Error::Device(error), Some(Box::new(hierarchy)))),
    }
}

/// A sensor hub: AMD's Sensor Fusion Hub, or Intel's Integrated Sensor Hub
/// when none of its HID clients is a keyboard or pointer.
pub enum SensorHub {
    Sfh(Box<Sfh>),
    Ish(Box<ish::Native>),
}

/// AMD SFH over its owned BAR2.
pub type Sfh = sfh::Controller<sfh::pci::NativeRegisters, Clock>;

/// PCI host bridges of Intel's Mehlow platforms, on which Linux `ish_probe`
/// refuses the ISH (`ish_invalid_pci_ids`).
pub(super) const MEHLOW: [u16; 2] = [0xa309, 0xa30a];

/// A claimed requester, rewrapped after its BARs were sized, its DMA domain
/// and its BARs.
type Sized = (StoppedRequester, Arc<dyn DmaDomain>, [Option<Bar>; 6]);

/// The function's claimed requester, its DMA domain and its BARs.
#[allow(
    clippy::result_large_err,
    reason = "a failed claim hands back the owners that must outlive the device"
)]
fn claim_sized(services: &dyn NativeServices, address: Address) -> Result<Sized, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let requester = services.claim_stopped(address).map_err(refused)?;
    let (requester, binding) = requester
        .into_dma_binding()
        .map_err(|(error, _)| refused(ServiceError::Claim(error)))?;
    let domain = services.domain(binding).map_err(refused)?;
    let mut function = requester.into_function();
    let bars = function.bars();
    // SAFETY: the mount claimed this function stopped, and sizing its BARs
    // with decode off left it so.
    let requester = unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) }
        .map_err(|(error, function)| {
            (
                Error::Native(ServiceError::Claim(error)),
                Some(Box::new(function) as Box<dyn Any>),
            )
        })?;
    Ok((requester, domain, bars))
}

/// Attach an AMD Sensor Fusion Hub and enable its sensors.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, and `clock` is the
/// handoff's calibrated clock.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn sfh(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<Sfh, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let (requester, domain, bars) = claim_sized(services, address)?;
    let Some(bar @ Bar::Memory { .. }) = bars[2] else {
        return Err(refused(ServiceError::Refused("missing memory BAR")));
    };
    let mapping = services.map_bar(address, bar).map_err(refused)?;
    // SAFETY: the mount claimed the stopped function and mapped exactly its
    // BAR2 uncached.
    let registers = unsafe { sfh::pci::NativeRegisters::attach(requester, mapping, bar) }.map_err(
        |failure| {
            (
                Error::Sfh(failure.error),
                Some(Box::new((failure.function, failure.mapping)) as Box<dyn Any>),
            )
        },
    )?;
    // SAFETY: `domain` is the mount's domain for this requester, which meets
    // the DmaDomain contract for its kind.
    let mut controller = unsafe { sfh::Controller::claim(registers, clock, domain) }
        .map_err(|error| (Error::Sfh(error), None))?;
    match controller.initialize(services.pages()) {
        Ok(()) => Ok(controller),
        Err(error) => Err((
            Error::Sfh(error),
            Some(Box::new(controller) as Box<dyn Any>),
        )),
    }
}

/// Attach an Intel Integrated Sensor Hub and start its HID clients.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, `clock` is the
/// handoff's calibrated clock, and probe's scan found no Mehlow host bridge
/// ([`MEHLOW`]).
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn ish(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<ish::Native, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let (requester, domain, bars) = claim_sized(services, address)?;
    let interrupts = services.interrupts().map_err(refused)?;
    let authority = services.authority().map_err(refused)?;
    let Some(bar @ Bar::Memory { .. }) = bars[0] else {
        return Err(refused(ServiceError::Refused("missing memory BAR")));
    };
    let mapping = services.map_bar(address, bar).map_err(refused)?;
    // SAFETY: the mount mapped exactly BAR0 of the claimed function uncached.
    let registers = unsafe { ish::MappedRegisters::new(mapping) }
        .map_err(|(error, mapping)| (Error::Ish(error), Some(Box::new(mapping) as Box<dyn Any>)))?;
    // SAFETY: the handoff's clock is the calibrated invariant TSC.
    let clock =
        unsafe { ish::NativeClock::new(clock) }.map_err(|error| (Error::Ish(error), None))?;
    let inputs = ish::Inputs {
        function: requester.into_function(),
        retained: Arc::new(authority),
        registers,
        domain,
        interrupts,
        clock,
    };
    // SAFETY: the mount claimed the stopped function, mapped its BAR0 and
    // gave its domain and MSI controller; the caller checked for Mehlow.
    let mut native = unsafe { ish::Native::new(inputs) }
        .map_err(|(error, inputs)| (Error::Ish(error), Some(Box::new(inputs) as Box<dyn Any>)))?;
    match native.start() {
        Ok(()) => Ok(native),
        Err(error) => Err((Error::Ish(error), Some(Box::new(native) as Box<dyn Any>))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::services::tests::Refusing;

    fn address() -> Address {
        Address {
            segment: 0,
            bus: 3,
            device: 0,
            function: 0,
        }
    }

    #[test]
    fn a_refused_claim_attaches_nothing_and_keeps_no_owner() {
        let services = Refusing::default();
        let clock = Clock {
            ticks_per_microsecond: 1000,
        };
        // SAFETY: the refusing services transfer no owner.
        let tg3 = unsafe { tg3(&services, address(), clock) };
        assert!(matches!(
            tg3,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        // SAFETY: as above.
        let aqtion = unsafe { aqtion(&services, address(), clock) };
        assert!(matches!(
            aqtion,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        // SAFETY: as above.
        let vmd = unsafe { vmd(&services, address(), clock) };
        assert!(matches!(
            vmd,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        assert_eq!(*services.requests.borrow(), [address(); 3]);
    }
}
