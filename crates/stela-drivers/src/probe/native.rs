//! PCI functions whose drivers attach through [`NativeServices`]: each takes
//! a stopped requester, its DMA domain and owned BAR mappings from the mount.
//! Among them are the AMD and Intel sensor hubs ([`SensorHub`]).
use super::{Error, NativeServices, ServiceError};
#[cfg(feature = "native-acpi")]
use crate::net::wifi;
use crate::{
    Clock,
    bluetooth::{bcm4377, intel_pcie},
    bus::{
        dma::{DomainAllocator, mapping::DmaDomain},
        mmio::owned::{CacheAttribute, Mapping, Protection},
        pci::{
            Address, Bar, ConfigSpace, Function,
            msix::MappedBar,
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
        wifi::{mediatek, realtek as realtek_wifi},
    },
    storage::nvme,
    usb::ehci,
};
use alloc::{boxed::Box, rc::Rc, string::String, sync::Arc, vec::Vec};
use core::{any::Any, cell::RefCell};

pub mod hda;
pub mod usb4;

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
    /// A MediaTek Wi-Fi function; only MT7925 attaches.
    MediatekWifi,
    /// A Realtek Wi-Fi function; only RTL8822C attaches.
    RealtekWifi,
    /// An Intel PCIe Bluetooth function, as `btintel_pcie_table` lists them.
    IntelBluetooth,
    /// A Broadcom PCIe Bluetooth function, as `bcm4377_devid_table` lists
    /// them.
    Bcm4377,
    /// An EHCI host controller (class 0c0320).
    Ehci,
    /// An HD Audio controller the bounded identity table admits.
    Hda,
    /// A USB4/Thunderbolt host interface, as `pci.c::nhi_ids` lists them.
    Usb4,
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
        } else if function.vendor == 0x14c3 && function.class[..2] == [2, 0x80] {
            Some(Self::MediatekWifi)
        } else if function.vendor == 0x10ec
            && function.class[..2] == [2, 0x80]
            && realtek_wifi::identity::RTL8822C_DEVICES.contains(&function.device)
        {
            Some(Self::RealtekWifi)
        } else if function.vendor == 0x8086 && intel_pcie::DEVICE_IDS.contains(&function.device) {
            Some(Self::IntelBluetooth)
        } else if function.vendor == 0x14e4
            && function.class[..2] == [2, 0x80]
            && bcm4377::Chip::of_device(function.device).is_some()
        {
            Some(Self::Bcm4377)
        } else if function.class == ehci::CLASS {
            Some(Self::Ehci)
        } else if crate::audio::hda::pci::identify(function).is_ok() {
            Some(Self::Hda)
        } else if crate::bus::thunderbolt::controller::Profile::identify(
            function.vendor,
            function.device,
            u32::from_be_bytes([0, function.class[0], function.class[1], function.class[2]]),
        )
        .is_ok()
        {
            Some(Self::Usb4)
        } else {
            None
        }
    }
}

/// A PCI bridge the scan passed.
#[derive(Clone, Copy, Debug)]
pub(super) struct Bridge {
    pub(super) address: Address,
    pub(super) secondary: u8,
    /// The ASPM Control field of its PCIe Link Control.
    pub(super) aspm: u16,
}

/// The bridge whose secondary bus is `bus`: Linux's `bus->self`.
fn upstream(bridges: &[Bridge], segment: u16, bus: u8) -> Option<&Bridge> {
    bridges.iter().find(|bridge| {
        bridge.address.segment == segment && bridge.secondary == bus && bridge.address.bus < bus
    })
}

/// `mt76_pci_aspm_supported`: whether firmware enabled ASPM on the
/// function's link, at either end.
pub(super) fn aspm_supported<C: ConfigSpace>(function: &Function<C>, bridges: &[Bridge]) -> bool {
    let address = function.address;
    crate::bus::pci::aspm_control(function) != 0
        || upstream(bridges, address.segment, address.bus).is_some_and(|parent| parent.aspm != 0)
}

fn mediatek_identity<C: ConfigSpace>(
    function: &mut Function<C>,
) -> mediatek::identity::PciIdentity {
    let (vendor, device) = (function.vendor, function.device);
    let config = function.config();
    mediatek::identity::PciIdentity {
        vendor,
        device,
        subsystem_vendor: config.read16(0x2c),
        subsystem_device: config.read16(0x2e),
        revision: config.read8(0x08),
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

/// Attach an EHCI host controller from its claimed function, BAR0 registers
/// and requester domain, returning the controller and that domain.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, `clock` is the
/// handoff's calibrated clock, and the handoff took this controller from
/// its BIOS owner and reset every companion controller of its roots.
#[expect(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn ehci(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<(ehci::host::Shared, Arc<dyn DmaDomain>), Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let Claimed {
        function,
        domain,
        bars,
    } = claim(services, address).map_err(refused)?;
    let registers = map(services, address, &bars, 0).map_err(refused)?;
    let resources = ehci::NativeResources {
        pci: function,
        registers,
        domain: domain.clone(),
        memory: services.pages(),
        clock,
    };
    // SAFETY: the mount claimed the stopped function, its BAR0 mapped
    // uncached and its own domain, with its interrupts masked; the caller's
    // handoff stopped the BIOS owner and the companions.
    match unsafe { ehci::attach(resources) } {
        Ok(controller) => Ok((Rc::new(RefCell::new(controller)), domain)),
        Err(failure) => Err((Error::Ehci(failure.error), Some(Box::new(failure)))),
    }
}

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
pub type IntelWifi = wifi::intel::link::Station<
    wifi::intel::boot::NativeBootIo,
    wifi::intel::radio::bios::service::native::NativeBios,
>;

/// The owners an MT7925 station keeps: its claimed function and BAR0.
pub type MediatekOwner = (Function<OwnedConfig>, Mapping);

/// An MT7925 station over its owned function and BAR0.
pub type MediatekWifi = mediatek::station::Wifi<MediatekOwner>;

/// Attach a MediaTek Wi-Fi function: BAR0 holds its registers and remap
/// windows.
///
/// # Safety
/// As for [`tg3`]; `inputs` describes this function's own link and ACPI
/// companion.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn mediatek_wifi(
    services: &dyn NativeServices,
    address: Address,
    inputs: mediatek::attach::Inputs,
) -> Result<Located<mediatek::attach::Attached<MediatekOwner>>, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let Claimed {
        mut function,
        domain,
        bars,
    } = claim(services, address).map_err(refused)?;
    let pci = mediatek_identity(&mut function);
    let registers = map(services, address, &bars, 0).map_err(refused)?;
    let (base, bytes) = registers
        .bytes()
        .and_then(|bytes| Ok((registers.address(0, bytes)?, bytes)))
        .map_err(|error| refused(ServiceError::Mapping(error)))?;
    // mt7925_pci_probe: memory decoding and bus mastering, polled.
    function.enable_polled();
    let owner = Arc::new((function, registers));
    let kept = Box::new(owner.clone()) as Box<dyn Any>;
    // SAFETY: the mount claimed the stopped function, mapped its BAR0
    // uncached and supplied an isolating domain; `owner` keeps the function
    // and mapping, and its interrupts are off.
    match unsafe { mediatek::attach::attach(pci, base.cast(), bytes, owner, domain, inputs) } {
        Ok(attached) => Ok(Located {
            location: alloc::format!("{address}"),
            link: attached,
        }),
        Err(error) => Err((Error::MediatekWifi(error), Some(kept))),
    }
}

/// An RTL8822C station on its hardware.
pub type RealtekWifi = realtek_wifi::station::Wifi<realtek_wifi::hardware::Hardware>;

/// Attach an RTL8822C: `rtw_pci_io_mapping` finds its registers in BAR2.
///
/// # Safety
/// As for [`tg3`].
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn realtek_wifi(
    services: &dyn NativeServices,
    address: Address,
    completion: Option<crate::bus::irq::MsiMessage>,
    mut inputs: realtek_wifi::attach::Inputs,
) -> Result<Located<RealtekWifi>, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let Claimed {
        mut function,
        domain,
        bars,
    } = claim(services, address).map_err(refused)?;
    let registers = map(services, address, &bars, 2).map_err(refused)?;
    let (base, bytes) = registers
        .bytes()
        .and_then(|bytes| Ok((registers.address(0, bytes)?, bytes)))
        .map_err(|error| refused(ServiceError::Mapping(error)))?;
    inputs.link_control = crate::bus::pci::link_control_word(&function);
    let config = function.config();
    let (subsystem_vendor, subsystem_device, pci_revision) =
        (config.read16(0x2c), config.read16(0x2e), config.read8(0x08));
    let observed = realtek_wifi::identity::Observed {
        vendor: function.vendor,
        device: function.device,
        subsystem_vendor,
        subsystem_device,
        pci_revision,
        // SAFETY: the BAR just mapped, whose first page holds SYS_CFG1.
        sys_cfg1: unsafe { crate::bus::mmio::Mmio::new(base.as_ptr() as u64) }.read32(0xf0),
    };
    // rtw_pci_setup_resource: memory decoding and bus mastering, then one MSI.
    function.enable_polled();
    inputs.vector = match (completion, function.interrupts().msi) {
        (Some(message), Some(msi)) => {
            function.enable_msi(msi, message);
            true
        }
        _ => false,
    };
    let owner: Arc<dyn Any> = Arc::new((function, registers));
    let kept = Box::new(owner.clone()) as Box<dyn Any>;
    // SAFETY: the mount claimed the stopped function, mapped its BAR2 uncached
    // and supplied an isolating domain; `owner` keeps the function and mapping,
    // and the device's interrupt masks are off until the station starts.
    match unsafe {
        realtek_wifi::attach::attach(base.cast(), bytes, owner, domain, observed, inputs)
    } {
        Ok(link) => Ok(Located {
            location: alloc::format!("{address}"),
            link,
        }),
        Err(error) => Err((Error::RealtekWifi(error), Some(kept))),
    }
}

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
    completion: Option<crate::bus::irq::MsiMessage>,
    inputs: wifi::intel::link::Inputs<B>,
) -> Result<Located<wifi::intel::link::Station<wifi::intel::boot::NativeBootIo, B>>, Failure> {
    use wifi::intel::attach::{AttachError, Pci, attach};
    let refused = |error: ServiceError| (Error::Native(error), None);
    let Claimed {
        mut function,
        domain,
        bars,
    } = claim(services, address).map_err(refused)?;
    let registers = map(services, address, &bars, 0).map_err(refused)?;
    let window = registers
        .address(0, 16384)
        .map_err(|error| refused(ServiceError::Mapping(error)))?;
    let vendor = function.vendor;
    let device = function.device;
    let link_speed = crate::bus::pci::link_speed(&function);
    let config = function.config();
    let pci = Pci {
        vendor,
        device,
        subsystem_vendor: config.read16(0x2c),
        subsystem_device: config.read16(0x2e),
        revision: config.read8(0x08),
        link_speed,
        vector: false,
    };
    // iwl_pci_probe: memory decoding and bus mastering.
    function.enable_polled();
    // iwl_pcie_set_interrupt_capa: the table lies in BAR0, at CSR_MSIX_BASE.
    let vector = match (completion, function.interrupts().msix) {
        (Some(message), Some(msix)) if msix.table_bar == 0 => {
            let table = registers
                .address(msix.table_offset as usize, 16)
                .map_err(|error| refused(ServiceError::Mapping(error)))?;
            // SAFETY: the claimed function's own MSI-X table, mapped uncached
            // by the mapping `owner` keeps.
            let table = unsafe { crate::bus::mmio::Mmio::new(table.as_ptr() as u64) };
            let vector = IntelVector {
                msix,
                table,
                message,
            };
            vector.enable(&mut function).then_some(vector)
        }
        _ => None,
    };
    let pci = Pci {
        vector: vector.is_some(),
        ..pci
    };
    let owner: Rc<dyn wifi::intel::boot::FunctionOwner> = Rc::new(IntelOwner {
        function: RefCell::new(function),
        _registers: registers,
        vector,
        clock: inputs.clock,
    });
    let kept = |owner: &Rc<dyn wifi::intel::boot::FunctionOwner>| {
        Some(Box::new(owner.clone()) as Box<dyn Any>)
    };
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

/// The MSI-X vector an Intel radio's completions arrive on.
#[cfg(feature = "native-acpi")]
struct IntelVector {
    msix: crate::bus::pci::MsiX,
    table: crate::bus::mmio::Mmio,
    message: crate::bus::irq::MsiMessage,
}

#[cfg(feature = "native-acpi")]
impl IntelVector {
    fn enable(&self, function: &mut Function<OwnedConfig>) -> bool {
        function
            .enable_msix(self.msix, || {
                self.table.write32(0, self.message.address as u32);
                self.table.write32(4, (self.message.address >> 32) as u32);
                self.table.write32(8, self.message.data);
                self.table.write32(12, 0);
                Ok(())
            })
            .is_ok()
    }
}

/// An Intel radio's function, with everything that outlives its users.
#[cfg(feature = "native-acpi")]
struct IntelOwner {
    function: RefCell<Function<OwnedConfig>>,
    _registers: Mapping,
    vector: Option<IntelVector>,
    clock: Clock,
}

#[cfg(feature = "native-acpi")]
impl wifi::intel::boot::FunctionOwner for IntelOwner {
    /// `pci_reset_function`, of its methods the one Intel radios have, with
    /// the vector back as `pci_restore_state` puts it.
    fn reset(&self) -> bool {
        let mut function = self.function.borrow_mut();
        function.function_level_reset(&self.clock) == Ok(true)
            && self
                .vector
                .as_ref()
                .is_none_or(|vector| vector.enable(&mut function))
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
    bridges: &[Bridge],
) -> Option<crate::platform::acpi::Handle<'static>> {
    use crate::platform::acpi::Handle;
    let parent = |handle: Handle<'static>| -> Option<String> {
        let path = handle.path().ok()?;
        path.rsplit_once('.')
            .map(|(parent, _)| String::from(parent))
    };
    let mut chain = alloc::vec![(address, false)];
    let mut bus = address.bus;
    while let Some(bridge) = upstream(bridges, address.segment, bus) {
        chain.push((bridge.address, true));
        bus = bridge.address.bus;
    }
    let devices = session.all_devices().ok()?;
    let (mut current, ..) = roots(session)
        .into_iter()
        .find(|&(_, segment, root)| segment == address.segment && root == bus)?;
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
    let bar = match unsafe { vmd::endpoint::FirmwareBar::claim(&mut host, child.address, bytes) } {
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
    match unsafe {
        crate::storage::nvme::vmd::attach(
            host,
            bar,
            domain,
            authority,
            services.pages(),
            clock,
            label,
        )
    } {
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

/// An Intel PCIe Bluetooth transport over its owned BAR0, whose MSI-X table
/// entry 0 delivers its interrupts.
pub type IntelBluetooth = intel_pcie::Transport<
    intel_pcie::native::NativePlatform<OwnedConfig, MappedBar, intel_pcie::native::MappedRegisters>,
>;

/// A Broadcom BCM4377-family transport over its owned BAR0 and BAR2, whose
/// MSI delivers its interrupts.
pub type Bcm4377 = bcm4377::Transport<bcm4377::native::NativePlatform>;

/// An attached PCIe Bluetooth controller and its one firmware initialization
/// attempt. A kept success is not radio or guest readiness.
pub struct PcieHci {
    pub location: String,
    pub controller: PcieController,
}

#[allow(
    clippy::large_enum_variant,
    reason = "one controller per attached function, kept for the boot"
)]
pub enum PcieController {
    Intel {
        transport: IntelBluetooth,
        initialization: Result<intel_pcie::firmware::Report, intel_pcie::firmware::Error>,
    },
    Broadcom {
        transport: Bcm4377,
        initialization: Result<bcm4377::Report, bcm4377::Error>,
    },
}

/// The root buses of `segment`, as the ACPI host bridges' `_SEG` and `_BBN`
/// declare them.
#[cfg(feature = "native-acpi")]
pub(super) fn root_buses(
    session: &'static crate::platform::acpi::Session,
    segment: u16,
) -> Vec<crate::bus::pci::native_aspm::RootBus> {
    use crate::bus::pci::native_aspm::RootBus;
    roots(session)
        .into_iter()
        .filter(|&(_, root_segment, _)| root_segment == segment)
        .map(|(_, segment, bus)| RootBus { segment, bus })
        .collect()
}

/// Each ACPI PCI host bridge with its `_SEG` and `_BBN`, zero when absent.
#[cfg(feature = "native-acpi")]
fn roots(
    session: &'static crate::platform::acpi::Session,
) -> Vec<(crate::platform::acpi::Handle<'static>, u16, u8)> {
    let mut roots = session.devices("PNP0A08").unwrap_or_default();
    roots.extend(session.devices("PNP0A03").unwrap_or_default());
    roots
        .into_iter()
        .filter_map(|root| {
            let segment = u16::try_from(integer(root, "_SEG").unwrap_or(0)).ok()?;
            let bus = u8::try_from(integer(root, "_BBN").unwrap_or(0)).ok()?;
            Some((root, segment, bus))
        })
        .collect()
}

/// The integer `name` evaluates to on `handle`, when it has one.
#[cfg(feature = "native-acpi")]
fn integer(handle: crate::platform::acpi::Handle<'static>, name: &str) -> Option<u64> {
    use crate::platform::acpi::Value;
    handle.child(name).ok()?;
    match handle.evaluate(Some(name), &[]).ok()? {
        Some(Value::Integer(value)) => Some(value),
        _ => None,
    }
}

/// Attach a Broadcom PCIe Bluetooth function, as `bcm4377_probe` does:
/// BAR0 and BAR2 hold its registers, `topology` its link's bridges and
/// `board` the board its firmware is chosen for.
///
/// # Safety
/// As for [`sfh`]; `topology` holds the mount's bridges of the function's
/// segment and its root buses, and no other owner sets their link policy.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn bcm4377(
    services: &dyn NativeServices,
    address: Address,
    topology: crate::bus::pci::native_aspm::Topology<OwnedConfig>,
    board: bcm4377::Board,
    clock: Clock,
) -> Result<Bcm4377, Failure> {
    use bcm4377::native::{
        Error as NativeError, Inputs, MappedRegisters, MsiCompletion, NativeClock, NativePlatform,
    };
    let refused = |error: ServiceError| (Error::Native(error), None);
    let failed =
        |error: NativeError, kept: Box<dyn Any>| (Error::Bcm4377(error.into()), Some(kept));
    // SAFETY: the handoff's clock is the calibrated invariant TSC.
    let clock =
        unsafe { NativeClock::new(clock) }.map_err(|error| (Error::Bcm4377(error.into()), None))?;
    let interrupts = services.interrupts().map_err(refused)?;
    let authority = services.authority().map_err(refused)?;
    let (requester, domain, bars) = claim_sized(services, address)?;
    let bar0 = match map(services, address, &bars, 0) {
        Ok(mapping) => mapping,
        Err(error) => return Err((Error::Native(error), Some(Box::new(requester)))),
    };
    let bar2 = match map(services, address, &bars, 2) {
        Ok(mapping) => mapping,
        Err(error) => return Err((Error::Native(error), Some(Box::new((requester, bar0))))),
    };
    let spans = match (bar0.physical_span(), bar2.physical_span()) {
        (Ok(bar0), Ok(bar2)) => [bar0, bar2],
        (Err(error), _) | (_, Err(error)) => {
            return Err(failed(
                NativeError::Mapping(error),
                Box::new((requester, bar0, bar2)),
            ));
        }
    };
    // SAFETY: the mount mapped exactly BAR0 and BAR2 uncached, once each.
    let registers = match unsafe { MappedRegisters::new(spans, [bar0, bar2]) } {
        Ok(registers) => registers,
        Err((error, mappings)) => return Err(failed(error, Box::new((requester, mappings)))),
    };
    let inputs = Inputs {
        function: requester.into_function(),
        retained: Arc::new(authority),
        topology,
        registers,
        domain,
        pages: Box::new(services.pages()),
        board,
        // An x86 board's firmware node carries none of the device-tree
        // calibration or address properties Apple silicon boards do.
        properties: Vec::new(),
        clock,
        interrupts,
        // No root delivery adapter completes posted MSIs yet, so a stopped
        // function stays quarantined with its owners rather than retired.
        msi_completion: MsiCompletion::unavailable(),
    };
    // SAFETY: the mount claimed the stopped function with its interrupts
    // drained, mapped its BARs, isolated its domain and handed over its
    // segment's bridges; the caller's contract covers the rest.
    let platform = unsafe { NativePlatform::new(inputs) }
        .map_err(|(error, inputs)| failed(error, Box::new(inputs)))?;
    platform
        .into_transport()
        .map_err(|error| (Error::Bcm4377(error), None))
}

/// Attach an Intel PCIe Bluetooth function and start its ROM transport, as
/// `btintel_pcie_probe` does before downloading firmware. Its reset is the
/// function's own, so it needs no coordination with the Wi-Fi function of the
/// same module, as in Linux.
///
/// # Safety
/// As for [`sfh`].
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn intel_bluetooth(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<IntelBluetooth, Failure> {
    use intel_pcie::native::{self as native, Inputs, NativePlatform};
    let refused = |error: ServiceError| (Error::Native(error), None);
    let failed =
        |error: intel_pcie::Error, kept: Box<dyn Any>| (Error::IntelBluetooth(error), Some(kept));
    let (requester, domain, bars) = claim_sized(services, address)?;
    let interrupts = services.interrupts().map_err(refused)?;
    let authority = services.authority().map_err(refused)?;
    let Some(bar @ Bar::Memory { .. }) = bars[0] else {
        return Err(refused(ServiceError::Refused("missing memory BAR")));
    };
    let mapping = services.map_bar(address, bar).map_err(refused)?;
    let full = match mapping.physical_span() {
        Ok(span) => span,
        Err(error) => {
            return Err(failed(
                native::Error::Mapping(error).into(),
                Box::new(mapping),
            ));
        }
    };
    // SAFETY: the mount mapped exactly BAR0 uncached, and the registers below
    // keep that mapping for as long as the MSI-X table is used.
    let table = match unsafe { MappedBar::new(full, [Some(&mapping), None]) } {
        Ok(table) => table,
        Err(error) => return Err(failed(native::Error::Msix(error).into(), Box::new(mapping))),
    };
    // SAFETY: as above; no other driver maps this BAR.
    let registers = unsafe { native::MappedRegisters::new(full, mapping) }
        .map_err(|(error, mapping)| failed(error.into(), Box::new(mapping)))?;
    let mut function = requester.into_function();
    // btintel_pcie_probe: memory decoding and bus mastering before MSI-X.
    function.enable_polled();
    let mut msix = [const { None }; 6];
    msix[0] = Some(table);
    let inputs = Inputs {
        function,
        retained: Arc::new(authority),
        bars: msix,
        registers,
        clock,
        interrupts,
    };
    // SAFETY: the mount claimed the stopped function with its interrupts
    // drained, mapped its BAR0 and gave its domain and MSI controller; the
    // function reset is this function's own.
    let platform = unsafe { NativePlatform::new(inputs) }
        .map_err(|(error, inputs)| failed(error.into(), Box::new(inputs)))?;
    // SAFETY: the mount's domain isolates this requester and its pages are
    // kept for the boot; the controller addresses 64 bits.
    let mut dma = unsafe { DomainAllocator::new(services.pages(), domain, u64::MAX) };
    let mut transport = intel_pcie::Transport::new(platform, &mut dma)
        .map_err(|error| (Error::IntelBluetooth(error), None))?;
    match transport.start() {
        Ok(()) => Ok(transport),
        Err(error) => Err(failed(error, Box::new(transport))),
    }
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
        // SAFETY: as above.
        let bluetooth = unsafe { intel_bluetooth(&services, address(), clock) };
        assert!(matches!(
            bluetooth,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        assert_eq!(*services.requests.borrow(), [address(); 4]);
    }

    #[test]
    fn a_broadcom_function_without_interrupts_claims_nothing() {
        let services = Refusing::default();
        let clock = Clock {
            ticks_per_microsecond: 1000,
        };
        // SAFETY: an empty topology owns no bridge, and the refusing services
        // transfer no owner.
        let topology =
            unsafe { crate::bus::pci::native_aspm::Topology::new(Vec::new(), Vec::new()) };
        let board = bcm4377::Board::from_dmi("Apple Inc.", "MacBookAir9,1").unwrap();
        // SAFETY: as above.
        let bluetooth = unsafe { bcm4377(&services, address(), topology, board, clock) };
        assert!(matches!(
            bluetooth,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        assert!(services.requests.borrow().is_empty());
    }

    #[test]
    fn broadcom_bluetooth_is_named_by_its_device_table() {
        assert_eq!(
            bcm4377::Chip::of_device(0x5fa0),
            Some(bcm4377::Chip::Bcm4377)
        );
        assert_eq!(
            bcm4377::Chip::of_device(0x5f72),
            Some(bcm4377::Chip::Bcm4388)
        );
        assert_eq!(bcm4377::Chip::of_device(0x4377), None);
    }
}
