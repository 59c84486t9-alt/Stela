//! The PCI scan that brings up every driver: each function of every mapped
//! ECAM window goes to the driver of its class, and what each driver found
//! or refused is collected in [`Devices`].
use crate::{
    Handoff,
    block::{BlockDevice, BlockError},
    bus::{
        dma::DmaAllocator,
        pci::{Address, EcamWindow, Function},
    },
    gpu,
    input::{self, InputDevice, virtio::VirtioInput},
    net::{
        self, Link, LinkError, Mac,
        e1000e::E1000e,
        igb::Igb,
        igc::Igc,
        realtek::{self, Realtek},
        virtio::VirtioNet,
    },
    storage::{ahci, nvme, rtsx, sdhci, virtio},
    usb::{self, bluetooth::UsbHci, cdc::UsbNet, ethernet::UsbEthernet, xhci},
};
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::fmt;

#[cfg(feature = "native-acpi")]
mod i2c;
#[cfg(feature = "native-acpi")]
mod power;
#[cfg(feature = "native-acpi")]
pub use power::{EmbeddedControllerInstallation, Power, install_embedded_controller};
pub mod native;
#[cfg(any(test, feature = "native-acpi"))]
mod platform;
pub mod services;
pub mod wifi;
pub use services::{NativeServices, ServiceError};
pub use wifi::{WifiConfig, WifiSecret, WifiSecretError};

/// A controller refusal keeps its original typed details for boot diagnostics.
/// In particular, firmware names and integrity/target errors are never replaced
/// by a generic unsupported-device message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Device(BlockError),
    Realtek(realtek::Error),
    /// The mount's [`NativeServices`] refused or lack a resource.
    Native(ServiceError),
    Vmd(crate::bus::vmd::Error),
    Tg3(net::tg3::Error),
    Aqtion(net::aqtion::Error),
    Sfh(input::sfh::Error),
    Ish(input::ish::Error),
    IntelWifi(net::wifi::intel::attach::AttachError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => error.fmt(f),
            Self::Realtek(error) => error.fmt(f),
            Self::Native(error) => error.fmt(f),
            Self::Vmd(error) => write!(f, "VMD: {error}"),
            Self::Tg3(error) => write!(f, "tg3: {error:?}"),
            Self::Aqtion(error) => write!(f, "atlantic: {error:?}"),
            Self::Sfh(error) => write!(f, "AMD SFH: {error:?}"),
            Self::Ish(error) => write!(f, "Intel ISH: {error:?}"),
            Self::IntelWifi(error) => write!(f, "iwlwifi: {error}"),
        }
    }
}

impl From<BlockError> for Error {
    fn from(error: BlockError) -> Self {
        Self::Device(error)
    }
}

impl From<realtek::Error> for Error {
    fn from(error: realtek::Error) -> Self {
        Self::Realtek(error)
    }
}

/// Why a device or controller outside the PCI drivers' attach was not brought
/// up or handed over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlatformError {
    /// A USB host controller could not be taken from firmware.
    Handoff(usb::handoff::Error),
    /// Walking the ACPI namespace or decoding a resource template failed.
    #[cfg(feature = "native-acpi")]
    Acpi(crate::platform::acpi::resources::Error),
    /// The description or the machine state rules attachment out.
    Refused(&'static str),
    Ps2(input::ps2::Error),
    Native(ServiceError),
    I2c(crate::bus::i2c::Error),
    Lpss(crate::bus::lpss::Error),
    LpssAttach(crate::bus::lpss::AttachError),
    HidI2c(input::hid_i2c::Error),
    /// The HID report descriptor could not be interpreted as input.
    HidDescriptor(usb::hid::ParseError),
    Touchpad(input::touchpad::Error),
    #[cfg(feature = "native-acpi")]
    Gpio(crate::bus::gpio::native::Error),
    /// The embedded controller's operation regions could not be installed.
    #[cfg(feature = "native-acpi")]
    Ec(crate::platform::ec::binding::Failure),
    /// The embedded controller's description could not be read.
    #[cfg(feature = "native-acpi")]
    EcDiscovery(crate::platform::ec::discovery::native::DiscoveryError),
    #[cfg(feature = "native-acpi")]
    Battery(crate::platform::battery::Error),
    /// Finding a device or evaluating its method failed.
    #[cfg(feature = "native-acpi")]
    AcpiMethod(crate::platform::acpi::Error),
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handoff(error) => error.fmt(f),
            #[cfg(feature = "native-acpi")]
            Self::Acpi(error) => write!(f, "ACPI: {error:?}"),
            Self::Refused(why) => f.write_str(why),
            Self::Ps2(error) => error.fmt(f),
            Self::Native(error) => error.fmt(f),
            Self::I2c(error) => write!(f, "I2C controller: {error:?}"),
            Self::Lpss(error) => write!(f, "LPSS: {error:?}"),
            Self::LpssAttach(error) => write!(f, "LPSS I2C attach: {error:?}"),
            Self::HidI2c(error) => error.fmt(f),
            Self::HidDescriptor(error) => error.fmt(f),
            Self::Touchpad(error) => error.fmt(f),
            #[cfg(feature = "native-acpi")]
            Self::Gpio(error) => write!(f, "GPIO controller: {error:?}"),
            #[cfg(feature = "native-acpi")]
            Self::Ec(error) => write!(f, "embedded controller: {error:?}"),
            #[cfg(feature = "native-acpi")]
            Self::EcDiscovery(error) => write!(f, "embedded controller description: {error:?}"),
            #[cfg(feature = "native-acpi")]
            Self::Battery(error) => write!(f, "battery: {error:?}"),
            #[cfg(feature = "native-acpi")]
            Self::AcpiMethod(error) => write!(f, "ACPI method: {error:?}"),
        }
    }
}

/// Nonfatal diagnostics keep controller-specific values through discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warning {
    Message(&'static str),
    Realtek(realtek::Warning),
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
            Self::Realtek(warning) => write!(f, "Realtek {warning}"),
        }
    }
}

/// A host network adapter, as a raw Ethernet link.
pub enum Adapter {
    Virtio(VirtioNet),
    Igc(Igc),
    E1000e(E1000e),
    Igb(Igb),
    Realtek(Realtek),
    Usb(UsbNet),
    UsbVendor(UsbEthernet),
    Tg3(Box<native::Located<native::Tg3>>),
    Aqtion(Box<native::Located<net::aqtion::Aqtion>>),
    #[cfg(feature = "native-acpi")]
    IntelWifi(Box<native::Located<native::IntelWifi>>),
}

impl Adapter {
    /// Stable implementation name for diagnostics and driver verification.
    pub fn driver(&self) -> &'static str {
        match self {
            Self::Virtio(_) => "virtio-net",
            Self::Igc(_) => "igc",
            Self::E1000e(_) => "e1000e",
            Self::Igb(_) => "igb",
            Self::Realtek(_) => "realtek",
            Self::Usb(_) => "usb-cdc",
            Self::Tg3(_) => "tg3",
            Self::Aqtion(_) => "atlantic",
            #[cfg(feature = "native-acpi")]
            Self::IntelWifi(_) => "iwlwifi",
            Self::UsbVendor(device) => device.driver(),
        }
    }

    /// Where the adapter is, for logs.
    pub fn location(&self) -> &str {
        match self {
            Self::Virtio(device) => &device.location,
            Self::Igc(device) => &device.location,
            Self::E1000e(device) => &device.location,
            Self::Igb(device) => &device.location,
            Self::Realtek(device) => &device.location,
            Self::Usb(device) => &device.location,
            Self::UsbVendor(device) => &device.location,
            Self::Tg3(device) => &device.location,
            Self::Aqtion(device) => &device.location,
            #[cfg(feature = "native-acpi")]
            Self::IntelWifi(device) => &device.location,
        }
    }
}

impl Link for Adapter {
    fn mac(&self) -> Mac {
        match self {
            Self::Virtio(device) => device.mac(),
            Self::Igc(device) => device.mac(),
            Self::E1000e(device) => device.mac(),
            Self::Igb(device) => device.mac(),
            Self::Realtek(device) => device.mac(),
            Self::Usb(device) => device.mac(),
            Self::UsbVendor(device) => device.mac(),
            Self::Tg3(device) => device.mac(),
            Self::Aqtion(device) => device.mac(),
            #[cfg(feature = "native-acpi")]
            Self::IntelWifi(device) => device.mac(),
        }
    }
    fn carrier(&mut self) -> bool {
        match self {
            Self::Virtio(device) => device.carrier(),
            Self::Igc(device) => device.carrier(),
            Self::E1000e(device) => device.carrier(),
            Self::Igb(device) => device.carrier(),
            Self::Realtek(device) => device.carrier(),
            Self::Usb(device) => device.carrier(),
            Self::UsbVendor(device) => device.carrier(),
            Self::Tg3(device) => device.carrier(),
            Self::Aqtion(device) => device.carrier(),
            #[cfg(feature = "native-acpi")]
            Self::IntelWifi(device) => device.carrier(),
        }
    }
    fn signals(&self) -> bool {
        match self {
            Self::Virtio(device) => device.signals(),
            Self::Igc(device) => device.signals(),
            Self::E1000e(device) => device.signals(),
            Self::Igb(device) => device.signals(),
            Self::Realtek(device) => device.signals(),
            Self::Usb(device) => device.signals(),
            Self::UsbVendor(device) => device.signals(),
            Self::Tg3(device) => device.signals(),
            Self::Aqtion(device) => device.signals(),
            #[cfg(feature = "native-acpi")]
            Self::IntelWifi(device) => device.signals(),
        }
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        match self {
            Self::Virtio(device) => device.transmit(frame),
            Self::Igc(device) => device.transmit(frame),
            Self::E1000e(device) => device.transmit(frame),
            Self::Igb(device) => device.transmit(frame),
            Self::Realtek(device) => device.transmit(frame),
            Self::Usb(device) => device.transmit(frame),
            Self::UsbVendor(device) => device.transmit(frame),
            Self::Tg3(device) => device.transmit(frame),
            Self::Aqtion(device) => device.transmit(frame),
            #[cfg(feature = "native-acpi")]
            Self::IntelWifi(device) => device.transmit(frame),
        }
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        match self {
            Self::Virtio(device) => device.receive(),
            Self::Igc(device) => device.receive(),
            Self::E1000e(device) => device.receive(),
            Self::Igb(device) => device.receive(),
            Self::Realtek(device) => device.receive(),
            Self::Usb(device) => device.receive(),
            Self::UsbVendor(device) => device.receive(),
            Self::Tg3(device) => device.receive(),
            Self::Aqtion(device) => device.receive(),
            #[cfg(feature = "native-acpi")]
            Self::IntelWifi(device) => device.receive(),
        }
    }
}

/// Whether a driver here may attach `function`, or probe hands it over from
/// firmware (every USB host controller), including the HD Audio check: its
/// memory BARs must be mapped uncached before ExitBootServices.
pub fn claims(function: &Function) -> bool {
    claims_identity(&function.identity())
}

/// Candidate selection from copied firmware/native header DATA only. This
/// grants neither resource ownership nor permission to size or attach BARs.
pub fn claims_identity(function: &crate::bus::pci::Identity) -> bool {
    virtio::matches_identity(function)
        || input::virtio::matches_identity(function)
        || net::virtio::matches_identity(function)
        || net::igc::matches_identity(function)
        || net::e1000e::matches_identity(function)
        || net::igb::matches_identity(function)
        || realtek::matches_identity(function)
        || crate::audio::hda::pci::identify_identity(function).is_ok()
        || function.class == nvme::CLASS
        || ahci::matches_identity(function)
        || sdhci::matches_identity(function)
        || rtsx::matches_identity(function)
        || function.class == xhci::CLASS
        || usb::handoff::Kind::of(function.class).is_some()
}

/// Why no driver here takes a function of a device class the host needs,
/// or none for classes outside this crate's scope.
fn unsupported(class: [u8; 3]) -> Option<&'static str> {
    match class {
        [0x01, 0x01, _] => Some("IDE storage controller"),
        [0x01, 0x04, _] => Some("RAID storage controller (Intel RST/VMD mode)"),
        [0x01, 0x06, _] => Some("SATA controller without the AHCI interface"),
        [0x01, 0x08, _] => Some("non-NVMe non-volatile memory controller"),
        [0x01, ..] => Some("storage controller"),
        [0x02, 0x00, _] => Some("Ethernet controller"),
        [0x02, 0x80, _] => Some("network controller (Wi-Fi is not attached yet)"),
        [0x02, ..] => Some("network controller"),
        [0x04, 0x03, _] => Some("HD Audio controller (audio is not attached yet)"),
        [0x0c, 0x03, _] => {
            Some("USB host controller other than xHCI (taken from firmware, not driven)")
        }
        [0x0c, 0x0a, _] => Some("USB4/Thunderbolt host (not attached yet)"),
        [0x08, 0x05, _] => Some("SD host controller without standard SDHCI interface"),
        [0x0d, 0x11, _] => Some("PCIe Bluetooth controller"),
        _ => None,
    }
}

/// Every block and input device the drivers brought up, and every
/// controller they could not.
#[derive(Default)]
pub struct Devices {
    /// Native UAC2 playback/capture owners, awaiting explicit runtime PCM use.
    pub audio: Vec<crate::usb::audio::UsbAudio>,
    pub disks: Vec<Box<dyn BlockDevice>>,
    /// Display controllers, inventoried without changing firmware scanout.
    /// These are not initialized accelerators; each records its missing port.
    pub gpus: Vec<gpu::Adapter>,
    /// Host keyboards and pointers: virtio-input devices, USB HID devices
    /// behind xHCI controllers, and the i8042 ports the ACPI namespace
    /// lists, each polled through [`InputDevice::poll`].
    pub inputs: Vec<InputDevice>,
    /// Complete descriptor inventories, including hubs and unbound devices.
    /// Retention does not grant hardware ownership or guest forwarding.
    pub usb_devices: Vec<xhci::Device>,
    /// Explicitly polled USB topology owners, including empty controllers.
    pub usb_hosts: Vec<xhci::Host>,
    /// Native SDHCI socket owners, including empty/removable card sockets.
    pub sd_hosts: Vec<sdhci::Host>,
    /// Native Realtek socket owners, kept for empty/removable SD/MMC cards.
    pub rtsx_hosts: Vec<rtsx::Host>,
    /// Storage class owners remain available for explicit media rescan.
    pub usb_storage: Vec<crate::usb::storage::UsbStorage>,
    /// USB HCI transports with kept device-specific initialization results.
    /// Historical evidence does not establish radio or guest readiness.
    pub bluetooth: Vec<UsbHci>,
    /// Raw firmware uploaders awaiting USB removal/fresh enumeration.
    pub bluetooth_bootloaders: Vec<crate::usb::bluetooth::ath3k::UsbBootloader>,
    /// Exact pre-EBS board-variable observation, including unavailable diagnostics.
    pub bluetooth_platform: crate::usb::bluetooth::intel::DsbrCapture,
    /// Network adapters, as raw Ethernet links.
    pub nics: Vec<Adapter>,
    /// The regulatory database, once probe found a Wi-Fi adapter (a PCI
    /// network controller of class 02/80) while a network is configured:
    /// `Err` reports once that it is missing, and no Wi-Fi adapter then
    /// scans or transmits.
    pub regulatory: Option<
        Result<
            crate::net::wifi::regulatory::database::Database,
            crate::net::wifi::regulatory::database::LoadError,
        >,
    >,
    /// Sensor hubs, their sensors enabled. Nothing reads their reports yet.
    pub sensors: Vec<native::SensorHub>,
    pub failures: Vec<(Address, Error)>,
    /// Devices behind an attached controller that failed on their own, such
    /// as AHCI ports and NVMe namespaces, by location.
    pub device_failures: Vec<(String, BlockError)>,
    /// Nonfatal initialization diagnostics, including adapters not selected.
    pub warnings: Vec<(Address, Warning)>,
    /// USB devices that failed to enumerate or bind, by location.
    pub usb_failures: Vec<(String, BlockError)>,
    /// Vendor initialization failures, preserving exact firmware requests.
    pub usb_vendor_failures: Vec<(String, crate::usb::ethernet::Error)>,
    /// USB interfaces no driver here takes, and why.
    pub usb_unused: Vec<(String, &'static str)>,
    /// Devices and controllers outside the PCI drivers' attach that were not
    /// brought up or handed over, by location, such as
    /// `0000:00:1d.0 EHCI handoff`.
    pub platform_failures: Vec<(String, PlatformError)>,
    /// Objects that must stay alive while the devices they set up exist,
    /// including attaches that failed, such as the Intel VMD hierarchy behind
    /// its NVMe controller and a failed controller's mappings and DMA domain.
    pub owners: Vec<Box<dyn core::any::Any>>,
    /// The batteries, AC adapter and lid the ACPI namespace lists.
    #[cfg(feature = "native-acpi")]
    pub power: Power,
    /// ECAM windows that were not mapped, and so not scanned.
    pub unmapped: Vec<EcamWindow>,
    /// Whether the mount supplied [`NativeServices`]. Drivers that attach
    /// through owned mappings, requester DMA domains or the ACPI namespace
    /// need them.
    pub native_services: bool,
    /// Storage, network, audio and USB functions no driver here takes, with
    /// their class and why.
    pub unsupported: Vec<(Address, [u8; 3], &'static str)>,
}

impl Devices {
    /// Failures from attempted native vendor initialization. Unknown
    /// vendors remain raw, unverified transports; they are not failed attempts
    /// of a backend implemented here.
    pub fn bluetooth_failures(
        &self,
    ) -> impl Iterator<Item = (&str, &crate::usb::bluetooth::InitializationError)> {
        self.bluetooth.iter().filter_map(|device| {
            let Err(error) = device.initialization()? else {
                return None;
            };
            if matches!(
                error,
                crate::usb::bluetooth::InitializationError::UnsupportedDevice { .. }
            ) {
                return None;
            }
            Some((device.binding().device().location.as_str(), error))
        })
    }
}

/// Enumerate PCI and bring up every virtio-blk, NVMe and AHCI controller,
/// every virtio-input device, every virtio-net and supported Intel/Realtek Ethernet adapter,
/// and every xHCI
/// controller with the USB disks, keyboards, pointers and Ethernet
/// adapters on it.
///
/// # Safety
///
/// `handoff` must describe the running machine after ExitBootServices,
/// with its ranges mapped as it says, and nothing else may drive these
/// controllers afterwards.
pub unsafe fn probe(handoff: &Handoff, dma: &mut dyn DmaAllocator) -> Devices {
    // SAFETY: the caller granted the complete machine/controller contract.
    unsafe { probe_with_provider(handoff, dma, handoff_provider(handoff), None, None) }
}

/// The handoff's firmware catalog as the provider [`probe_with_provider`]
/// takes. Attached devices keep borrowing their firmware for as long as
/// they run, so the catalog lives for the rest of the boot.
pub fn handoff_provider(handoff: &Handoff) -> &'static crate::firmware::HandoffProvider<'static> {
    let catalog = handoff
        .firmware
        .clone()
        // SAFETY: the reference count is never given back, so the catalog
        // stays allocated for every later borrow.
        .map(|catalog| unsafe { &*Arc::into_raw(catalog) });
    Box::leak(Box::new(crate::firmware::HandoffProvider::new(catalog)))
}

/// Attach the Intel Wi-Fi function at `address` for `network`, reading its
/// ACPI companion, once the regulatory database loaded.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, and nothing else
/// reaches the function.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
unsafe fn intel_wifi(
    services: &dyn NativeServices,
    address: Address,
    handoff: &Handoff,
    firmware: &'static dyn crate::firmware::Provider,
    network: &WifiConfig,
    regulatory: &Option<
        Result<
            crate::net::wifi::regulatory::database::Database,
            crate::net::wifi::regulatory::database::LoadError,
        >,
    >,
    bridges: &[(Address, u8)],
) -> Result<Adapter, native::Failure> {
    use net::wifi::intel::attach::AttachError;
    let Some(Ok(database)) = regulatory else {
        return Err((Error::IntelWifi(AttachError::NoRegulatoryDatabase), None));
    };
    #[cfg(feature = "native-acpi")]
    {
        let session = services.acpi();
        let companion = session.and_then(|session| native::companion(session, address, bridges));
        // SAFETY: `companion` is this function's own, and the handoff's
        // captured variables are this boot's.
        let bios = unsafe {
            net::wifi::intel::radio::bios::service::native::NativeBios::new(
                session,
                companion,
                firmware,
                handoff.wifi_platform,
            )
        };
        let inputs = net::wifi::intel::link::Inputs {
            firmware,
            observations: handoff.wifi_platform,
            pages: services.pages(),
            clock: handoff.clock,
            bios,
            database: database.clone(),
            network: network.clone(),
        };
        // SAFETY: forwarded from the caller.
        unsafe { native::intel_wifi(services, address, inputs) }
            .map(|link| Adapter::IntelWifi(Box::new(link)))
    }
    #[cfg(not(feature = "native-acpi"))]
    {
        let _ = (
            services, address, handoff, firmware, network, database, bridges,
        );
        Err((Error::IntelWifi(AttachError::NoNamespace), None))
    }
}

/// Enumerate and attach devices using an explicit exact firmware provider.
/// A loader can observe consumer requirements while delegating the original
/// lookup result, without reconstructing device identities outside drivers.
/// This performs the same hardware operations and reports the same failures as
/// [`probe`]; a missing resource still refuses that controller's initialization.
/// `services` supplies the native owners some drivers attach through.
/// `wifi` is the network the mount's configuration names; without one a
/// Wi-Fi adapter is unsupported and needs no Wi-Fi firmware or regulatory
/// data.
///
/// # Safety
/// The machine, mappings, DMA and exclusive post-ExitBootServices ownership
/// requirements of [`probe`] apply. The provider must preserve its documented
/// exact identity and integrity contract for every resource it returns. It
/// lives for the rest of the boot because attached devices keep borrowing
/// the firmware it returned.
pub unsafe fn probe_with_provider(
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
    firmware: &'static dyn crate::firmware::Provider,
    services: Option<&dyn NativeServices>,
    wifi: Option<&WifiConfig>,
) -> Devices {
    let mut devices = Devices {
        bluetooth_platform: handoff.bluetooth_platform,
        native_services: services.is_some(),
        ..Devices::default()
    };
    // Intel ISHs, attached once the scan has looked for a Mehlow host bridge.
    let mut sensor_hubs = Vec::new();
    let mut mehlow = false;
    // Each PCI bridge and its secondary bus, for ACPI companion lookups.
    let mut bridges = Vec::new();
    for window in &handoff.ecam {
        if !handoff.is_mapped(&window.range()) {
            devices.unmapped.push(*window);
            continue;
        }
        // SAFETY: mapped as checked; the caller owns the machine.
        for mut function in unsafe { Function::enumerate(window) } {
            let address = function.address;
            mehlow |= function.vendor == 0x8086 && native::MEHLOW.contains(&function.device);
            if function.class[..2] == [6, 4] {
                use crate::bus::pci::ConfigSpace;
                bridges.push((address, function.config().read8(0x19)));
            }
            if function.class[..2] == [2, 0x80] {
                if wifi.is_none() {
                    devices.device_failures.push((
                        alloc::format!("{address}"),
                        BlockError::Unsupported("Wi-Fi adapter without --wifi"),
                    ));
                } else if devices.regulatory.is_none() {
                    devices.regulatory =
                        Some(crate::net::wifi::regulatory::database::load(firmware));
                }
            }
            if let Some(adapter) = gpu::Adapter::discover(&function) {
                devices.gpus.push(adapter);
                continue;
            }
            crate::working(&alloc::format!("PCI {address}"));
            if let Some(kind) = usb::handoff::Kind::of(function.class) {
                // SAFETY: the caller owns the machine and no driver has bound
                // this controller yet, as Linux's early PCI fixup runs.
                match unsafe { usb::handoff::early(&mut function, handoff) } {
                    Some(Ok(handed)) if handed.forced => devices.warnings.push((
                        address,
                        Warning::Message(
                            "USB host firmware handoff timed out; ownership taken with its SMIs off",
                        ),
                    )),
                    Some(Err(error)) => devices.platform_failures.push((
                        alloc::format!("{address} {} handoff", kind.name()),
                        PlatformError::Handoff(error),
                    )),
                    _ => {}
                }
            }
            let result = if let Some(kind) = native::Kind::of(&function) {
                let Some(services) = services else {
                    devices
                        .failures
                        .push((address, Error::Native(ServiceError::Unavailable)));
                    continue;
                };
                let attached = match kind {
                    native::Kind::Sfh => {
                        // SAFETY: as for tg3 below.
                        match unsafe { native::sfh(services, address, handoff.clock) } {
                            Ok(hub) => devices.sensors.push(native::SensorHub::Sfh(Box::new(hub))),
                            Err((error, kept)) => {
                                devices.failures.push((address, error));
                                devices.owners.extend(kept);
                            }
                        }
                        continue;
                    }
                    native::Kind::Ish => {
                        sensor_hubs.push(address);
                        continue;
                    }
                    native::Kind::IntelWifi => {
                        let Some(network) = wifi else {
                            continue;
                        };
                        // SAFETY: as for tg3 below; the companion is this
                        // function's own.
                        match unsafe {
                            intel_wifi(
                                services,
                                address,
                                handoff,
                                firmware,
                                network,
                                &devices.regulatory,
                                &bridges,
                            )
                        } {
                            Ok(link) => devices.nics.push(link),
                            Err((error, kept)) => {
                                devices.failures.push((address, error));
                                devices.owners.extend(kept);
                            }
                        }
                        continue;
                    }
                    native::Kind::Vmd => {
                        // SAFETY: as for tg3 below; the host's hierarchy is
                        // stopped with it.
                        match unsafe { native::vmd(services, address, handoff.clock) } {
                            Ok(found) => {
                                for child in &found.others {
                                    let location = alloc::format!(
                                        "{address} VMD {:02x}:{:02x}.{}",
                                        child.address.bus,
                                        child.address.device,
                                        child.address.function
                                    );
                                    devices.device_failures.push((
                                        location,
                                        BlockError::Unsupported(
                                            "device behind VMD other than its first NVMe controller",
                                        ),
                                    ));
                                }
                                if let Some(attached) = found.nvme {
                                    devices.device_failures.extend(
                                        attached.failures.into_iter().map(|(namespace, error)| {
                                            (
                                                alloc::format!(
                                                    "{address} VMD namespace {namespace}"
                                                ),
                                                error,
                                            )
                                        }),
                                    );
                                    devices.disks.extend(
                                        attached
                                            .namespaces
                                            .into_iter()
                                            .map(|disk| Box::new(disk) as Box<dyn BlockDevice>),
                                    );
                                }
                                devices.owners.push(found.owner);
                            }
                            Err((error, kept)) => {
                                devices.failures.push((address, error));
                                devices.owners.extend(kept);
                            }
                        }
                        continue;
                    }
                    native::Kind::Tg3 => {
                        // SAFETY: the caller grants `services`' contract, and
                        // this loop leaves `function` alone once it is claimed.
                        let link = unsafe { native::tg3(services, address, handoff.clock) };
                        link.map(|link| Adapter::Tg3(Box::new(link)))
                    }
                    native::Kind::Aqtion => {
                        // SAFETY: as for tg3.
                        let link = unsafe { native::aqtion(services, address, handoff.clock) };
                        link.map(|link| Adapter::Aqtion(Box::new(link)))
                    }
                };
                match attached {
                    Ok(adapter) => devices.nics.push(adapter),
                    Err((error, kept)) => {
                        devices.failures.push((address, error));
                        devices.owners.extend(kept);
                    }
                }
                continue;
            } else if virtio::matches(&function) {
                virtio::VirtioBlk::new(&mut function, handoff, dma)
                    .map(|device| vec![Box::new(device) as Box<dyn BlockDevice>])
            } else if function.class == nvme::CLASS {
                nvme::attach(&mut function, handoff, dma).map(|attached| {
                    devices
                        .device_failures
                        .extend(attached.failures.into_iter().map(|(namespace, error)| {
                            (alloc::format!("{address} namespace {namespace}"), error)
                        }));
                    attached
                        .namespaces
                        .into_iter()
                        .map(|device| Box::new(device) as Box<dyn BlockDevice>)
                        .collect()
                })
            } else if function.class == xhci::CLASS {
                match xhci::attach_with_provider(&mut function, handoff, dma, firmware) {
                    Ok(found) => {
                        devices.disks.extend(
                            found
                                .disks
                                .into_iter()
                                .map(|d| Box::new(d) as Box<dyn BlockDevice>),
                        );
                        devices
                            .inputs
                            .extend(found.inputs.into_iter().map(InputDevice::Usb));
                        devices.usb_devices.extend(found.devices);
                        devices.usb_hosts.extend(found.hosts);
                        devices.usb_storage.extend(found.storage);
                        devices.audio.extend(found.audio);
                        devices.bluetooth_bootloaders.extend(found.bootloaders);
                        for mut device in found.bluetooth {
                            // The kept result owns its evidence/errors;
                            // no catalog borrow or firmware bytes escape.
                            let _ = device.initialize_with_provider(
                                firmware,
                                devices.bluetooth_platform.platform_inputs(),
                            );
                            devices.bluetooth.push(device);
                        }
                        devices
                            .nics
                            .extend(found.links.into_iter().map(Adapter::Usb));
                        devices
                            .nics
                            .extend(found.vendor_links.into_iter().map(Adapter::UsbVendor));
                        devices.usb_failures.extend(found.failures);
                        devices.usb_vendor_failures.extend(found.vendor_failures);
                        devices.usb_unused.extend(found.unused);
                    }
                    Err(error) => devices.failures.push((address, error.into())),
                }
                continue;
            } else if net::virtio::matches(&function) {
                match VirtioNet::new(&mut function, handoff, dma) {
                    Ok(device) => devices.nics.push(Adapter::Virtio(device)),
                    Err(error) => devices.failures.push((address, error.into())),
                }
                continue;
            } else if net::igc::matches(&function) {
                // SAFETY: the caller grants exclusive post-EBS controller,
                // segment configuration and firmware/ASPM policy ownership.
                match unsafe { Igc::new(&mut function, handoff, dma) } {
                    Ok(device) => devices.nics.push(Adapter::Igc(device)),
                    Err(error) => devices.failures.push((address, error.into())),
                }
                continue;
            } else if net::e1000e::matches(&function) {
                // SAFETY: the caller granted exclusive ownership of all mapped PCI
                // functions and controllers after ExitBootServices.
                match unsafe { E1000e::new(&mut function, handoff, dma) } {
                    Ok(device) => devices.nics.push(Adapter::E1000e(device)),
                    Err(error) => devices.failures.push((address, error.into())),
                }
                continue;
            } else if net::igb::matches(&function) {
                // SAFETY: as for e1000e, the caller granted exclusive ownership
                // of the mapped PCI functions and their controllers.
                match unsafe { Igb::new(&mut function, handoff, dma) } {
                    Ok(device) => {
                        if device.warnings.nvm_autoload_timeout {
                            devices.warnings.push((
                                address,
                                Warning::Message(
                                    "igb NVM autoload completion timed out; NVM contents validated",
                                ),
                            ));
                        }
                        if device.warnings.phy_configuration_timeout {
                            devices.warnings.push((
                                address,
                                Warning::Message("igb PHY configuration completion timed out; PHY transactions validated"),
                            ));
                        }
                        devices.nics.push(Adapter::Igb(device));
                    }
                    Err(error) => devices.failures.push((address, error.into())),
                }
                continue;
            } else if realtek::matches(&function) {
                // SAFETY: the caller granted exclusive post-EBS ownership of
                // mapped PCI/MMIO and DMA, including upstream ASPM configuration.
                match unsafe { Realtek::new(&mut function, handoff, dma, firmware) } {
                    Ok(device) => {
                        if let Some(warning) = device.warning() {
                            devices.warnings.push((address, Warning::Realtek(warning)));
                        }
                        devices.nics.push(Adapter::Realtek(device));
                    }
                    Err(error) => devices.failures.push((address, error.into())),
                }
                continue;
            } else if input::virtio::matches(&function) {
                match VirtioInput::new(&mut function, handoff, dma) {
                    Ok(device) => devices.inputs.push(InputDevice::Virtio(device)),
                    Err(error) => devices.failures.push((address, error.into())),
                }
                continue;
            } else if rtsx::matches(&function) {
                rtsx::attach(function, handoff).map(|attached| {
                    devices.rtsx_hosts.push(attached.host);
                    if let Some(error) = attached.failure {
                        devices
                            .device_failures
                            .push((alloc::format!("{address} RTSX SD slot"), error));
                    }
                    attached
                        .card
                        .into_iter()
                        .map(|card| Box::new(card) as Box<dyn BlockDevice>)
                        .collect()
                })
            } else if sdhci::matches(&function) {
                let attached = if sdhci::requires_owned_config(&function) {
                    sdhci::attach_owned(function, handoff, dma)
                } else {
                    sdhci::attach(&mut function, handoff, dma)
                };
                attached.map(|attached| {
                    devices.sd_hosts.extend(attached.hosts);
                    devices.device_failures.extend(
                        attached.failures.into_iter().map(|(slot, error)| {
                            (alloc::format!("{address} SD slot {slot}"), error)
                        }),
                    );
                    attached
                        .cards
                        .into_iter()
                        .map(|card| Box::new(card) as Box<dyn BlockDevice>)
                        .collect()
                })
            } else if ahci::matches(&function) {
                ahci::attach(&mut function, handoff, dma).map(|attached| {
                    devices.device_failures.extend(
                        attached
                            .failures
                            .into_iter()
                            .map(|(port, error)| (alloc::format!("{address} port {port}"), error)),
                    );
                    attached
                        .disks
                        .into_iter()
                        .map(|device| Box::new(device) as Box<dyn BlockDevice>)
                        .collect()
                })
            } else {
                if let Some(why) = unsupported(function.class) {
                    devices.unsupported.push((address, function.class, why));
                }
                continue;
            };
            match result {
                Ok(found) => devices.disks.extend(found),
                Err(error) => devices.failures.push((address, error.into())),
            }
        }
    }
    for address in sensor_hubs {
        let Some(services) = services else {
            devices
                .failures
                .push((address, Error::Native(ServiceError::Unavailable)));
            continue;
        };
        if mehlow {
            devices.failures.push((
                address,
                Error::Ish(input::ish::Error::Requirement(
                    "no ISH on a Mehlow platform, as Linux ish_probe refuses it",
                )),
            ));
            continue;
        }
        // SAFETY: as for tg3, and the scan found no Mehlow host bridge.
        match unsafe { native::ish(services, address, handoff.clock) } {
            Ok(hub) => {
                match input::ish::IshInput::new(hub, alloc::format!("Intel ISH {address}")) {
                    Ok(input) => devices.inputs.push(InputDevice::Ish(Box::new(input))),
                    Err(hub) => devices.sensors.push(native::SensorHub::Ish(Box::new(hub))),
                }
            }
            Err((error, kept)) => {
                devices.failures.push((address, error));
                devices.owners.extend(kept);
            }
        }
    }
    // After every USB host left firmware, as Linux's i8042 probe runs after
    // its PCI fixups.
    #[cfg(feature = "native-acpi")]
    if let Some((services, session)) =
        services.and_then(|services| services.acpi().map(|session| (services, session)))
    {
        // Before any other device's methods, which may read EC fields.
        match services.embedded_controller() {
            Ok(Some(installed)) => devices.owners.push(Box::new(installed)),
            Ok(None) => power::attach_ec(session, &mut devices),
            Err(error) => devices.platform_failures.push((
                String::from("embedded controller"),
                PlatformError::Native(error),
            )),
        }
        let usb_released = !devices
            .platform_failures
            .iter()
            .any(|(_, error)| matches!(error, PlatformError::Handoff(_)));
        platform::attach_i8042(session, handoff.clock, usb_released, &mut devices);
        i2c::attach(services, session, handoff.clock, &mut devices);
        power::attach_power(session, &mut devices);
    }
    devices
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firmware::{
        self, Catalog, HandoffProvider, Provenance, Provider, Requirement, Resource, Target,
    };
    use alloc::format;
    use sha2::{Digest, Sha256};

    #[test]
    fn unclaimed_host_classes_are_reported_and_others_ignored() {
        assert_eq!(
            unsupported([0x02, 0x80, 0x00]),
            Some("network controller (Wi-Fi is not attached yet)")
        );
        assert_eq!(
            unsupported([0x01, 0x04, 0x00]),
            Some("RAID storage controller (Intel RST/VMD mode)")
        );
        assert_eq!(
            unsupported([0x0c, 0x03, 0x20]),
            Some("USB host controller other than xHCI (taken from firmware, not driven)")
        );
        assert_eq!(
            unsupported([0x08, 0x05, 0x02]),
            Some("SD host controller without standard SDHCI interface")
        );
        assert_eq!(unsupported([0x06, 0x04, 0x00]), None); // PCI bridge
        assert_eq!(unsupported([0x03, 0x00, 0x00]), None); // display: GPU inventory
    }

    #[test]
    fn wifi_without_regulatory_data_never_claims_the_adapter() {
        let services = services::tests::Refusing::default();
        let handoff = Handoff {
            ecam: Vec::new(),
            mapped: Vec::new(),
            dma: 0..0,
            clock: crate::Clock {
                ticks_per_microsecond: 1,
            },
            firmware: None,
            bluetooth_platform: Default::default(),
            wifi_platform: Default::default(),
            completion: None,
        };
        let firmware = handoff_provider(&handoff);
        let network = WifiConfig {
            ssid: b"test".to_vec(),
            secret: WifiSecret::parse(b"test passphrase").unwrap(),
            country: None,
        };
        let address = Address {
            segment: 0,
            bus: 1,
            device: 0,
            function: 0,
        };
        // SAFETY: the refusing services cannot grant hardware access.
        let result =
            unsafe { intel_wifi(&services, address, &handoff, firmware, &network, &None, &[]) };
        assert!(matches!(
            result,
            Err((
                Error::IntelWifi(net::wifi::intel::attach::AttachError::NoRegulatoryDatabase),
                None
            ))
        ));
        assert!(services.requests.borrow().is_empty());
    }

    #[test]
    fn probe_diagnostics_preserve_exact_firmware_refusals() {
        let requirement = Requirement {
            name: "rtl_nic/rtl8168e-3.fw",
            target: Target {
                driver: "realtek",
                hardware: "10ec:8168",
                revision: "xid-2c8",
                board: None,
            },
            minimum_bytes: 4,
        };
        let missing = HandoffProvider::new(None).load(requirement).unwrap_err();
        let catalog = Catalog::from_handoff(vec![Resource {
            name: requirement.name,
            target: Target {
                revision: "xid-2c9",
                ..requirement.target
            },
            provenance: Provenance {
                source: "synthetic-fixtures",
                revision: "v1",
                member: "fixtures/abcd.bin",
                license: "CC0-1.0",
            },
            expected_length: 4,
            expected_sha256: Sha256::digest(b"abcd").into(),
            bytes: b"abcd".to_vec(),
        }])
        .unwrap();
        let wrong_target = HandoffProvider::new(Some(&catalog))
            .load(requirement)
            .unwrap_err();
        assert_eq!(wrong_target.kind, firmware::ErrorKind::WrongTarget);
        let address = Address {
            segment: 0,
            bus: 1,
            device: 2,
            function: 0,
        };
        let mut devices = Devices::default();
        for original in [missing, wrong_target] {
            let error = realtek::Error::Firmware(original.clone());
            devices.failures.push((address, error.into()));
            let (location, error) = devices.failures.last().unwrap();
            assert_eq!(*location, address);
            assert_eq!(
                *error,
                Error::Realtek(realtek::Error::Firmware(original.clone()))
            );
            assert_eq!(format!("{error}"), format!("{original}"));
            assert!(format!("{error}").contains(requirement.name));
        }
        let device: Error = BlockError::Device { status: 0x1234 }.into();
        assert_eq!(format!("{device}"), "device status 0x1234");
    }
}
