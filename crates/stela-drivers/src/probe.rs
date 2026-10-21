//! The PCI scan that brings up every driver: each function of every mapped
//! ECAM window goes to the driver of its class, and what each driver found
//! or refused is collected in [`Disks`].
use crate::{
    Handoff,
    block::{BlockDevice, BlockError},
    bus::{
        dma::DmaAllocator,
        pci::{Address, EcamWindow, Function},
    },
    input::{self, virtio::VirtioInput},
    net::{
        self, Link, LinkError, Mac,
        e1000e::E1000e,
        igb::Igb,
        igc::Igc,
        realtek::{self, Realtek},
        virtio::VirtioNet,
    },
    storage::{ahci, nvme, virtio},
    usb::{bluetooth::UsbHci, cdc::UsbNet, hid::UsbInput, xhci},
};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt;

/// A controller refusal retains its original typed details for boot diagnostics.
/// In particular, firmware names and integrity/target errors are never replaced
/// by a generic unsupported-device message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Device(BlockError),
    Realtek(realtek::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => error.fmt(f),
            Self::Realtek(error) => error.fmt(f),
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

/// A host network adapter, as a raw Ethernet link.
pub enum Adapter {
    Virtio(VirtioNet),
    Igc(Igc),
    E1000e(E1000e),
    Igb(Igb),
    Realtek(Realtek),
    Usb(UsbNet),
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
        }
    }
}

/// Every block and input device the drivers brought up, and every
/// controller they could not.
#[derive(Default)]
pub struct Disks {
    pub devices: Vec<Box<dyn BlockDevice>>,
    pub inputs: Vec<VirtioInput>,
    /// USB keyboards and pointers behind xHCI controllers.
    pub usb_inputs: Vec<UsbInput>,
    /// Raw USB HCI only; firmware readiness and guest forwarding are separate.
    pub bluetooth: Vec<UsbHci>,
    /// Network adapters, as raw Ethernet links.
    pub links: Vec<Adapter>,
    pub failures: Vec<(Address, Error)>,
    /// Nonfatal initialization diagnostics, including adapters not selected.
    pub warnings: Vec<(Address, &'static str)>,
    /// USB devices that failed to enumerate or bind, by location.
    pub usb_failures: Vec<(String, BlockError)>,
    /// USB interfaces no driver here takes, and why.
    pub usb_unused: Vec<(String, &'static str)>,
    /// ECAM windows that were not mapped, and so not scanned.
    pub unmapped: Vec<EcamWindow>,
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
pub unsafe fn probe(handoff: &Handoff, dma: &mut dyn DmaAllocator) -> Disks {
    let mut disks = Disks::default();
    let firmware = crate::firmware::HandoffProvider::new(handoff.firmware.as_deref());
    for window in &handoff.ecam {
        if !handoff.is_mapped(&window.range()) {
            disks.unmapped.push(*window);
            continue;
        }
        // SAFETY: mapped as checked; the caller owns the machine.
        for mut function in unsafe { Function::enumerate(window) } {
            let address = function.address;
            crate::working(&alloc::format!("PCI {address}"));
            let result = if virtio::matches(&function) {
                virtio::VirtioBlk::new(&mut function, handoff, dma)
                    .map(|device| vec![Box::new(device) as Box<dyn BlockDevice>])
            } else if function.class == nvme::CLASS {
                nvme::attach(&mut function, handoff, dma).map(|namespaces| {
                    namespaces
                        .into_iter()
                        .map(|device| Box::new(device) as Box<dyn BlockDevice>)
                        .collect()
                })
            } else if function.class == xhci::CLASS {
                match xhci::attach(&mut function, handoff, dma) {
                    Ok(found) => {
                        disks.devices.extend(
                            found
                                .disks
                                .into_iter()
                                .map(|d| Box::new(d) as Box<dyn BlockDevice>),
                        );
                        disks.usb_inputs.extend(found.inputs);
                        disks.bluetooth.extend(found.bluetooth);
                        disks
                            .links
                            .extend(found.links.into_iter().map(Adapter::Usb));
                        disks.usb_failures.extend(found.failures);
                        disks.usb_unused.extend(found.unused);
                    }
                    Err(error) => disks.failures.push((address, error.into())),
                }
                continue;
            } else if net::virtio::matches(&function) {
                match VirtioNet::new(&mut function, handoff, dma) {
                    Ok(device) => disks.links.push(Adapter::Virtio(device)),
                    Err(error) => disks.failures.push((address, error.into())),
                }
                continue;
            } else if net::igc::matches(&function) {
                match Igc::new(&mut function, handoff, dma) {
                    Ok(device) => disks.links.push(Adapter::Igc(device)),
                    Err(error) => disks.failures.push((address, error.into())),
                }
                continue;
            } else if net::e1000e::matches(&function) {
                // SAFETY: the caller granted exclusive ownership of all mapped PCI
                // functions and controllers after ExitBootServices.
                match unsafe { E1000e::new(&mut function, handoff, dma) } {
                    Ok(device) => disks.links.push(Adapter::E1000e(device)),
                    Err(error) => disks.failures.push((address, error.into())),
                }
                continue;
            } else if net::igb::matches(&function) {
                // SAFETY: as for e1000e, the caller granted exclusive ownership
                // of the mapped PCI functions and their controllers.
                match unsafe { Igb::new(&mut function, handoff, dma) } {
                    Ok(device) => {
                        if device.warnings.nvm_autoload_timeout {
                            disks.warnings.push((
                                address,
                                "igb NVM autoload completion timed out; NVM contents validated",
                            ));
                        }
                        if device.warnings.phy_configuration_timeout {
                            disks.warnings.push((
                                address,
                                "igb PHY configuration completion timed out; PHY transactions validated",
                            ));
                        }
                        disks.links.push(Adapter::Igb(device));
                    }
                    Err(error) => disks.failures.push((address, error.into())),
                }
                continue;
            } else if realtek::matches(&function) {
                // SAFETY: the caller granted exclusive post-EBS ownership of
                // mapped PCI/MMIO and DMA, including upstream ASPM configuration.
                match unsafe { Realtek::new(&mut function, handoff, dma, &firmware) } {
                    Ok(device) => disks.links.push(Adapter::Realtek(device)),
                    Err(error) => disks.failures.push((address, error.into())),
                }
                continue;
            } else if input::virtio::matches(&function) {
                match VirtioInput::new(&mut function, handoff, dma) {
                    Ok(device) => disks.inputs.push(device),
                    Err(error) => disks.failures.push((address, error.into())),
                }
                continue;
            } else if function.class == ahci::CLASS {
                ahci::attach(&mut function, handoff, dma).map(|ports| {
                    ports
                        .into_iter()
                        .map(|device| Box::new(device) as Box<dyn BlockDevice>)
                        .collect()
                })
            } else {
                continue;
            };
            match result {
                Ok(devices) => disks.devices.extend(devices),
                Err(error) => disks.failures.push((address, error.into())),
            }
        }
    }
    disks
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
        let mut disks = Disks::default();
        for original in [missing, wrong_target] {
            let error = realtek::Error::Firmware(original.clone());
            disks.failures.push((address, error.into()));
            let (location, error) = disks.failures.last().unwrap();
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
