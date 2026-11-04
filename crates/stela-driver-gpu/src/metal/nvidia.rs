//! NVIDIA GPUs under Stela's Metal device: nouveau with GSP firmware in the
//! kernel and NVK as the Vulkan driver.
//!
//! Hardware access, firmware, memory management, command submission and
//! shader code generation stay with nouveau, NVK and NAK; this module only
//! admits a device and supplies the facts Vulkan does not report, and
//! [`open`] serves it.
use super::{
    abi::DeviceLocation,
    capabilities::Platform,
    vulkan::{DriverId, PhysicalDeviceType, physical::Identity},
};
use alloc::string::String;

pub mod open;

pub const VENDOR_ID: u32 = 0x10de;

pub use crate::nouveau_chip::{Architecture, CHIPS, Chip};

/// The first Turing chipset; nouveau's card type for 0x160-0x16f is TU100.
const FIRST_GSP_CHIPSET: u16 = 0x160;

/// Why a Vulkan device is not admitted as an NVIDIA Metal device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    NotNvidia {
        vendor_id: u32,
    },
    /// Only NVK is integrated with Stela's nouveau winsys.
    NotNvk(DriverId),
    /// Chips before Turing have no GSP firmware path.
    PreTuring {
        chipset: u16,
    },
    /// nouveau does not name this chipset.
    UnknownChipset {
        chipset: u16,
    },
    /// Tegra parts share system memory and have no PCI function.
    NotDiscrete(PhysicalDeviceType),
}

impl Chip {
    /// Admits the Vulkan device `identity` whose kernel driver reports
    /// `chipset` (`NOUVEAU_GETPARAM_CHIPSET_ID`).
    pub fn admit(identity: &Identity, chipset: u16) -> Result<&'static Chip, Refusal> {
        if identity.vendor_id != VENDOR_ID {
            return Err(Refusal::NotNvidia {
                vendor_id: identity.vendor_id,
            });
        }
        if identity.driver_id != DriverId::MesaNvk {
            return Err(Refusal::NotNvk(identity.driver_id));
        }
        if identity.device_type != PhysicalDeviceType::DiscreteGpu {
            return Err(Refusal::NotDiscrete(identity.device_type));
        }
        if chipset < FIRST_GSP_CHIPSET {
            return Err(Refusal::PreTuring { chipset });
        }
        Self::find(chipset).ok_or(Refusal::UnknownChipset { chipset })
    }
}

/// The negotiated PCI Express link, from the Link Status register
/// (`PCI_EXP_LNKSTA`) of the GPU's PCIe capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcieLink {
    /// Current Link Speed: 1 for 2.5 GT/s through 6 for 64 GT/s.
    pub speed: u8,
    /// Negotiated Link Width in lanes.
    pub width: u8,
}

impl PcieLink {
    pub const fn from_link_status(status: u16) -> Self {
        Self {
            speed: (status & 0xf) as u8,
            width: ((status >> 4) & 0x3f) as u8,
        }
    }

    /// Data bandwidth in bytes per second after line encoding, as Linux's
    /// `PCIE_SPEED2MBS_ENC`: 8b/10b through 5 GT/s, 128b/130b from 8 GT/s,
    /// and FLIT mode at 64 GT/s. Unknown speeds report zero.
    pub const fn bytes_per_second(self) -> u64 {
        let megabits_per_lane: u64 = match self.speed {
            1 => 2500 * 8 / 10,
            2 => 5000 * 8 / 10,
            3 => 8000 * 128 / 130,
            4 => 16000 * 128 / 130,
            5 => 32000 * 128 / 130,
            6 => 64000,
            _ => 0,
        };
        megabits_per_lane * self.width as u64 * 1_000_000 / 8
    }
}

/// Where the GPU is attached, as the platform's PCI and ACPI owners report it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attachment {
    pub link: PcieLink,
    /// Behind a hot-pluggable Thunderbolt or USB4 tunnel.
    pub external: bool,
    /// The slot or enclosure index Metal reports as `locationNumber`.
    pub location_number: u64,
}

/// NVK's explicit linear layouts need 32-byte row pitches on Maxwell B and
/// later (NIL `Image::new_linear`).
const LINEAR_ROW_ALIGNMENT: u64 = 32;
/// NVK binds image memory at the kernel's page granularity
/// (`nvkmd_nouveau` `bind_align_B`), which also aligns linear image offsets.
const LINEAR_OFFSET_ALIGNMENT: u64 = 4096;
/// nouveau's sparse binding uses the GPU's 64 KiB big pages, matching
/// Vulkan's standard sparse block shapes.
const SPARSE_PAGE_BYTES: u64 = 64 << 10;

impl Chip {
    pub fn platform(&self, attachment: Attachment) -> Platform {
        Platform {
            architecture: String::from(self.name),
            location: if attachment.external {
                DeviceLocation::External
            } else {
                DeviceLocation::Slot
            },
            location_number: attachment.location_number,
            max_transfer_rate: attachment.link.bytes_per_second(),
            headless: !self.display,
            removable: attachment.external,
            linear_row_alignment: LINEAR_ROW_ALIGNMENT,
            linear_offset_alignment: LINEAR_OFFSET_ALIGNMENT,
            sparse_page_bytes: SPARSE_PAGE_BYTES,
        }
    }
}

#[cfg(test)]
pub(crate) mod fixture;

#[cfg(test)]
mod tests;
