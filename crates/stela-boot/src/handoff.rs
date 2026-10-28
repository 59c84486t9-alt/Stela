//! Plain data the loader phase passes to the engine phase. Addresses are host
//! physical; the engine reaches them through its physmap.
use crate::console::Framebuffer;
use alloc::vec::Vec;
use stela_runtime::{machine::mmu::placement::Placement, pc};

pub const MAGIC: u64 = 0x5354_454c_4153_5953; // "SYSALETS"
pub const MAX_GUEST_RANGES: usize = 128;
/// A restore bundle's files (13 for a MacBookPro18,3 with its USB-C port
/// controllers' firmware) and the install inventory's four, with room.
pub const MAX_FILES: usize = 32;
pub const MAX_NAME: usize = 48;
pub const MAX_ECAM: usize = 4;
pub const MAX_MAPPED: usize = 32;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Region {
    pub physical: u64,
    pub bytes: u64,
}

/// One file of a boot bundle, read by the loader.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct File {
    pub name: [u8; MAX_NAME],
    pub name_bytes: usize,
    pub contents: Region,
}

impl Default for File {
    fn default() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_bytes: 0,
            contents: Region::default(),
        }
    }
}

impl File {
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_bytes]).unwrap_or("")
    }
}

/// The host storage drivers' handoff (`stela_drivers::Handoff`) in
/// fixed arrays, for `--preboot`; `present` is false otherwise.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Storage {
    pub present: bool,
    pub ecam: [stela_drivers::bus::pci::EcamWindow; MAX_ECAM],
    pub ecam_count: usize,
    /// Ranges the loader identity-mapped uncached.
    pub mapped: [Region; MAX_MAPPED],
    pub mapped_count: usize,
    pub dma: Region,
    pub ticks_per_microsecond: u64,
    /// Copy-only pre-EBS board capture; no firmware service/heap borrow.
    pub bluetooth_platform: stela_drivers::usb::bluetooth::intel::DsbrCapture,
    pub wifi_platform: stela_drivers::net::wifi::intel::platform::Observations,
}

impl Storage {
    pub fn absent() -> Self {
        Self {
            present: false,
            ecam: [stela_drivers::bus::pci::EcamWindow {
                base: 0,
                segment: 0,
                start_bus: 0,
                end_bus: 0,
            }; MAX_ECAM],
            ecam_count: 0,
            mapped: [Region::default(); MAX_MAPPED],
            mapped_count: 0,
            dma: Region::default(),
            ticks_per_microsecond: 0,
            bluetooth_platform: Default::default(),
            wifi_platform: Default::default(),
        }
    }

    pub fn new(handoff: &stela_drivers::Handoff) -> Result<Self, &'static str> {
        if handoff.ecam.len() > MAX_ECAM || handoff.mapped.len() > MAX_MAPPED {
            return Err("too many storage ranges for the engine handoff");
        }
        let mut storage = Self::absent();
        storage.present = true;
        storage.ecam[..handoff.ecam.len()].copy_from_slice(&handoff.ecam);
        storage.ecam_count = handoff.ecam.len();
        for (slot, range) in storage.mapped.iter_mut().zip(&handoff.mapped) {
            *slot = Region {
                physical: range.start,
                bytes: range.end - range.start,
            };
        }
        storage.mapped_count = handoff.mapped.len();
        storage.dma = Region {
            physical: handoff.dma.start,
            bytes: handoff.dma.end - handoff.dma.start,
        };
        storage.ticks_per_microsecond = handoff.clock.ticks_per_microsecond;
        storage.bluetooth_platform = handoff.bluetooth_platform;
        storage.wifi_platform = handoff.wifi_platform;
        Ok(storage)
    }

    pub fn handoff(&self) -> Option<stela_drivers::Handoff> {
        self.present.then(|| stela_drivers::Handoff {
            firmware: None,
            bluetooth_platform: self.bluetooth_platform,
            wifi_platform: self.wifi_platform,
            completion: None,
            ecam: self.ecam[..self.ecam_count].to_vec(),
            mapped: self.mapped[..self.mapped_count]
                .iter()
                .map(|r| r.physical..r.physical + r.bytes)
                .collect::<Vec<_>>(),
            dma: self.dma.physical..self.dma.physical + self.dma.bytes,
            clock: stela_drivers::Clock {
                ticks_per_microsecond: self.ticks_per_microsecond,
            },
        })
    }
}

#[repr(C)]
pub struct Handoff {
    pub magic: u64,
    /// `stela.cfg`.
    pub options: Region,
    /// `source.bin`: the guest image, when no boot bundle is configured.
    pub source: Region,
    /// The boot bundle's `bundle.json` and every file it lists.
    pub files: [File; MAX_FILES],
    pub file_count: usize,
    pub heap: Region,
    pub stack: Region,
    pub code: Region,
    /// Page-table frames: engine roots and shadow tables.
    pub pool: Region,
    /// Where the guest's address space lies beside the window.
    pub placement: Placement,
    /// The loader's root, whose window entries every engine root shares.
    pub root: u64,
    /// The physical addresses of the bounce slot's two leaf entries.
    pub bounce: [u64; 2],
    pub screen: Option<Framebuffer>,
    /// The loader's finished status lines, which the engine's screen starts
    /// with (`status::replay`).
    pub history: [u8; crate::status::HISTORY_BYTES],
    pub history_bytes: usize,
    /// The partition holding the USB's boot log the loader keeps
    /// (`log_file`), which the engine writes on to.
    pub log_partition: Option<[u8; 16]>,
    /// TSC ticks per second, measured against the firmware's Stall.
    pub tsc_hz: u64,
    /// IA32_APIC_BASE as the firmware left it.
    pub apic_base: u64,
    /// Immutable copied UEFI processor identities and per-physical-core raw
    /// CPUID/control observations; absent unless native cores were requested.
    pub native_processors: Region,
    pub native_resources: crate::native_smp::resources::Resources,
    /// Sealed owned UEFI/ACPI resource inventory and empty MMIO aperture.
    /// Zero when capture is unavailable; this alone grants no device owner.
    pub native_mmio: Region,
    /// The firmware's real-time clock as Unix seconds, read at TSC
    /// `wall_tsc`; `None` when the firmware has no valid time.
    pub wall_seconds: Option<u64>,
    pub wall_tsc: u64,
    /// Free host RAM after boot services, in 2 MiB-aligned ranges.
    pub guest: [Region; MAX_GUEST_RANGES],
    pub guest_count: usize,
    /// The host's RAM in the firmware's memory map, every RAM type
    /// included: the DRAM the guest Mac reports.
    pub installed: u64,
    /// The host storage drivers' ranges, for a bundle built from a disk.
    pub storage: Storage,
    /// Host-device firmware, separate from guest boot-bundle files.
    pub host_firmware: crate::host_firmware::Resources,
    /// The host's ACPI power hardware, when its FADT is usable.
    pub power: Option<pc::power::HostPower>,
    /// The firmware's `ResetSystem` runtime service, whose regions the
    /// loader keeps mapped by identity; zero without one.
    pub efi_reset: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::usb::bluetooth::intel::{DsbrCapture, DsbrInput};
    #[test]
    fn storage_wire_keeps_wifi_status_metadata_after_source_owner_drops() {
        use stela_drivers::net::wifi::intel::platform::{Observation, Observations, Stage};
        let mut expected = Observations {
            oem_pnvm: Observation::Present {
                attributes: 0x87,
                bytes: 19,
                sha256: [0xab; 32],
                probe_reported_bytes: Some(23),
            },
            reduced_power: Observation::Absent {
                stage: Stage::Probe,
                status: 0x8000_0000_0000_000e,
                reported_bytes: Some(0),
            },
            step: Observation::Failed {
                stage: Stage::Read,
                status: 0,
                reported_bytes: Some(99),
            },
            ..Default::default()
        };
        for descriptor in &stela_drivers::net::wifi::intel::platform::VARIABLE_DESCRIPTORS[3..] {
            expected.set(
                descriptor.variable,
                Observation::BoundExceeded {
                    stage: Stage::Probe,
                    status: 0x8000_0000_0000_0005,
                    reported_bytes: descriptor.maximum_bytes as u64 + 1,
                },
            );
        }
        let physical = {
            let mut record = Storage::absent();
            record.present = true;
            record.wifi_platform = expected;
            let temporary = record.handoff().unwrap();
            Storage::new(&temporary).unwrap()
        };
        assert_eq!(physical.wifi_platform, expected);
        assert_eq!(physical.handoff().unwrap().wifi_platform, expected);
        assert_eq!(Storage::absent().wifi_platform, Observations::default());
    }
    #[test]
    fn physical_storage_record_preserves_owned_board_capture_after_source_drop() {
        for capture in [
            DsbrCapture::default(),
            DsbrCapture::from_variable(&[7, 0xb1, 0xbe, 0xad, 0xde], 0x87),
            DsbrCapture::from_uefi_error(0x8000_0000_0000_000e, None),
            DsbrCapture::from_variable(&[1, 2, 3, 4], 0),
            DsbrCapture::from_uefi_error(0x8000_0000_0000_0007, None),
        ] {
            let copied;
            {
                let mut record = Storage::absent();
                record.present = true;
                record.dma = Region {
                    physical: 0x1000,
                    bytes: 0x1000,
                };
                record.ticks_per_microsecond = 3;
                record.bluetooth_platform = capture;
                let source = record.handoff().unwrap();
                let physical = Storage::new(&source).unwrap();
                copied = physical;
            }
            let rebuilt = copied.handoff().unwrap();
            assert_eq!(rebuilt.bluetooth_platform, capture);
            assert_eq!(rebuilt.bluetooth_platform.input(), capture.input());
            assert_eq!(rebuilt.dma, 0x1000..0x2000);
            assert_eq!(rebuilt.clock.ticks_per_microsecond, 3);
        }
        let absent = Storage::absent();
        assert!(absent.handoff().is_none());
        assert_eq!(absent.bluetooth_platform.input(), DsbrInput::Unavailable);
    }
}
