//! Fixed-size records the loader phase hands the engine phase: physical
//! regions, boot-bundle files and the storage drivers' handoff and captures.
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::refuse;

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

/// The host storage drivers' handoff (`stela_drivers::Handoff`) in fixed
/// arrays plus the pre-ExitBootServices platform captures, for `--preboot`;
/// `present` is false otherwise.
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
    /// Copy-only board captures; no firmware service or heap borrow.
    pub captures: stela_drivers::PlatformCaptures,
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
            captures: Default::default(),
        }
    }

    pub fn new(
        handoff: &stela_drivers::Handoff,
        captures: stela_drivers::PlatformCaptures,
    ) -> Result<Self> {
        if handoff.ecam.len() > MAX_ECAM || handoff.mapped.len() > MAX_MAPPED {
            return Err(refuse!("too many storage ranges for the engine handoff"));
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
        storage.captures = captures;
        Ok(storage)
    }

    pub fn handoff(&self) -> Option<stela_drivers::Handoff> {
        self.present.then(|| stela_drivers::Handoff {
            firmware: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::PlatformCaptures;
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
        let captures = PlatformCaptures {
            wifi: expected,
            ..Default::default()
        };
        let physical = {
            let mut record = Storage::absent();
            record.present = true;
            let temporary = record.handoff().unwrap();
            Storage::new(&temporary, captures).unwrap()
        };
        assert_eq!(physical.captures.wifi, expected);
        assert_eq!(Storage::absent().captures.wifi, Observations::default());
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
                let source = record.handoff().unwrap();
                let captures = PlatformCaptures {
                    bluetooth: capture,
                    ..Default::default()
                };
                copied = Storage::new(&source, captures).unwrap();
            }
            assert_eq!(copied.captures.bluetooth, capture);
            assert_eq!(copied.captures.bluetooth.input(), capture.input());
            let rebuilt = copied.handoff().unwrap();
            assert_eq!(rebuilt.dma, 0x1000..0x2000);
            assert_eq!(rebuilt.clock.ticks_per_microsecond, 3);
        }
        let absent = Storage::absent();
        assert!(absent.handoff().is_none());
        assert_eq!(absent.captures.bluetooth.input(), DsbrInput::Unavailable);
    }
}
