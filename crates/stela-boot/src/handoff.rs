//! Plain data the loader phase passes to the engine phase. Addresses are host
//! physical; the engine reaches them through its physmap.
use crate::console::Framebuffer;
use alloc::vec::Vec;
use stela_runtime::{machine::mmu::placement::Placement, pc};

pub const MAGIC: u64 = 0x5354_454c_4153_5953; // "SYSALETS"
pub const MAX_GUEST_RANGES: usize = 128;
pub const MAX_FILES: usize = 16;
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

/// The host storage drivers' handoff (`stela_runtime::pc::Handoff`) in
/// fixed arrays, for `--preboot`; `present` is false otherwise.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Storage {
    pub present: bool,
    pub ecam: [pc::pci::EcamWindow; MAX_ECAM],
    pub ecam_count: usize,
    /// Ranges the loader identity-mapped uncached.
    pub mapped: [Region; MAX_MAPPED],
    pub mapped_count: usize,
    pub dma: Region,
    pub ticks_per_microsecond: u64,
}

impl Storage {
    pub fn absent() -> Self {
        Self {
            present: false,
            ecam: [pc::pci::EcamWindow {
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
        }
    }

    pub fn new(handoff: &pc::Handoff) -> Result<Self, &'static str> {
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
        Ok(storage)
    }

    pub fn handoff(&self) -> Option<pc::Handoff> {
        self.present.then(|| pc::Handoff {
            ecam: self.ecam[..self.ecam_count].to_vec(),
            mapped: self.mapped[..self.mapped_count]
                .iter()
                .map(|r| r.physical..r.physical + r.bytes)
                .collect::<Vec<_>>(),
            dma: self.dma.physical..self.dma.physical + self.dma.bytes,
            clock: pc::Clock {
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
    /// TSC ticks per second, measured against the firmware's Stall.
    pub tsc_hz: u64,
    /// IA32_APIC_BASE as the firmware left it.
    pub apic_base: u64,
    /// The firmware's real-time clock as Unix seconds, read at TSC
    /// `wall_tsc`; `None` when the firmware has no valid time.
    pub wall_seconds: Option<u64>,
    pub wall_tsc: u64,
    /// Free host RAM after boot services, in 2 MiB-aligned ranges.
    pub guest: [Region; MAX_GUEST_RANGES],
    pub guest_count: usize,
    /// The host storage drivers' ranges, for a bundle built from a disk.
    pub storage: Storage,
    /// The host's ACPI power hardware, when its FADT is usable.
    pub power: Option<pc::power::HostPower>,
}
