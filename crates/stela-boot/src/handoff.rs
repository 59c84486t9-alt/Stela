//! Plain data the loader phase passes to the engine phase. Addresses are host
//! physical; the engine reaches them through its physmap.
use crate::console::Framebuffer;

pub const MAGIC: u64 = 0x5354_454c_4153_5953; // "SYSALETS"
pub const MAX_GUEST_RANGES: usize = 128;
pub const MAX_FILES: usize = 16;
pub const MAX_NAME: usize = 48;

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
    /// The window's PML4, shared by every root.
    pub window: u64,
    pub screen: Option<Framebuffer>,
    /// TSC ticks per second, measured against the firmware's Stall.
    pub tsc_hz: u64,
    /// IA32_APIC_BASE as the firmware left it.
    pub apic_base: u64,
    /// Free host RAM after boot services, in 2 MiB-aligned ranges.
    pub guest: [Region; MAX_GUEST_RANGES],
    pub guest_count: usize,
}
