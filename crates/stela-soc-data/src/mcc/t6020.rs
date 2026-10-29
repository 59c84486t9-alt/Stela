//! Immutable T602x request aperture/channel geometry; no cache rights.
use crate::Result;
use stela_contracts::refuse;
pub const APERTURE_BYTES: u64 = 0x1000000;
pub const MAX_APERTURES: usize = 16;
pub const PLANES: u8 = 4;
pub const PLANE_STRIDE: u64 = 0x40000;
pub const CHANNELS: usize = 4;
pub const DCS_BASE: u64 = 0x200000;
pub const DCS_STRIDE: u64 = 0x200000;
pub const DRAIN: u64 = 0xa40;
pub const DRAM_CONFIGURATION: u64 = 0x13c8;
pub const DCS_GATING: u64 = 0x1c;
pub const MCC_GATING: u64 = 0x100004;
pub const CACHE_SIZE: u64 = 0x100020;
pub const CACHE_MODE: u64 = 0x1c1c00;
pub const CACHE_STATUS: u64 = 0x1c00;
pub const WAYS_STATUS: u64 = 0x1c04;

/// Source geometry only: it grants no physical/cache/native execution rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout(u8);
impl Layout {
    pub fn new(apertures: usize) -> Result<Self> {
        if !(1..=MAX_APERTURES).contains(&apertures) {
            return Err(refuse!(
                "T602x controller exceeds the source sixteen-aperture descriptor array"
            ));
        }
        Ok(Self(apertures as u8))
    }
    pub fn apertures(self) -> usize {
        usize::from(self.0)
    }
    pub fn channels(self) -> usize {
        self.apertures() * CHANNELS
    }
    pub fn channel(self, ordinal: usize) -> Result<(u8, u64)> {
        if ordinal >= self.channels() {
            return Err(refuse!(
                "T602x DCS ordinal exceeds the actual source apertures"
            ));
        }
        Ok((
            (ordinal / CHANNELS) as u8,
            DCS_BASE + (ordinal % CHANNELS) as u64 * DCS_STRIDE,
        ))
    }
}
