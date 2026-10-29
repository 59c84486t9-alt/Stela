//! AP-authored firmware PIO descriptors, copied by every modeled GFX family.
//!
//! The original G14G producer (`AGXFirmware::initFirmwareData`, kernel file
//! 0x1b34eb0..0x1b35024) writes forty-byte records at hardware-config +0x640.
//! Firmware 0xffffff8000035d54 copies each record by its *type*, not its index
//! in the name table. G13G/X, G14X and G15G use the same descriptor encoding.
//! Physical ranges and their firmware mappings are distinct: the latter must
//! pass the real UAT walk before a concrete native register owner is accessed.
//! See docs/research/agx.md for the original input and callback matrix.

use crate::Result;
use crate::platform::apple::agx::ring::Shared;
use stela_contracts::refuse;

/// The original `AGFIPIORegionType` values used by kept power callbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Kind {
    MCache = 3,
    ResourceWindows = 17,
    GFender = 31,
    GmGifaf = 32,
    Gcpms = 34,
    Mcw = 36,
    DFender = 40,
    Mtr = 44,
}

const DESCRIPTORS: u64 = 0x640;
const DESCRIPTOR_BYTES: u64 = 0x28;
const WRITABLE: u32 = 2;

/// A validated snapshot of one AP descriptor. Its first physical range is
/// explicit; subsequent ranges need their physical list and cannot be
/// inferred by adding to the first base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub kind: Kind,
    physical: u64,
    virtual_address: u64,
    bytes: u32,
    range_bytes: u32,
    /// Provider-relative offset copied from the accelerator's PIO object +210.
    pub relative: u64,
    flags: u32,
}

impl Region {
    pub fn geometry(&self) -> (u64, u32, u32) {
        (self.physical, self.bytes, self.range_bytes)
    }

    /// An original producer-checked physical list may check later
    /// ranges. No caller may synthesize that list by adding to the first
    /// descriptor base; every resulting native target still walks the UAT.
    pub fn listed_word(&self, offset: u32, bases: &[u64]) -> Result<(u64, u64)> {
        if bases.first() != Some(&self.physical)
            || (bases.len() as u64).checked_mul(u64::from(self.range_bytes))
                != Some(u64::from(self.bytes))
        {
            return Err(refuse!(
                "GFX firmware PIO physical list disagrees with its descriptor"
            ));
        }
        if offset & 3 != 0 || self.virtual_address & 3 != 0 || self.flags & WRITABLE == 0 {
            return Err(refuse!(
                "GFX firmware PIO listed write is unaligned or read-only"
            ));
        }
        let end = offset
            .checked_add(4)
            .ok_or(refuse!("GFX firmware PIO listed word wraps"))?;
        if end > self.bytes || offset / self.range_bytes != (end - 1) / self.range_bytes {
            return Err(refuse!(
                "GFX firmware PIO listed word exceeds one mapped range"
            ));
        }
        let base = bases[(offset / self.range_bytes) as usize];
        base.checked_add(u64::from(self.range_bytes))
            .ok_or(refuse!("GFX firmware PIO listed physical range wraps"))?;
        Ok((
            self.virtual_address + u64::from(offset),
            base + u64::from(offset % self.range_bytes),
        ))
    }

    pub fn read(memory: &mut dyn Shared, hardware_config: u64, kind: Kind) -> Result<Self> {
        let address = hardware_config
            .checked_add(DESCRIPTORS + kind as u64 * DESCRIPTOR_BYTES)
            .ok_or(refuse!("GFX firmware PIO descriptor address wraps"))?;
        let mut bytes = [0; DESCRIPTOR_BYTES as usize];
        address
            .checked_add(DESCRIPTOR_BYTES)
            .ok_or(refuse!("GFX firmware PIO descriptor range wraps"))?;
        memory.read(address, &mut bytes)?;
        Self::parse(kind, &bytes)
    }

    fn parse(kind: Kind, data: &[u8; DESCRIPTOR_BYTES as usize]) -> Result<Self> {
        let quad = |at| u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
        let word = |at| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
        let region = Self {
            kind,
            physical: quad(0),
            virtual_address: quad(8),
            bytes: word(0x10),
            range_bytes: word(0x14),
            relative: quad(0x18),
            flags: word(0x20),
        };
        if region.physical == 0 || region.virtual_address == 0 {
            return Err(refuse!(
                "GFX firmware PIO descriptor has no physical or virtual mapping"
            ));
        }
        if region.range_bytes == 0
            || region.bytes == 0
            || !region.bytes.is_multiple_of(region.range_bytes)
        {
            return Err(refuse!(
                "GFX firmware PIO descriptor has inconsistent range sizes"
            ));
        }
        if region.flags & !WRITABLE != 0 {
            return Err(refuse!(
                "GFX firmware PIO descriptor has unknown access flags"
            ));
        }
        // The firmware copies only through +0x23. The last four bytes are
        // padding and need not be zero in the AP's allocation.
        region
            .physical
            .checked_add(u64::from(region.range_bytes))
            .ok_or(refuse!("GFX firmware PIO physical range wraps"))?;
        region
            .virtual_address
            .checked_add(u64::from(region.bytes))
            .ok_or(refuse!("GFX firmware PIO virtual range wraps"))?;
        Ok(region)
    }

    /// Address a word in the first known physical range. The native target
    /// still has to check its physical bank and the UAT translation.
    pub fn word(&self, offset: u32, write: bool) -> Result<(u64, u64)> {
        self.range(offset, 4, write)
    }

    /// Check the complete native access, including eight-byte resource
    /// windows. This does not infer a secondary physical range or bypass UAT.
    pub fn range(&self, offset: u32, bytes: u32, write: bool) -> Result<(u64, u64)> {
        if !matches!(bytes, 4 | 8) {
            return Err(refuse!("GFX firmware PIO native width is not qualified"));
        }
        let mask = u64::from(bytes - 1);
        if u64::from(offset) & mask != 0
            || self.physical & mask != 0
            || self.virtual_address & mask != 0
        {
            return Err(refuse!("GFX firmware PIO word is unaligned"));
        }
        let end = offset
            .checked_add(bytes)
            .ok_or(refuse!("GFX firmware PIO word offset wraps"))?;
        if end > self.bytes {
            return Err(refuse!("GFX firmware PIO word exceeds its descriptor"));
        }
        if end > self.range_bytes {
            return Err(refuse!(
                "GFX firmware PIO secondary physical range is not qualified"
            ));
        }
        if write && self.flags & WRITABLE == 0 {
            return Err(refuse!("GFX firmware PIO descriptor is read-only"));
        }
        Ok((
            self.virtual_address + u64::from(offset),
            self.physical + u64::from(offset),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn descriptor(physical: u64, va: u64, bytes: u32) -> [u8; 0x28] {
        let mut data = [0; 0x28];
        data[..8].copy_from_slice(&physical.to_le_bytes());
        data[8..16].copy_from_slice(&va.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&bytes.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&bytes.to_le_bytes());
        data[0x20..0x24].copy_from_slice(&WRITABLE.to_le_bytes());
        data
    }

    #[test]
    fn descriptor_preserves_provider_offset_and_does_not_infer_scattered_ranges() {
        let mut data = descriptor(0x204d04000, 0x10000, 0x8000);
        data[0x14..0x18].copy_from_slice(&0x4000u32.to_le_bytes());
        data[0x18..0x20].copy_from_slice(&0xd04000u64.to_le_bytes());
        data[0x24..].fill(0xff); // Not copied by the original firmware.
        let region = Region::parse(Kind::GFender, &data).unwrap();
        assert_eq!(region.relative, 0xd04000);
        assert_eq!(region.word(0x2030, true), Ok((0x12030, 0x204d06030)));
        assert!(
            region
                .word(0x4000, false)
                .unwrap_err()
                .to_string()
                .contains("secondary physical range")
        );
        assert!(
            region
                .word(0x8000, false)
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
        assert!(
            region
                .word(1, false)
                .unwrap_err()
                .to_string()
                .contains("unaligned")
        );
    }

    #[test]
    fn malformed_or_unmapped_descriptors_never_become_pio_targets() {
        let good = descriptor(0x204d04000, 0x10000, 0xc000);
        for at in [0, 8, 0x10, 0x14] {
            let mut data = good;
            let bytes = if at < 16 { 8 } else { 4 };
            data[at..at + bytes].fill(0);
            assert!(Region::parse(Kind::GFender, &data).is_err());
        }
        let mut data = good;
        data[0x10..0x14].copy_from_slice(&0xc001u32.to_le_bytes());
        assert!(Region::parse(Kind::GFender, &data).is_err());
        data = good;
        data[0x20] = 4;
        assert!(Region::parse(Kind::GFender, &data).is_err());
        data = good;
        data[0x20] = 0;
        let region = Region::parse(Kind::GFender, &data).unwrap();
        assert!(
            region
                .word(0, true)
                .unwrap_err()
                .to_string()
                .contains("read-only")
        );
        assert!(region.word(0, false).is_ok());
        data = good;
        data[..8].copy_from_slice(&(u64::MAX - 3).to_le_bytes());
        assert!(
            Region::parse(Kind::GFender, &data)
                .unwrap_err()
                .to_string()
                .contains("wraps")
        );
        data = good;
        data[8..16].copy_from_slice(&(u64::MAX - 3).to_le_bytes());
        assert!(
            Region::parse(Kind::GFender, &data)
                .unwrap_err()
                .to_string()
                .contains("wraps")
        );
    }
}
