//! The J473AP display-hardware register apertures around the DCP: `dispext0`
//! (`dispext0,t8112`), `dptx-phy` (`dptx-phy,t8112`), `display-crossbar0`
//! (`display-crossbar,t8112`) and the DP2HDMI PCON GPIO nub.
//!
//! In the unified-pipeline architecture the DCP firmware, not the AP, programs
//! these blocks; the AP maps them for the DCP through `ServiceRelay`
//! (`mapDeviceMemoryWithIndex`, callback D411) and otherwise touches them
//! little. The model keeps each aperture present — so its DeviceTree node
//! stays visible and its DART (dart-dcpext, dart-dispext0) resolves for its
//! clients — but gives no register a modeled meaning: an access by the AP is
//! an explicit, named refusal that records the exact register for the owning
//! doc, never an invented value. This is the spec-first boundary; the
//! registers the restored_external boot touches are closed from its
//! trace, not guessed here.
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

/// A present-but-unmodeled register aperture: every access refuses, named.
pub struct Region {
    name: &'static str,
    /// Original named physical views; empty for the legacy offset interface.
    views: Vec<(&'static str, u64, u64)>,
}

impl Region {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            views: Vec::new(),
        }
    }

    /// One physical owner for a complete set of possibly contained aliases.
    /// Child DART/ASC routes are held by the bus, not implemented here.
    pub fn physical(views: Vec<(&'static str, u64, u64)>) -> Result<Self> {
        if views.is_empty()
            || views.iter().any(|(name, base, bytes)| {
                name.is_empty() || *bytes == 0 || base.checked_add(*bytes).is_none()
            })
        {
            return Err(refuse!("display physical views are empty or overflow"));
        }
        Ok(Self {
            name: "display apertures",
            views,
        })
    }

    fn location(&self, offset: u64, width: Width) -> (&'static str, u64) {
        self.views
            .iter()
            .filter(|(_, base, bytes)| {
                *base <= offset
                    && offset
                        .checked_add(width.bytes())
                        .is_some_and(|end| end <= base + bytes)
            })
            .min_by_key(|(_, _, bytes)| bytes)
            .map_or((self.name, offset), |(name, base, _)| {
                (*name, offset - base)
            })
    }
}

impl MmioDevice for Region {
    fn name(&self) -> &'static str {
        self.name
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let (name, offset) = self.location(offset, width);
        Err(refuse(
            name,
            offset,
            width,
            Direction::Read,
            "display register has no modeled meaning (DCP-programmed)",
        ))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        _: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let (name, offset) = self.location(offset, width);
        Err(refuse(
            name,
            offset,
            width,
            Direction::Write,
            "display register has no modeled meaning (DCP-programmed)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;

    #[test]
    fn every_display_register_access_refuses_by_name() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut region = Region::new("dispext0");
        assert_eq!(region.name(), "dispext0");
        assert!(region.read(0, Width::Word, &mut access).is_err());
        assert!(region.write(0x100, Width::Double, 0, &mut access).is_err());
    }

    #[test]
    fn physical_aliases_keep_source_names_and_relative_refusal_offsets() {
        let mut region = Region::physical(vec![
            ("pipe", 0x1000, 0x3000),
            ("bank", 0x2000, 0x400),
            ("shared", 0x8000, 0x400),
        ])
        .unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for (pa, name, offset) in [
            (0x1004, "pipe", 4),
            (0x2010, "bank", 0x10),
            (0x8018, "shared", 0x18),
        ] {
            assert_eq!(
                region.read(pa, Width::Word, &mut access),
                Err(refuse(
                    name,
                    offset,
                    Width::Word,
                    Direction::Read,
                    "display register has no modeled meaning (DCP-programmed)"
                ))
            );
            assert_eq!(
                region.write(pa, Width::Word, 0, &mut access),
                Err(refuse(
                    name,
                    offset,
                    Width::Word,
                    Direction::Write,
                    "display register has no modeled meaning (DCP-programmed)"
                ))
            );
        }
        assert!(Region::physical(vec![]).is_err());
        assert!(Region::physical(vec![("pipe", u64::MAX, 1)]).is_err());
        assert!(Region::physical(vec![("", 0x1000, 4)]).is_err());
    }
}
