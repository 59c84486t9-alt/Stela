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
//! doc, never a fabricated value. This is the spec-first boundary; the
//! registers the restored_external boot actually touches are closed from its
//! trace, not guessed here.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};

/// A present-but-unmodeled register aperture: every access refuses, named.
pub struct Region {
    name: &'static str,
}

impl Region {
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }
}

impl MmioDevice for Region {
    fn name(&self) -> &'static str {
        self.name
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        Err(refuse(
            self.name,
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
        Err(refuse(
            self.name,
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
    use crate::platform::apple::interrupt::InterruptLatch;

    #[test]
    fn every_display_register_access_refuses_by_name() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut region = Region::new("dispext0");
        assert_eq!(region.name(), "dispext0");
        assert!(region.read(0, Width::Word, &mut access).is_err());
        assert!(region.write(0x100, Width::Double, 0, &mut access).is_err());
    }
}
