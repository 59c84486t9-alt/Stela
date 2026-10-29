//! AOP AP wake masks: `AppleT8112PMGR::setAPWakeupSources` (kernel file
//! 0x2fa3f84, stores 0x2fa404c..0x2fa411c) writes `valid & !requested` to
//! eight 32-bit words at PMGR `reg[4]+8`. `writeAOPGlobalReg` (0x2f9dc70)
//! subtracts 0x4000 from its argument before accessing this bank.
//!
//! The valid masks are hardware data absent from the DT; the board supplies
//! them from `getAPWakeupSourcesValidMasks` (0x2fa3f74, data 0x7957ec).
//! Source n selects word n/32, bit n%32. A set bit inhibits that source.
//! `ap-wake-sources` carries reporting IDs/names, not the compiled valid mask.
//!
//! Stela's boot stage hands off with every valid source masked: the mask
//! words equal the valid bitmap, since a set bit inhibits a source. This is
//! the handoff of a boot chain that enables none of these wake sources;
//! iBoot's conditional programming is not reproduced. Masks keep full
//! writes. No status/acknowledgement lifecycle is established, so
//! no status words are claimed. AOP/NUB/SMC/ATC physical wake generators are
//! not emulated; this model supplies mask state for a supported generator to
//! query, and does not invent a wake event when a mask is written.
use crate::Result;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

const NAME: &str = "aop-wake-masks";
pub const WORDS: usize = 8;
pub const BYTES: u64 = WORDS as u64 * 4;

#[derive(Debug, Clone)]
pub struct WakeMasks {
    valid: [u32; WORDS],
    masks: [u32; WORDS],
}

impl WakeMasks {
    pub fn new(valid: [u32; WORDS]) -> Self {
        Self {
            valid,
            masks: valid,
        }
    }

    /// Whether the mask allows source n to wake the AP. Every
    /// valid source starts masked; unsupported source numbers refuse.
    pub fn enabled(&self, source: u8) -> Result<bool> {
        let word = usize::from(source) / u32::BITS as usize;
        let bit = 1 << (u32::from(source) % u32::BITS);
        if self.valid[word] & bit == 0 {
            return Err(refuse!("AOP wake source is not supported by this hardware"));
        }
        Ok(self.masks[word] & bit == 0)
    }

    fn word(offset: u64, width: Width) -> Result<usize> {
        if width != Width::Word || offset >= BYTES || !offset.is_multiple_of(4) {
            return Err(refuse!(
                "AOP wake mask register or width without described meaning"
            ));
        }
        Ok((offset / 4) as usize)
    }
}

impl MmioDevice for WakeMasks {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        Self::word(offset, width)
            .map(|word| u64::from(self.masks[word]))
            .map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let result = Self::word(offset, width).and_then(|word| {
            if value & !u64::from(self.valid[word]) != 0 {
                return Err(refuse!(
                    "AOP wake mask sets bits outside the hardware valid mask"
                ));
            }
            self.masks[word] = value as u32;
            Ok(())
        });
        result.map_err(|reason| refuse(NAME, offset, width, Direction::Write, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;

    #[test]
    fn active_low_masks_hold_writes_and_exclude_reserved_sources() {
        let mut valid = [u32::MAX; WORDS];
        valid[7] = 0x7fff_ffff;
        let mut masks = WakeMasks::new(valid);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for (word, &mask) in valid.iter().enumerate() {
            assert_eq!(
                masks.read(word as u64 * 4, Width::Word, &mut access),
                Ok(u64::from(mask))
            );
        }
        for source in 0..255 {
            assert_eq!(masks.enabled(source), Ok(false));
        }
        assert!(masks.enabled(255).is_err());
        for (word, value) in [
            0xf3ff_bfff,
            0xfb97_efff,
            0xffbd_fddf,
            0xffff_ffff,
            0xc3f7_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0x7fff_ffff,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = word as u64 * 4;
            masks
                .write(offset, Width::Word, value, &mut access)
                .unwrap();
            assert_eq!(masks.read(offset, Width::Word, &mut access), Ok(value));
        }
        assert_eq!(masks.enabled(14), Ok(true));
        assert_eq!(masks.enabled(13), Ok(false));
        assert_eq!(masks.enabled(157), Ok(true));
        assert!(masks.enabled(255).is_err());
        assert!(
            masks
                .write(28, Width::Word, 0xffff_ffff, &mut access)
                .is_err()
        );
        assert_eq!(masks.read(28, Width::Word, &mut access), Ok(0x7fff_ffff));
        for (offset, width) in [
            (32, Width::Word),
            (0, Width::Double),
            (0, Width::Half),
            (2, Width::Word),
        ] {
            assert!(masks.read(offset, width, &mut access).is_err());
            assert!(masks.write(offset, width, 0, &mut access).is_err());
        }
    }
}
