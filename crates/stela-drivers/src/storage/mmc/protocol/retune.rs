// SPDX-License-Identifier: GPL-2.0-only
// Linux MMC core, Copyright 2003-2004 Russell King, 2005-2007 Pierre Ossman;
// MMCv4 support Copyright 2006 Philip Langdale. All Rights Reserved.
// Host retuning: Copyright 2003 Russell King, 2007-2008 Pierre Ossman,
// 2010 Linus Walleij. See ../../THIRD_PARTY.md.
//! Explicit HS200 tuning and ordinary HS400 downgrade/tune/restore.
use super::*;
#[cfg(test)]
mod tests;

impl<H: Host> Session<'_, H> {
    fn retune_switch(&mut self, ext: &mut [u8], index: usize, value: u8) -> Result<(), BlockError> {
        self.execute(
            SWITCH,
            3 << 24 | (index as u32) << 16 | u32::from(value) << 8,
            Response::Busy,
            None,
        )?;
        ext[index] = value;
        Ok(())
    }

    pub(in crate::storage) fn retune_mmc(&mut self, info: &mut CardInfo) -> Result<(), BlockError> {
        let hs400 = info.timing == Timing::MmcHs400;
        if info.kind != Kind::Mmc
            || !matches!(info.timing, Timing::MmcHs200 | Timing::MmcHs400)
            || info.bus_width != 8
            || !self.host.mmc_fast_modes()
        {
            return Err(BlockError::Unsupported(
                "MMC retuning requires an admitted fast mode",
            ));
        }
        let ext = info.ext_csd.as_mut().ok_or(BlockError::Unsupported(
            "MMC retuning requires original EXT_CSD",
        ))?;
        if ext[EXT_BUS_WIDTH] != if hs400 { 6 } else { 2 } {
            // Enhanced-strobe operation has no sampled-data CMD21 procedure.
            return Err(BlockError::Unsupported(
                "MMC retuning requires ordinary sampled-data width",
            ));
        }
        let hs_hz = if ext[EXT_CARD_TYPE] & 2 != 0 {
            52_000_000
        } else {
            26_000_000
        };
        let drive = ext[EXT_TIMING] & 0xf0;
        let result = (|| {
            if hs400 {
                info.clock_hz = self.host.set_clock(hs_hz)?;
                self.retune_switch(ext, EXT_TIMING, 1)?;
                self.host.set_mmc_timing(Timing::MmcDdr52)?;
                self.host.mmc_switch_status(self.rca, true)?;
                self.retune_switch(ext, EXT_BUS_WIDTH, 2)?;
                self.host.set_mmc_timing(Timing::HighSpeed)?;
                self.host.mmc_switch_status(self.rca, true)?;
                self.retune_switch(ext, EXT_TIMING, drive | 2)?;
                self.host.set_mmc_timing(Timing::MmcHs200)?;
                self.host.mmc_switch_status(self.rca, false)?;
                info.clock_hz = self.host.set_clock(200_000_000)?;
            }
            self.host.tune_mmc()?;
            if hs400 {
                self.retune_switch(ext, EXT_TIMING, 1)?;
                self.host.set_mmc_timing(Timing::HighSpeed)?;
                info.clock_hz = self.host.set_clock(hs_hz)?;
                self.host.mmc_switch_status(self.rca, true)?;
                self.mmc_switch(EXT_BUS_WIDTH as u8, 6)?;
                ext[EXT_BUS_WIDTH] = 6;
                self.retune_switch(ext, EXT_TIMING, drive | 3)?;
                self.host.set_mmc_timing(Timing::MmcHs400)?;
                info.clock_hz = self.host.set_clock(200_000_000)?;
                self.host.mmc_switch_status(self.rca, true)?;
            }
            Ok(())
        })();
        result.map_err(|error| self.host.mmc_mode_failure(error))
    }
}
