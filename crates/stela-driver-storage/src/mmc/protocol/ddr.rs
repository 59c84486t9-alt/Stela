// SPDX-License-Identifier: GPL-2.0-only
// Linux MMC core, Copyright 2003-2004 Russell King, 2005-2007 Pierre Ossman;
// MMCv4 support Copyright 2006 Philip Langdale. All Rights Reserved.
//! Eight-pin embedded MMC DDR52 with source host-before-status ordering.
use super::*;

impl<H: Host> Session<'_, H> {
    pub(super) fn ddr52_supported(&self, ext: &[u8]) -> bool {
        self.host.mmc_fast_modes() && self.host.mmc_width() == 8 && ext[EXT_CARD_TYPE] & 4 != 0
    }
    pub(super) fn begin_ddr52(
        &mut self,
        ext: &mut [u8],
        info: &mut CardInfo,
    ) -> Result<(), BlockError> {
        self.execute(
            SWITCH,
            3 << 24 | (EXT_TIMING as u32) << 16 | 1 << 8,
            Response::Busy,
            None,
        )?;
        ext[EXT_TIMING] = 1;
        self.host.set_high_speed()?;
        self.host.mmc_switch_status(self.rca, true)?;
        info.clock_hz = self.host.set_clock(52_000_000)?;
        info.timing = Timing::HighSpeed;
        Ok(())
    }
    pub(super) fn finish_ddr52(
        &mut self,
        voltage: u32,
        ext: &mut [u8],
        info: &mut CardInfo,
    ) -> Result<(), BlockError> {
        self.execute(
            SWITCH,
            3 << 24 | (EXT_BUS_WIDTH as u32) << 16 | 6 << 8,
            Response::Busy,
            None,
        )?;
        ext[EXT_BUS_WIDTH] = 6;
        // DDR52 permits the old 3.3-V signaling pads during this transition.
        self.host.set_mmc_timing(Timing::MmcDdr52)?;
        self.host.mmc_switch_status(self.rca, true)?;
        self.host.set_mmc_signal_voltage()?;
        info.signal_voltage = SignalVoltage::V1_8;
        info.timing = Timing::MmcDdr52;
        let power = ext[if voltage == OCR_180 { 238 } else { 239 }] >> 4;
        if power != 0 {
            self.mmc_switch(187, power)?;
            ext[187] = power;
        }
        Ok(())
    }
}
