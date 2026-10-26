// SPDX-License-Identifier: GPL-2.0-only
// Linux MMC core, Copyright 2003-2004 Russell King, 2005-2007 Pierre Ossman;
// MMCv4 support Copyright 2006 Philip Langdale. All Rights Reserved.
//! Ordinary SDR high speed: host timing before status, bus clock before width.
use super::*;
#[cfg(test)]
mod tests;

impl<H: Host> Session<'_, H> {
    pub(super) fn begin_sdr_hs(
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
        self.wait_card_ready()?;
        info.clock_hz = self.host.set_clock(if ext[EXT_CARD_TYPE] & 2 != 0 {
            52_000_000
        } else {
            26_000_000
        })?;
        info.timing = Timing::HighSpeed;
        Ok(())
    }

    pub(super) fn select_sdr_power_class(
        &mut self,
        voltage: u32,
        ext: &mut [u8],
        info: &CardInfo,
    ) -> Result<(), BlockError> {
        // Power tables describe actual VCC and the established bus rate,
        // independently of the card's maximum advertised frequency.
        let index = match (voltage == OCR_180, info.clock_hz <= 26_000_000) {
            (true, true) => 201,
            (true, false) => 200,
            (false, true) => 203,
            (false, false) => 202,
        };
        let class = ext[index] >> if info.bus_width == 8 { 4 } else { 0 } & 15;
        if class != 0 {
            self.mmc_switch(187, class)?;
            ext[187] = class;
        }
        Ok(())
    }
}
