// SPDX-License-Identifier: GPL-2.0-only
// Native adaptation of Linux MMC mmc.c/mmc_ops.c; see ../../THIRD_PARTY.md.
// Copyright 2003-2004 Russell King, 2005-2007 Pierre Ossman;
// MMCv4 support Copyright 2006 Philip Langdale. All Rights Reserved.
//! MMC HS200/HS400 transitions preserve the card/host command ordering.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FastMode {
    Hs200,
    Hs400,
    Hs400Es,
}

impl<H: Host> Session<'_, H> {
    pub(super) fn fast_mode(&self, ext: &[u8]) -> Option<FastMode> {
        if !self.host.mmc_fast_modes() || self.host.mmc_width() != 8 {
            return None;
        }
        // The declared profile owns 1.8-V signaling. Never infer a 1.2-V pad
        // or an eight-pin board grant from generic controller capabilities.
        if ext[EXT_CARD_TYPE] & (1 << 6) != 0 && ext[184] & 1 != 0 {
            Some(FastMode::Hs400Es)
        } else if ext[EXT_CARD_TYPE] & (1 << 4) != 0 {
            Some(if ext[EXT_CARD_TYPE] & (1 << 6) != 0 {
                FastMode::Hs400
            } else {
                FastMode::Hs200
            })
        } else {
            None
        }
    }

    fn raw_timing(&mut self, ext: &mut [u8], value: u8) -> Result<(), BlockError> {
        // R1b establishes busy release, but CMD13 must follow host
        // timing/clock changes. Ordinary mmc_switch sends CMD13 too early.
        self.execute(
            SWITCH,
            3 << 24 | (EXT_TIMING as u32) << 16 | u32::from(value) << 8,
            Response::Busy,
            None,
        )?;
        ext[EXT_TIMING] = value;
        Ok(())
    }

    fn host_timing(
        &mut self,
        info: &mut CardInfo,
        timing: Timing,
        hz: u32,
    ) -> Result<(), BlockError> {
        self.host.set_mmc_timing(timing)?;
        info.clock_hz = self.host.set_clock(hz)?;
        info.timing = timing;
        Ok(())
    }

    pub(super) fn select_fast_mode(
        &mut self,
        mode: FastMode,
        voltage: u32,
        ext: &mut [u8],
        info: &mut CardInfo,
    ) -> Result<(), BlockError> {
        let hs_hz = if ext[EXT_CARD_TYPE] & 2 != 0 {
            52_000_000
        } else {
            26_000_000
        };
        if mode == FastMode::Hs400Es {
            self.raw_timing(ext, 1)?;
            self.host_timing(info, Timing::HighSpeed, hs_hz)?;
            self.host.mmc_switch_status(self.rca, true)?;
        } else {
            self.raw_timing(ext, 2)?;
            self.host_timing(info, Timing::MmcHs200, hs_hz)?;
            // Only a controller response-CRC failure may be ignored
            // here, as in mmc_switch_status(false). Card errors stay errors.
            self.host.mmc_switch_status(self.rca, false)?;
            info.clock_hz = self.host.set_clock(200_000_000)?;
            self.host.tune_mmc()?;
            if mode == FastMode::Hs400 {
                self.raw_timing(ext, 1)?;
                self.host_timing(info, Timing::HighSpeed, hs_hz)?;
                self.host.mmc_switch_status(self.rca, true)?;
            }
        }
        if mode != FastMode::Hs200 {
            let width = 6 | if mode == FastMode::Hs400Es { 0x80 } else { 0 };
            self.mmc_switch(EXT_BUS_WIDTH as u8, width)?;
            ext[EXT_BUS_WIDTH] = width;
            self.raw_timing(ext, 3)?;
            // The source ES path enables its host strobe before status, and
            // raises the bus frequency after the completed timing selection.
            self.host.set_mmc_timing(Timing::MmcHs400)?;
            if mode == FastMode::Hs400Es {
                self.host.set_mmc_strobe(true)?;
            }
            if mode == FastMode::Hs400 {
                info.clock_hz = self.host.set_clock(200_000_000)?;
            }
            self.host.mmc_switch_status(self.rca, true)?;
            if mode == FastMode::Hs400Es {
                info.clock_hz = self.host.set_clock(200_000_000)?;
            }
            info.timing = Timing::MmcHs400;
        }
        // Power class depends on VCC, current bus rate and SDR/DDR width;
        // signal voltage alone must never select the 1.8-V VCC table.
        let index = if voltage == OCR_180 {
            236
        } else if mode == FastMode::Hs200 {
            237
        } else {
            253
        };
        let power = ext[index] >> 4;
        if power != 0 {
            self.mmc_switch(187, power)?;
            ext[187] = power;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
