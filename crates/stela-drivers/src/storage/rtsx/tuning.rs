// SPDX-License-Identifier: GPL-2.0-only
// Native adaptation of rtsx_pci_sdmmc.c/rts5227.c, Copyright 2009-2013 Realtek.
// CMD11 sequence also adapts MMC core.c: Copyright 2003-2004 Russell King,
// 2004 Ian Molton, 2005-2008 Pierre Ossman, 2006 Philip Langdale.
//! Actual RTS522A CMD11 electrical transition, SD UHS clocks and phase tuning.
use super::*;

impl Engine {
    pub(super) fn rts522a_switch_signal(&mut self) -> Result<(), BlockError> {
        if self.config.profile != ChipProfile::Rts522a {
            return Err(BlockError::Unsupported(
                "RTSX profile has no qualified1.8V path",
            ));
        }
        let budget = Budget::new(self, 100_000);
        let result = (|| {
            self.clock.delay(1_000);
            self.check_card_before(budget)?;
            if self.read_reg_before(SD_BUS_STAT, Some(budget))? & SD_DAT_MASK == SD_DAT_MASK {
                return Err(BlockError::Unsupported("SD CMD11 did not pull DAT low"));
            }
            self.write_reg_before(CARD_CLK_EN, SD_CLK_EN, 0, Some(budget))?;
            self.write_reg_before(SD_BUS_STAT, 0xff, SD_CLK_FORCE_STOP, Some(budget))?;
            self.phy(0x11, 0x3c02)?;
            self.phy(8, 0x54a4)?;
            let drive = self.config.drive_1v8();
            for at in [SD30_CLK_DRIVE_SEL, SD30_CMD_DRIVE_SEL, SD30_DAT_DRIVE_SEL] {
                self.write_reg_before(at, 0xff, drive, Some(budget))?;
            }
            self.clock.delay(10_000);
            self.check_card_before(budget)?;
            self.write_reg_before(CARD_CLK_EN, SD_CLK_EN, SD_CLK_EN, Some(budget))?;
            self.write_reg_before(
                SD_BUS_STAT,
                SD_CLK_TOGGLE_EN | SD_CLK_FORCE_STOP,
                SD_CLK_TOGGLE_EN,
                Some(budget),
            )?;
            self.clock.delay(1_000);
            let pins = self.read_reg_before(SD_BUS_STAT, Some(budget))?;
            self.write_reg_before(
                SD_BUS_STAT,
                SD_CLK_TOGGLE_EN | SD_CLK_FORCE_STOP,
                0,
                Some(budget),
            )?;
            if pins & SD_DAT_MASK != SD_DAT_MASK {
                return Err(BlockError::Unsupported(
                    "SD1.8V transition did not release DAT",
                ));
            }
            self.check_card_before(budget)?;
            self.signal_voltage = SignalVoltage::V1_8;
            Ok(())
        })();
        result.map_err(|primary| self.emergency_off(primary, false))
    }
    pub(super) fn rts522a_timing(&mut self, timing: Timing) -> Result<(), BlockError> {
        if self.config.profile != ChipProfile::Rts522a || self.signal_voltage != SignalVoltage::V1_8
        {
            return Err(BlockError::Unsupported(
                "RTSX UHS timing requires qualified actual1.8V",
            ));
        }
        match timing {
            Timing::Sdr12 | Timing::Sdr25 => self.timing(false)?,
            Timing::Sdr50 | Timing::Sdr104 => {
                self.write_reg(
                    SD_CFG1,
                    0x0c | SD_ASYNC_FIFO_NOT_RST,
                    SD_30_MODE | SD_ASYNC_FIFO_NOT_RST,
                )?;
                self.write_reg(CLK_CTL, CLK_LOW_FREQ, CLK_LOW_FREQ)?;
                self.write_reg(CARD_CLK_SOURCE, 0xff, 0x21)?;
                self.write_reg(CLK_CTL, CLK_LOW_FREQ, 0)?;
            }
            _ => {
                return Err(BlockError::Unsupported(
                    "RTSX timing is not a declared SD UHS mode",
                ));
            }
        }
        self.timing_mode = timing;
        Ok(())
    }
    fn phase(&mut self, phase: u8, rx: bool) -> Result<(), BlockError> {
        self.write_reg(CLK_CTL, CLK_LOW_FREQ, CLK_LOW_FREQ)?;
        let at = if rx { SD_VPRX_CTL } else { SD_VPTX_CTL };
        self.write_reg(at, PHASE_SELECT_MASK, phase)?;
        self.write_reg(at, PHASE_NOT_RESET, 0)?;
        self.write_reg(at, PHASE_NOT_RESET, PHASE_NOT_RESET)?;
        self.write_reg(CLK_CTL, CLK_LOW_FREQ, 0)?;
        self.write_reg(SD_CFG1, SD_ASYNC_FIFO_NOT_RST, 0)
    }
    pub(super) fn rts522a_tune(&mut self) -> Result<(), BlockError> {
        if self.config.profile != ChipProfile::Rts522a
            || self.signal_voltage != SignalVoltage::V1_8
            || !matches!(self.timing_mode, Timing::Sdr50 | Timing::Sdr104)
        {
            return Err(BlockError::Unsupported(
                "RTSX tuning requires declared SDR50/104",
            ));
        }
        self.phase(20, false)?;
        let mut intersection = u32::MAX;
        for _ in 0..3 {
            let mut map = 0;
            for phase in 0..32 {
                self.phase(phase, true)?;
                self.write_reg(SD_CFG3, SD_RSP_80CLK_TIMEOUT_EN, SD_RSP_80CLK_TIMEOUT_EN)?;
                let result = self.execute(SD_SEND_TUNING, 0, Response::Status, Some(64));
                // A phase's real card CRC rejection is expected tuning evidence.
                // Removal, OCP, uncertain HAIMR and every other failure stop the
                // sweep. The ordinary command path already acknowledged Stop.
                let phase_rejection = match &result {
                    Err(BlockError::Device { status }) => {
                        status & !0xffff == 0 && status & (u32::from(SD_TRANSFER_ERR) | 0xe000) != 0
                    }
                    Err(BlockError::Timeout) => true,
                    _ => false,
                };
                let valid = match result {
                    Ok(_) => true,
                    Err(_)
                        if self.fault.is_none()
                            && self.tuning_rejection_observed
                            && phase_rejection =>
                    {
                        let budget = Budget::new(self, 10_000);
                        loop {
                            self.check_card_before(budget)?;
                            if self.read_reg_before(SD_DATA_STATE, Some(budget))? & SD_DATA_IDLE
                                != 0
                            {
                                break;
                            }
                        }
                        false
                    }
                    Err(error) => return Err(error),
                };
                self.write_reg(SD_CFG3, SD_RSP_80CLK_TIMEOUT_EN, 0)?;
                if valid {
                    map |= 1 << phase;
                }
            }
            intersection &= map;
            if intersection == 0 {
                return Err(BlockError::Unsupported(
                    "RTSX SD tuning has no common RX window",
                ));
            }
        }
        let selected =
            final_phase(intersection).ok_or(BlockError::Unsupported("RTSX empty tuning window"))?;
        self.phase(selected, true)?;
        // Recheck an actual completed tuning transaction at the selected phase.
        self.execute(SD_SEND_TUNING, 0, Response::Status, Some(64))?;
        Ok(())
    }
}

// Source longest circular run: strict greater-than preserves the first tie.
fn final_phase(map: u32) -> Option<u8> {
    if map == 0 {
        return None;
    }
    let (mut selected, mut longest) = (0, 0);
    let mut start = 0;
    while start < 32 {
        let length = (0..32)
            .take_while(|offset| map & (1 << ((start + offset) % 32)) != 0)
            .count();
        if length > longest {
            selected = start;
            longest = length;
        }
        start += length.max(1);
    }
    Some(((selected + longest / 2) % 32) as u8)
}

#[cfg(test)]
mod tests {
    use super::final_phase;
    #[test]
    fn circular_windows_and_equal_length_ties_follow_source() {
        assert_eq!(final_phase(0), None);
        assert_eq!(final_phase(u32::MAX), Some(16));
        assert_eq!(final_phase(0xc000_0003), Some(0));
        assert_eq!(final_phase(0x0000_0f0f), Some(2));
        for start in 0..32 {
            for length in 1..32 {
                let map = ((1u32 << length) - 1).rotate_left(start);
                assert_eq!(final_phase(map), Some(((start + length / 2) % 32) as u8));
            }
        }
    }
}
