// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of Linux sdhci.c and sdhci-pci-gli.c.
//! Checked embedded MMC signaling and sampling through the engine.
use super::*;

impl Engine {
    pub(super) fn mmc_failure(&mut self, error: BlockError) -> BlockError {
        let previous = self
            .last_failure
            .clone()
            .filter(|failure| failure.primary == error);
        let primary = self.uhs_failure(error);
        self.fault.get_or_insert_with(|| primary.clone());
        if let Some(failure) = &mut self.last_failure {
            if let Some(previous) = previous {
                if failure.retirement.is_none() {
                    failure.retirement = previous.retirement;
                }
                if failure.restoration.is_none() {
                    failure.restoration = previous.restoration;
                }
            }
            failure.quarantined = true;
        }
        primary
    }
    pub(super) fn mmc_fast_modes(&self) -> bool {
        self.profile == Profile::Gli9763e
            && self.version >= 2
            && self.base_hz >= 200_000_000
            && self.capabilities & CAP_HIGH_SPEED != 0
            && self.extended_capabilities & (3 << 14) == 0
            && self
                .retune_interval()
                .is_none_or(|us| self.clock.check_duration(us).is_ok())
    }

    pub(super) fn mmc_signal_180(&mut self) -> Result<(), BlockError> {
        let result = (|| {
            self.check_card()?;
            if !self.mmc_fast_modes() {
                return Err(BlockError::Unsupported(
                    "SDHCI MMC fast mode has no board grant",
                ));
            }
            if self.signal_voltage == SignalVoltage::V1_8 {
                if self.registers.read16(HOST_CONTROL2) & SIGNAL_180 != 0 {
                    return Ok(());
                }
                return Err(BlockError::Unsupported("MMC 1.8-V signaling state changed"));
            }
            let clock = self.registers.read16(CLOCK);
            self.registers.write16(CLOCK, clock & !CLOCK_CARD);
            if self.registers.read16(CLOCK) & CLOCK_CARD != 0 {
                return Err(BlockError::Unsupported("MMC signal clock did not gate"));
            }
            let control = self.registers.read16(HOST_CONTROL2) | SIGNAL_180;
            self.registers.write16(HOST_CONTROL2, control);
            // GL9763E's source uses the standard SDHCI voltage hook and its
            // 100-ms settle. MMC changes pads directly and never issues CMD11.
            self.quiet(100_000)?;
            self.check_card()?;
            if self.registers.read16(HOST_CONTROL2) & SIGNAL_180 == 0 {
                return Err(BlockError::Unsupported(
                    "MMC signal voltage did not acknowledge",
                ));
            }
            self.registers.write16(CLOCK, clock);
            if self.registers.read16(CLOCK) & CLOCK_CARD != clock & CLOCK_CARD {
                return Err(BlockError::Unsupported("MMC signal clock did not restart"));
            }
            self.signal_voltage = SignalVoltage::V1_8;
            Ok(())
        })();
        result.map_err(|error| self.mmc_failure(error))
    }

    pub(super) fn mmc_timing(&mut self, timing: Timing) -> Result<(), BlockError> {
        let result = (|| {
            self.check_card()?;
            let mode = match timing {
                Timing::HighSpeed => 1,
                Timing::MmcHs200 => 3,
                Timing::MmcHs400 => 7,
                Timing::MmcDdr52 => 4,
                _ => return Err(BlockError::Unsupported("MMC host timing")),
            };
            if !self.mmc_fast_modes()
                || self.signal_voltage != SignalVoltage::V1_8 && timing != Timing::MmcDdr52
            {
                return Err(BlockError::Unsupported(
                    "MMC fast timing requires actual 1.8-V pads",
                ));
            }
            let clock = self.registers.read16(CLOCK);
            self.registers.write16(CLOCK, clock & !CLOCK_CARD);
            if self.registers.read16(CLOCK) & CLOCK_CARD != 0 {
                return Err(BlockError::Unsupported("MMC timing clock did not gate"));
            }
            let host = self.registers.read8(HOST_CONTROL) | HIGH_SPEED;
            self.registers.write8(HOST_CONTROL, host);
            let control = (self.registers.read16(HOST_CONTROL2) & !UHS_MODE) | mode;
            self.registers.write16(HOST_CONTROL2, control);
            let signal = if self.signal_voltage == SignalVoltage::V1_8 {
                SIGNAL_180
            } else {
                0
            };
            if self.registers.read8(HOST_CONTROL) & HIGH_SPEED == 0
                || self.registers.read16(HOST_CONTROL2) & (UHS_MODE | SIGNAL_180) != mode | signal
            {
                return Err(BlockError::Unsupported(
                    "MMC host timing did not acknowledge",
                ));
            }
            self.registers.write16(CLOCK, clock);
            if self.registers.read16(CLOCK) & CLOCK_CARD != clock & CLOCK_CARD {
                return Err(BlockError::Unsupported("MMC timing clock did not restart"));
            }
            self.sd_timing = timing;
            self.tuned_at = None;
            Ok(())
        })();
        result.map_err(|error| self.mmc_failure(error))
    }

    pub(super) fn mmc_strobe(&mut self, enable: bool) -> Result<(), BlockError> {
        let result = (|| {
            self.check_card()?;
            if !self.mmc_fast_modes() || self.sd_timing != Timing::MmcHs400 {
                return Err(BlockError::Unsupported("MMC enhanced strobe timing"));
            }
            let old = self.registers.read32(0x52c);
            let next = old & !(1 << 8) | u32::from(enable) << 8;
            self.registers.write32(0x52c, next);
            let actual = self.registers.read32(0x52c);
            self.check_authority()?;
            if actual & (1 << 8) != next & (1 << 8) {
                return Err(BlockError::Unsupported(
                    "MMC enhanced strobe did not acknowledge",
                ));
            }
            Ok(())
        })();
        result.map_err(|error| self.mmc_failure(error))
    }
}
