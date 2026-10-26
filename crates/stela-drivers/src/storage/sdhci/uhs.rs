// SPDX-License-Identifier: GPL-2.0-only
// Native adaptation of Linux sdhci.c, Copyright 2005-2008 Pierre Ossman;
// CMD11 adapts MMC core.c, Copyright 2003-2004 Russell King, 2004 Ian Molton,
// 2005-2008 Pierre Ossman and 2006 Philip Langdale. See ../THIRD_PARTY.md.
//! Standard v3 Host Control 2 operations with actual DAT/clock observations.
use super::*;
use crate::storage::mmc::{SdUhsModes, wire::SD_SEND_TUNING};

impl Engine {
    pub(super) fn uhs_modes(&self) -> SdUhsModes {
        // Vendor-specific voltage, clock and tuning hooks must be qualified
        // separately; their standard-mode support grants no electrical authority.
        if !matches!(
            self.profile,
            Profile::Standard | Profile::Gli9750 | Profile::Gli9755 | Profile::Gli9767
        ) || self.version < 2
            || self.extended_capabilities & (CAP_SDR50 | CAP_SDR104 | CAP_DDR50) == 0
        {
            return SdUhsModes::default();
        }
        // Timer-based mode 1 is implemented. Interrupt/event-driven retuning
        // modes require a separate native service; SDR12/25 need no tuning.
        let timer_mode = self.extended_capabilities & (3 << 14) == 0
            && self
                .retune_interval()
                .is_none_or(|us| self.clock.check_duration(us).is_ok());
        SdUhsModes {
            sdr12: true,
            sdr25: true,
            sdr50: self.extended_capabilities & (CAP_SDR50 | CAP_SDR104) != 0
                && (timer_mode || self.extended_capabilities & CAP_SDR50_TUNING == 0),
            sdr104: self.extended_capabilities & CAP_SDR104 != 0 && timer_mode,
        }
    }

    pub(super) fn switch_signal_voltage(&mut self) -> Result<(), BlockError> {
        if !self.uhs_modes().available() || self.signal_voltage != SignalVoltage::V3_3 {
            return Err(BlockError::Unsupported(
                "SDHCI profile has no qualified SD voltage transition",
            ));
        }
        let result = (|| {
            self.healthy()?;
            self.check_card()?;
            // CMD11's R1 has completed. The card must actually pull every DAT
            // line low before its clock stops; one low pin is insufficient.
            self.clock.delay(1_000);
            if self.registers.read32(PRESENT) & DATA_LINES != 0 {
                return Err(BlockError::Unsupported("SD CMD11 did not pull DAT low"));
            }
            let clock = self.registers.read16(CLOCK);
            if clock & (CLOCK_INTERNAL | CLOCK_CARD | CLOCK_STABLE)
                != CLOCK_INTERNAL | CLOCK_CARD | CLOCK_STABLE
            {
                return Err(BlockError::Unsupported(
                    "SDHCI voltage switch needs a stable clock",
                ));
            }
            self.registers.write16(CLOCK, clock & !CLOCK_CARD);
            if self.registers.read16(CLOCK) & CLOCK_CARD != 0 {
                return Err(BlockError::Unsupported("SDHCI card clock did not stop"));
            }
            let control = self.registers.read16(HOST_CONTROL2);
            if control & SIGNAL_180 != 0 {
                return Err(BlockError::Unsupported(
                    "SDHCI CMD11 started with unexpected 1.8-V signaling",
                ));
            }
            self.registers.write16(HOST_CONTROL2, control | SIGNAL_180);
            // mmc_host_set_uhs_voltage keeps the clock gated for 10 ms,
            // retaining Linux's margin over the architectural 5-ms minimum.
            // Card VCC stays at its original 3.3/3.0-V supply.
            self.clock.delay(match self.profile {
                Profile::Gli9750 | Profile::Gli9755 => 110_000,
                Profile::Gli9767 => 15_000,
                _ => 10_000,
            });
            self.check_card()?;
            if self.registers.read16(HOST_CONTROL2) & SIGNAL_180 == 0 {
                return Err(BlockError::Unsupported(
                    "SDHCI 1.8-V signaling did not acknowledge",
                ));
            }
            self.registers.write16(CLOCK, clock);
            self.clock.delay(1_000);
            self.check_card()?;
            if self.registers.read16(CLOCK) & (CLOCK_CARD | CLOCK_STABLE)
                != CLOCK_CARD | CLOCK_STABLE
                || self.registers.read32(PRESENT) & DATA_LINES != DATA_LINES
            {
                return Err(BlockError::Unsupported(
                    "SD 1.8-V transition did not release DAT",
                ));
            }
            self.signal_voltage = SignalVoltage::V1_8;
            Ok(())
        })();
        result.map_err(|error| self.uhs_failure(error))
    }

    pub(super) fn set_uhs_timing(&mut self, timing: Timing) -> Result<(), BlockError> {
        let modes = self.uhs_modes();
        let mode = match timing {
            Timing::Sdr12 if modes.sdr12 => 0,
            Timing::Sdr25 if modes.sdr25 => 1,
            Timing::Sdr50 if modes.sdr50 => 2,
            Timing::Sdr104 if modes.sdr104 => 3,
            _ => return Err(BlockError::Unsupported("SDHCI unsupported UHS timing")),
        };
        let result = (|| {
            self.check_card()?;
            let control = self.registers.read16(HOST_CONTROL2);
            if self.signal_voltage != SignalVoltage::V1_8 || control & SIGNAL_180 == 0 {
                return Err(BlockError::Unsupported(
                    "SDHCI UHS requires actual 1.8-V signaling",
                ));
            }
            let clock = self.registers.read16(CLOCK);
            self.registers.write16(CLOCK, clock & !CLOCK_CARD);
            if self.registers.read16(CLOCK) & CLOCK_CARD != 0 {
                return Err(BlockError::Unsupported("SDHCI UHS clock did not stop"));
            }
            let host = self.registers.read8(HOST_CONTROL) & !HIGH_SPEED;
            let host = host
                | if timing == Timing::Sdr12 {
                    0
                } else {
                    HIGH_SPEED
                };
            self.registers.write8(HOST_CONTROL, host);
            if self.registers.read8(HOST_CONTROL) & HIGH_SPEED != host & HIGH_SPEED {
                return Err(BlockError::Unsupported(
                    "SDHCI UHS high-speed control did not acknowledge",
                ));
            }
            let next = (control & !(UHS_MODE | EXECUTE_TUNING | TUNED_CLOCK)) | mode;
            self.registers.write16(HOST_CONTROL2, next);
            if self.registers.read16(HOST_CONTROL2) & (UHS_MODE | SIGNAL_180) != mode | SIGNAL_180 {
                return Err(BlockError::Unsupported(
                    "SDHCI UHS timing did not acknowledge",
                ));
            }
            self.registers.write16(CLOCK, clock);
            self.sd_timing = timing;
            self.tuned_at = None;
            Ok(())
        })();
        result.map_err(|error| self.uhs_failure(error))
    }

    fn needs_tuning(&self) -> bool {
        self.sd_timing == Timing::MmcHs200
            || self.sd_timing == Timing::Sdr104
            || self.sd_timing == Timing::Sdr50 && self.extended_capabilities & CAP_SDR50_TUNING != 0
    }

    pub(super) fn retune_interval(&self) -> Option<u64> {
        let count = (self.extended_capabilities >> 8) & 15;
        (count != 0).then(|| (1u64 << (count - 1)) * 1_000_000)
    }

    pub(super) fn retune_if_needed(&mut self) -> Result<(), BlockError> {
        if !self.needs_tuning() {
            return Ok(());
        }
        let expired = self.tuned_at.is_none_or(|at| {
            self.retune_interval().is_some_and(|period| {
                self.clock
                    .try_elapsed_us(at)
                    .map_or(true, |elapsed| elapsed >= period)
            })
        });
        if expired {
            self.tune()?;
        }
        Ok(())
    }

    pub(super) fn tune(&mut self) -> Result<(), BlockError> {
        self.check_authority()?;
        if !self.needs_tuning() {
            return Ok(());
        }
        if self.profile == Profile::Gli9750 {
            return self.gli_tune();
        }
        let saved_enable = self.registers.read32(INTERRUPT_ENABLE);
        let result = (|| {
            self.healthy()?;
            self.check_card()?;
            if self.signal_voltage != SignalVoltage::V1_8
                || self.registers.read16(HOST_CONTROL2) & SIGNAL_180 == 0
            {
                return Err(BlockError::Unsupported(
                    "SDHCI tuning requires actual 1.8-V signaling",
                ));
            }
            let control = self.registers.read16(HOST_CONTROL2);
            self.registers
                .write16(HOST_CONTROL2, (control & !TUNED_CLOCK) | EXECUTE_TUNING);
            if self.registers.read16(HOST_CONTROL2) & (EXECUTE_TUNING | TUNED_CLOCK)
                != EXECUTE_TUNING
            {
                return Err(BlockError::Unsupported(
                    "SDHCI execute tuning did not acknowledge",
                ));
            }
            // The controller consumes the tuning pattern itself. Its Buffer
            // Read Ready indication completes one iteration; it produces no
            // ordinary FIFO payload or Transfer Complete to consume.
            self.registers.write32(
                INTERRUPT_ENABLE,
                READ_READY | ERROR | CARD_INSERT | CARD_REMOVE,
            );
            for _ in 0..40 {
                self.tuning_command()?;
                // The standard Linux SD CMD19 path uses a 1-ms inter-cycle
                // delay even though the architectural specification permits 0.
                if self.sd_timing != Timing::MmcHs200 {
                    self.clock.delay(1_000);
                }
                let control = self.registers.read16(HOST_CONTROL2);
                if control & EXECUTE_TUNING == 0 {
                    if control & TUNED_CLOCK == 0 {
                        return Err(BlockError::Unsupported(
                            "SDHCI tuning found no valid sampling clock",
                        ));
                    }
                    self.tuned_at = Some(self.clock.try_start().map_err(|_| {
                        BlockError::Unsupported("SDHCI tuning clock admission lost")
                    })?);
                    return Ok(());
                }
            }
            Err(BlockError::Unsupported(
                "SDHCI tuning did not finish in 40 iterations",
            ))
        })();
        if !self.uhs_failed {
            self.registers.write32(INTERRUPT_ENABLE, saved_enable);
        }
        result.map_err(|error| self.uhs_failure(error))
    }

    pub(super) fn tuning_command(&mut self) -> Result<(), BlockError> {
        self.check_card()?;
        let deadline = self.clock.deadline(50_000);
        while self.registers.read32(PRESENT) & (INHIBIT_COMMAND | INHIBIT_DATA) != 0 {
            self.check_card()?;
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            core::hint::spin_loop();
        }
        self.clear_command_status()?;
        let mmc = self.sd_timing == Timing::MmcHs200;
        let bytes = if mmc && self.registers.read8(HOST_CONTROL) & BUS8 != 0 {
            128
        } else {
            64
        };
        self.registers.write16(BLOCK_SIZE, bytes);
        self.registers.write16(BLOCK_COUNT, 1);
        self.registers.write16(TRANSFER_MODE, READ);
        self.registers.write32(ARGUMENT, 0);
        fence(Ordering::Release);
        let opcode = if mmc { 21 } else { SD_SEND_TUNING.number() };
        self.registers
            .write16(COMMAND, u16::from(opcode) << 8 | 0x3a);
        self.wait_interrupt(READ_READY, 50_000)?;
        self.registers.write32(INTERRUPT, READ_READY);
        self.check_card()
    }

    pub(super) fn uhs_failure(&mut self, primary: BlockError) -> BlockError {
        if self.uhs_failed {
            // A permanent electrical/authority fence already retained its
            // cleanup result. Unwinding must neither retry nor touch its BARs.
            return primary;
        }
        // Failed CMD11/tuning cannot resume on a card left at an unknown signal
        // state. Fence every alias, stop clocks, remove VCC and retire commands.
        self.medium = None;
        self.tuned_at = None;
        self.registers.write16(CLOCK, 0);
        let control = self.registers.read16(HOST_CONTROL2);
        self.registers
            .write16(HOST_CONTROL2, control & !(EXECUTE_TUNING | TUNED_CLOCK));
        let restoration = self
            .power_off()
            .and_then(|()| {
                if self.registers.read8(POWER) & POWER_ON == 0 {
                    self.clock.delay(1_000);
                    Ok(())
                } else {
                    Err(BlockError::Unsupported(
                        "SDHCI failed UHS power-off did not acknowledge",
                    ))
                }
            })
            .err();
        self.uhs_failed = false;
        let primary = self.retire_error(primary);
        if restoration.is_some() {
            self.fault = Some(primary.clone());
        }
        if let Some(failure) = &mut self.last_failure {
            failure.restoration = restoration;
            failure.quarantined |= self.fault.is_some();
        }
        self.uhs_failed = true;
        primary
    }
}

#[cfg(test)]
mod tests;
