// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of Linux sdhci-pci-gli.c, Copyright 2019 Genesys Logic,
// Inc.; author Ben Chuang. See ../../THIRD_PARTY.md.
//! GL9750 protected PHY, direct PLL clocks and two-polarity hardware tuning.
use super::*;
pub(super) mod dma;
pub(super) mod gl9755;
pub(super) mod gl9763e;
pub(super) mod gl9767;
mod pci;
#[cfg(test)]
mod tests;

const WT: usize = 0x800;
const CFG2: usize = 0x848;
const DRIVING: usize = 0x860;
const PLL: usize = 0x864;
const SSC: usize = 0x86c;
const SW: usize = 0x874;
const MISC: usize = 0x878;
const BURST: usize = 0x510;
const TUNING: usize = 0x540;
const PARAMETERS: usize = 0x544;
const DIRECT: u32 = 1 << 15;
const SSC_ENABLE: u32 = 1 << 31;

fn update(r: &mut dyn Registers, at: usize, mask: u32, bits: u32) -> Result<(), BlockError> {
    let previous = r.read32(at);
    if previous == u32::MAX {
        return Err(BlockError::Unsupported("GL9750 register is unavailable"));
    }
    r.write32(at, (previous & !mask) | bits);
    let actual = r.read32(at);
    if actual == u32::MAX || actual & mask != bits {
        return Err(BlockError::Unsupported(
            "GL9750 protected register did not acknowledge",
        ));
    }
    Ok(())
}
fn unlocked(
    r: &mut dyn Registers,
    operation: impl FnOnce(&mut dyn Registers) -> Result<(), BlockError>,
) -> Result<(), BlockError> {
    let result = update(r, WT, 1, 1).and_then(|()| operation(r));
    // An uncertain protected operation still closes the original write window.
    let close = update(r, WT, 1, 0);
    result.and(close)
}

pub(super) fn initialize(r: &mut dyn Registers) -> Result<(), BlockError> {
    unlocked(r, |r| {
        update(r, BURST, 3 << 16, 0)?;
        update(r, DRIVING, 0xff00_0fff, 0x8c00_0fff)?;
        update(r, SW, 3 << 6, 3 << 6)?;
        update(r, PLL, 15 << 20, 1 << 23)?;
        update(r, MISC, 0x7c, 5 << 4)?;
        let control = r.read16(HOST_CONTROL2) & !TUNED_CLOCK;
        r.write16(HOST_CONTROL2, control);
        if r.read16(HOST_CONTROL2) & TUNED_CLOCK != 0 {
            return Err(BlockError::Unsupported("GL9750 tuned clock did not clear"));
        }
        update(
            r,
            TUNING,
            1 << 16 | 3 << 19 | 1 << 4,
            1 << 16 | 2 << 19 | 1 << 4,
        )?;
        update(r, PARAMETERS, 7, 1)?;
        update(r, TUNING, 1 << 4, 0)?;
        let control = r.read16(HOST_CONTROL2) & !TUNED_CLOCK;
        r.write16(HOST_CONTROL2, control);
        Ok(())
    })
}

pub(super) fn set_clock(
    r: &mut dyn Registers,
    timer: Clock,
    version: u8,
    base: u32,
    timing: Timing,
    requested: u32,
) -> Result<u32, BlockError> {
    unlocked(r, |r| update(r, PLL, DIRECT | SSC_ENABLE, 0))?;
    r.write16(CLOCK, 0);
    if r.read16(CLOCK) & CLOCK_CARD != 0 {
        return Err(BlockError::Unsupported("GL9750 clock did not stop"));
    }
    if requested == 0 {
        return Ok(0);
    }
    // The common MMC core clamps the requested frequency to the host base
    // clock before invoking this donor's clock hook.
    let hz = requested.min(base);
    let (divisor, mut actual) = clock_divisor(version, base, hz)?;
    let settings = match (hz, timing) {
        (200_000_000, Timing::Sdr104) if requested >= 205_000_000 => {
            actual = 205_000_000;
            Some((15, 0x5a1d, 0x246, 0))
        }
        (100_000_000, _) => Some((14, 0x51ec, 0x244, 1)),
        (50_000_000, _) => Some((14, 0x51ec, 0x244, 3)),
        _ => None,
    };
    if let Some((step, ppm, ldiv, pdiv)) = settings {
        let enable = unlocked_read(r, MISC)? & (1 << 26) == 0;
        unlocked(r, |r| {
            update(r, SSC, 0xffff_0000, ppm << 16)?;
            update(
                r,
                PLL,
                31 << 24 | SSC_ENABLE,
                step << 24 | if enable { SSC_ENABLE } else { 0 },
            )
        })?;
        unlocked(r, |r| {
            update(r, PLL, 0x73ff | DIRECT, ldiv | pdiv << 12 | DIRECT)
        })?;
        timer.delay(1_000);
    }
    let field = (divisor & 0xff) << 8 | (divisor & 0x300) >> 2;
    enable_clock(r, timer, version, field)?;
    if r.read16(CLOCK) & CLOCK_CARD == 0 || actual > requested {
        return Err(BlockError::Unsupported(
            "GL9750 card clock was not acknowledged",
        ));
    }
    Ok(actual)
}
fn unlocked_read(r: &mut dyn Registers, at: usize) -> Result<u32, BlockError> {
    let mut value = 0;
    unlocked(r, |r| {
        value = r.read32(at);
        if value == u32::MAX {
            return Err(BlockError::Unsupported("GL9750 register is unavailable"));
        }
        Ok(())
    })?;
    Ok(value)
}

impl Engine {
    pub(super) fn gli_tune(&mut self) -> Result<(), BlockError> {
        let saved = self.registers.read32(INTERRUPT_ENABLE);
        let mut phase_retirement = None;
        let mut phase_timeout = false;
        let result = (|| {
            self.healthy()?;
            self.check_card()?;
            if self.signal_voltage != SignalVoltage::V1_8
                || self.registers.read16(HOST_CONTROL2) & SIGNAL_180 == 0
            {
                return Err(BlockError::Unsupported(
                    "GL9750 tuning requires actual 1.8-V signaling",
                ));
            }
            initialize(self.registers.as_mut())?;
            for invert in [false, true] {
                phase_timeout = false;
                unlocked(self.registers.as_mut(), |r| {
                    update(r, MISC, 1 << 3, if invert { 1 << 3 } else { 0 })
                })?;
                let control = self.registers.read16(HOST_CONTROL2);
                self.registers
                    .write16(HOST_CONTROL2, (control & !TUNED_CLOCK) | EXECUTE_TUNING);
                if self.registers.read16(HOST_CONTROL2) & (EXECUTE_TUNING | TUNED_CLOCK)
                    != EXECUTE_TUNING
                {
                    return Err(BlockError::Unsupported(
                        "GL9750 execute tuning did not acknowledge",
                    ));
                }
                self.registers.write32(
                    INTERRUPT_ENABLE,
                    READ_READY | ERROR | CARD_INSERT | CARD_REMOVE,
                );
                for _ in 0..40 {
                    match self.tuning_command() {
                        Ok(()) => {}
                        Err(BlockError::Timeout) => {
                            phase_timeout = true;
                            // Before trying another RX polarity, retire the old
                            // controller transfer and the card's tuning task.
                            let control = self.registers.read16(HOST_CONTROL2)
                                & !(EXECUTE_TUNING | TUNED_CLOCK);
                            self.registers.write16(HOST_CONTROL2, control);
                            if let Err(error) = self.reset(RESET_COMMAND | RESET_DATA) {
                                phase_retirement = Some(error);
                                return Err(BlockError::Timeout);
                            }
                            if let Err(error) = self.execute(
                                command::STOP_TRANSMISSION,
                                0,
                                command::Response::Busy,
                                None,
                            ) {
                                phase_retirement = Some(error);
                                return Err(BlockError::Timeout);
                            }
                            break;
                        }
                        Err(error) => return Err(error),
                    }
                    let control = self.registers.read16(HOST_CONTROL2);
                    if control & EXECUTE_TUNING == 0 {
                        if control & TUNED_CLOCK != 0 {
                            self.tuned_at = Some(self.clock.try_start().map_err(|_| {
                                BlockError::Unsupported("GL9750 tuning clock admission lost")
                            })?);
                            return Ok(());
                        }
                        break;
                    }
                }
                let control =
                    self.registers.read16(HOST_CONTROL2) & !(EXECUTE_TUNING | TUNED_CLOCK);
                self.registers.write16(HOST_CONTROL2, control);
            }
            if phase_timeout {
                Err(BlockError::Timeout)
            } else {
                Err(BlockError::Unsupported(
                    "GL9750 both sampling polarities failed tuning",
                ))
            }
        })();
        self.registers.write32(INTERRUPT_ENABLE, saved);
        result.map_err(|error| {
            let primary = self.uhs_failure(error);
            if let Some(retirement) = phase_retirement
                && let Some(failure) = &mut self.last_failure
            {
                failure.retirement.get_or_insert(retirement);
            }
            primary
        })
    }
}

pub(super) fn attach(
    mut function: Function,
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
) -> Result<Attached, BlockError> {
    validate_clock(handoff.clock)?;
    let profile = Profile::select(function.vendor, function.device);
    let mut mappings = prepare_slots(&mut function, handoff, profile)?;
    let registers = mappings
        .pop()
        .ok_or(BlockError::Unsupported("GL9750 slot mapping absent"))?;
    let location = format!("{} GL{:04x} SD slot", function.address, function.device);
    let registers = pci::prepare(function, registers, handoff.clock)?;
    let mut host = Host::new(Box::new(registers), handoff.clock, location, dma, profile)?;
    let (cards, failures) = match host.poll() {
        Ok(Some(card)) => (alloc::vec![card], Vec::new()),
        Ok(None) => (Vec::new(), Vec::new()),
        Err(error) => (Vec::new(), alloc::vec![(0, error)]),
    };
    Ok(Attached {
        hosts: alloc::vec![host],
        cards,
        failures,
    })
}
