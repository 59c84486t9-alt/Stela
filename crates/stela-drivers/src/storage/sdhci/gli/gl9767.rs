// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of Linux sdhci-pci-gli.c, Copyright 2019 Genesys Logic,
// Inc.; author Ben Chuang. See ../../THIRD_PARTY.md.
//! GL9767 protected PCI and ordinary SD/UHS-I hardware operations.
use super::*;
use gl9755::ClockFailure;

const ID: u32 = 0x9767_17a0;
const VHS: u16 = 0x884;
const PLL: u16 = 0x938;
const SSC: u16 = 0x93c;
const DIRECT: u32 = 1 << 16;
const SPREAD: u32 = 1 << 19;
const HOST_OPERATION: usize = 0x508;

fn update(c: &mut dyn ConfigSpace, at: u16, mask: u32, bits: u32) -> Result<(), BlockError> {
    if c.read32(0) != ID {
        return Err(BlockError::Unsupported("GL9767 original PCI identity lost"));
    }
    let old = c.read32(at);
    if old == u32::MAX {
        return Err(BlockError::Unsupported(
            "GL9767 PCI register is unavailable",
        ));
    }
    c.write32(at, (old & !mask) | bits);
    let value = c.read32(at);
    if value == u32::MAX || value & mask != bits {
        return Err(BlockError::Unsupported(
            "GL9767 PCI write did not acknowledge",
        ));
    }
    Ok(())
}
fn unlocked<T>(
    c: &mut dyn ConfigSpace,
    operation: impl FnOnce(&mut dyn ConfigSpace) -> Result<T, BlockError>,
) -> Result<T, BlockError> {
    super::unlocked_with(c, update, (VHS, 15 << 16, 2 << 16), operation)
}
fn mmio(r: &mut dyn Registers, at: usize, mask: u32, bits: u32) -> Result<(), BlockError> {
    let old = r.read32(at);
    if old == u32::MAX {
        return Err(BlockError::Unsupported("GL9767 MMIO is unavailable"));
    }
    r.write32(at, (old & !mask) | bits);
    let actual = r.read32(at);
    if actual == u32::MAX || actual & mask != bits {
        return Err(BlockError::Unsupported("GL9767 MMIO did not acknowledge"));
    }
    Ok(())
}

pub(in crate::storage::sdhci) fn card_event(r: &mut dyn Registers) -> Result<(), BlockError> {
    let present = r.read32(PRESENT) & CARD_PRESENT != 0;
    let (debounce, scale) = if present { (5, 2) } else { (63, 3) };
    mmio(r, HOST_OPERATION, 0xff << 16, debounce << 16 | scale << 22)
}
pub(in crate::storage::sdhci) fn after_reset(r: &mut dyn Registers) -> Result<(), BlockError> {
    mmio(r, 0x510, 1 << 8, 0)?;
    mmio(r, HOST_OPERATION, 1, 0)?;
    card_event(r)
}
fn pci_reset(c: &mut dyn ConfigSpace, clock: Clock) -> Result<(), BlockError> {
    unlocked(c, |c| {
        let old = c.read32(0x8e4);
        if old == u32::MAX {
            return Err(BlockError::Unsupported("GL9767 reset register unavailable"));
        }
        // Reset completion is asynchronous: do not require immediate equality.
        c.write32(0x8e4, old & !1);
        for _ in 0..5 {
            clock.delay(1);
            let value = c.read32(0x8e4);
            if value != u32::MAX && value & 1 == 0 {
                return Ok(());
            }
        }
        Err(BlockError::Timeout)
    })
}
pub(in crate::storage::sdhci) fn before_reset(
    r: &mut dyn Registers,
    clock: Clock,
    mask: u8,
) -> Result<(), ClockFailure> {
    r.check_authority().map_err(ClockFailure::Authority)?;
    gl9755::before_reset(r, clock, mask)?;
    if mask & RESET_ALL != 0 {
        let reset = pci_reset(r.configuration().map_err(ClockFailure::Authority)?, clock);
        r.check_authority().map_err(ClockFailure::Authority)?;
        reset?;
    }
    Ok(())
}
pub(super) fn initialize<C: ConfigSpace>(
    f: &mut Function<C>,
    r: &mut dyn Registers,
    clock: Clock,
) -> Result<(), BlockError> {
    validate_clock(clock)?;
    if f.config().read32(0) != ID {
        return Err(BlockError::Unsupported("GL9767 owned PCI identity changed"));
    }
    let mode = f.config().read32(0x940);
    if mode == u32::MAX || mode & 3 != 0 {
        return Err(BlockError::Unsupported(
            "GL9767 active SD Express requires its PCIe child owner",
        ));
    }
    pci::runtime_configuration(f, false)?;
    gl9755::before_reset(r, clock, RESET_ALL)?;
    pci_reset(f.config(), clock)?;
    pci::runtime_configuration(f, false)?;
    r.write8(RESET, RESET_ALL);
    if !clock.wait(RESET_US, || r.read8(RESET) & RESET_ALL == 0) {
        return Err(BlockError::Timeout);
    }
    after_reset(r)?;
    unlocked(f.config(), |c| {
        update(c, 0x8d0, 15 | 15 << 12 | 3 << 28, 15 | 7 << 12 | 3 << 28)?;
        update(
            c,
            0x8e0,
            3 << 16 | 1 << 30 | 3 << 6 | 3 << 9 | 1 << 21,
            3 << 6 | 3 << 9 | 1 << 21,
        )?;
        // The unchanged donor ORs these vendor defaults rather
        // than replacing every field; preserve preexisting PHY bits.
        let first = c.read32(0x90c);
        let second = c.read32(0x948);
        let control = c.read32(0x95c);
        let zero_cross = c.read32(0x964);
        if [first, second, control, zero_cross].contains(&u32::MAX) {
            return Err(BlockError::Unsupported("GL9767 PHY is unavailable"));
        }
        update(c, 0x90c, 3 << 29, 3 << 29)?;
        c.write32(0x948, second); // Source zero-valued OR still performs this store.
        if c.read32(0x948) != second {
            return Err(BlockError::Unsupported(
                "GL9767 PHY SSC did not acknowledge",
            ));
        }
        let bits = 1 << 5 | 1 << 6 | 3 << 7 | 15 << 11 | 1 << 25;
        update(c, 0x95c, bits, bits)?;
        update(c, 0x964, 0xb | 1 << 6, 0xb | 1 << 6)
    })
}

pub(in crate::storage::sdhci) fn set_clock(
    r: &mut dyn Registers,
    timer: Clock,
    version: u8,
    base: u32,
    timing: Timing,
    requested: u32,
) -> Result<u32, ClockFailure> {
    unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
        update(c, 0x8a0, 1 << 12, 1 << 12)
    })?;
    let result = (|| {
        unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
            update(c, PLL, DIRECT | SPREAD, 0)
        })?;
        r.write16(CLOCK, 0);
        if r.read16(CLOCK) & CLOCK_CARD != 0 {
            return Err(BlockError::Unsupported("GL9767 card clock did not stop").into());
        }
        if requested == 0 {
            return Ok(0);
        }
        let hz = requested.min(base);
        let (divisor, mut actual) = clock_divisor(version, base, hz)?;
        if hz == 200_000_000 && timing == Timing::Sdr104 && requested >= 205_000_000 {
            let enable = unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
                let value = c.read32(0x888);
                if value == u32::MAX {
                    return Err(BlockError::Unsupported("GL9767 SSC mailbox unavailable"));
                }
                Ok(value & 2 != 0)
            })?;
            unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
                update(c, SSC, 0xffff_0000, 0xf5c3_0000)?;
                update(
                    c,
                    PLL,
                    31 << 24 | SPREAD,
                    31 << 24 | if enable { SPREAD } else { 0 },
                )
            })?;
            unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
                update(c, PLL, 0xf3ff | DIRECT, 0x246 | DIRECT)
            })?;
            timer.delay(1_000);
            actual = 205_000_000;
        }
        let field = (divisor & 0xff) << 8 | (divisor & 0x300) >> 2;
        enable_clock(r, timer, version, field)?;
        if r.read16(CLOCK) & CLOCK_CARD == 0 || actual > requested {
            return Err(BlockError::Unsupported("GL9767 card clock did not acknowledge").into());
        }
        Ok(actual)
    })();
    // A lost PCI epoch forbids all further accesses, including window cleanup.
    if matches!(&result, Err(ClockFailure::Authority(_))) {
        return result;
    }
    let restore = unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
        update(c, 0x8a0, 1 << 12, 0)
    });
    match result {
        Ok(actual) => restore.map(|()| actual).map_err(Into::into),
        Err(error) => Err(error),
    }
}

pub(in crate::storage::sdhci) fn set_power(
    r: &mut dyn Registers,
    vdd1: u8,
) -> Result<(), ClockFailure> {
    unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
        update(c, 0x944, 1 << 5 | 1 << 8, 0)
    })?;
    let events = r.read32(INTERRUPT_ENABLE) & !BUS_POWER;
    r.write32(SIGNAL_ENABLE, 0);
    r.write32(INTERRUPT_ENABLE, events);
    r.write8(POWER, 0);
    if r.read8(POWER) != 0 {
        return Err(BlockError::Unsupported("GL9767 power-off did not acknowledge").into());
    }
    if vdd1 != 0 {
        r.write8(POWER, vdd1 | POWER_ON);
        if r.read8(POWER) != vdd1 | POWER_ON {
            return Err(BlockError::Unsupported("GL9767 VDD1 did not acknowledge").into());
        }
    }
    // This donor reenables OCP observation even for ordinary POWER_OFF.
    r.write32(INTERRUPT_ENABLE, events | BUS_POWER);
    if r.read32(SIGNAL_ENABLE) != 0 || r.read32(INTERRUPT_ENABLE) & BUS_POWER == 0 {
        return Err(
            BlockError::Unsupported("GL9767 power-event polling did not acknowledge").into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
