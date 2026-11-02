// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of Linux sdhci-pci-gli.c, Copyright 2019 Genesys Logic,
// Inc.; author Ben Chuang. See ../../THIRD_PARTY.md.
//! GL9755 PCI PHY/PLL and ordinary SD/UHS-I dual-rail power operation.
use super::*;

const ID: u32 = 0x9755_17a0;
const PLL: u16 = 0x64;
const SSC: u16 = 0x68;
const VDD2: u8 = 0xb0; // 1.8-V selection plus VDD2 power-on.

fn update(c: &mut dyn ConfigSpace, at: u16, mask: u32, bits: u32) -> Result<(), BlockError> {
    let old = c.read32(at)?;
    if old == u32::MAX {
        return Err(BlockError::Unsupported(
            "GL9755 PCI register is unavailable",
        ));
    }
    c.write32(at, (old & !mask) | bits)?;
    let actual = c.read32(at)?;
    if actual == u32::MAX || actual & mask != bits {
        return Err(BlockError::Unsupported(
            "GL9755 protected PCI write did not acknowledge",
        ));
    }
    Ok(())
}
fn unlocked<T>(
    c: &mut dyn ConfigSpace,
    operation: impl FnOnce(&mut dyn ConfigSpace) -> Result<T, BlockError>,
) -> Result<T, BlockError> {
    super::unlocked_with(c, update, (0x800, 1, 1), operation)
}

pub(in crate::sdhci) fn before_reset(
    r: &mut dyn Registers,
    clock: Clock,
    mask: u8,
) -> Result<(), BlockError> {
    if r.read16(HOST_CONTROL2) & (1 << 8) != 0 {
        return Err(BlockError::Unsupported(
            "GL9755 active UHS-II transport requires its native owner",
        ));
    }
    if mask & RESET_ALL != 0 {
        r.write16(CLOCK, CLOCK_INTERNAL);
        if !clock.wait(20_000, || r.read16(CLOCK) & CLOCK_STABLE != 0) {
            return Err(BlockError::Timeout);
        }
        r.write16(HOST_CONTROL2, 1 << 12);
        if r.read16(HOST_CONTROL2) != 1 << 12 {
            return Err(BlockError::Unsupported(
                "GL9755 reset v4 mode did not acknowledge",
            ));
        }
    }
    Ok(())
}

pub(super) fn initialize<C: ConfigSpace>(
    f: &mut Function<C>,
    r: &mut dyn Registers,
    clock: Clock,
    minimum: &dyn crate::bus::pci::power::Timer,
) -> Result<(), BlockError> {
    minimum.check().map_err(BlockError::PciPower)?;
    validate_clock(clock)?;
    if f.config().read32(0)? != ID {
        return Err(BlockError::Unsupported("GL9755 owned PCI identity changed"));
    }
    let pm = crate::pci::capability(f.config(), 1)?.ok_or(BlockError::Unsupported(
        "GL9755 requires PCI power management",
    ))?;
    let aer = pci::find_aer(f.config())?;
    before_reset(r, clock, RESET_ALL)?;
    r.write8(RESET, RESET_ALL);
    if !clock.wait(RESET_US, || r.read8(RESET) & RESET_ALL == 0) {
        return Err(BlockError::Timeout);
    }
    update(f.config(), 0x800, 1, 1)?;
    let result = (|| {
        // Preserve firmware CD/WP polarity; no invented board properties.
        update(f.config(), 0x44, 7 << 12 | 1 << 29, 0)?;
        update(f.config(), 0x70, 1 << 19, 0)?;
        update(f.config(), 0x48, 31 << 24, 31 << 24)?;
        let mut bars = [0u32; 6];
        for (i, saved) in bars.iter_mut().enumerate() {
            *saved = f.config().read32(0x10 + i as u16 * 4)?;
        }
        let control = f.config().read16(pm + 4)?;
        if control == u16::MAX || control & 3 != 0 {
            return Err(BlockError::Unsupported(
                "GL9755 power cycle requires actual D0",
            ));
        }
        set_pio_command(f, false)?;
        f.config().write16(pm + 4, (control & !0x8003) | 3)?;
        minimum.wait_us(10_000).map_err(BlockError::PciPower)?;
        if f.config().read16(pm + 4)? & 3 != 3 {
            return Err(BlockError::Unsupported("GL9755 D3hot did not acknowledge"));
        }
        f.config().write16(pm + 4, control & !0x8003)?;
        minimum.wait_us(10_000).map_err(BlockError::PciPower)?;
        if f.config().read16(pm + 4)? & 3 != 0
            || f.config().read32(0)? != ID
            || crate::pci::capability(f.config(), 1)? != Some(pm)
            || pci::find_aer(f.config())? != aer
        {
            return Err(BlockError::Unsupported(
                "GL9755 PCI power/identity epoch changed",
            ));
        }
        quiesce_pio(f)?;
        for (i, value) in bars.into_iter().enumerate() {
            let at = 0x10 + i as u16 * 4;
            f.config().write32(at, value)?;
            if f.config().read32(at)? != value {
                return Err(BlockError::Unsupported(
                    "GL9755 BAR restoration did not acknowledge",
                ));
            }
        }
        set_pio_command(f, true)?;
        if let Some(aer) = aer {
            update(f.config(), aer + 0x14, 1 << 12, 1 << 12)?;
        }
        Ok(())
    })();
    // The donor holds the same window through D3/D0 and AER. Close it only
    // while the original configuration-space identity is accessible in D0.

    if matches!(
        &result,
        Err(BlockError::Config(_)
            | BlockError::PciPower(_)
            | BlockError::PciCapability(crate::bus::pci::CapabilityError::Config { .. }))
    ) {
        return result;
    }
    let close = (|| {
        if f.config().read32(0)? == ID && f.config().read16(pm + 4)? & 3 == 0 {
            update(f.config(), 0x800, 1, 0)
        } else {
            Err(BlockError::Unsupported(
                "GL9755 write window remains inaccessible",
            ))
        }
    })();
    result.and(close)?;
    unlocked(f.config(), |c| {
        update(c, 0x70, 0xff00_00ff, 0xfc00_00b3)?;
        update(c, 0x6c, 3 << 8 | 1 << 18 | 1 << 27, 1 << 18 | 1 << 27)?;
        update(
            c,
            SSC,
            1 << 24 | 1 << 27 | 15 << 28,
            1 << 24 | 1 << 27 | 3 << 30,
        )
    })
}

#[derive(Debug)]
pub(in crate::sdhci) enum ClockFailure {
    Authority(BlockError),
    Hardware(BlockError),
}
impl From<BlockError> for ClockFailure {
    fn from(error: BlockError) -> Self {
        if matches!(
            error,
            BlockError::Config(_)
                | BlockError::PciPower(_)
                | BlockError::PciCapability(crate::bus::pci::CapabilityError::Config { .. })
        ) {
            Self::Authority(error)
        } else {
            Self::Hardware(error)
        }
    }
}

pub(in crate::sdhci) fn set_clock(
    r: &mut dyn Registers,
    timer: Clock,
    version: u8,
    base: u32,
    timing: Timing,
    requested: u32,
    minimum: &dyn crate::bus::pci::power::Timer,
) -> Result<u32, ClockFailure> {
    minimum.check().map_err(BlockError::PciPower)?;
    unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
        update(c, PLL, DIRECT | SSC_ENABLE, 0)
    })?;
    r.write16(CLOCK, 0);
    if r.read16(CLOCK) & CLOCK_CARD != 0 {
        return Err(BlockError::Unsupported("GL9755 card clock did not stop").into());
    }
    if requested == 0 {
        return Ok(0);
    }
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
        let enable = unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
            let misc = c.read32(0x78)?;
            if misc == u32::MAX {
                return Err(BlockError::Unsupported("GL9755 SSC policy unavailable"));
            }
            Ok(misc & (1 << 26) == 0)
        })?;
        unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
            update(c, SSC, 0xffff, ppm)?;
            update(
                c,
                PLL,
                31 << 24 | SSC_ENABLE,
                step << 24 | if enable { SSC_ENABLE } else { 0 },
            )
        })?;
        unlocked(r.configuration().map_err(ClockFailure::Authority)?, |c| {
            update(c, PLL, 0x73ff | DIRECT, ldiv | pdiv << 12 | DIRECT)
        })?;
        minimum.wait_us(1_000).map_err(BlockError::PciPower)?;
    }
    let field = (divisor & 0xff) << 8 | (divisor & 0x300) >> 2;
    enable_clock(r, timer, version, field)?;
    if r.read16(CLOCK) & CLOCK_CARD == 0 || actual > requested {
        return Err(BlockError::Unsupported("GL9755 card clock did not acknowledge").into());
    }
    Ok(actual)
}

pub(in crate::sdhci) fn set_power(
    r: &mut dyn Registers,
    minimum: &dyn crate::bus::pci::power::Timer,
    vdd1: u8,
) -> Result<(), BlockError> {
    minimum.check().map_err(BlockError::PciPower)?;
    let events = r.read32(INTERRUPT_ENABLE) & !BUS_POWER;
    r.write32(SIGNAL_ENABLE, 0); // Polling owner has no CPU interrupt route.
    r.write32(INTERRUPT_ENABLE, events);
    r.write8(POWER, 0);
    if r.read8(POWER) != 0 {
        return Err(BlockError::Unsupported(
            "GL9755 dual-rail power-off did not acknowledge",
        ));
    }
    if vdd1 != 0 {
        r.write8(POWER, vdd1 | POWER_ON);
        minimum.wait_us(5_000).map_err(BlockError::PciPower)?;
        if r.read8(POWER) != vdd1 | POWER_ON {
            return Err(BlockError::Unsupported("GL9755 VDD1 did not acknowledge"));
        }
        r.write8(POWER, vdd1 | POWER_ON | VDD2);
        minimum.wait_us(5_000).map_err(BlockError::PciPower)?;
        if r.read8(POWER) != vdd1 | POWER_ON | VDD2 {
            return Err(BlockError::Unsupported("GL9755 VDD2 did not acknowledge"));
        }
        r.write32(INTERRUPT_ENABLE, events | BUS_POWER);
        if r.read32(INTERRUPT_ENABLE) & BUS_POWER == 0 || r.read32(SIGNAL_ENABLE) != 0 {
            return Err(BlockError::Unsupported(
                "GL9755 power-event polling did not acknowledge",
            ));
        }
    }
    Ok(())
}

impl Engine {
    pub(in crate::sdhci) fn gli55_power_event(&mut self) -> Result<(), BlockError> {
        if !matches!(self.profile, Profile::Gli9755 | Profile::Gli9767) {
            return Ok(());
        }
        let status = self.registers.read32(INTERRUPT);
        if status & BUS_POWER == 0 {
            return Ok(());
        }
        let primary = BlockError::Device { status };
        self.medium = None;
        self.fault = Some(primary.clone());
        self.registers.write16(CLOCK, 0);
        let restoration = self.power_off().err();
        self.last_failure = Some(Failure {
            primary: primary.clone(),
            retirement: None,
            restoration,
            quarantined: true,
        });
        // Shared protocol unwinding must preserve the power-off outcome.
        self.uhs_failed = true;
        Err(primary)
    }
}

#[cfg(test)]
mod tests;
