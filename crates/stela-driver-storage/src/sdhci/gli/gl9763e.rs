// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of Linux sdhci-pci-gli.c, Copyright 2019 Genesys Logic,
// Inc.; CQHCI retirement follows cqhci-core.c/h, Copyright 2015 Linux Foundation.
//! GL9763E embedded MMC PHY and exclusive legacy-mode admission.
use super::*;

const ID: u32 = 0xe763_17a0;
const VHS: u16 = 0x884;
const CFG: u16 = 0x8a0;
const CQ_CFG: usize = 0x208;
const CQ_CONTROL: usize = 0x20c;

fn update(c: &mut dyn ConfigSpace, at: u16, mask: u32, bits: u32) -> Result<(), BlockError> {
    if c.read32(0) != ID {
        return Err(BlockError::Unsupported(
            "GL9763E original PCI identity lost",
        ));
    }
    let old = c.read32(at);
    c.write32(at, (old & !mask) | bits);
    let actual = c.read32(at);
    if c.read32(0) != ID || actual & mask != bits {
        return Err(BlockError::Unsupported(
            "GL9763E PCI write did not acknowledge",
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
pub(super) fn low_power(c: &mut dyn ConfigSpace, enable: bool) -> Result<(), BlockError> {
    unlocked(c, |c| {
        update(c, CFG, 1 << 12, if enable { 0 } else { 1 << 12 })
    })
}
fn read(r: &mut dyn Registers, at: usize) -> Result<u32, BlockError> {
    let value = r.read32(at);
    if value == u32::MAX {
        return Err(BlockError::Unsupported(
            "GL9763E CQHCI register unavailable",
        ));
    }
    Ok(value)
}
fn exact(r: &mut dyn Registers, at: usize, value: u32) -> Result<(), BlockError> {
    r.write32(at, value);
    if read(r, at)? != value {
        return Err(BlockError::Unsupported(
            "GL9763E CQHCI write did not acknowledge",
        ));
    }
    Ok(())
}

fn retire_idle_cqe(r: &mut dyn Registers, clock: Clock) -> Result<(), BlockError> {
    let configuration = read(r, CQ_CFG)?;
    if configuration & 1 != 0 {
        let control = read(r, CQ_CONTROL)?;
        r.write32(CQ_CONTROL, control | 1);
        if !clock.wait(100, || {
            let value = r.read32(CQ_CONTROL);
            value != u32::MAX && value & 1 != 0
        }) {
            return Err(BlockError::Timeout);
        }
    }
    // Existing task/completion ownership is not ours. Do not clear task lists
    // or claim BME-clear as a payload drain for an unknown firmware producer.
    for at in [0x228, 0x22c, 0x230, 0x234] {
        if read(r, at)? != 0 {
            return Err(BlockError::Unsupported(
                "GL9763E firmware CQE tasks require their retained owner",
            ));
        }
    }
    if read(r, 0x210)? & (1 << 2 | 1 << 4 | 1 << 5) != 0 {
        return Err(BlockError::Unsupported(
            "GL9763E unresolved firmware CQE error",
        ));
    }
    exact(r, 0x214, 0)?;
    exact(r, 0x218, 0)?;
    exact(r, CQ_CFG, configuration & !1)
}

pub(super) fn initialize<C: ConfigSpace>(
    f: &mut Function<C>,
    r: &mut dyn Registers,
    clock: Clock,
) -> Result<(), BlockError> {
    validate_clock(clock)?;
    pci::runtime_configuration(f, false)?;
    let aer = pci::find_aer(f.config())?;
    unlocked(f.config(), |c| {
        update(c, 0x8e0, 1 << 9, 1 << 9)?;
        update(c, 0x960, 1 << 3, 0)?;
        update(c, 0x8a4, 0x3ff << 19, 0x54 << 19)?;
        update(c, 0x934, 15 << 28, 5 << 28)?;
        if let Some(aer) = aer {
            update(c, aer + 0x14, 1 << 12, 1 << 12)?;
        }
        Ok(())
    })?;
    retire_idle_cqe(r, clock)?;
    r.write8(RESET, RESET_ALL);
    if !clock.wait(RESET_US, || r.read8(RESET) & RESET_ALL == 0) {
        return Err(BlockError::Timeout);
    }
    let strobe = r.read32(0x52c) & !(1 << 8);
    exact(r, 0x52c, strobe)?;
    pci::runtime_configuration(f, false)?;
    low_power(f.config(), false)
}

pub(super) fn legacy_authority(r: &mut dyn Registers) -> Result<(), BlockError> {
    if read(r, CQ_CFG)? & 1 != 0 {
        return Err(BlockError::Unsupported(
            "GL9763E CQE epoch changed before legacy controller access",
        ));
    }
    Ok(())
}

pub(in crate::sdhci) fn high_speed(r: &mut dyn Registers) -> Result<(), BlockError> {
    let clock = r.read16(CLOCK);
    r.write16(CLOCK, clock & !CLOCK_CARD);
    if r.read16(CLOCK) & CLOCK_CARD != 0 {
        return Err(BlockError::Unsupported(
            "GL9763E clock did not gate before signaling",
        ));
    }
    let control = r.read8(HOST_CONTROL) | HIGH_SPEED;
    r.write8(HOST_CONTROL, control);
    let mode = (r.read16(HOST_CONTROL2) & !UHS_MODE) | 1;
    r.write16(HOST_CONTROL2, mode);
    if r.read8(HOST_CONTROL) & HIGH_SPEED == 0 || r.read16(HOST_CONTROL2) & UHS_MODE != 1 {
        return Err(BlockError::Unsupported(
            "GL9763E MMC HS signaling did not acknowledge",
        ));
    }
    r.write16(CLOCK, clock);
    if r.read16(CLOCK) & CLOCK_CARD != clock & CLOCK_CARD {
        return Err(BlockError::Unsupported(
            "GL9763E clock did not restart after signaling",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
