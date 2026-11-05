// SPDX-License-Identifier: GPL-2.0-only
// Native adaptation of sdhci-pci-o2micro.c, Copyright 2013 BayHub Technology Ltd.
// Authors: Peter Guo, Adam Lee, Ernest Zhang.
//! Legacy O2Micro PCI setup, standard clock and power-off sequencing.
use super::super::{BlockError, Clock, registers::*};
use crate::bus::pci::ConfigSpace;

const LOCK_WP: u16 = 0xd3;
const MULTI_VCC3V: u16 = 0xee;
const CLKREQ: u16 = 0xec;
const CAPS: u16 = 0xe0;
const ADMA1: u16 = 0xe2;
const ADMA2: u16 = 0xe7;
const INFINITE_MODE: u16 = 0xf1;
const PLL_SETTING: u16 = 0x304;
const OUTPUT_CLOCK: u16 = 0x354;
const DLL_SELECT: u32 = 1 << 16;
const PHASE: u32 = 15 << 20;
const PLL_CONTROL: usize = 0x1cc;
const PLL_RESET: u32 = 1 << 12;
const PLL_ACTIVE: u32 = 1 << 18;
const PLL_LOCKED: u32 = 1 << 14;
const CD_LEVEL: u32 = 1 << 18;

fn checked8(r: &mut dyn ConfigSpace, at: u16, value: u8) -> Result<(), BlockError> {
    r.write8(at, value)?;
    if r.read8(at)? != value {
        return Err(BlockError::Unsupported(
            "O2Micro PCI byte write did not acknowledge",
        ));
    }
    Ok(())
}
fn checked32(r: &mut dyn ConfigSpace, at: u16, value: u32) -> Result<(), BlockError> {
    r.write32(at, value)?;
    if r.read32(at)? != value {
        return Err(BlockError::Unsupported(
            "O2Micro PCI clock write did not acknowledge",
        ));
    }
    Ok(())
}
fn unlocked(
    r: &mut dyn ConfigSpace,
    operation: impl FnOnce(&mut dyn ConfigSpace) -> Result<(), BlockError>,
) -> Result<(), BlockError> {
    let lock = r.read8(LOCK_WP)?;
    let result = checked8(r, LOCK_WP, lock & !0x80).and_then(|()| operation(r));
    if matches!(
        &result,
        Err(BlockError::Config(_)
            | BlockError::PciPower(_)
            | BlockError::PciCapability(crate::bus::pci::CapabilityError::Config { .. }))
    ) {
        return result;
    }

    // Even an uncertain operation must attempt to close the write-protection window.
    let close = (|| {
        let lock = r.read8(LOCK_WP)? | 0x80;
        checked8(r, LOCK_WP, lock)
    })();
    result.and(close)
}
pub(super) fn prepare(r: &mut dyn ConfigSpace) -> Result<(), BlockError> {
    unlocked(r, |r| {
        checked8(r, MULTI_VCC3V, 0x08)?;
        let clkreq = r.read8(CLKREQ)? | 0x20;
        checked8(r, CLKREQ, clkreq)?;
        let caps = r.read8(CAPS)? | 1;
        checked8(r, CAPS, caps)?;
        checked8(r, CAPS, 0x73)?;
        checked8(r, ADMA1, 0x39)?;
        checked8(r, ADMA2, 0x08)?;
        let finite = r.read8(INFINITE_MODE)? | 0x08;
        checked8(r, INFINITE_MODE, finite)
    })
}
pub(super) fn before_clock(r: &mut dyn ConfigSpace) -> Result<(), BlockError> {
    unlocked(r, |r| {
        let pll = r.read32(PLL_SETTING)?;
        if pll & 0xffff_0000 != 0x2510_0000 {
            checked32(r, PLL_SETTING, pll & 0xffff | 0x2510_0000)?;
        }
        let output = r.read32(OUTPUT_CLOCK)? & !(DLL_SELECT | PHASE);
        checked32(r, OUTPUT_CLOCK, output)
    })
}
pub(super) fn power_off(r: &mut dyn ConfigSpace) -> Result<(), BlockError> {
    unlocked(r, |r| {
        let output = r.read32(OUTPUT_CLOCK)? & !DLL_SELECT;
        checked32(r, OUTPUT_CLOCK, output)
    })
}
/// Keep source cleanup on failure; no card clock is enabled on a failed PLL/CD proof.
pub(in crate::sdhci) fn stabilize(
    r: &mut dyn Registers,
    clock: Clock,
    minimum: &dyn crate::bus::pci::power::Timer,
) -> Result<bool, BlockError> {
    minimum.check().map_err(BlockError::PciPower)?;
    let mut control = r.read32(PLL_CONTROL);
    r.write32(PLL_CONTROL, control | PLL_RESET);
    minimum.wait_us(1).map_err(BlockError::PciPower)?;
    control &= !PLL_RESET;
    r.write32(PLL_CONTROL, control);
    r.write32(PLL_CONTROL, control | PLL_ACTIVE);
    let result = (|| {
        let deadline = clock.deadline(20_000);
        while u32::from(r.read16(PLL_CONTROL)) & PLL_LOCKED == 0 {
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            clock.delay(10);
        }
        minimum.wait_us(1).map_err(BlockError::PciPower)?;
        let deadline = clock.deadline(50_000);
        loop {
            let state = r.read32(PRESENT);
            if (state & CARD_PRESENT != 0) == (state & CD_LEVEL != 0) {
                return Ok(state & CARD_PRESENT != 0);
            }
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            clock.delay(10);
        }
    })();
    if matches!(&result, Err(BlockError::PciPower(_))) {
        return result;
    }
    let control = r.read32(PLL_CONTROL) & !PLL_ACTIVE;
    r.write32(PLL_CONTROL, control);
    result
}
