// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! A chip that stops answering: every register reads all ones, or every
//! register reads one value that never changes. Each start step ends in a
//! named failure within a bound, for every implemented revision.
use super::*;

/// Registers that read `value` at every offset and ignore every write.
struct Stuck(u32);
impl Registers for Stuck {
    fn read8(&self, _: usize) -> u8 {
        self.0 as u8
    }
    fn read16(&self, _: usize) -> u16 {
        self.0 as u16
    }
    fn read32(&self, _: usize) -> u32 {
        self.0
    }
    fn write8(&self, _: usize, _: u8) {}
    fn write16(&self, _: usize, _: u16) {}
    fn write32(&self, _: usize, _: u32) {}
}

/// The longest a start on a silent chip may wait: the device's start
/// budget, which ends every counted poll, and the one poll that sees it
/// pass. The EP/FP CMAC stop alone would otherwise wait 100 s.
const BOUND_US: u64 = START_BUDGET_US + 50_000;

/// The steps `Realtek::new` runs once its registers are mapped, as far as
/// the first refusal.
fn start(registers: &Stuck, time: &Time, revision: Revision) -> Result<(), Error> {
    let mut hardware = Hardware::new(registers, time, revision, 0);
    if revision.nbase() && hardware.mac_ocp_read(0xd006)? & 0xff == 7 {
        return Err(BlockError::Unsupported("Realtek SFP mode").into());
    }
    hardware.initialize_modern()?;
    hardware.reset()?;
    hardware.dp_start()?;
    hardware.ep_start()?;
    read_station(&hardware)?;
    hardware.configure_phy(None, false)?;
    hardware.reset()?;
    hardware.configure_mac(None)?;
    Ok(())
}

#[test]
fn a_chip_that_stops_answering_fails_its_start_within_a_bound() {
    let versions = (2..=70).filter(|&version| {
        Revision {
            version,
            ..revision(2)
        }
        .implemented()
    });
    let mut wrong = alloc::vec::Vec::new();
    for version in versions {
        for value in [u32::MAX, 0, 0x5a5a_5a5a] {
            let time = Time::default();
            let result = start(&Stuck(value), &time, revision(version));
            if result.is_ok() || time.0.get() > BOUND_US {
                wrong.push((version, value, result, time.0.get()));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}
