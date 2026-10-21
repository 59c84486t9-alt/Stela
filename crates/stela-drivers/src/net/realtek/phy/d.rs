// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! MAC25/26 RTL8168D1/D2 PHY initialization from pinned r8169_phy_config.c.
use super::{BlockError, Error, Hardware, PHY_PAGE, Registers, Script, Timer};

const CHANNEL: &[(u16, u16)] = &[
    (0x1f, 0x0001),
    (0x06, 0x4064),
    (0x07, 0x2863),
    (0x08, 0x059c),
    (0x09, 0x26b4),
    (0x0a, 0x6a19),
    (0x0b, 0xdcc8),
    (0x10, 0xf06d),
    (0x14, 0x7f68),
    (0x18, 0x7fd9),
    (0x1c, 0xf0ff),
    (0x1d, 0x3d9c),
    (0x1f, 0x0003),
    (0x12, 0xf49f),
    (0x13, 0x070b),
    (0x1a, 0x05ad),
    (0x14, 0x94c0),
    (0x1f, 0x0002),
    (0x06, 0x5561),
    (0x1f, 0x0005),
    (0x05, 0x8332),
    (0x06, 0x5561),
    (0x1f, 0x0001),
    (0x17, 0x0cc0),
    (0x1f, 0x0000),
    (0x0d, 0xf880),
];

impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    fn d_common(&self) -> Result<(), BlockError> {
        self.paged(2, 5, 0xffff, 0x669a)?;
        self.parameter(0x8330, 0xffff, 0x669a)?;
        self.phy_write(PHY_PAGE, 2)?;
        let value = self.phy_read(0x0d)?;
        if value & 0xff != 0x6c {
            for low in 0x65..=0x6c {
                self.phy_write(0x0d, (value & 0xff00) | low)?;
            }
        }
        Ok(())
    }
    pub(super) fn d(&mut self, script: &Script<'_>) -> Result<(), Error> {
        self.batch(CHANNEL)?;
        let first = self.revision.version == 25;
        if first {
            self.phy_write(PHY_PAGE, 2)?;
            self.phy_modify(0x0b, 0x00ef, 0x0010)?;
            self.phy_modify(0x0c, 0x5d00, 0xa200)?;
        }
        if self.efuse_read(1)? == 0xb1 {
            self.d_common()?;
        } else {
            let tune = if first { 0x6662 } else { 0x2642 };
            self.paged(2, 5, 0xffff, tune)?;
            self.parameter(0x8330, 0xffff, tune)?;
        }
        self.phy_write(PHY_PAGE, 2)?;
        if first {
            self.phy_modify(0x0d, 0, 0x0300)?;
            self.phy_modify(0x0f, 0, 0x0010)?;
            self.phy_write(PHY_PAGE, 2)?;
        }
        self.phy_modify(2, 0x0600, 0x0100)?;
        self.phy_modify(3, 0xe000, 0)?;
        self.phy_write(PHY_PAGE, 0)?;
        if !first {
            self.paged(2, 0x0f, 0, 0x0017)?;
        }
        // Linux warns and omits firmware when this sentinel is different.
        // Refuse the incomplete startup explicitly instead of returning an
        // initialized adapter without its revision's required firmware.
        self.phy_write(PHY_PAGE, 5)?;
        self.phy_write(5, 0x001b)?;
        let readiness = self.phy_read(6);
        let restored = self.phy_write(PHY_PAGE, 0);
        let readiness = readiness?;
        restored?;
        if readiness != if first { 0xbf00 } else { 0xb300 } {
            return Err(Error::Script("RTL8168D PHY is not ready for firmware"));
        }
        self.apply_firmware(script)
    }
}
