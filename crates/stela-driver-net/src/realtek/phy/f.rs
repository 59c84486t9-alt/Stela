// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! RTL8168F1/F2 and RTL8411 PHY sequences from pinned Linux sources.
use super::{BlockError, Error, Hardware, PHY_PAGE, Registers, Script, Timer};

impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    fn f_common(&self) -> Result<(), BlockError> {
        self.parameter(0x8b80, 0, 6)?;
        self.extended_page(0x2d, 0x18, 0, 0x10)?;
        self.phy_modify(0x14, 0, 1 << 15)?;
        self.parameter(0x8b86, 0, 1)?;
        self.extended_page(0x20, 0x15, 0, 1 << 8)?;
        self.parameter(0x8b85, 0, 1 << 13)
    }
    fn f_green(&self, table: u16) -> Result<(), BlockError> {
        self.paged(3, 9, 0xffff, 0xa20f)?;
        for parameter in [0x8b55, 0x8b5e, 0x8b67, 0x8b70] {
            self.parameter(parameter, 0xffff, 0)?;
        }
        self.extended_page(0x78, 0x17, 0xffff, 0)?;
        self.extended_page(0x78, 0x19, 0xffff, table)?;
        self.parameter(0x8b79, 0xffff, 0xaa00)?;
        self.paged(3, 1, 0xffff, 0x328a)
    }
    pub(super) fn f(&mut self, script: &Script<'_>) -> Result<(), Error> {
        self.apply_firmware(script)?;
        match self.revision.version {
            35 => {
                self.f_green(0xfb)?;
                self.f_common()?;
                self.parameter(0x8b85, 0, 0x4000)?;
            }
            36 => self.f_common()?,
            38 => {
                self.f_common()?;
                self.parameter(0x8b85, 0, 0x4000)?;
                self.f_green(0xaa)?;
                self.parameter(0x8b54, 0x0800, 0)?;
                self.parameter(0x8b5d, 0x0800, 0)?;
                self.parameter(0x8a7c, 0x0100, 0)?;
                self.parameter(0x8a7f, 0, 0x0100)?;
                for parameter in [0x8a82, 0x8a85, 0x8a88] {
                    self.parameter(parameter, 0x0100, 0)?;
                }
                self.parameter(0x8b85, 0, 0x8000)?;
                self.phy_write(PHY_PAGE, 3)?;
                self.phy_modify(0x19, 1, 0)?;
                self.phy_modify(0x10, 1 << 10, 0)?;
                self.phy_write(PHY_PAGE, 0)?;
            }
            _ => return Err(Error::UnsupportedRevision(self.revision)),
        }
        Ok(())
    }
}
