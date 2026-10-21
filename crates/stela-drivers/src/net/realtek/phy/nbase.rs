// SPDX-License-Identifier: GPL-2.0-only AND GPL-2.0-or-later
// PHY identity/resume portions from Linux realtek_main.c (GPL-2.0-or-later):
// Copyright (c) 2004 Freescale Semiconductor, Inc.
// Author: Johnson Leung <r58129@freescale.com>
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! Exact RTL8125A2/B/D/K/9151A/CP/BP PHY paths from pinned r8169_phy_config.c.
use super::{BlockError, Error, Hardware, Registers, Script, Timer};
impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    fn n_parameter(&self, address: u16, clear: u16, set: u16) -> Result<(), BlockError> {
        // rtl8125_phy_param maps VEND2 b87c/b87e directly to PHY OCP.
        self.phy_ocp_write(0xb87c, address)?;
        let value = self.phy_ocp_read(0xb87e)?;
        self.phy_ocp_write(0xb87e, (value & !clear) | set)
    }
    pub(super) fn nbase_phy(&mut self, script: &Script<'_>) -> Result<(), Error> {
        if !matches!(self.revision.version, 61 | 63..=66) {
            return Err(Error::UnsupportedRevision(self.revision));
        }
        if self.revision.version == 61 {
            for &(page, reg, clear, set) in &[
                (0xad4, 0x17, 0, 0x10),
                (0xad1, 0x13, 0x3ff, 0x3ff),
                (0xad3, 0x11, 0x3f, 6),
                (0xac0, 0x14, 0x1100, 0),
                (0xacc, 0x10, 3, 2),
                (0xad4, 0x10, 0xe7, 0x44),
                (0xac1, 0x12, 0x80, 0),
                (0xac8, 0x10, 0x300, 0),
                (0xac5, 0x17, 7, 2),
                (0xad4, 0x16, 0xffff, 0xa8),
                (0xac5, 0x16, 0xffff, 0x1ff),
                (0xac8, 0x15, 0xf0, 0x30),
            ] {
                self.paged(page, reg, clear, set)?;
            }
            self.n_parameter(0x80a2, 0xffff, 0x0153)?;
            self.n_parameter(0x809c, 0xffff, 0x0153)?;
            self.phy_write(0x1f, 0xa43)?;
            self.phy_write(0x13, 0x81b3)?;
            for value in [
                0x43, 0xa7, 0xd6, 0xec, 0xf6, 0xfb, 0xfd, 0xff, 0xbb, 0x58, 0x29, 0x13, 9, 4, 2,
            ] {
                self.phy_write(0x14, value)?;
            }
            for _ in 0..25 {
                self.phy_write(0x14, 0)?;
            }
            self.phy_write(0x1f, 0)?;
            self.g_parameter(0x8257, 0xffff, 0x020f)?;
            self.g_parameter(0x80ea, 0xffff, 0x7843)?;
            self.apply_firmware(script)?;
            self.paged(0xd06, 0x14, 0, 0x2000)?;
            self.g_parameter(0x81a2, 0, 0x100)?;
            for &(page, reg, clear, set) in &[
                (0xb54, 0x16, 0xff00, 0xdb00),
                (0xa45, 0x12, 1, 0),
                (0xa5d, 0x12, 0, 0x20),
                (0xad4, 0x17, 0x10, 0),
                (0xa86, 0x15, 1, 0),
            ] {
                self.paged(page, reg, clear, set)?;
            }
            self.paged(0xa44, 0x11, 0, 1 << 11)?;
        } else if self.revision.version == 63 {
            self.apply_firmware(script)?;
            self.paged(0xa44, 0x11, 0, 1 << 11)?;
            self.paged(0xac4, 0x13, 0xf0, 0x90)?;
            self.paged(0xad3, 0x10, 3, 1)?;
            self.n_parameter(0x80f5, 0xffff, 0x760e)?;
            self.n_parameter(0x8107, 0xffff, 0x360e)?;
            self.n_parameter(0x8551, 0xff00, 0x0800)?;
            self.paged(0xbf0, 0x10, 0xe000, 0xa000)?;
            self.paged(0xbf4, 0x13, 0xf00, 0x300)?;
            for address in [
                0x8044, 0x804a, 0x8050, 0x8056, 0x805c, 0x8062, 0x8068, 0x806e, 0x8074, 0x807a,
            ] {
                self.g_parameter(address, 0xffff, 0x2417)?;
            }
            self.paged(0xa4c, 0x15, 0, 0x40)?;
            self.paged(0xbf8, 0x12, 0xe000, 0xa000)?;
            self.paged(0xa5b, 0x12, 1 << 15, 0)?; // Legacy force mode.
        } else {
            self.apply_firmware(script)?;
            self.paged(0xa44, 0x11, 0, 1 << 11)?; // GPHY 10M.
            if self.revision.version == 65 {
                self.paged(0xad0, 0x17, 0x7f, 0xb)?;
                self.paged(0xad7, 0x14, 0, 1 << 4)?;
                self.n_parameter(0x807f, 0xff00, 0x5300)?;
                for (address, value) in [
                    (0x81b8, 0x00b4),
                    (0x81ba, 0x00e4),
                    (0x81c5, 0x0104),
                    (0x81d0, 0x054d),
                ] {
                    self.g_parameter(address, 0xffff, value)?;
                }
                self.paged(0xa43, 0x10, 0, 3)?; // 10M/ALDPS PLL off.
                self.paged(0xa44, 0x11, 0, 1 << 7)?;
            }
            if self.revision.version == 66 {
                self.g_parameter(0x8010, 0x0800, 0)?;
                self.n_parameter(0x8088, 0xff00, 0x9000)?;
                self.n_parameter(0x808f, 0xff00, 0x9000)?;
                self.g_parameter(0x8174, 0x2000, 0x1800)?;
            }
            self.paged(0xa5b, 0x12, 1 << 15, 0)?; // Legacy force mode.
        }
        self.paged(0xa43, 0x10, 1 << 2, 0)?; // Disable ALDPS.
        self.paged(0xa43, 0x11, 0, 1 << 4)?;
        self.paged(0xa6d, 0x14, 0x10, 0)?;
        self.paged(0xa42, 0x14, 0x80, 0)?;
        self.paged(0xa4a, 0x11, 0x200, 0)?;
        Ok(())
    }
    pub(super) fn nbase_internal_phy(&self) -> Result<bool, BlockError> {
        // Pinned realtek_main.c: internal PHYs cannot access MMDs through
        // C22 registers13/14 and read zero even for this nonzero EEE ability.
        // These are real probe transactions, not an emulated MMD operation.
        self.phy_write(13, 3)?;
        self.phy_write(14, 20)?;
        self.phy_write(13, 0x4003)?;
        Ok(self.phy_read(14)? == 0)
    }
}
