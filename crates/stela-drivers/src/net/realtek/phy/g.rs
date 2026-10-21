// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! MAC40 G1 and MAC42/44 G2/8411B PHY tuning from pinned r8169_phy_config.c.
use super::{BlockError, Error, Hardware, PHY_PAGE, Registers, Script, Timer};
impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    fn g_parameter(&self, parameter: u16, clear: u16, set: u16) -> Result<(), BlockError> {
        let old = self.phy_read(PHY_PAGE)?;
        self.phy_write(PHY_PAGE, 0x0a43)?;
        let result = (|| {
            self.phy_write(0x13, parameter)?;
            self.phy_modify(0x14, clear, set)
        })();
        let restored = self.phy_write(PHY_PAGE, old);
        result.and(restored)
    }
    pub(super) fn g(&mut self, script: &Script<'_>) -> Result<(), Error> {
        self.apply_firmware(script)?;
        if self.revision.version == 40 {
            let first = self.paged_read(0x0a46, 0x10)?;
            self.paged(
                0x0bcc,
                0x12,
                1 << 15,
                if first & (1 << 8) == 0 { 1 << 15 } else { 0 },
            )?;
            let second = self.paged_read(0x0a46, 0x13)?;
            self.paged(
                0x0c41,
                0x15,
                1 << 1,
                if second & (1 << 8) != 0 { 1 << 1 } else { 0 },
            )?;
            self.paged(0x0a44, 0x11, 0, (1 << 3) | (1 << 2))?;
            self.paged(0x0bcc, 0x14, 1 << 8, 0)?;
            self.paged(0x0a44, 0x11, 0, (1 << 7) | (1 << 6))?;
            self.g_parameter(0x8084, 0x6000, 0)?;
            self.paged(0x0a43, 0x10, 0, 0x1003)?;
            self.paged(0x0a4b, 0x11, 0, 1 << 2)?;
            self.g_parameter(0x8012, 0, 0x8000)?;
            self.paged(0x0c42, 0x11, 1 << 13, 1 << 14)?;
            self.batch(&[
                (0x1f, 0x0bcd),
                (0x14, 0x5065),
                (0x14, 0xd065),
                (0x1f, 0x0bc8),
                (0x11, 0x5655),
                (0x1f, 0x0bcd),
                (0x14, 0x1065),
                (0x14, 0x9065),
                (0x14, 0x1065),
                (0x1f, 0),
            ])?;
            self.paged(0x0a43, 0x10, 1 << 2, 0)?;
        }
        self.paged(0x0a43, 0x11, 0, 1 << 4)?;
        Ok(())
    }
}
