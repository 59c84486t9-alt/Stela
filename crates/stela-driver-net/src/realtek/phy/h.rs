// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! Exact MAC46 H/M PHY and calibration from pinned r8169_phy_config.c.
use super::{BlockError, Error, Hardware, Registers, Script, Timer};
impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    pub(super) fn h(&mut self, script: &Script<'_>) -> Result<(), Error> {
        self.apply_firmware(script)?;
        self.g_parameter(0x808a, 0x003f, 0x000a)?;
        self.g_parameter(0x0811, 0, 0x0800)?;
        self.paged(0x0a42, 0x16, 0, 2)?;
        self.paged(0x0a44, 0x11, 0, 1 << 11)?; // Enable GPHY 10M.
        let bias = self.h_adc_bias()?;
        if bias != u16::MAX {
            self.paged(0x0bcf, 0x16, 0xffff, bias)?;
        }
        let data = self.paged_read(0x0bcd, 0x16)? & 0x000f;
        let rlen = data.saturating_sub(3);
        self.paged(0x0bcd, 0x17, 0xffff, rlen * 0x1111)?;
        self.paged(0x0a44, 0x11, 1 << 7, 0)?; // Disable PHY PFM mode.
        self.paged(0x0a43, 0x10, 1 << 0, 0)?; // Disable 10M PLL off.
        self.paged(0x0a43, 0x10, 1 << 2, 0)?; // Disable ALDPS.
        self.paged(0x0a43, 0x11, 0, 1 << 4)?;
        Ok(())
    }
    fn h_adc_bias(&self) -> Result<u16, BlockError> {
        self.mac_ocp_write(0xdd02, 0x807d)?;
        let data1 = self.mac_ocp_read(0xdd02)?;
        let data2 = self.mac_ocp_read(0xdd00)?;
        Ok(((data2 >> 1) & 0x7ff8) | (data2 & 7) | ((data1 & (1 << 7)) << 8))
    }
}
