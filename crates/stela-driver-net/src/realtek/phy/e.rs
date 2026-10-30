// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! RTL8168E1/E2 initialization and explicit optional EEE-cleanup limitation.
use super::{Error, Hardware, Registers, Script, Timer, Warning};

impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    pub(super) fn e(&mut self, script: &Script<'_>) -> Result<Warning, Error> {
        self.apply_firmware(script)?;
        self.parameter(0x8b80, 0xffff, 0xc896)?;
        self.batch(&[
            (0x1f, 1),
            (0x0b, 0x6c20),
            (7, 0x2872),
            (0x1c, 0xefff),
            (0x1f, 3),
            (0x14, 0x6420),
            (0x1f, 0),
        ])?;
        self.extended_page(0x2f, 0x15, 0xffff, 0x1919)?;
        self.extended_page(0xac, 0x18, 0xffff, 6)?;
        self.extended_page(0x23, 0x17, 0, 6)?;
        self.paged(2, 8, 0x7f00, 0x8000)?;
        self.extended_page(0x2d, 0x18, 0, 0x50)?;
        self.phy_modify(0x14, 0, 1 << 15)?;
        self.parameter(0x8b86, 0, 1)?;
        self.parameter(0x8b85, 0x2000, 0)?;
        self.extended_page(0x20, 0x15, 0x1100, 0)?;
        self.paged(6, 0, 0xffff, 0x5a00)?;
        // The donor next calls phy_write_mmd(AN, EEE_ADV, 0), ignoring its
        // error. Generic FE/GE maps that to C45 VEND2 a5d0, but the r8169 bus
        // only supplies C45 access from MAC40. __mdiobus_c45_write therefore
        // returns EOPNOTSUPP before any I/O for these exact MAC32/33 paths.
        // Report that this optional cleanup performs no I/O. The preceding
        // firmware/analogue programming and reset may affect EEE state, which
        // remains unverified; neither negotiation nor disable is claimed.
        Ok(Warning::EeeAdvertisementDisableUnavailable)
    }
}
