// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! Exact MAC46 H/M EPHY, FIFO and saw-count timer from pinned r8169_main.c.
use super::super::registers::*;
use super::{BlockError, Hardware, Registers, Timer};
impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    pub(super) fn h_start(&self) -> Result<(), BlockError> {
        let r = self.registers;
        self.ephys(&[
            (0x1e, 0x0800, 0x0001),
            (0x1d, 0, 0x0800),
            (5, 0xffff, 0x2089),
            (6, 0xffff, 0x5881),
            (4, 0xffff, 0x854a),
            (1, 0xffff, 0x068b),
        ])?;
        self.eri_write(0xc8, 15, (0x08 << 16) | 2)?;
        self.eri_write(0xe8, 15, (0x10 << 16) | 6)?;
        self.eri_write(0xcc, 1, 0x38)?;
        self.eri_write(0xd0, 1, 0x48)?;
        self.latency()?;
        self.eri_modify(0xdc, 1, 0)?;
        self.eri_modify(0xdc, 0, 1)?;
        self.eri_modify(0xdc, 0, 0x001c)?;
        self.eri_write(0x5f0, 3, 0x4f87)?;
        r.write32(MISC, self.mmio32(MISC)? & !RXDV_GATED);
        self.eri_write(0xc0, 3, 0)?;
        self.eri_write(0xb8, 3, 0)?;
        r.write8(DLL_POWER, self.mmio8(DLL_POWER)? & !(1 << 6));
        r.write8(MISC_1, self.mmio8(MISC_1)? & !(1 << 6));
        r.write8(DLL_POWER, self.mmio8(DLL_POWER)? & !(1 << 7));
        self.eri_modify(0x1b0, (1 << 12) | 3, 0)?; // RX config and TX-LPI off.
        r.write8(CONFIG3, self.mmio8(CONFIG3)? & !(1 << 1));
        let saw = self.paged_read(0x0c42, 0x13)? & 0x3fff;
        if saw != 0 {
            let count = ((16_000_000 / u32::from(saw)) & 0x0fff) as u16;
            self.mac_ocp_modify(0xd412, 0x0fff, count)?;
        }
        self.mac_ocp_modify(0xe056, 0x00f0, 0)?;
        self.mac_ocp_modify(0xe052, 0x6000, 0x8008)?;
        self.mac_ocp_modify(0xe0d6, 0x01ff, 0x017f)?;
        self.mac_ocp_modify(0xd420, 0x0fff, 0x047f)?;
        self.mac_ocp_write(0xe63e, 1)?;
        self.mac_ocp_write(0xe63e, 0)?;
        self.mac_ocp_write(0xc094, 0)?;
        self.mac_ocp_write(0xc09e, 0)?;
        r.write8(0x1b, self.mmio8(0x1b)? & !7);
        self.mac_ocp_modify(0xc0ac, 0, 0x1f80)
    }
}
