// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! Exact EP51/FP52 MAC start from pinned Linux, before MAC firmware and DMA.
use super::super::registers::*;
use super::{BlockError, Hardware, Registers, Timer};
const FP_EPHY: &[(u8, u16, u16)] = &[(0x19, 0x0040, 0x1100), (0x59, 0x0040, 0x1100)];
impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    pub(super) fn ep_mac(&self) -> Result<(), BlockError> {
        let r = self.registers;
        if self.revision.version == 51 {
            self.ephys(&[
                (0, 0, 0x80),
                (0xd, 0x100, 0x200),
                (0x19, 0x8021, 0),
                (0x1e, 0, 0x2000),
            ])?;
            self.ep_stop_cmac()?;
        } else {
            self.ep_stop_cmac()?;
            for &(address, clear, set) in FP_EPHY {
                // Pinned rtl_ephy_read/write mask offsets with1f: donor59
                // both encode the same physical register19.
                // Retain both table entries/transactions, not an invented bank.
                self.ephy(address & 0x1f, clear, set)?;
            }
        }
        self.eri_write(0xc8, 15, (0x08 << 16) | 2)?;
        self.eri_write(0xe8, 15, (0x10 << 16) | 6)?;
        self.eri_write(0xcc, 1, 0x2f)?;
        self.eri_write(0xd0, 1, 0x5f)?;
        self.latency()?;
        self.eri_modify(0xdc, 1, 0)?;
        self.eri_modify(0xdc, 0, 1)?;
        if self.revision.version == 52 {
            self.eri_modify(0xd4, 0, 0x10)?;
        }
        self.eri_write(0x5f0, 3, 0x4f87)?;
        r.write32(MISC, self.mmio32(MISC)? & !RXDV_GATED);
        self.eri_write(0xc0, 3, 0)?;
        self.eri_write(0xb8, 3, 0)?;
        if self.revision.version == 51 {
            self.eri_modify(0x2fc, 6, 1)?;
        }
        if self.revision.version == 52 {
            r.write8(DLL_POWER, self.mmio8(DLL_POWER)? & !(1 << 6));
            r.write8(MISC_1, self.mmio8(MISC_1)? & !(1 << 6));
        }
        r.write8(DLL_POWER, self.mmio8(DLL_POWER)? & !(1 << 7));
        if self.revision.version == 52 {
            self.eri_modify(0x1b0, 1 << 12, 0)?;
        }
        r.write8(CONFIG3, self.mmio8(CONFIG3)? & !(1 << 1));
        if self.revision.version == 51 {
            r.write8(DLL_POWER, self.mmio8(DLL_POWER)? & !(1 << 6));
            r.write8(MISC_1, self.mmio8(MISC_1)? & !(1 << 6));
            self.mac_ocp_modify(0xd3e2, 0x0fff, 0x0271)?;
            self.mac_ocp_modify(0xd3e4, 0x00ff, 0)?;
            self.mac_ocp_modify(0xe860, 0, 0x0080)?;
        } else {
            let saw = self.paged_read(0x0c42, 0x13)? & 0x3fff;
            if saw != 0 {
                self.mac_ocp_modify(
                    0xd412,
                    0x0fff,
                    ((16_000_000 / u32::from(saw)) & 0xfff) as u16,
                )?;
            }
            self.mac_ocp_modify(0xe056, 0x00f0, 0)?;
            self.mac_ocp_write(0xea80, 3)?;
            self.mac_ocp_modify(0xe052, 0, 9)?;
            self.mac_ocp_modify(0xd420, 0x0fff, 0x047f)?;
            self.mac_ocp_write(0xe63e, 1)?;
            self.mac_ocp_write(0xe63e, 0)?;
            self.mac_ocp_write(0xc094, 0)?;
            self.mac_ocp_write(0xc09e, 0)?;
        }
        r.write8(0x1b, self.mmio8(0x1b)? & !7);
        self.eri_modify(0x1b0, 3, 0)?;
        Ok(())
    }
}
