// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! MAC startup branches from pinned r8169_main.c, before DMA is published.
use super::{Error, Registers, Timer, firmware::Script, hardware::Hardware, registers::*};
use crate::block::BlockError;
mod ep;
mod g;
mod h;
mod nbase;

impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    fn ephys(&self, values: &[(u8, u16, u16)]) -> Result<(), BlockError> {
        for &(reg, clear, set) in values {
            self.ephy(reg, clear, set)?;
        }
        Ok(())
    }
    fn cp_common(&self) {
        self.registers
            .write8(CONFIG1, self.registers.read8(CONFIG1) | (1 << 4));
        self.registers
            .write8(CONFIG3, self.registers.read8(CONFIG3) & !1);
    }
    pub fn configure_mac(&mut self, script: Option<&Script<'_>>) -> Result<(), Error> {
        let r = self.registers;
        r.write8(CONFIG_LOCK, CONFIG_UNLOCKED);
        let result = (|| {
            // Keep ASPM disabled. CLKREQ is disabled before initialization;
            // MAC28's exact DP4 branch re-enables it in PCIe Link Control
            // after EPHY setup. MAC32+ clears these MAC-local bits first.
            if self.revision.version >= 32 {
                if self.revision.version == 46 || self.revision.nbase() {
                    self.mac_ocp_modify(0xe092, 0x00ff, 0)?;
                }
                if self.revision.version == 70 {
                    r.write8(0x34, self.mmio8(0x34)? & !(1 << 3)); // INT_CFG0 CLKREQ.
                } else {
                    r.write8(CONFIG2, r.read8(CONFIG2) & !(1 << 7));
                }
                r.write8(CONFIG5, r.read8(CONFIG5) & !1);
                if self.revision.version == 46 {
                    self.mac_ocp_write(0xe048, 1500 + 14 + 0x20)?; // Donor TX idle timer in bytes.
                }
                if self.revision.nbase() {
                    r.write16(NBASE_EEE_TXIDLE, 1500 + 14 + 0x20);
                }
            }
            let mut cplus = r.read16(CPLUS) & (1 << 13); // normal mode only; no VLAN/checksum offloads.
            if self.revision.version <= 6 {
                r.write8(EARLY_TX, 0x3f);
                cplus |= 1 << 3;
                if matches!(self.revision.version, 2 | 3) {
                    cplus |= 1 << 14;
                }
                if matches!(self.revision.version, 5 | 6) {
                    let mut magic = if self.revision.version == 5 {
                        0x000f_ff00
                    } else {
                        0x00ff_ff00
                    };
                    if r.read8(CONFIG2) & 1 != 0 {
                        magic |= 0xff;
                    }
                    r.write32(0x7c, magic);
                }
            } else if self.revision.nbase() {
                self.nbase_mac()?;
            } else {
                r.write8(
                    EARLY_TX,
                    if self.revision.version >= 34 {
                        0x27
                    } else {
                        (8064u16 >> 7) as u8
                    },
                );
                match self.revision.version {
                    17 => r.write8(CONFIG3, r.read8(CONFIG3) & !1),
                    18 => {
                        self.latency()?;
                        self.ephys(&[
                            (1, 0, 1),
                            (2, 0x0800, 0x1000),
                            (3, 0, 0x42),
                            (6, 0x80, 0),
                            (7, 0, 0x2000),
                        ])?;
                        self.cp_common();
                    }
                    19 => {
                        self.latency()?;
                        r.write8(DEBUG, 0x06 | (1 << 4) | (1 << 3));
                        self.ephys(&[(2, 0x0800, 0x1000), (3, 0, 2), (6, 0x80, 0)])?;
                        self.cp_common();
                    }
                    20 | 21 => {
                        self.latency()?;
                        self.ephys(&[(1, 0, 1), (3, 0x0400, 0x20)])?;
                        self.cp_common();
                    }
                    22 => {
                        self.latency()?;
                        self.cp_common();
                    }
                    23 => {
                        self.latency()?;
                        r.write8(CONFIG3, r.read8(CONFIG3) & !1);
                    }
                    24 => {
                        self.latency()?;
                        r.write8(CONFIG3, r.read8(CONFIG3) & !1);
                        r.write8(DEBUG, 0x20);
                    }
                    25 | 26 | 31 => self.latency()?,
                    28 => {
                        self.latency()?;
                        self.ephys(&[
                            (0xb, 0, 0x48),
                            (0x19, 0x20, 0x50),
                            (0xc, 0x100, 0x20),
                            (0x10, 4, 0),
                        ])?;
                    }
                    32 | 33 => {
                        self.latency()?;
                        self.ephys(&[
                            (0, 0x0200, 0x0100),
                            (0, 0, 4),
                            (6, 2, 1),
                            (6, 0, 0x30),
                            (7, 0, 0x2000),
                            (0, 0, 0x20),
                            (3, 0x5800, 0x2000),
                            (3, 0, 1),
                            (1, 0x0800, 0x1000),
                            (7, 0, 0x4000),
                            (0x1e, 0, 0x2000),
                            (0x19, 0xffff, 0xfe6c),
                            (0x0a, 0, 0x40),
                        ])?;
                        r.write32(MISC, r.read32(MISC) | (1 << 29));
                        r.write32(MISC, r.read32(MISC) & !(1 << 29));
                        r.write8(CONFIG5, r.read8(CONFIG5) & !(1 << 3));
                    }
                    35 | 36 | 38 => {
                        self.latency()?;
                        self.eri_write(0xc0, 3, 0)?;
                        self.eri_write(0xb8, 15, 0)?;
                        self.eri_write(0xc8, 15, (0x10 << 16) | 2)?;
                        self.eri_write(0xe8, 15, (0x10 << 16) | 6)?;
                        self.eri_modify(0xdc, 1, 0)?;
                        self.eri_modify(0xdc, 0, 1)?;
                        self.eri_modify(0x1b0, 3, 1 << 4)?;
                        self.eri_modify(0x1d0, 0, (1 << 4) | (1 << 1))?;
                        self.eri_write(0xcc, 15, 0x50)?;
                        self.eri_write(0xd0, 15, 0x60)?;
                        r.write8(MCU, r.read8(MCU) & !(1 << 7));
                        r.write8(DLL_POWER, r.read8(DLL_POWER) | (1 << 6));
                        r.write32(MISC, r.read32(MISC) | (1 << 22));
                        r.write8(CONFIG5, r.read8(CONFIG5) & !(1 << 3));
                        if self.revision.version == 38 {
                            r.write8(CONFIG3, r.read8(CONFIG3) & !(1 << 1));
                            self.ephys(&[
                                (6, 0xc0, 0x20),
                                (0xf, 0xffff, 0x5200),
                                (0x19, 0, 0x224),
                                (0, 0, 8),
                                (0xc, 0x3df0, 0x200),
                            ])?;
                            self.eri_modify(0xd4, 0, 0x0c00)?;
                        } else {
                            self.ephys(&[
                                (6, 0xc0, 0x20),
                                (8, 1, 2),
                                (9, 0, 0x80),
                                (0x19, 0, 0x224),
                                (0, 0, 8),
                                (0xc, 0x3df0, 0x200),
                            ])?;
                            r.write8(0x1b, r.read8(0x1b) & !7);
                            self.eri_modify(0xd4, 0, 0x1f00)?;
                        }
                    }
                    40 | 42 | 44 => self.g_start()?,
                    46 => self.h_start()?,
                    51 | 52 => {
                        self.ep_mac()?;
                        // FP's donor MAC-only firmware runs at the tail of
                        // rtl_hw_start_8117, before exit-L1/RX maximum/lock/DMA.
                        if self.revision.version == 52 && self.revision.firmware.is_some() {
                            self.apply_firmware(
                                script.ok_or(Error::Script("RTL8117 requires MAC firmware"))?,
                            )?;
                        }
                        self.mac_ocp_modify(0xc0ac, 0, 0x1f80)?;
                        self.eri_modify(0x1b0, 3, 0)?;
                    }
                    34 => {
                        self.latency()?;
                        self.ephys(&[
                            (9, 0, 0x80),
                            (0x19, 0, 0x224),
                            (0, 0, 4),
                            (0x0c, 0x3df0, 0x0200),
                        ])?;
                        self.eri_write(0xc0, 3, 0)?;
                        self.eri_write(0xb8, 15, 0)?;
                        self.eri_write(0xc8, 15, (0x10 << 16) | 2)?;
                        self.eri_write(0xe8, 15, (0x10 << 16) | 6)?;
                        self.eri_modify(0x1d0, 0, 1 << 1)?;
                        self.eri_modify(0xdc, 1, 0)?;
                        self.eri_modify(0xdc, 0, 1)?;
                        self.eri_modify(0x1b0, 3, 1 << 4)?; // Keep TX-LPI off, including stale firmware state.
                        r.write8(0x1b, r.read8(0x1b) & !7);
                        self.eri_write(0xcc, 15, 0x50)?;
                        self.eri_write(0xd0, 15, 0x07ff_0060)?;
                        r.write8(MCU, r.read8(MCU) & !(1 << 7));
                        r.write8(DLL_POWER, r.read8(DLL_POWER) | (1 << 6));
                        r.write32(MISC, r.read32(MISC) | (1 << 22));
                        r.write8(CONFIG5, r.read8(CONFIG5) & !(1 << 3));
                        self.eri_modify(0xd4, 0, 0x1f00)?; // exit L1 events, Linux rtl_enable_exit_l1.
                    }
                    _ => {
                        return Err(BlockError::Unsupported(
                            "unimplemented Realtek MAC start revision",
                        )
                        .into());
                    }
                }
                // Disable jumbo mode, including stale UNDI configuration.
                if self.revision.version == 17 {
                    r.write8(CONFIG4, r.read8(CONFIG4) & !1);
                }
                if matches!(self.revision.version, 31..=33) {
                    r.write8(EARLY_TX, 0x3f);
                    r.write8(CONFIG3, r.read8(CONFIG3) & !(1 << 2));
                    r.write8(CONFIG4, r.read8(CONFIG4) & !1);
                }
                if self.revision.version == 28 {
                    r.write8(CONFIG3, r.read8(CONFIG3) & !(1 << 2));
                }
                if (18..=26).contains(&self.revision.version) {
                    r.write8(CONFIG3, r.read8(CONFIG3) & !(1 << 2));
                    r.write8(CONFIG4, r.read8(CONFIG4) & !(1 << 1));
                }
            }
            r.write16(CPLUS, cplus);
            if !self.revision.nbase() {
                r.write16(INTERRUPT_MITIGATION, 0);
            }
            // Restrict receive size to one allocated buffer, allowing the FCS.
            r.write16(RX_MAXIMUM, BUFFER as u16);
            Ok(())
        })();
        r.write8(CONFIG_LOCK, CONFIG_LOCKED);
        result
    }
}
