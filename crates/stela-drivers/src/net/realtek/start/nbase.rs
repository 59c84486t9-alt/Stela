// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! Exact A2/B/D/K/9151A/CP RTL8125 MAC start and legacy descriptor selection from pinned Linux.
use super::super::registers::*;
use super::{BlockError, Hardware, Registers, Timer};
const A_EPHY: &[(u8, u16, u16)] = &[
    (0x04, 0xffff, 0xd000),
    (0x0a, 0xffff, 0x8653),
    (0x23, 0xffff, 0xab66),
    (0x20, 0xffff, 0x9455),
    (0x21, 0xffff, 0x99ff),
    (0x29, 0xffff, 0xfe04),
    (0x44, 0xffff, 0xd000),
    (0x4a, 0xffff, 0x8653),
    (0x63, 0xffff, 0xab66),
    (0x60, 0xffff, 0x9455),
    (0x61, 0xffff, 0x99ff),
    (0x69, 0xffff, 0xfe04),
];
const B_EPHY: &[(u8, u16, u16)] = &[
    (0x0b, 0xffff, 0xa908),
    (0x1e, 0xffff, 0x20eb),
    (0x4b, 0xffff, 0xa908),
    (0x5e, 0xffff, 0x20eb),
    (0x22, 0x0030, 0x0020),
    (0x62, 0x0030, 0x0020),
];
impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    pub(super) fn nbase_mac(&self) -> Result<(), BlockError> {
        if !matches!(self.revision.version, 61 | 63..=65) {
            return Err(BlockError::Unsupported(
                "unimplemented Realtek NBASE MAC start",
            ));
        }
        let r = self.registers;
        r.write8(0x34, 0); // INT_CFG0: interrupts stay disabled.
        let end = if self.revision.version != 63 {
            0xb00
        } else {
            0xa80
        };
        for offset in (0xa00..end).step_by(4) {
            r.write32(offset, 0);
        }
        if self.revision.version == 63 {
            r.write16(0x7a, 0);
        }
        self.mac_ocp_modify(0xea84, 0, 3)?; // Extended tally counter.
        self.latency()?;
        let entries = if self.revision.version == 61 {
            A_EPHY
        } else if self.revision.version == 63 {
            B_EPHY
        } else {
            &[] // D/K/9151A/CP have no donor EPHY table.
        };
        for &(address, clear, set) in entries {
            // Retain source offsets and both transactions for aliases. The
            // pinned read/write accessors transmit only five address bits.
            self.ephy(address & 0x1f, clear, set)?;
        }
        r.write8(CONFIG3, self.mmio8(CONFIG3)? & !(1 << 1));
        r.write16(0x382, 0x221b);
        r.write32(NBASE_RSS, 0);
        r.write16(NBASE_QUEUE, 0);
        self.mac_ocp_modify(0xd40a, 0x10, 0)?;
        r.write8(CONFIG1, self.mmio8(CONFIG1)? & !0x10);
        self.mac_ocp_write(0xc140, 0xffff)?;
        self.mac_ocp_write(0xc142, 0xffff)?;
        self.mac_ocp_modify(0xd3e2, 0x0fff, 0x03a9)?;
        self.mac_ocp_modify(0xd3e4, 0x00ff, 0)?;
        self.mac_ocp_modify(0xe860, 0, 0x80)?;
        self.mac_ocp_modify(0xeb58, 1, 0)?; // Use the implemented 16-byte descriptor format.
        self.mac_ocp_modify(
            0xe614,
            0x700,
            if self.revision.version == 63 {
                0x200
            } else {
                0x300
            },
        )?;
        self.mac_ocp_modify(
            0xe63e,
            0xc30,
            if self.revision.version == 63 { 0 } else { 0x20 },
        )?;
        for (address, clear, set) in [
            (0xc0b4, 0, 0xc),
            (0xeb6a, 0xff, 0x33),
            (0xeb50, 0x3e0, 0x40),
            (0xe056, 0xf0, 0),
            (0xe040, 0x1000, 0),
            (0xea1c, 3, 1),
            (0xea1c, 4, 0),
            (0xe0c0, 0x4f0f, 0x4403),
            (0xe052, 0x80, 0x68),
            (0xd430, 0xfff, 0x47f),
            (0xea1c, 4, 0),
        ] {
            self.mac_ocp_modify(address, clear, set)?;
        }
        self.mac_ocp_modify(0xeb54, 0, 1)?;
        self.timer.delay(1);
        self.mac_ocp_modify(0xeb54, 1, 0)?;
        r.write16(0x1880, self.mmio16(0x1880)? & !0x30);
        self.mac_ocp_write(0xe098, 0xc302)?;
        let mut ready = false;
        for _ in 0..10 {
            self.timer.delay(1000);
            if self.mac_ocp_read(0xe00e)? & (1 << 13) == 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(BlockError::Timeout);
        }
        r.write32(MISC, self.mmio32(MISC)? & !RXDV_GATED);
        self.mac_ocp_modify(0xc0ac, 0, 0x1f80)?;
        self.mac_ocp_modify(0xe040, 3, 0)?;
        if self.revision.version == 61 {
            self.mac_ocp_modify(0xeb62, 6, 0)?;
        }
        Ok(())
    }
}
