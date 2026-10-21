// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! Exact EP/FP OOB ERI address encoding and CMAC ownership from pinned Linux.
use super::super::registers::*;
use super::{BlockError, Hardware, Registers, Timer};
impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    fn ep_eri_command(&self, address: u16, mask: u8) -> Result<u32, BlockError> {
        if address & 3 != 0 || address > 0x0fff || mask == 0 || mask > 15 {
            return Err(BlockError::Unsupported(
                "invalid Realtek EP OOB ERI address or mask",
            ));
        }
        Ok(u32::from(address)
            | (u32::from(mask) << 12)
            | (2 << 16)
            | if self.revision.version == 52 {
                0x0f70 << 18
            } else {
                0
            })
    }
    fn ep_read(&self, address: u16) -> Result<u32, BlockError> {
        self.registers
            .write32(ERI_ADDRESS, self.ep_eri_command(address, 15)?);
        self.poll32(ERI_ADDRESS, ACCESS, true, 100, 100)?;
        self.mmio32(ERI_DATA)
    }
    fn ep_write(&self, address: u16, mask: u8, data: u32) -> Result<(), BlockError> {
        let command = self.ep_eri_command(address, mask)?;
        self.registers.write32(ERI_DATA, data);
        self.registers.write32(ERI_ADDRESS, ACCESS | command);
        self.poll32(ERI_ADDRESS, ACCESS, false, 100, 100)
    }
    pub(in super::super) fn ep_stop_cmac(&self) -> Result<(), BlockError> {
        let r = self.registers;
        r.write8(IBCR2, self.mmio8(IBCR2)? & !1);
        let mut ready = false;
        for _ in 0..2000 {
            self.timer.delay(50_000);
            if self.mmio8(IBISR0)? & 0x20 != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(BlockError::Timeout);
        }
        r.write8(IBISR0, self.mmio8(IBISR0)? | 0x20);
        r.write8(IBCR0, self.mmio8(IBCR0)? & !1);
        Ok(())
    }
    pub fn ep_start(&self) -> Result<(), BlockError> {
        if !matches!(self.revision.version, 51 | 52) {
            return Ok(());
        }
        let enabled = self.ep_read(0x128)? & 1 != 0;
        self.ep_write(0x180, 1, 5)?;
        self.ep_write(0x30, 1, self.ep_read(0x30)? | 1)?;
        if enabled {
            for _ in 0..30 {
                self.timer.delay(10_000);
                if self.ep_read(0x124)? & 1 != 0 {
                    return Ok(());
                }
            }
            return Err(BlockError::Timeout);
        }
        Ok(())
    }
}
