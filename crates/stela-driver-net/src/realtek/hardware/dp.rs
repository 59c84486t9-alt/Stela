// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! MAC28/31 MDIO gate and DP OOB ownership from pinned Linux r8169_main.c.
use super::super::registers::*;
use super::{BlockError, Hardware, Registers, Timer};
impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    pub(super) fn dp_mdio<V>(
        &self,
        access: impl FnOnce() -> Result<V, BlockError>,
    ) -> Result<V, BlockError> {
        if !matches!(self.revision.version, 28 | 31) {
            return access();
        }
        if self.dp_mdio_failed.get() {
            return Err(BlockError::Unsupported(
                "Realtek DP MDIO requires reset after failed command",
            ));
        }
        self.registers
            .write32(DP_MDIO_GATE, self.mmio32(DP_MDIO_GATE)? & !DP_MDIO_GATED);
        let result = access();
        // Restore the gate even if the PHY command timed out. Initialization
        // then fails; no later MDIO transaction can reuse that uncertain port.
        let restored = self
            .mmio32(DP_MDIO_GATE)
            .map(|v| self.registers.write32(DP_MDIO_GATE, v | DP_MDIO_GATED));
        // Page-restoration helpers also pass through this guard. A late
        // completion cannot authorize another transaction into this port.
        self.dp_mdio_failed
            .set(result.is_err() || restored.is_err());
        let value = result?;
        restored?;
        Ok(value)
    }
    fn dp_ocp_read(&self, address: u16) -> Result<u32, BlockError> {
        if address > 0x0fff {
            return Err(BlockError::Unsupported(
                "Realtek DP OCP address outside range",
            ));
        }
        self.registers
            .write32(DP_OCP_ACCESS, 0xf000 | u32::from(address));
        self.poll32(DP_OCP_ACCESS, ACCESS, true, 100, 20)?;
        self.mmio32(DP_OCP_DATA)
    }
    fn dp_notify(&self, command: u8) -> Result<(), BlockError> {
        self.eri_write(0xe8, 1, u32::from(command))?;
        self.registers.write32(DP_OCP_DATA, 1);
        self.registers
            .write32(DP_OCP_ACCESS, ACCESS | 0x1000 | 0x30);
        self.poll32(DP_OCP_ACCESS, ACCESS, false, 100, 20)
    }
    fn dp_status_register(&self) -> u16 {
        if self.revision.version == 31 {
            0xb8
        } else {
            0x10
        }
    }
    fn dp_wait(&self, started: bool) -> Result<(), BlockError> {
        for _ in 0..10 {
            self.timer.delay(10_000)?;
            if (self.dp_ocp_read(self.dp_status_register())? & (1 << 11) != 0) == started {
                return Ok(());
            }
        }
        Err(BlockError::Timeout)
    }
    pub fn dp_start(&self) -> Result<(), BlockError> {
        if !matches!(self.revision.version, 28 | 31) {
            return Ok(());
        }
        let dash_enabled = self.dp_ocp_read(self.dp_status_register())? & (1 << 15) != 0;
        self.dp_notify(5)?;
        if dash_enabled {
            self.dp_wait(true)?;
        }
        // Any failure aborts construction. Do not send another notification
        // into a command port whose completion may not have been observed.
        // DASH stop/release and removal are outside this boot-owned lifetime.
        Ok(())
    }
}
