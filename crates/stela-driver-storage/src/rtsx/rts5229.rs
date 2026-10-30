// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of rts5229.c, Copyright 2009-2013 Realtek Semiconductor Corp.
// Author: Wei WANG. See ../THIRD_PARTY.md.
//! RTS5229 drive mux and revision-selected socket electrical behavior.
use super::*;

impl Engine {
    pub(super) fn rts5229_initialize(&mut self) -> Result<(), BlockError> {
        for (at, mask, value) in [
            (GPIO_CTL, 2, 2),
            (ASPM_FORCE_CTL, 0x3f, 0),
            (PETXCFG, 8, 8),
            (LDO_PWR_SEL, 3, 0),
            (LDO_PWR_SEL, 3, 1),
            (OLT_LED_CTL, 15, 2),
        ] {
            self.write_reg(at, mask, value)?;
        }
        let drive = self.config.rts5229_drive(false);
        self.write_reg(SD30_CMD_DRIVE_SEL, 0xff, drive)
    }
    pub(super) fn rts5229_drive(&mut self, voltage180: bool) -> Result<(), BlockError> {
        self.write_reg(SD30_CMD_DRIVE_SEL, 7, self.config.rts5229_drive(voltage180))
    }
    pub(super) fn rts5229_voltage(&mut self, voltage180: bool) -> Result<(), BlockError> {
        self.rts5229_drive(voltage180)?;
        self.phy(8, if voltage180 { 0x4c64 } else { 0x4fe4 })
    }
}
