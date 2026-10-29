// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of rts5227.c and rtsx_pcr.c, Copyright 2009-2013 Realtek.
//! RTS522A electrical profile. This is independent of the RTS5227 PHY setup.
use super::*;

impl Engine {
    pub(super) fn rts522a_disable_aspm(&mut self) -> Result<(), BlockError> {
        let old = self.read_reg(ASPM_FORCE_CTL)?;
        self.write_reg(ASPM_FORCE_CTL, 0x30, 0x30)?;
        // Source register-mode ASPM: PCI Link Control is not the actuator.
        if old & 0x30 != 0x30 {
            self.clock.delay(10_000);
        }
        Ok(())
    }
    pub(super) fn rts522a_optimize_phy(&mut self) -> Result<(), BlockError> {
        let revision = self.read_reg(DUMMY_REG_RESET_0)? & 15;
        self.write_reg(RTS522A_PM_CTRL3, D3_DELINK_MODE_EN, 0)?;
        // Only the silicon A revision needs these five fixes. PCI's
        // revision byte and later silicon revisions cannot select this table.
        if revision == 0 {
            for (at, value) in [
                (3, 0xc152),
                (2, 0x0a1f),
                (0x1a, 0x2546),
                (0x1d, 4),
                (0x1e, 0x5c7f),
            ] {
                self.phy(at, value)?;
            }
        }
        Ok(())
    }
    fn read_phy(&mut self, address: u8) -> Result<u16, BlockError> {
        self.write_reg(PHYADDR, 0xff, address)?;
        self.write_reg(PHYRWCTL, 0xff, 0x80)?;
        for _ in 0..100_000 {
            if self.read_reg(PHYRWCTL)? & 0x80 == 0 {
                let lo = self.read_reg(PHYDATA0)?;
                let hi = self.read_reg(PHYDATA1)?;
                return Ok(u16::from_le_bytes([lo, hi]));
            }
        }
        self.failed(BlockError::Timeout)
    }
    pub(super) fn rts522a_oobs(&mut self, l1ss: bool) -> Result<(), BlockError> {
        let old = self.read_phy(1)?;
        self.phy(
            1,
            if l1ss {
                old & !(1 << 9)
            } else {
                old | (1 << 9)
            },
        )?;
        if !l1ss {
            self.write_reg(REG_CFG_OOBS_OFF_TIMER, 0xff, 0x32)?;
            self.write_reg(REG_CFG_OOBS_ON_TIMER, 0xff, 5)?;
        }
        self.write_reg(REG_CFG_VCM_ON_TIMER, 0xff, if l1ss { 3 } else { 0x83 })?;
        self.write_reg(REG_CFG_OOBS_POLLING, 0xff, if l1ss { 0 } else { 0xde })
    }
    pub(super) fn rts522a_extra(&mut self, rtd3: bool) -> Result<(), BlockError> {
        // Card-detect wake and board RTD3 bits are real initialization effects;
        // this does not claim a global suspend/runtime-PM service.
        self.write_reg(RTS522A_AUTOLOAD_CFG1, 0xf0, 0xf0)?;
        self.write_reg(RTS522A_PM_CTRL3, 1, u8::from(rtd3))?;
        self.write_reg(RTS522A_PME_FORCE_CTL, 0x30, if rtd3 { 0x30 } else { 0x20 })?;
        for (at, mask, value) in [
            (FUNC_FORCE_CTL, 2, 2),
            (PCLK_CTL, 4, 4),
            (PM_EVENT_DEBUG, 8, 8),
            (PM_CLK_FORCE_CTL, 0xff, 0x11),
        ] {
            self.write_reg(at, mask, value)?;
        }
        Ok(())
    }
    pub(super) fn rts522a_init_ocp(&mut self) -> Result<(), BlockError> {
        self.write_reg(FPDCTL, OC_POWER_DOWN, 0)?;
        self.write_reg(REG_OCPPARA1, 7, 5)?; // SD_OCP_TIME_800
        self.write_reg(REG_OCPPARA2, 7, 6)?; // RTS522A_OCP_THD_800
        self.write_reg(REG_OCPGLITCH, 15, 15)?; // SD_OCP_GLITCH_10M
        self.rts522a_enable_ocp()
    }
    pub(super) fn rts522a_enable_ocp(&mut self) -> Result<(), BlockError> {
        self.write_reg(FPDCTL, OC_POWER_DOWN, 0)?;
        self.write_reg(REG_OCPCTL, 0xff, SD_OCP_ENABLE)
    }
    pub(super) fn rts522a_disable_ocp(&mut self, budget: Budget) -> Result<(), BlockError> {
        // Capture status before disabling the detector. Preserve an earlier
        // event across a later ordinary power-off with zero status.
        let status = self.read_reg_before(REG_OCPSTAT, Some(budget))?;
        if status != 0 || self.ocp_status.is_none() {
            self.ocp_status = Some(status);
        }
        self.write_reg_before(REG_OCPCTL, SD_OCP_ENABLE, 0, Some(budget))?;
        self.write_reg_before(FPDCTL, OC_POWER_DOWN, OC_POWER_DOWN, Some(budget))
    }
    pub(super) fn rts522a_clear_ocp(&mut self, budget: Budget) -> Result<(), BlockError> {
        self.write_reg_before(REG_OCPCTL, SD_OCP_CLEAR, SD_OCP_CLEAR, Some(budget))?;
        self.clock.delay(100);
        self.write_reg_before(REG_OCPCTL, SD_OCP_CLEAR, 0, Some(budget))
    }
}
