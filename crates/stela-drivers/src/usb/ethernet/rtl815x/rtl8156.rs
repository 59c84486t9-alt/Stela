// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
//! Donor-shared RTL8156 power/up/enable with distinct A/B PHY callbacks.
use super::super::firmware::Firmware;
use super::*;

impl<C: Control> Chip<C> {
    pub(super) fn sram_modify(
        &mut self,
        address: u16,
        clear: u16,
        set: u16,
    ) -> Result<(), BlockError> {
        let value = self.sram_read(address)?;
        self.phy_write(OCP_SRAM_DATA, u32::from((value & !clear) | set))
    }
    fn sram2_read(&mut self, address: u16) -> Result<u16, BlockError> {
        self.phy_write(OCP_SRAM2_ADDR, u32::from(address))?;
        let mapped = self.phy_address(OCP_SRAM2_DATA)?;
        Ok(self.read(PLA, mapped, 2)? as u16)
    }
    pub(super) fn sram2_write(&mut self, address: u16, value: u16) -> Result<(), BlockError> {
        self.phy_write(OCP_SRAM2_ADDR, u32::from(address))?;
        self.phy_write(OCP_SRAM2_DATA, u32::from(value))
    }
    pub(super) fn sram2_modify(
        &mut self,
        address: u16,
        clear: u16,
        set: u16,
    ) -> Result<(), BlockError> {
        let value = self.sram2_read(address)?;
        self.phy_write(OCP_SRAM2_DATA, u32::from((value & !clear) | set))
    }
    pub(super) fn phy_read(&mut self, address: u32) -> Result<u32, BlockError> {
        let mapped = self.phy_address(address)?;
        self.read(PLA, mapped, 2)
    }

    fn mdi_swap_8156a11(&mut self) -> Result<(), BlockError> {
        if self.read(USB, USB_UPS_CFG, 2)? & MID_REVERSE == 0
            || self.phy_read(0xd068)? & (1 << 1) == 0
        {
            return Ok(());
        }
        let mut data = (self.phy_read(0xd068)? & !0x1f) | 1;
        self.phy_write(0xd068, data)?;
        let mut swap_a = self.phy_read(0xd06a)?;
        data = (data & !0x18) | 0x18;
        self.phy_write(0xd068, data)?;
        let mut swap_b = self.phy_read(0xd06a)?;
        data &= !0x18;
        self.phy_write(0xd068, data)?;
        self.phy_write(0xd06a, (swap_a & !0x7ff) | (swap_b & 0x7ff))?;
        data |= 0x18;
        self.phy_write(0xd068, data)?;
        self.phy_write(0xd06a, (swap_b & !0x7ff) | (swap_a & 0x7ff))?;
        data = (data & !0x18) | 8;
        self.phy_write(0xd068, data)?;
        swap_a = self.phy_read(0xd06a)?;
        data = (data & !0x18) | 0x10;
        self.phy_write(0xd068, data)?;
        swap_b = self.phy_read(0xd06a)?;
        data = (data & !0x18) | 8;
        self.phy_write(0xd068, data)?;
        self.phy_write(0xd06a, (swap_a & !0x7ff) | (swap_b & 0x7ff))?;
        data = (data & !0x18) | 0x10;
        self.phy_write(0xd068, data)?;
        self.phy_write(0xd06a, (swap_b & !0x7ff) | (swap_a & 0x7ff))?;
        for (a, b) in [(0xbd5a, 0xbd5c), (0xbc18, 0xbc1a)] {
            swap_a = self.phy_read(a)?;
            swap_b = self.phy_read(b)?;
            self.phy_write(
                a,
                (swap_a & !0x1f1f) | ((swap_b & 0x1f) << 8) | ((swap_b >> 8) & 0x1f),
            )?;
            self.phy_write(
                b,
                (swap_b & !0x1f1f) | ((swap_a & 0x1f) << 8) | ((swap_a >> 8) & 0x1f),
            )?;
        }
        Ok(())
    }

    fn hardware_phy_8156a(&mut self, firmware: Option<&Firmware<'_>>) -> Result<(), BlockError> {
        let misc = self.read(USB, USB_MISC_0, 2)?;
        if misc & PCUT_STATUS != 0 {
            self.write(USB, USB_MISC_0, 2, misc & !PCUT_STATUS)?;
        }
        let state = self.phy_state(None)?;
        if let Some(firmware) = firmware {
            self.upload_firmware(firmware, state == PHY_STAT_EXT_INIT)?;
        }
        if state == PHY_STAT_EXT_INIT {
            self.phy_modify(0xa468, (1 << 3) | (1 << 1), 0)?;
        }
        self.aldps(false)?;
        self.modify(PLA, PLA_EEE_CR, 2, EEE_RX_EN | EEE_TX_EN, 0)?;
        self.phy_modify(OCP_EEE_CFG, EEE10_EN, 0)?;
        self.phy_write(OCP_EEE_ADV, 0)?;
        self.phy_modify(OCP_EEE_ADV2, MDIO_EEE_2500_5000, 0)?;
        self.phy_state(Some(PHY_STAT_LAN_ON))?;
        self.modify(PLA, PLA_PHY_PWR, 2, 0, PFM_PWM_SWITCH)?;
        match self.revision.0 {
            0x7020 => self.tune_8156a10()?,
            0x7030 => {
                self.tune_8156a11()?;
                self.mdi_swap_8156a11()?;
                self.phy_modify(OCP_INTR_EN, 0, INTR_SPEED_FORCE)?;
            }
            _ => return Err(BlockError::Unsupported("RTL8156A exact analogue revision")),
        }
        self.sram_modify(SRAM_GREEN_CFG as u16, 0, GREEN_ETH_EN as u16)?;
        self.phy_modify(0xa428, 1 << 9, 0)?;
        self.phy_modify(0xa5ea, 1, 0)?;
        self.aldps(true)?;
        self.phy_modify(MII_ADVERTISE, 0, 0x0c00)?;
        self.u2p3(true)
    }

    fn hardware_phy_8156(&mut self, firmware: Option<&Firmware<'_>>) -> Result<(), BlockError> {
        if self.revision.is_8156a() {
            self.hardware_phy_8156a(firmware)
        } else if self.revision.is_8156b() {
            self.hardware_phy_8156b(firmware)
        } else {
            Err(BlockError::Unsupported("RTL8156 exact PHY callback"))
        }
    }

    fn autoneg_8156(&mut self) -> Result<(), BlockError> {
        self.phy_modify(MII_ADVERTISE, 0x01e0, ADVERTISE_10_100_PAUSE)?;
        self.phy_modify(OCP_BASE_MII + 18, 0x0300, 0x0200)?;
        // rtl8152_probe advertises 2.5G only at SuperSpeed/Plus. USB2 remains
        // gigabit-advertising even though the same PHY could negotiate 2.5G.
        if self.revision.supports_2500() {
            self.phy_modify(
                OCP_10GBT_CTRL,
                MDIO_ADV_MULTIGIG_MASK,
                if self.usb_speed >= SUPER_SPEED {
                    MDIO_ADV_2500
                } else {
                    0
                },
            )?;
        }
        self.phy_write(MII_BMCR, BMCR_ANENABLE_RESTART | BMCR_RESET)?;
        let mapped = self.phy_address(MII_BMCR)?;
        self.io.delay_us(20_000);
        self.poll(PLA, mapped, 2, BMCR_RESET, 0, (50, 20_000))
    }

    pub(super) fn initialize_8156(
        &mut self,
        firmware: Option<&Firmware<'_>>,
    ) -> Result<(), BlockError> {
        self.modify(USB, USB_ECM_OP, 1, EN_ALL_SPEED, 0)?;
        self.write(USB, USB_SPEED_OPTION, 2, 0)?;
        self.modify(USB, USB_ECM_OPTION, 2, 0, BYPASS_MAC_RESET)?;
        if self.revision.is_8156b() {
            self.modify(USB, USB_U2P3_CTRL, 2, 0, RX_DETECT8)?;
        }
        self.u1u2_8153b(false)?;
        if matches!(self.revision.0, 0x7410 | 0x7420) {
            self.wait_flash_8156b()?;
        }
        self.poll(
            PLA,
            PLA_BOOT_CTRL,
            2,
            AUTOLOAD_DONE,
            AUTOLOAD_DONE,
            (500, 20_000),
        )?;
        if self.phy_state(None)? == PHY_STAT_EXT_INIT {
            self.phy_modify(0xa468, (1 << 3) | (1 << 1), 0)?;
            if self.revision.is_8156b() {
                self.phy_modify(0xa466, 1, 0)?;
            }
        }
        let mapped = self.phy_address(MII_BMCR)?;
        let bmcr = self.read(PLA, mapped, 2)?;
        if bmcr & BMCR_PDOWN != 0 {
            self.write(PLA, mapped, 2, bmcr & !BMCR_PDOWN)?;
        }
        self.phy_state(Some(PHY_STAT_LAN_ON))?;
        self.u2p3(false)?;
        self.write(USB, USB_MSC_TIMER, 2, 0x0fff)?;
        self.write(USB, USB_U1U2_TIMER, 2, 500)?;
        self.modify(USB, USB_POWER_CUT, 2, PWR_EN, 0)?;
        self.modify(USB, USB_MISC_0, 2, PCUT_STATUS, 0)?;
        self.modify(USB, USB_POWER_CUT, 1, UPS_EN | USP_PREWAKE, 0)?;
        self.modify(USB, USB_MISC_2, 1, UPS_FORCE_PWR_DOWN, 0)?;
        if matches!(self.revision.0, 0x7410 | 0x7420) {
            self.modify(USB, USB_UPHY_XTAL, 2, OOBS_POLLING, 0)?;
        }
        if self.read(USB, USB_MISC_0, 2)? & PCUT_STATUS != 0 {
            self.hardware_phy_8156(firmware)?;
            self.autoneg_8156()?;
        }
        self.queue_wake_off()?;
        self.write(PLA, PLA_CRWECR, 1, 0xc0)?;
        self.modify(PLA, PLA_CONFIG34, 2, LINK_OFF_WAKE_EN, 0)?;
        self.write(PLA, PLA_CRWECR, 1, 0)?;
        if self.usb_speed >= SUPER_SPEED {
            self.u1u2_8153b(true)?;
        }
        if self.revision.is_8156b() {
            self.modify(PLA, PLA_RCR, 2, SLOT_EN, 0)?;
            self.modify(PLA, PLA_CPCR, 2, 0, FLOW_CTRL_EN)?;
            self.write(USB, USB_FC_TIMER, 2, CTRL_TIMER_EN | (600 / 8))?;
            let mut control = self.read(USB, USB_FW_CTRL, 2)?;
            if self.read(PLA, PLA_POL_GPIO_CTRL, 2)? & DACK_DET_EN == 0 {
                control |= FLOW_CTRL_PATCH_2;
            }
            self.write(USB, USB_FW_CTRL, 2, control & !AUTO_SPEEDUP)?;
            self.modify(USB, USB_FW_TASK, 2, 0, FC_PATCH_TASK)?;
        }
        self.write(PLA, PLA_MAC_PWR_CTRL, 2, 0x0403)?;
        self.modify(
            PLA,
            PLA_MAC_PWR_CTRL2,
            2,
            EEE_SPDWN_RATIO_MASK,
            MAC_CLK_SPDWN_EN | 3,
        )?;
        self.modify(PLA, PLA_MAC_PWR_CTRL3, 2, PLA_MCU_SPDWN_EN, 0)?;
        let status = self.read(PLA, PLA_PHYSTATUS, 2)?;
        self.modify(
            PLA,
            PLA_EXTRA_STATUS,
            2,
            CUR_LINK_OK,
            POLL_LINK_CHG
                | if status & PHYSTATUS_LINK != 0 {
                    CUR_LINK_OK
                } else {
                    0
                },
        )?;
        self.modify(USB, USB_USB_CTRL, 2, RX_AGG_DISABLE | RX_ZERO_EN, 0)?;
        if self.revision.is_8156a() {
            self.modify(USB, USB_BMU_CONFIG, 1, 0, ACT_ODMA)?;
        }
        let force = self.phy_read(0xa5b4)?;
        if force & (1 << 15) != 0 {
            self.phy_write(0xa5b4, force & !(1 << 15))?;
        }
        self.modify(PLA, PLA_RSTTALLY, 2, 0, TALLY_RESET)?;
        self.hardware_phy_8156(firmware)?;
        self.autoneg_8156()?;
        self.up_8156()
    }

    pub(super) fn flow_control_8156(&mut self) -> Result<(), BlockError> {
        self.write(PLA, PLA_RX_FIFO_FULL, 2, 512)?;
        self.write(PLA, PLA_RX_FIFO_EMPTY, 2, 1024)
    }

    fn up_8156(&mut self) -> Result<(), BlockError> {
        self.u1u2_8153b(false)?;
        self.u2p3(false)?;
        self.aldps(false)?;
        self.modify(PLA, PLA_MISC_1, 2, 0, RXDY_GATED_EN)?;
        self.write(PLA, PLA_TEREDO_CFG, 1, 0xff)?;
        self.write(PLA, PLA_WDT6_CTRL, 2, WDT6_SET_MODE)?;
        self.write(PLA, PLA_REALWOW_TIMER, 2, 0)?;
        self.write(PLA, PLA_TEREDO_TIMER, 4, 0)?;
        self.modify(PLA, PLA_RCR, 4, RCR_ACPT_ALL, 0)?;
        self.nic_reset()?;
        self.reset_bmu()?;
        self.modify(PLA, PLA_OOB_CTRL, 1, NOW_IS_OOB, 0)?;
        self.modify(PLA, PLA_SFF_STS_7, 2, MCU_BORW_EN, 0)?;
        // Unlike8153 first_init,8156_up has no link-list reinitialization.
        self.modify(PLA, PLA_RCR1, 2, OUTER_VLAN | INNER_VLAN, 0)?;
        self.write(PLA, PLA_RMS, 2, 1522)?;
        self.write(PLA, PLA_MTPS, 1, MTPS_JUMBO)?;
        self.flow_control_8156()?;
        self.write(PLA, PLA_TXFIFO_CTRL, 2, 512 / 64)?;
        self.write(PLA, PLA_TXFIFO_FULL, 2, 2048 / 16)?;
        if self.revision.is_8156a() {
            self.modify(USB, USB_BMU_CONFIG, 2, 0, ACT_ODMA)?;
        }
        self.modify(PLA, PLA_RXFIFO_FULL, 2, RXFIFO_FULL_MASK, 8)?;
        self.modify(PLA, PLA_MAC_PWR_CTRL3, 2, PLA_MCU_SPDWN_EN, 0)?;
        self.modify(USB, USB_SPEED_OPTION, 2, RG_PWRDN_EN | ALL_SPEED_OFF, 0)?;
        self.write(USB, USB_RX_BUF_TH, 4, 0x0060_0400)?;
        // Wake filters were preserved throughout this non-suspending path.
        self.aldps(true)?;
        self.u2p3(true)?;
        if self.usb_speed >= SUPER_SPEED {
            self.u1u2_8153b(true)?;
        }
        Ok(())
    }

    pub(super) fn enable_8156(&mut self, status: u32) -> Result<(), BlockError> {
        if self.revision.is_8156b() {
            self.modify(USB, USB_RX_AGGR_NUM, 2, RX_AGGR_NUM_MASK, 0)?;
        }
        self.write(USB, USB_RX_EARLY_TIMEOUT, 2, 640 / 8)?;
        self.write(USB, USB_RX_EXTRA_AGGR_TMR, 2, 15000 / 8)?;
        self.write(
            USB,
            USB_RX_EARLY_SIZE,
            2,
            ((self.receive_bytes() - 1554) / 8) as u32,
        )?;
        let half = status & (PHYSTATUS_10 | 8) != 0 && status & 1 == 0;
        self.modify(
            PLA,
            PLA_TCR1,
            2,
            IFG_MASK,
            if half { IFG_144NS } else { IFG_96NS },
        )?;
        self.modify(
            PLA,
            PLA_MAC_PWR_CTRL4,
            2,
            TX10MIDLE_EN,
            if half { 0 } else { TX10MIDLE_EN },
        )?;
        self.modify(
            PLA,
            PLA_MAC_PWR_CTRL4,
            2,
            IDLE_SPDWN_EN,
            if status & PHYSTATUS_2500 != 0 {
                0
            } else {
                IDLE_SPDWN_EN
            },
        )?;
        if self.revision.is_8156a() {
            if status & PHYSTATUS_1000 != 0 {
                self.write(PLA, PLA_EEE_TXTWSYS, 2, 0x11)?;
            } else if status & PHYSTATUS_500 != 0 {
                self.write(PLA, PLA_EEE_TXTWSYS, 2, 0x3d)?;
            }
        }
        if self.usb_speed == super::super::super::xhci::HIGH_SPEED {
            self.modify(
                USB,
                USB_L1_CTRL,
                2,
                0xf,
                if status & PHYSTATUS_FLOW == PHYSTATUS_FLOW {
                    0xf
                } else {
                    1
                },
            )?;
        }
        self.modify(USB, USB_FW_TASK, 2, FC_PATCH_TASK, 0)?;
        self.io.delay_us(1000);
        self.modify(USB, USB_FW_TASK, 2, 0, FC_PATCH_TASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::ethernet::{
        firmware::tests::synthetic_upload,
        rtl815x::{FirmwareIo, FirmwareModel},
    };
    use alloc::rc::Rc;
    use core::cell::RefCell;

    fn seed(model: &mut FirmwareModel, mdi: bool) {
        model
            .core
            .set(USB, USB_UPS_CFG, 2, if mdi { MID_REVERSE } else { 0 });
        model.core.set(PLA, 0xd068, 2, if mdi { 2 } else { 0 });
        model.mdi = [0x8111, 0x9222, 0xa333, 0xc444];
        model.core.set(PLA, 0xbd5a, 2, 0x1122);
        model.core.set(PLA, 0xbd5c, 2, 0x3344);
        model.core.set(PLA, 0xbc18, 2, 0x5566);
        model.core.set(PLA, 0xbc1a, 2, 0x7788);
        model.core.set(PLA, PLA_RCR1, 2, 0xa5ff);
        model.core.set(PLA, PLA_CPCR, 2, CPCR_RX_VLAN);
        model.core.set(PLA, OCP_EEE_ADV2, 2, 0xffff);
        model.core.set(PLA, OCP_10GBT_CTRL, 2, 0xffff);
        model.core.set(PLA, PLA_RXFIFO_CTRL0, 4, 0xaaaa_5555);
        model.core.set(PLA, PLA_TXFIFO_CTRL + 4, 4, 0x1234_abcd);
    }

    #[test]
    fn rtl8156a_exact_revision_phy_sram2_mdi_and_48k_receive() {
        for revision in [0x7020, 0x7030] {
            let bytes = if revision == 0x7030 {
                synthetic_upload(revision)
            } else {
                Vec::new()
            };
            let firmware =
                (!bytes.is_empty()).then(|| Firmware::parse(&bytes, Revision(revision)).unwrap());
            for speed in [1, 3, 4, 5] {
                for mdi in [false, true] {
                    let model = Rc::new(RefCell::new(FirmwareModel::new(revision, &bytes)));
                    seed(&mut model.borrow_mut(), mdi);
                    let (mut chip, _) = Chip::attach_with_firmware(
                        FirmwareIo(model.clone()),
                        Revision(revision),
                        speed,
                        firmware.as_ref(),
                    )
                    .unwrap();
                    assert!(chip.initialized);
                    assert_eq!(chip.receive_bytes(), 49152);
                    {
                        let hw = model.borrow();
                        assert_eq!(
                            hw.core.get(PLA, OCP_10GBT_CTRL, 2) & MDIO_ADV_MULTIGIG_MASK,
                            if speed >= SUPER_SPEED {
                                MDIO_ADV_2500
                            } else {
                                0
                            }
                        );
                        assert_eq!(hw.core.get(PLA, OCP_EEE_ADV2, 2), 0xfffc);
                        assert_eq!(hw.core.get(PLA, PLA_RCR1, 2), 0xa53f);
                        assert_eq!(hw.core.get(PLA, PLA_CPCR, 2) & CPCR_RX_VLAN, CPCR_RX_VLAN);
                        assert_eq!(hw.core.get(PLA, PLA_RXFIFO_CTRL0, 4), 0xa008_5555);
                        assert_eq!(hw.core.get(PLA, PLA_TXFIFO_CTRL, 4), 0x0080_0008);
                        assert_eq!(hw.core.get(PLA, PLA_TXFIFO_CTRL + 4, 4), 0x1234_abcd);
                        assert_eq!(hw.core.get(PLA, PLA_RX_FIFO_FULL, 2), 512);
                        assert_eq!(hw.core.get(PLA, PLA_RX_FIFO_EMPTY, 2), 1024);
                        assert_eq!(hw.core.get(USB, USB_RX_BUF_TH, 4), 0x0060_0400);
                        if revision == 0x7020 {
                            assert_eq!(hw.sram[&0x819f], 0xddb6);
                            assert_eq!(hw.core.get(PLA, 0xad16, 2) & 0x3ff, 6);
                        } else {
                            assert_eq!(hw.sram2[&0x80a2], 0x153);
                            assert_eq!(hw.sram2[&0x809c], 0x153);
                            assert_eq!(hw.sram2[&0x8157] & 0xff00, 0x500);
                            assert_eq!(hw.core.get(PLA, OCP_SYSCLK_CFG, 2), 5 << 8);
                            if mdi {
                                assert_eq!(hw.mdi, [0x8444, 0x9333, 0xa222, 0xc111]);
                                assert_eq!(hw.core.get(PLA, 0xbd5a, 2), 0x0433);
                                assert_eq!(hw.core.get(PLA, 0xbd5c, 2), 0x2251);
                                assert_eq!(hw.core.get(PLA, 0xbc18, 2), 0x4877);
                                assert_eq!(hw.core.get(PLA, 0xbc1a, 2), 0x6695);
                            }
                        }
                    }
                    for status in [0x06, 0x07, 0x0a, 0x0b, 0x13, 0x113, 0x403, 0x473] {
                        model.borrow_mut().core.phy_status = status;
                        let before = model.borrow().core.trace.len();
                        assert!(chip.carrier().unwrap());
                        {
                            let hw = model.borrow();
                            let writes = &hw.core.trace[before..];
                            let flow = writes
                                .iter()
                                .position(|(request, _)| {
                                    request[0] == 0x40
                                        && u16::from_le_bytes([request[2], request[3]])
                                            == (PLA_RX_FIFO_FULL as u16 & !3)
                                })
                                .unwrap();
                            let eee = writes
                                .iter()
                                .position(|(request, _)| {
                                    request[0] == 0x40
                                        && u16::from_le_bytes([request[2], request[3]])
                                            == (PLA_EEEP_CR as u16 & !3)
                                })
                                .unwrap();
                            assert!(flow < eee); // rtl8156_enable requires pause setup before EEE+.
                            assert_eq!(hw.core.get(USB, USB_RX_EARLY_TIMEOUT, 2), 80);
                            assert_eq!(hw.core.get(USB, USB_RX_EXTRA_AGGR_TMR, 2), 1875);
                            assert_eq!(hw.core.get(USB, USB_RX_EARLY_SIZE, 2), 5949);
                            assert_eq!(
                                hw.core.get(PLA, PLA_MAC_PWR_CTRL4, 2) & IDLE_SPDWN_EN,
                                if status & PHYSTATUS_2500 != 0 {
                                    0
                                } else {
                                    IDLE_SPDWN_EN
                                }
                            );
                            if speed == 3 {
                                assert_eq!(
                                    hw.core.get(USB, USB_L1_CTRL, 2) & 15,
                                    if status & PHYSTATUS_FLOW == PHYSTATUS_FLOW {
                                        15
                                    } else {
                                        1
                                    }
                                );
                            }
                        }
                        chip.stop().unwrap();
                        assert_eq!(model.borrow().core.get(PLA, PLA_RX_FIFO_FULL, 2), 0);
                        assert_eq!(model.borrow().core.get(PLA, PLA_RX_FIFO_EMPTY, 2), 0);
                    }
                }
            }
        }
    }

    #[test]
    fn rtl8156a_observed_phy_upload_modes_and_ups_reload_are_distinct() {
        let bytes = synthetic_upload(0x7030);
        let firmware = Firmware::parse(&bytes, Revision(0x7030)).unwrap();
        for state in [PHY_STAT_LAN_ON, PHY_STAT_PWRDN, PHY_STAT_EXT_INIT] {
            let model = Rc::new(RefCell::new(FirmwareModel::new(0x7030, &bytes)));
            model.borrow_mut().phy_states.extend([
                PHY_STAT_LAN_ON,
                PHY_STAT_LAN_ON,
                state,
                PHY_STAT_LAN_ON,
            ]);
            let (chip, _) = Chip::attach_with_firmware(
                FirmwareIo(model.clone()),
                Revision(0x7030),
                4,
                Some(&firmware),
            )
            .unwrap();
            assert!(chip.initialized);
            assert!(model.borrow().phy_states.is_empty());
            assert_eq!(
                model.borrow().core.get(PLA, 0xa468, 2) & ((1 << 3) | (1 << 1)),
                0
            );
        }
        let model = Rc::new(RefCell::new(FirmwareModel::new(0x7020, &[])));
        model.borrow_mut().ups_exit_power_cut = true;
        let (chip, _) =
            Chip::attach_with_firmware(FirmwareIo(model.clone()), Revision(0x7020), 4, None)
                .unwrap();
        assert!(chip.initialized);
        assert!(!model.borrow().ups_exit_power_cut);
        let resets = model
            .borrow()
            .core
            .trace
            .iter()
            .filter(|(request, bytes)| {
                request[0] == 0x40
                    && request[2..4] == [0, 0xb4]
                    && bytes.len() == 4
                    && u16::from_le_bytes([bytes[0], bytes[1]]) & BMCR_RESET as u16 != 0
            })
            .count();
        assert_eq!(resets, 2);
    }

    #[test]
    fn rtl8156a_every_mdi_startup_transfer_failure_and_deadline_refuses_ready() {
        let bytes = synthetic_upload(0x7030);
        let firmware = Firmware::parse(&bytes, Revision(0x7030)).unwrap();
        let model = Rc::new(RefCell::new(FirmwareModel::new(0x7030, &bytes)));
        seed(&mut model.borrow_mut(), true);
        Chip::attach_with_firmware(
            FirmwareIo(model.clone()),
            Revision(0x7030),
            4,
            Some(&firmware),
        )
        .unwrap();
        let count = model.borrow().core.trace.len();
        for at in 0..count {
            let model = Rc::new(RefCell::new(FirmwareModel::new(0x7030, &bytes)));
            seed(&mut model.borrow_mut(), true);
            model.borrow_mut().core.fail_at = Some(at);
            assert!(
                Chip::attach_with_firmware(
                    FirmwareIo(model.clone()),
                    Revision(0x7030),
                    4,
                    Some(&firmware)
                )
                .is_err()
            );
            assert_eq!(model.borrow().core.trace.len(), at + 1);
        }
        for case in 0..6 {
            let model = Rc::new(RefCell::new(FirmwareModel::new(0x7030, &bytes)));
            {
                let mut hw = model.borrow_mut();
                match case {
                    0 => hw.core.set(PLA, PLA_BOOT_CTRL, 2, 0),
                    1 => hw.core.set(PLA, OCP_PHY_STATUS, 2, 1),
                    2 => hw.core.set(PLA, 0xe000, 2, 0),
                    3 => hw.core.stuck_phy = true,
                    4 => hw.core.stuck_reset = true,
                    _ => hw.stuck_patch = true,
                }
            }
            assert!(matches!(
                Chip::attach_with_firmware(FirmwareIo(model), Revision(0x7030), 4, Some(&firmware)),
                Err(BlockError::Timeout)
            ));
        }
    }
    #[test]
    #[ignore = "requires pinned unchanged Linux RTL8156 enable trace"]
    fn unchanged_linux_rtl8156a_enable_register_effects() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let trace = std::fs::read_to_string(std::env::var("STELA_RTL8156A_ENABLE_ORACLE").unwrap())
            .unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
            "28c79c6b9b29e32a608a02816ce818bded7acfc95746039c9421ca89eb9489a9"
        );
        let fields = [
            (USB, USB_RX_EARLY_TIMEOUT),
            (USB, USB_RX_EXTRA_AGGR_TMR),
            (USB, USB_RX_EARLY_SIZE),
            (PLA, PLA_TCR1),
            (PLA, PLA_MAC_PWR_CTRL4),
            (USB, USB_L1_CTRL),
            (PLA, PLA_EEE_TXTWSYS),
            (PLA, PLA_RX_FIFO_FULL),
            (PLA, PLA_RX_FIFO_EMPTY),
            (USB, USB_FW_TASK),
            (PLA, PLA_EEEP_CR),
        ];
        let mut count = 0;
        for line in trace.lines() {
            let v: Vec<_> = line.split_whitespace().collect();
            assert_eq!(v.len(), 14);
            let revision = u16::from_str_radix(v[0], 16).unwrap();
            let speed = v[1].parse::<u8>().unwrap();
            let status = v[2].parse::<u32>().unwrap();
            let bytes = if revision == 0x7030 {
                synthetic_upload(revision)
            } else {
                Vec::new()
            };
            let firmware =
                (!bytes.is_empty()).then(|| Firmware::parse(&bytes, Revision(revision)).unwrap());
            let model = Rc::new(RefCell::new(FirmwareModel::new(revision, &bytes)));
            let (mut chip, _) = Chip::attach_with_firmware(
                FirmwareIo(model.clone()),
                Revision(revision),
                speed,
                firmware.as_ref(),
            )
            .unwrap();
            for (bank, address) in fields {
                model.borrow_mut().core.set(bank, address, 2, 0xa55a);
            }
            model.borrow_mut().core.phy_status = status;
            assert!(chip.carrier().unwrap());
            for ((bank, address), expected) in fields.into_iter().zip(&v[3..]) {
                assert_eq!(
                    model.borrow().core.get(bank, address, 2),
                    expected.parse::<u32>().unwrap(),
                    "{line}"
                );
            }
            count += 1;
        }
        assert_eq!(count, 64);
    }

    #[test]
    #[ignore = "requires immutable real RTL8156A firmware fixture"]
    fn real_firmware_8156a_full_startup_link_and_stop() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let (name, revision, _, hash) = crate::usb::ethernet::firmware::tests::FIXTURES
            .iter()
            .copied()
            .find(|(_, revision, _, _)| *revision == 0x7030)
            .unwrap();
        let directory = std::env::var("STELA_RTL815X_FIRMWARE").unwrap();
        let bytes = std::fs::read(std::path::Path::new(&directory).join(name)).unwrap();
        assert_eq!(alloc::format!("{:x}", Sha256::digest(&bytes)), hash);
        let firmware = Firmware::parse(&bytes, Revision(revision)).unwrap();
        for speed in [1, 3, 4, 5] {
            let model = Rc::new(RefCell::new(FirmwareModel::new(revision, &bytes)));
            seed(&mut model.borrow_mut(), true);
            let (mut chip, _) = Chip::attach_with_firmware(
                FirmwareIo(model.clone()),
                Revision(revision),
                speed,
                Some(&firmware),
            )
            .unwrap();
            assert!(chip.initialized && chip.carrier().unwrap());
            chip.stop().unwrap();
            assert_eq!(model.borrow().core.get(PLA, PLA_CR, 1), 0);
        }
    }
}
