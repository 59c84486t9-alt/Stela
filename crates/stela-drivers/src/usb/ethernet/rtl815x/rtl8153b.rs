// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
//! RTL8153B 08/09: independent r8153b_init/hw_phy_cfg/up, efuse calibration
//! and bank-specific upload/PHY power-cut handling. C explicitly shares the
//! PHY routine; its initialization/up remains separate. 8156 never enters here.
use super::super::firmware::Firmware;
use super::*;

impl<C: Control> Chip<C> {
    pub(super) fn u1u2_8153b(&mut self, enable: bool) -> Result<(), BlockError> {
        self.modify(
            USB,
            USB_LPM_CONFIG,
            2,
            LPM_U1U2_EN,
            if enable { LPM_U1U2_EN } else { 0 },
        )
    }

    pub(super) fn hardware_phy_8153b(
        &mut self,
        firmware: Option<&Firmware<'_>>,
    ) -> Result<(), BlockError> {
        let misc = self.read(USB, USB_MISC_0, 2)?;
        if misc & PCUT_STATUS != 0 {
            self.write(USB, USB_MISC_0, 2, misc & !PCUT_STATUS)?;
        }
        self.aldps(false)?;
        self.modify(PLA, PLA_EEE_CR, 2, EEE_RX_EN | EEE_TX_EN, 0)?;
        self.phy_modify(OCP_EEE_CFG, EEE10_EN, 0)?;
        self.phy_write(OCP_EEE_ADV, 0)?;
        self.write(USB, USB_U1U2_TIMER, 2, 500)?;
        let state = self.phy_state(None)?;
        let power_cut = matches!(state, PHY_STAT_PWRDN | PHY_STAT_EXT_INIT);
        if let Some(firmware) = firmware {
            self.upload_firmware(firmware, power_cut)?;
        }
        if power_cut {
            self.phy_modify(MII_BMCR, BMCR_PDOWN, 0)?;
        }
        // Linux init selects GREEN_ETHERNET for 08/09; these are its actual
        // per-speed analogue settings, not the older A impedance sequence.
        self.sram_write(0x8045, 0)?;
        self.sram_write(0x804d, 0x1222)?;
        self.sram_write(0x805d, 0x0022)?;
        let green = self.sram_read(SRAM_GREEN_CFG as u16)?;
        self.sram_write(SRAM_GREEN_CFG as u16, green | GREEN_ETH_EN as u16)?;
        let green = self.sram_read(SRAM_GREEN_CFG as u16)?;
        self.sram_write(SRAM_GREEN_CFG as u16, green | R_TUNE_EN as u16)?;
        self.phy_modify(OCP_NCTL_CFG, 0, PGA_RETURN_EN)?;
        // Preserve the adapter's actual efuse calibration. Bit3 in the 17-bit
        // efuse word is dummy; all-one calibration means no programmed value.
        self.write(PLA, PLA_EFUSE_CMD, 2, EFUSE_READ_CMD | 0x7d)?;
        let high = (self.read(PLA, PLA_EFUSE_CMD, 2)? & EFUSE_DATA_BIT16) << 9;
        let fuse = high | self.read(PLA, PLA_EFUSE_DATA, 2)?;
        let offset = ((fuse & 0x1fff0) >> 1) | (fuse & 7);
        if offset != 0xffff {
            self.phy_write(OCP_ADC_IOFFSET, offset)?;
        }
        let mapped = self.phy_address(0xc426)?;
        let counter = self.read(PLA, mapped, 2)? & 0x3fff;
        if let Some(timer) = 16_000_000u32.checked_div(counter) {
            self.modify(
                USB,
                USB_UPS_CFG,
                2,
                SAW_CNT_1MS_MASK,
                timer & SAW_CNT_1MS_MASK,
            )?;
        }
        self.modify(PLA, PLA_PHY_PWR, 2, 0, PFM_PWM_SWITCH)?;
        self.patch_request(true, true)?;
        self.phy_modify(OCP_POWER_CFG, 0, EEE_CLKDIV_EN)?;
        self.phy_modify(
            OCP_DOWN_SPEED,
            0,
            EN_EEE_CMODE | EN_EEE_1000 | EN_10M_CLKDIV,
        )?;
        self.phy_write(OCP_SYSCLK_CFG, 0)?;
        self.phy_write(OCP_SYSCLK_CFG, 5 << 4)?;
        self.patch_request(false, true)?;
        self.aldps(true)?;
        self.phy_modify(MII_ADVERTISE, 0x01e0, ADVERTISE_10_100_PAUSE)?;
        self.phy_modify(OCP_BASE_MII + 18, 0x0300, 0x0200)?;
        self.phy_write(MII_BMCR, BMCR_ANENABLE_RESTART | BMCR_RESET)?;
        let mapped = self.phy_address(MII_BMCR)?;
        self.io.delay_us(20_000);
        self.poll(PLA, mapped, 2, BMCR_RESET, 0, (50, 20_000))
    }

    pub(super) fn initialize_8153b(
        &mut self,
        firmware: Option<&Firmware<'_>>,
    ) -> Result<(), BlockError> {
        self.u1u2_8153b(false)?;
        self.poll(
            PLA,
            PLA_BOOT_CTRL,
            2,
            AUTOLOAD_DONE,
            AUTOLOAD_DONE,
            (500, 20_000),
        )?;
        self.phy_state(None)?;
        let mapped = self.phy_address(MII_BMCR)?;
        let bmcr = self.read(PLA, mapped, 2)?;
        if bmcr & BMCR_PDOWN != 0 {
            self.write(PLA, mapped, 2, bmcr & !BMCR_PDOWN)?;
        }
        self.phy_state(Some(PHY_STAT_LAN_ON))?;
        self.u2p3(false)?;
        self.write(USB, USB_MSC_TIMER, 2, 0x0fff)?;
        // B retains PHASE2_EN when disabling power-cut (A clears it).
        self.modify(USB, USB_POWER_CUT, 2, PWR_EN, 0)?;
        self.modify(USB, USB_MISC_0, 2, PCUT_STATUS, 0)?;
        self.modify(USB, USB_POWER_CUT, 1, UPS_EN | USP_PREWAKE, 0)?;
        self.modify(USB, USB_MISC_2, 1, UPS_FORCE_PWR_DOWN, 0)?;
        // A newly observed power-cut requires the donor's PHY reload before
        // continuing normal init; no optimistic reuse of the prior PHY state.
        if self.read(USB, USB_MISC_0, 2)? & PCUT_STATUS != 0 {
            self.poll(
                PLA,
                PLA_BOOT_CTRL,
                2,
                AUTOLOAD_DONE,
                AUTOLOAD_DONE,
                (500, 20_000),
            )?;
            self.hardware_phy_8153b(firmware)?;
        }
        self.queue_wake_off()?;
        // Preserve wake filters; this host never arms runtime USB suspend.
        self.write(PLA, PLA_CRWECR, 1, 0xc0)?;
        self.modify(PLA, PLA_CONFIG34, 2, LINK_OFF_WAKE_EN, 0)?;
        self.write(PLA, PLA_CRWECR, 1, 0)?;
        let linked = self.read(PLA, PLA_PHYSTATUS, 2)? & PHYSTATUS_LINK != 0;
        self.modify(
            PLA,
            PLA_EXTRA_STATUS,
            2,
            CUR_LINK_OK,
            POLL_LINK_CHG | if linked { CUR_LINK_OK } else { 0 },
        )?;
        if self.usb_speed >= SUPER_SPEED {
            self.u1u2_8153b(true)?;
        }
        self.modify(PLA, PLA_MAC_PWR_CTRL2, 2, 0, MAC_CLK_SPDWN_EN)?;
        self.modify(PLA, PLA_MAC_PWR_CTRL3, 2, PLA_MCU_SPDWN_EN, 0)?;
        if self.revision.0 == 0x6010 && self.read(PLA, 0xdc00, 1)? & (1 << 5) != 0 {
            self.modify(PLA, PLA_PHY_PWR, 2, 0, TEST_IO_OFF)?;
        }
        self.modify(USB, USB_USB_CTRL, 2, RX_AGG_DISABLE | RX_ZERO_EN, 0)?;
        self.modify(PLA, PLA_RSTTALLY, 2, 0, TALLY_RESET)?;
        self.hardware_phy_8153b(firmware)?;
        // rtl8153b_up uses exactly r8153_first_init, while C has different FIFO.
        self.u1u2_8153b(false)?;
        self.u2p3(false)?;
        self.aldps(false)?;
        self.first_init_8153()?;
        self.write(USB, USB_RX_BUF_TH, 4, RX_THR_B)?;
        self.modify(PLA, PLA_MAC_PWR_CTRL3, 2, PLA_MCU_SPDWN_EN, 0)?;
        self.aldps(true)?;
        if self.usb_speed >= SUPER_SPEED {
            self.u1u2_8153b(true)?;
        }
        Ok(())
    }

    pub(super) fn enable_8153b(&mut self, status: u32) -> Result<(), BlockError> {
        self.write(USB, USB_RX_EARLY_TIMEOUT, 2, 128 / 8)?;
        self.write(USB, USB_RX_EXTRA_AGGR_TMR, 2, 15000 / 8)?;
        self.write(
            USB,
            USB_RX_EARLY_SIZE,
            2,
            ((self.receive_bytes() - 1554) / 8) as u32,
        )?;
        let half = status & (PHYSTATUS_10 | 0x08) != 0 && status & 1 == 0;
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
        if matches!(self.revision.0, 0x6010 | 0x6400) {
            self.modify(USB, USB_FW_TASK, 2, FC_PATCH_TASK, 0)?;
            self.io.delay_us(1000);
            self.modify(USB, USB_FW_TASK, 2, 0, FC_PATCH_TASK)?;
        }
        Ok(())
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

    #[test]
    fn rtl8153b_actual_calibration_power_phy_and_receive_paths() {
        for revision in [0x6000, 0x6010] {
            let bytes = if revision == 0x6010 {
                synthetic_upload(revision)
            } else {
                Vec::new()
            };
            let firmware =
                (!bytes.is_empty()).then(|| Firmware::parse(&bytes, Revision(revision)).unwrap());
            for speed in [1, 3, 4, 5] {
                for (fuse, counter, test_io) in
                    [(0x1ffff, 0, false), (0x12345, 2000, true), (0, 1, false)]
                {
                    let model = Rc::new(RefCell::new(FirmwareModel::new(revision, &bytes)));
                    {
                        let mut hw = model.borrow_mut();
                        hw.efuse = fuse;
                        hw.core.set(PLA, OCP_ADC_IOFFSET, 2, 0xa55a);
                        hw.core.set(PLA, 0xc426, 2, counter);
                        hw.core.set(
                            USB,
                            USB_POWER_CUT,
                            2,
                            PWR_EN | PHASE2_EN | UPS_EN | USP_PREWAKE,
                        );
                        hw.core.set(USB, USB_UPS_CFG, 2, 0xa123);
                        hw.core
                            .set(PLA, 0xdc00, 1, if test_io { 1 << 5 } else { 0 });
                    }
                    let (mut chip, _) = Chip::attach_with_firmware(
                        FirmwareIo(model.clone()),
                        Revision(revision),
                        speed,
                        firmware.as_ref(),
                    )
                    .unwrap();
                    assert!(chip.initialized);
                    assert_eq!(chip.receive_bytes(), 32768);
                    {
                        let hw = model.borrow();
                        assert_eq!(hw.core.get(USB, USB_POWER_CUT, 2), PHASE2_EN);
                        assert_eq!(
                            hw.core.get(USB, USB_LPM_CONFIG, 2) & LPM_U1U2_EN,
                            if speed >= SUPER_SPEED { LPM_U1U2_EN } else { 0 }
                        );
                        assert_eq!(
                            hw.core.get(PLA, OCP_ADC_IOFFSET, 2),
                            if fuse == 0x1ffff {
                                0xa55a
                            } else {
                                ((fuse & 0x1fff0) >> 1) | (fuse & 7)
                            }
                        );
                        assert_eq!(
                            hw.core.get(USB, USB_UPS_CFG, 2),
                            match counter {
                                0 => 0xa123,
                                2000 => 0xaf40,
                                1 => 0xa400,
                                _ => unreachable!(),
                            }
                        );
                        assert_eq!(
                            hw.core.get(PLA, PLA_PHY_PWR, 2) & TEST_IO_OFF,
                            if revision == 0x6010 && test_io {
                                TEST_IO_OFF
                            } else {
                                0
                            }
                        );
                        assert_eq!(hw.sram[&0x8045], 0);
                        assert_eq!(hw.sram[&0x804d], 0x1222);
                        assert_eq!(hw.sram[&0x805d], 0x22);
                        assert_eq!(
                            hw.sram[&(SRAM_GREEN_CFG as u16)] & (GREEN_ETH_EN | R_TUNE_EN) as u16,
                            (GREEN_ETH_EN | R_TUNE_EN) as u16
                        );
                        assert_eq!(
                            hw.core.get(PLA, OCP_NCTL_CFG, 2) & PGA_RETURN_EN,
                            PGA_RETURN_EN
                        );
                        assert_eq!(hw.core.get(PLA, OCP_SYSCLK_CFG, 2), 5 << 4);
                        assert_eq!(hw.core.get(USB, USB_RX_BUF_TH, 4), RX_THR_B);
                        assert_eq!(hw.core.get(PLA, OCP_PHY_PATCH_CMD, 2) & PATCH_REQUEST, 0);
                    }
                    assert!(chip.carrier().unwrap());
                    {
                        let hw = model.borrow();
                        assert_eq!(hw.core.get(USB, USB_RX_EARLY_TIMEOUT, 2), 16);
                        assert_eq!(hw.core.get(USB, USB_RX_EXTRA_AGGR_TMR, 2), 1875);
                        assert_eq!(hw.core.get(USB, USB_RX_EARLY_SIZE, 2), (32768 - 1554) / 8);
                        assert_eq!(
                            hw.core.get(USB, USB_UPT_RXDMA_OWN, 1),
                            OWN_CLEAR | OWN_UPDATE
                        );
                        assert_eq!(
                            hw.core.get(USB, USB_FW_TASK, 2) & FC_PATCH_TASK,
                            if revision == 0x6010 { FC_PATCH_TASK } else { 0 }
                        );
                    }
                    chip.stop().unwrap();
                    assert_eq!(model.borrow().core.get(PLA, PLA_CR, 1), 0);
                }
            }
        }
    }

    #[test]
    fn rtl8153b_clears_w1c_teredo_events_with_one_byte_and_preserves_neighbors() {
        for revision in [0x6000, 0x6010] {
            let bytes = if revision == 0x6010 {
                synthetic_upload(revision)
            } else {
                Vec::new()
            };
            let firmware =
                (!bytes.is_empty()).then(|| Firmware::parse(&bytes, Revision(revision)).unwrap());
            let model = Rc::new(RefCell::new(FirmwareModel::new(revision, &bytes)));
            model
                .borrow_mut()
                .core
                .set(PLA, PLA_TEREDO_CFG, 4, 0x1234_abff);
            Chip::attach_with_firmware(
                FirmwareIo(model.clone()),
                Revision(revision),
                4,
                firmware.as_ref(),
            )
            .unwrap();
            assert_eq!(model.borrow().core.get(PLA, PLA_TEREDO_CFG, 4), 0x1234_ab00);
            let hw = model.borrow();
            let writes: Vec<_> = hw
                .core
                .trace
                .iter()
                .filter(|(request, _)| request[0] == 0x40 && request[2..4] == [0xbc, 0xc0])
                .collect();
            assert_eq!(writes.len(), 1);
            assert_eq!(writes[0].0[4..6], [0x11, 1]);
            assert_eq!(writes[0].1[0], 0xff);
        }
    }

    #[test]
    fn rtl8153b_power_cut_during_ups_exit_requires_an_extra_phy_reload() {
        let model = Rc::new(RefCell::new(FirmwareModel::new(0x6000, &[])));
        model.borrow_mut().ups_exit_power_cut = true;
        let (chip, _) =
            Chip::attach_with_firmware(FirmwareIo(model.clone()), Revision(0x6000), 4, None)
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
        assert_eq!(model.borrow().core.get(USB, USB_MISC_0, 2) & PCUT_STATUS, 0);
    }

    #[test]
    fn rtl8153b_reloads_observed_power_cut_phy_and_refuses_all_deadlines() {
        let bytes = synthetic_upload(0x6010);
        let firmware = Firmware::parse(&bytes, Revision(0x6010)).unwrap();
        for state in [PHY_STAT_LAN_ON, PHY_STAT_PWRDN, PHY_STAT_EXT_INIT] {
            let model = Rc::new(RefCell::new(FirmwareModel::new(0x6010, &bytes)));
            model
                .borrow_mut()
                .phy_states
                .extend([PHY_STAT_LAN_ON, PHY_STAT_LAN_ON, state]);
            let (chip, _) = Chip::attach_with_firmware(
                FirmwareIo(model.clone()),
                Revision(0x6010),
                4,
                Some(&firmware),
            )
            .unwrap();
            assert!(chip.initialized);
            assert!(model.borrow().phy_states.is_empty());
            assert_eq!(model.borrow().core.get(PLA, MII_BMCR, 2) & BMCR_PDOWN, 0);
        }
        for case in 0..6 {
            let model = Rc::new(RefCell::new(FirmwareModel::new(0x6000, &[])));
            {
                let mut hw = model.borrow_mut();
                match case {
                    0 => hw.core.set(PLA, PLA_BOOT_CTRL, 2, 0),
                    1 => hw.core.set(PLA, OCP_PHY_STATUS, 2, 1),
                    2 => hw.core.set(PLA, 0xe000, 2, 0),
                    3 => hw.core.stuck_phy = true,
                    4 => hw.core.stuck_list = true,
                    _ => hw.stuck_patch = true,
                }
            }
            assert!(matches!(
                Chip::attach_with_firmware(FirmwareIo(model), Revision(0x6000), 4, None),
                Err(BlockError::Timeout)
            ));
        }
    }

    #[test]
    #[ignore = "oracle: STELA_RTL8153B_LINK_ORACLE"]
    fn unchanged_linux_8153b_link_register_effects() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let trace =
            std::fs::read_to_string(std::env::var("STELA_RTL8153B_LINK_ORACLE").unwrap()).unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
            "8f3a8d6cc91aa85fe0408b578af853e2b8c5277a32a08c829cf4772db610f835"
        );
        let mut count = 0;
        for line in trace.lines() {
            let v: Vec<_> = line.split_whitespace().collect();
            assert_eq!(v.len(), 7);
            let revision = u16::from_str_radix(v[0], 16).unwrap();
            let speed = v[1].parse::<u8>().unwrap();
            let status = v[2].parse::<u32>().unwrap();
            let model = Rc::new(RefCell::new(FirmwareModel::new(revision, &[])));
            model
                .borrow_mut()
                .core
                .set(PLA, PLA_MAC_PWR_CTRL4, 2, 0xa55a);
            let mut chip = Chip::probe(FirmwareIo(model.clone()), Revision(revision)).unwrap();
            model.borrow_mut().core.set(PLA, PLA_TCR1, 2, 0xa55a);
            chip.usb_speed = speed;
            chip.enable_8153b(status).unwrap();
            for ((bank, address), expected) in [
                (USB, USB_RX_EARLY_TIMEOUT),
                (USB, USB_RX_EARLY_SIZE),
                (PLA, PLA_TCR1),
                (PLA, PLA_MAC_PWR_CTRL4),
            ]
            .into_iter()
            .zip(&v[3..])
            {
                assert_eq!(
                    model.borrow().core.get(bank, address, 2),
                    expected.parse::<u32>().unwrap(),
                    "{line}"
                );
            }
            count += 1;
        }
        assert_eq!(count, 40);
    }

    #[test]
    #[ignore = "oracle: STELA_RTL815X_FIRMWARE"]
    fn real_firmware_8153b_full_startup_and_link() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let (name, revision, _, hash) = crate::usb::ethernet::firmware::tests::FIXTURES
            .iter()
            .copied()
            .find(|(_, revision, _, _)| *revision == 0x6010)
            .unwrap();
        let directory = std::env::var("STELA_RTL815X_FIRMWARE").unwrap();
        let bytes = std::fs::read(std::path::Path::new(&directory).join(name)).unwrap();
        assert_eq!(alloc::format!("{:x}", Sha256::digest(&bytes)), hash);
        let firmware = Firmware::parse(&bytes, Revision(revision)).unwrap();
        for speed in [1, 3, 4, 5] {
            let model = Rc::new(RefCell::new(FirmwareModel::new(revision, &bytes)));
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

    #[test]
    fn every_rtl8153b_startup_transfer_failure_prevents_ready_state() {
        let bytes = synthetic_upload(0x6010);
        let firmware = Firmware::parse(&bytes, Revision(0x6010)).unwrap();
        let model = Rc::new(RefCell::new(FirmwareModel::new(0x6010, &bytes)));
        Chip::attach_with_firmware(
            FirmwareIo(model.clone()),
            Revision(0x6010),
            4,
            Some(&firmware),
        )
        .unwrap();
        let count = model.borrow().core.trace.len();
        for at in 0..count {
            let model = Rc::new(RefCell::new(FirmwareModel::new(0x6010, &bytes)));
            model.borrow_mut().core.fail_at = Some(at);
            assert!(
                Chip::attach_with_firmware(
                    FirmwareIo(model.clone()),
                    Revision(0x6010),
                    4,
                    Some(&firmware)
                )
                .is_err()
            );
            assert_eq!(model.borrow().core.trace.len(), at + 1);
        }
    }
}
