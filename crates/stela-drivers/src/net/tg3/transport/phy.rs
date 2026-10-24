// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! BCM5720/5762 A0 copper setup. EEE and pause are explicitly not advertised.
use super::{board::Board, regs::*, *};
const BMCR: u32 = 0;
const BMSR: u32 = 1;
const ADVERTISE: u32 = 4;
const CTRL1000: u32 = 9;
const BMCR_RESET: u16 = 0x8000;
const AN_ENABLE_RESTART: u16 = 0x1200;
const BMSR_LINK_AN_COMPLETE: u16 = 0x24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Speed {
    Mb10,
    Mb100,
    Mb1000,
}
impl<R: Registers, D: Delay> Hardware<R, D> {
    fn pr(&mut self, at: u32) -> Result<u16, Error> {
        self.phy_command(at as u8, None)
    }
    fn pw(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.phy_command(at as u8, Some(value as u16)).map(|_| ())
    }
    fn aux_read(&mut self, shadow: u32) -> Result<u32, Error> {
        self.pw(
            MII_TG3_AUX_CTRL,
            (shadow << MII_TG3_AUXCTL_MISC_RDSEL_SHIFT) | MII_TG3_AUXCTL_SHDWSEL_MISC,
        )?;
        self.pr(MII_TG3_AUX_CTRL).map(u32::from)
    }
    fn aux_write(&mut self, shadow: u32, value: u32) -> Result<(), Error> {
        self.pw(
            MII_TG3_AUX_CTRL,
            value
                | shadow
                | if shadow == MII_TG3_AUXCTL_SHDWSEL_MISC {
                    MII_TG3_AUXCTL_MISC_WREN
                } else {
                    0
                },
        )
    }
    fn smdsp(&mut self, enable: bool) -> Result<(), Error> {
        let value = self.aux_read(MII_TG3_AUXCTL_SHDWSEL_AUXCTL)?;
        self.aux_write(
            MII_TG3_AUXCTL_SHDWSEL_AUXCTL,
            (if enable {
                value | MII_TG3_AUXCTL_ACTL_SMDSP_ENA
            } else {
                value & !MII_TG3_AUXCTL_ACTL_SMDSP_ENA
            }) | MII_TG3_AUXCTL_ACTL_TX_6DB,
        )
    }
    pub(super) fn initialize_phy(&mut self, board: Board) -> Result<(), Error> {
        self.read_phy_identity()?;
        self.clear_packet_mac_status()?;
        self.pr(BMSR)?;
        self.pr(BMSR)?;
        self.pw(BMCR, u32::from(BMCR_RESET))?;
        let mut reset = false;
        for _ in 0..5000 {
            if self.pr(BMCR)? & BMCR_RESET == 0 {
                reset = true;
                break;
            }
            self.delay.delay_us(10);
        }
        if !reset {
            return Err(Error::PhyResetTimeout);
        }
        self.delay.delay_us(40);
        // No 5784 OTP override or 5761 jitter trim is applicable to 5720.
        self.pw(
            MII_TG3_MISC_SHDW,
            MII_TG3_MISC_SHDW_WREN
                | MII_TG3_MISC_SHDW_SCR5_SEL
                | MII_TG3_MISC_SHDW_SCR5_LPED
                | MII_TG3_MISC_SHDW_SCR5_DLPTLM
                | MII_TG3_MISC_SHDW_SCR5_SDTL
                | MII_TG3_MISC_SHDW_SCR5_C125OE
                | MII_TG3_MISC_SHDW_SCR5_DLLAPD,
        )?;
        self.pw(
            MII_TG3_MISC_SHDW,
            MII_TG3_MISC_SHDW_WREN
                | MII_TG3_MISC_SHDW_APD_SEL
                | MII_TG3_MISC_SHDW_APD_WKTM_84MS
                | if board.apd {
                    MII_TG3_MISC_SHDW_APD_ENABLE
                } else {
                    0
                },
        )?;
        let aux = self.aux_read(MII_TG3_AUXCTL_SHDWSEL_AUXCTL)?;
        self.aux_write(
            MII_TG3_AUXCTL_SHDWSEL_AUXCTL,
            aux | MII_TG3_AUXCTL_ACTL_EXTPKTLEN,
        )?;
        let ext = u32::from(self.pr(MII_TG3_EXT_CTRL)?);
        self.pw(MII_TG3_EXT_CTRL, ext | MII_TG3_EXT_CTRL_FIFO_ELASTIC)?;
        if self.identity.ok_or(Error::NotIdentified)?.asic == Asic::Bcm5762 {
            // tg3_phy_reset: this DSP calibration is exact 5762 A0 only.
            self.pw(MII_TG3_DSP_ADDRESS, 0x0ffb)?;
            self.pw(MII_TG3_DSP_RW_PORT, 0x4000)?;
        }
        let misc = self.aux_read(MII_TG3_AUXCTL_SHDWSEL_MISC)?;
        self.aux_write(
            MII_TG3_AUXCTL_SHDWSEL_MISC,
            misc | MII_TG3_AUXCTL_MISC_FORCE_AMDIX | MII_TG3_AUXCTL_MISC_WIRESPD_EN,
        )?;
        self.aux_write(MII_TG3_AUXCTL_SHDWSEL_PWRCTL, 0)?;
        self.pr(MII_TG3_ISTAT)?;
        self.pr(MII_TG3_ISTAT)?;
        self.pw(MII_TG3_IMASK, 0xffff)?;
        if board.capacitive {
            let value = self.aux_read(MII_TG3_AUXCTL_SHDWSEL_MISCTEST)?;
            self.aux_write(MII_TG3_AUXCTL_SHDWSEL_MISCTEST, value | (1 << 10))?;
        }
        // 10/100/1000 full duplex, no pause. This is a real negotiated subset;
        // no fabricated full duplex for a peer which did not negotiate it.
        self.pw(ADVERTISE, 0x0141)?;
        self.pw(CTRL1000, 0x0200)?;
        self.flush(
            TG3_CPMU_EEE_LNKIDL_CTRL,
            TG3_CPMU_EEE_LNKIDL_PCIE_NL0 | TG3_CPMU_EEE_LNKIDL_UART_IDL,
        )?;
        self.flush(TG3_CPMU_EEE_CTRL, TG3_CPMU_EEE_CTRL_EXIT_20_1_US)?;
        self.flush(TG3_CPMU_EEE_MODE, 0)?;
        self.smdsp(true)?;
        let result = (|| {
            self.write_mmd(7, 0x3c, 0)?; // MDIO_AN_EEE_ADV, disabled policy.
            self.pw(MII_TG3_DSP_ADDRESS, MII_TG3_DSP_CH34TP2)?;
            let value = u32::from(self.pr(MII_TG3_DSP_RW_PORT)?);
            self.pw(MII_TG3_DSP_ADDRESS, MII_TG3_DSP_CH34TP2)?;
            self.pw(MII_TG3_DSP_RW_PORT, value | MII_TG3_DSP_CH34TP2_HIBW01)
        })();
        let disable = self.smdsp(false);
        self.combine(result, disable)?;
        self.pw(BMCR, u32::from(AN_ENABLE_RESTART))?;
        let test = u32::from(self.pr(MII_TG3_TEST1)?);
        self.pw(MII_TG3_TEST1, test | MII_TG3_TEST1_CRC_EN)?;
        self.pr(MII_TG3_RXR_COUNTERS)?;
        Ok(())
    }
    fn clear_packet_mac_status(&mut self) -> Result<(), Error> {
        self.write(MAC_EVENT, 0)?;
        let changed = MAC_STATUS_SYNC_CHANGED
            | MAC_STATUS_CFG_CHANGED
            | MAC_STATUS_MI_COMPLETION
            | MAC_STATUS_LNKSTATE_CHANGED;
        for _ in 0..100 {
            self.flush(MAC_STATUS, changed)?;
            self.delay.delay_us(40);
            if self.read(MAC_STATUS)? & changed == 0 {
                return Ok(());
            }
        }
        Err(Error::ConfigDidNotLatch)
    }
    pub(super) fn copper_carrier(&mut self) -> Result<Option<Speed>, Error> {
        self.clear_packet_mac_status()?;
        self.pr(BMSR)?; // latch-low status must be sampled twice.
        if self.pr(BMSR)? & BMSR_LINK_AN_COMPLETE != BMSR_LINK_AN_COMPLETE {
            return Ok(None);
        }
        if self.pr(BMCR)? & 0x1000 == 0 {
            return Err(Error::UnsupportedMedia);
        }
        let aux = u32::from(self.pr(MII_TG3_AUX_STAT)?);
        let speed = match aux & MII_TG3_AUX_STAT_SPDMASK {
            MII_TG3_AUX_STAT_10FULL => Speed::Mb10,
            MII_TG3_AUX_STAT_100FULL => Speed::Mb100,
            MII_TG3_AUX_STAT_1000FULL => Speed::Mb1000,
            _ => return Ok(None),
        };
        let mut mode = self.read(MAC_MODE)? & !(MAC_MODE_PORT_MODE_MASK | MAC_MODE_HALF_DUPLEX);
        mode |= if speed == Speed::Mb1000 {
            MAC_MODE_PORT_MODE_GMII
        } else {
            MAC_MODE_PORT_MODE_MII
        };
        self.flush(MAC_MODE, mode)?;
        self.delay.delay_us(40);
        self.flush(MAC_EVENT, 0)?; // polled link; no IRQ callback exists.
        self.delay.delay_us(40);
        Ok(Some(speed))
    }
}
