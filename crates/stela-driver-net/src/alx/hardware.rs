// SPDX-License-Identifier: GPL-2.0-or-later AND ISC
// Copyright (c) 2013 Johannes Berg <johannes@sipsolutions.net>
// Copyright (c) 2012 Qualcomm Atheros, Inc.
// Copyright (c) 2026 Stela contributors
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//! The MAC, PHY and PCIe sequences of Linux `alx/hw.c`, in its order and
//! with its values, over a register window and the shared timing owner.
use super::registers::*;
use crate::{block::BlockError, bus::mmio::Mmio, timing::Timing};

/// One function's memory-mapped registers.
pub trait Registers {
    fn read16(&self, offset: usize) -> u16;
    fn read32(&self, offset: usize) -> u32;
    fn write16(&self, offset: usize, value: u16);
    fn write32(&self, offset: usize, value: u32);
}

impl Registers for Mmio {
    fn read16(&self, offset: usize) -> u16 {
        Mmio::read16(self, offset)
    }
    fn read32(&self, offset: usize) -> u32 {
        Mmio::read32(self, offset)
    }
    fn write16(&self, offset: usize, value: u16) {
        Mmio::write16(self, offset, value)
    }
    fn write32(&self, offset: usize, value: u32) {
        Mmio::write32(self, offset, value)
    }
}

/// What `alx_hw_revision`, `alx_hw_with_cr` and `alx_hw_giga` read from
/// the PCI identity, and `alx_init_sw`'s link patch selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Chip {
    pub(super) device: u16,
    /// The PCI revision ID byte.
    pub(super) revision: u8,
    pub(super) link_patch: bool,
}

impl Chip {
    pub(super) fn rev(self) -> u8 {
        self.revision >> REV_SHIFT
    }
    fn rev_a(self) -> bool {
        matches!(self.rev(), REV_A0 | REV_A1)
    }
    fn with_cr(self) -> bool {
        self.revision & 1 != 0
    }
    pub(super) fn giga(self) -> bool {
        self.device & 1 != 0
    }
    /// `alx_identify_hw`'s DMA read channels.
    fn dma_channels(self) -> u32 {
        if self.rev() >= REV_B0 { 4 } else { 2 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Speed {
    Ten,
    Hundred,
    Thousand,
}

/// The negotiated link `alx_read_phy_link` reports, `None` while down.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct LinkState {
    pub(super) speed: Option<Speed>,
    pub(super) full_duplex: bool,
}

/// `alx_init_sw`'s advertisement: autonegotiation of 10/100 half and full
/// and 1000 full, as `ethadv_to_hw_cfg` encodes it for `ALX_DRV`.
/// That encoding sets the 100 and duplex bits for 1000 full.
const DRV_ADVERTISED: u32 = DRV_PHY_AUTO | DRV_PHY_10 | DRV_PHY_100 | DRV_PHY_DUPLEX;

/// `alx_init_sw`'s interrupt moderation, receive buffer and ring values.
const IMT: u32 = 200;
pub(super) const TX_RING: usize = 256;
pub(super) const RX_RING: usize = 256;
const SMB_TIMER_VALUE: u32 = 400;
/// `ALX_RAW_MTU(1500)`: MTU, Ethernet header, FCS and one VLAN tag.
const RAW_MTU: u32 = 1500 + 14 + 4 + 4;
/// `ALX_MAX_FRAME_LEN(1500)`: the raw MTU and 16 bytes of padding, to 8.
pub(super) const RX_BUFFER: u32 = (RAW_MTU + 16 + 7) & !7;
/// `alx_init_sw`'s initial `rx_ctrl`.
const RX_CTRL: u32 = MAC_CTRL_WOLSPED_SWEN
    | MAC_CTRL_MHASH_ALG_HI5B
    | MAC_CTRL_BRD_EN
    | MAC_CTRL_PCRCE
    | MAC_CTRL_CRCE
    | MAC_CTRL_RXFC_EN
    | MAC_CTRL_TXFC_EN
    | (7 << MAC_CTRL_PRMBLEN_SHIFT);

pub(super) struct Hardware<R> {
    pub(super) registers: R,
    pub(super) timer: Timing,
    pub(super) chip: Chip,
    pub(super) rx_ctrl: u32,
    pub(super) link: LinkState,
    /// `pcie_get_readrq() >> 8`, as `alx_configure_basic` reads it.
    pub(super) read_request: u32,
}

impl<R: Registers> Hardware<R> {
    pub(super) fn new(registers: R, timer: Timing, chip: Chip, read_request: u32) -> Self {
        Self {
            registers,
            timer,
            chip,
            rx_ctrl: RX_CTRL,
            link: LinkState::default(),
            read_request,
        }
    }

    fn read(&self, offset: usize) -> u32 {
        self.registers.read32(offset)
    }
    fn write(&self, offset: usize, value: u32) {
        self.registers.write32(offset, value)
    }
    fn delay(&self, us: u64) -> Result<(), BlockError> {
        self.timer.delay(us)
    }

    fn wait_mdio_idle(&self) -> Result<u32, BlockError> {
        for _ in 0..MDIO_MAX_AC_TO {
            let value = self.read(MDIO);
            if value & MDIO_BUSY == 0 {
                return Ok(value);
            }
            self.delay(10)?;
        }
        Err(BlockError::Timeout)
    }

    /// `alx_read_phy_core` and `alx_write_phy_core`: the slow MDIO clock
    /// while the PHY may be hibernating, with no link.
    fn phy_core(
        &self,
        extended: Option<u8>,
        register: u16,
        write: Option<u16>,
    ) -> Result<u16, BlockError> {
        let clock = if self.link.speed.is_some() {
            MDIO_CLK_SEL_25MD4
        } else {
            MDIO_CLK_SEL_25MD128
        };
        let mut value = MDIO_SPRES_PRMBL | (clock << MDIO_CLK_SEL_SHIFT) | MDIO_START;
        match extended {
            Some(device) => {
                self.write(
                    MDIO_EXTN,
                    (u32::from(device) << MDIO_EXTN_DEVAD_SHIFT) | u32::from(register),
                );
                value |= MDIO_MODE_EXT;
            }
            None => value |= u32::from(register) << MDIO_REG_SHIFT,
        }
        value |= match write {
            Some(data) => u32::from(data),
            None => MDIO_OP_READ,
        };
        self.write(MDIO, value);
        let done = self.wait_mdio_idle()?;
        Ok(if write.is_some() { 0 } else { done as u16 })
    }

    pub(super) fn read_phy(&self, register: u16) -> Result<u16, BlockError> {
        self.phy_core(None, register, None)
    }
    pub(super) fn write_phy(&self, register: u16, value: u16) -> Result<(), BlockError> {
        self.phy_core(None, register, Some(value)).map(|_| ())
    }
    pub(super) fn read_ext(&self, device: u8, register: u16) -> Result<u16, BlockError> {
        self.phy_core(Some(device), register, None)
    }
    pub(super) fn write_ext(
        &self,
        device: u8,
        register: u16,
        value: u16,
    ) -> Result<(), BlockError> {
        self.phy_core(Some(device), register, Some(value))
            .map(|_| ())
    }
    fn read_dbg(&self, register: u16) -> Result<u16, BlockError> {
        self.write_phy(MII_DBG_ADDR, register)?;
        self.read_phy(MII_DBG_DATA)
    }
    fn write_dbg(&self, register: u16, value: u16) -> Result<(), BlockError> {
        self.write_phy(MII_DBG_ADDR, register)?;
        self.write_phy(MII_DBG_DATA, value)
    }

    /// `alx_get_phy_config`.
    fn phy_config(&self) -> Result<u32, BlockError> {
        if self.read(PHY_CTRL) & PHY_CTRL_DSPRST_OUT == 0 {
            return Ok(DRV_PHY_UNKNOWN);
        }
        let configured = field(self.read(DRV), DRV_PHY);
        if configured == DRV_PHY_UNKNOWN {
            return Ok(DRV_PHY_UNKNOWN);
        }
        Ok(if self.read_phy(MII_DBG_ADDR)? == PHY_INITED {
            configured
        } else {
            DRV_PHY_UNKNOWN
        })
    }

    /// `alx_phy_configured`: firmware left the PHY with this advertisement.
    pub(super) fn phy_configured(&self) -> Result<bool, BlockError> {
        let configured = self.phy_config()?;
        Ok(configured != DRV_PHY_UNKNOWN && configured == field(DRV_ADVERTISED, DRV_PHY))
    }

    fn wait_clear(&self, offset: usize, bits: u32) -> Result<Option<u32>, BlockError> {
        for _ in 0..SLD_MAX_TO {
            let value = self.read(offset);
            if value & bits == 0 {
                return Ok(Some(value));
            }
            self.delay(1000)?;
        }
        Ok(None)
    }

    fn station(&self) -> Option<crate::Mac> {
        let low = self.read(STAD0).to_be_bytes();
        let high = (self.read(STAD1) as u16).to_be_bytes();
        let mac = crate::Mac([high[0], high[1], low[0], low[1], low[2], low[3]]);
        (!mac.is_multicast() && mac.0 != [0; 6]).then_some(mac)
    }

    /// `alx_get_perm_macaddr`: the station registers, then the eFuse, then
    /// a flash or EEPROM when one is present; `None` when none holds a
    /// valid address.
    pub(super) fn permanent_mac(&self) -> Result<Option<crate::Mac>, BlockError> {
        if let Some(mac) = self.station() {
            return Ok(Some(mac));
        }
        let failed = BlockError::Unsupported("alx station address load timed out");
        let value = self
            .wait_clear(SLD, SLD_STAT | SLD_START)?
            .ok_or(failed.clone())?;
        self.write(SLD, value | SLD_START);
        self.wait_clear(SLD, SLD_START)?.ok_or(failed.clone())?;
        if let Some(mac) = self.station() {
            return Ok(Some(mac));
        }
        if self.read(EFLD) & (EFLD_F_EXIST | EFLD_E_EXIST) != 0 {
            let value = self
                .wait_clear(EFLD, EFLD_STAT | EFLD_START)?
                .ok_or(failed.clone())?;
            self.write(EFLD, value | EFLD_START);
            self.wait_clear(EFLD, EFLD_START)?.ok_or(failed)?;
            if let Some(mac) = self.station() {
                return Ok(Some(mac));
            }
        }
        Ok(None)
    }

    /// `alx_set_macaddr`.
    fn set_mac(&self, mac: crate::Mac) {
        let [a, b, c, d, e, f] = mac.0;
        self.write(STAD0, u32::from_be_bytes([c, d, e, f]));
        self.write(STAD1, u32::from(u16::from_be_bytes([a, b])));
    }

    /// `alx_reset_osc`.
    fn reset_oscillator(&self) -> Result<(), BlockError> {
        let value = self.read(MISC3);
        self.write(MISC3, (value & !MISC3_25M_BY_SW) | MISC3_25M_NOTO_INTNL);
        let mut value = self.read(MISC);
        if self.chip.rev() >= REV_B0 {
            value = set_field(value, MISC_PSW_OCP, MISC_PSW_OCP_DEF);
            value &= !MISC_INTNLOSC_OPEN;
            self.write(MISC, value);
            self.write(MISC, value | MISC_INTNLOSC_OPEN);
            let calibrate = self.read(MSIC2) & !MSIC2_CALB_START;
            self.write(MSIC2, calibrate);
            self.write(MSIC2, calibrate | MSIC2_CALB_START);
        } else {
            value &= !MISC_INTNLOSC_OPEN;
            if self.chip.rev_a() {
                value &= !MISC_ISO_EN;
            }
            self.write(MISC, value | MISC_INTNLOSC_OPEN);
            self.write(MISC, value);
        }
        self.delay(20)
    }

    /// `alx_stop_mac`.
    fn stop_mac(&mut self) -> Result<(), BlockError> {
        let receive = self.read(RXQ0);
        self.write(RXQ0, receive & !RXQ0_EN);
        let transmit = self.read(TXQ0);
        self.write(TXQ0, transmit & !TXQ0_EN);
        self.delay(40)?;
        self.rx_ctrl &= !(MAC_CTRL_RX_EN | MAC_CTRL_TX_EN);
        self.write(MAC_CTRL, self.rx_ctrl);
        for _ in 0..DMA_MAC_RST_TO {
            if self.read(MAC_STS) & MAC_STS_IDLE == 0 {
                return Ok(());
            }
            self.delay(10)?;
        }
        Err(BlockError::Timeout)
    }

    /// `alx_reset_mac`: interrupts off, queues and MAC stopped, then the
    /// whole MAC and its DMA reset, with the revision A CR workarounds.
    pub(super) fn reset_mac(&mut self) -> Result<(), BlockError> {
        let a_cr = self.chip.rev_a() && self.chip.with_cr();
        self.write(MSIX_MASK, u32::MAX);
        self.write(IMR, 0);
        self.write(ISR, ISR_DIS);
        self.stop_mac()?;
        // The MAC reset workaround.
        self.write(RFD_PIDX, 1);
        let mut power = 0;
        if a_cr {
            power = self.read(PMCTRL);
            if power & (PMCTRL_L1_EN | PMCTRL_L0S_EN) != 0 {
                self.write(PMCTRL, power & !(PMCTRL_L1_EN | PMCTRL_L0S_EN));
            }
        }
        let value = self.read(MASTER);
        self.write(MASTER, value | MASTER_DMA_MAC_RST | MASTER_OOB_DIS);
        self.delay(10)?;
        let mut polls = 0;
        while polls < DMA_MAC_RST_TO {
            if self.read(RFD_PIDX) == 0 {
                break;
            }
            self.delay(10)?;
            polls += 1;
        }
        let mut value = 0;
        while polls < DMA_MAC_RST_TO {
            value = self.read(MASTER);
            if value & MASTER_DMA_MAC_RST == 0 {
                break;
            }
            self.delay(10)?;
            polls += 1;
        }
        if polls == DMA_MAC_RST_TO {
            return Err(BlockError::Timeout);
        }
        self.delay(10)?;
        if a_cr {
            self.write(MASTER, value | MASTER_PCLKSEL_SRDS);
            if power & (PMCTRL_L1_EN | PMCTRL_L0S_EN) != 0 {
                self.write(PMCTRL, power);
            }
        }
        self.reset_oscillator()?;
        let value = self.read(MISC3);
        self.write(MISC3, (value & !MISC3_25M_BY_SW) | MISC3_25M_NOTO_INTNL);
        let mut value = self.read(MISC) & !MISC_INTNLOSC_OPEN;
        if self.chip.rev_a() {
            value &= !MISC_ISO_EN;
        }
        self.write(MISC, value);
        self.delay(20)?;
        self.write(MAC_CTRL, self.rx_ctrl);
        let value = self.read(SERDES);
        self.write(SERDES, value | SERDES_MACCLK_SLWDWN | SERDES_PHYCLK_SLWDWN);
        Ok(())
    }

    /// `alx_reset_phy`: DSP reset, then the power-saving, EEE-off and
    /// analog defaults, the link patch, and the link interrupt mask.
    pub(super) fn reset_phy(&self) -> Result<(), BlockError> {
        let mut value = self.read(PHY_CTRL);
        value &= !(PHY_CTRL_DSPRST_OUT
            | PHY_CTRL_IDDQ
            | PHY_CTRL_GATE_25M
            | PHY_CTRL_POWER_DOWN
            | PHY_CTRL_CLS);
        value |= PHY_CTRL_RST_ANALOG | PHY_CTRL_HIB_PULSE | PHY_CTRL_HIB_EN;
        self.write(PHY_CTRL, value);
        self.delay(10)?;
        self.write(PHY_CTRL, value | PHY_CTRL_DSPRST_OUT);
        self.delay(PHY_CTRL_DSPRST_TO * 10)?;
        self.write_dbg(MIIDBG_LEGCYPS, LEGCYPS_DEF)?;
        self.write_dbg(MIIDBG_SYSMODCTRL, SYSMODCTRL_IECHOADJ_DEF)?;
        self.write_ext(MIIEXT_PCS, MIIEXT_VDRVBIAS, VDRVBIAS_DEF)?;
        let lpi = self.read(LPI_CTRL);
        self.write(LPI_CTRL, lpi & !LPI_CTRL_EN);
        self.write_ext(MIIEXT_ANEG, MIIEXT_LOCAL_EEEADV, 0)?;
        self.write_dbg(MIIDBG_TST10BTCFG, TST10BTCFG_DEF)?;
        self.write_dbg(MIIDBG_SRDSYSMOD, SRDSYSMOD_DEF)?;
        self.write_dbg(MIIDBG_TST100BTCFG, TST100BTCFG_DEF)?;
        self.write_dbg(MIIDBG_ANACTRL, ANACTRL_DEF)?;
        let green = self.read_dbg(MIIDBG_GREENCFG2)?;
        self.write_dbg(MIIDBG_GREENCFG2, green & !GREENCFG2_GATE_DFSE_EN)?;
        self.write_ext(MIIEXT_ANEG, MIIEXT_NLP78, MIIEXT_NLP78_120M_DEF)?;
        self.write_ext(MIIEXT_ANEG, MIIEXT_S3DIG10, MIIEXT_S3DIG10_DEF)?;
        if self.chip.link_patch {
            let value = self.read_ext(MIIEXT_PCS, MIIEXT_CLDCTRL3)?;
            self.write_ext(
                MIIEXT_PCS,
                MIIEXT_CLDCTRL3,
                value | CLDCTRL3_BP_CABLE1TH_DET_GT,
            )?;
            let value = self.read_dbg(MIIDBG_GREENCFG2)?;
            self.write_dbg(MIIDBG_GREENCFG2, value | GREENCFG2_BP_GREEN)?;
            let value = self.read_ext(MIIEXT_PCS, MIIEXT_CLDCTRL5)?;
            self.write_ext(MIIEXT_PCS, MIIEXT_CLDCTRL5, value | CLDCTRL5_BP_VD_HLFBIAS)?;
        }
        self.write_phy(MII_IER, IER_LINK_UP | IER_LINK_DOWN)
    }

    /// `alx_reset_pcie`'s register part: WoL cleared, D3 PLL off disabled,
    /// PCIe protocol errors masked, the 25 MHz and PCLK selection, ASPM.
    /// The command register is the PCI owner's.
    pub(super) fn reset_pcie(&self) -> Result<(), BlockError> {
        self.read(WOL0);
        self.write(WOL0, 0);
        let value = self.read(PDLL_TRNS1);
        self.write(PDLL_TRNS1, value & !PDLL_TRNS1_D3PLLOFF_EN);
        let value = self.read(UE_SVRT);
        self.write(UE_SVRT, value & !(UE_SVRT_DLPROTERR | UE_SVRT_FCPROTERR));
        let value = self.read(MASTER);
        if self.chip.rev_a() && self.chip.with_cr() {
            if value & MASTER_WAKEN_25M == 0 || value & MASTER_PCLKSEL_SRDS == 0 {
                self.write(MASTER, value | MASTER_PCLKSEL_SRDS | MASTER_WAKEN_25M);
            }
        } else if value & MASTER_WAKEN_25M == 0 || value & MASTER_PCLKSEL_SRDS != 0 {
            self.write(MASTER, (value & !MASTER_PCLKSEL_SRDS) | MASTER_WAKEN_25M);
        }
        self.enable_aspm(true, true);
        self.delay(10)
    }

    /// `alx_start_mac`.
    pub(super) fn start_mac(&mut self) {
        let receive = self.read(RXQ0);
        self.write(RXQ0, receive | RXQ0_EN);
        let transmit = self.read(TXQ0);
        self.write(TXQ0, transmit | TXQ0_EN);
        let mut mac = self.rx_ctrl;
        if self.link.full_duplex {
            mac |= MAC_CTRL_FULLD;
        } else {
            mac &= !MAC_CTRL_FULLD;
        }
        let speed = if self.link.speed == Some(Speed::Thousand) {
            MAC_CTRL_SPEED_1000
        } else {
            MAC_CTRL_SPEED_10_100
        };
        mac = set_field(mac, MAC_CTRL_SPEED, speed);
        mac |= MAC_CTRL_TX_EN | MAC_CTRL_RX_EN;
        self.rx_ctrl = mac;
        self.write(MAC_CTRL, mac);
    }

    /// `alx_enable_aspm`: the MAC's own L0s/L1 policy register.
    pub(super) fn enable_aspm(&self, l0s: bool, l1: bool) {
        let mut power = self.read(PMCTRL);
        power = set_field(power, PMCTRL_LCKDET_TIMER, PMCTRL_LCKDET_TIMER_DEF);
        power |= PMCTRL_RCVR_WT_1US | PMCTRL_L1_CLKSW_EN | PMCTRL_L1_SRDSRX_PWD;
        power = set_field(power, PMCTRL_L1REQ_TO, PMCTRL_L1REG_TO_DEF);
        power = set_field(power, PMCTRL_L1_TIMER, PMCTRL_L1_TIMER_16US);
        power &= !(PMCTRL_L1_SRDS_EN
            | PMCTRL_L1_SRDSPLL_EN
            | PMCTRL_L1_BUFSRX_EN
            | PMCTRL_SADLY_EN
            | PMCTRL_HOTRST_WTEN
            | PMCTRL_L0S_EN
            | PMCTRL_L1_EN
            | PMCTRL_ASPM_FCEN
            | PMCTRL_TXL1_AFTER_L0S
            | PMCTRL_RXL1_AFTER_L0S);
        if self.chip.rev_a() && self.chip.with_cr() {
            power |= PMCTRL_L1_SRDS_EN | PMCTRL_L1_SRDSPLL_EN;
        }
        if l0s {
            power |= PMCTRL_L0S_EN | PMCTRL_ASPM_FCEN;
        }
        if l1 {
            power |= PMCTRL_L1_EN | PMCTRL_ASPM_FCEN;
        }
        self.write(PMCTRL, power);
    }

    /// `alx_setup_speed_duplex` with `alx_init_sw`'s advertisement and
    /// flow control (autonegotiated, receive and transmit).
    pub(super) fn setup_speed_duplex(&self) -> Result<(), BlockError> {
        self.write_phy(MII_DBG_ADDR, 0)?;
        let mut value = set_field(self.read(DRV), DRV_PHY, 0);
        // ALX_FC_ANEG | ALX_FC_RX | ALX_FC_TX adds ADVERTISED_Pause only.
        let advertise = ADVERTISE_CSMA | ADVERTISE_10_100 | ETHTOOL_ADVERTISED_PAUSE;
        let giga = if self.chip.giga() {
            ADVERTISE_1000FULL
        } else {
            0
        };
        let result = (|| {
            self.write_phy(MII_ADVERTISE, advertise)?;
            self.write_phy(MII_CTRL1000, giga)?;
            self.write_phy(MII_BMCR, BMCR_RESET | BMCR_ANENABLE | BMCR_ANRESTART)
        })();
        if result.is_ok() {
            self.write_phy(MII_DBG_ADDR, PHY_INITED)?;
            value |= DRV_ADVERTISED;
        }
        self.write(DRV, value);
        result
    }

    /// `alx_post_phy_link`: cable-length and noise thresholds of revisions
    /// A and B0.
    pub(super) fn post_phy_link(&self) -> Result<(), BlockError> {
        let revision = self.chip.rev();
        let adjust = revision == REV_B0;
        if revision != REV_B0 && !self.chip.rev_a() {
            return Ok(());
        }
        let patch = adjust && self.chip.link_patch;
        match self.link.speed {
            Some(speed) => {
                let length = field16(
                    self.read_ext(MIIEXT_PCS, MIIEXT_CLDCTRL6)?,
                    CLDCTRL6_CAB_LEN,
                );
                let gain = field16(self.read_dbg(MIIDBG_AGC)?, AGC_2_VGA);
                let long = match speed {
                    Speed::Thousand => {
                        length > CLDCTRL6_CAB_LEN_SHORT1G || (length == 0 && gain > AGC_LONG1G_LIMT)
                    }
                    Speed::Hundred => {
                        length > CLDCTRL6_CAB_LEN_SHORT100M
                            || (length == 0 && gain > AGC_LONG100M_LIMT)
                    }
                    Speed::Ten => false,
                };
                if long {
                    self.write_dbg(MIIDBG_AZ_ANADECT, AZ_ANADECT_LONG)?;
                    let value = self.read_ext(MIIEXT_ANEG, MIIEXT_AFE)?;
                    self.write_ext(MIIEXT_ANEG, MIIEXT_AFE, value | AFE_10BT_100M_TH)?;
                } else {
                    self.write_dbg(MIIDBG_AZ_ANADECT, AZ_ANADECT_DEF)?;
                    let value = self.read_ext(MIIEXT_ANEG, MIIEXT_AFE)?;
                    self.write_ext(MIIEXT_ANEG, MIIEXT_AFE, value & !AFE_10BT_100M_TH)?;
                }
                if patch {
                    match speed {
                        Speed::Hundred => self.write_dbg(MIIDBG_MSE16DB, MSE16DB_UP)?,
                        Speed::Thousand => {
                            let value = self.read_dbg(MIIDBG_MSE20DB)?;
                            self.write_dbg(
                                MIIDBG_MSE20DB,
                                set_field16(value, MSE20DB_TH, MSE20DB_TH_HI),
                            )?;
                        }
                        Speed::Ten => {}
                    }
                }
            }
            None => {
                let value = self.read_ext(MIIEXT_ANEG, MIIEXT_AFE)?;
                self.write_ext(MIIEXT_ANEG, MIIEXT_AFE, value & !AFE_10BT_100M_TH)?;
                if patch {
                    self.write_dbg(MIIDBG_MSE16DB, MSE16DB_DOWN)?;
                    let value = self.read_dbg(MIIDBG_MSE20DB)?;
                    self.write_dbg(
                        MIIDBG_MSE20DB,
                        set_field16(value, MSE20DB_TH, MSE20DB_TH_DEF),
                    )?;
                }
            }
        }
        Ok(())
    }

    /// `alx_read_phy_link`: the latched status read twice, then the
    /// resolved speed and duplex from the PHY specific status.
    pub(super) fn read_phy_link(&mut self) -> Result<LinkState, BlockError> {
        self.read_phy(MII_BMSR)?;
        let status = self.read_phy(MII_BMSR)?;
        if status & BMSR_LSTATUS == 0 {
            return Ok(LinkState::default());
        }
        let specific = self.read_phy(MII_GIGA_PSSR)?;
        if specific & GIGA_PSSR_SPD_DPLX_RESOLVED == 0 {
            return Err(BlockError::Unsupported(
                "alx PHY speed and duplex unresolved",
            ));
        }
        let speed = match specific & GIGA_PSSR_SPEED {
            GIGA_PSSR_1000MBS => Speed::Thousand,
            GIGA_PSSR_100MBS => Speed::Hundred,
            GIGA_PSSR_10MBS => Speed::Ten,
            _ => return Err(BlockError::Unsupported("alx PHY reports an invalid speed")),
        };
        Ok(LinkState {
            speed: Some(speed),
            full_duplex: specific & GIGA_PSSR_DPLX != 0,
        })
    }

    /// `alx_clear_phy_intr`.
    pub(super) fn clear_phy_interrupt(&self) -> Result<(), BlockError> {
        self.read_phy(MII_ISR).map(|_| ())
    }

    /// `alx_get_phy_info`'s identity read.
    pub(super) fn phy_identity(&self) -> Result<u32, BlockError> {
        let high = self.read_phy(MII_PHYSID1)?;
        let low = self.read_phy(MII_PHYSID2)?;
        Ok(u32::from(high) << 16 | u32::from(low))
    }

    /// `alx_configure_basic`, then `alx_disable_rss` and the receive filter
    /// of `__alx_set_rx_mode` with all multicast accepted.
    pub(super) fn configure(&mut self, mac: crate::Mac) {
        self.set_mac(mac);
        self.write(CLK_GATE, CLK_GATE_ALL);
        if self.chip.rev() >= REV_B0 {
            self.write(IDLE_DECISN_TIMER, IDLE_DECISN_TIMER_DEF);
        }
        self.write(SMB_TIMER, SMB_TIMER_VALUE * 500);
        let value = self.read(MASTER);
        self.write(
            MASTER,
            value | MASTER_IRQMOD2_EN | MASTER_IRQMOD1_EN | MASTER_SYSALVTIMER_EN,
        );
        self.write(IRQ_MODU_TIMER, IMT >> 1);
        self.write(INT_RETRIG, INT_RETRIG_TO);
        self.write(TINT_TPD_THRSHLD, (TX_RING / 3) as u32);
        self.write(TINT_TIMER, IMT);
        self.write(MTU, RAW_MTU);
        // The standard MTU keeps fast pause, which rx_ctrl never sets.
        const _: () = assert!(RAW_MTU <= MTU_JUMBO_TH + 4 + 4);
        let threshold = if RAW_MTU < TXQ1_JUMBO_TSO_TH {
            (RAW_MTU + 7) >> 3
        } else {
            TXQ1_JUMBO_TSO_TH >> 3
        };
        self.write(TXQ1, threshold | TXQ1_ERRLGPKT_DROP_EN);
        self.write(
            TXQ0,
            TXQ_TPD_BURSTPREF_DEF
                | TXQ0_MODE_ENHANCE
                | TXQ0_LSO_8023_EN
                | TXQ0_SUPT_IPOPT
                | (TXQ_TXF_BURST_PREF_DEF << TXQ0_TXF_BURST_PREF_SHIFT),
        );
        self.write(
            HQTPD,
            TXQ_TPD_BURSTPREF_DEF
                | (TXQ_TPD_BURSTPREF_DEF << 4)
                | (TXQ_TPD_BURSTPREF_DEF << 8)
                | HQTPD_BURST_EN,
        );
        let fifo = field(self.read(SRAM5), SRAM_RXF_LEN) << 3;
        let xoff = MTU_STD_ALGN >> 3;
        let xon = if fifo > SRAM_RXF_LEN_8K {
            fifo.wrapping_sub(RXQ2_RXF_FLOW_CTRL_RSVD) >> 3
        } else {
            fifo.wrapping_sub(MTU_STD_ALGN) >> 3
        };
        self.write(RXQ2, (xoff << RXQ2_RXF_XOFF_THRESH_SHIFT) | xon);
        let mut receive = (RXQ0_NUM_RFD_PREF_DEF << RXQ0_NUM_RFD_PREF_SHIFT)
            | (RXQ0_RSS_MODE_DIS << RXQ0_RSS_MODE_SHIFT)
            | (RXQ0_IDT_TBL_SIZE_DEF << RXQ0_IDT_TBL_SIZE_SHIFT)
            | RXQ0_RSS_HSTYP_ALL
            | RXQ0_RSS_HASH_EN
            | RXQ0_IPV6_PARSE_EN;
        if self.chip.giga() {
            receive = set_field(receive, RXQ0_ASPM_THRESH, RXQ0_ASPM_THRESH_100M);
        }
        self.write(RXQ0, receive);
        self.read(DMA);
        self.write(
            DMA,
            DMA_RORDER_MODE_OUT
                | DMA_RREQ_PRI_DATA
                | (self.read_request << DMA_RREQ_BLEN_SHIFT)
                | (DMA_WDLY_CNT_DEF << DMA_WDLY_CNT_SHIFT)
                | (DMA_RDLY_CNT_DEF << DMA_RDLY_CNT_SHIFT)
                | ((self.chip.dma_channels() - 1) << DMA_RCHNL_SEL_SHIFT),
        );
        self.write(
            WRR,
            (WRR_PRI_RESTRICT_NONE << WRR_PRI_SHIFT) | 4 | (4 << 8) | (4 << 16) | (4 << 24),
        );
        // alx_disable_rss.
        let receive = self.read(RXQ0);
        self.write(RXQ0, receive & !RXQ0_RSS_HASH_EN);
        // __alx_set_rx_mode with IFF_ALLMULTI leaves the hash table alone,
        // then alx_configure writes MAC_CTRL once more.
        self.rx_ctrl &= !(MAC_CTRL_MULTIALL_EN | MAC_CTRL_PROMISC_EN);
        self.rx_ctrl |= MAC_CTRL_MULTIALL_EN;
        self.write(MAC_CTRL, self.rx_ctrl);
        self.write(MAC_CTRL, self.rx_ctrl);
    }

    /// `alx_init_ring_ptrs`: one transmit and one receive queue, all three
    /// rings below the same 4 GiB boundary.
    pub(super) fn ring_pointers(&self, transmit: u64, receive_return: u64, receive_free: u64) {
        self.write(TPD_PRI0_ADDR_LO, transmit as u32);
        self.write(RRD_ADDR_LO, receive_return as u32);
        self.write(RFD_ADDR_LO, receive_free as u32);
        self.write(TX_BASE_ADDR_HI, (transmit >> 32) as u32);
        self.write(TPD_RING_SZ, TX_RING as u32);
        self.write(RX_BASE_ADDR_HI, (receive_return >> 32) as u32);
        self.write(RRD_RING_SZ, RX_RING as u32);
        self.write(RFD_RING_SZ, RX_RING as u32);
        self.write(RFD_BUF_SZ, RX_BUFFER);
        self.write(SRAM9, SRAM_LOAD_PTR);
    }

    /// Clear the interrupt status `alx_activate` and `__alx_open` clear.
    /// The interrupt mask stays zero: this driver polls.
    pub(super) fn clear_interrupts(&self) {
        self.write(ISR, !ISR_DIS);
    }

    pub(super) fn produce_receive(&self, index: usize) {
        self.registers.write16(RFD_PIDX, index as u16);
    }
    pub(super) fn produce_transmit(&self, index: usize) {
        self.registers.write16(TPD_PRI0_PIDX, index as u16);
    }
    pub(super) fn transmit_consumer(&self) -> usize {
        usize::from(self.registers.read16(TPD_PRI0_CIDX))
    }
}
