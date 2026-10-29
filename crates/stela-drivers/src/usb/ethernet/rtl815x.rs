// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
//! Linux r8152 register/OCP and distinct RTL8152B/RTL8153A startup paths.
//! Revision-specific implementations must be ready before configuration selection.
use super::registers::*;
use crate::usb::xhci::{
    DEVICE_TO_HOST, FULL_SPEED, HIGH_SPEED, LOW_SPEED, SUPER_SPEED, TYPE_VENDOR, setup,
};
use crate::{block::BlockError, net::Mac};
use alloc::vec::Vec;
mod rtl8153a;
mod rtl8153b;
mod rtl8153c;
mod rtl8156;
mod rtl8156a_tuning;
mod rtl8156b;
mod rtl8156b_tuning;
mod upload;
#[cfg(test)]
pub(crate) use upload::tests::Hardware as FirmwareModel;
#[cfg(test)]
pub(crate) use upload::tests::Io as FirmwareIo;

const PLA: u16 = 0x0100;
const USB: u16 = 0;
const MII_BMCR: u32 = OCP_BASE_MII;
const MII_ADVERTISE: u32 = OCP_BASE_MII + 8;
const BMCR_RESET: u32 = 0x8000;
const BMCR_PDOWN: u32 = 0x0800;
const BMCR_ANENABLE_RESTART: u32 = 0x1200;
const ADVERTISE_10_100_PAUSE: u32 = 0x0de0;
const PHYSTATUS_LINK: u32 = 0x02;
const PHYSTATUS_10: u32 = 0x04;

pub use super::Control;

/// Hardware identity, read from PLA_TCR0, independently of USB product strings.
/// Linux `RTL8152_REQ_GET_REGS` and `RTL8152_REQ_SET_REGS`.
const REGISTERS_REQUEST: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revision(pub u16);

impl Revision {
    pub(crate) fn request() -> [u8; 8] {
        setup(
            DEVICE_TO_HOST | TYPE_VENDOR,
            REGISTERS_REQUEST,
            PLA_TCR0 as u16,
            PLA,
            4,
        )
    }

    pub(crate) fn from_register(bytes: &[u8]) -> Result<Self, BlockError> {
        let data: [u8; 4] = bytes
            .try_into()
            .map_err(|_| BlockError::Unsupported("RTL815x short hardware revision register"))?;
        Ok(Self(
            ((u32::from_le_bytes(data) >> 16) & VERSION_MASK) as u16,
        ))
    }

    pub fn implemented(self) -> bool {
        matches!(self.0, 0x4c00 | 0x4c10 | 0x4800)
            || self.is_8153a()
            || self.is_8153b()
            || self.is_8153c()
            || self.is_8156a()
            || self.is_8156b()
    }

    pub fn is_8153a(self) -> bool {
        matches!(self.0, 0x5c00 | 0x5c10 | 0x5c20 | 0x5c30)
    }

    pub fn is_8153b(self) -> bool {
        matches!(self.0, 0x6000 | 0x6010)
    }

    pub fn is_8153c(self) -> bool {
        self.0 == 0x6400
    }

    pub fn is_8156a(self) -> bool {
        matches!(self.0, 0x7020 | 0x7030)
    }

    pub fn is_8156b(self) -> bool {
        matches!(self.0, 0x7400 | 0x7410 | 0x7420)
    }
    pub fn is_8156(self) -> bool {
        self.is_8156a() || self.is_8156b()
    }
    pub fn supports_2500(self) -> bool {
        matches!(self.0, 0x7020 | 0x7030 | 0x7400 | 0x7410)
    }

    /// Exact Linux firmware request for audited RTL8153/8156 revisions. None
    /// does not imply a supported chip or interchangeable initialization.
    pub fn firmware(self) -> Option<&'static str> {
        match self.0 {
            0x5c10 => Some("rtl_nic/rtl8153a-2.fw"),
            0x5c20 => Some("rtl_nic/rtl8153a-3.fw"),
            0x5c30 => Some("rtl_nic/rtl8153a-4.fw"),
            0x6010 => Some("rtl_nic/rtl8153b-2.fw"),
            0x7030 => Some("rtl_nic/rtl8156a-2.fw"),
            0x7410 | 0x7420 => Some("rtl_nic/rtl8156b-2.fw"),
            0x6400 => Some("rtl_nic/rtl8153c-1.fw"),
            _ => None,
        }
    }
}

/// Source-defined device policy applied only by the selected revision path.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    pub disable_receive_aggregation: bool,
}

/// Failed register accesses latch inaccessible until a new device attachment.
/// No read/modify/write is attempted after a short read or failed control TD.
pub struct Chip<C> {
    pub(super) io: C,
    revision: Revision,
    base: Option<u32>,
    accessible: bool,
    enabled: bool,
    initialized: bool,
    usb_speed: u8,
    policy: Policy,
}

impl<C: Control> Chip<C> {
    pub fn identify(mut io: C) -> Result<(C, Revision), BlockError> {
        let bytes = io.control(Revision::request(), &[])?;
        Ok((io, Revision::from_register(&bytes)?))
    }

    pub fn attach(io: C, expected: Revision, full_speed: bool) -> Result<(Self, Mac), BlockError> {
        Self::attach_with_firmware(
            io,
            expected,
            if full_speed { FULL_SPEED } else { HIGH_SPEED },
            None,
        )
    }

    pub fn attach_with_firmware(
        io: C,
        expected: Revision,
        speed: u8,
        firmware: Option<&super::firmware::Firmware<'_>>,
    ) -> Result<(Self, Mac), BlockError> {
        Self::attach_with_policy(io, expected, speed, firmware, Policy::default())
    }

    pub fn attach_with_policy(
        io: C,
        expected: Revision,
        speed: u8,
        firmware: Option<&super::firmware::Firmware<'_>>,
        policy: Policy,
    ) -> Result<(Self, Mac), BlockError> {
        let mut chip = Self::probe(io, expected)?;
        if !chip.revision.implemented() {
            return Err(BlockError::Unsupported(
                "RTL815x unimplemented or changed chip revision",
            ));
        }
        if !(1..=5).contains(&speed)
            || firmware.map(|image| image.revision())
                != chip.revision.firmware().map(|_| chip.revision)
        {
            return Err(BlockError::Unsupported(
                "RTL815x USB speed or required firmware identity",
            ));
        }
        chip.usb_speed = speed;
        chip.policy = policy;
        // determine_ethernet_addr: revision01 stores the permanent address in
        // IDR; later revisions use BACKUP without platform/OEM passthrough.
        let station = if chip.revision.0 == 0x4c00 {
            PLA_IDR
        } else {
            PLA_BACKUP
        };
        let first = chip.read(PLA, station, 4)?.to_le_bytes();
        let last = chip.read(PLA, station + 4, 4)?.to_le_bytes();
        let mac = Mac([first[0], first[1], first[2], first[3], last[0], last[1]]);
        if mac.0[0] & 1 != 0 || mac.0.iter().all(|b| *b == 0) {
            return Err(BlockError::Unsupported("RTL815x invalid station address"));
        }
        if chip.revision.is_8153a() {
            chip.initialize_8153a(firmware)?;
        } else if chip.revision.is_8153b() {
            chip.initialize_8153b(firmware)?;
        } else if chip.revision.is_8153c() {
            chip.initialize_8153c(firmware)?;
        } else if chip.revision.is_8156() {
            chip.initialize_8156(firmware)?;
        } else {
            chip.initialize(matches!(speed, FULL_SPEED | LOW_SPEED))?;
        }
        // set_ethernet_addr leaves revision01 IDR untouched. Later revisions
        // restore the permanent backup address through the configuration gate.
        if chip.revision.0 != 0x4c00 {
            chip.write(PLA, PLA_CRWECR, 1, 0xc0)?;
            chip.write(PLA, PLA_IDR, 4, u32::from_le_bytes(first))?;
            chip.write(
                PLA,
                PLA_IDR + 4,
                2,
                u32::from(u16::from_le_bytes([last[0], last[1]])),
            )?;
            chip.write(PLA, PLA_CRWECR, 1, 0)?;
        }
        chip.initialized = true;
        Ok((chip, mac))
    }

    /// Identify a chip without claiming initialization or carrier readiness.
    /// This permits revision-specific firmware preparation before PHY startup.
    pub fn probe(io: C, expected: Revision) -> Result<Self, BlockError> {
        let (io, revision) = Self::identify(io)?;
        if revision != expected {
            return Err(BlockError::Unsupported("RTL815x hardware revision changed"));
        }
        Ok(Self {
            io,
            revision,
            base: None,
            accessible: true,
            enabled: false,
            initialized: false,
            usb_speed: 0,
            policy: Policy::default(),
        })
    }

    pub fn receive_bytes(&self) -> usize {
        if self.revision.is_8156() {
            return 48 * 1024;
        }
        if self.revision.is_8153b()
            || self.revision.is_8153c()
            || (self.revision.is_8153a() && self.usb_speed >= SUPER_SPEED)
        {
            32 * 1024
        } else {
            16 * 1024
        }
    }

    fn transaction(&mut self, request: [u8; 8], data: &[u8]) -> Result<Vec<u8>, BlockError> {
        if !self.accessible {
            return Err(BlockError::Unsupported("RTL815x register access poisoned"));
        }
        let result = self.io.control(request, data);
        if result.is_err() {
            self.accessible = false;
            self.enabled = false;
        }
        result
    }

    fn read(&mut self, bank: u16, address: u32, width: u32) -> Result<u32, BlockError> {
        let shift = address & 3;
        if !matches!(width, 1 | 2 | 4)
            || shift + width > 4
            || !address.is_multiple_of(width)
            || address > 0xfffc + shift
        {
            return Err(BlockError::Unsupported("RTL815x unaligned OCP register"));
        }
        // The donor's word read passes the duplicated byte enables too.
        let index = bank | if width == 2 { 0x33 << shift } else { 0 };
        let request = setup(
            DEVICE_TO_HOST | TYPE_VENDOR,
            REGISTERS_REQUEST,
            (address & !3) as u16,
            index,
            4,
        );
        let bytes = self.transaction(request, &[])?;
        let Ok(data) = <[u8; 4]>::try_from(bytes) else {
            self.accessible = false;
            self.enabled = false;
            return Err(BlockError::Unsupported("RTL815x short register read"));
        };
        Ok((u32::from_le_bytes(data) >> (shift * 8)) & (u32::MAX >> ((4 - width) * 8)))
    }

    fn write(&mut self, bank: u16, address: u32, width: u32, value: u32) -> Result<(), BlockError> {
        let shift = address & 3;
        if !matches!(width, 1 | 2 | 4)
            || shift + width > 4
            || !address.is_multiple_of(width)
            || address > 0xfffc + shift
        {
            return Err(BlockError::Unsupported("RTL815x unaligned OCP register"));
        }
        let enables = match width {
            1 => 0x11,
            2 => 0x33,
            _ => 0xff,
        } << shift;
        let request = setup(
            TYPE_VENDOR,
            REGISTERS_REQUEST,
            (address & !3) as u16,
            bank | enables,
            4,
        );
        let mask = u32::MAX >> ((4 - width) * 8);
        self.transaction(request, &((value & mask) << (shift * 8)).to_le_bytes())?;
        Ok(())
    }

    fn modify(
        &mut self,
        bank: u16,
        address: u32,
        width: u32,
        clear: u32,
        set: u32,
    ) -> Result<(), BlockError> {
        let value = self.read(bank, address, width)?;
        self.write(bank, address, width, (value & !clear) | set)
    }

    fn phy_address(&mut self, address: u32) -> Result<u32, BlockError> {
        let base = address & 0xf000;
        if self.base != Some(base) {
            self.write(PLA, PLA_OCP_GPHY_BASE, 2, base)?;
            self.base = Some(base);
        }
        Ok((address & 0x0fff) | 0xb000)
    }

    fn phy_write(&mut self, address: u32, value: u32) -> Result<(), BlockError> {
        let mapped = self.phy_address(address)?;
        self.write(PLA, mapped, 2, value)
    }

    fn phy_modify(&mut self, address: u32, clear: u32, set: u32) -> Result<(), BlockError> {
        let mapped = self.phy_address(address)?;
        self.modify(PLA, mapped, 2, clear, set)
    }

    fn aldps(&mut self, enable: bool) -> Result<(), BlockError> {
        if self.revision.is_8153a()
            || self.revision.is_8153b()
            || self.revision.is_8153c()
            || self.revision.is_8156()
        {
            return self.aldps_8153(enable);
        }
        self.phy_write(
            OCP_ALDPS_CONFIG,
            ENPDNPS | LINKENA | DIS_SDSAVE | if enable { ENPWRSAVE } else { 0 },
        )?;
        if !enable {
            self.io.delay_us(20_000);
        }
        Ok(())
    }

    fn poll(
        &mut self,
        bank: u16,
        address: u32,
        width: u32,
        mask: u32,
        expected: u32,
        timing: (usize, u64),
    ) -> Result<(), BlockError> {
        for _ in 0..timing.0 {
            if self.read(bank, address, width)? & mask == expected {
                return Ok(());
            }
            self.io.delay_us(timing.1);
        }
        self.enabled = false;
        Err(BlockError::Timeout)
    }

    fn nic_reset(&mut self) -> Result<(), BlockError> {
        self.enabled = false;
        self.write(PLA, PLA_CR, 1, CR_RST)?;
        self.poll(PLA, PLA_CR, 1, CR_RST, 0, (1000, 100))
    }

    fn initialize(&mut self, full_speed: bool) -> Result<(), BlockError> {
        debug_assert!(self.revision.implemented());
        // r8152b_init: wake PHY, disable ALDPS/power cut, set MAC clocks and FIFO aggregation.
        self.phy_modify(MII_BMCR, BMCR_PDOWN, 0)?;
        self.aldps(false)?;
        if self.revision.0 == 0x4c00 {
            self.modify(PLA, PLA_LED_FEATURE, 2, LED_MODE_MASK, 0)?;
        }
        self.modify(USB, USB_UPS_CTRL, 2, POWER_CUT, 0)?;
        self.modify(USB, USB_PM_CTRL_STATUS, 2, RESUME_INDICATE, 0)?;
        self.modify(PLA, PLA_PHY_PWR, 2, 0, TX_10M_IDLE_EN | PFM_PWM_SWITCH)?;
        self.modify(
            PLA,
            PLA_MAC_PWR_CTRL,
            4,
            MCU_CLK_RATIO_MASK,
            MCU_CLK_RATIO | D3_CLK_GATED_EN,
        )?;
        self.write(
            PLA,
            PLA_GPHY_INTR_IMR,
            2,
            GPHY_STS_MSK | SPEED_DOWN_MSK | SPDWN_RXDV_MSK | SPDWN_LINKCHG_MSK,
        )?;
        self.modify(PLA, PLA_RSTTALLY, 2, 0, TALLY_RESET)?;
        self.modify(USB, USB_USB_CTRL, 2, RX_AGG_DISABLE | RX_ZERO_EN, 0)?;

        // r8152b_hw_phy_cfg with EEE disabled (no host EEE policy/offload).
        // No supported RTL8152 revision requests external firmware in rtl_fw_init.
        self.modify(PLA, PLA_EEE_CR, 2, EEE_RX_EN | EEE_TX_EN, 0)?;
        self.phy_modify(
            OCP_EEE_CONFIG1,
            SD_RISE_TIME_MASK | EEE_10_CAP | EEE_NWAY_EN | TX_QUIET_EN | RX_QUIET_EN,
            7 << 4,
        )?;
        self.phy_modify(OCP_EEE_CONFIG2, RG_DACQUIET_EN | RG_LDVQUIET_EN, 0)?;
        self.phy_modify(OCP_EEE_CONFIG3, FAST_SNR_MASK, 511 << 7)?;
        // MMD AN EEE advertisement, r8152_mmd_write(7, 0x3c, 0).
        self.phy_write(OCP_EEE_AR, 7)?;
        self.phy_write(OCP_EEE_DATA, 0x3c)?;
        self.phy_write(OCP_EEE_AR, 0x4007)?;
        self.phy_write(OCP_EEE_DATA, 0)?;
        self.phy_write(OCP_EEE_AR, 0)?;
        self.aldps(true)?;
        // Preserve selector/reserved bits, advertise all 10/100 duplex modes and pause.
        self.phy_modify(MII_ADVERTISE, 0x01e0, ADVERTISE_10_100_PAUSE)?;
        self.phy_write(MII_BMCR, BMCR_ANENABLE_RESTART | BMCR_RESET)?;
        let mapped = self.phy_address(MII_BMCR)?;
        self.poll(PLA, mapped, 2, BMCR_RESET, 0, (50, 20_000))?;
        self.up(full_speed)
    }

    fn up(&mut self, full_speed: bool) -> Result<(), BlockError> {
        self.aldps(false)?;
        self.modify(PLA, PLA_RCR, 4, RCR_ACPT_ALL, 0)?;
        self.modify(PLA, PLA_MISC_1, 2, 0, RXDY_GATED_EN)?;
        self.modify(
            PLA,
            PLA_TEREDO_CFG,
            2,
            TEREDO_SEL | TEREDO_RS_EVENT_MASK | OOB_TEREDO_EN,
            0,
        )?;
        self.write(PLA, PLA_WDT6_CTRL, 2, WDT6_SET_MODE)?;
        self.write(PLA, PLA_REALWOW_TIMER, 2, 0)?;
        self.write(PLA, PLA_TEREDO_TIMER, 4, 0)?;
        self.write(PLA, PLA_CRWECR, 1, 0)?;
        self.write(PLA, PLA_CR, 1, 0)?;
        self.modify(PLA, PLA_OOB_CTRL, 1, NOW_IS_OOB, 0)?;
        self.modify(PLA, PLA_SFF_STS_7, 2, MCU_BORW_EN, 0)?;
        self.poll(
            PLA,
            PLA_OOB_CTRL,
            1,
            LINK_LIST_READY,
            LINK_LIST_READY,
            (1000, 1000),
        )?;
        self.modify(PLA, PLA_SFF_STS_7, 2, 0, RE_INIT_LL)?;
        self.poll(
            PLA,
            PLA_OOB_CTRL,
            1,
            LINK_LIST_READY,
            LINK_LIST_READY,
            (1000, 1000),
        )?;
        self.nic_reset()?;
        self.write(PLA, PLA_RXFIFO_CTRL0, 4, RXFIFO_THR1_NORMAL)?;
        self.write(
            PLA,
            PLA_RXFIFO_CTRL1,
            4,
            if full_speed {
                RXFIFO_THR2_FULL
            } else {
                RXFIFO_THR2_HIGH
            },
        )?;
        self.write(
            PLA,
            PLA_RXFIFO_CTRL2,
            4,
            if full_speed {
                RXFIFO_THR3_FULL
            } else {
                RXFIFO_THR3_HIGH
            },
        )?;
        self.write(PLA, PLA_TXFIFO_CTRL, 4, TXFIFO_THR_NORMAL2)?;
        self.write(USB, USB_TX_AGG, 1, TX_AGG_MAX_THRESHOLD)?;
        self.write(USB, USB_RX_BUF_TH, 4, RX_THR_HIGH)?;
        self.write(USB, USB_TX_DMA, 4, TEST_MODE_DISABLE | TX_SIZE_ADJUST1)?;
        self.modify(PLA, PLA_CPCR, 2, CPCR_RX_VLAN, 0)?;
        self.write(PLA, PLA_RMS, 2, 1522)?;
        self.modify(PLA, PLA_TCR0, 2, 0, TCR0_AUTO_FIFO)?;
        self.aldps(true)
    }

    /// Actual PHY carrier drives MAC enabling. A disconnected link is never
    /// assumed up merely because USB enumeration or initialization succeeded.
    pub fn carrier(&mut self) -> Result<bool, BlockError> {
        if !self.initialized {
            return Err(BlockError::Unsupported("RTL815x chip is not initialized"));
        }
        let status = self.read(PLA, PLA_PHYSTATUS, 2)?;
        if status & PHYSTATUS_LINK == 0 {
            return Ok(false);
        }
        if !self.enabled {
            if self.revision.is_8156a() {
                self.flow_control_8156()?;
            }
            self.modify(
                PLA,
                PLA_EEEP_CR,
                2,
                EEEP_CR_EEEP_TX,
                if status & PHYSTATUS_10 != 0 {
                    EEEP_CR_EEEP_TX
                } else {
                    0
                },
            )?;
            if self.revision.is_8153a() {
                self.enable_8153a(status)?;
            } else if self.revision.is_8153b() || self.revision.is_8153c() {
                self.enable_8153b(status)?;
            } else if self.revision.is_8156() {
                self.enable_8156(status)?;
            }
            self.modify(PLA, PLA_FMC, 2, FMC_FCR_MCU_EN, 0)?;
            self.modify(PLA, PLA_FMC, 2, 0, FMC_FCR_MCU_EN)?;
            self.modify(PLA, PLA_CR, 1, 0, CR_RE | CR_TE)?;
            if self.revision.is_8153b() || self.revision.is_8153c() || self.revision.is_8156() {
                self.write(USB, USB_UPT_RXDMA_OWN, 1, OWN_UPDATE | OWN_CLEAR)?;
            }
            self.modify(PLA, PLA_MISC_1, 2, RXDY_GATED_EN, 0)?;
            // Directed, broadcast, all multicast. No VLAN/checksum offload.
            self.write(PLA, 0xcd00, 4, u32::MAX)?;
            self.write(PLA, 0xcd04, 4, u32::MAX)?;
            self.modify(PLA, PLA_RCR, 4, RCR_ACPT_ALL, 0x0e)?;
            self.enabled = true;
        }
        Ok(true)
    }

    /// Caller must quiesce bulk endpoints first; this drains the device FIFO
    /// and resets the MAC. Suspend/OOB and whole USB device reset are separate.
    pub fn stop(&mut self) -> Result<(), BlockError> {
        self.enabled = false;
        if self.revision.is_8156a() {
            self.write(PLA, PLA_RX_FIFO_FULL, 2, 0)?;
            self.write(PLA, PLA_RX_FIFO_EMPTY, 2, 0)?;
        }
        self.aldps(false)?;
        self.modify(PLA, PLA_RCR, 4, RCR_ACPT_ALL, 0)?;
        self.modify(PLA, PLA_MISC_1, 2, 0, RXDY_GATED_EN)?;
        self.poll(PLA, PLA_OOB_CTRL, 1, 0x30, 0x30, (1000, 1000))?;
        self.poll(PLA, PLA_TCR0, 2, TCR0_TX_EMPTY, TCR0_TX_EMPTY, (1000, 1000))?;
        self.nic_reset()?;
        if self.revision.is_8153a()
            || self.revision.is_8153b()
            || self.revision.is_8153c()
            || self.revision.is_8156()
        {
            self.reset_bmu()?;
        }
        self.aldps(true)
    }
}

#[cfg(test)]
pub(crate) mod tests;
