// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
//! Linux r8152 register/OCP and distinct RTL8152B/RTL8153A startup paths.
//! Revision-specific implementations must be ready before configuration selection.
use super::registers::*;
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

/// Synchronous endpoint-zero requests. Success includes the exact transferred
/// byte count; short replies/writes are errors, never fabricated register values.
pub trait Control {
    fn control(&mut self, request: [u8; 8], output: &[u8]) -> Result<Vec<u8>, BlockError>;
    fn delay_us(&mut self, microseconds: u64);
}

/// Hardware identity, read from PLA_TCR0, independently of USB product strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revision(pub u16);

impl Revision {
    pub(crate) fn request() -> [u8; 8] {
        super::super::xhci::setup(0xc0, 5, PLA_TCR0 as u16, PLA, 4)
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
            if full_speed {
                super::super::xhci::FULL_SPEED
            } else {
                super::super::xhci::HIGH_SPEED
            },
            None,
        )
    }

    pub fn attach_with_firmware(
        io: C,
        expected: Revision,
        speed: u8,
        firmware: Option<&super::firmware::Firmware<'_>>,
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
            chip.initialize(speed <= super::super::xhci::LOW_SPEED)?;
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
        })
    }

    pub fn receive_bytes(&self) -> usize {
        if self.revision.is_8156() {
            return 48 * 1024;
        }
        if self.revision.is_8153b()
            || self.revision.is_8153c()
            || (self.revision.is_8153a() && self.usb_speed >= super::super::xhci::SUPER_SPEED)
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
        let request = super::super::xhci::setup(0xc0, 5, (address & !3) as u16, index, 4);
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
        let request = super::super::xhci::setup(0x40, 5, (address & !3) as u16, bank | enables, 4);
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
pub(crate) mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, rc::Rc};
    use core::cell::RefCell;

    /// Independent byte-lane/OCP model. The window maps through the hardware
    /// base register, partial writes preserve disabled lanes, and reset/LL
    /// completion is driven by later reads instead of write echo.
    pub(crate) struct Model {
        registers: BTreeMap<(u16, u32), u8>,
        pub(super) base: u32,
        reset: usize,
        phy_reset: usize,
        pub trace: Vec<([u8; 8], Vec<u8>)>,
        pub delays: Vec<u64>,
        pub fail_at: Option<usize>,
        pub short_at: Option<usize>,
        pub link: bool,
        pub(crate) phy_status: u32,
        pub stuck_reset: bool,
        pub stuck_phy: bool,
        pub stuck_list: bool,
    }

    impl Model {
        pub(crate) fn new(revision: u16) -> Self {
            let mut model = Self {
                registers: BTreeMap::new(),
                base: 0,
                reset: 0,
                phy_reset: 0,
                trace: Vec::new(),
                delays: Vec::new(),
                fail_at: None,
                short_at: None,
                link: true,
                phy_status: 0x0a,
                stuck_reset: false,
                stuck_phy: false,
                stuck_list: false,
            };
            model.set(
                PLA,
                PLA_TCR0,
                4,
                (u32::from(revision) << 16) | TCR0_TX_EMPTY,
            );
            model.set(PLA, PLA_BACKUP, 4, 0x33221102);
            model.set(PLA, PLA_BACKUP + 4, 4, 0x5544);
            model.set(PLA, PLA_IDR, 4, 0x33221102);
            model.set(PLA, PLA_IDR + 4, 4, 0x5544);
            model.set(PLA, PLA_OOB_CTRL, 1, NOW_IS_OOB | LINK_LIST_READY | 0x30);
            model.set(PLA, PLA_BOOT_CTRL, 2, AUTOLOAD_DONE);
            model.set(PLA, OCP_PHY_STATUS, 2, PHY_STAT_LAN_ON);
            model.set(PLA, 0xe000, 2, 0x0100);
            model
        }

        pub(super) fn get(&self, bank: u16, address: u32, width: u32) -> u32 {
            (0..width).fold(0, |value, lane| {
                value
                    | (u32::from(*self.registers.get(&(bank, address + lane)).unwrap_or(&0))
                        << (lane * 8))
            })
        }
        pub(super) fn set(&mut self, bank: u16, address: u32, width: u32, value: u32) {
            for lane in 0..width {
                self.registers
                    .insert((bank, address + lane), (value >> (lane * 8)) as u8);
            }
        }

        pub(crate) fn request(
            &mut self,
            setup: [u8; 8],
            output: &[u8],
        ) -> Result<Vec<u8>, BlockError> {
            let at = self.trace.len();
            self.trace.push((setup, output.to_vec()));
            if self.fail_at == Some(at) {
                return Err(BlockError::Timeout);
            }
            assert_eq!(setup[1], 5);
            let length = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
            assert!(length > 0 && length <= 512 && length.is_multiple_of(4));
            let address = u32::from(u16::from_le_bytes([setup[2], setup[3]]));
            assert_eq!(address & 3, 0);
            let index = u16::from_le_bytes([setup[4], setup[5]]);
            let bank = index & 0xff00;
            assert!(matches!(bank, USB | PLA));
            let mapped = if bank == PLA && address & 0xf000 == 0xb000 {
                (address & 0xfff) | self.base
            } else {
                address
            };
            match setup[0] {
                0xc0 => {
                    assert_eq!(length, 4);
                    assert!(output.is_empty());
                    if address == PLA_CR & !3 && self.reset > 0 && !self.stuck_reset {
                        self.reset -= 1;
                        if self.reset == 0 {
                            self.set(PLA, PLA_CR, 1, 0);
                        }
                    }
                    if mapped == MII_BMCR && self.phy_reset > 0 && !self.stuck_phy {
                        self.phy_reset -= 1;
                        if self.phy_reset == 0 {
                            self.set(PLA, MII_BMCR, 2, BMCR_ANENABLE_RESTART);
                        }
                    }
                    if address == PLA_PHYSTATUS {
                        self.set(
                            PLA,
                            PLA_PHYSTATUS,
                            2,
                            if self.link { self.phy_status } else { 0 },
                        );
                    }
                    let mut value = self.get(bank, mapped, 4);
                    if address == PLA_OOB_CTRL & !3 && self.stuck_list {
                        value &= !(LINK_LIST_READY << 24);
                    }
                    let mut bytes = value.to_le_bytes().to_vec();
                    if self.short_at == Some(at) {
                        bytes.pop();
                    }
                    Ok(bytes)
                }
                0x40 => {
                    assert_eq!(output.len(), length);
                    let enables = index as u8;
                    assert_eq!(enables & 0xf, enables >> 4);
                    let lanes = enables & 0xf;
                    assert!(matches!(lanes, 1 | 2 | 4 | 8 | 3 | 12 | 15));
                    let teredo_events = self.get(PLA, PLA_TEREDO_CFG, 1);
                    let teredo_w1c = bank == PLA
                        && mapped == PLA_TEREDO_CFG
                        && lanes & 1 != 0
                        && (self.get(PLA, PLA_TCR0, 4) >> 16 & VERSION_MASK) >= 0x6000;
                    for (lane, byte) in output.iter().enumerate() {
                        if lanes & (1 << (lane % 4)) != 0 {
                            self.registers.insert((bank, mapped + lane as u32), *byte);
                        }
                    }
                    if teredo_w1c {
                        self.set(
                            PLA,
                            PLA_TEREDO_CFG,
                            1,
                            teredo_events & !u32::from(output[0]),
                        );
                    }
                    if address == PLA_OCP_GPHY_BASE {
                        self.base = self.get(PLA, PLA_OCP_GPHY_BASE, 2);
                    }
                    if address == PLA_CR & !3 && self.get(PLA, PLA_CR, 1) & CR_RST != 0 {
                        self.reset = 3;
                    }
                    if mapped == MII_BMCR && self.get(PLA, MII_BMCR, 2) & BMCR_RESET != 0 {
                        self.phy_reset = 3;
                    }
                    Ok(Vec::new())
                }
                _ => panic!("unexpected vendor control type"),
            }
        }
    }

    pub(crate) struct Io(pub Rc<RefCell<Model>>);
    impl Control for Io {
        fn control(&mut self, setup: [u8; 8], output: &[u8]) -> Result<Vec<u8>, BlockError> {
            self.0.borrow_mut().request(setup, output)
        }
        fn delay_us(&mut self, us: u64) {
            self.0.borrow_mut().delays.push(us);
        }
    }

    #[test]
    fn rtl8152_revisions_initialize_both_usb_fifo_modes_and_follow_carrier() {
        for revision in [0x4c00, 0x4c10, 0x4800] {
            for full_speed in [false, true] {
                let model = Rc::new(RefCell::new(Model::new(revision)));
                let (mut chip, mac) =
                    Chip::attach(Io(model.clone()), Revision(revision), full_speed).unwrap();
                assert_eq!(mac, Mac([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
                assert_eq!(
                    model.borrow().get(PLA, PLA_RXFIFO_CTRL1, 4),
                    if full_speed { 0x60 } else { 0x38 }
                );
                assert_eq!(
                    model.borrow().get(PLA, PLA_RXFIFO_CTRL2, 4),
                    if full_speed { 0x78 } else { 0x48 }
                );
                assert_eq!(model.borrow().get(PLA, PLA_CR, 1), 0);
                assert!(chip.carrier().unwrap());
                assert_eq!(model.borrow().get(PLA, PLA_CR, 1), 12);
                assert_eq!(model.borrow().get(PLA, PLA_RCR, 4) & 15, 14);
                model.borrow_mut().link = false;
                assert!(!chip.carrier().unwrap());
                chip.stop().unwrap();
                assert_eq!(model.borrow().get(PLA, PLA_CR, 1), 0);
                model.borrow_mut().link = true;
                assert!(chip.carrier().unwrap());
            }
        }
    }

    #[test]
    fn no_further_register_access_after_any_failed_initialization_transaction() {
        for revision in [0x4c00, 0x4c10, 0x4800] {
            let model = Rc::new(RefCell::new(Model::new(revision)));
            Chip::attach(Io(model.clone()), Revision(revision), false).unwrap();
            let operations = model.borrow().trace.len();
            assert!(operations > 80);
            for fail_at in 0..operations {
                let model = Rc::new(RefCell::new(Model::new(revision)));
                model.borrow_mut().fail_at = Some(fail_at);
                assert!(Chip::attach(Io(model.clone()), Revision(revision), false).is_err());
                assert_eq!(model.borrow().trace.len(), fail_at + 1);
            }
        }
        let model = Rc::new(RefCell::new(Model::new(0x4c10)));
        let (mut chip, _) = Chip::attach(Io(model.clone()), Revision(0x4c10), false).unwrap();
        let next = model.borrow().trace.len();
        model.borrow_mut().short_at = Some(next);
        assert!(chip.carrier().is_err());
        assert!(chip.carrier().is_err());
        assert_eq!(model.borrow().trace.len(), next + 1);
    }

    #[test]
    fn revision01_reads_idr_preserves_station_and_masks_only_led_mode() {
        for full_speed in [false, true] {
            let model = Rc::new(RefCell::new(Model::new(0x4c00)));
            model.borrow_mut().set(PLA, PLA_IDR, 4, 0x05040302);
            model.borrow_mut().set(PLA, PLA_IDR + 4, 4, 0x88770706);
            model.borrow_mut().set(PLA, PLA_BACKUP, 4, 0);
            model.borrow_mut().set(PLA, PLA_BACKUP + 4, 4, 0);
            model.borrow_mut().set(PLA, PLA_LED_FEATURE, 2, 0xa75a);
            let (mut chip, mac) =
                Chip::attach(Io(model.clone()), Revision(0x4c00), full_speed).unwrap();
            assert_eq!(mac.0, [2, 3, 4, 5, 6, 7]);
            assert_eq!(model.borrow().get(PLA, PLA_LED_FEATURE, 2), 0xa05a);
            assert_eq!(model.borrow().get(PLA, PLA_IDR + 4, 4), 0x88770706);
            assert!(model.borrow().trace.iter().all(|(request, _)| {
                request[0] != 0x40
                    || !matches!(
                        u16::from_le_bytes([request[2], request[3]]),
                        0xc000 | 0xc004
                    )
            }));
            assert!(chip.carrier().unwrap());
            chip.stop().unwrap();
        }
        for case in 0..4 {
            let model = Rc::new(RefCell::new(Model::new(0x4c00)));
            match case {
                0 => model.borrow_mut().stuck_reset = true,
                1 => model.borrow_mut().stuck_phy = true,
                2 => model.borrow_mut().stuck_list = true,
                _ => model.borrow_mut().set(PLA, PLA_IDR, 4, 0x05040303),
            }
            assert!(Chip::attach(Io(model), Revision(0x4c00), false).is_err());
        }
    }

    #[test]
    #[ignore = "requires pinned unchanged Linux RTL8152 revision trace"]
    fn unchanged_linux_rtl8152_revision_init_and_station_effects() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let trace =
            std::fs::read_to_string(std::env::var("STELA_RTL8152_REVISION_ORACLE").unwrap())
                .unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
            "982fba3636eed37444bd94b3a862144b26731b163e72bbbe0d7cd1b2b128d4a2"
        );
        let fields = [
            (PLA, PLA_LED_FEATURE, 2),
            (USB, USB_UPS_CTRL, 2),
            (USB, USB_PM_CTRL_STATUS, 2),
            (PLA, PLA_PHY_PWR, 2),
            (PLA, PLA_MAC_PWR_CTRL, 4),
            (PLA, PLA_GPHY_INTR_IMR, 2),
            (PLA, PLA_RSTTALLY, 2),
            (USB, USB_USB_CTRL, 2),
        ];
        let mut count = 0;
        for line in trace.lines() {
            let values: Vec<_> = line.split_whitespace().collect();
            assert_eq!(values.len(), 17);
            let revision = u16::from_str_radix(values[0], 16).unwrap();
            let seed = values[1].parse::<u32>().unwrap();
            let model = Rc::new(RefCell::new(Model::new(revision)));
            for (bank, address, width) in fields {
                model.borrow_mut().set(
                    bank,
                    address,
                    width,
                    if width == 4 {
                        seed | (seed << 16)
                    } else {
                        seed
                    },
                );
            }
            model.borrow_mut().set(PLA, PLA_IDR, 4, 0x05040302);
            model.borrow_mut().set(PLA, PLA_IDR + 4, 4, 0x0706);
            let (_, mac) = Chip::attach(Io(model.clone()), Revision(revision), false).unwrap();
            for (actual, expected) in mac.0.into_iter().zip(&values[3..9]) {
                assert_eq!(
                    u32::from(actual),
                    expected.parse::<u32>().unwrap(),
                    "{line}"
                );
            }
            let writes_idr = model
                .borrow()
                .trace
                .iter()
                .any(|(request, _)| request[0] == 0x40 && request[2..4] == [0, 0xc0]);
            assert_eq!(
                u32::from(writes_idr),
                values[2].parse::<u32>().unwrap(),
                "{line}"
            );
            for ((bank, address, width), expected) in fields.into_iter().zip(&values[9..]) {
                assert_eq!(
                    model.borrow().get(bank, address, width),
                    expected.parse::<u32>().unwrap(),
                    "{line}"
                );
            }
            count += 1;
        }
        assert_eq!(count, 12);
    }

    #[test]
    fn timeout_unknown_revision_and_alignment_are_explicit() {
        for case in 0..3 {
            let model = Rc::new(RefCell::new(Model::new(0x4c10)));
            match case {
                0 => model.borrow_mut().stuck_reset = true,
                1 => model.borrow_mut().stuck_phy = true,
                _ => model.borrow_mut().stuck_list = true,
            }
            assert!(matches!(
                Chip::attach(Io(model), Revision(0x4c10), false),
                Err(BlockError::Timeout)
            ));
        }
        for revision in [0x4c20, 0x5c10, 0x6010, 0x7030, 0x7410, 0xffff] {
            let model = Rc::new(RefCell::new(Model::new(revision)));
            assert!(Chip::attach(Io(model.clone()), Revision(revision), false).is_err());
            assert_eq!(model.borrow().trace.len(), 1);
        }
        let model = Rc::new(RefCell::new(Model::new(0x4c10)));
        let (mut chip, _) = Chip::attach(Io(model.clone()), Revision(0x4c10), false).unwrap();
        let before = model.borrow().trace.len();
        for (address, width) in [(0xe813, 2), (0xe812, 4), (0x10000, 1), (0xe810, 3)] {
            assert!(chip.read(PLA, address, width).is_err());
            assert!(chip.write(PLA, address, width, 0).is_err());
        }
        assert_eq!(model.borrow().trace.len(), before);
    }

    #[test]
    fn backup_station_address_is_validated_then_restored_with_write_gate() {
        let model = Rc::new(RefCell::new(Model::new(0x4c10)));
        let (_chip, mac) = Chip::attach(Io(model.clone()), Revision(0x4c10), false).unwrap();
        assert_eq!(mac.0, [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(model.borrow().get(PLA, PLA_IDR, 4), 0x33221102);
        assert_eq!(model.borrow().get(PLA, PLA_IDR + 4, 2), 0x5544);
        assert_eq!(model.borrow().get(PLA, PLA_CRWECR, 1), 0);
        for first in [0, 1, u32::MAX] {
            let model = Rc::new(RefCell::new(Model::new(0x4c10)));
            model.borrow_mut().set(PLA, PLA_BACKUP, 4, first);
            model.borrow_mut().set(PLA, PLA_BACKUP + 4, 4, 0);
            assert!(Chip::attach(Io(model.clone()), Revision(0x4c10), false).is_err());
            assert_eq!(model.borrow().trace.len(), 3);
        }
    }

    #[test]
    #[ignore = "requires unchanged pinned Linux source oracle; see tests/reference/rtl8152_oracle.py"]
    fn unchanged_linux_ocp_request_trace_matches_native_helpers() {
        extern crate std;
        use core::fmt::Write;
        let model = Rc::new(RefCell::new(Model::new(0x4c10)));
        let mut chip = Chip {
            io: Io(model.clone()),
            revision: Revision(0x4c10),
            base: None,
            accessible: true,
            enabled: false,
            initialized: false,
            usb_speed: 0,
        };
        for bank in [USB, PLA] {
            for address in 0xc000..0xc020 {
                chip.write(bank, address, 1, address * 7).unwrap();
                chip.read(bank, address, 1).unwrap();
            }
            for address in (0xe000..0xe020).step_by(2) {
                chip.write(bank, address, 2, address * 11).unwrap();
                chip.read(bank, address, 2).unwrap();
            }
            for address in (0xd000..0xd020).step_by(4) {
                chip.write(bank, address, 4, address * 0x1234).unwrap();
                chip.read(bank, address, 4).unwrap();
            }
        }
        for address in (0x2010..0xf000).step_by(0x102) {
            chip.phy_write(address, address * 7).unwrap();
            let mapped = chip.phy_address(address).unwrap();
            chip.read(PLA, mapped, 2).unwrap();
        }
        let mut actual = alloc::string::String::new();
        for (request, bytes) in &model.borrow().trace {
            for byte in request {
                write!(actual, "{byte:02x}").unwrap();
            }
            actual.push(':');
            for byte in bytes {
                write!(actual, "{byte:02x}").unwrap();
            }
            actual.push('\n');
        }
        let path = std::env::var("STELA_RTL8152_ORACLE").expect("path to generated donor trace");
        assert_eq!(actual, std::fs::read_to_string(path).unwrap());
    }
}
