// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2011-2013 ASIX
//! Native AX88179/178A register/PHY backend derived from pinned Linux usbnet.
//! DMA, configuration acknowledgement and endpoint quarantine stay in the
//! parent USB Ethernet transport; this module never owns controller rings.
use super::Control;
use crate::{block::BlockError, net::Mac};
use alloc::vec::Vec;
mod framing;
pub(super) use framing::{decode, encode};
mod identity;
mod led;
mod legacy;
#[cfg(test)]
pub(crate) mod model;
#[cfg(test)]
pub(crate) use legacy::model::Hardware as LegacyModel;
mod registers;
pub(super) use identity::{Identity, identify};
use registers::*;

/// Exact endpoint-zero transfers shared by both ASIX register protocols.
#[allow(clippy::too_many_arguments)]
fn request<C: Control>(
    io: &mut C,
    accessible: &mut bool,
    command: u8,
    value: u16,
    index: u16,
    data: &[u8],
    length: usize,
    read: bool,
) -> Result<Vec<u8>, BlockError> {
    if !*accessible {
        return Err(BlockError::Unsupported("ASIX register access poisoned"));
    }
    let request = crate::usb::xhci::setup(
        if read { 0xc0 } else { 0x40 },
        command,
        value,
        index,
        length as u16,
    );
    let result = io.control(request, data);
    match result {
        Ok(bytes) if bytes.len() == if read { length } else { 0 } => Ok(bytes),
        Ok(_) => {
            *accessible = false;
            Err(BlockError::Unsupported("ASIX short register transfer"))
        }
        Err(error) => {
            *accessible = false;
            Err(error)
        }
    }
}
pub(super) struct Chip<C> {
    io: C,
    accessible: bool,
    initialized: bool,
    status: Option<u16>,
    pub(super) general_status: u8,
    pub(super) phy_id: u32,
}

impl<C: Control> Chip<C> {
    fn request(
        &mut self,
        command: u8,
        value: u16,
        index: u16,
        data: &[u8],
        length: usize,
        read: bool,
    ) -> Result<Vec<u8>, BlockError> {
        request(
            &mut self.io,
            &mut self.accessible,
            command,
            value,
            index,
            data,
            length,
            read,
        )
    }

    fn read(
        &mut self,
        command: u8,
        value: u16,
        index: u16,
        length: usize,
    ) -> Result<Vec<u8>, BlockError> {
        self.request(command, value, index, &[], length, true)
    }
    fn write(
        &mut self,
        command: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<(), BlockError> {
        self.request(command, value, index, data, data.len(), false)
            .map(|_| ())
    }
    fn mac_read(&mut self, address: u16, width: usize) -> Result<u16, BlockError> {
        let bytes = self.read(AX_ACCESS_MAC, address, width as u16, width)?;
        Ok(if width == 1 {
            u16::from(bytes[0])
        } else {
            u16::from_le_bytes(bytes.try_into().unwrap())
        })
    }
    fn mac_write(&mut self, address: u16, width: usize, value: u16) -> Result<(), BlockError> {
        self.write(
            AX_ACCESS_MAC,
            address,
            width as u16,
            &value.to_le_bytes()[..width],
        )
    }
    fn phy_read(&mut self, address: u16) -> Result<u16, BlockError> {
        let bytes = self.read(AX_ACCESS_PHY, AX88179_PHY_ID, address, 2)?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }
    fn phy_write(&mut self, address: u16, value: u16) -> Result<(), BlockError> {
        self.write(AX_ACCESS_PHY, AX88179_PHY_ID, address, &value.to_le_bytes())
    }
    fn eeprom(&mut self, word: u16) -> Result<u16, BlockError> {
        let bytes = self.read(AX_ACCESS_EEPROM, word, 1, 2)?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }
    fn timeout(&mut self) -> BlockError {
        self.accessible = false;
        self.initialized = false;
        BlockError::Timeout
    }
    pub(super) fn attach(io: C) -> Result<(Self, Mac), BlockError> {
        let mut chip = Self {
            io,
            accessible: true,
            initialized: false,
            status: None,
            general_status: 0,
            phy_id: 0,
        };
        chip.mac_write(AX_PHYPWR_RSTCTL, 2, 0)?;
        chip.mac_write(AX_PHYPWR_RSTCTL, 2, AX_PHYPWR_RSTCTL_IPRL)?;
        chip.io.delay_us(500_000);
        chip.mac_write(AX_CLK_SELECT, 1, AX_CLK_SELECT_ACS | AX_CLK_SELECT_BCS)?;
        chip.io.delay_us(200_000);
        let detach = chip.eeprom(EEPROM_AUTODETACH)?;
        if detach != 0xffff && detach & EEPROM_AUTODETACH_ENABLE != 0 {
            let clock = chip.mac_read(AX_CLK_SELECT, 1)?;
            chip.mac_write(AX_CLK_SELECT, 1, clock | AX_CLK_SELECT_ULR)?;
            let power = chip.mac_read(AX_PHYPWR_RSTCTL, 2)?;
            chip.mac_write(AX_PHYPWR_RSTCTL, 2, power | AX_PHYPWR_RSTCTL_AT)?;
        }
        // The internal PHY's standard identification words must be readable.
        // Their complete value is retained rather than replaced with a rebrand
        // assumption. UA1/UA2 handling comes from GENERAL_STATUS below.
        chip.phy_id =
            (u32::from(chip.phy_read(MII_PHYSID1)?) << 16) | u32::from(chip.phy_read(MII_PHYSID2)?);
        if matches!(chip.phy_id, 0 | 0xffff_ffff) {
            return Err(BlockError::Unsupported("ASIX absent internal PHY identity"));
        }
        let address = chip.read(AX_ACCESS_MAC, AX_NODE_ID, 6, 6)?;
        let mac = Mac(address.as_slice().try_into().unwrap());
        if mac.0[0] & 1 != 0 || mac.0.iter().all(|b| *b == 0) {
            return Err(BlockError::Unsupported(
                "ASIX invalid permanent station address",
            ));
        }
        chip.write(AX_ACCESS_MAC, AX_NODE_ID, 6, &mac.0)?;
        chip.write(AX_ACCESS_MAC, AX_RX_BULKIN_QCTRL, 5, &BULKIN[0])?;
        chip.mac_write(AX_PAUSE_WATERLVL_LOW, 1, 0x34)?;
        chip.mac_write(AX_PAUSE_WATERLVL_HIGH, 1, 0x52)?;
        // Native packets carry no checksum/TSO metadata. Hardware offload must
        // therefore be disabled in both directions rather than claimed complete.
        chip.mac_write(AX_RXCOE_CTL, 1, 0)?;
        chip.mac_write(AX_TXCOE_CTL, 1, 0)?;
        chip.mac_write(AX_RX_CTL, 2, RX_CONTROL)?;
        chip.mac_write(
            AX_MONITOR_MOD,
            1,
            AX_MONITOR_MODE_PMETYPE | AX_MONITOR_MODE_PMEPOL | AX_MONITOR_MODE_RWMP,
        )?;
        chip.mac_write(
            AX_MEDIUM_STATUS_MODE,
            2,
            MEDIUM_BASE | AX_MEDIUM_FULL_DUPLEX | AX_MEDIUM_GIGAMODE,
        )?;
        chip.led_setting()?;
        chip.phy_write(GMII_PHY_PAGE_SELECT, GMII_PHY_PGSEL_PAGE3)?;
        chip.phy_write(MII_PHYADDR, 0x3246)?; // MII_PHYADDR, ax88179_disable_eee.
        chip.phy_write(GMII_PHY_PAGE_SELECT, GMII_PHY_PGSEL_PAGE0)?;
        // MMD AN EEE advertisement (ax88179_phy_write_mmd_indirect).
        chip.phy_write(MII_MMD_CTRL, MDIO_MMD_AN)?;
        chip.phy_write(MII_MMD_DATA, MDIO_AN_EEE_ADV)?;
        chip.phy_write(MII_MMD_CTRL, MDIO_MMD_AN | MII_MMD_CTRL_NOINCR)?;
        chip.phy_write(MII_MMD_DATA, 0)?;
        let bmcr = chip.phy_read(MII_BMCR)?;
        if bmcr & BMCR_ANENABLE == 0 {
            return Err(BlockError::Unsupported(
                "ASIX PHY autonegotiation disabled after reset",
            ));
        }
        chip.phy_write(MII_BMCR, bmcr | BMCR_ANRESTART)?; // mii_nway_restart preserves other PHY controls.
        chip.initialized = true;
        Ok((chip, mac))
    }
    pub(super) fn receive_bytes(&self) -> usize {
        32 * 1024
    }
    pub(super) fn carrier(&mut self) -> Result<bool, BlockError> {
        if !self.initialized {
            return Err(BlockError::Unsupported("ASIX chip is not initialized"));
        }
        let phy = self.phy_read(GMII_PHY_PHYSR)?;
        if phy & GMII_PHY_PHYSR_LINK == 0 {
            return Ok(false);
        }
        let selected = phy & (GMII_PHY_PHYSR_SMASK | GMII_PHY_PHYSR_FULL | GMII_PHY_PHYSR_LINK);
        if self.status == Some(selected) {
            return Ok(true);
        }
        let mut ready = false;
        for _ in 0..100 {
            self.mac_write(AX_RX_CTL, 2, 0)?;
            self.mac_write(AX_RX_CTL, 2, RX_CONTROL)?;
            let bytes = self.read(AX_FIFO_STATUS, AX_FIFO_STATUS_VALUE, 0, 4)?;
            if u32::from_le_bytes(bytes.try_into().unwrap()) & AX_TXFIFO_FULL == 0 {
                ready = true;
                break;
            }
            self.io.delay_us(1000);
        }
        if !ready {
            return Err(self.timeout());
        }
        let bus = self.mac_read(PHYSICAL_LINK_STATUS, 1)?;
        let mut mode = MEDIUM_BASE;
        let queue = match phy & GMII_PHY_PHYSR_SMASK {
            GMII_PHY_PHYSR_GIGA => {
                mode |= AX_MEDIUM_GIGAMODE | AX_MEDIUM_EN_125MHZ;
                if bus & AX_USB_SS != 0 {
                    0
                } else if bus & AX_USB_HS != 0 {
                    1
                } else {
                    3
                }
            }
            GMII_PHY_PHYSR_100 => {
                mode |= AX_MEDIUM_PS;
                if bus & (AX_USB_SS | AX_USB_HS) != 0 {
                    2
                } else {
                    3
                }
            }
            0 => 3,
            _ => {
                return Err(BlockError::Unsupported(
                    "ASIX reserved negotiated PHY speed",
                ));
            }
        };
        self.write(AX_ACCESS_MAC, AX_RX_BULKIN_QCTRL, 5, &BULKIN[queue])?;
        if phy & GMII_PHY_PHYSR_FULL != 0 {
            mode |= AX_MEDIUM_FULL_DUPLEX;
        }
        self.mac_write(AX_MEDIUM_STATUS_MODE, 2, mode)?;
        self.status = Some(selected);
        Ok(true)
    }
    pub(super) fn stop(&mut self) -> Result<(), BlockError> {
        self.status = None;
        let mode = self.mac_read(AX_MEDIUM_STATUS_MODE, 2)?;
        self.mac_write(AX_MEDIUM_STATUS_MODE, 2, mode & !AX_MEDIUM_RECEIVE_EN)?;
        self.mac_write(AX_RX_CTL, 2, 0)
    }
}

const BULKIN: [[u8; 5]; 4] = [
    [7, 0x4f, 0, 0x12, 0xff],
    [7, 0x20, 3, 0x16, 0xff],
    [7, 0xae, 7, 0x18, 0xff],
    [7, 0xcc, 0x4c, 0x18, 8],
];
const RX_CONTROL: u16 = AX_RX_CTL_DROPCRCERR
    | AX_RX_CTL_IPE
    | AX_RX_CTL_START
    | AX_RX_CTL_AP
    | AX_RX_CTL_AMALL
    | AX_RX_CTL_AB;
const MEDIUM_BASE: u16 = AX_MEDIUM_RECEIVE_EN | AX_MEDIUM_TXFLOW_CTRLEN | AX_MEDIUM_RXFLOW_CTRLEN;

#[cfg(test)]
pub(super) fn legacy_ids() -> &'static [(u16, u16, Identity)] {
    identity::LEGACY_IDS
}
#[cfg(test)]
pub(super) fn ids() -> &'static [(u16, u16, Identity)] {
    identity::IDS
}

/// Protocol dispatch only; the parent owns every USB endpoint and DMA lease.
pub(super) enum Device<C> {
    Modern(Chip<C>),
    Legacy(legacy::Chip<C>),
}
impl<C: Control> Device<C> {
    pub(super) fn attach(io: C, identity: Identity) -> Result<(Self, Mac), BlockError> {
        if let Identity::Ax88772 { eeprom_mac } = identity {
            legacy::Chip::attach(io, eeprom_mac).map(|(chip, mac)| (Self::Legacy(chip), mac))
        } else {
            Chip::attach(io).map(|(chip, mac)| (Self::Modern(chip), mac))
        }
    }
    pub(super) fn identity(&self) -> (u8, u32) {
        match self {
            Self::Modern(c) => (c.general_status, c.phy_id),
            Self::Legacy(c) => (c.raw_status, c.phy_id),
        }
    }
    pub(super) fn receive_bytes(&self) -> usize {
        match self {
            Self::Modern(c) => c.receive_bytes(),
            Self::Legacy(_) => 2048,
        }
    }
    pub(super) fn carrier(&mut self) -> Result<bool, BlockError> {
        match self {
            Self::Modern(c) => c.carrier(),
            Self::Legacy(c) => c.carrier(),
        }
    }
    pub(super) fn link_down(&mut self) -> Result<(), BlockError> {
        match self {
            Self::Modern(c) => c.stop(),
            Self::Legacy(c) => c.link_down(),
        }
    }
    pub(super) fn stop(&mut self) -> Result<(), BlockError> {
        match self {
            Self::Modern(c) => c.stop(),
            Self::Legacy(c) => c.stop(),
        }
    }
    pub(super) fn encode(
        &self,
        frame: &[u8],
        output: &mut [u8],
        packet: u16,
    ) -> Result<usize, &'static str> {
        match self {
            Self::Modern(_) => encode(frame, output, packet),
            Self::Legacy(_) => legacy::framing::encode(frame, output, packet),
        }
    }
    pub(super) fn decode(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        match self {
            Self::Modern(_) => decode(bytes),
            Self::Legacy(c) => c.decode(bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        model::{Hardware, Io},
        *,
    };
    use alloc::rc::Rc;
    use core::cell::RefCell;

    #[test]
    fn ax179_real_power_eeprom_efuse_old_led_phy_and_link_states() {
        for bus in [0, 2, 4] {
            for ua2 in [false, true] {
                for source in 0..3 {
                    let hw = Rc::new(RefCell::new(Hardware::new(bus, ua2)));
                    {
                        let mut h = hw.borrow_mut();
                        if source == 0 {
                            h.eeprom.fill(0);
                            h.eeprom[5] = 0xff;
                            h.eeprom[0x42] = 0x8c23;
                        } else if source == 1 {
                            h.efuse.fill(0);
                            h.efuse[51] = 0x8c;
                            h.efuse[52] = 0x23;
                            h.efuse[63] = 255 - 0x8c - 0x23;
                        } else {
                            h.eeprom[0x3c] = 0xfc00;
                        }
                        h.eeprom[0x43] = 0x100;
                    }
                    let (mut chip, mac) = Chip::attach(Io(hw.clone())).unwrap();
                    assert_eq!(mac.0, [2, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
                    assert_eq!(chip.general_status, if ua2 { 4 } else { 0 });
                    assert_eq!(chip.phy_id, 0x0007_c001);
                    let h = hw.borrow();
                    assert_eq!(&h.delays[..2], &[500_000, 200_000]);
                    assert_eq!(h.mac[0x33], 0x0b);
                    assert_eq!(h.word(0x26), 0x1020);
                    assert_eq!(h.mac[0x34], 0);
                    assert_eq!(h.mac[0x35], 0);
                    assert_eq!(h.mmd[&(7, 0x3c)], 0);
                    assert_eq!(h.phy[&(3, 0, 0x19)], 0x3246);
                    assert_eq!(h.phy[&(0, 0, 0)] & 0x1200, 0x1200);
                    assert_eq!(h.mac[0x25], if ua2 { 0 } else { 0xe0 });
                    let led = if source == 2 {
                        led::old_led(0xfc)
                    } else {
                        0x8c23
                    };
                    let (a, l, d) = led::led_masks(led, 0xa55a, 0x5aa5);
                    assert_eq!(h.phy[&(7, 0x2c, 0x1a)], a);
                    assert_eq!(h.phy[&(7, 0x2c, 0x1c)], l);
                    assert_eq!(h.mac[0x73], d);
                    drop(h);
                    for (speed, expected_queue, medium) in [
                        (
                            0x8000,
                            if bus == 4 {
                                0
                            } else if bus == 2 {
                                1
                            } else {
                                3
                            },
                            0x139,
                        ),
                        (0x4000, if bus != 0 { 2 } else { 3 }, 0x330),
                        (0, 3, 0x130),
                    ] {
                        for duplex in [0, 0x2000] {
                            hw.borrow_mut()
                                .phy
                                .insert((0, 0, 0x11), speed | duplex | 0x400);
                            assert!(chip.carrier().unwrap());
                            assert_eq!(&hw.borrow().mac[0x2e..0x33], &BULKIN[expected_queue]);
                            assert_eq!(
                                hw.borrow().word(0x22),
                                medium | if duplex != 0 { 2 } else { 0 }
                            );
                            chip.stop().unwrap();
                            assert_eq!(hw.borrow().word(0x22) & 0x100, 0);
                            assert_eq!(hw.borrow().word(0x0b), 0);
                        }
                    }
                    hw.borrow_mut().phy.insert((0, 0, 0x11), 0);
                    assert!(!chip.carrier().unwrap());
                }
            }
        }
    }

    #[test]
    fn ax179_all_startup_transfer_faults_and_short_reads_poison_access() {
        fn model(source: u8, ua2: bool) -> Hardware {
            let mut h = Hardware::new(4, ua2);
            if source == 0 {
                h.eeprom.fill(0);
                h.eeprom[5] = 0xff;
                h.eeprom[0x42] = 0x8c23;
            }
            if source == 1 {
                h.efuse.fill(0);
                h.efuse[51] = 0x8c;
                h.efuse[52] = 0x23;
                h.efuse[63] = 0x50;
            }
            h.eeprom[0x43] = 0x100;
            h
        }
        for source in 0..3 {
            for ua2 in [false, true] {
                let hw = Rc::new(RefCell::new(model(source, ua2)));
                Chip::attach(Io(hw.clone())).unwrap();
                let count = hw.borrow().trace.len();
                for at in 0..count {
                    let read = hw.borrow().trace[at].0[0] == 0xc0;
                    for short in [false, true] {
                        if short && !read {
                            continue;
                        }
                        let hw = Rc::new(RefCell::new(model(source, ua2)));
                        if short {
                            hw.borrow_mut().short_at = Some(at);
                        } else {
                            hw.borrow_mut().fail_at = Some(at);
                        }
                        assert!(
                            Chip::attach(Io(hw.clone())).is_err(),
                            "{source}/{ua2}/{at}/{short}"
                        );
                        assert_eq!(hw.borrow().trace.len(), at + 1);
                    }
                }
            }
        }
        let hw = Rc::new(RefCell::new(Hardware::new(4, true)));
        let (mut chip, _) = Chip::attach(Io(hw.clone())).unwrap();
        let at = hw.borrow().trace.len();
        hw.borrow_mut().fail_at = Some(at);
        assert!(chip.carrier().is_err());
        assert!(chip.carrier().is_err());
        assert_eq!(hw.borrow().trace.len(), at + 1);
    }

    #[test]
    fn ax179_hardware_deadlines_and_invalid_identity_refuse_success() {
        for case in 0..5 {
            let hw = Rc::new(RefCell::new(Hardware::new(4, true)));
            match case {
                0 => hw.borrow_mut().stuck_srom = true,
                1 => {
                    hw.borrow_mut().phy.insert((0, 0, 2), 0);
                    hw.borrow_mut().phy.insert((0, 0, 3), 0);
                }
                2 => hw.borrow_mut().mac[0x10] = 1,
                3 => {
                    hw.borrow_mut().phy.insert((0, 0, 0), 0);
                }
                _ => hw.borrow_mut().mac[0x10..0x16].fill(0),
            }
            assert!(Chip::attach(Io(hw)).is_err(), "{case}");
        }
        let hw = Rc::new(RefCell::new(Hardware::new(4, true)));
        let (mut chip, _) = Chip::attach(Io(hw.clone())).unwrap();
        hw.borrow_mut().stuck_fifo = true;
        assert!(matches!(chip.carrier(), Err(BlockError::Timeout)));
        let at = hw.borrow().trace.len();
        assert!(chip.carrier().is_err());
        assert_eq!(hw.borrow().trace.len(), at);
    }

    #[test]
    #[ignore = "requires unchanged pinned ASIX command/EEPROM/LED/MMD C oracle"]
    fn unchanged_linux_asix_led_eeprom_mmd_fields() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let fields =
            std::fs::read_to_string(std::env::var("STELA_ASIX_LED_ORACLE").unwrap()).unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(fields.as_bytes())),
            "6767be649469c4a73d2341c5e9f62d1f74a2fc9e40f3a2f37e10d2e49d3ea035"
        );
        let mut count = 0;
        for line in fields.lines() {
            let v: Vec<u32> = line
                .split_whitespace()
                .map(|v| v.parse().unwrap())
                .collect();
            assert_eq!(v.len(), 13);
            let (kind, raw, ua2, detach) = (v[0], v[1] as u16, v[2] != 0, v[3] != 0);
            let selected = if kind != 2 && raw != 0xffff && raw & 0x8000 != 0 {
                raw
            } else {
                led::old_led(if kind == 0 { 0xff } else { raw as u8 })
            };
            let (a, l, d) = led::led_masks(selected, 0xa55a, 0x5aa5);
            assert_eq!(
                (u32::from(a), u32::from(l), u32::from(d)),
                (v[4], v[5], v[6]),
                "{line}"
            );
            assert_eq!(
                &v[7..],
                &[
                    if ua2 { 0 } else { 0xe0 },
                    if detach { 0x0b } else { 3 },
                    if detach { 0x1020 } else { 0x20 },
                    0x3246,
                    0,
                    0
                ],
                "{line}"
            );
            if kind != 0 || raw % 4096 == 0 {
                let hw = Rc::new(RefCell::new(Hardware::new(4, ua2)));
                {
                    let mut h = hw.borrow_mut();
                    h.eeprom[0x3c] = raw.wrapping_shl(8);
                    if kind == 0 {
                        h.eeprom.fill(0);
                        h.eeprom[5] = 0xff;
                        h.eeprom[0x42] = raw;
                        h.eeprom[0x3c] = 0xff00;
                    }
                    if kind == 1 {
                        h.efuse.fill(0);
                        h.efuse[51] = (raw >> 8) as u8;
                        h.efuse[52] = raw as u8;
                        h.efuse[63] =
                            (255 - (u16::from(h.efuse[51]) + u16::from(h.efuse[52])) % 255) as u8;
                    }
                    h.eeprom[0x43] = if detach { 0x100 } else { 0xffff };
                }
                Chip::attach(Io(hw.clone())).unwrap();
                let h = hw.borrow();
                assert_eq!(
                    (
                        u32::from(h.phy[&(7, 0x2c, 0x1a)]),
                        u32::from(h.phy[&(7, 0x2c, 0x1c)]),
                        u32::from(h.mac[0x73])
                    ),
                    (v[4], v[5], v[6]),
                    "{line}"
                );
                assert_eq!(u32::from(h.mac[0x25]), v[7]);
                assert_eq!(u32::from(h.mac[0x33]), v[8]);
                assert_eq!(u32::from(h.word(0x26)), v[9]);
                assert_eq!(u32::from(h.phy[&(3, 0, 0x19)]), v[10]);
                assert_eq!(u32::from(h.mmd[&(7, 0x3c)]), v[11]);
            }
            count += 1;
        }
        assert_eq!(count, 66576);
    }

    #[test]
    #[ignore = "requires unchanged pinned ASIX negotiated-link C oracle"]
    fn unchanged_linux_asix_negotiated_queue_and_medium_fields() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let fields =
            std::fs::read_to_string(std::env::var("STELA_ASIX_LINK_ORACLE").unwrap()).unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(fields.as_bytes())),
            "8b437dc92942d630ae98fc666154363f92ee8087c91cc57b74c4dc258c0f5467"
        );
        let mut count = 0;
        for line in fields.lines() {
            let v: Vec<u32> = line
                .split_whitespace()
                .map(|v| v.parse().unwrap())
                .collect();
            assert_eq!(v.len(), 9);
            let hw = Rc::new(RefCell::new(Hardware::new(v[0] as u8, true)));
            let (mut chip, _) = Chip::attach(Io(hw.clone())).unwrap();
            hw.borrow_mut().phy.insert((0, 0, 0x11), v[1] as u16);
            assert!(chip.carrier().unwrap());
            assert_eq!(u32::from(hw.borrow().word(0x22)), v[2], "{line}");
            for (actual, expected) in hw.borrow().mac[0x2e..0x33].iter().zip(&v[3..8]) {
                assert_eq!(u32::from(*actual), *expected, "{line}");
            }
            assert_eq!(1024 * (u32::from(hw.borrow().mac[0x31]) + 2), v[8]);
            assert!(v[8] as usize <= chip.receive_bytes());
            count += 1;
        }
        assert_eq!(count, 24);
    }

    #[test]
    #[ignore = "requires unchanged pinned ASIX EEPROM/efuse checksum C corpus"]
    fn unchanged_linux_asix_eeprom_and_efuse_checksum_mutations() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let fields =
            std::fs::read_to_string(std::env::var("STELA_ASIX_CHECKSUM_ORACLE").unwrap()).unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(fields.as_bytes())),
            "703da1345df07e177c81cdfd5a3c1f56b9d463ac5ea3d4b99460edb4ab3bf3c2"
        );
        let mut count = 0;
        for line in fields.lines() {
            let v: Vec<_> = line.split_whitespace().collect();
            assert_eq!(v.len(), 3);
            let bytes: Vec<u8> = (0..v[1].len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&v[1][at..at + 2], 16).unwrap())
                .collect();
            let hw = Rc::new(RefCell::new(Hardware::new(4, true)));
            let (mut chip, _) = Chip::attach(Io(hw.clone())).unwrap();
            let valid = if v[0] == "0" {
                assert_eq!(bytes.len(), 12);
                for (i, word) in bytes.as_chunks::<2>().0.iter().enumerate() {
                    hw.borrow_mut().eeprom[i] = u16::from_le_bytes(*word);
                }
                chip.eeprom_valid().unwrap()
            } else {
                assert_eq!(bytes.len(), 64);
                hw.borrow_mut().efuse.copy_from_slice(&bytes);
                chip.efuse_led().unwrap().is_some()
            };
            assert_eq!(valid, v[2] == "1", "{line}");
            count += 1;
        }
        assert_eq!(count, 686);
    }

    #[test]
    #[ignore = "requires unchanged pinned ASIX USB/interface/driver_info initializers"]
    fn unchanged_linux_asix_exact_ids_and_shared_callback_flags() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let text =
            std::fs::read_to_string(std::env::var("STELA_ASIX_IDS_ORACLE").unwrap()).unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(text.as_bytes())),
            "685ea8ff81f174d8a8a2ffc27c7ad5c046b118119ead252220ddb60762bd37d9"
        );
        let mut count = 0;
        for (line, id) in text.lines().zip(identity::IDS) {
            let v: Vec<_> = line.split_whitespace().collect();
            assert_eq!(v.len(), 14);
            let pair = (
                u16::from_str_radix(v[0], 16).unwrap(),
                u16::from_str_radix(v[1], 16).unwrap(),
            );
            assert_eq!(pair, (id.0, id.1));
            let fields: Vec<u32> = v[2..].iter().map(|v| v.parse().unwrap()).collect();
            assert_eq!(fields, [255, 255, 0, 0x60, 1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(
                id.2,
                if pair == (0x0b95, 0x178a) {
                    Identity::Ax88178a
                } else {
                    Identity::Ax88179
                }
            );
            count += 1;
        }
        assert_eq!(count, 13);
        assert_eq!(identity::IDS.len(), 13);
    }
}
