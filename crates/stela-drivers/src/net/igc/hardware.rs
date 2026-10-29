// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2018 Intel Corporation
//! Checked boot-lifetime adaptation of Linux igc_base/mac/phy/nvm/i225.c.
use crate::{Clock, block::BlockError, bus::mmio::Mmio};

pub(super) trait Registers {
    fn read(&self, register: usize) -> u32;
    fn write(&self, register: usize, value: u32);
}

impl Registers for Mmio {
    fn read(&self, register: usize) -> u32 {
        self.read32(register)
    }
    fn write(&self, register: usize, value: u32) {
        self.write32(register, value);
    }
}
pub(super) trait Timer {
    fn delay(&self, microseconds: u64);
}
impl Timer for Clock {
    fn delay(&self, microseconds: u64) {
        Clock::delay(self, microseconds);
    }
}

const CTRL: usize = 0;
const STATUS: usize = 8;
const EECD: usize = 0x10;
const CTRL_EXT: usize = 0x18;
const MDIC: usize = 0x20;
const FCAL: usize = 0x28;
const FCAH: usize = 0x2c;
const FCT: usize = 0x30;
const RCTL: usize = 0x100;
const FCTTV: usize = 0x170;
const LTRMINV: usize = 0x5bb0;
const LTRMAXV: usize = 0x5bb4;
const TCTL: usize = 0x400;
const FCRTL: usize = 0x2160;
const FCRTH: usize = 0x2168;
const PHPM: usize = 0xe14;
const EEER: usize = 0xe30;
const IPCNFG: usize = 0xe38;
const IMC: usize = 0x150c;
const ICR: usize = 0x1500;
const EIMC: usize = 0x1528;
const RXPBS: usize = 0x2404;
const TXPBS: usize = 0x3404;
const RLPML: usize = 0x5004;
const RXCSUM: usize = 0x5000;
const RFCTL: usize = 0x5008;
const MTA: usize = 0x5200;
const RAL: usize = 0x5400;
const MANC: usize = 0x5820;
const SWSM: usize = 0x5b50;
const SW_FW_SYNC: usize = 0x5b5c;
const EERD: usize = 0x12014;
/// Queue `index`'s receive descriptor control.
const fn rxdctl(index: usize) -> usize {
    0xc028 + index * 0x40
}
const MPC: usize = 0x4010;
const RNBC: usize = 0x40a0;
const ROC: usize = 0x40ac;
/// Every clear-on-read counter igc_clear_hw_cntrs_base reads, CRCERRS
/// through LENERRS.
const COUNTERS: [usize; 66] = [
    0x4000, 0x4010, 0x4014, 0x4018, 0x401c, 0x4020, 0x4028, 0x402c, 0x4030, 0x4040, 0x4048, 0x404c,
    0x4050, 0x4054, 0x4058, 0x4074, 0x4078, 0x407c, 0x4080, 0x4088, 0x408c, 0x4090, 0x4094, 0x40a0,
    0x40a4, 0x40a8, 0x40ac, 0x40b0, 0x40c0, 0x40c4, 0x40c8, 0x40cc, 0x40d0, 0x40d4, 0x40f0, 0x40f4,
    0x405c, 0x4060, 0x4064, 0x4068, 0x406c, 0x4070, 0x40d8, 0x40dc, 0x40e0, 0x40e4, 0x40e8, 0x40ec,
    0x4004, 0x400c, 0x4034, 0x403c, 0x40f8, 0x40b4, 0x40b8, 0x40bc, 0x4100, 0x4104, 0x4148, 0x414c,
    0x4118, 0x4120, 0x4128, 0x412c, 0x4130, 0x4134,
];
const LENERRS: usize = 0x4138;

const MASTER_DISABLE: u32 = 1 << 2;
const MASTER_ENABLED: u32 = 1 << 19;
const MAC_RESET: u32 = 1 << 26;
const PHY_RESET: u32 = 1 << 31;
const AUTO_READ_DONE: u32 = 1 << 9;
const FLASH_PRESENT: u32 = 1 << 19;
const SMBI: u32 = 1;
const SWESMBI: u32 = 2;
const PHY_SYNC: u32 = 2;
const NVM_SYNC: u32 = 1;
const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
const MDIC_READ: u32 = 1 << 27;
const MDIC_WRITE: u32 = 1 << 26;
const MMD_CONTROL: u16 = 13;
const MMD_DATA: u16 = 14;
const PHY_CONTROL: u16 = 0;
const PHY_STATUS: u16 = 1;
const PHY_ADVERTISEMENT: u16 = 4;
const PHY_PARTNER: u16 = 5;
const PHY_GIGABIT: u16 = 9;
const PHY_GIGABIT_STATUS: u16 = 10;
const MII_LINK: u16 = 1 << 2;
const MII_AUTONEG_COMPLETE: u16 = 1 << 5;
const PAUSE: u16 = 1 << 10;
const ASYMMETRIC_PAUSE: u16 = 1 << 11;
const REMOTE_RECEIVER_OK: u16 = 1 << 12;
const STATUS_FD: u32 = 1;
const STATUS_SPEED_100: u32 = 1 << 6;
const STATUS_SPEED_1000: u32 = 1 << 7;
const STATUS_SPEED_2500: u32 = 1 << 22;
const CTRL_RFCE: u32 = 1 << 27;
const CTRL_TFCE: u32 = 1 << 28;
const MANC_RCV_TCO_EN: u32 = 1 << 17;
const RFCTL_IPV6_EX_DIS: u32 = 1 << 16;
const RFCTL_LEF: u32 = 1 << 18;
const RCTL_EN: u32 = 1 << 1;
const RCTL_SBP: u32 = 1 << 2;
const RCTL_LPE: u32 = 1 << 5;
const RXDCTL_ENABLE: u32 = 1 << 25;
const TCTL_EN: u32 = 1 << 1;
const DRV_LOAD: u32 = 1 << 28;
/// igc_reset: the 34 KiB receive packet buffer less one standard frame
/// (1500 MTU, header, FCS and VLAN tag) and one 9728-byte jumbo frame,
/// at 16-byte granularity; XON resumes 16 bytes below it.
const HIGH_WATER: u32 = ((34 << 10) - (1522 + 0x2600)) & 0xffff_fff0;
const LOW_WATER: u32 = HIGH_WATER - 16;
const FCRTL_XONE: u32 = 1 << 31;
const PAUSE_TIME: u32 = 0xffff;
const LTR_SNOOP: u32 = 1 << 15;
const LTR_SCALE_1024: u32 = 2;
const LTR_SCALE_32768: u32 = 3;

/// The MAC's clear-on-read counters, accumulated as igc_update_stats does.
/// Octet counters are 64-bit pairs that clear when the high half is read;
/// reading low then high keeps the high half Linux's 32-bit sums drop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    pub crc_errors: u64,
    pub alignment_errors: u64,
    pub receive_errors: u64,
    pub length_errors: u64,
    /// Frames dropped for lack of receive packet buffer space.
    pub missed: u64,
    /// Frames dropped for lack of a receive descriptor.
    pub no_buffers: u64,
    pub undersize: u64,
    pub fragments: u64,
    pub oversize: u64,
    pub jabbers: u64,
    pub single_collisions: u64,
    pub multiple_collisions: u64,
    pub excessive_collisions: u64,
    pub late_collisions: u64,
    pub collisions: u64,
    pub deferred: u64,
    pub xon_received: u64,
    pub xon_transmitted: u64,
    pub xoff_received: u64,
    pub xoff_transmitted: u64,
    pub unsupported_flow_control: u64,
    pub good_received: u64,
    pub broadcast_received: u64,
    pub multicast_received: u64,
    pub good_octets_received: u64,
    pub total_received: u64,
    pub total_octets_received: u64,
    pub good_transmitted: u64,
    pub broadcast_transmitted: u64,
    pub multicast_transmitted: u64,
    pub good_octets_transmitted: u64,
    pub total_transmitted: u64,
    pub total_octets_transmitted: u64,
}

impl Statistics {
    /// Add every counter's value since the last read. A failed status read
    /// means the function is gone; the totals then stay as they were.
    pub(super) fn accumulate<R: Registers>(&mut self, registers: &R) -> Result<(), BlockError> {
        if registers.read(STATUS) == u32::MAX {
            return Err(BlockError::Device { status: u32::MAX });
        }
        let read = |register| u64::from(registers.read(register));
        let pair = |low| read(low) | read(low + 4) << 32;
        let mut next = *self;
        for (total, register) in [
            (&mut next.crc_errors, 0x4000),
            (&mut next.alignment_errors, 0x4004),
            (&mut next.receive_errors, 0x400c),
            (&mut next.missed, MPC),
            (&mut next.single_collisions, 0x4014),
            (&mut next.excessive_collisions, 0x4018),
            (&mut next.multiple_collisions, 0x401c),
            (&mut next.late_collisions, 0x4020),
            (&mut next.collisions, 0x4028),
            (&mut next.deferred, 0x4030),
            (&mut next.length_errors, 0x4040),
            (&mut next.xon_received, 0x4048),
            (&mut next.xon_transmitted, 0x404c),
            (&mut next.xoff_received, 0x4050),
            (&mut next.xoff_transmitted, 0x4054),
            (&mut next.unsupported_flow_control, 0x4058),
            (&mut next.good_received, 0x4074),
            (&mut next.broadcast_received, 0x4078),
            (&mut next.multicast_received, 0x407c),
            (&mut next.good_transmitted, 0x4080),
            (&mut next.no_buffers, RNBC),
            (&mut next.undersize, 0x40a4),
            (&mut next.fragments, 0x40a8),
            (&mut next.oversize, ROC),
            (&mut next.jabbers, 0x40b0),
            (&mut next.total_received, 0x40d0),
            (&mut next.total_transmitted, 0x40d4),
            (&mut next.multicast_transmitted, 0x40f0),
            (&mut next.broadcast_transmitted, 0x40f4),
        ] {
            *total = total.wrapping_add(read(register));
        }
        for (total, low) in [
            (&mut next.good_octets_received, 0x4088),
            (&mut next.good_octets_transmitted, 0x4090),
            (&mut next.total_octets_received, 0x40c0),
            (&mut next.total_octets_transmitted, 0x40c8),
        ] {
            *total = total.wrapping_add(pair(low));
        }
        *self = next;
        Ok(())
    }
}

/// Resolved pause frame use, Linux `enum igc_fc_mode` without its default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowControl {
    None,
    /// Honor received PAUSE frames; never send them.
    ReceivePause,
    /// Send PAUSE frames; ignore received ones.
    TransmitPause,
    Full,
}

/// The negotiated copper link igc_check_for_copper_link observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Negotiated {
    /// Megabits per second: 10, 100, 1000 or 2500.
    pub speed: u16,
    pub full_duplex: bool,
    pub flow_control: FlowControl,
}
const MMD_AN: u16 = 7;
const MMD_MULTIGIG: u16 = 32;

/// Linux igc_rx_fifo_flush_base, after the receive queues are programmed and
/// before any receive buffer is offered: the IPv6 extension-header erratum,
/// then, when manageability receives TCO traffic, a 2 ms flush of the packets
/// that arrived while receive was enabling. A queue that does not report
/// itself disabled within 10 ms is logged-and-continued in Linux; with no
/// buffer offered yet nothing can be written, so the flush proceeds too.
pub(super) fn flush_receive_fifo<R: Registers, T: Timer>(
    registers: &R,
    timer: &T,
) -> Result<(), BlockError> {
    let read = |register| match registers.read(register) {
        u32::MAX => Err(BlockError::Device { status: u32::MAX }),
        value => Ok(value),
    };
    let rfctl = read(RFCTL)? | RFCTL_IPV6_EX_DIS;
    registers.write(RFCTL, rfctl);
    if read(MANC)? & MANC_RCV_TCO_EN == 0 {
        return Ok(());
    }
    let mut queues = [0; 4];
    for (index, control) in queues.iter_mut().enumerate() {
        *control = read(rxdctl(index))?;
        registers.write(rxdctl(index), *control & !RXDCTL_ENABLE);
    }
    for _ in 0..10 {
        timer.delay(1_000);
        let mut enabled = 0;
        for index in 0..queues.len() {
            enabled |= read(rxdctl(index))?;
        }
        if enabled & RXDCTL_ENABLE == 0 {
            break;
        }
    }
    // Reject every incoming packet while receive is briefly enabled.
    registers.write(RFCTL, rfctl & !RFCTL_LEF);
    let rlpml = read(RLPML)?;
    registers.write(RLPML, 0);
    let rctl = read(RCTL)?;
    let rejecting = rctl & !(RCTL_EN | RCTL_SBP) | RCTL_LPE;
    registers.write(RCTL, rejecting);
    registers.write(RCTL, rejecting | RCTL_EN);
    read(STATUS)?;
    timer.delay(2_000);
    for (index, control) in queues.into_iter().enumerate() {
        registers.write(rxdctl(index), control);
    }
    registers.write(RCTL, rctl);
    read(STATUS)?;
    registers.write(RLPML, rlpml);
    registers.write(RFCTL, rfctl);
    // The receive errors the flush itself generated.
    for counter in [ROC, RNBC, MPC] {
        registers.read(counter);
    }
    Ok(())
}

pub(super) struct Hardware<'a, R: Registers, T: Timer> {
    registers: &'a R,
    timer: &'a T,
    semaphore_attempts: usize,
    clear_semaphore_once: bool,
}

impl<'a, R: Registers, T: Timer> Hardware<'a, R, T> {
    pub(super) fn new(registers: &'a R, timer: &'a T) -> Result<Self, BlockError> {
        let eecd = registers.read(EECD);
        if eecd == u32::MAX {
            return Err(BlockError::Device { status: eecd });
        }
        // igc_init_nvm_params_base: NVM word count bounds semaphore polls.
        let shift = (((eecd & 0x7800) >> 11) + 6).min(15);
        Ok(Self {
            registers,
            timer,
            semaphore_attempts: (1usize << shift) + 1,
            clear_semaphore_once: true,
        })
    }

    fn read(&self, register: usize) -> Result<u32, BlockError> {
        let value = self.registers.read(register);
        if value == u32::MAX {
            Err(BlockError::Device { status: value })
        } else {
            Ok(value)
        }
    }
    fn modify(&self, register: usize, clear: u32, set: u32) -> Result<(), BlockError> {
        let value = self.read(register)?;
        self.registers.write(register, value & !clear | set);
        Ok(())
    }
    fn poll(
        &self,
        register: usize,
        mask: u32,
        set: bool,
        attempts: usize,
        delay: u64,
    ) -> Result<u32, BlockError> {
        for _ in 0..attempts {
            let value = self.read(register)?;
            if (value & mask != 0) == set {
                return Ok(value);
            }
            self.timer.delay(delay);
        }
        Err(BlockError::Timeout)
    }

    fn reset(&self) -> Result<(), BlockError> {
        self.registers.write(IMC, u32::MAX);
        self.registers.write(EIMC, u32::MAX);
        self.modify(CTRL, 0, MASTER_DISABLE)?;
        // Unlike Linux's log-and-continue recovery, a fresh Stela attachment
        // never continues past an uncertain DMA drain or NVM load.
        self.poll(STATUS, MASTER_ENABLED, false, 800, 2_000)?;
        self.registers.write(RCTL, 0);
        self.registers.write(TCTL, 1 << 3);
        self.read(STATUS)?; // Posted write flush before the required settle.
        self.timer.delay(10_000);
        self.modify(CTRL, 0, MAC_RESET)?;
        self.poll(CTRL, MAC_RESET, false, 10, 1_000)?;
        self.poll(EECD, AUTO_READ_DONE, true, 10, 1_000)?;
        self.registers.write(IMC, u32::MAX);
        self.registers.write(EIMC, u32::MAX);
        self.read(ICR)?;
        Ok(())
    }

    /// Linux igc_down's register sequence: stop receive and transmit, give
    /// in-flight frames 10 ms, then igc_reset's MAC reset after the bus master
    /// drain. Only a completed reset proves the controller writes no ring.
    pub(super) fn stop(&self) -> Result<(), BlockError> {
        self.modify(RCTL, RCTL_EN, 0)?;
        self.modify(TCTL, TCTL_EN, 0)?;
        self.read(STATUS)?;
        self.timer.delay(10_000);
        self.reset()
    }

    /// igc_release_hw_control: hand the controller back to manageability
    /// firmware once the driver no longer owns it.
    pub(super) fn release_control(&self) -> Result<(), BlockError> {
        self.modify(CTRL_EXT, DRV_LOAD, 0)
    }

    fn put_hw_semaphore(&self) -> Result<(), BlockError> {
        self.modify(SWSM, SMBI | SWESMBI, 0)
    }
    fn hw_semaphore(&mut self) -> Result<(), BlockError> {
        let mut acquired = false;
        for retry in 0..2 {
            for _ in 0..self.semaphore_attempts {
                if self.read(SWSM)? & SMBI == 0 {
                    acquired = true;
                    break;
                }
                self.timer.delay(500);
            }
            if acquired {
                break;
            }
            if retry != 0 || !self.clear_semaphore_once {
                return Err(BlockError::Timeout);
            }
            self.clear_semaphore_once = false;
            self.put_hw_semaphore()?;
        }
        for _ in 0..self.semaphore_attempts {
            self.modify(SWSM, 0, SWESMBI)?;
            if self.read(SWSM)? & SWESMBI != 0 {
                return Ok(());
            }
            self.timer.delay(500);
        }
        self.put_hw_semaphore()?;
        Err(BlockError::Timeout)
    }
    fn acquire(&mut self, mask: u32) -> Result<(), BlockError> {
        for _ in 0..200 {
            self.hw_semaphore()?;
            let result = self.read(SW_FW_SYNC);
            let value = match result {
                Ok(value) => value,
                Err(error) => {
                    let _ = self.put_hw_semaphore();
                    return Err(error);
                }
            };
            if value & (mask | mask << 16) == 0 {
                self.registers.write(SW_FW_SYNC, value | mask);
                // Observe the software bit before giving up HW ownership.
                let observed = self.read(SW_FW_SYNC);
                self.put_hw_semaphore()?;
                return match observed {
                    Ok(actual) if actual & (mask | mask << 16) == mask => Ok(()),
                    Ok(_) => Err(BlockError::Unsupported("igc SW/FW semaphore did not latch")),
                    Err(error) => Err(error),
                };
            }
            self.put_hw_semaphore()?;
            self.timer.delay(5_000);
        }
        Err(BlockError::Timeout)
    }
    fn release(&mut self, mask: u32) -> Result<(), BlockError> {
        self.hw_semaphore()?;
        let result = self.modify(SW_FW_SYNC, mask, 0).and_then(|()| {
            if self.read(SW_FW_SYNC)? & mask != 0 {
                Err(BlockError::Unsupported(
                    "igc SW/FW semaphore did not release",
                ))
            } else {
                Ok(())
            }
        });
        let released = self.put_hw_semaphore();
        result.and(released)
    }
    fn synchronized<V>(
        &mut self,
        mask: u32,
        operation: impl FnOnce(&mut Self) -> Result<V, BlockError>,
    ) -> Result<V, BlockError> {
        self.acquire(mask)?;
        let result = operation(self);
        let released = self.release(mask);
        match (result, released) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    fn mdio(&self, register: u16, write: Option<u16>) -> Result<u16, BlockError> {
        if register > 31 {
            return Err(BlockError::Unsupported(
                "igc MDIO register outside Clause22",
            ));
        }
        // Linux igc leaves the integrated PHY's MDIC address at zero.
        let command = u32::from(register) << 16
            | write.map_or(MDIC_READ, |value| MDIC_WRITE | u32::from(value));
        self.registers.write(MDIC, command);
        let mut value = 0;
        for _ in 0..1920 {
            self.timer.delay(50);
            value = self.read(MDIC)?;
            if value & MDIC_READY != 0 {
                break;
            }
        }
        if value & MDIC_READY == 0 {
            return Err(BlockError::Timeout);
        }
        if value & MDIC_ERROR != 0 {
            return Err(BlockError::Device { status: value });
        }
        if (value >> 16) & 31 != u32::from(register) {
            return Err(BlockError::Unsupported(
                "igc MDIO completion register mismatch",
            ));
        }
        Ok(value as u16)
    }
    fn mmd(&self, device: u16, register: u16, write: Option<u16>) -> Result<u16, BlockError> {
        // Hold the PHY semaphore across the entire address/data sequence;
        // no firmware or sibling operation can interleave its MMD selector.
        self.mdio(MMD_CONTROL, Some(device))?;
        self.mdio(MMD_DATA, Some(register))?;
        self.mdio(MMD_CONTROL, Some(0x4000 | device))?;
        let result = self.mdio(MMD_DATA, write)?;
        self.mdio(MMD_CONTROL, Some(0))?;
        Ok(result)
    }

    fn validate_nvm(&mut self) -> Result<(), BlockError> {
        if self.read(EECD)? & FLASH_PRESENT == 0 {
            return Ok(());
        }
        self.synchronized(NVM_SYNC, |hw| {
            let mut sum = 0u16;
            for word in 0..64u32 {
                hw.registers.write(EERD, word << 2 | 1);
                let value = hw.poll(EERD, 2, true, 100_000, 5)?;
                sum = sum.wrapping_add((value >> 16) as u16);
            }
            if sum != 0xbaba {
                return Err(BlockError::Unsupported("igc NVM checksum mismatch"));
            }
            Ok(())
        })
    }

    fn phy(&mut self) -> Result<u32, BlockError> {
        if self.read(MANC)? & (1 << 18) != 0 {
            return Err(BlockError::Unsupported(
                "igc PHY reset blocked by management firmware",
            ));
        }
        self.synchronized(PHY_SYNC, |hw| {
            let ctrl = hw.read(CTRL)?;
            hw.registers.write(CTRL, ctrl | PHY_RESET);
            hw.read(STATUS)?;
            hw.timer.delay(100);
            hw.registers.write(CTRL, ctrl);
            hw.read(STATUS)?;
            hw.timer.delay(100);
            hw.poll(PHPM, 1 << 8, true, 10_000, 1)?;
            hw.timer.delay(100);
            Ok(())
        })?;
        self.synchronized(PHY_SYNC, |hw| {
            let upper = hw.mdio(2, None)?;
            hw.timer.delay(200);
            let lower = hw.mdio(3, None)?;
            let identity = u32::from(upper) << 16 | u32::from(lower);
            if upper == 0 || upper == u16::MAX || lower == u16::MAX {
                return Err(BlockError::Unsupported("igc invalid internal PHY identity"));
            }
            // Source igc_power_up_phy_copper, followed by advertisement.
            let control = hw.mdio(PHY_CONTROL, None)?;
            hw.mdio(PHY_CONTROL, Some(control & !(1 << 11)))?;
            let adv = hw.mdio(PHY_ADVERTISEMENT, None)?;
            let gigabit = hw.mdio(PHY_GIGABIT, None)?;
            let multigig = hw.mmd(MMD_AN, MMD_MULTIGIG, None)?;
            // All source default copper speeds, no 1000/2500 half duplex;
            // igc_fc_default resolves to full: symmetric and asymmetric PAUSE.
            hw.mdio(PHY_ADVERTISEMENT, Some(adv | 0x0de0))?;
            hw.mdio(PHY_GIGABIT, Some((gigabit & !0x0300) | 0x0200))?;
            hw.mmd(MMD_AN, MMD_MULTIGIG, Some(multigig | 0x0080))?;
            let control = hw.mdio(PHY_CONTROL, None)?;
            hw.mdio(PHY_CONTROL, Some(control | 0x1200))?;
            Ok(identity)
        })
    }

    fn phy_read(&mut self, register: u16) -> Result<u16, BlockError> {
        self.synchronized(PHY_SYNC, |hw| hw.mdio(register, None))
    }

    /// Linux igc_check_for_copper_link, entered while a link status change
    /// is pending. The latched-low MII link bit is read twice. On link the
    /// MAC adopts the autonegotiated pause resolution, and LTR follows the
    /// observed link either way. A failed PHY exchange reports no link, as
    /// Linux's watchdog treats it; an absent function is a register error.
    pub(super) fn check_for_copper_link(&mut self) -> Result<Option<Negotiated>, BlockError> {
        let link = match self
            .phy_read(PHY_STATUS)
            .and_then(|_| self.phy_read(PHY_STATUS))
        {
            Ok(status) => status & MII_LINK != 0,
            Err(BlockError::Device { status: u32::MAX }) => {
                return Err(BlockError::Device { status: u32::MAX });
            }
            Err(_) => false,
        };
        let negotiated = if link {
            let flow_control = self.flow_control_after_link_up()?;
            let (speed, full_duplex) = self.speed_and_duplex()?;
            Some(Negotiated {
                speed,
                full_duplex,
                flow_control,
            })
        } else {
            None
        };
        self.set_ltr(negotiated.map(|link| link.speed))?;
        Ok(negotiated)
    }

    /// igc_get_speed_and_duplex_copper: I225/I226 report 2.5 Gb/s as the
    /// 1 Gb/s speed plus a separate 2.5 Gb/s bit.
    fn speed_and_duplex(&self) -> Result<(u16, bool), BlockError> {
        let status = self.read(STATUS)?;
        let speed = if status & STATUS_SPEED_1000 != 0 {
            if status & STATUS_SPEED_2500 != 0 {
                2500
            } else {
                1000
            }
        } else if status & STATUS_SPEED_100 != 0 {
            100
        } else {
            10
        };
        Ok((speed, status & STATUS_FD != 0))
    }

    /// igc_config_fc_after_link_up for the requested igc_fc_full mode: the
    /// IEEE 802.3 Annex 28B pause resolution, with Linux's receive-pause
    /// fallback when neither side's bits match, and none at half duplex.
    /// An incomplete autonegotiation leaves the MAC's pause enables as they
    /// were, as Linux does.
    fn flow_control_after_link_up(&mut self) -> Result<FlowControl, BlockError> {
        let status = self
            .phy_read(PHY_STATUS)
            .and_then(|_| self.phy_read(PHY_STATUS))?;
        if status & MII_AUTONEG_COMPLETE == 0 {
            let ctrl = self.read(CTRL)?;
            return Ok(match (ctrl & CTRL_RFCE != 0, ctrl & CTRL_TFCE != 0) {
                (false, false) => FlowControl::None,
                (true, false) => FlowControl::ReceivePause,
                (false, true) => FlowControl::TransmitPause,
                (true, true) => FlowControl::Full,
            });
        }
        let local = self.phy_read(PHY_ADVERTISEMENT)?;
        let partner = self.phy_read(PHY_PARTNER)?;
        let both = |bits: u16, value: u16| value & bits == bits;
        let mut mode = if local & PAUSE != 0 && partner & PAUSE != 0 {
            FlowControl::Full
        } else if local & PAUSE == 0
            && local & ASYMMETRIC_PAUSE != 0
            && both(PAUSE | ASYMMETRIC_PAUSE, partner)
        {
            FlowControl::TransmitPause
        } else {
            // Both the asymmetric receive-only match and Linux's fallback
            // for a requested full mode without strict IEEE resolution.
            FlowControl::ReceivePause
        };
        if !self.speed_and_duplex()?.1 {
            mode = FlowControl::None;
        }
        // igc_force_mac_fc.
        let (receive, transmit) = match mode {
            FlowControl::None => (false, false),
            FlowControl::ReceivePause => (true, false),
            FlowControl::TransmitPause => (false, true),
            FlowControl::Full => (true, true),
        };
        let set = if receive { CTRL_RFCE } else { 0 } | if transmit { CTRL_TFCE } else { 0 };
        self.modify(CTRL, CTRL_RFCE | CTRL_TFCE, set)?;
        Ok(mode)
    }

    /// igc_set_ltr_i225 with EEE disabled: the time the receive packet
    /// buffer takes to fill at the link speed, in 1024 or 32768 ns units.
    /// Without link Linux leaves the thresholds untouched.
    fn set_ltr(&mut self, speed: Option<u16>) -> Result<(), BlockError> {
        let Some(speed) = speed else {
            return Ok(());
        };
        let bits = (self.read(RXPBS)? & 0x3f) * 1024 * 8;
        let latency = 1000 * bits / u32::from(speed);
        let (scale, unit) = if latency / 1024 < 1024 {
            (LTR_SCALE_1024, 1024)
        } else {
            (LTR_SCALE_32768, 32768)
        };
        let value = (latency / unit).saturating_sub(1);
        for register in [LTRMINV, LTRMAXV] {
            if self.read(register)? & 0x3ff != value {
                self.registers
                    .write(register, LTR_SNOOP | value | scale << 10);
            }
        }
        Ok(())
    }

    /// The 1000BASE-T status register's remote receiver OK bit, which Linux
    /// waits on for up to two seconds before reporting a 1 Gb/s carrier.
    pub(super) fn remote_receiver_ready(&mut self) -> Result<bool, BlockError> {
        Ok(self.phy_read(PHY_GIGABIT_STATUS)? & REMOTE_RECEIVER_OK != 0)
    }

    pub(super) fn initialize(&mut self) -> Result<u32, BlockError> {
        self.reset()?;
        self.validate_nvm()?;
        let identity = self.phy()?;
        // igc_setup_copper_link_base. Pause stays off until the link-up
        // resolution in check_for_copper_link enables what was negotiated.
        self.modify(
            CTRL,
            (7 << 8) | (1 << 0) | (1 << 11) | (1 << 12) | (3 << 27),
            1 << 6,
        )?;
        self.modify(PHPM, 1 << 5, 0)?;
        self.modify(CTRL_EXT, 0, DRV_LOAD)?;
        // Explicit no-EEE profile: neither inherited LPI nor EEE advertisements.
        self.modify(IPCNFG, 0x1c, 0)?;
        self.modify(EEER, 7 << 16, 0)?;
        self.read(IPCNFG)?;
        self.read(EEER)?;
        // Source default packet buffers and collision distance.
        self.registers.write(RXPBS, 34 | 2 << 6);
        self.registers.write(TXPBS, 20 | 4 << 24);
        self.modify(TCTL, 0x003ff000, 63 << 12)?;
        self.registers.write(RLPML, (super::MAX_FRAME + 4) as u32);
        self.registers.write(RXCSUM, 0); // No checksum/CRC offload reporting.
        for index in 0..128 {
            self.registers.write(MTA + index * 4, 0);
        }
        for index in 1..16 {
            self.registers.write(RAL + index * 8, 0);
            self.registers.write(RAL + index * 8 + 4, 0);
        }
        // igc_setup_link: the PAUSE address, type and timer, and the
        // igc_set_fc_watermarks thresholds for transmitted PAUSE with XON.
        self.registers.write(FCT, 0x8808);
        self.registers.write(FCAH, 0x0100);
        self.registers.write(FCAL, 0x00c2_8001);
        self.registers.write(FCTTV, PAUSE_TIME);
        self.registers.write(FCRTL, LOW_WATER | FCRTL_XONE);
        self.registers.write(FCRTH, HIGH_WATER);
        // igc_clear_hw_cntrs_base, after link setup: the symbol error count
        // climbs while there is no link.
        for counter in COUNTERS.into_iter().chain([LENERRS]) {
            self.read(counter)?;
        }
        Ok(identity)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec::Vec};
    use core::cell::{Cell, RefCell};

    #[derive(Default)]
    pub(in super::super) struct State {
        pub(in super::super) registers: BTreeMap<usize, u32>,
        pub(in super::super) phy: BTreeMap<u16, u16>,
        mmd: BTreeMap<(u16, u16), u16>,
        mmd_control: u16,
        mmd_address: u16,
        writes: Vec<(usize, u32)>,
        nvm: Vec<u16>,
    }
    pub(in super::super) struct Model {
        pub(in super::super) state: RefCell<State>,
        reads: Cell<usize>,
        fail_read: Cell<Option<usize>>,
        pub(in super::super) mdio_count: Cell<usize>,
        mdio_fail: Cell<Option<usize>>,
        mdio_silent: Cell<bool>,
        master_stuck: Cell<bool>,
        reset_stuck: Cell<bool>,
        autoload_stuck: Cell<bool>,
        phy_reset_stuck: Cell<bool>,
        firmware_busy: Cell<bool>,
        software_busy: Cell<bool>,
        sw_semaphore_refused: Cell<bool>,
        elapsed: Cell<u64>,
    }
    impl Model {
        fn ready(flash: bool) -> Self {
            let mut state = State {
                nvm: vec![0; 64],
                ..State::default()
            };
            state
                .registers
                .insert(EECD, AUTO_READ_DONE | if flash { FLASH_PRESENT } else { 0 });
            state.registers.insert(PHPM, 1 << 8 | 1 << 5);
            state.registers.insert(CTRL, 0x18001f01);
            state.registers.insert(IPCNFG, 0xa51f);
            state.registers.insert(EEER, 0xa5071234);
            state.phy.extend([
                (0, 0x0800),
                (2, 0x67c9),
                (3, 0xdc01),
                (4, 0xafe1),
                (9, 0xf9ff),
            ]);
            state.mmd.insert((MMD_AN, MMD_MULTIGIG), 0x5501);
            state.nvm[63] = 0xbaba;
            Self {
                state: RefCell::new(state),
                reads: Cell::new(0),
                fail_read: Cell::new(None),
                mdio_count: Cell::new(0),
                mdio_fail: Cell::new(None),
                mdio_silent: Cell::new(false),
                master_stuck: Cell::new(false),
                reset_stuck: Cell::new(false),
                autoload_stuck: Cell::new(false),
                phy_reset_stuck: Cell::new(false),
                firmware_busy: Cell::new(false),
                software_busy: Cell::new(false),
                sw_semaphore_refused: Cell::new(false),
                elapsed: Cell::new(0),
            }
        }
    }
    impl Registers for Model {
        fn read(&self, register: usize) -> u32 {
            let count = self.reads.get() + 1;
            self.reads.set(count);
            if self.fail_read.get() == Some(count) {
                return u32::MAX;
            }
            if register == STATUS && self.master_stuck.get() {
                return MASTER_ENABLED;
            }
            if register == SWSM && self.software_busy.get() {
                return SMBI;
            }
            if register == SW_FW_SYNC && self.firmware_busy.get() {
                return PHY_SYNC << 16;
            }
            self.state
                .borrow()
                .registers
                .get(&register)
                .copied()
                .unwrap_or(0)
        }
        fn write(&self, register: usize, value: u32) {
            let mut state = self.state.borrow_mut();
            state.writes.push((register, value));
            state.registers.insert(register, value);
            if register == SWSM && self.sw_semaphore_refused.get() {
                state.registers.insert(SWSM, 0);
            }
            if register == CTRL && value & MAC_RESET != 0 && !self.reset_stuck.get() {
                state.registers.insert(CTRL, 0);
                let eecd = state.registers[&EECD];
                state.registers.insert(
                    EECD,
                    if self.autoload_stuck.get() {
                        eecd & !AUTO_READ_DONE
                    } else {
                        eecd | AUTO_READ_DONE
                    },
                );
            }
            if register == CTRL && value & PHY_RESET != 0 {
                state.mmd_control = 0;
                let phpm = state.registers[&PHPM];
                state.registers.insert(
                    PHPM,
                    if self.phy_reset_stuck.get() {
                        phpm & !(1 << 8)
                    } else {
                        phpm | 1 << 8
                    },
                );
            }
            if register == EERD {
                let word = ((value >> 2) & 0x3fff) as usize;
                let data = state.nvm[word];
                state
                    .registers
                    .insert(EERD, u32::from(data) << 16 | value | 2);
            }
            if register != MDIC {
                return;
            }
            let count = self.mdio_count.get() + 1;
            self.mdio_count.set(count);
            if self.mdio_silent.get() {
                return;
            }
            if self.mdio_fail.get() == Some(count) {
                state
                    .registers
                    .insert(MDIC, value | MDIC_READY | MDIC_ERROR);
                return;
            }
            assert_eq!(value & (31 << 21), 0, "real donor integrated PHY address");
            let reg = ((value >> 16) & 31) as u16;
            let data = if value & MDIC_WRITE != 0 {
                let data = value as u16;
                match reg {
                    MMD_CONTROL => state.mmd_control = data,
                    MMD_DATA if state.mmd_control & 0x4000 == 0 => state.mmd_address = data,
                    MMD_DATA => {
                        let key = (state.mmd_control & 31, state.mmd_address);
                        state.mmd.insert(key, data);
                    }
                    _ => {
                        state.phy.insert(reg, data);
                    }
                }
                data
            } else {
                match reg {
                    MMD_CONTROL => state.mmd_control,
                    MMD_DATA if state.mmd_control & 0x4000 != 0 => state
                        .mmd
                        .get(&(state.mmd_control & 31, state.mmd_address))
                        .copied()
                        .unwrap_or(0),
                    _ => state.phy.get(&reg).copied().unwrap_or(0),
                }
            };
            state
                .registers
                .insert(MDIC, value & !0xffff | u32::from(data) | MDIC_READY);
        }
    }
    impl Timer for Model {
        fn delay(&self, microseconds: u64) {
            self.elapsed.set(self.elapsed.get() + microseconds);
        }
    }

    #[test]
    fn complete_initialization_replaces_inherited_phy_and_mac_state_for_all_declared_ids() {
        for device in super::super::DEVICES {
            for flash in [false, true] {
                let model = Model::ready(flash);
                let mut hw = Hardware::new(&model, &model).unwrap();
                assert_eq!(hw.initialize(), Ok(0x67c9dc01), "device {device:04x}");
                let state = model.state.borrow();
                assert_eq!(state.phy[&0] & 0x1a00, 0x1200);
                // Symmetric and asymmetric PAUSE, all 10/100 modes, other bits kept.
                assert_eq!(state.phy[&4], 0xafe1);
                assert_eq!(state.registers[&FCT], 0x8808);
                assert_eq!(state.registers[&FCAH], 0x0100);
                assert_eq!(state.registers[&FCAL], 0x00c2_8001);
                assert_eq!(state.registers[&FCTTV], 0xffff);
                assert_eq!(state.registers[&FCRTH], 23552);
                assert_eq!(state.registers[&FCRTL], 23536 | FCRTL_XONE);
                assert_eq!(state.phy[&9], 0xfaff); // No1G half duplex, 1G full.
                assert_eq!(state.mmd[&(7, 32)], 0x5581);
                assert_eq!(state.mmd_control, 0);
                assert_eq!(state.registers[&SW_FW_SYNC] & 3, 0);
                assert_eq!(state.registers[&SWSM] & 3, 0);
                assert_eq!(state.registers[&CTRL] & (0x18001f01 | MASTER_DISABLE), 0);
                assert_eq!(state.registers[&CTRL] & (1 << 6), 1 << 6);
                assert_eq!(state.registers[&IPCNFG], 0xa503);
                assert_eq!(state.registers[&EEER], 0xa5001234);
                assert_eq!(state.registers[&RXPBS], 0xa2);
                assert_eq!(state.registers[&TXPBS], 0x04000014);
                assert_eq!(state.registers[&RLPML], 1518);
                assert!(
                    state
                        .writes
                        .iter()
                        .any(|&(r, v)| r == CTRL && v & MAC_RESET != 0)
                );
                assert!(
                    !state
                        .writes
                        .iter()
                        .any(|&(r, v)| r == CTRL && v & (1 << 29) != 0)
                );
                for index in 1..16 {
                    assert_eq!(state.registers[&(RAL + index * 8 + 4)], 0);
                }
                assert!(model.elapsed.get() >= 10_000);
            }
        }
    }

    #[test]
    fn drain_mac_reset_autoload_and_phy_reset_deadlines_never_look_successful() {
        for failure in 0..4 {
            let model = Model::ready(false);
            match failure {
                0 => model.master_stuck.set(true),
                1 => model.reset_stuck.set(true),
                2 => model.autoload_stuck.set(true),
                _ => model.phy_reset_stuck.set(true),
            }
            let mut hw = Hardware::new(&model, &model).unwrap();
            assert_eq!(hw.initialize(), Err(BlockError::Timeout));
            let state = model.state.borrow();
            assert!(!state.writes.iter().any(|&(r, _)| r == RXPBS));
            if failure == 0 {
                assert!(
                    !state
                        .writes
                        .iter()
                        .any(|&(r, v)| r == CTRL && v & MAC_RESET != 0)
                );
            }
            assert!(model.elapsed.get() < 2_000_000);
        }
    }

    #[test]
    fn every_actual_failed_register_read_refuses_initialization() {
        let model = Model::ready(true);
        Hardware::new(&model, &model).unwrap().initialize().unwrap();
        let reads = model.reads.get();
        for failure in 1..=reads {
            let model = Model::ready(true);
            model.fail_read.set(Some(failure));
            let result = Hardware::new(&model, &model).and_then(|mut h| h.initialize());
            assert!(result.is_err(), "failed read {failure}/{reads}");
        }
    }

    #[test]
    fn every_mdio_error_and_missing_completion_aborts_and_releases_software_ownership() {
        let model = Model::ready(false);
        Hardware::new(&model, &model).unwrap().initialize().unwrap();
        for failure in 1..=model.mdio_count.get() {
            let model = Model::ready(false);
            model.mdio_fail.set(Some(failure));
            assert!(Hardware::new(&model, &model).unwrap().initialize().is_err());
            assert_eq!(model.state.borrow().registers[&SW_FW_SYNC] & PHY_SYNC, 0);
            assert!(!model.state.borrow().writes.iter().any(|&(r, _)| r == RXPBS));
        }
        let model = Model::ready(false);
        model.mdio_silent.set(true);
        assert_eq!(
            Hardware::new(&model, &model).unwrap().initialize(),
            Err(BlockError::Timeout)
        );
    }

    #[test]
    fn firmware_management_and_semaphore_refusals_cannot_be_bypassed() {
        for failure in 0..4 {
            let model = Model::ready(false);
            match failure {
                0 => {
                    model.state.borrow_mut().registers.insert(MANC, 1 << 18);
                }
                1 => model.firmware_busy.set(true),
                2 => model.software_busy.set(true),
                _ => model.sw_semaphore_refused.set(true),
            }
            assert!(Hardware::new(&model, &model).unwrap().initialize().is_err());
            assert_eq!(model.mdio_count.get(), 0);
        }
    }

    #[test]
    fn programmed_flash_checksum_and_observed_phy_identity_are_not_fabricated() {
        let model = Model::ready(true);
        model.state.borrow_mut().nvm[10] = 1;
        assert_eq!(
            Hardware::new(&model, &model).unwrap().initialize(),
            Err(BlockError::Unsupported("igc NVM checksum mismatch"))
        );
        assert_eq!(model.mdio_count.get(), 0);
        for upper in [0, 0xffff] {
            let model = Model::ready(false);
            model.state.borrow_mut().phy.insert(2, upper);
            assert!(Hardware::new(&model, &model).unwrap().initialize().is_err());
        }
    }

    pub(in super::super) fn linked(status: u32, partner: u16) -> Model {
        let model = Model::ready(false);
        {
            let mut state = model.state.borrow_mut();
            state
                .registers
                .extend([(STATUS, status), (RXPBS, 34 | 2 << 6)]);
            state.phy.extend([
                (PHY_STATUS, MII_LINK | MII_AUTONEG_COMPLETE),
                (PHY_ADVERTISEMENT, 0x0de0),
                (PHY_PARTNER, partner),
            ]);
        }
        model
    }

    #[test]
    fn copper_link_check_resolves_pause_and_programs_ltr_from_the_negotiated_link() {
        let full = STATUS_FD | STATUS_SPEED_1000 | STATUS_SPEED_2500;
        for (partner, mode) in [
            (PAUSE, FlowControl::Full),
            (PAUSE | ASYMMETRIC_PAUSE, FlowControl::Full),
            (ASYMMETRIC_PAUSE, FlowControl::ReceivePause),
            // Linux's receive-pause fallback for a requested full mode.
            (0, FlowControl::ReceivePause),
        ] {
            let model = linked(full, partner);
            let mut hw = Hardware::new(&model, &model).unwrap();
            let link = hw.check_for_copper_link().unwrap().unwrap();
            assert_eq!(
                link,
                Negotiated {
                    speed: 2500,
                    full_duplex: true,
                    flow_control: mode,
                }
            );
            let state = model.state.borrow();
            let ctrl = state.registers[&CTRL] & (CTRL_RFCE | CTRL_TFCE);
            let expected = match mode {
                FlowControl::Full => CTRL_RFCE | CTRL_TFCE,
                _ => CTRL_RFCE,
            };
            assert_eq!(ctrl, expected, "partner {partner:#x}");
            // 34 KiB at 2.5 Gb/s is 111411 ns: 108 units of 1024 ns, less one.
            assert_eq!(state.registers[&LTRMINV], LTR_SNOOP | 107 | 2 << 10);
            assert_eq!(state.registers[&LTRMAXV], LTR_SNOOP | 107 | 2 << 10);
            assert_eq!(state.registers[&SW_FW_SYNC] & PHY_SYNC, 0);
        }

        // Without receive-pause ability on our side, the partner's symmetric
        // and asymmetric bits select transmit pause.
        let model = linked(STATUS_FD | STATUS_SPEED_100, PAUSE | ASYMMETRIC_PAUSE);
        model
            .state
            .borrow_mut()
            .phy
            .insert(PHY_ADVERTISEMENT, ASYMMETRIC_PAUSE);
        let mut hw = Hardware::new(&model, &model).unwrap();
        let link = hw.check_for_copper_link().unwrap().unwrap();
        assert_eq!(
            (link.speed, link.flow_control),
            (100, FlowControl::TransmitPause)
        );
        assert_eq!(
            model.state.borrow().registers[&CTRL] & (CTRL_RFCE | CTRL_TFCE),
            CTRL_TFCE
        );

        // Half duplex never pauses; 10 Mb/s needs the 32768 ns scale.
        let model = linked(0, PAUSE);
        model
            .state
            .borrow_mut()
            .registers
            .insert(CTRL, CTRL_RFCE | CTRL_TFCE);
        let mut hw = Hardware::new(&model, &model).unwrap();
        let link = hw.check_for_copper_link().unwrap().unwrap();
        assert_eq!(
            (link.speed, link.full_duplex, link.flow_control),
            (10, false, FlowControl::None)
        );
        let state = model.state.borrow();
        assert_eq!(state.registers[&CTRL] & (CTRL_RFCE | CTRL_TFCE), 0);
        assert_eq!(state.registers[&LTRMINV], LTR_SNOOP | 849 | 3 << 10);
        drop(state);

        // Incomplete autonegotiation keeps the MAC's pause enables.
        let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
        {
            let mut state = model.state.borrow_mut();
            state.phy.insert(PHY_STATUS, MII_LINK);
            state.registers.insert(CTRL, CTRL_TFCE);
        }
        let mut hw = Hardware::new(&model, &model).unwrap();
        let link = hw.check_for_copper_link().unwrap().unwrap();
        assert_eq!(
            (link.speed, link.flow_control),
            (1000, FlowControl::TransmitPause)
        );
        assert_eq!(model.state.borrow().registers[&CTRL], CTRL_TFCE);
    }

    #[test]
    fn copper_link_check_reports_no_link_without_touching_pause_or_ltr() {
        let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
        model.state.borrow_mut().phy.insert(PHY_STATUS, 0);
        let mut hw = Hardware::new(&model, &model).unwrap();
        assert_eq!(hw.check_for_copper_link(), Ok(None));
        let state = model.state.borrow();
        assert!(!state.registers.contains_key(&LTRMINV));
        assert!(!state.writes.iter().any(|&(r, _)| r == CTRL));
        drop(state);

        // A failed PHY exchange is no link; an absent function is an error.
        let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
        model.mdio_fail.set(Some(1));
        let mut hw = Hardware::new(&model, &model).unwrap();
        assert_eq!(hw.check_for_copper_link(), Ok(None));
        assert_eq!(model.state.borrow().registers[&SW_FW_SYNC] & PHY_SYNC, 0);
        let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
        model.software_busy.set(true);
        let mut hw = Hardware::new(&model, &model).unwrap();
        assert_eq!(hw.check_for_copper_link(), Ok(None));
        let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
        let mut hw = Hardware::new(&model, &model).unwrap();
        model.fail_read.set(Some(model.reads.get() + 1));
        assert_eq!(
            hw.check_for_copper_link(),
            Err(BlockError::Device { status: u32::MAX })
        );

        let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
        model.state.borrow_mut().phy.insert(PHY_GIGABIT_STATUS, 0);
        let mut hw = Hardware::new(&model, &model).unwrap();
        assert_eq!(hw.remote_receiver_ready(), Ok(false));
        model
            .state
            .borrow_mut()
            .phy
            .insert(PHY_GIGABIT_STATUS, REMOTE_RECEIVER_OK);
        assert_eq!(hw.remote_receiver_ready(), Ok(true));
    }

    #[test]
    fn initialization_clears_every_linux_counter_and_statistics_accumulate_whole_octet_pairs() {
        // Linux's 67 counters, each read once; a failed read refuses
        // initialization like every other register read.
        let model = Model::ready(false);
        Hardware::new(&model, &model).unwrap().initialize().unwrap();
        let after = model.reads.get();
        assert_eq!(COUNTERS.len() + 1, 67);
        let model = Model::ready(false);
        model.fail_read.set(Some(after));
        assert!(Hardware::new(&model, &model).unwrap().initialize().is_err());

        let model = Model::ready(false);
        {
            let mut state = model.state.borrow_mut();
            state.registers.extend([
                (0x4000, 2),     // CRCERRS
                (MPC, 3),        // MPC
                (0x4074, 10),    // GPRC
                (0x4088, 5),     // GORCL
                (0x408c, 1),     // GORCH
                (0x4080, 7),     // GPTC
                (0x4090, 0x400), // GOTCL
                (0x4054, 4),     // XOFFTXC
            ]);
        }
        let mut statistics = Statistics::default();
        statistics.accumulate(&model).unwrap();
        statistics.accumulate(&model).unwrap();
        assert_eq!(statistics.crc_errors, 4);
        assert_eq!(statistics.missed, 6);
        assert_eq!(statistics.good_received, 20);
        assert_eq!(statistics.good_octets_received, 2 * (1 << 32 | 5));
        assert_eq!(statistics.good_transmitted, 14);
        assert_eq!(statistics.good_octets_transmitted, 0x800);
        assert_eq!(statistics.xoff_transmitted, 8);
        let before = statistics;
        model.state.borrow_mut().registers.insert(STATUS, u32::MAX);
        assert!(statistics.accumulate(&model).is_err());
        assert_eq!(statistics, before);
    }

    #[test]
    fn stop_disables_both_directions_before_the_reset_and_release_returns_control() {
        let model = Model::ready(false);
        {
            let mut state = model.state.borrow_mut();
            state.registers.extend([
                (RCTL, RCTL_EN | 1 << 15),
                (TCTL, TCTL_EN | 1 << 3),
                (CTRL_EXT, DRV_LOAD | 1),
            ]);
        }
        let hw = Hardware::new(&model, &model).unwrap();
        hw.stop().unwrap();
        hw.release_control().unwrap();
        let state = model.state.borrow();
        let position = |entry| state.writes.iter().position(|&w| w == entry).unwrap();
        let reset = state
            .writes
            .iter()
            .position(|&(r, v)| r == CTRL && v & MAC_RESET != 0)
            .unwrap();
        assert!(position((RCTL, 1 << 15)) < reset);
        assert!(position((TCTL, 1 << 3)) < reset);
        assert_eq!(state.registers[&CTRL_EXT], 1);
        assert!(model.elapsed.get() >= 20_000);
        drop(state);

        // An incomplete drain or reset is never a stop.
        for stuck in [0, 1] {
            let model = Model::ready(false);
            if stuck == 0 {
                model.master_stuck.set(true);
            } else {
                model.reset_stuck.set(true);
            }
            assert_eq!(
                Hardware::new(&model, &model).unwrap().stop(),
                Err(BlockError::Timeout)
            );
        }
    }

    #[test]
    fn receive_fifo_flush_applies_the_ipv6_erratum_and_flushes_only_for_manageability() {
        let model = Model::ready(false);
        model.state.borrow_mut().registers.insert(RFCTL, 1 << 3);
        flush_receive_fifo(&model, &model).unwrap();
        let state = model.state.borrow();
        assert_eq!(state.writes, [(RFCTL, 1 << 3 | RFCTL_IPV6_EX_DIS)]);
        drop(state);

        let model = Model::ready(false);
        {
            let mut state = model.state.borrow_mut();
            state.registers.extend([
                (MANC, MANC_RCV_TCO_EN),
                (RFCTL, RFCTL_LEF),
                (RLPML, 1518),
                (RCTL, RCTL_SBP | 1 << 15),
                (rxdctl(0), RXDCTL_ENABLE | 0x0808),
                (rxdctl(2), RXDCTL_ENABLE),
            ]);
        }
        flush_receive_fifo(&model, &model).unwrap();
        let state = model.state.borrow();
        let rejecting = 1 << 15 | RCTL_LPE;
        let position = |entry| state.writes.iter().position(|&w| w == entry).unwrap();
        // Queues stop before receive briefly enables with every packet rejected.
        assert!(position((rxdctl(0), 0x0808)) < position((RCTL, rejecting)));
        assert!(position((RCTL, rejecting)) < position((RCTL, rejecting | RCTL_EN)));
        assert!(position((RLPML, 0)) < position((RCTL, rejecting | RCTL_EN)));
        assert!(position((RFCTL, RFCTL_IPV6_EX_DIS)) < position((RCTL, rejecting | RCTL_EN)));
        // Then every original setting returns, with the erratum kept.
        assert_eq!(state.registers[&rxdctl(0)], RXDCTL_ENABLE | 0x0808);
        assert_eq!(state.registers[&rxdctl(2)], RXDCTL_ENABLE);
        assert_eq!(state.registers[&RCTL], RCTL_SBP | 1 << 15);
        assert_eq!(state.registers[&RLPML], 1518);
        assert_eq!(state.registers[&RFCTL], RFCTL_LEF | RFCTL_IPV6_EX_DIS);
        assert!(model.elapsed.get() >= 3_000);
        drop(state);

        for failure in 1..=4 {
            let model = Model::ready(false);
            model
                .state
                .borrow_mut()
                .registers
                .insert(MANC, MANC_RCV_TCO_EN);
            model.fail_read.set(Some(failure));
            assert!(flush_receive_fifo(&model, &model).is_err());
        }
    }

    #[test]
    #[ignore = "oracle: STELA_IGC_AUTONEG_ORACLE"]
    fn unchanged_linux_advertisement_matches_real_mdio_and_mmd_operations() {
        extern crate std;
        let path = std::env::var("STELA_IGC_AUTONEG_ORACLE").unwrap();
        let trace = std::fs::read_to_string(path).unwrap();
        let mut cases = 0;
        for line in trace.lines() {
            let values: Vec<u16> = line
                .split_whitespace()
                .map(|v| u16::from_str_radix(v, 16).unwrap())
                .collect();
            assert_eq!(values.len(), 6);
            let model = Model::ready(false);
            {
                let mut state = model.state.borrow_mut();
                state.phy.insert(4, values[0]);
                state.phy.insert(9, values[1]);
                state.mmd.insert((7, 32), values[2]);
            }
            Hardware::new(&model, &model).unwrap().initialize().unwrap();
            let state = model.state.borrow();
            assert_eq!(
                [state.phy[&4], state.phy[&9], state.mmd[&(7, 32)]],
                values[3..]
            );
            cases += 1;
        }
        assert_eq!(cases, 4096);
    }
}
