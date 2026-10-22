// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! One polled queue for the declared cold PCH profiles. Native RX follows e1000e's
//! ordinary-MTU path; TX uses legacy descriptors without offloads. The PHY
//! jumbo workaround is explicitly restored to its non-jumbo settings. FCS is
//! received and removed in software as in that source profile. No IRQ, EEE,
//! pause, VLAN, jumbo, managed firmware or power-transition profile is claimed.
use super::{Controller, Delay, Error, Registers, i219, lpt, nvm, spt};
use crate::{
    bus::dma::DmaAllocator,
    net::{Link, LinkError, MAX_FRAME, MIN_FRAME, Mac},
};
use alloc::{format, vec::Vec};
use core::sync::atomic::{Ordering, fence};

// Common descriptor storage only; the 82574-specific programming/reset/start
// routines are never called. Addresses are boot-lifetime coherent DMA RAM.
use super::super::super::{BUFFER, DESCRIPTOR, DESCRIPTORS, Ring};

const CTRL_EXT: u32 = 0x18;
const FEXTNVM4: u32 = 0x24;
const KMRN: u32 = 0x34;
const TIPG: u32 = 0x410;
const RXCSUM: u32 = 0x5000;
const RFCTL: u32 = 0x5008;
const MTA: u32 = 0x5200;
const MTA_REGISTERS: u32 = 32;
const RAL: u32 = 0x5400;
const RAH: u32 = 0x5404;
const SHRAL: u32 = 0x5438;
const SHRAH: u32 = 0x543c;
const SHRAL_LPT: u32 = 0x5408;
const SHRAH_LPT: u32 = 0x540c;
const PBECCSTS: u32 = 0x100c;
const ECC_ENABLE: u32 = 1 << 16;
const MEMORY_ERROR_HANDLING: u32 = 1 << 19;
const FFLT_DBG: u32 = 0x5f04;
const GCR: u32 = 0x5b00;
const PBA: u32 = 0x1000;
const RDBAL: u32 = 0x2800;
const RDBAH: u32 = 0x2804;
const RDLEN: u32 = 0x2808;
const RDH: u32 = 0x2810;
const RDT: u32 = 0x2818;
const RDTR: u32 = 0x2820;
const RXDCTL: u32 = 0x2828;
const RADV: u32 = 0x282c;
const TDBAL: u32 = 0x3800;
const TDBAH: u32 = 0x3804;
const TDLEN: u32 = 0x3808;
const TDH: u32 = 0x3810;
const TDT: u32 = 0x3818;
const TIDV: u32 = 0x3820;
const TXDCTL: u32 = 0x3828;
const TADV: u32 = 0x382c;
const TARC: u32 = 0x3840;
const QUEUE_STRIDE: u32 = 0x100;
const ENABLE: u32 = 2;
const LINK_UP: u32 = 2;
const LINK_EVENT: u32 = 1 << 2;
const FULL_DUPLEX: u32 = 1;
const SPEED_MASK: u32 = 3 << 6;
const LINK_SUMMARY: u32 = LINK_UP | FULL_DUPLEX | SPEED_MASK;
const SLU: u32 = 1 << 6;
const FORCE_LINK: u32 = (1 << 11) | (1 << 12);
const PAUSE: u32 = (1 << 27) | (1 << 28);
const VLAN: u32 = 1 << 30;
const DRIVER_LOADED: u32 = 1 << 28;
const CTRL_EXT_POLICY: u32 = (1 << 17) | (1 << 20) | (1 << 22) | DRIVER_LOADED;
const NFS_DISABLE: u32 = (1 << 6) | (1 << 7);
const EXTENDED_RX: u32 = 1 << 15;
const VALID_ADDRESS: u32 = 1 << 31;
const TX_POLICY: u32 = (1 << 24) | (1 << 22) | (1 << 16) | 31;
const RX_POLICY: u32 = (1 << 16) | (4 << 8) | 8;
const RECEIVE_POLICY: u32 = ENABLE | (1 << 4) | (1 << 15);
const TRANSMIT_POLICY: u32 = ENABLE | super::PAD_SHORT | (15 << 4) | (63 << 12) | (1 << 24);
const RX_DONE: u32 = 1;
const RX_EOP: u32 = 2;
const RX_ERRORS: u32 = 0x9700_0000;
const TX_DONE: u8 = 1;
const TX_COMMAND: u32 = (1 << 24) | (1 << 25) | (1 << 27);
const FCS_BYTES: usize = 4;
const PHY_LINK_READY: u16 = (1 << 2) | (1 << 5);
const ADVERTISEMENT_SPEED: u16 = 0x1e0;
const ADVERTISEMENT_PAUSE: u16 = 0xc00;
const GIGABIT_ADVERTISEMENT: u16 = 0x300;
const GIGABIT_FULL: u16 = 0x200;
const MASTER_OVERRIDE: u16 = 0x1000;
const PHY_AN_RESTART: u16 = (1 << 12) | (1 << 9);
const PHY_QUIET: u16 = (1 << 14) | (1 << 11) | (1 << 10);
const RX_CONFIG: u16 = 0x3412;
const LPI_PLL_SHUT: u16 = 0x4412;
const EEE_PCS_STATUS: u16 = 0x182e;
const EEE_ADVERTISEMENT: u16 = 0x040e;
const LPI_ENABLE: u16 = 0x6000;

/// The actual controller owner and DMA storage remain retained after an
/// uncertain doorbell, timeout, removal or control failure. A fresh object is
/// not a retry mechanism; only an external real reset/recovery grants one.
pub struct Ethernet<R: Registers + nvm::Registers, D: Delay + Clone> {
    controller: Controller<R, D>,
    receive: Ring,
    transmit: Ring,
    next_rx: usize,
    next_tx: usize,
    clean_tx: usize,
    discard_rx: bool,
    link: Option<u32>,
    stopped: bool,
    failure: Option<Error>,
}
impl<R: Registers + nvm::Registers, D: Delay + Clone> Ethernet<R, D> {
    /// # Safety
    /// `dma` grants actual coherent boot-lifetime CPU/DMA RAM reachable by the
    /// same retained PCI requester as `controller`, using the allocator's real
    /// addressability/identity mapping contract. PCI memory decoding and bus
    /// mastering are enabled by the exclusive platform owner, with firmware,
    /// SMM and native interrupts excluded. No failed epoch may be reconstructed
    /// without actual reset/recovery. This constructor requires those grants;
    /// it neither synthesizes PCI ownership nor enables a broad probe match.
    pub unsafe fn new(
        controller: Controller<R, D>,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, Error> {
        if controller.is_poisoned() {
            return Err(Error::Poisoned);
        }
        let receive = Ring::new(dma).map_err(Error::Dma)?;
        let transmit = Ring::new(dma).map_err(Error::Dma)?;
        for ring in [&receive, &transmit] {
            if ring.descriptors.physical() & 127 != 0
                || ring.descriptors.len() != DESCRIPTORS * DESCRIPTOR
                || ring.buffers.len() != DESCRIPTORS * BUFFER
                || ring
                    .descriptors
                    .physical()
                    .checked_add(ring.descriptors.len() as u64)
                    .is_none()
                || ring
                    .buffers
                    .physical()
                    .checked_add(ring.buffers.len() as u64)
                    .is_none()
            {
                return Err(Error::DmaRange);
            }
        }
        let mut this = Self {
            controller,
            receive,
            transmit,
            next_rx: 0,
            next_tx: 0,
            clean_tx: 0,
            discard_rx: false,
            link: None,
            stopped: false,
            failure: None,
        };
        if let Err(error) = this.configure() {
            this.poison();
            return Err(error);
        }
        Ok(this)
    }
    fn poison(&mut self) {
        self.controller.poisoned = true;
        self.controller.phy.poisoned = true;
    }
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }
    fn check(&self) -> Result<(), Error> {
        if self.controller.is_poisoned() {
            Err(Error::Poisoned)
        } else if self.stopped {
            Err(Error::Stopped)
        } else {
            Ok(())
        }
    }
    fn modify_mac(&mut self, at: u32, clear: u32, set: u32) -> Result<(), Error> {
        let value = self.controller.read(at)?;
        self.controller.write(at, (value & !clear) | set)
    }
    fn kmrn(&mut self, index: u8, write: Option<u16>) -> Result<u16, Error> {
        Ok(self.controller.phy.transaction(|p| {
            p.write_mac(
                KMRN,
                (u32::from(index) << 16) | write.map_or(1 << 21, u32::from),
            )?;
            p.read_mac(super::STATUS)?;
            p.delay.delay(2);
            if write.is_none() {
                Ok(p.read_mac(KMRN)? as u16)
            } else {
                Ok(0)
            }
        })?)
    }
    fn standard_mtu(&mut self) -> Result<(), Error> {
        // Unchanged source's disabled-jumbo branch, with every formerly ignored
        // read failure made terminal. Do not restore RX on an uncertain write.
        let reg = super::super::Register::new(769, 20)?;
        let old = self.controller.phy.read(reg)?;
        self.controller.phy.write(reg, old | (1 << 14))?;
        self.modify_mac(FFLT_DBG, 0xf << 14, 0)?;
        self.modify_mac(super::RCTL, 1 << 26, 0)?;
        let value = self.kmrn(1, None)?;
        self.kmrn(1, Some(value & !1))?;
        let value = self.kmrn(16, None)?;
        self.kmrn(16, Some((value & !(0xf << 8)) | (0xb << 8)))?;
        self.controller.modify(769, 23, 0x7f << 5, 0)?;
        self.controller.modify(769, 16, 0, 1 << 13)?;
        self.controller.modify(776, 20, 0x3ff << 2, 8 << 2)?;
        self.controller
            .phy
            .write(super::super::Register::new(776, 23)?, 0x7e00)?;
        self.controller.modify(770, 17, 1 << 10, 0)?;
        self.controller.phy.write(reg, old & !(1 << 14))?;
        Ok(())
    }
    fn configure(&mut self) -> Result<(), Error> {
        self.controller.qualify()?;
        self.controller.write(0x5800, 0)?; // WUC: no wake ownership/profile
        self.controller.write(0x38, 0x8100)?; // VET: ordinary 802.1Q recognition
        // Real FIFO allocation must fit an ordinary frame (including metadata
        // in TX and received FCS in RX); never assume a reset/NVM buffer size.
        let pba = self.controller.read(PBA)?;
        if (pba & 0xffff) < 2 || (pba >> 16) < 2 {
            return Err(Error::Configuration);
        }
        self.modify_mac(CTRL_EXT, 0, CTRL_EXT_POLICY)?;
        for queue in 0..2 {
            self.modify_mac(TXDCTL + queue * QUEUE_STRIDE, 0x003f_003f, TX_POLICY)?;
        }
        self.modify_mac(TARC, 0, (1 << 23) | (1 << 24) | (1 << 26) | (1 << 27))?;
        let mulr = self.controller.read(super::TCTL)? & (1 << 28) != 0;
        self.modify_mac(
            TARC + QUEUE_STRIDE,
            1 << 28,
            (1 << 24) | (1 << 26) | (1 << 30) | if mulr { 0 } else { 1 << 28 },
        )?;
        if self.controller.is_spt_mac() {
            self.modify_mac(spt::IOSFPC, 0, spt::CORRUPTION_THRESHOLD)?; // SPT IOSFPC data-corruption erratum
            self.modify_mac(TARC, spt::TARC_REQUEST_MASK, spt::TARC_TWO_REQUESTS)?;
        }
        if self.controller.is_i219() {
            // Masked legacy/polled profile, without MSI/MSI-X clock requests.
            self.modify_mac(spt::FEXTNVM7, 0, spt::SIDE_CLOCK_UNGATE)?;
            self.modify_mac(spt::FEXTNVM9, 0, spt::IOSF_CLOCK_GATING_DISABLE)?;
        }
        self.modify_mac(GCR, 0x3f, 0)?;
        self.modify_mac(RFCTL, 0, NFS_DISABLE | EXTENDED_RX)?;
        if self.controller.profile.is_lpt_or_newer() {
            self.modify_mac(PBECCSTS, 0, ECC_ENABLE)?;
            self.modify_mac(super::CTRL, 0, MEMORY_ERROR_HANDLING)?;
        }
        self.controller.mtp_init_k1()?;
        self.station_filters()?;
        for index in 0..MTA_REGISTERS {
            self.controller.write(MTA + index * 4, 0)?;
        }
        self.standard_mtu()?;
        self.setup_link()?;
        self.i219_clock_policy()?;
        self.controller.write(RXCSUM, 0)?;
        self.controller.write(TIPG, 8 | (8 << 10) | (6 << 20))?;
        for (low, high, length, head, tail, address) in [
            (
                RDBAL,
                RDBAH,
                RDLEN,
                RDH,
                RDT,
                self.receive.descriptors.physical(),
            ),
            (
                TDBAL,
                TDBAH,
                TDLEN,
                TDH,
                TDT,
                self.transmit.descriptors.physical(),
            ),
        ] {
            self.controller.write(low, address as u32)?;
            self.controller.write(high, (address >> 32) as u32)?;
            self.controller
                .write(length, (DESCRIPTORS * DESCRIPTOR) as u32)?;
            self.controller.write(head, 0)?;
            self.controller.write(tail, 0)?;
        }
        self.controller.write(RXDCTL, RX_POLICY)?;
        self.controller.write(RXDCTL + QUEUE_STRIDE, RX_POLICY)?;
        let tx_policy = self.controller.read(TXDCTL)?;
        self.controller.write(TXDCTL + QUEUE_STRIDE, tx_policy)?;
        for at in [RDTR, RADV, TIDV, TADV] {
            self.controller.write(at, 0)?;
        }
        // Pause is explicitly disabled, including stale MAC control and
        // thresholds. PHY advertisement uses the same no-pause policy.
        for at in [0x2160, 0x2168] {
            self.controller.write(at, 0)?;
        }
        self.controller.write(0x170, 0xffff)?;
        self.controller.write(0x5f40, 0xffff)?;
        self.controller
            .phy
            .write(super::super::Register::new(769, 27)?, 0xffff)?;
        self.controller.write(super::IMC, u32::MAX)?;
        for index in 0..DESCRIPTORS {
            self.offer(index);
        }
        fence(Ordering::SeqCst);
        self.controller.write(RDT, (DESCRIPTORS - 1) as u32)?;
        self.modify_mac(
            super::CTRL,
            super::MASTER_DISABLE | FORCE_LINK | PAUSE | VLAN,
            SLU,
        )?;
        self.controller.write(super::RCTL, RECEIVE_POLICY)?;
        self.controller.write(super::TCTL, TRANSMIT_POLICY)?;
        self.controller.read(super::STATUS)?;
        self.update_link()?;
        Ok(())
    }
    fn i219_clock_policy(&mut self) -> Result<(), Error> {
        if self
            .controller
            .i219_family()
            .is_some_and(i219::Family::dma_clock_workaround)
            || self.controller.mtp_family().is_some()
        {
            self.modify_mac(FFLT_DBG, 0, i219::DONT_GATE_WAKE_DMA_CLOCK)?;
        }
        Ok(())
    }
    fn station_filters(&mut self) -> Result<(), Error> {
        let a = self.controller.station.0;
        let low = u32::from_le_bytes([a[0], a[1], a[2], a[3]]);
        let high = u32::from(u16::from_le_bytes([a[4], a[5]])) | VALID_ADDRESS;
        self.controller.write(RAL, low)?;
        self.controller.read(super::STATUS)?;
        self.controller.write(RAH, high)?;
        self.controller.read(super::STATUS)?;
        // PCH2 preserves RAR1..6 and uses SHRA0..3 at5438. LPT's eleven SHRA
        // slots begin at5408 and have actual FWSM ownership limits instead.
        let is_lpt = self.controller.profile.is_lpt_or_newer();
        let (low, high, count) = if is_lpt {
            (
                SHRAL_LPT,
                SHRAH_LPT,
                lpt::shared_count(self.controller.read(super::super::FWSM)?),
            )
        } else {
            (SHRAL, SHRAH, 4)
        };
        for index in 0..count {
            self.controller.phy.transaction(|p| {
                if is_lpt && lpt::shared_count(p.read_mac(super::super::FWSM)?) <= index {
                    return Err(super::super::Fault::FirmwareOwned);
                }
                p.write_mac(low + index * 8, 0)?;
                p.read_mac(super::STATUS)?;
                p.write_mac(high + index * 8, 0)?;
                p.read_mac(super::STATUS)?;
                Ok(())
            })?;
            if self.controller.read(low + index * 8)? != 0
                || self.controller.read(high + index * 8)? != 0
            {
                return Err(Error::Configuration);
            }
        }
        Ok(())
    }
    fn setup_link(&mut self) -> Result<(), Error> {
        self.modify_mac(super::CTRL, FORCE_LINK | PAUSE | VLAN, SLU)?;
        if !self.controller.profile.is_lpt_or_newer() {
            self.kmrn(4, Some(0xffff))?;
            let value = self.kmrn(9, None)?;
            self.kmrn(9, Some(value | 0x3f))?;
        }
        self.controller.modify(0, 22, 0, (1 << 15) | (3 << 10))?;
        self.controller.modify(0, 18, 0x600, 0x400)?;
        self.controller.modify(0, 9, MASTER_OVERRIDE, 0)?;
        self.controller.modify(
            0,
            4,
            ADVERTISEMENT_SPEED | ADVERTISEMENT_PAUSE,
            ADVERTISEMENT_SPEED,
        )?;
        self.controller
            .modify(0, 9, GIGABIT_ADVERTISEMENT, GIGABIT_FULL)?;
        self.disable_eee()?;
        self.controller.modify(0, 0, PHY_QUIET, PHY_AN_RESTART)?;
        Ok(())
    }
    fn disable_eee(&mut self) -> Result<(), Error> {
        let lpt = self.controller.profile.is_lpt_or_newer();
        self.controller.phy.transaction(|p| {
            Controller::<R, D>::emi(
                p,
                if lpt {
                    lpt::EEE_ADVERTISEMENT
                } else {
                    EEE_ADVERTISEMENT
                },
                0,
            )?;
            let control = super::super::Register {
                page: 772,
                index: 20,
            };
            let value = p.access(control, None)? & !LPI_ENABLE;
            if !lpt {
                p.access(
                    super::super::Register { page: 0, index: 16 },
                    Some(LPI_PLL_SHUT),
                )?;
                let pll = p.access(super::super::Register { page: 0, index: 17 }, None)?;
                Controller::<R, D>::emi(p, LPI_PLL_SHUT, pll & !4)?;
            }
            p.access(
                super::super::Register { page: 0, index: 16 },
                Some(if lpt {
                    lpt::EEE_PCS_STATUS
                } else {
                    EEE_PCS_STATUS
                }),
            )?;
            p.access(super::super::Register { page: 0, index: 17 }, None)?;
            p.access(control, Some(value))?;
            Ok(())
        })?;
        Ok(())
    }
    fn update_link(&mut self) -> Result<bool, Error> {
        self.check()?;
        let status = self.controller.read(super::STATUS)? & LINK_SUMMARY;
        // IMC masks interrupts, but ICR still latches link-status changes.
        // Consume that actual event so same-speed reconnects cannot bypass
        // PHY/K1 workarounds merely because the MAC summary is unchanged.
        let event = self.controller.read(super::ICR)?;
        if self.link == Some(status) && event & LINK_EVENT == 0 {
            return Ok(status & LINK_UP != 0);
        }
        let mii = super::super::Register::new(0, 1)?;
        self.controller.phy.read(mii)?; // clear latched-low observation
        let phy = self.controller.phy.read(mii)?;
        if status & LINK_UP == 0 || phy & PHY_LINK_READY != PHY_LINK_READY {
            self.controller
                .lpt_link_common(if status & LINK_UP != 0 && phy & 4 != 0 {
                    Some(status)
                } else {
                    None
                })?;
            self.link = if status & LINK_UP == 0 {
                Some(status)
            } else {
                None
            };
            return Ok(false);
        }
        let half_ten = status & (FULL_DUPLEX | SPEED_MASK) == 0;
        self.modify_mac(
            TIPG,
            0x3ff,
            if half_ten {
                0xff
            } else if self.controller.is_i219()
                && status & FULL_DUPLEX != 0
                && status & (1 << 7) == 0
            {
                0xc
            } else {
                8
            },
        )?;
        let lpt = self.controller.profile.is_lpt_or_newer();
        let mtp = self.controller.mtp_family().is_some();
        self.controller.phy.transaction(|p| {
            Controller::<R, D>::emi(
                p,
                if lpt { lpt::RX_CONFIG } else { RX_CONFIG },
                u16::from(!half_ten),
            )?;
            if lpt {
                let gate = lpt::PLL_CLOCK_GATE;
                let word = p.access(gate, None)?;
                p.access(
                    gate,
                    Some(
                        (word & !lpt::PLL_CLOCK_GATE_MASK)
                            | if status & (1 << 7) != 0 {
                                if mtp {
                                    super::mtp::GIGABIT_PLL_CLOCK_GATE
                                } else {
                                    lpt::PLL_CLOCK_GATE_GIGABIT
                                }
                            } else {
                                lpt::PLL_CLOCK_GATE_SLOW
                            },
                    ),
                )?;
                if status & (1 << 7) != 0 {
                    let pm = super::super::Register {
                        page: 770,
                        index: 17,
                    };
                    let word = p.access(pm, None)?;
                    p.access(pm, Some(word | lpt::K1_CLOCK_REQUEST))?;
                }
            }
            Ok(())
        })?;
        if self.controller.is_i219() {
            let gap = super::super::Register {
                page: 776,
                index: 20,
            };
            if status & (1 << 7) != 0 {
                let word = self.controller.phy.read(gap)?;
                if ((word >> 2) & 0x3ff) < 0x18 {
                    self.controller
                        .phy
                        .write(gap, (word & !(0x3ff << 2)) | (0x18 << 2))?;
                }
            } else {
                self.controller.phy.write(gap, 0xc023)?;
            }
        }
        if lpt {
            self.controller.lpt_link_common(Some(status))?;
            self.disable_eee()?;
            self.modify_mac(super::TCTL, 0x3ff << 12, 63 << 12)?;
            self.modify_mac(super::CTRL, PAUSE, 0)?;
            self.link = Some(status);
            return Ok(true);
        }
        // 82579 K1 and half-duplex preamble workarounds apply on every observed
        // speed/duplex transition, including a cable reconnection while polling.
        let hv = self
            .controller
            .phy
            .read(super::super::Register::new(0, 26)?)?;
        if hv & 0x1040 != 0x1040 || u32::from((hv & 0x300) >> 8) != (status & SPEED_MASK) >> 6 {
            self.link = None;
            return Ok(false);
        }
        if hv & 0x300 != 0 {
            self.controller.modify(770, 17, 1 << 14, 0)?;
        } else {
            self.modify_mac(FEXTNVM4, 7, 3)?;
        }
        self.controller.modify(
            770,
            16,
            0x7000,
            if status & FULL_DUPLEX == 0 { 0x1000 } else { 0 },
        )?;
        self.modify_mac(super::TCTL, 0x3ff << 12, 63 << 12)?;
        self.modify_mac(super::CTRL, PAUSE, 0)?;
        self.link = Some(status);
        Ok(true)
    }
    fn offer(&mut self, index: usize) {
        let base = index * DESCRIPTOR;
        self.receive
            .descriptors
            .write(base, self.receive.address(index));
        self.receive.descriptors.write(base + 8, 0u64);
    }
    fn reclaim(&mut self) -> bool {
        while self.clean_tx != self.next_tx {
            if self
                .transmit
                .descriptors
                .read::<u8>(self.clean_tx * DESCRIPTOR + 12)
                & TX_DONE
                == 0
            {
                break;
            }
            fence(Ordering::Acquire);
            self.clean_tx = (self.clean_tx + 1) % DESCRIPTORS;
        }
        (self.next_tx + 1) % DESCRIPTORS != self.clean_tx
    }
    fn spt_flush_descriptors(&mut self) -> Result<(), Error> {
        if !self.controller.is_i219() {
            return Ok(());
        }
        self.modify_mac(spt::FEXTNVM11, 0, spt::DISABLE_MULR_FIX)?;
        let length = self.controller.read(TDLEN)?;
        let status = self.controller.spt_config_status()?;
        if status & spt::FLUSH_REQUIRED == 0 || length == 0 {
            return Ok(());
        }
        let control = self.controller.read(super::TCTL)?;
        self.controller.write(super::TCTL, control | ENABLE)?;
        let tail = self.controller.read(TDT)?;
        if tail as usize != self.next_tx {
            return Err(Error::Configuration);
        }
        // Source's non-EOP flush descriptor reads512 bytes from the owned
        // descriptor ring itself. The single-empty-slot invariant reserves
        // this descriptor even while earlier packets await retirement.
        let index = self.next_tx;
        let base = index * DESCRIPTOR;
        self.transmit
            .descriptors
            .write(base, self.transmit.descriptors.physical());
        self.transmit
            .descriptors
            .write(base + 8, spt::FLUSH_BYTES | (1 << 25));
        self.transmit.descriptors.write(base + 12, 0u32);
        fence(Ordering::SeqCst);
        self.next_tx = (index + 1) % DESCRIPTORS;
        self.controller.write(TDT, self.next_tx as u32)?;
        self.controller.phy.delay.delay(200);
        if self.controller.spt_config_status()? & spt::FLUSH_REQUIRED != 0 {
            let control = self.controller.read(super::RCTL)?;
            self.controller.write(super::RCTL, control & !ENABLE)?;
            self.controller.read(super::STATUS)?;
            self.controller.phy.delay.delay(100);
            let value = self.controller.read(RXDCTL)?;
            self.controller
                .write(RXDCTL, (value & 0xffff_c000) | 0x1f | (1 << 8) | (1 << 24))?;
            self.controller.write(super::RCTL, control | ENABLE)?;
            self.controller.read(super::STATUS)?;
            self.controller.phy.delay.delay(100);
            self.controller.write(super::RCTL, control & !ENABLE)?;
            // Source only rechecks after TX. An unresolved RX flush is not
            // permission to reset/power down or release the actual owner.
            if self.controller.spt_config_status()? & spt::FLUSH_REQUIRED != 0 {
                return Err(Error::DescriptorFlushRequired);
            }
        }
        Ok(())
    }
    /// Stop both packet engines and observe PCIe master drain before releasing
    /// native resources. Any failure permanently retains the actual owner.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        if self.stopped {
            return Ok(());
        }
        self.check()?;
        let result = (|| {
            self.controller.write(super::IMC, u32::MAX)?;
            self.spt_flush_descriptors()?;
            self.modify_mac(super::RCTL, ENABLE, 0)?;
            self.modify_mac(super::TCTL, ENABLE, 0)?;
            self.controller.read(super::STATUS)?;
            self.controller.phy.delay.delay(10_000);
            self.modify_mac(super::CTRL, 0, super::MASTER_DISABLE)?;
            for _ in 0..800 {
                if self.controller.read(super::STATUS)? & super::MASTER_ENABLED == 0 {
                    self.controller.lpt_platform_pm(None)?;
                    self.modify_mac(CTRL_EXT, DRIVER_LOADED, 0)?;
                    if self.controller.read(CTRL_EXT)? & DRIVER_LOADED != 0 {
                        return Err(Error::Configuration);
                    }
                    return Ok(());
                }
                self.controller.phy.delay.delay(100);
            }
            Err(Error::MasterTimeout)
        })();
        match result {
            Ok(()) => {
                self.stopped = true;
                Ok(())
            }
            Err(e) => {
                self.failure.get_or_insert_with(|| e.clone());
                self.poison();
                Err(e)
            }
        }
    }
    fn error(&mut self, error: Error) -> LinkError {
        if error == Error::Stopped {
            return LinkError::Adapter("PCH Ethernet is stopped".into());
        }
        self.failure.get_or_insert_with(|| error.clone());
        self.poison();
        LinkError::Adapter(format!("PCH: {error}"))
    }
}
impl<R: Registers + nvm::Registers, D: Delay + Clone> Drop for Ethernet<R, D> {
    fn drop(&mut self) {
        if !self.stopped && !self.controller.is_poisoned() {
            let _ = self.shutdown();
        }
        // A poisoned PHY's Drop retains the actual shared function owner.
        // DMA RAM is independently boot-lifetime, including after uncertainty.
    }
}
impl<R: Registers + nvm::Registers, D: Delay + Clone> Link for Ethernet<R, D> {
    fn mac(&self) -> Mac {
        self.controller.station
    }
    fn carrier(&mut self) -> bool {
        match self.update_link() {
            Ok(up) => up,
            Err(Error::Stopped) => false,
            Err(e) => {
                self.failure.get_or_insert(e);
                self.poison();
                false
            }
        }
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        if !(14..=MAX_FRAME).contains(&frame.len()) {
            return Err(LinkError::Invalid("frame length is outside 14..=1514"));
        }
        self.check().map_err(|e| self.error(e))?;
        if !self.update_link().map_err(|e| self.error(e))? {
            return Err(LinkError::Adapter("PCH Ethernet link is down".into()));
        }
        let mut space = self.reclaim();
        for _ in 0..1000 {
            if space {
                break;
            }
            self.controller.phy.delay.delay(100);
            space = self.reclaim();
        }
        if !space {
            return Err(self.error(Error::QueueStalled));
        }
        let index = self.next_tx;
        let length = frame.len().max(MIN_FRAME);
        self.transmit.buffer(index)[..length].fill(0);
        self.transmit.buffer(index)[..frame.len()].copy_from_slice(frame);
        let base = index * DESCRIPTOR;
        self.transmit
            .descriptors
            .write(base, self.transmit.address(index));
        self.transmit
            .descriptors
            .write(base + 8, length as u32 | TX_COMMAND);
        self.transmit.descriptors.write(base + 12, 0u32);
        fence(Ordering::SeqCst);
        let tail = (index + 1) % DESCRIPTORS;
        if let Err(error) = self.controller.write(TDT, tail as u32) {
            return Err(self.error(error));
        }
        self.next_tx = tail;
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.check().map_err(|e| self.error(e))?;
        self.update_link().map_err(|e| self.error(e))?;
        for _ in 0..DESCRIPTORS {
            let index = self.next_rx;
            let base = index * DESCRIPTOR;
            let status = self.receive.descriptors.read::<u32>(base + 8);
            if status & RX_DONE == 0 {
                return Ok(None);
            }
            fence(Ordering::Acquire);
            let length = usize::from(self.receive.descriptors.read::<u16>(base + 12));
            let eop = status & RX_EOP != 0;
            let good = !self.discard_rx
                && eop
                && status & RX_ERRORS == 0
                && (14 + FCS_BYTES..=MAX_FRAME + FCS_BYTES).contains(&length);
            let frame = if good {
                let mut data = Vec::new();
                data.try_reserve_exact(length - FCS_BYTES).map_err(|_| {
                    LinkError::Adapter("PCH Ethernet receive allocation failed".into())
                })?;
                data.extend_from_slice(&self.receive.buffer(index)[..length - FCS_BYTES]);
                Some(data)
            } else {
                None
            };
            self.discard_rx = !eop;
            self.offer(index);
            fence(Ordering::SeqCst);
            if let Err(error) = self.controller.write(RDT, index as u32) {
                return Err(self.error(error));
            }
            self.next_rx = (index + 1) % DESCRIPTORS;
            if frame.is_some() {
                return Ok(frame);
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{Io, Model, Timer, fixture, fixture_lpt, start, start_lpt};
    use super::*;
    use crate::bus::dma::{DmaBuffer, RegionAllocator};
    use alloc::{rc::Rc, sync::Arc, vec};
    use core::{cell::RefCell, sync::atomic::AtomicUsize};

    struct Memory {
        // Actual native CPU RAM backs the model's published DMA addresses.
        // No asynchronous actor accesses it after the model is stopped/dropped.
        _ram: Vec<u128>,
        allocator: RegionAllocator,
    }
    impl Memory {
        fn new() -> Self {
            let mut ram = vec![0u128; (256 * 1024 + 4096) / 16];
            let start = ram.as_mut_ptr() as u64;
            // SAFETY: exclusively owned native test RAM, used only by the
            // synchronous software device model while this owner is alive.
            let allocator = unsafe { RegionAllocator::new(start..start + (ram.len() * 16) as u64) };
            Self {
                _ram: ram,
                allocator,
            }
        }
    }
    impl DmaAllocator for Memory {
        fn allocate(
            &mut self,
            bytes: usize,
            align: usize,
        ) -> Result<DmaBuffer, crate::block::BlockError> {
            self.allocator.allocate(bytes, align)
        }
    }
    type Net = Ethernet<Io, Timer>;
    type Setup = (Rc<RefCell<Model>>, Arc<AtomicUsize>, Controller<Io, Timer>);
    fn setup() -> Setup {
        let (state, released, io, timer) = fixture();
        let controller = start(io, timer).unwrap();
        {
            let mut m = state.borrow_mut();
            m.mac
                .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
            m.phy.insert((2, 0, 1), PHY_LINK_READY);
            m.phy.insert((2, 0, 26), 0x1240);
            m.phy.insert((1, 770, 17), 1 << 14);
            // Preserve manageability-owned receive addresses verbatim.
            for index in 1..7 {
                m.mac.insert(RAL + index * 8, 0x1234_0000 | index);
                m.mac.insert(RAH + index * 8, 0xabcd_0000 | index);
            }
        }
        (state, released, controller)
    }
    fn setup_lpt(device: u16, lock: u32) -> Setup {
        let (state, released, io, timer) = fixture_lpt();
        let fw = state.borrow().mac[&super::super::super::FWSM] | (lock << 7);
        state.borrow_mut().mac.insert(super::super::super::FWSM, fw);
        let controller = start_lpt(device, io, timer).unwrap();
        {
            let mut m = state.borrow_mut();
            m.mac
                .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
            m.phy.insert((2, 0, 1), PHY_LINK_READY);
            m.phy.insert((1, 772, 20), 0xffff);
            m.phy.insert((1, 772, 28), 0xf800);
            for index in 0..11 {
                m.mac.insert(SHRAL_LPT + index * 8, 0x1234_0000 | index);
                m.mac.insert(SHRAH_LPT + index * 8, 0xabcd_0000 | index);
            }
        }
        (state, released, controller)
    }
    fn open(controller: Controller<Io, Timer>, memory: &mut Memory) -> Net {
        // SAFETY: the actual synchronous model's same native CPU RAM grant.
        unsafe { Ethernet::new(controller, memory) }.unwrap()
    }
    fn inject(net: &mut Net, index: usize, status: u32, length: usize, fill: u8) {
        net.receive.buffer(index).fill(fill);
        let base = index * DESCRIPTOR;
        net.receive.descriptors.write(base + 12, length as u16);
        fence(Ordering::Release);
        net.receive.descriptors.write(base + 8, status);
    }
    #[test]
    #[ignore = "set STELA_E1000E_PCH_LPT_ORACLE to an unchanged helper trace"]
    fn unchanged_linux_lpt_shared_address_ownership_and_register_effects() {
        replay_shared(false);
    }
    fn replay_shared(spt: bool) {
        let cases = if spt {
            spt::tests::oracle_cases(2)
        } else {
            lpt::tests::oracle_cases(2)
        };
        replay_shared_cases(spt.then_some(0x156f), cases);
    }
    fn replay_shared_family(family: i219::Family) {
        replay_shared_cases(
            Some(i219::tests::sample_device(family)),
            i219::tests::oracle_cases(family, 2),
        );
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_shared_cases(
        profile: Option<u16>,
        cases: Vec<([u32; 4], Vec<[u32; 3]>)>,
    ) {
        assert_eq!(cases.len(), 8);
        for ([lock, count, _, _], expected) in cases {
            assert_eq!(count, lpt::shared_count(lock << 7) + 1);
            let (state, _, controller) = if let Some(device) = profile {
                setup_integrated(device, lock)
            } else {
                setup_lpt(0x153a, lock)
            };
            let mut memory = Memory::new();
            let mut net = open(controller, &mut memory);
            {
                let mut m = state.borrow_mut();
                m.mac.insert(super::super::STATUS, 0x83);
                for i in 0..11 {
                    m.mac.insert(SHRAL_LPT + i * 8, 0x1234_0000 | i);
                    m.mac.insert(SHRAH_LPT + i * 8, 0xabcd_0000 | i);
                }
                m.operations.clear();
            }
            net.station_filters().unwrap();
            let actual: Vec<_> = state
                .borrow()
                .operations
                .iter()
                .copied()
                .filter(|o| {
                    o[0] <= 1 && (o[1] == super::super::STATUS || (0x5400..0x5460).contains(&o[1]))
                })
                .collect();
            assert_eq!(actual, expected, "FWSM lock={lock}");
            net.shutdown().unwrap();
        }
    }
    #[test]
    #[ignore = "set STELA_E1000E_PCH_LPT_ORACLE to an unchanged helper trace"]
    fn unchanged_linux_lpt_eee_disabled_phy_and_emi_effects() {
        replay_eee(false);
    }
    fn replay_eee(spt: bool) {
        let cases = if spt {
            spt::tests::oracle_cases(3)
        } else {
            lpt::tests::oracle_cases(3)
        };
        replay_eee_cases(spt.then_some(0x156f), cases);
    }
    fn replay_eee_family(family: i219::Family) {
        replay_eee_cases(
            Some(i219::tests::sample_device(family)),
            i219::tests::oracle_cases(family, 3),
        );
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_eee_cases(
        profile: Option<u16>,
        cases: Vec<([u32; 4], Vec<[u32; 3]>)>,
    ) {
        assert_eq!(cases.len(), 3);
        for ([control, _, _, _], expected) in cases {
            let (state, _, controller) = if let Some(device) = profile {
                setup_integrated(device, 0)
            } else {
                setup_lpt(0x153b, 0)
            };
            let mut memory = Memory::new();
            let mut net = open(controller, &mut memory);
            let ext;
            {
                let mut m = state.borrow_mut();
                m.phy.insert((1, 772, 20), control as u16);
                m.emi.insert(0x9401, 0x3c00);
                m.emi.insert(0x8001, 0xffff);
                ext = m.mac[&super::super::super::EXTCNF_CTRL];
                m.operations.clear();
            }
            net.disable_eee().unwrap();
            let actual = super::super::tests::post_effects(&state.borrow().operations, ext);
            assert_eq!(actual, expected, "initial LPI control={control:x}");
            net.shutdown().unwrap();
        }
    }
    #[test]
    fn only_the_actual_32_mta_words_are_cleared_before_packet_initialization() {
        // Prove the hardware model refuses every word beyond the actual MTA
        // table instead of accepting all BAR-relative addresses as registers.
        for address in (0x5280..0x5400).step_by(4) {
            let (state, _, mut io, _) = fixture();
            assert_eq!(
                Registers::write32(&mut io, address, 0),
                Err(super::super::super::Fault::OutsideBar)
            );
            assert!(state.borrow().operations.is_empty());
        }
        let mut memory = Memory::new();
        let (state, released, controller) = setup();
        {
            let mut model = state.borrow_mut();
            for address in (MTA..0x5400).step_by(4) {
                model.mac.insert(address, 0xa55a_0000 | address);
            }
        }
        let mut net = open(controller, &mut memory);
        assert!(net.carrier());
        let model = state.borrow();
        let actual: Vec<_> = model
            .operations
            .iter()
            .copied()
            .filter(|o| o[0] == 1 && (MTA..0x5400).contains(&o[1]))
            .collect();
        let expected: Vec<_> = (0..32).map(|index| [1, MTA + index * 4, 0]).collect();
        assert_eq!(actual, expected);
        for address in (0x5280..0x5400).step_by(4) {
            assert_eq!(model.mac[&address], 0xa55a_0000 | address);
        }
        assert_eq!(model.mac[&super::super::RCTL], RECEIVE_POLICY);
        assert_eq!(model.mac[&super::super::TCTL], TRANSMIT_POLICY);
        assert_eq!(model.mac[&RFCTL] & EXTENDED_RX, EXTENDED_RX);
        assert_eq!(model.mac[&RDLEN], (DESCRIPTORS * DESCRIPTOR) as u32);
        assert_eq!(model.mac[&TDLEN], (DESCRIPTORS * DESCRIPTOR) as u32);
        drop(model);
        net.transmit(&[0x66; 60]).unwrap();
        inject(&mut net, 0, RX_DONE | RX_EOP, 64, 0x77);
        assert_eq!(net.receive().unwrap(), Some(vec![0x77; 60]));
        net.shutdown().unwrap();
        drop(net);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn native_extended_rx_and_legacy_tx_payloads_wrap_without_offloads() {
        let mut memory = Memory::new();
        let (state, released, controller) = setup();
        let mut net = open(controller, &mut memory);
        assert!(net.carrier());
        for n in 0..97 {
            let size = if n % 3 == 0 { 14 } else { MAX_FRAME };
            let frame = vec![n as u8; size];
            let index = net.next_tx;
            net.transmit(&frame).unwrap();
            assert_eq!(&net.transmit.buffer(index)[..size], frame.as_slice());
            assert!(
                net.transmit.buffer(index)[size..size.max(MIN_FRAME)]
                    .iter()
                    .all(|b| *b == 0)
            );
            assert_eq!(
                net.transmit.descriptors.read::<u32>(index * DESCRIPTOR + 8),
                size.max(MIN_FRAME) as u32 | TX_COMMAND
            );
            // Actual hardware DD is the only retirement evidence. Head/tail
            // equality and a doorbell write never substitute for completion.
            net.transmit
                .descriptors
                .write(index * DESCRIPTOR + 12, TX_DONE);
            let index = net.next_rx;
            inject(&mut net, index, RX_DONE | RX_EOP, size + FCS_BYTES, n as u8);
            assert_eq!(net.receive().unwrap().unwrap(), frame);
            assert_eq!(
                net.receive.descriptors.read::<u64>(index * DESCRIPTOR),
                net.receive.address(index)
            );
            assert_eq!(
                net.receive.descriptors.read::<u64>(index * DESCRIPTOR + 8),
                0
            );
        }
        let m = state.borrow();
        assert_eq!(m.mac[&RFCTL] & EXTENDED_RX, EXTENDED_RX);
        assert_eq!(
            m.mac[&super::super::RCTL] & (1 << 26),
            0,
            "FCS is retained for software removal"
        );
        assert_eq!(m.mac[&TXDCTL], m.mac[&(TXDCTL + QUEUE_STRIDE)]);
        assert_eq!(m.phy[&(2, 0, 4)] & ADVERTISEMENT_PAUSE, 0);
        assert_eq!(m.phy[&(1, 772, 20)] & LPI_ENABLE, 0);
        assert_eq!(m.phy[&(1, 776, 23)], 0x7e00);
        for index in 1..7 {
            assert_eq!(m.mac[&(RAL + index * 8)], 0x1234_0000 | index);
            assert_eq!(m.mac[&(RAH + index * 8)], 0xabcd_0000 | index);
        }
        drop(m);
        net.shutdown().unwrap();
        assert_eq!(state.borrow().mac[&CTRL_EXT] & DRIVER_LOADED, 0);
        let accesses = state.borrow().accesses;
        assert!(net.transmit(&[0; 60]).is_err());
        assert_eq!(state.borrow().accesses, accesses);
        drop(net);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn fragments_bad_status_and_bad_lengths_are_never_delivered() {
        let mut memory = Memory::new();
        let (_, _, controller) = setup();
        let mut net = open(controller, &mut memory);
        inject(&mut net, 0, RX_DONE, 64, 1);
        inject(&mut net, 1, RX_DONE | RX_EOP, 64, 2);
        inject(&mut net, 2, RX_DONE | RX_EOP | 0x0100_0000, 64, 3);
        inject(&mut net, 3, RX_DONE | RX_EOP, BUFFER + 1, 4);
        inject(&mut net, 4, RX_DONE | RX_EOP, 3, 5);
        inject(&mut net, 5, RX_DONE | RX_EOP, 64, 6);
        assert_eq!(net.receive().unwrap(), Some(vec![6; 60]));
        assert_eq!(net.next_rx, 6);
        assert_eq!(net.receive().unwrap(), None);
    }
    #[test]
    fn link_reconnect_and_speed_changes_apply_actual_82579_workarounds() {
        let mut memory = Memory::new();
        let (state, _, controller) = setup();
        let mut net = open(controller, &mut memory);
        assert_eq!(state.borrow().phy[&(1, 770, 17)] & (1 << 14), 0);
        state.borrow_mut().mac.insert(super::super::STATUS, 0);
        assert!(!net.carrier());
        state.borrow_mut().mac.insert(super::super::STATUS, LINK_UP);
        state.borrow_mut().phy.insert((2, 0, 26), 0x1040);
        assert!(net.carrier());
        assert_eq!(state.borrow().mac[&TIPG] & 0x3ff, 0xff);
        assert_eq!(state.borrow().mac[&FEXTNVM4] & 7, 3);
        assert_eq!(state.borrow().emi[&RX_CONFIG], 0);
        assert_eq!(state.borrow().phy[&(1, 770, 16)] & 0x7000, 0x1000);
        state
            .borrow_mut()
            .mac
            .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 6));
        state.borrow_mut().phy.insert((2, 0, 26), 0x1140);
        assert!(net.carrier());
        assert_eq!(state.borrow().mac[&TIPG] & 0x3ff, 8);
        assert_eq!(state.borrow().emi[&RX_CONFIG], 1);
        assert_eq!(state.borrow().phy[&(1, 770, 16)] & 0x7000, 0);
        // A same-speed LSC can arrive while PHY negotiation is still settling.
        // Do not cache a mismatched MAC/PHY observation as fully configured.
        state.borrow_mut().mac.insert(super::super::ICR, LINK_EVENT);
        state.borrow_mut().phy.insert((2, 0, 26), 0x1040);
        assert!(!net.carrier());
        assert_eq!(net.link, None);
        state.borrow_mut().phy.insert((2, 0, 26), 0x1140);
        assert!(net.carrier());
        assert!(!net.controller.is_poisoned());
    }
    #[test]
    fn unretired_tx_cannot_be_overwritten_and_stall_poison_retains_owner() {
        let mut memory = Memory::new();
        let (state, released, controller) = setup();
        let mut net = open(controller, &mut memory);
        for _ in 0..DESCRIPTORS - 1 {
            net.transmit(&[0x55; 60]).unwrap();
        }
        let before = net.transmit.descriptors.bytes().to_vec();
        let time = state.borrow().time;
        assert!(net.transmit(&[0x99; 60]).is_err());
        assert_eq!(state.borrow().time - time, 100_000);
        assert_eq!(net.transmit.descriptors.bytes(), before);
        assert_eq!(net.failure(), Some(&Error::QueueStalled));
        let accesses = state.borrow().accesses;
        assert!(net.receive().is_err());
        assert!(net.shutdown().is_err());
        assert_eq!(state.borrow().accesses, accesses);
        drop(net);
        assert_eq!(released.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn uncertain_tx_rx_doorbells_and_stop_drain_never_release_actual_owner() {
        for lpt in [false, true] {
            for failure in 0..5 {
                let mut memory = Memory::new();
                let (state, released, controller) =
                    if lpt { setup_lpt(0x153a, 0) } else { setup() };
                let mut net = open(controller, &mut memory);
                match failure {
                    0 => {
                        // update_link's STATUS/ICR reads then the actual TDT store.
                        let at = state.borrow().accesses + 2;
                        state.borrow_mut().fail_at = Some(at);
                        assert!(net.transmit(&[0; 60]).is_err());
                        assert_eq!(net.next_tx, 0);
                    }
                    1 => {
                        inject(&mut net, 0, RX_DONE | RX_EOP, 64, 0x44);
                        let at = state.borrow().accesses + 2;
                        state.borrow_mut().fail_at = Some(at);
                        assert!(net.receive().is_err());
                        assert_eq!(net.next_rx, 0);
                    }
                    2 => {
                        state.borrow_mut().master_busy = 10_000;
                        assert_eq!(net.shutdown(), Err(Error::MasterTimeout));
                    }
                    3 => {
                        let at = state.borrow().accesses;
                        state.borrow_mut().fail_at = Some(at);
                        assert!(net.shutdown().is_err());
                    }
                    4 => {
                        state
                            .borrow_mut()
                            .mac
                            .insert(super::super::STATUS, u32::MAX);
                        assert!(!net.carrier());
                        assert!(matches!(
                            net.failure(),
                            Some(Error::Phy(super::super::super::Error {
                                primary: super::super::super::Fault::Removed,
                                ..
                            }))
                        ));
                    }
                    _ => unreachable!(),
                }
                assert!(net.controller.is_poisoned());
                let accesses = state.borrow().accesses;
                assert!(!net.carrier());
                assert!(net.transmit(&[0; 60]).is_err());
                assert_eq!(state.borrow().accesses, accesses);
                drop(net);
                assert_eq!(released.load(Ordering::SeqCst), 0);
            }
        }
    }
    #[test]
    fn every_queue_configuration_access_failure_prevents_reuse_and_retains_owner() {
        let mut memory = Memory::new();
        let (state, _, controller) = setup();
        let first = state.borrow().accesses;
        let net = open(controller, &mut memory);
        let last = state.borrow().accesses;
        drop(net);
        for at in first..last {
            let mut memory = Memory::new();
            let (state, released, controller) = setup();
            state.borrow_mut().fail_at = Some(at);
            // SAFETY: the same isolated actual native-RAM model grant.
            assert!(
                unsafe { Ethernet::new(controller, &mut memory) }.is_err(),
                "lost queue fault at {at}"
            );
            assert_eq!(
                released.load(Ordering::SeqCst),
                0,
                "released actual owner at {at}"
            );
        }
    }
    #[test]
    fn every_shutdown_access_failure_retains_the_actual_owner() {
        for lpt in [false, true] {
            let mut memory = Memory::new();
            let (state, _, controller) = if lpt { setup_lpt(0x153a, 0) } else { setup() };
            let mut net = open(controller, &mut memory);
            let first = state.borrow().accesses;
            net.shutdown().unwrap();
            let last = state.borrow().accesses;
            drop(net);
            for at in first..last {
                let mut memory = Memory::new();
                let (state, released, controller) =
                    if lpt { setup_lpt(0x153a, 0) } else { setup() };
                let mut net = open(controller, &mut memory);
                state.borrow_mut().fail_at = Some(at);
                assert!(net.shutdown().is_err(), "lost stop fault at {at}");
                let accesses = state.borrow().accesses;
                drop(net);
                assert_eq!(
                    state.borrow().accesses,
                    accesses,
                    "drop retried failed stop"
                );
                assert_eq!(
                    released.load(Ordering::SeqCst),
                    0,
                    "released owner after stop fault {at}"
                );
            }
        }
    }
    #[test]
    fn lpt_exact_devices_honor_actual_shra_locks_ecc_and_packet_lifecycle() {
        for device in [0x153a, 0x153b, 0x15a0, 0x15a1] {
            for lock in 0..8 {
                let mut memory = Memory::new();
                let (state, released, controller) = setup_lpt(device, lock);
                let mut net = open(controller, &mut memory);
                assert!(net.carrier());
                {
                    let m = state.borrow();
                    let count = match lock {
                        0 => 11,
                        1 => 0,
                        _ => lock,
                    };
                    for index in 0..11 {
                        assert_eq!(
                            m.mac[&(SHRAL_LPT + index * 8)],
                            if index < count {
                                0
                            } else {
                                0x1234_0000 | index
                            }
                        );
                        assert_eq!(
                            m.mac[&(SHRAH_LPT + index * 8)],
                            if index < count {
                                0
                            } else {
                                0xabcd_0000 | index
                            }
                        );
                    }
                    assert_eq!(m.mac[&PBECCSTS] & ECC_ENABLE, ECC_ENABLE);
                    assert_eq!(
                        m.mac[&super::super::CTRL] & MEMORY_ERROR_HANDLING,
                        MEMORY_ERROR_HANDLING
                    );
                    assert_eq!(m.mac[&0xf8], 0xc8b9_88b9);
                    assert_eq!(m.phy[&(1, 772, 28)], 0xf8fa);
                    assert_eq!(m.phy[&(1, 770, 17)] & (1 << 9), 1 << 9);
                    assert_eq!(m.phy[&(1, 772, 20)] & LPI_ENABLE, 0);
                    assert_eq!(m.emi[&0x8001], 0);
                    assert!(!m.emi.contains_key(&LPI_PLL_SHUT));
                    assert!(!m.kmrn.contains_key(&4));
                    assert!(!m.kmrn.contains_key(&9));
                }
                for n in 0..65 {
                    let frame = vec![n as u8; 60];
                    let tx = net.next_tx;
                    net.transmit(&frame).unwrap();
                    assert_eq!(&net.transmit.buffer(tx)[..60], frame.as_slice());
                    net.transmit
                        .descriptors
                        .write(tx * DESCRIPTOR + 12, TX_DONE);
                    let rx = net.next_rx;
                    inject(&mut net, rx, RX_DONE | RX_EOP, 64, n as u8);
                    assert_eq!(net.receive().unwrap(), Some(frame));
                }
                net.shutdown().unwrap();
                assert_eq!(state.borrow().mac[&0xf8], 1 << 30);
                drop(net);
                assert_eq!(released.load(Ordering::SeqCst), 1);
            }
        }
    }
    #[test]
    fn lpt_link_speeds_and_same_speed_events_update_pll_emi_and_platform_ltr() {
        let mut memory = Memory::new();
        let (state, _, controller) = setup_lpt(0x15a0, 0);
        let mut net = open(controller, &mut memory);
        for (status, tipg, ltr, emi) in [
            (LINK_UP, 0xff, 0xd003_9003, 0),
            (LINK_UP | FULL_DUPLEX | (1 << 6), 8, 0xcc3a_8c3a, 1),
            (LINK_UP | FULL_DUPLEX | (1 << 7), 8, 0xc8b9_88b9, 1),
        ] {
            state.borrow_mut().mac.insert(super::super::STATUS, status);
            assert!(net.carrier());
            let m = state.borrow();
            assert_eq!(m.mac[&TIPG] & 0x3ff, tipg);
            assert_eq!(m.mac[&0xf8], ltr);
            assert_eq!(m.emi[&0xb20c], emi);
            assert_eq!(
                m.phy[&(1, 772, 28)] & 0x7ff,
                if status & (1 << 7) != 0 { 0xfa } else { 0x3e8 }
            );
            assert_eq!(m.mac[&FEXTNVM4] & 7, 7);
        }
        state.borrow_mut().mac.insert(super::super::ICR, LINK_EVENT);
        state.borrow_mut().phy.insert((1, 772, 28), 0xffff);
        assert!(net.carrier());
        assert_eq!(state.borrow().phy[&(1, 772, 28)] & 0x7ff, 0xfa);
        state.borrow_mut().mac.insert(super::super::STATUS, 0);
        assert!(!net.carrier());
        assert_eq!(state.borrow().mac[&0xf8], 1 << 30);
    }
    #[test]
    fn every_lpt_queue_config_and_link_transition_access_failure_retains_owner() {
        let mut memory = Memory::new();
        let (state, _, controller) = setup_lpt(0x153a, 0);
        let first = state.borrow().accesses;
        let mut net = open(controller, &mut memory);
        let configured = state.borrow().accesses;
        state.borrow_mut().mac.insert(super::super::STATUS, LINK_UP);
        assert!(net.carrier());
        let linked = state.borrow().accesses;
        drop(net);
        for at in first..linked {
            let mut memory = Memory::new();
            let (state, released, controller) = setup_lpt(0x153a, 0);
            if at < configured {
                state.borrow_mut().fail_at = Some(at);
                // SAFETY: isolated same-function model's actual native RAM.
                assert!(
                    unsafe { Ethernet::new(controller, &mut memory) }.is_err(),
                    "lost LPT queue fault at{at}"
                );
            } else {
                let mut net = open(controller, &mut memory);
                state.borrow_mut().mac.insert(super::super::STATUS, LINK_UP);
                state.borrow_mut().fail_at = Some(at);
                assert!(!net.carrier(), "lost LPT link fault at{at}");
                let accesses = state.borrow().accesses;
                assert!(net.transmit(&[0; 60]).is_err());
                assert!(net.shutdown().is_err());
                assert_eq!(state.borrow().accesses, accesses);
                drop(net);
            }
            assert_eq!(
                released.load(Ordering::SeqCst),
                0,
                "released LPT owner at{at}"
            );
        }
    }
    fn setup_spt(device: u16, lock: u32) -> Setup {
        let (state, released, io, timer) = spt::tests::fixture_spt();
        let fw = state.borrow().mac[&super::super::super::FWSM] | (lock << 7);
        state.borrow_mut().mac.insert(super::super::super::FWSM, fw);
        let controller = spt::tests::start_spt(device, io, timer).unwrap();
        {
            let mut m = state.borrow_mut();
            m.mac
                .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
            m.phy.insert((2, 0, 1), PHY_LINK_READY);
            for i in 0..11 {
                m.mac.insert(SHRAL_LPT + i * 8, 0x1234_0000 | i);
                m.mac.insert(SHRAH_LPT + i * 8, 0xabcd_0000 | i);
            }
        }
        (state, released, controller)
    }
    #[test]
    fn spt_cohort_ecc_shra_errata_link_payload_wrap_and_live_stop_status() {
        for device in [0x156f, 0x1570] {
            for lock in 0..8 {
                let (state, released, controller) = setup_spt(device, lock);
                let mut memory = Memory::new();
                let mut net = open(controller, &mut memory);
                {
                    let m = state.borrow();
                    let count = lpt::shared_count(lock << 7);
                    for i in 0..11 {
                        assert_eq!(
                            m.mac[&(SHRAL_LPT + i * 8)],
                            if i < count { 0 } else { 0x1234_0000 | i }
                        );
                    }
                    assert_ne!(m.mac[&PBECCSTS] & ECC_ENABLE, 0);
                    assert_ne!(m.mac[&super::super::CTRL] & MEMORY_ERROR_HANDLING, 0);
                    assert_ne!(m.mac[&0xf28] & 0x1_0000, 0);
                    assert_eq!(m.mac[&TARC] & 0x3000_0000, 0x2000_0000);
                    assert_ne!(m.mac[&0xe4] & 4, 0);
                    assert_eq!(m.mac[&0x5bb4] & 0x1800, 0x1800);
                    assert!((m.phy[&(1, 776, 20)] >> 2) & 0x3ff >= 0x18);
                }
                for n in 0..65 {
                    let frame = vec![n as u8; 60];
                    let tx = net.next_tx;
                    net.transmit(&frame).unwrap();
                    assert_eq!(&net.transmit.buffer(tx)[..60], frame.as_slice());
                    net.transmit
                        .descriptors
                        .write(tx * DESCRIPTOR + 12, TX_DONE);
                    let rx = net.next_rx;
                    inject(&mut net, rx, RX_DONE | RX_EOP, 64, n as u8);
                    assert_eq!(net.receive().unwrap(), Some(frame));
                }
                net.shutdown().unwrap();
                drop(net);
                assert_eq!(released.load(Ordering::SeqCst), 1);
            }
        }
    }
    #[test]
    fn spt_all_speeds_apply_ipg_gap_and_actual_analog_k1_policy() {
        let (state, _, controller) = setup_spt(0x1570, 0);
        let mut memory = Memory::new();
        let mut net = open(controller, &mut memory);
        for (status, ipg, gap) in [
            (LINK_UP, 0xff, 0xc023),
            (LINK_UP | FULL_DUPLEX, 0xc, 0xc023),
            (LINK_UP | (1 << 6), 8, 0xc023),
            (LINK_UP | FULL_DUPLEX | (1 << 6), 0xc, 0xc023),
            (LINK_UP | FULL_DUPLEX | (1 << 7), 8, 0x60),
        ] {
            let mut m = state.borrow_mut();
            m.mac.insert(super::super::STATUS, status);
            m.phy.insert((1, 776, 20), 0);
            m.mac.insert(0xf18, 1 << 31);
            drop(m);
            assert!(net.carrier());
            let m = state.borrow();
            assert_eq!(m.mac[&TIPG] & 0x3ff, ipg);
            assert_eq!(m.phy[&(1, 776, 20)], gap);
            assert_eq!(m.mac[&0x10] & (1 << 31), 1 << 31);
        }
        let mut m = state.borrow_mut();
        m.mac.insert(0xf18, 0);
        m.mac.insert(super::super::ICR, LINK_EVENT);
        drop(m);
        assert!(net.carrier());
        assert_eq!(state.borrow().mac[&0x10] & (1 << 31), 0);
    }
    #[test]
    fn spt_owned_ring_flush_uses_actual_dummy_dma_and_rx_fallback_before_vendor_drain() {
        for rx in [false, true] {
            for tail in [0, 31] {
                let (state, released, controller) = setup_spt(0x156f, 0);
                let mut memory = Memory::new();
                let mut net = open(controller, &mut memory);
                net.next_tx = tail;
                net.clean_tx = tail;
                {
                    let mut m = state.borrow_mut();
                    m.mac.insert(TDT, tail as u32);
                    m.config.insert(0xe4, 0x100);
                    m.flush_after_tx = !rx;
                    m.flush_after_rx = rx;
                    m.operations.clear();
                }
                net.shutdown().unwrap();
                let base = tail * DESCRIPTOR;
                assert_eq!(
                    net.transmit.descriptors.read::<u64>(base),
                    net.transmit.descriptors.physical()
                );
                assert_eq!(
                    net.transmit.descriptors.read::<u32>(base + 8),
                    512 | (1 << 25)
                );
                assert_eq!(net.transmit.descriptors.read::<u32>(base + 12), 0);
                assert_eq!(state.borrow().config[&0xe4] & 0x100, 0);
                assert!(state.borrow().operations.contains(&[2, 200, 0]));
                let m = state.borrow();
                let doorbell = m
                    .operations
                    .iter()
                    .position(|o| o[0] == 1 && o[1] == TDT)
                    .unwrap();
                let drained = m
                    .operations
                    .iter()
                    .position(|o| {
                        o[0] == 1
                            && o[1] == super::super::CTRL
                            && o[2] & super::super::MASTER_DISABLE != 0
                    })
                    .unwrap();
                assert!(doorbell < drained);
                drop(m);
                drop(net);
                assert_eq!(released.load(Ordering::SeqCst), 1);
            }
        }
    }
    #[test]
    fn unresolved_flush_tail_mismatch_or_independent_master_timeout_never_release_owner() {
        for failure in 0..3 {
            let (state, released, controller) = setup_spt(0x156f, 0);
            let mut memory = Memory::new();
            let mut net = open(controller, &mut memory);
            {
                let mut m = state.borrow_mut();
                m.config.insert(0xe4, 0x100);
                m.flush_after_tx = failure != 0;
                if failure == 1 {
                    m.mac.insert(TDT, 7);
                }
                if failure == 2 {
                    m.master_busy = 2000;
                }
            }
            assert!(net.shutdown().is_err());
            let accesses = state.borrow().accesses;
            assert!(net.transmit(&[0; 60]).is_err());
            assert!(!net.carrier());
            drop(net);
            assert_eq!(state.borrow().accesses, accesses);
            assert_eq!(released.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn every_spt_config_link_and_flushing_stop_access_failure_retains_owner() {
        let (state, _, controller) = setup_spt(0x156f, 0);
        let mut memory = Memory::new();
        let first = state.borrow().accesses;
        let mut net = open(controller, &mut memory);
        let configured = state.borrow().accesses;
        state
            .borrow_mut()
            .mac
            .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 6));
        assert!(net.carrier());
        let linked = state.borrow().accesses;
        {
            let mut m = state.borrow_mut();
            m.config.insert(0xe4, 0x100);
            m.flush_after_rx = true;
        }
        net.shutdown().unwrap();
        let last = state.borrow().accesses;
        drop(net);
        for at in first..last {
            let (state, released, controller) = setup_spt(0x156f, 0);
            let mut memory = Memory::new();
            if at < configured {
                state.borrow_mut().fail_at = Some(at); /* SAFETY: actual isolated native RAM grant. */
                assert!(
                    unsafe { Ethernet::new(controller, &mut memory) }.is_err(),
                    "lost SPT config{at}"
                );
            } else {
                let mut net = open(controller, &mut memory);
                state
                    .borrow_mut()
                    .mac
                    .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 6));
                if at < linked {
                    state.borrow_mut().fail_at = Some(at);
                    assert!(!net.carrier(), "lost SPT link{at}");
                } else {
                    assert!(net.carrier());
                    let mut m = state.borrow_mut();
                    m.config.insert(0xe4, 0x100);
                    m.flush_after_rx = true;
                    m.fail_at = Some(at);
                    drop(m);
                    assert!(net.shutdown().is_err(), "lost SPT stop{at}");
                }
                let count = state.borrow().accesses;
                assert!(net.transmit(&[0; 60]).is_err());
                assert!(!net.carrier());
                drop(net);
                assert_eq!(state.borrow().accesses, count);
            }
            assert_eq!(released.load(Ordering::SeqCst), 0, "released SPT owner{at}");
        }
    }
    #[test]
    #[ignore = "set STELA_E1000E_PCH_SPT_ORACLE to an unchanged helper trace"]
    fn unchanged_linux_spt_shared_address_and_eee_disabled_effects() {
        replay_shared(true);
        replay_eee(true);
    }
    #[test]
    #[ignore = "set STELA_E1000E_PCH_SPT_ORACLE to an unchanged helper trace"]
    fn unchanged_linux_spt_link_phy_mac_and_platform_workarounds() {
        replay_i219_link(0x156f, spt::tests::oracle_cases(6));
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_i219_link(
        device: u16,
        cases: Vec<([u32; 4], Vec<[u32; 3]>)>,
    ) {
        assert_eq!(cases.len(), 48);
        for ([status, analog, gap, _], expected) in cases {
            let (state, _, controller) = setup_integrated(device, 0);
            let mut memory = Memory::new();
            let mut net = open(controller, &mut memory);
            net.link = None;
            {
                let mut m = state.borrow_mut();
                m.mac.insert(super::super::STATUS, status);
                m.mac.insert(TIPG, 0x76543210);
                m.mac.insert(FEXTNVM4, 0xabcdef00);
                m.mac
                    .insert(0x10, 0x23456789 | if analog != 0 { 0 } else { 1 << 31 });
                m.mac.insert(0xf18, if analog != 0 { 1 << 31 } else { 0 });
                m.mac.insert(PBA, 26);
                m.phy
                    .insert((2, 0, 1), if status & 2 != 0 { 0x24 } else { 0 });
                m.phy.insert((1, 772, 28), 0xf812);
                m.phy.insert((1, 770, 17), 0xa533);
                m.phy.insert((1, 776, 20), gap as u16);
                m.phy.insert((1, 772, 20), 0xffff);
                m.emi.insert(0x9401, 0x3c00);
                m.operations.clear();
            }
            assert_eq!(net.carrier(), status & 2 != 0);
            let actual = spt::tests::source_effects(&state.borrow().operations, 6);
            assert_eq!(
                actual, expected,
                "status={status:x} analog={analog} gap={gap:x}"
            );
            net.shutdown().unwrap();
        }
    }
    #[test]
    #[ignore = "set STELA_E1000E_PCH_SPT_ORACLE to an unchanged helper trace"]
    fn unchanged_linux_spt_owned_descriptor_flush_effects_and_exact_dma_bytes() {
        replay_i219_flush(0x156f, spt::tests::oracle_cases(7));
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_i219_flush(
        device: u16,
        cases: Vec<([u32; 4], Vec<[u32; 3]>)>,
    ) {
        assert_eq!(cases.len(), 15);
        for ([scenario, tail, _, _], expected) in cases {
            let (state, _, controller) = setup_integrated(device, 0);
            let mut memory = Memory::new();
            let mut net = open(controller, &mut memory);
            net.next_tx = tail as usize;
            net.clean_tx = tail as usize;
            {
                let mut m = state.borrow_mut();
                m.mac.insert(spt::FEXTNVM11, 0x9234);
                m.mac.insert(TDLEN, if scenario == 4 { 0 } else { 512 });
                m.mac.insert(super::super::TCTL, 0x12345670);
                m.mac.insert(TDT, tail);
                m.mac.insert(super::super::RCTL, 0x76543212);
                m.mac.insert(RXDCTL, 0xa5a53fff);
                m.mac.insert(super::super::STATUS, 0x83);
                m.config.insert(0xe4, if scenario == 0 { 0 } else { 0x100 });
                m.flush_after_tx = scenario == 1;
                m.flush_after_rx = scenario == 2;
                m.operations.clear();
            }
            let result = net.spt_flush_descriptors();
            assert_eq!(
                result,
                if scenario == 3 {
                    Err(Error::DescriptorFlushRequired)
                } else {
                    Ok(())
                }
            );
            let mut cfg_reads = 0;
            let mut actual: Vec<_> = state
                .borrow()
                .operations
                .iter()
                .copied()
                .filter(|o| {
                    if o[0] == 7 {
                        cfg_reads += 1;
                        return cfg_reads <= 2;
                    }
                    o[0] <= 2
                })
                .collect();
            if (1..=3).contains(&scenario) {
                let base = tail as usize * DESCRIPTOR;
                actual.extend_from_slice(&[
                    [
                        21,
                        0,
                        u32::from(
                            net.transmit.descriptors.read::<u64>(base)
                                == net.transmit.descriptors.physical(),
                        ),
                    ],
                    [21, 8, net.transmit.descriptors.read::<u32>(base + 8)],
                    [21, 12, net.transmit.descriptors.read::<u32>(base + 12)],
                    [21, 16, net.next_tx as u32],
                ]);
            }
            assert_eq!(actual, expected, "scenario={scenario} tail={tail}");
            if result.is_err() {
                net.poison();
            } else {
                state.borrow_mut().config.insert(0xe4, 0);
                net.shutdown().unwrap();
            }
        }
    }
    #[test]
    fn spt_flush_uses_the_reserved_slot_without_overwriting_unretired_packet_descriptors() {
        let (state, released, controller) = setup_spt(0x156f, 0);
        let mut memory = Memory::new();
        let mut net = open(controller, &mut memory);
        for n in 0..DESCRIPTORS - 1 {
            net.transmit(&[n as u8; 60]).unwrap();
        }
        assert_eq!(net.next_tx, DESCRIPTORS - 1);
        assert_eq!(net.clean_tx, 0);
        let before: Vec<_> = (0..DESCRIPTORS - 1)
            .map(|i| {
                (
                    net.transmit.descriptors.read::<u64>(i * DESCRIPTOR),
                    net.transmit.descriptors.read::<u64>(i * DESCRIPTOR + 8),
                )
            })
            .collect();
        {
            let mut m = state.borrow_mut();
            m.config.insert(0xe4, 0x100);
            m.flush_after_tx = true;
        }
        net.shutdown().unwrap();
        for (i, &(address, command)) in before.iter().enumerate() {
            assert_eq!(
                net.transmit.descriptors.read::<u64>(i * DESCRIPTOR),
                address
            );
            assert_eq!(
                net.transmit.descriptors.read::<u64>(i * DESCRIPTOR + 8),
                command
            );
            assert_eq!(&net.transmit.buffer(i)[..60], vec![i as u8; 60]);
        }
        drop(net);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }
    fn setup_i219(device: u16, lock: u32) -> Setup {
        setup_integrated(device, lock)
    }
    fn setup_integrated(device: u16, lock: u32) -> Setup {
        let (state, released, io, timer) = i219::tests::fixture();
        let fw = state.borrow().mac[&super::super::super::FWSM] | (lock << 7);
        state.borrow_mut().mac.insert(super::super::super::FWSM, fw);
        let controller = super::super::mtp::tests::start_any(device, io, timer).unwrap();
        {
            let mut m = state.borrow_mut();
            m.mac
                .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
            m.phy.insert((2, 0, 1), PHY_LINK_READY);
            for i in 0..11 {
                m.mac.insert(SHRAL_LPT + i * 8, 0x1234_0000 | i);
                m.mac.insert(SHRAH_LPT + i * 8, 0xabcd_0000 | i);
            }
        }
        (state, released, controller)
    }
    #[test]
    #[ignore = "set all four STELA_E1000E_PCH_I219_*_ORACLE paths"]
    fn unchanged_family_shra_eee_link_flush_and_dma_clock_effects() {
        for family in i219::tests::families() {
            replay_shared_family(family);
            replay_eee_family(family);
            replay_i219_link(
                i219::tests::sample_device(family),
                i219::tests::oracle_cases(family, 6),
            );
            replay_i219_flush(
                i219::tests::sample_device(family),
                i219::tests::oracle_cases(family, 7),
            );
            let cases = i219::tests::oracle_cases(family, 8);
            assert_eq!(cases.len(), 2);
            for ([initial, _, _, _], expected) in cases {
                let (state, _, controller) = setup_i219(i219::tests::sample_device(family), 0);
                let mut memory = Memory::new();
                let mut net = open(controller, &mut memory);
                state.borrow_mut().mac.insert(FFLT_DBG, initial);
                state.borrow_mut().operations.clear();
                net.i219_clock_policy().unwrap();
                let actual: Vec<_> = state
                    .borrow()
                    .operations
                    .iter()
                    .copied()
                    .filter(|o| o[0] <= 1 && o[1] == FFLT_DBG)
                    .collect();
                assert_eq!(actual, expected, "DMA clock{family:?} initial{initial:x}");
                assert_eq!(
                    state.borrow().mac[&FFLT_DBG] & !i219::DONT_GATE_WAKE_DMA_CLOCK,
                    initial & !i219::DONT_GATE_WAKE_DMA_CLOCK
                );
                net.shutdown().unwrap();
            }
        }
    }
    #[test]
    fn all_declared_i219_ids_complete_cold_packet_wrap_and_live_flushing_stop() {
        let devices = i219::tests::inventory();
        assert_eq!(devices.len(), 39);
        for (n, (device, family)) in devices.into_iter().enumerate() {
            let lock = n as u32 % 8;
            let (state, released, controller) = setup_i219(device, lock);
            {
                let mut m = state.borrow_mut();
                m.mac.insert(
                    spt::IOSFPC,
                    if family == i219::Family::Spt {
                        0x4000
                    } else {
                        u32::MAX
                    },
                );
                m.mac.insert(TARC, 0x3000_0000);
                m.mac.insert(FFLT_DBG, 0x2345_0abc);
                m.mac.insert(spt::PCIE_ANALOG, 1 << 31);
                m.mac.insert(0x10, 0x23456789);
            }
            let mut memory = Memory::new();
            let mut net = open(controller, &mut memory);
            {
                let m = state.borrow();
                assert_eq!(
                    m.mac[&spt::IOSFPC],
                    if family == i219::Family::Spt {
                        0x4000 | spt::CORRUPTION_THRESHOLD
                    } else {
                        u32::MAX
                    }
                );
                assert_eq!(
                    m.mac[&TARC] & spt::TARC_REQUEST_MASK,
                    if family == i219::Family::Spt {
                        spt::TARC_TWO_REQUESTS
                    } else {
                        0x3000_0000
                    }
                );
                assert_eq!(
                    m.mac[&0x10] & (1 << 31),
                    if family == i219::Family::Spt {
                        1 << 31
                    } else {
                        0
                    }
                );
                assert_eq!(
                    m.mac[&FFLT_DBG] & 0x1000,
                    if family.dma_clock_workaround() {
                        0x1000
                    } else {
                        0
                    }
                );
                let count = lpt::shared_count(lock << 7);
                for i in 0..11 {
                    assert_eq!(
                        m.mac[&(SHRAL_LPT + i * 8)],
                        if i < count { 0 } else { 0x1234_0000 | i }
                    );
                }
            }
            for packet in 0..65 {
                let frame = vec![packet as u8; 60];
                let tx = net.next_tx;
                net.transmit(&frame).unwrap();
                assert_eq!(&net.transmit.buffer(tx)[..60], frame.as_slice());
                net.transmit
                    .descriptors
                    .write(tx * DESCRIPTOR + 12, TX_DONE);
                let rx = net.next_rx;
                inject(&mut net, rx, RX_DONE | RX_EOP, 64, packet as u8);
                assert_eq!(net.receive().unwrap(), Some(frame));
            }
            {
                let mut m = state.borrow_mut();
                m.config.insert(0xe4, 0x100);
                m.flush_after_tx = n % 2 == 0;
                m.flush_after_rx = n % 2 != 0;
            }
            net.shutdown().unwrap();
            assert_eq!(state.borrow().config[&0xe4] & 0x100, 0);
            assert_eq!(state.borrow().mac[&0xf8], 1 << 30);
            drop(net);
            assert_eq!(released.load(Ordering::SeqCst), 1, "retained {device:04x}");
        }
    }
    #[test]
    fn each_new_family_cold_config_link_and_flushing_stop_fault_retains_actual_owner() {
        for family in i219::tests::families() {
            let device = i219::tests::sample_device(family);
            let (state, _, io, timer) = i219::tests::fixture();
            let mut memory = Memory::new();
            let controller = super::super::mtp::tests::start_any(device, io, timer).unwrap();
            let cold = state.borrow().accesses;
            {
                let mut m = state.borrow_mut();
                m.mac
                    .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
                m.phy.insert((2, 0, 1), PHY_LINK_READY);
            }
            let mut net = open(controller, &mut memory);
            let configured = state.borrow().accesses;
            state
                .borrow_mut()
                .mac
                .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 6));
            assert!(net.carrier());
            let linked = state.borrow().accesses;
            {
                let mut m = state.borrow_mut();
                m.config.insert(0xe4, 0x100);
                m.flush_after_rx = true;
            }
            net.shutdown().unwrap();
            let last = state.borrow().accesses;
            drop(net);
            for at in 0..last {
                let (state, released, io, timer) = i219::tests::fixture();
                let mut memory = Memory::new();
                if at < cold {
                    state.borrow_mut().fail_at = Some(at);
                    assert!(
                        i219::tests::start(device, io, timer).is_err(),
                        "lost cold{family:?}:{at}"
                    );
                } else {
                    let controller =
                        super::super::mtp::tests::start_any(device, io, timer).unwrap();
                    {
                        let mut m = state.borrow_mut();
                        m.mac
                            .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
                        m.phy.insert((2, 0, 1), PHY_LINK_READY);
                    }
                    if at < configured {
                        state.borrow_mut().fail_at = Some(at);
                        // SAFETY: the same isolated model's actual native RAM.
                        assert!(
                            unsafe { Ethernet::new(controller, &mut memory) }.is_err(),
                            "lost config{family:?}:{at}"
                        );
                    } else {
                        let mut net = open(controller, &mut memory);
                        state
                            .borrow_mut()
                            .mac
                            .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 6));
                        if at < linked {
                            state.borrow_mut().fail_at = Some(at);
                            assert!(!net.carrier(), "lost link{family:?}:{at}");
                        } else {
                            assert!(net.carrier());
                            let mut m = state.borrow_mut();
                            m.config.insert(0xe4, 0x100);
                            m.flush_after_rx = true;
                            m.fail_at = Some(at);
                            drop(m);
                            assert!(net.shutdown().is_err(), "lost stop{family:?}:{at}");
                        }
                        let count = state.borrow().accesses;
                        assert!(net.transmit(&[0; 60]).is_err());
                        assert!(!net.carrier());
                        drop(net);
                        assert_eq!(state.borrow().accesses, count);
                    }
                }
                assert_eq!(
                    released.load(Ordering::SeqCst),
                    0,
                    "released {family:?}:{at}"
                );
            }
        }
    }
    #[test]
    #[ignore = "set all four STELA_E1000E_PCH_I219_*_ORACLE paths"]
    fn source_nvm_outcomes_compose_through_every_cold_reset_packet_and_stop() {
        for family in i219::tests::families() {
            for ([marker, check, expected, _], _) in i219::tests::oracle_cases(family, 9) {
                let (state, released, io, timer) = i219::tests::fixture();
                {
                    let mut m = state.borrow_mut();
                    m.words[3] = (m.words[3] & !1) | marker as u16;
                    let sum = m.words[..63].iter().copied().fold(0u16, u16::wrapping_add);
                    m.words[63] = 0xbabau16.wrapping_sub(sum);
                    if check == 1 {
                        m.words[63] ^= 1;
                    }
                    if check == 2 {
                        m.words[63] = 0xffff;
                    }
                }
                let result = i219::tests::start(i219::tests::sample_device(family), io, timer);
                if expected != 0 {
                    let kind = match result {
                        Err(Error::Nvm(nvm::Error::Checksum(_))) => 1,
                        Err(Error::Nvm(nvm::Error::RepairRequired)) => 2,
                        _ => panic!(
                            "accepted invalid family image{family:?} marker{marker} check{check}"
                        ),
                    };
                    assert_eq!(kind, expected);
                    assert_eq!(released.load(Ordering::SeqCst), 0);
                    continue;
                }
                let controller = result.unwrap();
                if family == i219::Family::Tgp && marker == 0 {
                    assert!(
                        !state.borrow().operations.contains(&[6, 8, 0x7c]),
                        "TGP skip incorrectly read checksum word"
                    );
                }
                {
                    let mut m = state.borrow_mut();
                    m.mac
                        .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
                    m.phy.insert((2, 0, 1), PHY_LINK_READY);
                }
                let mut memory = Memory::new();
                let mut net = open(controller, &mut memory);
                let frame = [0x71; 60];
                net.transmit(&frame).unwrap();
                net.transmit.descriptors.write(12, TX_DONE);
                inject(&mut net, 0, RX_DONE | RX_EOP, 64, 0x71);
                assert_eq!(net.receive().unwrap(), Some(frame.to_vec()));
                net.shutdown().unwrap();
                drop(net);
                assert_eq!(released.load(Ordering::SeqCst), 1);
            }
        }
    }
    #[test]
    fn all_fourteen_mtp_ptp_ids_and_both_real_board_policies_complete_packets_and_live_stop() {
        use super::super::mtp;
        let devices: Vec<_> = (0..=u16::MAX)
            .filter(|id| mtp::Family::from_device(*id).is_some())
            .collect();
        assert_eq!(devices.len(), 14);
        for device in devices {
            for disable in [false, true] {
                let (state, released, io, timer) = spt::tests::fixture_spt();
                {
                    let mut m = state.borrow_mut();
                    m.kmrn.insert(7, 0xa5a7);
                    m.phy.insert((1, 770, 21), 0x1234);
                    m.mac.insert(0x18, 0x5a5a0008);
                }
                // SAFETY: one actual source-selected host/Function/reset model grant.
                let controller =
                    unsafe { Controller::new_mtp(device, io, timer, mtp::tests::host(disable)) }
                        .unwrap();
                let ptp = mtp::Family::from_device(device) == Some(mtp::Family::Ptp);
                assert_eq!(state.borrow().mac[&0x18] & 8, if ptp { 0 } else { 8 });
                {
                    let mut m = state.borrow_mut();
                    m.mac
                        .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
                    m.phy.insert((2, 0, 1), PHY_LINK_READY);
                    m.mac.insert(spt::IOSFPC, u32::MAX);
                }
                let mut memory = Memory::new();
                let mut net = open(controller, &mut memory);
                {
                    let m = state.borrow();
                    assert_eq!(m.kmrn[&7] & 2, if disable { 0 } else { 2 });
                    assert_eq!(m.phy[&(1, 770, 21)] & 0xfc0, 0xf00);
                    assert_eq!(m.mac[&0x5bc0] & 0xc00000, 0x800000);
                    assert_eq!(m.mac[&FFLT_DBG] & 0x1000, 0x1000);
                    assert_eq!(m.phy[&(1, 772, 28)] & lpt::PLL_CLOCK_GATE_MASK, 0x1d5);
                    assert_eq!(m.mac[&spt::IOSFPC], u32::MAX);
                }
                for n in 0..65 {
                    let frame = vec![n as u8; 60];
                    let tx = net.next_tx;
                    net.transmit(&frame).unwrap();
                    assert_eq!(&net.transmit.buffer(tx)[..60], frame.as_slice());
                    net.transmit
                        .descriptors
                        .write(tx * DESCRIPTOR + 12, TX_DONE);
                    let rx = net.next_rx;
                    inject(&mut net, rx, RX_DONE | RX_EOP, 64, n as u8);
                    assert_eq!(net.receive().unwrap(), Some(frame));
                }
                {
                    let mut m = state.borrow_mut();
                    m.config.insert(0xe4, 0x100);
                    m.flush_after_tx = disable;
                    m.flush_after_rx = !disable;
                }
                net.shutdown().unwrap();
                assert_eq!(state.borrow().config[&0xe4] & 0x100, 0);
                assert_eq!(state.borrow().mac[&0xf8], 1 << 30);
                drop(net);
                assert_eq!(released.load(Ordering::SeqCst), 1);
            }
        }
    }
    #[test]
    #[ignore = "set MTP/PTP source oracle paths"]
    fn mandatory_mtp_nvm_source_outcomes_and_clock_policy_compose_through_packet_stop() {
        use super::super::mtp;
        for (family, device) in [(mtp::Family::Mtp, 0x550a), (mtp::Family::Ptp, 0x57b3)] {
            for ([marker, check, expected, _], _) in mtp::tests::cases(family, 9) {
                for disable in [false, true] {
                    let (state, released, io, timer) = spt::tests::fixture_spt();
                    {
                        let mut m = state.borrow_mut();
                        m.words[3] = (m.words[3] & !1) | marker as u16;
                        let sum = m.words[..63].iter().copied().fold(0u16, u16::wrapping_add);
                        m.words[63] = 0xbabau16.wrapping_sub(sum);
                        if check == 1 {
                            m.words[63] ^= 1;
                        }
                        if check == 2 {
                            m.words[63] = 0xffff;
                        }
                    }
                    // SAFETY: actual same-host modeled identity and Function grant.
                    let result = unsafe {
                        Controller::new_mtp(device, io, timer, mtp::tests::host(disable))
                    };
                    if expected != 0 {
                        assert_eq!(expected, 1);
                        assert!(matches!(result, Err(Error::Nvm(nvm::Error::Checksum(_)))));
                        assert_eq!(released.load(Ordering::SeqCst), 0);
                        continue;
                    }
                    let controller = result.unwrap();
                    {
                        let mut m = state.borrow_mut();
                        m.mac
                            .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
                        m.phy.insert((2, 0, 1), PHY_LINK_READY);
                    }
                    let mut memory = Memory::new();
                    let mut net = open(controller, &mut memory);
                    net.transmit(&[0x71; 60]).unwrap();
                    net.transmit.descriptors.write(12, TX_DONE);
                    inject(&mut net, 0, RX_DONE | RX_EOP, 64, 0x71);
                    assert_eq!(net.receive().unwrap(), Some(vec![0x71; 60]));
                    net.shutdown().unwrap();
                    drop(net);
                    assert_eq!(released.load(Ordering::SeqCst), 1);
                }
            }
            for ([initial, _, _, _], expected) in mtp::tests::cases(family, 8) {
                let (state, _, controller) = setup_integrated(device, 0);
                let mut memory = Memory::new();
                let mut net = open(controller, &mut memory);
                state.borrow_mut().mac.insert(FFLT_DBG, initial);
                state.borrow_mut().operations.clear();
                net.i219_clock_policy().unwrap();
                assert_eq!(state.borrow().operations, expected);
                net.shutdown().unwrap();
            }
        }
    }
    #[test]
    fn every_mtp_ptp_cold_k1_queue_link_and_flushing_stop_access_fault_retains_owner() {
        use super::super::mtp;
        for device in [0x550a, 0x57b3] {
            for disable in [false, true] {
                let (state, _, io, timer) = spt::tests::fixture_spt();
                // SAFETY: one actual same-host model and source-selected family.
                let controller =
                    unsafe { Controller::new_mtp(device, io, timer, mtp::tests::host(disable)) }
                        .unwrap();
                let cold = state.borrow().accesses;
                {
                    let mut m = state.borrow_mut();
                    m.mac
                        .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
                    m.phy.insert((2, 0, 1), PHY_LINK_READY);
                }
                let mut memory = Memory::new();
                let mut net = open(controller, &mut memory);
                let configured = state.borrow().accesses;
                state
                    .borrow_mut()
                    .mac
                    .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 6));
                assert!(net.carrier());
                let linked = state.borrow().accesses;
                {
                    let mut m = state.borrow_mut();
                    m.config.insert(0xe4, 0x100);
                    m.flush_after_rx = true;
                }
                net.shutdown().unwrap();
                let last = state.borrow().accesses;
                drop(net);
                for at in 0..last {
                    let (state, released, io, timer) = spt::tests::fixture_spt();
                    let mut memory = Memory::new();
                    if at < cold {
                        state.borrow_mut().fail_at = Some(at);
                        // SAFETY: fresh same-host model; failure never retried as a new owner.
                        assert!(
                            unsafe {
                                Controller::new_mtp(device, io, timer, mtp::tests::host(disable))
                            }
                            .is_err(),
                            "cold{device:x}/{disable}/{at}"
                        );
                    } else {
                        // SAFETY: fresh actual same-host source-selected model.
                        let controller = unsafe {
                            Controller::new_mtp(device, io, timer, mtp::tests::host(disable))
                        }
                        .unwrap();
                        {
                            let mut m = state.borrow_mut();
                            m.mac
                                .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 7));
                            m.phy.insert((2, 0, 1), PHY_LINK_READY);
                        }
                        if at < configured {
                            state.borrow_mut().fail_at = Some(at);
                            // SAFETY: actual live model requester and owned coherent model RAM.
                            assert!(
                                unsafe { Ethernet::new(controller, &mut memory) }.is_err(),
                                "queue{device:x}/{disable}/{at}"
                            );
                        } else {
                            let mut net = open(controller, &mut memory);
                            state
                                .borrow_mut()
                                .mac
                                .insert(super::super::STATUS, LINK_UP | FULL_DUPLEX | (1 << 6));
                            if at < linked {
                                state.borrow_mut().fail_at = Some(at);
                                assert!(!net.carrier(), "link{device:x}/{disable}/{at}");
                            } else {
                                assert!(net.carrier());
                                {
                                    let mut m = state.borrow_mut();
                                    m.config.insert(0xe4, 0x100);
                                    m.flush_after_rx = true;
                                    m.fail_at = Some(at);
                                }
                                assert!(net.shutdown().is_err(), "stop{device:x}/{disable}/{at}");
                            }
                            let count = state.borrow().accesses;
                            assert!(net.transmit(&[0; 60]).is_err());
                            assert!(!net.carrier());
                            drop(net);
                            assert_eq!(state.borrow().accesses, count);
                        }
                    }
                    assert_eq!(
                        released.load(Ordering::SeqCst),
                        0,
                        "released{device:x}/{disable}/{at}"
                    );
                }
            }
        }
    }
    #[test]
    fn mtp_flush_success_does_not_replace_vendor_drain_and_unresolved_flush_never_releases() {
        for device in [0x550a, 0x57b3] {
            for unresolved in [false, true] {
                let (state, released, controller) = setup_integrated(device, 0);
                let mut memory = Memory::new();
                let mut net = open(controller, &mut memory);
                {
                    let mut m = state.borrow_mut();
                    m.config.insert(0xe4, 0x100);
                    m.flush_after_tx = !unresolved;
                    m.master_busy = 2000;
                }
                assert_eq!(
                    net.shutdown(),
                    Err(if unresolved {
                        Error::DescriptorFlushRequired
                    } else {
                        Error::MasterTimeout
                    })
                );
                if !unresolved {
                    assert_eq!(state.borrow().config[&0xe4] & 0x100, 0);
                }
                let accesses = state.borrow().accesses;
                assert!(net.transmit(&[0; 60]).is_err());
                assert!(!net.carrier());
                drop(net);
                assert_eq!(state.borrow().accesses, accesses);
                assert_eq!(released.load(Ordering::SeqCst), 0);
            }
        }
    }
}
