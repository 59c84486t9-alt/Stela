// SPDX-License-Identifier: BSD-3-Clause AND GPL-2.0-only
// Copyright (c) 2001-2020, Intel Corporation
// Linux e1000e adaptations: Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of Intel Corporation nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! Intel 82574L (`8086:10d3`), one polled Ethernet queue with legacy
//! descriptors, no checksum/segmentation/VLAN offloads and no interrupts.
//!
//! The MAC/MDIO reset and hardware errata sequence is adapted from Intel's
//! BSD-licensed shared code, FreeBSD `sys/dev/e1000/e1000_82571.c`,
//! `e1000_phy.c`, `e1000_regs.h` and `e1000_defines.h`:
//! <https://github.com/freebsd/freebsd-src/tree/c6d7a2478c9eeb38ed1284e4ee1ff64c75ca8b09/sys/dev/e1000>.
//! Subsequent Linux `e1000e` adaptations follow commit
//! `a804c5742bff224d4cb4d25dd383554d598be32b`, `82571.c`, `phy.c`,
//! `netdev.c`, `defines.h` and `regs.h` under
//! <https://github.com/torvalds/linux/tree/a804c5742bff224d4cb4d25dd383554d598be32b/drivers/net/ethernet/intel/e1000e>.
//! These portions are GPL-2.0-only; see `LICENSES/GPL-2.0-only.txt`.
//! The descriptor datapath and Stela integration are independent Rust code.
//! This is deliberately not a match for the I217/I218/I219 integrated PHYs.
//!
//! DMA allocations live until reboot, including after a transmit timeout;
//! a descriptor is never reused until the device writes its done bit.
use super::{Link, LinkError, MAX_FRAME, MIN_FRAME, Mac};
use crate::{
    Clock, Handoff,
    block::BlockError,
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        mmio::Mmio,
        pci::{self, ConfigSpace, Function},
    },
    registers,
};
use alloc::{format, string::String, vec::Vec};
use core::sync::atomic::{Ordering, fence};

const VENDOR: u16 = 0x8086;
const DEVICE: u16 = 0x10d3;
const REGISTER_BYTES: u64 = 0x1_0000;
const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const EECD: usize = 0x0010;
const CTRL_EXT: usize = 0x0018;
const MDIC: usize = 0x0020;
const ICR: usize = 0x00c0;
const IMC: usize = 0x00d8;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const EXTCNF_CTRL: usize = 0x0f00;
const POEMB: usize = 0x0f10;
const RDBAL: usize = 0x2800;
const RDBAH: usize = 0x2804;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;
const RXDCTL: usize = 0x2828;
const TDBAL: usize = 0x3800;
const TDBAH: usize = 0x3804;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;
const TXDCTL: usize = 0x3828;
const TARC: usize = 0x3840;
const RXCSUM: usize = 0x5000;
const RFCTL: usize = 0x5008;
const MTA: usize = 0x5200;
const RAL: usize = 0x5400;
const RAH: usize = 0x5404;
const GCR: usize = 0x5b00;
const GCR2: usize = 0x5b64;

const CTRL_MASTER_DISABLE: u32 = 1 << 2;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_FRCSPD: u32 = 1 << 11;
const CTRL_FRCDPX: u32 = 1 << 12;
const CTRL_RST: u32 = 1 << 26;
const CTRL_RFCE: u32 = 1 << 27;
const CTRL_TFCE: u32 = 1 << 28;
const CTRL_RESERVED_29: u32 = 1 << 29;
const CTRL_VME: u32 = 1 << 30;
const STATUS_LU: u32 = 1 << 1;
const STATUS_MASTER: u32 = 1 << 19;
const EECD_AUTO_RD: u32 = 1 << 9;
const MDIO_OWN: u32 = 1 << 5;
const CTRL_EXT_DRIVER: u32 = 1 << 28;
const CTRL_EXT_LINK_MASK: u32 = 3 << 22;
const CTRL_EXT_LINK_82574: u32 = 1 << 22;
const POEMB_LPLU: u32 = (1 << 1) | (1 << 2);
const RCTL_EN: u32 = 1 << 1;
const RCTL_MPE: u32 = 1 << 4;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_COLLISIONS: u32 = (15 << 4) | (63 << 12);
const TCTL_RTLC: u32 = 1 << 24;
const TARC_ENABLE: u32 = 1 << 10;
const TARC_REQUIRED: u32 = 1 << 26;
const TARC_RESERVED: u32 = 0xf << 27;
const TXDCTL_POLICY: u32 = (1 << 24) | (1 << 22) | (1 << 16) | (1 << 8) | 31;
const RFCTL_EXTEN: u32 = 1 << 15;
const RAH_VALID: u32 = 1 << 31;
const GCR_REQUIRED: u32 = 1 << 22;
const GCR_L1_WITHOUT_L0S: u32 = 1 << 27;
const GCR2_ERRATA: u32 = 1;

const MDIC_WRITE: u32 = 1 << 26;
const MDIC_READ: u32 = 1 << 27;
const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
const MDIC_PHY: u32 = 1 << 21;
const MDIC_REGISTER: u32 = 0x1f << 16;
const PHY_CONTROL: u16 = 0;
const PHY_ID1: u16 = 2;
const PHY_ID2: u16 = 3;
const PHY_ADVERTISE: u16 = 4;
const PHY_GIGABIT: u16 = 9;
const PHY_SPECIFIC: u16 = 16;
const PHY_PAGE: u16 = 22;
const PHY_BIAS1: u16 = 29;
const PHY_BIAS2: u16 = 30;
const PHY_RESET: u16 = 1 << 15;
const PHY_LOOPBACK: u16 = 1 << 14;
const PHY_AUTONEG: u16 = 1 << 12;
const PHY_POWERDOWN: u16 = 1 << 11;
const PHY_ISOLATE: u16 = 1 << 10;
const PHY_RESTART: u16 = 1 << 9;
const PHY_DOWNSHIFT: u16 = 1 << 11;
const PHY_AUTO_MDIX: u16 = 3 << 5;
const PHY_POLARITY_DISABLE: u16 = 1 << 1;
const PHY_BM_REV2: u32 = 0x0141_0cb1;

const DESCRIPTORS: usize = 32;
const DESCRIPTOR: usize = 16;
const BUFFER: usize = 2048;
const RX_DONE: u8 = 1;
const RX_EOP: u8 = 1 << 1;
// Checksum errors are irrelevant because checksum offload is disabled.
const RX_FRAME_ERRORS: u8 = 0x97;
const TX_DONE: u8 = 1;
const TX_EOP: u32 = 1 << 24;
const TX_IFCS: u32 = 1 << 25;
const TX_REPORT: u32 = 1 << 27;
const MASTER_WAIT_US: u64 = 160_000;
const RESET_WAIT_US: u64 = 20_000;
const OWNERSHIP_WAIT_US: u64 = 200_000;
const MDIC_WAIT_US: u64 = 20_000;
const PHY_WAIT_US: u64 = 500_000;
const TRANSMIT_WAIT_US: u64 = 100_000;

pub fn matches<C: ConfigSpace>(function: &Function<C>) -> bool {
    function.vendor == VENDOR && function.device == DEVICE && function.class == [2, 0, 0]
}

/// The reset and MDIO state machines use the same register interface in
/// production and in fault-injection tests.
trait Registers {
    fn read(&self, offset: usize) -> u32;
    fn write(&self, offset: usize, value: u32);
}

impl Registers for Mmio {
    fn read(&self, offset: usize) -> u32 {
        self.read32(offset)
    }

    fn write(&self, offset: usize, value: u32) {
        self.write32(offset, value);
    }
}

trait Timer {
    fn delay(&self, microseconds: u64);
    fn wait(&self, microseconds: u64, ready: impl FnMut() -> bool) -> bool;
}

impl Timer for Clock {
    fn delay(&self, microseconds: u64) {
        self.delay(microseconds);
    }

    fn wait(&self, microseconds: u64, ready: impl FnMut() -> bool) -> bool {
        self.wait(microseconds, ready)
    }
}

fn ownership(device: &impl Registers, clock: &impl Timer) -> Result<(), BlockError> {
    if clock.wait(OWNERSHIP_WAIT_US, || {
        device.write(EXTCNF_CTRL, device.read(EXTCNF_CTRL) | MDIO_OWN);
        device.read(EXTCNF_CTRL) & MDIO_OWN != 0
    }) {
        Ok(())
    } else {
        release(device);
        Err(BlockError::Timeout)
    }
}

fn release(device: &impl Registers) {
    device.write(EXTCNF_CTRL, device.read(EXTCNF_CTRL) & !MDIO_OWN);
}

fn reset(device: &impl Registers, clock: &impl Timer) -> Result<(), BlockError> {
    device.write(IMC, u32::MAX);
    device.write(RCTL, 0);
    device.write(TCTL, device.read(TCTL) & !TCTL_EN);
    device.write(CTRL, device.read(CTRL) | CTRL_MASTER_DISABLE);
    if !clock.wait(MASTER_WAIT_US, || device.read(STATUS) & STATUS_MASTER == 0) {
        return Err(BlockError::Timeout);
    }
    device.read(STATUS); // flush posted PCIe writes before the settle time
    clock.delay(10_000);
    ownership(device, clock)?;
    device.write(CTRL, device.read(CTRL) | CTRL_RST);
    let reset_done = clock.wait(RESET_WAIT_US, || device.read(CTRL) & CTRL_RST == 0);
    release(device);
    if !reset_done || !clock.wait(RESET_WAIT_US, || device.read(EECD) & EECD_AUTO_RD != 0) {
        return Err(BlockError::Timeout);
    }
    // NVM auto-read starts the PHY configuration; do not access MDIO yet.
    clock.delay(25_000);
    device.write(IMC, u32::MAX);
    device.read(ICR);
    Ok(())
}

fn mdic(
    device: &impl Registers,
    clock: &impl Timer,
    register: u16,
    data: Option<u16>,
) -> Result<u16, BlockError> {
    let command = MDIC_PHY
        | (u32::from(register) << 16)
        | data.map_or(MDIC_READ, |data| MDIC_WRITE | u32::from(data));
    device.write(MDIC, command);
    if !clock.wait(MDIC_WAIT_US, || device.read(MDIC) & MDIC_READY != 0) {
        return Err(BlockError::Timeout);
    }
    let result = device.read(MDIC);
    if result & MDIC_ERROR != 0 || result & MDIC_REGISTER != command & MDIC_REGISTER {
        return Err(BlockError::Device { status: result });
    }
    Ok(result as u16)
}

fn reset_phy(device: &impl Registers, clock: &impl Timer) -> Result<(), BlockError> {
    let control = mdic(device, clock, PHY_CONTROL, None)?;
    mdic(device, clock, PHY_CONTROL, Some(control | PHY_RESET))?;
    let mut last = Ok(0);
    if !clock.wait(PHY_WAIT_US, || {
        last = mdic(device, clock, PHY_CONTROL, None);
        match &last {
            Ok(value) => value & PHY_RESET == 0,
            Err(_) => true,
        }
    }) {
        return Err(BlockError::Timeout);
    }
    last.map(|_| ())
}

fn configure_phy(device: &impl Registers, clock: &impl Timer) -> Result<(), BlockError> {
    ownership(device, clock)?;
    let result = (|| {
        mdic(device, clock, PHY_PAGE, Some(0))?;
        let id = u32::from(mdic(device, clock, PHY_ID1, None)?) << 16
            | u32::from(mdic(device, clock, PHY_ID2, None)?);
        if id != PHY_BM_REV2 {
            return Err(BlockError::Unsupported("82574L with an unknown PHY"));
        }
        let mut specific = mdic(device, clock, PHY_SPECIFIC, None)?;
        specific = (specific | PHY_AUTO_MDIX) & !PHY_POLARITY_DISABLE;
        if id == PHY_BM_REV2 {
            mdic(device, clock, PHY_SPECIFIC, Some(specific & !PHY_DOWNSHIFT))?;
            reset_phy(device, clock)?;
        }
        mdic(device, clock, PHY_SPECIFIC, Some(specific | PHY_DOWNSHIFT))?;
        if id == PHY_BM_REV2 {
            mdic(device, clock, PHY_BIAS1, Some(3))?;
            mdic(device, clock, PHY_BIAS2, Some(0))?;
        }
        reset_phy(device, clock)?;
        // Advertise 10/100 half/full and 1000 full, with no pause frames.
        mdic(device, clock, PHY_ADVERTISE, Some(0x01e1))?;
        let gigabit = mdic(device, clock, PHY_GIGABIT, None)?;
        mdic(
            device,
            clock,
            PHY_GIGABIT,
            Some((gigabit & !0x1f00) | 0x0200),
        )?;
        let control = mdic(device, clock, PHY_CONTROL, None)?;
        mdic(
            device,
            clock,
            PHY_CONTROL,
            Some(
                (control & !(PHY_RESET | PHY_LOOPBACK | PHY_POWERDOWN | PHY_ISOLATE))
                    | PHY_AUTONEG
                    | PHY_RESTART,
            ),
        )?;
        Ok(())
    })();
    release(device);
    result
}

fn station(low: u32, high: u32) -> Option<Mac> {
    let [a, b, c, d] = low.to_le_bytes();
    let [e, f, _, _] = high.to_le_bytes();
    let mac = Mac([a, b, c, d, e, f]);
    (high & RAH_VALID != 0 && mac.0 != [0; 6] && !mac.is_multicast()).then_some(mac)
}

struct Ring {
    descriptors: DmaBuffer,
    buffers: DmaBuffer,
}

impl Ring {
    fn new(dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        Ok(Self {
            descriptors: dma.allocate(DESCRIPTORS * DESCRIPTOR, 4096)?,
            buffers: dma.allocate(DESCRIPTORS * BUFFER, 4096)?,
        })
    }

    fn address(&self, index: usize) -> u64 {
        self.buffers.physical() + (index * BUFFER) as u64
    }

    fn buffer(&mut self, index: usize) -> &mut [u8] {
        &mut self.buffers.bytes_mut()[index * BUFFER..(index + 1) * BUFFER]
    }

    fn program(&self, device: &Mmio, low: usize, high: usize, length: usize) {
        device.write32(low, self.descriptors.physical() as u32);
        device.write32(high, (self.descriptors.physical() >> 32) as u32);
        device.write32(length, (DESCRIPTORS * DESCRIPTOR) as u32);
    }
}

/// The 82574L owns these buffers until reboot. Polling never waits for a
/// cable to be connected; [`Link::carrier`] reports autonegotiation's result.
pub struct E1000e {
    device: Mmio,
    receive: Ring,
    transmit: Ring,
    next_receive: usize,
    next_transmit: usize,
    clean_transmit: usize,
    dropping_receive: bool,
    mac: Mac,
    clock: Clock,
    pub location: String,
}

impl E1000e {
    /// Take an 82574L after ExitBootServices, including the required ASPM
    /// workaround on the endpoint and its immediate upstream PCIe bridge.
    ///
    /// # Safety
    ///
    /// The caller must own the controller and PCI configuration access in
    /// its segment exclusively. `handoff` must describe the actual machine's
    /// mapped ECAM/MMIO and DMA ranges. No firmware or other driver may
    /// access these resources during initialization.
    pub unsafe fn new(
        function: &mut Function,
        handoff: &Handoff,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        if !matches(function) {
            return Err(BlockError::Unsupported("not an Intel 82574L"));
        }
        // SAFETY: the constructor's caller owns segment configuration and
        // the mapped ECAM handoff. Do this before enabling device decoding.
        unsafe { pci::disable_aspm_link(function, handoff)? };
        let device = registers(handoff, function.bars()[0], 0, REGISTER_BYTES)?;
        function.enable();
        reset(&device, &handoff.clock)?;
        let mac = station(device.read32(RAL), device.read32(RAH)).ok_or(
            BlockError::Unsupported("82574L without a valid NVM MAC address"),
        )?;
        configure_phy(&device, &handoff.clock)?;
        let mut net = Self {
            device,
            receive: Ring::new(dma)?,
            transmit: Ring::new(dma)?,
            next_receive: 0,
            next_transmit: 0,
            clean_transmit: 0,
            dropping_receive: false,
            mac,
            clock: handoff.clock,
            location: format!("{} Intel 82574L", function.address),
        };
        net.start();
        Ok(net)
    }

    fn start(&mut self) {
        let device = &self.device;
        let control = device.read32(CTRL);
        device.write32(
            CTRL,
            (control | CTRL_SLU)
                & !(CTRL_MASTER_DISABLE
                    | CTRL_FRCSPD
                    | CTRL_FRCDPX
                    | CTRL_RFCE
                    | CTRL_TFCE
                    | CTRL_RESERVED_29
                    | CTRL_VME),
        );
        device.write32(
            CTRL_EXT,
            (device.read32(CTRL_EXT) & !CTRL_EXT_LINK_MASK) | CTRL_EXT_LINK_82574 | CTRL_EXT_DRIVER,
        );
        device.write32(POEMB, device.read32(POEMB) & !POEMB_LPLU);
        // Linux's 82574 setup enables L1 activation without L0s receive.
        device.write32(GCR, device.read32(GCR) | GCR_REQUIRED | GCR_L1_WITHOUT_L0S);
        device.write32(GCR2, device.read32(GCR2) | GCR2_ERRATA);
        // Other receive addresses and multicast hashes must not retain UNDI state.
        for entry in 1..16 {
            device.write32(RAL + entry * 8, 0);
            device.write32(RAH + entry * 8, 0);
        }
        for entry in 0..128 {
            device.write32(MTA + entry * 4, 0);
        }
        device.write32(RFCTL, device.read32(RFCTL) & !RFCTL_EXTEN);
        device.write32(RXCSUM, 0);
        self.receive.program(device, RDBAL, RDBAH, RDLEN);
        self.transmit.program(device, TDBAL, TDBAH, TDLEN);
        device.write32(RDH, 0);
        device.write32(RDT, 0);
        device.write32(TDH, 0);
        device.write32(TDT, 0);
        device.write32(RXDCTL, 1 << 16 | 4 << 8 | 8);
        device.write32(TXDCTL, TXDCTL_POLICY);
        // 82574 erratum: both queues must use the same write-back policy.
        device.write32(TXDCTL + 0x100, TXDCTL_POLICY);
        device.write32(
            TARC,
            (device.read32(TARC) & !TARC_RESERVED) | TARC_REQUIRED | TARC_ENABLE,
        );
        // Copper inter-packet gaps: IPGT=8, IPGR1=8, IPGR2=6.
        device.write32(TIPG, 8 | 8 << 10 | 6 << 20);
        for index in 0..DESCRIPTORS {
            self.offer_receive(index);
        }
        fence(Ordering::SeqCst);
        self.device.write32(RDT, (DESCRIPTORS - 1) as u32);
        self.device
            .write32(RCTL, RCTL_EN | RCTL_MPE | RCTL_BAM | RCTL_SECRC);
        self.device
            .write32(TCTL, TCTL_EN | TCTL_PSP | TCTL_COLLISIONS | TCTL_RTLC);
        self.device.read32(STATUS);
    }

    fn offer_receive(&mut self, index: usize) {
        let base = index * DESCRIPTOR;
        let address = self.receive.address(index);
        self.receive.descriptors.write(base, address);
        self.receive.descriptors.write(base + 8, 0u64);
    }

    fn reclaim(&mut self) -> bool {
        while self.clean_transmit != self.next_transmit {
            let status: u8 = self
                .transmit
                .descriptors
                .read(self.clean_transmit * DESCRIPTOR + 12);
            if status & TX_DONE == 0 {
                break;
            }
            fence(Ordering::Acquire);
            self.clean_transmit = (self.clean_transmit + 1) % DESCRIPTORS;
        }
        // The hardware uses head==tail for empty: retain one unused descriptor.
        (self.next_transmit + 1) % DESCRIPTORS != self.clean_transmit
    }
}

impl Link for E1000e {
    fn mac(&self) -> Mac {
        self.mac
    }

    fn carrier(&mut self) -> bool {
        self.device.read32(STATUS) & STATUS_LU != 0
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        if !(14..=MAX_FRAME).contains(&frame.len()) {
            return Err(LinkError::Invalid("frame length is outside 14..=1514"));
        }
        if !self.reclaim() {
            let clock = self.clock;
            if !clock.wait(TRANSMIT_WAIT_US, || self.reclaim()) {
                return Err(LinkError::Adapter(format!(
                    "{} transmit ring stalled",
                    self.location
                )));
            }
        }
        let index = self.next_transmit;
        let length = frame.len().max(MIN_FRAME);
        let buffer = self.transmit.buffer(index);
        buffer[..length].fill(0);
        buffer[..frame.len()].copy_from_slice(frame);
        let base = index * DESCRIPTOR;
        let address = self.transmit.address(index);
        self.transmit.descriptors.write(base, address);
        self.transmit
            .descriptors
            .write(base + 8, length as u32 | TX_EOP | TX_IFCS | TX_REPORT);
        self.transmit.descriptors.write(base + 12, 0u32);
        self.next_transmit = (index + 1) % DESCRIPTORS;
        fence(Ordering::SeqCst);
        self.device.write32(TDT, self.next_transmit as u32);
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        // Bound processing even if a device continually supplies bad frames.
        for _ in 0..DESCRIPTORS {
            let index = self.next_receive;
            let base = index * DESCRIPTOR;
            let status: u8 = self.receive.descriptors.read(base + 12);
            if status & RX_DONE == 0 {
                return Ok(None);
            }
            fence(Ordering::Acquire);
            let length = usize::from(self.receive.descriptors.read::<u16>(base + 8));
            let errors: u8 = self.receive.descriptors.read(base + 13);
            let eop = status & RX_EOP != 0;
            let good = !self.dropping_receive
                && eop
                && errors & RX_FRAME_ERRORS == 0
                && (14..=MAX_FRAME).contains(&length);
            let frame = good.then(|| self.receive.buffer(index)[..length].to_vec());
            self.dropping_receive = !eop;
            self.offer_receive(index);
            self.next_receive = (index + 1) % DESCRIPTORS;
            fence(Ordering::SeqCst);
            self.device.write32(RDT, index as u32);
            if frame.is_some() {
                return Ok(frame);
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{
        dma::RegionAllocator,
        pci::{Address, ConfigSpace},
    };
    use alloc::collections::BTreeMap;
    use core::cell::RefCell;

    #[derive(Default)]
    struct Model {
        registers: RefCell<BTreeMap<usize, u32>>,
        writes: RefCell<Vec<(usize, u32)>>,
        phy: RefCell<[u16; 32]>,
        ownership_blocked: bool,
        master_stuck: bool,
        reset_stuck: bool,
        mdic_timeout: bool,
        mdic_error: bool,
        wrong_register: bool,
    }

    impl Model {
        fn ready() -> Self {
            let model = Self::default();
            model.registers.borrow_mut().insert(EECD, EECD_AUTO_RD);
            model.phy.borrow_mut()[usize::from(PHY_ID1)] = (PHY_BM_REV2 >> 16) as u16;
            model.phy.borrow_mut()[usize::from(PHY_ID2)] = PHY_BM_REV2 as u16;
            model
        }
    }

    impl Registers for Model {
        fn read(&self, offset: usize) -> u32 {
            self.registers.borrow().get(&offset).copied().unwrap_or(0)
        }

        fn write(&self, offset: usize, mut value: u32) {
            self.writes.borrow_mut().push((offset, value));
            if offset == EXTCNF_CTRL && self.ownership_blocked {
                value &= !MDIO_OWN;
            }
            if offset == CTRL {
                if value & CTRL_RST != 0 && !self.reset_stuck {
                    value &= !CTRL_RST;
                }
                if value & CTRL_MASTER_DISABLE != 0 && !self.master_stuck {
                    self.registers.borrow_mut().insert(STATUS, 0);
                }
            }
            if offset == MDIC && !self.mdic_timeout {
                let register = ((value & MDIC_REGISTER) >> 16) as usize;
                if self.mdic_error {
                    value |= MDIC_ERROR;
                } else if value & MDIC_READ != 0 {
                    value |= u32::from(self.phy.borrow()[register]);
                } else {
                    let data = value as u16;
                    self.phy.borrow_mut()[register] = if register == usize::from(PHY_CONTROL) {
                        data & !(PHY_RESET | PHY_RESTART)
                    } else {
                        data
                    };
                }
                if self.wrong_register {
                    value ^= 1 << 16;
                }
                value |= MDIC_READY;
            }
            self.registers.borrow_mut().insert(offset, value);
        }
    }

    #[derive(Default)]
    struct ModelTimer {
        delays: RefCell<Vec<u64>>,
    }

    impl Timer for ModelTimer {
        fn delay(&self, microseconds: u64) {
            self.delays.borrow_mut().push(microseconds);
        }

        fn wait(&self, _: u64, mut ready: impl FnMut() -> bool) -> bool {
            (0..4).any(|_| ready())
        }
    }

    #[test]
    fn reset_drains_dma_reloads_nvm_and_releases_mdio() {
        let model = Model::ready();
        model.registers.borrow_mut().insert(STATUS, STATUS_MASTER);
        model.registers.borrow_mut().insert(TCTL, TCTL_EN);
        let timer = ModelTimer::default();
        assert_eq!(reset(&model, &timer), Ok(()));
        assert_eq!(*timer.delays.borrow(), [10_000, 25_000]);
        assert_eq!(model.read(EXTCNF_CTRL) & MDIO_OWN, 0);
        assert_eq!(model.read(RCTL), 0);
        assert_eq!(model.read(TCTL) & TCTL_EN, 0);
        let writes = model.writes.borrow();
        let own = writes
            .iter()
            .position(|&(at, value)| at == EXTCNF_CTRL && value & MDIO_OWN != 0)
            .unwrap();
        let rst = writes
            .iter()
            .position(|&(at, value)| at == CTRL && value & CTRL_RST != 0)
            .unwrap();
        assert!(own < rst);
    }

    #[test]
    fn a_bus_master_that_will_not_drain_is_not_reset() {
        let model = Model {
            master_stuck: true,
            ..Model::ready()
        };
        model.registers.borrow_mut().insert(STATUS, STATUS_MASTER);
        assert_eq!(
            reset(&model, &ModelTimer::default()),
            Err(BlockError::Timeout)
        );
        assert!(
            !model
                .writes
                .borrow()
                .iter()
                .any(|&(at, value)| at == CTRL && value & CTRL_RST != 0)
        );
    }

    #[test]
    fn ownership_and_nvm_failures_do_not_look_successful() {
        let ownership = Model {
            ownership_blocked: true,
            ..Model::ready()
        };
        assert_eq!(
            reset(&ownership, &ModelTimer::default()),
            Err(BlockError::Timeout)
        );
        assert!(
            !ownership
                .writes
                .borrow()
                .iter()
                .any(|&(at, value)| at == CTRL && value & CTRL_RST != 0)
        );
        let nvm = Model::default();
        assert_eq!(
            reset(&nvm, &ModelTimer::default()),
            Err(BlockError::Timeout)
        );
        assert_eq!(nvm.read(EXTCNF_CTRL) & MDIO_OWN, 0);
        let stuck = Model {
            reset_stuck: true,
            ..Model::ready()
        };
        assert_eq!(
            reset(&stuck, &ModelTimer::default()),
            Err(BlockError::Timeout)
        );
        assert_eq!(stuck.read(EXTCNF_CTRL) & MDIO_OWN, 0);
    }

    #[test]
    fn phy_setup_programs_autonegotiation_and_releases_the_firmware_lock() {
        let model = Model::ready();
        model.phy.borrow_mut()[usize::from(PHY_CONTROL)] =
            PHY_POWERDOWN | PHY_LOOPBACK | PHY_ISOLATE;
        assert_eq!(configure_phy(&model, &ModelTimer::default()), Ok(()));
        assert_eq!(model.read(EXTCNF_CTRL) & MDIO_OWN, 0);
        let phy = model.phy.borrow();
        assert_eq!(phy[usize::from(PHY_ADVERTISE)], 0x01e1);
        assert_eq!(phy[usize::from(PHY_GIGABIT)], 0x0200);
        assert_eq!(phy[usize::from(PHY_CONTROL)], PHY_AUTONEG);
        assert_eq!(
            phy[usize::from(PHY_SPECIFIC)] & (PHY_AUTO_MDIX | PHY_DOWNSHIFT),
            PHY_AUTO_MDIX | PHY_DOWNSHIFT
        );
        assert_eq!(phy[usize::from(PHY_BIAS1)], 3);
    }

    #[test]
    fn mdio_timeout_error_wrong_response_and_unknown_phy_are_explicit() {
        for model in [
            Model {
                mdic_timeout: true,
                ..Model::ready()
            },
            Model {
                mdic_error: true,
                ..Model::ready()
            },
            Model {
                wrong_register: true,
                ..Model::ready()
            },
            Model::default(),
        ] {
            assert!(configure_phy(&model, &ModelTimer::default()).is_err());
            assert_eq!(model.read(EXTCNF_CTRL) & MDIO_OWN, 0);
        }
    }

    struct Fixture {
        net: E1000e,
        registers: Vec<u32>,
        _memory: Vec<u64>,
    }

    impl Fixture {
        fn new() -> Self {
            let mut registers = vec![0u32; REGISTER_BYTES as usize / 4];
            let mut memory = vec![u64::MAX; 40_000];
            let start = memory.as_mut_ptr() as u64;
            // SAFETY: the fixture owns the memory for the driver's whole lifetime.
            let mut allocator = unsafe { RegionAllocator::new(start..start + 320_000) };
            // SAFETY: this aligned backing covers every register used by the driver.
            let device = unsafe { Mmio::new(registers.as_mut_ptr() as u64) };
            let mut net = E1000e {
                device,
                receive: Ring::new(&mut allocator).unwrap(),
                transmit: Ring::new(&mut allocator).unwrap(),
                next_receive: 0,
                next_transmit: 0,
                clean_transmit: 0,
                dropping_receive: false,
                mac: Mac([2, 0, 0, 0, 0, 1]),
                clock: Clock {
                    ticks_per_microsecond: 1,
                },
                location: String::from("model"),
            };
            net.start();
            Self {
                net,
                registers,
                _memory: memory,
            }
        }

        fn inject(&mut self, index: usize, length: u16, status: u8, errors: u8, byte: u8) {
            self.net.receive.buffer(index).fill(byte);
            self.net
                .receive
                .descriptors
                .write(index * DESCRIPTOR + 8, length);
            self.net
                .receive
                .descriptors
                .write(index * DESCRIPTOR + 13, errors);
            // Hardware makes DD visible after the data and metadata writes.
            self.net
                .receive
                .descriptors
                .write(index * DESCRIPTOR + 12, status);
        }
    }

    #[test]
    fn dma_rings_use_legacy_descriptors_and_a_single_empty_slot() {
        let mut fixture = Fixture::new();
        assert_eq!(fixture.registers[RDLEN / 4], 512);
        assert_eq!(fixture.registers[TDLEN / 4], 512);
        assert_eq!(fixture.registers[RDT / 4], 31);
        assert_eq!(fixture.registers[RFCTL / 4] & RFCTL_EXTEN, 0);
        for _ in 0..DESCRIPTORS - 1 {
            fixture.net.transmit(&[7; 60]).unwrap();
        }
        let before = fixture.net.transmit.descriptors.bytes().to_vec();
        assert!(fixture.net.transmit(&[8; 60]).is_err());
        assert_eq!(fixture.net.transmit.descriptors.bytes(), before);
        assert_eq!(fixture.net.next_transmit, 31);
        // Completion of the oldest descriptor permits only that buffer to be reused.
        fixture.net.transmit.descriptors.write(12, TX_DONE);
        fixture.net.transmit(&[9; 60]).unwrap();
        assert_eq!(fixture.net.next_transmit, 0);
        assert_eq!(fixture.net.clean_transmit, 1);
        assert!(!fixture.net.reclaim());
    }

    #[test]
    fn transmit_padding_descriptors_and_wrap_are_real_dma_state() {
        let mut fixture = Fixture::new();
        for index in 0..DESCRIPTORS * 3 {
            let descriptor = index % DESCRIPTORS;
            fixture.net.transmit(&[0xa5; 14]).unwrap();
            assert_eq!(&fixture.net.transmit.buffer(descriptor)[..14], &[0xa5; 14]);
            assert_eq!(&fixture.net.transmit.buffer(descriptor)[14..60], &[0; 46]);
            assert_eq!(
                fixture
                    .net
                    .transmit
                    .descriptors
                    .read::<u32>(descriptor * DESCRIPTOR + 8),
                60 | TX_EOP | TX_IFCS | TX_REPORT
            );
            fixture
                .net
                .transmit
                .descriptors
                .write(descriptor * DESCRIPTOR + 12, TX_DONE);
        }
        assert_eq!(fixture.net.next_transmit, 0);
        assert_eq!(fixture.registers[TDT / 4], 0);
        let before = fixture.net.next_transmit;
        for bad in [vec![], vec![0; 13], vec![0; MAX_FRAME + 1]] {
            assert!(matches!(
                fixture.net.transmit(&bad),
                Err(LinkError::Invalid(_))
            ));
            assert_eq!(fixture.net.next_transmit, before);
        }
    }

    #[test]
    fn receive_drops_errors_oversize_and_entire_fragment_chains() {
        let mut fixture = Fixture::new();
        fixture.inject(0, 60, RX_DONE, 0, 1); // first fragment
        fixture.inject(1, 60, RX_DONE | RX_EOP, 0, 2); // not a standalone packet
        fixture.inject(2, 60, RX_DONE | RX_EOP, 1, 3); // bad FCS
        fixture.inject(3, 4096, RX_DONE | RX_EOP, 0, 4); // don't slice out of bounds
        fixture.inject(4, 60, RX_DONE | RX_EOP, 0, 5);
        assert_eq!(fixture.net.receive().unwrap(), Some(vec![5; 60]));
        assert_eq!(fixture.net.next_receive, 5);
        assert_eq!(fixture.registers[RDT / 4], 4);
        assert_eq!(
            fixture
                .net
                .receive
                .descriptors
                .read::<u64>(4 * DESCRIPTOR + 8),
            0
        );
        assert_eq!(fixture.net.receive().unwrap(), None);
    }

    #[test]
    fn receive_wraps_and_reoffers_every_descriptor_before_the_doorbell() {
        let mut fixture = Fixture::new();
        for count in 0..DESCRIPTORS * 3 {
            let index = count % DESCRIPTORS;
            fixture.inject(index, 60, RX_DONE | RX_EOP, 0, count as u8);
            assert_eq!(fixture.net.receive().unwrap(), Some(vec![count as u8; 60]));
            assert_eq!(
                fixture
                    .net
                    .receive
                    .descriptors
                    .read::<u64>(index * DESCRIPTOR),
                fixture.net.receive.address(index)
            );
            assert_eq!(
                fixture
                    .net
                    .receive
                    .descriptors
                    .read::<u64>(index * DESCRIPTOR + 8),
                0
            );
            assert_eq!(fixture.registers[RDT / 4], index as u32);
        }
        assert_eq!(fixture.net.next_receive, 0);
    }

    #[test]
    fn station_addresses_reject_invalid_zero_and_multicast_nvm() {
        assert_eq!(
            station(0x5634_1202, RAH_VALID | 0xbc9a),
            Some(Mac([2, 0x12, 0x34, 0x56, 0x9a, 0xbc]))
        );
        assert_eq!(station(0x5634_1202, 0xbc9a), None);
        assert_eq!(station(0, RAH_VALID), None);
        assert_eq!(station(u32::MAX, u32::MAX), None);
    }

    struct Config(u32, u32);

    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> u32 {
            match offset {
                0 => self.0,
                8 => self.1,
                _ => 0,
            }
        }
        fn write32(&mut self, _: u16, _: u32) {}
    }

    #[test]
    fn match_is_restricted_to_82574l_and_ethernet_class() {
        for (id, class, expected) in [
            (0x10d3_8086, 0x0200_0000, true),
            (0x10d3_8086, 0, false),
            (0x15b8_8086, 0x0200_0000, false),
            (0x10d3_1234, 0x0200_0000, false),
        ] {
            let function = crate::bus::pci::Function::new(
                Address {
                    segment: 0,
                    bus: 0,
                    device: 1,
                    function: 0,
                },
                Config(id, class),
            )
            .unwrap();
            assert_eq!(matches(&function), expected);
        }
    }
}
