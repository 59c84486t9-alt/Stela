// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2007 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Intel igb copper Ethernet: 82575/82576/82580, I350 and I210/I211.
//!
//! Native Stela adaptation of Linux's `drivers/net/ethernet/intel/igb` at
//! `a804c5742bff224d4cb4d25dd383554d598be32b`. Reset, EEPROM/iNVM,
//! firmware synchronization, PHY and PLL algorithms retain the GPL terms;
//! source hashes and supported subsets are in `THIRD_PARTY.md`.
//!
//! One polled advanced-descriptor queue, ordinary Ethernet frames, no
//! offloads, SR-IOV, timestamping, EEE, fiber, SerDes or SGMII. Matching a
//! copper PCI ID still requires a supported PHY and valid programmed NVM.
//! DMA remains allocated until reboot, including after errors or drop.
use super::{Link, LinkError, MAX_FRAME, MIN_FRAME, Mac};
use crate::{
    Clock, Handoff,
    block::BlockError,
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        mmio::Mmio,
        pci::{ConfigSpace, Function},
    },
    registers as mapped_registers,
};
use alloc::{format, string::String, vec::Vec};
use core::sync::atomic::{Ordering, fence};

mod hardware;
mod nvm;
mod phy;
mod registers;
use hardware::{Hardware, PciCapabilities};
use registers::*;

const DESCRIPTORS: usize = 32;
const DESCRIPTOR: usize = 16;
const BUFFER: usize = 2048;
const RX_DONE: u32 = 1;
const RX_EOP: u32 = 1 << 1;
const RX_FRAME_ERRORS: u32 = 0x9700_0000;
const TX_DONE: u32 = 1;
const TX_COMMAND: u32 = (3 << 20) | (1 << 24) | (1 << 25) | (1 << 27) | (1 << 29);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Chip {
    I82575,
    I82576,
    I82580,
    I350,
    I210,
    I211,
}

impl Chip {
    fn device(id: u16) -> Option<Self> {
        match id {
            0x10a7 | 0x10d6 => Some(Self::I82575),
            0x10c9 | 0x10e8 | 0x1526 | 0x150a => Some(Self::I82576),
            0x150e | 0x1516 => Some(Self::I82580),
            0x1521 => Some(Self::I350),
            0x1533 | 0x157b => Some(Self::I210),
            0x1539 => Some(Self::I211),
            _ => None,
        }
    }
    fn modern(self) -> bool {
        matches!(self, Self::I210 | Self::I211)
    }
    fn old_reset(self) -> bool {
        matches!(self, Self::I82575 | Self::I82576)
    }
    fn queues(self) -> usize {
        match self {
            Self::I82575 | Self::I210 => 4,
            Self::I82576 => 16,
            Self::I82580 | Self::I350 => 8,
            Self::I211 => 2,
        }
    }
    fn receive_addresses(self) -> usize {
        match self {
            Self::I82576 | Self::I82580 => 24,
            Self::I350 => 32,
            _ => 16,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::I82575 => "82575",
            Self::I82576 => "82576",
            Self::I82580 => "82580",
            Self::I350 => "I350",
            Self::I210 => "I210",
            Self::I211 => "I211",
        }
    }
}

pub fn matches<C: ConfigSpace>(function: &Function<C>) -> bool {
    function.vendor == 0x8086
        && function.class == [2, 0, 0]
        && Chip::device(function.device).is_some()
}

/// Linux continues after these firmware completion indications time out,
/// then checks NVM and PHY transactions. Keep those diagnostics visible.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InitializationWarnings {
    pub nvm_autoload_timeout: bool,
    pub phy_configuration_timeout: bool,
}

pub(crate) trait RegisterIo {
    fn read(&self, offset: usize) -> u32;
    fn write(&self, offset: usize, value: u32);
}
impl RegisterIo for Mmio {
    fn read(&self, offset: usize) -> u32 {
        self.read32(offset)
    }
    fn write(&self, offset: usize, value: u32) {
        self.write32(offset, value);
    }
}
pub(crate) trait Timer {
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
    fn program(&self, io: &impl RegisterIo, low: usize, high: usize, length: usize) {
        io.write(low, self.descriptors.physical() as u32);
        io.write(high, (self.descriptors.physical() >> 32) as u32);
        io.write(length, (DESCRIPTORS * DESCRIPTOR) as u32);
    }
}

pub struct Igb {
    device: Mmio,
    receive: Ring,
    transmit: Ring,
    received: usize,
    tail: usize,
    clean: usize,
    dropping: bool,
    mac: Mac,
    clock: Clock,
    pub location: String,
    pub warnings: InitializationWarnings,
}

impl Igb {
    /// # Safety
    /// The caller exclusively owns this physical PCI function after
    /// ExitBootServices and supplies its actual mapped MMIO/DMA handoff.
    /// No firmware or other driver may drive the function afterwards.
    pub unsafe fn new(
        function: &mut Function,
        handoff: &Handoff,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        if !matches(function) {
            return Err(BlockError::Unsupported("not an igb copper controller"));
        }
        let chip = Chip::device(function.device).unwrap();
        let bytes = if chip.modern() { 0x2_0000 } else { 0x1_0000 };
        let device = mapped_registers(handoff, function.bars()[0], 0, bytes)?;
        let capabilities = PciCapabilities::read(function);
        function.enable();
        let mut hardware = Hardware::new(&device, &handoff.clock, chip);
        let (mac, warnings) = hardware.initialize(function.config(), capabilities)?;
        let mut net = Self {
            device,
            receive: Ring::new(dma)?,
            transmit: Ring::new(dma)?,
            received: 0,
            tail: 0,
            clean: 0,
            dropping: false,
            mac,
            clock: handoff.clock,
            location: format!("{} Intel {}", function.address, chip.name()),
            warnings,
        };
        net.start()?;
        Ok(net)
    }

    fn start(&mut self) -> Result<(), BlockError> {
        start_queues(&self.device, &self.clock, &mut self.receive, &self.transmit)?;
        Ok(())
    }

    fn reclaim(&mut self) -> bool {
        while self.clean != self.tail {
            let status: u32 = self.transmit.descriptors.read(self.clean * DESCRIPTOR + 12);
            if status & TX_DONE == 0 {
                break;
            }
            fence(Ordering::Acquire);
            self.clean = (self.clean + 1) % DESCRIPTORS;
        }
        (self.tail + 1) % DESCRIPTORS != self.clean
    }
}

fn start_queues(
    io: &impl RegisterIo,
    clock: &impl Timer,
    receive: &mut Ring,
    transmit: &Ring,
) -> Result<(), BlockError> {
    receive.program(io, RDBAL, RDBAH, RDLEN);
    transmit.program(io, TDBAL, TDBAH, TDLEN);
    io.write(RDH, 0);
    io.write(RDT, 0);
    io.write(TDH, 0);
    io.write(TDT, 0);
    io.write(SRRCTL, (BUFFER >> 10) as u32 | (1 << 25));
    // One-at-a-time write-back keeps polling live even for isolated packets.
    io.write(RXDCTL, 8 | (8 << 8) | (1 << 16) | QUEUE_ENABLE);
    io.write(TXDCTL, 8 | (1 << 8) | QUEUE_ENABLE);
    let enabled = clock.wait(20_000, || {
        io.read(RXDCTL) & QUEUE_ENABLE != 0 && io.read(TXDCTL) & QUEUE_ENABLE != 0
    });
    if !enabled {
        io.write(RXDCTL, 0);
        io.write(TXDCTL, 0);
        io.write(RCTL, 0);
        io.write(TCTL, TCTL_PSP);
        return Err(BlockError::Timeout);
    }
    for index in 0..DESCRIPTORS {
        offer_receive(receive, index);
    }
    fence(Ordering::SeqCst);
    io.write(RDT, (DESCRIPTORS - 1) as u32);
    io.write(RCTL, RCTL_EN | RCTL_MPE | RCTL_BAM | RCTL_SECRC);
    io.write(TCTL, TCTL_EN | TCTL_PSP | TCTL_RTLC | TCTL_COLLISIONS);
    io.read(STATUS);
    Ok(())
}

fn offer_receive(ring: &mut Ring, index: usize) {
    let address = ring.address(index);
    ring.descriptors.write(index * DESCRIPTOR, address);
    ring.descriptors.write(index * DESCRIPTOR + 8, 0u64);
}

impl Link for Igb {
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
            if !clock.wait(100_000, || self.reclaim()) {
                return Err(LinkError::Adapter(format!(
                    "{} transmit ring stalled",
                    self.location
                )));
            }
        }
        let index = self.tail;
        let length = frame.len().max(MIN_FRAME);
        let buffer = self.transmit.buffer(index);
        buffer[..length].fill(0);
        buffer[..frame.len()].copy_from_slice(frame);
        let address = self.transmit.address(index);
        self.transmit.descriptors.write(index * DESCRIPTOR, address);
        self.transmit
            .descriptors
            .write(index * DESCRIPTOR + 8, TX_COMMAND | length as u32);
        self.transmit
            .descriptors
            .write(index * DESCRIPTOR + 12, (length as u32) << 14);
        self.tail = (index + 1) % DESCRIPTORS;
        fence(Ordering::SeqCst);
        self.device.write32(TDT, self.tail as u32);
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        for _ in 0..DESCRIPTORS {
            let index = self.received;
            let status: u32 = self.receive.descriptors.read(index * DESCRIPTOR + 8);
            if status & RX_DONE == 0 {
                return Ok(None);
            }
            fence(Ordering::Acquire);
            let length = usize::from(
                self.receive
                    .descriptors
                    .read::<u16>(index * DESCRIPTOR + 12),
            );
            let eop = status & RX_EOP != 0;
            let good = !self.dropping
                && eop
                && status & RX_FRAME_ERRORS == 0
                && (14..=MAX_FRAME).contains(&length);
            let frame = good.then(|| self.receive.buffer(index)[..length].to_vec());
            self.dropping = !eop;
            offer_receive(&mut self.receive, index);
            self.received = (index + 1) % DESCRIPTORS;
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
mod tests;
