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
use super::{
    HEADER, Link, LinkError, MAX_FRAME, MIN_FRAME, Mac,
    advanced::{
        self, QUEUE_ENABLE, RX_DD, RX_EOP, RXDCTL_THRESHOLDS, SRRCTL_ONE_BUFFER, TXDCTL_THRESHOLDS,
        TransmitQueue, transmitted,
    },
    check_frame,
    ring::{DESCRIPTOR, DESCRIPTORS, Ring},
};
use crate::{
    Clock, Handoff,
    block::BlockError,
    bus::{
        dma::DmaAllocator,
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

/// Receive descriptor errors that drop a frame: RXE, IPE, TCPE and CE;
/// checksum errors are irrelevant with checksum offload disabled.
const RX_FRAME_ERRORS: u32 = 0x9700_0000;
const TRANSMIT_QUEUE: TransmitQueue = TransmitQueue {
    head: TDH,
    tail: TDT,
    control: TXDCTL,
};

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

pub struct Igb {
    device: Mmio,
    receive: Ring,
    transmit: Ring,
    dropping: bool,
    /// Register reads return all ones: the function is gone.
    faulted: bool,
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
        function.power_up(&handoff.clock)?;
        let device = mapped_registers(handoff, function.bars()[0], 0, bytes)?;
        let capabilities = PciCapabilities::read(function);
        function.enable_polled();
        let mut hardware = Hardware::new(&device, &handoff.clock, chip);
        let (mac, warnings) = hardware.initialize(function.config(), capabilities)?;
        let mut net = Self {
            device,
            receive: Ring::new(dma)?,
            transmit: Ring::new(dma)?,
            dropping: false,
            faulted: false,
            mac,
            clock: handoff.clock,
            location: format!("{} Intel {}", function.address, chip.name()),
            warnings,
        };
        start_queues(&net.device, &net.clock, &mut net.receive, &net.transmit)?;
        Ok(net)
    }

    /// Report a lost function, and discard the transmit work a lost link
    /// strands (Linux `igb_watchdog_task` resets for it). Returns the carrier.
    fn watchdog(&mut self) -> Result<bool, LinkError> {
        let status = self.device.read32(STATUS);
        self.faulted |= status == u32::MAX;
        if !self.faulted && status & STATUS_LU == 0 && self.transmit.pending() {
            let device = self.device;
            self.faulted = !TRANSMIT_QUEUE.flush(
                &mut self.transmit,
                self.clock,
                |offset| device.read32(offset),
                |offset, value| device.write32(offset, value),
            );
        }
        match self.faulted {
            true => Err(LinkError::Adapter(format!(
                "{} lost register access; reinitialization required",
                self.location
            ))),
            false => Ok(status & STATUS_LU != 0),
        }
    }
}

fn start_queues(
    io: &impl RegisterIo,
    clock: &impl Timer,
    receive: &mut Ring,
    transmit: &Ring,
) -> Result<(), BlockError> {
    let write = |offset, value| io.write(offset, value);
    receive.program(write, RDBAL, RDBAH, RDLEN);
    transmit.program(write, TDBAL, TDBAH, TDLEN);
    io.write(RDH, 0);
    io.write(RDT, 0);
    io.write(TDH, 0);
    io.write(TDT, 0);
    io.write(SRRCTL, SRRCTL_ONE_BUFFER);
    // One-at-a-time write-back keeps polling live even for isolated packets.
    io.write(RXDCTL, RXDCTL_THRESHOLDS | QUEUE_ENABLE);
    io.write(TXDCTL, TXDCTL_THRESHOLDS | QUEUE_ENABLE);
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
        advanced::offer_receive(receive, index);
    }
    fence(Ordering::SeqCst);
    io.write(RDT, (DESCRIPTORS - 1) as u32);
    io.write(RCTL, RCTL_EN | RCTL_MPE | RCTL_BAM | RCTL_SECRC);
    io.write(TCTL, TCTL_EN | TCTL_PSP | TCTL_RTLC | TCTL_COLLISIONS);
    io.read(STATUS);
    Ok(())
}

impl Link for Igb {
    fn mac(&self) -> Mac {
        self.mac
    }
    fn carrier(&mut self) -> bool {
        self.watchdog().unwrap_or(false)
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        check_frame(frame)?;
        if !self.watchdog()? {
            return Err(LinkError::NoCarrier);
        }
        if !self.transmit.free(self.clock, transmitted) {
            return Err(LinkError::Adapter(format!(
                "{} transmit ring stalled",
                self.location
            )));
        }
        advanced::queue_frame(&mut self.transmit, frame, frame.len().max(MIN_FRAME));
        self.device.write32(TDT, self.transmit.next as u32);
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.watchdog()?;
        for _ in 0..DESCRIPTORS {
            let index = self.receive.next;
            let status: u32 = self.receive.descriptors.read(index * DESCRIPTOR + 8);
            if status & RX_DD == 0 {
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
                && (HEADER..=MAX_FRAME).contains(&length);
            let frame = good.then(|| self.receive.buffer(index)[..length].to_vec());
            self.dropping = !eop;
            advanced::offer_receive(&mut self.receive, index);
            self.receive.advance();
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
