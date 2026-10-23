// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of Linux sdhci.c/h, Copyright 2005-2008 Pierre Ossman;
// MMC/SD protocol sequencing retains the source notices in THIRD_PARTY.md.
//! Native polled SDHCI storage with retained host and generation-bound cards.
//! SD/SDHC/SDXC and eMMC user-area access share the actual command engine.
use crate::{
    Clock, Handoff,
    block::{BlockDevice, BlockError, Identity, Transport},
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        pci::{ConfigSpace, Function},
    },
    registers as mapped_registers,
};
use alloc::{boxed::Box, format, rc::Rc, string::String, vec::Vec};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicU64, Ordering, fence},
};
mod command;
mod protocol;
mod registers;
use registers::*;
#[cfg(test)]
mod model;
#[cfg(test)]
mod qtest;
#[cfg(test)]
mod tests;

const PCI_SLOT_INFO: u16 = 0x40;
const TRANSFER_BYTES: usize = 64 * 1024;
const STALE: &str = "SDHCI card publication is permanently stale";
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Standard PCI SD host programming interfaces, including the DMA interface.
pub fn matches(function: &Function) -> bool {
    function.class[0..2] == [0x08, 0x05] && matches!(function.class[2], 0 | 1)
}

/// Native PCI slots, including empty sockets retained for explicit polling.
pub struct Attached {
    pub hosts: Vec<Host>,
    pub cards: Vec<Card>,
    pub failures: Vec<(u8, BlockError)>,
}

/// Attach only MMIO already mapped by the normal firmware handoff. Vendor
/// electrical/reset/clock quirks require their own qualified source profiles.
pub fn attach(
    function: &mut Function,
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
) -> Result<Attached, BlockError> {
    if !matches(function) {
        return Err(BlockError::Unsupported(
            "PCI function is not standard SDHCI",
        ));
    }
    function.power_up(&handoff.clock)?;
    let info = function.config().read8(PCI_SLOT_INFO);
    let slots = ((info >> 4) & 7) + 1;
    let first = usize::from(info & 7);
    if first + usize::from(slots) > 6 {
        return Err(BlockError::Unsupported("SDHCI slot BAR inventory"));
    }
    let bars = function.bars();
    // Validate the complete mapping set before any controller is enabled.
    let mut mappings = Vec::new();
    for index in 0..slots {
        mappings.push(mapped_registers(
            handoff,
            bars[first + usize::from(index)],
            0,
            0x100,
        )?);
    }
    function.enable_polled();
    let mut attached = Attached {
        hosts: Vec::new(),
        cards: Vec::new(),
        failures: Vec::new(),
    };
    for (index, registers) in mappings.into_iter().enumerate() {
        let location = format!("{} SD slot {index}", function.address);
        match Host::new(Box::new(registers), handoff.clock, location, dma) {
            Ok(mut host) => {
                match host.poll() {
                    Ok(Some(card)) => attached.cards.push(card),
                    Ok(None) => {}
                    Err(error) => attached.failures.push((index as u8, error)),
                };
                attached.hosts.push(host);
            }
            Err(error) => attached.failures.push((index as u8, error)),
        }
    }
    Ok(attached)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Sd,
    Mmc,
}
/// Actual card registers and the acknowledged physical operating mode.
#[derive(Clone, Debug)]
pub struct CardInfo {
    pub kind: Kind,
    pub cid: [u32; 4],
    pub csd: [u32; 4],
    pub scr: Option<[u8; 8]>,
    pub ext_csd: Option<Vec<u8>>,
    pub clock_hz: u32,
    pub bus_width: u8,
}
struct Medium {
    id: u64,
    identity: Identity,
    kind: Kind,
    sector_addressed: bool,
    cache: bool,
    info: CardInfo,
    notify: bool,
}
struct Engine {
    registers: Box<dyn Registers>,
    clock: Clock,
    location: String,
    version: u8,
    capabilities: u32,
    base_hz: u32,
    extended_capabilities: u32,
    rca: u16,
    data: DmaBuffer,
    descriptors: DmaBuffer,
    dma_mode: Option<bool>,
    medium: Option<Medium>,
    fault: Option<BlockError>,
}

/// Actual architectural registers captured after acknowledged host reset.
#[derive(Clone, Copy, Debug)]
pub struct HostInfo {
    pub specification_version: u8,
    pub base_clock_hz: u32,
    pub capabilities: u32,
    pub extended_capabilities: u32,
}

/// Keep this owner even when a removable socket is empty. Polling a real
/// removal/change fences every previous Card before reset or fresh discovery.
pub struct Host {
    inner: Rc<RefCell<Engine>>,
}
impl Host {
    pub fn info(&self) -> HostInfo {
        let c = self.inner.borrow();
        HostInfo {
            specification_version: c.version,
            base_clock_hz: c.base_hz,
            capabilities: c.capabilities,
            extended_capabilities: c.extended_capabilities,
        }
    }
    fn new(
        registers: Box<dyn Registers>,
        clock: Clock,
        location: String,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        if clock.ticks_per_microsecond == 0 {
            return Err(BlockError::Unsupported(
                "SDHCI requires a calibrated native clock",
            ));
        }
        let data = dma.allocate(TRANSFER_BYTES, 64)?;
        let descriptors = dma.allocate(4096, 64)?;
        let mut engine = Engine {
            registers,
            clock,
            location,
            version: 0,
            capabilities: 0,
            base_hz: 0,
            extended_capabilities: 0,
            rca: 0,
            data,
            descriptors,
            dma_mode: None,
            medium: None,
            fault: None,
        };
        engine.configure_host()?;
        Ok(Self {
            inner: Rc::new(RefCell::new(engine)),
        })
    }
    pub fn poll(&mut self) -> Result<Option<Card>, BlockError> {
        let mut c = self.inner.borrow_mut();
        c.healthy()?;
        let changed = c.observe_medium()?;
        if c.medium.is_some() && !changed {
            return Ok(None);
        }
        let state = c.registers.read32(PRESENT);
        if state & (CARD_PRESENT | CARD_STABLE) != CARD_PRESENT | CARD_STABLE {
            return Ok(None);
        }
        c.medium = None;
        c.configure_host()?;
        let medium = c.identify()?;
        let card = Card {
            inner: self.inner.clone(),
            generation: medium.id,
            identity: medium.identity.clone(),
            info: medium.info.clone(),
        };
        c.medium = Some(medium);
        Ok(Some(card))
    }
}

/// Immutable published identity. An old clone never names a replacement card.
#[derive(Clone)]
pub struct Card {
    inner: Rc<RefCell<Engine>>,
    generation: u64,
    identity: Identity,
    info: CardInfo,
}
impl Card {
    pub fn info(&self) -> &CardInfo {
        &self.info
    }
}
impl BlockDevice for Card {
    fn identity(&self) -> &Identity {
        &self.identity
    }
    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let mut c = self.inner.borrow_mut();
        c.live(self.generation)?;
        self.identity.check(lba, buffer.len())?;
        for (index, chunk) in buffer.chunks_mut(TRANSFER_BYTES).enumerate() {
            let at = lba + (index * TRANSFER_BYTES / 512) as u64;
            c.block_transfer(self.generation, at, chunk.len(), true)?;
            chunk.copy_from_slice(&c.data.bytes()[..chunk.len()]);
        }
        Ok(())
    }
    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        let mut c = self.inner.borrow_mut();
        c.live(self.generation)?;
        self.identity.check_write(lba, data.len())?;
        if self.info.kind == Kind::Sd && c.registers.read32(PRESENT) & WRITE_ALLOWED == 0 {
            return Err(BlockError::ReadOnly);
        }
        for (index, chunk) in data.chunks(TRANSFER_BYTES).enumerate() {
            c.live(self.generation)?;
            c.data.bytes_mut()[..chunk.len()].copy_from_slice(chunk);
            c.block_transfer(
                self.generation,
                lba + (index * TRANSFER_BYTES / 512) as u64,
                chunk.len(),
                false,
            )?;
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        let mut c = self.inner.borrow_mut();
        c.live(self.generation)?;
        let medium = c.medium.as_ref().unwrap();
        if medium.kind == Kind::Mmc && medium.cache {
            c.mmc_switch(32, 1)?;
        }
        c.wait_card_ready()
    }
    fn shutdown(&mut self, power_off: bool) -> Result<(), BlockError> {
        self.flush()?;
        if power_off {
            let mut c = self.inner.borrow_mut();
            c.live(self.generation)?;
            let notify = c.medium.as_ref().is_some_and(|medium| medium.notify);
            // A notified MMC may stop accepting commands until power cycles.
            // Fence every alias before the notification starts, and never send
            // CMD13 after its actual R1b/DAT0 completion.
            c.medium = None;
            if notify {
                c.power_off_notify()?;
            }
            c.reset(RESET_COMMAND | RESET_DATA)?;
            c.registers.write16(CLOCK, 0);
            c.registers.write8(POWER, 0);
        }
        Ok(())
    }
}
impl Engine {
    fn healthy(&self) -> Result<(), BlockError> {
        self.fault.clone().map_or(Ok(()), Err)
    }
    fn live(&mut self, id: u64) -> Result<(), BlockError> {
        if self.medium.as_ref().is_none_or(|medium| medium.id != id) {
            return Err(BlockError::Unsupported(STALE));
        }
        self.healthy()?;
        self.observe_medium()?;
        if self.medium.as_ref().is_none_or(|medium| medium.id != id) {
            return Err(BlockError::Unsupported(STALE));
        }
        Ok(())
    }
    fn observe_medium(&mut self) -> Result<bool, BlockError> {
        let changes = self.registers.read32(INTERRUPT) & (CARD_INSERT | CARD_REMOVE);
        let present = self.registers.read32(PRESENT) & CARD_PRESENT != 0;
        let changed = changes != 0 || !present && self.medium.is_some();
        if changed {
            self.medium = None;
            self.reset(RESET_COMMAND | RESET_DATA)?;
            self.registers.write32(INTERRUPT, changes);
        }
        Ok(changed)
    }
    fn reset(&mut self, mask: u8) -> Result<(), BlockError> {
        self.registers.write8(RESET, mask);
        if !self
            .clock
            .wait(RESET_US, || self.registers.read8(RESET) & mask == 0)
        {
            self.medium = None;
            self.fault = Some(BlockError::Unsupported(
                "SDHCI reset did not acknowledge DMA retirement",
            ));
            return Err(self.fault.clone().unwrap());
        }
        fence(Ordering::Acquire);
        Ok(())
    }
    fn configure_host(&mut self) -> Result<(), BlockError> {
        self.reset(RESET_ALL)?;
        self.version = self.registers.read16(VERSION) as u8;
        if self.version > 5 {
            return Err(BlockError::Unsupported(
                "unknown SDHCI specification version",
            ));
        }
        self.capabilities = self.registers.read32(CAPABILITIES);
        self.extended_capabilities = if self.version >= 2 {
            self.registers.read32(CAPABILITIES2)
        } else {
            0
        };
        let power = if self.capabilities & CAP_330 != 0 {
            POWER_330
        } else if self.capabilities & CAP_300 != 0 {
            POWER_300
        } else if self.capabilities & CAP_180 != 0 {
            return Err(BlockError::Unsupported(
                "SDHCI 1.8-V-only supply requires a qualified electrical profile",
            ));
        } else {
            return Err(BlockError::Unsupported(
                "SDHCI has no supported supply voltage",
            ));
        };

        let mask = if self.version >= 2 { 0xff } else { 0x3f };
        self.base_hz = ((self.capabilities >> 8) & mask) * 1_000_000;
        if self.base_hz == 0 {
            return Err(BlockError::Unsupported("SDHCI needs an actual base clock"));
        }
        self.dma_mode = if self.capabilities & CAP_ADMA2 == 0 {
            None
        } else if self.capabilities & CAP_64 != 0 {
            Some(true)
        } else if self
            .data
            .physical()
            .checked_add(self.data.len() as u64)
            .is_some_and(|end| end <= 1u64 << 32)
            && self
                .descriptors
                .physical()
                .checked_add(self.descriptors.len() as u64)
                .is_some_and(|end| end <= 1u64 << 32)
        {
            Some(false)
        } else {
            None
        };
        // The generic boundary uses ordinary SDHCI v1-v3 operation even on
        // newer controllers. V4/ADMA3 and UHS2 are never silently enabled.
        if self.version >= 2 {
            self.registers.write16(HOST_CONTROL2, 0);
        }
        self.registers.write8(HOST_CONTROL, 0);
        self.registers.write8(TIMEOUT, 0x0e);
        self.registers.write32(SIGNAL_ENABLE, 0);
        self.registers.write32(INTERRUPT_ENABLE, u32::MAX);
        self.registers
            .write32(INTERRUPT, !(CARD_INSERT | CARD_REMOVE));
        self.registers.write8(POWER, 0);
        self.clock.delay(1000);
        self.registers.write8(POWER, power);
        self.registers.write8(POWER, power | POWER_ON);
        self.clock.delay(10_000);
        self.set_clock(INIT_HZ)?;
        // mmc_power_up requires >=74 card clocks/1ms after enabling f_init.
        // The pre-clock power delay cannot supply any of these card clocks.
        self.clock.delay(1000);
        Ok(())
    }
    fn set_clock(&mut self, hz: u32) -> Result<(), BlockError> {
        self.registers.write16(CLOCK, 0);
        let (divisor, actual) = clock_divisor(self.version, self.base_hz, hz)?;
        let field = (divisor & 0xff) << 8 | (divisor & 0x300) >> 2;
        self.registers.write16(CLOCK, field | CLOCK_INTERNAL);
        if !self
            .clock
            .wait(20_000, || self.registers.read16(CLOCK) & CLOCK_STABLE != 0)
        {
            return Err(BlockError::Timeout);
        }
        self.registers
            .write16(CLOCK, field | CLOCK_INTERNAL | CLOCK_CARD);
        if actual > hz {
            return Err(BlockError::Unsupported("SDHCI clock exceeds card limit"));
        }
        Ok(())
    }
}
fn clock_divisor(version: u8, base: u32, hz: u32) -> Result<(u16, u32), BlockError> {
    if hz == 0 || base == 0 {
        return Err(BlockError::Unsupported("SDHCI zero clock"));
    }
    let mut divisor = 1u32;
    if base > hz {
        if version >= 2 {
            divisor = base.div_ceil(hz).next_multiple_of(2);
        } else {
            while base.div_ceil(divisor) > hz && divisor < 256 {
                divisor *= 2;
            }
        }
    }
    let limit = if version >= 2 { 2046 } else { 256 };
    if divisor > limit || base.div_ceil(divisor) > hz {
        return Err(BlockError::Unsupported(
            "SDHCI cannot generate required card clock",
        ));
    }
    Ok(((divisor / 2) as u16, base / divisor))
}
fn generation() -> Result<u64, BlockError> {
    generation_from(&NEXT_ID)
}
fn generation_from(counter: &AtomicU64) -> Result<u64, BlockError> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| BlockError::Unsupported("SDHCI media generation exhausted"))
}
