// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of rtsx_pcr.c, rts5227.c and rtsx_pci_sdmmc.c.
// Copyright(c) 2009-2013 Realtek Semiconductor Corp. All rights reserved.
// Authors: Wei WANG, Roger Tseng. See ../THIRD_PARTY.md.
//! Native RTS5227 PCIe SD/MMC reader with actual HAIMR and ping-pong PIO.
//! Command-buffer/data DMA, Memory Stick, UHS/DDR and global PM remain separate.
use crate::{
    Clock, Handoff,
    block::{BlockDevice, BlockError, Identity},
    bus::{mmio::Mmio, pci::{ConfigSpace, Function}},
    storage::mmc::{protocol::{Description, Session}, wire::*},
};
use alloc::{boxed::Box, rc::Rc, string::String, vec::Vec};
use core::{cell::RefCell, sync::atomic::{AtomicU64, Ordering}};
pub use super::mmc::{CardInfo, Kind};
mod controller;
mod command;
mod registers;
use registers::*;

const VENDOR: u16 = 0x10ec;
const DEVICE: u16 = 0x5227;
const STALE: &str = "RTSX card publication is permanently stale";
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Exact source identity and class; other Realtek reader generations have
/// different PHY/power/clock profiles and cannot inherit this setup.
pub fn matches(function: &Function) -> bool {
    function.vendor == VENDOR && function.device == DEVICE && function.class[0] == 0xff
}

/// Retained even when the socket is empty or card identification fails.
pub struct Attached {
    pub host: Host,
    pub card: Option<Card>,
    pub failure: Option<BlockError>,
}

/// The actual enumerated function and mapping remain owned through every host
/// and card alias. PIO never grants bus mastering or fabricates a DMA address.
pub fn attach(mut function: Function, handoff: &Handoff) -> Result<Attached, BlockError> {
    if !matches(&function) {
        return Err(BlockError::Unsupported("PCI function is not qualified RTS5227"));
    }
    if handoff.clock.ticks_per_microsecond == 0 {
        return Err(BlockError::Unsupported("RTSX requires a calibrated native clock"));
    }
    let admission = controller::admission(&mut function)?;
    super::pci::quiesce_pio(&mut function)?;
    function.power_up(&handoff.clock)?;
    let config = controller::Configuration::capture(&mut function, admission)?;
    let bars = function.bars();
    let registers = crate::registers(handoff, bars[0], 0, 0x20)?;
    super::pci::set_pio_command(&mut function, true)?;
    let location = alloc::format!("{} RTS5227 SD slot", function.address);
    let engine = Engine::new(Box::new(function), Box::new(registers), config, handoff.clock, location)?;
    let mut host = Host { inner: Rc::new(RefCell::new(engine)) };
    let (card, failure) = match host.poll() {
        Ok(card) => (card, None),
        Err(error) => (None, Some(error)),
    };
    Ok(Attached { host, card, failure })
}

trait Pci {
    fn read8(&mut self, at: u16) -> u8;
    fn read16(&mut self, at: u16) -> u16;
    fn read32(&mut self, at: u16) -> u32;
    fn write8(&mut self, at: u16, value: u8);
    fn write16(&mut self, at: u16, value: u16);
}
impl<C: ConfigSpace> Pci for Function<C> {
    fn read8(&mut self, at: u16) -> u8 { self.config().read8(at) }
    fn read16(&mut self, at: u16) -> u16 { self.config().read16(at) }
    fn read32(&mut self, at: u16) -> u32 { self.config().read32(at) }
    fn write8(&mut self, at: u16, value: u8) { self.config().write8(at, value); }
    fn write16(&mut self, at: u16, value: u16) { self.config().write16(at, value); }
}

/// Poll the actual socket explicitly. Observed removal/replacement permanently
/// retires every old disk alias before another physical card can be published.
pub struct Host { inner: Rc<RefCell<Engine>> }
impl Host {
    pub fn poll(&mut self) -> Result<Option<Card>, BlockError> {
        let mut engine = self.inner.borrow_mut();
        engine.healthy()?;
        if !engine.observe()? || engine.medium.is_some() { return Ok(None); }
        engine.configure_card()?;
        let card = match Session::new(&mut *engine, 0).identify() {
            Ok(card) => card,
            Err(error) => { engine.medium = None; return Err(error); }
        };
        engine.rca = card.rca;
        let id = NEXT_ID.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |id| id.checked_add(1)).map_err(|_| BlockError::Unsupported("RTSX card identity exhausted"))?;
        let published = Card { inner: self.inner.clone(), generation: id,
            identity: card.identity.clone(), info: card.info.clone() };
        engine.medium = Some(Medium { id, card });
        Ok(Some(published))
    }
}

#[derive(Clone)]
pub struct Card {
    inner: Rc<RefCell<Engine>>,
    generation: u64,
    identity: Identity,
    info: CardInfo,
}
impl Card { pub fn info(&self) -> &CardInfo { &self.info } }
impl BlockDevice for Card {
    fn identity(&self) -> &Identity { &self.identity }
    fn read(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), BlockError> {
        let mut engine = self.inner.borrow_mut();
        engine.live(self.generation)?;
        self.identity.check(lba, bytes.len())?;
        for (index, block) in bytes.chunks_mut(512).enumerate() {
            engine.live(self.generation)?;
            let address = engine.address(lba + index as u64)?;
            engine.execute(READ_SINGLE, address, Response::Status, Some(512))?;
            engine.ready()?;
            block.copy_from_slice(&engine.scratch);
        }
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &[u8]) -> Result<(), BlockError> {
        let mut engine = self.inner.borrow_mut();
        engine.live(self.generation)?;
        self.identity.check_write(lba, bytes.len())?;
        for (index, block) in bytes.chunks(512).enumerate() {
            engine.live(self.generation)?;
            if engine.status()? & SD_WRITE_PROTECT != 0 { return Err(BlockError::ReadOnly); }
            let address = engine.address(lba + index as u64)?;
            engine.write_block(address, block)?;
            engine.ready()?;
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        let mut engine = self.inner.borrow_mut();
        engine.live(self.generation)?;
        let card = &engine.medium.as_ref().expect("live").card;
        if card.kind == Kind::Mmc && card.cache {
            let rca = engine.rca;
            Session::new(&mut *engine, rca).mmc_switch(32, 1)?;
        }
        engine.ready()
    }
    fn shutdown(&mut self, power_off: bool) -> Result<(), BlockError> {
        self.flush()?;
        if power_off {
            let mut engine = self.inner.borrow_mut();
            engine.live(self.generation)?;
            let notify = engine.medium.as_ref().expect("live").card.notify;
            engine.medium = None;
            if notify {
                let rca = engine.rca;
                Session::new(&mut *engine, rca).power_off_notify()?;
            }
            engine.power_off()?;
        }
        Ok(())
    }
}
struct Medium { id: u64, card: Description }
struct Engine {
    pci: Box<dyn Pci>,
    registers: Box<dyn Registers>,
    config: controller::Configuration,
    clock: Clock,
    location: String,
    rca: u16,
    scratch: [u8; 512],
    medium: Option<Medium>,
    fault: Option<BlockError>,
}
impl Engine {
    fn healthy(&mut self) -> Result<(), BlockError> {
        if let Some(error) = &self.fault { return Err(error.clone()); }
        if self.pci.read32(0) != u32::from(VENDOR) | u32::from(DEVICE) << 16 {
            let error = BlockError::Unsupported("RTSX owned PCI function disappeared");
            self.medium = None;
            self.fault = Some(error.clone());
            return Err(error);
        }
        Ok(())
    }
    fn status(&mut self) -> Result<u32, BlockError> {
        let status = self.registers.read32(BIPR);
        if status == u32::MAX || status & (DELINK_INT | SD_OC_INT) != 0 {
            self.medium = None;
            let error = BlockError::Device { status };
            self.fault = Some(error.clone());
            return Err(error);
        }
        Ok(status)
    }
    fn observe(&mut self) -> Result<bool, BlockError> {
        let status = self.status()?;
        if status & SD_INT != 0 || status & SD_EXIST == 0 {
            self.medium = None;
            self.stop_card()?;
            self.registers.write32(BIPR, status & SD_INT);
        }
        if status & MS_EXIST != 0 {
            self.medium = None;
            return Err(BlockError::Unsupported("RTSX shared PMOS refuses concurrent Memory Stick"));
        }
        Ok(status & SD_EXIST != 0)
    }
    fn live(&mut self, generation: u64) -> Result<(), BlockError> {
        if self.medium.as_ref().is_none_or(|card| card.id != generation) {
            return Err(BlockError::Unsupported(STALE));
        }
        self.healthy()?;
        self.observe()?;
        if self.medium.as_ref().is_none_or(|card| card.id != generation) {
            return Err(BlockError::Unsupported(STALE));
        }
        Ok(())
    }
    fn address(&self, lba: u64) -> Result<u32, BlockError> {
        let sectors = self.medium.as_ref().expect("live").card.sector_addressed;
        let address = if sectors { Some(lba) } else { lba.checked_mul(512) };
        address.and_then(|address| u32::try_from(address).ok())
            .ok_or(BlockError::Unsupported("RTSX card address exceeds native command field"))
    }
    fn ready(&mut self) -> Result<(), BlockError> {
        let rca = self.rca;
        Session::new(self, rca).wait_card_ready()
    }
}
