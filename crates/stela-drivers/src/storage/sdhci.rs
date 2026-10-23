// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of Linux sdhci.c/h, Copyright 2005-2008 Pierre Ossman;
// MMC/SD protocol sequencing retains the source notices in THIRD_PARTY.md.
//! Native polled SDHCI storage with retained host and generation-bound cards.
//! SD/SDHC/SDXC and eMMC user-area access share the actual command engine.
use crate::{
    Clock, Handoff,
    block::{BlockDevice, BlockError, Identity},
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        pci::Function,
    },
    registers as mapped_registers,
};
use alloc::{
    boxed::Box,
    format,
    rc::Rc,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicU64, Ordering, fence},
};
mod command;
mod pci;
mod protocol;
use super::pci::{quiesce_pio, set_pio_command};
#[cfg(test)]
use crate::block::Transport;
use pci::{Control, Controller, Profile};
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
    let profile = Profile::select(function.vendor, function.device);
    if profile.retained_config() {
        return Err(BlockError::Unsupported(
            "SDHCI profile requires owned PCI function attachment",
        ));
    }
    let mappings = prepare_slots(function, handoff, profile)?;
    Ok(finish_attach(
        mappings,
        handoff.clock,
        function.address.to_string(),
        dma,
        profile,
        None,
    ))
}

/// Whether later host clock/power operations require retained PCI ownership.
pub fn requires_owned_config(function: &Function) -> bool {
    matches(function) && Profile::select(function.vendor, function.device).retained_config()
}

/// Consume the actual enumerated function for profiles requiring future PCI
/// configuration. All slots share that original authority, without raw ECAM aliases.
pub fn attach_owned(
    mut function: Function,
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
) -> Result<Attached, BlockError> {
    if !requires_owned_config(&function) {
        return attach(&mut function, handoff, dma);
    }
    if handoff.clock.ticks_per_microsecond == 0 {
        return Err(BlockError::Unsupported(
            "SDHCI requires a calibrated native clock",
        ));
    }
    let profile = Profile::select(function.vendor, function.device);
    let location = function.address.to_string();
    let mappings = prepare_slots(&mut function, handoff, profile)?;
    // Retire every slot before changing shared PCI clock/capability registers.
    for registers in &mappings {
        registers.write8(RESET, RESET_ALL);
        if !handoff
            .clock
            .wait(RESET_US, || registers.read8(RESET) & RESET_ALL == 0)
        {
            return Err(BlockError::Unsupported(
                "SDHCI owned-function slot reset did not retire",
            ));
        }
    }
    let control = Controller::new(function);
    control.borrow_mut().prepare()?;
    Ok(finish_attach(
        mappings,
        handoff.clock,
        location,
        dma,
        profile,
        Some(control),
    ))
}

fn prepare_slots(
    function: &mut Function,
    handoff: &Handoff,
    profile: Profile,
) -> Result<Vec<crate::bus::mmio::Mmio>, BlockError> {
    if profile.retained_config() {
        quiesce_pio(function)?;
    }
    function.power_up(&handoff.clock)?;
    let info = function.config().read8(PCI_SLOT_INFO);
    let slots = profile.slots(((info >> 4) & 7) + 1);
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
            profile.register_bytes(),
        )?);
    }
    if profile.retained_config() {
        set_pio_command(function, true)?;
    } else {
        function.enable_polled();
    }
    Ok(mappings)
}
fn finish_attach(
    mappings: Vec<crate::bus::mmio::Mmio>,
    clock: Clock,
    location: String,
    dma: &mut dyn DmaAllocator,
    profile: Profile,
    control: Option<Control>,
) -> Attached {
    let mut attached = Attached {
        hosts: Vec::new(),
        cards: Vec::new(),
        failures: Vec::new(),
    };
    for (index, registers) in mappings.into_iter().enumerate() {
        let location = format!("{location} SD slot {index}");
        let host = if let Some(control) = &control {
            Host::new_with_controller(
                Box::new(registers),
                clock,
                location,
                dma,
                profile,
                Some(control.clone()),
            )
        } else {
            Host::new(Box::new(registers), clock, location, dma, profile)
        };
        match host {
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
    attached
}

pub use super::mmc::{CardInfo, Failure, Kind};
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
    profile: Profile,
    controller: Option<Control>,
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
    last_failure: Option<Failure>,
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
    /// Retained primary/cleanup diagnostics require no physical access.
    pub fn last_failure(&self) -> Option<Failure> {
        self.inner.borrow().last_failure.clone()
    }
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
        profile: Profile,
    ) -> Result<Self, BlockError> {
        Self::new_with_controller(registers, clock, location, dma, profile, None)
    }
    fn new_with_controller(
        registers: Box<dyn Registers>,
        clock: Clock,
        location: String,
        dma: &mut dyn DmaAllocator,
        profile: Profile,
        controller: Option<Control>,
    ) -> Result<Self, BlockError> {
        if profile.retained_config() != controller.is_some() {
            return Err(BlockError::Unsupported(
                "SDHCI retained PCI authority does not match profile",
            ));
        }
        if clock.ticks_per_microsecond == 0 {
            return Err(BlockError::Unsupported(
                "SDHCI requires a calibrated native clock",
            ));
        }
        if let Some(control) = &controller {
            control.borrow().healthy()?;
        }
        let data = dma.allocate(TRANSFER_BYTES, 64)?;
        let descriptors = dma.allocate(4096, 64)?;
        let mut engine = Engine {
            registers,
            profile,
            controller,
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
            last_failure: None,
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
        if c.profile.retained_config() && !c.o2_card_present()? {
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
            c.power_off()?;
            c.finish_ios()?;
        }
        Ok(())
    }
}
impl Engine {
    fn healthy(&self) -> Result<(), BlockError> {
        self.fault.clone().map_or(Ok(()), Err)?;
        if let Some(control) = &self.controller {
            control.borrow().healthy()?;
        }
        Ok(())
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
        self.healthy()?;
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
        self.dma_mode = if self.profile.disable_adma() || self.capabilities & CAP_ADMA2 == 0 {
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
        self.power_off()?;
        self.clock.delay(1000);
        if !self.profile.single_power_write() {
            self.registers.write8(POWER, power);
        }
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
        if let Some(control) = &self.controller {
            control.borrow_mut().before_clock()?;
        }
        let (divisor, actual) = clock_divisor(self.version, self.base_hz, hz)?;
        let field = (divisor & 0xff) << 8 | (divisor & 0x300) >> 2;
        self.registers.write16(CLOCK, field | CLOCK_INTERNAL);
        let present = if self.profile.retained_config() {
            self.o2_card_present()?
        } else {
            if !self
                .clock
                .wait(20_000, || self.registers.read16(CLOCK) & CLOCK_STABLE != 0)
            {
                return Err(BlockError::Timeout);
            }
            true
        };
        if present {
            self.registers
                .write16(CLOCK, field | CLOCK_INTERNAL | CLOCK_CARD);
        }
        if actual > hz {
            return Err(BlockError::Unsupported("SDHCI clock exceeds card limit"));
        }
        self.finish_ios()
    }
    fn power_off(&mut self) -> Result<(), BlockError> {
        if let Some(control) = &self.controller {
            self.registers.write16(CLOCK, 0);
            control.borrow_mut().power_off()?;
        }
        self.registers.write8(POWER, 0);
        Ok(())
    }
    fn o2_card_present(&mut self) -> Result<bool, BlockError> {
        let result = pci::o2_stabilize(self.registers.as_mut(), self.clock);
        if let Err(error) = &result {
            self.medium = None;
            if let Some(control) = &self.controller {
                control.borrow_mut().fail(error.clone());
            }
        }
        result
    }
    fn set_high_speed_host(&mut self) -> Result<(), BlockError> {
        let control = self.registers.read8(HOST_CONTROL) & !HIGH_SPEED;
        let high_speed = if self.profile.no_high_speed_bit() {
            0
        } else {
            HIGH_SPEED
        };
        self.set_ios_control(control | high_speed)
    }
    fn set_ios_control(&mut self, value: u8) -> Result<(), BlockError> {
        self.registers.write8(HOST_CONTROL, value);
        self.finish_ios()
    }
    fn finish_ios(&mut self) -> Result<(), BlockError> {
        // ENE CB714 signals spurious timeout/CRC after host settings change.
        // The source set_ios hook resets command/data after applying settings.
        if self.profile.reset_after_ios() {
            self.reset(RESET_COMMAND | RESET_DATA)?;
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

#[cfg(test)]
mod owned_tests {
    use super::{model::*, *};
    use crate::bus::dma::RegionAllocator;

    fn o2_slot(chip: &Rc<RefCell<O2Chip>>, kind: Kind, present: bool) -> Rc<RefCell<Hardware>> {
        let slot = Rc::new(RefCell::new(Hardware::new(kind, true)));
        {
            let mut s = slot.borrow_mut();
            s.o2_chip = Some(chip.clone());
            s.present = present;
            s.adma_broken = true;
            s.caps = (s.caps & !(255 << 8)) | 200 << 8;
        }
        chip.borrow_mut().slots.push(Rc::downgrade(&slot));
        slot
    }
    fn o2_host(
        dma: &mut dyn DmaAllocator,
        slot: &Rc<RefCell<Hardware>>,
        device: u16,
        control: &Control,
    ) -> Host {
        Host::new_with_controller(
            Box::new(Port(slot.clone())),
            Clock {
                ticks_per_microsecond: CLOCK_TICKS_PER_US,
            },
            "O2 native model".into(),
            dma,
            Profile::select(0x1217, device),
            Some(control.clone()),
        )
        .unwrap()
    }

    #[test]
    fn o2_owned_config_drives_actual_pll_pio_empty_insertion_and_power_cycles() {
        for device in [0x8220, 0x8221, 0x8320, 0x8321] {
            for kind in [Kind::Sd, Kind::Mmc] {
                let mut backing = vec![0u64; 128 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: the retained controller owns every physical buffer in this fixture.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let chip = Rc::new(RefCell::new(O2Chip::new(device)));
                let slot = o2_slot(&chip, kind, false);
                let control = Controller::model(
                    Box::new(O2ConfigPort(chip.clone())),
                    0x1217 | u32::from(device) << 16,
                );
                control.borrow_mut().prepare().unwrap();
                let mut host = o2_host(&mut dma, &slot, device, &control);
                assert!(host.poll().unwrap().is_none());
                assert!(slot.borrow().commands.is_empty());
                assert!(
                    slot.borrow()
                        .writes
                        .iter()
                        .all(|(at, _, v)| *at != CLOCK || v & u32::from(CLOCK_CARD) == 0)
                );
                slot.borrow_mut().replace();
                let mut card = host.poll().unwrap().unwrap();
                let mut clone = card.clone();
                let mut bytes = [0xa5; 1024];
                card.read(4, &mut bytes).unwrap();
                assert_eq!(bytes, [0x3c; 1024]);
                bytes.fill(0x67);
                card.write(8, &bytes).unwrap();
                card.flush().unwrap();
                assert_eq!(bytes, slot.borrow().disk[8 * 512..10 * 512]);
                assert!(
                    slot.borrow()
                        .writes
                        .iter()
                        .all(|(at, _, v)| *at != TRANSFER_MODE || v & u32::from(DMA) == 0)
                );
                card.shutdown(true).unwrap();
                assert!(host.poll().unwrap().is_some());
                let before = (
                    slot.borrow().reads,
                    slot.borrow().writes.len(),
                    chip.borrow().reads,
                    chip.borrow().writes.len(),
                );
                assert_eq!(clone.flush(), Err(BlockError::Unsupported(STALE)));
                assert_eq!(
                    (
                        slot.borrow().reads,
                        slot.borrow().writes.len(),
                        chip.borrow().reads,
                        chip.borrow().writes.len()
                    ),
                    before
                );
                assert_eq!(chip.borrow().reg32(0x304), 0x2510_551a);
                assert_eq!(chip.borrow().reg32(0x354), 0x43);
                assert!(chip.borrow().ready);
            }
        }
    }

    #[test]
    fn o2_config_fault_after_effect_relocks_and_latches_shared_refusal() {
        for after_effect in [false, true] {
            let chip = Rc::new(RefCell::new(O2Chip::new(0x8220)));
            if after_effect {
                chip.borrow_mut().read_fault_after_write = Some(0xe2);
            } else {
                chip.borrow_mut().ignore_write = Some(0xe2);
            }
            let control = Controller::model(Box::new(O2ConfigPort(chip.clone())), 0x8220_1217);
            assert!(control.borrow_mut().prepare().is_err());
            assert_ne!(chip.borrow().reg32(0xd0) & (0x80 << 24), 0);
            assert_eq!(
                (chip.borrow().reg32(0xe0) >> 16) & 255,
                if after_effect { 0x39 } else { 0 }
            );
            let before = (chip.borrow().reads, chip.borrow().writes.len());
            assert!(control.borrow_mut().prepare().is_err());
            assert_eq!((chip.borrow().reads, chip.borrow().writes.len()), before);
        }
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: both slot engines retain disjoint DMA allocations even on PCI faults.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let chip = Rc::new(RefCell::new(O2Chip::new(0x8320)));
        let slot0 = o2_slot(&chip, Kind::Sd, true);
        let slot1 = o2_slot(&chip, Kind::Sd, true);
        let control = Controller::model(Box::new(O2ConfigPort(chip.clone())), 0x8320_1217);
        control.borrow_mut().prepare().unwrap();
        let mut h0 = o2_host(&mut dma, &slot0, 0x8320, &control);
        let mut c0 = h0.poll().unwrap().unwrap();
        let mut h1 = o2_host(&mut dma, &slot1, 0x8320, &control);
        let mut c1 = h1.poll().unwrap().unwrap();
        chip.borrow_mut().read_fault_after_write = Some(0x354);
        assert!(c0.shutdown(true).is_err());
        assert_ne!(chip.borrow().reg32(0xd0) & (0x80 << 24), 0);
        let before = (
            slot0.borrow().reads,
            slot0.borrow().writes.len(),
            slot1.borrow().reads,
            slot1.borrow().writes.len(),
            chip.borrow().reads,
            chip.borrow().writes.len(),
        );
        let mut bytes = [0x95; 512];
        assert!(c0.read(0, &mut bytes).is_err());
        assert!(c1.read(0, &mut bytes).is_err());
        assert_eq!(bytes, [0x95; 512]);
        assert!(h0.poll().is_err());
        assert!(h1.poll().is_err());
        assert_eq!(
            (
                slot0.borrow().reads,
                slot0.borrow().writes.len(),
                slot1.borrow().reads,
                slot1.borrow().writes.len(),
                chip.borrow().reads,
                chip.borrow().writes.len()
            ),
            before
        );
    }

    #[test]
    fn o2_first_slot_config_fault_refuses_second_constructor_before_mmio_or_allocation() {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: the failed first constructor cannot publish or recycle these buffers.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let chip = Rc::new(RefCell::new(O2Chip::new(0x8320)));
        let slot0 = o2_slot(&chip, Kind::Sd, true);
        let slot1 = o2_slot(&chip, Kind::Sd, true);
        let control = Controller::model(Box::new(O2ConfigPort(chip.clone())), 0x8320_1217);
        control.borrow_mut().prepare().unwrap();
        chip.borrow_mut().read_fault_after_write = Some(0x354);
        let construct = |slot: &Rc<RefCell<Hardware>>, dma: &mut dyn DmaAllocator| {
            Host::new_with_controller(
                Box::new(Port(slot.clone())),
                Clock {
                    ticks_per_microsecond: CLOCK_TICKS_PER_US,
                },
                "O2 shared admission".into(),
                dma,
                Profile::select(0x1217, 0x8320),
                Some(control.clone()),
            )
        };
        assert!(construct(&slot0, &mut dma).is_err());
        assert!(!slot0.borrow().writes.is_empty());
        assert_eq!(slot1.borrow().reads, 0);
        assert!(slot1.borrow().writes.is_empty());
        assert!(control.borrow().healthy().is_err());
        let before = (chip.borrow().reads, chip.borrow().writes.len());
        struct NoAllocation;
        impl DmaAllocator for NoAllocation {
            fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
                panic!("a poisoned shared controller must refuse before DMA allocation");
            }
        }
        assert!(construct(&slot1, &mut NoAllocation).is_err());
        assert_eq!(slot1.borrow().reads, 0);
        assert!(slot1.borrow().writes.is_empty());
        assert_eq!((chip.borrow().reads, chip.borrow().writes.len()), before);
    }

    #[test]
    fn o2_failed_pll_or_card_detect_proof_cleans_force_active_and_refuses_publication() {
        for pll in [false, true] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: failed clock proof cannot publish or recycle its retained payloads.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let chip = Rc::new(RefCell::new(O2Chip::new(0x8221)));
            let slot = o2_slot(&chip, Kind::Sd, false);
            let control = Controller::model(Box::new(O2ConfigPort(chip.clone())), 0x8221_1217);
            control.borrow_mut().prepare().unwrap();
            let mut host = o2_host(&mut dma, &slot, 0x8221, &control);
            slot.borrow_mut().replace();
            if pll {
                slot.borrow_mut().o2_pll_stuck = true;
            } else {
                slot.borrow_mut().o2_cd_mismatch = true;
            }
            assert!(host.poll().is_err());
            assert!(host.inner.borrow().medium.is_none());
            assert!(slot.borrow().commands.is_empty());
            assert_eq!(
                slot.borrow()
                    .writes
                    .iter()
                    .rfind(|(at, _, _)| *at == 0x1cc)
                    .unwrap()
                    .2
                    & (1 << 18),
                0
            );
            let before = (
                slot.borrow().reads,
                slot.borrow().writes.len(),
                chip.borrow().reads,
                chip.borrow().writes.len(),
            );
            assert!(host.poll().is_err());
            assert_eq!(
                (
                    slot.borrow().reads,
                    slot.borrow().writes.len(),
                    chip.borrow().reads,
                    chip.borrow().writes.len()
                ),
                before
            );
        }
    }
}
