// SPDX-License-Identifier: GPL-2.0-only
//! Native Raven ACP3x (rev00) and Vangogh ACP5x (rev50) serial-I2S DMA.
//! Adapted from pinned Linux sound/soc/amd/{raven,vangogh}/ PCI/I2S/PCM donors
//! at a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//! Copyright (C) 2016, 2021, 2023 Advanced Micro Devices, Inc.
//!
//! One kept whole-function controller, four native stream slots. Firmware,
//! board/codec routing and serial clocks are platform prerequisites;
//! this module never invents those grants from an ID or pin configuration.
//! This controller candidate does not establish an attached codec/frontend.
pub use super::acp_pdm::{Error, Identity, Phase, Registers, State};
use super::{
    Direction,
    acp_pdm::{
        access::{self, Deadline},
        check_dma_range,
    },
};
use crate::bus::{
    dma::{
        mapping::{Direction as DmaDirection, DmaDomain, DmaMapping},
        memory::{CacheAttribute, CpuMapping, PageSource},
    },
    i2c::Timer,
};
use alloc::sync::Arc;
use core::sync::atomic::{Ordering, fence};
pub mod pci;
mod registers;
mod stream;
#[cfg(test)]
mod test_support;
use registers::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    Raven,
    Vangogh,
}
impl Generation {
    fn identify(identity: Identity) -> Result<Self, Error> {
        if identity.vendor != 0x1022 || identity.device != 0x15e2 {
            return Err(Error::UnsupportedController);
        }
        match identity.revision {
            0 => Ok(Self::Raven),
            0x50 => Ok(Self::Vangogh),
            _ => Err(Error::UnsupportedController),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Port {
    SpeakerPlayback = 0,
    SpeakerCapture = 1,
    /// Raven BT interface; Vangogh HS interface. Board wiring selects it.
    AuxiliaryPlayback = 2,
    AuxiliaryCapture = 3,
}
impl Port {
    fn direction(self) -> Direction {
        if (self as u8).is_multiple_of(2) {
            Direction::Playback
        } else {
            Direction::Capture
        }
    }
    fn paired(self) -> usize {
        self as usize ^ 1
    }
}
const PORTS: [Port; 4] = [
    Port::SpeakerPlayback,
    Port::SpeakerCapture,
    Port::AuxiliaryPlayback,
    Port::AuxiliaryCapture,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sample {
    Unsigned8,
    Signed8,
    Signed16,
    Signed32,
}
impl Sample {
    fn bytes(self) -> usize {
        match self {
            Self::Unsigned8 | Self::Signed8 => 1,
            Self::Signed16 => 2,
            Self::Signed32 => 4,
        }
    }
    fn resolution(self) -> u32 {
        match self {
            Self::Unsigned8 | Self::Signed8 => 0,
            Self::Signed16 => 2,
            Self::Signed32 => 5,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    I2s,
    DspA { slots: u8, slot_bits: u8 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    pub rate: u32,
    pub channels: u8,
    pub sample: Sample,
    pub signal: Signal,
}
impl Format {
    fn frame_bytes(self) -> usize {
        usize::from(self.channels) * self.sample.bytes()
    }
    fn frame_control(self) -> Result<Option<u32>, Error> {
        match self.signal {
            Signal::I2s if self.channels == 2 => Ok(None),
            Signal::DspA { slots, slot_bits }
                if (2..=8).contains(&slots)
                    && self.channels <= slots
                    && usize::from(slot_bits) >= self.sample.bytes() * 8
                    && matches!(slot_bits, 8 | 16 | 24 | 32) =>
            {
                let width = if slot_bits == 32 {
                    0
                } else {
                    u32::from(slot_bits)
                };
                Ok(Some(
                    FRAME_LENGTH | (u32::from(slots) << 15) | (width << 18),
                ))
            }
            _ => Err(Error::InvalidFormat),
        }
    }
    fn validate(self, generation: Generation, port: Port) -> Result<(), Error> {
        if !matches!(
            self.rate,
            8_000 | 11_025 | 16_000 | 22_050 | 32_000 | 44_100 | 48_000 | 88_200 | 96_000
        ) || !(2..=8).contains(&self.channels)
            || (generation == Generation::Vangogh && self.channels != 2)
            || (port.direction() == Direction::Capture
                && (self.channels != 2 || (generation == Generation::Raven && self.rate > 48_000)))
        {
            return Err(Error::InvalidFormat);
        }
        self.frame_control().map(|_| ())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clock {
    /// The codec/board owner supplies correctly checked BCLK/LRCLK.
    External,
    /// Vangogh serial generator reference in this board epoch.
    /// It must equal rate * source BCLK divider * source LRCLK divider.
    Master { reference_hz: u32 },
}
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub acp_config: Option<u32>,
    pub dma_address_bits: u8,
    pub clock: Clock,
}
/// Cyclic ring geometry within the source's 2..8 / 1..8-KiB limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring {
    pub period_bytes: usize,
    pub periods: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub bytes: u64,
    pub ring_offset: usize,
    pub period_pending: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapturePeriod {
    pub first_frame: u64,
    pub frames: usize,
}
struct Stream {
    cpu: CpuMapping,
    dma: DmaMapping,
    published: bool,
    format: Format,
    period: usize,
    bytes: usize,
    control: u32,
    running: bool,
    started: bool,
    baseline: u64,
    produced: u64,
    completed: u64,
    consumed: u64,
}
impl Drop for Stream {
    fn drop(&mut self) {
        if !self.published && self.dma.address().is_ok() {
            // SAFETY: this IOVA was never supplied to a device.
            let _ = unsafe { self.dma.unmap() };
        }
        // Published mappings remain quarantined by the canonical DMA owner.
    }
}
pub struct Controller<R, T> {
    registers: R,
    timer: T,
    domain: Arc<dyn DmaDomain>,
    identity: Identity,
    generation: Generation,
    config: Config,
    saved_pme: Option<u32>,
    state: State,
    first_error: Option<Error>,
    streams: [Option<Stream>; 4],
}
impl<R: Registers, T: Timer> Controller<R, T> {
    /// Claim without any MMIO writes. No firmware/board resources are inferred.
    ///
    /// # Safety
    /// The exact function's PCI D0, board rails, clocks, codec routing and
    /// firmware/SOF/AML/SMM/CPU exclusion remain owned for this entire epoch.
    /// Registers keep canonical PCI/UC owners; domain is the attached
    /// requester/root path and source allocates checked coherent WB RAM.
    /// External or master serial-clock evidence must be board/codec
    /// observations, with routing/clock ownership held through errors or drop.
    /// No parallel PDM/SDW/firmware engines may submit DMA. Native interrupts
    /// remain contained. Keep every root, pin and board grant until this
    /// controller acknowledges complete stop/reset/drain and retirement.
    pub unsafe fn claim(
        mut registers: R,
        timer: T,
        domain: Arc<dyn DmaDomain>,
        config: Config,
    ) -> Result<Self, Error> {
        if !(32..=63).contains(&config.dma_address_bits) {
            return Err(Error::InvalidConfiguration);
        }
        if registers.region_bytes() < REGION_BYTES {
            return Err(Error::InvalidBar);
        }
        let identity = registers.identity()?;
        let generation = Generation::identify(identity)?;
        if generation == Generation::Vangogh && config.acp_config != Some(8) {
            return Err(Error::Ownership);
        }
        if generation == Generation::Raven && config.clock != Clock::External {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            registers,
            timer,
            domain,
            identity,
            generation,
            config,
            saved_pme: None,
            state: State::Claimed,
            first_error: None,
            streams: core::array::from_fn(|_| None),
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn first_error(&self) -> Option<Error> {
        self.first_error
    }
    pub fn generation(&self) -> Generation {
        self.generation
    }
    fn finish<U>(&mut self, result: Result<U, Error>) -> Result<U, Error> {
        if let Err(error) = &result {
            self.first_error.get_or_insert(*error);
            self.state = State::Faulted;
        }
        result
    }
    fn usable(&self) -> Result<(), Error> {
        access::usable(self.state)
    }
    fn read(&mut self, offset: usize) -> Result<u32, Error> {
        access::read(&mut self.registers, offset)
    }
    fn expect(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        if self.read(offset)? == value {
            Ok(())
        } else {
            Err(Error::RegisterRejected(offset))
        }
    }
    fn write(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.registers.write32(offset, value);
        self.expect(offset, value)
    }
    fn deadline(&self, phase: Phase, budget: u64) -> Deadline {
        Deadline::new(phase, self.timer.now_us(), budget)
    }
    fn timely(&self, deadline: Deadline) -> Result<(), Error> {
        deadline.check(&self.timer)
    }
    fn phase_read(&mut self, offset: usize, deadline: Deadline) -> Result<u32, Error> {
        access::phase_read(&mut self.registers, &self.timer, offset, deadline)
    }
    fn phase_write(&mut self, offset: usize, value: u32, deadline: Deadline) -> Result<(), Error> {
        self.timely(deadline)?;
        self.registers.write32(offset, value);
        self.timely(deadline)
    }
    fn wait(
        &mut self,
        offset: usize,
        deadline: Deadline,
        ready: impl Fn(u32) -> bool,
    ) -> Result<(), Error> {
        access::wait(&mut self.registers, &self.timer, offset, deadline, ready)
    }
    fn associated(&mut self) -> Result<(), Error> {
        if self.registers.identity()? == self.identity {
            Ok(())
        } else {
            Err(Error::AuthorityChanged)
        }
    }
    fn quiet_engines(&mut self) -> Result<(), Error> {
        for port in PORTS {
            if self.read(self.generation.stream(port).enable)? & STREAM_ENABLE != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    fn live(&mut self) -> Result<(), Error> {
        self.associated()?;
        if self.read(PIN_CONFIG)? != self.generation.pin_mode() || self.read(IRQ_ENABLE)? != 1 {
            return Err(Error::AuthorityChanged);
        }
        let power = self.read(self.generation.power_status())?;
        if (self.generation == Generation::Raven && power != 0) || power & POWER_MASK != 0 {
            return Err(Error::AuthorityChanged);
        }
        if self.generation == Generation::Vangogh
            && (self.read(CLOCK)? != CLOCK_ON || self.read(CONTROL)? != 1)
        {
            return Err(Error::AuthorityChanged);
        }
        let status = self.read(IRQ_STATUS)?;
        if status & ERROR_IRQ != 0 {
            return Err(Error::DmaFault(status));
        }
        Ok(())
    }
    fn reset(&mut self) -> Result<(), Error> {
        let assert = self.deadline(Phase::ResetAssert, POWER_TIMEOUT_US);
        self.phase_write(RESET, 1, assert)?;
        self.wait(RESET, assert, |value| value & RESET_ACK != 0)?;
        let clear = self.deadline(Phase::ResetClear, POWER_TIMEOUT_US);
        self.phase_write(RESET, 0, clear)?;
        self.wait(RESET, clear, |value| value == 0)?;
        self.quiet_engines()
    }
    fn drain(&self) -> Result<(), Error> {
        // SAFETY: each caller first read stopped engines or acknowledged
        // a whole-function reset. The attached domain/root and all pins remain.
        unsafe { self.domain.drain_posted_writes() }.map_err(Error::Dma)
    }
    fn release_streams(&mut self) -> Result<(), Error> {
        self.drain()?;
        for stream in &mut self.streams {
            if let Some(owned) = stream {
                // SAFETY: whole reset, disabled group1/BME and requester
                // payload drain were established before releasing any lease.
                unsafe { owned.dma.unmap() }.map_err(Error::Dma)?;
            }
            *stream = None;
        }
        Ok(())
    }
    fn initialize_inner(&mut self) -> Result<(), Error> {
        self.associated()?;
        if self.generation == Generation::Raven && self.saved_pme.is_none() {
            self.saved_pme = Some(self.read(self.generation.pme())?);
        }
        let power_reg = self.generation.power_status();
        let deadline = self.deadline(Phase::PowerOn, POWER_TIMEOUT_US);
        let power = self.phase_read(power_reg, deadline)?;
        if power != 0 {
            if power & POWER_MASK != POWER_ON {
                self.phase_write(self.generation.power_control(), POWER_ON, deadline)?;
            }
            let generation = self.generation;
            self.wait(power_reg, deadline, |value| {
                if generation == Generation::Raven {
                    value == 0
                } else {
                    value & POWER_MASK == 0
                }
            })?;
            if self.generation == Generation::Raven {
                self.write(self.generation.pme(), self.saved_pme.unwrap())?;
            }
        }
        if self.generation == Generation::Vangogh {
            self.write(CONTROL, 1)?;
        }
        self.reset()?;
        if self.generation == Generation::Vangogh {
            self.write(CLOCK, CLOCK_ON)?;
        }
        self.write(PAGE_BASE, 0)?;
        self.registers.set_bus_master(false)?;
        self.drain()?;
        self.registers.write32(IRQ_STATUS, u32::MAX);
        self.write(IRQ_CONTROL, 0)?;
        self.write(IRQ_ENABLE, 1)?;
        if self.read(PIN_CONFIG)? != self.generation.pin_mode() {
            return Err(Error::UnsupportedPinMode(self.read(PIN_CONFIG)?));
        }
        Ok(())
    }
    /// Whole-function reset recovery. Old mappings are released only
    /// after complete acknowledged reset, group1/BME containment and domain drain.
    pub fn initialize(&mut self) -> Result<(), Error> {
        if self.state == State::Shutdown {
            return Err(Error::Shutdown);
        }
        self.state = State::Faulted;
        let result = (|| {
            self.initialize_inner()?;
            self.release_streams()?;
            self.state = State::Ready;
            Ok(())
        })();
        self.finish(result)
    }
    fn quiet_controller(&mut self) -> Result<(), Error> {
        self.associated()?;
        for port in PORTS {
            self.stop_inner(port)?;
        }
        self.registers.write32(IRQ_STATUS, u32::MAX);
        self.write(IRQ_CONTROL, 0)?;
        self.write(IRQ_ENABLE, 0)?;
        self.reset()?;
        self.write(PAGE_BASE, 0)?;
        self.registers.set_bus_master(false)?;
        self.drain()?;
        if self.generation == Generation::Vangogh {
            self.write(CLOCK, 0)?;
            self.write(CONTROL, 0)?;
        }
        Ok(())
    }
    /// Controller-level PM with the original PCI D0/board epoch held.
    /// Platform D3/S3/S0ix/wake transitions require the platform owner.
    pub fn suspend_held_d0(&mut self) -> Result<(), Error> {
        self.usable()?;
        let result = self.quiet_controller();
        if result.is_ok() {
            self.state = State::Suspended;
        }
        self.finish(result)
    }
    /// Recreate every stream's PTE/ring/format. Explicit start is
    /// required; old PCM/counter progress never appears as resumed capture.
    pub fn resume_held_d0(&mut self) -> Result<(), Error> {
        match self.state {
            State::Suspended => (),
            State::Faulted => return Err(Error::NeedsReset),
            State::Shutdown => return Err(Error::Shutdown),
            _ => return Err(Error::NotSuspended),
        }
        let result = (|| {
            self.initialize_inner()?;
            for port in PORTS {
                if let Some(stream) = self.streams[port as usize].as_ref() {
                    stream
                        .dma
                        .sync_for_device(0..stream.dma.bytes())
                        .map_err(Error::Dma)?;
                    if port.direction() == Direction::Capture {
                        stream.dma.read_coherent_u32(0).map_err(Error::Dma)?;
                    }
                    self.program(port)?;
                }
            }
            if self.streams.iter().any(Option::is_some) {
                fence(Ordering::Release);
                // Source ATU_CTRL bit0 requests cache invalidation; it is not
                // an enable/disable latch or an acknowledged completion bit.
                self.registers.write32(ATU_CONTROL, 1);
                self.state = State::Prepared;
            } else {
                self.state = State::Ready;
            }
            Ok(())
        })();
        self.finish(result)
    }
    pub fn shutdown(&mut self) -> Result<(), Error> {
        if self.state == State::Shutdown {
            return Ok(());
        }
        let result = (|| {
            if self.state == State::Suspended {
                self.initialize_inner()?;
            }
            self.quiet_controller()?;
            self.release_streams()?;
            self.state = State::Shutdown;
            Ok(())
        })();
        self.finish(result)
    }
    /// Keep a nonretired controller intact; failed ownership return allocates
    /// nothing and cannot drop an active native/DMA owner.
    #[allow(
        clippy::result_large_err,
        reason = "A controller that has not acknowledged shutdown must return its original register and clock owners intact"
    )]
    pub fn into_stopped(self) -> Result<(R, T), Self> {
        if self.state != State::Shutdown {
            Err(self)
        } else {
            Ok((self.registers, self.timer))
        }
    }
}

#[cfg(test)]
mod tests;
