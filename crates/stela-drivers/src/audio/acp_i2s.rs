// SPDX-License-Identifier: GPL-2.0-only
//! Native Raven ACP3x (rev00) and Vangogh ACP5x (rev50) serial-I2S DMA.
//! Adapted from pinned Linux sound/soc/amd/{raven,vangogh}/ PCI/I2S/PCM donors
//! at a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//! Copyright (C) 2016, 2021, 2023 Advanced Micro Devices, Inc.
//!
//! One retained whole-function controller, four native stream slots. Firmware,
//! board/codec routing and serial clocks are actual platform prerequisites;
//! this module never fabricates those grants from an ID or pin configuration.
//! This controller candidate does not establish an attached codec/frontend.
pub use super::acp_pdm::{Error, Identity, Phase, Registers, State};
use super::{Direction, acp_pdm::check_dma_range};
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
    /// Raven BT interface; Vangogh HS interface. Actual board wiring selects it.
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
    /// The actual codec/board owner supplies correctly qualified BCLK/LRCLK.
    External,
    /// Actual Vangogh serial generator reference in this retained board epoch.
    /// It must equal rate * source BCLK divider * source LRCLK divider.
    Master { reference_hz: u32 },
}
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub acp_config: Option<u32>,
    pub dma_address_bits: u8,
    pub clock: Clock,
}
/// Actual cyclic ring geometry within the source's 2..8 / 1..8-KiB limits.
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
#[derive(Clone, Copy)]
struct Deadline {
    phase: Phase,
    start: u64,
    budget: u64,
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
    /// Registers retain canonical PCI/UC owners; domain is the actually attached
    /// requester/root path and source allocates qualified coherent WB RAM.
    /// External or master serial-clock evidence must be actual board/codec
    /// observations, with routing/clock ownership held through errors or drop.
    /// No parallel PDM/SDW/firmware engines may submit DMA. Native interrupts
    /// remain contained. Retain every root, pin and board grant until this
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
        match self.state {
            State::Claimed => Err(Error::NotInitialized),
            State::Faulted => Err(Error::NeedsReset),
            State::Shutdown => Err(Error::Shutdown),
            State::Suspended => Err(Error::Suspended),
            _ => Ok(()),
        }
    }
    fn read(&mut self, offset: usize) -> Result<u32, Error> {
        let value = self.registers.read32(offset);
        if value == u32::MAX {
            Err(Error::RegisterUnavailable(offset))
        } else {
            Ok(value)
        }
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
        Deadline {
            phase,
            budget,
            start: self.timer.now_us(),
        }
    }
    fn timely(&self, deadline: Deadline) -> Result<(), Error> {
        if self.timer.now_us().wrapping_sub(deadline.start) >= deadline.budget {
            Err(Error::Timeout(deadline.phase))
        } else {
            Ok(())
        }
    }
    fn phase_read(&mut self, offset: usize, deadline: Deadline) -> Result<u32, Error> {
        self.timely(deadline)?;
        let value = self.read(offset)?;
        self.timely(deadline)?;
        Ok(value)
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
        loop {
            if ready(self.phase_read(offset, deadline)?) {
                return Ok(());
            }
            self.timer.relax();
        }
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
        // SAFETY: each caller first read actual stopped engines or acknowledged
        // a whole-function reset. The attached domain/root and all pins remain.
        unsafe { self.domain.drain_posted_writes() }.map_err(Error::Dma)
    }
    fn release_streams(&mut self) -> Result<(), Error> {
        self.drain()?;
        for stream in &mut self.streams {
            if let Some(owned) = stream {
                // SAFETY: whole reset, disabled group1/BME and actual requester
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
    /// Actual whole-function reset recovery. Old mappings are released only
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
    /// Controller-level PM with the actual original PCI D0/board epoch held.
    /// Platform D3/S3/S0ix/wake transitions require the actual platform owner.
    pub fn suspend_held_d0(&mut self) -> Result<(), Error> {
        self.usable()?;
        let result = self.quiet_controller();
        if result.is_ok() {
            self.state = State::Suspended;
        }
        self.finish(result)
    }
    /// Recreate every retained stream's PTE/ring/format. Explicit start is
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
    /// Retain a nonretired controller intact; failed ownership return allocates
    /// nothing and cannot drop an active native/DMA owner.
    #[allow(clippy::result_large_err)]
    pub fn into_stopped(self) -> Result<(R, T), Self> {
        if self.state != State::Shutdown {
            Err(self)
        } else {
            Ok((self.registers, self.timer))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use alloc::vec::Vec;
    // All tests below are authored SOURCE ONLY, UNRUN until the parent's finite gate.
    #[test]
    fn actual_four_stream_pte_dma_duplex_and_independent_auxiliary_layouts() {
        for revision in [0, 0x50] {
            let (mut controller, device, source) = fixture(revision);
            controller.initialize().unwrap();
            let pcm: Vec<u8> = (0..8192).map(|index| (index * 37 + 9) as u8).collect();
            for port in PORTS {
                controller
                    .prepare(
                        port,
                        stereo(),
                        Ring {
                            period_bytes: 2048,
                            periods: 4,
                        },
                        if port.direction() == Direction::Playback {
                            Some(&pcm)
                        } else {
                            None
                        },
                        &source,
                    )
                    .unwrap();
            }
            for port in PORTS {
                controller.start(port).unwrap();
            }
            let mut capture = vec![0xa5; 2048];
            for period in 0..12u64 {
                for slot in 0..4 {
                    device.lock().unwrap().advance(slot, 256, 4);
                }
                for port in [Port::SpeakerCapture, Port::AuxiliaryCapture] {
                    assert_eq!(
                        controller.capture_period(port, &mut capture).unwrap(),
                        Some(CapturePeriod {
                            first_frame: period * 256,
                            frames: 256
                        })
                    );
                    for frame in 0..256 {
                        for channel in 0..2 {
                            let offset = frame * 8 + channel * 4;
                            assert_eq!(
                                i32::from_le_bytes(capture[offset..offset + 4].try_into().unwrap()),
                                sample(period * 256 + frame as u64, channel)
                            );
                        }
                    }
                }
                if period == 5 {
                    controller.stop(Port::SpeakerPlayback).unwrap();
                    assert_eq!(
                        device.lock().unwrap().words[0x2400 / 4],
                        1,
                        "capture keeps shared serial IER"
                    );
                    controller.start(Port::SpeakerPlayback).unwrap();
                }
            }
            for slot in [0, 2] {
                assert_eq!(device.lock().unwrap().output[slot], pcm.repeat(3));
            }
            assert_eq!(device.lock().unwrap().maps, 4);
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            controller.shutdown().unwrap();
            assert_eq!(device.lock().unwrap().unmaps, 4);
            assert_eq!(source.drops.load(Ordering::Relaxed), 4);
            assert!(controller.into_stopped().is_ok());
        }
    }
    #[test]
    fn real_retained_pte_clock_and_pcm_epochs_survive_controller_pm() {
        for revision in [0, 0x50] {
            let (mut controller, device, source) = fixture(revision);
            controller.initialize().unwrap();
            controller
                .prepare(
                    Port::AuxiliaryCapture,
                    stereo(),
                    Ring {
                        period_bytes: 1024,
                        periods: 4,
                    },
                    None,
                    &source,
                )
                .unwrap();
            let address = controller.streams[3]
                .as_ref()
                .unwrap()
                .dma
                .address()
                .unwrap();
            controller.start(Port::AuxiliaryCapture).unwrap();
            device.lock().unwrap().advance(3, 128, 4);
            let mut output = vec![0; 1024];
            assert!(
                controller
                    .capture_period(Port::AuxiliaryCapture, &mut output)
                    .unwrap()
                    .is_some()
            );
            controller.suspend_held_d0().unwrap();
            assert_eq!(controller.state(), State::Suspended);
            assert_eq!(device.lock().unwrap().unmaps, 0);
            if revision == 0 {
                assert_eq!(device.lock().unwrap().words[0x1418 / 4], 0x40);
            } else {
                assert_eq!(device.lock().unwrap().words[0x142c / 4], 0);
                assert_eq!(device.lock().unwrap().words[0x1004 / 4], 0);
            }
            controller.resume_held_d0().unwrap();
            assert_eq!(controller.state(), State::Prepared);
            assert_eq!(
                controller.streams[3]
                    .as_ref()
                    .unwrap()
                    .dma
                    .address()
                    .unwrap(),
                address
            );
            controller.start(Port::AuxiliaryCapture).unwrap();
            assert_eq!(
                controller
                    .capture_period(Port::AuxiliaryCapture, &mut output)
                    .unwrap(),
                None
            );
            device.lock().unwrap().advance(3, 128, 4);
            assert_eq!(
                controller
                    .capture_period(Port::AuxiliaryCapture, &mut output)
                    .unwrap()
                    .unwrap()
                    .first_frame,
                0
            );
            assert_eq!(
                i32::from_le_bytes(output[..4].try_into().unwrap()),
                sample(128, 0)
            );
            controller.shutdown().unwrap();
            assert_eq!(device.lock().unwrap().maps, 1);
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn malformed_formats_master_ratios_and_link_pair_conflicts_have_no_dma_effects() {
        let (mut controller, device, source) = fixture(0x50);
        controller.initialize().unwrap();
        for format in [
            Format {
                rate: 192_000,
                ..stereo()
            },
            Format {
                channels: 8,
                ..stereo()
            },
            Format {
                signal: Signal::DspA {
                    slots: 1,
                    slot_bits: 32,
                },
                ..stereo()
            },
            Format {
                signal: Signal::DspA {
                    slots: 2,
                    slot_bits: 16,
                },
                ..stereo()
            },
        ] {
            assert!(
                controller
                    .prepare(
                        Port::SpeakerCapture,
                        format,
                        Ring {
                            period_bytes: 1024,
                            periods: 4
                        },
                        None,
                        &source
                    )
                    .is_err()
            );
        }
        assert_eq!(device.lock().unwrap().maps, 0);
        controller.config.clock = Clock::Master {
            reference_hz: 196_608_000,
        };
        assert_eq!(
            controller.master_control(stereo()).unwrap(),
            Some(1 | (64 << 2) | (64 << 11))
        );
        assert!(
            controller
                .master_control(Format {
                    rate: 44_100,
                    ..stereo()
                })
                .is_err()
        );
        controller.config.clock = Clock::Master {
            reference_hz: 180_633_600,
        };
        assert!(
            controller
                .master_control(Format {
                    rate: 44_100,
                    ..stereo()
                })
                .is_ok()
        );
        controller.config.clock = Clock::External;
        controller
            .prepare(
                Port::SpeakerCapture,
                stereo(),
                Ring {
                    period_bytes: 1024,
                    periods: 4,
                },
                None,
                &source,
            )
            .unwrap();
        let pcm = vec![0; 4096];
        assert_eq!(
            controller.prepare(
                Port::SpeakerPlayback,
                Format {
                    rate: 44_100,
                    ..stereo()
                },
                Ring {
                    period_bytes: 1024,
                    periods: 4
                },
                Some(&pcm),
                &source
            ),
            Err(Error::InvalidFormat)
        );
        controller.shutdown().unwrap();
    }
    #[test]
    fn capture_coalescing_overrun_and_mid_copy_race_never_publish_stale_periods() {
        for race in [false, true] {
            let (mut controller, device, source) = fixture(0);
            controller.initialize().unwrap();
            controller
                .prepare(
                    Port::SpeakerCapture,
                    stereo(),
                    Ring {
                        period_bytes: 1024,
                        periods: 4,
                    },
                    None,
                    &source,
                )
                .unwrap();
            controller.start(Port::SpeakerCapture).unwrap();
            device
                .lock()
                .unwrap()
                .advance(1, if race { 128 } else { 512 }, 4);
            if race {
                let mut model = device.lock().unwrap();
                model.race_copy = Some((model.coherent + 3, 1, 384));
            }
            let mut pcm = vec![0; 1024];
            assert!(matches!(
                controller.capture_period(Port::SpeakerCapture, &mut pcm),
                Err(Error::CaptureOverrun { .. })
            ));
            assert_eq!(controller.streams[1].as_ref().unwrap().consumed, 0);
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            controller.shutdown().unwrap();
        }
    }
    #[test]
    fn stop_payload_drain_and_faulted_reset_do_not_release_a_published_iova() {
        let (mut controller, device, source) = fixture(0x50);
        controller.initialize().unwrap();
        controller
            .prepare(
                Port::AuxiliaryCapture,
                stereo(),
                Ring {
                    period_bytes: 1024,
                    periods: 4,
                },
                None,
                &source,
            )
            .unwrap();
        controller.start(Port::AuxiliaryCapture).unwrap();
        {
            let mut model = device.lock().unwrap();
            model.defer_payload = true;
            model.advance(3, 128, 4);
            model.drain_fail = true;
        }
        assert_eq!(
            controller.stop(Port::AuxiliaryCapture),
            Err(Error::Dma(
                crate::bus::dma::mapping::DmaError::InvalidationFailed
            ))
        );
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert_eq!(device.lock().unwrap().unmaps, 0);
        device.lock().unwrap().reset_never = true;
        assert_eq!(
            controller.shutdown(),
            Err(Error::Timeout(Phase::ResetClear))
        );
        assert_eq!(device.lock().unwrap().unmaps, 0);
        {
            let mut model = device.lock().unwrap();
            model.reset_never = false;
            model.drain_fail = false;
        }
        controller.shutdown().unwrap();
        assert!(device.lock().unwrap().posted.is_empty());
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn actual_pin_pte_pci_and_clock_authority_loss_quarantine_dma() {
        for fault in 0..4 {
            let (mut controller, device, source) = fixture(0x50);
            controller.initialize().unwrap();
            controller
                .prepare(
                    Port::SpeakerCapture,
                    stereo(),
                    Ring {
                        period_bytes: 1024,
                        periods: 4,
                    },
                    None,
                    &source,
                )
                .unwrap();
            controller.start(Port::SpeakerCapture).unwrap();
            {
                let mut model = device.lock().unwrap();
                match fault {
                    0 => model.words[0x1400 / 4] = 4,
                    1 => model.words[0x10100 / 4] ^= 0x1000,
                    2 => model.identity.device ^= 1,
                    _ => model.words[0x142c / 4] = 0,
                }
            }
            assert!(controller.position(Port::SpeakerCapture).is_err());
            assert_eq!(controller.state(), State::Faulted);
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            {
                let mut model = device.lock().unwrap();
                model.identity.device = 0x15e2;
            }
            controller.shutdown().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn successful_but_late_power_start_and_stop_effects_retain_original_owners() {
        for phase in [Phase::PowerOn, Phase::DmaStart, Phase::DmaStop] {
            let (mut controller, device, source) = fixture(0x50);
            if phase != Phase::PowerOn {
                controller.initialize().unwrap();
                controller
                    .prepare(
                        Port::SpeakerCapture,
                        stereo(),
                        Ring {
                            period_bytes: 1024,
                            periods: 4,
                        },
                        None,
                        &source,
                    )
                    .unwrap();
            }
            if phase == Phase::DmaStop {
                controller.start(Port::SpeakerCapture).unwrap();
            }
            let (offset, value, budget) = match phase {
                Phase::PowerOn => (0x1424, 1, 501),
                Phase::DmaStart => (0x2404, 41, 100001),
                _ => (0x2404, 40, 100001),
            };
            device.lock().unwrap().jump_write = Some((offset, value, budget));
            let result = match phase {
                Phase::PowerOn => controller.initialize(),
                Phase::DmaStart => controller.start(Port::SpeakerCapture),
                _ => controller.stop(Port::SpeakerCapture),
            };
            assert_eq!(result, Err(Error::Timeout(phase)));
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            assert_eq!(device.lock().unwrap().unmaps, 0);
            controller.shutdown().unwrap();
        }
    }
    #[test]
    fn exact_generation_admission_and_active_drop_do_not_invent_native_completion() {
        for revision in 0..=255 {
            assert_eq!(
                Generation::identify(Identity {
                    vendor: 0x1022,
                    device: 0x15e2,
                    revision
                })
                .is_ok(),
                matches!(revision, 0 | 0x50)
            );
        }
        let (mut controller, device, source) = fixture(0);
        controller.initialize().unwrap();
        controller
            .prepare(
                Port::SpeakerCapture,
                stereo(),
                Ring {
                    period_bytes: 1024,
                    periods: 4,
                },
                None,
                &source,
            )
            .unwrap();
        controller.start(Port::SpeakerCapture).unwrap();
        drop(controller);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert_eq!(device.lock().unwrap().unmaps, 0);
        device.lock().unwrap().advance(1, 128, 4);
    }
    #[test]
    fn coherent_capability_and_failed_resume_preserve_published_and_unpublished_leases() {
        let (mut controller, device, source) = fixture(0x50);
        controller.initialize().unwrap();
        device.lock().unwrap().coherent_fail = true;
        assert_eq!(
            controller.prepare(
                Port::SpeakerCapture,
                stereo(),
                Ring {
                    period_bytes: 1024,
                    periods: 4
                },
                None,
                &source
            ),
            Err(Error::Dma(
                crate::bus::dma::mapping::DmaError::CoherenceUnavailable
            ))
        );
        assert_eq!(device.lock().unwrap().unmaps, 1);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        device.lock().unwrap().coherent_fail = false;
        controller.initialize().unwrap();
        controller
            .prepare(
                Port::SpeakerCapture,
                stereo(),
                Ring {
                    period_bytes: 1024,
                    periods: 4,
                },
                None,
                &source,
            )
            .unwrap();
        controller.start(Port::SpeakerCapture).unwrap();
        controller.suspend_held_d0().unwrap();
        let address = controller.streams[1]
            .as_ref()
            .unwrap()
            .dma
            .address()
            .unwrap();
        {
            let mut model = device.lock().unwrap();
            model.words[0x10104 / 4] = 0; // Actual retained SRAM was lost across suspend.
            model.ignore = Some(0x10104);
        }
        assert_eq!(
            controller.resume_held_d0(),
            Err(Error::RegisterRejected(0x10104))
        );
        assert_eq!(
            controller.streams[1]
                .as_ref()
                .unwrap()
                .dma
                .address()
                .unwrap(),
            address
        );
        assert_eq!(device.lock().unwrap().unmaps, 1);
        device.lock().unwrap().ignore = None;
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn full_counter_halves_and_partial_frames_do_not_alias_the_raven_header_or_bug() {
        let (mut controller, device, source) = fixture(0);
        controller.initialize().unwrap();
        controller
            .prepare(
                Port::SpeakerCapture,
                stereo(),
                Ring {
                    period_bytes: 1024,
                    periods: 4,
                },
                None,
                &source,
            )
            .unwrap();
        device.lock().unwrap().count[1] = 0x1_ffff_ffff;
        controller.start(Port::SpeakerCapture).unwrap();
        assert_eq!(
            controller.streams[1].as_ref().unwrap().baseline,
            0x1_ffff_ffff
        );
        device.lock().unwrap().advance(1, 128, 4);
        let mut pcm = vec![0; 1024];
        assert_eq!(
            controller
                .capture_period(Port::SpeakerCapture, &mut pcm)
                .unwrap()
                .unwrap()
                .first_frame,
            0
        );
        device.lock().unwrap().count[1] += 3;
        assert_eq!(
            controller.position(Port::SpeakerCapture).unwrap().bytes,
            1024
        );
        controller.shutdown().unwrap();
    }
    #[test]
    #[ignore = "requires unchanged Linux trace in STELA_ACP_I2S_ORACLE"]
    fn unchanged_linux_acp3x_acp5x_dma_configuration() {
        extern crate std;
        use std::fmt::Write;
        let original =
            std::fs::read_to_string(std::env::var("STELA_ACP_I2S_ORACLE").unwrap()).unwrap();
        let mut actual =
            std::string::String::from("linux a804c5742bff224d4cb4d25dd383554d598be32b\n");
        for revision in [0, 0x50] {
            for port in PORTS {
                let (mut controller, device, source) = fixture(revision);
                controller.initialize().unwrap();
                device.lock().unwrap().writes.clear();
                let pcm = vec![0x37; 12288];
                controller
                    .prepare(
                        port,
                        stereo(),
                        Ring {
                            period_bytes: 3072,
                            periods: 4,
                        },
                        if port.direction() == Direction::Playback {
                            Some(&pcm)
                        } else {
                            None
                        },
                        &source,
                    )
                    .unwrap();
                writeln!(actual, "case {revision:02x} {}", port as usize).unwrap();
                let regs = controller.generation.stream(port);
                let first_pte = SCRATCH + regs.pte;
                for (offset, value) in &device.lock().unwrap().writes {
                    if (*offset == PAGE_BASE && *value == SRAM | PTE_VALID)
                        || *offset == PAGE_SIZE
                        || (*offset == IRQ_CONTROL && *value != 0)
                        || [
                            regs.ring,
                            regs.fifo_address(),
                            regs.fifo_size(),
                            regs.dma_size(),
                        ]
                        .contains(offset)
                        || (first_pte..first_pte + 3 * 8).contains(offset)
                    {
                        writeln!(actual, "w {offset:04x} {value:08x}").unwrap();
                    }
                }
                controller.shutdown().unwrap();
            }
        }
        assert_eq!(actual, original);
    }
}
