// SPDX-License-Identifier: GPL-2.0-only
//! Shared owned direct-PDM PCM, deadline and DMA lifecycle. Hardware profiles
//! retain their own source admission and actual register facts. Adapted from
//! AMD Linux yc (2021) and renoir (2020), at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//! Copyright (C) 2020, 2021 Advanced Micro Devices, Inc.
use alloc::sync::Arc;
use core::sync::atomic::{Ordering, fence};

use super::PcmFormat;
use crate::bus::{
    dma::{
        mapping::{Direction as DmaDirection, DmaDomain, DmaError, DmaMapping},
        memory::{CacheAttribute, CpuMapping, MemoryError, PageSource},
    },
    i2c::Timer,
};
pub(super) mod pci;
pub(super) mod registers;
pub use registers::Registers;
use registers::*;

pub const CAPTURE_FORMAT: PcmFormat = PcmFormat {
    rate: 48_000,
    bits: 32,
    channels: 2,
};
const PAGE_BYTES: usize = 4096;
const FRAME_BYTES: usize = 8;
const DMA_TIMEOUT_US: u64 = 100_000;
const POWER_TIMEOUT_US: u64 = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub vendor: u16,
    pub device: u16,
    pub revision: u8,
}
/// Sealed hardware profile. Only the two source-reviewed direct PDM variants
/// implement this interface; a matching PCI ID never selects register behavior.
pub trait Profile {
    const POWER_CONTROL: usize;
    const POWER_STATUS: usize;
    const CLOCK: usize;
    const IRQ_ENABLE: usize;
    const IRQ_CONTROL: usize;
    const IRQ_STATUS: usize;
    const SRAM_TABLE: u32;
    const ERROR_ENABLE: u32;
    const REQUIRE_DRAIN: bool;
    const PERIOD_DELIVERY: bool;
    fn supported(identity: Identity) -> bool;
    fn class_allowed(class: [u8; 3]) -> bool;
    fn pin_mode<R: Registers>(registers: &mut R) -> Result<Option<u32>, Error>;
    fn validate_pin(mode: Option<u32>, identity: Identity) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DmaConfig {
    pub(super) dma_address_bits: u8,
    pub(super) gain: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    PowerOn,
    PowerOff,
    ResetAssert,
    ResetClear,
    DmaStart,
    DmaStop,
}
#[derive(Clone, Copy)]
struct Deadline {
    phase: Phase,
    start: u64,
    timeout: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Ownership,
    MicrophoneAbsent,
    UnsupportedController,
    PciAuthority,
    InvalidConfiguration,
    InvalidBar,
    UnsupportedPinMode(u32),
    AuthorityChanged,
    RegisterUnavailable(usize),
    RegisterRejected(usize),
    Timeout(Phase),
    NotInitialized,
    Suspended,
    NotSuspended,
    NotPrepared,
    Busy,
    InvalidFormat,
    InvalidBuffer,
    Memory(MemoryError),
    Dma(DmaError),
    DmaAddress,
    DmaFault(u32),
    CounterUnstable,
    CounterDiscontinuity,
    CaptureOverrun { produced: u64, consumed: u64 },
    NeedsReset,
    Shutdown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Claimed,
    Ready,
    Prepared,
    Running,
    Stopped,
    Faulted,
    Suspended,
    Shutdown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    /// Bytes since the latest start, including complete ring wraps.
    pub bytes: u64,
    pub ring_offset: usize,
    pub period_pending: bool,
}
/// One successfully copied source-completed period. Individual device words
/// are observed coherently; this is not an atomic multiword DMA snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapturePeriod {
    pub first_frame: u64,
    pub frames: usize,
}
pub(super) struct Capture {
    pub(super) cpu: CpuMapping,
    pub(super) dma: DmaMapping,
    pub(super) published: bool,
    pub(super) period_bytes: usize,
    pub(super) baseline: u64,
    pub(super) produced: u64,
    completed: u64,
    consumed: u64,
}

impl Drop for Capture {
    fn drop(&mut self) {
        if !self.published && self.dma.address().is_ok() {
            // SAFETY: no device has received this mapping's address.
            let _ = unsafe { self.dma.unmap() };
        }
        // A published still-live lease is quarantined by DmaMapping's Drop.
    }
}

pub struct Controller<R, T, P: Profile> {
    _profile: core::marker::PhantomData<P>,
    registers: R,
    timer: T,
    pub(super) config: DmaConfig,
    identity: Identity,
    pin_mode: Option<u32>,
    state: State,
    first_error: Option<Error>,
    pub(super) capture: Option<Capture>,
    pub(super) domain: Arc<dyn DmaDomain>,
}
impl<R: Registers, T: Timer, P: Profile> Controller<R, T, P> {
    pub(super) fn claim_profile(
        mut registers: R,
        timer: T,
        config: DmaConfig,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        if !(32..=63).contains(&config.dma_address_bits) || config.gain > 3 {
            return Err(Error::InvalidConfiguration);
        }
        if registers.region_bytes() < REGION_BYTES {
            return Err(Error::InvalidBar);
        }
        let identity = registers.identity()?;
        if !P::supported(identity) {
            return Err(Error::UnsupportedController);
        }
        Ok(Self {
            _profile: core::marker::PhantomData,
            registers,
            timer,
            config,
            identity,
            pin_mode: None,
            state: State::Claimed,
            first_error: None,
            capture: None,
            domain,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// The first actual hardware/lifecycle failure in this ownership epoch.
    /// Cleanup failures, NeedsReset and successful recovery never overwrite
    /// this diagnostic. Invalid requests rejected before effects do not latch.
    pub fn first_error(&self) -> Option<Error> {
        self.first_error
    }
    pub fn buffer_bytes(&self) -> Option<usize> {
        self.capture
            .as_ref()
            .map(|capture| capture.period_bytes * 4)
    }

    fn read(&mut self, offset: usize) -> Result<u32, Error> {
        let value = self.registers.read32(offset);
        if value == u32::MAX {
            Err(Error::RegisterUnavailable(offset))
        } else {
            Ok(value)
        }
    }
    fn write_checked(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.registers.write32(offset, value);
        let observed = if value == u32::MAX {
            self.registers.read32(offset)
        } else {
            self.read(offset)?
        };
        if observed != value {
            return Err(Error::RegisterRejected(offset));
        }
        Ok(())
    }
    fn deadline(&self, phase: Phase, timeout: u64) -> Deadline {
        Deadline {
            phase,
            start: self.timer.now_us(),
            timeout,
        }
    }
    fn check_deadline(&self, deadline: Deadline) -> Result<(), Error> {
        if self.timer.now_us().wrapping_sub(deadline.start) >= deadline.timeout {
            return Err(Error::Timeout(deadline.phase));
        }
        Ok(())
    }
    fn phase_read(&mut self, offset: usize, deadline: Deadline) -> Result<u32, Error> {
        self.check_deadline(deadline)?;
        // A failed actual access takes priority over the clock observed after
        // that access; a successful late ready value never grants completion.
        let value = self.read(offset)?;
        self.check_deadline(deadline)?;
        Ok(value)
    }
    fn phase_write(&mut self, offset: usize, value: u32, deadline: Deadline) -> Result<(), Error> {
        self.check_deadline(deadline)?;
        self.registers.write32(offset, value);
        self.check_deadline(deadline)
    }
    fn phase_expect(&mut self, offset: usize, value: u32, deadline: Deadline) -> Result<(), Error> {
        self.check_deadline(deadline)?;
        let observed = self.read(offset)?;
        if observed != value {
            return Err(Error::RegisterRejected(offset));
        }
        self.check_deadline(deadline)
    }
    fn phase_checked_write(
        &mut self,
        offset: usize,
        value: u32,
        deadline: Deadline,
    ) -> Result<(), Error> {
        self.phase_write(offset, value, deadline)?;
        self.phase_expect(offset, value, deadline)
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
    fn pci_authority(&mut self) -> Result<(), Error> {
        if self.registers.identity()? != self.identity {
            return Err(Error::AuthorityChanged);
        }
        Ok(())
    }
    fn live(&mut self) -> Result<(), Error> {
        self.pci_authority()?;
        let observed_pin_mode = P::pin_mode(&mut self.registers)?;
        if self.pin_mode != observed_pin_mode
            || self.read(P::POWER_STATUS)? != 0
            || self.read(CONTROL)? != 1
            || self.read(P::CLOCK)? != 3
            || self.read(P::IRQ_ENABLE)? != 1
            || (P::ERROR_ENABLE != 0
                && self.read(P::IRQ_CONTROL)? & P::ERROR_ENABLE != P::ERROR_ENABLE)
        {
            return Err(Error::AuthorityChanged);
        }
        if P::ERROR_ENABLE != 0 {
            let status = self.read(P::IRQ_STATUS)?;
            if status & ERROR_IRQ != 0 {
                return Err(Error::DmaFault(status));
            }
        }
        Ok(())
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
    fn finish<U>(&mut self, result: Result<U, Error>) -> Result<U, Error> {
        if let Err(error) = result.as_ref() {
            self.first_error.get_or_insert(*error);
            self.state = State::Faulted;
        }
        result
    }
    fn soft_reset(&mut self) -> Result<(), Error> {
        let assert = self.deadline(Phase::ResetAssert, POWER_TIMEOUT_US);
        self.phase_write(RESET, 1, assert)?;
        // The source accepts either bit of 0x10001, not bit16 alone. Require
        // its actual observed handshake and a bounded complete clear.
        self.wait(RESET, assert, |value| value & RESET_ACK != 0)?;
        let clear = self.deadline(Phase::ResetClear, POWER_TIMEOUT_US);
        self.phase_write(RESET, 0, clear)?;
        self.wait(RESET, clear, |value| value == 0)?;
        self.phase_expect(DMA_ENABLE, 0, clear)?;
        self.phase_expect(PDM_ENABLE, 0, clear)
    }
    /// Initialize or recover a fault through an actual whole-function reset.
    /// Existing capture ownership survives any failed handshake. A successful
    /// reset invalidates the old ring and requires a fresh prepare.
    pub fn initialize(&mut self) -> Result<(), Error> {
        if self.state == State::Shutdown {
            return Err(Error::Shutdown);
        }
        self.state = State::Faulted;
        let result = (|| {
            self.pci_authority()?;
            self.initialize_inner()?;
            self.release_capture()?;
            self.state = State::Ready;
            Ok(())
        })();
        self.finish(result)
    }
    fn initialize_inner(&mut self) -> Result<(), Error> {
        let deadline = self.deadline(Phase::PowerOn, POWER_TIMEOUT_US);
        let power = self.phase_read(P::POWER_STATUS, deadline)?;
        if power != 0 {
            if power & POWER_STATE_MASK != POWER_ON_IN_PROGRESS {
                self.phase_write(P::POWER_CONTROL, POWER_ON_REQUEST, deadline)?;
            }
            self.wait(P::POWER_STATUS, deadline, |value| value == 0)?;
        }
        self.write_checked(CONTROL, 1)?;
        self.soft_reset()?;
        self.write_checked(P::CLOCK, 3)?;
        self.write_checked(PAGE_BASE, 0)?;
        self.registers.set_bus_master(false)?;
        // Admit the actual completion service while the reset-acknowledged
        // engine is quiet, before exposing even the first capture mapping.
        self.drain_stopped_domain()?;
        if P::ERROR_ENABLE == 0 {
            self.write_checked(P::IRQ_CONTROL, 0)?;
            self.registers.write32(P::IRQ_STATUS, u32::MAX);
            self.write_checked(P::IRQ_ENABLE, 1)?;
        } else {
            // Renoir source enables the external gate before preserving the
            // existing control word and setting its error-enable bit. Its
            // pending status is not implicitly discarded by initialization.
            self.write_checked(P::IRQ_ENABLE, 1)?;
            let control = self.read(P::IRQ_CONTROL)?;
            self.write_checked(P::IRQ_CONTROL, control | P::ERROR_ENABLE)?;
        }
        let mode = P::pin_mode(&mut self.registers)?;
        P::validate_pin(mode, self.identity)?;
        self.pin_mode = mode;
        Ok(())
    }
    /// Four equal 4K..8K periods. No allocation is published before complete
    /// format/range checks; once programming begins it is retained on faults.
    pub fn prepare_capture(
        &mut self,
        source: &dyn PageSource,
        format: PcmFormat,
        period_bytes: usize,
    ) -> Result<(), Error> {
        self.usable()?;
        if self.state == State::Running {
            return Err(Error::Busy);
        }
        if format != CAPTURE_FORMAT {
            return Err(Error::InvalidFormat);
        }
        if !(4096..=8192).contains(&period_bytes) || !period_bytes.is_multiple_of(FRAME_BYTES) {
            return Err(Error::InvalidBuffer);
        }
        let result = self.prepare_inner(source, period_bytes);
        self.finish(result)
    }
    fn prepare_inner(&mut self, source: &dyn PageSource, period_bytes: usize) -> Result<(), Error> {
        self.live()?;
        if self.read(DMA_ENABLE)? != 0 || self.read(PDM_ENABLE)? != 0 {
            return Err(Error::Busy);
        }
        let bytes = period_bytes * 4;
        // Source allocates 32K but permits a smaller runtime ring. Own the
        // complete rounded page range without mapping a partial final page.
        let allocation_bytes = bytes.next_multiple_of(PAGE_BYTES);
        if self.capture.is_some() {
            // PTE cache invalidation has no source completion handshake.
            // Reset the actual function before replacing any published lease,
            // then reestablish generation-specific clocks/IRQs and exclusion.
            self.initialize_inner()?;
        } else {
            self.write_checked(PAGE_BASE, 0)?;
            self.registers.set_bus_master(false)?;
        }
        self.release_capture()?;
        let geometry = source.page_geometry().map_err(Error::Memory)?;
        if geometry.base_shift() != 12 {
            return Err(Error::InvalidBuffer);
        }
        let pages = source
            .allocate(allocation_bytes, PAGE_BYTES, CacheAttribute::WriteBack)
            .map_err(Error::Memory)?;
        if pages.page_shift() != 12
            || pages.bytes() != allocation_bytes
            || pages.logical_bytes() != allocation_bytes
        {
            return Err(Error::InvalidBuffer);
        }
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(Error::Memory)?;
        let dma = DmaMapping::map(
            self.domain.clone(),
            pages,
            DmaDirection::FromDevice,
            (1u64 << self.config.dma_address_bits) - 1,
        )
        .map_err(Error::Dma)?;
        let capture = Capture {
            cpu,
            dma,
            published: false,
            period_bytes,
            baseline: 0,
            produced: 0,
            completed: 0,
            consumed: 0,
        };
        check_dma_range(
            capture.dma.address().map_err(Error::Dma)?,
            capture.dma.bytes(),
            allocation_bytes,
            self.config.dma_address_bits,
        )?;
        capture
            .dma
            .sync_for_device(0..allocation_bytes)
            .map_err(Error::Dma)?;
        if P::PERIOD_DELIVERY {
            // Qualify actual concurrent word observation before publishing an
            // IOVA. This discarded value grants no captured sample freshness.
            capture.dma.read_coherent_u32(0).map_err(Error::Dma)?;
        }
        self.capture = Some(capture);
        // From this point even partial SRAM publication retains the lease.
        self.capture.as_mut().unwrap().published = true;
        self.program_capture_ring()?;
        self.state = State::Prepared;
        Ok(())
    }
    fn program_capture_ring(&mut self) -> Result<(), Error> {
        let capture = self.capture.as_ref().ok_or(Error::NotPrepared)?;
        let base = capture.dma.address().map_err(Error::Dma)?;
        let allocation_bytes = capture.dma.bytes();
        let period_bytes = capture.period_bytes;
        let bytes = period_bytes * 4;
        self.write_checked(PAGE_BASE, P::SRAM_TABLE | GROUP_ENABLE)?;
        self.write_checked(PAGE_SIZE, 2)?;
        for page in 0..allocation_bytes / PAGE_BYTES {
            let address = base + (page * PAGE_BYTES) as u64;
            self.write_checked(SCRATCH + page * 8, address as u32)?;
            self.write_checked(SCRATCH + page * 8 + 4, (address >> 32) as u32 | PTE_VALID)?;
        }
        // Invalidate remaining group1 slots from a previous larger ring.
        for page in allocation_bytes / PAGE_BYTES..8 {
            self.write_checked(SCRATCH + page * 8 + 4, 0)?;
        }
        self.write_checked(RING_ADDRESS, PDM_WINDOW)?;
        self.write_checked(RING_SIZE, bytes as u32)?;
        self.write_checked(WATERMARK, period_bytes as u32)?;
        fence(Ordering::Release);
        // Source: flush ATU cache after PTE update. There is no documented
        // sticky readback or ACK latency. This request neither disables DMA nor
        // proves host IOTLB invalidation/payload completion or releases a pin.
        self.registers.write32(ATU_CONTROL, ATU_CACHE_INVALIDATE);
        Ok(())
    }
    fn ring_authority(&mut self) -> Result<(), Error> {
        self.live()?;
        let capture = self.capture.as_ref().ok_or(Error::NotPrepared)?;
        let (base, allocation, period) = (
            capture.dma.address().map_err(Error::Dma)?,
            capture.dma.bytes(),
            capture.period_bytes,
        );
        for (offset, expected) in [
            (PAGE_BASE, P::SRAM_TABLE | GROUP_ENABLE),
            (PAGE_SIZE, 2),
            (RING_ADDRESS, PDM_WINDOW),
            (RING_SIZE, (period * 4) as u32),
            (WATERMARK, period as u32),
        ] {
            if self.read(offset)? != expected {
                return Err(Error::AuthorityChanged);
            }
        }
        for page in 0..allocation / PAGE_BYTES {
            let address = base + (page * PAGE_BYTES) as u64;
            if self.read(SCRATCH + page * 8)? != address as u32
                || self.registers.read32(SCRATCH + page * 8 + 4)
                    != ((address >> 32) as u32 | PTE_VALID)
            {
                return Err(Error::AuthorityChanged);
            }
        }
        if self.state == State::Running {
            for (offset, expected) in [(CHANNELS, 0), (DECIMATION, 2), (PDM_CLOCK, 7)] {
                if self.read(offset)? != expected {
                    return Err(Error::AuthorityChanged);
                }
            }
            if self.read(MISC)? & GAIN_MASK != u32::from(self.config.gain) << 3 {
                return Err(Error::AuthorityChanged);
            }
        }
        Ok(())
    }
    fn byte_count(&mut self) -> Result<u64, Error> {
        // Registers are ordinary halves, not a documented latch. Retry a
        // rollover rather than manufacture a position from different epochs.
        for _ in 0..8 {
            let high = self.registers.read32(COUNT_HIGH);
            let low = self.registers.read32(COUNT_LOW);
            if self.registers.read32(COUNT_HIGH) == high {
                return Ok(u64::from(high) << 32 | u64::from(low));
            }
        }
        Err(Error::CounterUnstable)
    }
    pub fn start(&mut self) -> Result<(), Error> {
        self.usable()?;
        if self.state == State::Running {
            return Err(Error::Busy);
        }
        if !matches!(self.state, State::Prepared | State::Stopped) {
            return Err(Error::NotPrepared);
        }
        let result = self.start_inner();
        self.finish(result)
    }
    fn start_inner(&mut self) -> Result<(), Error> {
        self.ring_authority()?;
        if self.read(DMA_ENABLE)? != 0 || self.read(PDM_ENABLE)? != 0 {
            return Err(Error::AuthorityChanged);
        }
        self.write_checked(CHANNELS, 0)?;
        self.write_checked(DECIMATION, 2)?;
        let baseline = self.byte_count()?;
        let capture = self.capture.as_mut().unwrap();
        capture.baseline = baseline;
        capture.produced = 0;
        capture.completed = 0;
        capture.consumed = 0;
        capture
            .dma
            .sync_for_device(0..capture.dma.bytes())
            .map_err(Error::Dma)?;
        self.registers.write32(P::IRQ_STATUS, PERIOD_IRQ);
        let irq = self.read(P::IRQ_CONTROL)?;
        self.write_checked(P::IRQ_CONTROL, irq | PERIOD_IRQ)?;
        let deadline = self.deadline(Phase::DmaStart, DMA_TIMEOUT_US);
        self.phase_checked_write(PDM_CLOCK, 7, deadline)?;
        let misc =
            self.phase_read(MISC, deadline)? & !GAIN_MASK | (u32::from(self.config.gain) << 3);
        self.phase_checked_write(MISC, misc, deadline)?;
        fence(Ordering::Release);
        self.phase_checked_write(PDM_ENABLE, 1, deadline)?;
        // The status bit may become set immediately, so an exact readback of
        // request1 is invalid. Acknowledgement is the separate active bit.
        self.check_deadline(deadline)?;
        self.registers.set_bus_master(true)?;
        self.check_deadline(deadline)?;
        self.phase_write(DMA_ENABLE, DMA_REQUEST, deadline)?;
        self.wait(DMA_ENABLE, deadline, |value| value & DMA_ACTIVE != 0)?;
        self.state = State::Running;
        Ok(())
    }
    fn position_inner(&mut self) -> Result<Position, Error> {
        self.ring_authority()?;
        let status = self.read(P::IRQ_STATUS)?;
        if status & ERROR_IRQ != 0 {
            return Err(Error::DmaFault(status));
        }
        let dma = self.read(DMA_ENABLE)?;
        if dma & !3 != 0
            || (self.state == State::Running && dma & DMA_ACTIVE == 0)
            || (self.state != State::Running && dma != 0)
            || self.read(PDM_ENABLE)? != u32::from(self.state == State::Running)
        {
            return Err(Error::AuthorityChanged);
        }
        if P::PERIOD_DELIVERY && status & PERIOD_IRQ != 0 {
            // Match Renoir's actual source ISR: acknowledge its period event
            // before ALSA-style hardware-pointer sampling. The period event,
            // not bare counter movement, grants completed-period progression.
            self.registers.write32(P::IRQ_STATUS, PERIOD_IRQ);
        }
        let count = self.byte_count()?;
        let capture = self.capture.as_mut().ok_or(Error::NotPrepared)?;
        let produced =
            count.wrapping_sub(capture.baseline) / FRAME_BYTES as u64 * FRAME_BYTES as u64;
        if produced < capture.produced || produced >= (1u64 << 63) {
            return Err(Error::CounterDiscontinuity);
        }
        capture.produced = produced;
        if P::PERIOD_DELIVERY && status & PERIOD_IRQ != 0 {
            let completed = produced / capture.period_bytes as u64 * capture.period_bytes as u64;
            capture.completed = capture.completed.max(completed);
        }
        fence(Ordering::Acquire);
        Ok(Position {
            bytes: produced,
            ring_offset: (produced % (capture.period_bytes * 4) as u64) as usize,
            period_pending: status & PERIOD_IRQ != 0,
        })
    }
    /// Observe the real byte counter and acknowledge only the PDM period bit.
    /// Multiple periods may coalesce; `bytes` is authoritative, not IRQ count.
    pub fn position(&mut self) -> Result<Position, Error> {
        self.usable()?;
        if !matches!(self.state, State::Running | State::Stopped) {
            return Err(Error::NotPrepared);
        }
        let result = self.position_inner().inspect(|position| {
            if position.period_pending && !P::PERIOD_DELIVERY {
                self.registers.write32(P::IRQ_STATUS, PERIOD_IRQ);
            }
        });
        self.finish(result)
    }
    pub(super) fn read_completed_period(
        &mut self,
        destination: &mut [u8],
    ) -> Result<Option<CapturePeriod>, Error> {
        self.usable()?;
        if self.state != State::Running {
            return Err(Error::NotPrepared);
        }
        if destination.len()
            != self
                .capture
                .as_ref()
                .ok_or(Error::NotPrepared)?
                .period_bytes
        {
            return Err(Error::InvalidBuffer);
        }
        let result = self.read_period_inner(destination);
        self.finish(result)
    }
    fn read_period_inner(
        &mut self,
        destination: &mut [u8],
    ) -> Result<Option<CapturePeriod>, Error> {
        let before = self.position_inner()?;
        let capture = self.capture.as_ref().ok_or(Error::NotPrepared)?;
        let consumed = capture.consumed;
        let period = capture.period_bytes;
        let ring = (period * 4) as u64;
        // A full ring of unread progress is already too late for a producer
        // that can immediately begin overwriting its oldest completed period.
        if before.bytes - consumed >= ring {
            return Err(Error::CaptureOverrun {
                produced: before.bytes,
                consumed,
            });
        }
        if capture.completed - consumed < period as u64 {
            return Ok(None);
        }
        let start = (consumed % ring) as usize;
        for (word, output) in destination.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let observed = capture
                .dma
                .read_coherent_u32(start + word * 4)
                .map_err(Error::Dma)?;
            output.copy_from_slice(&observed.to_le_bytes());
        }
        // A producer may keep advancing during the copy. Under the pinned
        // source completed-period/pointer contract, accept bytes only if a
        // second actual pointer sample has not reached the copied period.
        // A failed copy publishes no consumer progress.
        let after = self.position_inner()?;
        if after.bytes - consumed >= ring {
            return Err(Error::CaptureOverrun {
                produced: after.bytes,
                consumed,
            });
        }
        self.capture.as_mut().unwrap().consumed = consumed + period as u64;
        Ok(Some(CapturePeriod {
            first_frame: consumed / FRAME_BYTES as u64,
            frames: period / FRAME_BYTES,
        }))
    }

    /// Copy the acknowledged stopped ring in its physical cyclic layout.
    /// `Position::ring_offset` identifies the next write position for ordering
    /// the latest ring after wraps. A running cyclic producer never grants the
    /// canonical DMA domain's required CPU ownership; copying while running
    /// refuses before touching the destination. No CPU/physical/IOVA alias is
    /// inferred. Every admitted profile completes the actual retained domain's
    /// translated payload write drain before CPU cache synchronization. On a
    /// mapping error the destination may be partly modified.
    pub fn copy_stopped_ring(
        &mut self,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<(), Error> {
        self.usable()?;
        if self.state == State::Running {
            return Err(Error::Busy);
        }
        if self.state != State::Stopped {
            return Err(Error::NotPrepared);
        }
        let ring = self
            .capture
            .as_ref()
            .ok_or(Error::NotPrepared)?
            .period_bytes
            * 4;
        if !offset.is_multiple_of(FRAME_BYTES)
            || !destination.len().is_multiple_of(FRAME_BYTES)
            || offset
                .checked_add(destination.len())
                .is_none_or(|last| last > ring)
        {
            return Err(Error::InvalidBuffer);
        }
        let result = self.ring_authority().and_then(|()| {
            if self.read(DMA_ENABLE)? != 0 || self.read(PDM_ENABLE)? != 0 {
                return Err(Error::AuthorityChanged);
            }
            self.drain_stopped_domain()?;
            let capture = self.capture.as_ref().unwrap();
            // SAFETY: actual stop acknowledgement, PDM disable and required
            // same-domain posted-payload completion were checked;
            // there are no asynchronous submissions or interrupt workers here.
            unsafe { capture.dma.sync_for_cpu(offset..offset + destination.len()) }
                .map_err(Error::Dma)?;
            for (index, byte) in destination.iter_mut().enumerate() {
                let pointer = capture
                    .cpu
                    .address(offset + index, 1)
                    .map_err(Error::Memory)?;
                // SAFETY: retained real CPU mapping, checked bounds, no DMA.
                *byte = unsafe { pointer.as_ptr().read_volatile() };
            }
            Ok(())
        });
        self.finish(result)
    }
    fn stop_inner(&mut self) -> Result<(), Error> {
        self.pci_authority()?;
        let deadline = self.deadline(Phase::DmaStop, DMA_TIMEOUT_US);
        if self.phase_read(DMA_ENABLE, deadline)? & (DMA_REQUEST | DMA_ACTIVE) != 0 {
            self.phase_write(DMA_ENABLE, DMA_ACTIVE, deadline)?;
            self.wait(DMA_ENABLE, deadline, |value| {
                value & (DMA_REQUEST | DMA_ACTIVE) == 0
            })?;
        }
        self.phase_checked_write(PDM_ENABLE, 0, deadline)?;
        self.phase_write(FIFO_FLUSH, 1, deadline)?;
        let irq = self.phase_read(P::IRQ_CONTROL, deadline)?;
        self.phase_checked_write(P::IRQ_CONTROL, irq & !PERIOD_IRQ, deadline)
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        self.usable()?;
        if !matches!(self.state, State::Running | State::Stopped) {
            return Err(Error::NotPrepared);
        }
        let result = self.ring_authority().and_then(|()| {
            self.stop_inner()?;
            self.drain_stopped_domain()
        });
        if result.is_ok() {
            self.state = State::Stopped;
        }
        self.finish(result)
    }
    pub(super) fn suspend_retained(&mut self, power_gate: bool) -> Result<(), Error> {
        self.usable()?;
        let result = self.suspend_inner(power_gate);
        if result.is_ok() {
            self.state = State::Suspended;
        }
        self.finish(result)
    }
    fn suspend_inner(&mut self, power_gate: bool) -> Result<(), Error> {
        if self.capture.is_some() {
            self.ring_authority()?;
        } else {
            self.live()?;
        }
        self.stop_inner()?;
        self.disable_interrupts()?;
        self.soft_reset()?;
        self.write_checked(PAGE_BASE, 0)?;
        self.registers.set_bus_master(false)?;
        self.drain_stopped_domain()?;
        self.write_checked(P::CLOCK, 0)?;
        self.write_checked(CONTROL, 0)?;
        if power_gate {
            let deadline = self.deadline(Phase::PowerOff, POWER_TIMEOUT_US);
            self.phase_write(P::POWER_CONTROL, POWER_OFF_REQUEST, deadline)?;
            self.wait(P::POWER_STATUS, deadline, |value| {
                value & POWER_STATE_MASK == POWERED_OFF
            })?;
        }
        Ok(())
    }
    pub(super) fn resume_retained(&mut self) -> Result<(), Error> {
        match self.state {
            State::Suspended => (),
            State::Faulted => return Err(Error::NeedsReset),
            State::Shutdown => return Err(Error::Shutdown),
            _ => return Err(Error::NotSuspended),
        }
        self.state = State::Faulted;
        let result = self.resume_inner();
        self.finish(result)
    }
    fn resume_inner(&mut self) -> Result<(), Error> {
        // The unsafe claim still owns the same PCI/firmware/board epoch. The
        // native provider revalidates actual BDF/BAR/D0/delivery containment;
        // actual domain completion below revalidates retained root authority.
        self.pci_authority()?;
        self.initialize_inner()?;
        if let Some(capture) = self.capture.as_ref() {
            capture
                .dma
                .sync_for_device(0..capture.dma.bytes())
                .map_err(Error::Dma)?;
            if P::PERIOD_DELIVERY {
                // Recheck the actual retained domain's coherent observation
                // capability, discarding old PCM before publishing its PTEs.
                capture.dma.read_coherent_u32(0).map_err(Error::Dma)?;
            }
            // This is the original ever-published lease, never a fresh mapping.
            self.program_capture_ring()?;
            let control = self.read(P::IRQ_CONTROL)?;
            self.write_checked(P::IRQ_CONTROL, control | PERIOD_IRQ)?;
            self.state = State::Prepared;
        } else {
            self.state = State::Ready;
        }
        // Source trigger RESUME/START is a separate explicit start operation.
        Ok(())
    }
    fn disable_interrupts(&mut self) -> Result<(), Error> {
        if P::ERROR_ENABLE == 0 {
            self.write_checked(P::IRQ_CONTROL, 0)?;
            self.write_checked(P::IRQ_ENABLE, 0)?;
            self.registers.write32(P::IRQ_STATUS, u32::MAX);
        } else {
            // Renoir source quiets pending status before disabling the gate;
            // stop already removed the period bit without losing error policy.
            self.registers.write32(P::IRQ_STATUS, u32::MAX);
            self.write_checked(P::IRQ_ENABLE, 0)?;
        }
        Ok(())
    }
    /// Stop first, then contain interrupts and reset the function. Memory and
    /// ownership remain retained on any failure; a subsequent explicit reset
    /// may recover them. No writes follow a lost PCI association.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        if self.state == State::Shutdown {
            return Ok(());
        }
        let result = self.shutdown_inner();
        if result.is_ok() {
            self.state = State::Shutdown;
        }
        self.finish(result)
    }
    fn shutdown_inner(&mut self) -> Result<(), Error> {
        if self.state == State::Suspended {
            // Restore real register accessibility before the existing full
            // shutdown proof; a cached suspend flag never frees DMA owners.
            self.resume_inner()?;
        }
        self.pci_authority()?;
        self.stop_inner()?;
        self.disable_interrupts()?;
        self.soft_reset()?;
        self.write_checked(PAGE_BASE, 0)?;
        self.registers.set_bus_master(false)?;
        self.release_capture()?;
        self.write_checked(P::CLOCK, 0)?;
        self.write_checked(CONTROL, 0)
    }
    /// Callers must first observe engine stop/PDM disable or actual reset,
    /// while preserving the requester, root, domain and every target mapping.
    fn drain_stopped_domain(&self) -> Result<(), Error> {
        if P::REQUIRE_DRAIN {
            // SAFETY: each caller first acknowledged actual engine quiescence;
            // this exact attached domain and all backing remain owned. No IRQ,
            // work item or other submission can restart this exclusive device.
            unsafe { self.domain.drain_posted_writes() }.map_err(Error::Dma)?;
        }
        Ok(())
    }
    fn release_capture(&mut self) -> Result<(), Error> {
        if self
            .capture
            .as_ref()
            .is_some_and(|capture| capture.published)
        {
            self.drain_stopped_domain()?;
        }
        if let Some(capture) = self.capture.as_mut() {
            // SAFETY: callers first acknowledge actual whole-function reset,
            // disabled address group1 and PCI BME, then same-domain payload
            // completion. No IRQ/work submissions exist. Cache-command readback
            // supplies none of this proof. Failure retains this exact lease.
            unsafe { capture.dma.unmap() }.map_err(Error::Dma)?;
        }
        self.capture = None;
        Ok(())
    }
    /// Transfer the retained register provider only after acknowledged shutdown.
    /// A non-shutdown owner is returned intact, including every DMA lease.
    // Returning ownership must neither allocate nor drop a retained DMA lease.
    #[allow(clippy::result_large_err)]
    pub fn into_stopped(self) -> Result<(R, T), Self> {
        if self.state != State::Shutdown {
            return Err(self);
        }
        Ok((self.registers, self.timer))
    }
}

pub(super) fn check_dma_range(
    base: u64,
    bytes: usize,
    required: usize,
    bits: u8,
) -> Result<(), Error> {
    if base == 0
        || !base.is_multiple_of(PAGE_BYTES as u64)
        || bytes != required
        || !bytes.is_multiple_of(PAGE_BYTES)
        || !(32..=63).contains(&bits)
        || base
            .checked_add(bytes as u64 - 1)
            .is_none_or(|last| last >> bits != 0)
    {
        return Err(Error::DmaAddress);
    }
    Ok(())
}

/// Assertions over independent model write traces, not a translation-cache
/// implementation or a cache-completion/ACK model. Source addresses and order
/// below come from the pinned YC/Renoir DMA configuration and ring helpers.
#[cfg(test)]
pub(super) mod trace_assertions {
    use alloc::vec::Vec;

    pub(in crate::audio) fn assert_ring_invalidation(
        writes: &[(usize, u32)],
        iova: u64,
        sram: u32,
        period_bytes: usize,
        started: bool,
    ) {
        let ring_bytes = period_bytes * 4;
        let pages = ring_bytes.next_multiple_of(4096) / 4096;
        let mut expected = vec![(0xc04, sram | 0x8000_0000), (0xc00, 2)];
        for page in 0..pages {
            let address = iova + (page * 4096) as u64;
            expected.push((0x10000 + page * 8, address as u32));
            expected.push((0x10004 + page * 8, (address >> 32) as u32 | 0x8000_0000));
        }
        for page in pages..8 {
            expected.push((0x10004 + page * 8, 0));
        }
        expected.extend([
            (0x2c0c, 0x0400_0000),
            (0x2c10, ring_bytes as u32),
            (0x2c20, period_bytes as u32),
            (0xc40, 1),
        ]);
        let observed: Vec<_> = writes
            .iter()
            .copied()
            .filter(|(offset, value)| {
                (*offset == 0xc04 && *value != 0)
                    || matches!(*offset, 0xc00 | 0xc40 | 0x2c0c | 0x2c10 | 0x2c20)
                    || (0x10000..0x10040).contains(offset)
            })
            .collect();
        assert_eq!(
            observed, expected,
            "exact PTE/ring sequence must end with one required invalidate1 request"
        );
        let invalidations: Vec<_> = writes
            .iter()
            .enumerate()
            .filter(|(_, (offset, _))| *offset == 0xc40)
            .collect();
        assert_eq!(
            invalidations.len(),
            1,
            "required request cannot be absent or duplicated"
        );
        let invalidate = invalidations[0].0;
        for request in [(0x2c04, 1), (0x2c08, 1)] {
            let starts: Vec<_> = writes
                .iter()
                .enumerate()
                .filter(|(_, actual)| **actual == request)
                .collect();
            assert_eq!(starts.len(), usize::from(started));
            if started {
                assert!(
                    invalidate < starts[0].0,
                    "PDM/DMA cannot start before required cache request"
                );
            }
        }
    }
}
