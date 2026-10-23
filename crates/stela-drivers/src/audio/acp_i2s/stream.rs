// SPDX-License-Identifier: GPL-2.0-only
//! Retained Raven/Vangogh PTE/ring, serial format, PCM and stream lifecycle.
//! Copyright (C) 2016, 2021, 2023 Advanced Micro Devices, Inc.
use super::*;
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn master_control(&self, format: Format) -> Result<Option<u32>, Error> {
        let Clock::Master { reference_hz } = self.config.clock else {
            return Ok(None);
        };
        // Source ACP5x master table covers 16/32-bit stereo with 32/64 LRCLK.
        // Refuse a TDM geometry whose clock ratio that table does not describe.
        if !matches!(
            format.signal,
            Signal::I2s
                | Signal::DspA {
                    slots: 2,
                    slot_bits: 16 | 32
                }
        ) {
            return Err(Error::InvalidFormat);
        }
        let (lrclk, base) = match format.sample {
            Sample::Signed16 => (32, 128),
            Sample::Signed32 => (64, 64),
            _ => return Err(Error::InvalidFormat),
        };
        if let Signal::DspA { slot_bits, .. } = format.signal
            && usize::from(slot_bits) != format.sample.bytes() * 8
        {
            return Err(Error::InvalidFormat);
        }
        let bclk = match format.rate {
            8_000 => base * 6,
            16_000 => base * 3,
            32_000 => base * 3 / 2,
            44_100 | 48_000 => base,
            88_200 | 96_000 => base / 2,
            _ => return Err(Error::InvalidFormat),
        };
        if u64::from(format.rate) * u64::from(lrclk) * u64::from(bclk) != u64::from(reference_hz) {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Some(
            1 | (u32::from(matches!(format.signal, Signal::DspA { .. })) << 1)
                | (lrclk << 2)
                | (bclk << 11),
        ))
    }
    /// Allocate a real DMA ring while every native stream is stopped. Playback
    /// initial PCM must fill the entire cyclic ring; capture accepts no payload.
    pub fn prepare(
        &mut self,
        port: Port,
        format: Format,
        ring: Ring,
        initial_pcm: Option<&[u8]>,
        source: &dyn PageSource,
    ) -> Result<(), Error> {
        self.usable()?;
        let Ring {
            period_bytes: period,
            periods,
        } = ring;
        format.validate(self.generation, port)?;
        self.master_control(format)?;
        let bytes = period
            .checked_mul(usize::from(periods))
            .ok_or(Error::InvalidBuffer)?;
        if !(2..=8).contains(&periods)
            || !(PERIOD_MIN..=PERIOD_MAX).contains(&period)
            || !period.is_multiple_of(format.frame_bytes())
            || !period.is_multiple_of(4)
            || bytes > BUFFER_MAX
            || match port.direction() {
                Direction::Playback => initial_pcm.is_none_or(|pcm| pcm.len() != bytes),
                Direction::Capture => initial_pcm.is_some(),
            }
        {
            return Err(Error::InvalidBuffer);
        }
        if self.streams.iter().flatten().any(|stream| stream.running) {
            return Err(Error::Busy);
        }
        if let Some(pair) = self.streams[port.paired()].as_ref()
            && (pair.format.rate != format.rate
                || pair.format.sample.bytes() != format.sample.bytes()
                || pair.format.signal != format.signal)
        {
            return Err(Error::InvalidFormat);
        }
        let result = self.prepare_inner(port, format, period, bytes, initial_pcm, source);
        self.finish(result)
    }
    fn prepare_inner(
        &mut self,
        port: Port,
        format: Format,
        period: usize,
        bytes: usize,
        initial_pcm: Option<&[u8]>,
        source: &dyn PageSource,
    ) -> Result<(), Error> {
        self.live()?;
        self.quiet_engines()?;
        // Reconfiguration may replace a previously cached PTE. A whole actual
        // reset precedes releasing its old lease; cache-invalidate request1
        // alone is never interpreted as completion or as an engine stop.
        self.initialize_inner()?;
        let slot = port as usize;
        if let Some(stream) = self.streams[slot].as_mut() {
            // SAFETY: no engine can fetch PTEs, group1/BME disabled and real domain drained.
            unsafe { stream.dma.unmap() }.map_err(Error::Dma)?;
        }
        self.streams[slot] = None;
        let allocation = bytes.next_multiple_of(PAGE_BYTES);
        if source.page_geometry().map_err(Error::Memory)?.base_shift() != 12 {
            return Err(Error::InvalidBuffer);
        }
        let pages = source
            .allocate(allocation, PAGE_BYTES, CacheAttribute::WriteBack)
            .map_err(Error::Memory)?;
        if pages.page_shift() != 12
            || pages.bytes() != allocation
            || pages.logical_bytes() != allocation
        {
            return Err(Error::InvalidBuffer);
        }
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(Error::Memory)?;
        if let Some(payload) = initial_pcm {
            for (offset, byte) in payload.iter().enumerate() {
                let pointer = cpu.address(offset, 1).map_err(Error::Memory)?;
                // SAFETY: retained actual CPU RAM, not yet mapped/published for DMA.
                unsafe { pointer.as_ptr().write_volatile(*byte) };
            }
        }
        let direction = if port.direction() == Direction::Playback {
            DmaDirection::ToDevice
        } else {
            DmaDirection::FromDevice
        };
        let dma = DmaMapping::map(
            self.domain.clone(),
            pages,
            direction,
            (1u64 << self.config.dma_address_bits) - 1,
        )
        .map_err(Error::Dma)?;
        let mut stream = Stream {
            cpu,
            dma,
            published: false,
            format,
            period,
            bytes,
            control: 0,
            running: false,
            started: false,
            baseline: 0,
            produced: 0,
            completed: 0,
            consumed: 0,
        };
        check_dma_range(
            stream.dma.address().map_err(Error::Dma)?,
            stream.dma.bytes(),
            allocation,
            self.config.dma_address_bits,
        )?;
        stream
            .dma
            .sync_for_device(0..allocation)
            .map_err(Error::Dma)?;
        if port.direction() == Direction::Capture {
            stream.dma.read_coherent_u32(0).map_err(Error::Dma)?;
        }
        // Retain before even a partial SRAM PTE store; errors never free a published IOVA.
        stream.published = true;
        self.streams[slot] = Some(stream);
        for other in PORTS {
            if other != port && self.streams[other as usize].is_some() {
                self.program(other)?;
            }
        }
        self.program(port)?;
        fence(Ordering::Release);
        self.registers.write32(ATU_CONTROL, 1);
        self.state = State::Prepared;
        Ok(())
    }
    pub(super) fn program(&mut self, port: Port) -> Result<(), Error> {
        let regs = self.generation.stream(port);
        let stream = self.streams[port as usize]
            .as_ref()
            .ok_or(Error::NotPrepared)?;
        let base = stream.dma.address().map_err(Error::Dma)?;
        let allocation = stream.dma.bytes();
        let format = stream.format;
        let bytes = stream.bytes;
        let period = stream.period;
        self.write(PAGE_BASE, SRAM | PTE_VALID)?;
        self.write(PAGE_SIZE, 2)?;
        for page in 0..PTE_SLOTS {
            let offset = SCRATCH + regs.pte + page * 8;
            if page < allocation / PAGE_BYTES {
                let address = base + (page * PAGE_BYTES) as u64;
                self.write(offset, address as u32)?;
                self.write(offset + 4, (address >> 32) as u32 | PTE_VALID)?;
            } else {
                self.write(offset + 4, 0)?;
            }
        }
        self.write(regs.ring, regs.window)?;
        self.write(regs.dma_size(), DMA_SIZE)?;
        self.write(regs.fifo_address(), regs.fifo)?;
        self.write(regs.fifo_size(), FIFO_SIZE)?;
        self.write(regs.size(), bytes as u32)?;
        self.write(regs.watermark(), period as u32)?;
        let mut control = self.read(regs.enable)? & !(SAMPLE_MASK | TDM_ENABLE | STREAM_ENABLE);
        if let Some(frame) = format.frame_control()? {
            self.write(regs.frame, frame)?;
            control |= TDM_ENABLE;
        }
        control |= format.sample.resolution() << 3;
        self.write(regs.enable, control)?;
        let stream = self.streams[port as usize].as_mut().unwrap();
        stream.control = control;
        stream.started = false;
        self.write(IRQ_CONTROL, self.generation.irq_mask())
    }
    fn ring_authority(&mut self, port: Port) -> Result<(), Error> {
        self.live()?;
        let regs = self.generation.stream(port);
        let stream = self.streams[port as usize]
            .as_ref()
            .ok_or(Error::NotPrepared)?;
        let base = stream.dma.address().map_err(Error::Dma)?;
        let allocation = stream.dma.bytes();
        let format = stream.format;
        let bytes = stream.bytes;
        let period = stream.period;
        let running = stream.running;
        let enable = stream.control | u32::from(running);
        for (offset, value) in [
            (PAGE_BASE, SRAM | PTE_VALID),
            (PAGE_SIZE, 2),
            (regs.ring, regs.window),
            (regs.size(), bytes as u32),
            (regs.watermark(), period as u32),
            (regs.fifo_address(), regs.fifo),
            (regs.fifo_size(), FIFO_SIZE),
            (regs.dma_size(), DMA_SIZE),
            (regs.enable, enable),
            (IRQ_CONTROL, self.generation.irq_mask()),
        ] {
            if self.read(offset)? != value {
                return Err(Error::AuthorityChanged);
            }
        }
        if running && let Some(value) = self.master_control(format)? {
            let offset = if port as usize >= 2 {
                AUXILIARY_MASTER
            } else {
                SPEAKER_MASTER
            };
            if self.read(offset)? != value {
                return Err(Error::AuthorityChanged);
            }
        }
        if let Some(frame) = format.frame_control()?
            && self.read(regs.frame)? != frame
        {
            return Err(Error::AuthorityChanged);
        }
        for page in 0..PTE_SLOTS {
            let offset = SCRATCH + regs.pte + page * 8;
            let high = if page < allocation / PAGE_BYTES {
                ((base + (page * PAGE_BYTES) as u64) >> 32) as u32 | PTE_VALID
            } else {
                0
            };
            if self.read(offset + 4)? != high {
                return Err(Error::AuthorityChanged);
            }
            if page < allocation / PAGE_BYTES
                && self.read(offset)? != (base + (page * PAGE_BYTES) as u64) as u32
            {
                return Err(Error::AuthorityChanged);
            }
        }
        Ok(())
    }
    fn counter(&mut self, regs: StreamRegisters) -> Result<u64, Error> {
        for _ in 0..8 {
            // Counter halves legitimately contain all ones. PCI/BAR/live
            // authority was checked first; do not reinterpret data as absence.
            let high = self.registers.read32(regs.count_high());
            let low = self.registers.read32(regs.count_low());
            if self.registers.read32(regs.count_high()) == high {
                return Ok(u64::from(high) << 32 | u64::from(low));
            }
        }
        Err(Error::CounterUnstable)
    }
    pub fn start(&mut self, port: Port) -> Result<(), Error> {
        self.usable()?;
        if self.streams[port as usize]
            .as_ref()
            .is_none_or(|stream| stream.running)
        {
            return Err(Error::Busy);
        }
        let result = (|| {
            self.ring_authority(port)?;
            let regs = self.generation.stream(port);
            let format = self.streams[port as usize].as_ref().unwrap().format;
            let clock = self.master_control(format)?;
            let deadline = self.deadline(Phase::DmaStart, STREAM_TIMEOUT_US);
            if let Some(value) = clock {
                let offset = if port as usize >= 2 {
                    AUXILIARY_MASTER
                } else {
                    SPEAKER_MASTER
                };
                self.phase_write(offset, value, deadline)?;
                self.wait(offset, deadline, |actual| actual == value)?;
            }
            self.phase_write(IRQ_STATUS, regs.irq, deadline)?;
            let baseline = self.counter(regs)?;
            self.timely(deadline)?;
            let stream = self.streams[port as usize].as_ref().unwrap();
            stream
                .dma
                .sync_for_device(0..stream.dma.bytes())
                .map_err(Error::Dma)?;
            let control = stream.control;
            self.timely(deadline)?;
            fence(Ordering::Release);
            self.registers.set_bus_master(true)?;
            self.timely(deadline)?;
            self.phase_write(regs.enable, control | STREAM_ENABLE, deadline)?;
            self.wait(regs.enable, deadline, |value| {
                value == control | STREAM_ENABLE
            })?;
            self.phase_write(regs.ier, 1, deadline)?;
            self.wait(regs.ier, deadline, |value| value == 1)?;
            let stream = self.streams[port as usize].as_mut().unwrap();
            stream.running = true;
            stream.started = true;
            stream.baseline = baseline;
            stream.produced = 0;
            stream.completed = 0;
            stream.consumed = 0;
            self.state = State::Running;
            Ok(())
        })();
        self.finish(result)
    }
    fn position_inner(&mut self, port: Port) -> Result<Position, Error> {
        self.ring_authority(port)?;
        let regs = self.generation.stream(port);
        let status = self.read(IRQ_STATUS)?;
        if status & regs.irq != 0 {
            self.registers.write32(IRQ_STATUS, regs.irq);
        }
        let count = self.counter(regs)?;
        let stream = self.streams[port as usize].as_mut().unwrap();
        let frame = stream.format.frame_bytes() as u64;
        let bytes = count.wrapping_sub(stream.baseline) / frame * frame;
        if bytes >= 1u64 << 63 || bytes < stream.produced {
            return Err(Error::CounterDiscontinuity);
        }
        stream.produced = bytes;
        if status & regs.irq != 0 {
            stream.completed = bytes / stream.period as u64 * stream.period as u64;
        }
        fence(Ordering::Acquire);
        Ok(Position {
            bytes,
            ring_offset: (bytes % stream.bytes as u64) as usize,
            period_pending: status & regs.irq != 0,
        })
    }
    pub fn position(&mut self, port: Port) -> Result<Position, Error> {
        self.usable()?;
        if self.streams[port as usize]
            .as_ref()
            .is_none_or(|stream| !stream.started)
        {
            return Err(Error::NotPrepared);
        }
        let result = self.position_inner(port);
        self.finish(result)
    }
    /// Copy one source-completed capture period while the device owns its ring.
    /// Coherent words are not an atomic frame snapshot. Discard output on error.
    pub fn capture_period(
        &mut self,
        port: Port,
        destination: &mut [u8],
    ) -> Result<Option<CapturePeriod>, Error> {
        self.usable()?;
        if port.direction() != Direction::Capture {
            return Err(Error::InvalidConfiguration);
        }
        let stream = self.streams[port as usize]
            .as_ref()
            .ok_or(Error::NotPrepared)?;
        if !stream.running {
            return Err(Error::NotPrepared);
        }
        if destination.len() != stream.period {
            return Err(Error::InvalidBuffer);
        }
        let result = (|| {
            let before = self.position_inner(port)?;
            let stream = self.streams[port as usize].as_ref().unwrap();
            let consumed = stream.consumed;
            let period = stream.period;
            let bytes = stream.bytes;
            let frame = stream.format.frame_bytes();
            if before.bytes - consumed >= bytes as u64 {
                return Err(Error::CaptureOverrun {
                    produced: before.bytes,
                    consumed,
                });
            }
            if stream.completed - consumed < period as u64 {
                return Ok(None);
            }
            let offset = (consumed % bytes as u64) as usize;
            for (index, word) in destination.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                word.copy_from_slice(
                    &stream
                        .dma
                        .read_coherent_u32(offset + index * 4)
                        .map_err(Error::Dma)?
                        .to_le_bytes(),
                );
            }
            let after = self.position_inner(port)?;
            if after.bytes - consumed >= bytes as u64 {
                return Err(Error::CaptureOverrun {
                    produced: after.bytes,
                    consumed,
                });
            }
            self.streams[port as usize].as_mut().unwrap().consumed += period as u64;
            Ok(Some(CapturePeriod {
                first_frame: consumed / frame as u64,
                frames: period / frame,
            }))
        })();
        self.finish(result)
    }
    pub(super) fn stop_inner(&mut self, port: Port) -> Result<(), Error> {
        self.associated()?;
        let regs = self.generation.stream(port);
        let deadline = self.deadline(Phase::DmaStop, STREAM_TIMEOUT_US);
        let control = self.phase_read(regs.enable, deadline)? & !STREAM_ENABLE;
        self.phase_write(regs.enable, control, deadline)?;
        self.wait(regs.enable, deadline, |value| value == control)?;
        let pair = self.generation.stream(PORTS[port.paired()]);
        if self.phase_read(pair.enable, deadline)? & STREAM_ENABLE == 0 {
            self.phase_write(regs.ier, 0, deadline)?;
            self.wait(regs.ier, deadline, |value| value == 0)?;
        }
        if let Some(stream) = self.streams[port as usize].as_mut() {
            stream.running = false;
        }
        Ok(())
    }
    pub fn stop(&mut self, port: Port) -> Result<(), Error> {
        self.usable()?;
        if self.streams[port as usize].is_none() {
            return Err(Error::NotPrepared);
        }
        let result = (|| {
            self.ring_authority(port)?;
            self.stop_inner(port)?;
            if !self.streams.iter().flatten().any(|stream| stream.running) {
                self.quiet_engines()?;
                self.drain()?;
                self.state = State::Stopped;
            }
            Ok(())
        })();
        self.finish(result)
    }
    /// Copy a fully stopped capture ring with actual CPU ownership; the whole
    /// controller must be quiet so domain completion is a real device proof.
    pub fn copy_stopped_capture(
        &mut self,
        port: Port,
        destination: &mut [u8],
    ) -> Result<(), Error> {
        self.usable()?;
        let stream = self.streams[port as usize]
            .as_ref()
            .ok_or(Error::NotPrepared)?;
        if !stream.started {
            return Err(Error::NotPrepared);
        }
        if port.direction() != Direction::Capture || destination.len() != stream.bytes {
            return Err(Error::InvalidBuffer);
        }
        if self.streams.iter().flatten().any(|stream| stream.running) {
            return Err(Error::Busy);
        }
        let result = (|| {
            self.ring_authority(port)?;
            self.quiet_engines()?;
            self.drain()?;
            let stream = self.streams[port as usize].as_ref().unwrap();
            // SAFETY: actual native engine disable/readback, no submissions,
            // all controller engines quiet and same-domain posted writes drained.
            unsafe { stream.dma.sync_for_cpu(0..stream.dma.bytes()) }.map_err(Error::Dma)?;
            for (offset, byte) in destination.iter_mut().enumerate() {
                let pointer = stream.cpu.address(offset, 1).map_err(Error::Memory)?;
                // SAFETY: actual retained CPU-owned RAM after the above proof.
                *byte = unsafe { pointer.as_ptr().read_volatile() };
            }
            Ok(())
        })();
        self.finish(result)
    }
}
