// SPDX-License-Identifier: GPL-2.0-only
//! HDA host DMA with kept real RAM pins and device-domain IOVAs.
//! BDL and cAVS host-stream sequence adapt pinned SOF hda-stream.c.
//! Copyright(c) 2018 Intel Corporation
use super::{Controller, Error, Phase, Registers, registers::*};
use crate::Timer;
use crate::{
    Direction,
    bus::dma::{
        mapping::{Direction as DmaDirection, DmaDomain, DmaMapping},
        memory::{CacheAttribute, CpuMapping, PageSource},
    },
};
use alloc::sync::Arc;
use core::sync::atomic::{Ordering, fence};

struct Buffer {
    cpu: CpuMapping,
    dma: DmaMapping,
    published: bool,
}
impl Buffer {
    fn allocate(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        limit: u64,
        direction: DmaDirection,
    ) -> Result<Self, Error> {
        let geometry = source.page_geometry()?;
        if geometry.base_shift() != 12 {
            return Err(Error::Buffer);
        }
        let pin = source.allocate(bytes, 4096, CacheAttribute::WriteBack)?;
        if pin.logical_bytes() < bytes
            || pin.page_shift() != 12
            || pin.cache_attribute() != CacheAttribute::WriteBack
        {
            return Err(Error::Buffer);
        }
        let cpu = pin.cpu_mapping(CacheAttribute::WriteBack)?;
        let dma = DmaMapping::map(domain, pin, direction, limit)?;
        Ok(Self {
            cpu,
            dma,
            published: false,
        })
    }
    fn address(&self) -> Result<u64, Error> {
        Ok(self.dma.address()?)
    }
    fn copy_to(&self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let pointer = self.cpu.address(offset, bytes.len())?;
        // SAFETY: this buffer is CPU-owned and caller prevents concurrent DMA;
        // checked real kept RAM mapping, non-overlapping source slice.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.as_ptr(), bytes.len()) };
        Ok(())
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.published {
            // SAFETY: no hardware ever received this private allocation IOVA.
            let _ = unsafe { self.dma.unmap() };
        }
        // DmaMapping quarantines any still-live published or failed mapping.
    }
}
pub(super) struct Stream {
    data: Buffer,
    bdl: Buffer,
    domain: Arc<dyn DmaDomain>,
    pub index: u8,
    pub tag: u8,
    pub direction: Direction,
    pub bytes: usize,
    pub format: u16,
    pub running: bool,
    pub cpu_owned: bool,
    entries: u16,
}
impl Stream {
    pub fn allocate(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        limit: u64,
        index: u8,
        tag: u8,
        direction: Direction,
    ) -> Result<Self, Error> {
        let capacity = bytes
            .checked_add(4095)
            .map(|n| n & !4095)
            .filter(|n| *n >= 4096 && *n <= 16 * 1024 * 1024)
            .ok_or(Error::Buffer)?;
        if bytes < 4096 || tag == 0 || tag > 15 || index > 29 {
            return Err(Error::Buffer);
        }
        let data = Buffer::allocate(
            source,
            domain.clone(),
            capacity,
            limit,
            match direction {
                Direction::Playback => DmaDirection::ToDevice,
                Direction::Capture => DmaDirection::FromDevice,
            },
        )?;
        let bdl = Buffer::allocate(source, domain.clone(), 4096, limit, DmaDirection::ToDevice)?;
        let mut stream = Self {
            data,
            bdl,
            domain,
            index,
            tag,
            direction,
            bytes,
            format: 0x40,
            running: false,
            cpu_owned: true,
            entries: 0,
        };
        // The domain supplies one contiguous IOVA even over scattered pins.
        // Two 128-byte-aligned segments meet LVI>=1 without a physical-contiguity
        // or identity-map assumption. cAVS2.5 has no 4K BDLE split quirk.
        // Allocations round to pages; the ROM transfer length does not. Keep
        // both BDLE starts 128-byte aligned, with an exact final partial BDLE.
        let first = (bytes / 2) & !127;
        stream.descriptor(0, 0, first)?;
        stream.descriptor(1, first, bytes - first)?;
        stream.entries = 2;
        Ok(stream)
    }
    fn descriptor(&self, index: usize, offset: usize, bytes: usize) -> Result<(), Error> {
        let base = self.data.address()?;
        let mut entry = [0u8; 16];
        entry[..8].copy_from_slice(&(base + offset as u64).to_le_bytes());
        entry[8..12].copy_from_slice(&(bytes as u32).to_le_bytes());
        entry[12..].copy_from_slice(&1u32.to_le_bytes());
        self.bdl.copy_to(index * 16, &entry)
    }
    pub fn descriptors(&mut self, period: usize) -> Result<(), Error> {
        if self.running
            || !self.cpu_owned
            || period == 0
            || !period.is_multiple_of(128)
            || !self.bytes.is_multiple_of(period)
            || !(2..=256).contains(&(self.bytes / period))
        {
            return Err(Error::Buffer);
        }
        for index in 0..self.bytes / period {
            self.descriptor(index, index * period, period)?;
        }
        self.entries = (self.bytes / period) as u16;
        Ok(())
    }
    pub fn copy_to(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if self.running
            || !self.cpu_owned
            || self.direction != Direction::Playback
            || offset
                .checked_add(bytes.len())
                .is_none_or(|end| end > self.bytes)
        {
            return Err(Error::Buffer);
        }
        self.data.copy_to(offset, bytes)
    }
    pub fn copy_from(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        if self.running
            || !self.cpu_owned
            || self.direction != Direction::Capture
            || offset
                .checked_add(bytes.len())
                .is_none_or(|end| end > self.bytes)
        {
            return Err(Error::Buffer);
        }
        let pointer = self.data.cpu.address(offset, bytes.len())?;
        // SAFETY: stopped DMA and successful sync transferred ownership;
        // bounds checked mapping and non-overlapping destination.
        unsafe {
            core::ptr::copy_nonoverlapping(pointer.as_ptr(), bytes.as_mut_ptr(), bytes.len())
        };
        Ok(())
    }
    fn publish(&mut self) -> Result<(), Error> {
        self.data.dma.sync_for_device(0..self.bytes)?;
        self.bdl.dma.sync_for_device(0..4096)?;
        self.data.published = true;
        self.bdl.published = true;
        self.cpu_owned = false;
        fence(Ordering::Release);
        Ok(())
    }
    fn stopped(&mut self) {
        // RUN clear stops new host-stream requests, but previously posted RAM
        // writes can still be in flight. Keep device ownership until drain.
        self.running = false;
    }
    unsafe fn complete_stopped(&mut self) -> Result<(), Error> {
        // SAFETY: caller verified every host stream stopped and the
        // requester BME clear/readback, then drained this original domain.
        unsafe {
            if self.data.dma.address().is_ok() {
                self.data.dma.sync_for_cpu(0..self.bytes)?;
            }
            if self.bdl.dma.address().is_ok() {
                self.bdl.dma.sync_for_cpu(0..4096)?;
            }
        }
        self.cpu_owned = true;
        Ok(())
    }
    pub fn retire(&mut self) -> Result<(), Error> {
        if self.running {
            return Err(Error::Busy);
        }
        // SAFETY: caller has stopped every DMA/core and disabled mastering.
        unsafe {
            self.domain.drain_posted_writes()?;
        }
        // SAFETY: all engines, submissions and polled callbacks are drained;
        // original pins/domain remain held if either invalidation fails.
        unsafe {
            if self.bdl.dma.address().is_ok() {
                self.bdl.dma.unmap()?;
            }
            if self.data.dma.address().is_ok() {
                self.data.dma.unmap()?;
            }
        }
        Ok(())
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn complete_stopped_dma(&mut self) -> Result<(), Error> {
        self.minimum_guard()?;
        // Check the complete requester, including ICCmax and loader,
        // rather than trusting one stream's software running flag. Firmware
        // remains alive for pause/restart, but cannot initiate translated DMA
        // once the original requester is contained.
        for index in 0..self.input_streams + self.output_streams {
            if self.registers.read8(Bar::Hda, stream_base(index))? & RUN != 0 {
                return Err(Error::Busy);
            }
        }
        if self.registers.read8(Bar::Hda, CORBCTL)? & 2 != 0
            || self.registers.read8(Bar::Hda, RIRBCTL)? & 2 != 0
        {
            return Err(Error::Busy);
        }
        self.registers.set_bus_master(false)?;
        self.dma_contained = true;
        // Drain every domain before any CPU ownership transfer.
        // Distinct streams may hold distinct domains for this same requester.
        for stream in [&self.pcm, &self.boot, &self.iccmax].into_iter().flatten() {
            // SAFETY: every host engine/submission path is stopped, native
            // mastering is acknowledged contained, and all original owners
            // remain held. This is payload completion, not cache sync.
            unsafe { stream.domain.drain_posted_writes()? };
        }
        for stream in [&mut self.pcm, &mut self.boot, &mut self.iccmax]
            .into_iter()
            .flatten()
        {
            // SAFETY: its own original domain completed above, with no
            // subsequent bus-master enable or stream submission.
            unsafe { stream.complete_stopped()? };
        }
        Ok(())
    }
    fn stream_mut(&mut self, loader: bool, iccmax: bool) -> Result<&mut Stream, Error> {
        self.minimum_guard()?;
        if loader {
            if iccmax {
                self.iccmax.as_mut()
            } else {
                self.boot.as_mut()
            }
        } else {
            self.pcm.as_mut()
        }
        .ok_or(Error::State)
    }
    pub(super) fn program_stream(&mut self, loader: bool, iccmax: bool) -> Result<(), Error> {
        self.minimum_guard()?;
        let (index, tag, bytes, format, entries, data_bdl) = {
            let stream = self.stream_mut(loader, iccmax)?;
            stream.publish()?;
            (
                stream.index,
                stream.tag,
                stream.bytes,
                stream.format,
                stream.entries,
                stream.bdl.address()?,
            )
        };
        let base = stream_base(index);
        let mask = 1u32 << index;
        self.update(Bar::Hda, self.pp + PPCTL, mask, mask)?;
        let start = self.timer.now_us();
        let previous = self.registers.read8(Bar::Hda, base)?;
        self.registers
            .write8(Bar::Hda, base, previous & !(RUN | 0x1c))?;
        self.stream_poll(index, RUN, 0, start, Phase::StreamRun)?;
        self.registers.write8(Bar::Hda, base + STS, W1C)?;
        let start = self.timer.now_us();
        self.registers
            .write8(Bar::Hda, base, (previous & !(RUN | 0x1c)) | SRST)?;
        self.stream_poll(index, SRST, SRST, start, Phase::StreamReset)?;
        let start = self.timer.now_us();
        self.registers
            .write8(Bar::Hda, base, previous & !(RUN | SRST | 0x1c))?;
        self.delay(3)?;
        self.stream_poll(index, SRST, 0, start, Phase::StreamReset)?;
        // Stream tag occupies byte2, separately from byte3 W1C status.
        let ctl2 = self.registers.read8(Bar::Hda, base + 2)?;
        self.registers
            .write8(Bar::Hda, base + 2, (ctl2 & 15) | tag << 4)?;
        self.registers.write16(Bar::Hda, base + FORMAT, format)?;
        self.write(Bar::Hda, base + CBL, bytes as u32)?;
        self.registers.write16(Bar::Hda, base + LVI, entries - 1)?;
        self.write(Bar::Hda, base + BDLPL, data_bdl as u32)?;
        self.write(Bar::Hda, base + BDLPU, (data_bdl >> 32) as u32)?;
        if loader && !iccmax {
            self.write(
                Bar::Hda,
                self.spib + 8 + usize::from(index) * 8,
                bytes as u32,
            )?;
            self.update(Bar::Hda, self.spib + 4, mask, mask)?;
        }
        // Read hardware programming rather than report a posted write
        // as completion. No device status byte is ever dword-RMW'd.
        if self.read(Bar::Hda, base + BDLPL)? != data_bdl as u32
            || self.read(Bar::Hda, base + BDLPU)? != (data_bdl >> 32) as u32
            || self.read(Bar::Hda, base + CBL)? != bytes as u32
            || self.registers.read16(Bar::Hda, base + LVI)? != entries - 1
            || self.registers.read16(Bar::Hda, base + FORMAT)? != format
        {
            return Err(Error::Rejected(Bar::Hda, base));
        }
        Ok(())
    }
    fn stream_poll(
        &mut self,
        index: u8,
        mask: u8,
        value: u8,
        start: u64,
        phase: Phase,
    ) -> Result<(), Error> {
        self.minimum_guard()?;
        loop {
            if self.timer.now_us().wrapping_sub(start) >= 500 {
                return Err(Error::Timeout(phase));
            }
            let observed = self.registers.read8(Bar::Hda, stream_base(index))?;
            if self.timer.now_us().wrapping_sub(start) >= 500 {
                return Err(Error::Timeout(phase));
            }
            if observed & mask == value {
                return Ok(());
            }
            self.timer.relax();
        }
    }
    pub(super) fn stream_run(
        &mut self,
        loader: bool,
        iccmax: bool,
        run: bool,
    ) -> Result<(), Error> {
        self.minimum_guard()?;
        if run {
            let (index, tag, bytes, format, entries, bdl) = {
                let stream = self.stream_mut(loader, iccmax)?;
                (
                    stream.index,
                    stream.tag,
                    stream.bytes,
                    stream.format,
                    stream.entries,
                    stream.bdl.address()?,
                )
            };
            let base = stream_base(index);
            let control = self.read(Bar::Hda, self.pp + PPCTL)?;
            let owned = GPROCEN | (1u32 << index);
            if control & owned != owned
                || self.read(Bar::Hda, base + BDLPL)? != bdl as u32
                || self.read(Bar::Hda, base + BDLPU)? != (bdl >> 32) as u32
                || self.read(Bar::Hda, base + CBL)? != bytes as u32
                || self.registers.read16(Bar::Hda, base + FORMAT)? != format
                || self.registers.read16(Bar::Hda, base + LVI)? != entries - 1
                || self.registers.read8(Bar::Hda, base + 2)? >> 4 != tag
            {
                return Err(Error::Rejected(Bar::Hda, base));
            }
            if !loader && self.read(Bar::Dsp, ADSPCS)? & 0x01010101 != 0x01010000 {
                return Err(Error::Authority);
            }
        }
        let index = {
            let stream = self.stream_mut(loader, iccmax)?;
            if run {
                stream.publish()?;
                stream.running = true;
            }
            stream.index
        };
        if run && self.dma_contained {
            // Publication above relinquished CPU ownership before a
            // BME enable can make any device request possible again.
            self.dma_contained = false;
            self.registers.set_bus_master(true)?;
        }
        let base = stream_base(index);
        let start = self.timer.now_us();
        let before = self.registers.read8(Bar::Hda, base)?;
        self.registers.write8(
            Bar::Hda,
            base,
            if run { before | RUN } else { before & !RUN },
        )?;
        self.stream_poll(
            index,
            RUN,
            if run { RUN } else { 0 },
            start,
            Phase::StreamRun,
        )?;
        if !run {
            self.stream_mut(loader, iccmax)?.stopped();
        }
        Ok(())
    }
}
