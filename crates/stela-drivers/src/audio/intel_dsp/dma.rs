// SPDX-License-Identifier: GPL-2.0-only
//! HDA host DMA with retained real RAM pins and device-domain IOVAs.
//! BDL and cAVS host-stream sequence adapt pinned SOF hda-stream.c.
//! Copyright(c) 2018 Intel Corporation
use super::{Controller, Error, Phase, Registers, registers::*};
use crate::{
    audio::Direction,
    bus::{
        dma::{
            mapping::{Direction as DmaDirection, DmaDomain, DmaMapping},
            memory::{CacheAttribute, CpuMapping, PageSource},
        },
        i2c::Timer,
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
        // checked real retained RAM mapping, non-overlapping source slice.
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
        let bytes = bytes
            .checked_add(4095)
            .map(|n| n & !4095)
            .filter(|n| *n >= 4096 && *n <= 16 * 1024 * 1024)
            .ok_or(Error::Buffer)?;
        if tag == 0 || tag > 15 || index > 29 {
            return Err(Error::Buffer);
        }
        let data = Buffer::allocate(
            source,
            domain.clone(),
            bytes,
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
        stream.descriptors(bytes / 2)?;
        Ok(stream)
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
        let base = self.data.address()?;
        for index in 0..self.bytes / period {
            let mut entry = [0u8; 16];
            entry[..8].copy_from_slice(&(base + (index * period) as u64).to_le_bytes());
            entry[8..12].copy_from_slice(&(period as u32).to_le_bytes());
            entry[12..].copy_from_slice(&1u32.to_le_bytes());
            self.bdl.copy_to(index * 16, &entry)?;
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
        // SAFETY: actual stopped DMA and successful sync transferred ownership;
        // bounds checked retained mapping and non-overlapping destination.
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
    fn stopped(&mut self) -> Result<(), Error> {
        self.running = false;
        // SAFETY: observed SD_RUN clear precedes this cache ownership transfer.
        // The DSP may not use host data independently of this HDA stream.
        if self.data.dma.address().is_ok() {
            unsafe {
                self.data.dma.sync_for_cpu(0..self.bytes)?;
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
    fn stream_mut(&mut self, loader: bool, iccmax: bool) -> Result<&mut Stream, Error> {
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
        self.delay(3);
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
        // Read actual hardware programming rather than report a posted write
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
            self.stream_mut(loader, iccmax)?.stopped()?;
        }
        Ok(())
    }
}
