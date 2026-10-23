// SPDX-License-Identifier: GPL-2.0-only
//! Stream reset, format and BDL programming adapted from Linux
//! sound/hda/core/stream.c; descriptor ownership is local Stela policy.
//! AMD FIFO correction/start clamp adapts controllers/intel.c and
//! common/controller.c at a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright(c) 2004 Intel Corporation
//! Copyright (c) 2004 Takashi Iwai <tiwai@suse.de>
//!                     PeiSen Hou <pshou@realtek.com.tw>
use super::super::{Direction, Error, PcmFormat, Phase};
use super::{CodecGraph, Controller, ControllerToken, Registers, Verb, WidgetKind, registers::*};
use crate::bus::{
    dma::{DmaAllocator, DmaBuffer},
    i2c::Timer,
};
use core::sync::atomic::{Ordering, fence};

/// Opaque controller/reset-local allocation. A reset invalidates old IDs even
/// when the next allocation reuses the same descriptor and stream tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamId {
    index: u8,
    tag: u8,
    token: ControllerToken,
}

impl StreamId {
    pub fn descriptor_index(self) -> u8 {
        self.index
    }
    pub fn tag(self) -> u8 {
        self.tag
    }
}

/// Identity-selected stream-tag namespace. Tags are 1..=15, independently of
/// descriptor index; handles still carry index and controller reset generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StreamTagPolicy {
    /// Unique across both directions, allowing at most 15 allocations total.
    #[default]
    Global,
    /// Separate capture/playback namespaces, as required by modern Intel PCH
    /// and Linux's fallback when GCAP reports more than 15 fixed streams.
    PerDirection,
}

const AMD_FIFO_FRAMES: usize = 32;

/// Select from the actual controller's source-backed identity policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PositionPolicy {
    #[default]
    Link,
    /// AMD's fixed 32-PCM-frame FIFO consumer correction. The exact LPIB
    /// transport value remains available and never includes this correction.
    AmdFifo32,
}
impl PositionPolicy {
    pub(super) fn fifo_frames(self) -> usize {
        match self {
            Self::Link => 0,
            Self::AmdFifo32 => AMD_FIFO_FRAMES,
        }
    }
}

/// One position snapshot. Byte coordinates wrap modulo CBL; none is a monotonic
/// transfer counter or a precise acoustic timestamp. FIFO metadata never proves
/// that the device transferred additional bytes or completed another ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositionInfo {
    /// Exact LPIB value, including the permitted inclusive CBL endpoint.
    pub raw_link_bytes: u32,
    /// Actual normalized LPIB: CBL maps to 0, with no FIFO arithmetic.
    pub transport_bytes: u32,
    /// PCM consumer coordinate. AMD capture subtracts the effective FIFO delay
    /// modulo CBL; playback and ordinary controllers retain transport_bytes.
    pub pcm_bytes: u32,
    /// Effective delay in bytes, initially clamped to observed link progress.
    pub fifo_delay_bytes: u32,
    /// Whole interleaved PCM frames in the delay (byte remainder truncated).
    pub fifo_delay_frames: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamStatus {
    pub running: bool,
    /// At least one descriptor with IOC completed since the last poll. This
    /// coalesced bit is not a period count or an underrun/overrun detector.
    pub period_completed: bool,
    /// Actual normalized transport coordinate, retained for DMA diagnostics.
    pub position_bytes: u32,
    pub position: PositionInfo,
}

pub(super) struct Stream {
    id: StreamId,
    direction: Direction,
    format: PcmFormat,
    frame_bytes: u32,
    payload_words: u16,
    buffer: DmaBuffer,
    // Kept for the boot even when stopped: the controller can prefetch it.
    _bdl: DmaBuffer,
    pub(super) running: bool,
    pub(super) poisoned: bool,
    fifo_insufficient: bool,
}

impl<R: Registers, T: Timer> Controller<R, T> {
    pub(super) fn stop_descriptor(&mut self, index: u8) -> Result<(), Error> {
        let base = stream_base(index);
        let control = self.registers.read8(base + SD_CTL);
        if control == u8::MAX {
            return Err(Error::RegisterUnavailable {
                offset: base + SD_CTL,
            });
        }
        let control = control & !(SD_RUN | SD_STATUS);
        self.registers.write8(base + SD_CTL, control);
        self.wait(Phase::StreamStop, |r| {
            let value = r.read8(base + SD_CTL);
            value != u8::MAX && value & SD_RUN == 0
        })?;
        // SD_STS is W1C, so never access it through a dword CTL RMW.
        self.registers.write8(base + SD_STS, SD_STATUS);
        Ok(())
    }

    fn reset_descriptor(&mut self, index: u8) -> Result<(), Error> {
        self.stop_descriptor(index)?;
        let base = stream_base(index);
        self.registers.write8(base + SD_CTL, SD_RESET);
        self.wait(Phase::StreamResetEnter, |r| {
            let value = r.read8(base + SD_CTL);
            value != u8::MAX && value & SD_RESET != 0
        })?;
        self.registers.write8(base + SD_CTL, 0);
        self.wait(Phase::StreamResetExit, |r| {
            let value = r.read8(base + SD_CTL);
            value != u8::MAX && value & SD_RESET == 0
        })
    }

    fn stream(&self, id: StreamId) -> Result<&Stream, Error> {
        if id.token != self.token {
            return Err(Error::InvalidStream);
        }
        if self.lifecycle_failed {
            return Err(Error::NeedsReset);
        }
        if self.stopped {
            return Err(Error::Shutdown);
        }
        let stream = self
            .streams
            .get(usize::from(id.index))
            .and_then(Option::as_ref)
            .filter(|stream| stream.id == id)
            .ok_or(Error::InvalidStream)?;
        if stream.poisoned {
            return Err(Error::NeedsReset);
        }
        Ok(stream)
    }

    /// Allocate one fixed-direction stream, cyclic PCM buffer and 4K BDL.
    /// Periods must be frame-aligned multiples of 128 bytes. Entries are split
    /// at 4K boundaries, including controller families with that restriction.
    /// Max 256 entries and 4MiB cyclic buffers; bidirectional engines, non-PCM,
    /// scatter/gather external buffers and live refill are not provided here.
    pub fn allocate_stream(
        &mut self,
        direction: Direction,
        format: PcmFormat,
        period_bytes: usize,
        periods: usize,
        allocator: &mut dyn DmaAllocator,
    ) -> Result<StreamId, Error> {
        if self.lifecycle_failed {
            return Err(Error::NeedsReset);
        }
        if self.stopped {
            return Err(Error::Shutdown);
        }
        if self.config.probe_policy != super::ProbePolicy::Once && !self.discovery_ready {
            return Err(Error::NeedsDiscovery);
        }
        let encoded = format.encode()?;
        let frame = format.frame_bytes()?;
        let bytes = period_bytes
            .checked_mul(periods)
            .ok_or(Error::InvalidBuffer)?;
        if !(2..=256).contains(&periods)
            || period_bytes == 0
            || !period_bytes.is_multiple_of(128)
            || !period_bytes.is_multiple_of(frame)
            || !bytes.is_multiple_of(format.packet_bytes()?)
            || bytes > 4 * 1024 * 1024
        {
            return Err(Error::InvalidBuffer);
        }
        // A corrected consumer coordinate needs more than a FIFO's storage;
        // smaller rings cannot represent the source policy without ambiguity.
        let fifo_bytes = self.config.position_policy.fifo_frames() * frame;
        if fifo_bytes != 0 && bytes <= fifo_bytes {
            return Err(Error::InvalidBuffer);
        }
        // Reserve peak packet demand even for fractional-rate cadence. All
        // outputs use SDO0; capture is conservatively budgeted as one SDI until
        // codec/SDI-aware routing is implemented. Include the inline input tag
        // and byte padding; output tags are sideband SYNC and cost no SDO bits.
        let multiplier = u16::from(((encoded >> 11) & 7) as u8 + 1);
        let sample_bits = u16::from(format.bits) * u16::from(format.channels) * multiplier;
        let payload_words = match direction {
            Direction::Playback => sample_bits.div_ceil(16),
            Direction::Capture => (sample_bits.div_ceil(8) * 8 + 10).div_ceil(16),
        };
        let (total, limit) = match direction {
            Direction::Playback => (
                self.capabilities.output_payload_words,
                self.capabilities.output_stream_payload_words,
            ),
            Direction::Capture => (
                self.capabilities.input_payload_words,
                self.capabilities.input_stream_payload_words,
            ),
        };
        if limit != 0 && payload_words > limit {
            return Err(Error::LinkBandwidth {
                required_words: payload_words,
                available_words: limit,
            });
        }
        let reserved: u16 = self
            .streams
            .iter()
            .flatten()
            .filter(|stream| stream.direction == direction)
            .map(|stream| stream.payload_words)
            .sum();
        let available = total.saturating_sub(reserved);
        if payload_words > available {
            return Err(Error::LinkBandwidth {
                required_words: payload_words,
                available_words: available,
            });
        }
        let range = match direction {
            Direction::Capture => 0..self.capabilities.input_streams,
            Direction::Playback => {
                self.capabilities.input_streams
                    ..self.capabilities.input_streams + self.capabilities.output_streams
            }
        };
        let index = range
            .into_iter()
            .find(|index| self.streams[usize::from(*index)].is_none())
            .ok_or(Error::NoStream)?;
        let tag = (1..=15)
            .find(|tag| {
                !self.streams.iter().flatten().any(|stream| {
                    stream.id.tag == *tag
                        && (self.config.stream_tag_policy == StreamTagPolicy::Global
                            || stream.direction == direction)
                })
            })
            .ok_or(Error::NoStream)?;
        // Count before any allocation/MMIO. Every period end is an IOC entry.
        let mut count = 0;
        let mut offset = 0;
        while offset < bytes {
            let chunk = (4096 - offset % 4096).min(period_bytes - offset % period_bytes);
            count += 1;
            offset += chunk;
        }
        if count > 256 {
            return Err(Error::InvalidBuffer);
        }
        let mut buffer = allocator
            .allocate(bytes, 4096)
            .map_err(|_| Error::NoDmaMemory)?;
        let mut bdl = allocator
            .allocate(4096, 128)
            .map_err(|_| Error::NoDmaMemory)?;
        Self::check_dma(&buffer, 4096, self.capabilities.dma_address_bits)?;
        Self::check_dma(&bdl, 128, self.capabilities.dma_address_bits)?;
        if buffer.len() != bytes || bdl.len() < 4096 {
            return Err(Error::InvalidBuffer);
        }
        buffer.bytes_mut().fill(0);
        bdl.bytes_mut().fill(0);
        offset = 0;
        let mut entry = 0;
        while offset < bytes {
            let chunk = (4096 - offset % 4096).min(period_bytes - offset % period_bytes);
            bdl.write(entry * 16, (buffer.physical() + offset as u64).to_le());
            bdl.write(entry * 16 + 8, (chunk as u32).to_le());
            let period_end = (offset + chunk).is_multiple_of(period_bytes);
            bdl.write(entry * 16 + 12, u32::from(period_end).to_le());
            offset += chunk;
            entry += 1;
        }
        self.reset_descriptor(index)?;
        let base = stream_base(index);
        self.registers.write8(base + SD_CTL + 2, tag << 4); // tag bits23:20; stripe/priority/direction=0.
        self.registers.write32(base + SD_CBL, bytes as u32);
        self.registers.write16(base + SD_FORMAT, encoded);
        self.registers.write16(base + SD_LVI, (count - 1) as u16);
        self.registers
            .write32(base + SD_BDLPL, bdl.physical() as u32);
        self.registers
            .write32(base + SD_BDLPU, (bdl.physical() >> 32) as u32);
        fence(Ordering::SeqCst);
        let id = StreamId {
            index,
            tag,
            token: self.token,
        };
        self.streams[usize::from(index)] = Some(Stream {
            id,
            direction,
            format,
            frame_bytes: frame as u32,
            payload_words,
            buffer,
            _bdl: bdl,
            running: false,
            poisoned: false,
            fifo_insufficient: true,
        });
        Ok(id)
    }

    pub fn stream_direction(&self, id: StreamId) -> Result<Direction, Error> {
        Ok(self.stream(id)?.direction)
    }

    pub(super) fn require_routing_stopped(&self) -> Result<(), Error> {
        if self.lifecycle_failed {
            return Err(Error::NeedsReset);
        }
        // A failed stop can clear software `running` while DMA is still active.
        if self.streams.iter().flatten().any(|stream| stream.poisoned) {
            return Err(Error::NeedsReset);
        }
        if self.streams.iter().flatten().any(|stream| stream.running) {
            return Err(Error::StreamRunning);
        }
        Ok(())
    }

    pub fn stream_format(&self, id: StreamId) -> Result<PcmFormat, Error> {
        Ok(self.stream(id)?.format)
    }
    pub fn stream_buffer_bytes(&self, id: StreamId) -> Result<usize, Error> {
        Ok(self.stream(id)?.buffer.len())
    }

    /// Only a stopped stream's PCM memory can be accessed. Continuous refill,
    /// capture consumption and xrun accounting need a future period-ownership
    /// API; LPIB alone is insufficient to hand a live period back to the CPU.
    pub fn write_pcm(&mut self, id: StreamId, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let stream = self.stream(id)?;
        if stream.running {
            return Err(Error::StreamRunning);
        }
        if stream.direction != Direction::Playback
            || offset
                .checked_add(bytes.len())
                .is_none_or(|end| end > stream.buffer.len())
        {
            return Err(Error::InvalidBuffer);
        }
        let stream = self.streams[usize::from(id.index)]
            .as_mut()
            .ok_or(Error::InvalidStream)?;
        stream.buffer.bytes_mut()[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Fill a stopped capture ring with a known byte before starting DMA.
    /// This supports buffer sanitization and detecting actual device writes.
    pub fn fill_capture(&mut self, id: StreamId, value: u8) -> Result<(), Error> {
        let stream = self.stream(id)?;
        if stream.running {
            return Err(Error::StreamRunning);
        }
        if stream.direction != Direction::Capture {
            return Err(Error::InvalidStream);
        }
        self.streams[usize::from(id.index)]
            .as_mut()
            .ok_or(Error::InvalidStream)?
            .buffer
            .bytes_mut()
            .fill(value);
        Ok(())
    }

    /// Copy a stopped capture ring range into CPU-owned memory.
    pub fn read_pcm(&self, id: StreamId, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        let stream = self.stream(id)?;
        if stream.running {
            return Err(Error::StreamRunning);
        }
        if stream.direction != Direction::Capture
            || offset
                .checked_add(bytes.len())
                .is_none_or(|end| end > stream.buffer.len())
        {
            return Err(Error::InvalidBuffer);
        }
        fence(Ordering::Acquire);
        bytes.copy_from_slice(&stream.buffer.bytes()[offset..offset + bytes.len()]);
        Ok(())
    }

    pub fn start(&mut self, id: StreamId) -> Result<(), Error> {
        if self.routing_failed {
            return Err(Error::NeedsReset);
        }
        if self.stream(id)?.running {
            return Err(Error::StreamRunning);
        }
        self.require_sigmatel_route_power(id)?;
        let base = stream_base(id.index);
        self.registers.write8(base + SD_STS, SD_STATUS);
        fence(Ordering::SeqCst);
        self.registers.write8(base + SD_CTL, SD_RUN); // Polling; all IRQ enables remain zero.
        if let Err(error) = self.wait(Phase::StreamStart, |r| {
            let value = r.read8(base + SD_CTL);
            value != u8::MAX && value & SD_RUN != 0
        }) {
            let _ = self.stop_descriptor(id.index);
            self.streams[usize::from(id.index)]
                .as_mut()
                .unwrap()
                .poisoned = true;
            return Err(error);
        }
        self.streams[usize::from(id.index)]
            .as_mut()
            .unwrap()
            .running = true;
        // Linux resets the initial FIFO clamp on start, resume and unpause.
        self.streams[usize::from(id.index)]
            .as_mut()
            .unwrap()
            .fifo_insufficient = true;
        self.status(id).map(|_| ())
    }

    pub fn stop(&mut self, id: StreamId) -> Result<(), Error> {
        self.stream(id)?;
        let result = self.stop_descriptor(id.index);
        let stream = self.streams[usize::from(id.index)].as_mut().unwrap();
        stream.running = false;
        if result.is_err() {
            stream.poisoned = true;
        }
        // Coherent capture data is only exposed after stop acknowledged.
        fence(Ordering::SeqCst);
        result
    }

    pub fn status(&mut self, id: StreamId) -> Result<StreamStatus, Error> {
        let running = self.stream(id)?.running;
        let base = stream_base(id.index);
        let status = self.registers.read8(base + SD_STS);
        if status & (SD_FIFO_ERROR | SD_DESC_ERROR) != 0 {
            let _ = self.stop_descriptor(id.index);
            let stream = self.streams[usize::from(id.index)].as_mut().unwrap();
            stream.running = false;
            stream.poisoned = true;
            return Err(Error::StreamDma { status });
        }
        let position = self.position_info(id)?;
        self.registers.write8(base + SD_STS, status & SD_COMPLETE);
        Ok(StreamStatus {
            running,
            period_completed: status & SD_COMPLETE != 0,
            position_bytes: position.transport_bytes,
            position,
        })
    }

    /// Actual normalized link coordinate. CBL maps to zero, per HDA1.0a
    /// §3.3.37. No FIFO correction is credited as physical DMA progress.
    pub fn position(&mut self, id: StreamId) -> Result<u32, Error> {
        Ok(self.position_info(id)?.transport_bytes)
    }

    /// Exact LPIB readback, including CBL. Invalid values fail before arithmetic.
    pub fn link_position(&mut self, id: StreamId) -> Result<u32, Error> {
        let bytes = self.stream(id)?.buffer.len();
        let position = self.registers.read32(stream_base(id.index) + SD_LPIB);
        if position as usize > bytes {
            return Err(Error::InvalidPosition(position));
        }
        Ok(position)
    }

    /// Read actual transport position and apply only the identity-selected PCM
    /// consumer policy. AMD capture subtracts 32 frames modulo CBL, initially
    /// clamped to actual observed progress; playback reports its delay without
    /// changing position. A late first poll cannot infer missed complete wraps.
    pub fn position_info(&mut self, id: StreamId) -> Result<PositionInfo, Error> {
        let (bytes, frame_bytes, direction, insufficient) = {
            let stream = self.stream(id)?;
            (
                stream.buffer.len() as u32,
                stream.frame_bytes,
                stream.direction,
                stream.fifo_insufficient,
            )
        };
        let raw = self.link_position(id)?;
        let transport = if raw == bytes { 0 } else { raw };
        let full_delay = self.config.position_policy.fifo_frames() as u32 * frame_bytes;
        let delay = if full_delay != 0 && insufficient && raw < full_delay {
            raw
        } else {
            full_delay
        };
        if full_delay != 0 && raw >= full_delay {
            self.streams[usize::from(id.index)]
                .as_mut()
                .unwrap()
                .fifo_insufficient = false;
        }
        let pcm = if direction == Direction::Capture && delay != 0 {
            if transport >= delay {
                transport - delay
            } else {
                bytes - (delay - transport)
            }
        } else {
            transport
        };
        Ok(PositionInfo {
            raw_link_bytes: raw,
            transport_bytes: transport,
            pcm_bytes: pcm,
            fifo_delay_bytes: delay,
            fifo_delay_frames: delay / frame_bytes,
        })
    }

    /// Bind one standard analog PCM converter. The caller supplies an actual
    /// enumerated graph and must separately power/unmute/route its widgets and
    /// pins. No speaker/OEM amplifier policy is guessed here. Binding requires
    /// a stopped controller stream and is verified through converter readback.
    /// Mono/stereo converters consume their declared channel span starting at
    /// `channel`. Wider converters need channel-count control and are rejected.
    /// A converter reserved by an analog route cannot be rebound, including
    /// reconfiguration by the same stream, until controller reinitialization.
    pub fn bind_converter(
        &mut self,
        graph: &CodecGraph,
        node: u8,
        id: StreamId,
        channel: u8,
    ) -> Result<(), Error> {
        if self.routing_failed {
            return Err(Error::NeedsReset);
        }
        if self.routes.iter().any(|(_, route)| {
            route.codec_address() == graph.address && route.nodes().contains(&node)
        }) || self
            .codec_controls
            .iter()
            .any(|(_, codec, control)| *codec == graph.address && *control == node)
        {
            return Err(Error::RouteInUse);
        }
        self.validate_converter(graph, node, id, channel)?;
        let stream = self.stream(id)?;
        let format = stream.format.encode()?;
        let binding = (id.tag << 4) | channel;
        self.verb(Verb::long(graph.address, node, 2, format)?)?;
        self.verb(Verb::short(graph.address, node, 0x706, binding)?)?;
        let read_format = self.verb(Verb::short(graph.address, node, 0xa00, 0)?)?;
        let read_binding = self.verb(Verb::short(graph.address, node, 0xf06, 0)?)?;
        if read_format != u32::from(format) || read_binding != u32::from(binding) {
            return Err(Error::ConverterRejected);
        }
        Ok(())
    }
    pub(super) fn validate_converter(
        &self,
        graph: &CodecGraph,
        node: u8,
        id: StreamId,
        channel: u8,
    ) -> Result<(), Error> {
        if graph.token != self.token {
            return Err(Error::InvalidCodecGraph);
        }
        let stream = self.stream(id)?;
        if stream.running {
            return Err(Error::StreamRunning);
        }
        let widget = graph.widget(node).ok_or(Error::InvalidCodecGraph)?;
        let expected = match stream.direction {
            Direction::Playback => WidgetKind::Output,
            Direction::Capture => WidgetKind::Input,
        };
        if widget.kind != expected || widget.capabilities & (1 << 9) != 0 || widget.channels() > 2 {
            return Err(Error::UnsupportedTopology);
        }
        if !widget.pcm.supports(stream.format)
            || channel >= stream.format.channels
            || widget.channels() > stream.format.channels - channel
        {
            return Err(Error::InvalidFormat);
        }
        Ok(())
    }
}
