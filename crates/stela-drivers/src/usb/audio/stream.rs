// SPDX-License-Identifier: GPL-2.0-or-later
//! Polled PCM packet ownership. Buffers return to the CPU only after a terminal
//! isochronous completion or acknowledged endpoint removal. No live refill is
//! inferred from a clock, ring position, or failed cancellation.
use super::packet::Packetizer;
use super::{Binding, Completion, Error, Format, PacketStatus, ResolvedClock, Sync, Transport};
use crate::{
    audio::Direction,
    bus::dma::{DmaAllocator, DmaBuffer},
    usb::xhci::Endpoint,
};
use alloc::{collections::VecDeque, vec::Vec};

const PACKETS: usize = 32;
const BUFFER_BYTES: usize = 4096;
const PCM_LIMIT: usize = 1024 * 1024;
const FEEDBACK_TIMEOUT_US: u64 = 100_000;

struct Packet<K> {
    buffer: DmaBuffer,
    ticket: Option<K>,
    bytes: usize,
}
struct Lane<K> {
    endpoint: Option<Endpoint>,
    packets: Vec<Packet<K>>,
    order: VecDeque<usize>,
}
impl<K> Lane<K> {
    fn new(dma: &mut dyn DmaAllocator) -> Result<Self, Error> {
        let mut packets = Vec::new();
        for _ in 0..PACKETS {
            packets.push(Packet {
                buffer: dma.allocate(BUFFER_BYTES, BUFFER_BYTES)?,
                ticket: None,
                bytes: 0,
            });
        }
        Ok(Self {
            endpoint: None,
            packets,
            order: VecDeque::new(),
        })
    }
    fn queued(&self) -> usize {
        self.packets.iter().filter(|p| p.ticket.is_some()).count()
    }
    fn endpoints(&self) -> Vec<Endpoint> {
        self.endpoint.into_iter().collect()
    }
    fn released(&mut self) {
        for p in &mut self.packets {
            p.ticket = None;
            p.bytes = 0;
        }
        self.endpoint = None;
        self.order.clear();
    }
}
struct Playback {
    format: Format,
    rate: u32,
    clock: ResolvedClock,
    packetizer: Packetizer,
    planned: Option<usize>,
    finite: bool,
    last_feedback: u64,
    last_progress: u64,
}
struct Capture {
    format: Format,
    rate: u32,
    clock: ResolvedClock,
    requested: bool,
    implicit: bool,
    last_progress: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub playback_frames: u64,
    pub capture_frames: u64,
    pub feedback_updates: u64,
    pub queued_playback: usize,
    pub queued_capture: usize,
    pub playback_drained: bool,
}

pub struct AudioDevice<T: Transport> {
    transport: T,
    binding: Binding,
    output: Lane<T::Ticket>,
    input: Lane<T::Ticket>,
    feedback: Lane<T::Ticket>,
    playback: Option<Playback>,
    capture: Option<Capture>,
    output_pcm: VecDeque<u8>,
    input_pcm: VecDeque<u8>,
    implicit_frames: VecDeque<usize>,
    progress: Progress,
    poisoned: bool,
    /// First failure is retained even if cleanup itself fails.
    pub last_fault: Option<Error>,
}

impl<T: Transport> AudioDevice<T> {
    pub fn new(transport: T, binding: Binding, dma: &mut dyn DmaAllocator) -> Result<Self, Error> {
        Ok(Self {
            transport,
            binding,
            output: Lane::new(dma)?,
            input: Lane::new(dma)?,
            feedback: Lane::new(dma)?,
            playback: None,
            capture: None,
            output_pcm: VecDeque::new(),
            input_pcm: VecDeque::new(),
            implicit_frames: VecDeque::new(),
            progress: Progress::default(),
            poisoned: false,
            last_fault: None,
        })
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    pub fn progress(&self) -> Progress {
        let mut p = self.progress;
        p.queued_playback = self.output.queued();
        p.queued_capture = self.input.queued();
        p
    }
    fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    fn clock(&mut self, format: &Format, rate: u32) -> Result<ResolvedClock, Error> {
        let clock = self
            .binding
            .graph
            .resolve_clock(&mut self.transport, format.clock)?;
        for (other_clock, other_rate) in self
            .playback
            .iter()
            .map(|p| (p.clock, p.rate))
            .chain(self.capture.iter().map(|c| (c.clock, c.rate)))
        {
            if other_clock.source == clock.source
                && other_clock.source_rate(other_rate)? != clock.source_rate(rate)?
            {
                return Err(Error::Busy);
            }
        }
        self.binding
            .graph
            .set_rate(&mut self.transport, clock, rate)?;
        Ok(clock)
    }
    fn format(&self, index: usize, direction: Direction) -> Result<Format, Error> {
        let f = self
            .binding
            .formats
            .get(index)
            .filter(|f| f.direction == direction)
            .ok_or(Error::Format)?;
        Ok(f.clone())
    }
    /// Start a finite or continuous playback queue with actual interleaved PCM.
    /// A continuous producer must replenish it before all submitted packets
    /// complete; starvation is an explicit underrun, never implicit silence.
    pub fn start_playback(
        &mut self,
        index: usize,
        rate: u32,
        pcm: &[u8],
        finite: bool,
    ) -> Result<(), Error> {
        self.ready()?;
        if self.playback.is_some() {
            return Err(Error::Busy);
        }
        let format = self.format(index, Direction::Playback)?;
        if format.frame_bytes() == 0
            || pcm.is_empty()
            || pcm.len() > PCM_LIMIT
            || !pcm.len().is_multiple_of(format.frame_bytes())
        {
            return Err(Error::Format);
        }
        let packetizer = Packetizer::new(&format, rate)?;
        if self.capture.as_ref().is_some_and(|c| {
            c.format.interface == format.interface || c.format.data.dci() == format.data.dci()
        }) {
            return Err(Error::Busy);
        }
        if let Sync::Implicit {
            interface,
            alternate,
            ..
        } = format.sync
            && self.capture.as_ref().is_some_and(|c| {
                c.format.interface != interface || c.format.alternate != alternate || c.rate != rate
            })
        {
            return Err(Error::Busy);
        }
        let clock = self.clock(&format, rate)?;
        let result = (|| {
            if let Sync::Implicit {
                interface,
                alternate,
                ..
            } = format.sync
            {
                let capture_index = self
                    .binding
                    .formats
                    .iter()
                    .position(|f| {
                        f.interface == interface
                            && f.alternate == alternate
                            && f.direction == Direction::Capture
                    })
                    .ok_or(Error::Descriptor(
                        "implicit feedback source format is missing",
                    ))?;
                self.start_capture_inner(capture_index, rate, false, true)?;
            }
            let mut endpoints = vec![format.data];
            if let Sync::Explicit(endpoint) = format.sync {
                endpoints.push(endpoint);
            }
            self.output.endpoint = Some(format.data);
            if let Sync::Explicit(endpoint) = format.sync {
                self.feedback.endpoint = Some(endpoint);
            }
            self.output_pcm.extend(pcm.iter().copied());
            self.progress.playback_drained = false;
            self.playback = Some(Playback {
                format,
                rate,
                clock,
                packetizer,
                planned: None,
                finite,
                last_feedback: self.transport.now_us(),
                last_progress: self.transport.now_us(),
            });
            self.transport.alternate(
                self.playback.as_ref().unwrap().format.interface,
                self.playback.as_ref().unwrap().format.alternate,
            )?;
            self.transport.configure(Direction::Playback, &endpoints)?;
            self.queue_inputs()?;
            self.queue_output()?;
            Ok(())
        })();
        if let Err(error) = result {
            return self.fail(error);
        }
        Ok(())
    }
    pub fn write_playback(&mut self, pcm: &[u8]) -> Result<(), Error> {
        self.ready()?;
        let p = self.playback.as_ref().ok_or(Error::NotRunning)?;
        if p.finite {
            return Err(Error::Busy);
        }
        if !pcm.len().is_multiple_of(p.format.frame_bytes()) {
            return Err(Error::Format);
        }
        if self.output_pcm.len().saturating_add(pcm.len()) > PCM_LIMIT {
            return Err(Error::Overrun);
        }
        self.output_pcm.extend(pcm.iter().copied());
        Ok(())
    }
    pub fn finish_playback(&mut self) -> Result<(), Error> {
        self.ready()?;
        self.playback.as_mut().ok_or(Error::NotRunning)?.finite = true;
        Ok(())
    }
    pub fn start_capture(&mut self, index: usize, rate: u32) -> Result<(), Error> {
        self.ready()?;
        let format = self.format(index, Direction::Capture)?;
        if self
            .capture
            .as_ref()
            .is_some_and(|c| c.format != format || c.rate != rate)
        {
            return Err(Error::Busy);
        }
        let result = self.start_capture_inner(index, rate, true, false);
        if let Err(error) = result {
            if self.input.endpoint.is_none() {
                return Err(error);
            }
            return self.fail(error);
        }
        Ok(())
    }
    fn start_capture_inner(
        &mut self,
        index: usize,
        rate: u32,
        requested: bool,
        implicit: bool,
    ) -> Result<(), Error> {
        let format = self.format(index, Direction::Capture)?;
        Packetizer::new(&format, rate)?;
        if let Some(c) = self.capture.as_mut() {
            if c.format != format || c.rate != rate {
                return Err(Error::Busy);
            }
            c.requested |= requested;
            c.implicit |= implicit;
            return Ok(());
        }
        if self.playback.as_ref().is_some_and(|p| {
            p.format.interface == format.interface || p.format.data.dci() == format.data.dci()
        }) {
            return Err(Error::Busy);
        }
        let clock = self.clock(&format, rate)?;
        self.input.endpoint = Some(format.data);
        self.capture = Some(Capture {
            format,
            rate,
            clock,
            requested,
            implicit,
            last_progress: self.transport.now_us(),
        });
        let format = &self.capture.as_ref().unwrap().format;
        self.transport
            .alternate(format.interface, format.alternate)?;
        self.transport
            .configure(Direction::Capture, &self.input.endpoints())?;
        self.queue_inputs()
    }
    pub fn read_capture(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        self.ready()?;
        let c = self
            .capture
            .as_ref()
            .filter(|c| c.requested)
            .ok_or(Error::NotRunning)?;
        if !out.len().is_multiple_of(c.format.frame_bytes()) {
            return Err(Error::Format);
        }
        let bytes = self.input_pcm.len().min(out.len());
        for byte in &mut out[..bytes] {
            *byte = self.input_pcm.pop_front().unwrap();
        }
        Ok(bytes)
    }
    pub fn set_mute(&mut self, entity: u8, channel: u8, muted: bool) -> Result<(), Error> {
        self.ready()?;
        self.binding
            .graph
            .set_mute(&mut self.transport, entity, channel, muted)
    }
    pub fn set_volume(&mut self, entity: u8, channel: u8, volume_db256: i16) -> Result<(), Error> {
        self.ready()?;
        self.binding
            .graph
            .set_volume(&mut self.transport, entity, channel, volume_db256)
    }
    pub fn select_clock(&mut self, entity: u8, pin: u8) -> Result<(), Error> {
        self.ready()?;
        if self.playback.is_some() || self.capture.is_some() {
            return Err(Error::Busy);
        }
        self.binding
            .graph
            .clock_selection(&mut self.transport, entity, pin)
    }
    pub fn select_input(&mut self, entity: u8, pin: u8) -> Result<(), Error> {
        self.ready()?;
        if self.playback.is_some() || self.capture.is_some() {
            return Err(Error::Busy);
        }
        self.binding
            .graph
            .signal_selection(&mut self.transport, entity, pin)
    }
    fn queue_inputs(&mut self) -> Result<(), Error> {
        for lane in [&mut self.input, &mut self.feedback] {
            let Some(endpoint) = lane.endpoint else {
                continue;
            };
            let bytes = if endpoint.attributes & 0x30 == 0x10 {
                if self.binding.speed == 3 { 4 } else { 3 }
            } else {
                self.capture
                    .as_ref()
                    .ok_or(Error::NotRunning)?
                    .format
                    .max_bytes
            };
            for (index, packet) in lane.packets.iter_mut().enumerate() {
                if packet.ticket.is_none() {
                    packet.buffer.bytes_mut()[..bytes].fill(0xa5);
                    packet.bytes = bytes;
                    packet.ticket = Some(self.transport.submit(
                        &endpoint,
                        packet.buffer.physical(),
                        bytes,
                    )?);
                    lane.order.push_back(index);
                }
            }
        }
        Ok(())
    }
    fn queue_output(&mut self) -> Result<(), Error> {
        let Some(p) = self.playback.as_mut() else {
            return Ok(());
        };
        let endpoint = self.output.endpoint.ok_or(Error::NotRunning)?;
        for (index, packet) in self.output.packets.iter_mut().enumerate() {
            if packet.ticket.is_some() {
                continue;
            }
            let bytes = match p.planned.take() {
                Some(bytes) => bytes,
                None => {
                    if matches!(p.format.sync, Sync::Implicit { .. }) {
                        let Some(frames) = self.implicit_frames.pop_front() else {
                            break;
                        };
                        frames
                            .checked_mul(p.format.frame_bytes())
                            .ok_or(Error::Feedback)?
                    } else {
                        p.packetizer.next_bytes()?
                    }
                }
            };
            if bytes > p.format.max_bytes {
                return Err(Error::Feedback);
            }
            let bytes = if self.output_pcm.len() < bytes {
                if p.finite {
                    self.output_pcm.len()
                } else {
                    p.planned = Some(bytes);
                    break;
                }
            } else {
                bytes
            };
            if bytes == 0 {
                if p.finite {
                    break;
                } else {
                    continue;
                }
            }
            for b in &mut packet.buffer.bytes_mut()[..bytes] {
                *b = self.output_pcm.pop_front().unwrap();
            }
            packet.bytes = bytes;
            packet.ticket = Some(self.transport.submit(
                &endpoint,
                packet.buffer.physical(),
                bytes,
            )?);
            self.output.order.push_back(index);
        }
        Ok(())
    }
    fn packet(completion: Completion, expected: usize, input: bool) -> Result<usize, Error> {
        match completion.status {
            PacketStatus::Success | PacketStatus::Short => {}
            PacketStatus::MissedService => {
                return Err(Error::Packet("missed USB audio service interval"));
            }
            PacketStatus::Transaction => return Err(Error::Packet("USB audio transaction error")),
            PacketStatus::Babble => return Err(Error::Packet("USB audio babble")),
            PacketStatus::Bandwidth => return Err(Error::Packet("USB audio bandwidth error")),
            PacketStatus::BufferOverrun => return Err(Error::Packet("USB audio buffer overrun")),
        }
        if completion.bytes > expected || (!input && completion.bytes != expected) {
            return Err(Error::Packet("USB audio packet length"));
        }
        Ok(completion.bytes)
    }
    fn poll_inner(&mut self) -> Result<(), Error> {
        while let Some(index) = self.feedback.order.front().copied() {
            let packet = &mut self.feedback.packets[index];
            let ticket = packet.ticket.as_ref().unwrap();
            let Some(result) = self.transport.completed(ticket) else {
                break;
            };
            let bytes = Self::packet(result?, packet.bytes, true)?;
            packet.ticket = None;
            self.feedback.order.pop_front();
            if bytes == 0 || packet.buffer.bytes()[..bytes].iter().all(|byte| *byte == 0) {
                continue;
            }
            let p = self.playback.as_mut().ok_or(Error::NotRunning)?;
            p.packetizer
                .feedback(&packet.buffer.bytes()[..bytes], self.binding.speed)?;
            p.last_feedback = self.transport.now_us();
            self.progress.feedback_updates += 1;
        }
        if let Some(c) = &mut self.capture {
            while let Some(index) = self.input.order.front().copied() {
                let packet = &mut self.input.packets[index];
                let ticket = packet.ticket.as_ref().unwrap();
                let Some(result) = self.transport.completed(ticket) else {
                    break;
                };
                let bytes = Self::packet(result?, packet.bytes, true)?;
                packet.ticket = None;
                self.input.order.pop_front();
                if !bytes.is_multiple_of(c.format.frame_bytes()) {
                    return Err(Error::Packet("capture packet splits a PCM frame"));
                }
                let frames = bytes / c.format.frame_bytes();
                if frames > 0 {
                    c.last_progress = self.transport.now_us();
                }
                if c.requested {
                    if self.input_pcm.len().saturating_add(bytes) > PCM_LIMIT {
                        return Err(Error::Overrun);
                    }
                    self.input_pcm
                        .extend(packet.buffer.bytes()[..bytes].iter().copied());
                    self.progress.capture_frames += frames as u64;
                }
                if c.implicit && frames > 0 {
                    if self.implicit_frames.len() >= PACKETS * 2 {
                        return Err(Error::Overrun);
                    }
                    self.implicit_frames.push_back(frames);
                    self.progress.feedback_updates += 1;
                    if let Some(p) = self.playback.as_mut() {
                        p.last_feedback = self.transport.now_us();
                    }
                }
            }
        }
        if let Some(p) = self.playback.as_mut() {
            while let Some(index) = self.output.order.front().copied() {
                let packet = &mut self.output.packets[index];
                let ticket = packet.ticket.as_ref().unwrap();
                let Some(result) = self.transport.completed(ticket) else {
                    break;
                };
                let bytes = Self::packet(result?, packet.bytes, false)?;
                packet.ticket = None;
                self.output.order.pop_front();
                self.progress.playback_frames += (bytes / p.format.frame_bytes()) as u64;
                if bytes > 0 {
                    p.last_progress = self.transport.now_us();
                }
            }
            if matches!(p.format.sync, Sync::Explicit(_) | Sync::Implicit { .. })
                && self.transport.now_us().saturating_sub(p.last_feedback) > FEEDBACK_TIMEOUT_US
            {
                return Err(Error::Feedback);
            }
        }
        let now = self.transport.now_us();
        // No completion (or indefinitely empty input) is not healthy streaming.
        // Include four actual service intervals for unusual long-bInterval alts.
        let deadline = |f: &Format| 1_000_000u64.max(u64::from(f.service_microframes) * 125 * 4);
        if self
            .playback
            .as_ref()
            .is_some_and(|p| now.saturating_sub(p.last_progress) > deadline(&p.format))
        {
            return Err(Error::Packet("USB audio playback made no progress"));
        }
        if self
            .capture
            .as_ref()
            .is_some_and(|c| now.saturating_sub(c.last_progress) > deadline(&c.format))
        {
            return Err(Error::Packet("USB audio capture made no progress"));
        }
        self.queue_inputs()?;
        self.queue_output()?;
        if let Some(p) = &self.playback
            && self.output.queued() == 0
            && (self.output_pcm.is_empty() || (!p.finite && p.planned.is_some()))
        {
            if p.finite {
                self.stop_playback()?;
                self.progress.playback_drained = true;
            } else {
                return Err(Error::Underrun);
            }
        }
        Ok(())
    }
    pub fn poll(&mut self) -> Result<Progress, Error> {
        self.ready()?;
        if let Err(error) = self.poll_inner() {
            return self.fail(error);
        }
        Ok(self.progress())
    }
    fn stop_output(&mut self) -> Result<(), Error> {
        let mut endpoints = self.output.endpoints();
        endpoints.extend(self.feedback.endpoints());
        if !endpoints.is_empty() {
            self.transport
                .deconfigure(Direction::Playback, &endpoints)?;
        }
        if let Some(p) = &self.playback {
            self.transport.alternate(p.format.interface, 0)?;
        }
        self.output.released();
        self.feedback.released();
        self.playback = None;
        self.output_pcm.clear();
        self.implicit_frames.clear();
        Ok(())
    }
    fn stop_input(&mut self) -> Result<(), Error> {
        let endpoints = self.input.endpoints();
        if !endpoints.is_empty() {
            self.transport.deconfigure(Direction::Capture, &endpoints)?;
        }
        if let Some(c) = &self.capture {
            self.transport.alternate(c.format.interface, 0)?;
        }
        self.input.released();
        self.capture = None;
        self.input_pcm.clear();
        Ok(())
    }
    pub fn stop_playback(&mut self) -> Result<(), Error> {
        self.ready()?;
        if let Err(error) = self.stop_output() {
            self.last_fault = Some(error);
            self.poisoned = true;
            return Err(Error::Poisoned);
        }
        if let Some(c) = self.capture.as_mut() {
            c.implicit = false;
            if !c.requested
                && let Err(error) = self.stop_input()
            {
                self.last_fault = Some(error);
                self.poisoned = true;
                return Err(Error::Poisoned);
            }
        }
        Ok(())
    }
    pub fn stop_capture(&mut self) -> Result<(), Error> {
        self.ready()?;
        if let Some(c) = self.capture.as_mut()
            && c.implicit
        {
            c.requested = false;
            self.input_pcm.clear();
            return Ok(());
        }
        if let Err(error) = self.stop_input() {
            self.last_fault = Some(error);
            self.poisoned = true;
            return Err(Error::Poisoned);
        }
        Ok(())
    }
    pub fn shutdown(&mut self) -> Result<(), Error> {
        let output = self.stop_output();
        let input = self.stop_input();
        if output.is_err() || input.is_err() {
            self.poisoned = true;
            return Err(Error::Poisoned);
        }
        self.poisoned = false;
        Ok(())
    }
    fn fail<R>(&mut self, error: Error) -> Result<R, Error> {
        self.last_fault = Some(error.clone());
        if self.shutdown().is_err() {
            Err(Error::Poisoned)
        } else {
            Err(error)
        }
    }
}

impl<T: Transport> Drop for AudioDevice<T> {
    fn drop(&mut self) {
        // DMA storage lives for the boot. An uncertain stop is retained and
        // quarantined by Transport; it never licenses reuse by this owner.
        let _ = self.shutdown();
    }
}

#[cfg(test)]
#[path = "tests.rs"]
pub(crate) mod tests;
