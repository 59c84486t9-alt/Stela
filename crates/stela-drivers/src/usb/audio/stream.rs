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
#[derive(Clone, Copy)]
enum StreamClock {
    Entity(ResolvedClock),
    Endpoint,
    Fixed,
}

struct Playback {
    format: Format,
    rate: u32,
    clock: StreamClock,
    packetizer: Packetizer,
    planned: Option<usize>,
    finite: bool,
    last_feedback: u64,
    last_progress: u64,
}
struct Capture {
    format: Format,
    rate: u32,
    clock: StreamClock,
    requested: bool,
    implicit: bool,
    last_progress: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub playback_frames: u64,
    pub capture_frames: u64,
    pub feedback_updates: u64,
    /// Packets whose data a USB error lost; the stream keeps running.
    pub packet_errors: u64,
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
    power_owners: Vec<super::PowerDomain>,
    /// First failure is retained even if cleanup itself fails.
    pub last_fault: Option<Error>,
}

impl AudioDevice<super::Native> {
    /// Create an idle owner for the actual optional UAC1/UAC2 AC status endpoint.
    /// Call `start`, poll and drain notices explicitly, then acknowledge `stop`.
    pub fn status_notifications(
        &self,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Option<super::StatusNotifications>, Error> {
        self.transport.status_notifications(dma)
    }
}

impl<T: Transport> AudioDevice<T> {
    pub fn new(transport: T, binding: Binding, dma: &mut dyn DmaAllocator) -> Result<Self, Error> {
        transport.validate()?;
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
            power_owners: Vec::new(),
            last_fault: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn generation_transport(&mut self) -> &mut T {
        &mut self.transport
    }

    #[cfg(test)]
    pub(crate) fn generation_snapshot(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.output_pcm.iter().copied());
        bytes.extend(self.input_pcm.iter().copied());
        for count in [
            self.output_pcm.len(),
            self.input_pcm.len(),
            self.implicit_frames.len(),
        ] {
            bytes.extend_from_slice(&count.to_le_bytes());
        }
        bytes.extend([
            u8::from(self.playback.is_some()),
            u8::from(self.capture.is_some()),
            u8::from(self.poisoned),
            u8::from(self.last_fault.is_some()),
        ]);
        for lane in [&self.output, &self.input, &self.feedback] {
            bytes.extend_from_slice(&lane.order.len().to_le_bytes());
            bytes.push(u8::from(lane.endpoint.is_some()));
            for packet in &lane.packets {
                bytes.extend_from_slice(packet.buffer.bytes());
                bytes.extend_from_slice(&packet.bytes.to_le_bytes());
                bytes.push(u8::from(packet.ticket.is_some()));
            }
        }
        bytes
    }

    /// Immutable descriptor snapshot; this does not establish current attachment.
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    /// Historical software accounting; poll validates the actual native owner.
    pub fn progress(&self) -> Progress {
        let mut p = self.progress;
        p.queued_playback = self.output.queued();
        p.queued_capture = self.input.queued();
        p
    }
    fn ready(&self) -> Result<(), Error> {
        self.transport.validate()?;
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    fn prepare_power(&mut self) -> Result<(), Error> {
        if self.playback.is_some() || self.capture.is_some() {
            // This is a polled transport. Sleeping for a cold sibling's 300ms
            // recovery while an existing 32-packet queue runs would starve it.
            // Both BADD domains stay awake for the complete duplex session.
            for domain in &self.power_owners {
                domain.ensure_awake(&mut self.transport, self.binding.graph.control_interface)?;
            }
            return Ok(());
        }
        for format in &self.binding.formats {
            if let Some(domain) = format.power_domain
                && !self.power_owners.iter().any(|d| d.id == domain.id)
            {
                // Initially selected by class attachment; acknowledge zero again
                // before retaining a power owner, including an unused sibling.
                self.transport.alternate(format.interface, 0)?;
                self.power_owners.push(domain);
                domain.awake(&mut self.transport, self.binding.graph.control_interface)?;
            }
        }
        Ok(())
    }
    fn idle_power(&mut self) -> Result<(), Error> {
        if self.playback.is_none() && self.capture.is_none() {
            while let Some(domain) = self.power_owners.last().copied() {
                domain.idle(&mut self.transport, self.binding.graph.control_interface)?;
                self.power_owners.pop();
            }
        }
        Ok(())
    }
    fn powered_clock(&mut self, format: &Format, rate: u32) -> Result<StreamClock, Error> {
        if format.power_domain.is_none() {
            return self.clock(format, rate);
        }
        if self.binding.basic_profile.is_some() && rate != super::badd::RATE {
            return Err(Error::RateUnsupported);
        }
        let active = self.playback.is_some() || self.capture.is_some();
        // Full UAC3 clock entities may share the stream's power domain. Their
        // controls are usable only after actual D0 recovery, before any DMA.
        if let Err(error) = self.prepare_power() {
            return self.fail(error);
        }
        match self.clock(format, rate) {
            Ok(clock) => Ok(clock),
            // These are request/clock-sharing refusals before any rate write.
            // An existing healthy session must survive an invalid new request.
            Err(error @ (Error::Busy | Error::RateUnsupported)) if active => Err(error),
            Err(error) => self.fail(error),
        }
    }
    fn clock(&mut self, format: &Format, rate: u32) -> Result<StreamClock, Error> {
        if self.binding.basic_profile.is_some() {
            if rate != super::badd::RATE {
                return Err(Error::RateUnsupported);
            }
            return Ok(StreamClock::Fixed);
        }
        if let Some(rates) = &format.endpoint_rates {
            rates.validate_rate(rate)?;
            // UAC1 provides no clock-sharing graph. Do not retune one side of
            // an active duplex device to a conflicting nominal frequency.
            if self
                .playback
                .iter()
                .map(|p| p.rate)
                .chain(self.capture.iter().map(|c| c.rate))
                .any(|active| active != rate)
            {
                return Err(Error::Busy);
            }
            return Ok(StreamClock::Endpoint);
        }
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
            if let StreamClock::Entity(other_clock) = other_clock
                && other_clock.source == clock.source
                && other_clock.source_rate(other_rate)? != clock.source_rate(rate)?
            {
                return Err(Error::Busy);
            }
        }
        self.binding
            .graph
            .set_rate(&mut self.transport, clock, rate)?;
        Ok(StreamClock::Entity(clock))
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
        if finite && format.fill_max && !pcm.len().is_multiple_of(format.max_bytes) {
            return Err(Error::Format);
        }
        let endpoints = format.endpoints();
        if self.capture.as_ref().is_some_and(|c| {
            c.format.interface == format.interface
                || endpoints.iter().any(|ep| ep.dci() == c.format.data.dci())
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
        if let Sync::Implicit {
            interface,
            alternate,
            ..
        } = format.sync
        {
            let source = self
                .binding
                .formats
                .iter()
                .find(|f| {
                    f.interface == interface
                        && f.alternate == alternate
                        && f.direction == Direction::Capture
                })
                .ok_or(Error::Descriptor(
                    "implicit feedback source format is missing",
                ))?;
            if endpoints.iter().any(|ep| ep.dci() == source.data.dci()) {
                return Err(Error::Busy);
            }
        }
        self.transport.preflight(&endpoints)?;
        let clock = self.powered_clock(&format, rate)?;
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
                self.start_capture_inner(capture_index, rate, false, true, &mut false)?;
            }
            self.prepare_power()?;
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
            let format = &self.playback.as_ref().unwrap().format;
            if let Some(rates) = &format.endpoint_rates {
                rates.apply(&mut self.transport, format.data.address, rate)?;
            }
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
        let p = self.playback.as_mut().ok_or(Error::NotRunning)?;
        if p.format.fill_max && !self.output_pcm.len().is_multiple_of(p.format.max_bytes) {
            return Err(Error::Format);
        }
        p.finite = true;
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
        let mut effects_attempted = false;
        let result = self.start_capture_inner(index, rate, true, false, &mut effects_attempted);
        if let Err(error) = result {
            // Existing duplex-session power does not belong to this request.
            // A rate/alias/preflight refusal cannot tear down a healthy sibling.
            if self.input.endpoint.is_none() && !effects_attempted {
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
        effects_attempted: &mut bool,
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
            p.format.interface == format.interface
                || p.format
                    .endpoints()
                    .iter()
                    .any(|ep| ep.dci() == format.data.dci())
        }) {
            return Err(Error::Busy);
        }
        self.transport.preflight(&[format.data])?;
        let clock = self.powered_clock(&format, rate)?;
        // Beyond preflight, an unsuccessful live power observation invalidates
        // the session's authority even if it does not acquire a new domain.
        *effects_attempted = true;
        self.prepare_power()?;
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
        if let Some(rates) = &format.endpoint_rates {
            rates.apply(&mut self.transport, format.data.address, rate)?;
        }
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
    /// Poll the standardized headset-adapter insertion bitmap. Status delivery
    /// is explicit polling; no interrupt notification is inferred from this read.
    pub fn connector_present(&mut self, terminal: u8) -> Result<bool, Error> {
        self.ready()?;
        if self.binding.basic_profile != Some(super::BasicProfile::HeadsetAdapter)
            || !matches!(terminal, 3 | 4)
        {
            return Err(Error::Unsupported(
                "no BADD insertion control for this terminal",
            ));
        }
        let reply = self.transport.control(
            crate::usb::xhci::setup(
                0xa1,
                1,
                1 << 8,
                u16::from(terminal) << 8 | u16::from(self.binding.graph.control_interface),
                2,
            ),
            &[],
        )?;
        if reply.len() != 2 {
            return Err(Error::ControlLength);
        }
        if reply[0] != 1 || reply[1] & !1 != 0 {
            return Err(Error::ControlReadback);
        }
        Ok(reply[1] != 0)
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
    pub fn feature_value(
        &mut self,
        entity: u8,
        channel: u8,
        feature: super::FeatureControl,
    ) -> Result<super::FeatureValue, Error> {
        self.ready()?;
        self.binding
            .graph
            .feature_value(&mut self.transport, entity, channel, feature)
    }
    pub fn feature_ranges(
        &mut self,
        entity: u8,
        channel: u8,
        feature: super::FeatureControl,
    ) -> Result<Vec<super::FeatureRange>, Error> {
        self.ready()?;
        self.binding
            .graph
            .feature_ranges(&mut self.transport, entity, channel, feature)
    }
    pub fn set_feature_value(
        &mut self,
        entity: u8,
        channel: u8,
        feature: super::FeatureControl,
        value: super::FeatureValue,
    ) -> Result<(), Error> {
        self.ready()?;
        self.binding
            .graph
            .set_feature_value(&mut self.transport, entity, channel, feature, value)
    }
    pub fn mixer_volume(&mut self, entity: u8, input: u8, output: u8) -> Result<i16, Error> {
        self.ready()?;
        self.binding
            .graph
            .mixer_volume(&mut self.transport, entity, input, output)
    }
    pub fn set_mixer_volume(
        &mut self,
        entity: u8,
        input: u8,
        output: u8,
        value: i16,
    ) -> Result<(), Error> {
        self.ready()?;
        self.binding
            .graph
            .set_mixer_volume(&mut self.transport, entity, input, output, value)
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
        self.transport.validate()?;
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
        self.transport.validate()?;
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
            if bytes == 0 && p.finite && self.output_pcm.is_empty() {
                break;
            }
            // A fractional zero-frame interval still consumes USB service time.
            // Submit its actual ZLP TD rather than compressing sample cadence.
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
    /// Like snd-usb-audio, a packet error loses only that packet: playback
    /// counts it as sent, while capture and feedback take no bytes from it.
    fn packet(
        progress: &mut Progress,
        completion: Completion,
        expected: usize,
        input: bool,
    ) -> Result<usize, Error> {
        if !matches!(
            completion.status,
            PacketStatus::Success | PacketStatus::Short
        ) {
            progress.packet_errors += 1;
            return Ok(if input { 0 } else { expected });
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
            let bytes = Self::packet(&mut self.progress, result?, packet.bytes, true)?;
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
                let bytes = Self::packet(&mut self.progress, result?, packet.bytes, true)?;
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
                let bytes = Self::packet(&mut self.progress, result?, packet.bytes, false)?;
                packet.ticket = None;
                self.output.order.pop_front();
                self.progress.playback_frames += (bytes / p.format.frame_bytes()) as u64;
                p.last_progress = self.transport.now_us();
            }
            let feedback_deadline = if let Sync::Explicit(endpoint) = p.format.sync {
                FEEDBACK_TIMEOUT_US.max(
                    u64::from(super::descriptors::service_interval(
                        endpoint,
                        self.binding.speed,
                    )?) * 125
                        * 4,
                )
            } else {
                FEEDBACK_TIMEOUT_US
            };
            if matches!(p.format.sync, Sync::Explicit(_) | Sync::Implicit { .. })
                && self.transport.now_us().saturating_sub(p.last_feedback) > feedback_deadline
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
        self.idle_power()
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
        self.idle_power()
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
        self.transport.validate()?;
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
pub(crate) mod tests {
    // SPDX-License-Identifier: GPL-2.0-or-later
    //! Representative standard UAC2 descriptors, not a dump of the physical PC.
    use super::*;
    mod badd;
    mod mixer;
    mod uac1;
    mod uac3;
    use crate::usb::audio::*;
    use crate::{
        bus::dma::RegionAllocator,
        usb::xhci::{interfaces, setup},
    };
    use alloc::{collections::BTreeMap, vec::Vec};

    fn append(v: &mut Vec<u8>, d: &[u8]) {
        v.extend_from_slice(d);
    }
    pub(crate) fn configuration() -> Vec<u8> {
        let mut v = vec![9, 2, 0, 0, 3, 1, 0, 0x80, 50];
        append(&mut v, &[8, 11, 0, 3, 1, 0, 0x20, 0]);
        append(&mut v, &[9, 4, 0, 0, 0, 1, 1, 0x20, 0]);
        let start = v.len();
        append(&mut v, &[9, 0x24, 1, 0, 2, 1, 0, 0, 0]);
        append(&mut v, &[8, 0x24, 10, 10, 3, 7, 0, 0]); // rw frequency + ro validity
        append(
            &mut v,
            &[17, 0x24, 2, 1, 1, 1, 0, 10, 2, 3, 0, 0, 0, 0, 0, 0, 0],
        );
        append(
            &mut v,
            &[18, 0x24, 6, 2, 1, 15, 0, 0, 0, 15, 0, 0, 0, 15, 0, 0, 0, 0],
        );
        append(&mut v, &[12, 0x24, 3, 3, 1, 3, 0, 2, 10, 0, 0, 0]);
        append(
            &mut v,
            &[17, 0x24, 2, 4, 1, 2, 0, 10, 2, 3, 0, 0, 0, 0, 0, 0, 0],
        );
        append(&mut v, &[12, 0x24, 3, 5, 1, 1, 0, 4, 10, 0, 0, 0]);
        let total = (v.len() - start) as u16;
        v[start + 6..start + 8].copy_from_slice(&total.to_le_bytes());
        for (i, terminal, address, attrs) in [(1, 1, 1, 0x0d), (2, 5, 0x82, 0x05)] {
            append(&mut v, &[9, 4, i, 0, 0, 1, 2, 0x20, 0]);
            append(&mut v, &[9, 4, i, 1, 1, 1, 2, 0x20, 0]);
            append(
                &mut v,
                &[16, 0x24, 1, terminal, 0, 1, 1, 0, 0, 0, 2, 3, 0, 0, 0, 0],
            );
            append(&mut v, &[6, 0x24, 2, 1, 2, 16]);
            append(&mut v, &[7, 5, address, attrs, 0xc0, 0, 4]);
            append(&mut v, &[8, 0x25, 1, 0, 0, 0, 0, 0]);
        }
        let total = v.len() as u16;
        v[2..4].copy_from_slice(&total.to_le_bytes());
        v
    }
    fn binding() -> Binding {
        let c = configuration();
        let all = interfaces(&c);
        Binding::parse(&all[0], &all, &c, 3).unwrap()
    }

    #[test]
    fn runtime_descriptors_select_graph_and_pcm_not_product_nodes() {
        let b = binding();
        assert_eq!(b.formats.len(), 2);
        assert_eq!(b.formats[0].frame_bytes(), 4);
        assert_eq!(b.graph.terminal_clock(5, Direction::Capture), Ok(10));
        assert_eq!(b.settings(), vec![(0, 0), (1, 0), (2, 0)]);
        let mut c = configuration();
        c.pop();
        let a = interfaces(&c);
        assert!(Binding::parse(&a[0], &a, &c, 3).is_err());
        let mut c = configuration();
        let n = c
            .windows(8)
            .position(|w| w == [8, 0x24, 10, 10, 3, 7, 0, 0])
            .unwrap();
        c[n + 3] = 1;
        let a = interfaces(&c);
        assert!(Binding::parse(&a[0], &a, &c, 3).is_err());
    }

    #[derive(Default)]
    struct Model {
        overrides: BTreeMap<[u8; 8], Vec<u8>>,
        selection: u8,
        numerator: u16,
        denominator: u16,
        rate: u32,
        time: u64,
        valid: bool,
        muted: bool,
        volume: i16,
        active: Vec<u8>,
        pending: BTreeMap<u64, (Endpoint, u64, usize)>,
        next: u64,
        output: Vec<u8>,
        submitted: Vec<(u8, usize)>,
        alternates: Vec<(u8, u8)>,
        cancel_fail: bool,
        packet_fault: Option<PacketStatus>,
        transport_fault: bool,
        hold: bool,
    }
    impl Model {
        fn new() -> Self {
            Self {
                selection: 1,
                numerator: 2,
                denominator: 1,
                rate: 48_000,
                valid: true,
                ..Self::default()
            }
        }
    }
    impl Control for Model {
        fn now_us(&self) -> u64 {
            self.time
        }
        fn relax(&mut self) {
            self.time += 1000;
        }
        fn control(&mut self, r: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
            if let Some(reply) = self.overrides.get(&r) {
                return Ok(reply.clone());
            }
            let entity = r[5];
            let sel = r[3];
            let len = u16::from_le_bytes([r[6], r[7]]) as usize;
            if r[0] == 1 && r[1] == 11 {
                self.alternates.push((r[4], r[2]));
                return Ok(Vec::new());
            }
            assert_eq!(r[4], 0);
            assert_eq!(r[2], 0);
            if r[0] == 0x21 {
                match (entity, sel) {
                    (11 | 14, 1) => self.selection = out[0],
                    (10, 1) => self.rate = u32::from_le_bytes(out.try_into().unwrap()),
                    (2, 1) => self.muted = out[0] != 0,
                    (2, 2) => self.volume = i16::from_le_bytes(out.try_into().unwrap()),
                    _ => panic!("unexpected set {r:?}"),
                };
                return Ok(Vec::new());
            }
            assert_eq!(r[0], 0xa1);
            let data = match (entity, sel, r[1]) {
                (11 | 14, 1, 1) => vec![self.selection],
                (12, 1, 1) => self.numerator.to_le_bytes().to_vec(),
                (12, 2, 1) => self.denominator.to_le_bytes().to_vec(),
                (10, 1, 1) => self.rate.to_le_bytes().to_vec(),
                (10, 2, 1) => vec![u8::from(self.valid)],
                (10, 1, 2) => {
                    let mut v = 1u16.to_le_bytes().to_vec();
                    v.extend_from_slice(&44_100u32.to_le_bytes());
                    v.extend_from_slice(&96_000u32.to_le_bytes());
                    v.extend_from_slice(&100u32.to_le_bytes());
                    v
                }
                (2, 1, 1) => vec![u8::from(self.muted)],
                (2, 2, 1) => self.volume.to_le_bytes().to_vec(),
                (2, 2, 2) => vec![1, 0, 0, 0xc0, 0, 0, 0, 1],
                _ => panic!("unexpected get {r:?}"),
            };
            Ok(data[..len.min(data.len())].to_vec())
        }
    }
    impl Transport for Model {
        // Independent in-memory device peer; it owns no native attachment.
        fn validate(&self) -> Result<(), BlockError> {
            Ok(())
        }
        type Ticket = u64;
        fn preflight(&mut self, eps: &[Endpoint]) -> Result<(), BlockError> {
            if eps.iter().any(|e| self.active.contains(&e.address)) {
                return Err(BlockError::Unsupported("foreign endpoint owner"));
            }
            Ok(())
        }
        fn configure(&mut self, _: Direction, eps: &[Endpoint]) -> Result<(), BlockError> {
            for e in eps {
                assert!(!self.active.contains(&e.address));
                self.active.push(e.address);
            }
            Ok(())
        }
        fn deconfigure(&mut self, _: Direction, eps: &[Endpoint]) -> Result<(), BlockError> {
            if self.cancel_fail {
                return Err(BlockError::Timeout);
            }
            for e in eps {
                self.active.retain(|a| *a != e.address);
                self.pending.retain(|_, (ep, _, _)| ep.address != e.address);
            }
            Ok(())
        }
        fn submit(&mut self, e: &Endpoint, p: u64, n: usize) -> Result<u64, BlockError> {
            assert!(self.active.contains(&e.address));
            assert!(n <= 3072);
            assert_eq!(p & 4095, 0);
            self.submitted.push((e.address, n));
            self.next += 1;
            self.pending.insert(self.next, (*e, p, n));
            Ok(self.next)
        }
        fn completed(&mut self, t: &u64) -> Option<Result<Completion, BlockError>> {
            if self.hold {
                return None;
            }
            if self.transport_fault {
                return Some(Err(BlockError::Timeout));
            }
            let (e, p, n) = self.pending.remove(t).expect("ticket consumed once");
            // SAFETY: the class's live DMA buffer remains owned by this ticket until this terminal completion.
            let data = unsafe { core::slice::from_raw_parts_mut(p as *mut u8, n) };
            if e.attributes & 0x30 == 0x10 {
                data[..4].copy_from_slice(&(6u32 << 16).to_le_bytes());
            } else if e.is_in() {
                data.fill(*t as u8);
            } else {
                self.output.extend_from_slice(data);
            }
            Some(Ok(Completion {
                bytes: n,
                status: self.packet_fault.take().unwrap_or(PacketStatus::Success),
            }))
        }
    }
    fn run(f: impl FnOnce(&mut AudioDevice<Model>)) {
        let mut memory = vec![0u64; 80 * 1024];
        let p = memory.as_mut_ptr() as u64;
        // SAFETY: backing memory outlives this test's class, and only its allocator uses it.
        let mut dma = unsafe { RegionAllocator::new(p..p + memory.len() as u64 * 8) };
        let mut a = AudioDevice::new(Model::new(), binding(), &mut dma).unwrap();
        f(&mut a);
    }
    #[test]
    fn controls_use_ranges_exact_requests_and_actual_readback() {
        let g = binding().graph;
        let mut m = Model::new();
        let c = g.resolve_clock(&mut m, 10).unwrap();
        g.set_rate(&mut m, c, 44_100).unwrap();
        assert_eq!(m.rate, 44_100);
        assert_eq!(g.set_rate(&mut m, c, 44_101), Err(Error::RateUnsupported));
        g.set_mute(&mut m, 2, 0, true).unwrap();
        g.set_volume(&mut m, 2, 0, -256).unwrap();
        assert_eq!(m.volume, -256);
        assert_eq!(g.set_volume(&mut m, 2, 0, -257), Err(Error::Format));
        m.valid = false;
        assert_eq!(g.valid_clock(&mut m, c), Err(Error::ClockInvalid));
        assert!(m.time >= 100000);
        assert_eq!(
            setup(0xa1, 1, 0x100, 0xa00, 4),
            [0xa1, 1, 0, 1, 0, 10, 4, 0]
        );
    }
    #[test]
    fn finite_pcm_is_exact_across_many_packet_ring_wraps_and_restart() {
        run(|a| {
            let pcm: Vec<u8> = (0..65536).map(|i| (i * 17) as u8).collect();
            a.start_playback(0, 48000, &pcm, true).unwrap();
            for _ in 0..200 {
                if a.poll().unwrap().playback_drained {
                    break;
                }
            }
            assert!(a.progress().playback_drained);
            assert_eq!(a.transport.output, pcm);
            assert!(a.transport.pending.is_empty());
            assert_eq!(a.transport.alternates.last(), Some(&(1, 0)));
            a.start_playback(0, 48000, &pcm[..24], true).unwrap();
            a.poll().unwrap();
            assert_eq!(a.progress().playback_frames, 16390);
        });
    }
    #[test]
    fn duplex_capture_uses_actual_packet_bytes_and_shared_clock_is_not_retuned() {
        run(|a| {
            a.start_capture(1, 48000).unwrap();
            a.start_playback(0, 48000, &vec![7; 24000], true).unwrap();
            a.poll().unwrap();
            assert_eq!(a.progress().capture_frames, 1536);
            let mut pcm = vec![0; 6144];
            assert_eq!(a.read_capture(&mut pcm).unwrap(), 6144);
            assert_eq!(&pcm[..192], &[1; 192]);
            assert_eq!(&pcm[192..384], &[2; 192]);
            assert_eq!(a.start_capture(1, 44100), Err(Error::Busy));
            a.stop_playback().unwrap();
            assert!(a.capture.is_some());
            a.stop_capture().unwrap();
            assert!(a.transport.pending.is_empty());
        });
    }
    #[test]
    fn packet_errors_lose_one_packet_and_failed_cancel_keeps_dma_quarantined() {
        run(|a| {
            a.start_capture(1, 48000).unwrap();
            a.transport.packet_fault = Some(PacketStatus::MissedService);
            a.poll().unwrap();
            assert_eq!(a.progress().packet_errors, 1);
            a.shutdown().unwrap();
            assert!(a.transport.pending.is_empty());
            a.start_capture(1, 48000).unwrap();
            a.transport.transport_fault = true;
            a.transport.cancel_fail = true;
            assert_eq!(a.poll(), Err(Error::Poisoned));
            assert!(!a.transport.pending.is_empty());
            assert_eq!(a.start_capture(1, 48000), Err(Error::Poisoned));
            a.transport.transport_fault = false;
            a.transport.cancel_fail = false;
            a.shutdown().unwrap();
            assert!(a.transport.pending.is_empty());
        });
    }
    #[test]
    fn continuous_partial_packet_starvation_is_explicit_and_capture_fifo_wraps() {
        run(|a| {
            a.start_playback(0, 48000, &[1; 28], false).unwrap();
            assert_eq!(a.poll(), Err(Error::Underrun));
            a.start_capture(1, 48000).unwrap();
            for _ in 0..3 {
                a.poll().unwrap();
                let mut out = vec![0; 6144];
                assert_eq!(a.read_capture(&mut out).unwrap(), 6144);
                for (n, p) in out.chunks(192).enumerate() {
                    assert!(p.iter().all(|v| *v == p[0]), "packet{n}");
                }
            }
            a.shutdown().unwrap();
        });
    }

    #[test]
    fn explicit_feedback_updates_packetizer_and_stale_feedback_stops() {
        run(|a| {
            let fb = Endpoint {
                address: 0x83,
                attributes: 0x11,
                max_packet: 4,
                interval: 4,
                companion: None,
            };
            a.binding.formats[0].sync = Sync::Explicit(fb);
            a.start_playback(0, 48000, &vec![9; 24000], false).unwrap();
            assert_eq!(a.poll().unwrap().feedback_updates, 32);
            a.transport.hold = true;
            a.transport.time = 100001;
            assert_eq!(a.poll(), Err(Error::Feedback));
            assert!(a.transport.pending.is_empty());
        });
    }
    #[test]
    fn implicit_feedback_uses_actual_capture_packet_frames_and_retains_requested_capture() {
        run(|a| {
            let c = a.binding.formats[1].clone();
            a.binding.formats[0].sync = Sync::Implicit {
                interface: c.interface,
                alternate: c.alternate,
                endpoint: c.data,
                frame_bytes: c.frame_bytes(),
            };
            a.start_playback(0, 48000, &vec![3; 12288], true).unwrap();
            assert_eq!(a.progress().queued_playback, 0);
            a.start_capture(1, 48000).unwrap();
            for _ in 0..4 {
                a.poll().unwrap();
            }
            assert!(a.progress().playback_drained);
            assert_eq!(a.transport.output, vec![3; 12288]);
            assert!(a.capture.as_ref().unwrap().requested);
            assert!(!a.capture.as_ref().unwrap().implicit);
            a.stop_capture().unwrap();
            assert!(a.transport.pending.is_empty());
        });
    }

    #[test]
    fn selected_clock_multiplier_and_control_short_or_false_readback_are_not_success() {
        let mut graph = binding().graph;
        graph.entities.extend([
            Entity::ClockSelector {
                id: 11,
                sources: vec![10],
                controls: 3,
            },
            Entity::ClockMultiplier {
                id: 12,
                source: 11,
                controls: 5,
            },
        ]);
        graph.entities.push(Entity::Selector {
            id: 14,
            sources: vec![1, 4],
            controls: 3,
        });
        let mut m = Model::new();
        graph.signal_selection(&mut m, 14, 2).unwrap();
        assert_eq!(m.selection, 2);
        m.selection = 1;
        let c = graph.resolve_clock(&mut m, 12).unwrap();
        assert_eq!(
            c,
            ResolvedClock {
                source: 10,
                numerator: 2,
                denominator: 1
            }
        );
        graph.set_rate(&mut m, c, 88200).unwrap();
        assert_eq!(m.rate, 44100);
        graph.clock_selection(&mut m, 11, 1).unwrap();
        m.selection = 0;
        assert_eq!(graph.resolve_clock(&mut m, 12), Err(Error::ClockInvalid));
        m.selection = 1;
        m.denominator = 0;
        assert_eq!(graph.resolve_clock(&mut m, 12), Err(Error::ClockInvalid));
        m.denominator = 1;
        m.overrides
            .insert(setup(0xa1, 1, 0x100, 0xa00, 4), vec![0; 3]);
        assert_eq!(graph.current_rate(&mut m, c), Err(Error::ControlLength));
        m.overrides.clear();
        m.overrides.insert(setup(0x21, 1, 0x100, 0xa00, 4), vec![]);
        assert_eq!(
            graph.set_rate(&mut m, c, 96000),
            Err(Error::ControlReadback)
        );
        assert_eq!(
            graph.current_rate(
                &mut m,
                ResolvedClock {
                    source: 10,
                    numerator: 1,
                    denominator: 0
                }
            ),
            Err(Error::ClockInvalid)
        );
    }
    #[test]
    fn raw_endpoint_counts_reserved_usage_and_implicit_association_are_checked() {
        let mut c = configuration();
        let n = c
            .windows(7)
            .position(|w| w == [7, 5, 1, 13, 192, 0, 4])
            .unwrap();
        c[n + 3] = 0x35;
        let all = interfaces(&c);
        assert!(Binding::parse(&all[0], &all, &c, 3).is_err());
        let mut c = configuration();
        let n = c
            .windows(9)
            .position(|w| w == [9, 4, 1, 1, 1, 1, 2, 32, 0])
            .unwrap();
        c[n + 4] = 2;
        let all = interfaces(&c);
        assert!(Binding::parse(&all[0], &all, &c, 3).is_err());
        let mut c = configuration();
        let n = c
            .windows(7)
            .position(|w| w == [7, 5, 1, 13, 192, 0, 4])
            .unwrap();
        c[n + 3] = 5;
        let n = c
            .windows(7)
            .position(|w| w == [7, 5, 0x82, 5, 192, 0, 4])
            .unwrap();
        c[n + 3] = 0x25;
        let all = interfaces(&c);
        let b = Binding::parse(&all[0], &all, &c, 3).unwrap();
        assert!(matches!(
            b.formats[0].sync,
            Sync::Implicit {
                interface: 2,
                alternate: 1,
                ..
            }
        ));
        c[n + 6] = 3;
        let all = interfaces(&c);
        let b = Binding::parse(&all[0], &all, &c, 3).unwrap();
        assert_eq!(b.formats.len(), 1);
        assert!(!b.unsupported.is_empty());
    }

    #[test]
    fn missing_capture_or_synchronous_output_completions_fail_and_cancel() {
        run(|a| {
            a.start_capture(1, 48000).unwrap();
            a.transport.hold = true;
            a.transport.time = 1_000_001;
            assert_eq!(
                a.poll(),
                Err(Error::Packet("USB audio capture made no progress"))
            );
            assert!(a.transport.pending.is_empty());
            a.transport.time = 0;
            a.transport.hold = false;
            a.start_playback(0, 48000, &vec![0; 6144], true).unwrap();
            a.transport.hold = true;
            a.transport.time = 1_000_001;
            assert_eq!(
                a.poll(),
                Err(Error::Packet("USB audio playback made no progress"))
            );
            assert!(a.transport.pending.is_empty());
        });
    }

    #[test]
    fn foreign_endpoint_refusal_never_stages_cleanup_or_changes_alternate() {
        run(|a| {
            a.transport.active.push(1);
            let before = a.transport.alternates.clone();
            assert_eq!(
                a.start_playback(0, 48000, &[0; 192], true),
                Err(Error::Transport(BlockError::Unsupported(
                    "foreign endpoint owner"
                )))
            );
            assert_eq!(a.transport.active, vec![1]);
            assert_eq!(a.transport.alternates, before);
            assert!(a.playback.is_none());
            assert!(a.output.endpoint.is_none());
        });
    }
    #[test]
    fn explicit_feedback_cannot_alias_active_capture_in_either_start_order() {
        run(|a| {
            let mut fb = a.binding.formats[1].data;
            fb.attributes = 0x11;
            fb.max_packet = 4;
            a.binding.formats[0].sync = Sync::Explicit(fb);
            a.start_capture(1, 48000).unwrap();
            assert_eq!(
                a.start_playback(0, 48000, &[0; 192], true),
                Err(Error::Busy)
            );
            assert!(a.capture.is_some());
            a.stop_capture().unwrap();
            a.start_playback(0, 48000, &[0; 192], true).unwrap();
            assert_eq!(a.start_capture(1, 48000), Err(Error::Busy));
            assert!(a.playback.is_some());
            a.stop_playback().unwrap();
        });
    }
    #[test]
    fn descriptor_audio_alternate_cannot_claim_foreign_class_dci() {
        let mut c = configuration();
        c[4] = 4;
        c.extend_from_slice(&[9, 4, 3, 0, 1, 3, 1, 1, 0, 7, 5, 1, 3, 8, 0, 1]);
        let n = c.len() as u16;
        c[2..4].copy_from_slice(&n.to_le_bytes());
        let all = interfaces(&c);
        assert_eq!(
            Binding::parse(&all[0], &all, &c, 3),
            Err(Error::Descriptor(
                "audio alternate aliases a foreign interface endpoint"
            ))
        );
    }

    #[test]
    fn max_packets_only_refuses_short_finite_tail_until_producer_completes_packet() {
        run(|a| {
            a.binding.formats[0].fill_max = true;
            assert_eq!(
                a.start_playback(0, 48000, &[1; 24], true),
                Err(Error::Format)
            );
            assert!(a.transport.active.is_empty());
            assert!(a.transport.alternates.is_empty());
            let pcm = vec![1; 6168];
            a.start_playback(0, 48000, &pcm, false).unwrap();
            assert_eq!(a.finish_playback(), Err(Error::Format));
            assert!(!a.playback.as_ref().unwrap().finite);
            a.write_playback(&[2; 168]).unwrap();
            a.finish_playback().unwrap();
            for _ in 0..3 {
                a.poll().unwrap();
            }
            assert!(a.progress().playback_drained);
            let mut expected = pcm;
            expected.extend_from_slice(&[2; 168]);
            assert_eq!(a.transport.output, expected);
            assert_eq!(a.transport.output.len() % 192, 0);
        });
    }

    #[test]
    fn fractional_low_rate_preserves_zero_length_service_intervals() {
        run(|a| {
            a.binding.formats[0].service_microframes = 1;
            a.binding.formats[0].data.interval = 1;
            let mut range = vec![1, 0];
            range.extend_from_slice(&4000u32.to_le_bytes());
            range.extend_from_slice(&4000u32.to_le_bytes());
            range.extend_from_slice(&0u32.to_le_bytes());
            a.transport
                .overrides
                .insert(setup(0xa1, 2, 0x100, 0xa00, 2), vec![1, 0]);
            a.transport
                .overrides
                .insert(setup(0xa1, 2, 0x100, 0xa00, 14), range);
            let pcm = [1, 2, 3, 4, 5, 6, 7, 8];
            a.start_playback(0, 4000, &pcm, true).unwrap();
            assert_eq!(a.transport.submitted, vec![(1, 0), (1, 4), (1, 0), (1, 4)]);
            assert_eq!(a.progress().queued_playback, 4);
            a.poll().unwrap();
            assert!(a.progress().playback_drained);
            assert_eq!(a.progress().playback_frames, 2);
            assert_eq!(a.transport.output, pcm);
        });
    }
}
