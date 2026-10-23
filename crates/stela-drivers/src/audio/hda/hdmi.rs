// SPDX-License-Identifier: GPL-2.0-only
//! Copyright(c) 2008-2010 Intel Corporation
//! Copyright (c) 2006 ATI Technologies Inc.
//! Copyright (c) 2008 NVIDIA Corp. All rights reserved.
//! Copyright (c) 2008 Wei Ni <wni@nvidia.com>
//! Copyright (c) 2013 Anssi Hannula <anssi.hannula@iki.fi>
//! Author: Wu Fengguang <wfg@linux.intel.com>
//!
//! Owned HDMI/DP codec routing, adapted from pinned Linux HDMI/nvhdmi/ELD
//! sources. The first concrete profile is nvhdmi MODEL_LEGACY, not a vendor
//! wildcard. Display programming stays with the actual GPU port owner.
use super::{CodecGraph, Controller, ControllerToken, Registers, StreamId, Verb, WidgetKind};
use crate::{
    audio::{Direction, Error, PcmFormat, Phase},
    bus::{i2c::Timer, pci::Address},
};
use alloc::{sync::Arc, vec::Vec};
use core::mem::ManuallyDrop;
mod chmap;
mod eld;
mod playback;
pub use chmap::{ChannelMap, Speaker};
pub use eld::{AudioDescriptor, Connection, Eld};
pub use playback::RefilledPeriod;

const LEGACY_IDS: &[u32] = &[
    0x10de0008, 0x10de0009, 0x10de000a, 0x10de000b, 0x10de000c, 0x10de000d, 0x10de0010, 0x10de0011,
    0x10de0012, 0x10de0013, 0x10de0014, 0x10de0015, 0x10de0016, 0x10de0018, 0x10de0019, 0x10de001a,
    0x10de001b, 0x10de001c,
];
const PIN_SENSE: u16 = 0xf09;
const PRESENT: u32 = 1 << 31;
const ELD_VALID: u32 = 1 << 30;
const DIGITAL: u32 = 1 << 9;
const PIN_HDMI: u32 = 1 << 7;
const PIN_DP: u32 = 1 << 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayAudioIdentity {
    pub hda_function: Address,
    pub gpu_function: Address,
    pub codec: u8,
    pub pin: u8,
    /// Actual GPU connector identity, not a guessed pin-to-port arithmetic map.
    pub port: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayAudioState {
    /// Non-recycled port/sink generation, changed for disconnect, ELD rewrite,
    /// modeset or loss/recovery of the original power/clock/ownership epoch.
    pub generation: u64,
    pub connected: bool,
}
/// Actual original GPU/HDA coordination owner. Merely implementing an ID table
/// or copying an ELD blob does not satisfy this interface.
///
/// # Safety
/// Retain the original actual HDA function and GPU port/sink association,
/// exclusive audio route, powered HDA registers/link and firmware exclusion.
/// The original HDA MMIO/power grant cannot be revoked while this owner is
/// retained, even on observe failure; bounded stream/codec stop remains valid.
/// GPU sink availability may change and must revoke new playback immediately.
/// `observe` must query live authority and report every sink/ELD/modeset change;
/// absence of a native service MUST fail. `enable_audio` performs/acknowledges
/// real rate/clock/link coordination; `disable_audio` quiesces it even after
/// hotplug. Never release authority merely because this Arc is dropped. Calls
/// use the controller Timer's absolute microsecond deadline; return errors on
/// access/acknowledgement uncertainty. Port identities/numeric BDFs alone do
/// not establish requester, remapping, MMIO, DMA or power authority.
/// The HDA constructor's unique coherent identity-reachable boot-lifetime RAM
/// contract still applies; unavailable IOMMU services are never a bypass grant.
pub unsafe trait DisplayAudioPort {
    fn identity(&self) -> DisplayAudioIdentity;
    fn observe(&self, deadline_us: u64) -> Result<DisplayAudioState, Error>;
    fn enable_audio(&self, format: PcmFormat, deadline_us: u64) -> Result<(), Error>;
    fn disable_audio(&self, deadline_us: u64) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdmiPortId {
    token: ControllerToken,
    index: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HdmiSink {
    pub state: DisplayAudioState,
    pub eld: Option<Eld>,
}
struct Route {
    stream: StreamId,
    converter: u8,
    mux: u8,
    format: PcmFormat,
    map: ChannelMap,
    digital: u8,
    generation: u64,
    prepared: bool,
    progress: Option<playback::Progress>,
}
pub(super) struct Port {
    attachment: HdmiPortId,
    // Intentional quarantine: no ordinary Drop can release the GPU/HDA owner.
    owner: ManuallyDrop<Arc<dyn DisplayAudioPort>>,
    graph: CodecGraph,
    pin: u8,
    sink: Option<HdmiSink>,
    route: Option<Route>,
    first_error: Option<Error>,
}
impl Port {
    fn owner(&self) -> &dyn DisplayAudioPort {
        self.owner.as_ref()
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    fn hdmi_index(&self, id: HdmiPortId) -> Result<usize, Error> {
        if id.token != self.token
            || self
                .hdmi_ports
                .get(id.index)
                .and_then(Option::as_ref)
                .is_none()
        {
            return Err(Error::InvalidHdmiPort);
        }
        Ok(id.index)
    }
    fn hdmi_deadline(&self) -> u64 {
        self.timer
            .now_us()
            .wrapping_add(u64::from(self.config.transition_timeout_us))
    }
    fn hdmi_late(&self, start: u64) -> Result<(), Error> {
        if self.timer.now_us().wrapping_sub(start) >= u64::from(self.config.transition_timeout_us) {
            Err(Error::Timeout(Phase::DisplayAudio))
        } else {
            Ok(())
        }
    }
    fn hdmi_observe(&self, index: usize) -> Result<DisplayAudioState, Error> {
        let start = self.timer.now_us();
        let state = self.hdmi_ports[index]
            .as_ref()
            .unwrap()
            .owner()
            .observe(self.hdmi_deadline())?;
        self.hdmi_late(start)?;
        Ok(state)
    }
    fn hdmi_effect(&mut self, index: usize, format: Option<PcmFormat>) -> Result<(), Error> {
        let start = self.timer.now_us();
        let owner = self.hdmi_ports[index].as_ref().unwrap().owner();
        let result = if let Some(format) = format {
            owner.enable_audio(format, self.hdmi_deadline())
        } else {
            owner.disable_audio(self.hdmi_deadline())
        };
        result.and_then(|()| self.hdmi_late(start))
    }
    fn hdmi_topology(&mut self, graph: &CodecGraph, pin: u8) -> Result<(), Error> {
        if graph.token != self.token {
            return Err(Error::InvalidCodecGraph);
        }
        if !LEGACY_IDS.contains(&graph.vendor_id) {
            return Err(Error::UnsupportedTopology);
        }
        let group = graph
            .groups
            .iter()
            .find(|g| g.function_type & 255 == 1 && g.widgets.iter().any(|w| w.node == pin))
            .ok_or(Error::InvalidCodecGraph)?;
        let widget = graph.widget(pin).ok_or(Error::InvalidCodecGraph)?;
        if group
            .power_states
            .is_none_or(|p| p == u32::MAX || p & 1 == 0)
            || widget
                .power_states
                .is_some_and(|p| p == u32::MAX || p & 1 == 0)
            || widget.kind != WidgetKind::Pin
            || widget.capabilities & DIGITAL == 0
            || widget
                .pin_capabilities
                .is_none_or(|p| p == u32::MAX || p & (PIN_HDMI | PIN_DP) == 0 || p & 0x10 == 0)
            || widget
                .pin_default
                .is_none_or(|p| p == u32::MAX || p >> 30 == 1)
            || widget.connections.is_empty()
            || widget.connections.len() > 32
        {
            return Err(Error::UnsupportedTopology);
        }
        // Fresh enumeration includes inherited PCM, actual connection expansion,
        // pin capabilities and defaults. A mutable public graph is no authority.
        let actual = self.enumerate_codec(graph.address)?;
        if actual.vendor_id != graph.vendor_id || actual.revision_id != graph.revision_id {
            return Err(Error::InvalidCodecGraph);
        }
        let live = actual
            .groups
            .iter()
            .find(|g| g.node == group.node)
            .ok_or(Error::InvalidCodecGraph)?;
        let pin_live = actual.widget(pin).ok_or(Error::InvalidCodecGraph)?;
        if live.function_type != group.function_type
            || live.power_states != group.power_states
            || pin_live.power_states != widget.power_states
            || pin_live.output_amplifier != widget.output_amplifier
            || pin_live.kind != widget.kind
            || pin_live.capabilities != widget.capabilities
            || pin_live.pin_capabilities != widget.pin_capabilities
            || pin_live.pin_default != widget.pin_default
            || pin_live.connections != widget.connections
        {
            return Err(Error::InvalidCodecGraph);
        }
        Ok(())
    }
    /// Bind a genuine original GPU/HDA port owner. No ELD can be supplied by
    /// the caller. Modern NVIDIA/MST and Intel/AMD vendor profiles are refused.
    /// # Safety
    /// `owner` must retain and coordinate THIS actual controller/function,
    /// graph codec and physical pin. Its unsafe trait contract must hold for the
    /// complete attachment, including failures, reset and controller Drop.
    pub unsafe fn attach_hdmi_port(
        &mut self,
        graph: &CodecGraph,
        pin: u8,
        owner: Arc<dyn DisplayAudioPort>,
    ) -> Result<HdmiPortId, Error> {
        if self.routing_failed {
            return Err(Error::NeedsReset);
        }
        self.require_routing_stopped()?;
        let identity = owner.identity();
        if identity.codec != graph.address
            || identity.pin != pin
            || self
                .hdmi_ports
                .iter()
                .flatten()
                .any(|p| p.graph.address == graph.address && p.pin == pin)
        {
            return Err(Error::InvalidHdmiPort);
        }
        self.hdmi_topology(graph, pin)?;
        let start = self.timer.now_us();
        owner.observe(self.hdmi_deadline())?;
        self.hdmi_late(start)?;
        let id = HdmiPortId {
            token: self.token,
            index: self.hdmi_ports.len(),
        };
        self.hdmi_ports.push(Some(Port {
            attachment: id,
            owner: ManuallyDrop::new(owner),
            graph: graph.clone(),
            pin,
            sink: None,
            route: None,
            first_error: None,
        }));
        Ok(id)
    }
    /// Sticky original cause remains inspectable if a later full reset fails.
    /// Old handles still grant no route/control operations in the new epoch.
    pub fn hdmi_first_error(&self, id: HdmiPortId) -> Result<Option<Error>, Error> {
        self.hdmi_ports
            .get(id.index)
            .and_then(Option::as_ref)
            .filter(|p| p.attachment == id && id.token.owner == self.token.owner)
            .map(|p| p.first_error)
            .ok_or(Error::InvalidHdmiPort)
    }
    pub(super) fn hdmi_note_descriptor_fault(&mut self, descriptor: u8, error: Error) {
        for port in self.hdmi_ports.iter_mut().flatten() {
            if port
                .route
                .as_ref()
                .is_some_and(|r| r.stream.descriptor_index() == descriptor)
            {
                port.first_error.get_or_insert(error);
            }
        }
    }
    fn hdmi_record(&mut self, index: usize, error: Error) -> Error {
        self.hdmi_ports[index]
            .as_mut()
            .unwrap()
            .first_error
            .get_or_insert(error);
        error
    }
    fn hdmi_read_eld(&mut self, index: usize, state: DisplayAudioState) -> Result<HdmiSink, Error> {
        let port = self.hdmi_ports[index].as_ref().unwrap();
        let (codec, pin) = (port.graph.address, port.pin);
        let sense = self.verb(Verb::short(codec, pin, PIN_SENSE, 0)?)?;
        if sense == u32::MAX {
            return Err(Error::InvalidEld);
        }
        if !state.connected || sense & PRESENT == 0 {
            return Ok(HdmiSink { state, eld: None });
        }
        if sense & ELD_VALID == 0 {
            return Ok(HdmiSink { state, eld: None });
        }
        let size = self.verb(Verb::short(codec, pin, 0xf2e, 8)?)?;
        // Same donor compatibility fallback: a genuine zero length means 128,
        // never a missing service or fabricated monitor/ELD-valid bit.
        let size = if size == 0 {
            128
        } else {
            usize::try_from(size).map_err(|_| Error::InvalidEld)?
        };
        if !(20..=256).contains(&size) {
            return Err(Error::InvalidEld);
        }
        let mut raw = Vec::with_capacity(size);
        for byte in 0..size {
            let value = self.verb(Verb::short(codec, pin, 0xf2f, byte as u8)?)?;
            if value == u32::MAX || value & (1 << 31) == 0 || (byte == 0 && value & 255 == 0) {
                return Err(Error::InvalidEld);
            }
            raw.push(value as u8);
        }
        let after = self.verb(Verb::short(codec, pin, PIN_SENSE, 0)?)?;
        if after != sense || self.hdmi_observe(index)? != state {
            return Err(Error::SinkChanged);
        }
        Ok(HdmiSink {
            state,
            eld: Some(Eld::parse(&raw)?),
        })
    }
    /// Explicit polled hotplug/ELD service. A failed/changed snapshot first
    /// stops any actual PCM route; a new valid snapshot requires fresh prepare.
    pub fn poll_hdmi_sink(&mut self, id: HdmiPortId) -> Result<HdmiSink, Error> {
        let index = self.hdmi_index(id)?;
        if self.routing_failed {
            return Err(Error::NeedsReset);
        }
        let observed = self
            .hdmi_observe(index)
            .and_then(|s| self.hdmi_read_eld(index, s));
        let changed = match &observed {
            Ok(s) => self.hdmi_ports[index].as_ref().unwrap().sink.as_ref() != Some(s),
            Err(_) => true,
        };
        if changed && self.hdmi_ports[index].as_ref().unwrap().route.is_some() {
            let cause = observed
                .as_ref()
                .err()
                .copied()
                .unwrap_or(Error::SinkChanged);
            self.hdmi_record(index, cause);
            if let Err(error) = self.hdmi_close_index(index) {
                self.routing_failed = true;
                self.hdmi_record(index, error);
                return Err(cause);
            }
        }
        match observed {
            Ok(sink) => {
                self.hdmi_ports[index].as_mut().unwrap().sink = Some(sink.clone());
                Ok(sink)
            }
            Err(error) => Err(self.hdmi_record(index, error)),
        }
    }
    fn hdmi_long_control(
        &mut self,
        codec: u8,
        node: u8,
        set: u8,
        get: u8,
        value: u16,
    ) -> Result<(), Error> {
        self.verb(Verb::long(codec, node, set, value)?)?;
        if self.verb(Verb::long(codec, node, get, 0)?)? != u32::from(value) {
            return Err(Error::RouteRejected);
        }
        Ok(())
    }
    fn hdmi_digital_control(&mut self, codec: u8, node: u8, value: u8) -> Result<(), Error> {
        self.verb(Verb::short(codec, node, 0x70d, value)?)?;
        let observed = self.verb(Verb::short(codec, node, 0xf0d, 0)?)?;
        if observed == u32::MAX || observed & 255 != u32::from(value) {
            return Err(Error::RouteRejected);
        }
        Ok(())
    }
    fn hdmi_packet(
        &mut self,
        codec: u8,
        pin: u8,
        connection: Connection,
        map: &ChannelMap,
    ) -> Result<(), Error> {
        let mut packet = [0u8; 9];
        packet[0] = 0x84;
        match connection {
            Connection::Hdmi => {
                packet[1] = 1;
                packet[2] = 10;
            }
            Connection::DisplayPort => {
                packet[1] = 0x1b;
                packet[2] = 0x44;
            }
        }
        packet[4] = map.order.len() as u8 - 1;
        packet[7] = map.allocation;
        packet[3] = 0u8.wrapping_sub(packet.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
        // Stop -> write entire union -> verify actual DIP RAM -> transmit.
        self.route_control(codec, pin, 0x730, 0xf30, 0)?;
        self.route_control(codec, pin, 0x732, 0xf32, 0)?;
        for byte in packet {
            self.verb(Verb::short(codec, pin, 0x731, byte)?)?;
        }
        self.route_control(codec, pin, 0x730, 0xf30, 0)?;
        for byte in packet {
            if self.verb(Verb::short(codec, pin, 0xf31, 0)?)? != u32::from(byte) {
                return Err(Error::RouteRejected);
            }
        }
        self.route_control(codec, pin, 0x730, 0xf30, 0)?;
        self.route_control(codec, pin, 0x732, 0xf32, 0xc0)
    }
    /// Prepare actual digital converter, mux, count, slots, packet and pin for
    /// 2..8ch LPCM, constrained by this sink's actual ELD. No HBR/non-PCM alias.
    pub fn prepare_hdmi(
        &mut self,
        id: HdmiPortId,
        stream: StreamId,
        converter: u8,
        custom_map: Option<&[Speaker]>,
    ) -> Result<ChannelMap, Error> {
        let index = self.hdmi_index(id)?;
        if self.routing_failed {
            return Err(Error::NeedsReset);
        }
        self.require_routing_stopped()?;
        if self.hdmi_ports[index].as_ref().unwrap().route.is_some() {
            return Err(Error::RouteInUse);
        }
        let format = self.stream_format(stream)?;
        let period = self.stream(stream)?.period_bytes;
        let ring = self.stream_buffer_bytes(stream)?;
        if ring / period < 3 {
            return Err(Error::InvalidBuffer);
        }
        if self.stream_direction(stream)? != Direction::Playback {
            return Err(Error::InvalidFormat);
        }
        let graph = self.hdmi_ports[index].as_ref().unwrap().graph.clone();
        let pin = self.hdmi_ports[index].as_ref().unwrap().pin;
        self.hdmi_topology(&graph, pin)?;
        let snapshot = self.poll_hdmi_sink(id)?;
        let eld = snapshot.eld.as_ref().ok_or(Error::SinkUnavailable)?;
        if !eld.supports(format) {
            return Err(Error::InvalidFormat);
        }
        let map = ChannelMap::choose(format.channels, eld.speakers, custom_map)?;
        let widget = graph.widget(converter).ok_or(Error::InvalidCodecGraph)?;
        let actual = self.enumerate_codec(graph.address)?;
        let live = actual.widget(converter).ok_or(Error::InvalidCodecGraph)?;
        if widget.kind != WidgetKind::Output
            || widget.capabilities & DIGITAL == 0
            || widget.channels() < format.channels
            || widget
                .power_states
                .is_some_and(|p| p == u32::MAX || p & 1 == 0)
            || live.power_states != widget.power_states
            || !widget.pcm.supports(format)
            || live.capabilities != widget.capabilities
            || live.pcm.rates_and_bits != widget.pcm.rates_and_bits
            || live.pcm.stream_formats != widget.pcm.stream_formats
        {
            return Err(Error::InvalidFormat);
        }
        let mux = graph
            .widget(pin)
            .unwrap()
            .connections
            .iter()
            .position(|n| *n == converter)
            .ok_or(Error::UnsupportedTopology)? as u8;
        if self.converter_bindings.iter().any(|binding| {
            binding.stream == stream
                || (binding.codec == graph.address
                    && (binding.node == pin || binding.node == converter))
        }) {
            return Err(Error::RouteInUse);
        }
        if self.hdmi_ports.iter().flatten().any(|p| {
            p.route.as_ref().is_some_and(|r| {
                r.stream == stream || (p.graph.address == graph.address && r.converter == converter)
            })
        }) || self.routes.iter().any(|(owner, r)| {
            *owner == stream
                || (r.codec_address() == graph.address
                    && (r.nodes().contains(&pin) || r.nodes().contains(&converter)))
        }) || self
            .codec_controls
            .iter()
            .any(|(_, c, n)| *c == graph.address && (*n == pin || *n == converter))
        {
            return Err(Error::RouteInUse);
        }
        let packet_size = self.verb(Verb::short(graph.address, pin, 0xf2e, 0)?)?;
        if !(9..=32).contains(&packet_size) {
            return Err(Error::RouteRejected);
        }
        let digital = self.verb(Verb::short(graph.address, converter, 0xf0d, 0)?)?;
        if digital == u32::MAX {
            return Err(Error::RouteRejected);
        }
        let digital = (digital as u8 & !0x21) | 1; // actual LPCM + enabled; retain unrelated channel-status controls.
        // Reserve all owners BEFORE GPU or codec effects, including failed ACK.
        self.streams[usize::from(stream.descriptor_index())]
            .as_mut()
            .unwrap()
            .hdmi_required = true;
        self.hdmi_ports[index].as_mut().unwrap().route = Some(Route {
            stream,
            converter,
            mux,
            format,
            map: map.clone(),
            digital,
            generation: snapshot.state.generation,
            prepared: false,
            progress: None,
        });
        let result = (|| {
            self.hdmi_effect(index, Some(format))?;
            let group = graph
                .groups
                .iter()
                .find(|g| g.widgets.iter().any(|w| w.node == pin))
                .ok_or(Error::InvalidCodecGraph)?;
            self.power_d0(graph.address, group.node)?;
            for node in [converter, pin] {
                if graph.widget(node).unwrap().power_states.is_some() {
                    self.power_d0(graph.address, node)?;
                }
            }
            self.route_control(graph.address, pin, 0x701, 0xf01, mux)?;
            self.route_control(graph.address, pin, 0x707, 0xf07, 0)?;
            self.hdmi_digital_control(graph.address, converter, digital)?;
            self.route_control(graph.address, converter, 0x72d, 0xf2d, format.channels - 1)?;
            for slot in map.slots {
                self.verb(Verb::short(graph.address, pin, 0x734, slot)?)?;
            }
            // NVIDIA stereo ignores ASP remapping; the fixed FL/FR map is
            // validated above. Wider maps must actually read back every slot.
            if format.channels > 2 {
                for slot in map.slots {
                    let value = self.verb(Verb::short(graph.address, pin, 0xf34, slot & 15)?)?;
                    if value & 0xf0 != u32::from(slot & 0xf0) || value == u32::MAX {
                        return Err(Error::RouteRejected);
                    }
                }
            }
            if graph.widget(pin).unwrap().output_amplifier.is_some() {
                self.verb(Verb::long(graph.address, pin, 3, 0xb000)?)?;
                for channel in [0x8000, 0xa000] {
                    if self.verb(Verb::long(graph.address, pin, 0xb, channel)?)? & 0xff != 0 {
                        return Err(Error::RouteRejected);
                    }
                }
            }
            self.hdmi_packet(graph.address, pin, eld.connection, &map)?;
            self.route_control(graph.address, pin, 0x707, 0xf07, 0x40)?;
            self.hdmi_long_control(graph.address, converter, 2, 0xa, format.encode()?)?;
            self.route_control(graph.address, converter, 0x706, 0xf06, stream.tag() << 4)?;
            if self.hdmi_observe(index)? != snapshot.state {
                return Err(Error::SinkChanged);
            }
            self.hdmi_ports[index]
                .as_mut()
                .unwrap()
                .route
                .as_mut()
                .unwrap()
                .prepared = true;
            Ok(map)
        })();
        result.map_err(|error| {
            self.routing_failed = true;
            self.hdmi_record(index, error)
        })
    }
    /// Standard IEC958 digital-output enable, with live retained sink/route
    /// validation. This does not change coding type, PCM format, rate or GPU
    /// association; the DMA clock may continue while the output is disabled.
    pub fn set_hdmi_enabled(&mut self, id: HdmiPortId, enabled: bool) -> Result<(), Error> {
        let index = self.hdmi_index(id)?;
        if self.routing_failed {
            return Err(Error::NeedsReset);
        }
        let port = self.hdmi_ports[index].as_ref().unwrap();
        let route = port.route.as_ref().ok_or(Error::SinkUnavailable)?;
        let (stream, codec, cvt, value) = (
            route.stream,
            port.graph.address,
            route.converter,
            (route.digital & !1) | u8::from(enabled),
        );
        self.stream(stream)?;
        self.hdmi_runtime(stream)?;
        self.hdmi_ports[index]
            .as_mut()
            .unwrap()
            .route
            .as_mut()
            .unwrap()
            .digital = value;
        self.hdmi_digital_control(codec, cvt, value).map_err(|e| {
            self.routing_failed = true;
            self.hdmi_record(index, e)
        })
    }
    fn hdmi_close_index(&mut self, index: usize) -> Result<(), Error> {
        let port = self.hdmi_ports[index].as_ref().unwrap();
        let (codec, pin) = (port.graph.address, port.pin);
        let Some(route) = port.route.as_ref() else {
            return Ok(());
        };
        let (stream, converter, digital) = (route.stream, route.converter, route.digital);
        // DMA-stop ACK is mandatory before changing route/clock owners.
        self.stop_descriptor(stream.descriptor_index())?;
        if let Some(s) = self.streams[usize::from(stream.descriptor_index())].as_mut() {
            s.running = false;
        }
        self.route_control(codec, pin, 0x730, 0xf30, 0)?;
        self.route_control(codec, pin, 0x732, 0xf32, 0)?;
        self.route_control(codec, pin, 0x707, 0xf07, 0)?;
        self.route_control(codec, converter, 0x706, 0xf06, 0)?;
        self.hdmi_digital_control(codec, converter, digital & !1)?;
        self.hdmi_effect(index, None)?;
        self.hdmi_ports[index].as_mut().unwrap().route = None;
        Ok(())
    }
    pub fn close_hdmi(&mut self, id: HdmiPortId) -> Result<(), Error> {
        let index = self.hdmi_index(id)?;
        self.hdmi_close_index(index).map_err(|e| {
            self.routing_failed = true;
            self.hdmi_record(index, e)
        })
    }
    pub fn detach_hdmi_port(&mut self, id: HdmiPortId) -> Result<(), Error> {
        let index = self.hdmi_index(id)?;
        self.close_hdmi(id)?;
        let mut port = self.hdmi_ports[index].take().unwrap();
        // SAFETY: exact route/stream/packet/converter/GPU stop succeeded; this
        // is the only place ordinary release of this retained owner is allowed.
        unsafe {
            ManuallyDrop::drop(&mut port.owner);
        }
        Ok(())
    }
    pub(super) fn shutdown_hdmi(&mut self) -> Result<(), Error> {
        let mut first = None;
        for index in 0..self.hdmi_ports.len() {
            if self.hdmi_ports[index].is_some()
                && let Err(error) = self.hdmi_close_index(index)
            {
                first.get_or_insert(self.hdmi_record(index, error));
            }
        }
        first.map_or(Ok(()), Err)
    }
    /// Release only already-quiet GPU/HDA D0 grants before native PCI suspend.
    /// A mere request to enter D3, PMCSR capability or cleared software RUN is
    /// not proof. Successful shutdown must have acknowledged every DMA/command
    /// stop and every codec/GPU route effect in the original D0 epoch.
    #[allow(dead_code)] // Consumer is the separately owned native PCI lifecycle.
    pub(super) fn retire_hdmi_for_pci_suspend(&mut self) -> Result<(), Error> {
        if !self.stopped
            || self.lifecycle_failed
            || !self.command_poisoned
            || self.hdmi_ports.iter().flatten().any(|p| p.route.is_some())
        {
            return Err(Error::NeedsReset);
        }
        for entry in &mut self.hdmi_ports {
            if let Some(mut port) = entry.take() {
                // SAFETY: actual complete shutdown established quiet above;
                // retain None tombstones so no same-epoch ID can be recycled.
                unsafe {
                    ManuallyDrop::drop(&mut port.owner);
                }
            }
        }
        Ok(())
    }
    pub(super) fn retire_hdmi_after_reset(&mut self) -> Result<(), Error> {
        // A lost command ACK may prevent pre-reset codec cleanup. The actual
        // full link/command reset restores unambiguous verbs; re-enumerate the
        // original codec/pin before proving quiet and releasing any old owner.
        for index in 0..self.hdmi_ports.len() {
            if let Some(port) = self.hdmi_ports[index].as_ref() {
                if port.route.is_none() {
                    continue;
                }
                let (codec, pin, vendor) = (port.graph.address, port.pin, port.graph.vendor_id);
                let graph = self.enumerate_codec(codec)?;
                if graph.vendor_id != vendor {
                    return Err(Error::InvalidCodecGraph);
                }
                self.hdmi_topology(&graph, pin)?;
                self.hdmi_ports[index].as_mut().unwrap().graph = graph;
                self.hdmi_close_index(index)?;
            }
        }
        // Do not discard a failed route on reset. Whole stream/codec/GPU quiet
        // must have succeeded; otherwise the original port remains quarantined.
        if self.hdmi_ports.iter().flatten().any(|p| p.route.is_some()) {
            return Err(Error::NeedsReset);
        }
        for entry in &mut self.hdmi_ports {
            if let Some(mut p) = entry.take() {
                unsafe {
                    ManuallyDrop::drop(&mut p.owner);
                }
            }
        }
        self.hdmi_ports.clear();
        Ok(())
    }
    pub(super) fn hdmi_owns_node(&self, codec: u8, node: u8) -> bool {
        self.hdmi_ports.iter().flatten().any(|p| {
            p.graph.address == codec
                && (p.pin == node || p.route.as_ref().is_some_and(|r| r.converter == node))
        })
    }
    pub(super) fn hdmi_start_failed(&mut self, index: usize, id: StreamId, error: Error) {
        self.hdmi_record(index, error);
        if let Some(stream) = self.streams[usize::from(id.descriptor_index())].as_mut() {
            stream.poisoned = true;
        }
        self.routing_failed = true;
    }
    pub(super) fn hdmi_stream_port(&self, id: StreamId) -> Option<usize> {
        self.hdmi_ports.iter().position(|p| {
            p.as_ref()
                .is_some_and(|p| p.route.as_ref().is_some_and(|r| r.stream == id))
        })
    }
    pub(super) fn hdmi_runtime(&mut self, id: StreamId) -> Result<(), Error> {
        let Some(index) = self.hdmi_stream_port(id) else {
            return Ok(());
        };
        let result = (|| {
            let port = self.hdmi_ports[index].as_ref().unwrap();
            let route = port.route.as_ref().unwrap();
            let (codec, pin, cvt, mux, digital, format, generation, prepared) = (
                port.graph.address,
                port.pin,
                route.converter,
                route.mux,
                route.digital,
                route.format,
                route.generation,
                route.prepared,
            );
            if !prepared {
                return Err(Error::SinkChanged);
            }
            let state = self.hdmi_observe(index)?;
            if state.generation != generation || !state.connected {
                return Err(Error::SinkChanged);
            }
            let sense = self.verb(Verb::short(codec, pin, PIN_SENSE, 0)?)?;
            if sense == u32::MAX || sense & (PRESENT | ELD_VALID) != (PRESENT | ELD_VALID) {
                return Err(Error::SinkChanged);
            }
            for (node, get, expected) in [
                (pin, 0xf01, u32::from(mux)),
                (pin, 0xf07, 0x40),
                (cvt, 0xf06, u32::from(id.tag() << 4)),
                (cvt, 0xf2d, u32::from(format.channels - 1)),
                (pin, 0xf32, 0xc0),
            ] {
                if self.verb(Verb::short(codec, node, get, 0)?)? != expected {
                    return Err(Error::RouteRejected);
                }
            }
            let observed_digital = self.verb(Verb::short(codec, cvt, 0xf0d, 0)?)?;
            if observed_digital == u32::MAX || observed_digital & 255 != u32::from(digital) {
                return Err(Error::RouteRejected);
            }
            let map = self.hdmi_ports[index]
                .as_ref()
                .unwrap()
                .route
                .as_ref()
                .unwrap()
                .map
                .clone();
            if format.channels > 2 {
                for slot in map.slots {
                    let observed = self.verb(Verb::short(codec, pin, 0xf34, slot & 15)?)?;
                    if observed == u32::MAX || observed & 0xf0 != u32::from(slot & 0xf0) {
                        return Err(Error::RouteRejected);
                    }
                }
            }
            if self.verb(Verb::long(codec, cvt, 0xa, 0)?)? != u32::from(format.encode()?) {
                return Err(Error::RouteRejected);
            }
            Ok(())
        })();
        if let Err(error) = result {
            // A normal hotplug is recoverable after actual cleanup. A failed
            // stop/command/access keeps the route, first error and exact owners.
            self.hdmi_record(index, error);
            if let Err(cleanup) = self.hdmi_close_index(index) {
                self.routing_failed = true;
                self.hdmi_record(index, cleanup);
            }
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
