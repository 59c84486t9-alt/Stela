// SPDX-License-Identifier: GPL-2.0-or-later
//! USB Audio 1.0 Type-I PCM: descriptor frequencies and endpoint controls.
//! Reference: Linux sound/usb/{format,clock,mixer}.c, pinned in THIRD_PARTY.md.
//! Alan Cox, Thomas Sailer, Takashi Iwai and Daniel Mack retain their notices.
use super::{Binding, Control, Entity, Error, Format, Graph, RateRange, Sync};
use super::{CLASS, STREAMING_SUBCLASS, UAC1};
use crate::{
    audio::Direction,
    bytes::le16,
    usb::xhci::{Interface, setup},
};
use alloc::vec::Vec;

const CS_INTERFACE: u8 = 0x24;
const CS_ENDPOINT: u8 = 0x25;
const SAMPLE_RATE: u16 = 1 << 8;
const PITCH: u16 = 2 << 8;
const GET_CUR: u8 = 0x81;
const SET_CUR: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointRates {
    pub ranges: Vec<RateRange>,
    pub frequency_control: bool,
    pub pitch_control: bool,
}
impl EndpointRates {
    pub(super) fn validate_rate(&self, rate: u32) -> Result<(), Error> {
        if rate == 0 || rate > 768_000 || !self.ranges.iter().any(|r| r.contains(rate)) {
            return Err(Error::RateUnsupported);
        }
        // Without frequency control an alternate must unambiguously name one
        // fixed frequency. Do not claim an arbitrary requested physical rate.
        if !self.frequency_control
            && (self.ranges.len() != 1 || self.ranges[0].min != self.ranges[0].max)
        {
            return Err(Error::Unsupported(
                "UAC1 multiple frequencies without endpoint control",
            ));
        }
        Ok(())
    }
    pub(super) fn apply<C: Control>(
        &self,
        io: &mut C,
        endpoint: u8,
        rate: u32,
    ) -> Result<(), Error> {
        self.validate_rate(rate)?;
        if self.pitch_control {
            endpoint_control(io, endpoint, PITCH, &[1])?;
        }
        if self.frequency_control {
            endpoint_control(io, endpoint, SAMPLE_RATE, &rate.to_le_bytes()[..3])?;
        }
        Ok(())
    }
}
fn endpoint_control<C: Control>(
    io: &mut C,
    endpoint: u8,
    selector: u16,
    value: &[u8],
) -> Result<(), Error> {
    let n = value.len() as u16;
    if !io
        .control(
            setup(0x22, SET_CUR, selector, u16::from(endpoint), n),
            value,
        )?
        .is_empty()
    {
        return Err(Error::ControlLength);
    }
    let reply = io.control(setup(0xa2, GET_CUR, selector, u16::from(endpoint), n), &[])?;
    if reply.len() != value.len() {
        return Err(Error::ControlLength);
    }
    if reply != value {
        return Err(Error::ControlReadback);
    }
    Ok(())
}
fn triple(d: &[u8]) -> u32 {
    u32::from_le_bytes([d[0], d[1], d[2], 0])
}

fn graph(control: &Interface) -> Result<(Graph, Vec<u8>), Error> {
    let mut entities = Vec::new();
    let mut collection = None;
    let mut advertised = 0;
    let mut total = 0;
    for d in control
        .extra
        .iter()
        .filter(|d| d.len() >= 3 && d[1] == CS_INTERFACE)
    {
        total += d.len();
        let invalid = || Error::Descriptor("invalid UAC1 control descriptor");
        let entity = match d[2] {
            1 => {
                if collection.is_some()
                    || d.len() < 9
                    || le16(d, 3) != 0x0100
                    || d.len() != 8 + usize::from(d[7])
                    || d[7] == 0
                {
                    return Err(invalid());
                }
                advertised = usize::from(le16(d, 5));
                let members = d[8..].to_vec();
                for (i, number) in members.iter().enumerate() {
                    if *number == control.number || members[..i].contains(number) {
                        return Err(invalid());
                    }
                }
                collection = Some(members);
                None
            }
            2 => {
                if d.len() != 12 || d[7] == 0 {
                    return Err(invalid());
                }
                Some(Entity::Input {
                    id: d[3],
                    terminal_type: le16(d, 4),
                    clock: 0,
                    channels: d[7],
                    channel_config: u32::from(le16(d, 8)),
                })
            }
            3 => {
                if d.len() != 9 {
                    return Err(invalid());
                }
                Some(Entity::Output {
                    id: d[3],
                    terminal_type: le16(d, 4),
                    source: d[7],
                    clock: 0,
                })
            }
            5 => {
                if d.len() < 7 || d[4] == 0 || d.len() != 6 + usize::from(d[4]) {
                    return Err(invalid());
                }
                Some(Entity::Selector {
                    id: d[3],
                    sources: d[5..d.len() - 1].to_vec(),
                    controls: 3,
                })
            }
            6 => {
                if d.len() < 8 || !(1..=4).contains(&d[5]) {
                    return Err(invalid());
                }
                let size = usize::from(d[5]);
                if !(d.len() - 7).is_multiple_of(size) {
                    return Err(invalid());
                }
                let mut controls = Vec::new();
                for channel in d[6..d.len() - 1].chunks_exact(size) {
                    let mut raw = [0; 4];
                    raw[..size].copy_from_slice(channel);
                    let raw = u32::from_le_bytes(raw);
                    if raw >> 16 != 0 {
                        return Err(invalid());
                    }
                    let mut normalized = 0;
                    for bit in 0..16 {
                        if raw & (1 << bit) != 0 {
                            normalized |= 3 << (bit * 2);
                        }
                    }
                    controls.push(normalized);
                }
                Some(Entity::Feature {
                    id: d[3],
                    source: d[4],
                    controls,
                })
            }
            _ => return Err(Error::Unsupported("UAC1 mixer/processing/extension entity")),
        };
        if let Some(entity) = entity {
            if entity.id() == 0 || entities.iter().any(|e: &Entity| e.id() == entity.id()) {
                return Err(invalid());
            }
            entities.push(entity);
        }
    }
    let collection = collection.ok_or(Error::Descriptor("missing UAC1 header"))?;
    if total != advertised || entities.is_empty() {
        return Err(Error::Descriptor("UAC1 control total length"));
    }
    let graph = Graph {
        protocol: UAC1,
        control_interface: control.number,
        entities,
    };
    graph.validate()?;
    // Validate feature-channel extents against the actual source cluster.
    for entity in &graph.entities {
        if let Entity::Feature {
            source, controls, ..
        } = entity
            && controls.len() != usize::from(channels(&graph, *source, &mut [false; 256])?) + 1
        {
            return Err(Error::Descriptor("UAC1 feature channel count"));
        }
    }
    Ok((graph, collection))
}
fn channels(graph: &Graph, id: u8, visited: &mut [bool; 256]) -> Result<u8, Error> {
    cluster(graph, id, visited).map(|(count, _)| count)
}
fn cluster(graph: &Graph, id: u8, visited: &mut [bool; 256]) -> Result<(u8, u32), Error> {
    if visited[usize::from(id)] {
        return Err(Error::Descriptor("cyclic UAC1 signal cluster"));
    }
    visited[usize::from(id)] = true;
    let result = match graph.entity(id)? {
        Entity::Input {
            channels,
            channel_config,
            ..
        } => Ok((*channels, *channel_config)),
        Entity::Feature { source, .. } | Entity::Output { source, .. } => {
            cluster(graph, *source, visited)
        }
        Entity::Selector { sources, .. } => {
            let mut common = None;
            for source in sources {
                let value = cluster(graph, *source, &mut *visited)?;
                if common.is_some_and(|n| n != value) {
                    return Err(Error::Unsupported("UAC1 selector changes channel cluster"));
                }
                common = Some(value);
            }
            common.ok_or(Error::Descriptor("empty UAC1 selector"))
        }
        _ => Err(Error::Descriptor("UAC1 signal references a clock")),
    };
    visited[usize::from(id)] = false;
    result
}
fn endpoint_descriptor(
    configuration: &[u8],
    interface: &Interface,
    address: u8,
) -> Result<Vec<u8>, Error> {
    let mut at = 0;
    let mut selected = false;
    while at < configuration.len() {
        let n = usize::from(configuration[at]);
        let d = &configuration[at..at + n]; // shared scope() validated every extent
        if d[1] == 4 {
            selected = d[2] == interface.number && d[3] == interface.alternate;
        }
        if selected && d[1] == 5 && d[2] == address {
            return Ok(d.to_vec());
        }
        at += n;
    }
    Err(Error::Descriptor("missing UAC1 endpoint bytes"))
}
fn format(
    interface: &Interface,
    graph: &Graph,
    configuration: &[u8],
    speed: u8,
) -> Result<Format, Error> {
    let only = |subtype| -> Result<&Vec<u8>, Error> {
        let mut values = interface
            .extra
            .iter()
            .filter(|d| d.len() >= 3 && d[1] == CS_INTERFACE && d[2] == subtype);
        let value = values
            .next()
            .ok_or(Error::Descriptor("missing UAC1 streaming descriptor"))?;
        if values.next().is_some() {
            return Err(Error::Descriptor("duplicate UAC1 streaming descriptor"));
        }
        Ok(value)
    };
    let general = only(1)?;
    let descriptor = only(2)?;
    if general.len() != 7 || descriptor.len() < 8 {
        return Err(Error::Descriptor("short UAC1 AS/format"));
    }
    if le16(general, 5) != 1 || descriptor[3] != 1 {
        return Err(Error::Unsupported("UAC1 non-Type-I signed PCM"));
    }
    let channels_count = descriptor[4];
    let subslot = descriptor[5];
    let bits = descriptor[6];
    if !(1..=32).contains(&channels_count)
        || !(1..=4).contains(&subslot)
        || bits == 0
        || bits > subslot * 8
    {
        return Err(Error::Format);
    }
    let n = usize::from(descriptor[7]);
    if descriptor.len() != 8 + 3 * if n == 0 { 2 } else { n } {
        return Err(Error::Descriptor("UAC1 frequency extent"));
    }
    let ranges = if n == 0 {
        let (min, max) = (triple(&descriptor[8..11]), triple(&descriptor[11..14]));
        if min == 0 || min > max {
            return Err(Error::Descriptor("UAC1 frequency range"));
        }
        vec![RateRange {
            min,
            max,
            resolution: 1,
        }]
    } else {
        let mut ranges = Vec::new();
        for bytes in descriptor[8..].as_chunks::<3>().0 {
            let rate = triple(bytes);
            if rate == 0 || ranges.iter().any(|r: &RateRange| r.min == rate) {
                return Err(Error::Descriptor("UAC1 zero/duplicate frequency"));
            }
            ranges.push(RateRange {
                min: rate,
                max: rate,
                resolution: 0,
            });
        }
        ranges
    };
    let data: Vec<_> = interface
        .endpoints
        .iter()
        .filter(|e| e.kind() == 1 && e.attributes & 0x30 == 0)
        .copied()
        .collect();
    let feedback: Vec<_> = interface
        .endpoints
        .iter()
        .filter(|e| e.kind() == 1 && e.attributes & 0x30 == 0x10)
        .copied()
        .collect();
    if data.len() != 1
        || feedback.len() > 1
        || data.len() + feedback.len() != interface.endpoints.len()
    {
        return Err(Error::Descriptor("UAC1 data/feedback endpoints"));
    }
    let data = data[0];
    let direction = if data.is_in() {
        Direction::Capture
    } else {
        Direction::Playback
    };
    graph.terminal_clock(general[3], direction)?;
    let (terminal_channels, channel_config) = cluster(graph, general[3], &mut [false; 256])?;
    if terminal_channels != channels_count {
        return Err(Error::Descriptor("UAC1 format/terminal channel mismatch"));
    }
    let ep = endpoint_descriptor(configuration, interface, data.address)?;
    if !matches!(ep.len(), 7 | 9) {
        return Err(Error::Descriptor("UAC1 standard endpoint size"));
    }
    let synch = if ep.len() == 9 { ep[8] } else { 0 };
    let sync = match ((data.attributes >> 2) & 3, direction, feedback.first()) {
        (3, _, None) => Sync::Synchronous,
        (2, _, None) => Sync::Adaptive,
        (1, Direction::Capture, None) => Sync::Synchronous,
        (1, Direction::Playback, Some(fb)) if fb.is_in() && synch == fb.address => {
            let mut fb = *fb;
            let raw = endpoint_descriptor(configuration, interface, fb.address)?;
            if !matches!(raw.len(), 7 | 9) || raw.len() == 9 && raw[8] != 0 {
                return Err(Error::Descriptor("invalid UAC1 feedback descriptor"));
            }
            // Linux endpoint_set_syncinterval uses bRefresh when present,
            // otherwise its full-speed default or high-speed bInterval.
            if raw.len() == 9 && (1..=9).contains(&raw[7]) {
                fb.interval = raw[7] + 1;
            } else if speed == crate::usb::xhci::FULL_SPEED {
                fb.interval = 2;
            }
            if super::descriptors::capacity(fb, speed)? < if speed == 3 { 4 } else { 3 } {
                return Err(Error::Descriptor("short UAC1 feedback endpoint"));
            }
            super::descriptors::service_interval(fb, speed)?;
            Sync::Explicit(fb)
        }
        _ => {
            return Err(Error::Unsupported(
                "UAC1 synchronization/feedback association",
            ));
        }
    };
    if !matches!(sync, Sync::Explicit(_)) && synch != 0 {
        return Err(Error::Descriptor(
            "unexpected UAC1 synchronization endpoint",
        ));
    }
    let mut cs = interface
        .extra
        .iter()
        .filter(|d| d.len() >= 3 && d[1] == CS_ENDPOINT && d[2] == 1);
    let controls = cs
        .next()
        .ok_or(Error::Descriptor("missing UAC1 class endpoint"))?;
    if cs.next().is_some() || controls.len() != 7 || controls[3] & !0x83 != 0 {
        return Err(Error::Descriptor("invalid UAC1 class endpoint"));
    }
    let max_bytes = super::descriptors::capacity(data, speed)?;
    let service_microframes = super::descriptors::service_interval(data, speed)?;
    Ok(Format {
        endpoint_rates: Some(EndpointRates {
            ranges,
            frequency_control: controls[3] & 1 != 0,
            pitch_control: controls[3] & 2 != 0,
        }),
        interface: interface.number,
        alternate: interface.alternate,
        terminal: general[3],
        clock: 0,
        direction,
        channels: channels_count,
        subslot,
        bits,
        channel_config,
        data,
        sync,
        service_microframes,
        max_bytes,
        fill_max: controls[3] & 0x80 != 0,
    })
}

pub(super) fn binding(
    control: &Interface,
    all: &[Interface],
    configuration: &[u8],
    speed: u8,
) -> Result<Binding, Error> {
    let scope = super::descriptors::scope(configuration, control.number, all, UAC1)?;
    let (graph, collection) = graph(control)?;
    if collection
        .iter()
        .any(|member| !scope.contains(&u16::from(*member)))
    {
        return Err(Error::Descriptor(
            "UAC1 stream outside interface association",
        ));
    }
    // A legacy AC header may have no own IAD. Its collection still cannot
    // claim an interface which a sibling function's IAD owns.
    let mut at = 0;
    while at < configuration.len() {
        let n = usize::from(configuration[at]);
        let d = &configuration[at..at + n]; // scope() validated all extents
        if d[1] == crate::usb::xhci::INTERFACE_ASSOCIATION_DESCRIPTOR {
            let range = u16::from(d[2])..u16::from(d[2]) + u16::from(d[3]);
            if !range.contains(&u16::from(control.number))
                && collection.iter().any(|id| range.contains(&u16::from(*id)))
            {
                return Err(Error::Descriptor(
                    "UAC1 stream belongs to sibling association",
                ));
            }
        }
        at += n;
    }
    for other in all.iter().filter(|i| {
        i.number != control.number
            && i.alternate == 0
            && (i.class, i.subclass, i.protocol) == (CLASS, super::CONTROL_SUBCLASS, UAC1)
    }) {
        for header in other
            .extra
            .iter()
            .filter(|d| d.len() >= 8 && d[1] == CS_INTERFACE && d[2] == 1)
        {
            if header.len() != 8 + usize::from(header[7]) {
                return Err(Error::Descriptor("invalid sibling UAC1 collection"));
            }
            if header[8..].iter().any(|id| collection.contains(id)) {
                return Err(Error::Descriptor("overlapping UAC1 collections"));
            }
        }
    }

    for member in &collection {
        if !all.iter().any(|i| {
            i.number == *member
                && i.alternate == 0
                && i.class == CLASS
                && i.subclass == STREAMING_SUBCLASS
                && i.protocol == UAC1
                && i.endpoints.is_empty()
        }) {
            return Err(Error::Descriptor(
                "UAC1 collection has no zero-bandwidth stream",
            ));
        }
    }
    let mut formats = Vec::new();
    let mut unsupported = Vec::new();
    for interface in all
        .iter()
        .filter(|i| collection.contains(&i.number) && i.alternate != 0)
    {
        if (interface.class, interface.subclass, interface.protocol)
            != (CLASS, STREAMING_SUBCLASS, UAC1)
        {
            return Err(Error::Descriptor("UAC1 alternate changes interface class"));
        }
        match format(interface, &graph, configuration, speed) {
            Ok(format) => formats.push(format),
            Err(Error::Unsupported(reason)) => {
                unsupported.push((interface.number, interface.alternate, reason))
            }
            Err(error) => return Err(error),
        }
    }
    if formats.is_empty() {
        return Err(Error::Unsupported("no usable UAC1 PCM alternate"));
    }
    // Reject endpoint aliases across independently owned functions/collections.
    for format in &formats {
        for other in all
            .iter()
            .filter(|i| i.number != format.interface && !collection.contains(&i.number))
        {
            if other
                .endpoints
                .iter()
                .any(|e| format.endpoints().iter().any(|ours| ours.dci() == e.dci()))
            {
                return Err(Error::Descriptor("UAC1 endpoint aliases foreign owner"));
            }
        }
    }
    Ok(Binding {
        graph,
        formats,
        speed,
        unsupported,
    })
}
