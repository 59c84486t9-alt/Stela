// SPDX-License-Identifier: GPL-2.0-only
//! UAC2 descriptor layouts from Linux include/linux/usb/audio-v2.h and
//! sound/usb/format.c. All IDs and relationships come from runtime descriptors.
use super::{CLASS, CONTROL_SUBCLASS, Error, STREAMING_SUBCLASS, UAC2};
use crate::{
    audio::Direction,
    usb::xhci::{Endpoint, Interface},
};
use alloc::vec::Vec;

const CS_INTERFACE: u8 = 0x24;
const CS_ENDPOINT: u8 = 0x25;
const USB_STREAMING: u16 = 0x0101;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entity {
    ClockSource {
        id: u8,
        controls: u8,
    },
    ClockSelector {
        id: u8,
        sources: Vec<u8>,
        controls: u8,
    },
    ClockMultiplier {
        id: u8,
        source: u8,
        controls: u8,
    },
    Input {
        id: u8,
        terminal_type: u16,
        clock: u8,
        channels: u8,
    },
    Output {
        id: u8,
        terminal_type: u16,
        source: u8,
        clock: u8,
    },
    Feature {
        id: u8,
        source: u8,
        controls: Vec<u32>,
    },
    Selector {
        id: u8,
        sources: Vec<u8>,
        controls: u8,
    },
}
impl Entity {
    pub fn id(&self) -> u8 {
        match self {
            Self::ClockSource { id, .. }
            | Self::ClockSelector { id, .. }
            | Self::ClockMultiplier { id, .. }
            | Self::Input { id, .. }
            | Self::Output { id, .. }
            | Self::Feature { id, .. }
            | Self::Selector { id, .. } => *id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graph {
    pub control_interface: u8,
    pub entities: Vec<Entity>,
}
impl Graph {
    pub fn entity(&self, id: u8) -> Result<&Entity, Error> {
        self.entities
            .iter()
            .find(|entity| entity.id() == id)
            .ok_or(Error::Descriptor("dangling UAC2 entity reference"))
    }
    pub fn terminal_clock(&self, terminal: u8, direction: Direction) -> Result<u8, Error> {
        match (self.entity(terminal)?, direction) {
            (
                Entity::Input {
                    terminal_type: USB_STREAMING,
                    clock,
                    ..
                },
                Direction::Playback,
            )
            | (
                Entity::Output {
                    terminal_type: USB_STREAMING,
                    clock,
                    ..
                },
                Direction::Capture,
            ) => Ok(*clock),
            _ => Err(Error::Descriptor(
                "AS terminal link has the wrong direction/type",
            )),
        }
    }
    fn validate(&self) -> Result<(), Error> {
        for entity in &self.entities {
            let refs: Vec<u8> = match entity {
                Entity::ClockSource { .. } => Vec::new(),
                Entity::ClockSelector { sources, .. } | Entity::Selector { sources, .. } => {
                    sources.clone()
                }
                Entity::ClockMultiplier { source, .. } | Entity::Feature { source, .. } => {
                    vec![*source]
                }
                Entity::Input { clock, .. } => vec![*clock],
                Entity::Output { source, clock, .. } => vec![*source, *clock],
            };
            for id in refs {
                self.entity(id)?;
            }
            self.acyclic(entity.id(), &mut [false; 256], &mut [false; 256])?;
        }
        Ok(())
    }
    fn acyclic(
        &self,
        id: u8,
        active: &mut [bool; 256],
        done: &mut [bool; 256],
    ) -> Result<(), Error> {
        if active[usize::from(id)] {
            return Err(Error::Descriptor("cyclic UAC2 graph"));
        }
        if done[usize::from(id)] {
            return Ok(());
        }
        active[usize::from(id)] = true;
        let sources: &[u8] = match self.entity(id)? {
            Entity::ClockSelector { sources, .. } | Entity::Selector { sources, .. } => sources,
            Entity::ClockMultiplier { source, .. }
            | Entity::Feature { source, .. }
            | Entity::Output { source, .. } => core::slice::from_ref(source),
            _ => &[],
        };
        for source in sources {
            self.acyclic(*source, active, done)?;
        }
        active[usize::from(id)] = false;
        done[usize::from(id)] = true;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sync {
    Synchronous,
    Adaptive,
    Explicit(Endpoint),
    Implicit {
        interface: u8,
        alternate: u8,
        endpoint: Endpoint,
        frame_bytes: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Format {
    pub interface: u8,
    pub alternate: u8,
    pub terminal: u8,
    pub clock: u8,
    pub direction: Direction,
    pub channels: u8,
    pub subslot: u8,
    pub bits: u8,
    pub channel_config: u32,
    pub data: Endpoint,
    pub sync: Sync,
    pub service_microframes: u32,
    pub max_bytes: usize,
    pub fill_max: bool,
}
impl Format {
    pub fn frame_bytes(&self) -> usize {
        usize::from(self.channels) * usize::from(self.subslot)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub graph: Graph,
    pub formats: Vec<Format>,
    pub speed: u8,
    /// Unsupported advertised alternates retained without hiding the reason.
    pub unsupported: Vec<(u8, u8, &'static str)>,
}

fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn controls(mut bits: u32, count: usize) -> Result<(), Error> {
    for _ in 0..count {
        if bits & 3 == 2 {
            return Err(Error::Descriptor("reserved UAC2 control access"));
        }
        bits >>= 2;
    }
    Ok(())
}

fn graph(control: &Interface) -> Result<Graph, Error> {
    let mut entities = Vec::new();
    let mut header = false;
    let mut total = 0usize;
    let mut advertised = 0usize;
    for d in &control.extra {
        if d.len() < 3 || d[1] != CS_INTERFACE {
            continue;
        }
        total += d.len();
        let short = || Error::Descriptor("short/invalid UAC2 AC descriptor");
        let entity = match d[2] {
            1 => {
                if header || d.len() != 9 || le16(d, 3) != 0x0200 {
                    return Err(short());
                }
                header = true;
                advertised = usize::from(le16(d, 6));
                None
            }
            2 => {
                if d.len() != 17 || d[8] == 0 {
                    return Err(short());
                }
                Some(Entity::Input {
                    id: d[3],
                    terminal_type: le16(d, 4),
                    clock: d[7],
                    channels: d[8],
                })
            }
            3 => {
                if d.len() != 12 {
                    return Err(short());
                }
                Some(Entity::Output {
                    id: d[3],
                    terminal_type: le16(d, 4),
                    source: d[7],
                    clock: d[8],
                })
            }
            5 | 11 => {
                if d.len() < 8 || d[4] == 0 || d.len() != usize::from(d[4]) + 7 {
                    return Err(short());
                }
                let n = usize::from(d[4]);
                controls(u32::from(d[5 + n]), 1)?;
                if d[2] == 5 {
                    Some(Entity::Selector {
                        id: d[3],
                        sources: d[5..5 + n].to_vec(),
                        controls: d[5 + n],
                    })
                } else {
                    Some(Entity::ClockSelector {
                        id: d[3],
                        sources: d[5..5 + n].to_vec(),
                        controls: d[5 + n],
                    })
                }
            }
            6 => {
                if d.len() < 10 || !(d.len() - 6).is_multiple_of(4) {
                    return Err(short());
                }
                let values: Vec<u32> = d[5..d.len() - 1]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| le32(b, 0))
                    .collect();
                for value in &values {
                    controls(*value, 16)?;
                }
                Some(Entity::Feature {
                    id: d[3],
                    source: d[4],
                    controls: values,
                })
            }
            10 => {
                if d.len() != 8 {
                    return Err(short());
                }
                controls(u32::from(d[5]), 2)?;
                Some(Entity::ClockSource {
                    id: d[3],
                    controls: d[5],
                })
            }
            12 => {
                if d.len() != 7 {
                    return Err(short());
                }
                controls(u32::from(d[5]), 2)?;
                Some(Entity::ClockMultiplier {
                    id: d[3],
                    source: d[4],
                    controls: d[5],
                })
            }
            _ => {
                return Err(Error::Unsupported(
                    "UAC2 mixer/effect/processing/extension entity",
                ));
            }
        };
        if let Some(entity) = entity {
            if entity.id() == 0 || entities.iter().any(|e: &Entity| e.id() == entity.id()) {
                return Err(Error::Descriptor("duplicate/zero UAC2 entity ID"));
            }
            entities.push(entity);
        }
    }
    if !header || total != advertised || entities.is_empty() {
        return Err(Error::Descriptor("UAC2 AC header total length"));
    }
    let graph = Graph {
        control_interface: control.number,
        entities,
    };
    graph.validate()?;
    Ok(graph)
}

fn scope(
    configuration: &[u8],
    control: u8,
    all: &[Interface],
) -> Result<core::ops::Range<u16>, Error> {
    if configuration.len() < 9
        || configuration[0] != 9
        || configuration[1] != 2
        || usize::from(le16(configuration, 2)) != configuration.len()
    {
        return Err(Error::Descriptor("incomplete USB configuration"));
    }
    let mut at = 0;
    let mut settings = Vec::new();
    let mut numbers = Vec::new();
    let mut endpoint_count = 0usize;
    let mut expected = None;
    let mut addresses = Vec::new();
    let mut association = None;
    while at < configuration.len() {
        if configuration.len() - at < 2 {
            return Err(Error::Descriptor("truncated USB descriptor"));
        }
        let n = usize::from(configuration[at]);
        if n < 2 || at + n > configuration.len() {
            return Err(Error::Descriptor("USB descriptor length"));
        }
        let d = &configuration[at..at + n];
        match d[1] {
            4 => {
                if n < 9
                    || expected.is_some_and(|count| count != endpoint_count)
                    || settings.contains(&(d[2], d[3]))
                {
                    return Err(Error::Descriptor(
                        "invalid/duplicate audio interface extent",
                    ));
                }
                settings.push((d[2], d[3]));
                if !numbers.contains(&d[2]) {
                    numbers.push(d[2]);
                }
                expected = Some(usize::from(d[4]));
                endpoint_count = 0;
                addresses.clear();
            }
            5 => {
                if n < 7 || expected.is_none() || addresses.contains(&d[2]) {
                    return Err(Error::Descriptor("invalid audio endpoint extent/count"));
                }
                addresses.push(d[2]);
                endpoint_count += 1;
            }
            _ => {}
        }
        if d[1] == 11 {
            if n != 8 || d[3] == 0 {
                return Err(Error::Descriptor("invalid interface association"));
            }
            let start = u16::from(d[2]);
            let end = start + u16::from(d[3]);
            if start <= u16::from(control) && u16::from(control) < end {
                if association.is_some()
                    || d[4] != CLASS
                    || d[6] != UAC2
                    || d[2] != control
                    || end > 256
                {
                    return Err(Error::Descriptor(
                        "ambiguous/non-UAC2 interface association",
                    ));
                }
                association = Some(start..end);
            }
        }
        at += n;
    }
    if expected.is_some_and(|count| count != endpoint_count)
        || numbers.len() != usize::from(configuration[4])
        || numbers
            .iter()
            .any(|number| !settings.contains(&(*number, 0)))
    {
        return Err(Error::Descriptor("audio interface/endpoint count mismatch"));
    }
    association
        .or_else(|| {
            (all.iter()
                .filter(|i| i.alternate == 0 && i.class == CLASS && i.subclass == CONTROL_SUBCLASS)
                .count()
                == 1)
                .then_some(0..256)
        })
        .ok_or(Error::Descriptor(
            "multiple UAC2 functions require interface associations",
        ))
}

fn format(
    interface: &Interface,
    graph: &Graph,
    speed: u8,
    all: &[Interface],
) -> Result<Format, Error> {
    let general: Vec<_> = interface
        .extra
        .iter()
        .filter(|d| d.len() >= 3 && d[1] == CS_INTERFACE && d[2] == 1)
        .collect();
    let ty: Vec<_> = interface
        .extra
        .iter()
        .filter(|d| d.len() >= 3 && d[1] == CS_INTERFACE && d[2] == 2)
        .collect();
    if general.len() != 1 || ty.len() != 1 || general[0].len() != 16 || ty[0].len() != 6 {
        return Err(Error::Descriptor("UAC2 AS/format descriptor"));
    }
    let g = general[0];
    let f = ty[0];
    if g[5] != 1 || f[3] != 1 || le32(g, 6) & 1 == 0 {
        return Err(Error::Unsupported("UAC2 non-Type-I signed PCM"));
    }
    if !(1..=32).contains(&g[10]) || !(1..=4).contains(&f[4]) || f[5] == 0 || f[5] > f[4] * 8 {
        return Err(Error::Format);
    }
    let data: Vec<_> = interface
        .endpoints
        .iter()
        .filter(|ep| ep.kind() == 1 && ep.attributes & 0x30 != 0x10)
        .copied()
        .collect();
    let feedback: Vec<_> = interface
        .endpoints
        .iter()
        .filter(|ep| ep.kind() == 1 && ep.attributes & 0x30 == 0x10)
        .copied()
        .collect();
    if data.len() != 1
        || feedback.len() > 1
        || interface.endpoints.len() != data.len() + feedback.len()
    {
        return Err(Error::Descriptor("UAC2 data/feedback endpoint layout"));
    }
    let data = data[0];
    let direction = if data.is_in() {
        Direction::Capture
    } else {
        Direction::Playback
    };
    let max_bytes = capacity(data, speed)?;
    let interval = service_interval(data, speed)?;
    let clock = graph.terminal_clock(g[3], direction)?;
    let sync = match ((data.attributes >> 2) & 3, direction) {
        (3, _) => Sync::Synchronous,
        (2, _) => Sync::Adaptive,
        (1, Direction::Capture) => Sync::Synchronous,
        (1, Direction::Playback) => {
            if let Some(fb) = feedback.first().copied() {
                if !fb.is_in() || capacity(fb, speed)? < if speed == 3 { 4 } else { 3 } {
                    return Err(Error::Descriptor("UAC2 feedback endpoint"));
                }
                service_interval(fb, speed)?;
                Sync::Explicit(fb)
            } else {
                // Linux's generic UAC2 implicit-feedback association is the
                // immediately following AS interface at the same alternate,
                // explicitly marked as implicit-feedback data (usage 2).
                let source = all
                    .iter()
                    .find(|i| {
                        u16::from(i.number) == u16::from(interface.number) + 1
                            && i.alternate == interface.alternate
                            && i.class == CLASS
                            && i.subclass == STREAMING_SUBCLASS
                            && i.protocol == UAC2
                    })
                    .ok_or(Error::Unsupported(
                        "asynchronous playback has no feedback source",
                    ))?;
                let endpoint = source
                    .endpoints
                    .first()
                    .copied()
                    .filter(|e| e.kind() == 1 && e.is_in() && e.attributes & 0x30 == 0x20)
                    .ok_or(Error::Unsupported(
                        "adjacent AS interface is not implicit feedback",
                    ))?;
                let input = format(source, graph, speed, all)?;
                if input.service_microframes != interval {
                    return Err(Error::Unsupported(
                        "implicit feedback service interval differs from playback",
                    ));
                }
                Sync::Implicit {
                    interface: source.number,
                    alternate: source.alternate,
                    endpoint,
                    frame_bytes: input.frame_bytes(),
                }
            }
        }
        _ => return Err(Error::Unsupported("UAC2 endpoint synchronization type")),
    };
    if !matches!(sync, Sync::Explicit(_)) && !feedback.is_empty() {
        return Err(Error::Descriptor("unexpected explicit feedback endpoint"));
    }
    let endpoint: Vec<_> = interface
        .extra
        .iter()
        .filter(|d| d.len() >= 3 && d[1] == CS_ENDPOINT && d[2] == 1)
        .collect();
    if endpoint.len() != 1 || endpoint[0].len() != 8 {
        return Err(Error::Descriptor("UAC2 class-specific data endpoint"));
    }
    let fill_max = endpoint[0][3] & 0x80 != 0;
    Ok(Format {
        interface: interface.number,
        alternate: interface.alternate,
        terminal: g[3],
        clock,
        direction,
        channels: g[10],
        subslot: f[4],
        bits: f[5],
        channel_config: le32(g, 11),
        data,
        sync,
        service_microframes: interval,
        max_bytes,
        fill_max,
    })
}

pub(super) fn capacity(endpoint: Endpoint, speed: u8) -> Result<usize, Error> {
    let packet = usize::from(endpoint.max_packet & 0x7ff);
    let extra = (endpoint.max_packet >> 11) & 3;
    if endpoint.kind() != 1
        || endpoint.attributes & 0xc0 != 0
        || endpoint.attributes & 0x30 == 0x30
        || endpoint.address & 0x70 != 0
        || endpoint.address & 15 == 0
        || packet == 0
        || endpoint.companion.is_some()
        || endpoint.max_packet & 0xe000 != 0
    {
        return Err(Error::Descriptor("invalid USB2 isochronous endpoint"));
    }
    match speed {
        1 if packet <= 1023 && extra == 0 => Ok(packet),
        3 if packet <= 1024 && extra <= 2 => Ok(packet * (usize::from(extra) + 1)),
        _ => Err(Error::Unsupported(
            "USB audio requires full/high-speed isochronous transport",
        )),
    }
}
pub(super) fn service_interval(endpoint: Endpoint, speed: u8) -> Result<u32, Error> {
    if !(1..=16).contains(&endpoint.interval) {
        return Err(Error::Descriptor("invalid isochronous bInterval"));
    }
    match speed {
        1 => Ok(8u32 << u32::from(endpoint.interval - 1)),
        3 => Ok(1u32 << u32::from(endpoint.interval - 1)),
        _ => Err(Error::Unsupported("USB audio speed")),
    }
}

impl Binding {
    pub fn parse(
        control: &Interface,
        all: &[Interface],
        configuration: &[u8],
        speed: u8,
    ) -> Result<Self, Error> {
        if control.class != CLASS
            || control.subclass != CONTROL_SUBCLASS
            || control.protocol != UAC2
            || control.alternate != 0
        {
            return Err(Error::Unsupported(
                "standard UAC2 control interface required",
            ));
        }
        let scope = scope(configuration, control.number, all)?;
        let graph = graph(control)?;
        let mut formats = Vec::new();
        let mut unsupported = Vec::new();
        for interface in all.iter().filter(|i| {
            scope.contains(&u16::from(i.number))
                && i.class == CLASS
                && i.subclass == STREAMING_SUBCLASS
                && i.protocol == UAC2
                && i.alternate != 0
        }) {
            if !all
                .iter()
                .any(|i| i.number == interface.number && i.alternate == 0 && i.endpoints.is_empty())
            {
                return Err(Error::Descriptor(
                    "audio streaming interface has no zero-bandwidth alternate",
                ));
            }
            match format(interface, &graph, speed, all) {
                Ok(format) => formats.push(format),
                Err(Error::Unsupported(reason)) => {
                    unsupported.push((interface.number, interface.alternate, reason))
                }
                Err(error) => return Err(error),
            }
        }
        if formats.is_empty() {
            return Err(Error::Unsupported("no usable UAC2 PCM alternate"));
        }
        for (n, a) in formats.iter().enumerate() {
            if formats[n + 1..]
                .iter()
                .any(|b| a.interface == b.interface && a.alternate == b.alternate)
            {
                return Err(Error::Descriptor("duplicate audio alternate"));
            }
        }
        Ok(Self {
            graph,
            formats,
            speed,
            unsupported,
        })
    }
    pub(crate) fn settings(&self) -> Vec<(u8, u8)> {
        let mut settings = vec![(self.graph.control_interface, 0)];
        for f in &self.formats {
            if !settings.iter().any(|(i, _)| *i == f.interface) {
                settings.push((f.interface, 0));
            }
        }
        settings
    }
}
