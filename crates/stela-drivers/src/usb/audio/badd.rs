// SPDX-License-Identifier: GPL-2.0-or-later
//! UAC3 Basic Audio Device Definition: profile-declared topology, not synthesized
//! device observations. BADD intentionally has no class-specific descriptors.
//! Reference Linux stream.c/mixer.c and audio-v3.h, Copyright (c) 2017 Ruslan Bilovol.
use super::descriptors::{capacity, scope, service_interval};
use super::{
    Binding, CLASS, CONTROL_SUBCLASS, Entity, Error, Format, Graph, PowerDomain,
    STREAMING_SUBCLASS, Sync, UAC3,
};
use crate::{
    audio::Direction,
    usb::xhci::{INTERFACE_ASSOCIATION_DESCRIPTOR, Interface},
};
use alloc::vec::Vec;

pub(super) const RATE: u32 = 48_000;
const CLOCK: u8 = 9;
/// The standardized BADD function subclass carried by the owning IAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BasicProfile {
    GenericIo = 0x20,
    Headphone = 0x21,
    Speaker = 0x22,
    Microphone = 0x23,
    Headset = 0x24,
    HeadsetAdapter = 0x25,
    Speakerphone = 0x26,
}
impl BasicProfile {
    fn parse(value: u8) -> Result<Self, Error> {
        match value {
            0x20 => Ok(Self::GenericIo),
            0x21 => Ok(Self::Headphone),
            0x22 => Ok(Self::Speaker),
            0x23 => Ok(Self::Microphone),
            0x24 => Ok(Self::Headset),
            0x25 => Ok(Self::HeadsetAdapter),
            0x26 => Ok(Self::Speakerphone),
            _ => Err(Error::Unsupported("full UAC3/high-capability function")),
        }
    }
}
use BasicProfile::*;

fn class_specific(i: &Interface) -> bool {
    i.extra
        .iter()
        .any(|d| d.len() >= 2 && matches!(d[1], 0x24 | 0x25))
}
fn format(i: &Interface, speed: u8) -> Result<Format, Error> {
    if class_specific(i) {
        return Err(Error::Descriptor(
            "BADD must not contain class-specific descriptors",
        ));
    }
    let data: Vec<_> = i
        .endpoints
        .iter()
        .copied()
        .filter(|e| e.attributes & 0x30 == 0)
        .collect();
    let feedback: Vec<_> = i
        .endpoints
        .iter()
        .copied()
        .filter(|e| e.attributes & 0x30 == 0x10)
        .collect();
    if data.len() != 1 || feedback.len() > 1 || data.len() + feedback.len() != i.endpoints.len() {
        return Err(Error::Descriptor("BADD data/feedback endpoint extent"));
    }
    let data = data[0];
    let max_bytes = capacity(data, speed)?;
    let interval = service_interval(data, speed)?;
    if interval != 8 {
        return Err(Error::Descriptor(
            "BADD requires a one-millisecond data interval",
        ));
    }
    let (channels, subslot, asynchronous) = match data.max_packet {
        0x0060 => (1, 2, false),
        0x0062 => (1, 2, true),
        0x0090 => (1, 3, false),
        0x0093 => (1, 3, true),
        0x00c0 => (2, 2, false),
        0x00c4 => (2, 2, true),
        0x0120 => (2, 3, false),
        0x0126 => (2, 3, true),
        _ => return Err(Error::Unsupported("nonstandard BADD packet size")),
    };
    let synchronization = (data.attributes >> 2) & 3;
    if synchronization != if asynchronous { 1 } else { 3 } {
        return Err(Error::Descriptor(
            "BADD packet capacity/synchronization mismatch",
        ));
    }
    let direction = if data.is_in() {
        Direction::Capture
    } else {
        Direction::Playback
    };
    let sync = if asynchronous && direction == Direction::Playback {
        let Some(feedback) = feedback.first().copied() else {
            return Err(Error::Unsupported(
                "BADD asynchronous playback requires explicit feedback",
            ));
        };
        let bytes = if speed == 3 { 4 } else { 3 };
        if !feedback.is_in()
            || feedback.attributes & 0x0c != 0
            || capacity(feedback, speed)? != bytes
        {
            return Err(Error::Descriptor("BADD explicit feedback endpoint"));
        }
        service_interval(feedback, speed)?;
        Sync::Explicit(feedback)
    } else {
        if !feedback.is_empty() {
            return Err(Error::Descriptor("unexpected BADD feedback endpoint"));
        }
        Sync::Synchronous
    };
    Ok(Format {
        cluster_id: None,
        power_domain: Some(PowerDomain {
            id: if direction == Direction::Playback {
                10
            } else {
                11
            },
            recovery_d1: 0x0258,
            recovery_d2: 0x1770,
        }),
        endpoint_rates: None,
        interface: i.number,
        alternate: i.alternate,
        terminal: if direction == Direction::Playback {
            1
        } else {
            6
        },
        clock: CLOCK,
        direction,
        channels,
        subslot,
        bits: subslot * 8,
        channel_config: channel_mask(channels),
        data,
        sync,
        service_microframes: interval,
        max_bytes,
        fill_max: false,
    })
}
fn channel_mask(channels: u8) -> u32 {
    if channels == 1 { 4 } else { 3 }
}
fn features(id: u8, source: u8, channels: u8) -> Entity {
    // BADD master mute; per-channel volume. Master volume/per-channel mute
    // are not implied by the profile, so do not send requests for them.
    let mut controls = vec![3];
    controls.extend(core::iter::repeat_n(12, usize::from(channels)));
    Entity::Feature {
        id,
        source,
        controls,
    }
}
fn graph(profile: BasicProfile, control: u8, playback: u8, capture: u8) -> Result<Graph, Error> {
    let valid = match profile {
        GenericIo => playback != 0 || capture != 0,
        Headphone => playback == 2 && capture == 0,
        Speaker => playback != 0 && capture == 0,
        Microphone => playback == 0 && capture != 0,
        Headset => playback != 0 && capture == 1,
        HeadsetAdapter => playback == 2 && capture == 1,
        Speakerphone => playback == 1 && capture == 1,
    };
    if !valid {
        return Err(Error::Descriptor("BADD profile direction/channel mismatch"));
    }
    let mut entities = vec![Entity::ClockSource {
        id: CLOCK,
        attributes: 0,
        controls: 0,
    }];
    if playback != 0 {
        entities.push(Entity::Input {
            id: 1,
            terminal_type: 0x0101,
            clock: CLOCK,
            channels: playback,
            channel_config: channel_mask(playback),
        });
        entities.push(features(2, 1, playback));
        let sidetone = matches!(profile, Headset | HeadsetAdapter);
        if sidetone {
            entities.push(features(7, 4, 1));
            entities.push(Entity::Mixer {
                id: 8,
                sources: vec![2, 7],
                channels: playback,
                channel_config: channel_mask(playback),
                matrix: vec![0; (usize::from(playback + 1) * usize::from(playback)).div_ceil(8)],
                unit_controls: Some(0),
            });
        }
        let terminal_type = match profile {
            Headphone => 0x0302,
            Headset | HeadsetAdapter => 0x0402,
            Speakerphone => 0x0403,
            GenericIo => 0x0300,
            _ => 0x0301,
        };
        entities.push(Entity::Output {
            id: 3,
            terminal_type,
            source: if sidetone { 8 } else { 2 },
            clock: CLOCK,
        });
    }
    if capture != 0 {
        let terminal_type = match profile {
            Headset | HeadsetAdapter => 0x0402,
            Speakerphone => 0x0403,
            GenericIo => 0x0200,
            _ => 0x0201,
        };
        entities.push(Entity::Input {
            id: 4,
            terminal_type,
            clock: CLOCK,
            channels: capture,
            channel_config: channel_mask(capture),
        });
        entities.push(features(5, 4, capture));
        entities.push(Entity::Output {
            id: 6,
            terminal_type: 0x0101,
            source: 5,
            clock: CLOCK,
        });
    }
    let graph = Graph {
        protocol: UAC3,
        control_interface: control,
        entities,
    };
    graph.validate()?;
    Ok(graph)
}

pub(super) fn binding(
    control: &Interface,
    all: &[Interface],
    configuration: &[u8],
    speed: u8,
) -> Result<Binding, Error> {
    let range = scope(configuration, control.number, all, UAC3)?;
    let mut at = 0;
    let mut profile = None;
    while at < configuration.len() {
        let d = &configuration[at..at + usize::from(configuration[at])];
        if d[1] == INTERFACE_ASSOCIATION_DESCRIPTOR && d[2] == control.number {
            profile = Some(d[5]);
        }
        at += d.len();
    }
    let profile = BasicProfile::parse(
        profile.ok_or(Error::Descriptor("BADD requires an interface association"))?,
    )?;
    if !control.endpoints.is_empty()
        || class_specific(control)
        || all
            .iter()
            .any(|i| i.number == control.number && i.alternate != 0)
    {
        return Err(Error::Descriptor("BADD control interface layout"));
    }
    let mut formats = Vec::new();
    let mut unsupported = Vec::new();
    let mut playback = 0;
    let mut capture = 0;
    for number in range.clone().filter(|n| *n != u16::from(control.number)) {
        let settings: Vec<_> = all
            .iter()
            .filter(|i| u16::from(i.number) == number)
            .collect();
        if settings.is_empty()
            || settings
                .iter()
                .any(|i| (i.class, i.subclass, i.protocol) != (CLASS, STREAMING_SUBCLASS, UAC3))
        {
            return Err(Error::Descriptor(
                "BADD association includes a foreign/missing interface",
            ));
        }
        if !settings
            .iter()
            .any(|i| i.alternate == 0 && i.endpoints.is_empty() && !class_specific(i))
        {
            return Err(Error::Descriptor(
                "BADD requires a zero-bandwidth alternate",
            ));
        }
        let primary = settings
            .iter()
            .find(|i| i.alternate == 1)
            .ok_or(Error::Descriptor("BADD requires alternate one"))?;
        let primary = format(primary, speed)?;
        let channels = match primary.direction {
            Direction::Playback => &mut playback,
            Direction::Capture => &mut capture,
        };
        if *channels != 0 {
            return Err(Error::Descriptor(
                "multiple BADD interfaces for one direction",
            ));
        }
        *channels = primary.channels;
        for i in settings.iter().filter(|i| i.alternate != 0) {
            match format(i, speed) {
                Ok(f) => {
                    if f.direction != primary.direction || f.channels > primary.channels {
                        return Err(Error::Descriptor(
                            "BADD alternate changes primary direction/channel limit",
                        ));
                    }
                    formats.push(f);
                }
                Err(Error::Unsupported(reason)) => {
                    unsupported.push((i.number, i.alternate, reason))
                }
                Err(error) => return Err(error),
            }
        }
    }
    // Shared scope validates descriptor/IAD extent. Still refuse foreign DCIs:
    // audio cannot coordinate alternate changes with another function owner.
    for f in &formats {
        let endpoints = f.endpoints();
        if all
            .iter()
            .filter(|i| !range.contains(&u16::from(i.number)) || i.subclass == CONTROL_SUBCLASS)
            .any(|i| {
                i.endpoints
                    .iter()
                    .any(|e| endpoints.iter().any(|ours| ours.dci() == e.dci()))
            })
        {
            return Err(Error::Descriptor(
                "BADD endpoint aliases a foreign interface",
            ));
        }
    }
    Ok(Binding {
        clusters: Vec::new(),
        entity_clusters: Vec::new(),
        basic_profile: Some(profile),
        graph: graph(profile, control.number, playback, capture)?,
        formats,
        speed,
        unsupported,
    })
}
