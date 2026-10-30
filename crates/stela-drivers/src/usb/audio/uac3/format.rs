// SPDX-License-Identifier: GPL-2.0-or-later
//! UAC3 AS descriptors and explicit/generic implicit feedback on real clusters.
use super::super::descriptors::{capacity, service_interval};
use super::super::{Control, Error, Format, Sync};
use super::{Reader, graph::ParsedGraph};
use crate::{audio::Direction, bytes::le16, usb::descriptor::Interface};
use alloc::vec::Vec;

pub(super) fn parse<C: Control>(
    interface: &Interface,
    parsed: &ParsedGraph,
    reader: &mut Reader<'_, C>,
    speed: u8,
    all: &[Interface],
) -> Result<Format, Error> {
    let general: Vec<_> = interface
        .extra
        .iter()
        .filter(|d| d.len() >= 3 && d[1] == 0x24 && d[2] == 1)
        .collect();
    if general.len() != 1 || general[0].len() != 23 {
        return Err(Error::Descriptor("UAC3 AS descriptor extent"));
    }
    let g = general[0];
    if g[10] & 1 == 0 {
        return Err(Error::Unsupported("UAC3 non-Type-I signed PCM"));
    }
    if le16(g, 20) != 0 || g[22] != 0 {
        return Err(Error::Unsupported(
            "UAC3 auxiliary/embedded control protocols",
        ));
    }
    let cluster = reader.get(le16(g, 8))?;
    if !(1..=4).contains(&g[18]) || g[19] == 0 || g[19] > g[18] * 8 {
        return Err(Error::Format);
    }
    let data: Vec<_> = interface
        .endpoints
        .iter()
        .copied()
        .filter(|e| e.kind() == 1 && e.attributes & 0x30 != 0x10)
        .collect();
    let feedback: Vec<_> = interface
        .endpoints
        .iter()
        .copied()
        .filter(|e| e.kind() == 1 && e.attributes & 0x30 == 0x10)
        .collect();
    if data.len() != 1
        || feedback.len() > 1
        || data.len() + feedback.len() != interface.endpoints.len()
    {
        return Err(Error::Descriptor("UAC3 data/feedback endpoint extent"));
    }
    let data = data[0];
    if data.attributes & 0x30 == 0x20 && !data.is_in() {
        return Err(Error::Descriptor(
            "UAC3 implicit feedback must be an input endpoint",
        ));
    }
    let direction = if data.is_in() {
        Direction::Capture
    } else {
        Direction::Playback
    };
    let maximum = capacity(data, speed)?;
    let interval = service_interval(data, speed)?;
    let clock = parsed.graph.terminal_clock(g[3], direction)?;
    let signal = parsed.signal_cluster(g[3], reader)?;
    if cluster.channels != signal.channels || cluster.information != signal.information {
        return Err(Error::Descriptor(
            "UAC3 AS/terminal channel cluster mismatch",
        ));
    }
    let sync = match ((data.attributes >> 2) & 3, direction) {
        (3, _) => Sync::Synchronous,
        (2, _) => Sync::Adaptive,
        (1, Direction::Capture) => Sync::Synchronous,
        (1, Direction::Playback) => {
            if let Some(fb) = feedback.first().copied() {
                if !fb.is_in() || capacity(fb, speed)? < if speed == 3 { 4 } else { 3 } {
                    return Err(Error::Descriptor("UAC3 explicit feedback endpoint"));
                }
                service_interval(fb, speed)?;
                Sync::Explicit(fb)
            } else {
                let source = all
                    .iter()
                    .find(|i| {
                        u16::from(i.number) == u16::from(interface.number) + 1
                            && i.alternate == interface.alternate
                    })
                    .ok_or(Error::Unsupported(
                        "UAC3 asynchronous playback lacks feedback source",
                    ))?;
                let source_format = parse(source, parsed, reader, speed, all)?;
                if source_format.direction != Direction::Capture
                    || source_format.data.attributes & 0x30 != 0x20
                    || source_format.service_microframes != interval
                {
                    return Err(Error::Unsupported(
                        "UAC3 adjacent alternate is not matching implicit feedback",
                    ));
                }
                Sync::Implicit {
                    interface: source.number,
                    alternate: source.alternate,
                    endpoint: source_format.data,
                    frame_bytes: source_format.frame_bytes(),
                }
            }
        }
        _ => return Err(Error::Unsupported("UAC3 endpoint synchronization type")),
    };
    if !matches!(sync, Sync::Explicit(_)) && !feedback.is_empty() {
        return Err(Error::Descriptor("unexpected UAC3 feedback endpoint"));
    }
    let endpoint: Vec<_> = interface
        .extra
        .iter()
        .filter(|d| d.len() >= 3 && d[1] == 0x25 && d[2] == 1)
        .collect();
    if endpoint.len() != 1 || endpoint[0].len() != 10 {
        return Err(Error::Descriptor("UAC3 class-specific endpoint extent"));
    }
    let power = parsed
        .power
        .iter()
        .find(|(_, entities)| entities.contains(&g[3]))
        .map(|(domain, _)| *domain);
    if !parsed.power.is_empty() && power.is_none() {
        return Err(Error::Descriptor(
            "UAC3 stream terminal lacks a power domain",
        ));
    }
    Ok(Format {
        cluster_id: Some(cluster.id),
        power_domain: power,
        endpoint_rates: None,
        interface: interface.number,
        alternate: interface.alternate,
        terminal: g[3],
        clock,
        direction,
        channels: cluster.channels,
        subslot: g[18],
        bits: g[19],
        channel_config: cluster.channel_config(),
        data,
        sync,
        service_microframes: interval,
        max_bytes: maximum,
        fill_max: false,
        pitch: None,
    })
}
