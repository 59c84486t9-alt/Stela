// SPDX-License-Identifier: GPL-2.0-or-later
//! UAC3 AC entity layouts, observed clusters, signal references and power ownership.
use super::super::{Control, Entity, Error, Graph, PowerDomain, UAC3};
use super::{Cluster, Reader};
use crate::{
    bytes::{le16, le32},
    usb::descriptor::Interface,
};
use alloc::vec::Vec;

pub(super) struct ParsedGraph {
    pub(super) graph: Graph,
    pub(super) clusters: Vec<(u8, u16)>,
    pub(super) power: Vec<(PowerDomain, Vec<u8>)>,
}
fn access32(bits: u32, count: u8) -> Result<u8, Error> {
    for selector in 1..=count {
        super::super::control::access(bits, selector)?;
    }
    if bits >> (count * 2) != 0 {
        return Err(Error::Unsupported("additional UAC3 entity controls"));
    }
    Ok(bits as u8)
}
pub(super) fn parse<C: Control>(
    control: &Interface,
    reader: &mut Reader<'_, C>,
) -> Result<ParsedGraph, Error> {
    let mut entities = Vec::new();
    let mut clusters = Vec::new();
    let mut power: Vec<(PowerDomain, Vec<u8>)> = Vec::new();
    let mut ids = [false; 256];
    let mut header = false;
    let mut total = 0;
    let mut advertised = 0;
    for d in control
        .extra
        .iter()
        .filter(|d| d.len() >= 2 && d[1] == 0x24)
    {
        if d.len() < 3 {
            return Err(Error::Descriptor("short UAC3 AC descriptor"));
        }
        total += d.len();
        let short = || Error::Descriptor("invalid UAC3 AC descriptor extent");
        if !header && d[2] != 1 {
            return Err(Error::Descriptor("UAC3 AC header must precede entities"));
        }
        if d[2] == 1 {
            if header || d.len() != 10 {
                return Err(short());
            }
            header = true;
            advertised = usize::from(le16(d, 4));
            continue;
        }
        if d.len() < 4 || d[3] == 0 || ids[usize::from(d[3])] {
            return Err(Error::Descriptor("duplicate/zero UAC3 entity ID"));
        }
        ids[usize::from(d[3])] = true;
        let entity = match d[2] {
            2 => {
                if d.len() != 20 {
                    return Err(short());
                }
                let id = le16(d, 12);
                let cluster = reader.get(id)?;
                clusters.push((d[3], id));
                Entity::Input {
                    id: d[3],
                    terminal_type: le16(d, 4),
                    clock: d[7],
                    channels: cluster.channels,
                    channel_config: cluster.channel_config(),
                }
            }
            3 => {
                if d.len() != 19 {
                    return Err(short());
                }
                Entity::Output {
                    id: d[3],
                    terminal_type: le16(d, 4),
                    source: d[7],
                    clock: d[8],
                }
            }
            5 => {
                if d.len() < 5 || d[4] == 0 {
                    return Err(short());
                }
                let n = usize::from(d[4]);
                if d.len() < 13 + n {
                    return Err(short());
                }
                let cluster_id = le16(d, 5 + n);
                let cluster = reader.get(cluster_id)?;
                clusters.push((d[3], cluster_id));
                let controls = le32(d, d.len() - 6);
                for selector in 1..=16 {
                    super::super::control::access(controls, selector)?;
                }
                Entity::Mixer {
                    id: d[3],
                    sources: d[5..5 + n].to_vec(),
                    channels: cluster.channels,
                    channel_config: cluster.channel_config(),
                    matrix: d[7 + n..d.len() - 6].to_vec(),
                    unit_controls: Some(controls),
                }
            }
            6 | 12 => {
                if d.len() < 5 || d[4] == 0 {
                    return Err(short());
                }
                let n = usize::from(d[4]);
                if d.len() != 11 + n {
                    return Err(short());
                }
                let controls = access32(le32(d, 5 + n), 1)?;
                if d[2] == 6 {
                    Entity::Selector {
                        id: d[3],
                        sources: d[5..5 + n].to_vec(),
                        controls,
                    }
                } else {
                    Entity::ClockSelector {
                        id: d[3],
                        sources: d[5..5 + n].to_vec(),
                        controls,
                    }
                }
            }
            7 => {
                if d.len() < 11 || !(d.len() - 7).is_multiple_of(4) {
                    return Err(short());
                }
                let controls: Vec<_> = d[5..d.len() - 2]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| le32(b, 0))
                    .collect();
                for bits in &controls {
                    for selector in 1..=16 {
                        super::super::control::access(*bits, selector)?;
                    }
                }
                Entity::Feature {
                    id: d[3],
                    source: d[4],
                    controls,
                }
            }
            11 => {
                if d.len() != 12 {
                    return Err(short());
                }
                Entity::ClockSource {
                    id: d[3],
                    attributes: d[4],
                    controls: access32(le32(d, 5), 2)?,
                }
            }
            13 => {
                if d.len() != 11 {
                    return Err(short());
                }
                Entity::ClockMultiplier {
                    id: d[3],
                    source: d[4],
                    controls: access32(le32(d, 5), 2)?,
                }
            }
            16 => {
                if d.len() < 11 || d[8] == 0 || d.len() != 11 + usize::from(d[8]) {
                    return Err(short());
                }
                let members = d[9..d.len() - 2].to_vec();
                if members.iter().enumerate().any(|(n, id)| {
                    *id == 0
                        || members[..n].contains(id)
                        || power.iter().any(|(_, m)| m.contains(id))
                }) {
                    return Err(Error::Descriptor(
                        "overlapping/duplicate UAC3 power-domain entities",
                    ));
                }
                power.push((
                    PowerDomain {
                        id: d[3],
                        recovery_d1: le16(d, 4),
                        recovery_d2: le16(d, 6),
                    },
                    members,
                ));
                continue;
            }
            _ => {
                return Err(Error::Unsupported(
                    "UAC3 extended-terminal/effect/processing/extension/converter entity",
                ));
            }
        };
        entities.push(entity);
    }
    if !header || total != advertised || entities.is_empty() {
        return Err(Error::Descriptor("UAC3 AC total length/header"));
    }
    let graph = Graph {
        protocol: UAC3,
        control_interface: control.number,
        entities,
    };
    graph.validate()?;
    for (_, members) in &power {
        for id in members {
            graph.entity(*id)?;
        }
    }
    let parsed = ParsedGraph {
        graph,
        clusters,
        power,
    };
    for entity in &parsed.graph.entities {
        if let Entity::Feature {
            source, controls, ..
        } = entity
        {
            let source = parsed.signal_cluster(*source, reader)?;
            if controls.len() != usize::from(source.channels) + 1 {
                return Err(Error::Descriptor("UAC3 feature channel-control extent"));
            }
        }
        if matches!(entity, Entity::Selector { .. }) {
            parsed.signal_cluster(entity.id(), reader)?;
        }
    }
    Ok(parsed)
}
impl ParsedGraph {
    pub(super) fn signal_cluster<C: Control>(
        &self,
        id: u8,
        reader: &mut Reader<'_, C>,
    ) -> Result<Cluster, Error> {
        if let Some((_, cluster)) = self.clusters.iter().find(|(entity, _)| *entity == id) {
            return reader.get(*cluster);
        }
        match self.graph.entity(id)? {
            Entity::Feature { source, .. } | Entity::Output { source, .. } => {
                self.signal_cluster(*source, reader)
            }
            Entity::Selector { sources, .. } => {
                let mut common: Option<Cluster> = None;
                for source in sources {
                    let c = self.signal_cluster(*source, reader)?;
                    if common.as_ref().is_some_and(|other| {
                        other.channels != c.channels || other.information != c.information
                    }) {
                        return Err(Error::Unsupported(
                            "UAC3 selector changes ordered channel cluster",
                        ));
                    }
                    common = Some(c);
                }
                common.ok_or(Error::Descriptor("empty UAC3 signal selector"))
            }
            _ => Err(Error::Descriptor("UAC3 signal has no cluster")),
        }
    }
}
