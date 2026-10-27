// SPDX-License-Identifier: GPL-2.0-or-later
//! Standard UAC1/UAC2 mixer clusters and programmable signed-volume crosspoints.
//! Reference: Linux mixer.c check_matrix_bitmap/parse_audio_mixer_unit and the
//! standard descriptor helpers; Copyright (c) 2002 Takashi Iwai.
use super::{Control, Entity, Error, Graph, UAC1, UAC2};
use crate::bytes::{le16, le32};

pub(super) fn parse(d: &[u8], protocol: u8) -> Result<Entity, Error> {
    if d.len() < 5 || d[2] != 4 || d[4] == 0 {
        return Err(Error::Descriptor("invalid USB mixer unit"));
    }
    let n = usize::from(d[4]);
    let (matrix_start, suffix) = match protocol {
        UAC1 => (9 + n, 1),
        UAC2 => (11 + n, 2),
        _ => return Err(Error::Unsupported("USB mixer protocol")),
    };
    if d.len() < matrix_start + suffix || !(1..=32).contains(&d[5 + n]) {
        return Err(Error::Descriptor("short USB mixer unit/cluster"));
    }
    let channel_config = if protocol == UAC1 {
        u32::from(le16(d, 6 + n))
    } else {
        le32(d, 6 + n)
    };
    let unit_controls = if protocol == UAC2 {
        let controls = d[d.len() - 2];
        for selector in 1..=4 {
            super::control::access(u32::from(controls), selector)?;
        }
        Some(u32::from(controls))
    } else {
        None
    };
    Ok(Entity::Mixer {
        id: d[3],
        sources: d[5..5 + n].to_vec(),
        channels: d[5 + n],
        channel_config,
        matrix: d[matrix_start..d.len() - suffix].to_vec(),
        unit_controls,
    })
}
impl Graph {
    /// Cluster metadata follows actual sources. Mixer outputs declare their own
    /// cluster; a selector with incompatible sources requires a separate policy.
    pub fn signal_cluster(&self, id: u8) -> Result<(u8, u32), Error> {
        self.cluster(id, &mut [false; 256])
    }
    fn cluster(&self, id: u8, visited: &mut [bool; 256]) -> Result<(u8, u32), Error> {
        if visited[usize::from(id)] {
            return Err(Error::Descriptor("cyclic USB audio signal cluster"));
        }
        visited[usize::from(id)] = true;
        let result = match self.entity(id)? {
            Entity::Input {
                channels,
                channel_config,
                ..
            }
            | Entity::Mixer {
                channels,
                channel_config,
                ..
            } => Ok((*channels, *channel_config)),
            Entity::Feature { source, .. } | Entity::Output { source, .. } => {
                self.cluster(*source, visited)
            }
            Entity::Selector { sources, .. } => {
                let mut common = None;
                for source in sources {
                    let value = self.cluster(*source, visited)?;
                    if common.is_some_and(|n| n != value) {
                        return Err(Error::Unsupported("audio selector changes channel cluster"));
                    }
                    common = Some(value);
                }
                common.ok_or(Error::Descriptor("empty audio selector"))
            }
            _ => Err(Error::Descriptor("signal references a clock entity")),
        };
        visited[usize::from(id)] = false;
        result
    }
    fn mixer_inputs(&self, sources: &[u8]) -> Result<usize, Error> {
        if sources.is_empty() {
            return Err(Error::Descriptor("mixer has no sources"));
        }
        let mut count = 0usize;
        for source in sources {
            count = count
                .checked_add(usize::from(self.signal_cluster(*source)?.0))
                .ok_or(Error::Format)?;
        }
        if count == 0 || count > 255 {
            return Err(Error::Unsupported("mixer input channel addressing"));
        }
        Ok(count)
    }
    pub(super) fn validate_mixers(&self) -> Result<(), Error> {
        for entity in &self.entities {
            if let Entity::Mixer {
                sources,
                channels,
                matrix,
                ..
            } = entity
            {
                if !(1..=32).contains(channels) {
                    return Err(Error::Format);
                }
                let cells = self.mixer_inputs(sources)? * usize::from(*channels);
                if matrix.len() != cells.div_ceil(8) {
                    return Err(Error::Descriptor("mixer matrix extent"));
                }
                let remainder = cells % 8;
                if remainder != 0
                    && matrix.last().copied().unwrap_or(0) & ((1 << (8 - remainder)) - 1) != 0
                {
                    return Err(Error::Descriptor("mixer matrix reserved padding"));
                }
            }
        }
        Ok(())
    }
    /// Flattened source channels and output channels are one-based, as encoded
    /// in wValue. This is a programmable mixer cell, not a feature-unit selector.
    fn mixer_cell(&self, id: u8, input: u8, output: u8) -> Result<(), Error> {
        let Entity::Mixer {
            sources,
            channels,
            matrix,
            ..
        } = self.entity(id)?
        else {
            return Err(Error::Descriptor("not a mixer unit"));
        };
        let inputs = self.mixer_inputs(sources)?;
        if input == 0 || usize::from(input) > inputs || output == 0 || output > *channels {
            return Err(Error::Format);
        }
        let cell = (usize::from(input) - 1) * usize::from(*channels) + usize::from(output) - 1;
        let byte = matrix
            .get(cell / 8)
            .ok_or(Error::Descriptor("mixer matrix extent"))?;
        if byte & (0x80 >> (cell % 8)) == 0 {
            return Err(Error::Unsupported("fixed mixer crosspoint"));
        }
        Ok(())
    }
    pub fn mixer_volume<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        input: u8,
        output: u8,
    ) -> Result<i16, Error> {
        self.mixer_cell(id, input, output)?;
        super::control::signed_current(io, self.protocol, self.control_interface, id, input, output)
    }
    /// Probe a mixer cell's range once, before its first set.
    pub fn mixer_volume_range<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        input: u8,
        output: u8,
    ) -> Result<super::MixerRange, Error> {
        self.mixer_cell(id, input, output)?;
        super::control::probe_range(
            io,
            self.protocol,
            self.control_interface,
            id,
            input,
            output,
            super::control::Width::S16,
        )
    }
    pub fn set_mixer_volume<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        input: u8,
        output: u8,
        range: super::MixerRange,
        value: i16,
    ) -> Result<(), Error> {
        self.mixer_cell(id, input, output)?;
        super::control::set_signed(
            io,
            self.control_interface,
            id,
            input,
            output,
            range.snap(i64::from(value)) as i16,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block::BlockError, usb::xhci::setup};
    use alloc::{collections::BTreeMap, vec::Vec};

    fn graph_fixture(protocol: u8) -> Graph {
        let matrix = if protocol == UAC1 {
            vec![13, 0x24, 4, 6, 2, 1, 4, 2, 3, 0, 0, 0x91, 0]
        } else {
            vec![16, 0x24, 4, 6, 2, 1, 4, 2, 3, 0, 0, 0, 0, 0x91, 0, 0]
        };
        Graph {
            protocol,
            control_interface: 3,
            entities: vec![
                Entity::ClockSource {
                    id: 10,
                    attributes: 0,
                    controls: 3,
                },
                Entity::Input {
                    id: 1,
                    terminal_type: 0x101,
                    clock: 10,
                    channels: 2,
                    channel_config: 3,
                },
                Entity::Input {
                    id: 4,
                    terminal_type: 0x201,
                    clock: 10,
                    channels: 2,
                    channel_config: 3,
                },
                parse(&matrix, protocol).unwrap(),
            ],
        }
    }
    struct Device {
        protocol: u8,
        gains: BTreeMap<(u8, u8), i16>,
        writes: usize,
        short: bool,
        false_readback: bool,
        set_failure: bool,
    }
    impl Device {
        fn new(protocol: u8) -> Self {
            Self {
                protocol,
                gains: BTreeMap::new(),
                writes: 0,
                short: false,
                false_readback: false,
                set_failure: false,
            }
        }
    }
    impl Control for Device {
        fn now_us(&self) -> u64 {
            0
        }
        fn relax(&mut self) {}
        fn control(&mut self, r: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
            assert_eq!((r[4], r[5]), (3, 6));
            let key = (r[3], r[2]);
            assert!(matches!(key, (1, 1) | (2, 2) | (4, 2)));
            let request = if self.protocol == UAC1 { 0x81 } else { 1 };
            if r[0] == 0x21 && r[1] == 4 {
                // UAC1 SET_RES is refused.
                return Err(BlockError::Timeout);
            }
            if r[0] == 0x21 {
                assert_eq!(
                    r,
                    setup(
                        0x21,
                        1,
                        (u16::from(key.0) << 8) | u16::from(key.1),
                        0x603,
                        2
                    )
                );
                self.gains
                    .insert(key, i16::from_le_bytes(out.try_into().unwrap()));
                self.writes += 1;
                return if self.set_failure {
                    Err(BlockError::Timeout)
                } else {
                    Ok(Vec::new())
                };
            }
            assert_eq!(r[0], 0xa1);
            let data = if r[1] == request {
                (if self.false_readback {
                    123
                } else {
                    *self.gains.get(&key).unwrap_or(&0)
                })
                .to_le_bytes()
                .to_vec()
            } else if self.protocol == UAC1 {
                match r[1] {
                    0x82 => (-16384_i16).to_le_bytes().to_vec(),
                    0x83 => 0_i16.to_le_bytes().to_vec(),
                    0x84 => 256_u16.to_le_bytes().to_vec(),
                    _ => panic!("bad v1 mixer request {r:?}"),
                }
            } else {
                assert_eq!(r[1], 2);
                vec![1, 0, 0, 0xc0, 0, 0, 0, 1]
            };
            let n = usize::from(u16::from_le_bytes([r[6], r[7]]));
            Ok(data[..n.min(data.len()).saturating_sub(usize::from(self.short))].to_vec())
        }
    }
    #[test]
    fn matrix_bitmap_is_msb_first_and_wire_address_is_input_then_output() {
        for protocol in [UAC1, UAC2] {
            let graph = graph_fixture(protocol);
            graph.validate().unwrap();
            assert_eq!(graph.signal_cluster(6), Ok((2, 3)));
            let mut device = Device::new(protocol);
            // Probing writes the minimum, one step and the saved value back.
            let range = graph.mixer_volume_range(&mut device, 6, 1, 1).unwrap();
            assert_eq!(
                range,
                crate::usb::audio::MixerRange {
                    min: -16384,
                    max: 0,
                    res: 256,
                    db: Some((-6400, 0))
                }
            );
            assert_eq!((device.writes, device.gains[&(1, 1)]), (3, 0));
            device.writes = 0;
            for (input, output) in [(1, 1), (2, 2), (4, 2)] {
                graph
                    .set_mixer_volume(&mut device, 6, input, output, range, -256)
                    .unwrap();
                assert_eq!(graph.mixer_volume(&mut device, 6, input, output), Ok(-256));
            }
            assert_eq!(device.writes, 3);
            for (input, output, error) in [
                (1, 2, Error::Unsupported("fixed mixer crosspoint")),
                (3, 1, Error::Unsupported("fixed mixer crosspoint")),
                (0, 1, Error::Format),
                (4, 3, Error::Format),
            ] {
                assert_eq!(
                    graph.set_mixer_volume(&mut device, 6, input, output, range, 0),
                    Err(error)
                );
            }
            assert_eq!(device.writes, 3);
            // A value between steps snaps down, and nothing is read back.
            device.false_readback = true;
            graph
                .set_mixer_volume(&mut device, 6, 1, 1, range, -257)
                .unwrap();
            assert_eq!(device.gains[&(1, 1)], -512);
            device.false_readback = false;
            device.set_failure = true;
            assert_eq!(
                graph.set_mixer_volume(&mut device, 6, 1, 1, range, 0),
                Err(Error::Transport(BlockError::Timeout))
            );
            device.set_failure = false;
            device.short = true;
            assert_eq!(
                graph.mixer_volume(&mut device, 6, 1, 1),
                Err(Error::ControlLength)
            );
        }
    }
    #[test]
    fn malformed_matrix_extent_padding_cycles_and_sources_are_rejected() {
        for protocol in [UAC1, UAC2] {
            let mut graph = graph_fixture(protocol);
            let Entity::Mixer { matrix, .. } = &mut graph.entities[3] else {
                unreachable!()
            };
            matrix.clear();
            assert_eq!(
                graph.validate(),
                Err(Error::Descriptor("mixer matrix extent"))
            );
            let mut graph = graph_fixture(protocol);
            let Entity::Mixer { sources, .. } = &mut graph.entities[3] else {
                unreachable!()
            };
            sources[0] = 6;
            assert!(graph.validate().is_err());
            let Entity::Mixer { sources, .. } = &mut graph.entities[3] else {
                unreachable!()
            };
            sources[0] = 99;
            assert!(graph.validate().is_err());
            let mut graph = graph_fixture(protocol);
            let Entity::Mixer {
                sources,
                channels,
                matrix,
                ..
            } = &mut graph.entities[3]
            else {
                unreachable!()
            };
            sources.truncate(1);
            *channels = 1;
            *matrix = vec![0xc1]; // two cells + nonzero reserved low padding
            assert_eq!(
                graph.validate(),
                Err(Error::Descriptor("mixer matrix reserved padding"))
            );
        }
    }
}
