// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual UAC3 high-capability cluster requests, bounded and stable across the
//! required header/full-descriptor transactions. Linux stream.c is the reference.
use super::super::{Control, Error};
use crate::{bytes::le16, usb::xhci::setup};
use alloc::vec::Vec;

const HEADER: usize = 6;
const CLUSTER_HEADER: usize = 7;
const MAX_CLUSTER: usize = 4096;

/// Exact per-channel information advertised by the device, in descriptor order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelInformation {
    pub purpose: u8,
    pub relationship: u8,
    pub group: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cluster {
    pub id: u16,
    pub channels: u8,
    /// Some channel maps omit information. Missing entries remain explicitly
    /// unspecified; they are not replaced by invented stereo speaker positions.
    pub information: Vec<ChannelInformation>,
    /// Preserve additional standard/vendor/description/ambisonic metadata.
    pub descriptor: Vec<u8>,
}
impl Cluster {
    pub(super) fn channel_config(&self) -> u32 {
        if self.information.len() != usize::from(self.channels) {
            return 0;
        }
        let mut mask = 0;
        for c in &self.information {
            let bit = match c.relationship {
                0x02 | 0x80 | 0xbb => 0,
                0x03 | 0x81 | 0xbc => 1,
                0x01 | 0x82 => 2,
                0xb8 => 3,
                0x8b => 4,
                0x8c => 5,
                0x83 => 6,
                0x84 => 7,
                0x8d => 8,
                0x87 => 9,
                0x88 => 10,
                0x92 => 11,
                0x93 => 12,
                0x95 => 13,
                0x94 => 14,
                0x9e => 15,
                0xa0 => 16,
                0x9f => 17,
                _ => return 0,
            };
            if mask & (1 << bit) != 0 {
                return 0;
            }
            mask |= 1 << bit;
        }
        mask
    }
}

pub(super) struct Reader<'a, C> {
    pub io: &'a mut C,
    pub interface: u8,
    pub clusters: Vec<Cluster>,
}
impl<C: Control> Reader<'_, C> {
    pub fn get(&mut self, id: u16) -> Result<Cluster, Error> {
        if let Some(c) = self.clusters.iter().find(|c| c.id == id) {
            return Ok(c.clone());
        }
        if id == 0 {
            return Err(Error::Descriptor("zero UAC3 cluster reference"));
        }
        if self.clusters.len() >= 256 {
            return Err(Error::Unsupported(
                "UAC3 cluster inventory exceeds 256 descriptors",
            ));
        }
        let request = |length| setup(0xa1, 6, id, u16::from(self.interface), length);
        let head = self.io.control(request(HEADER as u16), &[])?;
        if head.len() != HEADER {
            return Err(Error::ControlLength);
        }
        let length = usize::from(le16(&head, 0));
        if length > MAX_CLUSTER {
            return Err(Error::Unsupported(
                "UAC3 cluster descriptor exceeds 4096 bytes",
            ));
        }
        if length < CLUSTER_HEADER || head[2] != 0x26 || le16(&head, 4) != id {
            return Err(Error::Descriptor("UAC3 high-capability cluster header"));
        }
        let descriptor = self.io.control(request(length as u16), &[])?;
        if descriptor.len() != length {
            return Err(Error::ControlLength);
        }
        if descriptor[..HEADER] != head {
            return Err(Error::ControlReadback);
        }
        let channels = descriptor[6];
        if !(1..=32).contains(&channels) {
            return Err(Error::Unsupported("UAC3 PCM channel count"));
        }
        let mut information = Vec::new();
        let mut at = CLUSTER_HEADER;
        while at < length {
            if length - at < 3 {
                return Err(Error::Descriptor("short UAC3 cluster segment"));
            }
            let n = usize::from(le16(&descriptor, at));
            if n < 3 || n > length - at {
                return Err(Error::Descriptor("UAC3 cluster segment extent"));
            }
            let d = &descriptor[at..at + n];
            if d[2] == 0x20 {
                if n < 6 || information.len() >= usize::from(channels) {
                    return Err(Error::Descriptor("UAC3 channel information extent/count"));
                }
                information.push(ChannelInformation {
                    purpose: d[3],
                    relationship: d[4],
                    group: d[5],
                });
            }
            at += n;
        }
        let cluster = Cluster {
            id,
            channels,
            information,
            descriptor,
        };
        self.clusters.push(cluster.clone());
        Ok(cluster)
    }
}
