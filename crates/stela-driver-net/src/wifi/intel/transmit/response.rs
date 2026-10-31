// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! API7 single-frame firmware TX observations. Parsing does not correlate an
//! owned submitted frame, release DMA or grant an OS completion/ACK receipt.
use crate::wifi::{
    RawRate,
    intel::{
        firmware::{Family, Firmware},
        receive::Packet,
    },
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Version,
    Packet,
    FrameCount(u8),
    Length,
    Queue(u16),
    RateFormat,
}
/// Wire result observations; source Success and DirectDone stay distinct.
/// Neither is an owned canonical on-air ACK without the submitted-frame policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    DirectDone,
    Failed,
    Flushed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response<'a> {
    raw: &'a [u8],
    pub sequence: u16,
    pub queue: u16,
    pub status: u16,
    pub aggregate_sequence: u16,
    pub scd_ssn: u16,
    /// Host queue-pointer normalization, not MAC sequence permission.
    pub next_pointer: u16,
    pub attempts: u16,
    pub rate: RawRate,
    /// Source says this MAC sequence is unreliable upon failure/BAR.
    pub reported_mac_sequence: u16,
    pub media_time: u16,
    pub ra_tid: u8,
    pub frame_control: u16,
    pub byte_count: u16,
}
impl<'a> Response<'a> {
    pub fn parse(fw: &Firmware<'_>, family: Family, packet: &Packet<'a>) -> Result<Self, Error> {
        Self::parse_raw(fw, family, packet.raw())
    }
    pub fn parse_raw(fw: &Firmware<'_>, family: Family, raw: &'a [u8]) -> Result<Self, Error> {
        Self::check(fw, family)?;
        if raw.len() < 8
            || (u32::from_le_bytes(raw[..4].try_into().unwrap()) & 0x3fff) as usize + 4 != raw.len()
            || raw[4..6] != [0x1c, 0]
        {
            return Err(Error::Packet);
        }
        let sequence = u16::from_le_bytes([raw[6], raw[7]]);
        Self::parse_body(family, sequence, raw, &raw[8..])
    }
    /// The response of a retained notification: `body` without its header.
    pub fn parse_notification(
        fw: &Firmware<'_>,
        family: Family,
        sequence: u16,
        body: &'a [u8],
    ) -> Result<Self, Error> {
        Self::check(fw, family)?;
        Self::parse_body(family, sequence, body, body)
    }
    fn check(fw: &Firmware<'_>, family: Family) -> Result<(), Error> {
        if fw.command_version(1, 0x1c).map(|v| v.notification_version) != Some(7) {
            return Err(Error::Version);
        }
        if super::rate_format_2(fw, family).is_err() {
            return Err(Error::RateFormat);
        }
        Ok(())
    }
    fn parse_body(
        family: Family,
        sequence: u16,
        raw: &'a [u8],
        d: &'a [u8],
    ) -> Result<Self, Error> {
        let count = *d.first().ok_or(Error::Length)?;
        if count != 1 {
            return Err(Error::FrameCount(count));
        }
        if d.len() < 48 {
            return Err(Error::Length);
        }
        let h = |at| u16::from_le_bytes([d[at], d[at + 1]]);
        let w = |at| u32::from_le_bytes(d[at..at + 4].try_into().unwrap());
        let queue = h(36);
        if queue >= 512 {
            return Err(Error::Queue(queue));
        }
        let scd_ssn = (w(44)
            & if family == Family::Ax200 {
                0xfff
            } else {
                0xffff
            }) as u16;
        Ok(Self {
            raw,
            sequence,
            queue,
            status: h(40),
            aggregate_sequence: h(42),
            scd_ssn,
            next_pointer: if family == Family::Ax200 {
                scd_ssn & 255
            } else {
                scd_ssn
            },
            attempts: u16::from(d[3]) + 1,
            rate: RawRate {
                layout: 2,
                words: [w(4), 0, 0, 0],
            },
            reported_mac_sequence: h(28),
            media_time: h(8),
            ra_tid: d[33],
            frame_control: h(34),
            byte_count: h(30),
        })
    }
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    /// Reported direct result only. A queue owner must match full body
    /// queue, short echo index, normalized SSN and kept native epoch before
    /// assigning this result to one submitted frame. It must separately finish
    /// canonical descriptor/TB0/payload DMA handoffs and keep the key context.
    pub fn reported_outcome(&self) -> Outcome {
        match self.status & 255 {
            1 => Outcome::Success,
            2 => Outcome::DirectDone,
            0x85 | 0x8e => Outcome::Flushed,
            _ => Outcome::Failed,
        }
    }
    pub fn echo_queue(&self) -> u8 {
        ((self.sequence >> 8) & 31) as u8
    }
    pub fn echo_index(&self) -> u8 {
        self.sequence as u8
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::tests::{firmware, rows};
    use super::*;
    use alloc::{vec, vec::Vec};
    fn packet(body: &[u8], queue: u16, index: u16) -> Vec<u8> {
        let mut raw = vec![0; 8];
        raw[..4].copy_from_slice(&((body.len() + 4) as u32).to_le_bytes());
        raw[4] = 0x1c;
        raw[6..8].copy_from_slice(&(((queue & 31) << 8) | (index & 255)).to_le_bytes());
        raw.extend(body);
        raw
    }
    fn body(queue: u16, ssn: u32) -> Vec<u8> {
        let mut body = vec![0; 48];
        body[0] = 1;
        body[3] = 255;
        body[36..38].copy_from_slice(&queue.to_le_bytes());
        body[40..42].copy_from_slice(&1u16.to_le_bytes());
        body[44..48].copy_from_slice(&ssn.to_le_bytes());
        body
    }
    #[test]
    fn full_queue_ssn_echo_and_reported_air_never_imply_owned_dma_completion() {
        for family in [Family::Ax200, Family::Ax210] {
            let b = firmware(&rows(family));
            let fw = Firmware::parse(&b).unwrap();
            let payload = body(511, 0xfedcabcd);
            let raw = packet(&payload, 511, 0x1234);
            let response = Response::parse_raw(&fw, family, &raw).unwrap();
            assert_eq!(response.queue, 511);
            assert_eq!(response.echo_queue(), 31);
            assert_eq!(response.echo_index(), 0x34);
            assert_eq!(
                response.scd_ssn,
                if family == Family::Ax200 {
                    0xbcd
                } else {
                    0xabcd
                }
            );
            assert_eq!(
                response.next_pointer,
                if family == Family::Ax200 {
                    0xcd
                } else {
                    0xabcd
                }
            );
            assert_eq!(response.attempts, 256);
            assert_eq!(response.raw(), raw);
            assert_eq!(response.reported_outcome(), Outcome::Success);
            for (status, air) in [
                (0x101, Outcome::Success),
                (0xab02, Outcome::DirectDone),
                (0xaa85, Outcome::Flushed),
                (0x128e, Outcome::Flushed),
                (0, Outcome::Failed),
                (0x88, Outcome::Failed),
                (0x40, Outcome::Failed),
                (0xffff, Outcome::Failed),
            ] {
                let mut payload = payload.clone();
                payload[40..42].copy_from_slice(&(status as u16).to_le_bytes());
                let raw = packet(&payload, 511, 0x1234);
                assert_eq!(
                    Response::parse_raw(&fw, family, &raw)
                        .unwrap()
                        .reported_outcome(),
                    air
                );
            }
            for len in 0..48 {
                let raw = packet(&payload[..len], 511, 0x1234);
                assert_eq!(Response::parse_raw(&fw, family, &raw), Err(Error::Length));
            }
            for count in [0, 2, 255] {
                let mut payload = payload.clone();
                payload[0] = count;
                let raw = packet(&payload, 511, 0x1234);
                assert_eq!(
                    Response::parse_raw(&fw, family, &raw),
                    Err(Error::FrameCount(count))
                );
            }
            for queue in [512, u16::MAX] {
                let raw = packet(&body(queue, 1), queue, 0);
                assert_eq!(
                    Response::parse_raw(&fw, family, &raw),
                    Err(Error::Queue(queue))
                );
            }
            let mut raw = raw.clone();
            raw[4] = 0x77;
            assert_eq!(Response::parse_raw(&fw, family, &raw), Err(Error::Packet));
            let mut raw = packet(&payload, 511, 0x1234);
            raw[0] ^= 1;
            assert_eq!(Response::parse_raw(&fw, family, &raw), Err(Error::Packet));
            // Mutable Packet diagnostics cannot retag canonical packet bytes.
            let mut rb = packet(&payload, 511, 0x1234);
            rb.resize(rb.len().next_multiple_of(64), 0);
            let mut p = crate::wifi::intel::receive::Packets::new(family, 0, &rb)
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
            p.command = 0x77;
            p.group = 3;
            p.sequence = 0;
            assert_eq!(Response::parse(&fw, family, &p).unwrap().queue, 511);
            let mut mismatch = rows(family);
            mismatch[0][3] = 6;
            let b = firmware(&mismatch);
            let fw = Firmware::parse(&b).unwrap();
            assert_eq!(
                Response::parse_raw(&fw, family, &packet(&payload, 511, 0x1234)),
                Err(Error::Version)
            );
            mismatch[0][3] = 7;
            mismatch[1][3] = 2;
            let b = firmware(&mismatch);
            let fw = Firmware::parse(&b).unwrap();
            assert_eq!(
                Response::parse_raw(&fw, family, &packet(&payload, 511, 0x1234)),
                Err(Error::RateFormat)
            );
        }
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
    fn images_negotiate_complete_source_format2_and_tx_response7() {
        for family in [Family::Ax200, Family::Ax210] {
            let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
            let b =
                std::fs::read(std::path::Path::new(&root).join(family.firmware_name())).unwrap();
            let fw = Firmware::parse(&b).unwrap();
            let raw = packet(&body(256, 0x1234), 256, 0x1233);
            let r = Response::parse_raw(&fw, family, &raw).unwrap();
            assert_eq!(r.queue, 256);
            assert_eq!(r.echo_queue(), 0);
            assert_eq!(r.rate.layout, 2);
        }
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_TX_QUEUE_ORACLE"]
    fn unchanged_linux_full_response_layout_and_trailing_ssn_helpers_match() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_TX_QUEUE_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&trace)),
            "4c80c65cd1d3cde98cd9843493c183d778e7f951e469d0a0f096c7e2ec6abe63"
        );
        let mut total = 0;
        let mut admitted = 0;
        for line in core::str::from_utf8(&trace)
            .unwrap()
            .lines()
            .filter(|s| s.starts_with("tx "))
        {
            let f: Vec<_> = line.split_whitespace().collect();
            let n = |i: usize| f[i].parse::<u32>().unwrap();
            let family = if n(1) == 0 {
                Family::Ax200
            } else {
                Family::Ax210
            };
            let sample = n(2);
            let b = firmware(&rows(family));
            let fw = Firmware::parse(&b).unwrap();
            let data: Vec<_> = f[8]
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|h| u8::from_str_radix(core::str::from_utf8(h).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(n(6), 44);
            assert_eq!(n(7), 40);
            assert_eq!(data.len(), n(4) as usize);
            let raw = packet(&data, sample as u16, sample as u16);
            let parsed = Response::parse_raw(&fw, family, &raw);
            if n(3) != 1 {
                assert_eq!(parsed, Err(Error::FrameCount(n(3) as u8)));
            } else {
                let r = parsed.unwrap();
                admitted += 1;
                assert_eq!(u32::from(r.scd_ssn), n(5));
                assert_eq!(u32::from(r.queue), sample);
                assert_eq!(r.attempts, u16::from(data[3]) + 1);
                assert_eq!(
                    r.status,
                    u16::from_le_bytes(data[40..42].try_into().unwrap())
                );
                assert_eq!(
                    r.aggregate_sequence,
                    u16::from_le_bytes(data[42..44].try_into().unwrap())
                );
                assert_eq!(
                    r.rate.words[0],
                    u32::from_le_bytes(data[4..8].try_into().unwrap())
                );
                assert_eq!(
                    r.reported_mac_sequence,
                    u16::from_le_bytes(data[28..30].try_into().unwrap())
                );
                assert_eq!(r.ra_tid, data[33]);
                assert_eq!(
                    r.frame_control,
                    u16::from_le_bytes(data[34..36].try_into().unwrap())
                );
                assert_eq!(
                    r.media_time,
                    u16::from_le_bytes(data[8..10].try_into().unwrap())
                );
                assert_eq!(
                    r.byte_count,
                    u16::from_le_bytes(data[30..32].try_into().unwrap())
                );
            }
            total += 1;
        }
        assert_eq!((total, admitted), (1024, 514));
    }
}
