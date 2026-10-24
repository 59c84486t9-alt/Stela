// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! MTK interrupt ISO padding/framing from btmtk_isopkt_pad/recv_isopkt;
//! SCO three-byte transport framing uses the Bluetooth USB HCI boundary.
use super::{Error, Result};
use alloc::vec::Vec;
pub const ISO_TRANSFER_BYTES: usize = 264;
pub const SCO_PACKET_BYTES: usize = 258;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Sco,
    Iso,
}
impl Kind {
    fn header(self) -> usize {
        match self {
            Self::Sco => 3,
            Self::Iso => 4,
        }
    }
    fn maximum(self) -> usize {
        match self {
            Self::Sco => SCO_PACKET_BYTES,
            Self::Iso => ISO_TRANSFER_BYTES,
        }
    }
    fn length(self, packet: &[u8]) -> usize {
        match self {
            Self::Sco => usize::from(packet[2]),
            Self::Iso => usize::from(u16::from_le_bytes([packet[2], packet[3]])),
        }
    }
}
pub(super) fn validate(kind: Kind, packet: &[u8]) -> Result<()> {
    if packet.len() < kind.header() || packet.len() != kind.header() + kind.length(packet) {
        return Err(Error::Packet("complete media HCI length"));
    }
    if packet.len() > kind.maximum() {
        return Err(Error::Packet("bounded media HCI packet"));
    }
    Ok(())
}
pub(super) fn iso_output(packet: &[u8]) -> Result<[u8; ISO_TRANSFER_BYTES]> {
    validate(Kind::Iso, packet)?;
    let mut bytes = [0; ISO_TRANSFER_BYTES];
    bytes[..packet.len()].copy_from_slice(packet);
    Ok(bytes)
}
pub(super) struct Framer {
    kind: Kind,
    bytes: Vec<u8>,
    expected: usize,
    since: Option<u64>,
}
impl Framer {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            bytes: Vec::new(),
            expected: kind.header(),
            since: None,
        }
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> (Vec<u8>, usize, Option<u64>) {
        (self.bytes.clone(), self.expected, self.since)
    }
    pub fn reset(&mut self) {
        self.bytes.clear();
        self.expected = self.kind.header();
        self.since = None;
    }
    pub fn partial(&self) -> bool {
        self.since.is_some()
    }
    pub fn feed(&mut self, mut input: &[u8], now: u64) -> Result<Vec<Vec<u8>>> {
        if self
            .since
            .is_some_and(|since| now.saturating_sub(since) >= 1_000_000)
        {
            return Err(Error::Packet("media partial deadline"));
        }
        let mut frames = Vec::new();
        while !input.is_empty() {
            if self.bytes.is_empty() {
                self.since = Some(now);
            }
            let take = (self.expected - self.bytes.len()).min(input.len());
            self.bytes.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.bytes.len() < self.expected {
                continue;
            }
            if self.expected == self.kind.header() {
                self.expected += self.kind.length(&self.bytes);
                if self.expected > self.kind.maximum() {
                    return Err(Error::Packet("bounded media HCI receive"));
                }
                if self.bytes.len() < self.expected {
                    continue;
                }
            }
            frames.push(core::mem::take(&mut self.bytes));
            self.expected = self.kind.header();
            self.since = None;
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_padding_and_all_split_coalesced_frames() {
        for kind in [Kind::Sco, Kind::Iso] {
            let mut one = vec![0x21, 0, 3];
            if kind == Kind::Iso {
                one.push(0);
            }
            one.extend_from_slice(&[1, 2, 3]);
            for split in 0..=one.len() {
                let mut f = Framer::new(kind);
                let mut got = f.feed(&one[..split], 0).unwrap();
                let mut tail = one[split..].to_vec();
                tail.extend_from_slice(&one);
                got.extend(f.feed(&tail, 1).unwrap());
                assert_eq!(got, vec![one.clone(), one.clone()]);
                assert!(!f.partial());
            }
            validate(kind, &one).unwrap();
            let mut short = one.clone();
            short.pop();
            assert!(validate(kind, &short).is_err());
        }
        let packet = [1, 0, 2, 0, 5, 6];
        let padded = iso_output(&packet).unwrap();
        assert_eq!(&padded[..packet.len()], &packet);
        assert!(padded[packet.len()..].iter().all(|b| *b == 0));
        let mut maximum = vec![0; 264];
        maximum[2..4].copy_from_slice(&260u16.to_le_bytes());
        assert_eq!(iso_output(&maximum).unwrap().as_slice(), maximum);
        maximum.push(0);
        maximum[2..4].copy_from_slice(&261u16.to_le_bytes());
        assert!(iso_output(&maximum).is_err());
    }
    #[test]
    fn silence_deadline_and_retirement_discard_partial_without_success() {
        let mut f = Framer::new(Kind::Sco);
        assert!(f.feed(&[1, 0, 3, 9], 10).unwrap().is_empty());
        assert!(f.feed(&[], 1_000_010).is_err());
        f.reset();
        assert_eq!(
            f.feed(&[2, 0, 1, 8], 2_000_000).unwrap(),
            vec![vec![2, 0, 1, 8]]
        );
        let mut f = Framer::new(Kind::Iso);
        assert!(f.feed(&[0, 0, 0xff, 0xff], 0).is_err());
    }
}
