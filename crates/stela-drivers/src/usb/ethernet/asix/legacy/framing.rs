// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2003-2006 David Hollis <dhollis@davehollis.com>
// Copyright (C) 2005 Phil Chang <pchang23@sbcglobal.net>
// Copyright (C) 2006 James Painter <jamie.painter@iname.com>
// Copyright (C) 2002-2003 TiVo Inc.
//! Stateful AX88772 length/complement framing, including split URB headers.
use alloc::vec::Vec;
const MAX_FRAME: usize = 1518;
const MAX_TRANSFER: usize = 2048;

pub(in crate::usb::ethernet) fn encode(
    frame: &[u8],
    output: &mut [u8],
    packet: u16,
) -> Result<usize, &'static str> {
    if !(14..=MAX_FRAME).contains(&frame.len()) || !matches!(packet, 8 | 16 | 32 | 64 | 512) {
        return Err("AX88772 unsupported frame or USB2 bulk packet size");
    }
    let length = frame.len().max(60);
    let padding = if (length + 4).is_multiple_of(usize::from(packet)) {
        4
    } else {
        0
    };
    let total = length + 4 + padding;
    if total > output.len() {
        return Err("AX88772 TX exceeds DMA buffer");
    }
    let word = (length as u32) | ((!(length as u32) & 0xffff) << 16);
    output[..4].copy_from_slice(&word.to_le_bytes());
    output[4..4 + frame.len()].copy_from_slice(frame);
    output[4 + frame.len()..4 + length].fill(0);
    if padding != 0 {
        output[4 + length..total].copy_from_slice(&0xffff0000u32.to_le_bytes());
    }
    Ok(total)
}

#[derive(Default)]
pub(super) struct Decoder {
    remaining: usize,
    split: bool,
    header: u32,
    frame: Vec<u8>,
}
impl Decoder {
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }
    pub(super) fn decode(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        let result = self.consume(bytes);
        if result.is_err() {
            self.reset();
        }
        result
    }
    fn consume(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        if bytes.len() > MAX_TRANSFER {
            return Err("AX88772 RX exceeds selected URB size");
        }
        if self.remaining != 0 && self.remaining + 4 <= bytes.len() {
            let next = self.remaining.next_multiple_of(2);
            let raw = bytes
                .get(next..next + 4)
                .ok_or("AX88772 unaligned continuation bounds")?;
            let word = u32::from_le_bytes(raw.try_into().unwrap());
            if !valid(word) {
                // Donor abandons a truncated previous frame and resynchronizes
                // at this URB's header, without appending unrelated bytes.
                self.reset();
            }
        }
        let mut offset = 0;
        let mut frames = Vec::new();
        while offset + 2 <= bytes.len() {
            if self.remaining == 0 {
                // Finish a retained low half before recognizing a new split header.
                // The pinned donor reverses these cases and loses 2+2 headers.
                if bytes.len() - offset == 2 && !self.split {
                    self.header = u32::from(u16::from_le_bytes(
                        bytes[offset..offset + 2].try_into().unwrap(),
                    ));
                    self.split = true;
                    offset += 2;
                    break;
                }
                if self.split {
                    self.header |= u32::from(u16::from_le_bytes(
                        bytes[offset..offset + 2].try_into().unwrap(),
                    )) << 16;
                    self.split = false;
                    offset += 2;
                } else {
                    self.header = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                    offset += 4;
                }
                if !valid(self.header) {
                    return Err("AX88772 RX length complement mismatch");
                }
                self.remaining = (self.header & 0x7ff) as usize;
                if self.remaining > MAX_FRAME {
                    return Err("AX88772 RX frame exceeds selected MTU");
                }
                self.frame.clear();
            }
            let copy = self.remaining.min(bytes.len() - offset);
            self.frame.extend_from_slice(&bytes[offset..offset + copy]);
            self.remaining -= copy;
            if self.remaining == 0 && !self.frame.is_empty() {
                if self.frame.len() < 14 {
                    return Err("AX88772 RX runt frame");
                }
                frames.push(core::mem::take(&mut self.frame));
            } // Length-zero padding is consumed, never exposed as a frame.
            offset += copy.next_multiple_of(2);
        }
        if offset != bytes.len() {
            return Err("AX88772 RX incomplete word alignment");
        }
        Ok(frames)
    }
}
fn valid(word: u32) -> bool {
    word & 0x7ff == (!word >> 16) & 0x7ff
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;
    fn wire(frame: &[u8]) -> Vec<u8> {
        let n = frame.len() as u32;
        let mut bytes = (n | ((!n & 0xffff) << 16)).to_le_bytes().to_vec();
        bytes.extend_from_slice(frame);
        bytes.resize(bytes.len().next_multiple_of(2), 0);
        bytes
    }
    #[test]
    fn all_even_split_points_and_multiframe_continuations_preserve_bytes() {
        for n in [14, 60, 61, 1514, 1518] {
            let a = vec![0x93; n];
            let b = vec![0x4d; 60];
            let mut bytes = wire(&a);
            bytes.extend(wire(&b));
            for split in (0..=bytes.len()).step_by(2) {
                let mut decoder = Decoder::default();
                let mut frames = decoder.decode(&bytes[..split]).unwrap();
                frames.extend(decoder.decode(&bytes[split..]).unwrap());
                assert_eq!(
                    frames,
                    vec![a.clone(), b.clone()],
                    "length {n} split {split}"
                );
                assert_eq!(decoder.remaining, 0);
            }
        }
    }
    #[test]
    fn pending_header_survives_three_fragments_and_repeated_two_byte_transfers() {
        for n in [14, 60, 61, 1514, 1518] {
            let first = vec![0x53; n];
            let second = vec![0x87; 60];
            let mut bytes = wire(&first);
            bytes.extend_from_slice(&0xffff0000u32.to_le_bytes());
            bytes.extend(wire(&second));
            let expected = vec![first, second];
            let mut decoder = Decoder::default();
            assert!(decoder.decode(&bytes[..2]).unwrap().is_empty());
            assert!(decoder.decode(&bytes[2..4]).unwrap().is_empty());
            assert_eq!(decoder.decode(&bytes[4..]).unwrap(), expected);
            let mut decoder = Decoder::default();
            let mut frames = Vec::new();
            for chunk in bytes.chunks(2) {
                frames.extend(decoder.decode(chunk).unwrap());
            }
            assert_eq!(frames, expected);
            assert_eq!((decoder.remaining, decoder.split), (0, false));
        }
    }
    #[test]
    fn malformed_stream_reset_resynchronization_and_tx_bounds() {
        let a = vec![0x72; 60];
        let b = vec![0x37; 61];
        let mut d = Decoder::default();
        assert!(d.decode(&wire(&a)[..24]).unwrap().is_empty());
        // A missing continuation is detected by the next-header sanity test.
        assert_eq!(d.decode(&wire(&b)).unwrap(), vec![b]);
        for bytes in [&[1][..], &[0, 0, 0, 0][..], &[0; 2049][..]] {
            assert!(d.decode(bytes).is_err());
            assert_eq!(d.decode(&wire(&a)).unwrap(), vec![a.clone()]);
        }
        for packet in [8, 16, 32, 64, 512] {
            for n in [14, 60, 61, 508, 509, 1518] {
                let mut out = vec![0xad; 2048];
                let frame = vec![0x54; n];
                let total = encode(&frame, &mut out, packet).unwrap();
                assert!(!total.is_multiple_of(packet as usize));
                assert_eq!(&out[4..4 + n], &frame);
                assert_eq!(out[total], 0xad);
                assert!(encode(&frame, &mut out[..total - 1], packet).is_err());
            }
        }
    }
    #[test]
    #[ignore = "requires unchanged pinned AX88772 split RX/TX C corpus"]
    fn unchanged_linux_ax88772_split_frames_and_padding_bytes() {
        fn hex(text: &str) -> Vec<u8> {
            if text == "-" {
                return Vec::new();
            }
            text.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|v| u8::from_str_radix(core::str::from_utf8(v).unwrap(), 16).unwrap())
                .collect()
        }
        let text = std::fs::read_to_string(std::env::var("STELA_AX88772_FRAMING_ORACLE").unwrap())
            .unwrap();
        let mut count = 0;
        for line in text.lines() {
            count += 1;
            let fields: Vec<_> = line.split_whitespace().collect();
            let mut d = Decoder::default();
            match fields[0] {
                "T" => {
                    let packet = fields[1].parse().unwrap();
                    let n = fields[2].parse().unwrap();
                    let mut out = vec![0; 2048];
                    let total = encode(&vec![0x53; n], &mut out, packet).unwrap();
                    assert_eq!(out[..total], hex(fields[3]));
                }
                "B" => assert!(d.decode(&hex(fields[1])).is_err()),
                "S" | "L" => {
                    let frames = if fields[0] == "S" {
                        let bytes = hex(fields[2]);
                        let split = fields[1].parse().unwrap();
                        let mut frames = d.decode(&bytes[..split]).unwrap();
                        frames.extend(d.decode(&bytes[split..]).unwrap());
                        frames
                    } else {
                        let mut frames = d.decode(&hex(fields[1])).unwrap();
                        frames.extend(d.decode(&hex(fields[2])).unwrap());
                        frames
                    };
                    assert_eq!(frames.len(), fields[3].parse::<usize>().unwrap());
                    assert_eq!(
                        frames,
                        fields[4]
                            .split(',')
                            .filter(|v| *v != "-")
                            .map(hex)
                            .collect::<Vec<_>>()
                    );
                }
                _ => panic!("unknown fixture kind"),
            }
        }
        assert_eq!(count, 1799);
    }
}
