// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2011-2013 ASIX
//! AX88179/178A no-offload TX and bounded aggregate metadata decoding.
use alloc::vec::Vec;

const MAX_AGGREGATE: usize = 32 * 1024;
const MIN_FRAME: usize = 14;
const MAX_FRAME: usize = 1518;
const RX_CRC_ERROR: u32 = 1 << 29;
const RX_DROP_ERROR: u32 = 1 << 31;
const TX_PADDING: u32 = 0x8000_8000;

pub(in crate::usb::ethernet) fn encode(
    frame: &[u8],
    output: &mut [u8],
    max_packet: u16,
) -> Result<usize, &'static str> {
    if !(MIN_FRAME..=MAX_FRAME).contains(&frame.len())
        || !matches!(max_packet, 8 | 16 | 32 | 64 | 512 | 1024)
    {
        return Err("ASIX unsupported frame or bulk packet size");
    }
    // The host supplies complete Ethernet frames; pad the minimum Ethernet
    // payload explicitly. AX88179's header carries the padded frame length.
    let length = frame.len().max(60);
    let total = length + 8;
    if total > output.len() {
        return Err("ASIX TX exceeds DMA buffer");
    }
    output[..4].copy_from_slice(&(length as u32).to_le_bytes());
    let flags = if total.is_multiple_of(usize::from(max_packet)) {
        TX_PADDING
    } else {
        0
    };
    output[4..8].copy_from_slice(&flags.to_le_bytes());
    output[8..8 + frame.len()].copy_from_slice(frame);
    output[8 + frame.len()..total].fill(0);
    Ok(total)
}

pub(in crate::usb::ethernet) fn decode(bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    if bytes.len() < 4 || bytes.len() > MAX_AGGREGATE {
        return Err("ASIX invalid RX aggregate length");
    }
    let end = bytes.len() - 4;
    let trailer = u32::from_le_bytes(bytes[end..].try_into().unwrap());
    let count = (trailer & 0xffff) as usize;
    let offset = (trailer >> 16) as usize;
    if count == 0 || offset & 7 != 0 || offset > end || count > (end - offset) / 4 {
        return Err("ASIX invalid RX metadata bounds");
    }
    let mut packets = Vec::new();
    let mut cursor = 0;
    for raw in bytes[offset..offset + count * 4].as_chunks::<4>().0 {
        let header = u32::from_le_bytes(*raw);
        let length = ((header >> 16) & 0x1fff) as usize;
        if length == 0 {
            continue; // Donor accepts the current firmware's optional dummy entries.
        }
        let padded = (length + 7) & !7;
        if padded > offset - cursor {
            return Err("ASIX RX packet overlaps metadata");
        }
        if header & (RX_CRC_ERROR | RX_DROP_ERROR) == 0 && length >= MIN_FRAME + 2 {
            if length > MAX_FRAME + 2 {
                return Err("ASIX RX frame exceeds selected MTU");
            }
            // Hardware already removed the FCS. Only the two-byte IP alignment
            // pseudo header precedes the Ethernet frame in this protocol.
            packets.push(bytes[cursor + 2..cursor + length].to_vec());
        }
        cursor += padded;
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    pub(crate) fn aggregate(frames: &[&[u8]], dummy: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut headers = Vec::new();
        for frame in frames {
            let length = frame.len() + 2;
            headers.push((length as u32) << 16);
            bytes.extend_from_slice(&[0, 0]);
            bytes.extend_from_slice(frame);
            bytes.resize(bytes.len().next_multiple_of(8), 0);
            if dummy {
                headers.push(RX_DROP_ERROR);
            }
        }
        let offset = bytes.len();
        for header in &headers {
            bytes.extend_from_slice(&header.to_le_bytes());
        }
        if dummy {
            bytes.extend_from_slice(&[0; 4]);
        }
        bytes.extend_from_slice(&((offset as u32) << 16 | headers.len() as u32).to_le_bytes());
        bytes
    }

    #[test]
    fn actual_old_and_dummy_metadata_preserve_complete_frame_without_fcs_trim() {
        for dummy in [false, true] {
            let a = vec![0x53; 60];
            let b = vec![0xa9; 1518];
            let bytes = aggregate(&[&a, &b], dummy);
            assert_eq!(decode(&bytes).unwrap(), vec![a.clone(), b.clone()]);
            let mut bad = bytes.clone();
            let offset =
                (u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap()) >> 16) as usize;
            bad[offset + 3] |= 0x20; // CRC-failed first packet is consumed, not returned.
            assert_eq!(decode(&bad).unwrap(), vec![b]);
            bad[offset + 2..offset + 4].copy_from_slice(&0x1fffu16.to_le_bytes());
            assert!(decode(&bad).is_err());
        }
        for length in 0..4 {
            assert!(decode(&vec![0; length]).is_err());
        }
        assert!(decode(&[0; 8]).is_err());
        let mut bad = aggregate(&[&[0; 60]], false);
        let end = bad.len() - 4;
        bad[end..].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn transmit_padding_flag_uses_real_endpoint_packet_size_and_keeps_dma_bounds() {
        for packet in [8, 16, 32, 64, 512, 1024] {
            for length in [14, 60, 61, 504, 505, 1016, 1017, 1514, 1518] {
                let mut bytes = vec![0xa7; 2048];
                let frame = vec![0x4d; length];
                let actual = encode(&frame, &mut bytes, packet).unwrap();
                assert_eq!(actual, length.max(60) + 8);
                assert_eq!(
                    u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                    length.max(60) as u32
                );
                assert_eq!(
                    u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
                    if actual.is_multiple_of(packet as usize) {
                        TX_PADDING
                    } else {
                        0
                    }
                );
                assert_eq!(&bytes[8..8 + length], &frame);
                assert!(bytes[actual..].iter().all(|b| *b == 0xa7));
            }
        }
        assert!(encode(&[0; 1519], &mut [0; 2048], 512).is_err());
        assert!(encode(&[0; 60], &mut [0; 67], 512).is_err());
        assert!(encode(&[0; 60], &mut [0; 2048], 0).is_err());
    }
    #[test]
    #[ignore = "oracle: STELA_ASIX_FRAMING_ORACLE"]
    fn unchanged_linux_asix_packet_fixup_bytes() {
        extern crate std;
        use sha2::{Digest, Sha256};
        fn hex(text: &str) -> Vec<u8> {
            if text == "-" {
                return Vec::new();
            }
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
                .collect()
        }
        let cases =
            std::fs::read_to_string(std::env::var("STELA_ASIX_FRAMING_ORACLE").unwrap()).unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(cases.as_bytes())),
            "3a92c66d118d7c0d2674be883df9e6d98aeb6c459773e6f270547b0c5e7e9d41"
        );
        let mut count = 0;
        for line in cases.lines() {
            let v: Vec<_> = line.split_whitespace().collect();
            assert_eq!(v.len(), 4);
            if v[0] == "T" {
                let packet = v[1].parse().unwrap();
                let length = v[2].parse().unwrap();
                let frame = vec![0x53; length];
                let mut buffer = vec![0; 2048];
                let n = encode(&frame, &mut buffer, packet).unwrap();
                assert_eq!(&buffer[..n], hex(v[3]));
            } else {
                let input = hex(v[1]);
                let expected: Vec<Vec<u8>> = if v[3] == "-" {
                    Vec::new()
                } else {
                    v[3].split(',').map(hex).collect()
                };
                assert_eq!(expected.len(), v[2].parse::<usize>().unwrap());
                if v[0] == "B" {
                    assert!(expected.is_empty() && decode(&input).is_err());
                } else {
                    assert_eq!(decode(&input).unwrap(), expected, "{line}");
                }
            }
            count += 1;
        }
        assert_eq!(count, 212);
    }
}
