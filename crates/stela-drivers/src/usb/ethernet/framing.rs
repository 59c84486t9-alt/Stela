// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
//! r8152_desc_init, r8152_tx_csum (no offloads), r8152_rx_len and
//! rx_agg_align: 8-byte TX header, 24-byte RX header, 8-byte RX alignment.
use crate::net::MAX_FRAME;
use alloc::vec::Vec;

pub const AGGREGATE: usize = 32 * 1024;
const RX_DESCRIPTOR: usize = 24;
const TX_DESCRIPTOR: usize = 8;
const FCS: usize = 4;
const RX_LENGTH_MASK: u32 = 0x7fff;
const TX_FIRST_LAST: u32 = (1 << 31) | (1 << 30);

pub fn encode(frame: &[u8], output: &mut [u8]) -> Result<usize, &'static str> {
    if !(14..=MAX_FRAME).contains(&frame.len()) {
        return Err("RTL815x invalid Ethernet frame length");
    }
    let length = frame.len().max(60);
    let bytes = TX_DESCRIPTOR + length;
    if output.len() < bytes {
        return Err("RTL815x TX buffer too small");
    }
    output[..bytes].fill(0);
    output[..4].copy_from_slice(&(TX_FIRST_LAST | length as u32).to_le_bytes());
    output[TX_DESCRIPTOR..TX_DESCRIPTOR + frame.len()].copy_from_slice(frame);
    Ok(bytes)
}

/// Validate the entire block before exposing any frames. Device-supplied
/// lengths never index outside the actual completed transfer; FCS is removed.
pub fn decode(bytes: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    if bytes.len() > AGGREGATE {
        return Err("RTL815x oversized RX aggregate");
    }
    let mut frames = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let descriptor = bytes
            .get(at..at + RX_DESCRIPTOR)
            .ok_or("RTL815x truncated RX descriptor")?;
        let length =
            (u32::from_le_bytes(descriptor[..4].try_into().unwrap()) & RX_LENGTH_MASK) as usize;
        if !(60..=MAX_FRAME + FCS).contains(&length) {
            return Err("RTL815x invalid RX packet length");
        }
        let start = at + RX_DESCRIPTOR;
        let end = start + length;
        let frame = bytes
            .get(start..end - FCS)
            .ok_or("RTL815x truncated RX frame")?;
        if end > bytes.len() {
            return Err("RTL815x truncated RX FCS");
        }
        // RX VLAN stripping is disabled. Refuse unexpected stripped metadata
        // instead of passing a silently changed Ethernet frame to the guest.
        let opts2 = u32::from_le_bytes(descriptor[4..8].try_into().unwrap());
        if opts2 & (1 << 16) != 0 {
            return Err("RTL815x unexpected stripped VLAN");
        }
        frames.push(frame.to_vec());
        if end == bytes.len() {
            break;
        }
        at = end.next_multiple_of(8);
        if at > bytes.len() {
            return Err("RTL815x truncated RX alignment padding");
        }
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_headers_padding_and_all_frame_lengths() {
        for length in 14..=MAX_FRAME {
            let frame = vec![0x5a; length];
            let mut buffer = vec![0xa5; 2048];
            let count = encode(&frame, &mut buffer).unwrap();
            assert_eq!(count, 8 + length.max(60));
            assert_eq!(
                u32::from_le_bytes(buffer[..4].try_into().unwrap()),
                TX_FIRST_LAST | length.max(60) as u32
            );
            assert_eq!(&buffer[8..8 + length], frame);
            assert!(buffer[8 + length..count].iter().all(|b| *b == 0));
            assert_eq!(&buffer[4..8], &[0; 4]);
            assert_eq!(buffer[count], 0xa5);
        }
        assert!(encode(&[0; 13], &mut [0; 2048]).is_err());
        assert!(encode(&[0; 64], &mut [0; 71]).is_err());
    }

    fn packet(length: usize, value: u8) -> Vec<u8> {
        let mut bytes = vec![0; RX_DESCRIPTOR + length + FCS];
        bytes[..4].copy_from_slice(&((length + FCS) as u32).to_le_bytes());
        bytes[RX_DESCRIPTOR..RX_DESCRIPTOR + length].fill(value);
        bytes[RX_DESCRIPTOR + length..].fill(0xcc);
        bytes
    }

    #[test]
    fn rx_aggregation_fcs_alignment_and_every_truncation() {
        for length in 60..=MAX_FRAME {
            let first = packet(length, 0x5a);
            assert_eq!(decode(&first).unwrap(), vec![vec![0x5a; length]]);
            for cut in [1, 4, 23, first.len() - 1] {
                assert!(decode(&first[..cut]).is_err());
            }
            let mut bytes = first.clone();
            bytes.resize(bytes.len().next_multiple_of(8), 0);
            bytes.extend(packet(60, 0x6a));
            assert_eq!(
                decode(&bytes).unwrap(),
                vec![vec![0x5a; length], vec![0x6a; 60]]
            );
        }
        let mut bytes = packet(60, 1);
        bytes[6] = 1; // opts2.RX_VLAN_TAG (r8152_rx_vlan_tag)
        assert!(decode(&bytes).is_err());
        bytes[..4].copy_from_slice(&0x7fffu32.to_le_bytes());
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn superspeed_32k_aggregate_keeps_each_frame_and_rejects_over_limit() {
        let mut bytes = Vec::new();
        for value in 0..21 {
            bytes.extend(packet(1500, value));
            bytes.resize(bytes.len().next_multiple_of(8), 0);
        }
        assert!(bytes.len() > 16384 && bytes.len() < AGGREGATE);
        let frames = decode(&bytes).unwrap();
        assert_eq!(frames.len(), 21);
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame, &vec![index as u8; 1500]);
        }
        assert!(decode(&vec![0; AGGREGATE + 1]).is_err());
    }
}
