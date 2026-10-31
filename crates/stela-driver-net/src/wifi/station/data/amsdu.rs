// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2002-2005, Instant802 Networks, Inc.; 2005-2006, Devicescape
// Software, Inc.; 2006-2007 Jiri Benc; 2007 Johannes Berg; 2013-2014 Intel
// Mobile Communications GmbH; 2018-2026 Intel Corporation. See THIRD_PARTY.md.
//! A transmitted A-MSDU, built in place over a waiting QoS MPDU as
//! `ieee80211_amsdu_prepare_head` and `ieee80211_amsdu_aggregate` do, for a
//! device that keeps the MAC header and encrypts the MPDU itself.

/// A QoS header to the AP, the only form a station sends.
const HEADER: usize = 26;
const QOS_CONTROL: usize = 24;
const AMSDU: u8 = 0x80;

fn subframe_header(mpdu: &[u8]) -> [u8; 14] {
    let mut header = [0; 14];
    header[..6].copy_from_slice(&mpdu[16..22]);
    header[6..12].copy_from_slice(&mpdu[10..16]);
    header[12..14].copy_from_slice(&((mpdu.len() - HEADER) as u16).to_be_bytes());
    header
}

/// Make `mpdu`, one MSDU, the head of an A-MSDU: its body becomes the first
/// subframe, and its address 3 the BSSID that address 1 already is.
fn open(mpdu: &mut alloc::vec::Vec<u8>) {
    let header = subframe_header(mpdu);
    mpdu.splice(HEADER..HEADER, header);
    mpdu.copy_within(4..10, 16);
    mpdu[QOS_CONTROL] |= AMSDU;
}

/// Add `next`, a QoS MPDU of one MSDU, to `head`, padding the subframe before.
pub fn append(head: &mut alloc::vec::Vec<u8>, next: &[u8]) {
    if head[QOS_CONTROL] & AMSDU == 0 {
        open(head);
    }
    let pad = (4 - (head.len() - HEADER) % 4) % 4;
    head.resize(head.len() + pad, 0);
    head.extend_from_slice(&subframe_header(next));
    head.extend_from_slice(&next[HEADER..]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    fn mpdu(destination: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; HEADER];
        bytes[0] = 0x88;
        bytes[1] = 0x41;
        bytes[4..10].fill(0xa);
        bytes[10..16].fill(0xb);
        bytes[16..22].fill(destination);
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn each_msdu_becomes_a_padded_subframe_under_the_bssid() {
        let mut head = mpdu(1, &[7; 5]);
        append(&mut head, &mpdu(2, &[8; 3]));
        append(&mut head, &mpdu(3, &[9; 1]));
        assert_eq!(head[QOS_CONTROL] & AMSDU, AMSDU);
        assert_eq!(head[16..22], [0xa; 6]);
        let mut expected = Vec::new();
        for (destination, body, pad) in [(1, &[7; 5][..], 1), (2, &[8; 3], 3), (3, &[9; 1], 0)] {
            expected.extend([destination; 6]);
            expected.extend([0xb; 6]);
            expected.extend((body.len() as u16).to_be_bytes());
            expected.extend(body);
            expected.extend(vec![0; pad]);
        }
        assert_eq!(head[HEADER..], expected);
    }
}
