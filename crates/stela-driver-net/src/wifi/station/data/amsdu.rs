// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2002-2005, Instant802 Networks, Inc.; 2005-2006, Devicescape
// Software, Inc.; 2006-2007 Jiri Benc; 2007 Johannes Berg; 2013-2014 Intel
// Mobile Communications GmbH; 2018-2026 Intel Corporation. See THIRD_PARTY.md.
//! A transmitted A-MSDU, built in place over a waiting QoS MPDU as
//! `ieee80211_amsdu_prepare_head` and `ieee80211_amsdu_aggregate` do, for a
//! device that keeps the MAC header and encrypts the MPDU itself. Behind the
//! header each MPDU may hold `iv` bytes for the device to protect it under,
//! which stay there, outside the subframes.

/// A QoS header to the AP, the only form a station sends.
const HEADER: usize = 26;
const QOS_CONTROL: usize = 24;
const AMSDU: u8 = 0x80;
/// What an MSDU's QoS header and LLC add to its Ethernet frame.
pub const SUBFRAME_OVERHEAD: usize = HEADER + 8 - 14;

fn subframe_header(mpdu: &[u8], iv: usize) -> [u8; 14] {
    let mut header = [0; 14];
    header[..6].copy_from_slice(&mpdu[16..22]);
    header[6..12].copy_from_slice(&mpdu[10..16]);
    header[12..14].copy_from_slice(&((mpdu.len() - HEADER - iv) as u16).to_be_bytes());
    header
}

/// Make `mpdu`, one MSDU, the head of an A-MSDU: its body becomes the first
/// subframe, and its address 3 the BSSID that address 1 already is.
fn open(mpdu: &mut alloc::vec::Vec<u8>, iv: usize) {
    let header = subframe_header(mpdu, iv);
    mpdu.splice(HEADER + iv..HEADER + iv, header);
    mpdu.copy_within(4..10, 16);
    mpdu[QOS_CONTROL] |= AMSDU;
}

/// Add `next`, a QoS MPDU of one MSDU, to `head`, padding the subframe before.
pub fn append(head: &mut alloc::vec::Vec<u8>, next: &[u8], iv: usize) {
    if head[QOS_CONTROL] & AMSDU == 0 {
        open(head, iv);
    }
    let pad = (4 - (head.len() - HEADER - iv) % 4) % 4;
    head.resize(head.len() + pad, 0);
    head.extend_from_slice(&subframe_header(next, iv));
    head.extend_from_slice(&next[HEADER + iv..]);
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
        append(&mut head, &mpdu(2, &[8; 3]), 0);
        append(&mut head, &mpdu(3, &[9; 1]), 0);
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

    #[test]
    fn an_iv_stays_behind_the_header() {
        let mut head = mpdu(1, &[0xee; 8]);
        head.extend([7; 4]);
        let mut next = mpdu(2, &[0xdd; 8]);
        next.extend([8; 2]);
        append(&mut head, &next, 8);
        assert_eq!(head[HEADER..HEADER + 8], [0xee; 8], "the head's own");
        let body = &head[HEADER + 8..];
        assert_eq!(body[12..14], [0, 4]);
        assert_eq!(body[14..18], [7; 4]);
        assert_eq!(body[18..20], [0; 2], "padded to a word");
        assert_eq!(body[20..26], [2; 6]);
        assert_eq!(body[32..34], [0, 2]);
        assert_eq!(body[34..], [8; 2]);
    }
}
