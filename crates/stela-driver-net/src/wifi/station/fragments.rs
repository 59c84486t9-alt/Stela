// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2002-2005, Instant802 Networks, Inc.; 2005-2006, Devicescape
// Software, Inc.; 2006-2007 Jiri Benc; 2007-2010 Johannes Berg; 2013-2014 Intel
// Mobile Communications GmbH; 2015-2017 Intel Deutschland GmbH; 2018-2026 Intel
// Corporation. See THIRD_PARTY.md.
//! MSDU reassembly, as `ieee80211_rx_h_defragment`. Fragments of a protected
//! MSDU must carry consecutive packet numbers under one key, which keeps out
//! the mixed key and fragment cache attacks. A frame that fails this is dropped.
use crate::{
    Mac,
    wifi::{
        RadioStatus,
        frame::{Header, Mpdu},
        security::{Integrity, KeyIdentity, KeySlot, PacketNumber, SecurityStatus},
    },
};
use alloc::vec::Vec;

/// `IEEE80211_FRAGMENT_MAX`.
const ENTRIES: usize = 4;
/// How long an MSDU may take to arrive, the two seconds of
/// `ieee80211_reassemble_find`.
const LIFETIME_US: u64 = 2_000_000;
const MORE_FRAGMENTS: u8 = 0x04;

/// `ieee80211_fragment_entry`: the MSDU so far under its first header.
struct Entry {
    frame: Vec<u8>,
    radio: RadioStatus,
    sequence: u16,
    last: u8,
    started: u64,
    receiver: Mac,
    transmitter: Option<Mac>,
    key: Option<KeyIdentity>,
    pn: Option<PacketNumber>,
}

/// `ieee80211_fragment_cache`.
#[derive(Default)]
pub struct Fragments {
    entries: [Option<Entry>; ENTRIES],
    next: usize,
}

impl Fragments {
    /// Drop everything, as a departure or a new key does.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// `frame`, a fragment of unicast data, with `slot` its installed key.
    /// The whole MSDU comes back with the last fragment, as a frame that
    /// `Station::receive_msdu_refs` authorizes under that fragment's number.
    pub fn add(&mut self, frame: &Mpdu, slot: Option<&mut KeySlot>, now: u64) -> Option<Mpdu> {
        let header = frame.header();
        if header.receiver.is_multicast() {
            return None;
        }
        let control = u16::from_le_bytes(frame.bytes()[22..24].try_into().unwrap());
        let (sequence, number) = (control >> 4, (control & 15) as u8);
        let more = frame.bytes()[1] & MORE_FRAGMENTS != 0;
        let key = frame.security.key;
        let (payload, pn) = match slot {
            Some(slot) if key.is_some() && slot.installed() == key => {
                let (payload, pn) = slot.fragment_payload(frame, !more).ok()?;
                (payload, Some(pn))
            }
            None if key.is_none() && !header.protected() => (&frame.bytes()[header.length..], None),
            _ => return None,
        };
        if number == 0 {
            self.begin(frame, header, payload, sequence, now, pn);
            return None;
        }
        let index = self.find(sequence, number, header, now)?;
        let entry = self.entries[index].as_mut()?;
        let follows = match (entry.pn, pn) {
            (Some(previous), Some(pn)) => previous.value() + 1 == pn.value(),
            (None, None) => true,
            _ => false,
        };
        if !follows || entry.key != key {
            return None;
        }
        if entry.frame.len() + payload.len() > usize::from(u16::MAX) {
            self.entries[index] = None;
            return None;
        }
        entry.frame.extend_from_slice(payload);
        entry.last = number;
        entry.pn = pn;
        if more {
            return None;
        }
        let entry = self.entries[index].take()?;
        let protected = entry.key.is_some();
        let security = SecurityStatus {
            key: entry.key,
            pn: entry.pn,
            decrypted: protected,
            integrity: if protected {
                Integrity::Verified
            } else {
                Integrity::Unknown
            },
            iv_stripped: protected,
            mic_stripped: protected,
            ..SecurityStatus::default()
        };
        Mpdu::new(entry.frame, entry.radio, security).ok()
    }

    /// `ieee80211_reassemble_add`, overwriting the oldest.
    fn begin(
        &mut self,
        frame: &Mpdu,
        header: &Header,
        payload: &[u8],
        sequence: u16,
        now: u64,
        pn: Option<PacketNumber>,
    ) {
        let mut bytes = Vec::with_capacity(header.length + payload.len());
        bytes.extend_from_slice(&frame.bytes()[..header.length]);
        bytes.extend_from_slice(payload);
        bytes[1] &= !MORE_FRAGMENTS;
        self.entries[self.next] = Some(Entry {
            frame: bytes,
            radio: frame.radio.clone(),
            sequence,
            last: 0,
            started: now,
            receiver: header.receiver,
            transmitter: header.transmitter,
            key: frame.security.key,
            pn,
        });
        self.next = (self.next + 1) % ENTRIES;
    }

    /// `ieee80211_reassemble_find`, newest first.
    fn find(&mut self, sequence: u16, number: u8, header: &Header, now: u64) -> Option<usize> {
        for age in 1..=ENTRIES {
            let index = (self.next + ENTRIES - age) % ENTRIES;
            let Some(entry) = &self.entries[index] else {
                continue;
            };
            if entry.sequence != sequence
                || entry.last + 1 != number
                || entry.receiver != header.receiver
                || entry.transmitter != header.transmitter
            {
                continue;
            }
            if now.saturating_sub(entry.started) > LIFETIME_US {
                self.entries[index] = None;
                continue;
            }
            return Some(index);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::{Band, RawRate};

    const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const PEER: [u8; 6] = [2, 0, 0, 0, 0, 2];

    fn radio() -> RadioStatus {
        RadioStatus {
            band: Band::Ghz5,
            channel: 36,
            frequency_mhz: 5180,
            signal_dbm: None,
            chain_signal_dbm: [None; 4],
            rate: RawRate {
                layout: 1,
                words: [0; 4],
            },
            rx_rate: None,
            tsf: None,
        }
    }

    /// An open frame's fragment `number` of `sequence`, carrying one byte.
    fn open(sequence: u16, number: u8, more: bool) -> Mpdu {
        let mut bytes = vec![0; 26];
        bytes[0] = 0x88;
        bytes[1] = 0x02 | u8::from(more) << 2;
        bytes[4..10].copy_from_slice(&LOCAL);
        bytes[10..16].copy_from_slice(&PEER);
        bytes[16..22].copy_from_slice(&PEER);
        bytes[22..24].copy_from_slice(&(sequence << 4 | u16::from(number)).to_le_bytes());
        bytes.push(number);
        Mpdu::new(bytes, radio(), SecurityStatus::default()).unwrap()
    }

    #[test]
    fn the_whole_msdu_loses_the_marks_of_its_fragments() {
        let mut fragments = Fragments::default();
        assert!(fragments.add(&open(7, 0, true), None, 0).is_none());
        let whole = fragments.add(&open(7, 1, false), None, 1).unwrap();
        assert_eq!(whole.bytes()[26..], [0, 1]);
        assert!(!whole.header().fragmented());
        assert_eq!(whole.bytes()[22..24], (7u16 << 4).to_le_bytes());
    }

    #[test]
    fn an_msdu_older_than_two_seconds_is_gone() {
        let mut fragments = Fragments::default();
        assert!(fragments.add(&open(7, 0, true), None, 0).is_none());
        assert!(fragments.add(&open(7, 1, false), None, 2_000_001).is_none());
    }

    #[test]
    fn a_fifth_msdu_replaces_the_oldest() {
        let mut fragments = Fragments::default();
        for sequence in 0..5 {
            assert!(fragments.add(&open(sequence, 0, true), None, 0).is_none());
        }
        assert!(fragments.add(&open(0, 1, false), None, 0).is_none());
        assert!(fragments.add(&open(4, 1, false), None, 0).is_some());
        assert!(fragments.add(&open(1, 1, false), None, 0).is_some());
    }

    #[test]
    fn multicast_fragments_are_not_gathered() {
        let mut fragments = Fragments::default();
        let mut bytes = open(7, 0, true).bytes().to_vec();
        bytes[4] |= 1;
        let multicast = Mpdu::new(bytes, radio(), SecurityStatus::default()).unwrap();
        assert!(fragments.add(&multicast, None, 0).is_none());
        assert!(fragments.add(&open(7, 1, false), None, 0).is_none());
    }
}
