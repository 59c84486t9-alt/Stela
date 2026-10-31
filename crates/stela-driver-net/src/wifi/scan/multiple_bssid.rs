// SPDX-License-Identifier: GPL-2.0-only
// Adapted from Linux net/wireless/scan.c, net/mac80211/parse.c and
// include/net/cfg80211.h. Copyright 2003 Jouni Malinen; 2008 Johannes Berg;
// 2013-2015 Intel Mobile Communications GmbH; 2016-2017 Intel Deutschland GmbH;
// 2018-2026 Intel Corporation. Full source notices in THIRD_PARTY.md.
//! The nontransmitted BSSes of a Multiple BSSID set: `cfg80211_parse_mbssid_data`
//! makes a record of each one a frame names, on the elements `cfg80211_gen_new_ie`
//! inherits for it, and `ieee802_11_find_bssid_profile` finds a joined BSS's own
//! profile again in its transmitter's beacons. An AP MLD's element is not read
//! out of a profile, so a nontransmitted BSS joins on one link.

use super::result::{Bss, Profile};
use crate::{Mac, wifi::station::wire::multi_link};
use alloc::vec::Vec;

const SSID: u8 = 0;
/// `WLAN_EID_MULTIPLE_BSSID`.
const MULTIPLE_BSSID: u8 = 71;
/// `WLAN_EID_NON_TX_BSSID_CAP`.
const CAPABILITY: u8 = 83;
/// `WLAN_EID_MULTI_BSSID_IDX`.
const INDEX: u8 = 85;
/// `WLAN_EID_FRAGMENT`.
const FRAGMENT: u8 = 242;
/// `WLAN_EID_EXTENSION`.
const EXTENSION: u8 = 255;
/// `WLAN_EID_EXT_HE_CAPABILITY`.
const HE_CAPABILITY: u8 = 35;
/// `WLAN_EID_EXT_NON_INHERITANCE`.
const NON_INHERITANCE: u8 = 56;
/// The highest BSSID index cfg80211 reads.
const MAX_INDEX: u8 = 46;
/// An element this long may carry on in fragments.
const FULL_ELEMENT: usize = 255;

/// `for_each_element`, which ends at the first element that does not fit.
fn walk(mut bytes: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    core::iter::from_fn(move || {
        let [id, length, rest @ ..] = bytes else {
            return None;
        };
        let body = rest.get(..usize::from(*length))?;
        bytes = &rest[body.len()..];
        Some((*id, body))
    })
}

/// `cfg80211_find_elem_match` on an ID and its extension.
fn same(a: (u8, &[u8]), b: (u8, &[u8])) -> bool {
    a.0 == b.0 && (a.0 != EXTENSION || a.1.first() == b.1.first())
}

/// One profile among a frame's Multiple BSSID elements.
struct Found {
    indicator: u8,
    index: u8,
    capabilities: u16,
    elements: Vec<u8>,
}

/// `cfg80211_merge_profile`'s subelement body at `(element, start)`, with
/// whatever continues it in the next Multiple BSSID element.
fn merge(bodies: &[&[u8]], element: usize, sub: &[u8], last: bool) -> Vec<u8> {
    let mut merged = sub.to_vec();
    let mut last = last;
    for next in &bodies[element + 1..] {
        // cfg80211_get_profile_continuation.
        let Some((0, continued)) = next.get(1..).and_then(|subs| walk(subs).next()) else {
            break;
        };
        if !last || next.len() < 4 || continued.len() < 2 || continued[0] == CAPABILITY {
            break;
        }
        merged.extend_from_slice(continued);
        last = walk(&next[1..]).count() == 1;
    }
    merged
}

/// The valid profiles of `elements`, `cfg80211_parse_mbssid_data`'s two loops.
fn found(elements: &[u8]) -> Vec<Found> {
    let bodies: Vec<&[u8]> = walk(elements)
        .filter(|&(id, _)| id == MULTIPLE_BSSID)
        .map(|(_, body)| body)
        .collect();
    let mut profiles = Vec::new();
    for (element, body) in bodies.iter().enumerate() {
        if body.len() < 4 || !(1..=8).contains(&body[0]) {
            continue;
        }
        let subs: Vec<(u8, &[u8])> = walk(&body[1..]).collect();
        for (at, &(id, sub)) in subs.iter().enumerate() {
            if id != 0 || sub.len() < 4 || sub[0] != CAPABILITY || sub[1] != 2 {
                continue;
            }
            let merged = merge(&bodies, element, sub, at + 1 == subs.len());
            let index = walk(&merged)
                .find(|&(id, _)| id == INDEX)
                .and_then(|(_, index)| index.first().copied());
            let Some(index) = index.filter(|index| {
                (1..=MAX_INDEX).contains(index) && u16::from(*index) < 1 << body[0]
            }) else {
                continue;
            };
            profiles.push(Found {
                indicator: body[0],
                index,
                capabilities: u16::from_le_bytes([merged[2], merged[3]]),
                elements: merged,
            });
        }
    }
    profiles
}

/// `cfg80211_copy_elem_with_frags`.
fn copy(elements: &[(u8, &[u8])], at: usize, out: &mut Vec<u8>) {
    let (id, body) = elements[at];
    out.extend_from_slice(&[id, body.len() as u8]);
    out.extend_from_slice(body);
    if body.len() != FULL_ELEMENT {
        return;
    }
    for &(id, body) in &elements[at + 1..] {
        if id != FRAGMENT {
            break;
        }
        out.extend_from_slice(&[id, body.len() as u8]);
        out.extend_from_slice(body);
        if body.len() != FULL_ELEMENT {
            break;
        }
    }
}

/// `cfg80211_gen_new_ie`: the elements of a BSS whose profile is `profile` in
/// a frame carrying `parent`, in the parent's order and then the profile's.
fn generated(parent: &[u8], profile: &[u8]) -> Vec<u8> {
    let parents: Vec<(u8, &[u8])> = walk(parent).collect();
    let subs: Vec<(u8, &[u8])> = walk(profile).collect();
    let refused = subs
        .iter()
        .find(|(id, body)| *id == EXTENSION && body.first() == Some(&NON_INHERITANCE))
        .map(|(_, body)| &body[1..]);
    let mut out = Vec::new();
    for (at, &element) in parents.iter().enumerate() {
        let (id, body) = element;
        if id == FRAGMENT || (id == EXTENSION && body.is_empty()) {
            continue;
        }
        if !subs.iter().any(|&sub| same(sub, element)) {
            if multi_link::inherited(id, body, refused) {
                copy(&parents, at, &mut out);
            }
            continue;
        }
        if parents[..at].iter().any(|&earlier| same(earlier, element)) {
            continue;
        }
        for (position, &sub) in subs.iter().enumerate() {
            if same(sub, element) {
                copy(&subs, position, &mut out);
            }
        }
    }
    for (position, &(id, body)) in subs.iter().enumerate() {
        let skipped = id == CAPABILITY
            || id == FRAGMENT
            || (id == EXTENSION && body.first().is_none_or(|&ext| ext == NON_INHERITANCE));
        if !skipped && !parents.iter().any(|&parent| same(parent, (id, body))) {
            copy(&subs, position, &mut out);
        }
    }
    out
}

/// `cfg80211_gen_new_bssid`.
fn bssid_of(transmitter: Mac, indicator: u8, index: u8) -> Mac {
    let [a, b, c, d, e, f] = transmitter.0;
    let bssid = u64::from_be_bytes([0, 0, a, b, c, d, e, f]);
    let mask = (1u64 << indicator) - 1;
    let derived = (bssid & !mask) | ((bssid & mask) + u64::from(index)) & mask;
    let [_, _, a, b, c, d, e, f] = derived.to_be_bytes();
    Mac([a, b, c, d, e, f])
}

/// What each nontransmitted BSS `transmitted`'s frame names is, for the
/// drivers that set `SUPPORTS_MULTI_BSSID` and `SUPPORTS_ONLY_HE_MULTI_BSSID`.
pub fn nontransmitted(transmitted: &Bss) -> Vec<Bss> {
    let he = walk(&transmitted.elements)
        .any(|(id, body)| id == EXTENSION && body.first() == Some(&HE_CAPABILITY));
    if !he {
        return Vec::new();
    }
    let mut records = Vec::new();
    for profile in found(&transmitted.elements) {
        let elements = generated(&transmitted.elements, &profile.elements);
        if elements.is_empty() {
            continue;
        }
        let ssid = walk(&elements)
            .find(|&(id, _)| id == SSID)
            .map(|(_, ssid)| ssid.to_vec());
        records.push(Bss {
            bssid: bssid_of(transmitted.bssid, profile.indicator, profile.index),
            capabilities: profile.capabilities,
            ssid,
            elements,
            profile: Some(Profile {
                indicator: profile.indicator,
                index: profile.index,
            }),
            ..transmitted.clone()
        });
    }
    records
}

/// What a beacon says of a nontransmitted BSS.
pub struct Heard {
    pub capabilities: u16,
    pub elements: Vec<u8>,
}

/// `ieee802_11_find_bssid_profile`: `joined`'s share of a beacon carrying
/// `elements`, which an EMA AP names only every few beacons.
pub fn heard(joined: &Bss, elements: &[u8]) -> Option<Heard> {
    let wanted = joined.profile?;
    found(elements)
        .into_iter()
        .find(|profile| {
            profile.index == wanted.index
                && bssid_of(joined.transmitter, profile.indicator, profile.index) == joined.bssid
        })
        .map(|profile| Heard {
            capabilities: profile.capabilities,
            elements: generated(elements, &profile.elements),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::{
        Band, Channel, RadioStatus, RawRate,
        scan::{Ticket, result::Kind},
    };
    use alloc::vec;

    const AP: Mac = Mac([2, 3, 4, 5, 6, 0x07]);
    /// A TIM, for inheriting, and an HE capability, for reading profiles at all.
    const TIM: [u8; 6] = [5, 4, 0, 3, 0, 0];
    const HE: [u8; 4] = [255, 2, HE_CAPABILITY, 9];

    fn profile(index: u8, ssid: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut sub = vec![CAPABILITY, 2, 0x11, 0x04, INDEX, 3, index, 2, 1];
        sub.extend_from_slice(&[SSID, ssid.len() as u8]);
        sub.extend_from_slice(ssid);
        sub.extend_from_slice(extra);
        sub
    }

    fn set(indicator: u8, profiles: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![indicator];
        for sub in profiles {
            body.extend_from_slice(&[0, sub.len() as u8]);
            body.extend_from_slice(sub);
        }
        let mut element = vec![MULTIPLE_BSSID, body.len() as u8];
        element.extend_from_slice(&body);
        element
    }

    fn transmitted(extra: &[u8]) -> Bss {
        let mut elements = vec![SSID, 3];
        elements.extend_from_slice(b"top");
        elements.extend_from_slice(&TIM);
        elements.extend_from_slice(&HE);
        elements.extend_from_slice(extra);
        let channel = Channel {
            band: Band::Ghz5,
            number: 36,
            frequency_mhz: 5180,
        };
        Bss {
            ticket: Ticket(1),
            kind: Kind::Beacon,
            bssid: AP,
            transmitter: AP,
            timestamp: 0,
            beacon_interval: 100,
            capabilities: 0x0431,
            channel,
            observed: RadioStatus {
                band: channel.band,
                channel: channel.number,
                frequency_mhz: channel.frequency_mhz,
                signal_dbm: None,
                chain_signal_dbm: [None; 4],
                rate: RawRate {
                    layout: 0,
                    words: [0; 4],
                },
                rx_rate: None,
                tsf: None,
            },
            signal_dbm: None,
            ssid: Some(b"top".to_vec()),
            elements,
            profile: None,
        }
    }

    #[test]
    fn a_profile_gets_its_own_address_name_and_capabilities_and_inherits_the_rest() {
        let records = nontransmitted(&transmitted(&set(3, &[profile(1, b"side", &[])])));
        let [record] = records.as_slice() else {
            panic!("{records:?}");
        };
        assert_eq!(
            record.bssid,
            Mac([2, 3, 4, 5, 6, 0x00]),
            "wraps within its set"
        );
        assert_eq!(record.transmitter, AP);
        assert_eq!(record.ssid.as_deref(), Some(&b"side"[..]));
        assert_eq!(record.capabilities, 0x0411);
        assert_eq!(
            record.profile,
            Some(Profile {
                indicator: 3,
                index: 1
            })
        );
        let ids: Vec<u8> = walk(&record.elements).map(|(id, _)| id).collect();
        assert_eq!(
            ids,
            [SSID, 5, 255, INDEX],
            "no Multiple BSSID or capability"
        );
    }

    #[test]
    fn a_profile_refuses_what_it_will_not_inherit() {
        let refusal = [255, 5, NON_INHERITANCE, 1, 5, 1, HE_CAPABILITY];
        let records = nontransmitted(&transmitted(&set(2, &[profile(1, b"side", &refusal)])));
        let ids: Vec<u8> = walk(&records[0].elements).map(|(id, _)| id).collect();
        assert_eq!(ids, [SSID, INDEX]);
    }

    #[test]
    fn a_profile_runs_on_into_the_next_element() {
        let whole = profile(2, b"side", &[]);
        let (head, tail) = whole.split_at(9);
        let mut elements = set(3, &[head.to_vec()]);
        elements.extend(set(3, &[tail.to_vec()]));
        let records = nontransmitted(&transmitted(&elements));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ssid.as_deref(), Some(&b"side"[..]));
    }

    #[test]
    fn a_new_profile_in_the_next_element_stands_alone() {
        let mut elements = set(3, &[profile(1, b"one", &[])]);
        elements.extend(set(3, &[profile(2, b"two", &[])]));
        let records = nontransmitted(&transmitted(&elements));
        let names: Vec<_> = records
            .iter()
            .map(|bss| bss.ssid.clone().unwrap())
            .collect();
        assert_eq!(names, [b"one".to_vec(), b"two".to_vec()]);
    }

    #[test]
    fn indices_beyond_the_set_and_ones_without_he_name_nothing() {
        let beyond = transmitted(&set(1, &[profile(2, b"side", &[])]));
        assert!(nontransmitted(&beyond).is_empty());
        let mut old = transmitted(&set(3, &[profile(1, b"side", &[])]));
        let at = old.elements.windows(4).position(|w| w == HE).unwrap();
        old.elements.drain(at..at + 4);
        assert!(nontransmitted(&old).is_empty());
    }

    #[test]
    fn a_beacon_gives_a_joined_bss_its_own_share_or_nothing() {
        let frame = transmitted(&set(3, &[profile(1, b"one", &[]), profile(2, b"two", &[])]));
        let joined = nontransmitted(&frame).pop().unwrap();
        let share = heard(&joined, &frame.elements).unwrap();
        assert_eq!(share.capabilities, 0x0411);
        assert_eq!(walk(&share.elements).next(), Some((SSID, &b"two"[..])));
        let other = set(3, &[profile(1, b"one", &[])]);
        assert!(heard(&joined, &transmitted(&other).elements).is_none());
        assert!(heard(&frame, &frame.elements).is_none());
    }
}
