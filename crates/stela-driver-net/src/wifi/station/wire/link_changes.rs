// SPDX-License-Identifier: GPL-2.0-only
// Layouts follow pinned Linux include/linux/ieee80211-eht.h; the readings
// follow net/mac80211/mlme.c (ieee80211_ml_reconfiguration,
// ieee80211_parse_adv_t2l). Source notices in wifi/THIRD_PARTY.md.
//! What an AP MLD's elements say of its links: the Reconfiguration Multi-Link
//! element and advertised TID-to-Link Mapping (IEEE 802.11be-2024 9.4.2.321.4
//! and 9.4.2.314).
use alloc::vec::Vec;

/// WLAN_EID_EXTENSION, WLAN_EID_EXT_EHT_MULTI_LINK and
/// WLAN_EID_EXT_TID_TO_LINK_MAPPING.
const EXTENSION: u8 = 255;
const MULTI_LINK: u8 = 107;
const TID_TO_LINK: u8 = 109;
/// `IEEE80211_ML_CONTROL_TYPE` and its `_RECONF`.
const TYPE: u16 = 0x0007;
const RECONFIGURATION: u16 = 2;
/// `IEEE80211_MLE_SUBELEM_PER_STA_PROFILE`.
const PER_STA_PROFILE: u8 = 0;
/// `IEEE80211_MLE_STA_RECONF_CONTROL_*`.
const LINK_ID: u16 = 0x000f;
const STA_ADDRESS: u16 = 0x0020;
const REMOVAL_TIMER: u16 = 0x0040;
const OPERATION_PARAMETERS: u16 = 0x0800;
/// `IEEE80211_MLD_MAX_NUM_LINKS`.
const MAX_LINKS: u16 = 15;
/// `IEEE80211_TTLM_MAX_CNT`.
const MAX_MAPPINGS: usize = 2;
/// `IEEE80211_TTLM_CONTROL_*` and `IEEE80211_TTLM_DIRECTION_BOTH`.
const DIRECTION: u8 = 0x03;
const BOTH_DIRECTIONS: u8 = 2;
const DEFAULT_MAP: u8 = 0x04;
const SWITCH_TIME: u8 = 0x08;
const EXPECTED_DURATION: u8 = 0x10;
const ONE_BYTE_MAPS: u8 = 0x20;
/// Every TID has a map.
const ALL_TIDS: u8 = 0xff;
const TIDS: usize = 8;

/// One advertised mapping, of every TID to `links`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub links: u16,
    /// The low partial TSF it takes effect at, zero when it stands already.
    pub switch_time: u16,
}

/// The advertised mapping an element's body after its ID was malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid;

/// Each element `id` of the extensions among `elements`, after its ID.
fn extensions(elements: &[u8], id: u8) -> impl Iterator<Item = &[u8]> {
    let mut rest = elements;
    core::iter::from_fn(move || {
        while let [element, length, tail @ ..] = rest {
            let body = tail.get(..usize::from(*length))?;
            rest = &tail[body.len()..];
            if *element == EXTENSION && body.first() == Some(&id) {
                return Some(&body[1..]);
            }
        }
        None
    })
}

/// `ieee80211_ml_reconfiguration`: the links the Reconfiguration element among
/// `elements` removes, with what each one's AP Removal Timer says. `None`
/// without such an element, or with a profile that says too little.
pub fn removals(elements: &[u8]) -> Option<Vec<(u8, u16)>> {
    let body = extensions(elements, MULTI_LINK).find(|body| {
        body.first_chunk()
            .is_some_and(|&control| u16::from_le_bytes(control) & TYPE == RECONFIGURATION)
    })?;
    let common = usize::from(*body.get(2)?);
    let mut rest = body.get(2 + common..)?;
    let mut removed = Vec::new();
    while let [id, length, tail @ ..] = rest {
        let sub = tail.get(..usize::from(*length))?;
        rest = &tail[sub.len()..];
        if *id != PER_STA_PROFILE {
            continue;
        }
        // `ieee80211_mle_reconf_sta_prof_size_ok`.
        let [low, high, information, ..] = *sub else {
            return None;
        };
        let control = u16::from_le_bytes([low, high]);
        let address = if control & STA_ADDRESS != 0 { 6 } else { 0 };
        let timer = usize::from(control & REMOVAL_TIMER != 0) * 2;
        let parameters = usize::from(control & OPERATION_PARAMETERS != 0) * 2;
        if usize::from(information) < 1 + address + timer + parameters
            || 2 + usize::from(information) > sub.len()
        {
            return None;
        }
        let link = control & LINK_ID;
        if link >= MAX_LINKS {
            continue;
        }
        let at = 3 + address;
        let left = if timer != 0 {
            u16::from_le_bytes([sub[at], sub[at + 1]])
        } else {
            0
        };
        removed.push((link as u8, left));
    }
    Some(removed)
}

/// `ieee80211_tid_to_link_map_size_ok`.
fn size_ok(body: &[u8]) -> bool {
    let Some(&control) = body.first() else {
        return false;
    };
    let mut needed = usize::from(control & SWITCH_TIME != 0) * 2
        + usize::from(control & EXPECTED_DURATION != 0) * 3;
    if control & DEFAULT_MAP == 0 {
        needed += 1;
        let Some(&presence) = body.get(1) else {
            return false;
        };
        let size = if control & ONE_BYTE_MAPS != 0 { 1 } else { 2 };
        needed += presence.count_ones() as usize * size;
    }
    body.len() > needed
}

/// `ieee80211_parse_adv_t2l` of an element `size_ok` took.
fn mapping(body: &[u8]) -> Result<Mapping, Invalid> {
    let control = body[0];
    if control & DIRECTION != BOTH_DIRECTIONS {
        return Err(Invalid);
    }
    let default = control & DEFAULT_MAP != 0;
    let mut at = 1 + usize::from(!default);
    let mut switch_time = 0;
    if control & SWITCH_TIME != 0 {
        // Zero says there is none, so a time of zero goes up by one.
        switch_time = u16::from_le_bytes([body[at], body[at + 1]]).max(1);
        at += 2;
    }
    if control & EXPECTED_DURATION != 0 {
        at += 3;
    }
    if default {
        return Ok(Mapping {
            links: u16::MAX,
            switch_time,
        });
    }
    if body[1] != ALL_TIDS {
        return Err(Invalid);
    }
    let size = if control & ONE_BYTE_MAPS != 0 { 1 } else { 2 };
    let read = |index: usize| {
        let map = &body[at + index * size..];
        u16::from(map[0]) | if size == 2 { u16::from(map[1]) << 8 } else { 0 }
    };
    let links = read(0);
    if links == 0 || (1..TIDS).any(|tid| read(tid) != links) {
        return Err(Invalid);
    }
    Ok(Mapping { links, switch_time })
}

/// The advertised mappings among `elements`, as many as mac80211 keeps.
pub fn mappings(elements: &[u8]) -> Result<Vec<Mapping>, Invalid> {
    extensions(elements, TID_TO_LINK)
        .filter(|body| size_ok(body))
        .take(MAX_MAPPINGS)
        .map(mapping)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn element(id: u8, body: &[u8]) -> Vec<u8> {
        [&[EXTENSION, body.len() as u8 + 1, id][..], body].concat()
    }

    #[test]
    fn a_reconfiguration_names_its_links_and_their_timers() {
        let mut body = vec![2, 0, 1];
        body.extend([PER_STA_PROFILE, 5, 5 | 0x40, 0, 3, 9, 0]);
        // No timer, an address in the way of nothing, and a link past the last.
        body.extend([PER_STA_PROFILE, 3, 3, 0, 1]);
        body.extend([PER_STA_PROFILE, 11, 7 | 0x60, 0, 9, 1, 2, 3, 4, 5, 6, 4, 0]);
        body.extend([PER_STA_PROFILE, 3, 15, 0, 1]);
        let removed = removals(&element(MULTI_LINK, &body)).unwrap();
        assert_eq!(removed, [(5, 9), (3, 0), (7, 4)]);
    }

    #[test]
    fn another_multi_link_type_or_a_short_profile_removes_nothing() {
        assert_eq!(removals(&element(MULTI_LINK, &[0, 0, 1])), None);
        assert_eq!(removals(&[]), None);
        let short = [2, 0, 1, PER_STA_PROFILE, 3, 0x45, 0, 3];
        assert_eq!(removals(&element(MULTI_LINK, &short)), None);
        let empty = removals(&element(MULTI_LINK, &[2, 0, 1])).unwrap();
        assert!(empty.is_empty(), "a cancelled removal");
    }

    #[test]
    fn a_mapping_takes_every_tid_to_one_set_of_links() {
        let mut body = vec![2 | 0x08 | 0x10 | 0x20, 0xff, 0, 0, 1, 2, 3];
        body.extend([8; 8]);
        let links = mappings(&element(TID_TO_LINK, &body)).unwrap();
        assert_eq!(
            links,
            [Mapping {
                links: 8,
                switch_time: 1
            }],
            "a switch time of zero goes up"
        );
        let wide: Vec<u8> = [2, 0xff].into_iter().chain([0x20, 0].repeat(8)).collect();
        assert_eq!(
            mappings(&element(TID_TO_LINK, &wide)).unwrap()[0].links,
            0x20
        );
        let default = [2 | 0x04 | 0x08, 5, 0];
        assert_eq!(
            mappings(&element(TID_TO_LINK, &default)).unwrap(),
            [Mapping {
                links: u16::MAX,
                switch_time: 5
            }]
        );
    }

    #[test]
    fn a_mapping_that_breaks_the_rules_is_refused_and_a_short_one_unseen() {
        let mut uneven = vec![2 | 0x20, 0xff];
        uneven.extend([8; 7]);
        uneven.push(4);
        assert_eq!(mappings(&element(TID_TO_LINK, &uneven)), Err(Invalid));
        let mut down = vec![0x20, 0xff];
        down.extend([8; 8]);
        assert_eq!(mappings(&element(TID_TO_LINK, &down)), Err(Invalid));
        let mut part = vec![2 | 0x20, 0x0f];
        part.extend([8; 4]);
        assert_eq!(mappings(&element(TID_TO_LINK, &part)), Err(Invalid));
        let mut none = vec![2 | 0x20, 0xff];
        none.extend([0; 8]);
        assert_eq!(mappings(&element(TID_TO_LINK, &none)), Err(Invalid));
        let short = [2 | 0x20, 0xff, 8];
        assert_eq!(mappings(&element(TID_TO_LINK, &short)), Ok(Vec::new()));
    }
}
