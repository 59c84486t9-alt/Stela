// SPDX-License-Identifier: GPL-2.0-only
// Layouts follow pinned Linux include/linux/ieee80211-eht.h and
// include/linux/ieee80211.h; fragmentation follows net/wireless/scan.c
// (cfg80211_defragment_element, cfg80211_is_element_inherited) and
// net/mac80211/util.c (ieee80211_fragment_element); request profiles and
// response answers follow net/mac80211/mlme.c (ieee80211_assoc_add_ml_elem,
// ieee80211_add_non_inheritance_elem, ieee80211_assoc_config_link). Source
// notices in wifi/THIRD_PARTY.md.
//! The Basic Multi-Link element (IEEE 802.11be-2024 9.4.2.321.2) of an AP
//! MLD and of a non-AP MLD's authentication and association, its per-STA
//! profiles with their inheritance, and the affiliated APs a Reduced
//! Neighbor Report names through its MLD parameters (9.4.2.169.2).
use super::Error;
use crate::Mac;
use alloc::vec::Vec;

/// WLAN_EID_EXTENSION and WLAN_EID_EXT_EHT_MULTI_LINK.
const EXTENSION: u8 = 255;
const MULTI_LINK: u8 = 107;
/// WLAN_EID_FRAGMENT and IEEE80211_MLE_SUBELEM_FRAGMENT.
const FRAGMENT: u8 = 242;
const SUBELEMENT_FRAGMENT: u8 = 254;
/// IEEE80211_MLE_SUBELEM_PER_STA_PROFILE.
const PER_STA_PROFILE: u8 = 0;
const REDUCED_NEIGHBOR_REPORT: u8 = 201;
/// WLAN_EID_EXT_NON_INHERITANCE.
const NON_INHERITANCE: u8 = 56;

/// IEEE80211_ML_CONTROL_TYPE and its Basic variant.
const TYPE: u16 = 0x0007;
const BASIC: u16 = 0;
// IEEE80211_MLC_BASIC_PRES_*.
const LINK_ID: u16 = 0x0010;
const BSS_PARAMETERS_CHANGE_COUNT: u16 = 0x0020;
const MEDIUM_SYNC_DELAY: u16 = 0x0040;
const EML_CAPABILITIES: u16 = 0x0080;
const MLD_CAPABILITIES: u16 = 0x0100;
const MLD_ID: u16 = 0x0200;
const EXTENDED_MLD_CAPABILITIES: u16 = 0x0400;
const ENHANCED_CRITICAL_UPDATE: u16 = 0x0800;
// IEEE80211_MLE_STA_CONTROL_*.
const STA_LINK_ID: u16 = 0x000f;
const COMPLETE_PROFILE: u16 = 0x0010;
const STA_ADDRESS: u16 = 0x0020;
const BEACON_INTERVAL: u16 = 0x0040;
const TSF_OFFSET: u16 = 0x0080;
const DTIM_INFO: u16 = 0x0100;
const NSTR_LINK_PAIR: u16 = 0x0200;
const NSTR_BITMAP_SIZE: u16 = 0x0400;
const STA_BSS_PARAMETERS_CHANGE_COUNT: u16 = 0x0800;
const STA_ENHANCED_CRITICAL_UPDATE: u16 = 0x1000;
const AP_CONDUCTED_TX_POWER: u16 = 0x2000;

/// IEEE80211_MLD_MAX_NUM_LINKS.
pub const MAX_LINKS: usize = 15;
/// IEEE80211_EML_CAP_EMLSR_SUPP and IEEE80211_EML_CAP_EMLMR_SUPPORT, either
/// of which `ieee80211_assoc_add_ml_elem` advertises EML capabilities for.
pub const EML_SUPPORT: u16 = 0x0001 | 0x0080;

/// A Basic Multi-Link element.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Basic {
    /// The MLD MAC address.
    pub address: Mac,
    pub link_id: Option<u8>,
    pub bss_parameters_change_count: Option<u8>,
    pub medium_sync_delay: Option<u16>,
    pub eml_capabilities: Option<u16>,
    pub mld_capabilities: Option<u16>,
    pub mld_id: Option<u8>,
    pub extended_mld_capabilities: Option<u16>,
    pub enhanced_critical_update: Option<u8>,
    pub profiles: Vec<Profile>,
}

/// A per-STA profile: one affiliated STA's link and the frame contents it
/// carries for that link.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Profile {
    pub link_id: u8,
    /// Whether `body` holds the link's complete frame contents.
    pub complete: bool,
    /// The affiliated STA's or AP's own MAC address.
    pub address: Option<Mac>,
    pub beacon_interval: Option<u16>,
    pub tsf_offset: Option<u64>,
    /// The DTIM count and period.
    pub dtim: Option<(u8, u8)>,
    /// The NSTR indication bitmap, one or two bytes.
    pub nstr: Option<Vec<u8>>,
    pub bss_parameters_change_count: Option<u8>,
    pub enhanced_critical_update: Option<u8>,
    pub ap_conducted_tx_power: Option<u8>,
    /// The STA profile: the frame's fixed fields for the link (its
    /// capability information, and a response's status code) and elements.
    pub body: Vec<u8>,
}

/// An AP of the same AP MLD that a Reduced Neighbor Report names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Affiliated {
    pub link_id: u8,
    pub bssid: Mac,
    pub operating_class: u8,
    pub channel: u8,
    pub bss_parameters_change_count: u8,
}

fn take<'a>(rest: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
    let (head, tail) = rest.split_at_checked(count).ok_or(Error::Truncated)?;
    *rest = tail;
    Ok(head)
}
fn byte(rest: &mut &[u8]) -> Result<u8, Error> {
    Ok(take(rest, 1)?[0])
}
fn word(rest: &mut &[u8]) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(take(rest, 2)?.try_into().unwrap()))
}
fn mac(rest: &mut &[u8]) -> Result<Mac, Error> {
    Ok(Mac(take(rest, 6)?.try_into().unwrap()))
}

/// `cfg80211_defragment_element`: the data of the element at the start of
/// `rest`, with the fragments after it, and the elements that follow.
/// Fragments continue while the previous piece filled 255 bytes.
fn defragment(rest: &[u8], fragment: u8) -> Result<(Vec<u8>, &[u8]), Error> {
    let mut rest = rest;
    take(&mut rest, 1)?;
    let length = usize::from(byte(&mut rest)?);
    let mut data = take(&mut rest, length)?.to_vec();
    let mut full = length == 255;
    while full && rest.first() == Some(&fragment) {
        take(&mut rest, 1)?;
        let length = usize::from(byte(&mut rest)?);
        data.extend_from_slice(take(&mut rest, length)?);
        full = length == 255;
    }
    Ok((data, rest))
}

/// `ieee80211_fragment_element`: `data` as the element `id`, continued in
/// `fragment` elements past 255 bytes.
fn fragmented(out: &mut Vec<u8>, id: u8, fragment: u8, data: &[u8]) {
    let mut pieces = data.chunks(255);
    let first = pieces.next().unwrap_or_default();
    out.extend_from_slice(&[id, first.len() as u8]);
    out.extend_from_slice(first);
    for piece in pieces {
        out.extend_from_slice(&[fragment, piece.len() as u8]);
        out.extend_from_slice(piece);
    }
}

impl Basic {
    /// The first Basic Multi-Link element among `elements`, defragmented.
    pub fn find(elements: &[u8]) -> Result<Option<Self>, Error> {
        let mut rest = elements;
        while let [id, length, tail @ ..] = rest {
            if *id == EXTENSION && tail.first() == Some(&MULTI_LINK) {
                let (data, _) = defragment(rest, FRAGMENT)?;
                let body = &data[1..];
                // Another multi-link type is not this element.
                if body.len() >= 2 && u16::from_le_bytes([body[0], body[1]]) & TYPE == BASIC {
                    return Self::parse(body).map(Some);
                }
            }
            rest = tail.get(usize::from(*length)..).ok_or(Error::Truncated)?;
        }
        Ok(None)
    }

    /// The element's body after its extension ID, defragmented, checked as
    /// `ieee80211_mle_type_ok` and `ieee80211_mle_basic_sta_prof_size_ok`
    /// check it.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut rest = body;
        let control = word(&mut rest)?;
        if control & TYPE != BASIC {
            return Err(Error::Unsupported("multi-link element type"));
        }
        let length = usize::from(*rest.first().ok_or(Error::Truncated)?);
        let mut common = take(&mut rest, length)?;
        take(&mut common, 1)?;
        let address = mac(&mut common)?;
        let mut field = |bit: u16, bytes: usize| -> Result<Option<&[u8]>, Error> {
            if control & bit == 0 {
                return Ok(None);
            }
            take(&mut common, bytes)
                .map(Some)
                .map_err(|_| Error::Invalid("multi-link common info length"))
        };
        let as_word = |bytes: &[u8]| u16::from_le_bytes([bytes[0], bytes[1]]);
        let link_id = field(LINK_ID, 1)?.map(|b| b[0] & 0x0f);
        let bss_parameters_change_count = field(BSS_PARAMETERS_CHANGE_COUNT, 1)?.map(|b| b[0]);
        let medium_sync_delay = field(MEDIUM_SYNC_DELAY, 2)?.map(as_word);
        let eml_capabilities = field(EML_CAPABILITIES, 2)?.map(as_word);
        let mld_capabilities = field(MLD_CAPABILITIES, 2)?.map(as_word);
        let mld_id = field(MLD_ID, 1)?.map(|b| b[0]);
        let extended_mld_capabilities = field(EXTENDED_MLD_CAPABILITIES, 2)?.map(as_word);
        let enhanced_critical_update = field(ENHANCED_CRITICAL_UPDATE, 1)?.map(|b| b[0]);
        let mut profiles = Vec::new();
        while !rest.is_empty() {
            let (data, tail) = defragment(rest, SUBELEMENT_FRAGMENT)?;
            if rest[0] == PER_STA_PROFILE {
                if profiles.len() == MAX_LINKS {
                    return Err(Error::Invalid("multi-link per-STA profile count"));
                }
                profiles.push(Profile::parse(&data)?);
            }
            rest = tail;
        }
        Ok(Self {
            address,
            link_id,
            bss_parameters_change_count,
            medium_sync_delay,
            eml_capabilities,
            mld_capabilities,
            mld_id,
            extended_mld_capabilities,
            enhanced_critical_update,
            profiles,
        })
    }

    /// The whole element, its profiles and itself fragmented as
    /// `ieee80211_assoc_add_ml_elem` fragments them.
    pub fn encode(&self) -> Vec<u8> {
        let mut control = BASIC;
        let mut common = Vec::from(self.address.0);
        if let Some(id) = self.link_id {
            control |= LINK_ID;
            common.push(id);
        }
        if let Some(count) = self.bss_parameters_change_count {
            control |= BSS_PARAMETERS_CHANGE_COUNT;
            common.push(count);
        }
        for (bit, value) in [
            (MEDIUM_SYNC_DELAY, self.medium_sync_delay),
            (EML_CAPABILITIES, self.eml_capabilities),
            (MLD_CAPABILITIES, self.mld_capabilities),
        ] {
            if let Some(value) = value {
                control |= bit;
                common.extend_from_slice(&value.to_le_bytes());
            }
        }
        if let Some(id) = self.mld_id {
            control |= MLD_ID;
            common.push(id);
        }
        if let Some(value) = self.extended_mld_capabilities {
            control |= EXTENDED_MLD_CAPABILITIES;
            common.extend_from_slice(&value.to_le_bytes());
        }
        if let Some(update) = self.enhanced_critical_update {
            control |= ENHANCED_CRITICAL_UPDATE;
            common.push(update);
        }
        let mut data = Vec::from([MULTI_LINK]);
        data.extend_from_slice(&control.to_le_bytes());
        data.push(common.len() as u8 + 1);
        data.extend_from_slice(&common);
        for profile in &self.profiles {
            fragmented(
                &mut data,
                PER_STA_PROFILE,
                SUBELEMENT_FRAGMENT,
                &profile.encode(),
            );
        }
        let mut out = Vec::new();
        fragmented(&mut out, EXTENSION, FRAGMENT, &data);
        out
    }
}

impl Profile {
    fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;
        let control = word(&mut rest)?;
        let length = usize::from(*rest.first().ok_or(Error::Truncated)?);
        let mut info = take(&mut rest, length)?;
        take(&mut info, 1)?;
        let mut field = |bit: bool, bytes: usize| -> Result<Option<&[u8]>, Error> {
            if !bit {
                return Ok(None);
            }
            take(&mut info, bytes)
                .map(Some)
                .map_err(|_| Error::Invalid("multi-link STA info length"))
        };
        let complete = control & COMPLETE_PROFILE != 0;
        let address = field(control & STA_ADDRESS != 0, 6)?.map(|b| Mac(b.try_into().unwrap()));
        let beacon_interval =
            field(control & BEACON_INTERVAL != 0, 2)?.map(|b| u16::from_le_bytes([b[0], b[1]]));
        let tsf_offset =
            field(control & TSF_OFFSET != 0, 8)?.map(|b| u64::from_le_bytes(b.try_into().unwrap()));
        let dtim = field(control & DTIM_INFO != 0, 2)?.map(|b| (b[0], b[1]));
        let nstr_bytes = if control & NSTR_BITMAP_SIZE != 0 {
            2
        } else {
            1
        };
        let nstr =
            field(complete && control & NSTR_LINK_PAIR != 0, nstr_bytes)?.map(<[u8]>::to_vec);
        let bss_parameters_change_count =
            field(control & STA_BSS_PARAMETERS_CHANGE_COUNT != 0, 1)?.map(|b| b[0]);
        let enhanced_critical_update =
            field(control & STA_ENHANCED_CRITICAL_UPDATE != 0, 1)?.map(|b| b[0]);
        let ap_conducted_tx_power = field(control & AP_CONDUCTED_TX_POWER != 0, 1)?.map(|b| b[0]);
        Ok(Self {
            link_id: (control & STA_LINK_ID) as u8,
            complete,
            address,
            beacon_interval,
            tsf_offset,
            dtim,
            nstr,
            bss_parameters_change_count,
            enhanced_critical_update,
            ap_conducted_tx_power,
            body: rest.to_vec(),
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut control = u16::from(self.link_id) & STA_LINK_ID;
        let mut info = Vec::new();
        if let Some(address) = self.address {
            control |= STA_ADDRESS;
            info.extend_from_slice(&address.0);
        }
        if let Some(interval) = self.beacon_interval {
            control |= BEACON_INTERVAL;
            info.extend_from_slice(&interval.to_le_bytes());
        }
        if let Some(offset) = self.tsf_offset {
            control |= TSF_OFFSET;
            info.extend_from_slice(&offset.to_le_bytes());
        }
        if let Some((count, period)) = self.dtim {
            control |= DTIM_INFO;
            info.extend_from_slice(&[count, period]);
        }
        if self.complete {
            control |= COMPLETE_PROFILE;
            if let Some(nstr) = &self.nstr {
                control |= NSTR_LINK_PAIR;
                if nstr.len() == 2 {
                    control |= NSTR_BITMAP_SIZE;
                }
                info.extend_from_slice(nstr);
            }
        }
        for (bit, value) in [
            (
                STA_BSS_PARAMETERS_CHANGE_COUNT,
                self.bss_parameters_change_count,
            ),
            (STA_ENHANCED_CRITICAL_UPDATE, self.enhanced_critical_update),
            (AP_CONDUCTED_TX_POWER, self.ap_conducted_tx_power),
        ] {
            if let Some(value) = value {
                control |= bit;
                info.push(value);
            }
        }
        let mut out = control.to_le_bytes().to_vec();
        out.push(info.len() as u8 + 1);
        out.extend_from_slice(&info);
        out.extend_from_slice(&self.body);
        out
    }
}

/// Whether `ieee80211_add_link_elems` writes the element `id` (its
/// extension ID after 255) into a link's part of a request: the rates,
/// power capability, supported channels and the HT, VHT, HE, HE 6 GHz band
/// and EHT capabilities.
fn link_element(id: u8, body: &[u8]) -> bool {
    matches!(
        (id, body.first()),
        (1 | 50 | 33 | 36 | 45 | 191, _) | (EXTENSION, Some(35 | 59 | 108))
    )
}

/// The link elements `ieee80211_add_link_elems` records as present among
/// `elements` for the Non-Inheritance element, an extension as 256 plus its
/// ID; it records neither the rates nor the HE 6 GHz band capabilities.
fn present(elements: &[u8]) -> Vec<u16> {
    let mut present = Vec::new();
    let mut rest = elements;
    while let [id, length, tail @ ..] = rest {
        let Some(body) = tail.get(..usize::from(*length)) else {
            break;
        };
        rest = &tail[body.len()..];
        match (*id, body.first()) {
            (33 | 36 | 45 | 191, _) => present.push(u16::from(*id)),
            (EXTENSION, Some(&ext @ (35 | 108))) => present.push(256 + u16::from(ext)),
            _ => {}
        }
    }
    present.sort_unstable();
    present
}

/// `ieee80211_add_non_inheritance_elem`: the elements of `outer` that
/// `inner` lacks, or nothing when it lacks none.
fn non_inheritance(outer: &[u16], inner: &[u16]) -> Vec<u8> {
    let missing = || outer.iter().filter(|id| !inner.contains(id));
    let ids: Vec<u8> = missing()
        .filter(|&&id| id < 256)
        .map(|&id| id as u8)
        .collect();
    let extensions: Vec<u8> = missing()
        .filter(|&&id| id >= 256)
        .map(|&id| id as u8)
        .collect();
    if ids.is_empty() && extensions.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::from([
        EXTENSION,
        (3 + ids.len() + extensions.len()) as u8,
        NON_INHERITANCE,
        ids.len() as u8,
    ]);
    out.extend_from_slice(&ids);
    out.push(extensions.len() as u8);
    out.extend_from_slice(&extensions);
    out
}

/// `cfg80211_is_element_inherited`: whether a per-STA profile whose
/// Non-Inheritance element is `refused` takes the outer element `id`.
fn inherited(id: u8, body: &[u8], refused: Option<&[u8]>) -> bool {
    // WLAN_EID_MULTIPLE_BSSID and a multi-link element are never inherited.
    if id == 71 || (id == EXTENSION && body.first() == Some(&MULTI_LINK)) {
        return false;
    }
    let Some(refused) = refused else {
        return true;
    };
    let (list, extension) = if id == EXTENSION {
        let Some(&ext) = body.first() else {
            return true;
        };
        let skip = 1 + usize::from(refused.first().copied().unwrap_or(0));
        (refused.get(skip..), ext)
    } else {
        (Some(refused), id)
    };
    list.and_then(|list| {
        let count = usize::from(*list.first()?);
        list.get(1..1 + count)
    })
    .is_none_or(|ids| !ids.contains(&extension))
}

/// The elements a per-STA profile's `elements` stand for in a frame whose
/// own elements are `outer`: its own, then each outer element of an ID it
/// lacks that its Non-Inheritance element does not refuse, as
/// `ieee802_11_parse_elems_full` merges a link's profile.
pub fn merged(elements: &[u8], outer: &[u8]) -> Result<Vec<u8>, Error> {
    let own = split(elements)?;
    let refused = own
        .iter()
        .find(|(id, body)| *id == EXTENSION && body.first() == Some(&NON_INHERITANCE))
        .map(|(_, body)| &body[1..]);
    let mut out = Vec::new();
    for &(id, body) in &own {
        if !(id == EXTENSION && body.first() == Some(&NON_INHERITANCE)) {
            out.extend_from_slice(&[id, body.len() as u8]);
            out.extend_from_slice(body);
        }
    }
    let same = |(a, x): (u8, &[u8]), (b, y): (u8, &[u8])| {
        a == b && (a != EXTENSION || x.first() == y.first())
    };
    for &(id, body) in &split(outer)? {
        if !own.iter().any(|&element| same(element, (id, body))) && inherited(id, body, refused) {
            out.extend_from_slice(&[id, body.len() as u8]);
            out.extend_from_slice(body);
        }
    }
    Ok(out)
}

fn split(elements: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut parts = Vec::new();
    let mut rest = elements;
    while let [id, length, tail @ ..] = rest {
        let body = tail.get(..usize::from(*length)).ok_or(Error::Truncated)?;
        parts.push((*id, body));
        rest = &tail[body.len()..];
    }
    if !rest.is_empty() {
        return Err(Error::Truncated);
    }
    Ok(parts)
}

/// One other link a non-AP MLD's association requests.
#[derive(Clone, Copy, Debug)]
pub struct Requested<'a> {
    pub link_id: u8,
    /// The station's address on the link.
    pub address: Mac,
    /// The capability field the link's own association would carry.
    pub capability: u16,
    /// The elements the link's own association request would carry.
    pub elements: &'a [u8],
}

/// `ieee80211_assoc_add_ml_elem`: the Basic Multi-Link element of the
/// station MLD `address` for an association request whose own elements are
/// `outer`. It advertises the MLD capabilities and, when they support EMLSR
/// or EMLMR, the EML capabilities, and requests each of `links` in a
/// complete per-STA profile: the station's link address, the link's
/// capability and link elements, and a Non-Inheritance element for the
/// outer link elements the link lacks.
pub fn association_request(
    address: Mac,
    mld_capabilities: u16,
    eml_capabilities: u16,
    outer: &[u8],
    links: &[Requested<'_>],
) -> Vec<u8> {
    let outer_present = present(outer);
    let profiles = links
        .iter()
        .map(|link| {
            let mut body = link.capability.to_le_bytes().to_vec();
            let mut rest = link.elements;
            while let [id, length, tail @ ..] = rest {
                let Some(element) = tail.get(..usize::from(*length)) else {
                    break;
                };
                if link_element(*id, element) {
                    body.extend_from_slice(&[*id, *length]);
                    body.extend_from_slice(element);
                }
                rest = &tail[element.len()..];
            }
            body.extend(non_inheritance(&outer_present, &present(link.elements)));
            Profile {
                link_id: link.link_id,
                complete: true,
                address: Some(link.address),
                body,
                ..Profile::default()
            }
        })
        .collect();
    Basic {
        address,
        eml_capabilities: (eml_capabilities & EML_SUPPORT != 0).then_some(eml_capabilities),
        mld_capabilities: Some(mld_capabilities),
        profiles,
        ..Basic::default()
    }
    .encode()
}

/// What an AP MLD's association response says of one requested link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Answer {
    pub link_id: u8,
    pub status: u16,
    /// The link's capability field.
    pub capability: u16,
    /// The link's elements, the response's own inherited.
    pub elements: Vec<u8>,
}

/// The AP MLD `ap`'s Basic Multi-Link element in an association response
/// with `elements`, and its answer for each link of `requested`, as
/// `ieee80211_rx_mgmt_assoc_resp` and `ieee80211_assoc_config_link` take
/// them: the element must name the AP MLD, each requested link needs a
/// complete profile, and an accepted one its BSS parameters change count.
pub fn association_response(
    ap: Mac,
    elements: &[u8],
    requested: &[u8],
) -> Result<(Basic, Vec<Answer>), Error> {
    let basic = Basic::find(elements)?.ok_or(Error::Invalid("multi-link response element"))?;
    if basic.address != ap {
        return Err(Error::WrongPeer);
    }
    let answers = requested
        .iter()
        .map(|&link_id| {
            let profile = basic
                .profiles
                .iter()
                .find(|profile| profile.link_id == link_id && profile.complete)
                .ok_or(Error::Invalid("link missing from association response"))?;
            let mut body = &profile.body[..];
            let capability = word(&mut body)?;
            let status = word(&mut body)?;
            if status == 0 && profile.bss_parameters_change_count.is_none() {
                return Err(Error::Invalid(
                    "per-STA profile BSS parameters change count",
                ));
            }
            Ok(Answer {
                link_id,
                status,
                capability,
                elements: merged(body, elements)?,
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok((basic, answers))
}

/// The authentication frame's Basic Multi-Link element of a non-AP MLD:
/// its MLD address alone (IEEE 802.11be-2024 35.3.5.4).
pub fn authentication(address: Mac) -> Vec<u8> {
    Basic {
        address,
        ..Basic::default()
    }
    .encode()
}

/// The APs of the reporting AP's own MLD that `elements`' Reduced Neighbor
/// Reports name: TBTT information carrying MLD parameters whose AP MLD ID is
/// 0, as wpa_supplicant's `wpa_bss_parse_ml_rnr_ap_info` takes them, skipping
/// disabled links (IEEE80211_RNR_MLD_PARAMS_DISABLED_LINK).
pub fn affiliated(elements: &[u8]) -> Result<Vec<Affiliated>, Error> {
    // ieee80211_tbtt_info_ge_11 up to its MLD parameters.
    const MLD_PARAMETERS_END: usize = 16;
    let mut found = Vec::new();
    let mut rest = elements;
    while let [id, length, tail @ ..] = rest {
        let body = tail.get(..usize::from(*length)).ok_or(Error::Truncated)?;
        rest = &tail[usize::from(*length)..];
        if *id != REDUCED_NEIGHBOR_REPORT {
            continue;
        }
        let mut infos = body;
        while let [header, length, operating_class, channel, more @ ..] = infos {
            let count = usize::from(header >> 4) + 1;
            let length = usize::from(*length);
            let (entries, more) = more
                .split_at_checked(count * length)
                .ok_or(Error::Invalid("reduced neighbor report length"))?;
            infos = more;
            // TBTT information field type 0 with MLD parameters.
            if header & 0x03 != 0 || length < MLD_PARAMETERS_END {
                continue;
            }
            for entry in entries.chunks_exact(length) {
                let parameters = u16::from_le_bytes([entry[14], entry[15]]);
                if entry[13] != 0 || parameters & 0x2000 != 0 {
                    continue;
                }
                let link = Affiliated {
                    link_id: (parameters & 0x000f) as u8,
                    bssid: Mac(entry[1..7].try_into().unwrap()),
                    operating_class: *operating_class,
                    channel: *channel,
                    bss_parameters_change_count: (parameters >> 4) as u8,
                };
                if !found.iter().any(|f: &Affiliated| f.link_id == link.link_id) {
                    found.push(link);
                }
            }
        }
        if !infos.is_empty() {
            return Err(Error::Invalid("reduced neighbor report length"));
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests;
