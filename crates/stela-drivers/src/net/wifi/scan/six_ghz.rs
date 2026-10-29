// SPDX-License-Identifier: GPL-2.0-only
// Adapted from Linux net/wireless/scan.c (cfg80211_scan, cfg80211_scan_6ghz,
// cfg80211_parse_colocated_ap): Copyright 2008 Johannes Berg;
// 2013-2014 Intel Mobile Communications GmbH; 2016 Intel Deutschland GmbH;
// 2018-2025 Intel Corporation. See THIRD_PARTY.md.
//! The split 6 GHz scan of WIPHY_FLAG_SPLIT_SCAN_6GHZ drivers such as mt7925:
//! the other bands first, then the 6 GHz channels the known BSSes' Reduced
//! Neighbor Reports and the PSC rule select.

use super::{super::network::SSID_BYTES, Error, MAX_SIX_GHZ, Request, SixGhz, result};
use crate::net::{
    Mac,
    wifi::{Band, Channel},
};
use alloc::vec::Vec;

const SSID: u8 = 0;
const REDUCED_NEIGHBOR_REPORT: u8 = 201;
const TBTT_HDR_TYPE: u8 = 0x03;
const TBTT_HDR_COUNT_SHIFT: u8 = 4;
const TBTT_INFO_TYPE_TBTT: u8 = 0;
const SAME_SSID: u8 = 0x02;
const MULTI_BSSID: u8 = 0x04;
const TRANSMITTED_BSSID: u8 = 0x08;
const COLOC_ESS: u8 = 0x10;
const PROBE_ACTIVE: u8 = 0x20;
const COLOC_AP: u8 = 0x40;
const PSD_RESERVED: i8 = -128;
const MLD_DISABLED_LINK: u16 = 0x2000;
// ieee80211_tbtt_info_7_8_9 and ieee80211_tbtt_info_ge_11 field ends.
const SHORT_BSS_PARAMS_END: usize = 8;
const SHORT_LENGTH: usize = 9;
const LONG_BSS_PARAMS_END: usize = 12;
const LONG_PSD_END: usize = 13;
const LONG_MLD_END: usize = 16;

/// The scan request's NL80211_SCAN_FLAG_COLOCATED_6GHZ and BSSID.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub colocated: bool,
    pub bssid: Option<Mac>,
}

/// `struct cfg80211_colocated_ap`: a 6 GHz AP another BSS reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Colocated {
    pub bssid: Mac,
    pub channel: u8,
    pub ssid: Option<Vec<u8>>,
    pub short_ssid: Option<u32>,
    pub unsolicited_probe: bool,
    pub multi_bss: bool,
    pub transmitted_bssid: bool,
    pub colocated_ess: bool,
    pub psd_20: i8,
}

/// The short SSID, `~crc32_le(~0, ssid)`.
pub fn short_ssid(ssid: &[u8]) -> u32 {
    crate::net::wifi::security::wep::crc32(ssid)
}

/// `cfg80211_channel_is_psc`.
pub fn is_psc(channel: Channel) -> bool {
    channel.band == Band::Ghz6 && channel.number % 16 == 5
}

fn ssid(elements: &[u8]) -> Option<&[u8]> {
    let (_, ssid) = result::elements(elements)
        .ok()?
        .into_iter()
        .find(|(id, _)| *id == SSID)?;
    (ssid.len() <= SSID_BYTES).then_some(ssid)
}

/// `cfg80211_parse_colocated_ap`: the 6 GHz APs a BSS's RNR elements report
/// as colocated, or none when the reporter has no SSID or an RNR is malformed.
pub fn colocated(elements: &[u8]) -> Vec<Colocated> {
    let Some(reporter) = ssid(elements) else {
        return Vec::new();
    };
    let Ok(parsed) = result::elements(elements) else {
        return Vec::new();
    };
    let mut list = Vec::new();
    for (_, mut rest) in parsed
        .into_iter()
        .filter(|(id, _)| *id == REDUCED_NEIGHBOR_REPORT)
    {
        while let [header, length, op_class, channel, tail @ ..] = rest {
            let count = usize::from(header >> TBTT_HDR_COUNT_SHIFT) + 1;
            let length = usize::from(*length);
            let Some((entries, tail)) = tail.split_at_checked(count * length) else {
                return Vec::new();
            };
            rest = tail;
            // ieee80211_operating_class_to_band: 131..=135 and 137 are 6 GHz.
            let six = matches!(op_class, 131..=135 | 137);
            if header & TBTT_HDR_TYPE != TBTT_INFO_TYPE_TBTT
                || !six
                || !(length == SHORT_BSS_PARAMS_END
                    || length == SHORT_LENGTH
                    || length >= LONG_BSS_PARAMS_END)
            {
                continue;
            }
            for entry in entries.chunks_exact(length) {
                let Some(ap) = parse(entry, *channel, reporter) else {
                    continue;
                };
                // Don't add duplicate BSSIDs on the same channel.
                if !list
                    .iter()
                    .any(|c: &Colocated| c.bssid == ap.bssid && c.channel == ap.channel)
                {
                    list.push(ap);
                }
            }
        }
        if !rest.is_empty() {
            return Vec::new();
        }
    }
    list
}

/// `cfg80211_parse_ap_info` and `cfg80211_parse_bss_param`.
fn parse(entry: &[u8], channel: u8, reporter: &[u8]) -> Option<Colocated> {
    let bssid = Mac(entry[1..7].try_into().unwrap());
    let (params, short, psd_20) = if entry.len() > SHORT_LENGTH {
        if entry.len() >= LONG_MLD_END
            && u16::from_le_bytes([entry[14], entry[15]]) & MLD_DISABLED_LINK != 0
        {
            return None;
        }
        let psd = if entry.len() >= LONG_PSD_END {
            entry[12] as i8
        } else {
            PSD_RESERVED
        };
        let short = u32::from_le_bytes(entry[7..11].try_into().unwrap());
        (entry[11], Some(short), psd)
    } else {
        let psd = if entry.len() == SHORT_LENGTH {
            entry[8] as i8
        } else {
            PSD_RESERVED
        };
        (entry[7], None, psd)
    };
    if bssid.is_multicast() || bssid.0 == [0; 6] || params & COLOC_AP == 0 {
        return None;
    }
    let same = params & SAME_SSID != 0;
    Some(Colocated {
        bssid,
        channel,
        ssid: same.then(|| reporter.to_vec()),
        short_ssid: if same {
            Some(short_ssid(reporter))
        } else {
            short
        },
        unsolicited_probe: params & PROBE_ACTIVE != 0,
        multi_bss: params & MULTI_BSSID != 0,
        transmitted_bssid: params & TRANSMITTED_BSSID != 0,
        colocated_ess: params & COLOC_ESS != 0,
        psd_20,
    })
}

/// `cfg80211_find_ssid_match`.
fn matches(ap: &Colocated, ssids: &[Vec<u8>]) -> bool {
    ssids.iter().any(|ssid| {
        if ssid.is_empty() {
            return !(ap.multi_bss && !ap.transmitted_bssid);
        }
        match &ap.ssid {
            Some(own) if !own.is_empty() && own.len() == ssid.len() => own == ssid,
            _ => ap.short_ssid == Some(short_ssid(ssid)),
        }
    })
}

/// `cfg80211_scan`'s first part: every channel outside 6 GHz, or none when the
/// request asks only for 6 GHz.
pub fn first_part(request: &Request) -> Result<Option<Request>, Error> {
    let channels: Vec<Channel> = request
        .channels()
        .iter()
        .copied()
        .filter(|channel| channel.band != Band::Ghz6)
        .collect();
    if channels.is_empty() {
        return Ok(None);
    }
    Request::new(
        channels,
        request.ssids().to_vec(),
        request.extra_elements().to_vec(),
    )
    .map(Some)
}

/// `cfg80211_scan_6ghz`: the 6 GHz part after `known`, the BSSes found so
/// far, or none when it selects no channel and the scan is done.
pub fn second_part<'a>(
    request: &Request,
    options: Options,
    known: impl IntoIterator<Item = &'a result::Bss>,
) -> Result<Option<Request>, Error> {
    let mut aps = Vec::new();
    if options.colocated {
        for bss in known {
            aps.extend(colocated(&bss.elements));
            // A requested 6 GHz BSSID already known is probed directly.
            if options.bssid != Some(bss.bssid) || bss.channel.band != Band::Ghz6 {
                continue;
            }
            let (Some(own), Ok(channel)) = (ssid(&bss.elements), u8::try_from(bss.channel.number))
            else {
                continue;
            };
            aps.push(Colocated {
                bssid: bss.bssid,
                channel,
                ssid: Some(own.to_vec()),
                short_ssid: Some(short_ssid(own)),
                unsolicited_probe: false,
                multi_bss: false,
                transmitted_bssid: false,
                colocated_ess: false,
                psd_20: 0,
            });
        }
    }
    let ssids = request.ssids();
    // A direct scan for one SSID whose ESS is all colocated skips the PSCs.
    let need_psc = !(ssids.len() == 1
        && !ssids[0].is_empty()
        && aps.iter().any(|ap| ap.colocated_ess && matches(ap, ssids)));
    let mut channels: Vec<Channel> = Vec::new();
    let mut add = |channel: Channel| match channels.iter().position(|c| *c == channel) {
        Some(index) => index,
        None => {
            channels.push(channel);
            channels.len() - 1
        }
    };
    for &channel in request.channels() {
        if channel.band == Band::Ghz6 && ((need_psc && is_psc(channel)) || !options.colocated) {
            add(channel);
        }
    }
    let mut targets = Vec::new();
    for ap in &aps {
        let Some(&channel) = request
            .channels()
            .iter()
            .find(|channel| channel.band == Band::Ghz6 && channel.number == u16::from(ap.channel))
        else {
            continue;
        };
        if (!ssids.is_empty() && !matches(ap, ssids))
            || options.bssid.is_some_and(|bssid| bssid != ap.bssid)
            || (ssids.is_empty() && ap.multi_bss && !ap.transmitted_bssid)
        {
            continue;
        }
        // The firmware takes only so many targets, as mt76 truncates its RNR list.
        if targets.len() == MAX_SIX_GHZ {
            break;
        }
        targets.push(SixGhz {
            channel_index: add(channel),
            bssid: ap.bssid,
            short_ssid: ap.short_ssid,
            unsolicited_probe: ap.unsolicited_probe,
            psc_no_listen: is_psc(channel) && !need_psc,
            psd_20: ap.psd_20,
        });
    }
    if channels.is_empty() {
        return Ok(None);
    }
    Request::with_six_ghz(
        channels,
        ssids.to_vec(),
        request.extra_elements().to_vec(),
        targets,
    )
    .map(Some)
}

#[cfg(test)]
mod tests;
