// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! UMAC14 to 17 regular, unassociated scan bytes, passive or probing.
use super::*;
/// What a probing scan's frames carry and radiate beyond the request's own
/// elements, which they share.
#[derive(Clone, Debug)]
pub struct Probe {
    /// `ieee80211_build_preq_ies`' per-band parts for 2.4, 5 and 6 GHz.
    pub elements: [Vec<u8>; 3],
    /// The legacy rates firmware probes at, under the country's limit it holds.
    pub profiles: regulatory::ProbeProfiles,
}
/// What firmware does in a scan by itself.
#[derive(Clone, Copy, Debug)]
pub(super) struct Abilities {
    /// `iwl_mvm_rrm_scan_needed`: it fills a DS Parameter Set placeholder for
    /// the channel it probes.
    pub(super) ds_parameters: bool,
    /// It writes a WFA TPC report itself.
    pub(super) tpc_report: bool,
    /// It probes a 6 GHz channel for a hidden SSID's name.
    pub(super) hidden_six_ghz: bool,
    /// It keeps one antenna through a 6 GHz scan.
    pub(super) fixed_antenna: bool,
}
pub(super) const REQUEST: Id = Id {
    group: 1,
    opcode: 0x0d,
    version: 0,
};
pub(super) const ABORT: Id = Id {
    group: 1,
    opcode: 0x0e,
    version: 0,
};
pub(super) const COMPLETE_OPCODE: u8 = 0x0f;
// RX_HANDLER(SCAN_COMPLETE_UMAC) uses the legacy RX group, unlike wide HCMDs.
pub(super) const COMPLETE_GROUP: u8 = 0;
const GENERAL: usize = 8;
const GENERAL_BYTES: usize = 36;
const CHANNELS: usize = GENERAL + GENERAL_BYTES;
const CHANNEL_CONFIG_BYTES: usize = 8;
const PROBE_SEGMENTS: usize = 5 * 4;
const PROBE_BUFFER_BYTES: usize = 512;
const SSID_ENTRY_BYTES: usize = 34;
const DIRECT_SSIDS: usize = 20 * SSID_ENTRY_BYTES;
const SHORT_SSID_ENTRIES: usize = 8;
const SHORT_SSIDS: usize = SHORT_SSID_ENTRIES * 4;
const BSSID_ENTRIES: usize = 16;
const BSSIDS: usize = BSSID_ENTRIES * 6;
/// Where a request's tables lie, after its channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    channels: usize,
    periodic: usize,
    probe: usize,
    ssids: usize,
    bytes: usize,
}
impl Layout {
    /// `SCAN_MAX_NUM_CHANS_V3`, and `_V4` from version 18.
    const fn of(version: u8) -> Self {
        let channels = if version >= 18 { 68 } else { 67 };
        let periodic = CHANNELS + 4 + channels * CHANNEL_CONFIG_BYTES;
        let probe = periodic + 12;
        let ssids = probe + PROBE_SEGMENTS + PROBE_BUFFER_BYTES + 4;
        Self {
            channels,
            periodic,
            probe,
            ssids,
            bytes: ssids + DIRECT_SSIDS + SHORT_SSIDS + BSSIDS,
        }
    }
}
/// A management header and the wildcard SSID firmware replaces.
const HEADER: usize = 26;
/// The first version carrying a channel's band in its flags, not its own byte.
const BAND_IN_FLAGS: u8 = 17;
/// `IWL_CHAN_CFG_FLAGS_BAND_POS`.
const BAND_SHIFT: u32 = 30;
const PHY_BAND_5: u8 = 0;
const PHY_BAND_24: u8 = 1;
const PHY_BAND_6: u8 = 2;
const FORCE_PASSIVE: u16 = 1 << 11;
const NOTIFY_START: u16 = 1 << 9;
const PASS_ALL: u16 = 1 << 1;
const USE_ALL_RX_CHAINS: u16 = 1 << 6;
const ADAPTIVE_DWELL: u16 = 1 << 7;
const ENABLE_CHANNEL_ORDER: u8 = 1 << 5;
const PSC_NO_FILTER: u8 = 1 << 6;
const FLAGS2: usize = GENERAL + 9;
/// `IWL_UMAC_SCAN_GEN_PARAMS_FLAGS2_DONT_TOGGLE_ANT`.
const DONT_TOGGLE_ANTENNA: u8 = 1 << 2;
const UNSOLICITED_PROBE_RESPONSE: u32 = 1 << 24;
const PSC_NO_LISTEN: u32 = 1 << 25;
const CHANNEL_FORCE_PASSIVE: u32 = 1 << 26;
/// `IEEE80211_RNR_TBTT_PARAMS_PSD_RESERVED`.
const PSD_RESERVED: i8 = -128;
const PRIORITY_EXT_6: u32 = 6;
const PRIORITY_EXT_4: u32 = 4;
/// `scan_timing[IWL_SCAN_TYPE_WILD]`, for a station whose traffic is light.
const MAX_OUT_OF_SERVICE_TU: u32 = 120;
const SUSPEND_TU: u32 = 30;
const ACTIVE_DWELL: u8 = 10;
const PASSIVE_DWELL: u8 = 110;
const FULL_SCAN_BUDGET_TU: u16 = 300;
const DIRECTED_SCAN_BUDGET_TU: u16 = 100;
/// `iwl_mvm_add_tpc_report_ie`, whose power firmware inserts.
const TPC_REPORT: [u8; 9] = [221, 7, 0x00, 0x50, 0xf2, 8, 0, 0, 0];
/// The request's version, every one Linux fills through
/// `iwl_mvm_scan_umac_v14_and_above`, whose differences `encode` carries.
pub(super) fn validate(
    firmware: &crate::wifi::intel::firmware::Firmware<'_>,
) -> Result<u8, Ax200ScanError> {
    let version = |id: Id| {
        firmware
            .command_version(id.group, id.opcode)
            .map(|v| v.command_version)
            .ok_or(Ax200ScanError::MissingApi(id.opcode))
    };
    let request = version(REQUEST)?;
    if !(14..=18).contains(&request) {
        return Err(Ax200ScanError::Version {
            command: REQUEST.opcode,
            version: request,
        });
    }
    let abort = version(ABORT)?;
    if abort != 1 {
        return Err(Ax200ScanError::Version {
            command: ABORT.opcode,
            version: abort,
        });
    }
    Ok(request)
}
/// `iwl_scan_build_ssids`: the firmware's direct SSID table, last first, and
/// the bitmap of its entries each channel probes.
fn direct_ssids(table: &mut [u8], ssids: &[Vec<u8>]) -> u32 {
    let mut filled = 0;
    let mut bitmap = 0;
    for ssid in ssids.iter().rev() {
        let found = table.as_chunks::<SSID_ENTRY_BYTES>().0[..filled]
            .iter()
            .position(|entry| entry[2..2 + usize::from(entry[1])] == ssid[..]);
        let index = found.unwrap_or(filled);
        if found.is_none() {
            let entry = &mut table[index * SSID_ENTRY_BYTES..][..SSID_ENTRY_BYTES];
            entry[1] = ssid.len() as u8;
            entry[2..2 + ssid.len()].copy_from_slice(ssid);
            filled += 1;
        }
        bitmap |= 1 << index;
    }
    bitmap
}
/// `iwl_mvm_copy_and_insert_ds_elem`: the placeholder firmware fills with the
/// channel it probes, after the elements that precede it in a probe.
fn with_ds_placeholder(elements: &[u8]) -> Vec<u8> {
    let mut split = 0;
    while let Some(&[id, length]) = elements.get(split..split + 2).and_then(|e| e.first_chunk())
        && matches!(id, 0 | 1 | 10 | 50)
    {
        split += 2 + usize::from(length);
    }
    let split = split.min(elements.len());
    [&elements[..split], &[3, 1, 0], &elements[split..]].concat()
}
/// `iwl_mvm_scan_umac_v14_and_above` for an ordinary scan of 2.4 and 5 GHz:
/// passive without `probe`, else probing for the request's SSIDs.
pub(super) fn encode(
    request: &protocol::Request,
    version: u8,
    local: crate::Mac,
    probe: Option<&Probe>,
    abilities: Abilities,
) -> Result<Vec<u8>, Ax200ScanError> {
    if request.active() != probe.is_some() {
        return Err(Ax200ScanError::ProbePowerRequired);
    }
    let layout = Layout::of(version);
    // cfg80211 splits a scan, so a request is all 6 GHz or none of it.
    let six_ghz = request
        .channels()
        .first()
        .is_some_and(|ch| ch.band == Band::Ghz6);
    if request.channels().is_empty()
        || request.channels().len() > layout.channels
        || (!six_ghz && !request.six_ghz().is_empty())
        || request
            .channels()
            .iter()
            .any(|ch| (ch.band == Band::Ghz6) != six_ghz || ch.number > u8::MAX.into())
    {
        return Err(Ax200ScanError::UnsupportedRequest);
    }
    let [ghz2, ghz5, ghz6] = match probe {
        Some(probe) if abilities.ds_parameters => [
            with_ds_placeholder(&probe.elements[0]),
            probe.elements[1].clone(),
            probe.elements[2].clone(),
        ],
        Some(probe) => probe.elements.clone(),
        None => [Vec::new(), Vec::new(), Vec::new()],
    };
    let mut common = Vec::from(request.extra_elements());
    if probe.is_some() && abilities.ds_parameters && !abilities.tpc_report {
        common.extend_from_slice(&TPC_REPORT);
    }
    // Even a passive scan's unused template is bounded and keeps every caller
    // IE. It sets no direct SSID, so no firmware probe selector can transmit.
    if HEADER + ghz2.len() + ghz5.len() + ghz6.len() + common.len() > PROBE_BUFFER_BYTES {
        return Err(Ax200ScanError::UnsupportedRequest);
    }
    let ssids = request.ssids();
    let directed = ssids.first().is_some_and(|ssid| !ssid.is_empty());
    let mut flags = PASS_ALL | ADAPTIVE_DWELL;
    if ssids.is_empty() {
        flags |= FORCE_PASSIVE;
    } else if ssids.len() == 1 && directed {
        flags |= USE_ALL_RX_CHAINS;
    }
    let budget = if directed {
        DIRECTED_SCAN_BUDGET_TU
    } else {
        FULL_SCAN_BUDGET_TU
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(layout.bytes)
        .map_err(|_| Ax200ScanError::NoMemory)?;
    bytes.resize(layout.bytes, 0);
    // One serialized UID0. Only the same owner can reuse it after
    // completion, command reclaim and old-RB/deferred-user retirement.
    bytes[4..8].copy_from_slice(&PRIORITY_EXT_6.to_le_bytes());
    bytes[GENERAL..GENERAL + 2].copy_from_slice(&flags.to_le_bytes());
    bytes[GENERAL + 4..GENERAL + 6].fill(ACTIVE_DWELL);
    bytes[GENERAL + 6..GENERAL + 9].copy_from_slice(&[2, 8, 10]);
    bytes[GENERAL + 10..GENERAL + 12].copy_from_slice(&budget.to_le_bytes());
    bytes[GENERAL + 28..GENERAL + 32].copy_from_slice(&PRIORITY_EXT_6.to_le_bytes());
    bytes[GENERAL + 32..GENERAL + 34].fill(PASSIVE_DWELL);
    // Both LMAC timing arrays are zero for the unassociated MAC.
    // EBS is disabled: no previous successful EBS is invented.
    if six_ghz {
        encode_six_ghz(&mut bytes, request, version, abilities, layout)?;
    } else {
        let table = layout.ssids..layout.ssids + DIRECT_SSIDS;
        let bitmap = direct_ssids(&mut bytes[table], ssids);
        bytes[CHANNELS] = ENABLE_CHANNEL_ORDER;
        bytes[CHANNELS + 1] = request.channels().len() as u8;
        bytes[CHANNELS + 2..CHANNELS + 4].copy_from_slice(&[10, 2]);
        for (index, &channel) in request.channels().iter().enumerate() {
            put_channel(&mut bytes, index, channel, bitmap, version);
        }
    }
    bytes[layout.periodic + 2] = 1; // one ordinary iteration, interval/delay zero
    bytes[layout.probe + 2..layout.probe + 4].copy_from_slice(&(HEADER as u16).to_le_bytes());
    let frame = layout.probe + PROBE_SEGMENTS;
    bytes[frame] = 0x40; // a probe request, with the wildcard SSID firmware replaces
    bytes[frame + 4..frame + 10].fill(0xff);
    bytes[frame + 10..frame + 16].copy_from_slice(&local.0);
    bytes[frame + 16..frame + 22].fill(0xff);
    let mut offset = HEADER;
    let parts: [&[u8]; 4] = [&ghz2, &ghz5, &ghz6, &common];
    for (segment, part) in parts.into_iter().enumerate() {
        let at = layout.probe + (segment + 1) * 4;
        bytes[at..at + 2].copy_from_slice(&(offset as u16).to_le_bytes());
        bytes[at + 2..at + 4].copy_from_slice(&(part.len() as u16).to_le_bytes());
        bytes[frame + offset..frame + offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    Ok(bytes)
}

/// `iwl_mld_int_mlo_scan_start`: a passive scan beside the association on
/// firmware link `link`, which leaves that link's channel for what
/// `scan_timing` allows and says when it starts.
pub(super) fn encode_internal(
    request: &protocol::Request,
    version: u8,
    local: crate::Mac,
    link: u8,
) -> Result<Vec<u8>, Ax200ScanError> {
    let abilities = Abilities {
        ds_parameters: false,
        tpc_report: false,
        hidden_six_ghz: false,
        fixed_antenna: false,
    };
    let mut bytes = encode(request, version, local, None, abilities)?;
    bytes[4..8].copy_from_slice(&PRIORITY_EXT_4.to_le_bytes());
    bytes[GENERAL + 1] |= (NOTIFY_START >> 8) as u8;
    bytes[GENERAL + 3] = link;
    bytes[GENERAL + 12..GENERAL + 16].copy_from_slice(&MAX_OUT_OF_SERVICE_TU.to_le_bytes());
    bytes[GENERAL + 20..GENERAL + 24].copy_from_slice(&SUSPEND_TU.to_le_bytes());
    Ok(bytes)
}

/// One `iwl_scan_channel_cfg_umac`: its one iteration, and its band where
/// `version` reads it.
fn put_channel(bytes: &mut [u8], index: usize, channel: Channel, flags: u32, version: u8) {
    let at = CHANNELS + 4 + index * CHANNEL_CONFIG_BYTES;
    let band = match channel.band {
        Band::Ghz2 => PHY_BAND_24,
        Band::Ghz5 => PHY_BAND_5,
        Band::Ghz6 => PHY_BAND_6,
    };
    let flags = if version < BAND_IN_FLAGS {
        bytes[at + 5] = band;
        flags
    } else {
        flags | u32::from(band) << BAND_SHIFT
    };
    bytes[at..at + 4].copy_from_slice(&flags.to_le_bytes());
    bytes[at + 4] = channel.number as u8;
    bytes[at + 6] = 1;
}

/// The short SSIDs and BSSIDs a 6 GHz scan's channels index.
struct SixGhzTables {
    /// Each short SSID, and whether its full name is also in the table.
    short_ssids: Vec<(u32, bool)>,
    bssids: Vec<crate::Mac>,
}

/// `iwl_mvm_umac_scan_fill_6g_chan_list`.
fn six_ghz_tables(
    bytes: &mut [u8],
    request: &protocol::Request,
    hidden: bool,
    ssids: usize,
) -> SixGhzTables {
    let mut tables = SixGhzTables {
        short_ssids: Vec::new(),
        bssids: Vec::new(),
    };
    let named = request.ssids().iter().filter(|ssid| !ssid.is_empty());
    for (index, ssid) in named.take(SHORT_SSID_ENTRIES).enumerate() {
        if hidden {
            let entry = &mut bytes[ssids + index * SSID_ENTRY_BYTES..][..SSID_ENTRY_BYTES];
            entry[1] = ssid.len() as u8;
            entry[2..2 + ssid.len()].copy_from_slice(ssid);
        }
        let short = protocol::six_ghz::short_ssid(ssid);
        tables.short_ssids.push((short, hidden));
    }
    for target in request.six_ghz() {
        if let Some(short) = target.short_ssid
            && tables.short_ssids.len() < SHORT_SSID_ENTRIES
            && !tables.short_ssids.iter().any(|known| known.0 == short)
        {
            tables.short_ssids.push((short, false));
        }
        if tables.bssids.len() < BSSID_ENTRIES
            && !tables.bssids.contains(&target.bssid)
            && !target.bssid.is_multicast()
            && target.bssid.0 != [0; 6]
        {
            tables.bssids.push(target.bssid);
        }
    }
    let shorts = ssids + DIRECT_SSIDS;
    for (index, (short, _)) in tables.short_ssids.iter().enumerate() {
        bytes[shorts + index * 4..][..4].copy_from_slice(&short.to_le_bytes());
    }
    for (index, bssid) in tables.bssids.iter().enumerate() {
        bytes[shorts + SHORT_SSIDS + index * 6..][..6].copy_from_slice(&bssid.0);
    }
    bytes[ssids - 4] = tables.short_ssids.len() as u8;
    bytes[ssids - 3] = tables.bssids.len() as u8;
    tables
}

/// `iwl_mvm_umac_scan_cfg_channels_v7_6g`, for the unfragmented scan of an idle
/// station: which of the tables' entries each channel probes for.
fn encode_six_ghz(
    bytes: &mut [u8],
    request: &protocol::Request,
    version: u8,
    abilities: Abilities,
    layout: Layout,
) -> Result<(), Ax200ScanError> {
    let tables = six_ghz_tables(bytes, request, abilities.hidden_six_ghz, layout.ssids);
    let targets = request.six_ghz();
    let ssids = request.ssids();
    let mut count = 0;
    for (index, &channel) in request.channels().iter().enumerate() {
        let psc = protocol::six_ghz::is_psc(channel);
        if !psc && targets.is_empty() && !ssids.is_empty() {
            continue;
        }
        let here = || {
            targets
                .iter()
                .filter(|target| target.channel_index == index)
        };
        let unsolicited = here().any(|target| target.unsolicited_probe);
        let no_listen = here().any(|target| target.psc_no_listen);
        let psd = here()
            .map(|target| target.psd_20)
            .filter(|&psd| psd != PSD_RESERVED)
            .max()
            .unwrap_or(PSD_RESERVED);
        let (most_shorts, most_bssids) = if (!psc || no_listen) && !unsolicited {
            (3, 9)
        } else {
            (2, 6)
        };
        let (mut short_bitmap, mut bssid_bitmap) = (0u32, 0u32);
        let (mut shorts, mut bssids) = (0, 0);
        let (mut force_passive, mut allow_passive) = (false, true);
        for target in here() {
            // Probing a short SSID covers every BSS of it in one dwell, so three
            // direct BSSIDs go with each, and a hidden AP takes one regardless.
            let short = tables
                .short_ssids
                .iter()
                .enumerate()
                .find(|(_, known)| !target.unsolicited_probe && target.short_ssid == Some(known.0))
                .filter(|_| shorts < most_shorts);
            if let Some((entry, &(_, named))) = short {
                if short_bitmap & 1 << entry != 0 {
                    continue;
                }
                if 3 * shorts <= bssids || named {
                    allow_passive &= !named;
                    short_bitmap |= 1 << entry;
                    shorts += 1;
                    continue;
                }
            }
            let Some(entry) = tables.bssids.iter().position(|b| *b == target.bssid) else {
                continue;
            };
            if bssid_bitmap & 1 << entry == 0 {
                if bssids < most_bssids {
                    bssid_bitmap |= 1 << entry;
                    bssids += 1;
                } else {
                    force_passive = true;
                }
            }
        }
        let mut flags = 0;
        if psc && no_listen {
            flags |= PSC_NO_LISTEN;
        }
        if unsolicited {
            flags |= UNSOLICITED_PROBE_RESPONSE;
        }
        if (allow_passive && force_passive) || (bssid_bitmap | short_bitmap == 0 && !psc) {
            flags |= CHANNEL_FORCE_PASSIVE;
        } else {
            flags |= bssid_bitmap | short_bitmap << 16;
        }
        put_channel(bytes, count, channel, flags, version);
        if version >= BAND_IN_FLAGS {
            bytes[CHANNELS + 4 + count * CHANNEL_CONFIG_BYTES + 5] = psd as u8;
        }
        count += 1;
    }
    if count == 0 {
        return Err(Ax200ScanError::UnsupportedRequest);
    }
    bytes[CHANNELS + 1] = count as u8;
    if ssids.is_empty() || (ssids.len() == 1 && ssids[0].is_empty()) {
        bytes[CHANNELS] = PSC_NO_FILTER;
    }
    if version >= 15 && abilities.fixed_antenna {
        bytes[FLAGS2] = DONT_TOGGLE_ANTENNA;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: crate::Mac = crate::Mac([2, 0, 0, 0, 0, 1]);
    const LAYOUT: Layout = Layout::of(17);
    const PROBE: usize = LAYOUT.probe;
    const SSIDS: usize = LAYOUT.ssids;
    const FRAME: usize = PROBE + PROBE_SEGMENTS;

    #[test]
    fn an_internal_scan_listens_beside_its_link_within_linux_s_times() {
        let channel = Channel {
            band: Band::Ghz2,
            number: 1,
            frequency_mhz: 2412,
        };
        let request = protocol::Request::new(vec![channel], Vec::new(), Vec::new()).unwrap();
        let bytes = encode_internal(&request, 17, LOCAL, 1).unwrap();
        let flags = u16::from_le_bytes([bytes[GENERAL], bytes[GENERAL + 1]]);
        assert_eq!(
            flags,
            PASS_ALL | ADAPTIVE_DWELL | FORCE_PASSIVE | NOTIFY_START
        );
        assert_eq!(bytes[4..8], 4u32.to_le_bytes());
        assert_eq!(bytes[GENERAL + 3], 1);
        assert_eq!(bytes[GENERAL + 12..GENERAL + 16], 120u32.to_le_bytes());
        assert_eq!(bytes[GENERAL + 16..GENERAL + 20], [0; 4]);
        assert_eq!(bytes[GENERAL + 20..GENERAL + 24], 30u32.to_le_bytes());
        assert_eq!(bytes[GENERAL + 24..GENERAL + 28], [0; 4]);
    }

    #[test]
    fn version_18_has_room_for_one_more_channel() {
        let (old, new) = (Layout::of(17), Layout::of(18));
        assert_eq!((old.channels, new.channels), (67, 68));
        assert_eq!(
            old.bytes,
            8 + 36 + 4 + 67 * 8 + 12 + 20 + 512 + 4 + 680 + 32 + 96
        );
        assert_eq!(new.bytes, old.bytes + 8);
        assert_eq!(new.ssids, old.ssids + 8);
    }

    fn channel(band: Band, number: u16, frequency_mhz: u16) -> Channel {
        Channel {
            band,
            number,
            frequency_mhz,
        }
    }

    fn channels() -> Vec<Channel> {
        vec![channel(Band::Ghz2, 1, 2412), channel(Band::Ghz5, 36, 5180)]
    }

    fn probe() -> Probe {
        let profile = regulatory::TxProfile {
            width: regulatory::Width::Legacy20,
            rate: regulatory::LegacyRate::Ofdm6,
            short_preamble: false,
            max_eirp_mbm: 2000,
        };
        Probe {
            elements: [
                vec![1, 1, 2, 50, 1, 96, 45, 1, 9],
                vec![1, 1, 12],
                vec![1, 1, 12, 255, 3, 59, 0, 0],
            ],
            profiles: regulatory::ProbeProfiles::uniform(profile),
        }
    }

    fn word(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([bytes[at], bytes[at + 1]])
    }

    fn segment(bytes: &[u8], index: usize) -> &[u8] {
        let at = PROBE + index * 4;
        &bytes[FRAME + usize::from(word(bytes, at))..][..usize::from(word(bytes, at + 2))]
    }

    const MEASURED: Abilities = Abilities {
        ds_parameters: true,
        tpc_report: false,
        hidden_six_ghz: false,
        fixed_antenna: false,
    };

    const SIX_1: Channel = Channel {
        band: Band::Ghz6,
        number: 1,
        frequency_mhz: 5955,
    };
    const SIX_5: Channel = Channel {
        band: Band::Ghz6,
        number: 5,
        frequency_mhz: 5975,
    };

    fn target(channel_index: usize, last: u8) -> protocol::SixGhz {
        protocol::SixGhz {
            channel_index,
            bssid: crate::Mac([2, 0, 0, 0, 1, last]),
            short_ssid: None,
            unsolicited_probe: false,
            psc_no_listen: false,
            psd_20: PSD_RESERVED,
        }
    }

    fn six_ghz(
        channels: Vec<Channel>,
        ssids: Vec<Vec<u8>>,
        targets: Vec<protocol::SixGhz>,
    ) -> Vec<u8> {
        let request = protocol::Request::with_six_ghz(channels, ssids, vec![], targets).unwrap();
        encode(&request, 17, LOCAL, Some(&probe()), MEASURED).unwrap()
    }

    fn flags(bytes: &[u8], index: usize) -> u32 {
        let at = CHANNELS + 4 + index * CHANNEL_CONFIG_BYTES;
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    const BAND_6: u32 = (PHY_BAND_6 as u32) << BAND_SHIFT;

    #[test]
    fn a_six_ghz_scan_probes_each_channel_for_what_is_known_on_it() {
        let reported = protocol::SixGhz {
            short_ssid: Some(0xaabb_ccdd),
            psd_20: 4,
            ..target(1, 1)
        };
        let bytes = six_ghz(vec![SIX_5, SIX_1], vec![vec![]], vec![reported]);
        assert_eq!(bytes[CHANNELS], PSC_NO_FILTER);
        assert_eq!(bytes[CHANNELS + 1], 2);
        assert_eq!(bytes[SSIDS - 4..SSIDS - 2], [1, 1]);
        let tables = SSIDS + DIRECT_SSIDS;
        assert_eq!(bytes[tables..tables + 4], 0xaabb_ccddu32.to_le_bytes());
        assert_eq!(
            bytes[tables + SHORT_SSIDS..tables + SHORT_SSIDS + 6],
            [2, 0, 0, 0, 1, 1]
        );
        assert_eq!(flags(&bytes, 0), BAND_6);
        assert_eq!(bytes[CHANNELS + 4 + 5], PSD_RESERVED as u8);
        assert_eq!(flags(&bytes, 1), BAND_6 | 1 << 16);
        assert_eq!(bytes[CHANNELS + 4 + CHANNEL_CONFIG_BYTES + 4], 1);
        assert_eq!(bytes[CHANNELS + 4 + CHANNEL_CONFIG_BYTES + 5], 4);
        assert_eq!(segment(&bytes, 3), probe().elements[2]);
    }

    #[test]
    fn a_channel_that_answers_by_itself_takes_its_bssids() {
        let reported = protocol::SixGhz {
            short_ssid: Some(1),
            unsolicited_probe: true,
            ..target(0, 1)
        };
        let bytes = six_ghz(vec![SIX_1], vec![vec![]], vec![reported]);
        assert_eq!(flags(&bytes, 0), BAND_6 | UNSOLICITED_PROBE_RESPONSE | 1);
    }

    #[test]
    fn too_many_bssids_listen_instead() {
        let many = (0..10).map(|last| target(0, last)).collect();
        let bytes = six_ghz(vec![SIX_1], vec![vec![]], many);
        assert_eq!(flags(&bytes, 0), BAND_6 | CHANNEL_FORCE_PASSIVE);
    }

    #[test]
    fn a_hidden_ap_is_named_and_never_listened_for() {
        let ssid = b"net".to_vec();
        let short = protocol::six_ghz::short_ssid(&ssid);
        let reported = protocol::SixGhz {
            short_ssid: Some(short),
            ..target(0, 1)
        };
        let request = protocol::Request::with_six_ghz(
            vec![SIX_1],
            vec![ssid.clone()],
            vec![],
            vec![reported],
        )
        .unwrap();
        let abilities = Abilities {
            hidden_six_ghz: true,
            fixed_antenna: true,
            ..MEASURED
        };
        let bytes = encode(&request, 17, LOCAL, Some(&probe()), abilities).unwrap();
        assert_eq!(bytes[SSIDS..SSIDS + 5], [0, 3, b'n', b'e', b't']);
        assert_eq!(bytes[FLAGS2], DONT_TOGGLE_ANTENNA);
        assert_eq!(bytes[CHANNELS], 0);
        assert_eq!(flags(&bytes, 0), BAND_6 | 1 << 16);
    }

    #[test]
    fn an_unreported_channel_outside_the_psc_is_skipped() {
        let request = protocol::Request::new(vec![SIX_1], vec![vec![]], vec![]).unwrap();
        assert_eq!(
            encode(&request, 17, LOCAL, Some(&probe()), MEASURED).unwrap_err(),
            Ax200ScanError::UnsupportedRequest
        );
    }

    #[test]
    fn a_request_never_mixes_6_ghz_with_other_bands() {
        let mut mixed = channels();
        mixed.push(SIX_5);
        let request = protocol::Request::new(mixed, vec![vec![]], vec![]).unwrap();
        assert_eq!(
            encode(&request, 17, LOCAL, Some(&probe()), MEASURED).unwrap_err(),
            Ax200ScanError::UnsupportedRequest
        );
    }

    #[test]
    fn each_channel_names_its_band_where_its_version_reads_it() {
        let request = protocol::Request::new(channels(), vec![vec![]], vec![]).unwrap();
        let config = |bytes: &[u8], index: usize| {
            let at = CHANNELS + 4 + index * CHANNEL_CONFIG_BYTES;
            (
                u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()),
                bytes[at + 4],
                bytes[at + 5],
                bytes[at + 6],
            )
        };
        for version in [14, 15, 16] {
            let bytes = encode(&request, version, LOCAL, Some(&probe()), MEASURED).unwrap();
            assert_eq!(config(&bytes, 0), (1, 1, PHY_BAND_24, 1));
            assert_eq!(config(&bytes, 1), (1, 36, PHY_BAND_5, 1));
        }
        let bytes = encode(&request, 17, LOCAL, Some(&probe()), MEASURED).unwrap();
        assert_eq!(config(&bytes, 0), (1 | 1 << 30, 1, 0, 1));
        assert_eq!(config(&bytes, 1), (1, 36, 0, 1));
    }

    #[test]
    fn a_wildcard_scan_probes_every_channel_under_its_one_ssid() {
        let request = protocol::Request::new(channels(), vec![vec![]], vec![221, 1, 7]).unwrap();
        let bytes = encode(&request, 15, LOCAL, Some(&probe()), MEASURED).unwrap();
        assert_eq!(word(&bytes, GENERAL), PASS_ALL | ADAPTIVE_DWELL);
        assert_eq!(word(&bytes, GENERAL + 10), FULL_SCAN_BUDGET_TU);
        for index in 0..2 {
            let at = CHANNELS + 4 + index * CHANNEL_CONFIG_BYTES;
            assert_eq!(bytes[at..at + 4], [1, 0, 0, 0]);
        }
        assert_eq!(bytes[CHANNELS + 4 + CHANNEL_CONFIG_BYTES + 5], PHY_BAND_5);
        assert_eq!(bytes[SSIDS..SSIDS + 2], [0, 0]);
        assert_eq!(word(&bytes, PROBE + 2), 26);
        assert_eq!(bytes[FRAME + 24..FRAME + 26], [0, 0]);
        assert_eq!(
            segment(&bytes, 1),
            [1, 1, 2, 50, 1, 96, 3, 1, 0, 45, 1, 9],
            "the placeholder follows the rates"
        );
        assert_eq!(segment(&bytes, 2), [1, 1, 12]);
        assert_eq!(segment(&bytes, 3), probe().elements[2]);
        assert_eq!(segment(&bytes, 4)[..3], [221, 1, 7]);
        assert_eq!(segment(&bytes, 4)[3..], TPC_REPORT);
    }

    #[test]
    fn firmware_that_writes_the_power_report_is_left_to() {
        let request = protocol::Request::new(channels(), vec![vec![]], vec![]).unwrap();
        let reports = Abilities {
            hidden_six_ghz: false,
            fixed_antenna: false,
            ds_parameters: true,
            tpc_report: true,
        };
        let bytes = encode(&request, 15, LOCAL, Some(&probe()), reports).unwrap();
        assert_eq!(segment(&bytes, 4), []);
        let quiet = Abilities {
            hidden_six_ghz: false,
            fixed_antenna: false,
            ds_parameters: false,
            tpc_report: false,
        };
        let bytes = encode(&request, 15, LOCAL, Some(&probe()), quiet).unwrap();
        assert_eq!(segment(&bytes, 1), probe().elements[0]);
        assert_eq!(segment(&bytes, 4), []);
    }

    #[test]
    fn one_named_network_listens_on_every_chain_within_the_directed_budget() {
        let ssids = vec![b"net".to_vec()];
        let request = protocol::Request::new(channels(), ssids, vec![]).unwrap();
        let bytes = encode(&request, 15, LOCAL, Some(&probe()), MEASURED).unwrap();
        assert_eq!(
            word(&bytes, GENERAL),
            PASS_ALL | ADAPTIVE_DWELL | USE_ALL_RX_CHAINS
        );
        assert_eq!(word(&bytes, GENERAL + 10), DIRECTED_SCAN_BUDGET_TU);
        assert_eq!(bytes[SSIDS..SSIDS + 5], [0, 3, b'n', b'e', b't']);
    }

    #[test]
    fn ssids_fill_the_table_last_first_and_every_channel_names_them() {
        let ssids = vec![b"one".to_vec(), vec![], b"one".to_vec()];
        let request = protocol::Request::new(channels(), ssids, vec![]).unwrap();
        let bytes = encode(&request, 15, LOCAL, Some(&probe()), MEASURED).unwrap();
        assert_eq!(bytes[SSIDS + 1], 3);
        assert_eq!(bytes[SSIDS + SSID_ENTRY_BYTES + 1], 0);
        assert_eq!(bytes[SSIDS + 2 * SSID_ENTRY_BYTES + 1], 0);
        assert_eq!(bytes[CHANNELS + 4], 0b11);
    }

    #[test]
    fn a_passive_scan_stays_passive_and_names_no_ssid() {
        let request = protocol::Request::new(channels(), vec![], vec![221, 1, 7]).unwrap();
        let bytes = encode(&request, 15, LOCAL, None, MEASURED).unwrap();
        assert_eq!(
            word(&bytes, GENERAL),
            FORCE_PASSIVE | PASS_ALL | ADAPTIVE_DWELL
        );
        assert_eq!(bytes[CHANNELS + 4..CHANNELS + 8], [0; 4]);
        assert!(bytes[SSIDS..SSIDS + DIRECT_SSIDS].iter().all(|&b| b == 0));
        assert_eq!(segment(&bytes, 4), [221, 1, 7]);
    }

    #[test]
    fn a_scan_and_its_probe_must_agree() {
        let active = protocol::Request::new(channels(), vec![vec![]], vec![]).unwrap();
        let passive = protocol::Request::new(channels(), vec![], vec![]).unwrap();
        assert_eq!(
            encode(&active, 15, LOCAL, None, MEASURED).unwrap_err(),
            Ax200ScanError::ProbePowerRequired
        );
        assert!(encode(&passive, 15, LOCAL, Some(&probe()), MEASURED).is_err());
    }

    #[test]
    fn elements_beyond_the_template_are_refused() {
        let request = protocol::Request::new(channels(), vec![vec![]], vec![]).unwrap();
        let mut oversized = probe();
        oversized.elements[1] = vec![0; PROBE_BUFFER_BYTES];
        assert_eq!(
            encode(&request, 15, LOCAL, Some(&oversized), MEASURED).unwrap_err(),
            Ax200ScanError::UnsupportedRequest
        );
    }
}
