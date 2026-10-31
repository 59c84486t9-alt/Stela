// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! UMAC15 regular, unassociated scan bytes, passive or probing.
use super::*;
/// What a probing scan's frames carry and radiate beyond the request's own
/// elements, which they share.
#[derive(Clone, Debug)]
pub struct Probe {
    /// `ieee80211_build_preq_ies`' per-band parts for 2.4 and for 5 GHz.
    pub elements: [Vec<u8>; 2],
    /// The legacy rates firmware probes at, under the country's limit it holds.
    pub profiles: regulatory::ProbeProfiles,
}
/// `iwl_mvm_rrm_scan_needed`: firmware that fills a DS Parameter Set placeholder
/// for the channel it probes, and writes a WFA TPC report itself.
#[derive(Clone, Copy, Debug)]
pub(super) struct Measurement {
    pub(super) ds_parameters: bool,
    pub(super) tpc_report: bool,
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
const FIRMWARE_CHANNELS: usize = 67;
const CHANNEL_CONFIG_BYTES: usize = 8;
const PERIODIC: usize = CHANNELS + 4 + FIRMWARE_CHANNELS * CHANNEL_CONFIG_BYTES;
const PROBE: usize = PERIODIC + 12;
const PROBE_SEGMENTS: usize = 5 * 4;
const PROBE_BUFFER_BYTES: usize = 512;
const SSID_ENTRY_BYTES: usize = 34;
const DIRECT_SSIDS: usize = 20 * SSID_ENTRY_BYTES;
const SHORT_SSIDS: usize = 8 * 4;
const BSSIDS: usize = 16 * 6;
const SSIDS: usize = PROBE + PROBE_SEGMENTS + PROBE_BUFFER_BYTES + 4;
pub(super) const REQUEST_BYTES: usize = SSIDS + DIRECT_SSIDS + SHORT_SSIDS + BSSIDS;
/// A management header and the wildcard SSID firmware replaces.
const HEADER: usize = 26;
const FORCE_PASSIVE: u16 = 1 << 11;
const PASS_ALL: u16 = 1 << 1;
const USE_ALL_RX_CHAINS: u16 = 1 << 6;
const ADAPTIVE_DWELL: u16 = 1 << 7;
const ENABLE_CHANNEL_ORDER: u8 = 1 << 5;
const PRIORITY_EXT_6: u32 = 6;
const ACTIVE_DWELL: u8 = 10;
const PASSIVE_DWELL: u8 = 110;
const FULL_SCAN_BUDGET_TU: u16 = 300;
const DIRECTED_SCAN_BUDGET_TU: u16 = 100;
/// `iwl_mvm_add_tpc_report_ie`, whose power firmware inserts.
const TPC_REPORT: [u8; 9] = [221, 7, 0x00, 0x50, 0xf2, 8, 0, 0, 0];
pub(super) fn validate(
    firmware: &crate::wifi::intel::firmware::Firmware<'_>,
) -> Result<(), Ax200ScanError> {
    for (id, expected) in [(REQUEST, 15), (ABORT, 1)] {
        let version = firmware
            .command_version(id.group, id.opcode)
            .ok_or(Ax200ScanError::MissingApi(id.opcode))?
            .command_version;
        if version != expected {
            return Err(Ax200ScanError::Version {
                command: id.opcode,
                version,
            });
        }
    }
    Ok(())
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
    local: crate::Mac,
    probe: Option<&Probe>,
    measurement: Measurement,
) -> Result<Vec<u8>, Ax200ScanError> {
    if request.active() != probe.is_some() {
        return Err(Ax200ScanError::ProbePowerRequired);
    }
    if request.channels().is_empty()
        || request.channels().len() > FIRMWARE_CHANNELS
        || !request.six_ghz().is_empty()
        || request
            .channels()
            .iter()
            .any(|ch| ch.band == Band::Ghz6 || ch.number > u8::MAX.into())
    {
        return Err(Ax200ScanError::UnsupportedRequest);
    }
    let (ghz2, ghz5) = match probe {
        Some(probe) if measurement.ds_parameters => (
            with_ds_placeholder(&probe.elements[0]),
            probe.elements[1].clone(),
        ),
        Some(probe) => (probe.elements[0].clone(), probe.elements[1].clone()),
        None => (Vec::new(), Vec::new()),
    };
    let mut common = Vec::from(request.extra_elements());
    if probe.is_some() && measurement.ds_parameters && !measurement.tpc_report {
        common.extend_from_slice(&TPC_REPORT);
    }
    // Even a passive scan's unused template is bounded and keeps every caller
    // IE. It sets no direct SSID, so no firmware probe selector can transmit.
    if HEADER + ghz2.len() + ghz5.len() + common.len() > PROBE_BUFFER_BYTES {
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
        .try_reserve_exact(REQUEST_BYTES)
        .map_err(|_| Ax200ScanError::NoMemory)?;
    bytes.resize(REQUEST_BYTES, 0);
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
    let bitmap = direct_ssids(&mut bytes[SSIDS..SSIDS + DIRECT_SSIDS], ssids);
    bytes[CHANNELS] = ENABLE_CHANNEL_ORDER;
    bytes[CHANNELS + 1] = request.channels().len() as u8;
    bytes[CHANNELS + 2..CHANNELS + 4].copy_from_slice(&[10, 2]);
    for (i, channel) in request.channels().iter().enumerate() {
        let at = CHANNELS + 4 + i * CHANNEL_CONFIG_BYTES;
        bytes[at..at + 4].copy_from_slice(&bitmap.to_le_bytes());
        bytes[at + 4] = channel.number as u8;
        bytes[at + 5] = u8::from(channel.band == Band::Ghz5);
        bytes[at + 6] = 1;
    }
    bytes[PERIODIC + 2] = 1; // one ordinary iteration, interval/delay zero
    bytes[PROBE + 2..PROBE + 4].copy_from_slice(&(HEADER as u16).to_le_bytes());
    let frame = PROBE + PROBE_SEGMENTS;
    bytes[frame] = 0x40; // a probe request, with the wildcard SSID firmware replaces
    bytes[frame + 4..frame + 10].fill(0xff);
    bytes[frame + 10..frame + 16].copy_from_slice(&local.0);
    bytes[frame + 16..frame + 22].fill(0xff);
    let mut offset = HEADER;
    let parts: [&[u8]; 4] = [&ghz2, &ghz5, &[], &common];
    for (segment, part) in parts.into_iter().enumerate() {
        let at = PROBE + (segment + 1) * 4;
        bytes[at..at + 2].copy_from_slice(&(offset as u16).to_le_bytes());
        bytes[at + 2..at + 4].copy_from_slice(&(part.len() as u16).to_le_bytes());
        bytes[frame + offset..frame + offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: crate::Mac = crate::Mac([2, 0, 0, 0, 0, 1]);
    const FRAME: usize = PROBE + PROBE_SEGMENTS;

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
            elements: [vec![1, 1, 2, 50, 1, 96, 45, 1, 9], vec![1, 1, 12]],
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

    const MEASURED: Measurement = Measurement {
        ds_parameters: true,
        tpc_report: false,
    };

    #[test]
    fn a_wildcard_scan_probes_every_channel_under_its_one_ssid() {
        let request = protocol::Request::new(channels(), vec![vec![]], vec![221, 1, 7]).unwrap();
        let bytes = encode(&request, LOCAL, Some(&probe()), MEASURED).unwrap();
        assert_eq!(word(&bytes, GENERAL), PASS_ALL | ADAPTIVE_DWELL);
        assert_eq!(word(&bytes, GENERAL + 10), FULL_SCAN_BUDGET_TU);
        for index in 0..2 {
            let at = CHANNELS + 4 + index * CHANNEL_CONFIG_BYTES;
            assert_eq!(bytes[at..at + 4], [1, 0, 0, 0]);
        }
        assert_eq!(bytes[CHANNELS + 4 + CHANNEL_CONFIG_BYTES + 5], 1);
        assert_eq!(bytes[SSIDS..SSIDS + 2], [0, 0]);
        assert_eq!(word(&bytes, PROBE + 2), 26);
        assert_eq!(bytes[FRAME + 24..FRAME + 26], [0, 0]);
        assert_eq!(
            segment(&bytes, 1),
            [1, 1, 2, 50, 1, 96, 3, 1, 0, 45, 1, 9],
            "the placeholder follows the rates"
        );
        assert_eq!(segment(&bytes, 2), [1, 1, 12]);
        assert_eq!(segment(&bytes, 3), []);
        assert_eq!(segment(&bytes, 4)[..3], [221, 1, 7]);
        assert_eq!(segment(&bytes, 4)[3..], TPC_REPORT);
    }

    #[test]
    fn firmware_that_writes_the_power_report_is_left_to() {
        let request = protocol::Request::new(channels(), vec![vec![]], vec![]).unwrap();
        let reports = Measurement {
            ds_parameters: true,
            tpc_report: true,
        };
        let bytes = encode(&request, LOCAL, Some(&probe()), reports).unwrap();
        assert_eq!(segment(&bytes, 4), []);
        let quiet = Measurement {
            ds_parameters: false,
            tpc_report: false,
        };
        let bytes = encode(&request, LOCAL, Some(&probe()), quiet).unwrap();
        assert_eq!(segment(&bytes, 1), probe().elements[0]);
        assert_eq!(segment(&bytes, 4), []);
    }

    #[test]
    fn one_named_network_listens_on_every_chain_within_the_directed_budget() {
        let ssids = vec![b"net".to_vec()];
        let request = protocol::Request::new(channels(), ssids, vec![]).unwrap();
        let bytes = encode(&request, LOCAL, Some(&probe()), MEASURED).unwrap();
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
        let bytes = encode(&request, LOCAL, Some(&probe()), MEASURED).unwrap();
        assert_eq!(bytes[SSIDS + 1], 3);
        assert_eq!(bytes[SSIDS + SSID_ENTRY_BYTES + 1], 0);
        assert_eq!(bytes[SSIDS + 2 * SSID_ENTRY_BYTES + 1], 0);
        assert_eq!(bytes[CHANNELS + 4], 0b11);
    }

    #[test]
    fn a_passive_scan_stays_passive_and_names_no_ssid() {
        let request = protocol::Request::new(channels(), vec![], vec![221, 1, 7]).unwrap();
        let bytes = encode(&request, LOCAL, None, MEASURED).unwrap();
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
            encode(&active, LOCAL, None, MEASURED).unwrap_err(),
            Ax200ScanError::ProbePowerRequired
        );
        assert!(encode(&passive, LOCAL, Some(&probe()), MEASURED).is_err());
    }

    #[test]
    fn elements_beyond_the_template_are_refused() {
        let request = protocol::Request::new(channels(), vec![vec![]], vec![]).unwrap();
        let mut oversized = probe();
        oversized.elements[1] = vec![0; PROBE_BUFFER_BYTES];
        assert_eq!(
            encode(&request, LOCAL, Some(&oversized), MEASURED).unwrap_err(),
            Ax200ScanError::UnsupportedRequest
        );
    }
}
