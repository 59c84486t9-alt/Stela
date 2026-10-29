// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! UMAC15 regular, unassociated, explicitly forced-passive scan bytes.
use super::*;
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
const DIRECT_SSIDS: usize = 20 * 34;
const SHORT_SSIDS: usize = 8 * 4;
const BSSIDS: usize = 16 * 6;
pub(super) const REQUEST_BYTES: usize =
    PROBE + PROBE_SEGMENTS + PROBE_BUFFER_BYTES + 4 + DIRECT_SSIDS + SHORT_SSIDS + BSSIDS;
const FORCE_PASSIVE: u16 = 1 << 11;
const PASS_ALL: u16 = 1 << 1;
const ADAPTIVE_DWELL: u16 = 1 << 7;
const ENABLE_CHANNEL_ORDER: u8 = 1 << 5;
const PRIORITY_EXT_6: u32 = 6;
const ACTIVE_DWELL: u8 = 10;
const PASSIVE_DWELL: u8 = 110;
const FULL_SCAN_BUDGET_TU: u16 = 300;
pub(super) fn validate(
    firmware: &crate::net::wifi::intel::firmware::Firmware<'_>,
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
pub(super) fn passive(
    request: &protocol::Request,
    local: crate::net::Mac,
) -> Result<Vec<u8>, Ax200ScanError> {
    if request.active() {
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
    // Even the unused passive template is bounded and keeps every caller IE.
    // All SSID/short-SSID/BSSID arrays remain zero; no firmware probe selector
    // or implicit 6GHz/scheduled scan can enable transmission.
    let extra = request.extra_elements();
    if 26usize
        .checked_add(extra.len())
        .is_none_or(|n| n > PROBE_BUFFER_BYTES)
    {
        return Err(Ax200ScanError::UnsupportedRequest);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(REQUEST_BYTES)
        .map_err(|_| Ax200ScanError::NoMemory)?;
    bytes.resize(REQUEST_BYTES, 0);
    // One serialized UID0. Only the same owner can reuse it after
    // completion, command reclaim and old-RB/deferred-user retirement.
    bytes[4..8].copy_from_slice(&PRIORITY_EXT_6.to_le_bytes());
    bytes[GENERAL..GENERAL + 2]
        .copy_from_slice(&(FORCE_PASSIVE | PASS_ALL | ADAPTIVE_DWELL).to_le_bytes());
    bytes[GENERAL + 4..GENERAL + 6].fill(ACTIVE_DWELL);
    bytes[GENERAL + 6..GENERAL + 9].copy_from_slice(&[2, 8, 10]);
    bytes[GENERAL + 10..GENERAL + 12].copy_from_slice(&FULL_SCAN_BUDGET_TU.to_le_bytes());
    bytes[GENERAL + 28..GENERAL + 32].copy_from_slice(&PRIORITY_EXT_6.to_le_bytes());
    bytes[GENERAL + 32..GENERAL + 34].fill(PASSIVE_DWELL);
    // Both LMAC timing arrays are zero for the unassociated MAC.
    // EBS is disabled: no previous successful EBS is invented.
    bytes[CHANNELS] = ENABLE_CHANNEL_ORDER;
    bytes[CHANNELS + 1] = request.channels().len() as u8;
    bytes[CHANNELS + 2..CHANNELS + 4].copy_from_slice(&[10, 2]);
    for (i, channel) in request.channels().iter().enumerate() {
        let at = CHANNELS + 4 + i * CHANNEL_CONFIG_BYTES;
        bytes[at + 4] = channel.number as u8;
        bytes[at + 5] = u8::from(channel.band == Band::Ghz5);
        bytes[at + 6] = 1;
    }
    bytes[PERIODIC + 2] = 1; // one ordinary iteration, interval/delay zero
    bytes[PROBE + 2..PROBE + 4].copy_from_slice(&26u16.to_le_bytes());
    for segment in 1..=4 {
        bytes[PROBE + segment * 4..PROBE + segment * 4 + 2].copy_from_slice(&26u16.to_le_bytes());
    }
    bytes[PROBE + 18..PROBE + 20].copy_from_slice(&(extra.len() as u16).to_le_bytes());
    let frame = PROBE + PROBE_SEGMENTS;
    bytes[frame] = 0x40; // source probe-request subtype, unused under FORCE_PASSIVE
    bytes[frame + 4..frame + 10].fill(0xff);
    bytes[frame + 10..frame + 16].copy_from_slice(&local.0);
    bytes[frame + 16..frame + 22].fill(0xff);
    bytes[frame + 26..frame + 26 + extra.len()].copy_from_slice(extra);
    Ok(bytes)
}
