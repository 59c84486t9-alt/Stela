// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! The firmware commands of one association, as mvm's MLD callbacks fill them:
//! session protection around the join, the MAC, link and station updates of
//! `iwl_mvm_mld_mac_sta_state`, firmware rate selection (`rs_fw_rate_init`),
//! keys (`iwl_mvm_sec_key_add`), and the smart FIFO, power and beacon filter
//! changes an associated station takes. These are bytes: nothing here is
//! published or proves a firmware state.
use super::command::Id;
use crate::{
    Mac,
    wifi::{
        Band,
        regulatory::PowerType,
        security::{Cipher, management::ManagementCipher},
        station::{
            AssociationContext,
            operations::MuEdcaRecord,
            phy::{AccessCategory, He, Mode, Negotiated, Width},
            power_envelope::PowerEnvelope,
        },
    },
};
use alloc::vec::Vec;

pub const BLOCK_ACK_ALLOCATION: Id = Id {
    group: 5,
    opcode: 0x16,
    version: 0,
};
pub const SESSION_PROTECTION: Id = Id {
    group: 3,
    opcode: 5,
    version: 0,
};
pub const MAC_CONFIG: Id = Id {
    group: 3,
    opcode: 8,
    version: 0,
};
pub const LINK_CONFIG: Id = Id {
    group: 3,
    opcode: 9,
    version: 0,
};
pub const STATION_CONFIG: Id = Id {
    group: 3,
    opcode: 0x0a,
    version: 0,
};
pub const RATE_CONFIG: Id = Id {
    group: 5,
    opcode: 0x0f,
    version: 0,
};
pub const SECURITY_KEY: Id = Id {
    group: 5,
    opcode: 0x18,
    version: 0,
};
pub const SMART_FIFO: Id = Id {
    group: 0,
    opcode: 0xd1,
    version: 0,
};
pub const POWER_CONSTRAINTS: Id = Id {
    group: 4,
    opcode: 0x0c,
    version: 0,
};
pub const MAC_POWER: Id = Id {
    group: 0,
    opcode: 0xa9,
    version: 0,
};
pub const BEACON_FILTER: Id = Id {
    group: 0,
    opcode: 0xd2,
    version: 0,
};

const ACTION_ADD: u32 = 1;
const ACTION_MODIFY: u32 = 2;
const ACTION_REMOVE: u32 = 3;
const MAC_TYPE_BSS_STATION: u32 = 5;
const ACCEPT_GROUP: u32 = 1 << 2;
const ACCEPT_BEACON: u32 = 1 << 3;
const COEX_HIGH_PRIORITY: u32 = 1 << 5;
/// `LINK_CONTEXT_MODIFY_ALL` without `LINK_CONTEXT_MODIFY_ACTIVE`.
const MODIFY_ALL_BUT_ACTIVE: u32 = 0xfe;
/// `iwl_mvm_protect_assoc`'s 900 ms in `MSEC_TO_TU` time units.
const ASSOCIATION_PROTECTION_TU: u32 = 900 * 1000 / 1024;
/// `POWER_KEEP_ALIVE_PERIOD_SEC`.
const KEEP_ALIVE_SECONDS: u32 = 25;
const TU_US: u32 = 1024;

fn word(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn half(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

/// `SESSION_PROTECTION_CMD` for `SESSION_PROTECT_CONF_ASSOC` on link and MAC
/// 0, keeping the link on its channel while the join's exchange runs.
pub fn protect_session(remove: bool) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 24];
    word(
        &mut bytes,
        4,
        if remove { ACTION_REMOVE } else { ACTION_ADD },
    );
    if !remove {
        word(&mut bytes, 12, ASSOCIATION_PROTECTION_TU);
    }
    bytes
}

/// What `MAC_CONFIG_CMD` says of the station once the AP knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacState {
    pub address: Mac,
    pub he: bool,
    pub eht: bool,
    /// The association's AID, once it has one.
    pub aid: Option<u16>,
    /// `COEX_HIGH_PRIORITY_ENABLE`: until the port opens, Bluetooth yields to
    /// the handshake's frames.
    pub high_priority: bool,
}

/// `iwl_mac_config_cmd`: version 4 can name NAN addresses.
pub fn mac_bytes(version: u8) -> usize {
    if version >= 4 { 56 } else { 52 }
}

/// `iwl_mac_power_cmd`: version 3 keeps the first 20 of `_v2`'s 40 bytes, and a
/// station without power management or uAPSD leaves zero what it moved.
pub fn power_bytes(version: u8) -> usize {
    if version >= 3 { 20 } else { 40 }
}

/// `iwl_sta_cfg_cmd`: each later version names more of the peer.
pub fn station_bytes(version: u8) -> usize {
    match version {
        0 | 1 => 96,
        2 => 104,
        _ => 112,
    }
}

/// `iwl_mvm_mld_mac_ctxt_cmd_sta` modifying MAC 0. `version` is the firmware's
/// `MAC_CONFIG_CMD` version.
pub fn mac_config(version: u8, state: MacState) -> Vec<u8> {
    let mut bytes = alloc::vec![0; mac_bytes(version)];
    word(&mut bytes, 4, ACTION_MODIFY);
    word(&mut bytes, 8, MAC_TYPE_BSS_STATION);
    bytes[12..18].copy_from_slice(&state.address.0);
    let beacons = if state.aid.is_some() {
        0
    } else {
        ACCEPT_BEACON
    };
    word(&mut bytes, 20, ACCEPT_GROUP | beacons);
    if version == 2 {
        half(&mut bytes, 24, u16::from(state.he));
        word(&mut bytes, 28, u32::from(state.eht));
    } else {
        bytes[24] = u8::from(state.he);
        bytes[26] = u8::from(state.eht);
    }
    word(&mut bytes, 32, 1);
    if let Some(aid) = state.aid {
        word(&mut bytes, 36, 1);
        word(&mut bytes, 40, u32::from(aid));
    }
    if state.high_priority {
        word(&mut bytes, 44, COEX_HIGH_PRIORITY);
    }
    bytes
}

/// `iwl_mvm_ack_rates`: the CCK and OFDM masks of the rates the station
/// responds at: the BSS's basic rates, in the hardware's order of 1 Mb/s
/// first, with the mandatory rates below the lowest of them.
fn ack_rates(band: Band, basic: u16) -> (u32, u32) {
    let (mut cck, mut ofdm) = (u32::from(basic & 0xf), u32::from(basic >> 4));
    ofdm |= 1;
    let lowest_ofdm = if ofdm >> 1 == 0 {
        u32::MAX
    } else {
        (ofdm >> 1).trailing_zeros() + 1
    };
    // 24 and 12 Mb/s are ofdm bits 4 and 2.
    if lowest_ofdm > 4 {
        ofdm |= 1 << 4;
    }
    if lowest_ofdm > 2 {
        ofdm |= 1 << 2;
    }
    if band == Band::Ghz2 {
        let lowest = if cck == 0 { 4 } else { cck.trailing_zeros() };
        cck |= (1 << lowest) - 1;
    }
    (cck, ofdm)
}

/// The rates of `band` as the firmware numbers them, 1 Mb/s first: a station's
/// are in its band's own table, whose 5 GHz one starts at 6 Mb/s.
pub fn hardware_rates(band: Band, rates: u16) -> u16 {
    if band == Band::Ghz2 {
        rates
    } else {
        rates << 4
    }
}

/// `iwl_mvm_set_fw_protection_flags`' inputs from the AP's beacon.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Protection {
    /// ERP `Use_Protection`.
    pub erp: bool,
    /// HT Operation's HT protection field.
    pub ht_mode: u8,
}

fn protection_flags(protection: Protection, width: Width) -> u32 {
    const TGG: u32 = 1;
    const HT: u32 = 2;
    const FAT: u32 = 4;
    let wide = width != Width::Mhz20;
    let ht = match protection.ht_mode {
        // IEEE80211_HT_OP_MODE_PROTECTION_NONMEMBER and _NONHT_MIXED.
        1 | 3 => HT | if wide { FAT } else { 0 },
        // IEEE80211_HT_OP_MODE_PROTECTION_20MHZ.
        2 if wide => HT | FAT,
        _ => 0,
    };
    ht | if protection.erp { TGG } else { 0 }
}

/// What `LINK_CONFIG_CMD` says of the link once its BSS is known.
#[derive(Clone, Copy, Debug)]
pub struct LinkState<'a> {
    pub address: Mac,
    pub band: Band,
    pub basic_rates: u16,
    pub short_preamble: bool,
    pub short_slot: bool,
    pub protection: Protection,
    pub width: Width,
    pub qos: bool,
    pub edca: &'a [AccessCategory; 4],
    pub beacon_interval: u16,
    pub dtim_period: u8,
    pub he: Option<LinkHe>,
}

/// What a link says of an HE AP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkHe {
    pub packet_extension: u8,
    /// The OCW range, where the AP runs random access.
    pub uora: Option<u8>,
    pub mu_edca: Option<[MuEdcaRecord; 4]>,
    pub color: u8,
    pub color_enabled: bool,
    pub rts_threshold: u16,
    /// `IEEE80211_HE_MAC_CAP5_OM_CTRL_UL_MU_DATA_DIS_RX`.
    pub uplink_data_disabled: bool,
}

/// `iwl_mvm_mac80211_ac_to_ucode_ac`: the firmware orders them BK, BE.
const fn firmware_category(aci: usize) -> usize {
    match aci {
        0 => 1,
        1 => 0,
        other => other,
    }
}

/// `iwl_mvm_send_ap_tx_power_constraint_cmd` for link 0 of a station, with
/// `iwl_mvm_tpe_sta_cmd_data`'s stricter of the AP's own and client limits.
pub fn power_constraints(ap_type: PowerType, envelope: &PowerEnvelope) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 28];
    bytes[2] = match ap_type {
        PowerType::LowPowerIndoor => 0,
        PowerType::StandardPower => 1,
        PowerType::VeryLowPower => 2,
    };
    let (local, client) = (&envelope.max_local[0], &envelope.max_client[0]);
    for (index, out) in bytes[4..9].iter_mut().enumerate() {
        *out = local.power[index].min(client.power[index]) as u8;
    }
    let (local, client) = (&envelope.psd_local[0], &envelope.psd_client[0]);
    for (index, out) in bytes[9..25].iter_mut().enumerate() {
        *out = local.power[index].min(client.power[index]) as u8;
    }
    bytes
}

/// `iwl_mvm_link_changed` for every part but activation.
pub fn link_config(version: u8, state: LinkState<'_>) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 208];
    word(&mut bytes, 0, ACTION_MODIFY);
    bytes[16..22].copy_from_slice(&state.address.0);
    word(&mut bytes, 24, MODIFY_ALL_BUT_ACTIVE);
    word(&mut bytes, 28, 1);
    let (cck, ofdm) = ack_rates(state.band, hardware_rates(state.band, state.basic_rates));
    word(&mut bytes, 36, cck);
    word(&mut bytes, 40, ofdm);
    word(&mut bytes, 44, u32::from(state.short_preamble));
    word(&mut bytes, 48, u32::from(state.short_slot));
    word(
        &mut bytes,
        52,
        protection_flags(state.protection, state.width),
    );
    let flags = u32::from(state.qos) | u32::from(state.width != Width::Mhz20) << 1;
    word(&mut bytes, 56, flags);
    for category in state.edca {
        let ac = firmware_category(usize::from(category.aci));
        let at = 60 + ac * 8;
        half(&mut bytes, at, (1 << category.ecw_min) - 1);
        half(&mut bytes, at + 2, (1 << category.ecw_max) - 1);
        bytes[at + 4] = category.aifsn;
        bytes[at + 5] = 1 << (ac + 1);
        half(&mut bytes, at + 6, category.txop_32us.saturating_mul(32));
    }
    let interval = u32::from(state.beacon_interval);
    word(&mut bytes, 136, interval);
    word(&mut bytes, 140, interval * u32::from(state.dtim_period));
    if let Some(he) = state.he {
        link_he(&mut bytes, version, he);
    }
    bytes
}

/// The HE half of `iwl_mvm_link_changed`.
fn link_he(bytes: &mut [u8], version: u8, he: LinkHe) {
    const COLOR_DISABLED: u32 = 1;
    const MU_EDCA: u32 = 2;
    bytes[100] = he.packet_extension;
    if let Some(range) = he.uora {
        bytes[101] = range & 7;
        bytes[102] = (range >> 3) & 7;
    }
    bytes[167] = u8::from(he.uplink_data_disabled);
    let mut flags = 0;
    if let Some(records) = he.mu_edca {
        flags |= MU_EDCA;
        for (aci, record) in records.into_iter().enumerate() {
            let at = 104 + firmware_category(aci) * 8;
            half(bytes, at, u16::from(record.ecw_min_max & 0xf));
            half(bytes, at + 2, u16::from(record.ecw_min_max >> 4));
            half(bytes, at + 4, u16::from(record.aifsn & 0xf));
            half(bytes, at + 6, u16::from(record.timer));
        }
    }
    bytes[165] = he.color;
    if !he.color_enabled {
        flags |= COLOR_DISABLED;
    }
    half(bytes, 146, he.rts_threshold);
    word(bytes, 148, flags);
    if version < 6 {
        word(bytes, 152, flags);
    }
}

/// What `STA_CONFIG_CMD` says of the AP station.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerState {
    pub address: Mac,
    pub aid: u16,
    /// Robust frames need the firmware's protection: the association's PMF
    /// and, as `iwl_mvm_mld_cfg_sta` sets it, every station before its port
    /// opens where the firmware has `IWL_UCODE_TLV_CAPA_STA_EXP_MFP_SUPPORT`.
    pub mfp: bool,
    pub mimo: bool,
    pub ampdu_spacing: u8,
    pub ampdu_exponent: u8,
    pub wmm_service_period: Option<u8>,
    pub uapsd_queues: u8,
    pub he: Option<PeerHe>,
}

/// What `STA_CONFIG_CMD` says of an HE AP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerHe {
    pub ack_enabled: bool,
    pub random_access: bool,
    pub packet_extension: [u8; PACKET_EXTENSION_BYTES],
    pub control: u32,
}

/// `iwl_he_pkt_ext_v2`: two thresholds for two streams at five widths.
const PACKET_EXTENSION_BYTES: usize = 20;
const STREAMS: usize = 2;
const WIDTHS: usize = 5;
/// `IWL_HE_PKT_EXT_NONE`.
const EXTENSION_NONE: u8 = 7;
/// `IWL_HE_PKT_EXT_BPSK`.
const EXTENSION_BPSK: u8 = 0;

/// `iwl_mvm_he_get_ppe_val`: three bits at `position`, which may straddle a byte.
fn threshold(ppe: &[u8], position: usize) -> u8 {
    let byte = |index: usize| u16::from(ppe.get(index).copied().unwrap_or(0));
    let pair = byte(position / 8) | byte(position / 8 + 1) << 8;
    ((pair >> (position % 8)) & 7) as u8
}

/// `iwl_mvm_set_sta_pkt_ext` for an HE AP: its PPE thresholds, or else what its
/// nominal padding implies.
pub fn packet_extension(he: &He) -> [u8; PACKET_EXTENSION_BYTES] {
    const THRESHOLDS_PRESENT: u8 = 0x80;
    const PADDING_RESERVED: u8 = 3;
    let mut table = [EXTENSION_NONE; PACKET_EXTENSION_BYTES];
    if he.phy[6] & THRESHOLDS_PRESENT != 0 {
        let ppe = he.ppe.as_slice();
        let header = ppe.first().copied().unwrap_or(0);
        let streams = (usize::from(header & 7) + 1).min(STREAMS);
        let widths = (header >> 3) & 0xf;
        let mut position = 7;
        for stream in 0..streams {
            for width in 0..WIDTHS {
                if widths >> width & 1 == 0 {
                    continue;
                }
                let at = (stream * WIDTHS + width) * 2;
                table[at + 1] = threshold(ppe, position);
                table[at] = threshold(ppe, position + 3);
                position += 6;
            }
        }
        return table;
    }
    let (low, high) = match he.phy[9] >> 6 {
        0 => (EXTENSION_NONE, EXTENSION_NONE),
        1 => (EXTENSION_BPSK, EXTENSION_NONE),
        2 => (EXTENSION_NONE, EXTENSION_BPSK),
        PADDING_RESERVED.. => return table,
    };
    for pair in table.as_chunks_mut::<2>().0 {
        *pair = [low, high];
    }
    table
}

/// `iwl_mvm_get_sta_htc_flags`.
pub fn control_flags(mac: &[u8; 6]) -> u32 {
    const SUPPORT: u32 = 1;
    const LINK_ADAPTATION_UNSOLICITED: u32 = 2 << 1;
    const LINK_ADAPTATION_BOTH: u32 = 3 << 1;
    const BUFFER_STATUS: u32 = 1 << 4;
    const OPERATING_MODE: u32 = 1 << 5;
    const BANDWIDTH_QUERY: u32 = 1 << 6;
    let mut flags = 0;
    if mac[0] & 1 != 0 {
        flags |= SUPPORT;
    }
    match (mac[2] & 1) << 1 | mac[1] >> 7 {
        2 => flags |= LINK_ADAPTATION_UNSOLICITED,
        3 => flags |= LINK_ADAPTATION_BOTH,
        _ => {}
    }
    if mac[2] & 8 != 0 {
        flags |= BUFFER_STATUS;
    }
    if mac[3] & 2 != 0 {
        flags |= OPERATING_MODE;
    }
    if mac[4] & 4 != 0 {
        flags |= BANDWIDTH_QUERY;
    }
    flags
}

/// `iwl_mvm_get_sta_ampdu_dens`' size: the base exponent and the HE extension,
/// bounded by the firmware's 4 MB.
pub fn ampdu_exponent(negotiated: &Negotiated) -> u8 {
    const LIMIT_4M: u8 = 7;
    let extension = negotiated.he.as_ref().map_or(0, |he| (he.mac[3] >> 3) & 3);
    (negotiated.peer_ampdu_base_exponent + extension).min(LIMIT_4M)
}

/// `iwl_mvm_mld_cfg_sta` for station 0 on link 0. `version` is the firmware's
/// `STA_CONFIG_CMD` version.
pub fn station_config(version: u8, state: PeerState) -> Vec<u8> {
    let mut bytes = alloc::vec![0; station_bytes(version)];
    if version >= 3 {
        word(&mut bytes, 4, 1);
    }
    bytes[8..14].copy_from_slice(&state.address.0);
    bytes[16..22].copy_from_slice(&state.address.0);
    word(&mut bytes, 28, u32::from(state.aid));
    word(&mut bytes, 36, u32::from(state.mfp));
    word(&mut bytes, 40, u32::from(state.mimo));
    word(&mut bytes, 56, u32::from(state.ampdu_spacing));
    word(&mut bytes, 60, u32::from(state.ampdu_exponent));
    if let Some(period) = state.wmm_service_period {
        word(
            &mut bytes,
            64,
            if period == 0 {
                128
            } else {
                u32::from(period) * 2
            },
        );
        word(&mut bytes, 68, u32::from(state.uapsd_queues));
    }
    if let Some(he) = state.he {
        word(&mut bytes, 48, u32::from(he.ack_enabled));
        word(&mut bytes, 52, u32::from(he.random_access));
        bytes[72..92].copy_from_slice(&he.packet_extension);
        word(&mut bytes, 92, he.control);
    }
    bytes
}

/// `rs_fw_he_ieee80211_mcs_to_rs_mcs`, and the VHT table's first three values.
fn mcs_bits(map: u16, nss: usize, top: [u16; 3]) -> u16 {
    match (map >> (nss * 2)) & 3 {
        3 => 0,
        value => (1 << (top[usize::from(value)] + 1)) - 1,
    }
}

/// `iwl_tlc_config_cmd_v4`'s width code.
fn width_code(width: Width) -> Option<u8> {
    match width {
        Width::Mhz20 => Some(0),
        Width::Mhz40 => Some(1),
        Width::Mhz80 => Some(2),
        Width::Mhz160 => Some(3),
        Width::Mhz320 => Some(4),
        Width::Mhz80P80 => None,
    }
}

/// `rs_fw_get_max_amsdu_len`: the longest A-MSDU the AP takes. An HT peer's
/// long form does not apply, because the firmware may put it in an A-MPDU.
pub fn max_amsdu(negotiated: &Negotiated) -> u16 {
    match negotiated.max_tx_amsdu {
        7935 => 4095,
        bytes => bytes,
    }
}

/// How a `TLC_MNG_CONFIG_CMD` version lays out what `rate_config` fills.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateShape {
    pub bytes: usize,
    /// Where `max_ch_width` lies.
    pub head: usize,
    /// Width classes per stream.
    classes: usize,
    /// One class's rate bitmap.
    rate_bytes: usize,
}

impl RateShape {
    pub fn of(version: u8) -> Option<Self> {
        match version {
            1 | 2 => Some(Self {
                bytes: 24,
                head: 4,
                classes: 2,
                rate_bytes: 2,
            }),
            3 | 4 => Some(Self {
                bytes: 28,
                head: 4,
                classes: 3,
                rate_bytes: 2,
            }),
            6 => Some(Self {
                bytes: 52,
                head: 8,
                classes: 4,
                rate_bytes: 4,
            }),
            _ => None,
        }
    }
}

/// `rs_fw_set_supp_rates` and the rest of `iwl_mvm_rs_fw_rate_init`: the
/// rates firmware rate selection may use for the AP. Until the port opens
/// `authorized` is false and it stays at 20 MHz. `max_mpdu` is what the
/// firmware may report as an A-MSDU's limit, or zero for none.
pub fn rate_config(
    negotiated: &Negotiated,
    band: Band,
    antennas: u8,
    shape: RateShape,
    authorized: bool,
    max_mpdu: u16,
) -> Option<Vec<u8>> {
    let RateShape { bytes, head, .. } = shape;
    let mut out = alloc::vec![0; bytes];
    // Version 6 names stations by mask, station 0 by its bit.
    if head == 8 {
        out[0] = 1;
    }
    half(&mut out, bytes - 4, max_mpdu);
    let width = if authorized {
        width_code(negotiated.width)?
    } else {
        0
    };
    out[head] = width;
    out[head + 1] = match negotiated.mode {
        Mode::Legacy => 0,
        Mode::Ht => 1,
        Mode::Vht => 2,
        Mode::He => 3,
        Mode::Eht => return None,
    };
    out[head + 2] = antennas;
    let (ht, vht, he) = (&negotiated.ht, &negotiated.vht, &negotiated.he);
    if he.is_none() {
        // rs_fw_sgi_cw_support: an HE station's guard intervals are the
        // firmware's own.
        let ht_cap = ht.as_ref().map_or(0, |ht| ht.capability);
        let vht_cap = vht.as_ref().map_or(0, |vht| vht.capability);
        out[head + 3] = u8::from(ht_cap & 0x20 != 0)
            | u8::from(ht_cap & 0x40 != 0) << 1
            | u8::from(vht_cap & 0x20 != 0) << 2
            | u8::from(vht_cap & 0x40 != 0) << 3;
    }
    // rs_fw_get_config_flags. Both STBC and LDPC need the peer to receive
    // them; STBC also needs a second transmit chain.
    let ht_cap = ht.as_ref().map_or(0, |ht| ht.capability);
    let vht_cap = vht.as_ref().map_or(0, |vht| vht.capability);
    let stbc = he.as_ref().is_some_and(|he| he.phy[2] & 0x80 != 0)
        || vht_cap & 0x700 != 0
        || ht_cap & 0x300 != 0;
    let ldpc = ht_cap & 1 != 0
        || vht_cap & 0x10 != 0
        || he.as_ref().is_some_and(|he| he.phy[1] & 0x20 != 0);
    let flags = u16::from(stbc && antennas.count_ones() > 1) | u16::from(ldpc) << 1;
    half(&mut out, head + 4, flags);
    half(
        &mut out,
        head + 6,
        hardware_rates(band, negotiated.legacy.supported),
    );
    // Each stream's rates, per width class of the command's version.
    let mut set = |nss: usize, wide: usize, bits: u16| {
        let at = head + 8 + (nss * shape.classes + wide) * shape.rate_bytes;
        half(&mut out, at, bits);
    };
    match negotiated.mode {
        Mode::Legacy | Mode::Eht => {}
        Mode::Ht => {
            let mcs = ht.as_ref()?.peer_rx_mcs;
            set(0, 0, u16::from(mcs[0]));
            set(1, 0, u16::from(mcs[1]));
        }
        Mode::Vht => {
            let vht = vht.as_ref()?;
            for nss in 0..2 {
                let mut bits = mcs_bits(vht.mcs.rx, nss, [7, 8, 9]);
                // MCS 9 does not exist at 20 MHz for one or two streams.
                if negotiated.width == Width::Mhz20 {
                    bits &= 0x1ff;
                }
                set(nss, 0, bits);
                if negotiated.width == Width::Mhz160 {
                    set(nss, 1, bits);
                }
            }
        }
        Mode::He => {
            let he = he.as_ref()?;
            for nss in 0..2 {
                set(nss, 0, mcs_bits(he.mcs_80.rx, nss, [7, 9, 11]));
                if let Some(wide) = he.mcs_160 {
                    set(nss, 1, mcs_bits(wide.rx, nss, [7, 9, 11]));
                }
            }
        }
    }
    Some(out)
}

/// `iwl_mvm_get_sec_flags` for a data or group key.
pub fn key_flags(cipher: Cipher, pairwise: bool, management: bool) -> Option<u32> {
    const CCMP: u32 = 2;
    const GCMP: u32 = 5;
    const KEY_SIZE: u32 = 0x10;
    const MFP: u32 = 0x20;
    const MCAST: u32 = 0x40;
    let suite = match cipher {
        Cipher::Ccmp128 => CCMP,
        Cipher::Ccmp256 => CCMP | KEY_SIZE,
        Cipher::Gcmp128 => GCMP,
        Cipher::Gcmp256 => GCMP | KEY_SIZE,
        Cipher::Tkip | Cipher::Wep40 | Cipher::Wep104 => return None,
    };
    Some(suite | if pairwise { 0 } else { MCAST } | if management { MFP } else { 0 })
}

/// `iwl_mvm_get_sec_flags` for an IGTK.
pub fn management_key_flags(cipher: ManagementCipher) -> u32 {
    const CCMP: u32 = 2;
    const GCMP: u32 = 5;
    const KEY_SIZE: u32 = 0x10;
    const MFP: u32 = 0x20;
    const MCAST: u32 = 0x40;
    MFP | MCAST
        | match cipher {
            ManagementCipher::Cmac128 => CCMP,
            ManagementCipher::Cmac256 => CCMP | KEY_SIZE,
            ManagementCipher::Gmac128 => GCMP,
            ManagementCipher::Gmac256 => GCMP | KEY_SIZE,
        }
}

/// `iwl_mvm_mld_send_key` adding a key for station 0. `receive` is the
/// packet number the AP's frames continue from.
pub fn add_key(index: u8, flags: u32, material: &[u8], receive: u64) -> Option<Vec<u8>> {
    if material.len() > 32 {
        return None;
    }
    let mut bytes = alloc::vec![0; 80];
    word(&mut bytes, 0, ACTION_ADD);
    word(&mut bytes, 4, 1);
    word(&mut bytes, 8, u32::from(index));
    word(&mut bytes, 12, flags);
    bytes[16..16 + material.len()].copy_from_slice(material);
    bytes[64..72].copy_from_slice(&receive.to_le_bytes());
    Some(bytes)
}

/// The AP's firmware station, as `iwl_mvm_sta_fw_id_mask` names it.
const STATION_MASK: u32 = 1;

/// `iwl_rx_baid_cfg_cmd`, for `IWL_RX_BAID_ACTION_ADD`.
pub fn allocate_block_ack(tid: u8, start: u16, window: u16) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 16];
    word(&mut bytes, 4, STATION_MASK);
    bytes[8] = tid;
    bytes[12..14].copy_from_slice(&start.to_le_bytes());
    bytes[14..16].copy_from_slice(&window.to_le_bytes());
    bytes
}

/// `iwl_rx_baid_cfg_cmd`, for `IWL_RX_BAID_ACTION_REMOVE`: version 1 names
/// the session the firmware gave, later ones its station and TID.
pub fn remove_block_ack(version: u8, id: u8, tid: u8) -> Vec<u8> {
    const REMOVE: u32 = 2;
    let mut bytes = alloc::vec![0; 16];
    word(&mut bytes, 0, REMOVE);
    if version <= 1 {
        word(&mut bytes, 4, u32::from(id));
    } else {
        word(&mut bytes, 4, STATION_MASK);
        word(&mut bytes, 8, u32::from(tid));
    }
    bytes
}

/// `__iwl_mvm_sec_key_del`.
pub fn remove_key(index: u8, flags: u32) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 80];
    word(&mut bytes, 0, ACTION_REMOVE);
    word(&mut bytes, 4, 1);
    word(&mut bytes, 8, u32::from(index));
    word(&mut bytes, 12, flags);
    bytes
}

/// `iwl_mvm_fill_sf_command` for `SF_FULL_ON`: what the firmware's smart FIFO
/// keeps for the AP's rates, on firmware that does not manage it itself.
pub fn smart_fifo(negotiated: &Negotiated) -> Vec<u8> {
    const FULL_ON: u32 = 0;
    const LONG_DELAY_AGING: u32 = 1_000_000;
    const FULL_TIMEOUTS: [[u32; 2]; 5] = [
        [2016, 320],
        [2016, 320],
        [10016, 2016],
        [2016, 320],
        [2016, 320],
    ];
    let watermark = match (negotiated.mode, negotiated.rx_nss) {
        (Mode::Legacy, _) => 4096,
        (_, 1) => 6144,
        (_, 2) => 8192,
        _ => 6144,
    };
    let mut bytes = alloc::vec![0; 92];
    word(&mut bytes, 0, FULL_ON);
    word(&mut bytes, 4, 4096);
    word(&mut bytes, 8, watermark);
    for index in 0..10 {
        word(&mut bytes, 12 + index * 4, LONG_DELAY_AGING);
    }
    for (index, timeout) in FULL_TIMEOUTS.iter().flatten().enumerate() {
        word(&mut bytes, 52 + index * 4, *timeout);
    }
    bytes
}

/// `iwl_mvm_power_build_cmd` for a station whose power management stays off:
/// the keep-alive a beacon interval and DTIM period need.
pub fn power(version: u8, save_power: bool, beacon_interval: u16, dtim_period: u8) -> Vec<u8> {
    let mut bytes = alloc::vec![0; power_bytes(version)];
    half(&mut bytes, 4, u16::from(save_power));
    let beacons = 3 * u32::from(dtim_period) * u32::from(beacon_interval);
    let keep_alive = (beacons * TU_US)
        .div_ceil(1_000_000)
        .max(KEEP_ALIVE_SECONDS);
    half(&mut bytes, 6, keep_alive as u16);
    bytes
}

/// `IWL_BF_CMD_CONFIG_DEFAULTS` enabling the filter: `bytes` is the firmware's
/// 44 or 60 byte body.
pub fn beacon_filter(bytes: usize) -> Vec<u8> {
    let mut out = alloc::vec![0; bytes];
    for (index, value) in [5, 1, 72, 112, 1, 5, 1, 0, 0, 6, 1].into_iter().enumerate() {
        word(&mut out, index * 4, value);
    }
    out
}

/// What the AP's beacon says of protection, ERP and HT Operation alike.
pub fn protection(context: &AssociationContext) -> Protection {
    let elements = &context.beacon().elements;
    Protection {
        erp: crate::wifi::connection::find(elements, 42)
            .and_then(|erp| erp.first())
            .is_some_and(|erp| erp & 2 != 0),
        ht_mode: crate::wifi::connection::find(elements, 61)
            .and_then(|operation| operation.get(2))
            .map_or(0, |mode| mode & 3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_7_firmware_reads_its_support_as_bytes_in_a_longer_command() {
        let state = MacState {
            address: Mac([2, 0, 0, 0, 0, 1]),
            he: true,
            eht: true,
            aid: Some(7),
            high_priority: false,
        };
        let bytes = mac_config(4, state);
        assert_eq!(bytes.len(), 56);
        assert_eq!(bytes[24..28], [1, 0, 1, 0]);
        assert_eq!(bytes[28..32], [0; 4]);
        assert_eq!(bytes[40..42], [7, 0]);
        let older = mac_config(2, state);
        assert_eq!(older.len(), 52);
        assert_eq!(older[24..32], [1, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn a_peer_is_named_by_its_links_mask_from_version_3() {
        let state = PeerState {
            address: Mac([2, 0, 0, 0, 0, 2]),
            aid: 1,
            mfp: false,
            mimo: false,
            ampdu_spacing: 0,
            ampdu_exponent: 0,
            wmm_service_period: None,
            uapsd_queues: 0,
            he: None,
        };
        let bytes = station_config(3, state);
        assert_eq!(bytes.len(), 112);
        assert_eq!(bytes[4..8], [1, 0, 0, 0]);
        let older = station_config(2, state);
        assert_eq!(older.len(), 104);
        assert_eq!(older[4..8], [0; 4]);
    }

    #[test]
    fn a_rate_command_has_its_versions_shape() {
        let shape = |version| RateShape::of(version).map(|shape| (shape.bytes, shape.head));
        assert_eq!(shape(2), Some((24, 4)));
        assert_eq!(shape(4), Some((28, 4)));
        assert_eq!(shape(6), Some((52, 8)));
        assert_eq!(shape(5), None);
    }

    #[test]
    fn power_constraints_take_the_stricter_limit_of_each_width() {
        let mut envelope = PowerEnvelope::none();
        envelope.max_local[0].power[0] = 30;
        envelope.max_client[0].power[0] = 20;
        envelope.psd_client[0].power[15] = -8;
        let bytes = power_constraints(PowerType::VeryLowPower, &envelope);
        assert_eq!(bytes.len(), 28);
        assert_eq!(bytes[..4], [0, 0, 2, 0]);
        assert_eq!(bytes[4..6], [20, 127]);
        assert_eq!(bytes[23..25], [127, 0xf8]);
        assert_eq!(bytes[25..], [0; 3]);
    }

    #[test]
    fn mandatory_rates_fill_in_below_the_lowest_basic_rate() {
        // iwl_mvm_ack_rates at 2.4 GHz with basic 11 Mb/s and 24 Mb/s.
        assert_eq!(ack_rates(Band::Ghz2, 0b1_0000_1000), (0b1111, 0b10101));
        // 5 GHz basic 6 and 12 Mb/s stays without CCK.
        assert_eq!(ack_rates(Band::Ghz5, 0b101_0000), (0, 0b101));
        assert_eq!(hardware_rates(Band::Ghz5, 0b101), 0b101_0000);
    }

    #[test]
    fn a_session_protects_900_ms_and_its_removal_carries_no_duration() {
        let add = protect_session(false);
        assert_eq!(add[4], 1);
        assert_eq!(u32::from_le_bytes(add[12..16].try_into().unwrap()), 878);
        let remove = protect_session(true);
        assert_eq!(remove[4], 3);
        assert_eq!(remove[12..16], [0; 4]);
    }

    #[test]
    fn the_mac_stops_taking_beacons_once_it_has_an_aid() {
        let mut state = MacState {
            address: Mac([2, 0, 0, 0, 0, 1]),
            he: true,
            eht: false,
            aid: None,
            high_priority: true,
        };
        let bytes = mac_config(2, state);
        assert_eq!(bytes[4], 2);
        assert_eq!(bytes[20], 0b1100);
        assert_eq!(bytes[24], 1);
        assert_eq!(bytes[44], 1 << 5);
        state.aid = Some(7);
        state.high_priority = false;
        let bytes = mac_config(2, state);
        assert_eq!(bytes[20], 0b100);
        assert_eq!((bytes[36], bytes[40], bytes[44]), (1, 7, 0));
    }

    #[test]
    fn a_link_orders_edca_by_the_firmware_and_derives_the_dtim_interval() {
        let edca: [AccessCategory; 4] = core::array::from_fn(|aci| AccessCategory {
            aci: aci as u8,
            admission_control: false,
            aifsn: 2 + aci as u8,
            ecw_min: 4,
            ecw_max: 10,
            txop_32us: aci as u16,
        });
        let bytes = link_config(
            5,
            LinkState {
                address: Mac([2; 6]),
                band: Band::Ghz5,
                basic_rates: 1,
                short_preamble: false,
                short_slot: true,
                protection: Protection {
                    erp: true,
                    ht_mode: 1,
                },
                width: Width::Mhz40,
                qos: true,
                edca: &edca,
                beacon_interval: 100,
                dtim_period: 3,
                he: None,
            },
        );
        assert_eq!(bytes[24], 0xfe);
        assert_eq!(bytes[36], 0);
        assert_eq!(bytes[40], 0b10101);
        assert_eq!(bytes[52], 0b111);
        assert_eq!(bytes[56], 0b11);
        // BE's ACI 0 is the firmware's AC 1.
        assert_eq!(bytes[60 + 8 + 4], 2);
        assert_eq!(bytes[60 + 8 + 5], 1 << 2);
        assert_eq!(bytes[60 + 4], 3);
        assert_eq!(
            u16::from_le_bytes([bytes[60 + 16 + 6], bytes[60 + 16 + 7]]),
            64
        );
        assert_eq!(u32::from_le_bytes(bytes[140..144].try_into().unwrap()), 300);
        assert_eq!(
            bytes[156..162],
            [0; 6],
            "only a nontransmitted BSS names one"
        );
    }

    #[test]
    fn keys_carry_their_suite_and_scope() {
        assert_eq!(key_flags(Cipher::Ccmp128, true, false), Some(2));
        assert_eq!(key_flags(Cipher::Gcmp256, false, false), Some(0x55));
        assert_eq!(key_flags(Cipher::Ccmp128, false, true), Some(0x62));
        assert_eq!(key_flags(Cipher::Tkip, true, false), None);
        let bytes = add_key(1, 0x42, &[9; 16], 5).unwrap();
        assert_eq!((bytes[0], bytes[4], bytes[8], bytes[12]), (1, 1, 1, 0x42));
        assert_eq!(bytes[16..32], [9; 16]);
        assert_eq!(bytes[64], 5);
        assert_eq!(add_key(0, 2, &[0; 33], 0), None);
    }

    #[test]
    fn the_keep_alive_covers_three_dtim_periods() {
        let quick = power(2, false, 100, 1);
        assert_eq!(u16::from_le_bytes([quick[6], quick[7]]), 25);
        let slow = power(3, false, 1000, 10);
        assert_eq!(slow.len(), 20);
        assert_eq!(u16::from_le_bytes([slow[6], slow[7]]), 31);
    }

    #[test]
    fn the_beacon_filter_takes_mvm_defaults() {
        let bytes = beacon_filter(44);
        assert_eq!(
            (bytes[0], bytes[8], bytes[24], bytes[36], bytes[40]),
            (5, 72, 1, 6, 1)
        );
    }

    /// `he`, an AP's HE capabilities with these MAC and PHY bytes and `ppe`.
    fn ap(mac: [u8; 6], phy: [u8; 11], ppe: &[u8]) -> crate::wifi::station::phy::Capabilities {
        let mut elements = alloc::vec![1, 1, 0x8c, 255, 0, 35];
        elements.extend(mac);
        elements.extend(phy);
        elements.extend([0xfa, 0xff, 0xfa, 0xff]);
        elements.extend(ppe);
        elements[4] = (elements.len() - 5) as u8;
        crate::wifi::station::phy::Capabilities::parse(
            Band::Ghz5,
            crate::wifi::station::phy::Role::AccessPoint,
            &elements,
        )
        .unwrap()
    }

    #[test]
    fn ppe_thresholds_fill_the_widths_their_bitmap_names() {
        // Two streams at widths two and three, as Intel's own thresholds:
        // PPET16 of 0 and PPET8 of 7, which take bits across bytes.
        let mut phy = [0; 11];
        phy[6] = 0x80;
        let capabilities = ap([0; 6], phy, &[0x61, 0x1c, 0xc7, 0x71]);
        let table = packet_extension(capabilities.he().unwrap());
        assert_eq!(table[..4], [7; 4], "narrower widths stay unset");
        assert_eq!(table[4..8], [7, 0, 7, 0]);
        assert_eq!(table[8..10], [7, 7]);
        assert_eq!(table[10..14], [7; 4]);
        assert_eq!(table[14..18], [7, 0, 7, 0]);
    }

    #[test]
    fn a_nominal_padding_stands_in_for_absent_thresholds() {
        let padded = |value: u8| {
            let mut phy = [0; 11];
            phy[9] = value << 6;
            packet_extension(ap([0; 6], phy, &[]).he().unwrap())
        };
        assert_eq!(padded(0), [7; 20]);
        assert_eq!(padded(1)[..2], [EXTENSION_BPSK, EXTENSION_NONE]);
        assert_eq!(padded(2)[18..], [EXTENSION_NONE, EXTENSION_BPSK]);
        assert_eq!(padded(3), [7; 20], "reserved");
    }

    #[test]
    fn control_flags_follow_the_peer_mac_capabilities() {
        assert_eq!(control_flags(&[0; 6]), 0);
        assert_eq!(control_flags(&[1, 0, 0, 0, 0, 0]), 1);
        assert_eq!(control_flags(&[0, 0, 1, 0, 0, 0]), 2 << 1);
        assert_eq!(control_flags(&[0, 0x80, 1, 0, 0, 0]), 3 << 1);
        assert_eq!(control_flags(&[0, 0x80, 0, 0, 0, 0]), 0, "no feedback");
        assert_eq!(control_flags(&[0, 0, 8, 2, 4, 0]), 0x70);
    }

    #[test]
    fn a_disabled_color_is_kept_and_newer_links_have_no_mask() {
        let edca = [AccessCategory {
            aci: 0,
            admission_control: false,
            aifsn: 2,
            ecw_min: 4,
            ecw_max: 10,
            txop_32us: 0,
        }; 4];
        let bytes = link_config(
            6,
            LinkState {
                address: Mac([2; 6]),
                band: Band::Ghz5,
                basic_rates: 1,
                short_preamble: false,
                short_slot: true,
                protection: Protection {
                    erp: false,
                    ht_mode: 0,
                },
                width: Width::Mhz20,
                qos: true,
                edca: &edca,
                beacon_interval: 100,
                dtim_period: 1,
                he: Some(LinkHe {
                    packet_extension: 0,
                    uora: None,
                    mu_edca: None,
                    color: 3,
                    color_enabled: false,
                    rts_threshold: 1023,
                    uplink_data_disabled: true,
                }),
            },
        );
        assert_eq!(bytes[148], 1);
        assert_eq!(bytes[152], 0);
        assert_eq!(bytes[165], 3);
        assert_eq!(bytes[167], 1);
        assert_eq!(bytes[146..148], 1023u16.to_le_bytes());
    }
}
