// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Full single-link MT7925 modern station/BSS/EDCA and BA requests.
//! Negotiated metadata encodes capabilities; only the current shared
//! association owner and matching native completions can install these bytes.
use super::{Error, Profile, put16, put32, tlv};
use crate::net::wifi::{
    Band,
    station::phy::{AccessCategory, McsMaps, Negotiated, Width},
};
use alloc::vec::Vec;

/// Selected operating channel, including the second center used by
/// 80+80/320 and the disabled-subchannel bitmap. These are source channel
/// numbers, not MHz or inferred regulatory permissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    pub center_channel: u8,
    pub second_center_channel: u8,
    pub punctured: u16,
    pub he: Option<HeOperation>,
    pub mbssid_indicator: u8,
    pub mbssid_index: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeOperation {
    pub packet_extension: u8,
    pub rts_threshold: u16,
    pub color_enabled: bool,
    pub color: u8,
}
/// Keeps the exact validated local/peer provenance and operation. This is
/// not an association, key, radio or applied-policy receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Configuration {
    negotiated: Negotiated,
    operation: Operation,
    local_he_maps: [McsMaps; 3],
    /// The BSS's operating width: the negotiated one until a channel switch.
    width: Width,
}
impl Configuration {
    pub fn new(
        profile: Profile,
        negotiated: Negotiated,
        operation: Operation,
        local_he_maps: [McsMaps; 3],
    ) -> Result<Self, Error> {
        let width = negotiated.width;
        Self::checked(profile, negotiated, operation, local_he_maps, width)
    }
    /// The configuration once a channel switch moved the BSS to `operation`
    /// at `width`, no wider than negotiated, on `profile`'s channel.
    pub fn switched(
        &self,
        profile: Profile,
        operation: Operation,
        width: Width,
    ) -> Result<Self, Error> {
        let mhz = |width| match width {
            Width::Mhz20 => 20,
            Width::Mhz40 => 40,
            Width::Mhz80 => 80,
            Width::Mhz160 | Width::Mhz80P80 => 160,
            Width::Mhz320 => 320,
        };
        if mhz(width) > mhz(self.negotiated.width)
            || operation.he != self.operation.he
            || (operation.mbssid_indicator, operation.mbssid_index)
                != (self.operation.mbssid_indicator, self.operation.mbssid_index)
        {
            return Err(Error::InvalidGeometry);
        }
        Self::checked(
            profile,
            self.negotiated.clone(),
            operation,
            self.local_he_maps,
            width,
        )
    }
    fn checked(
        profile: Profile,
        negotiated: Negotiated,
        operation: Operation,
        local_he_maps: [McsMaps; 3],
        width: Width,
    ) -> Result<Self, Error> {
        profile.validate_inner(true)?;
        // The pinned MT7925 local advertisement includes160MHz, not80+80;
        // is_320mhz_supported() explicitly admits onlyMT7927. Generic shared
        // metadata can describe those widths without checking this device.
        if matches!(negotiated.width, Width::Mhz80P80 | Width::Mhz320) {
            return Err(Error::UnsupportedWidth);
        }
        // Negotiated's outputs are public for consumers; reject edited outputs
        // rather than accepting capabilities disconnected from their inputs.
        let checked = Negotiated::between(
            negotiated.local(),
            negotiated.peer(),
            negotiated.mode,
            negotiated.width,
        )
        .map_err(|_| Error::InvalidNegotiation)?;
        if checked != negotiated
            || negotiated.local().band() != profile.channel.band
            || negotiated.rx_nss > profile.antenna_mask.count_ones() as u8
            || negotiated.tx_nss > profile.antenna_mask.count_ones() as u8
            || (profile.channel.band != Band::Ghz6
                && (profile.basic_rates != negotiated.legacy.basic
                    || profile.supported_rates != negotiated.legacy.supported))
        {
            return Err(Error::InvalidNegotiation);
        }
        validate_geometry(profile, width, operation)?;
        if negotiated
            .local()
            .local_he_source_maps()
            .is_some_and(|maps| *maps != local_he_maps)
        {
            return Err(Error::InvalidNegotiation);
        }
        if let Some(local) = negotiated.local().he()
            && [Some(local.mcs_80), local.mcs_160, local.mcs_80p80]
                .into_iter()
                .zip(local_he_maps)
                .any(|(wire, source)| wire.is_some_and(|wire| wire != source))
        {
            return Err(Error::InvalidNegotiation);
        }
        if negotiated.he.is_some() != operation.he.is_some()
            || operation
                .he
                .is_some_and(|h| h.color > 63 || h.packet_extension > 7)
            || operation.mbssid_indicator > 8
            || u16::from(operation.mbssid_index) >= 1u16 << operation.mbssid_indicator
        {
            return Err(Error::InvalidNegotiation);
        }
        Ok(Self {
            negotiated,
            operation,
            local_he_maps,
            width,
        })
    }
    pub fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }
    pub const fn operation(&self) -> Operation {
        self.operation
    }
    pub fn peer_request(&self, profile: Profile, associated: bool) -> Result<Vec<u8>, Error> {
        self.matches(profile)?;
        profile.peer_request_inner(true, associated, Some(self))
    }
    pub fn bss_request(&self, profile: Profile, enable: bool) -> Result<Vec<u8>, Error> {
        self.matches(profile)?;
        profile.bss_request_inner(enable, Some(self))
    }
    fn matches(&self, profile: Profile) -> Result<(), Error> {
        // Recheck supplied resources/rates/antenna against this kept
        // metadata on every request, before any caller can publish it.
        Self::checked(
            profile,
            self.negotiated.clone(),
            self.operation,
            self.local_he_maps,
            self.width,
        )
        .map(|_| ())
    }
    pub(super) fn station_bandwidth(&self) -> u8 {
        match self.negotiated.width {
            Width::Mhz20 => 0,
            Width::Mhz40 => 1,
            Width::Mhz80 => 2,
            Width::Mhz160 | Width::Mhz80P80 => 3,
            Width::Mhz320 => 4,
        }
    }
    fn command_bandwidth(&self) -> u8 {
        match self.width {
            Width::Mhz20 => 0,
            Width::Mhz40 => 1,
            Width::Mhz80 => 2,
            Width::Mhz160 => 3,
            Width::Mhz80P80 => 6,
            Width::Mhz320 => 7,
        }
    }
    pub(super) fn peer_capabilities(&self, p: Profile, out: &mut Vec<u8>) -> Result<(), Error> {
        let n = &self.negotiated;
        // Existing full BASIC20 + PHY12 prefix. Source BASIC.qos reflects WME;
        // source sta_uapsd emits AP-only records, never station STA_APPS here.
        out[8 + 9] = u8::from(n.wmm.is_some());
        let phy = &mut out[28..40];
        phy[6] = phy_type(p.channel.band, n);
        phy[7] = (n.peer_ampdu_base_exponent & 3) | (n.peer_mpdu_spacing & 7) << 2;
        phy[10] = n.peer_ampdu_base_exponent;
        if let Some(h) = &n.ht {
            put16(tlv(out, 9, 8), 4, h.capability);
        }
        // Source demands this record on 6GHz even without a VHT capability.
        if n.vht.is_some() || n.peer().he_6ghz().is_some_and(|v| v != 0) {
            let v = tlv(out, 10, 16);
            if let Some(c) = &n.vht {
                put32(v, 4, c.capability);
                put16(v, 8, c.mcs.rx);
                put16(v, 10, c.mcs.tx);
            }
        }
        if n.max_tx_amsdu != 0 {
            let a = tlv(out, 15, 8);
            a[4] = 8;
            a[5] = match n.max_tx_amsdu {
                11454 => 2,
                7935 | 7991 => 1,
                _ => 0,
            };
            a[6] = 1;
        }
        if let Some(h) = &n.he {
            let t = tlv(out, 0x19, 28);
            t[4..10].copy_from_slice(&h.mac);
            t[10..21].copy_from_slice(&h.phy);
            t[21] = 2; // source nominal-packet-padding16us enum
            put16(t, 22, h.mcs_80.rx);
            if self.station_bandwidth() == 3 {
                if let Some(m) = h.mcs_160 {
                    put16(t, 24, m.rx);
                }
                if h.phy[0] & 16 != 0
                    && let Some(m) = h.mcs_80p80
                {
                    put16(t, 26, m.rx);
                }
            }
        }
        if let Some(c) = n.peer().he_6ghz().filter(|&v| v != 0) {
            put16(tlv(out, 0x17, 8), 4, c);
        }
        if let Some(e) = n.peer().eht().filter(|_| n.eht.is_some()) {
            let t = tlv(out, 0x22, 40);
            t[4] = 0xff;
            t[6..8].copy_from_slice(&e.mac);
            t[8..16].copy_from_slice(&e.phy[..8]);
            t[16] = e.phy[8];
            // Source's link_sta EHT map is the observed zero-filled nine-byte
            // peer union, independently of directional common-map admission.
            let union = e.source_mcs_union().bytes();
            if self.station_bandwidth() == 0 {
                t[24..28].copy_from_slice(&union[..4]);
            }
            t[28..31].copy_from_slice(&union[..3]);
            t[31..34].copy_from_slice(&union[3..6]);
            t[34..37].copy_from_slice(&union[6..9]);
        }
        Ok(())
    }
    pub(super) fn bss_capabilities(
        &self,
        p: Profile,
        enable: bool,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let n = &self.negotiated;
        // Source BSS_BASIC uses the older family bitmap and separate extension.
        let (mode, ext) = bss_phy_mode(p.channel.band, n);
        out[4 + 25] = mode;
        out[4 + 30] = ext;
        // QBSS WMM flag, sourced from the negotiated station WME state.
        let qos = find_tlv_mut(out, 4, 15).ok_or(Error::InvalidNegotiation)?;
        qos[4] = u8::from(n.wmm.is_some());
        if let Some(op) = self.operation.he {
            let h = tlv(out, 5, 16);
            // Source defaults on parsed zero-valued operation
            // fields; these are firmware packet-extension/RTS values, no policy.
            put16(
                h,
                4,
                if op.rts_threshold == 0 {
                    1023
                } else {
                    op.rts_threshold
                },
            );
            h[6] = if op.packet_extension == 0 {
                4
            } else {
                op.packet_extension
            };
            for (index, maps) in self.local_he_maps.iter().enumerate() {
                put16(h, 8 + index * 2, maps.tx);
            }
            let c = tlv(out, 4, 8);
            c[4] = u8::from(enable && op.color_enabled);
            c[5] = if enable { op.color } else { 0 };
        }
        Ok(())
    }
    pub(super) fn rlm(&self, p: Profile, r: &mut [u8]) {
        r[5] = self.operation.center_channel;
        r[6] = self.operation.second_center_channel;
        r[7] = self.command_bandwidth();
        r[10] = if self.width == Width::Mhz20 { 0 } else { 4 };
        r[11] = match (p.channel.number as u8).cmp(&r[5]) {
            core::cmp::Ordering::Less => 1,
            core::cmp::Ordering::Greater => 3,
            core::cmp::Ordering::Equal => 0,
        };
        r[12] = match p.channel.band {
            Band::Ghz2 => 1,
            Band::Ghz5 => 2,
            Band::Ghz6 => 3,
        };
    }
    /// Source set_tx full four-queue update. WMM ACI order BE/BK/VI/VO differs
    /// from ieee80211_ac_numbers VO/VI/BE/BK consumed by mt7925_mcu_set_tx.
    pub fn edca_request(&self, p: Profile) -> Result<Vec<u8>, Error> {
        self.matches(p)?;
        self.edca_restricted_request(p, &self.negotiated.edca())
    }
    /// Private native queue restriction; never change negotiated AP metadata.
    pub(in crate::net::wifi::mediatek) fn edca_restricted_request(
        &self,
        p: Profile,
        effective: &[AccessCategory; 4],
    ) -> Result<Vec<u8>, Error> {
        self.matches(p)?;
        Self::observed_edca_request(p, &self.negotiated.edca(), effective)
    }
    /// Current native RX supplies the new AP baseline; it is not a replacement
    /// association or a mutation of the immutable negotiated capability object.
    pub(in crate::net::wifi::mediatek) fn observed_edca_request(
        p: Profile,
        original: &[AccessCategory; 4],
        effective: &[AccessCategory; 4],
    ) -> Result<Vec<u8>, Error> {
        p.validate_inner(true)?;
        let mut seen = 0u8;
        for ac in effective {
            let old = original
                .iter()
                .find(|old| old.aci == ac.aci)
                .ok_or(Error::InvalidNegotiation)?;
            if ac.aci >= 4
                || seen & (1 << ac.aci) != 0
                || ac.ecw_min < old.ecw_min
                || ac.ecw_max < old.ecw_max
                || ac.ecw_min > ac.ecw_max
                || ac.ecw_max > 15
                || ac.aifsn < old.aifsn
                || ac.txop_32us > old.txop_32us
            {
                return Err(Error::InvalidNegotiation);
            }
            seen |= 1 << ac.aci;
        }
        let mut out = Vec::new();
        out.try_reserve_exact(52).map_err(|_| Error::NoMemory)?;
        out.extend_from_slice(&[p.interface.bss_index, 0, 0, 0]);
        for (queue, aci) in [3, 2, 0, 1].into_iter().enumerate() {
            let ac = effective
                .iter()
                .find(|c| c.aci == aci)
                .ok_or(Error::InvalidNegotiation)?;
            let e = tlv(&mut out, 0, 12);
            e[4] = queue as u8;
            e[5] = 15;
            // fls((1<<ECW)-1)==ECW; source substitutes5/10 for zeroCW.
            e[6] = if ac.ecw_min == 0 { 5 } else { ac.ecw_min };
            e[7] = if ac.ecw_max == 0 { 10 } else { ac.ecw_max };
            put16(e, 8, ac.txop_32us);
            e[10] = ac.aifsn;
        }
        super::recount(&mut out, 4);
        Ok(out)
    }
    /// Separate source EHT puncture update, including a zero bitmap.
    pub fn puncture_request(&self, p: Profile) -> Result<Vec<u8>, Error> {
        self.matches(p)?;
        if self.negotiated.eht.is_none() {
            return Err(Error::InvalidNegotiation);
        }
        let mut out = vec![p.interface.bss_index, 0, 0, 0];
        let t = tlv(&mut out, 30, 16);
        t[5] = u8::from(self.operation.punctured != 0);
        put16(t, 10, self.operation.punctured);
        super::recount(&mut out, 4);
        Ok(out)
    }
}
fn find_tlv_mut(bytes: &mut [u8], mut at: usize, tag: u16) -> Option<&mut [u8]> {
    while at < bytes.len() {
        let id = u16::from_le_bytes(bytes[at..at + 2].try_into().ok()?);
        let len = u16::from_le_bytes(bytes[at + 2..at + 4].try_into().ok()?) as usize;
        if id == tag {
            return bytes.get_mut(at..at + len);
        }
        at += len;
    }
    None
}
fn phy_type(band: Band, n: &Negotiated) -> u8 {
    let base = if band == Band::Ghz2 { 3 } else { 8 };
    base | u8::from(n.ht.is_some()) << 4
        | u8::from(band != Band::Ghz2 && n.vht.is_some()) << 5
        | u8::from(n.he.is_some()) << 6
        | u8::from(n.eht.is_some()) << 7
}
fn bss_phy_mode(band: Band, n: &Negotiated) -> (u8, u8) {
    let ht = u8::from(n.ht.is_some());
    let vht = u8::from(n.vht.is_some());
    let he = u8::from(n.he.is_some());
    let eht = u8::from(n.eht.is_some());
    match band {
        Band::Ghz2 => (6 | ht << 3 | he << 6, eht << 1),
        Band::Ghz5 => (1 | ht << 4 | vht << 5 | he << 7, eht << 2),
        // Source advertises A|AN|AC|AX5 on6GHz plus extension,
        // independent of the invalid/absent HT/VHT IEs on that band.
        Band::Ghz6 => (
            0xb1,
            u8::from(n.peer().he_6ghz().is_some_and(|v| v != 0)) | eht << 3,
        ),
    }
}
fn validate_geometry(p: Profile, width: Width, op: Operation) -> Result<(), Error> {
    let delta = p.channel.number.abs_diff(u16::from(op.center_channel));
    let max = match width {
        Width::Mhz20 => 0,
        Width::Mhz40 => 2,
        Width::Mhz80 | Width::Mhz80P80 => 6,
        Width::Mhz160 => 14,
        Width::Mhz320 => 30,
    };
    if op.center_channel == 0
        || delta > max
        || (delta != 0 && delta % 4 != 2)
        || (width == Width::Mhz20 && delta != 0)
        || (width != Width::Mhz20 && delta == 0)
        || (!matches!(width, Width::Mhz80P80 | Width::Mhz320) && op.second_center_channel != 0)
        || (width == Width::Mhz80P80
            && (op.second_center_channel == 0
                || op.second_center_channel.abs_diff(op.center_channel) <= 16))
        || (op.punctured != 0 && !matches!(width, Width::Mhz80 | Width::Mhz160 | Width::Mhz320))
    {
        return Err(Error::InvalidGeometry);
    }
    let subchannels = match width {
        Width::Mhz80 => 4,
        Width::Mhz160 => 8,
        Width::Mhz320 => 16,
        _ => 0,
    };
    if subchannels != 0 {
        let mask = (1u32 << subchannels) - 1;
        let first = i32::from(op.center_channel) - 2 * (subchannels - 1);
        let primary = (i32::from(p.channel.number) - first) / 4;
        if primary < 0
            || primary >= subchannels
            || u32::from(op.punctured) & !mask != 0
            || u32::from(op.punctured) & (1 << primary) != 0
        {
            return Err(Error::InvalidGeometry);
        }
    }
    Ok(())
}

/// Source STA_REC_BA (recipient/originator), not an ADDBA exchange or reorder
/// receipt. Caller must bind peer/TID/generation and keep the
/// reorder/token/key owners through the matching command and later drain.
pub fn ba_request(
    p: Profile,
    tid: u8,
    ssn: u16,
    window: u16,
    amsdu: bool,
    enable: bool,
    transmit: bool,
) -> Result<Vec<u8>, Error> {
    p.validate_inner(true)?;
    if tid >= 8 || ssn >= 4096 || window == 0 || window > 1024 {
        return Err(Error::InvalidAggregation);
    }
    let mut out = vec![0; 8];
    out[0] = p.interface.bss_index;
    out[1] = p.wcid as u8;
    out[2] = 1;
    out[4] = 1;
    out[5] = p.interface.omac_index;
    let t = tlv(&mut out, 6, 16);
    t[4] = tid;
    t[5] = if transmit { 1 } else { 2 };
    t[6] = u8::from(amsdu);
    t[7] = u8::from(enable) << tid;
    put16(t, 8, ssn);
    put16(t, 10, window);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::super::device::Context;
    use super::*;
    use crate::net::{
        Mac,
        wifi::{
            Channel,
            station::phy::{Capabilities, McsMaps, Mode, Role},
        },
    };
    use alloc::{vec, vec::Vec};

    fn ie(out: &mut Vec<u8>, id: u8, data: &[u8]) {
        out.extend_from_slice(&[id, data.len() as u8]);
        out.extend_from_slice(data);
    }
    fn extension(out: &mut Vec<u8>, id: u8, data: &[u8]) {
        let mut extended = vec![id];
        extended.extend_from_slice(data);
        ie(out, 255, &extended);
    }
    fn ht() -> [u8; 26] {
        let mut data = [0; 26];
        data[..2].copy_from_slice(&0x19e3_u16.to_le_bytes());
        data[2] = 3 | (4 << 2);
        data[3..5].fill(0xff);
        data[7] = 1;
        data[15] = 1;
        data
    }
    fn vht() -> [u8; 12] {
        let mut data = [0; 12];
        data[..4].copy_from_slice(&(1_u32 | 8 | 0x60 | 0x180 | (3 << 23)).to_le_bytes());
        data[4..6].copy_from_slice(&0xfffa_u16.to_le_bytes());
        data[8..10].copy_from_slice(&0xfffa_u16.to_le_bytes());
        data
    }
    fn he(width_bits: u8) -> Vec<u8> {
        let mut data = vec![0; 17];
        data[6] = width_bits;
        for _ in 0..1 + usize::from(width_bits & 8 != 0) + usize::from(width_bits & 16 != 0) {
            data.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff]);
        }
        data
    }
    fn eht(width_bits: u8, role: Role, width320: bool) -> Vec<u8> {
        let mut data = vec![0; 11];
        data[0] = 1 << 6; // 2.4GHz max-MPDU selection; ignored elsewhere.
        data[2] = if width320 { 2 } else { 0 };
        if width_bits & 2 != 0 {
            data.extend_from_slice(&[0x22, 0x22, 0x11]);
        } else {
            for present in [width_bits & 4 != 0, width_bits & 8 != 0, width320] {
                if present {
                    data.extend_from_slice(&[0x22, 0x22, 0x11]);
                }
            }
            if data.len() == 11 {
                data.extend_from_slice(if role == Role::Station {
                    &[0x22, 0x22, 0x22, 0x11]
                } else {
                    &[0x22, 0x22, 0x11]
                });
            }
        }
        data
    }
    fn wmm(role: Role) -> Vec<u8> {
        if role == Role::Station {
            return vec![0, 0x50, 0xf2, 2, 0, 1, 0x6f];
        }
        vec![
            0, 0x50, 0xf2, 2, 1, 1, 0x89, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94, 0,
            0x62, 0x32, 47, 0,
        ]
    }
    fn modern_ies(band: Band, role: Role, width_bits: u8, width320: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if band == Band::Ghz2 {
            ie(&mut out, 1, &[0x82, 0x84, 11, 22, 0x8c, 0x98, 0xb0, 108]);
            ie(&mut out, 50, &[18, 36, 72, 96]);
        } else if band != Band::Ghz6 {
            ie(&mut out, 1, &[0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108]);
        }
        if band != Band::Ghz6 {
            ie(&mut out, 45, &ht());
            if band == Band::Ghz5 {
                ie(&mut out, 191, &vht());
            }
        }
        extension(&mut out, 35, &he(width_bits));
        extension(&mut out, 108, &eht(width_bits, role, width320));
        if band == Band::Ghz6 {
            extension(&mut out, 59, &0x004a_u16.to_le_bytes());
        }
        ie(&mut out, 221, &wmm(role));
        out
    }
    fn pair(band: Band, width_bits: u8, width320: bool) -> (Capabilities, Capabilities) {
        (
            Capabilities::parse(
                band,
                Role::Station,
                &modern_ies(band, Role::Station, width_bits, width320),
            )
            .unwrap(),
            Capabilities::parse(
                band,
                Role::AccessPoint,
                &modern_ies(band, Role::AccessPoint, width_bits, width320),
            )
            .unwrap(),
        )
    }

    fn fixture(band: Band, mode: Mode, width: Width) -> (Profile, Configuration) {
        let bits = if band == Band::Ghz2 { 2 } else { 4 | 8 | 16 };
        let (local, peer) = pair(band, bits, band == Band::Ghz6);
        let n = Negotiated::between(&local, &peer, mode, width).unwrap();
        let p = Profile {
            interface: Context {
                bss_index: 1,
                omac_index: 2,
                band_index: 255,
                wmm_index: 1,
                link_index: 0,
                broadcast_wcid: 18,
                address: Mac([2, 1, 2, 3, 4, 5]),
            },
            peer: Mac([2, 6, 7, 8, 9, 10]),
            wcid: 1,
            channel: Channel {
                band,
                number: if band == Band::Ghz2 {
                    6
                } else if band == Band::Ghz5 {
                    36
                } else {
                    1
                },
                frequency_mhz: if band == Band::Ghz2 {
                    2437
                } else if band == Band::Ghz5 {
                    5180
                } else {
                    5955
                },
            },
            aid: 13,
            basic_rates: if band == Band::Ghz6 {
                0x15
            } else {
                n.legacy.basic
            },
            supported_rates: if band == Band::Ghz6 {
                0xff
            } else {
                n.legacy.supported
            },
            beacon_interval: 100,
            dtim_period: 2,
            slot_time: 9,
            antenna_mask: 3,
            cipher: 4,
        };
        let center = p.channel.number as u8
            + match width {
                Width::Mhz20 => 0,
                Width::Mhz40 => 2,
                Width::Mhz80 | Width::Mhz80P80 => 6,
                Width::Mhz160 => 14,
                Width::Mhz320 => 30,
            };
        let local_he_maps = n.local().he().map_or([McsMaps { rx: 0, tx: 0 }; 3], |h| {
            [
                h.mcs_80,
                h.mcs_160.unwrap_or(h.mcs_80),
                h.mcs_80p80.unwrap_or(McsMaps { rx: 0, tx: 0 }),
            ]
        });
        let c = Configuration::new(
            p,
            n,
            Operation {
                center_channel: center,
                second_center_channel: if width == Width::Mhz80P80 { 106 } else { 0 },
                punctured: 0,
                he: if matches!(mode, Mode::He | Mode::Eht) {
                    Some(HeOperation {
                        packet_extension: 0,
                        rts_threshold: 0,
                        color_enabled: true,
                        color: 37,
                    })
                } else {
                    None
                },
                mbssid_indicator: 2,
                mbssid_index: 1,
            },
            local_he_maps,
        )
        .unwrap();
        (p, c)
    }
    fn field(bytes: &[u8], mut at: usize, wanted: u16) -> &[u8] {
        while at < bytes.len() {
            let tag = u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
            let len = u16::from_le_bytes(bytes[at + 2..at + 4].try_into().unwrap()) as usize;
            if tag == wanted {
                return &bytes[at..at + len];
            }
            at += len;
        }
        panic!("missing tag{wanted}")
    }
    #[test]
    fn full_modern_family_records_keep_peer_and_local_directions_and_source_order() {
        for band in [Band::Ghz2, Band::Ghz5, Band::Ghz6] {
            for mode in [Mode::Ht, Mode::Vht, Mode::He, Mode::Eht] {
                if (band == Band::Ghz2 && mode == Mode::Vht)
                    || (band == Band::Ghz6 && !matches!(mode, Mode::He | Mode::Eht))
                {
                    continue;
                }
                let (p, c) = fixture(band, mode, Width::Mhz20);
                let peer = c.peer_request(p, true).unwrap();
                let bss = c.bss_request(p, true).unwrap();
                assert_eq!(field(&peer, 8, 0)[9], 1);
                let phy = field(&peer, 8, 0x15);
                assert_eq!(phy[10], c.negotiated.peer_ampdu_base_exponent);
                if matches!(mode, Mode::He | Mode::Eht) {
                    let he = field(&peer, 8, 0x19);
                    assert_eq!(&he[4..10], &c.negotiated.he.as_ref().unwrap().mac);
                    assert_eq!(he[21], 2);
                    let he_bss = field(&bss, 4, 5);
                    assert_eq!(&he_bss[4..8], &[255, 3, 4, 0]);
                    assert_eq!(
                        &he_bss[8..10],
                        &c.negotiated.local().he().unwrap().mcs_80.tx.to_le_bytes()
                    );
                    assert_eq!(&field(&bss, 4, 4)[4..6], &[1, 37]);
                }
                assert_eq!(&field(&bss, 4, 6)[4..6], &[2, 1]);
                if band == Band::Ghz6 {
                    assert_eq!(&field(&peer, 8, 10)[4..12], &[0; 8]);
                    assert_eq!(field(&bss, 4, 0)[25], 0xb1);
                    assert_eq!(field(&bss, 4, 2)[12], 3);
                }
                assert_eq!(&field(&peer, 8, 0x2b)[5..7], &[1, 1]);
            }
        }
    }

    #[test]
    fn bss_he_keeps_source_hidden_maps_without_advertising_their_widths() {
        let (p, c) = fixture(Band::Ghz2, Mode::He, Width::Mhz20);
        let wire = c.negotiated.local().he().unwrap();
        assert_eq!(wire.mcs_160, None);
        assert_eq!(wire.mcs_80p80, None);
        let body = c.bss_request(p, true).unwrap();
        let he = field(&body, 4, 5);
        // Full source initialization writes160 on2GHz, while source
        // zero-allocation leaves80+80 untouched. Wire absence is not either value.
        assert_eq!(&he[8..10], &wire.mcs_80.tx.to_le_bytes());
        assert_eq!(&he[10..12], &wire.mcs_80.tx.to_le_bytes());
        assert_eq!(&he[12..14], &[0, 0]);
        let mut wrong = c.local_he_maps;
        wrong[0].tx ^= 1;
        assert_eq!(
            Configuration::new(p, c.negotiated.clone(), c.operation, wrong),
            Err(Error::InvalidNegotiation)
        );
    }
    #[test]
    fn every_supported_width_encodes_actual_centers_and_distinct_command_bandwidth() {
        for (band, mode) in [
            (Band::Ghz2, Mode::Ht),
            (Band::Ghz5, Mode::He),
            (Band::Ghz6, Mode::Eht),
        ] {
            for width in [
                Width::Mhz20,
                Width::Mhz40,
                Width::Mhz80,
                Width::Mhz160,
                Width::Mhz80P80,
                Width::Mhz320,
            ] {
                if matches!(width, Width::Mhz80P80 | Width::Mhz320) {
                    continue;
                }
                if (band == Band::Ghz2 && !matches!(width, Width::Mhz20 | Width::Mhz40))
                    || (width == Width::Mhz320 && band != Band::Ghz6)
                    || (width == Width::Mhz80P80 && mode == Mode::Eht)
                {
                    continue;
                }
                let (p, c) = fixture(band, mode, width);
                let b = c.bss_request(p, true).unwrap();
                let r = field(&b, 4, 2);
                assert_eq!(r[4], p.channel.number as u8);
                assert_eq!(r[5], c.operation.center_channel);
                assert_eq!(r[6], c.operation.second_center_channel);
                assert_eq!(
                    r[7],
                    match width {
                        Width::Mhz20 => 0,
                        Width::Mhz40 => 1,
                        Width::Mhz80 => 2,
                        Width::Mhz160 => 3,
                        Width::Mhz80P80 => 6,
                        Width::Mhz320 => 7,
                    }
                );
            }
        }
    }
    #[test]
    fn edca_wmm_aci_mapping_uses_firmware_queue_order_and_full_parameter_updates() {
        let (p, c) = fixture(Band::Ghz5, Mode::He, Width::Mhz80);
        let b = c.edca_request(p).unwrap();
        assert_eq!(b.len(), 52);
        let expected = [
            (0, 2, 2, 3, 47),
            (1, 2, 3, 4, 94),
            (2, 3, 4, 10, 0),
            (3, 7, 4, 10, 0),
        ];
        for (i, (queue, aifs, min, max, txop)) in expected.into_iter().enumerate() {
            let e = &b[4 + i * 12..4 + (i + 1) * 12];
            assert_eq!((e[4], e[5], e[6], e[7], e[10]), (queue, 15, min, max, aifs));
            assert_eq!(u16::from_le_bytes([e[8], e[9]]), txop);
        }
    }
    #[test]
    fn tampered_negotiation_wrong_antenna_primary_puncture_and_stale_resources_refuse() {
        let (p, c) = fixture(Band::Ghz5, Mode::He, Width::Mhz80);
        let mut n = c.negotiated.clone();
        n.rx_nss = 1;
        assert_eq!(
            Configuration::new(p, n, c.operation, c.local_he_maps),
            Err(Error::InvalidNegotiation)
        );
        let mut p2 = p;
        p2.antenna_mask = 1;
        assert!(c.peer_request(p2, true).is_err());
        let mut op = c.operation;
        op.punctured = 1;
        assert_eq!(
            Configuration::new(p, c.negotiated.clone(), op, c.local_he_maps),
            Err(Error::InvalidGeometry)
        );
        op = c.operation;
        op.second_center_channel = 106;
        assert_eq!(
            Configuration::new(p, c.negotiated.clone(), op, c.local_he_maps),
            Err(Error::InvalidGeometry)
        );
        p2 = p;
        p2.basic_rates = 1;
        assert!(c.bss_request(p2, true).is_err());
    }
    #[test]
    fn ba_encodes_real_recipient_originator_tid_window_and_source_bitmap() {
        let (p, _) = fixture(Band::Ghz5, Mode::He, Width::Mhz80);
        for tid in 0..8 {
            for transmit in [false, true] {
                let b = ba_request(p, tid, 4095, 1024, true, true, transmit).unwrap();
                assert_eq!(
                    &b[12..16],
                    &[tid, if transmit { 1 } else { 2 }, 1, 1 << tid]
                );
                assert_eq!(&b[16..20], &[255, 15, 0, 4]);
            }
        }
        assert_eq!(
            ba_request(p, 8, 0, 64, false, true, false),
            Err(Error::InvalidAggregation)
        );
        assert_eq!(
            ba_request(p, 0, 4096, 64, false, true, false),
            Err(Error::InvalidAggregation)
        );
    }

    #[test]
    #[ignore = "oracle: STELA_MT7925_MODERN_ORACLE"]
    fn full_source_modern_peer_bss_edca_ba_and_puncture_match_exact_requests() {
        extern crate std;
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let root =
            std::path::PathBuf::from(std::env::var_os("STELA_MT7925_MODERN_ORACLE").unwrap());
        let mut input = Vec::new();
        let mut expected = Vec::new();
        let mut count = 0;
        for band in [Band::Ghz2, Band::Ghz5, Band::Ghz6] {
            for mode in [Mode::Ht, Mode::Vht, Mode::He, Mode::Eht] {
                if (band == Band::Ghz2 && mode == Mode::Vht)
                    || (band == Band::Ghz6 && !matches!(mode, Mode::He | Mode::Eht))
                {
                    continue;
                }
                for width in [
                    Width::Mhz20,
                    Width::Mhz40,
                    Width::Mhz80,
                    Width::Mhz160,
                    Width::Mhz80P80,
                    Width::Mhz320,
                ] {
                    if matches!(width, Width::Mhz80P80 | Width::Mhz320) {
                        continue;
                    }
                    if (band == Band::Ghz2 && !matches!(width, Width::Mhz20 | Width::Mhz40))
                        || (mode == Mode::Ht && !matches!(width, Width::Mhz20 | Width::Mhz40))
                        || (width == Width::Mhz320 && (mode != Mode::Eht || band != Band::Ghz6))
                        || (width == Width::Mhz80P80 && mode == Mode::Eht)
                    {
                        continue;
                    }
                    for variant in 0..8 {
                        let (mut p, c) = fixture(band, mode, width);
                        p.interface.omac_index = [0, 1, 17, 63][variant % 4];
                        p.interface.wmm_index = (variant % 4) as u8;
                        p.antenna_mask = [3, 5, 9, 15][variant % 4];
                        p.cipher = [0, 4, 10, 11, 12, 4, 11, 12][variant];
                        let n = c.negotiated();
                        let op = c.operation();
                        let flags = u8::from(n.ht.is_some())
                            | u8::from(n.vht.is_some()) << 1
                            | u8::from(n.he.is_some()) << 2
                            | u8::from(n.eht.is_some()) << 3;
                        input.extend_from_slice(&[
                            match band {
                                Band::Ghz2 => 0,
                                Band::Ghz5 => 1,
                                Band::Ghz6 => 3,
                            },
                            p.channel.number as u8,
                            op.center_channel,
                            op.second_center_channel,
                            match width {
                                Width::Mhz20 => 0,
                                Width::Mhz40 => 2,
                                Width::Mhz80 => 3,
                                Width::Mhz80P80 => 4,
                                Width::Mhz160 => 5,
                                Width::Mhz320 => 6,
                            },
                            c.station_bandwidth(),
                        ]);
                        input.extend_from_slice(&p.interface.address.0);
                        input.extend_from_slice(&p.peer.0);
                        input.extend_from_slice(&[
                            p.interface.bss_index,
                            p.interface.omac_index,
                            p.interface.band_index,
                            p.interface.wmm_index,
                        ]);
                        for v in [
                            p.wcid,
                            p.interface.broadcast_wcid,
                            p.aid,
                            p.basic_rates,
                            p.supported_rates,
                            p.beacon_interval,
                        ] {
                            input.extend_from_slice(&v.to_le_bytes())
                        }
                        input.push(p.dtim_period);
                        input.extend_from_slice(&p.slot_time.to_le_bytes());
                        input.extend_from_slice(&[p.antenna_mask, p.cipher, flags]);
                        input.extend_from_slice(
                            &n.ht.as_ref().map_or(0, |h| h.capability).to_le_bytes(),
                        );
                        input.extend_from_slice(&[
                            n.ht.as_ref().map_or(0, |h| h.peer_ampdu_base_exponent),
                            n.ht.as_ref().map_or(0, |h| h.peer_mpdu_spacing),
                        ]);
                        input.extend_from_slice(&n.ht.as_ref().map_or([0; 10], |h| h.peer_rx_mcs));
                        input.extend_from_slice(
                            &n.vht.as_ref().map_or(0, |v| v.capability).to_le_bytes(),
                        );
                        for v in [
                            n.vht.as_ref().map_or(0, |v| v.mcs.rx),
                            n.vht.as_ref().map_or(0, |v| v.mcs.tx),
                        ] {
                            input.extend_from_slice(&v.to_le_bytes())
                        }
                        input.extend_from_slice(&n.he.as_ref().map_or([0; 6], |h| h.mac));
                        input.extend_from_slice(&n.he.as_ref().map_or([0; 11], |h| h.phy));
                        let maps =
                            n.he.as_ref()
                                .map(|h| [Some(h.mcs_80), h.mcs_160, h.mcs_80p80])
                                .unwrap_or([None; 3]);
                        for m in maps {
                            for v in [m.map_or(0, |m| m.rx), m.map_or(0, |m| m.tx)] {
                                input.extend_from_slice(&v.to_le_bytes())
                            }
                        }
                        input.extend_from_slice(&n.peer().he_6ghz().unwrap_or(0).to_le_bytes());
                        if let Some(e) = n.peer().eht().filter(|_| n.eht.is_some()) {
                            input.extend_from_slice(&e.mac);
                            input.extend_from_slice(&e.phy);
                            input.extend_from_slice(e.source_mcs_union().bytes());
                        } else {
                            input.extend_from_slice(&[0; 20])
                        }
                        input.push(n.tx_nss);
                        input.extend_from_slice(&n.max_tx_amsdu.to_le_bytes());
                        let local = n.local().he().filter(|_| n.he.is_some());
                        input.extend_from_slice(&local.map_or([0; 6], |h| h.mac));
                        input.extend_from_slice(&local.map_or([0; 11], |h| h.phy));
                        for m in c.local_he_maps {
                            for v in [m.rx, m.tx] {
                                input.extend_from_slice(&v.to_le_bytes())
                            }
                        }
                        input.push(op.he.map_or(0, |h| h.packet_extension));
                        input
                            .extend_from_slice(&op.he.map_or(0, |h| h.rts_threshold).to_le_bytes());
                        input.extend_from_slice(&[
                            u8::from(op.he.is_some_and(|h| h.color_enabled)),
                            op.he.map_or(0, |h| h.color),
                            op.mbssid_indicator,
                            op.mbssid_index,
                        ]);
                        input.extend_from_slice(&op.punctured.to_le_bytes());
                        for aci in [3, 2, 0, 1] {
                            let ac = n
                                .wmm
                                .as_ref()
                                .unwrap()
                                .access_categories
                                .iter()
                                .find(|a| a.aci == aci)
                                .unwrap();
                            input.extend_from_slice(&[ac.aifsn, ac.ecw_min, ac.ecw_max]);
                            input.extend_from_slice(&ac.txop_32us.to_le_bytes())
                        }
                        let tid = variant as u8;
                        let ssn = (count * 31 % 4096) as u16;
                        let window = [1, 64, 256, 1024][variant % 4];
                        let amsdu = variant & 1 != 0;
                        let enable = variant & 2 != 0;
                        let transmit = variant & 4 != 0;
                        input.push(tid);
                        input.extend_from_slice(&ssn.to_le_bytes());
                        input.extend_from_slice(&u16::to_le_bytes(window));
                        input.extend_from_slice(&[
                            u8::from(amsdu),
                            u8::from(enable),
                            u8::from(transmit),
                        ]);
                        expected.extend([
                            (3, c.peer_request(p, false).unwrap()),
                            (3, c.peer_request(p, true).unwrap()),
                            (2, c.bss_request(p, false).unwrap()),
                            (2, c.bss_request(p, true).unwrap()),
                            (4, c.edca_request(p).unwrap()),
                            (
                                3,
                                ba_request(p, tid, ssn, window, amsdu, enable, transmit).unwrap(),
                            ),
                        ]);
                        if n.eht.is_some() {
                            expected.push((2, c.puncture_request(p).unwrap()))
                        }
                        count += 1;
                    }
                }
            }
        }
        std::fs::write(root.join("modern.input"), &input).unwrap();
        let mut child = Command::new(root.join("client"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let result = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert!(result.status.success());
        std::fs::write(root.join("modern.trace"), &result.stdout).unwrap();
        let mut at = 0;
        for (index, (command, body)) in expected.iter().enumerate() {
            let trace = &result.stdout;
            assert_eq!(trace[at], *command, "record{index}");
            let n = u16::from_le_bytes(trace[at + 1..at + 3].try_into().unwrap()) as usize;
            at += 3;
            assert_eq!(body, &trace[at..at + n], "record{index}");
            at += n;
        }
        assert_eq!(at, result.stdout.len());
        use sha2::{Digest, Sha256};
        let input_hash = Sha256::digest(std::fs::read(root.join("modern.input")).unwrap());
        let trace_hash = Sha256::digest(&result.stdout);
        std::fs::write(
            root.join("modern-run.json"),
            std::format!(
                "{{\n  \"contexts\": {count},\n  \"requests\": {},\n  \"input_sha256\": \"{input_hash:x}\",\n  \"trace_sha256\": \"{trace_hash:x}\"\n}}\n",
                expected.len()
            ),
        )
        .unwrap();
        std::println!(
            "{count} actual modern contexts, {} complete unchanged source requests",
            expected.len()
        );
    }
}
