// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! MT7925 ordinary non-MLO legacy20 station/BSS commands. These are the full
//! source-selected TLV sets for that explicitly negotiated profile. Encoding
//! does not establish a firmware context or grant regulatory permission.
use super::device::{Context, Requests};
use crate::net::{
    Mac,
    wifi::{Band, Channel},
};
use alloc::vec::Vec;

pub mod modern;
pub(in crate::net::wifi::mediatek) mod six_ghz;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NoMemory,
    Context(super::device::Error),
    InvalidPeer,
    InvalidWcid,
    InvalidChannel,
    InvalidScanTargets,
    InvalidScanElements,
    InvalidRates,
    InvalidTiming,
    UnsupportedCipher,
    UnsupportedWidth,
    InvalidNegotiation,
    InvalidGeometry,
    InvalidAggregation,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MT7925 client codec: {self:?}")
    }
}
impl core::error::Error for Error {}
/// Exact source resource and observed legacy BSS inputs. No inferred EEPROM,
/// beacon/DTIM, antenna count, channel, rate bitmap, or policy default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    pub interface: Context,
    pub peer: Mac,
    pub wcid: u16,
    pub channel: Channel,
    pub aid: u16,
    pub basic_rates: u16,
    pub supported_rates: u16,
    pub beacon_interval: u16,
    pub dtim_period: u8,
    pub slot_time: u16,
    pub antenna_mask: u8,
    /// Source Connac3 cipher number: open0, CCMP1284/CCMP25610/GCMP12811/GCMP25612.
    pub cipher: u8,
}
fn put16(bytes: &mut [u8], at: usize, v: u16) {
    bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, v: u32) {
    bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn tlv(bytes: &mut Vec<u8>, tag: u16, len: usize) -> &mut [u8] {
    let start = bytes.len();
    bytes.resize(start + len, 0);
    put16(bytes, start, tag);
    put16(bytes, start + 2, len as u16);
    &mut bytes[start..]
}
/// Store the number of TLVs that [`tlv`] appended after `start`.
fn recount(bytes: &mut [u8], start: usize) {
    let mut at = start;
    let mut count = 0;
    while at < bytes.len() {
        let len = u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]) as usize;
        // Every TLV holds its own 4-byte header, so the walk always advances.
        assert!(len >= 4, "MCU TLV shorter than its header");
        at += len;
        count += 1;
    }
    assert_eq!(at, bytes.len(), "MCU TLV overruns its command");
    put16(bytes, 2, count);
}
impl Profile {
    /// Source mt792x_rx_get_wcid lookup for this retained single-peer namespace.
    /// This is only slot selection, never key/association or DMA authority.
    pub(in crate::net::wifi::mediatek) fn receive_slot(
        self,
        raw: u16,
        unicast: bool,
    ) -> Option<u16> {
        if raw == self.wcid {
            Some(if unicast {
                self.wcid
            } else {
                self.interface.broadcast_wcid
            })
        } else if raw == self.interface.broadcast_wcid && unicast {
            Some(raw)
        } else {
            None
        }
    }
    pub fn validate(self) -> Result<(), Error> {
        self.validate_inner(false)
    }
    fn validate_inner(self, modern: bool) -> Result<(), Error> {
        Requests::station(self.interface, true).map_err(Error::Context)?;
        if self.peer.is_multicast() || self.peer.0 == [0; 6] {
            return Err(Error::InvalidPeer);
        }
        if self.wcid >= 14 || self.wcid == self.interface.broadcast_wcid {
            return Err(Error::InvalidWcid);
        }
        let ch = u8::try_from(self.channel.number).map_err(|_| Error::InvalidChannel)?;
        super::init::validate_channel(self.channel.band, ch, self.channel.frequency_mhz)
            .map_err(|_| Error::InvalidChannel)?;
        if self.channel.band == Band::Ghz6 && !modern {
            return Err(Error::InvalidChannel);
        }
        let mask = if self.channel.band == Band::Ghz2 {
            0xfff
        } else {
            0xff
        };
        if self.supported_rates == 0
            || self.supported_rates & !mask != 0
            || self.basic_rates == 0
            || self.basic_rates & !self.supported_rates != 0
        {
            return Err(Error::InvalidRates);
        }
        if self.aid > 2007
            || self.beacon_interval == 0
            || self.dtim_period == 0
            || !matches!(self.slot_time, 9 | 20)
            || self.antenna_mask == 0
            || self.antenna_mask & !0xf != 0
        {
            return Err(Error::InvalidTiming);
        }
        if !matches!(self.cipher, 0 | 4 | 10 | 11 | 12) {
            return Err(Error::UnsupportedCipher);
        }
        Ok(())
    }
    /// Full mt7925_mcu_sta_cmd. NONE=0 creates an unassociated actual peer;
    /// ASSOC=2 includes the source single-link MLD record. PORT_SECURE is the
    /// source wire state only; the shared OS controlled port stays independent.
    pub fn peer_request(self, enable: bool, associated: bool) -> Result<Vec<u8>, Error> {
        self.peer_request_inner(enable, associated, None)
    }
    fn peer_request_inner(
        self,
        enable: bool,
        associated: bool,
        modern: Option<&modern::Configuration>,
    ) -> Result<Vec<u8>, Error> {
        self.peer_request_validated(enable, associated, modern, modern.is_some())
    }
    fn peer_request_validated(
        self, enable: bool, associated: bool,
        modern: Option<&modern::Configuration>, allow_six: bool,
    ) -> Result<Vec<u8>, Error> {
        self.validate_inner(allow_six)?;
        let mut out = vec![0; 8];
        out[0] = self.interface.bss_index;
        out[1] = self.wcid as u8;
        out[4] = 1;
        out[5] = self.interface.omac_index;
        if !enable {
            tlv(&mut out, 0x25, 8);
            tlv(&mut out, 0x23, 4);
            put16(&mut out, 2, 2);
            return Ok(out);
        }
        let basic = tlv(&mut out, 0, 20);
        put32(basic, 4, 0x10002);
        basic[8] = 2;
        put16(basic, 10, self.aid);
        basic[12..18].copy_from_slice(&self.peer.0);
        put16(basic, 18, if associated { 1 } else { 3 });
        let phy = tlv(&mut out, 0x15, 12);
        put16(phy, 4, self.basic_rates);
        phy[6] = if self.channel.band == Band::Ghz2 {
            3
        } else {
            8
        };
        if let Some(m) = modern {
            m.peer_capabilities(self, &mut out)?;
        }
        let ra = tlv(&mut out, 1, 16);
        put16(
            ra,
            4,
            if self.channel.band == Band::Ghz2 {
                (self.supported_rates >> 4) << 6 | (self.supported_rates & 15)
            } else {
                self.supported_rates << 6
            },
        );
        if let Some(h) = modern.and_then(|m| m.negotiated().ht.as_ref()) {
            ra[6..16].copy_from_slice(&h.peer_rx_mcs);
        }
        let state = tlv(&mut out, 7, 16);
        state[4] = if associated { 2 } else { 0 };
        if let Some(m) = modern.filter(|m| m.negotiated().vht.is_some()) {
            state[12] = m.station_bandwidth() | m.negotiated().tx_nss << 4;
        }
        if associated {
            let mld = tlv(&mut out, 0x20, 28);
            mld[4..10].copy_from_slice(&self.peer.0);
            put16(mld, 10, self.wcid);
            put16(mld, 14, self.wcid);
            mld[16] = 1;
            put16(mld, 20, self.wcid);
            mld[22] = self.interface.bss_index;
        }
        let hdr = tlv(&mut out, 0x2b, 8);
        hdr[5] = 1;
        hdr[6] = 1;
        recount(&mut out, 8);
        Ok(out)
    }
    /// Broadcast slot uses the source no-link_sta path: only its own header
    /// translation TLV, distinct from a full peer and from WMWA raw updates.
    pub fn broadcast_request(self) -> Result<Vec<u8>, Error> {
        self.broadcast_request_validated(false)
    }
    fn broadcast_request_validated(self, allow_six: bool) -> Result<Vec<u8>, Error> {
        self.validate_inner(allow_six)?;
        let mut out = vec![0; 8];
        out[0] = self.interface.bss_index;
        out[1] = self.interface.broadcast_wcid as u8;
        out[2] = 1;
        out[4] = 1;
        out[5] = 0xe;
        let h = tlv(&mut out, 0x2b, 8);
        h[5] = 1;
        h[6] = 1;
        Ok(out)
    }
    pub fn beacon_filter(self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut b = vec![self.interface.bss_index, 0, 0, 0];
        let t = tlv(&mut b, 22, 12);
        put16(t, 4, self.beacon_interval);
        t[6] = self.dtim_period;
        Ok(b)
    }
    /// Source explicit always-awake native profile, without runtime/deep sleep.
    pub fn awake(self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut b = vec![self.interface.bss_index, 0, 0, 0];
        tlv(&mut b, 21, 8);
        Ok(b)
    }
    pub fn disable_beacon_pm(self) -> Result<Vec<u8>, Error> {
        self.disable_beacon_pm_validated(false)
    }
    fn disable_beacon_pm_validated(self, allow_six: bool) -> Result<Vec<u8>, Error> {
        self.validate_inner(allow_six)?;
        let mut b = vec![self.interface.bss_index, 0, 0, 0];
        tlv(&mut b, 27, 4);
        Ok(b)
    }
    pub fn filter_request(self, enable: bool) -> Result<super::init::Request, Error> {
        self.filter_request_validated(enable, false)
    }
    fn filter_request_validated(self, enable: bool, allow_six: bool) -> Result<super::init::Request, Error> {
        self.validate_inner(allow_six)?;
        let mut b = vec![0; 72];
        // Actual primary PHY band_idx is 0 for this single-PHY profile,
        // distinct from the non-MLO interface's band selector ff.
        put16(&mut b, 4, 12);
        put16(&mut b, 6, 68);
        b[8] = 1;
        put32(&mut b, 16, 1 << 11);
        b[20] = if enable { 1 } else { 2 };
        Ok(super::init::Request::client_filter(b))
    }
    pub fn roc(self, token: u8, duration_ms: u32) -> Result<super::init::Request, Error> {
        self.roc_validated(token, duration_ms, false)
    }
    fn roc_validated(self, token: u8, duration_ms: u32, allow_six: bool) -> Result<super::init::Request, Error> {
        self.validate_inner(allow_six)?;
        if duration_ms == 0 {
            return Err(Error::InvalidTiming);
        }
        let mut b = vec![0; 28];
        put16(&mut b, 6, 24);
        b[8] = self.interface.bss_index;
        b[9] = token;
        b[10] = self.channel.number as u8;
        b[12] = match self.channel.band { Band::Ghz2 => 1, Band::Ghz5 => 2, Band::Ghz6 => 3 };
        b[14] = self.channel.number as u8;
        b[17] = self.channel.number as u8;
        put32(&mut b, 20, duration_ms);
        b[24] = 255;
        Ok(super::init::Request::roc(b))
    }
    pub fn abort_roc(self, token: u8) -> Result<super::init::Request, Error> {
        self.abort_roc_validated(token, false)
    }
    fn abort_roc_validated(self, token: u8, allow_six: bool) -> Result<super::init::Request, Error> {
        self.validate_inner(allow_six)?;
        let mut b = vec![0; 16];
        put16(&mut b, 4, 1);
        put16(&mut b, 6, 12);
        b[8] = self.interface.bss_index;
        b[9] = token;
        b[10] = 255;
        Ok(super::init::Request::roc(b))
    }
    /// Full associated BSS helper for the admitted local/peer legacy profile.
    pub fn bss_request(self, enable: bool) -> Result<Vec<u8>, Error> {
        self.bss_request_inner(enable, None)
    }
    fn bss_request_inner(
        self,
        enable: bool,
        modern: Option<&modern::Configuration>,
    ) -> Result<Vec<u8>, Error> {
        self.bss_request_validated(enable, modern, modern.is_some())
    }
    fn bss_request_validated(
        self, enable: bool, modern: Option<&modern::Configuration>, allow_six: bool,
    ) -> Result<Vec<u8>, Error> {
        self.validate_inner(allow_six)?;
        let c = self.interface;
        let two = self.channel.band == Band::Ghz2;
        let mut out = vec![c.bss_index, 0, 0, 0];
        let b = tlv(&mut out, 0, 32);
        b[4] = 1;
        b[5] = c.omac_index;
        b[6] = if c.omac_index > 0x10 { 0 } else { c.omac_index };
        b[7] = c.band_index;
        put32(b, 8, 0x10001);
        b[12] = u8::from(!enable);
        b[13] = c.wmm_index;
        b[14..20].copy_from_slice(&self.peer.0);
        put16(b, 20, c.broadcast_wcid);
        put16(b, 22, self.beacon_interval);
        b[24] = self.dtim_period;
        b[25] = if two { 6 } else { 1 };
        put16(b, 26, self.wcid);
        put16(b, 28, if two { 1 } else { 3 });
        b[31] = c.bss_index;
        let sec = tlv(&mut out, 16, 8);
        // Exact source switch, including its default for CCMP256. These are
        // firmware BSS fields, never evidence of an OS SAE/RSN authentication.
        let (mode, status) = match self.cipher {
            4 => (7, 6),
            11 | 12 => (11, 8),
            _ => (0, 1),
        };
        sec[4] = mode;
        sec[5] = status;
        sec[6] = self.cipher;
        let rate = tlv(&mut out, 11, 16);
        put16(rate, 6, if two { 15 } else { 0x540 });
        rate[12] = u8::from(two);
        rate[13] = (if two { 14 } else { 18 }) + self.basic_rates.trailing_zeros() as u8;
        rate[14] = rate[13];
        tlv(&mut out, 15, 8);
        let m = tlv(&mut out, 26, 20);
        m[4] = 255;
        m[5] = c.bss_index + 32;
        m[6..12].copy_from_slice(&c.address.0);
        m[12] = 255;
        m[13] = 255;
        let ifs = tlv(&mut out, 23, 20);
        ifs[4] = 1;
        put16(ifs, 8, self.slot_time);
        if let Some(m) = modern {
            m.bss_capabilities(self, enable, &mut out)?;
        }
        if enable {
            let r = tlv(&mut out, 2, 16);
            r[4] = self.channel.number as u8;
            r[5] = r[4];
            r[8] = self.antenna_mask.count_ones() as u8;
            r[9] = r[8];
            r[12] = if two { 1 } else { 2 };
            if let Some(m) = modern {
                m.rlm(self, r);
            }
            let mbssid = tlv(&mut out, 6, 8);
            if let Some(m) = modern {
                mbssid[4] = m.operation().mbssid_indicator;
                mbssid[5] = m.operation().mbssid_index;
            }
        }
        recount(&mut out, 4);
        Ok(out)
    }
}

/// Full non-random MT7925 scan TLVs, including source RNR BSSID targeting.
/// The caller supplies already prepared probe IEs for this codec-only entry.
pub fn scan(
    context: Context,
    sequence: u8,
    request: &crate::net::wifi::scan::Request,
) -> Result<super::init::Request, Error> {
    scan_with_elements(context, sequence, request, None)
}
/// Native prepared per-band probe IEs. Capacity refusal precedes scan ownership;
/// the native caller must never silently lose a later band's capabilities.
pub(in crate::net::wifi::mediatek) fn scan_with_elements(
    context: Context,
    sequence: u8,
    request: &crate::net::wifi::scan::Request,
    elements: Option<&[Vec<u8>; 3]>,
) -> Result<super::init::Request, Error> {
    const SCAN_IE_BUDGET: usize = 608;
    const RNR_MAX_BSSIDS: usize = 10;
    const SCAN_FUNCTION_SPLIT: u8 = 1 << 5;
    const SCAN_FUNCTION_RNR: u8 = 1 << 3;
    if let Some(elements) = elements {
        let required: usize = elements
            .iter()
            .filter(|ie| !ie.is_empty())
            .map(|ie| 8 + ie.len())
            .sum();
        if required > SCAN_IE_BUDGET {
            return Err(Error::InvalidScanElements);
        }
    }
    Requests::station(context, true).map_err(Error::Context)?;
    // Source deduplicates by BSSID, preserving the first channel association.
    // Firmware can consume only ten unique targets. Refuse excess work explicitly
    // before scan ownership/publication rather than silently dropping a target.
    let mut targets = [None; RNR_MAX_BSSIDS];
    let mut target_count = 0;
    for target in request.six_ghz() {
        if targets[..target_count]
            .iter()
            .flatten()
            .any(|&(bssid, _)| bssid == target.bssid)
        {
            continue;
        }
        if target_count == targets.len() {
            return Err(Error::InvalidScanTargets);
        }
        let channel = request
            .channels()
            .get(target.channel_index)
            .filter(|ch| ch.band == Band::Ghz6)
            .ok_or(Error::InvalidScanTargets)?;
        let number = u8::try_from(channel.number).map_err(|_| Error::InvalidChannel)?;
        targets[target_count] = Some((target.bssid, number));
        target_count += 1;
    }
    let mut out = Vec::new();
    out.try_reserve_exact(1308).map_err(|_| Error::NoMemory)?;
    out.extend_from_slice(&[
        sequence | (context.band_index << 7),
        context.bss_index,
        0,
        0,
    ]);
    let req = tlv(&mut out, 1, 20);
    req[4] = u8::from(request.active());
    req[5] = if request.active() { 2 } else { 0 };
    req[6] = SCAN_FUNCTION_SPLIT
        | if request.six_ghz().is_empty() {
            0
        } else {
            SCAN_FUNCTION_RNR
        };
    let ssid = tlv(&mut out, 10, 368);
    let mut count = 0;
    for name in request.ssids() {
        if name.is_empty() {
            continue;
        }
        let at = 8 + count * 36;
        put32(ssid, at, name.len() as u32);
        ssid[at + 4..at + 4 + name.len()].copy_from_slice(name);
        count += 1;
    }
    ssid[4] = if count > 0 { 4 } else { 1 };
    ssid[5] = count as u8;
    if target_count == 0 {
        tlv(&mut out, 11, 16)[4..10].copy_from_slice(&[255; 6]);
    } else {
        for &(bssid, channel) in targets[..target_count].iter().flatten() {
            let bssid_tlv = tlv(&mut out, 11, 16);
            bssid_tlv[4..10].copy_from_slice(&bssid.0);
            bssid_tlv[10] = channel;
            bssid_tlv[11] = RNR_MAX_BSSIDS as u8;
            bssid_tlv[13] = RNR_MAX_BSSIDS as u8;
        }
    }
    let channels = tlv(&mut out, 12, 136);
    channels[4] = 4;
    channels[5] = request.channels().len() as u8;
    for (i, ch) in request.channels().iter().enumerate() {
        if ch.number > 255 {
            return Err(Error::InvalidChannel);
        }
        channels[8 + i * 2] = match ch.band {
            Band::Ghz2 => 1,
            Band::Ghz5 => 2,
            Band::Ghz6 => 3,
        };
        channels[9 + i * 2] = ch.number as u8;
    }
    tlv(&mut out, 14, 12);
    let mut ie_count = 0;
    if elements.is_some() || !request.extra_elements().is_empty() {
        // Full source helper shares this budget between all selected bands;
        // it stops, rather than emitting an over-budget later band.
        let mut remaining = SCAN_IE_BUDGET;
        for (index, band) in [Band::Ghz2, Band::Ghz5, Band::Ghz6].into_iter().enumerate() {
            if request.channels().iter().any(|ch| ch.band == band) {
                let bytes = elements.map_or(request.extra_elements(), |ies| ies[index].as_slice());
                if bytes.is_empty() {
                    continue;
                }
                let length = 8 + bytes.len();
                if length > remaining {
                    break;
                }
                let ie = tlv(&mut out, 13, length);
                put16(ie, 4, bytes.len() as u16);
                ie[6] = match band {
                    Band::Ghz2 => 1,
                    Band::Ghz5 => 2,
                    Band::Ghz6 => 3,
                };
                ie[8..].copy_from_slice(bytes);
                ie_count += 1;
                remaining -= length;
            }
        }
    }
    let count = 4 + target_count.max(1) + ie_count;
    put16(&mut out, 2, count as u16);
    Ok(super::init::Request::scan(out, false))
}
pub fn cancel_scan(context: Context, sequence: u8) -> super::init::Request {
    let mut b = vec![sequence, context.bss_index, 0, 0];
    tlv(&mut b, 2, 8);
    super::init::Request::scan(b, true)
}
/// UNI_SCAN_DONE's four-byte fixed header followed by source TLVs. Unknown
/// country/channel facts stay raw; they never overwrite trusted policy.
pub fn scan_done(payload: &[u8]) -> Result<bool, Error> {
    let mut rest = payload.get(4..).ok_or(Error::InvalidTiming)?;
    let mut done = false;
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(Error::InvalidTiming);
        }
        let tag = u16::from_le_bytes([rest[0], rest[1]]);
        let len = u16::from_le_bytes([rest[2], rest[3]]) as usize;
        if len < 4 || len > rest.len() {
            return Err(Error::InvalidTiming);
        }
        done |= tag == 0;
        rest = &rest[len..];
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    fn scan_elements(length: usize) -> Vec<u8> {
        let mut bytes = vec![0x5a; length];
        let mut at = 0;
        while at < length {
            let size = (length - at).min(257);
            bytes[at] = 221;
            bytes[at + 1] = (size - 2) as u8;
            at += size;
        }
        bytes
    }
    fn scan_channels(mask: u8) -> Vec<Channel> {
        [
            Channel {
                band: Band::Ghz2,
                number: 1,
                frequency_mhz: 2412,
            },
            Channel {
                band: Band::Ghz5,
                number: 36,
                frequency_mhz: 5180,
            },
            Channel {
                band: Band::Ghz6,
                number: 1,
                frequency_mhz: 5955,
            },
        ]
        .into_iter()
        .enumerate()
        .filter_map(|(i, c)| (mask & (1 << i) != 0).then_some(c))
        .collect()
    }
    fn scan_context() -> Context {
        Context {
            bss_index: 0,
            omac_index: 0,
            band_index: 255,
            wmm_index: 0,
            link_index: 0,
            broadcast_wcid: 19,
            address: Mac([2; 6]),
        }
    }
    #[test]
    fn full_source_rnr_scan_requests_match_targets_duplicates_bands_and_ie_budget() {
        use crate::net::wifi::scan::{Request, SixGhz};
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        let mut index = 0;
        for n in [1, 2, 4, 10] {
            for duplicate in 0..3 {
                for names in [0, 1, 2, 4] {
                    for length in [0, 4, 200] {
                        for mix in 0..3 {
                            let all = [
                                Channel {
                                    band: Band::Ghz2,
                                    number: 1,
                                    frequency_mhz: 2412,
                                },
                                Channel {
                                    band: Band::Ghz5,
                                    number: 36,
                                    frequency_mhz: 5180,
                                },
                                Channel {
                                    band: Band::Ghz6,
                                    number: 1,
                                    frequency_mhz: 5955,
                                },
                                Channel {
                                    band: Band::Ghz6,
                                    number: 5,
                                    frequency_mhz: 5975,
                                },
                            ];
                            let mut channels = Vec::new();
                            if mix == 2 {
                                channels.push(all[0]);
                            }
                            if mix != 0 {
                                channels.push(all[1]);
                            }
                            let six = channels.len();
                            channels.extend_from_slice(&all[2..]);
                            let mut params = Vec::new();
                            for j in 0..n {
                                let target = SixGhz {
                                    channel_index: six + j % 2,
                                    bssid: Mac([
                                        2,
                                        0x42,
                                        (index & 255) as u8,
                                        (index >> 8) as u8,
                                        j as u8,
                                        0x7f,
                                    ]),
                                    short_ssid: (j % 2 != 0).then_some(0xabc000 + j as u32),
                                    unsolicited_probe: j % 2 == 0,
                                    psc_no_listen: j % 2 != 0,
                                    psd_20: -75 + j as i8,
                                };
                                params.push(target);
                                if duplicate == 2 {
                                    params.push(SixGhz {
                                        channel_index: six + (j + 1) % 2,
                                        ..target
                                    });
                                }
                            }
                            if duplicate == 1 {
                                for j in 0..n {
                                    params.push(SixGhz {
                                        channel_index: six + j % 2,
                                        ..params[n - 1 - j]
                                    });
                                }
                            }
                            let ssids = (0..names).map(|j| vec![65 + j as u8; j]).collect();
                            let request = Request::with_six_ghz(
                                channels,
                                ssids,
                                scan_elements(length),
                                params,
                            )
                            .unwrap();
                            let encoded =
                                scan(scan_context(), (index % 127 + 1) as u8, &request).unwrap();
                            hash.update([0x16]);
                            hash.update((encoded.body().len() as u16).to_le_bytes());
                            hash.update(encoded.body());
                            index += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(index, 432);
        assert_eq!(
            alloc::format!("{:x}", hash.finalize()),
            "68a1c494a1886a2da6e86f7f013f35f70d3990ae076f4bf0f4c71216d722c831"
        );
    }
    #[test]
    fn native_per_band_probe_budget_refuses_before_losing_a_band() {
        let request =
            crate::net::wifi::scan::Request::new(scan_channels(7), vec![], vec![]).unwrap();
        let over = core::array::from_fn(|_| scan_elements(200));
        assert!(matches!(
            scan_with_elements(scan_context(), 1, &request, Some(&over)),
            Err(Error::InvalidScanElements)
        ));
        let mut fit = over;
        fit[2] = scan_elements(184);
        let bytes = scan_with_elements(scan_context(), 1, &request, Some(&fit)).unwrap();
        assert_eq!(
            u16::from_le_bytes(bytes.body()[2..4].try_into().unwrap()),
            8
        );
        assert_eq!(bytes.body().len(), 4 + 20 + 368 + 16 + 136 + 12 + 608);
    }
    #[test]
    fn odd_scan_elements_keep_byte_layout_and_shared_band_budget() {
        for length in [3, 199, 295, 297, 383] {
            let request = crate::net::wifi::scan::Request::new(
                scan_channels(7),
                vec![],
                scan_elements(length),
            )
            .unwrap();
            let encoded = scan(scan_context(), 1, &request).unwrap();
            let mut rest = &encoded.body()[4..];
            let mut ie_bytes = Vec::new();
            while !rest.is_empty() {
                let size = u16::from_le_bytes(rest[2..4].try_into().unwrap()) as usize;
                if rest[..2] == 13u16.to_le_bytes() {
                    ie_bytes.push(rest[..size].to_vec());
                }
                rest = &rest[size..];
            }
            // Independent byte-level expectation: consecutive 8-byte IE
            // headers plus payload fit in the source's 608-byte total budget.
            let expected = (608 / (length + 8)).min(3);
            assert_eq!(ie_bytes.len(), expected);
            assert!(ie_bytes.iter().map(Vec::len).sum::<usize>() <= 608);
            assert_eq!(
                u16::from_le_bytes(encoded.body()[2..4].try_into().unwrap()) as usize,
                5 + expected
            );
            for (index, bytes) in ie_bytes.iter().enumerate() {
                assert_eq!(&bytes[..2], &13u16.to_le_bytes());
                assert_eq!(&bytes[2..4], &((length + 8) as u16).to_le_bytes());
                assert_eq!(&bytes[4..6], &(length as u16).to_le_bytes());
                assert_eq!(bytes[6], index as u8 + 1);
                assert_eq!(bytes[7], 0);
                assert_eq!(&bytes[8..], request.extra_elements());
            }
        }
    }
    #[test]
    fn unchanged_full_scan_helper_matches_three_bands_and_total_ie_budget() {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        let mut case = 0;
        for mask in 1..8 {
            for length in [0, 4, 200, 296, 297, 300, 384] {
                let request = crate::net::wifi::scan::Request::new(
                    scan_channels(mask),
                    vec![],
                    scan_elements(length),
                )
                .unwrap();
                let encoded = scan(scan_context(), (case % 127 + 1) as u8, &request).unwrap();
                hash.update([0x16]);
                hash.update((encoded.body().len() as u16).to_le_bytes());
                hash.update(encoded.body());
                case += 1;
            }
        }
        assert_eq!(case, 49);
        // Full unchanged mt7925_mcu_hw_scan/build_scan_ie_tlv bodies, source
        // layouts and TLV appender under ASan/UBSan. Odd subsequent IE alignment
        // is an explicit donor oracle limit; the independent test retains it.
        assert_eq!(
            <[u8; 32]>::from(hash.finalize()),
            [
                0x0f, 0xea, 0x6a, 0xda, 0xf0, 0xfa, 0xe0, 0x04, 0xa7, 0xde, 0xaa, 0xad, 0x2f, 0x26,
                0xd0, 0x3e, 0x7f, 0x28, 0x3e, 0x6c, 0xaa, 0x52, 0x65, 0x1b, 0x1a, 0xf6, 0x19, 0xcf,
                0xfe, 0x25, 0xce, 0x3a
            ]
        );
    }

    #[test]
    #[ignore = "requires fresh unchanged full MT7925 client source helpers"]
    fn unchanged_full_client_helpers_match_selected_legacy_requests_and_wcid() {
        let root = std::path::PathBuf::from(
            std::env::var_os("STELA_MT7925_CLIENT_ORACLE").expect("client source oracle"),
        );
        let trace = std::fs::read(root.join("client.trace")).unwrap();
        let mut at = 0;
        for i in 0..128u16 {
            let two = i % 2 == 0;
            let mut local =
                core::array::from_fn(|j| 2u8.wrapping_add(i as u8).wrapping_add(j as u8));
            local[0] &= 254;
            let mut peer =
                core::array::from_fn(|j| 4u8.wrapping_add(i as u8).wrapping_add(j as u8));
            peer[0] &= 254;
            let p = Profile {
                interface: Context {
                    bss_index: (i % 4) as u8,
                    omac_index: ((i * 7) % 64) as u8,
                    band_index: 255,
                    wmm_index: ((i / 4) % 4) as u8,
                    link_index: 0,
                    broadcast_wcid: 19 - i % 4,
                    address: Mac(local),
                },
                peer: Mac(peer),
                wcid: i % 14,
                channel: Channel {
                    band: if two { Band::Ghz2 } else { Band::Ghz5 },
                    number: if two { 6 } else { 36 },
                    frequency_mhz: if two { 2437 } else { 5180 },
                },
                aid: i + 1,
                basic_rates: if two { 15 } else { 0x15 },
                supported_rates: if two { 0xfff } else { 0xff },
                beacon_interval: 100 + i,
                dtim_period: 1 + (i % 4) as u8,
                slot_time: if (i / 8) % 2 == 1 { 9 } else { 20 },
                antenna_mask: 1 + (i % 15) as u8,
                cipher: if (i / 16) % 2 == 1 { 4 } else { 0 },
            };
            let names = (0..i % 5).map(|k| vec![65 + k as u8; k as usize]).collect();
            let scan_request = crate::net::wifi::scan::Request::new(
                vec![p.channel],
                names,
                if (i / 4) % 2 == 1 {
                    vec![1, 1, 0x8c]
                } else {
                    vec![]
                },
            )
            .unwrap();
            let sequence = ((i % 127) + 1) as u8 & 127;
            for (command, body) in [
                (3, p.peer_request(true, false).unwrap()),
                (3, p.peer_request(true, true).unwrap()),
                (3, p.peer_request(false, false).unwrap()),
                (2, p.bss_request(false).unwrap()),
                (2, p.bss_request(true).unwrap()),
                (0x27, p.roc((i + 1) as u8, 1000).unwrap().body().to_vec()),
                (0x27, p.abort_roc((i + 1) as u8).unwrap().body().to_vec()),
                (2, p.beacon_filter().unwrap()),
                (2, p.awake().unwrap()),
                (2, p.disable_beacon_pm().unwrap()),
                (8, p.filter_request(true).unwrap().body().to_vec()),
                (8, p.filter_request(false).unwrap().body().to_vec()),
                (
                    0x16,
                    scan(p.interface, sequence, &scan_request)
                        .unwrap()
                        .body()
                        .to_vec(),
                ),
                (0x16, cancel_scan(p.interface, sequence).body().to_vec()),
            ] {
                assert_eq!(trace[at], command, "case {i}");
                let n = u16::from_le_bytes(trace[at + 1..at + 3].try_into().unwrap()) as usize;
                at += 3;
                assert_eq!(body, &trace[at..at + n], "case {i} cmd {command}");
                at += n;
            }
        }
        let p = Profile {
            wcid: 1,
            interface: Context {
                bss_index: 0,
                omac_index: 0,
                band_index: 255,
                wmm_index: 0,
                link_index: 0,
                broadcast_wcid: 19,
                address: Mac([2; 6]),
            },
            peer: Mac([4; 6]),
            channel: Channel {
                band: Band::Ghz5,
                number: 36,
                frequency_mhz: 5180,
            },
            aid: 1,
            basic_rates: 1,
            supported_rates: 1,
            beacon_interval: 100,
            dtim_period: 1,
            slot_time: 9,
            antenna_mask: 1,
            cipher: 0,
        };
        for raw in 0..22 {
            for unicast in [false, true] {
                let expected = u16::from_le_bytes(trace[at..at + 2].try_into().unwrap());
                at += 2;
                assert_eq!(p.receive_slot(raw, unicast).unwrap_or(u16::MAX), expected);
            }
        }
        assert_eq!(at, trace.len());
    }
}

/// Actual UNI_ROC event observations. Unlike the source's global boolean, the
/// native owner additionally matches exact token/BSS/channel/profile. The raw
/// status remains visible; no copied grant may authorize a different owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocGrant {
    pub bss: u8,
    pub token: u8,
    pub status: u8,
    pub channel: u8,
    pub sco: u8,
    pub band: u8,
    pub width: u8,
    pub center: u8,
    pub center2: u8,
    pub request_type: u8,
    pub hardware_band: u8,
    pub duration_ms: u32,
}
pub fn roc_grants(payload: &[u8]) -> Result<Vec<RocGrant>, Error> {
    let mut rest = payload.get(4..).ok_or(Error::InvalidTiming)?;
    let mut out = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(Error::InvalidTiming);
        }
        let tag = u16::from_le_bytes([rest[0], rest[1]]);
        let len = u16::from_le_bytes([rest[2], rest[3]]) as usize;
        if len < 4 || len > rest.len() {
            return Err(Error::InvalidTiming);
        }
        if tag == 0 {
            if len < 20 {
                return Err(Error::InvalidTiming);
            }
            out.push(RocGrant {
                bss: rest[4],
                token: rest[5],
                status: rest[6],
                channel: rest[7],
                sco: rest[8],
                band: rest[9],
                width: rest[10],
                center: rest[11],
                center2: rest[12],
                request_type: rest[13],
                hardware_band: rest[14],
                duration_ms: u32::from_le_bytes(rest[16..20].try_into().unwrap()),
            });
        }
        rest = &rest[len..];
    }
    Ok(out)
}
