// SPDX-License-Identifier: GPL-2.0-only
// Capability layouts and intersections adapt pinned Linux mac80211
// {ht,vht,he,eht}.c and ieee80211-{ht,vht,he,eht}.h; see THIRD_PARTY.md.
//! Validated single-link PHY negotiation inputs and directional rate bounds.
//!
//! These are observations/negotiation results, never radio, key or association
//! authority. The vendor must encode every negotiated effect and obtain actual
//! firmware completion before station attachment. Existing legacy constructors
//! remain restricted until their modern configuration/data paths consume this.

use crate::net::wifi::Band;
use alloc::vec::Vec;

mod caps;
mod negotiate;
pub use caps::{Eht, EhtMcs, EhtMcsUnion, He, Ht, McsMaps, Ppe, Vht};
pub use negotiate::{
    CommonEhtMcs, Negotiated, NegotiatedEht, NegotiatedHe, NegotiatedHt, NegotiatedVht,
    NegotiatedWmm,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    Invalid(&'static str),
    Missing(&'static str),
    Unsupported(&'static str),
    Incompatible(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Station,
    AccessPoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    Legacy,
    Ht,
    Vht,
    He,
    Eht,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    Mhz20,
    Mhz40,
    Mhz80,
    Mhz160,
    Mhz80P80,
    Mhz320,
}

/// Source mt76 rate-table indices: CCK first on 2.4GHz, OFDM-only elsewhere.
/// Membership selectors are separate and never masquerade as ordinary rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LegacyRates {
    pub supported: u16,
    pub basic: u16,
    /// Bits0..3: HT(127), VHT(126), HE(122), EHT(121). Bit4 retains
    /// SAE H2E(123) for the real authentication owner; it is not a PHY rate.
    pub selectors: u8,
}

const RATES_2G: [u8; 12] = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];

impl LegacyRates {
    fn add(&mut self, band: Band, bytes: &[u8]) -> Result<(), Error> {
        let table = if band == Band::Ghz2 {
            &RATES_2G[..]
        } else {
            &RATES_2G[4..]
        };
        for &raw in bytes {
            let rate = raw & 0x7f;
            if raw & 0x80 != 0 {
                let selector = match rate {
                    127 => Some(0),
                    126 => Some(1),
                    122 => Some(2),
                    121 => Some(3),
                    123 => Some(4),
                    _ => None,
                };
                if let Some(bit) = selector {
                    self.selectors |= 1 << bit;
                    continue;
                }
            }
            let Some(index) = table.iter().position(|&value| value == rate) else {
                if raw & 0x80 != 0 {
                    return Err(Error::Unsupported("unknown mandatory legacy rate/selector"));
                }
                continue; // Unknown optional rates cannot enter the hardware bitmap.
            };
            self.supported |= 1 << index;
            if raw & 0x80 != 0 {
                self.basic |= 1 << index;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessCategory {
    pub aci: u8,
    pub admission_control: bool,
    pub aifsn: u8,
    pub ecw_min: u8,
    pub ecw_max: u8,
    /// Wire units are 32 microseconds, not milliseconds.
    pub txop_32us: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wmm {
    pub qos_info: u8,
    pub parameters: Option<[AccessCategory; 4]>,
}

impl Wmm {
    pub(in crate::net::wifi) fn parse(bytes: &[u8], role: Role) -> Result<Self, Error> {
        if bytes.get(..4) != Some(&[0, 0x50, 0xf2, 2]) || bytes.get(5) != Some(&1) {
            return Err(Error::Invalid("WMM OUI/type/version"));
        }
        let subtype = *bytes.get(4).ok_or(Error::Truncated)?;
        let qos_info = *bytes.get(6).ok_or(Error::Truncated)?;
        if subtype == 0 && bytes.len() == 7 {
            return Ok(Self {
                qos_info,
                parameters: None,
            });
        }
        if subtype != 1 || bytes.len() != 24 || role != Role::AccessPoint {
            return Err(Error::Invalid("WMM subtype/length/role"));
        }
        let mut parsed = [None; 4];
        for data in bytes[8..].as_chunks::<4>().0 {
            let aci = (data[0] >> 5) & 3;
            let ac = AccessCategory {
                aci,
                admission_control: data[0] & 0x10 != 0,
                aifsn: data[0] & 0xf,
                ecw_min: data[1] & 0xf,
                ecw_max: data[1] >> 4,
                txop_32us: u16::from_le_bytes([data[2], data[3]]),
            };
            if parsed[usize::from(aci)].is_some() || ac.aifsn < 2 || ac.ecw_min > ac.ecw_max {
                return Err(Error::Invalid("WMM duplicate/invalid access category"));
            }
            parsed[usize::from(aci)] = Some(ac);
        }
        Ok(Self {
            qos_info,
            parameters: Some(parsed.map(Option::unwrap)),
        })
    }
}

/// Actual complete management-IE observations, parsed in two passes so EHT
/// sizing uses HE regardless of IE order. Duplicates and partial fields refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    band: Band,
    role: Role,
    rates: LegacyRates,
    ht: Option<Ht>,
    vht: Option<Vht>,
    he: Option<He>,
    eht: Option<Eht>,
    he_6ghz: Option<u16>,
    wmm: Option<Wmm>,
    // Complete outer ML TLVs and contiguous fragments; unparsed AP facts only.
    unselected_multi_link: Vec<u8>,
    // Actual local source object words, including untransmitted width slots.
    // Observations only; the native owner must bind them to its real issuer.
    local_he_source_maps: Option<[McsMaps; 3]>,
}

fn insert<'a>(slot: &mut Option<&'a [u8]>, data: &'a [u8]) -> Result<(), Error> {
    if slot.replace(data).is_some() {
        return Err(Error::Invalid("duplicate capability IE"));
    }
    Ok(())
}

impl Capabilities {
    pub fn parse(band: Band, role: Role, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 2300 {
            return Err(Error::Invalid("capability IE bound"));
        }
        let (mut rates_ie, mut ext_rates, mut ht, mut vht, mut he, mut eht, mut he6, mut wmm) =
            (None, None, None, None, None, None, None, None);
        let mut unselected_multi_link = Vec::new();
        let mut ml_fragment = false;
        let mut rest = bytes;
        while !rest.is_empty() {
            let header = rest.get(..2).ok_or(Error::Truncated)?;
            let data = rest
                .get(2..2 + usize::from(header[1]))
                .ok_or(Error::Truncated)?;
            let mle = header[0] == 255 && data.first() == Some(&107);
            let fragment = header[0] == 242 && ml_fragment;
            if role == Role::AccessPoint && (mle || fragment) {
                // Follow the non-MLD Linux path: no common/per-STA field or
                // profile is interpreted. Preserve even malformed/unknown
                // bodies as opaque facts, never MLD permission.
                unselected_multi_link.extend_from_slice(&rest[..2 + data.len()]);
            }
            ml_fragment = (mle || fragment) && data.len() == 255;
            match header[0] {
                1 => {
                    if data.is_empty() || data.len() > 8 {
                        return Err(Error::Invalid("supported rates length"));
                    }
                    insert(&mut rates_ie, data)?;
                }
                50 => {
                    if data.is_empty() {
                        return Err(Error::Invalid("extended rates length"));
                    }
                    insert(&mut ext_rates, data)?;
                }
                45 => insert(&mut ht, data)?,
                191 => insert(&mut vht, data)?,
                221 if data.starts_with(&[0, 0x50, 0xf2, 2]) => insert(&mut wmm, data)?,
                255 => match data.first() {
                    Some(35) => insert(&mut he, &data[1..])?,
                    Some(59) => insert(&mut he6, &data[1..])?,
                    Some(108) => insert(&mut eht, &data[1..])?,
                    Some(107) if role == Role::Station => {
                        return Err(Error::Unsupported("requested multi-link capability"));
                    }
                    Some(107) => (),
                    None => return Err(Error::Truncated),
                    _ => (),
                },
                _ => (),
            }
            rest = &rest[2 + data.len()..];
        }
        let mut rates = LegacyRates::default();
        if let Some(data) = rates_ie {
            rates.add(band, data)?;
        }
        if let Some(data) = ext_rates {
            rates.add(band, data)?;
        }
        if band != Band::Ghz6 && (rates_ie.is_none() || rates.supported == 0) {
            return Err(Error::Missing("ordinary supported legacy rates"));
        }
        if band == Band::Ghz6 && (ht.is_some() || vht.is_some()) {
            return Err(Error::Invalid("HT/VHT capabilities in 6GHz"));
        }
        let ht = ht.map(Ht::parse).transpose()?;
        let vht = vht.map(Vht::parse).transpose()?;
        let he = he.map(He::parse).transpose()?;
        let eht = eht
            .map(|data| Eht::parse(data, he.as_ref().ok_or(Error::Missing("HE for EHT"))?, role))
            .transpose()?;
        let he_6ghz = he6
            .map(|data| {
                <[u8; 2]>::try_from(data)
                    .map(u16::from_le_bytes)
                    .map_err(|_| Error::Invalid("HE6 capability length"))
            })
            .transpose()?;
        if band == Band::Ghz6 && (he.is_none() || he_6ghz.is_none()) {
            return Err(Error::Missing("HE/HE6 on 6GHz"));
        }
        if band != Band::Ghz6 && he_6ghz.is_some() {
            return Err(Error::Invalid("HE6 capability outside 6GHz"));
        }
        if vht.is_some() && ht.is_none() {
            return Err(Error::Missing("HT for VHT"));
        }
        let wmm = wmm.map(|data| Wmm::parse(data, role)).transpose()?;
        Ok(Self {
            band,
            role,
            rates,
            ht,
            vht,
            he,
            eht,
            he_6ghz,
            wmm,
            unselected_multi_link,
            local_he_source_maps: None,
        })
    }
    /// Opaque AP advertisement TLVs, including contiguous full-length ML
    /// fragments. No MLD MAC, link/profile, capability or structural validity
    /// is inferred from these bytes. Local/outgoing ML remains unsupported.
    pub fn unselected_multi_link_elements(&self) -> &[u8] {
        &self.unselected_multi_link
    }
    /// Retain actual local source struct slots without inferring hidden words
    /// from absent wire maps. These are observations, never hardware authority.
    /// The physical owner must compare them to its genuine source-cap issuer.
    pub fn with_local_he_source_maps(mut self, maps: [McsMaps; 3]) -> Result<Self, Error> {
        if self.role != Role::Station {
            return Err(Error::Invalid("local source maps on AP observation"));
        }
        let he = self
            .he
            .as_ref()
            .ok_or(Error::Missing("local HE capability"))?;
        if he.mcs_80 != maps[0]
            || he.mcs_160.is_some_and(|m| m != maps[1])
            || he.mcs_80p80.is_some_and(|m| m != maps[2])
        {
            return Err(Error::Incompatible("local source/transmitted HE maps"));
        }
        self.local_he_source_maps = Some(maps);
        Ok(self)
    }
    pub fn local_he_source_maps(&self) -> Option<&[McsMaps; 3]> {
        self.local_he_source_maps.as_ref()
    }
    pub(crate) fn matches_wire_capabilities(&self, observed: &Self) -> bool {
        let mut stripped = self.clone();
        stripped.local_he_source_maps = None;
        stripped == *observed
    }
    pub fn meets_peer_he_basic(&self, required: u16) -> bool {
        self.role == Role::AccessPoint
            && self
                .he
                .as_ref()
                .is_some_and(|he| he.peer_meets_basic(required))
    }
    pub fn meets_local_he_basic(&self, required: u16) -> Result<bool, Error> {
        if self.role != Role::Station {
            return Err(Error::Invalid("local HE verification role"));
        }
        self.he
            .as_ref()
            .ok_or(Error::Missing("local HE capability"))?
            .local_meets_basic(required, self.local_he_source_maps)
    }
    /// Check the AP basic EHT MCS/NSS requirement against every actual local
    /// supported width, including20-only STA mapping. This is metadata
    /// validation only, not regulatory, association or publication authority.
    pub fn meets_eht_basic(&self, required: [u8; 4]) -> bool {
        self.he
            .as_ref()
            .zip(self.eht.as_ref())
            .is_some_and(|(he, eht)| eht.meets_basic(he, required))
    }
    pub const fn band(&self) -> Band {
        self.band
    }
    pub const fn role(&self) -> Role {
        self.role
    }
    pub const fn rates(&self) -> LegacyRates {
        self.rates
    }
    pub const fn ht(&self) -> Option<&Ht> {
        self.ht.as_ref()
    }
    pub const fn vht(&self) -> Option<&Vht> {
        self.vht.as_ref()
    }
    pub const fn he(&self) -> Option<&He> {
        self.he.as_ref()
    }
    pub const fn eht(&self) -> Option<&Eht> {
        self.eht.as_ref()
    }
    pub const fn he_6ghz(&self) -> Option<u16> {
        self.he_6ghz
    }
    pub const fn wmm(&self) -> Option<&Wmm> {
        self.wmm.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        data[..4].copy_from_slice(&(1_u32 | 4 | 0x60 | 0x180 | (3 << 23)).to_le_bytes());
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
        data[0] = 1 << 6; // Actual 2.4GHz max-MPDU selection; ignored elsewhere.
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

    #[test]
    fn source_rate_indices_basic_rates_and_membership_are_distinct() {
        let (local, peer) = pair(Band::Ghz2, 2, false);
        assert_eq!(local.rates().supported, 0xfff);
        assert_eq!(peer.rates().basic, 0x153);
        let (local, peer) = pair(Band::Ghz5, 12, false);
        assert_eq!(local.rates().supported, 0xff);
        assert_eq!(peer.rates().basic, 0x15);
        let mut ies = modern_ies(Band::Ghz5, Role::AccessPoint, 12, false);
        // Required HT/VHT/HE/EHT selectors occupy none of the eight rate bits.
        ie(&mut ies, 50, &[0xff, 0xfe, 0xfa, 0xf9]);
        let peer = Capabilities::parse(Band::Ghz5, Role::AccessPoint, &ies).unwrap();
        assert_eq!(peer.rates().selectors, 15);
        assert_eq!(peer.rates().supported, 0xff);
        assert!(Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).is_ok());
        let mut rates = LegacyRates::default();
        assert!(rates.add(Band::Ghz5, &[0x82]).is_err()); // CCK cannot become an OFDM bit.
        rates.add(Band::Ghz5, &[0xfb]).unwrap(); // SAE H2E is retained separately.
        assert_eq!((rates.supported, rates.selectors), (0, 16));
        assert!(Negotiated::between(&local, &peer, Mode::Ht, Width::Mhz40).is_err());
        assert!(rates.add(Band::Ghz5, &[0xf8]).is_err()); // UHR remains unsupported.
    }

    #[test]
    fn real_selected_family_width_nss_aggregation_and_edca_reach_typed_output() {
        let (local, peer) = pair(Band::Ghz5, 12, false);
        for (mode, width) in [
            (Mode::Ht, Width::Mhz40),
            (Mode::Vht, Width::Mhz160),
            (Mode::He, Width::Mhz160),
            (Mode::Eht, Width::Mhz160),
        ] {
            let n = Negotiated::between(&local, &peer, mode, width).unwrap();
            assert_eq!((n.rx_nss, n.tx_nss), (2, 2));
            assert_eq!(n.legacy.basic, 0x15);
            assert_eq!(n.peer_mpdu_spacing, 4);
            assert!(!n.legacy20_compatible());
            let wmm = n.wmm.as_ref().unwrap();
            assert_eq!(wmm.parameter_set_count, 9);
            assert_eq!((wmm.uapsd_queues, wmm.max_service_period), (15, 3));
            assert_eq!(wmm.access_categories[2].txop_32us, 94);
            assert_eq!(wmm.access_categories[3].txop_32us, 47);
            assert_eq!(n.peer(), &peer);
        }
        let (local, peer) = pair(Band::Ghz6, 12, true);
        let n = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz320).unwrap();
        assert_eq!((n.rx_nss, n.tx_nss, n.max_tx_amsdu), (2, 2, 7991));
        assert_eq!(n.legacy.supported, 0);
        assert_eq!(n.peer_ampdu_base_exponent, 1);
        assert_eq!(n.peer_mpdu_spacing, 2);
    }

    #[test]
    fn no_width_rate_nss_or_wmm_fallback_when_required_effects_absent() {
        let (local, peer) = pair(Band::Ghz5, 4, false);
        for (mode, width) in [
            (Mode::He, Width::Mhz160),
            (Mode::Eht, Width::Mhz160),
            (Mode::Eht, Width::Mhz320),
            (Mode::Eht, Width::Mhz80P80),
        ] {
            assert!(Negotiated::between(&local, &peer, mode, width).is_err());
        }
        let mut bad = peer.clone();
        bad.he.as_mut().unwrap().mcs_80 = McsMaps {
            rx: 0xffff,
            tx: 0xffff,
        };
        assert!(matches!(
            Negotiated::between(&local, &bad, Mode::He, Width::Mhz80),
            Err(Error::Incompatible(_))
        ));
        bad = peer.clone();
        bad.wmm = None;
        assert!(matches!(
            Negotiated::between(&local, &bad, Mode::He, Width::Mhz80),
            Err(Error::Missing(_))
        ));
        bad = peer.clone();
        bad.rates.basic |= 1 << 10;
        assert!(matches!(
            Negotiated::between(&local, &bad, Mode::He, Width::Mhz80),
            Err(Error::Incompatible(_))
        ));
        bad = peer.clone();
        bad.eht.as_mut().unwrap().mcs.bw80 = Some([0; 3]);
        assert!(matches!(
            Negotiated::between(&local, &bad, Mode::Eht, Width::Mhz80),
            Err(Error::Incompatible(_))
        ));
    }

    #[test]
    fn asymmetric_directional_maps_do_not_transpose_or_invent_streams() {
        let (mut local, mut peer) = pair(Band::Ghz5, 12, false);
        local.he.as_mut().unwrap().mcs_160 = Some(McsMaps {
            rx: 0xfffa,
            tx: 0xfffc,
        });
        peer.he.as_mut().unwrap().mcs_160 = Some(McsMaps {
            rx: 0xfffa,
            tx: 0xfffe,
        });
        let n = Negotiated::between(&local, &peer, Mode::He, Width::Mhz160).unwrap();
        let map = n.he.unwrap().mcs_160.unwrap();
        assert_eq!(
            map,
            McsMaps {
                rx: 0xfffc,
                tx: 0xfffe
            }
        );
        assert_eq!((n.tx_nss, n.rx_nss), (1, 1));
        local.eht.as_mut().unwrap().mcs.bw160 = Some([0x21, 0x21, 0]);
        peer.eht.as_mut().unwrap().mcs.bw160 = Some([0x12, 0x12, 0]);
        let n = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).unwrap();
        assert_eq!(n.eht.unwrap().ranges, [0x12, 0x12, 0x12, 0]);
        assert_eq!((n.tx_nss, n.rx_nss), (2, 1));
    }

    #[test]
    fn ht_asymmetric_stbc_stream_limits_and_mcs32_width_have_actual_effect() {
        let (mut local, mut peer) = pair(Band::Ghz5, 12, false);
        local.ht.as_mut().unwrap().capability &= !0x380;
        local.ht.as_mut().unwrap().tx_params = 3; // Explicit one TX stream.
        let n = Negotiated::between(&local, &peer, Mode::Ht, Width::Mhz40).unwrap();
        let h = n.ht.as_ref().unwrap();
        assert_eq!(h.capability & 0x380, 0);
        assert_eq!(h.peer_rx_mcs[1], 0);
        assert_eq!((n.tx_nss, n.rx_nss), (1, 2));
        assert_eq!(n.peer().ht().unwrap().capability & 0x380, 0x180);
        for cap in [&mut local, &mut peer] {
            cap.ht.as_mut().unwrap().rx_mcs.fill(0);
            cap.ht.as_mut().unwrap().rx_mcs[4] = 1;
        }
        assert!(Negotiated::between(&local, &peer, Mode::Ht, Width::Mhz20).is_err());
        assert_eq!(
            Negotiated::between(&local, &peer, Mode::Ht, Width::Mhz40)
                .unwrap()
                .tx_nss,
            1
        );
        local.ht.as_mut().unwrap().tx_params = 0;
        assert!(Negotiated::between(&local, &peer, Mode::Ht, Width::Mhz40).is_err());
    }

    #[test]
    fn selected_vht_width_matches_final_source_intersection_without_limiting_he_eht() {
        for (own_width, peer_width, expected_160) in
            [(4, 8, false), (8, 4, true), (4, 4, true), (8, 8, true)]
        {
            let (mut local, mut peer) = pair(Band::Ghz5, 12, false);
            local.vht.as_mut().unwrap().capability =
                (local.vht().unwrap().capability & !0xc) | own_width;
            peer.vht.as_mut().unwrap().capability =
                (peer.vht().unwrap().capability & !0xc) | peer_width;
            assert_eq!(
                Negotiated::between(&local, &peer, Mode::Vht, Width::Mhz160).is_ok(),
                expected_160
            );
            assert_eq!(
                Negotiated::between(&local, &peer, Mode::Vht, Width::Mhz80P80).is_ok(),
                own_width == 8 && peer_width == 8
            );
            assert!(Negotiated::between(&local, &peer, Mode::Vht, Width::Mhz80).is_ok());
            // A lower-family VHT restriction cannot disable actual HE/EHT160.
            assert!(Negotiated::between(&local, &peer, Mode::He, Width::Mhz160).is_ok());
            assert!(Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).is_ok());
        }
    }

    #[test]
    fn base_af_scalar_never_claims_he_eht_extensions_while_raw_effects_are_preserved() {
        let (local, mut peer) = pair(Band::Ghz5, 12, false);
        let before = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).unwrap();
        peer.he.as_mut().unwrap().mac[3] |= 0x18;
        peer.eht.as_mut().unwrap().mac[1] |= 1;
        let after = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).unwrap();
        assert_eq!(
            after.peer_ampdu_base_exponent,
            before.peer_ampdu_base_exponent
        );
        assert_eq!(after.peer_ampdu_base_exponent, 3);
        assert_eq!(after.peer().he().unwrap().mac[3] & 0x18, 0x18);
        assert_eq!(after.he.as_ref().unwrap().mac[3] & 0x18, 0x18);
        assert_eq!(after.peer().eht().unwrap().mac[1] & 1, 1);
    }

    #[test]
    fn capability_sizing_and_duplicates_never_accept_partial_fields() {
        for band in [Band::Ghz2, Band::Ghz5, Band::Ghz6] {
            let bits = if band == Band::Ghz2 { 2 } else { 12 };
            let bytes = modern_ies(band, Role::AccessPoint, bits, band == Band::Ghz6);
            for end in 1..bytes.len() {
                // A truncation inside an IE must refuse; complete earlier IE sets
                // may be valid observations and do not imply modern negotiation.
                let prefix = &bytes[..end];
                let mut pos = 0;
                while pos + 2 <= prefix.len()
                    && pos + 2 + usize::from(prefix[pos + 1]) <= prefix.len()
                {
                    pos += 2 + usize::from(prefix[pos + 1]);
                }
                if pos != prefix.len() {
                    assert!(Capabilities::parse(band, Role::AccessPoint, prefix).is_err());
                }
            }
            let mut duplicate = bytes;
            extension(&mut duplicate, 35, &he(bits));
            assert!(matches!(
                Capabilities::parse(band, Role::AccessPoint, &duplicate),
                Err(Error::Invalid(_))
            ));
        }
        for length in 0..26 {
            assert!(caps::Ht::parse(&ht()[..length]).is_err());
        }
        for length in 0..12 {
            assert!(caps::Vht::parse(&vht()[..length]).is_err());
        }
    }

    #[test]
    fn deferred_eht_layout_uses_actual_he_and_role_not_ie_order() {
        let h = he(0);
        let e_sta = eht(0, Role::Station, false);
        let e_ap = eht(0, Role::AccessPoint, false);
        let mut bytes = vec![1, 1, 12];
        extension(&mut bytes, 108, &e_sta);
        extension(&mut bytes, 35, &h);
        let parsed = Capabilities::parse(Band::Ghz5, Role::Station, &bytes).unwrap();
        assert!(parsed.eht().unwrap().mcs.only_20.is_some());
        assert!(parsed.eht().unwrap().mcs.bw80.is_none());
        assert!(caps::Eht::parse(&e_sta, parsed.he().unwrap(), Role::AccessPoint).is_err());
        assert!(caps::Eht::parse(&e_ap, parsed.he().unwrap(), Role::Station).is_err());
        assert!(Capabilities::parse(Band::Ghz6, Role::Station, &bytes).is_err());
    }

    #[test]
    fn ppe_presence_length_and_nss_are_checked_before_any_slice_use() {
        for header in 0..=255_u8 {
            let mut bytes = he(12);
            bytes[12] |= 0x80;
            let size = caps::he_ppe_len(header);
            bytes.resize(bytes.len() + size, 0);
            let offset = bytes.len() - size;
            bytes[offset] = header;
            assert_eq!(caps::He::parse(&bytes).unwrap().ppe.len(), size);
            assert!(caps::He::parse(&bytes[..bytes.len() - 1]).is_err());
        }
        for header in 0..512_u16 {
            let h = caps::He::parse(&he(12)).unwrap();
            let mut bytes = eht(12, Role::AccessPoint, false);
            bytes[7] |= 8;
            let size = caps::eht_ppe_len(header);
            let offset = bytes.len();
            bytes.resize(offset + size, 0);
            bytes[offset..offset + 2].copy_from_slice(&header.to_le_bytes());
            if header & 15 < 8 {
                assert_eq!(
                    caps::Eht::parse(&bytes, &h, Role::AccessPoint)
                        .unwrap()
                        .ppe
                        .len(),
                    size
                );
                assert!(
                    caps::Eht::parse(&bytes[..bytes.len() - 1], &h, Role::AccessPoint).is_err()
                );
            } else {
                assert!(caps::Eht::parse(&bytes, &h, Role::AccessPoint).is_err());
            }
        }
    }

    #[test]
    fn malformed_wmm_no_defaults_duplicate_aci_and_mlo_are_explicit() {
        let mut bytes = wmm(Role::AccessPoint);
        bytes[12] = bytes[8];
        assert!(Wmm::parse(&bytes, Role::AccessPoint).is_err());
        bytes = wmm(Role::AccessPoint);
        bytes[9] = 0x23;
        assert!(Wmm::parse(&bytes, Role::AccessPoint).is_err());
        bytes = modern_ies(Band::Ghz5, Role::Station, 12, false);
        extension(&mut bytes, 107, &[]);
        assert!(matches!(
            Capabilities::parse(Band::Ghz5, Role::Station, &bytes),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn unchanged_linux_directional_mcs_and_sizing_helpers_match_complete_oracle() {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        for nss in 0..8 {
            for own_rx in 0..4 {
                for own_tx in 0..4 {
                    for peer_rx in 0..4 {
                        for peer_tx in 0..4 {
                            let shift = nss * 2;
                            let mask = !(3_u16 << shift);
                            let own = McsMaps {
                                rx: mask | own_rx << shift,
                                tx: mask | own_tx << shift,
                            };
                            let peer = McsMaps {
                                rx: mask | peer_rx << shift,
                                tx: mask | peer_tx << shift,
                            };
                            let result = McsMaps::intersect(own, peer);
                            hash.update(result.rx.to_le_bytes());
                            hash.update(result.tx.to_le_bytes());
                        }
                    }
                }
            }
        }
        for enabled in [false, true] {
            for header in 0..=255_u8 {
                hash.update([if enabled {
                    caps::he_ppe_len(header) as u8
                } else {
                    0
                }]);
            }
        }
        for enabled in [false, true] {
            for header in 0..512_u16 {
                hash.update([if enabled {
                    caps::eht_ppe_len(header) as u8
                } else {
                    0
                }]);
            }
        }
        for phy0 in 0..=255_u8 {
            let h = caps::He::parse(&he(phy0)).unwrap();
            for width320 in [false, true] {
                for role in [Role::Station, Role::AccessPoint] {
                    let mut accepted = None;
                    for count in [3, 4, 6, 9] {
                        let mut bytes = vec![0; 11 + count];
                        bytes[2] = if width320 { 2 } else { 0 };
                        if caps::Eht::parse(&bytes, &h, role).is_ok() {
                            assert!(accepted.replace(count).is_none());
                        }
                    }
                    hash.update([accepted.unwrap() as u8]);
                }
            }
        }
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "b65d15db624c62db45cb60b3c2d1b426a1cbb7e496e0af8d76b1a6c88c37e26c"
        );
    }

    #[test]
    fn full_eht_maps_keep_each_width_direction_and_source_union_distinct() {
        let (mut local, mut peer) = pair(Band::Ghz6, 12, true);
        let own = [0x12, 0x34, 0x56, 0x23, 0x45, 0x67, 0x34, 0x56, 0x78];
        let ap = [0x87, 0x65, 0x43, 0x76, 0x54, 0x32, 0x65, 0x43, 0x21];
        for (cap, raw, role) in [
            (&mut local, own, Role::Station),
            (&mut peer, ap, Role::AccessPoint),
        ] {
            let mut bytes = eht(12, role, true);
            bytes[11..20].copy_from_slice(&raw);
            cap.eht = Some(Eht::parse(&bytes, cap.he().unwrap(), role).unwrap());
        }
        let n = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).unwrap();
        let map = n.eht.unwrap();
        assert_eq!(map.peer_source_mcs_union.bytes(), &ap);
        assert_eq!(map.peer_source_mcs_union.wire_len(), 9);
        assert_eq!(map.common.bw20, Some([0x21, 0x21, 0x43, 0x43]));
        assert_eq!(map.common.bw80, map.common.bw20);
        assert_eq!(map.common.bw160, Some([0x32, 0x32, 0x54, 0x32]));
        assert_eq!(map.common.bw320, Some([0x43, 0x43, 0x43, 0x21]));
        assert_eq!(map.ranges, map.common.bw160.unwrap());
        assert_ne!(&map.ranges[..3], &map.peer_source_mcs_union.bytes()[..3]);
    }

    #[test]
    fn twenty_only_sta_four_groups_do_not_shift_the_ap_three_group_source_overlay() {
        let (mut local, mut peer) = pair(Band::Ghz5, 0, false);
        let mut own = eht(0, Role::Station, false);
        own[11..].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        local.eht = Some(Eht::parse(&own, local.he().unwrap(), Role::Station).unwrap());
        let mut ap = eht(0, Role::AccessPoint, false);
        ap[11..].copy_from_slice(&[0x87, 0x65, 0x43]);
        peer.eht = Some(Eht::parse(&ap, peer.he().unwrap(), Role::AccessPoint).unwrap());
        let n = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz20).unwrap();
        let map = n.eht.unwrap();
        assert_eq!(map.ranges, [0x21, 0x43, 0x65, 0x43]);
        assert_eq!(map.common.bw20, Some(map.ranges));
        assert_eq!(map.common.bw80, None);
        assert_eq!(map.common.bw160, None);
        assert_eq!(map.common.bw320, None);
        assert_eq!(
            local.eht().unwrap().source_mcs_union().bytes(),
            &[0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0]
        );
        assert_eq!(local.eht().unwrap().source_mcs_union().wire_len(), 4);
        assert_eq!(
            map.peer_source_mcs_union.bytes(),
            &[0x87, 0x65, 0x43, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(map.peer_source_mcs_union.wire_len(), 3);
    }

    #[test]
    fn complete_unchanged_linux_eht_station_union_oracle() {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        let mut cases = 0;
        for phy0 in 0..=255 {
            for wide320 in [false, true] {
                for role in [Role::Station, Role::AccessPoint] {
                    let he = He::parse(&he(phy0)).unwrap();
                    let mut bytes = eht(phy0, role, wide320);
                    for (i, octet) in bytes[11..].iter_mut().enumerate() {
                        *octet = 0x11 * (1 + i as u8 % 8);
                    }
                    for available in [false, true] {
                        for extra in [-1_i32, 0, 1] {
                            cases += 1;
                            if !available || extra < 0 {
                                hash.update([0; 10]);
                            } else {
                                let parsed = Eht::parse(&bytes, &he, role).unwrap();
                                hash.update([1]);
                                hash.update(parsed.source_mcs_union().bytes());
                                assert_eq!(parsed.source_mcs_union().wire_len(), bytes.len() - 11);
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 6144);
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "f1aa36b6d5c91454e1be078fdf8a7557367687f48448b669742387785110f5aa"
        );
    }

    #[test]
    fn basic_eht_twenty_only_mapping_and_unsupported_width_skip_use_actual_local_union() {
        let mut local = pair(Band::Ghz5, 0, false).0;
        let mut bytes = eht(0, Role::Station, false);
        bytes[11..].copy_from_slice(&[0x12, 0x23, 0x34, 0x45]);
        local.eht = Some(Eht::parse(&bytes, local.he().unwrap(), Role::Station).unwrap());
        assert!(local.meets_eht_basic([0x12, 0x23, 0x34, 0x45]));
        assert!(!local.meets_eht_basic([0x13, 0x23, 0x34, 0x45]));
        assert!(!local.meets_eht_basic([0x12, 0x33, 0x34, 0x45]));
        let local = pair(Band::Ghz5, 4, false).0;
        assert_eq!(
            &local.eht().unwrap().source_mcs_union().bytes()[3..],
            &[0; 6]
        );
        assert!(local.meets_eht_basic([0x22, 0x22, 0x22, 0x11])); //Absent widths are0xff, not required zero-NSS maps.
        let no_eht =
            Capabilities::parse(Band::Ghz5, Role::Station, &[1, 3, 0x8c, 0x98, 0xb0]).unwrap();
        assert!(!no_eht.meets_eht_basic([0; 4]));
    }

    #[test]
    fn ap_multi_link_is_bounded_opaque_observation_not_requested_local_capability() {
        let (local, peer) = pair(Band::Ghz5, 12, false);
        let baseline = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).unwrap();
        // Basic common info carries an MLD MAC different from any selected BSSID.
        for body in [
            &[0, 0, 7, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee][..],
            &[][..],
            &[0][..],
            &[0, 0, 255][..],
            &[7, 0][..],
            &[0x10, 0, 8, 2, 1, 2, 3, 4, 5, 0][..],
        ] {
            let mut ap = modern_ies(Band::Ghz5, Role::AccessPoint, 12, false);
            let mut raw = Vec::new();
            extension(&mut raw, 107, body);
            ap.extend_from_slice(&raw);
            let observed = Capabilities::parse(Band::Ghz5, Role::AccessPoint, &ap).unwrap();
            assert_eq!(observed.unselected_multi_link_elements(), raw);
            let n = Negotiated::between(&local, &observed, Mode::Eht, Width::Mhz160).unwrap();
            assert_eq!(n.ht, baseline.ht);
            assert_eq!(n.vht, baseline.vht);
            assert_eq!(n.he, baseline.he);
            assert_eq!(n.eht, baseline.eht);
            assert_eq!(n.wmm, baseline.wmm);
            assert_eq!(
                (n.mode, n.width, n.rx_nss, n.tx_nss),
                (
                    baseline.mode,
                    baseline.width,
                    baseline.rx_nss,
                    baseline.tx_nss
                )
            );
            let mut sta = modern_ies(Band::Ghz5, Role::Station, 12, false);
            sta.extend_from_slice(&raw);
            assert!(matches!(
                Capabilities::parse(Band::Ghz5, Role::Station, &sta),
                Err(Error::Unsupported(_))
            ));
        }
    }
    #[test]
    fn opaque_multi_link_fragments_cannot_inherit_other_link_ie_fields() {
        let mut ap = modern_ies(Band::Ghz5, Role::AccessPoint, 12, false);
        let mut body = vec![0; 254];
        body[..9].copy_from_slice(&[0, 0, 7, 2, 1, 2, 3, 4, 5]);
        let mut raw = Vec::new();
        extension(&mut raw, 107, &body);
        // A profile/fragment containing IE-looking channel/rate bytes remains raw.
        ie(&mut raw, 242, &[61, 2, 149, 3, 1, 1, 0xff]);
        ap.extend_from_slice(&raw);
        let cap = Capabilities::parse(Band::Ghz5, Role::AccessPoint, &ap).unwrap();
        assert_eq!(cap.unselected_multi_link_elements(), raw);
        assert_eq!(cap.rates().supported, 0xff);
        let mut truncated = ap.clone();
        truncated.pop();
        assert!(Capabilities::parse(Band::Ghz5, Role::AccessPoint, &truncated).is_err());
        ap.extend_from_slice(&[255, 0]);
        assert!(Capabilities::parse(Band::Ghz5, Role::AccessPoint, &ap).is_err());
        let mut too_long = modern_ies(Band::Ghz5, Role::AccessPoint, 12, false);
        while too_long.len() <= 2300 {
            too_long.extend_from_slice(&raw);
        }
        assert!(Capabilities::parse(Band::Ghz5, Role::AccessPoint, &too_long).is_err());
    }

    #[test]
    fn complete_local_he_source_words_must_match_transmitted_maps_without_gaining_authority() {
        let (local, ap) = pair(Band::Ghz5, 12, false);
        let he = local.he().unwrap();
        let maps = [he.mcs_80, he.mcs_160.unwrap(), McsMaps { rx: 0, tx: 0 }];
        let complete = local.clone().with_local_he_source_maps(maps).unwrap();
        assert_eq!(complete.local_he_source_maps(), Some(&maps));
        assert!(complete.matches_wire_capabilities(&local));
        let two = pair(Band::Ghz2, 2, false).0;
        assert_eq!(two.he().unwrap().mcs_160, None);
        let m = two.he().unwrap().mcs_80;
        let two = two
            .with_local_he_source_maps([m, m, McsMaps { rx: 0, tx: 0 }])
            .unwrap();
        assert_eq!(two.local_he_source_maps().unwrap()[1], m);
        assert_eq!(two.he().unwrap().mcs_160, None);
        assert!(ap.with_local_he_source_maps(maps).is_err());
        for slot in 0..2 {
            let mut wrong = maps;
            wrong[slot].rx ^= 1;
            assert!(local.clone().with_local_he_source_maps(wrong).is_err());
        }
        let no_he =
            Capabilities::parse(Band::Ghz5, Role::Station, &[1, 3, 0x8c, 0x98, 0xb0]).unwrap();
        assert!(no_he.clone().with_local_he_source_maps(maps).is_err());
        assert!(no_he.meets_local_he_basic(0).is_err());
    }
}
