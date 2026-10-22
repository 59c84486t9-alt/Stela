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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    fn parse(bytes: &[u8], role: Role) -> Result<Self, Error> {
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
        let mut rest = bytes;
        while !rest.is_empty() {
            let header = rest.get(..2).ok_or(Error::Truncated)?;
            let data = rest
                .get(2..2 + usize::from(header[1]))
                .ok_or(Error::Truncated)?;
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
                    Some(107) => return Err(Error::Unsupported("multi-link capability")),
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
        })
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
mod tests;
