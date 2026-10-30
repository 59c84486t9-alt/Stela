// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2021-2026 Intel Corporation
//! Raw UEFI power/coexistence observations, not selected BIOS permission,
//! approved platform policy, submitted firmware tables or transmit permission.
use super::{Error, bounded, prefix};
use crate::bytes::le32;
fn exact(raw: &[u8], expected: usize) -> Result<(), Error> {
    if raw.len() != expected {
        return Err(Error::ExactSize {
            expected,
            actual: raw.len(),
        });
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SarKind {
    Wrds,
    Ewrd,
}
#[derive(Clone, Copy, Debug)]
pub struct Sar<'a> {
    kind: SarKind,
    raw: &'a [u8],
    subbands: usize,
    profiles: u8,
}
impl<'a> Sar<'a> {
    pub fn parse(kind: SarKind, raw: &'a [u8]) -> Result<Self, Error> {
        let extended = kind == SarKind::Ewrd;
        bounded(raw, if extended { 141 } else { 49 })?;
        let subbands = match raw[0] {
            2 => 11,
            3 => 12,
            revision => return Err(Error::Revision(revision)),
        };
        let offset = if extended { 9 } else { 5 };
        let capacity = if extended { 3 } else { 1 };
        exact(raw, offset + capacity * 4 * subbands)?;
        let profiles = if extended { le32(raw, 5) } else { 1 };
        if profiles > 3 {
            return Err(Error::ProfileCount {
                minimum: 0,
                maximum: 3,
                actual: profiles,
            });
        }
        Ok(Self {
            kind,
            raw,
            subbands,
            profiles: profiles as u8,
        })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn kind(self) -> SarKind {
        self.kind
    }
    pub fn subbands(self) -> usize {
        self.subbands
    }
    pub fn declared_profiles(self) -> u8 {
        self.profiles
    }
    pub fn raw_mode(self) -> u32 {
        le32(self.raw, 1)
    }
    /// Source C call converts mode to the bool parameter of
    /// iwl_uefi_set_sar_profile before applying its enable mask. Preserve mode
    /// separately; this observation is not a SAR programming receipt.
    pub fn source_enabled(self) -> bool {
        self.raw_mode() != 0
    }
    /// Source official profiles are WRDS profile 1 and EWRD profiles 2..4. Unused full-capacity
    /// slots remain in raw(), without becoming declared profiles or zero data.
    pub fn value(self, profile: u8, chain: usize, subband: usize) -> Option<u8> {
        let index = match self.kind {
            SarKind::Wrds if profile == 1 => 0,
            SarKind::Ewrd if (2..=4).contains(&profile) => usize::from(profile - 2),
            _ => return None,
        };
        if index >= usize::from(self.profiles) || chain >= 4 || subband >= self.subbands {
            return None;
        }
        let offset = if self.kind == SarKind::Ewrd { 9 } else { 5 };
        Some(self.raw[offset + (index * 4 + chain) * self.subbands + subband])
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoBand {
    pub maximum: u8,
    pub chain_offsets: [u8; 2],
}
#[derive(Clone, Copy, Debug)]
pub struct Geo<'a> {
    raw: &'a [u8],
    bands: usize,
}
impl<'a> Geo<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        bounded(raw, 74)?;
        let bands = match raw[0] {
            3 => 3,
            4 => 4,
            revision => return Err(Error::Revision(revision)),
        };
        exact(raw, 2 + 8 * bands * 3)?;
        if !(3..=8).contains(&raw[1]) {
            return Err(Error::ProfileCount {
                minimum: 3,
                maximum: 8,
                actual: u32::from(raw[1]),
            });
        }
        Ok(Self { raw, bands })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn bands(self) -> usize {
        self.bands
    }
    pub fn declared_profiles(self) -> u8 {
        self.raw[1]
    }
    /// Zero-based source array index, distinct from SGOM's raw nibble values.
    pub fn band(self, profile_index: usize, band: usize) -> Option<GeoBand> {
        if profile_index >= usize::from(self.declared_profiles()) || band >= self.bands {
            return None;
        }
        let at = 2 + (profile_index * self.bands + band) * 3;
        Some(GeoBand {
            maximum: self.raw[at],
            chain_offsets: [self.raw[at + 1], self.raw[at + 2]],
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Ppag<'a> {
    raw: &'a [u8],
    subbands: usize,
}
impl<'a> Ppag<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        bounded(raw, 27)?;
        // The getter attempts the 29-byte shape first; a longer revision 1..4
        // table is not reinterpreted through the shorter fallback branch.
        let subbands = if raw.len() >= 29 {
            if raw[0] != 5 {
                return Err(Error::Revision(raw[0]));
            }
            12
        } else {
            if !(1..=4).contains(&raw[0]) {
                return Err(Error::Revision(raw[0]));
            }
            11
        };
        Ok(Self { raw, subbands })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn subbands(self) -> usize {
        self.subbands
    }
    pub fn raw_modes(self) -> u32 {
        le32(self.raw, 1)
    }
    pub fn source_flags(self) -> u32 {
        match self.raw[0] {
            1 | 2 => self.raw_modes() & 3,
            3 => self.raw_modes() & 0x7ff,
            _ => self.raw_modes(),
        }
    }
    /// Raw signed source gain. Validation for command version and
    /// approved platform identity belongs to the later consumer.
    pub fn gain(self, chain: usize, subband: usize) -> Option<i8> {
        if chain >= 2 || subband >= self.subbands {
            return None;
        }
        Some(self.raw[5 + chain * self.subbands + subband] as i8)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TasSelection {
    pub override_iec: bool,
    pub enable_iec: bool,
    pub usa_uhb: bool,
    pub canada_uhb: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct Tas<'a> {
    raw: &'a [u8],
}
impl<'a> Tas<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        bounded(raw, 38)?;
        if !(1..=2).contains(&raw[0]) {
            return Err(Error::Revision(raw[0]));
        }
        if raw[5] > 16 {
            return Err(Error::ProfileCount {
                minimum: 0,
                maximum: 16,
                actual: u32::from(raw[5]),
            });
        }
        Ok(Self { raw })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn raw_selection(self) -> u32 {
        le32(self.raw, 1)
    }
    pub fn source_enabled(self) -> bool {
        self.raw_selection() & 1 != 0
    }
    pub fn selection(self) -> TasSelection {
        let v = self.raw_selection();
        TasSelection {
            override_iec: v & (1 << 1) != 0,
            enable_iec: v & (1 << 2) != 0,
            usa_uhb: v & (1 << 16) != 0,
            canada_uhb: self.raw[0] > 1 && v & (1 << 15) != 0,
        }
    }
    pub fn declared_countries(self) -> u8 {
        self.raw[5]
    }
    pub fn country(self, index: usize) -> Option<u16> {
        if index >= usize::from(self.declared_countries()) {
            return None;
        }
        let at = 6 + index * 2;
        Some(u16::from_le_bytes([self.raw[at], self.raw[at + 1]]))
    }
}
#[derive(Clone, Copy, Debug)]
pub struct CountryMap<'a> {
    raw: &'a [u8],
}
impl<'a> CountryMap<'a> {
    /// SGOM and UATS share this packed revision 1 prefix, while their
    /// consumers and prerequisites remain separate.
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        prefix(raw, 339, 1)?;
        Ok(Self { raw })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn raw_map(self) -> &'a [u8] {
        &self.raw[1..339]
    }
    /// Source SGOM nibble clamp. The input count is pure data here;
    /// geo-SAR initialization and enabled state must be separately held.
    pub fn sgom(self, geo_profiles: u8) -> Result<[u8; 338], Error> {
        if geo_profiles > 8 {
            return Err(Error::ProfileCount {
                minimum: 0,
                maximum: 8,
                actual: u32::from(geo_profiles),
            });
        }
        Ok(core::array::from_fn(|i| {
            let v = self.raw_map()[i];
            let high = v >> 4;
            let low = v & 15;
            (if high > geo_profiles { 0 } else { high } << 4)
                | if low > geo_profiles { 0 } else { low }
        }))
    }
}

#[cfg(test)]
mod tests;
