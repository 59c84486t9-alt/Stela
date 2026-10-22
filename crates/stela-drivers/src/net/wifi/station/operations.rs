// SPDX-License-Identifier: GPL-2.0-only
// Adapted from pinned Linux mac80211/util.c, wireless/chan.c and IEEE headers.
// Copyright 2009 Johannes Berg; 2013-2014 Intel Mobile Communications GmbH;
// 2018-2026 Intel Corporation. Full source notices in THIRD_PARTY.md.
//! Actual single-link BSS operation observations, never radio/TX authority.

use super::phy::{Error, Mode, Negotiated, Width};
use crate::net::wifi::{Band, Channel};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtOperation {
    pub primary: u8,
    pub parameter: u8,
    pub protection: u16,
    pub stbc: u16,
    pub basic_mcs: [u8; 16],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VhtOperation {
    pub width: u8,
    pub center0: u8,
    pub center1: u8,
    pub basic_mcs: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeOperation {
    pub parameters: u32,
    pub basic_mcs: u16,
    pub vht: Option<[u8; 3]>,
    pub cohosted_bssid: Option<u8>,
    pub six_ghz: Option<[u8; 5]>,
}
impl HeOperation {
    /// Actual encoded value; vendor source transformations remain explicit.
    pub fn packet_extension(&self) -> u8 {
        (self.parameters & 7) as u8
    }
    pub fn rts_threshold(&self) -> u16 {
        ((self.parameters >> 4) & 0x3ff) as u16
    }
    pub fn color(&self) -> u8 {
        ((self.parameters >> 24) & 0x3f) as u8
    }
    pub fn color_enabled(&self) -> bool {
        self.parameters & 0x8000_0000 == 0
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EhtOperation {
    pub parameters: u8,
    pub basic_mcs: [u8; 4],
    pub information: Option<[u8; 3]>,
    pub punctured: u16,
}

/// Source-valid geometry only. Regulatory/provider authority, actual NIC
/// support and applied per-rate power remain independently required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelDefinition {
    pub control: Channel,
    pub width: Width,
    pub center1_mhz: u32,
    pub center2_mhz: Option<u32>,
    pub punctured: u16,
}

fn mhz(width: Width) -> u32 {
    match width {
        Width::Mhz20 => 20,
        Width::Mhz40 => 40,
        Width::Mhz80 | Width::Mhz80P80 => 80,
        Width::Mhz160 => 160,
        Width::Mhz320 => 320,
    }
}

fn frequency(band: Band, channel: u8) -> Result<u32, Error> {
    let n = u32::from(channel);
    match band {
        Band::Ghz2 if (1..=13).contains(&n) => Ok(2407 + 5 * n),
        Band::Ghz2 if n == 14 => Ok(2484),
        Band::Ghz5 if n > 0 => Ok(if (182..=196).contains(&n) {
            4000 + 5 * n
        } else {
            5000 + 5 * n
        }),
        Band::Ghz6 if n == 2 => Ok(5935),
        Band::Ghz6 if (1..=233).contains(&n) => Ok(5950 + 5 * n),
        _ => Err(Error::Invalid("operating channel number")),
    }
}

fn center_valid(center: u32, width: Width) -> bool {
    if !(5955..=7215).contains(&center) {
        return true;
    }
    let bw = mhz(width);
    let step = if bw == 320 { 160 } else { bw };
    center >= 5945 + bw / 2
        && center + bw / 2 <= 7225
        && (center - bw / 2 - 5945).is_multiple_of(step)
}
fn puncture_valid(def: &ChannelDefinition) -> bool {
    let values: &[u16] = match def.width {
        Width::Mhz80 => &[8, 4, 2, 1],
        Width::Mhz160 => &[0x80, 0x40, 0x20, 0x10, 8, 4, 2, 1, 0xc0, 0x30, 0xc, 3],
        Width::Mhz320 => &[
            0xc000, 0x3000, 0xc00, 0x300, 0xc0, 0x30, 0xc, 3, 0xf000, 0xf00, 0xf0, 0xf, 0xfc00,
            0xf300, 0xf0c0, 0xf030, 0xf00c, 0xf003, 0xc00f, 0x300f, 0xc0f, 0x30f, 0xcf, 0x3f,
        ],
        _ => return def.punctured == 0,
    };
    if def.punctured == 0 {
        return true;
    }
    let start = def.center1_mhz - mhz(def.width) / 2;
    let primary = (u32::from(def.control.frequency_mhz) - start) / 20;
    def.punctured & (1 << primary) == 0 && values.contains(&def.punctured)
}
impl ChannelDefinition {
    pub fn validate(&self) -> Result<(), Error> {
        let number =
            u8::try_from(self.control.number).map_err(|_| Error::Invalid("control channel"))?;
        if frequency(self.control.band, number)? != u32::from(self.control.frequency_mhz) {
            return Err(Error::Invalid("control frequency alias"));
        }
        let bw = mhz(self.width);
        let distance = self
            .center1_mhz
            .abs_diff(u32::from(self.control.frequency_mhz));
        let control_valid = if self.width == Width::Mhz20 {
            distance == 0
        } else {
            distance >= 10 && distance <= bw / 2 - 10 && distance % 20 == 10
        };
        let second = match (self.width, self.center2_mhz) {
            (Width::Mhz80P80, Some(center)) => {
                center > 0
                    && center.abs_diff(self.center1_mhz) > 80
                    && center_valid(center, self.width)
            }
            (Width::Mhz80P80, None) => false,
            (_, None) => true,
            _ => false,
        };
        if !control_valid
            || !second
            || !center_valid(self.center1_mhz, self.width)
            || self.center1_mhz == 2484
            || (self.width == Width::Mhz320 && self.control.band != Band::Ghz6)
            || (self.control.band == Band::Ghz2 && bw > 40)
            || !puncture_valid(self)
        {
            return Err(Error::Invalid("operating channel geometry/puncture"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operations {
    pub ht: Option<HtOperation>,
    pub vht: Option<VhtOperation>,
    pub he: Option<HeOperation>,
    pub eht: Option<EhtOperation>,
}
fn word(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().unwrap())
}
fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), Error> {
    if slot.replace(value).is_some() {
        return Err(Error::Invalid("duplicate operation IE"));
    }
    Ok(())
}
fn exact(bytes: &[u8], n: usize) -> Result<&[u8], Error> {
    if bytes.len() < n {
        Err(Error::Truncated)
    } else if bytes.len() > n {
        Err(Error::Unsupported("trailing operation effects"))
    } else {
        Ok(bytes)
    }
}
impl Operations {
    pub fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        let mut out = Self {
            ht: None,
            vht: None,
            he: None,
            eht: None,
        };
        while !bytes.is_empty() {
            let h = bytes.get(..2).ok_or(Error::Truncated)?;
            let data = bytes
                .get(2..2 + usize::from(h[1]))
                .ok_or(Error::Truncated)?;
            match h[0] {
                61 => {
                    let b = exact(data, 22)?;
                    once(
                        &mut out.ht,
                        HtOperation {
                            primary: b[0],
                            parameter: b[1],
                            protection: word(&b[2..4]),
                            stbc: word(&b[4..6]),
                            basic_mcs: b[6..].try_into().unwrap(),
                        },
                    )?;
                }
                192 => {
                    let b = exact(data, 5)?;
                    once(
                        &mut out.vht,
                        VhtOperation {
                            width: b[0],
                            center0: b[1],
                            center1: b[2],
                            basic_mcs: word(&b[3..5]),
                        },
                    )?;
                }
                255 => match data.first() {
                    Some(36) => once(&mut out.he, HeOperation::parse(&data[1..])?)?,
                    Some(106) => once(&mut out.eht, EhtOperation::parse(&data[1..])?)?,
                    Some(107) => return Err(Error::Unsupported("multi-link operation")),
                    None => return Err(Error::Truncated),
                    _ => (),
                },
                _ => (),
            }
            bytes = &bytes[2 + data.len()..];
        }
        Ok(out)
    }

    /// Derive the advertised operation without downshifting or inventing a
    /// center/width. Local selected capabilities must subsequently agree.
    pub fn channel_for(
        &self,
        control: Channel,
        negotiated: &Negotiated,
    ) -> Result<ChannelDefinition, Error> {
        let caps = negotiated
            .local()
            .vht()
            .zip(negotiated.peer().vht())
            .map(|(local, peer)| (local.capability, peer.capability));
        self.channel(control, negotiated.mode, caps)
    }

    fn channel(
        &self,
        control: Channel,
        mode: Mode,
        vht_caps: Option<(u32, u32)>,
    ) -> Result<ChannelDefinition, Error> {
        let mut def = ChannelDefinition {
            control,
            width: Width::Mhz20,
            center1_mhz: u32::from(control.frequency_mhz),
            center2_mhz: None,
            punctured: 0,
        };
        if control.band != Band::Ghz6 && mode != Mode::Legacy {
            let ht = self.ht.as_ref().ok_or(Error::Missing("HT operation"))?;
            if u16::from(ht.primary) != control.number {
                return Err(Error::Incompatible("HT primary channel"));
            }
            match ht.parameter & 3 {
                0 => (),
                1 => {
                    def.width = Width::Mhz40;
                    def.center1_mhz = u32::from(control.frequency_mhz) + 10;
                }
                3 => {
                    def.width = Width::Mhz40;
                    def.center1_mhz = u32::from(control.frequency_mhz)
                        .checked_sub(10)
                        .ok_or(Error::Invalid("HT center"))?;
                }
                _ => return Err(Error::Invalid("HT secondary offset")),
            }
            if control.band == Band::Ghz5 && matches!(mode, Mode::Vht | Mode::He | Mode::Eht) {
                let v = self.vht.as_ref().ok_or(Error::Missing("VHT operation"))?;
                let (own_cap, peer_cap) =
                    vht_caps.ok_or(Error::Missing("local/peer VHT operation capabilities"))?;
                if (own_cap | peer_cap) & 0xc000_0000 != 0 {
                    return Err(Error::Unsupported("VHT extended NSS operation"));
                }
                let ccf1 = if peer_cap & 0xc == 0 { 0 } else { v.center1 };
                let support_160 = own_cap & 0xc != 0 && peer_cap & 0xc != 0;
                let support_80p80 = own_cap & 0xc == 8 && peer_cap & 0xc != 0;
                match v.width {
                    0 => (),
                    1 => {
                        def.width = Width::Mhz80;
                        def.center1_mhz = frequency(control.band, v.center0)?;
                        if ccf1 != 0 {
                            let diff = v.center0.abs_diff(ccf1);
                            if diff == 8 && support_160 {
                                def.width = Width::Mhz160;
                                def.center1_mhz = frequency(control.band, ccf1)?;
                            } else if diff > 8 && support_80p80 {
                                def.width = Width::Mhz80P80;
                                def.center2_mhz = Some(frequency(control.band, ccf1)?);
                            }
                        }
                    }
                    2 => {
                        def.width = Width::Mhz160;
                        def.center1_mhz = frequency(control.band, v.center0)?;
                    }
                    3 => {
                        def.width = Width::Mhz80P80;
                        def.center1_mhz = frequency(control.band, v.center0)?;
                        def.center2_mhz = Some(frequency(control.band, ccf1)?);
                    }
                    _ => return Err(Error::Invalid("VHT operation width")),
                }
            }
        }
        if matches!(mode, Mode::He | Mode::Eht) {
            let he = self.he.as_ref().ok_or(Error::Missing("HE operation"))?;
            if control.band == Band::Ghz6 {
                let s = he.six_ghz.ok_or(Error::Missing("HE6 operation"))?;
                if u16::from(s[0]) != control.number {
                    return Err(Error::Incompatible("HE6 primary channel"));
                }
                def.width = match s[1] & 3 {
                    0 => Width::Mhz20,
                    1 => Width::Mhz40,
                    2 | 3 => Width::Mhz80,
                    _ => unreachable!(),
                };
                def.center1_mhz = frequency(control.band, s[2])?;
                def.center2_mhz = None;
                if s[1] & 3 == 3 && s[3] != 0 {
                    if s[2].abs_diff(s[3]) == 8 {
                        def.width = Width::Mhz160;
                        def.center1_mhz = frequency(control.band, s[3])?;
                    } else {
                        def.width = Width::Mhz80P80;
                        def.center2_mhz = Some(frequency(control.band, s[3])?);
                    }
                }
            } else if he.six_ghz.is_some() {
                return Err(Error::Invalid("HE6 operation outside 6GHz"));
            }
        }
        if mode == Mode::Eht {
            let e = self.eht.as_ref().ok_or(Error::Missing("EHT operation"))?;
            if let Some(info) = e.information {
                def.width = match info[0] & 7 {
                    0 => Width::Mhz20,
                    1 => Width::Mhz40,
                    2 => Width::Mhz80,
                    3 => Width::Mhz160,
                    4 => Width::Mhz320,
                    _ => return Err(Error::Invalid("EHT operation width")),
                };
                def.center1_mhz = frequency(
                    control.band,
                    if matches!(def.width, Width::Mhz160 | Width::Mhz320) {
                        info[2]
                    } else {
                        info[1]
                    },
                )?;
                def.center2_mhz = None;
            }
            def.punctured = e.punctured;
        }
        def.validate()?;
        Ok(def)
    }
}
impl HeOperation {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let b = bytes.get(..6).ok_or(Error::Truncated)?;
        let parameters = u32::from_le_bytes(b[..4].try_into().unwrap());
        if parameters & 0x00fc_0000 != 0 {
            return Err(Error::Unsupported("reserved HE operation parameters"));
        }
        let mut offset = 6;
        let mut part = |count| -> Result<&[u8], Error> {
            let p = bytes.get(offset..offset + count).ok_or(Error::Truncated)?;
            offset += count;
            Ok(p)
        };
        let vht = if parameters & 0x4000 != 0 {
            Some(part(3)?.try_into().unwrap())
        } else {
            None
        };
        let cohosted_bssid = if parameters & 0x8000 != 0 {
            Some(part(1)?[0])
        } else {
            None
        };
        let six_ghz = if parameters & 0x20000 != 0 {
            Some(part(5)?.try_into().unwrap())
        } else {
            None
        };
        exact(bytes, offset)?;
        Ok(Self {
            parameters,
            basic_mcs: word(&b[4..6]),
            vht,
            cohosted_bssid,
            six_ghz,
        })
    }
}
impl EhtOperation {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let b = bytes.get(..5).ok_or(Error::Truncated)?;
        let parameters = b[0];
        if parameters & 0x80 != 0 {
            return Err(Error::Unsupported("reserved EHT operation parameters"));
        }
        let mut n = 5;
        let information = if parameters & 1 != 0 {
            n += 3;
            Some(bytes.get(5..8).ok_or(Error::Truncated)?.try_into().unwrap())
        } else {
            None
        };
        let punctured = if parameters & 2 != 0 {
            if information.is_none() {
                return Err(Error::Invalid("puncture without EHT operation info"));
            }
            n += 2;
            word(bytes.get(8..10).ok_or(Error::Truncated)?)
        } else {
            0
        };
        exact(bytes, n)?;
        if b[1..5].iter().any(|v| v & 15 > 8 || v >> 4 > 8) {
            return Err(Error::Invalid("EHT basic NSS exceeds eight"));
        }
        Ok(Self {
            parameters,
            basic_mcs: b[1..5].try_into().unwrap(),
            information,
            punctured,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec, vec::Vec};
    fn ext(id: u8, b: &[u8]) -> Vec<u8> {
        let mut v = vec![255, (b.len() + 1) as u8, id];
        v.extend_from_slice(b);
        v
    }
    fn six(n: u16) -> Channel {
        Channel {
            band: Band::Ghz6,
            number: n,
            frequency_mhz: if n == 2 { 5935 } else { 5950 + n * 5 },
        }
    }
    #[test]
    fn six_ghz_he_and_eht_actual_center_puncture_and_raw_parameters() {
        let mut bytes = ext(36, &[3, 0x20, 2, 0x2a, 0xff, 0xff, 1, 3, 7, 15, 6]);
        bytes.extend_from_slice(&ext(106, &[3, 1, 1, 1, 1, 3, 7, 15, 0x80, 0]));
        let ops = Operations::parse(&bytes).unwrap();
        let def = ops.channel(six(1), Mode::Eht, None).unwrap();
        assert_eq!(
            (def.width, def.center1_mhz, def.punctured),
            (Width::Mhz160, 6025, 0x80)
        );
        assert_eq!(ops.he.as_ref().unwrap().six_ghz, Some([1, 3, 7, 15, 6]));
        assert_eq!(
            ops.channel(six(1), Mode::He, None).unwrap().center1_mhz,
            6025
        );
        assert!(ops.channel(six(5), Mode::Eht, None).is_err());
        let mut primary_punctured = bytes.clone();
        let n = primary_punctured.len();
        primary_punctured[n - 2] = 1;
        assert!(
            Operations::parse(&primary_punctured)
                .unwrap()
                .channel(six(1), Mode::Eht, None)
                .is_err()
        );
        let mut invalid = bytes;
        invalid.pop();
        assert!(Operations::parse(&invalid).is_err());
    }
    #[test]
    fn variable_operation_fields_require_complete_exact_nonduplicated_observations() {
        for mask in 0..8 {
            let params = ((mask & 1) << 14) | ((mask & 2) << 14) | ((mask & 4) << 15);
            let mut b = (params as u32).to_le_bytes().to_vec();
            b.extend_from_slice(&[0xff, 0xff]);
            if mask & 1 != 0 {
                b.extend_from_slice(&[1, 42, 0]);
            }
            if mask & 2 != 0 {
                b.push(0);
            }
            if mask & 4 != 0 {
                b.extend_from_slice(&[1, 2, 7, 0, 6]);
            }
            let bytes = ext(36, &b);
            let ops = Operations::parse(&bytes).unwrap();
            let he = ops.he.unwrap();
            assert_eq!(he.vht.is_some(), mask & 1 != 0);
            assert_eq!(he.cohosted_bssid.is_some(), mask & 2 != 0);
            assert_eq!(he.six_ghz.is_some(), mask & 4 != 0);
            for n in 0..bytes.len() {
                assert!(Operations::parse(&bytes[..n]).is_err() || n == 0);
            }
            let mut twice = bytes.clone();
            twice.extend_from_slice(&bytes);
            assert!(Operations::parse(&twice).is_err());
            let mut extra = b.clone();
            extra.push(0);
            assert!(Operations::parse(&ext(36, &extra)).is_err());
        }
        assert!(Operations::parse(&ext(106, &[2, 0, 0, 0, 0])).is_err());
        assert!(Operations::parse(&ext(106, &[1, 0, 0, 0, 0, 2, 42])).is_err());
        assert!(Operations::parse(&ext(106, &[0, 0x99, 0, 0, 0])).is_err());
    }
    #[test]
    fn source_geometry_and_puncture_stream_matches_full_linux_helper() {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        let mut cases = 0;
        let widths = [
            Width::Mhz20,
            Width::Mhz40,
            Width::Mhz80,
            Width::Mhz160,
            Width::Mhz80P80,
            Width::Mhz320,
        ];
        for width in widths {
            for n in 1..=233 {
                for c in 1..=233 {
                    let def = ChannelDefinition {
                        control: six(n),
                        width,
                        center1_mhz: 5950 + c * 5,
                        center2_mhz: if width == Width::Mhz80P80 {
                            Some(6755)
                        } else {
                            None
                        },
                        punctured: 0,
                    };
                    hash.update([u8::from(def.validate().is_ok())]);
                    cases += 1;
                }
            }
        }
        for width in [Width::Mhz80, Width::Mhz160, Width::Mhz320] {
            let bw = mhz(width);
            let center = 5945 + bw / 2;
            for n in 0..bw / 20 {
                for mask in 0..=u16::MAX {
                    let freq = center - bw / 2 + 10 + n * 20;
                    let channel = ((freq - 5950) / 5) as u16;
                    let def = ChannelDefinition {
                        control: six(channel),
                        width,
                        center1_mhz: center,
                        center2_mhz: None,
                        punctured: mask,
                    };
                    hash.update([u8::from(def.validate().is_ok())]);
                    cases += 1;
                }
            }
        }
        let control = Channel {
            band: Band::Ghz5,
            number: 36,
            frequency_mhz: 5180,
        };
        for own in [0, 4, 8] {
            for peer in [0, 4, 8] {
                for width in 0..4 {
                    for c0 in 0..178 {
                        for c1 in 0..178 {
                            let ops = Operations {
                                ht: Some(HtOperation {
                                    primary: 36,
                                    parameter: 5,
                                    protection: 0,
                                    stbc: 0,
                                    basic_mcs: [0; 16],
                                }),
                                vht: Some(VhtOperation {
                                    width,
                                    center0: c0,
                                    center1: c1,
                                    basic_mcs: 0xffff,
                                }),
                                he: None,
                                eht: None,
                            };
                            let mut record = [0; 6];
                            if let Ok(def) = ops.channel(control, Mode::Vht, Some((own, peer))) {
                                record[0] = 1;
                                record[1] = match def.width {
                                    Width::Mhz20 => 0,
                                    Width::Mhz40 => 1,
                                    Width::Mhz80 => 2,
                                    Width::Mhz160 => 3,
                                    Width::Mhz80P80 => 4,
                                    Width::Mhz320 => 5,
                                };
                                record[2..4]
                                    .copy_from_slice(&(def.center1_mhz as u16).to_le_bytes());
                                record[4..6].copy_from_slice(
                                    &(def.center2_mhz.unwrap_or(0) as u16).to_le_bytes(),
                                );
                            }
                            hash.update(record);
                            cases += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 3301366);
        assert_eq!(
            format!("{:x}", hash.finalize()),
            // Raw unchanged donor output has SHA1f5f5724... . The declared
            // native profile additionally refuses856 overlapping80+80 cases.
            "8fa34e65decb1e61aa4cef19fabf84aa0299a8b17c5236c3071bc96e5f3812c5"
        );
    }
    #[test]
    fn invalid_geometry_and_frequency_aliases_are_not_permissions() {
        let def = ChannelDefinition {
            control: six(1),
            width: Width::Mhz80,
            center1_mhz: 5985,
            center2_mhz: None,
            punctured: 0,
        };
        def.validate().unwrap();
        for invalid in [
            ChannelDefinition {
                control: Channel {
                    frequency_mhz: 5985,
                    ..six(1)
                },
                ..def
            },
            ChannelDefinition {
                center1_mhz: 5980,
                ..def
            },
            ChannelDefinition {
                center2_mhz: Some(6755),
                ..def
            },
            ChannelDefinition {
                punctured: 3,
                ..def
            },
            ChannelDefinition {
                punctured: 1,
                ..def
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }
}
