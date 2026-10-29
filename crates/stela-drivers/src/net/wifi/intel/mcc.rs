// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2005-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Source MCC command/response ABI. A decoded response is raw firmware
//! observation, not channel, power, scan or transmit permission.
use super::{command::Id, firmware::Firmware};
use alloc::vec::Vec;
pub mod channel;
const MAX_CHANNELS: usize = 115;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Country,
    MissingApi,
    Version(u8),
    Length,
    ChannelCount(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub country: [u8; 2],
    pub source: u8,
}
impl Request {
    /// Source get-current query; absence of multi-source support
    /// selects OLD_FW rather than falsely attributing a location source.
    pub fn current(firmware: &Firmware<'_>) -> Self {
        Self {
            country: *b"ZZ",
            source: if firmware.supports_api(9) || firmware.supports_capability(29) {
                0x10
            } else {
                0
            },
        }
    }
    pub const fn id() -> Id {
        Id {
            group: 0,
            opcode: 0xc8,
            version: 0,
        }
    }
    /// Pure source provenance input, never a claim that caller-provided BIOS,
    /// OS or cellular location data was observed/authenticated.
    pub fn bytes(self) -> Result<[u8; 28], Error> {
        if self.country != *b"00" && !self.country.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Country);
        }
        let mut bytes = [0; 28];
        bytes[..2].copy_from_slice(&u16::from_be_bytes(self.country).to_le_bytes());
        bytes[2] = self.source;
        Ok(bytes)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    V3,
    V4,
    V8,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Puncturing {
    #[default]
    Unknown,
    Disabled,
    Enabled,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub allow_40mhz: bool,
    pub allow_80mhz: bool,
    pub allow_160mhz: bool,
    pub allow_320mhz: bool,
    pub disable_11ax: bool,
    pub disable_11be: bool,
    pub disable_11bn: bool,
    pub puncturing: Puncturing,
}
impl Capabilities {
    /// Exact iwl_get_reg_capa interpretation. Only declares the source's
    /// domain-wide capability flags, not valid per-channel authorization.
    pub fn decode(version: u8, flags: u32) -> Result<Self, Error> {
        if !(3..=10).contains(&version) {
            return Err(Error::Version(version));
        }
        let bit = |n: u32| flags & (1u32 << n) != 0u32;
        let mut out = Self::default();
        if version >= 10 {
            out.puncturing = if bit(18) {
                Puncturing::Enabled
            } else {
                Puncturing::Disabled
            };
        }
        if version >= 8 {
            out.allow_40mhz = true;
            out.allow_80mhz = bit(4);
            out.allow_160mhz = bit(3);
            out.allow_320mhz = bit(16);
            out.disable_11ax = bit(13);
            out.disable_11be = bit(8);
            out.disable_11bn = bit(17);
        } else if version >= 6 {
            out.allow_40mhz = bit(8);
            out.allow_80mhz = bit(4);
            out.allow_160mhz = bit(3);
            out.disable_11ax = bit(10);
        } else {
            out.allow_40mhz = !bit(7);
            out.allow_80mhz = bit(3);
            out.allow_160mhz = bit(2);
            out.disable_11ax = bit(10);
        }
        Ok(out)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub version: u8,
    pub layout: Layout,
    pub status: u32,
    pub raw_country: u16,
    pub country: [u8; 2],
    pub capability_flags: u32,
    pub capabilities: Capabilities,
    pub source: u8,
    pub elapsed_30s: u16,
    pub geo_information: u16,
    pub channels: Vec<u32>,
    pub raw: Vec<u8>,
}
impl Response {
    pub fn layout(firmware: &Firmware<'_>) -> Result<(u8, Layout), Error> {
        let version = firmware
            .command_version(1, 0xc8)
            .ok_or(Error::MissingApi)?
            .notification_version;
        if !(3..=10).contains(&version) {
            return Err(Error::Version(version));
        }
        let layout = if version >= 8 {
            Layout::V8
        } else if firmware.supports_capability(89) {
            Layout::V4
        } else {
            Layout::V3
        };
        Ok((version, layout))
    }
    pub fn decode(firmware: &Firmware<'_>, bytes: &[u8]) -> Result<Self, Error> {
        let (version, layout) = Self::layout(firmware)?;
        let header = match layout {
            Layout::V3 => 16,
            Layout::V4 => 20,
            Layout::V8 => 24,
        };
        if bytes.len() < header {
            return Err(Error::Length);
        }
        let word = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let half = |at| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        let count = word(header - 4);
        if count as usize > MAX_CHANNELS {
            return Err(Error::ChannelCount(count));
        }
        if bytes.len() != header + count as usize * 4 {
            return Err(Error::Length);
        }
        let (capability_flags, source, time, geo) = match layout {
            Layout::V3 => (u32::from(bytes[6]), bytes[7], 8, 10),
            Layout::V4 => (u32::from(half(6)), bytes[12], 8, 10),
            Layout::V8 => (word(8), bytes[16], 12, 14),
        };
        let raw_country = half(4);
        // Source FW/NVM workaround: raw zero is reported as world domain00.
        // Preserve raw_country so this is never confused with echoed input.
        let country = if raw_country == 0 {
            *b"00"
        } else {
            raw_country.to_be_bytes()
        };
        Ok(Self {
            version,
            layout,
            status: word(0),
            raw_country,
            country,
            capability_flags,
            capabilities: Capabilities::decode(version, capability_flags)?,
            source,
            elapsed_30s: half(time),
            geo_information: half(geo),
            channels: (0..count as usize).map(|i| word(header + i * 4)).collect(),
            raw: bytes.to_vec(),
        })
    }
    /// Linux treats NEW_CHAN_PROFILE and ILLEGAL as changed; it still keeps
    /// the returned country/profile rather than echoing the request.
    pub fn profile_changed(&self) -> bool {
        matches!(self.status, 0 | 4)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::net::wifi::intel::{command::Command, firmware::Family};
    fn firmware(version: u8, cap89: bool, multi: bool) -> Vec<u8> {
        let mut b = alloc::vec![0;88];
        b[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
        let mut tlv = |kind: u32, d: &[u8]| {
            b.extend(kind.to_le_bytes());
            b.extend((d.len() as u32).to_le_bytes());
            b.extend(d);
            b.resize(b.len().next_multiple_of(4), 0);
        };
        tlv(48, &[0xc8, 1, 1, version]);
        if cap89 {
            tlv(30, &[2, 0, 0, 0, 0, 0, 0, 2]);
        }
        if multi {
            tlv(29, &[0, 0, 0, 0, 0, 2, 0, 0]);
        }
        b
    }
    fn payload(layout: Layout, count: usize, country: u16) -> Vec<u8> {
        let header = match layout {
            Layout::V3 => 16,
            Layout::V4 => 20,
            Layout::V8 => 24,
        };
        let mut b = alloc::vec![0;header+count*4];
        b[..4].copy_from_slice(&4u32.to_le_bytes());
        b[4..6].copy_from_slice(&country.to_le_bytes());
        let (time, geo, source) = match layout {
            Layout::V3 => {
                b[6] = 0x9c;
                (8, 10, 7)
            }
            Layout::V4 => {
                b[6..8].copy_from_slice(&0xa19cu16.to_le_bytes());
                (8, 10, 12)
            }
            Layout::V8 => {
                b[8..12].copy_from_slice(&0x00a7a19cu32.to_le_bytes());
                (12, 14, 16)
            }
        };
        b[time..time + 2].copy_from_slice(&0x1234u16.to_le_bytes());
        b[geo..geo + 2].copy_from_slice(&0x5678u16.to_le_bytes());
        b[source] = 0x10;
        b[header - 4..header].copy_from_slice(&(count as u32).to_le_bytes());
        for i in 0..count {
            b[header + i * 4..header + (i + 1) * 4]
                .copy_from_slice(&(0x80000109u32 + i as u32 * 0x10000).to_le_bytes());
        }
        b
    }
    #[test]
    fn source_country_bytes_provenance_and_wide_header_version_are_exact() {
        for a in b'A'..=b'Z' {
            for b in b'A'..=b'Z' {
                let bytes = Request {
                    country: [a, b],
                    source: 0x10,
                }
                .bytes()
                .unwrap();
                assert_eq!(&bytes[..4], &[b, a, 0x10, 0]);
                assert!(bytes[4..].iter().all(|v| *v == 0));
                let cmd = Command::encode(Request::id(), 0, 0, &bytes).unwrap();
                assert_eq!(&cmd.bytes()[..8], &[0xc8, 1, 0, 0, 28, 0, 0, 0]);
            }
        }
        for country in [*b"00", *b"ZZ"] {
            assert!(Request { country, source: 0 }.bytes().is_ok());
        }
        for country in [*b"us", *b"0A", [0, 0]] {
            assert_eq!(Request { country, source: 0 }.bytes(), Err(Error::Country));
        }
        for multi in [false, true] {
            let b = firmware(5, true, multi);
            let fw = Firmware::parse(&b).unwrap();
            assert_eq!(Request::current(&fw).source, if multi { 0x10 } else { 0 });
        }
    }
    #[test]
    fn exact_variable_layouts_preserve_raw_status_country_padding_and_channel_words() {
        for (version, cap, layout) in [
            (3, false, Layout::V3),
            (5, true, Layout::V4),
            (6, true, Layout::V4),
            (8, false, Layout::V8),
            (10, true, Layout::V8),
        ] {
            let b = firmware(version, cap, true);
            let fw = Firmware::parse(&b).unwrap();
            for count in [0, 1, 51, 110, 115] {
                let payload = payload(layout, count, 0x5553);
                let r = Response::decode(&fw, &payload).unwrap();
                assert_eq!(
                    (
                        r.version,
                        r.layout,
                        r.status,
                        r.country,
                        r.source,
                        r.elapsed_30s,
                        r.geo_information
                    ),
                    (version, layout, 4, *b"US", 0x10, 0x1234, 0x5678)
                );
                assert!(r.profile_changed());
                assert_eq!(r.raw, payload);
                assert_eq!(r.channels.len(), count);
                for (i, ch) in r.channels.iter().enumerate() {
                    assert_eq!(*ch, 0x80000109 + i as u32 * 0x10000);
                }
                for n in 0..payload.len() {
                    assert!(Response::decode(&fw, &payload[..n]).is_err());
                }
                let mut extra = payload.clone();
                extra.push(0);
                assert_eq!(Response::decode(&fw, &extra), Err(Error::Length));
            }
            let mut empty = payload(layout, 0, 0);
            let r = Response::decode(&fw, &empty).unwrap();
            assert_eq!((r.raw_country, r.country), (0, *b"00"));
            let n = empty.len();
            empty[n - 4..].copy_from_slice(&116u32.to_le_bytes());
            assert_eq!(Response::decode(&fw, &empty), Err(Error::ChannelCount(116)));
        }
        // The same physical capability bit changes meaning at response6.
        assert!(Capabilities::decode(5, 0).unwrap().allow_40mhz);
        assert!(!Capabilities::decode(6, 0).unwrap().allow_40mhz);
        assert!(Capabilities::decode(5, 1 << 3).unwrap().allow_80mhz);
        assert!(!Capabilities::decode(6, 1 << 3).unwrap().allow_80mhz);
        assert!(!Capabilities::decode(5, 1 << 3).unwrap().allow_160mhz);
        assert!(Capabilities::decode(6, 1 << 3).unwrap().allow_160mhz);
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_MCC_ORACLE"]
    fn unchanged_linux_mcc_layouts_and_capability_semantics_oracle() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_MCC_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "14e4b35ecebb1e2a2e40a73c1bc08be76dd01083cb91680d96686eca5afcf07c"
        );
        let text = core::str::from_utf8(&bytes).unwrap();
        let decode = |hex: &str| -> Vec<u8> {
            hex.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u8::from_str_radix(core::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect()
        };
        let mut responses = 0;
        let mut caps = 0;
        for line in text.lines() {
            let f: Vec<_> = line.split_whitespace().collect();
            match f[0] {
                "sizes" => assert_eq!(&f[1..], ["28", "16", "20", "24"]),
                "request" => assert_eq!(
                    decode(f[1]),
                    Request {
                        country: *b"US",
                        source: 16
                    }
                    .bytes()
                    .unwrap()
                ),
                "response" => {
                    let version = f[1].parse::<u8>().unwrap();
                    let layout = match f[2] {
                        "3" => Layout::V3,
                        "4" => Layout::V4,
                        "8" => Layout::V8,
                        _ => panic!("layout"),
                    };
                    let count = f[3].parse::<usize>().unwrap();
                    let country = f[4].parse::<u16>().unwrap();
                    let wire = decode(f[5]);
                    assert_eq!(wire, payload(layout, count, country));
                    let b = firmware(version, layout == Layout::V4, true);
                    let fw = Firmware::parse(&b).unwrap();
                    let r = Response::decode(&fw, &wire).unwrap();
                    assert_eq!(
                        r.capability_flags,
                        match layout {
                            Layout::V3 => 0x9c,
                            Layout::V4 => 0xa19c,
                            Layout::V8 => 0xa7a19c,
                        }
                    );
                    assert_eq!(
                        (
                            r.status,
                            r.raw_country,
                            r.country,
                            r.elapsed_30s,
                            r.geo_information,
                            r.source
                        ),
                        (
                            4,
                            country,
                            if country == 0 { *b"00" } else { *b"US" },
                            0x1234,
                            0x5678,
                            16
                        )
                    );
                    assert_eq!(r.channels.len(), count);
                    assert_eq!(r.raw, wire);
                    responses += 1;
                }
                "caps" => {
                    let version = f[1].parse::<u8>().unwrap();
                    let flags = f[2].parse::<u32>().unwrap();
                    let c = Capabilities::decode(version, flags).unwrap();
                    let got = [
                        u8::from(c.allow_40mhz),
                        u8::from(c.allow_80mhz),
                        u8::from(c.allow_160mhz),
                        u8::from(c.allow_320mhz),
                        u8::from(c.disable_11ax),
                        u8::from(c.disable_11be),
                        u8::from(c.disable_11bn),
                        match c.puncturing {
                            Puncturing::Unknown => 0,
                            Puncturing::Enabled => 1,
                            Puncturing::Disabled => 2,
                        },
                    ];
                    let expected: Vec<u8> = f[3..].iter().map(|v| v.parse().unwrap()).collect();
                    assert_eq!(got.as_slice(), expected);
                    caps += 1;
                }
                _ => panic!("unknown trace row"),
            }
        }
        assert_eq!((responses, caps), (50, 1024));
    }
    #[test]
    fn unknown_schema_missing_api_and_unknown_status_are_explicit_raw_observations() {
        let b = firmware(5, true, false);
        let fw = Firmware::parse(&b[..88]).unwrap();
        assert_eq!(Response::layout(&fw), Err(Error::MissingApi));
        for version in [0, 1, 2, 11, 255] {
            let b = firmware(version, false, false);
            let fw = Firmware::parse(&b).unwrap();
            assert_eq!(Response::decode(&fw, &[]), Err(Error::Version(version)));
        }
        let mut b = firmware(5, true, false);
        b.extend(30u32.to_le_bytes());
        b.extend(8u32.to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.extend((1u32 << 29).to_le_bytes());
        let fw = Firmware::parse(&b).unwrap();
        assert_eq!(Request::current(&fw).source, 0x10);
        let mut raw = payload(Layout::V4, 0, 0xdead);
        raw[..4].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        raw[13..16].copy_from_slice(&[0xa5, 0x5a, 0xff]);
        let r = Response::decode(&fw, &raw).unwrap();
        assert_eq!((r.status, r.country), (0xdeadbeef, [0xde, 0xad]));
        assert!(!r.profile_changed());
        assert_eq!(r.raw, raw);
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
    fn actual_images_select_same_v4_layout_but_different_capability_semantics() {
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        for (family, version) in [(Family::Ax200, 5), (Family::Ax210, 6)] {
            let b =
                std::fs::read(std::path::Path::new(&root).join(family.firmware_name())).unwrap();
            let fw = Firmware::parse(&b).unwrap();
            assert_eq!(Response::layout(&fw).unwrap(), (version, Layout::V4));
            assert_eq!(
                Request::current(&fw),
                Request {
                    country: *b"ZZ",
                    source: 0x10
                }
            );
            assert_eq!(fw.command_version(1, 0xc8).unwrap().command_version, 1);
            assert_eq!(
                Response::decode(&fw, &payload(Layout::V4, 51, 0x5553))
                    .unwrap()
                    .version,
                version
            );
        }
    }
}
