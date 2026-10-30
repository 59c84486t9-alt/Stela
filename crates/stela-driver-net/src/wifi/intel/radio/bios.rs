// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2021-2026 Intel Corporation
//! Pure packed UEFI radio configuration observations from fw/uefi.{c,h}.
//! These parsers prove no evaluated GLAI, locked-variable source preference,
//! ACPI fallback, vendor authenticity, programmed power or RF permission.
use crate::bytes::le32;
const MAX_RAW_BYTES: usize = 4096;
pub mod power_tables;
pub mod service;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Size {
        minimum: usize,
        actual: usize,
    },
    Bound(usize),
    Revision(u8),
    Country(u32),
    UnsupportedFunction(u8),
    FunctionUnavailable(u8),
    ExactSize {
        expected: usize,
        actual: usize,
    },
    ProfileCount {
        minimum: u32,
        maximum: u32,
        actual: u32,
    },
}
fn bounded(raw: &[u8], minimum: usize) -> Result<(), Error> {
    if raw.len() > MAX_RAW_BYTES {
        return Err(Error::Bound(raw.len()));
    }
    if raw.len() < minimum {
        return Err(Error::Size {
            minimum,
            actual: raw.len(),
        });
    }
    Ok(())
}
fn prefix(raw: &[u8], minimum: usize, revision: u8) -> Result<(), Error> {
    bounded(raw, minimum)?;
    if raw[0] != revision {
        return Err(Error::Revision(raw[0]));
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarKind {
    Country,
    ExternalClock,
    WideBandwidth,
    DevicePowerLimit,
}
#[derive(Clone, Copy, Debug)]
pub struct Scalar<'a> {
    kind: ScalarKind,
    raw: &'a [u8],
    raw_value: u32,
    value: u32,
}
impl<'a> Scalar<'a> {
    /// Source WRDD/ECKV/WBEM/SPLC revision0 packed prefix. Trailing data is
    /// within the explicit native 4 KiB bound, not silently discarded.
    pub fn parse(kind: ScalarKind, raw: &'a [u8]) -> Result<Self, Error> {
        prefix(raw, 5, 0)?;
        let raw_value = le32(raw, 1);
        let value = match kind {
            ScalarKind::Country => {
                // Both source UEFI and ACPI BIOS country paths admit CN only.
                if raw_value != 0x434e {
                    return Err(Error::Country(raw_value));
                }
                raw_value
            }
            ScalarKind::WideBandwidth => raw_value & 3,
            ScalarKind::ExternalClock | ScalarKind::DevicePowerLimit => raw_value,
        };
        Ok(Self {
            kind,
            raw,
            raw_value,
            value,
        })
    }
    pub fn kind(self) -> ScalarKind {
        self.kind
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn raw_value(self) -> u32 {
        self.raw_value
    }
    pub fn value(self) -> u32 {
        self.value
    }
}
#[derive(Clone, Copy, Debug)]
pub struct GeneralConfiguration<'a> {
    raw: &'a [u8],
}
impl<'a> GeneralConfiguration<'a> {
    /// Source rejects unsupported function indices before fetching/parsing the
    /// table, so these requests cannot turn missing input into a zero value.
    pub fn query(raw: &'a [u8], index: u8) -> Result<u32, Error> {
        Self::supported(index)?;
        Self::parse(raw)?.function(index)
    }
    fn supported(index: u8) -> Result<(), Error> {
        if index >= 15 || index == 5 {
            return Err(Error::UnsupportedFunction(index));
        }
        Ok(())
    }
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        prefix(raw, 129, 4)?;
        Ok(Self { raw })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    /// The whole 32-entry source package is held, including entries the
    /// current driver does not interpret. This is not a valid-function grant.
    pub fn raw_function(self, index: usize) -> Option<u32> {
        (index < 32).then(|| le32(self.raw, 1 + index * 4))
    }
    pub fn raw_function_bitmap(self) -> u32 {
        le32(self.raw, 1)
    }
    pub fn source_function_bitmap(self) -> u32 {
        self.raw_function_bitmap() | 1
    }
    /// Source supported-function range, forced cached query bit and
    /// unsupported function 5 behavior. Missing data never becomes zero.
    pub fn function(self, index: u8) -> Result<u32, Error> {
        Self::supported(index)?;
        if self.source_function_bitmap() & (1u32 << index) == 0 {
            return Err(Error::FunctionUnavailable(index));
        }
        Ok(le32(self.raw, 1 + usize::from(index) * 4))
    }
}
#[derive(Clone, Copy, Debug)]
pub struct PhyFilters<'a> {
    raw: &'a [u8],
}
impl<'a> PhyFilters<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        prefix(raw, 17, 0)?;
        Ok(Self { raw })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn chains(self) -> [u32; 4] {
        core::array::from_fn(|i| le32(self.raw, 1 + i * 4))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec::Vec;
    fn fixture(seed: u32, revision: u8, length: usize) -> Vec<u8> {
        let mut raw: Vec<u8> = (0..4096).map(|i| (i * 37 + seed as usize) as u8).collect();
        raw[0] = revision;
        raw.truncate(length);
        raw
    }
    #[test]
    fn bounded_raw_prefixes_preserve_trailing_and_reserved_observations() {
        for kind in [
            ScalarKind::Country,
            ScalarKind::ExternalClock,
            ScalarKind::WideBandwidth,
            ScalarKind::DevicePowerLimit,
        ] {
            let mut bytes = fixture(33, 0, 4096);
            bytes[1..5].copy_from_slice(&0x434eu32.to_le_bytes());
            let value = Scalar::parse(kind, &bytes).unwrap();
            assert_eq!(value.raw().as_ptr(), bytes.as_ptr());
            assert_eq!(value.raw(), bytes);
            assert_eq!(value.raw_value(), 0x434e);
            for n in 0..5 {
                assert!(matches!(
                    Scalar::parse(kind, &bytes[..n]),
                    Err(Error::Size { minimum: 5, .. })
                ));
            }
            bytes[0] = 1;
            assert!(matches!(
                Scalar::parse(kind, &bytes),
                Err(Error::Revision(1))
            ));
            bytes.push(0);
            assert!(matches!(
                Scalar::parse(kind, &bytes),
                Err(Error::Bound(4097))
            ));
        }
        let mut country = alloc::vec![0;5];
        country[1..].copy_from_slice(&0x5553u32.to_le_bytes());
        assert!(matches!(
            Scalar::parse(ScalarKind::Country, &country),
            Err(Error::Country(0x5553))
        ));
        let raw = fixture(0, 0, 17);
        let filters = PhyFilters::parse(&raw).unwrap();
        assert_eq!(filters.raw().as_ptr(), raw.as_ptr());
        assert!(PhyFilters::parse(&raw[..16]).is_err());
        let mut wide = alloc::vec![0;5];
        wide[1..].copy_from_slice(&u32::MAX.to_le_bytes());
        let decoded = Scalar::parse(ScalarKind::WideBandwidth, &wide).unwrap();
        assert_eq!((decoded.raw_value(), decoded.value()), (u32::MAX, 3));
    }
    #[test]
    fn dsm_forced_query_bit_range_and_missing_functions_are_explicit() {
        let mut raw = fixture(0, 4, 129);
        raw[1..5].copy_from_slice(&0u32.to_le_bytes());
        let table = GeneralConfiguration::parse(&raw).unwrap();
        assert_eq!(table.raw().as_ptr(), raw.as_ptr());
        assert_eq!(
            (
                table.raw_function_bitmap(),
                table.source_function_bitmap(),
                table.function(0)
            ),
            (0, 1, Ok(0))
        );
        for index in 1..15 {
            if index != 5 {
                assert_eq!(
                    table.function(index),
                    Err(Error::FunctionUnavailable(index))
                );
            }
        }
        for index in [5, 15, 31, 32, 255] {
            assert_eq!(
                GeneralConfiguration::query(&[], index),
                Err(Error::UnsupportedFunction(index))
            );
        }
        assert!(table.raw_function(31).is_some());
        assert_eq!(table.raw_function(32), None);
        assert_eq!(table.raw_function(usize::MAX), None);
        for size in 0..129 {
            assert!(matches!(
                GeneralConfiguration::parse(&raw[..size]),
                Err(Error::Size { minimum: 129, .. })
            ));
        }
        let mut extended = raw.clone();
        extended.resize(4096, 0xcc);
        assert_eq!(
            GeneralConfiguration::parse(&extended).unwrap().raw(),
            extended
        );
        extended.push(0);
        assert!(matches!(
            GeneralConfiguration::parse(&extended),
            Err(Error::Bound(4097))
        ));
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_RADIO_BIOS_ORACLE"]
    fn unchanged_linux_uefi_radio_scalar_dsm_and_phy_getters_oracle() {
        use sha2::{Digest, Sha256};
        let bytes =
            std::fs::read(std::env::var("STELA_IWLWIFI_RADIO_BIOS_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "84b163dcdd852ee2cb027afda511f217b5f2ea6596b1b1929f27c9f00966cea7"
        );
        let (mut scalars, mut dsms, mut phys) = (0, 0, 0);
        for line in core::str::from_utf8(&bytes).unwrap().lines() {
            let f: Vec<_> = line.split_whitespace().collect();
            match f[0] {
                "scalar" => {
                    let kind = f[1].parse::<u32>().unwrap();
                    let revision = f[2].parse::<u8>().unwrap();
                    let len = f[3].parse::<usize>().unwrap();
                    let input = f[4].parse::<u32>().unwrap();
                    let mut raw = fixture(kind * 11 + u32::from(revision), revision, 4096);
                    raw[1..5].copy_from_slice(&input.to_le_bytes());
                    raw.truncate(len);
                    let kind = match kind {
                        0 => ScalarKind::Country,
                        1 => ScalarKind::ExternalClock,
                        2 => ScalarKind::WideBandwidth,
                        3 => ScalarKind::DevicePowerLimit,
                        _ => panic!("kind"),
                    };
                    let result = Scalar::parse(kind, &raw);
                    let code = if result.is_ok() { 0 } else { -1 };
                    assert_eq!(code, f[5].parse::<i32>().unwrap(), "{line}");
                    if let Ok(value) = result {
                        assert_eq!(value.value(), f[6].parse::<u32>().unwrap(), "{line}");
                        assert_eq!(value.raw(), raw);
                    }
                    scalars += 1;
                }
                "dsm" => {
                    let revision = f[1].parse::<u8>().unwrap();
                    let len = f[2].parse::<usize>().unwrap();
                    let mask = f[3].parse::<u32>().unwrap();
                    let index = f[4].parse::<u8>().unwrap();
                    let mut raw = fixture(0, revision, 4096);
                    for i in 0..32 {
                        let value = 0x9e3779b9u32.wrapping_mul(i as u32 + 1) ^ mask;
                        raw[1 + i * 4..5 + i * 4].copy_from_slice(&value.to_le_bytes());
                    }
                    raw[1..5].copy_from_slice(&mask.to_le_bytes());
                    raw.truncate(len);
                    let result = GeneralConfiguration::query(&raw, index);
                    let code = match result {
                        Ok(_) => 0,
                        Err(Error::UnsupportedFunction(_)) => -2,
                        Err(_) => -1,
                    };
                    assert_eq!(code, f[5].parse::<i32>().unwrap(), "{line}");
                    if let Ok(value) = result {
                        assert_eq!(value, f[6].parse::<u32>().unwrap(), "{line}");
                    }
                    dsms += 1;
                }
                "phy" => {
                    let revision = f[1].parse::<u8>().unwrap();
                    let len = f[2].parse::<usize>().unwrap();
                    let raw = fixture(13, revision, len);
                    let result = PhyFilters::parse(&raw);
                    let code = if result.is_ok() { 0 } else { -1 };
                    assert_eq!(code, f[3].parse::<i32>().unwrap(), "{line}");
                    if let Ok(value) = result {
                        let expected: Vec<u32> =
                            f[4..].iter().map(|v| v.parse().unwrap()).collect();
                        assert_eq!(value.chains().as_slice(), expected, "{line}");
                    }
                    phys += 1;
                }
                _ => panic!("unknown trace row"),
            }
        }
        assert_eq!((scalars, dsms, phys), (49152, 12704, 1536));
    }
}
