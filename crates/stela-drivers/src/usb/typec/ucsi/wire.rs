// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! UCSI wire fields from pinned Linux ucsi.h. Unknown bits remain observable.

use super::Error;

pub(super) const RESET: u64 = 1;
pub(super) const CANCEL: u64 = 2;
pub(super) const ACK: u64 = 4;
pub(super) const NOTIFY: u64 = 5;
pub(super) const CAPABILITY: u64 = 6;
pub(super) const CONNECTOR_CAPABILITY: u64 = 7;
pub(super) const SET_DATA_ROLE: u64 = 9;
pub(super) const SET_POWER_ROLE: u64 = 0x0b;
pub(super) const ALTERNATE_MODES: u64 = 0x0c;
pub(super) const CAM_SUPPORTED: u64 = 0x0d;
pub(super) const CURRENT_CAM: u64 = 0x0e;
pub(super) const NEW_CAM: u64 = 0x0f;
pub(super) const PDOS: u64 = 0x10;
pub(super) const CABLE_PROPERTY: u64 = 0x11;
pub(super) const STATUS: u64 = 0x12;
pub(super) const ERROR_STATUS: u64 = 0x13;
pub(super) const ACK_CONNECTOR: u64 = 1 << 16;
pub(super) const ACK_COMMAND: u64 = 1 << 17;
pub(super) const NOTIFY_BASIC: u64 = (1 << 16) | (1 << 31);

pub(super) const NOT_SUPPORTED: u32 = 1 << 25;
pub(super) const CANCEL_COMPLETE: u32 = 1 << 26;
pub(super) const RESET_COMPLETE: u32 = 1 << 27;
pub(super) const BUSY: u32 = 1 << 28;
pub(super) const ACK_COMPLETE: u32 = 1 << 29;
pub(super) const ERROR: u32 = 1 << 30;
pub(super) const COMMAND_COMPLETE: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u16);

impl Version {
    pub fn new(raw: u16) -> Result<Self, Error> {
        match raw {
            0x0100 | 0x0110 | 0x0120 | 0x0200 | 0x0210 | 0x0300 => Ok(Self(raw)),
            _ => Err(Error::UnsupportedVersion(raw)),
        }
    }
    pub fn raw(self) -> u16 {
        self.0
    }
    pub fn message_in_bytes(self) -> usize {
        if self.0 < 0x0200 { 16 } else { 255 }
    }
    pub fn message_out_bytes(self) -> usize {
        match self.0 {
            0x0100..=0x0120 => 16,
            0x0200..=0x0210 => 256,
            _ => 255,
        }
    }
    pub fn message_out_offset(self) -> usize {
        if self.0 <= 0x0120 { 32 } else { 272 }
    }
    pub fn mailbox_bytes(self) -> usize {
        self.message_out_offset() + self.message_out_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorNumber(u8);

impl ConnectorNumber {
    pub fn new(number: u8) -> Result<Self, Error> {
        match number {
            1..=127 => Ok(Self(number)),
            _ => Err(Error::InvalidConnector { number, count: 127 }),
        }
    }
    pub fn get(self) -> u8 {
        self.0
    }
    pub(super) fn control(self) -> u64 {
        u64::from(self.0) << 16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cci(pub u32);

impl Cci {
    pub fn connector(self) -> Option<ConnectorNumber> {
        match (self.0 >> 1) as u8 & 0x7f {
            0 => None,
            n => Some(ConnectorNumber(n)),
        }
    }
    pub fn length(self) -> usize {
        ((self.0 >> 8) & 0xff) as usize
    }
    pub fn busy(self) -> bool {
        self.0 & BUSY != 0
    }
    pub(super) fn validate(self) -> Result<(), Error> {
        // Busy makes all other fields undefined in real buggy firmware; Linux
        // ignores them. An all-ones failed read is never a valid completion.
        if self.0 == u32::MAX || (!self.busy() && self.0 & 0x01ff_0001 != 0) {
            Err(Error::InvalidCci(self.0))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    pub raw: [u8; 16],
    /// The original byte includes the donor's documented reserved-bit quirk.
    pub reported_connectors: u8,
    pub connectors: u8,
    pub attributes: u32,
    pub features: u16,
}

impl Capability {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let raw: [u8; 16] = bytes.try_into().map_err(|_| Error::InvalidResponseLength {
            command: CAPABILITY as u8,
            bytes: bytes.len(),
        })?;
        let connectors = raw[4] & 0x7f;
        if connectors == 0 {
            return Err(Error::InvalidConnector {
                number: raw[4],
                count: 0,
            });
        }
        Ok(Self {
            raw,
            reported_connectors: raw[4],
            connectors,
            attributes: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
            features: u16::from_le_bytes(raw[5..7].try_into().unwrap()),
        })
    }

    pub fn notifications(self, version: Version) -> u64 {
        let mut mask = 0xdbe7_0000u64;
        if self.features & (1 << 2) == 0 {
            mask &= !(1 << 24);
        }
        if self.features & (1 << 4) == 0 {
            mask &= !((1 << 22) | (1 << 21));
        }
        if self.features & (1 << 6) == 0 {
            mask &= !(1 << 17);
        }
        if self.features & (1 << 7) == 0 {
            mask &= !(1 << 23);
        }
        if version.raw() > 0x0120 {
            mask |= 1 << 32;
            for (feature, notification) in [(9, 19), (10, 20), (12, 26), (13, 29)] {
                if self.features & (1 << feature) != 0 {
                    mask |= 1 << notification;
                }
            }
        }
        mask
    }
}

/// Actual command-return bytes. Optional fields absent from the version or
/// returned length remain None rather than being manufactured as zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorStatus {
    version: Version,
    raw: [u8; 19],
    bytes: u8,
}

impl ConnectorStatus {
    pub fn version(self) -> Version {
        self.version
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw[..usize::from(self.bytes)]
    }
    pub fn bytes(self) -> usize {
        usize::from(self.bytes)
    }
    pub fn parse(version: Version, bytes: &[u8]) -> Result<Self, Error> {
        if !(9..=version.message_in_bytes().min(19)).contains(&bytes.len()) {
            return Err(Error::InvalidResponseLength {
                command: STATUS as u8,
                bytes: bytes.len(),
            });
        }
        let mut raw = [0; 19];
        raw[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            version,
            raw,
            bytes: bytes.len() as u8,
        })
    }
    fn field(self, offset: usize, size: usize) -> Option<u32> {
        if offset + size > usize::from(self.bytes) * 8 {
            return None;
        }
        let mut value = 0;
        for bit in 0..size {
            value |= u32::from((self.raw[(offset + bit) / 8] >> ((offset + bit) % 8)) & 1) << bit;
        }
        Some(value)
    }
    pub fn change(self) -> u16 {
        self.field(0, 16).unwrap() as u16
    }
    pub fn connected(self) -> bool {
        self.field(19, 1) == Some(1)
    }
    pub fn power_source(self) -> bool {
        self.field(20, 1) == Some(1)
    }
    pub fn partner_type(self) -> u8 {
        self.field(29, 3).unwrap() as u8
    }
    pub fn usb_data(self) -> bool {
        self.field(21, 1) == Some(1)
    }
    pub fn alternate_mode(self) -> bool {
        self.field(22, 1) == Some(1)
    }
    pub fn power_mode(self) -> u8 {
        self.field(16, 3).unwrap() as u8
    }
    pub fn rdo(self) -> u32 {
        self.field(32, 32).unwrap()
    }
    pub fn orientation_reversed(self) -> Option<bool> {
        (self.version.raw() >= 0x0200)
            .then(|| self.field(86, 1))
            .flatten()
            .map(|v| v != 0)
    }
    pub fn pd_revision(self) -> Option<u16> {
        (self.version.raw() >= 0x0120)
            .then(|| self.field(70, 16))
            .flatten()
            .map(|v| v as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fields_are_version_and_length_checked() {
        let v1 = Version::new(0x0110).unwrap();
        let v12 = Version::new(0x0120).unwrap();
        let v2 = Version::new(0x0200).unwrap();
        let mut bytes = [0xff; 19];
        bytes[0] = 0x34;
        bytes[1] = 0x12;
        let base = ConnectorStatus::parse(v1, &bytes[..9]).unwrap();
        assert_eq!(base.change(), 0x1234);
        assert_eq!(base.rdo(), u32::MAX);
        assert_eq!(base.pd_revision(), None);
        assert_eq!(base.orientation_reversed(), None);
        assert_eq!(
            ConnectorStatus::parse(v12, &bytes[..10])
                .unwrap()
                .pd_revision(),
            None
        );
        assert_eq!(
            ConnectorStatus::parse(v12, &bytes[..11])
                .unwrap()
                .pd_revision(),
            Some(0xffff)
        );
        assert_eq!(
            ConnectorStatus::parse(v2, &bytes[..11])
                .unwrap()
                .orientation_reversed(),
            Some(true)
        );
        assert!(ConnectorStatus::parse(v1, &bytes).is_err());
        assert!(ConnectorStatus::parse(v2, &bytes[..8]).is_err());
        for version in [0, 0x0101, 0x0130, 0x0201, 0x0301, 0xffff] {
            assert_eq!(
                Version::new(version),
                Err(Error::UnsupportedVersion(version))
            );
        }
        assert!(ConnectorNumber::new(0).is_err());
        assert!(ConnectorNumber::new(128).is_err());
        assert!(ConnectorNumber::new(127).is_ok());
    }
    #[test]
    fn busy_fields_are_undefined_but_failed_all_ones_read_is_never_valid() {
        assert!(Cci(BUSY | 0x01ff_ffff).validate().is_ok());
        assert!(Cci(u32::MAX).validate().is_err());
        assert!(Cci(1).validate().is_err());
        assert!(Cci(COMMAND_COMPLETE | (255 << 8) | 254).validate().is_ok());
    }
}
