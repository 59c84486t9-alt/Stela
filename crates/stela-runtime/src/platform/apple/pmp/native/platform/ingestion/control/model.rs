//! Data model of the auxiliary control tail: the `Configuration` of its four
//! source rows, the `SoftwareImage` and `SlotImage` state they describe, and
//! little-endian accessors for the raw slot bytes.
use super::super::{Auxiliary, Descriptor, Error, Ordinal};
use alloc::{vec, vec::Vec};

/// Complete raw source rows. Pointer words are provenance only; the retained
/// owned member arrays replace no actual provider, bank, or callback.
#[derive(Clone, Debug)]
pub struct Configuration {
    pub(super) ordinal: Ordinal,
    pub(super) slice: Option<super::super::super::Slice>,
    pub(super) enabled: bool,
    pub(super) rows: Vec<Auxiliary>,
}
impl Configuration {
    pub fn t8112(descriptor: &Descriptor) -> Result<Self, Error> {
        let config = super::super::Configuration::t8112(descriptor)?;
        Self::declared(descriptor, config.auxiliary_descriptors())
    }
    /// Declared source software configuration. Overrides require their actual
    /// producer and provider bindings; this constructor grants none of them.
    pub fn declared(descriptor: &Descriptor, rows: &[Auxiliary]) -> Result<Self, Error> {
        if rows.len() != 4 {
            return Err(Error::Contract(
                "control tail requires four complete56-byte rows",
            ));
        }
        for row in rows {
            if row.words[7] as usize != row.members.len() || row.words[2] > 2 {
                return Err(Error::Contract(
                    "auxiliary row count or packed source kind is unqualified",
                ));
            }
            if row.words[2] == 2 && row.words[5] > 64 {
                return Err(Error::Contract(
                    "auxiliary packed field width exceeds source word",
                ));
            }
            if row.members.iter().any(|member| member[0] > 2) {
                return Err(Error::Contract(
                    "auxiliary member class has no qualified source path",
                ));
            }
        }
        Ok(Self {
            ordinal: descriptor.ordinal(),
            slice: descriptor.counter_slice(),
            enabled: rows.iter().any(|row| row.words[2] != 0),
            rows: rows.to_vec(),
        })
    }
    pub fn ordinal(&self) -> Ordinal {
        self.ordinal
    }
    pub fn rows(&self) -> &[Auxiliary] {
        &self.rows
    }
}

/// New software image or retained source observation, never hardware reset or
/// controller readiness. Raw40-byte slots retain opaque/pointer provenance;
/// member data lives in this sole actual allocation, not at those raw pointers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotImage {
    pub raw: [u8; 40],
    pub timer: [u32; 3],
    pub members: Vec<[u8; 24]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoftwareImage {
    /// Actual source P8 byte. Only bit2 gates101b464.
    pub flags: u8,
    /// Declared opaque source sp+14 image. Its preserved bits are not a reset
    /// observation:101b64c reads them before the first local packed store.
    pub scratch: u32,
    pub slots: [SlotImage; 4],
}
impl SoftwareImage {
    /// Explicit Stela software initialization. This does not register members,
    /// enable a controller, configure a period, produce data or complete init.
    pub fn zeroed(configuration: &Configuration) -> Self {
        Self {
            flags: if configuration.enabled { 4 } else { 0 },
            scratch: 0,
            slots: core::array::from_fn(|i| SlotImage {
                raw: [0; 40],
                timer: [0; 3],
                members: vec![[0; 24]; configuration.rows[i].members.len()],
            }),
        }
    }
    pub(super) fn check(&self, configuration: &Configuration) -> Result<(), Error> {
        if (self.flags & 4 != 0) != configuration.enabled {
            return Err(Error::Contract(
                "control gate differs from source-configured auxiliary kinds",
            ));
        }
        for (slot, row) in self.slots.iter().zip(&configuration.rows) {
            if slot.members.len() != row.members.len() || word(&slot.raw, 8) > 2 {
                return Err(Error::Contract(
                    "control software image has foreign geometry or mode",
                ));
            }
        }
        Ok(())
    }
}
pub(super) fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
pub(super) fn put_word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn half(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
pub(super) fn put_half(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_rows_and_declared_software_geometry_are_checked_before_admission() {
        let descriptor =
            super::super::super::super::profile::tests::fixture().descriptors()[4].clone();
        let cfg = Configuration::t8112(&descriptor).unwrap();
        let mut rows = cfg.rows.clone();
        rows[0].words[7] += 1;
        assert!(Configuration::declared(&descriptor, &rows).is_err());
        rows = cfg.rows.clone();
        rows[0].members[8][0] = 3;
        assert!(Configuration::declared(&descriptor, &rows).is_err());
        let mut image = SoftwareImage::zeroed(&cfg);
        image.slots[0].members.pop();
        assert!(image.check(&cfg).is_err());
        image = SoftwareImage::zeroed(&cfg);
        image.flags = 0;
        assert!(image.check(&cfg).is_err());
        image = SoftwareImage::zeroed(&cfg);
        put_word(&mut image.slots[0].raw, 8, 3);
        assert!(image.check(&cfg).is_err());
        let raw = cfg.rows[0].words;
        assert_eq!(raw[8], 17070656); // Pointer provenance is preserved, never dereferenced.
        assert!(SoftwareImage::zeroed(&cfg).check(&cfg).is_ok());
    }
}
