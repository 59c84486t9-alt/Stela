// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! Explicit UefiCnvCommonDSBR policy, adapted from pinned btintel_set_dsbr.
//!
//! Capture belongs before ExitBootServices: the packed UEFI value is revision
//! byte + LE u32, GUID e65d8884-d4af-4b20-8d03-772ecc3da531. The donor does not
//! reject revision/reserved bits after a successful read. Preserve them here;
//! command bytes follow its actual mask behavior, without a guessed whitelist.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DsbrInput {
    Present {
        revision: u8,
        raw: u32,
    },
    Absent,
    /// Capture/runtime service unavailable or failed, distinct from absence.
    #[default]
    Unavailable,
}
impl DsbrInput {
    /// Decode exactly the donor's five packed bytes. Wrong-size capture remains
    /// an explicit error for the caller to classify; it is never "absent".
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; 5] = bytes.try_into().ok()?;
        Some(Self::Present {
            revision: bytes[0],
            raw: u32::from_le_bytes(bytes[1..].try_into().unwrap()),
        })
    }
    pub(super) fn parameters(self) -> [u8; 2] {
        let raw = match self {
            Self::Present { raw, .. } => raw,
            Self::Absent | Self::Unavailable => 0,
        };
        [(raw & 1) as u8, ((raw >> 4) & 0xf) as u8]
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlatformInputs {
    pub dsbr: DsbrInput,
}
/// `applied` is Some only after a real successful 0xfc0a Command Complete.
/// Absent/Unavailable then record the documented donor default explicitly.
/// None means this initialization path did not modify DSBR; supplied raw input
/// is still retained, including when firmware was already operational.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DsbrReport {
    pub input: DsbrInput,
    pub applied: Option<[u8; 2]>,
}
impl DsbrReport {
    pub(super) fn new(input: DsbrInput) -> Self {
        Self {
            input,
            applied: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dsbr_capture_keeps_raw_revision_and_matches_donor_masks() {
        for raw in [0u32, 0xb1, 0xf1, 1, 0xffff_ffff, 0xdead_beef] {
            let mut bytes = vec![7];
            bytes.extend_from_slice(&raw.to_le_bytes());
            let input = DsbrInput::decode(&bytes).unwrap();
            assert_eq!(input, DsbrInput::Present { revision: 7, raw });
            assert_eq!(
                input.parameters(),
                [(raw & 1) as u8, ((raw >> 4) & 15) as u8]
            );
        }
        assert_eq!(DsbrInput::Absent.parameters(), [0, 0]);
        assert_eq!(DsbrInput::Unavailable.parameters(), [0, 0]);
        for n in [0, 1, 2, 3, 4, 6] {
            assert_eq!(DsbrInput::decode(&vec![0; n]), None);
        }
    }
}
