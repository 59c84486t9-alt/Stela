// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
// Statistics layouts and signal conversion follow pinned iwlwifi
// fw/api/stats.h and mvm/rx.c; source notices are in wifi/THIRD_PARTY.md.
//! Firmware beacon-filter energy for AX200/AX210 Bluetooth coexistence.
//! Both families use the multi-queue RX API. The older statistics layout
//! therefore uses v11, while NEW_RX_STATS selects the v13 layout.

const MACS: usize = 4;
const PER_MAC_BYTES: usize = 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Format {
    Legacy { version: u8, new_statistics: bool },
    System { version: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Version(u8),
    Length { expected: usize, actual: usize },
    Header,
    Mac(u8),
}

impl Format {
    /// Read only a complete notification of the negotiated format. A different
    /// MAC and a zero energy measurement supply no new RSSI, as mac80211's
    /// active-interface iterator and iwl_mvm_update_link_sig leave them alone.
    pub(super) fn signal(self, raw: &[u8], mac: u8) -> Result<Option<i32>, Error> {
        if usize::from(mac) >= MACS {
            return Err(Error::Mac(mac));
        }
        let word = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let (size, tlv) = match self {
            Self::Legacy {
                version: 0..=13,
                new_statistics,
            } => (if new_statistics { 564 } else { 760 }, false),
            Self::Legacy { version: 14, .. } => (196, true),
            Self::Legacy { version: 15, .. } => (480, true),
            Self::System { version: 3 } => (492, false),
            Self::Legacy { version, .. } | Self::System { version } => {
                return Err(Error::Version(version));
            }
        };
        // Legacy fixed structures have an exact length; the TLV verifier
        // admits trailing data but requires the header's complete source size.
        if raw.len() < size || (!tlv && raw.len() != size) {
            return Err(Error::Length {
                expected: size,
                actual: raw.len(),
            });
        }
        if tlv {
            let Self::Legacy { version, .. } = self else {
                unreachable!()
            };
            if raw[0] & 0x7f != 0
                || raw[1] != version
                || usize::from(u16::from_le_bytes([raw[2], raw[3]])) != size
            {
                return Err(Error::Header);
            }
        }
        let energy = match self {
            Self::Legacy {
                version: 0..=13,
                new_statistics,
            } => {
                let (id, energy) = if new_statistics {
                    (120, 404)
                } else {
                    (252, 584)
                };
                if word(id) as u16 != u16::from(mac) {
                    return Ok(None);
                }
                u32::from(raw[energy])
            }
            Self::Legacy { version: 14, .. } => {
                if word(8) as u16 != u16::from(mac) {
                    return Ok(None);
                }
                // iwl_mvm_stat_data stores this field as u8, unlike the
                // per-MAC v15 and per-link system notification structures.
                u32::from(word(12) as u8)
            }
            Self::Legacy { version: 15, .. } => word(8 + usize::from(mac) * PER_MAC_BYTES),
            Self::System { version: 3 } => word(4 + usize::from(mac) * PER_MAC_BYTES),
            _ => unreachable!(),
        };
        Ok((energy != 0).then_some((energy as i32).wrapping_neg()))
    }
}

#[cfg(test)]
mod tests;
