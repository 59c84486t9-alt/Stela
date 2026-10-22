// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2005-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Pure source MCC channel observations. Neither valid flags nor a decoded
//! country supply OS/location authority, programmed power or a publication lease.
use super::{Capabilities, Response};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inventory {
    Extended,
    UltraHighBand,
    Unii9,
}
impl Inventory {
    pub const fn channel_count(self) -> usize {
        match self {
            Self::Extended => 51,
            Self::UltraHighBand => 110,
            Self::Unii9 => 115,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    Ghz2,
    Ghz5,
    Ghz6,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    pub band: Band,
    pub number: u16,
    pub frequency_mhz: u16,
}
impl Channel {
    /// Exact source extended/UHB/UNII9 index table; choosing an inventory is
    /// pure input, not proof of the actual controller's configured inventory.
    pub fn at(inventory: Inventory, index: usize) -> Option<Self> {
        const FIVE: [u16; 37] = [
            36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112,
            116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177, 181,
        ];
        if index >= inventory.channel_count() {
            return None;
        }
        let (band, number, frequency_mhz) = if index < 14 {
            let number = index as u16 + 1;
            (
                Band::Ghz2,
                number,
                if number == 14 {
                    2484
                } else {
                    2407 + number * 5
                },
            )
        } else if index < 51 {
            let number = FIVE[index - 14];
            (Band::Ghz5, number, 5000 + number * 5)
        } else {
            let number = 1 + (index - 51) as u16 * 4;
            (Band::Ghz6, number, 5950 + number * 5)
        };
        Some(Self {
            band,
            number,
            frequency_mhz,
        })
    }
}

/// Semantic projection of the complete source iwl_nvm_get_regdom_bw_flags.
/// These remain observations, including concurrent-GO and 6GHz exceptions;
/// the initial station profile cannot use those exceptions as authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restrictions {
    pub no_ht40_plus: bool,
    pub no_ht40_minus: bool,
    pub no_80mhz: bool,
    pub no_160mhz: bool,
    pub no_320mhz: bool,
    pub no_initiate_radiation: bool,
    pub dfs: bool,
    pub indoor_only: bool,
    pub allow_20mhz_activity: bool,
    pub go_concurrent: bool,
    pub dfs_concurrent: bool,
    pub allow_6ghz_vlp_ap: bool,
    pub no_6ghz_vlp_client: bool,
    pub no_6ghz_afc_client: bool,
    pub no_he: bool,
    pub no_eht: bool,
    pub no_uhr: bool,
}
impl Restrictions {
    fn decode(index: usize, channel: Channel, raw: u32, caps: Capabilities) -> Self {
        let flags = raw as u16;
        let bit = |n: u32| flags & (1u16 << n) != 0u16;
        let (plus, minus) = if !bit(9) {
            (false, false)
        } else if index < 14 {
            (channel.number <= 9, channel.number >= 5)
        } else if index < 51 {
            (
                (index - 14).is_multiple_of(2),
                !(index - 14).is_multiple_of(2),
            )
        } else {
            (true, true)
        };
        let no_ir = !bit(3);
        let dfs = bit(4);
        Self {
            no_ht40_plus: !plus || (index >= 14 && !caps.allow_40mhz),
            no_ht40_minus: !minus || (index >= 14 && !caps.allow_40mhz),
            no_80mhz: !bit(10) || (index >= 14 && !caps.allow_80mhz),
            no_160mhz: !bit(11) || (index >= 14 && !caps.allow_160mhz),
            no_320mhz: index >= 14 && !caps.allow_320mhz,
            no_initiate_radiation: no_ir && !(bit(6) && dfs),
            dfs,
            indoor_only: bit(5),
            allow_20mhz_activity: bit(2) && no_ir,
            go_concurrent: bit(6) && no_ir,
            dfs_concurrent: bit(6) && dfs,
            allow_6ghz_vlp_ap: bit(13) && !bit(15),
            no_6ghz_vlp_client: !bit(13),
            no_6ghz_afc_client: !bit(14),
            no_he: caps.disable_11ax,
            no_eht: caps.disable_11be,
            no_uhr: caps.disable_11bn,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub index: usize,
    pub channel: Channel,
    pub raw: u32,
    pub valid: bool,
    pub restrictions: Restrictions,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryMismatch {
    pub declared: usize,
    pub capacity: usize,
}
impl Response {
    /// No invented power limit: source max_eirp is a default annotated as not
    /// used by firmware, not actual per-channel calibration or programming.
    /// Invalid channels and unknown high bits are retained. Empty stays empty;
    /// the cfg80211-only unusable dummy rule is not a usable native channel.
    pub fn channel_observations(
        &self,
        inventory: Inventory,
    ) -> Result<Vec<Observation>, InventoryMismatch> {
        if self.channels.len() > inventory.channel_count() {
            return Err(InventoryMismatch {
                declared: self.channels.len(),
                capacity: inventory.channel_count(),
            });
        }
        Ok(self
            .channels
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                let channel = Channel::at(inventory, index).unwrap();
                Observation {
                    index,
                    channel,
                    raw: *raw,
                    valid: raw & 1 != 0,
                    restrictions: Restrictions::decode(index, channel, *raw, self.capabilities),
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{Layout, Puncturing};
    use super::*;
    fn caps(mask: u8) -> Capabilities {
        Capabilities {
            allow_40mhz: mask & 1 != 0,
            allow_80mhz: mask & 2 != 0,
            allow_160mhz: mask & 4 != 0,
            allow_320mhz: mask & 8 != 0,
            disable_11ax: mask & 16 != 0,
            disable_11be: mask & 32 != 0,
            disable_11bn: mask & 64 != 0,
            puncturing: Puncturing::Unknown,
        }
    }
    fn response(channels: Vec<u32>) -> Response {
        Response {
            version: 5,
            layout: Layout::V4,
            status: 0,
            raw_country: 0,
            country: *b"00",
            capability_flags: 0,
            capabilities: caps(15),
            source: 0,
            elapsed_30s: 0,
            geo_information: 0,
            channels,
            raw: Vec::new(),
        }
    }
    #[test]
    fn channel_inventory_boundaries_and_no_fabricated_missing_channels() {
        for (inventory, last) in [
            (Inventory::Extended, (50, Band::Ghz5, 181, 5905)),
            (Inventory::UltraHighBand, (109, Band::Ghz6, 233, 7115)),
            (Inventory::Unii9, (114, Band::Ghz6, 253, 7215)),
        ] {
            let (index, band, number, frequency_mhz) = last;
            assert_eq!(
                Channel::at(inventory, index),
                Some(Channel {
                    band,
                    number,
                    frequency_mhz
                })
            );
            assert_eq!(Channel::at(inventory, index + 1), None);
            assert_eq!(Channel::at(inventory, usize::MAX), None);
            assert!(
                response(Vec::new())
                    .channel_observations(inventory)
                    .unwrap()
                    .is_empty()
            );
            let values = response(alloc::vec![0xa5a50001; inventory.channel_count()]);
            let observations = values.channel_observations(inventory).unwrap();
            assert_eq!(observations.len(), inventory.channel_count());
            assert!(observations.iter().all(|v| v.raw == 0xa5a50001 && v.valid));
            let mut excess = values;
            excess.channels.push(1);
            assert_eq!(
                excess.channel_observations(inventory),
                Err(InventoryMismatch {
                    declared: inventory.channel_count() + 1,
                    capacity: inventory.channel_count()
                })
            );
        }
        for (index, number, frequency_mhz) in [
            (0, 1, 2412),
            (12, 13, 2472),
            (13, 14, 2484),
            (14, 36, 5180),
            (28, 92, 5460),
            (51, 1, 5955),
        ] {
            let c = Channel::at(Inventory::Unii9, index).unwrap();
            assert_eq!((c.number, c.frequency_mhz), (number, frequency_mhz));
        }
        let invalid = response(alloc::vec![0xffff0000]);
        let obs = invalid.channel_observations(Inventory::Extended).unwrap();
        assert!(!obs[0].valid);
        assert_eq!(obs[0].raw, 0xffff0000);
    }
    #[test]
    fn source_dfs_no_ir_exceptions_and_widths_remain_observations() {
        let decode = |index, raw, mask| {
            Restrictions::decode(
                index,
                Channel::at(Inventory::Unii9, index).unwrap(),
                raw,
                caps(mask),
            )
        };
        let normal = decode(14, 1 << 2, 15);
        assert!(normal.no_initiate_radiation && normal.allow_20mhz_activity);
        assert!(!normal.dfs && !normal.go_concurrent);
        let go = decode(14, (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6), 15);
        assert!(!go.no_initiate_radiation);
        assert!(
            go.dfs
                && go.indoor_only
                && go.go_concurrent
                && go.dfs_concurrent
                && go.allow_20mhz_activity
        );
        let active = decode(14, (1 << 3) | (1 << 6), 15);
        assert!(!active.no_initiate_radiation && !active.go_concurrent);
        // Domain-wide wide-channel disables do not apply to source 2.4GHz
        // HT40. This is not permission to use impossible widths in that band.
        assert!(!decode(8, 1 << 9, 0).no_ht40_plus);
        assert!(!decode(8, 1 << 9, 0).no_ht40_minus);
        assert!(decode(14, 1 << 9, 0).no_ht40_plus);
        assert!(!decode(14, 1 << 9, 15).no_ht40_plus);
        assert!(decode(14, 1 << 9, 15).no_ht40_minus);
        assert!(!decode(15, 1 << 9, 15).no_ht40_minus);
        assert!(!decode(51, 1 << 9, 15).no_ht40_minus);
        assert!(decode(13, 1 << 9, 15).no_ht40_plus);
        assert!(decode(51, 0, 0).no_6ghz_vlp_client);
        let vlp = decode(51, 1 << 13, 15);
        assert!(vlp.allow_6ghz_vlp_ap && !vlp.no_6ghz_vlp_client);
        assert!(!decode(51, (1 << 13) | (1 << 15), 15).allow_6ghz_vlp_ap);
    }
    #[test]
    #[ignore = "requires fresh unchanged Linux full channel restriction oracle"]
    fn unchanged_linux_channel_inventory_and_full_restriction_oracle() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_CHANNEL_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "5e2da34876f79da3a5fe5bd413f3b74045a3b31599da62f1de13592a887bdf7e"
        );
        let text = core::str::from_utf8(&bytes).unwrap();
        let (mut channels, mut cases) = (0, 0);
        for line in text.lines() {
            let f: Vec<_> = line.split_whitespace().collect();
            let index = f[1].parse::<usize>().unwrap();
            let channel = Channel::at(Inventory::Unii9, index).unwrap();
            if f[0] == "channel" {
                assert_eq!(channel.number, f[2].parse::<u16>().unwrap());
                channels += 1;
            } else {
                assert_eq!(f[0], "rule");
                let r = Restrictions::decode(
                    index,
                    channel,
                    f[2].parse().unwrap(),
                    caps(f[3].parse().unwrap()),
                );
                let fields = [
                    r.no_ht40_plus,
                    r.no_ht40_minus,
                    r.no_80mhz,
                    r.no_160mhz,
                    r.no_320mhz,
                    r.no_initiate_radiation,
                    r.dfs,
                    r.indoor_only,
                    r.allow_20mhz_activity,
                    r.go_concurrent,
                    r.dfs_concurrent,
                    r.allow_6ghz_vlp_ap,
                    r.no_6ghz_vlp_client,
                    r.no_6ghz_afc_client,
                    r.no_he,
                    r.no_eht,
                    r.no_uhr,
                ];
                let packed = fields
                    .iter()
                    .enumerate()
                    .fold(0u32, |mask, (i, value)| mask | ((*value as u32) << i));
                assert_eq!(packed, f[4].parse::<u32>().unwrap(), "{line}");
                cases += 1;
            }
        }
        assert_eq!((channels, cases), (115, 65536 + 115 * 16 * 2));
    }
}
