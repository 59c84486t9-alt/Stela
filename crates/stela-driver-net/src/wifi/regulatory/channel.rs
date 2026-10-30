// SPDX-License-Identifier: ISC
// Channel regulation follows pinned Linux net/wireless/reg.c.
// Copyright (C) 2002-2005 Instant802 Networks, Inc.
// Copyright (C) 2005-2006 Devicescape Software, Inc.
// Copyright 2007 Johannes Berg; 2008-2011 Luis R. Rodriguez.
// Copyright 2013-2014 Intel Mobile Communications GmbH;
// 2017 Intel Deutschland GmbH; 2018-2026 Intel Corporation.
// Channel flag ABI: include/net/cfg80211.h, Copyright 2006-2010 Johannes Berg.
//! One band's channels under a country's rules, as cfg80211's `handle_band`
//! leaves the channels of a wiphy that starts them unrestricted, followed by
//! `reg_process_ht_flags`. The flags are `ieee80211_channel_flags`.

use super::database::{Country, Rule};
use alloc::vec::Vec;

pub const DISABLED: u32 = 1 << 0;
pub const NO_IR: u32 = 1 << 1;
pub const RADAR: u32 = 1 << 3;
pub const NO_HT40PLUS: u32 = 1 << 4;
pub const NO_HT40MINUS: u32 = 1 << 5;
pub const NO_HT40: u32 = NO_HT40PLUS | NO_HT40MINUS;
pub const NO_OFDM: u32 = 1 << 6;
pub const NO_80MHZ: u32 = 1 << 7;
pub const NO_160MHZ: u32 = 1 << 8;
pub const INDOOR_ONLY: u32 = 1 << 9;
pub const NO_20MHZ: u32 = 1 << 11;
pub const NO_10MHZ: u32 = 1 << 12;
pub const NO_HE: u32 = 1 << 13;
pub const NO_320MHZ: u32 = 1 << 19;
pub const NO_EHT: u32 = 1 << 20;
pub const NO_6GHZ_VLP_CLIENT: u32 = 1 << 22;
pub const NO_6GHZ_AFC_CLIENT: u32 = 1 << 23;

/// A channel's `flags` and `max_reg_power` once its country applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Regulated {
    pub flags: u32,
    /// The rule's EIRP in whole dBm (`MBM_TO_DBM`); zero when disabled.
    pub max_reg_dbm: i32,
}

impl Regulated {
    const DISABLED: Self = Self {
        flags: DISABLED,
        max_reg_dbm: 0,
    };
    /// `is_ht40_allowed`.
    fn ht40(self) -> bool {
        self.flags & DISABLED == 0 && self.flags & NO_HT40 != NO_HT40
    }
}

/// `cfg80211_does_bw_fit_range`.
fn fits(start_khz: u32, end_khz: u32, center_khz: u32, bandwidth_khz: u32) -> bool {
    center_khz
        .checked_sub(bandwidth_khz / 2)
        .is_some_and(|start| start >= start_khz)
        && center_khz + bandwidth_khz / 2 <= end_khz
}

/// `map_regdom_flags` of the restrictions regulatory.db carries.
fn restrictions(rule: &Rule) -> u32 {
    [
        (rule.no_ir, NO_IR),
        (rule.dfs, RADAR),
        (rule.no_ofdm, NO_OFDM),
        (rule.indoor_only, INDOOR_ONLY),
    ]
    .into_iter()
    .filter(|&(set, _)| set)
    .fold(0, |flags, (_, flag)| flags | flag)
}

impl Country {
    /// `freq_reg_info` above 1 GHz: the first rule holding 20 MHz around
    /// `center_khz`, once a rule edge lies within 2 GHz of it.
    fn rule_at(&self, center_khz: u32) -> Option<&Rule> {
        let mut near = false;
        self.rules().iter().find(|r| {
            near |= r.start_khz.abs_diff(center_khz) <= 2_000_000
                || r.end_khz.abs_diff(center_khz) <= 2_000_000;
            near && fits(r.start_khz, r.end_khz, center_khz, 20_000)
        })
    }
    /// `reg_rule_to_chan_bw_flags`.
    fn bandwidth_flags(&self, rule: &Rule, center_khz: u32) -> u32 {
        let max = self.bandwidth(rule).unwrap_or(rule.max_bandwidth_khz);
        let mut flags = 0;
        if !fits(rule.start_khz, rule.end_khz, center_khz, 10_000) || max < 10_000 {
            flags |= NO_10MHZ;
        }
        if !fits(rule.start_khz, rule.end_khz, center_khz, 20_000) || max < 20_000 {
            flags |= NO_20MHZ;
        }
        for (below, flag) in [
            (40_000, NO_HT40),
            (80_000, NO_80MHZ),
            (160_000, NO_160MHZ),
            (320_000, NO_320MHZ),
        ] {
            if max < below {
                flags |= flag;
            }
        }
        flags
    }
    /// The 20 MHz channel at `center_mhz` as `handle_channel` regulates it:
    /// by the one rule holding it, else by two adjacent rules that together
    /// do, else disabled.
    pub fn channel(&self, center_mhz: u16) -> Regulated {
        let khz = u32::from(center_mhz) * 1000;
        let dbm = |rule: &Rule| i32::from(rule.max_eirp_mbm) / 100;
        if let Some(rule) = self.rule_at(khz) {
            return Regulated {
                flags: self.bandwidth_flags(rule, khz) | restrictions(rule),
                max_reg_dbm: dbm(rule),
            };
        }
        let (Some(below), Some(above)) = (
            khz.checked_sub(20_000).and_then(|k| self.rule_at(k)),
            self.rule_at(khz + 20_000),
        ) else {
            return Regulated::DISABLED;
        };
        if below.end_khz != above.start_khz || !fits(below.start_khz, above.end_khz, khz, 20_000) {
            return Regulated::DISABLED;
        }
        let mut flags = self.bandwidth_flags(below, khz)
            | self.bandwidth_flags(above, khz)
            | restrictions(below)
            | restrictions(above);
        // handle_channel_adjacent_rules rechecks what each rule alone forbade.
        if fits(below.start_khz, above.end_khz, khz, 10_000) {
            flags &= !NO_10MHZ;
        }
        flags &= !NO_20MHZ;
        Regulated {
            flags,
            max_reg_dbm: dbm(below).min(dbm(above)),
        }
    }
    /// Every channel of one band, `centers_mhz` in the wiphy's order, with
    /// `reg_process_ht_flags` marking each side whose 20 MHz neighbor is
    /// missing or cannot bond. `None` when the result cannot be allocated.
    pub fn band(&self, centers_mhz: &[u16]) -> Option<Vec<Regulated>> {
        let mut band = Vec::new();
        band.try_reserve_exact(centers_mhz.len()).ok()?;
        band.extend(centers_mhz.iter().map(|&mhz| self.channel(mhz)));
        for (i, &mhz) in centers_mhz.iter().enumerate() {
            if !band[i].ht40() {
                band[i].flags |= NO_HT40;
                continue;
            }
            let bonds = |neighbor: Option<u16>| {
                centers_mhz
                    .iter()
                    .position(|&c| Some(c) == neighbor)
                    .is_some_and(|j| band[j].ht40())
            };
            let (minus, plus) = (bonds(mhz.checked_sub(20)), bonds(mhz.checked_add(20)));
            band[i].flags &= !NO_HT40;
            if !minus {
                band[i].flags |= NO_HT40MINUS;
            }
            if !plus {
                band[i].flags |= NO_HT40PLUS;
            }
        }
        Some(band)
    }
}

#[cfg(test)]
mod tests;
