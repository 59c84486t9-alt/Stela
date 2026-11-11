// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! What the rate firmware reports is worth: `cfg80211_calculate_bitrate` of
//! `rtw_fw_ra_report_iter`'s `rate_info`, in units of 100 kbps, and the
//! A-MSDU `get_max_amsdu_len` lets it carry.

/// `rtw_ratetable`, of `DESC_RATE1M` up to `DESC_RATE54M`.
const LEGACY: [u32; 12] = [10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540];
/// `DESC_RATEMCS0`, `DESC_RATEVHT1SS_MCS0`, and how far one VHT stream count
/// lies from the next.
const MCS0: u8 = 0x0c;
const VHT_MCS0: u8 = 0x2c;
const VHT_MCS_COUNT: u8 = 10;
const VHT_STREAMS: u8 = 4;
/// `cfg80211_calculate_bitrate_vht`'s table, of 20, 40 and 80 MHz.
const VHT: [[u32; VHT_MCS_COUNT as usize]; 3] = [
    [
        6_500_000, 13_000_000, 19_500_000, 26_000_000, 39_000_000, 52_000_000, 58_500_000,
        65_000_000, 78_000_000, 86_700_000,
    ],
    [
        13_500_000,
        27_000_000,
        40_500_000,
        54_000_000,
        81_000_000,
        108_000_000,
        121_500_000,
        135_000_000,
        162_000_000,
        180_000_000,
    ],
    [
        29_300_000,
        58_500_000,
        87_800_000,
        117_000_000,
        175_500_000,
        234_000_000,
        263_300_000,
        292_500_000,
        351_000_000,
        390_000_000,
    ],
];

/// The rounding both of cfg80211's formulas end on, past the short guard
/// interval's tenth.
fn in_units(bits: u32, short_gi: bool) -> u32 {
    let bits = if short_gi { (bits / 9) * 10 } else { bits };
    (bits + 50_000) / 100_000
}

/// `cfg80211_calculate_bitrate_ht`.
fn ht(mcs: u8, short_gi: bool, width: u8) -> u32 {
    let modulation = u32::from(mcs & 7);
    let streams = u32::from(mcs >> 3) + 1;
    let base = if width == 1 { 13_500_000 } else { 6_500_000 };
    let factor = match modulation {
        0..4 => modulation + 1,
        4 => modulation + 2,
        _ => modulation + 3,
    };
    in_units(base * factor * streams, short_gi)
}

/// A rate as firmware names it, sent `width` wide as `rtw_fw_ra_report_iter`
/// reads it: 0 for 20 MHz, 1 for 40 and 2 for 80. Zero for no such rate.
pub fn bit_rate(rate: u8, short_gi: bool, width: u8) -> u32 {
    if let Some(&legacy) = LEGACY.get(usize::from(rate)) {
        return legacy;
    }
    if rate < VHT_MCS0 {
        return ht(rate - MCS0, short_gi, width);
    }
    let index = rate - VHT_MCS0;
    let (streams, mcs) = (index / VHT_MCS_COUNT, index % VHT_MCS_COUNT);
    match VHT.get(usize::from(width)) {
        Some(rates) if streams < VHT_STREAMS => {
            in_units(rates[usize::from(mcs)] * (u32::from(streams) + 1), short_gi)
        }
        _ => 0,
    }
}

/// `get_max_amsdu_len`: the bytes an A-MSDU may take at `bit_rate`, where 1
/// lets no two frames join and 0 sets no limit.
pub fn max_amsdu(bit_rate: u32) -> u16 {
    match bit_rate {
        0..550 => 1,
        550..1800 => 1200,
        1800..4000 => 2600,
        4000..7000 => 3500,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_rates_come_from_the_table() {
        assert_eq!(bit_rate(0, false, 0), 10);
        assert_eq!(
            bit_rate(2, true, 1),
            55,
            "no guard interval or width applies"
        );
        assert_eq!(bit_rate(11, false, 0), 540);
    }

    #[test]
    fn ht_rates_follow_modulation_streams_width_and_guard() {
        assert_eq!(bit_rate(MCS0, false, 0), 65);
        assert_eq!(bit_rate(MCS0 + 7, false, 0), 650);
        assert_eq!(bit_rate(MCS0 + 7, true, 0), 722);
        assert_eq!(bit_rate(MCS0 + 15, false, 1), 2700);
        assert_eq!(bit_rate(MCS0 + 15, true, 1), 3000);
    }

    #[test]
    fn vht_rates_multiply_by_stream() {
        assert_eq!(bit_rate(VHT_MCS0, false, 0), 65);
        assert_eq!(bit_rate(VHT_MCS0 + 9, false, 2), 3900);
        assert_eq!(bit_rate(VHT_MCS0 + 19, false, 2), 7800);
        assert_eq!(bit_rate(VHT_MCS0 + 19, true, 2), 8667);
        assert_eq!(bit_rate(VHT_MCS0, false, 3), 0, "a width cfg80211 warns of");
    }

    #[test]
    fn each_rate_tier_bounds_an_amsdu() {
        assert_eq!(max_amsdu(0), 1);
        assert_eq!(max_amsdu(549), 1);
        assert_eq!(max_amsdu(550), 1200);
        assert_eq!(max_amsdu(1800), 2600);
        assert_eq!(max_amsdu(4000), 3500);
        assert_eq!(max_amsdu(7000), 0);
    }
}
