// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2024-2026 Intel Corporation
//! `iwl_mld_get_link_grade`: what a link is worth from its signal, width,
//! load and puncturing.
use super::*;
use crate::wifi::station::operations::mhz;

/// A signal in the 2.4 GHz and other bands' columns, and its grade.
type Line = (i8, i8, u32);

/// One band column for both.
const fn same<const N: usize>(lines: [(i8, u32); N]) -> [Line; N] {
    let mut table = [(0, 0, 0); N];
    let mut at = 0;
    while at < N {
        table[at] = (lines[at].0, lines[at].0, lines[at].1);
        at += 1;
    }
    table
}

const GRADES_20: [Line; 15] = [
    (-94, -95, 9),
    (-92, -93, 17),
    (-90, -90, 34),
    (-87, -87, 52),
    (-83, -84, 69),
    (-79, -80, 103),
    (-75, -75, 137),
    (-72, -73, 155),
    (-70, -71, 172),
    (-67, -68, 206),
    (-64, -65, 230),
    (-59, -60, 258),
    (-57, -58, 287),
    (-52, -53, 310),
    (-50, -50, 345),
];
const GRADES_40: [Line; 17] = [
    (-95, -95, 9),
    (-93, -93, 17),
    (-91, -92, 18),
    (-89, -90, 34),
    (-87, -87, 68),
    (-84, -84, 104),
    (-80, -81, 138),
    (-77, -77, 206),
    (-72, -72, 274),
    (-69, -70, 310),
    (-67, -68, 344),
    (-64, -65, 412),
    (-61, -62, 460),
    (-56, -57, 516),
    (-54, -55, 574),
    (-49, -50, 620),
    (-46, -47, 690),
];
const GRADES_80: [Line; 19] = same([
    (-95, 9),
    (-93, 17),
    (-92, 18),
    (-90, 34),
    (-89, 36),
    (-87, 68),
    (-83, 136),
    (-80, 208),
    (-77, 276),
    (-74, 412),
    (-69, 548),
    (-67, 620),
    (-66, 688),
    (-61, 824),
    (-59, 920),
    (-54, 1032),
    (-52, 1148),
    (-47, 1240),
    (-44, 1380),
]);
const GRADES_160: [Line; 21] = same([
    (-95, 9),
    (-93, 17),
    (-92, 18),
    (-90, 34),
    (-89, 36),
    (-87, 68),
    (-86, 72),
    (-84, 136),
    (-81, 272),
    (-78, 416),
    (-75, 552),
    (-71, 824),
    (-67, 1096),
    (-65, 1240),
    (-63, 1376),
    (-59, 1648),
    (-57, 1840),
    (-52, 2064),
    (-50, 2296),
    (-46, 2480),
    (-42, 2760),
]);
const GRADES_320: [Line; 23] = same([
    (-95, 9),
    (-93, 17),
    (-92, 18),
    (-90, 34),
    (-89, 36),
    (-87, 68),
    (-86, 72),
    (-84, 136),
    (-83, 144),
    (-81, 272),
    (-78, 544),
    (-75, 832),
    (-72, 1104),
    (-69, 1648),
    (-64, 2192),
    (-62, 2480),
    (-61, 2752),
    (-57, 3296),
    (-55, 3680),
    (-50, 4128),
    (-47, 4592),
    (-43, 4960),
    (-40, 5520),
]);

/// `WLAN_EID_QBSS_LOAD`.
const BSS_LOAD: u8 = 11;
/// `IEEE80211_HE_6GHZ_OPER_CTRL_DUP_BEACON`.
const DUPLICATE_BEACON: u8 = 4;
/// `IEEE80211_6GHZ_CTRL_REG_VLP_AP`.
const VERY_LOW_POWER: u8 = 2;
/// How far `iwl_mld_get_link_grade` trusts a 6 GHz beacon to understate data.
const DEFAULT_GAIN: i8 = 4;
/// `SCALE_FACTOR`, against which a channel's load runs.
pub(super) const SCALE: u32 = 256;

/// `iwl_mld_get_dup_beacon_rssi_adjust`: an AP that duplicates its beacons
/// across `width` is that much louder in data.
fn duplicate_beacon_gain(control: u8, width: phy::Width) -> i8 {
    if control & DUPLICATE_BEACON == 0 {
        return 0;
    }
    match width {
        phy::Width::Mhz40 => 3,
        phy::Width::Mhz80 => 6,
        phy::Width::Mhz160 => 9,
        phy::Width::Mhz320 => 12,
        phy::Width::Mhz20 | phy::Width::Mhz80P80 => 0,
    }
}

/// `iwl_mld_get_psd_eirp_rssi_adjust`: how much more an AP limited by
/// `envelope` may send across all of `definition` than on 20 MHz.
fn envelope_gain(envelope: &PowerEnvelope, definition: &ChannelDefinition, very_low: bool) -> i8 {
    let width = mhz(definition.width);
    let index = match width {
        20 => 0,
        40 => 1,
        80 => 2,
        160 => 3,
        320 => 4,
        _ => return 0,
    };
    let ap = if very_low { 14 } else { 23 };
    let (psd_local, psd_client) = (&envelope.psd_local[0], &envelope.psd_client[0]);
    let (eirp_local, eirp_client) = (&envelope.max_local[0], &envelope.max_client[0]);
    let psd_narrow = psd_local
        .primary(definition)
        .min(psd_client.primary(definition));
    let eirp_narrow = eirp_local.limit(0).min(eirp_client.limit(0));
    let subchannels = (width / 20) as usize;
    let psd_wide = psd_local
        .mean(subchannels)
        .min(psd_client.mean(subchannels));
    let eirp_wide = eirp_local.limit(index).min(eirp_client.limit(index));
    let narrow = ap.min(eirp_narrow).min(psd_narrow);
    // 10 log10(subchannels), as 3 for each doubling.
    let boost = 3 * subchannels.ilog2() as i8;
    let wide = ap.min(eirp_wide).min(psd_wide.saturating_add(boost));
    wide.saturating_sub(narrow).max(0)
}

/// `iwl_mld_get_link_grade`: on 6 GHz the signal of an AP's beacons, heard at
/// `signal` with `elements`, is below that of its data on `definition`.
pub(super) fn data_signal(signal: i8, elements: &[u8], definition: &ChannelDefinition) -> i8 {
    if definition.control.band != Band::Ghz6 || signal == 0 {
        return signal;
    }
    let operations = Operations::parse(elements).ok();
    let operations = operations.as_ref();
    let control = operations
        .and_then(|operations| operations.he.as_ref()?.six_ghz)
        .map(|six| six[1]);
    let mut gain = duplicate_beacon_gain(control.unwrap_or(0), definition.width);
    if gain == 0 {
        let channel = definition.control;
        let ap = operations.and_then(|operations| {
            let eht = operations.channel(channel, phy::Mode::Eht, None);
            eht.or_else(|_| operations.channel(channel, phy::Mode::He, None))
                .ok()
        });
        let mut envelope = PowerEnvelope::parse(elements);
        match ap {
            Some(ap) => envelope.fit(&ap, definition),
            None => envelope = PowerEnvelope::none(),
        }
        let very_low = control.is_some_and(|control| (control & 0x78) >> 3 == VERY_LOW_POWER);
        gain = envelope_gain(&envelope, definition, very_low);
    }
    signal.saturating_add(if gain == 0 { DEFAULT_GAIN } else { gain })
}

/// `iwl_mld_get_chan_load`: the BSS Load element's channel utilization, or
/// the band's default. `by_us` is the percent the station's own frames take
/// of the element's load; a count past the element's own is ignored.
pub(super) fn load(band: Band, elements: &[u8], by_us: u32) -> u32 {
    if let Some(load) = load_by_others(elements, by_us) {
        return load;
    }
    let percent = match band {
        Band::Ghz2 => 30,
        Band::Ghz5 => 15,
        Band::Ghz6 => 0,
    };
    percent * SCALE / 100
}

/// `iwl_mld_get_chan_load_by_others`: what `elements` say of the channel's
/// load, without the `by_us` percent that is the station's.
pub(super) fn load_by_others(elements: &[u8], by_us: u32) -> Option<u32> {
    let &[_, _, utilization, _, _] = crate::wifi::connection::find(elements, BSS_LOAD)? else {
        return None;
    };
    let load = u32::from(utilization);
    let by_us = by_us * SCALE / 100;
    Some(if by_us <= load { load - by_us } else { load })
}

/// The grade of a link of `width` with `punctured` subchannels, heard at
/// `signal` on `band` with `elements`, `by_us` percent of its air the
/// station's own. 80+80 MHz has none, because no Intel link runs it.
pub(super) fn grade(
    band: Band,
    signal: Option<i8>,
    elements: &[u8],
    width: phy::Width,
    punctured: u16,
    by_us: u32,
) -> Option<u32> {
    let table: &[Line] = match width {
        phy::Width::Mhz20 => &GRADES_20,
        phy::Width::Mhz40 => &GRADES_40,
        phy::Width::Mhz80 => &GRADES_80,
        phy::Width::Mhz160 => &GRADES_160,
        phy::Width::Mhz320 => &GRADES_320,
        phy::Width::Mhz80P80 => return None,
    };
    let column = |line: &Line| {
        if band == Band::Ghz2 { line.0 } else { line.1 }
    };
    let signal = signal
        .filter(|&signal| signal != 0)
        .unwrap_or_else(|| column(&table[0]));
    let top = table[table.len() - 1].2;
    let graded = table
        .iter()
        .find(|line| signal <= column(line))
        .map_or(top, |line| line.2);
    let graded = graded * (SCALE - load(band, elements, by_us)) / SCALE;
    // `iwl_mld_apply_puncturing_penalty`.
    let subchannels: u32 = match width {
        phy::Width::Mhz80 => 4,
        phy::Width::Mhz160 => 8,
        phy::Width::Mhz320 => 16,
        _ => return Some(graded),
    };
    Some(graded * subchannels.saturating_sub(punctured.count_ones()) / subchannels)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOW: Band = Band::Ghz2;
    const HIGH: Band = Band::Ghz5;

    /// An HE operation with 6 GHz information of `control`, 80 MHz at
    /// channel 7.
    fn six_ghz(control: u8) -> Vec<u8> {
        alloc::vec![255, 12, 36, 0, 0, 2, 0, 0xfc, 0xff, 1, 2 | control, 7, 0, 6]
    }

    fn eighty(band: Band) -> ChannelDefinition {
        ChannelDefinition {
            control: Channel {
                band,
                number: 1,
                frequency_mhz: 5955,
            },
            width: phy::Width::Mhz80,
            center1_mhz: 5985,
            center2_mhz: None,
            punctured: 0,
        }
    }

    #[test]
    fn a_6_ghz_beacon_understates_data_by_its_duplicates_or_its_envelope() {
        let definition = eighty(Band::Ghz6);
        assert_eq!(data_signal(-60, &[], &definition), -56, "the default");
        assert_eq!(data_signal(0, &[], &definition), 0, "no measurement");
        assert_eq!(data_signal(-60, &[], &eighty(HIGH)), -60);
        assert_eq!(
            data_signal(-60, &six_ghz(DUPLICATE_BEACON), &definition),
            -54
        );
        // 10 dBm/MHz on each of four subchannels gives 6 dB more over 80 MHz.
        let mut limited = six_ghz(0);
        limited.extend([195, 5, 3 | 1 << 3, 20, 20, 20, 20]);
        assert_eq!(data_signal(-60, &limited, &definition), -54);
        // A very low power AP has no more than 14 dBm to spread.
        let mut low = six_ghz(VERY_LOW_POWER << 3);
        low.extend([195, 5, 3 | 1 << 3, 24, 24, 24, 24]);
        assert_eq!(data_signal(-60, &low, &definition), -58);
    }

    #[test]
    fn a_link_is_graded_by_its_signal_width_load_and_puncturing() {
        use phy::Width::{Mhz20, Mhz80, Mhz80P80};
        // -72 dBm is 155 at 20 MHz in 2.4 GHz, with its default 30% load.
        assert_eq!(
            grade(LOW, Some(-72), &[], Mhz20, 0, 0),
            Some(155 * 180 / 256)
        );
        // The other bands' column, and their 15% load.
        assert_eq!(
            grade(HIGH, Some(-72), &[], Mhz20, 0, 0),
            Some(172 * 218 / 256)
        );
        // Better than the table's last line is the last line.
        assert_eq!(
            grade(HIGH, Some(-30), &[], Mhz80, 0, 0),
            Some(1380 * 218 / 256)
        );
        // No signal is the lowest line.
        assert_eq!(grade(HIGH, None, &[], Mhz20, 0, 0), Some(9 * 218 / 256));
        // The element replaces the default; a quarter of 80 MHz is punctured.
        let loaded = [11, 5, 0, 0, 128, 0, 0];
        assert_eq!(grade(HIGH, Some(-30), &loaded, Mhz20, 0, 0), Some(345 / 2));
        assert_eq!(
            grade(HIGH, Some(-30), &loaded, Mhz80, 0b10, 0),
            Some(690 * 3 / 4)
        );
        assert_eq!(grade(HIGH, Some(-30), &loaded, Mhz80P80, 0, 0), None);
        // The station's own quarter leaves a quarter for others, unless
        // firmware counts more of it than the AP does.
        assert_eq!(
            grade(HIGH, Some(-30), &loaded, Mhz20, 0, 25),
            Some(345 * 192 / 256)
        );
        assert_eq!(grade(HIGH, Some(-30), &loaded, Mhz20, 0, 90), Some(345 / 2));
    }
}
