// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2024-2026 Intel Corporation
//! `iwl_mld_get_link_grade`: what a link is worth from its signal, width,
//! load and puncturing.
use super::*;

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
/// `SCALE_FACTOR`, against which a channel's load runs.
const SCALE: u32 = 256;

/// `iwl_mld_get_chan_load`: the BSS Load element's channel utilization, or
/// the band's default. `by_us` is the percent the station's own frames take
/// of the element's load; a count past the element's own is ignored.
fn load(band: Band, elements: &[u8], by_us: u32) -> u32 {
    if let Some([_, _, utilization, _, _]) = crate::wifi::connection::find(elements, BSS_LOAD) {
        let load = u32::from(*utilization);
        let by_us = by_us * SCALE / 100;
        return if by_us <= load { load - by_us } else { load };
    }
    let percent = match band {
        Band::Ghz2 => 30,
        Band::Ghz5 => 15,
        Band::Ghz6 => 0,
    };
    percent * SCALE / 100
}

/// Whether `elements` say how loaded the channel is.
pub(super) fn reports_load(elements: &[u8]) -> bool {
    crate::wifi::connection::find(elements, BSS_LOAD).is_some_and(|load| load.len() == 5)
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
