// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! What the receive path learns of the air, and what rtw88's
//! `rtw_phy_dynamic_mechanism` makes of it: `query_phy_status`, the peer's RSSI,
//! its level among rates, and the gain `rtw_phy_dig` sets against false alarms.

/// `db_invert_table`: rows past the third hold `FRAC_BITS` less, and 62 dB's
/// entry is the driver's own.
const DB_INVERT: [[u32; 8]; 12] = [
    [10, 13, 16, 20, 25, 32, 40, 50],
    [64, 80, 101, 128, 160, 201, 256, 318],
    [401, 505, 635, 800, 1007, 1268, 1596, 2010],
    [316, 398, 501, 631, 794, 1000, 1259, 1585],
    [1995, 2512, 3162, 3981, 5012, 6310, 7943, 10000],
    [12589, 15849, 19953, 25119, 31623, 39811, 50119, 63098],
    [
        79433, 100000, 125893, 158489, 199526, 251189, 316228, 398107,
    ],
    [
        501187, 630957, 794328, 1000000, 1258925, 1584893, 1995262, 2511886,
    ],
    [
        3162278, 3981072, 5011872, 6309573, 7943282, 1000000, 12589254, 15848932,
    ],
    [
        19952623, 25118864, 31622777, 39810717, 50118723, 63095734, 79432823, 100000000,
    ],
    [
        125892541, 158489319, 199526232, 251188643, 316227766, 398107171, 501187234, 630957345,
    ],
    [
        794328235, 1000000000, 1258925412, 1584893192, 1995262315, 2511886432, 3162277660,
        3981071706,
    ],
];
const FRAC_BITS: u32 = 3;

/// `DIG_PERF_*` and `DIG_CVRG_*`, with `rtw8822c_hw_spec.dig_min`.
const LINKED_ALARMS: [u16; 3] = [750, 500, 250];
const LINKED_LOW: u16 = 250;
const LINKED_HIGH: u16 = 500;
const LINKED_MAX: u8 = 0x5a;
const LINKED_MID: u8 = 0x40;
const LINKED_MIN: u8 = 0x20;
const COVERAGE_ALARMS: [u16; 3] = [5000, 4000, 2000];
const COVERAGE_MAX: u8 = 0x2a;
const COVERAGE_MID: u8 = 0x26;
/// `DIG_CVRG_MIN`, where a scan listens widest.
pub const MAX_COVERAGE: u8 = 0x1c;
const RSSI_GAIN_OFFSET: u8 = 15;
/// `DECLARE_EWMA(rssi, 10, 16)`.
const AVERAGE_PRECISION: u32 = 10;
const AVERAGE_WEIGHT: u32 = 4;
/// `rtw_phy_get_rssi_level`'s table and `RA_FLOOR_UP_GAP`.
const LEVELS: [u8; 7] = [20, 34, 38, 42, 46, 50, 100];
const LEVEL_UP_GAP: u8 = 3;
/// `RA_MASK_CCK_RATES` and `RA_MASK_OFDM_RATES`.
const LEGACY_RATES: u64 = 0xfff;
/// `DESC_RATEVHT4SS_MCS0` down to `DESC_RATE1M`, each family's first rate.
const FIRST_RATES: [u8; 10] = [0x4a, 0x40, 0x36, 0x2c, 0x24, 0x1c, 0x14, 0x0c, 0x04, 0];
const FIRST_HT_RATE: u8 = 0x0c;
/// `RRSR_RATE_ORDER_CCK_LEN`.
const CCK_ORDERS: u8 = 4;

/// What a frame's PHY status says of its signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signal {
    /// `pkt_stat->rssi`.
    pub rssi: u8,
    /// `pkt_stat->signal_power`.
    pub power_dbm: i8,
}

fn power_2_db(power: i8) -> u8 {
    if power <= -100 || power >= 20 {
        0
    } else if power >= 0 {
        100
    } else {
        (100 + i16::from(power)) as u8
    }
}

fn db_2_linear(power_db: u8) -> u64 {
    if power_db < 1 {
        return 1;
    }
    let at = usize::from(power_db.min(96) - 1);
    let (row, column) = (at >> 3, at & 7);
    let linear = u64::from(DB_INVERT[row][column]);
    if row > 2 { linear << FRAC_BITS } else { linear }
}

fn linear_2_db(linear: u64) -> u8 {
    let scaled = |row: usize| {
        if row <= 2 {
            linear << FRAC_BITS
        } else {
            linear
        }
    };
    let found = (0..12).find_map(|row| {
        (0..8)
            .find(|&column| scaled(row) <= u64::from(DB_INVERT[row][column]))
            .map(|column| (row, column))
    });
    let Some((mut row, mut column)) = found else {
        return 96;
    };
    let entry = |row: usize, column: usize| u64::from(DB_INVERT[row][column]);
    // Unsigned as the driver's, whose first rows are compared unscaled here.
    let nearer_below =
        |above: u64, below: u64| above.wrapping_sub(linear) > linear.wrapping_sub(below);
    if column > 0 {
        if nearer_below(entry(row, column), entry(row, column - 1)) {
            column -= 1;
        }
    } else if row > 0 && nearer_below(entry(row, 0), entry(row - 1, 7)) {
        row -= 1;
        column = 7;
    }
    ((row << 3) + column + 1) as u8
}

/// `rtw_phy_rf_power_2_rssi`.
fn rssi(power: &[i8]) -> u8 {
    let sum: u64 = power
        .iter()
        .map(|&path| db_2_linear(power_2_db(path)))
        .sum();
    let sum = (sum + (1 << (FRAC_BITS - 1))) >> FRAC_BITS;
    linear_2_db(sum >> (power.len() - 1))
}

/// `query_phy_status` of a frame's driver information, under the upper and
/// lower CCK gains `rtw8822c_phy_cck_pd_set`'s tables left.
pub fn phy_status(info: &[u8], [upper, lower]: [u8; 2]) -> Option<Signal> {
    let bytes = info.first_chunk::<4>()?;
    let word = u32::from_le_bytes(*bytes);
    let reading = |at: u32| (word >> at) as u8 as i8;
    match word & 15 {
        0 => {
            let gain = ((word >> 16) & 0x3f) as u8;
            let power = if gain < lower {
                reading(8).wrapping_add(((lower - gain) << 1) as i8)
            } else if gain > upper {
                reading(8).wrapping_sub(((gain - upper) << 1) as i8)
            } else {
                reading(8)
            };
            let power = power.wrapping_sub(110);
            Some(Signal {
                rssi: rssi(&[power]),
                power_dbm: power.max(-120),
            })
        }
        1 => {
            let paths = [reading(8).wrapping_sub(110), reading(16).wrapping_sub(110)];
            Some(Signal {
                rssi: rssi(&paths),
                power_dbm: paths[0].max(paths[1]).max(-120),
            })
        }
        _ => None,
    }
}

/// `rtw_rate_mask_rssi` and `rtw_rate_mask_recover` of a peer's rates.
pub fn rates_at_level(rates: u64, level: u8, cck_only: bool) -> u64 {
    let allowed = match level {
        _ if cck_only => u64::MAX,
        0 => u64::MAX,
        1 => 0xffff_ffff_ffff_fff0,
        2 => 0xffff_ffff_ffff_efe0,
        3 => 0xffff_ffff_ffff_cfc0,
        4 => 0xffff_ffff_ffff_8f80,
        _ => 0xffff_ffff_ffff_0f00,
    };
    let mut kept = rates & allowed;
    if kept & !LEGACY_RATES == 0 {
        kept |= rates & !LEGACY_RATES;
    }
    if kept == 0 {
        kept |= rates & LEGACY_RATES;
    }
    kept
}

/// `rtw_phy_get_rrsr_mask` of the rate firmware last reported.
pub fn response_rates(rate: u8) -> u32 {
    let first = FIRST_RATES.into_iter().find(|&first| rate >= first);
    let order = rate - first.unwrap_or(0);
    let order = if rate >= FIRST_HT_RATE || order == 0 {
        order + 1
    } else {
        order
    };
    (1 << (order + CCK_ORDERS)) - 1
}

/// `rtw_dm_info`'s RSSI and gain, and the peer's `rtw_sta_info`.
#[derive(Debug)]
pub struct Dynamic {
    /// `si->avg_rssi`, in `AVERAGE_PRECISION` fixed point.
    average: u64,
    level: u8,
    min_rssi: u8,
    previous_min: u8,
    gains: [u8; 4],
    alarms: [u16; 4],
    /// `igi_bitmap`: which of the last changes rose.
    rises: u8,
    damping: bool,
    damping_count: u8,
    damping_rssi: u8,
}

impl Dynamic {
    pub fn new(gains: [u8; 4]) -> Self {
        Self {
            average: 0,
            level: 0,
            min_rssi: 0,
            previous_min: 0,
            gains,
            alarms: [0; 4],
            rises: 0,
            damping: false,
            damping_count: 0,
            damping_rssi: 0,
        }
    }

    /// `ewma_rssi_add`.
    pub fn heard(&mut self, rssi: u8) {
        let value = u64::from(rssi) << AVERAGE_PRECISION;
        self.average = if self.average == 0 {
            value
        } else {
            ((self.average << AVERAGE_WEIGHT) - self.average + value) >> AVERAGE_WEIGHT
        };
    }

    /// `ewma_rssi_read`.
    pub fn rssi(&self) -> u8 {
        (self.average >> AVERAGE_PRECISION) as u8
    }

    /// `si->rssi_level`.
    pub fn level(&self) -> u8 {
        self.level
    }

    pub fn current_gain(&self) -> u8 {
        self.gains[0]
    }

    /// `rtw_phy_stat_rssi` of the peer, or of nobody.
    pub fn sample(&mut self, linked: bool) {
        self.previous_min = self.min_rssi;
        self.min_rssi = if linked {
            let (rssi, old) = (self.rssi(), usize::from(self.level));
            let floor = |at: usize| LEVELS[at] + if at >= old { LEVEL_UP_GAP } else { 0 };
            let level = (0..LEVELS.len()).find(|&at| rssi < floor(at));
            self.level = level.unwrap_or(0) as u8;
            rssi
        } else {
            u8::MAX
        };
    }

    /// A new peer's `ewma_rssi_init`, with its level.
    pub fn forget(&mut self) {
        self.average = 0;
        self.level = 0;
    }

    /// `rtw_phy_dig_check_damping`.
    fn damped(&mut self) -> bool {
        let [g0, g1, g2, g3] = self.gains;
        let [a0, a1, a2, a3] = self.alarms;
        if self.damping {
            let moved = self.min_rssi.abs_diff(self.damping_rssi) > 3;
            let expired = self.damping_count > 20;
            self.damping_count = self.damping_count.saturating_add(1);
            if moved || expired {
                self.damping = false;
                return false;
            }
            return true;
        }
        let swinging = match self.rises & 15 {
            5 => {
                g0 > g1
                    && g2 > g3
                    && g0 - g1 >= 2
                    && g2 - g3 >= 2
                    && a0 > LINKED_HIGH
                    && a1 < LINKED_LOW
                    && a2 > LINKED_HIGH
                    && a3 < LINKED_LOW
            }
            9 => {
                g0 > g1
                    && g3 > g2
                    && g0 - g1 >= 4
                    && g3 - g2 >= 2
                    && a0 > LINKED_HIGH
                    && a1 < LINKED_LOW
                    && a2 < LINKED_LOW
                    && a3 > LINKED_HIGH
            }
            _ => false,
        };
        if swinging {
            self.damping = true;
            self.damping_count = 0;
            self.damping_rssi = self.min_rssi;
        }
        swinging
    }

    /// `rtw_phy_dig`: the gain to write after `alarms` false alarms, if it moved.
    pub fn gain(&mut self, alarms: u16, linked: bool) -> Option<u8> {
        if self.damped() {
            return None;
        }
        let previous = self.gains[0];
        let (thresholds, steps) = match linked {
            true if self.previous_min > self.min_rssi => (LINKED_ALARMS, [6, 4, 2]),
            true => (LINKED_ALARMS, [4, 3, 2]),
            false => (COVERAGE_ALARMS, [4, 3, 2]),
        };
        let step = thresholds
            .into_iter()
            .zip(steps)
            .find_map(|(threshold, step)| (alarms > threshold).then_some(step))
            .unwrap_or(0);
        let (max, mid, min, floor) = if linked {
            let floor = self.min_rssi.max(LINKED_MIN);
            (LINKED_MAX, LINKED_MID, LINKED_MIN, floor)
        } else {
            (COVERAGE_MAX, COVERAGE_MID, MAX_COVERAGE, MAX_COVERAGE)
        };
        let max = max.min(floor.saturating_add(RSSI_GAIN_OFFSET));
        let lower = floor.clamp(min, mid);
        let upper = (lower + RSSI_GAIN_OFFSET).clamp(min, max);
        // Each step stands two above its meaning, so a quiet channel falls.
        let gain = previous
            .wrapping_add(step)
            .wrapping_sub(2)
            .clamp(lower, upper);
        self.rises = (self.rises << 1) | u8::from(gain > previous);
        self.gains = [gain, self.gains[0], self.gains[1], self.gains[2]];
        self.alarms = [alarms, self.alarms[0], self.alarms[1], self.alarms[2]];
        (gain != previous).then_some(gain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_paths_power_comes_back_as_its_own_rssi() {
        assert_eq!(rssi(&[-50]), 50);
        assert_eq!(rssi(&[-90]), 10);
        assert_eq!(rssi(&[-100]), 1);
        assert_eq!(rssi(&[-60, -60]), 40);
    }

    #[test]
    fn a_cck_frame_corrects_its_power_by_the_gain_outside_its_bounds() {
        let mut info = [0; 4];
        // Page 0, power 70, gain 10 under a lower bound of 12.
        info[1] = 70;
        info[2] = 10;
        let signal = phy_status(&info, [30, 12]).unwrap();
        assert_eq!(signal.power_dbm, 70 + 4 - 110);
        assert_eq!(signal.rssi, 64);
        // Gain 34 over an upper bound of 30.
        info[2] = 34;
        assert_eq!(phy_status(&info, [30, 12]).unwrap().power_dbm, 70 - 8 - 110);
    }

    #[test]
    fn an_ofdm_frame_takes_the_stronger_path_and_other_pages_say_nothing() {
        let mut info = [0; 4];
        info[0] = 1;
        info[1] = 60;
        info[2] = 70;
        assert_eq!(phy_status(&info, [0, 0]).unwrap().power_dbm, -40);
        info[0] = 2;
        assert_eq!(phy_status(&info, [0, 0]), None);
        assert_eq!(phy_status(&[1, 2], [0, 0]), None);
    }

    #[test]
    fn the_average_starts_at_the_first_frame_and_follows_by_sixteenths() {
        let mut dynamic = Dynamic::new([0x2a; 4]);
        dynamic.heard(50);
        assert_eq!(dynamic.rssi(), 50);
        dynamic.heard(66);
        assert_eq!(dynamic.rssi(), 51);
        dynamic.forget();
        assert_eq!(dynamic.rssi(), 0);
    }

    #[test]
    fn a_level_rises_past_its_gap_and_falls_at_its_floor() {
        let mut dynamic = Dynamic::new([0x2a; 4]);
        dynamic.heard(36);
        dynamic.sample(true);
        // Level 0 asks three over each floor: 36 is under 34 + 3 at index 1.
        assert_eq!(dynamic.level(), 1);
        dynamic.heard(0xff);
        for _ in 0..40 {
            dynamic.heard(60);
        }
        dynamic.sample(true);
        assert_eq!(dynamic.level(), 6);
        dynamic.forget();
        assert_eq!(dynamic.level(), 0);
    }

    #[test]
    fn a_level_keeps_some_rates_whatever_it_would_drop() {
        assert_eq!(rates_at_level(0xf_f15f, 0, false), 0xf_f15f);
        assert_eq!(rates_at_level(0xf_f15f, 5, false), 0xf_0100);
        // CCK alone is left whole, and legacy returns when nothing else stood.
        assert_eq!(rates_at_level(0xf, 5, true), 0xf);
        assert_eq!(rates_at_level(0x15, 5, false), 0x15);
    }

    #[test]
    fn responses_keep_to_the_rates_of_the_data_they_answer() {
        assert_eq!(response_rates(0), 0x1f);
        // 11 Mb/s is order three within CCK.
        assert_eq!(response_rates(3), 0x7f);
        // 6 Mb/s opens OFDM's order.
        assert_eq!(response_rates(4), 0x1f);
        assert_eq!(response_rates(0x0c), 0x1f);
        // MCS7 and VHT MCS9 of one stream.
        assert_eq!(response_rates(0x13), 0xfff);
        assert_eq!(response_rates(0x35), 0x3fff);
    }

    #[test]
    fn false_alarms_raise_the_gain_within_what_the_peers_signal_allows() {
        let mut dynamic = Dynamic::new([0x30; 4]);
        dynamic.heard(0x30);
        dynamic.sample(true);
        assert_eq!(dynamic.gain(800, true), Some(0x32));
        assert_eq!(dynamic.gain(0, true), Some(0x30));
        let mut dynamic = Dynamic::new([0x60; 4]);
        dynamic.heard(10);
        dynamic.sample(true);
        assert_eq!(dynamic.gain(0, true), Some(0x2f));
    }

    #[test]
    fn unlinked_gain_stays_in_the_coverage_range() {
        let mut dynamic = Dynamic::new([0x20; 4]);
        dynamic.sample(false);
        assert_eq!(dynamic.gain(6000, false), Some(0x22));
        for _ in 0..8 {
            dynamic.gain(0, false);
        }
        assert_eq!(dynamic.current_gain(), MAX_COVERAGE);
    }

    #[test]
    fn a_gain_swinging_with_its_alarms_is_left_alone_until_the_signal_moves() {
        let mut dynamic = Dynamic::new([0x24; 4]);
        dynamic.heard(0x24);
        dynamic.sample(true);
        dynamic.rises = 5;
        dynamic.gains = [0x28, 0x24, 0x28, 0x24];
        dynamic.alarms = [600, 100, 600, 100];
        assert_eq!(dynamic.gain(800, true), None);
        assert_eq!(dynamic.gain(800, true), None);
        for _ in 0..3 {
            dynamic.heard(100);
        }
        dynamic.sample(true);
        assert!(dynamic.gain(800, true).is_some());
    }
}
