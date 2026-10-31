// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2024-2026 Intel Corporation
//! `iwl_mld_handle_stats_oper_notif`: what firmware reports every 5 s of an MLD
//! association says when to look for a better link, how long a scan may stay
//! away, and how much of the link's load is the station's own.
use super::*;

pub(super) const OPERATIONAL_NOTIFICATION: (u8, u8) = (0x00, 0x10);
/// `IWL_MLD_LOW_RSSI_MLO_SCAN_THRESH`, and `IWL_MLD_LOW_RSSI_THRESH_*` of EMLSR.
const LOW_SIGNAL_DBM: i32 = -72;
/// `IWL_MLD_EXIT_EMLSR_CHAN_LOAD`, of 256.
const LOAD_TOO_LOW: u32 = 2 * 256 / 100;
/// The loads whose crossing makes EMLSR worth another look, with the width's.
const LOADS_WORTH_A_LOOK: [u32; 3] = [25, 40, 50];
/// `IWL_FW_MAX_LINKS` of `iwl_stats_ntfy_per_link`, after the time stamp.
const LINKS: usize = 4 * 28;
const LINK_BYTES: usize = 28;
/// `iwl_stats_ntfy_per_phy`, and its first version without coexistence.
const PHY_BYTES: usize = 104;
const PHY_BYTES_V3: usize = 88;
/// `IWL_STATS_MAX_PHY_OPERATIONAL`.
const PHYS: usize = 3;
/// `IWL_STATS_UNKNOWN_CHANNEL_LOAD`.
const UNKNOWN_LOAD: u32 = u32::MAX;
/// `IWL_MLD_TRAFFIC_LOAD_MEDIUM_THRESH` and `_HIGH_THRESH`.
const MEDIUM_TRAFFIC: u64 = 10;
const HIGH_TRAFFIC: u64 = 50;
/// `IWL_MLD_TRAFFIC_LOAD_MIN_WINDOW_USEC`.
const SHORTEST_WINDOW_US: u32 = 500_000;
/// `link_chan_load_thresh_tbl`: the percent each level rises at and falls
/// below.
const LOAD_LEVELS: [(u32, u32); 3] = [(45, 40), (70, 65), (85, 80)];

/// What firmware says of one seat's link and PHY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SeatReport {
    signal: i32,
    air_us: u32,
    load_by_us: u32,
    load_not_by_us: u32,
}

/// One report of the seats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Report {
    stamp: u32,
    seats: [SeatReport; 2],
}

impl Report {
    /// `iwl_system_statistics_notif_oper` of `version`.
    fn parse(raw: &[u8], version: u8) -> Option<Self> {
        let word = |at: usize| {
            raw.get(at..at + 4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        };
        let phy_bytes = if version >= 4 {
            PHY_BYTES
        } else {
            PHY_BYTES_V3
        };
        // The stations follow the PHYs: the whole report arrived.
        word(4 + LINKS + PHYS * phy_bytes)?;
        let seat = |seat: usize| {
            let link = 4 + seat * LINK_BYTES;
            let phy = 4 + LINKS + seat * phy_bytes;
            Some(SeatReport {
                signal: (word(link)? as i32).wrapping_neg(),
                air_us: word(link + 4)?,
                load_by_us: word(phy + 4)?,
                load_not_by_us: word(phy + 8)?,
            })
        };
        Some(Self {
            stamp: word(0)?,
            seats: [seat(0)?, seat(1)?],
        })
    }
}

/// What the reports of one association add up to.
#[derive(Default)]
pub(super) struct Statistics {
    /// Whether firmware reports.
    watched: bool,
    /// `last_stats_ts_usec`.
    stamp: u32,
    pub(super) traffic: boot::Ax200ScanTraffic,
    /// `channel_load_by_us` of each seat's PHY.
    pub(super) load_by_us: [u32; 2],
    /// `avg_channel_load_not_by_us` of each seat's PHY.
    pub(super) load_not_by_us: [u32; 2],
    /// `chan_load_lvl`.
    level: usize,
}

impl Statistics {
    /// `iwl_mld_stats_recalc_traffic_load`.
    fn count_traffic(&mut self, air_us: u32, stamp: u32) {
        if self.stamp != 0 {
            let elapsed = stamp.wrapping_sub(self.stamp);
            let percent = if elapsed < SHORTEST_WINDOW_US {
                0
            } else {
                100 * u64::from(air_us) / u64::from(elapsed)
            };
            self.traffic = match percent {
                percent if percent > HIGH_TRAFFIC => boot::Ax200ScanTraffic::High,
                percent if percent > MEDIUM_TRAFFIC => boot::Ax200ScanTraffic::Medium,
                _ => boot::Ax200ScanTraffic::Low,
            };
        }
        self.stamp = stamp;
    }

    /// `iwl_mld_chan_load_requires_scan`: whether `load` is a level up. A
    /// level falls only below its lower limit, so a load between the two
    /// neither rises nor falls.
    fn load_rises(&mut self, load: u32) -> bool {
        let level = (1..=LOAD_LEVELS.len())
            .rev()
            .find(|&level| {
                let (high, low) = LOAD_LEVELS[level - 1];
                load >= high || (load >= low && self.level >= level)
            })
            .unwrap_or(0);
        let rises = level > self.level;
        self.level = level;
        rises
    }

    /// Seat `seat` emptied: what its PHY counted went with it.
    pub(super) fn seat_emptied(&mut self, seat: u8) {
        self.load_by_us[usize::from(seat)] = 0;
        self.load_not_by_us[usize::from(seat)] = 0;
        self.level = 0;
    }
}

impl Client {
    /// `iwl_mld_vif_cfg_changed_sta`: clean counters, then a report every 5 s.
    pub(super) fn watch_statistics(&mut self) {
        self.statistics.watched = true;
        self.command(commands::SYSTEM_STATISTICS, commands::clear_statistics());
        self.command(
            commands::SYSTEM_STATISTICS,
            commands::periodic_statistics(true),
        );
    }

    /// The association ends, and the reports with it.
    pub(super) fn stop_statistics(&mut self) {
        if core::mem::take(&mut self.statistics.watched) {
            self.command(
                commands::SYSTEM_STATISTICS,
                commands::periodic_statistics(false),
            );
        }
    }

    /// What the AP of `seat`'s link last said of itself: without a load
    /// element the links grade on defaults, and a scan would change nothing.
    fn heard_elements(&self, seat: u8) -> Option<&[u8]> {
        let active = self.context_at(seat)?;
        self.observed
            .iter()
            .find(|heard| heard.observation.bss().bssid == active.bssid())
            .map(|heard| &heard.observation.bss().elements[..])
    }

    /// `iwl_mld_update_link_sig`: 0 is no measurement. EMLSR gives up a link
    /// this weak; otherwise it is time to look at the other.
    fn seat_heard(&mut self, seat: u8, signal: i32, now: u64) {
        if signal == 0 || signal >= LOW_SIGNAL_DBM {
            return;
        }
        if self.emlsr.active {
            self.emlsr.ask_exit(emlsr::Exit::LowSignal, 1 - seat);
        } else {
            self.ask_link_scan(now);
        }
    }

    /// `iwl_mld_fill_chanctx_stats` and `iwl_mld_chan_load_update_iter`.
    fn seat_measured(&mut self, seat: u8, report: &SeatReport, now: u64) {
        let (at, primary) = (usize::from(seat), seat == self.seat);
        let old = self.statistics.load_not_by_us[at];
        self.statistics.load_by_us[at] = report.load_by_us;
        if report.load_not_by_us != UNKNOWN_LOAD {
            if report.load_not_by_us > 100 {
                self.unsupported("a channel load past 100%");
                return;
            }
            self.statistics.load_not_by_us[at] = (report.load_not_by_us >> 1) + (old >> 1);
        }
        let load = self.statistics.load_not_by_us[at];
        let elements = self.heard_elements(seat).unwrap_or_default();
        let by_others = grade::load_by_others(elements, report.load_by_us);
        if !primary {
            return;
        }
        if by_others.is_some() && self.statistics.load_rises(load) {
            self.ask_link_scan(now);
        }
        if self.emlsr.active {
            if by_others.is_some_and(|load| load < LOAD_TOO_LOW) {
                self.emlsr.ask_exit(emlsr::Exit::ChannelLoad, seat);
            }
            return;
        }
        let Some(active) = &self.context else {
            return;
        };
        let lowest = emlsr::lowest_load(active.definition().width);
        let crossed = |level: u32| old <= level && load > level;
        if crossed(lowest) || LOADS_WORTH_A_LOOK.into_iter().any(crossed) {
            self.retry_emlsr(now);
        }
    }

    /// `iwl_mld_process_per_link_stats`, then `iwl_mld_process_per_phy_stats`,
    /// for one report.
    pub(super) fn statistics_arrived(&mut self, raw: &[u8], version: u8, now: u64) {
        if !self.statistics.watched {
            return;
        }
        let Some(report) = Report::parse(raw, version) else {
            self.unsupported("a short statistics report");
            return;
        };
        let primary = self.seat;
        let second = self.emlsr.active.then_some(1 - primary);
        let seats = core::iter::once(primary).chain(second);
        let air_us = seats
            .clone()
            .map(|seat| report.seats[usize::from(seat)].air_us)
            .fold(0, u32::wrapping_add);
        self.statistics.count_traffic(air_us, report.stamp);
        for seat in seats.clone() {
            self.seat_heard(seat, report.seats[usize::from(seat)].signal, now);
        }
        for seat in seats {
            self.seat_measured(seat, &report.seats[usize::from(seat)], now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boot::Ax200ScanTraffic::{High, Low, Medium};

    fn raw(version: u8, seat: usize) -> Vec<u8> {
        let phy = if version >= 4 {
            PHY_BYTES
        } else {
            PHY_BYTES_V3
        };
        let mut raw = vec![0; 4 + LINKS + PHYS * phy + 16 * 4];
        raw[..4].copy_from_slice(&7u32.to_le_bytes());
        let link = 4 + seat * LINK_BYTES;
        raw[link..link + 4].copy_from_slice(&80u32.to_le_bytes());
        raw[link + 4..link + 8].copy_from_slice(&9u32.to_le_bytes());
        let at = 4 + LINKS + seat * phy;
        raw[at + 4..at + 8].copy_from_slice(&5u32.to_le_bytes());
        raw[at + 8..at + 12].copy_from_slice(&60u32.to_le_bytes());
        raw
    }

    #[test]
    fn a_report_is_read_at_each_seat_in_either_version() {
        let wanted = SeatReport {
            signal: -80,
            air_us: 9,
            load_by_us: 5,
            load_not_by_us: 60,
        };
        let seats = |raw: Vec<u8>, version| Report::parse(&raw, version).unwrap().seats;
        assert_eq!(seats(raw(3, 1), 3)[1], wanted);
        assert_eq!(seats(raw(4, 1), 4)[1], wanted);
        assert_eq!(seats(raw(4, 0), 4)[0], wanted);
        assert_eq!(seats(raw(4, 0), 4)[1].signal, 0);
        let short = &raw(4, 0)[..4 + LINKS + PHYS * PHY_BYTES];
        assert_eq!(Report::parse(short, 4), None);
    }

    #[test]
    fn traffic_is_the_share_of_the_time_since_the_last_report() {
        let mut statistics = Statistics::default();
        statistics.count_traffic(5_000_000, 1_000_000);
        assert_eq!(statistics.traffic, Low, "the first report has no window");
        statistics.count_traffic(600_000, 2_000_000);
        assert_eq!(statistics.traffic, High);
        statistics.count_traffic(200_000, 3_000_000);
        assert_eq!(statistics.traffic, Medium);
        statistics.count_traffic(100_000, 4_000_000);
        assert_eq!(statistics.traffic, Low);
        statistics.count_traffic(100_000, 4_100_000);
        assert_eq!(statistics.traffic, Low, "too short a window counts nothing");
    }

    #[test]
    fn only_a_level_up_asks_for_a_scan_and_levels_fall_below_their_lower_limit() {
        let mut statistics = Statistics::default();
        assert!(!statistics.load_rises(44));
        assert!(statistics.load_rises(45));
        assert!(!statistics.load_rises(40), "level 1 holds down to 40");
        assert_eq!(statistics.level, 1);
        assert!(!statistics.load_rises(39));
        assert_eq!(statistics.level, 0);
        assert!(statistics.load_rises(90));
        assert_eq!(statistics.level, 3);
        assert!(!statistics.load_rises(69));
        assert_eq!(statistics.level, 2, "level 2 holds down to 65");
        statistics.seat_emptied(1);
        assert!(statistics.load_rises(45), "a new PHY starts again");
    }
}
