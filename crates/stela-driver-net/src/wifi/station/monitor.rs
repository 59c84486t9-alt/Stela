// SPDX-License-Identifier: GPL-2.0-only
// Adapted from pinned Linux mac80211/mlme.c: Copyright 2004, Instant802
// Networks, Inc.; 2005, Devicescape Software, Inc.; 2006-2007 Jiri Benc;
// 2007, Michael Wu; 2013-2014 Intel Mobile Communications GmbH; 2018-2026
// Intel Corporation. Full source notices in THIRD_PARTY.md.
//! mac80211's watch on a connection for hardware that keeps none: the beacon
//! monitor, the connection monitor, and the nullfunc probe either one starts.
//! A frame leaving a ring proves nothing of the AP, so only what is heard and
//! an acknowledged probe count, where rtw88's blanket TX status would let data
//! on a dead link end a probe.

/// `beacon_loss_count`.
const BEACON_LOSS_COUNT: u64 = 7;
/// `IEEE80211_CONNECTION_IDLE_TIME`.
const IDLE_US: u64 = 30_000_000;
/// `probe_wait_ms`.
const PROBE_WAIT_US: u64 = 500_000;
/// `max_nullfunc_tries`.
const MAX_TRIES: u8 = 2;
/// One TU.
const TU_US: u64 = 1024;

/// What the monitor asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Wait,
    /// `ieee80211_mgd_probe_ap_send`: send a nullfunc and report its ACK.
    Probe,
    /// `ieee80211_sta_connection_lost`.
    Lost,
}

/// `IEEE80211_STA_CONNECTION_POLL`.
#[derive(Clone, Copy, Debug)]
struct Probe {
    /// `probe_send_count`.
    tries: u8,
    /// `nullfunc_failed`.
    failed: bool,
    /// `probe_timeout`.
    until: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Monitor {
    /// `beacon_timeout`.
    beacon_timeout_us: u64,
    /// `bcn_mon_timer`.
    beacon_due: u64,
    /// `conn_mon_timer`.
    idle_due: u64,
    probe: Option<Probe>,
}

impl Monitor {
    /// A monitor of an association to a BSS beaconing each `interval_tu`.
    pub fn new(interval_tu: u16, now: u64) -> Self {
        let beacon_timeout_us = BEACON_LOSS_COUNT * u64::from(interval_tu) * TU_US;
        Self {
            beacon_timeout_us,
            beacon_due: now + beacon_timeout_us,
            idle_due: now + IDLE_US,
            probe: None,
        }
    }

    /// `IEEE80211_STA_CONNECTION_POLL`.
    pub fn probing(&self) -> bool {
        self.probe.is_some()
    }

    /// `ieee80211_reset_ap_probe` without its check: nothing is in question.
    pub fn restart(&mut self, now: u64) {
        self.probe = None;
        self.beacon_due = now + self.beacon_timeout_us;
        self.idle_due = now + IDLE_US;
    }

    /// `ieee80211_rx_mgmt_beacon`'s care of the monitors.
    pub fn beacon(&mut self, now: u64) {
        if self.probe.is_some() {
            self.restart(now);
        }
        self.beacon_due = now + self.beacon_timeout_us;
    }

    /// A frame came from the AP to this station, `last_rx`.
    pub fn heard(&mut self, now: u64) {
        self.idle_due = now + IDLE_US;
    }

    /// `ieee80211_sta_tx_notify` of the nullfunc.
    pub fn acknowledged(&mut self, acknowledged: bool, now: u64) {
        if acknowledged {
            self.restart(now);
        } else if let Some(probe) = &mut self.probe {
            probe.failed = true;
        }
    }

    /// `ieee80211_sta_work`'s poll, and each timer's work.
    pub fn poll(&mut self, now: u64) -> Step {
        let Some(probe) = &mut self.probe else {
            if now < self.beacon_due && now < self.idle_due {
                return Step::Wait;
            }
            self.probe = Some(Probe {
                tries: 1,
                failed: false,
                until: now + PROBE_WAIT_US,
            });
            return Step::Probe;
        };
        if probe.failed && probe.tries < MAX_TRIES {
            probe.tries += 1;
            probe.failed = false;
            probe.until = now + PROBE_WAIT_US;
            Step::Probe
        } else if probe.failed || now >= probe.until {
            Step::Lost
        } else {
            Step::Wait
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOSS: u64 = 7 * 100 * TU_US;

    #[test]
    fn seven_beacons_missed_start_a_probe_and_a_beacon_cancels_it() {
        let mut monitor = Monitor::new(100, 0);
        assert_eq!(monitor.poll(LOSS - 1), Step::Wait);
        monitor.beacon(LOSS - 1);
        assert_eq!(monitor.poll(LOSS), Step::Wait);
        assert_eq!(monitor.poll(2 * LOSS), Step::Probe);
        assert_eq!(monitor.poll(2 * LOSS + 1), Step::Wait);
        monitor.beacon(2 * LOSS + 1);
        assert_eq!(monitor.poll(2 * LOSS + PROBE_WAIT_US), Step::Wait);
    }

    #[test]
    fn thirty_seconds_unheard_start_a_probe_though_beacons_come() {
        let mut monitor = Monitor::new(100, 0);
        monitor.heard(10);
        monitor.beacon(IDLE_US - 1);
        assert_eq!(monitor.poll(IDLE_US), Step::Wait);
        monitor.beacon(IDLE_US + 10);
        assert_eq!(monitor.poll(IDLE_US + 10), Step::Probe);
    }

    #[test]
    fn an_acknowledged_probe_settles_it_and_two_refused_lose_the_link() {
        let mut monitor = Monitor::new(100, 0);
        assert_eq!(monitor.poll(LOSS), Step::Probe);
        monitor.acknowledged(true, LOSS);
        assert_eq!(monitor.poll(2 * LOSS - 1), Step::Wait);
        assert_eq!(monitor.poll(2 * LOSS), Step::Probe);
        monitor.acknowledged(false, 2 * LOSS);
        assert_eq!(monitor.poll(2 * LOSS), Step::Probe);
        monitor.acknowledged(false, 2 * LOSS);
        assert_eq!(monitor.poll(2 * LOSS), Step::Lost);
    }

    #[test]
    fn a_probe_no_report_answers_loses_the_link() {
        let mut monitor = Monitor::new(100, 0);
        assert_eq!(monitor.poll(LOSS), Step::Probe);
        assert_eq!(monitor.poll(LOSS + PROBE_WAIT_US - 1), Step::Wait);
        assert_eq!(monitor.poll(LOSS + PROBE_WAIT_US), Step::Lost);
    }
}
