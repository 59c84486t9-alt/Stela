// SPDX-License-Identifier: GPL-2.0-only
// Beacon-signal tracking adapts Linux net/mac80211/mlme.c.
//! Connection-quality RSSI monitoring. Firmware reporting RSSI_NOTIFY_EVT_EN
//! watches the threshold itself; otherwise the current AP's beacon signal is
//! averaged and compared as mac80211's `ieee80211_handle_beacon_sig` does.
use super::*;

/// IEEE80211_SIGNAL_AVE_MIN_COUNT: beacons before the average is trusted.
const MIN_COUNT: u32 = 4;

#[derive(Clone, Copy)]
pub(super) struct Monitor {
    pub(super) threshold: i32,
    hysteresis: i32,
    pub(super) firmware: bool,
}

#[derive(Default)]
pub(super) struct Cqm {
    pub(super) monitor: Option<Monitor>,
    association: Option<u64>,
    /// `DECLARE_EWMA(beacon_signal, 4, 4)` over the negated signal.
    average: u64,
    count: u32,
    /// `last_cqm_event_signal`, zero before the first event.
    last_event: i32,
    /// Crossings found from beacons, reported by the next poll.
    pub(super) ready: Vec<Event>,
}

impl Cqm {
    /// `ieee80211_set_cqm_rssi_config`: a new monitor restarts its events.
    pub(super) fn set(&mut self, monitor: Option<(i32, u32)>, firmware: bool) {
        self.monitor = monitor.map(|(threshold, hysteresis)| Monitor {
            threshold,
            hysteresis: hysteresis as i32,
            firmware,
        });
        self.last_event = 0;
    }

    /// One beacon from the current AP of `association`.
    pub(super) fn beacon(&mut self, association: u64, signal: i32) {
        // tracking_signal_avg restarts with each association.
        if self.association != Some(association) {
            self.association = Some(association);
            self.average = 0;
            self.count = 0;
            self.last_event = 0;
        }
        self.count = self.count.saturating_add(1);
        let value = u64::from((-signal).max(0) as u32) << 4;
        self.average = if self.average == 0 {
            value
        } else {
            ((self.average << 2) - self.average + value) >> 2
        };
        let Some(monitor) = self.monitor else {
            return;
        };
        if monitor.firmware || monitor.threshold == 0 || self.count < MIN_COUNT {
            return;
        }
        let rssi = -((self.average >> 4) as i32);
        let last = self.last_event;
        let high = if rssi < monitor.threshold && (last == 0 || rssi < last - monitor.hysteresis) {
            false
        } else if rssi > monitor.threshold && (last == 0 || rssi > last + monitor.hysteresis) {
            true
        } else {
            return;
        };
        self.last_event = rssi;
        self.ready.push(Event::Rssi { rssi, high });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_signal_crosses_the_threshold_like_ieee80211_handle_beacon_sig() {
        if crate::test_process::isolate_model() {
            return;
        }
        let mut cqm = Cqm::default();
        cqm.set(Some((-70, 4)), false);
        for _ in 0..3 {
            cqm.beacon(1, -80);
        }
        assert!(cqm.ready.is_empty());
        cqm.beacon(1, -80);
        assert!(matches!(
            cqm.ready[..],
            [Event::Rssi {
                rssi: -80,
                high: false
            }]
        ));
        // The average moves a quarter of the way: -77.5 truncates to -77,
        // within the hysteresis of the last event.
        cqm.beacon(1, -70);
        assert_eq!(cqm.ready.len(), 1);
        for _ in 0..8 {
            cqm.beacon(1, -60);
        }
        assert!(matches!(cqm.ready[1], Event::Rssi { high: true, .. }));
        // A new association starts over; a firmware monitor is left alone.
        cqm.beacon(2, -90);
        assert_eq!(cqm.count, 1);
        let reported = cqm.ready.len();
        cqm.set(Some((-70, 4)), true);
        for _ in 0..4 {
            cqm.beacon(2, -90);
        }
        assert_eq!(cqm.ready.len(), reported);
    }
}
