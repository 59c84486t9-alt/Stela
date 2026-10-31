// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! What firmware says of the Bluetooth half: `rtw_coex_bt_info_notify` and
//! `rtw_coex_update_bt_link_info`.
use super::tables::{BLUETOOTH_RSSI_STEPS, RSSI_TOLERANCE};

/// `COEX_BTINFO_LENGTH`.
const INFO_LENGTH: usize = 7;
/// `COEX_INFO_*`.
const INFO_CONNECTION: u8 = 1 << 0;
const INFO_SCO_ESCO: u8 = 1 << 1;
const INFO_INQ_PAGE: u8 = 1 << 2;
const INFO_ACL_BUSY: u8 = 1 << 3;
const INFO_SCO_BUSY: u8 = 1 << 4;
const INFO_HID: u8 = 1 << 5;
const INFO_A2DP: u8 = 1 << 6;
const INFO_FTP: u8 = 1 << 7;

/// `coex_bt_status`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum Status {
    #[default]
    NotConnectedIdle,
    ConnectedIdle,
    InquiryOrPage,
    AclBusy,
    ScoBusy,
    AclScoBusy,
    /// `COEX_BTSTATUS_MAX`: a connection that fits no case.
    Other,
}

/// `rtw_coex_next_rssi_state`, which only the sides of its steps tell apart.
pub(super) fn rssi_high(high: bool, rssi: u8, step: u8) -> bool {
    if high {
        rssi >= step
    } else {
        rssi >= step + RSSI_TOLERANCE
    }
}

/// What a report with new contents changed, for the arbiter's timers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Changes {
    /// `bt_inq_page` went to this.
    pub inquiring: Option<bool>,
    /// A link is being set up.
    pub setting_up: bool,
    /// More than one link became one.
    pub multi_link_ended: bool,
    /// Bluetooth came back from a reset that lost what it knew of Wi-Fi.
    pub reset: bool,
    /// Bluetooth ignores Wi-Fi's activity with no link being set up.
    pub ignoring_wifi: bool,
}

/// `coex_stat`'s view of Bluetooth.
#[derive(Debug, Default)]
pub(super) struct Bluetooth {
    /// `bt_info_lb2`, `lb3`, `hb0` to `hb3`.
    info: [u8; 6],
    /// `coex_dm->bt_status`.
    pub status: Status,
    pub hfp: bool,
    pub hid: bool,
    pub a2dp: bool,
    pub pan: bool,
    /// `bt_profile_num`.
    pub profiles: u8,
    /// `bt_whck_test`.
    pub certification: bool,
    /// `bt_inq_page`.
    pub inquiring: bool,
    /// `bt_page`.
    pub paging: bool,
    /// `bt_ble_exist`: a remote control over Bluetooth Low Energy.
    pub low_energy: bool,
    /// `bt_ble_hid_exist`.
    pub low_energy_hid: bool,
    /// `bt_ble_scan_en`.
    pub low_energy_scan: bool,
    /// `bt_ble_scan_type`.
    pub scan_type: u8,
    /// `bt_setup_link`.
    pub setting_up: bool,
    /// `bt_multi_link`.
    pub multi_link: bool,
    /// `bt_multi_link_remain`.
    pub multi_link_remains: bool,
    /// `bt_a2dp_active`.
    pub a2dp_active: bool,
    /// `bt_a2dp_sink`.
    pub a2dp_sink: bool,
    /// `bt_slave`.
    pub slave: bool,
    /// `bt_hid_slot` and `bt_hid_pair_num`.
    hid_slot: u8,
    pub hid_pairs: u8,
    /// `bt_418_hid_exist`: a controller polled every 4.18 ms.
    pub hid_418: bool,
    /// `bt_rssi`.
    rssi: u8,
    /// `coex_dm->bt_rssi_state`, each `COEX_RSSI_HIGH`.
    pub rssi_high: [bool; 4],
    /// `cnt_bt[COEX_CNT_BT_INFOUPDATE]`.
    updates: u32,
}

impl Bluetooth {
    /// `rtw_coex_bt_info_notify`'s reading of a report from Bluetooth, none
    /// when it is short or says nothing new.
    pub fn report(&mut self, bytes: &[u8]) -> Option<Changes> {
        if bytes.len() != INFO_LENGTH {
            return None;
        }
        let info: [u8; 6] = bytes[1..].try_into().ok()?;
        if info == self.info {
            return None;
        }
        self.info = info;
        let [low2, _low3, high0, high1, high2, _high3] = info;
        let mut changes = Changes::default();
        self.certification = low2 == 0xff;
        let inquiring = low2 & INFO_INQ_PAGE != 0;
        if inquiring != self.inquiring {
            self.inquiring = inquiring;
            changes.inquiring = Some(inquiring);
        }
        // ble_hid_profile_support.
        self.low_energy_hid = low2 & INFO_HID != 0 && high1 & 1 != 0;
        self.low_energy = low2 & INFO_HID == 0 && high1 & 1 != 0;
        self.paging = info[1] & (1 << 7) != 0;
        // COEX_BTRSSI_DBM.
        self.rssi = match high0 {
            0..=127 => 100,
            156..=255 => 100 - (0u8.wrapping_sub(high0)),
            _ => 0,
        };
        changes.reset = high1 & (1 << 1) != 0;
        changes.setting_up = high1 & (1 << 2) != 0;
        self.setting_up |= changes.setting_up;
        changes.ignoring_wifi = high1 & (1 << 3) != 0 && !changes.setting_up;
        self.low_energy_scan = high1 & (1 << 5) != 0;
        let multi_link = high1 & (1 << 7) != 0;
        if !multi_link && self.multi_link {
            self.multi_link_remains = true;
            changes.multi_link_ended = true;
        }
        self.multi_link = multi_link;
        self.a2dp_active = high2 & (1 << 2) != 0;
        self.slave = high2 & (1 << 3) != 0;
        self.hid_slot = (high2 & 0x30) >> 4;
        self.hid_pairs = (high2 & 0xc0) >> 6;
        if self.hid_pairs > 0 && self.hid_slot >= 2 {
            self.hid_418 = true;
        } else if self.hid_pairs == 0 || self.hid_slot == 1 {
            self.hid_418 = false;
        }
        self.a2dp_sink = info[5] & (1 << 7) != 0;
        Some(changes)
    }

    /// `rtw_coex_update_bt_link_info`. True when it is time to ask what kind
    /// of scan Bluetooth Low Energy runs.
    pub fn update_links(&mut self) -> bool {
        for (high, step) in self.rssi_high.iter_mut().zip(BLUETOOTH_RSSI_STEPS) {
            *high = rssi_high(*high, self.rssi, step);
        }
        let ask = self.low_energy_scan && self.updates.is_multiple_of(3);
        let low2 = self.info[0];
        let connected = low2 & INFO_CONNECTION != 0;
        self.pan = connected && low2 & INFO_FTP != 0;
        self.a2dp = connected && low2 & INFO_A2DP != 0;
        self.hid = connected && low2 & INFO_HID != 0;
        self.hfp = connected && low2 & INFO_SCO_ESCO != 0;
        self.profiles = [self.pan, self.a2dp, self.hid, self.hfp]
            .iter()
            .map(|&profile| u8::from(profile))
            .sum();
        self.status = if low2 & INFO_INQ_PAGE != 0 {
            Status::InquiryOrPage
        } else if !connected {
            self.multi_link_remains = false;
            Status::NotConnectedIdle
        } else if low2 == INFO_CONNECTION {
            Status::ConnectedIdle
        } else if low2 & (INFO_SCO_ESCO | INFO_SCO_BUSY) != 0 {
            if low2 & INFO_ACL_BUSY != 0 {
                Status::AclScoBusy
            } else {
                Status::ScoBusy
            }
        } else if low2 & INFO_ACL_BUSY != 0 {
            Status::AclBusy
        } else {
            Status::Other
        };
        self.updates = self.updates.wrapping_add(1);
        ask
    }

    /// `coex_stat`'s fields `rtw_coex_monitor_bt_enable` clears with Bluetooth.
    pub fn disabled(&mut self) {
        self.scan_type = 0;
    }

    /// `bt_ble_scan_type` as `BT_MP_INFO_OP_SCAN_TYPE` answers.
    pub fn scan_answer(&mut self, kind: u8) {
        self.scan_type = kind;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_names_the_links_and_what_is_busy() {
        let mut bluetooth = Bluetooth::default();
        // Connected, A2DP and busy, at -60 dBm.
        let report = [1, 0x49, 0, 0xc4, 0, 0, 0];
        assert_eq!(bluetooth.report(&report), Some(Changes::default()));
        bluetooth.update_links();
        assert!(bluetooth.a2dp && !bluetooth.hid);
        assert_eq!(bluetooth.profiles, 1);
        assert_eq!(bluetooth.status, Status::AclBusy);
        assert_eq!(bluetooth.rssi, 40);
        assert_eq!(bluetooth.rssi_high, [true, true, true, true]);
        assert_eq!(bluetooth.report(&report), None, "nothing new");
    }

    #[test]
    fn a_short_report_is_no_report() {
        assert_eq!(Bluetooth::default().report(&[1, 0x49]), None);
    }

    #[test]
    fn every_other_kind_of_link_finds_its_status() {
        let status = |low2| {
            let mut bluetooth = Bluetooth::default();
            bluetooth.report(&[1, low2, 0, 0, 0, 0, 1]);
            bluetooth.update_links();
            bluetooth.status
        };
        assert_eq!(status(0), Status::NotConnectedIdle);
        assert_eq!(status(1), Status::ConnectedIdle);
        assert_eq!(status(4), Status::InquiryOrPage);
        assert_eq!(status(1 | 2), Status::ScoBusy);
        assert_eq!(status(1 | 2 | 8), Status::AclScoBusy);
        assert_eq!(status(1 | 32), Status::Other);
    }

    #[test]
    fn low_energy_reads_as_a_remote_or_a_hid_by_the_hid_bit() {
        let mut bluetooth = Bluetooth::default();
        bluetooth.report(&[1, 0, 0, 0, 1, 0, 0]);
        assert!(bluetooth.low_energy && !bluetooth.low_energy_hid);
        bluetooth.report(&[1, 0x20, 0, 0, 1, 0, 0]);
        assert!(!bluetooth.low_energy && bluetooth.low_energy_hid);
    }

    #[test]
    fn a_418_controller_stands_until_a_report_rules_it_out() {
        let mut bluetooth = Bluetooth::default();
        // One pair, slot 2.
        bluetooth.report(&[1, 0, 0, 0, 0, 0x60, 0]);
        assert!(bluetooth.hid_418);
        // One pair, slot 0: no ruling.
        bluetooth.report(&[1, 0, 0, 0, 0, 0x40, 0]);
        assert!(bluetooth.hid_418);
        bluetooth.report(&[1, 0, 0, 0, 0, 0x50, 0]);
        assert!(!bluetooth.hid_418);
    }

    #[test]
    fn the_end_of_multiple_links_leaves_a_remnant() {
        let mut bluetooth = Bluetooth::default();
        bluetooth.report(&[1, 1, 0, 0, 0x80, 0, 0]);
        let changes = bluetooth.report(&[1, 3, 0, 0, 0, 0, 0]).unwrap();
        assert!(changes.multi_link_ended && bluetooth.multi_link_remains);
    }

    #[test]
    fn rssi_needs_the_tolerance_to_rise_but_not_to_stay() {
        assert!(!rssi_high(false, 61, 60));
        assert!(rssi_high(false, 62, 60));
        assert!(rssi_high(true, 60, 60));
        assert!(!rssi_high(true, 59, 60));
    }
}
