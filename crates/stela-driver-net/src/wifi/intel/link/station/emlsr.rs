// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2024-2026 Intel Corporation
//! EMLSR as `iwlmld` runs it: a busy association with two good links keeps both
//! active, listening on both and exchanging frames on one at a time. Firmware
//! does the air's side. The driver decides when two links are worth it, and
//! `iwl_mld_exit_emlsr` gives one up when a link fades, firmware asks, or too
//! little traffic is left to use it.
use super::*;
use crate::wifi::station::operations::mhz;
use crate::wifi::station::wire::multi_link::Basic;

/// `IWL_MLD_EMLSR_CAPA`: EMLSR, 32 us of padding and 64 us of transition.
pub(super) const CAPABILITIES: u16 = 1 | 1 << 1 | 3 << 4;
/// `IEEE80211_EML_CAP_EMLSR_SUPP`.
const SUPPORT: u16 = 1;
/// `IEEE80211_EML_CAP_TRANSITION_TIMEOUT`, and its `_64TU`.
const TIMEOUT_SHIFT: u16 = 11;
const LONGEST_TIMEOUT: u16 = 10;
/// `IEEE80211_MED_SYNC_DELAY_DEFAULT`, for an AP that does not name one.
const DEFAULT_SYNC_DELAY: u16 = 0x10ac;
pub(super) const MODE_NOTIFICATION: (u8, u8) = (0xf3, 5);
pub(super) const TRANSITION_FAILED_NOTIFICATION: (u8, u8) = (0xf7, 3);
/// `PROFILE_NOTIF` of `BT_COEX_GROUP`.
pub(super) const BLUETOOTH_NOTIFICATION: (u8, u8) = (0xff, 9);
/// `ESR_RECOMMEND_LEAVE`.
pub(super) const RECOMMEND_LEAVE: u32 = 0;
/// `IWL_MLD_TPT_COUNT_WINDOW`.
const WINDOW_US: u64 = 5_000_000;
/// `IWL_MLD_ENTER_EMLSR_TPT_THRESH`.
const ENOUGH_MPDUS: u32 = 400;
/// `EMLSR_MIN_TX`, `EMLSR_MIN_RX` and `EMLSR_SEC_LINK_MIN_PERC`.
const COUNTED_TX: u32 = 3000;
const COUNTED_RX: u32 = 400;
const SECOND_LINK_PERCENT: u64 = 10;
/// `IWL_MLD_TRIGGER_LINK_SEL_TIME_SEC`.
const PREVENTED_US: u64 = 30_000_000;
/// `IWL_MLD_EMLSR_PREVENT_SHORT` and `_LONG`.
const PREVENTED_AGAIN_US: u64 = 300_000_000;
const PREVENTED_LONG_US: u64 = 600_000_000;
/// `IWL_MLD_PREVENT_EMLSR_TIMEOUT`.
const REPEAT_US: u64 = 400_000_000;
/// `IWL_MLD_BCN_LOSS_EXIT_ESR_THRESH_2_LINKS` and `_THRESH`.
const BOTH_LINKS_MISSED: u32 = 5;
const LINK_MISSED: u32 = 15;

/// `enum iwl_mld_emlsr_exit`, of the reasons a station here can have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Exit {
    Block,
    MissedBeacon,
    FailedEntry,
    LowSignal,
    LinkUsage,
    Bluetooth,
    ChannelLoad,
    Firmware,
    ChannelSwitch,
}

/// What `_iwl_mld_select_links` settled on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Choice {
    Active,
    Other,
    Both,
}

/// `struct iwl_mld_link_sel_data`.
#[derive(Clone, Copy, Debug)]
pub(super) struct Graded {
    pub(super) grade: u32,
    pub(super) signal: Option<i8>,
    /// `iwl_mld_get_chan_load`, of 256.
    pub(super) load: u32,
    pub(super) definition: ChannelDefinition,
}

/// `iwl_mld_get_min_chan_load_thresh`.
pub(super) fn lowest_load(width: phy::Width) -> u32 {
    match width {
        phy::Width::Mhz320 | phy::Width::Mhz160 => 5,
        phy::Width::Mhz80 => 7,
        _ => 10,
    }
}

/// `IWL_MLD_HIGH_RSSI_THRESH_*`, the signal EMLSR starts from.
fn enough_signal(width: phy::Width) -> i8 {
    match width {
        phy::Width::Mhz40 => -64,
        phy::Width::Mhz80 | phy::Width::Mhz80P80 => -61,
        phy::Width::Mhz160 => -58,
        phy::Width::Mhz20 | phy::Width::Mhz320 => -67,
    }
}

/// `iwl_mld_emlsr_pair_state`'s check of two links in one band: their
/// channels stand far enough apart only across the middle of 5 GHz.
fn separated(a: &ChannelDefinition, b: &ChannelDefinition) -> bool {
    if a.control.band != b.control.band {
        return true;
    }
    let (low, high) = if a.control.frequency_mhz > b.control.frequency_mhz {
        (b, a)
    } else {
        (a, b)
    };
    a.control.band == Band::Ghz5
        && low.center1_mhz + mhz(low.width) / 2 <= 5330
        && high.center1_mhz - mhz(high.width) / 2 >= 5490
}

/// `iwl_mld_channel_load_allows_emlsr`: `load` percent of the primary's channel
/// is others', and a narrower second link must be worth what it gives up.
fn load_allows(primary: &ChannelDefinition, second: &ChannelDefinition, load: u32) -> bool {
    if load < lowest_load(primary.width) {
        return false;
    }
    if mhz(primary.width) <= mhz(second.width) {
        return true;
    }
    match mhz(primary.width) / mhz(second.width) {
        2 => load > 25,
        4 => load > 40,
        8 | 16 => load > 50,
        _ => false,
    }
}

/// `mld_vif->emlsr`.
#[derive(Default)]
pub(super) struct Emlsr {
    /// The AP MLD's `eml_cap` has EMLSR, and the radio can run it.
    offered: bool,
    /// `esr_transition_timeout` and `medium_sync_delay`.
    transition: (u8, u16),
    /// Both links are active: `dormant` is the one that is not primary.
    pub(super) active: bool,
    /// `IWL_MLD_EMLSR_BLOCKED_TPT`.
    too_little_traffic: bool,
    /// `IWL_MLD_EMLSR_BLOCKED_PREVENTION`, until this time.
    prevented: Option<u64>,
    /// `last_exit_reason` and `last_exit_ts`, and `exit_repeat_count`.
    last_exit: Option<(Exit, u64)>,
    repeats: u8,
    /// `last_entry_ts`.
    entered: u64,
    /// `check_tpt_wk`.
    check_at: Option<u64>,
    /// `mpdu_counters`, of each seat, sent then received.
    counted: [(u32, u32); 2],
    /// `window_start_time`.
    window: u64,
    /// `bt_is_active`.
    bluetooth: bool,
    /// The exit asked for, and the seat that stays.
    exit: Option<(Exit, u8)>,
}

impl Emlsr {
    /// What the AP MLD's association response offers.
    pub(super) fn offered(elements: &[u8]) -> Self {
        let basic = Basic::find(elements).ok().flatten();
        let basic = basic.as_ref();
        let capabilities = basic.and_then(|basic| basic.eml_capabilities).unwrap_or(0);
        let delay = basic.and_then(|basic| basic.medium_sync_delay);
        Self {
            offered: capabilities & SUPPORT != 0,
            transition: (
                (capabilities >> TIMEOUT_SHIFT & 0xf).min(LONGEST_TIMEOUT) as u8,
                delay.unwrap_or(DEFAULT_SYNC_DELAY),
            ),
            ..Self::default()
        }
    }

    /// What firmware's MAC context says of the AP MLD's transitions.
    pub(super) fn transition(&self) -> Option<(u8, u16)> {
        self.offered.then_some(self.transition)
    }

    fn blocked(&self) -> bool {
        self.too_little_traffic || self.prevented.is_some()
    }

    /// `iwl_mld_block_emlsr` when the port opens: EMLSR waits for traffic.
    pub(super) fn block_for_throughput(&mut self, now: u64) {
        if self.offered {
            self.too_little_traffic = true;
            self.window = now;
            self.check_at = None;
        }
    }

    pub(super) fn entered(&mut self, now: u64) {
        self.active = true;
        self.entered = now;
        self.exit = None;
        self.check_at = self.check_at.or(Some(now + WINDOW_US));
    }

    pub(super) fn ask_exit(&mut self, reason: Exit, keep: u8) {
        if self.active && keep < 2 {
            self.exit.get_or_insert((reason, keep));
        }
    }

    /// `iwl_mld_count_mpdu`: frames of firmware station `seat`, and whether
    /// they are the traffic EMLSR was waiting for.
    fn count(&mut self, seat: u8, sent: bool, count: u32, now: u64) -> bool {
        if !self.offered || seat >= 2 {
            return false;
        }
        if self.too_little_traffic && now.saturating_sub(self.window) > WINDOW_US {
            self.counted = [(0, 0); 2];
            self.window = now;
        }
        let counted = &mut self.counted[usize::from(seat)];
        let direction = if sent { &mut counted.0 } else { &mut counted.1 };
        *direction = direction.saturating_add(count);
        let [first, second] = self.counted;
        let total = if sent {
            first.0.saturating_add(second.0)
        } else {
            first.1.saturating_add(second.1)
        };
        self.too_little_traffic && total >= ENOUGH_MPDUS
    }

    /// `iwl_mld_emlsr_check_tpt`, every window traffic is not blocking EMLSR,
    /// with `primary` the seat that stays.
    fn check_throughput(&mut self, primary: u8, now: u64) {
        let counted = core::mem::take(&mut self.counted);
        let [first, second] = counted;
        let sent = first.0.saturating_add(second.0);
        let received = first.1.saturating_add(second.1);
        if sent < ENOUGH_MPDUS && received < ENOUGH_MPDUS {
            self.too_little_traffic = true;
            self.window = now;
            self.check_at = None;
            self.ask_exit(Exit::Block, primary);
            return;
        }
        self.check_at = Some(now + WINDOW_US);
        // The second link has had its chance after one window.
        if !self.active || now.saturating_sub(self.entered) < WINDOW_US {
            return;
        }
        let (other_sent, other_received) = counted[usize::from(1 - primary)];
        let share = |part: u32, whole: u32| u64::from(part) * 100 / u64::from(whole.max(1));
        if (sent > COUNTED_TX && share(other_sent, sent) < SECOND_LINK_PERCENT)
            || (received > COUNTED_RX && share(other_received, received) < SECOND_LINK_PERCENT)
        {
            self.ask_exit(Exit::LinkUsage, primary);
        }
    }

    /// `iwl_mld_check_emlsr_prevention`: how long `reason` keeps EMLSR off.
    fn prevent(&mut self, reason: Exit, now: u64) {
        let repeated = self
            .last_exit
            .is_some_and(|(last, at)| last == reason && now.saturating_sub(at) <= REPEAT_US);
        self.repeats = if repeated { self.repeats + 1 } else { 1 };
        self.last_exit = Some((reason, now));
        if reason == Exit::Block {
            return;
        }
        let lasting = matches!(
            reason,
            Exit::MissedBeacon | Exit::LinkUsage | Exit::Firmware
        );
        let delay = match self.repeats {
            2 if lasting => PREVENTED_AGAIN_US,
            3.. if lasting => PREVENTED_LONG_US,
            _ => PREVENTED_US,
        };
        self.prevented = Some(now + delay);
    }

    /// `iwl_mld_emlsr_disallowed_with_link`.
    fn takes(&self, link: &Graded) -> bool {
        !(link.definition.control.band == Band::Ghz2 && self.bluetooth)
            && link
                .signal
                .is_some_and(|signal| signal >= enough_signal(link.definition.width))
    }

    /// The EMLSR half of `_iwl_mld_select_links`: `active` and `other` were
    /// heard, and `load` is the percent of each one's channel that is others'
    /// in the same order. Only an active primary has a load firmware measured,
    /// so a better link waits to be active first. `iwl_mld_get_emlsr_grade`
    /// adds the second link's grade by how loaded the primary is.
    pub(super) fn choose(
        &self,
        active: &Graded,
        other: &Graded,
        load: [u32; 2],
        now: u64,
    ) -> Choice {
        let (single, first, second) = if other.grade > active.grade {
            (Choice::Other, other, active)
        } else {
            (Choice::Active, active, other)
        };
        let primary_load = load[usize::from(single == Choice::Other)];
        let measured = self.active || single == Choice::Active;
        let waiting = self.prevented.is_some_and(|until| until > now);
        if !self.offered
            || self.too_little_traffic
            || waiting
            || !measured
            || !self.takes(first)
            || !self.takes(second)
            || second.grade * first.load / grade::SCALE == 0
            || !separated(&first.definition, &second.definition)
            || !load_allows(&first.definition, &second.definition, primary_load)
        {
            return single;
        }
        Choice::Both
    }
}

impl Client {
    /// `iwl_mld_retry_emlsr`.
    pub(super) fn retry_emlsr(&mut self, now: u64) {
        if self.emlsr.offered && !self.emlsr.active && !self.emlsr.blocked() {
            self.ask_link_scan(now);
        }
    }

    /// `iwl_mld_handle_bt_coex_notif` and `iwl_mld_emlsr_check_bt`.
    pub(super) fn bluetooth_changed(&mut self, active: bool, now: u64) {
        if core::mem::replace(&mut self.emlsr.bluetooth, active) == active {
            return;
        }
        if !active {
            return self.retry_emlsr(now);
        }
        let on_2_4 = [0, 1].into_iter().any(|seat| {
            self.context_at(seat)
                .is_some_and(|link| link.definition().control.band == Band::Ghz2)
        });
        if on_2_4 {
            self.emlsr.ask_exit(Exit::Bluetooth, self.seat);
        }
    }

    /// `iwl_mld_handle_missed_beacon_notif` of two active links: `link` missed
    /// `missed` beacons and the other `other`. Both quiet leaves the primary,
    /// and one quiet leaves the one that is not.
    pub(super) fn emlsr_missed_beacons(&mut self, link: u8, missed: u32, other: u32) {
        if missed >= BOTH_LINKS_MISSED && other >= BOTH_LINKS_MISSED {
            self.emlsr.ask_exit(Exit::MissedBeacon, self.seat);
        } else if missed >= LINK_MISSED {
            self.emlsr.ask_exit(Exit::MissedBeacon, 1 ^ link);
        }
    }

    /// `iwl_mld_count_mpdu`.
    pub(super) fn count_mpdus(&mut self, seat: u8, sent: bool, count: u32, now: u64) {
        if self.emlsr.count(seat, sent, count, now) {
            self.throughput_reached(now);
        }
    }

    /// `iwl_mld_emlsr_unblock_tpt_wk`.
    fn throughput_reached(&mut self, now: u64) {
        self.emlsr.too_little_traffic = false;
        self.emlsr.check_at = Some(now + WINDOW_US);
        if !self.emlsr.blocked() {
            self.ask_link_scan(now);
        }
    }

    /// `iwl_mld_emlsr_prevent_done_wk` and the windows of traffic.
    fn tick_emlsr(&mut self, now: u64) {
        if self.emlsr.prevented.is_some_and(|until| now >= until) {
            self.emlsr.prevented = None;
            self.retry_emlsr(now);
        }
        if self.emlsr.check_at.is_some_and(|at| now >= at) {
            self.emlsr.check_throughput(self.seat, now);
        }
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// `_iwl_mld_exit_emlsr`, once nothing else is in firmware's hands.
    pub(super) fn run_emlsr(&mut self, queue: &mut Queue<Q, B>, now: u64) -> Result<(), Error> {
        let client = &mut self.client;
        if !client.emlsr.offered || client.leaving {
            return Ok(());
        }
        client.tick_emlsr(now);
        if !client.idle() || !client.emlsr.active {
            return Ok(());
        }
        let Some((reason, keep)) = client.emlsr.exit.take() else {
            return Ok(());
        };
        client.emlsr.prevent(reason, now);
        // They are not to be trusted in EMLSR.
        client.statistics.load_not_by_us = [0; 2];
        self.lower_second(queue, keep)
    }

    #[cfg(test)]
    pub(crate) fn emlsr_active(&self) -> bool {
        self.client.emlsr.active
    }

    /// EMLSR's wait for traffic is over: tests have no 400 frames to send.
    #[cfg(test)]
    pub(crate) fn end_throughput_block(&mut self) {
        let now = self.clock.now_us();
        self.client.throughput_reached(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(band: Band, frequency_mhz: u16, width: phy::Width) -> ChannelDefinition {
        ChannelDefinition {
            control: Channel {
                band,
                number: 1,
                frequency_mhz,
            },
            width,
            center1_mhz: u32::from(frequency_mhz),
            center2_mhz: None,
            punctured: 0,
        }
    }

    fn link(grade: u32, signal: i8, definition: ChannelDefinition) -> Graded {
        Graded {
            grade,
            signal: Some(signal),
            load: 64,
            definition,
        }
    }

    fn open() -> Emlsr {
        Emlsr {
            offered: true,
            ..Emlsr::default()
        }
    }

    const NARROW: phy::Width = phy::Width::Mhz20;

    #[test]
    fn two_strong_links_on_two_bands_go_active_together() {
        let (low, high) = (
            definition(Band::Ghz2, 2412, NARROW),
            definition(Band::Ghz5, 5180, NARROW),
        );
        let (better, worse) = (link(300, -50, high), link(200, -50, low));
        let emlsr = open();
        assert_eq!(emlsr.choose(&better, &worse, [20, 0], 0), Choice::Both);
        // Too little of the air is others', and EMLSR would only cost.
        assert_eq!(emlsr.choose(&better, &worse, [9, 0], 0), Choice::Active);
        // The better link has no measured load until it is active.
        assert_eq!(emlsr.choose(&worse, &better, [20, 0], 0), Choice::Other);
        // Either link too weak, or Bluetooth on 2.4 GHz.
        let weak = link(200, -68, low);
        assert_eq!(emlsr.choose(&better, &weak, [20, 0], 0), Choice::Active);
        let busy = Emlsr {
            bluetooth: true,
            ..open()
        };
        assert_eq!(busy.choose(&better, &worse, [20, 0], 0), Choice::Active);
        let quiet = Emlsr {
            too_little_traffic: true,
            ..open()
        };
        assert_eq!(quiet.choose(&better, &worse, [20, 0], 0), Choice::Active);
        assert_eq!(
            Emlsr::default().choose(&better, &worse, [20, 0], 0),
            Choice::Active
        );
    }

    #[test]
    fn two_links_in_one_band_must_stand_across_the_gap_in_5_ghz() {
        let (low, far) = (
            definition(Band::Ghz5, 5180, NARROW),
            definition(Band::Ghz5, 5500, NARROW),
        );
        assert!(separated(&far, &low));
        assert!(!separated(&low, &definition(Band::Ghz5, 5300, NARROW)));
        assert!(!separated(
            &definition(Band::Ghz2, 2412, NARROW),
            &definition(Band::Ghz2, 2462, NARROW)
        ));
    }

    #[test]
    fn a_narrower_second_link_must_pay_for_itself() {
        let wide = definition(Band::Ghz5, 5180, phy::Width::Mhz80);
        let narrow = definition(Band::Ghz2, 2412, NARROW);
        assert!(!load_allows(&wide, &narrow, 40));
        assert!(load_allows(&wide, &narrow, 41));
        assert!(load_allows(&narrow, &wide, 10));
        assert!(!load_allows(&narrow, &wide, 9));
    }

    #[test]
    fn traffic_in_one_direction_across_both_seats_ends_the_wait_within_a_window() {
        let mut emlsr = Emlsr {
            too_little_traffic: true,
            ..open()
        };
        assert!(!emlsr.count(0, true, 300, 0));
        assert!(!emlsr.count(1, false, 300, 0), "the other direction");
        assert!(!emlsr.count(2, true, 300, 0), "no station of the links");
        assert!(emlsr.count(1, true, 100, 0));
        let mut late = Emlsr {
            too_little_traffic: true,
            ..open()
        };
        assert!(!late.count(0, true, 300, 0));
        assert!(!late.count(0, true, 100, WINDOW_US + 1), "a new window");
        assert!(!Emlsr::default().count(0, true, 400, 0), "not offered");
    }

    #[test]
    fn a_quiet_window_blocks_emlsr_and_leaves_the_second_link() {
        let mut emlsr = Emlsr {
            active: true,
            ..open()
        };
        emlsr.counted = [(399, 399), (0, 0)];
        emlsr.check_throughput(0, WINDOW_US);
        assert!(emlsr.too_little_traffic);
        assert_eq!(emlsr.exit, Some((Exit::Block, 0)));
        assert_eq!(emlsr.check_at, None);
    }

    #[test]
    fn a_second_link_that_carries_too_little_is_given_up_after_its_window() {
        let mut emlsr = Emlsr {
            active: true,
            ..open()
        };
        // The primary is seat 1, and seat 0 took 9% of what was sent.
        emlsr.counted = [(300, 0), (3000, 0)];
        emlsr.check_throughput(1, WINDOW_US - 1);
        assert_eq!(emlsr.exit, None, "its first window is not over");
        emlsr.counted = [(300, 0), (3000, 0)];
        emlsr.check_throughput(1, WINDOW_US);
        assert_eq!(emlsr.exit, Some((Exit::LinkUsage, 1)));
        assert_eq!(emlsr.check_at, Some(2 * WINDOW_US));
        let mut busy = Emlsr {
            active: true,
            ..open()
        };
        busy.counted = [(400, 400), (3000, 3000)];
        busy.check_throughput(1, WINDOW_US);
        assert_eq!(busy.exit, None);
    }

    #[test]
    fn repeated_exits_keep_emlsr_off_for_longer() {
        let mut emlsr = open();
        emlsr.prevent(Exit::MissedBeacon, 1_000);
        assert_eq!(emlsr.prevented, Some(1_000 + PREVENTED_US));
        emlsr.prevent(Exit::MissedBeacon, 2_000);
        assert_eq!(emlsr.prevented, Some(2_000 + PREVENTED_AGAIN_US));
        emlsr.prevent(Exit::MissedBeacon, 3_000);
        assert_eq!(emlsr.prevented, Some(3_000 + PREVENTED_LONG_US));
        emlsr.prevent(Exit::LowSignal, 4_000);
        assert_eq!(emlsr.prevented, Some(4_000 + PREVENTED_US));
        emlsr.prevent(Exit::LowSignal, 5_000);
        assert_eq!(
            emlsr.prevented,
            Some(5_000 + PREVENTED_US),
            "not a lasting reason"
        );
        emlsr.prevented = None;
        emlsr.prevent(Exit::Block, 6_000);
        assert_eq!(emlsr.prevented, None, "unblocking is its own way back");
    }

    #[test]
    fn the_ap_names_its_transition_or_gets_the_default_delay() {
        let response = Basic {
            eml_capabilities: Some(1 | 12 << 11),
            ..Basic::default()
        };
        let emlsr = Emlsr::offered(&response.encode());
        assert_eq!(emlsr.transition(), Some((10, 0x10ac)));
        assert_eq!(Emlsr::offered(&[]).transition(), None);
    }
}
