// SPDX-License-Identifier: GPL-2.0-only
// Adapted from pinned Linux mac80211/mlme.c: Copyright 2004, Instant802
// Networks, Inc.; 2005, Devicescape Software, Inc.; 2006-2007 Jiri Benc;
// 2007, Michael Wu; 2013-2014 Intel Mobile Communications GmbH; 2018-2026
// Intel Corporation. The firmware's side follows iwlwifi's mvm and mld.
//! `ieee80211_rx_mgmt_beacon` once associated: firmware's beacon filter passes
//! a beacon that changed, and what it says of a link's capabilities, protection,
//! EDCA and width replaces what association said. A channel switch runs
//! `ieee80211_sta_process_chanswitch`: firmware times the move and says when
//! it starts, the link's PHY follows, and silence ends at the AP's first beacon
//! on the new channel. Frames queued in firmware before a quiet switch stay
//! firmware's, which `iwl_mvm_csa_client_absent` would disable.
use super::*;
use crate::wifi::intel::firmware::Firmware;
use crate::wifi::station::{
    csa::{self, ChannelSwitch, Frame, Refusal},
    operations::ChannelDefinition,
    phy::{AccessCategory, Role, Wmm},
};

pub(super) const SWITCH_START_NOTIFICATION: (u8, u8) = (0xff, 3);
pub(super) const SWITCH_ERROR_NOTIFICATION: (u8, u8) = (0xf9, 3);
/// `CS_ERR_COUNT_ERROR`, `CS_ERR_LONG_DELAY_AFTER_CS` and
/// `CS_ERR_TX_BLOCK_TIMER_EXPIRED`.
const FATAL_SWITCH_ERRORS: u32 = 0b1011;
/// `IWL_UCODE_TLV_CAPA_CHANNEL_SWITCH_CMD` and `IWL_UCODE_TLV_CAPA_CS_MODIFY`.
const SWITCH_COMMAND: u32 = 46;
const SWITCH_MODIFY: u32 = 49;
/// `IWL_MAX_CSA_BLOCK_TX`, in TU and in microseconds.
const LONGEST_SILENCE_TU: u32 = 1500;
const LONGEST_SILENCE_US: u64 = 1_500_000;
/// One TU.
const TU_US: u64 = 1024;

/// Whether firmware's channel switch error `mask` ends the association.
pub(super) fn switch_failed(mask: u32) -> bool {
    mask & FATAL_SWITCH_ERRORS != 0
}

/// What beacons said of one link, over what association said.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Heard {
    ap: Mac,
    pub(super) capabilities: u16,
    pub(super) protection: commands::Protection,
    /// The WMM parameter set count and parameters.
    pub(super) edca: Option<(u8, [AccessCategory; 4])>,
    pub(super) definition: ChannelDefinition,
    /// The link's firmware state lags behind.
    stale: bool,
    /// So does its PHY.
    moved: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    /// Firmware has yet to hear of it.
    Announced,
    /// Firmware knows, and starts it when it is due.
    Scheduled,
    /// Firmware started it, and the link follows.
    Started,
    /// `csa.waiting_bcn`.
    Moved,
}

/// `link->conf->csa_active`, and iwlwifi's `csa_count` and `csa_misbehave`.
#[derive(Clone, Copy, Debug)]
struct Switch {
    ap: Mac,
    announced: ChannelSwitch,
    progress: Progress,
    tsf: u32,
    /// `link->u.mgd.csa.time`.
    due: u64,
    /// When `csa_work` gives up on a long silence.
    silence_ends: Option<u64>,
    /// A later beacon's count for firmware.
    recount: Option<ChannelSwitch>,
    misbehaved: bool,
}

/// What an announcement asks of the station.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Announced {
    Nothing,
    Begin(ChannelSwitch),
    Recount(ChannelSwitch),
}

#[derive(Default)]
pub(super) struct Tracking {
    links: Vec<Heard>,
    switch: Option<Switch>,
    /// `csa.blocked_tx`.
    blocked_tx: bool,
    /// `csa_connection_drop_work`.
    dropped: bool,
    /// A switch firmware started that no announcement explains.
    cancel: Option<u32>,
}

/// The AP's EDCA parameters among `elements`, with their set count.
fn wmm_parameters(mut elements: &[u8]) -> Option<(u8, [AccessCategory; 4])> {
    while let [id, length, tail @ ..] = elements {
        let (data, next) = tail.split_at_checked(usize::from(*length))?;
        if *id == 221 && data.starts_with(&[0, 0x50, 0xf2, 2]) {
            let wmm = Wmm::parse(data, Role::AccessPoint).ok()?;
            return Some((wmm.qos_info & 15, wmm.parameters?));
        }
        elements = next;
    }
    None
}

impl Tracking {
    pub(super) fn of(&self, ap: Mac) -> Option<&Heard> {
        self.links.iter().find(|heard| heard.ap == ap)
    }

    /// A switch is under way.
    pub(super) fn moving(&self) -> bool {
        self.switch.is_some()
    }

    /// The AP asked for silence.
    pub(super) fn silent(&self) -> bool {
        self.blocked_tx
    }

    pub(super) fn drop_connection(&mut self) {
        self.dropped = true;
    }

    /// The part of `ieee80211_sta_process_chanswitch` a beacon of `ap`
    /// settles, with the link on `current`.
    fn announced(
        &mut self,
        ap: Mac,
        parsed: Result<Option<ChannelSwitch>, Refusal>,
        current: &ChannelDefinition,
    ) -> Announced {
        if self.switch.is_some_and(|active| active.ap != ap) {
            return Announced::Nothing;
        }
        let switch = match parsed {
            Ok(switch) => switch,
            Err(refusal) => {
                self.dropped = true;
                self.blocked_tx = refusal.block_tx;
                return Announced::Nothing;
            }
        };
        if let Some(active) = &self.switch {
            if active.progress == Progress::Moved {
                // ieee80211_chswitch_post_beacon; a switch still announced
                // afterwards is a new one.
                self.switch = None;
                self.blocked_tx = false;
            } else if let Some(switch) = switch {
                return Announced::Recount(switch);
            } else {
                // ieee80211_sta_abort_chanswitch: the AP withdrew it.
                self.switch = None;
                self.blocked_tx = false;
                return Announced::Nothing;
            }
        }
        let Some(switch) = switch else {
            self.blocked_tx = false;
            return Announced::Nothing;
        };
        if switch.definition.control.band != current.control.band {
            self.dropped = true;
            self.blocked_tx = switch.block_tx;
            return Announced::Nothing;
        }
        if switch.definition == *current && !switch.block_tx {
            return Announced::Nothing;
        }
        Announced::Begin(switch)
    }

    /// `iwl_mvm_channel_switch_rx_beacon`: a later beacon's count for firmware
    /// that takes one, and the end of an AP that counts backwards twice.
    fn recounted(&mut self, modifies: bool) {
        let Some(active) = &mut self.switch else {
            return;
        };
        let Some(recount) = active.recount.filter(|_| modifies) else {
            active.recount = None;
            return;
        };
        if recount.count >= active.announced.count && recount.block_tx {
            if active.misbehaved {
                self.dropped = true;
                self.switch = None;
                return;
            }
            active.misbehaved = true;
        }
        active.announced.count = recount.count;
    }
}

impl Client {
    /// The channel `context`'s link runs now.
    pub(super) fn link_definition(&self, context: &AssociationContext) -> ChannelDefinition {
        self.tracking
            .of(context.bssid())
            .map_or_else(|| context.definition(), |heard| heard.definition)
    }

    /// `ieee80211_rx_mgmt_beacon`, when `frame` is a beacon of an active link.
    pub(super) fn beacon_heard(&mut self, frame: &Mpdu, now: u64) -> bool {
        let header = frame.header();
        if header.control & 0xfc != 0x80 || self.station.phase() != Peering::Associated {
            return false;
        }
        let Some(ap) = header.transmitter else {
            return false;
        };
        let Some(context) = self
            .seat_of(ap)
            .and_then(|seat| self.context_at(seat))
            .cloned()
        else {
            return false;
        };
        let bytes = frame.bytes();
        let (Some(&[tsf0, tsf1, tsf2, tsf3]), Some(&[low, high]), Some(elements)) = (
            bytes.get(24..28).and_then(|tsf| tsf.first_chunk()),
            bytes.get(34..36).and_then(|bits| bits.first_chunk()),
            bytes.get(36..),
        ) else {
            return true;
        };
        let current = self.link_definition(&context);
        let band = current.control.band;
        let parsed = csa::parse(elements, Frame::Beacon, None, band, context.negotiated());
        match self.tracking.announced(ap, parsed, &current) {
            Announced::Nothing => {}
            Announced::Begin(switch) => {
                let known = self
                    .channels
                    .iter()
                    .any(|(channel, _)| *channel == switch.definition.control);
                if !known {
                    self.tracking.drop_connection();
                    self.tracking.blocked_tx = switch.block_tx;
                    return true;
                }
                let interval = u64::from(context.beacon().beacon_interval);
                let beacons = u64::from(switch.count.max(1) - 1);
                self.tracking.blocked_tx = switch.block_tx;
                self.tracking.switch = Some(Switch {
                    ap,
                    announced: switch,
                    progress: Progress::Announced,
                    tsf: u32::from_le_bytes([tsf0, tsf1, tsf2, tsf3]),
                    due: now + beacons * interval * TU_US,
                    silence_ends: None,
                    recount: None,
                    misbehaved: false,
                });
            }
            Announced::Recount(switch) => {
                if let Some(active) = &mut self.tracking.switch {
                    active.recount = Some(switch);
                }
            }
        }
        if !self.tracking.links.iter().any(|heard| heard.ap == ap) {
            let negotiated = context.negotiated();
            self.tracking.links.push(Heard {
                ap,
                capabilities: context.beacon().capabilities,
                protection: commands::protection(&context.beacon().elements),
                edca: negotiated
                    .wmm
                    .as_ref()
                    .map(|wmm| (wmm.parameter_set_count, wmm.access_categories)),
                definition: current,
                stale: false,
                moved: false,
            });
        }
        let moving = self.tracking.moving();
        let width = (!moving).then(|| context.beacon_definition(elements, current.control));
        if matches!(width, Some(Err(_))) {
            self.tracking.drop_connection();
            return true;
        }
        let Some(heard) = self.tracking.links.iter_mut().find(|heard| heard.ap == ap) else {
            return true;
        };
        let capabilities = u16::from_le_bytes([low, high]);
        let protection = commands::protection(elements);
        heard.stale |= capabilities != heard.capabilities || protection != heard.protection;
        heard.capabilities = capabilities;
        heard.protection = protection;
        // ieee80211_sta_wmm_params: the count differs, and 15 to 0 counts.
        if let (Some((count, _)), Some(new)) = (heard.edca, wmm_parameters(elements))
            && new.0 != count
        {
            heard.edca = Some(new);
            heard.stale = true;
        }
        if let Some(Ok(definition)) = width
            && definition != heard.definition
        {
            heard.definition = definition;
            heard.stale = true;
            heard.moved = true;
        }
        true
    }

    /// Firmware's channel switch started: `iwl_mvm_channel_switch_start_notif`.
    pub(super) fn switch_started(&mut self, id: u32) {
        match &mut self.tracking.switch {
            Some(active) if active.progress == Progress::Scheduled => {
                active.progress = Progress::Started;
                active.silence_ends = None;
            }
            _ => self.tracking.cancel = Some(id),
        }
    }

    /// `iwl_mvm_pre_channel_switch` and `iwl_mld_pre_channel_switch`. The
    /// newest firmware times a switch by itself.
    fn schedule_switch(&mut self, firmware: &Firmware<'_>, now: u64) {
        let Some(active) = &mut self.tracking.switch else {
            return;
        };
        active.progress = Progress::Scheduled;
        let announced = active.announced;
        let (ap, tsf) = (active.ap, active.tsf);
        let primary = self.seat;
        let quiet = announced.block_tx;
        if self.emlsr.active {
            // Stay on the primary unless it is the link going quiet.
            let seat = self.seat_of(ap).unwrap_or(primary);
            let keep = if seat == primary && quiet {
                1 - primary
            } else {
                primary
            };
            self.emlsr.ask_exit(emlsr::Exit::ChannelSwitch, keep);
        }
        if firmware
            .command_version(3, SWITCH_ERROR_NOTIFICATION.0)
            .is_some_and(|version| version.notification_version != 0)
        {
            return;
        }
        if !firmware.supports_capability(SWITCH_COMMAND) {
            self.unsupported("a channel switch this firmware cannot time");
            self.tracking.drop_connection();
            return;
        }
        let interval = self
            .context_at(self.seat_of(ap).unwrap_or(primary))
            .map_or(100, |link| u32::from(link.beacon().beacon_interval));
        if announced.max_switch_time > LONGEST_SILENCE_TU {
            self.tracking.drop_connection();
            return;
        }
        let beacons = u32::from(announced.count) * interval;
        if quiet && (announced.count == 0 || beacons > LONGEST_SILENCE_TU) {
            active_silence(&mut self.tracking, now);
        }
        let delayed = announced.max_switch_time.div_ceil(interval.max(1));
        self.command(
            commands::CHANNEL_SWITCH,
            commands::channel_switch(false, tsf, announced.count, delayed as u8, quiet),
        );
    }

    /// `iwl_mvm_channel_switch_rx_beacon`.
    fn recount_switch(&mut self, firmware: &Firmware<'_>) {
        let timed_by_firmware = firmware
            .command_version(3, SWITCH_ERROR_NOTIFICATION.0)
            .is_some_and(|version| version.notification_version != 0);
        let modifies = !timed_by_firmware && firmware.supports_capability(SWITCH_MODIFY);
        let recount = self.tracking.switch.and_then(|active| active.recount);
        self.tracking.recounted(modifies);
        let Some(active) = &mut self.tracking.switch else {
            return;
        };
        let (tsf, Some(recount)) = (active.tsf, recount.filter(|_| modifies)) else {
            return;
        };
        active.recount = None;
        self.command(
            commands::CHANNEL_SWITCH,
            commands::channel_switch(true, tsf, recount.count, 0, recount.block_tx),
        );
    }
}

/// `csa_work` is due when a long silence ends.
fn active_silence(tracking: &mut Tracking, now: u64) {
    if let Some(active) = &mut tracking.switch {
        active.silence_ends = Some(now + LONGEST_SILENCE_US);
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// Whether the AP's silence holds frames.
    #[cfg(test)]
    pub(crate) fn silent(&self) -> bool {
        self.client.tracking.silent()
    }

    /// What the last beacons left to do, once firmware is free.
    pub(super) fn run_tracking(&mut self, queue: &mut Queue<Q, B>, now: u64) -> Result<(), Error> {
        let client = &mut self.client;
        if client.leaving || client.station.phase() != Peering::Associated {
            return Ok(());
        }
        let silence_over = client
            .tracking
            .switch
            .and_then(|active| active.silence_ends)
            .is_some_and(|ends| now >= ends);
        if core::mem::take(&mut client.tracking.dropped) || silence_over {
            client.events.push_back(keeper::Event::ConnectionLost);
            let action = client.station.disconnect().map_err(Error::Station)?;
            client.act(action);
            return Ok(());
        }
        // A link that left firmware follows without it: `ieee80211_csa_switch_work`.
        if let Some(active) = client.tracking.switch
            && client.seat_of(active.ap).is_none()
            && now >= active.due
        {
            if let Some(heard) = client
                .tracking
                .links
                .iter_mut()
                .find(|heard| heard.ap == active.ap)
            {
                heard.definition = active.announced.definition;
            }
            client.tracking.switch = None;
            client.tracking.blocked_tx = false;
        }
        if !client.idle() {
            return Ok(());
        }
        if let Some(id) = client.tracking.cancel.take() {
            if queue
                .firmware()
                .command_version(3, SWITCH_ERROR_NOTIFICATION.0)
                .is_some_and(|version| version.notification_version != 0)
            {
                client.command(
                    commands::CANCEL_CHANNEL_SWITCH,
                    commands::cancel_channel_switch(id),
                );
            }
            return Ok(());
        }
        match client.tracking.switch.map(|active| active.progress) {
            Some(Progress::Announced) => {
                self.client.schedule_switch(queue.firmware(), now);
                return Ok(());
            }
            Some(Progress::Scheduled) => self.client.recount_switch(queue.firmware()),
            Some(Progress::Started) => return self.follow_switch(queue),
            _ => {}
        }
        let stale = self
            .client
            .tracking
            .links
            .iter()
            .find(|heard| heard.stale && self.client.seat_of(heard.ap).is_some());
        match stale.copied() {
            Some(heard) => self.update_link(queue, heard),
            None => Ok(()),
        }
    }

    /// `ieee80211_link_change_chanreq` and `ieee80211_link_info_change_notify`:
    /// firmware's link takes what `heard` says.
    fn update_link(&mut self, queue: &mut Queue<Q, B>, heard: Heard) -> Result<(), Error> {
        let client = &self.client;
        let seat = client.seat_of(heard.ap).ok_or(Error::Refused("no link"))?;
        let context = client
            .context_at(seat)
            .cloned()
            .ok_or(Error::Refused("no context"))?;
        let authorized = client.port_open;
        let link = self.link_commands(queue, &context, seat, authorized)?;
        let phy = if heard.moved {
            let moved = queue.phy_moved(seat, &heard.definition, link.wide_ofdma.as_ref());
            Some(moved.ok_or(Error::Refused("channel width"))?)
        } else {
            None
        };
        let client = &mut self.client;
        if let Some((id, bytes)) = phy {
            client.command(id, bytes);
        }
        client.command(commands::LINK_CONFIG, link.link);
        if heard.moved {
            client.command(commands::RATE_CONFIG, link.rates);
        }
        if let Some(heard) = client
            .tracking
            .links
            .iter_mut()
            .find(|tracked| tracked.ap == heard.ap)
        {
            heard.stale = false;
            heard.moved = false;
        }
        Ok(())
    }

    /// `iwl_mld_switch_vif_chanctx_swap` for firmware's started switch: the
    /// link leaves its PHY for one on the new channel, and waits to hear the AP.
    fn follow_switch(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        let client = &mut self.client;
        let active = client.tracking.switch.ok_or(Error::Refused("no switch"))?;
        let target = active.announced.definition;
        let seat = client.seat_of(active.ap).ok_or(Error::Refused("no link"))?;
        let context = client
            .context_at(seat)
            .cloned()
            .ok_or(Error::Refused("no context"))?;
        let old = client.link_definition(&context);
        let heard = client
            .tracking
            .links
            .iter_mut()
            .find(|heard| heard.ap == active.ap)
            .ok_or(Error::Refused("no beacon"))?;
        heard.definition = target;
        heard.stale = false;
        heard.moved = false;
        let authorized = client.port_open;
        let link = self.link_commands(queue, &context, seat, authorized)?;
        let (removal_id, removal) = queue
            .phy_removal(seat, &old)
            .ok_or(Error::Refused("channel width"))?;
        let phy = queue
            .phy_context(seat, &target, None)
            .ok_or(Error::Refused("channel width"))?;
        let dbm = self.regulated_power_dbm(target.control.frequency_mhz);
        let (power_id, power_limit) = queue
            .transmit_limit(seat, dbm)
            .ok_or(Error::Refused("transmit power"))?;
        let mut bss = context.beacon().clone();
        bss.channel = target.control;
        let constraints = self.six_ghz_power(queue, &bss, seat);
        let client = &mut self.client;
        client.command(
            commands::LINK_CONFIG,
            commands::activation(link.link.clone(), false),
        );
        client.command(removal_id, removal);
        for (id, bytes) in phy {
            client.command(id, bytes);
        }
        client.command(commands::LINK_CONFIG, link.link.clone());
        client.command(commands::RATE_CONFIG, link.rates);
        client.command(power_id, power_limit);
        if let Some(bytes) = constraints {
            client.command(commands::POWER_CONSTRAINTS, bytes);
        }
        client.command(commands::LINK_CONFIG, commands::activation(link.link, true));
        // The chain's own link is the station's context.
        if client
            .station
            .validate_association_context(&context)
            .is_ok()
        {
            client
                .station
                .switch_channel(&context, target)
                .map_err(Error::Station)?;
        }
        if let Some(active) = &mut client.tracking.switch {
            active.progress = Progress::Moved;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP: Mac = Mac([2, 0, 0, 0, 0, 3]);

    fn definition(band: Band, number: u16, frequency_mhz: u16) -> ChannelDefinition {
        ChannelDefinition {
            control: Channel {
                band,
                number,
                frequency_mhz,
            },
            width: phy::Width::Mhz20,
            center1_mhz: u32::from(frequency_mhz),
            center2_mhz: None,
            punctured: 0,
        }
    }

    fn switch(definition: ChannelDefinition, block_tx: bool, count: u8) -> ChannelSwitch {
        ChannelSwitch {
            block_tx,
            count,
            definition,
            ap: definition,
            max_switch_time: 0,
        }
    }

    fn running(announced: ChannelSwitch, progress: Progress) -> Tracking {
        Tracking {
            blocked_tx: announced.block_tx,
            switch: Some(Switch {
                ap: AP,
                announced,
                progress,
                tsf: 0,
                due: 0,
                silence_ends: None,
                recount: None,
                misbehaved: false,
            }),
            ..Tracking::default()
        }
    }

    const fn here() -> (u16, u16) {
        (36, 5180)
    }

    #[test]
    fn a_beacon_begins_a_switch_and_a_later_one_counts_it_down() {
        let current = definition(Band::Ghz5, here().0, here().1);
        let target = definition(Band::Ghz5, 40, 5200);
        let mut tracking = Tracking::default();
        assert_eq!(
            tracking.announced(AP, Ok(Some(switch(target, false, 5))), &current),
            Announced::Begin(switch(target, false, 5))
        );
        let mut tracking = running(switch(target, false, 5), Progress::Scheduled);
        assert_eq!(
            tracking.announced(AP, Ok(Some(switch(target, false, 4))), &current),
            Announced::Recount(switch(target, false, 4))
        );
        let other = Mac([2, 0, 0, 0, 0, 4]);
        assert_eq!(
            tracking.announced(other, Ok(Some(switch(target, false, 4))), &current),
            Announced::Nothing,
            "one link at a time"
        );
    }

    #[test]
    fn silence_ends_with_the_ap_withdrawing_or_being_heard_after_the_move() {
        let current = definition(Band::Ghz5, here().0, here().1);
        let target = definition(Band::Ghz5, 40, 5200);
        let mut withdrawn = running(switch(target, true, 5), Progress::Scheduled);
        assert!(withdrawn.silent());
        assert_eq!(
            withdrawn.announced(AP, Ok(None), &current),
            Announced::Nothing
        );
        assert!(!withdrawn.silent() && !withdrawn.moving());
        let mut heard = running(switch(target, true, 1), Progress::Moved);
        assert_eq!(heard.announced(AP, Ok(None), &target), Announced::Nothing);
        assert!(!heard.silent() && !heard.moving());
    }

    #[test]
    fn a_switch_to_another_band_or_refused_drops_the_connection() {
        let current = definition(Band::Ghz5, here().0, here().1);
        let target = definition(Band::Ghz2, 1, 2412);
        let mut tracking = Tracking::default();
        tracking.announced(AP, Ok(Some(switch(target, true, 5))), &current);
        assert!(tracking.dropped && tracking.silent());
        let mut tracking = Tracking::default();
        let refusal = Refusal {
            block_tx: false,
            error: phy::Error::Unsupported("test"),
        };
        tracking.announced(AP, Err(refusal), &current);
        assert!(tracking.dropped && !tracking.silent());
    }

    #[test]
    fn a_switch_to_the_same_channel_matters_only_when_it_silences() {
        let current = definition(Band::Ghz5, here().0, here().1);
        let mut tracking = Tracking::default();
        assert_eq!(
            tracking.announced(AP, Ok(Some(switch(current, false, 5))), &current),
            Announced::Nothing
        );
        assert_eq!(
            tracking.announced(AP, Ok(Some(switch(current, true, 5))), &current),
            Announced::Begin(switch(current, true, 5))
        );
    }

    #[test]
    fn an_ap_that_keeps_raising_a_quiet_count_is_given_up_on() {
        let target = definition(Band::Ghz5, 40, 5200);
        let mut tracking = running(switch(target, true, 5), Progress::Scheduled);
        let raised = |tracking: &mut Tracking, count| {
            if let Some(active) = &mut tracking.switch {
                active.recount = Some(switch(target, true, count));
            }
            tracking.recounted(true);
        };
        raised(&mut tracking, 5);
        assert!(!tracking.dropped);
        raised(&mut tracking, 5);
        assert!(tracking.dropped);
    }

    #[test]
    fn the_wmm_set_count_comes_with_its_parameters() {
        let mut element = vec![221, 24, 0, 0x50, 0xf2, 2, 1, 1, 7, 0];
        for aci in 0..4u8 {
            element.extend([aci << 5 | 3, 0x54, 0, 0]);
        }
        let (count, parameters) = wmm_parameters(&element).unwrap();
        assert_eq!(count, 7);
        assert_eq!(parameters[1].aci, 1);
        assert_eq!(wmm_parameters(&[3, 1, 36]), None);
    }
}
