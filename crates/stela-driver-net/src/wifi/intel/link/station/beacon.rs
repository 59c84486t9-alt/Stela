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
//! on the new channel. Firmware that leaves it to the host stops sending to
//! the AP for the move, as `iwl_mvm_csa_client_absent` tells it to. A
//! nontransmitted BSS reads its share of its transmitter's beacons, and an EMA
//! AP's beacon without that share says only what they all inherit.
use super::*;
use crate::wifi::intel::firmware::Firmware;
use crate::wifi::scan::multiple_bssid;
use crate::wifi::station::{
    csa::{
        self, Announced, Announcement, ChannelSwitch, Frame, Progress, Refusal, Source, Switch,
        Watch,
    },
    operations::{ChannelDefinition, MuEdcaRecord, Operations},
    phy::{AccessCategory, Wmm},
};

pub(super) const SWITCH_START_NOTIFICATION: (u8, u8) = (0xff, 3);
pub(super) const SWITCH_ERROR_NOTIFICATION: (u8, u8) = (0xf9, 3);
/// `CS_ERR_COUNT_ERROR`, `CS_ERR_LONG_DELAY_AFTER_CS` and
/// `CS_ERR_TX_BLOCK_TIMER_EXPIRED`.
const FATAL_SWITCH_ERRORS: u32 = 0b1011;
/// `IWL_UCODE_TLV_CAPA_CHANNEL_SWITCH_CMD` and `IWL_UCODE_TLV_CAPA_CS_MODIFY`.
const SWITCH_COMMAND: u32 = 46;
const SWITCH_MODIFY: u32 = 49;
/// `IWL_UCODE_TLV_API_NO_HOST_DISABLE_TX`.
pub(super) const FIRMWARE_DISABLES_TX: u32 = 66;
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
    /// The MU EDCA set in force and its count, once the beacon holds one.
    pub(super) mu_edca: Option<(u8, [MuEdcaRecord; 4])>,
    pub(super) definition: ChannelDefinition,
    /// The link's firmware state lags behind.
    stale: bool,
    /// So does its PHY.
    moved: bool,
}

#[derive(Default)]
pub(super) struct Tracking {
    links: Vec<Heard>,
    /// What the AP announced, and how far the switch has come.
    pub(super) watch: Watch,
    /// A switch firmware started that no announcement explains.
    cancel: Option<u32>,
    /// The station firmware was told not to send to.
    disabled: Option<u8>,
}

impl Tracking {
    pub(super) fn of(&self, ap: Mac) -> Option<&Heard> {
        self.links.iter().find(|heard| heard.ap == ap)
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
        let Some(sender) = header.transmitter else {
            return false;
        };
        let Some(context) = self
            .seat_of(sender)
            .and_then(|seat| self.context_at(seat))
            .cloned()
        else {
            return false;
        };
        let ap = context.bssid();
        let bytes = frame.bytes();
        let (Some(&[tsf0, tsf1, tsf2, tsf3]), Some(&[low, high]), Some(elements)) = (
            bytes.get(24..28).and_then(|tsf| tsf.first_chunk()),
            bytes.get(34..36).and_then(|bits| bits.first_chunk()),
            bytes.get(36..),
        ) else {
            return true;
        };
        let own = multiple_bssid::heard(context.beacon(), elements);
        let elements = own.as_ref().map_or(elements, |own| own.elements.as_slice());
        let current = self.link_definition(&context);
        let band = current.control.band;
        let parsed = csa::parse(elements, Frame::Beacon, None, band, context.negotiated());
        let tsf = u32::from_le_bytes([tsf0, tsf1, tsf2, tsf3]);
        if self.announcement(&context, parsed, Source::Beacon, tsf, now) {
            return true;
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
                mu_edca: {
                    let operations = context.operations();
                    operations.mu_edca_count.zip(operations.mu_edca)
                },
                definition: current,
                stale: false,
                moved: false,
            });
        }
        let moving = self.tracking.watch.moving();
        let width = (!moving).then(|| context.beacon_definition(elements, current.control));
        if matches!(width, Some(Err(_))) {
            self.tracking.watch.drop_connection();
            return true;
        }
        let Some(heard) = self.tracking.links.iter_mut().find(|heard| heard.ap == ap) else {
            return true;
        };
        let capabilities = match &own {
            Some(own) => own.capabilities,
            None if context.beacon().profile.is_some() => heard.capabilities,
            None => u16::from_le_bytes([low, high]),
        };
        let protection = commands::protection(elements);
        heard.stale |= capabilities != heard.capabilities || protection != heard.protection;
        heard.capabilities = capabilities;
        heard.protection = protection;
        // ieee80211_sta_wmm_params: a count differs, and 15 to 0 counts. A set
        // of MU EDCA that goes away differs too.
        let mu_edca = Operations::parse(elements).map_or(heard.mu_edca, |operations| {
            operations.mu_edca_count.zip(operations.mu_edca)
        });
        let mu_edca_count = |set: Option<(u8, [MuEdcaRecord; 4])>| set.map(|(count, _)| count);
        if let (Some((count, _)), Some(new)) = (heard.edca, Wmm::announced(elements))
            && (new.0 != count || mu_edca_count(mu_edca) != mu_edca_count(heard.mu_edca))
        {
            heard.edca = Some(new);
            heard.mu_edca = mu_edca;
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

    /// What `ieee80211_sta_process_chanswitch` makes of an announcement on
    /// `context`'s link heard at `tsf`, and whether it gave the link up.
    fn announcement(
        &mut self,
        context: &AssociationContext,
        parsed: Result<Option<ChannelSwitch>, Refusal>,
        source: Source,
        tsf: u32,
        now: u64,
    ) -> bool {
        let ap = context.bssid();
        let current = self.link_definition(context);
        match self.tracking.watch.announced(ap, parsed, source, &current) {
            Announced::Nothing => {}
            Announced::Begin(switch) => {
                let known = self
                    .channels
                    .iter()
                    .any(|(channel, _)| *channel == switch.definition.control);
                if !known {
                    self.tracking.watch.drop_connection();
                    self.tracking.watch.blocked_tx = switch.block_tx;
                    return true;
                }
                let interval = u64::from(context.beacon().beacon_interval);
                let beacons = u64::from(switch.count.max(1) - 1);
                self.tracking.watch.blocked_tx = switch.block_tx;
                self.tracking.watch.switch = Some(Switch {
                    ap,
                    announced: switch,
                    progress: Progress::Announced,
                    tsf,
                    due: now + beacons * interval * TU_US,
                    silence_ends: None,
                    recount: None,
                    misbehaved: false,
                });
            }
            Announced::Recount(switch) => {
                if let Some(active) = &mut self.tracking.watch.switch {
                    active.recount = Some(switch);
                }
            }
        }
        false
    }

    /// A Spectrum Management or (Protected Dual of) Public action frame from
    /// `ap`, as `ieee80211_sta_rx_queued_mgmt` takes it.
    pub(super) fn switch_action(&mut self, frame: &Mpdu, body: &[u8], now: u64) {
        let Some(ap) = frame.header().transmitter else {
            return;
        };
        let tsf = match frame.radio.tsf {
            Some(crate::wifi::Timestamp::Full64(tsf)) => tsf as u32,
            _ => 0,
        };
        let Some(announcement) = Announcement::of(body) else {
            return;
        };
        let Some(context) = self
            .seat_of(ap)
            .and_then(|seat| self.context_at(seat))
            .cloned()
        else {
            return;
        };
        let band = self.link_definition(&context).control.band;
        let negotiated = context.negotiated();
        let Announcement {
            elements,
            extended,
            source,
        } = announcement;
        let parsed = csa::parse(elements, Frame::Action, extended, band, negotiated);
        self.announcement(&context, parsed, source, tsf, now);
    }

    /// Firmware's channel switch started: `iwl_mvm_channel_switch_start_notif`,
    /// `disable_tx` if the host has to stop what firmware holds for the AP.
    pub(super) fn switch_started(&mut self, id: u32, disable_tx: bool) {
        let Some(active) = self
            .tracking
            .watch
            .switch
            .as_mut()
            .filter(|active| active.progress == Progress::Scheduled)
        else {
            self.tracking.cancel = Some(id);
            return;
        };
        active.progress = Progress::Started;
        active.silence_ends = None;
        let ap = active.ap;
        if disable_tx {
            let station = self.seat_of(ap).unwrap_or(self.seat);
            self.tracking.disabled = Some(station);
            self.command(
                commands::STATION_DISABLE_TX,
                commands::station_disable_tx(station, true),
            );
        }
    }

    /// `iwl_mvm_pre_channel_switch` and `iwl_mld_pre_channel_switch`. The
    /// newest firmware times a switch by itself.
    fn schedule_switch(&mut self, firmware: &Firmware<'_>, now: u64) {
        let Some(active) = &mut self.tracking.watch.switch else {
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
            self.tracking.watch.drop_connection();
            return;
        }
        let interval = self
            .context_at(self.seat_of(ap).unwrap_or(primary))
            .map_or(100, |link| u32::from(link.beacon().beacon_interval));
        if announced.max_switch_time > LONGEST_SILENCE_TU {
            self.tracking.watch.drop_connection();
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
        let recount = self.tracking.watch.switch.and_then(|active| active.recount);
        self.tracking.watch.recounted(modifies);
        let Some(active) = &mut self.tracking.watch.switch else {
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
    if let Some(active) = &mut tracking.watch.switch {
        active.silence_ends = Some(now + LONGEST_SILENCE_US);
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// Whether the AP's silence holds frames.
    #[cfg(test)]
    pub(crate) fn silent(&self) -> bool {
        self.client.tracking.watch.silent()
    }

    /// What the last beacons left to do, once firmware is free.
    pub(super) fn run_tracking(&mut self, queue: &mut Queue<Q, B>, now: u64) -> Result<(), Error> {
        let client = &mut self.client;
        if client.leaving || client.station.phase() != Peering::Associated {
            return Ok(());
        }
        client.check_links_usable(now);
        let silence_over = client
            .tracking
            .watch
            .switch
            .and_then(|active| active.silence_ends)
            .is_some_and(|ends| now >= ends);
        if core::mem::take(&mut client.tracking.watch.dropped) || silence_over {
            client.events.push_back(keeper::Event::ConnectionLost);
            let action = client.station.disconnect().map_err(Error::Station)?;
            client.act(action);
            return Ok(());
        }
        // iwl_mvm_post_channel_switch, past the AP's first beacon there.
        let moving =
            client.tracking.watch.switch.is_some_and(|active| {
                matches!(active.progress, Progress::Started | Progress::Moved)
            });
        if !moving && let Some(station) = client.tracking.disabled.take() {
            client.command(
                commands::STATION_DISABLE_TX,
                commands::station_disable_tx(station, false),
            );
        }
        // A link that left firmware follows without it: `ieee80211_csa_switch_work`.
        if let Some(active) = client.tracking.watch.switch
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
            client.tracking.watch.switch = None;
            client.tracking.watch.blocked_tx = false;
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
        match client.tracking.watch.switch.map(|active| active.progress) {
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
        client.bluetooth.link_changed();
        let active = client
            .tracking
            .watch
            .switch
            .ok_or(Error::Refused("no switch"))?;
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
        if let Some(active) = &mut client.tracking.watch.switch {
            active.progress = Progress::Moved;
        }
        Ok(())
    }
}
