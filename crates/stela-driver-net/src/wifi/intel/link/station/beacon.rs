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
    pub(super) ap: Mac,
    pub(super) capabilities: u16,
    pub(super) protection: commands::Protection,
    /// The WMM parameter set count and parameters.
    pub(super) edca: Option<(u8, [AccessCategory; 4])>,
    /// The MU EDCA set in force and its count, once the beacon holds one.
    pub(super) mu_edca: Option<(u8, [MuEdcaRecord; 4])>,
    pub(super) definition: ChannelDefinition,
    /// What the AP limits, fitted to the link.
    envelope: PowerEnvelope,
    /// The link's firmware state lags behind.
    stale: bool,
    /// So does its PHY.
    moved: bool,
    /// So does what firmware knows of `envelope`.
    limited: bool,
}

/// What `elements` limit on the `used` part of the AP's channel, as
/// `ieee80211_config_bw` keeps it.
fn fitted(
    elements: &[u8],
    control: Channel,
    mode: phy::Mode,
    used: &ChannelDefinition,
) -> PowerEnvelope {
    let ap = Operations::parse(elements)
        .ok()
        .and_then(|operations| operations.channel(control, mode, None).ok());
    let Some(ap) = ap else {
        return PowerEnvelope::none();
    };
    let mut envelope = PowerEnvelope::parse(elements);
    envelope.fit(&ap, used);
    envelope
}

#[derive(Default)]
pub(super) struct Tracking {
    pub(super) links: Vec<Heard>,
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
        if context.affiliation().is_some()
            && let Some(&timestamp) = bytes.get(24..32).and_then(|stamp| stamp.first_chunk())
        {
            self.links_announced(elements, u64::from_le_bytes(timestamp), now);
        }
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
                envelope: fitted(
                    &context.beacon().elements,
                    current.control,
                    negotiated.mode,
                    &current,
                ),
                stale: false,
                moved: false,
                limited: false,
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
        if band == Band::Ghz6 && !moving {
            let mode = context.negotiated().mode;
            // ieee80211_config_bw selects the new operating width before
            // rearranging the beacon's TPE subchannel limits.
            let used = width
                .as_ref()
                .and_then(|width| width.as_ref().ok())
                .unwrap_or(&current);
            let envelope = fitted(elements, used.control, mode, used);
            heard.limited |= envelope != heard.envelope;
            heard.envelope = envelope;
        }
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

    /// `silent_deactivation`: `link` is going quiet for a switch.
    pub(super) fn going_quiet(&self, link: &AssociationContext) -> bool {
        self.tracking.watch.switch.is_some_and(|active| {
            active.announced.block_tx
                && (active.ap == link.bssid() || active.ap == link.beacon().transmitter)
        })
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
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
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
        let lagging = self.client.tracking.links.iter().find(|heard| {
            (heard.stale || heard.limited) && self.client.seat_of(heard.ap).is_some()
        });
        match lagging.copied() {
            Some(heard) if heard.stale => self.update_link(queue, heard),
            Some(heard) => self.update_power(queue, heard),
            None => Ok(()),
        }
    }

    /// `BSS_CHANGED_TPE`, as `iwl_mld_send_ap_tx_power_constraint_cmd` tells
    /// firmware.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn update_power(&mut self, queue: &mut Queue<Q, B>, heard: Heard) -> Result<(), Error> {
        let client = &self.client;
        let seat = client.seat_of(heard.ap).ok_or(Error::Refused("no link"))?;
        let mut bss = client
            .context_at(seat)
            .ok_or(Error::Refused("no context"))?
            .beacon()
            .clone();
        bss.channel = heard.definition.control;
        let constraints = self.six_ghz_power(queue, &bss, seat, Some(heard.envelope));
        let client = &mut self.client;
        if let Some(bytes) = constraints {
            client.command(commands::POWER_CONSTRAINTS, bytes);
        }
        if let Some(heard) = client
            .tracking
            .links
            .iter_mut()
            .find(|tracked| tracked.ap == heard.ap)
        {
            heard.limited = false;
        }
        Ok(())
    }

    /// `ieee80211_link_change_chanreq` and `ieee80211_link_info_change_notify`:
    /// firmware's link takes what `heard` says.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
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
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
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
        // Applied at once on the new channel, until its beacons say.
        let mut envelope = active.announced.envelope;
        envelope.fit(&active.announced.ap, &target);
        heard.definition = target;
        heard.envelope = envelope;
        heard.stale = false;
        heard.moved = false;
        heard.limited = false;
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
        let constraints = self.six_ghz_power(queue, &bss, seat, Some(envelope));
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

#[cfg(test)]
mod tests {
    //! Protocol-only beacon power tracking with no native transmission permission.
    use super::*;
    use crate::wifi::{
        RadioStatus, RawRate,
        security::SecurityStatus,
        station::{
            self, Completion, Join, PortPolicy,
            phy::{Mode, Width},
            tests::{AP, LOCAL, Policy, ticket},
        },
    };
    use alloc::vec;
    fn channel() -> Channel {
        Channel {
            band: Band::Ghz6,
            number: 13,
            frequency_mhz: 6015,
        }
    }
    fn extension(out: &mut Vec<u8>, id: u8, bytes: &[u8]) {
        out.extend([255, (bytes.len() + 1) as u8, id]);
        out.extend(bytes);
    }
    fn elements(ap: bool, wide: bool, limits: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 1, b'x', 1, 3, 0x8c, 0x98, 0xb0];
        let mut he = vec![0; 17];
        he[6] = 4;
        he.extend([0xfa, 0xff, 0xfa, 0xff]);
        extension(&mut out, 35, &he);
        extension(&mut out, 59, &[0x4a, 0]);
        if ap {
            out.extend([
                221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x80, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42,
                0x43, 94, 0, 0x62, 0x32, 47, 0,
            ]);
            extension(
                &mut out,
                36,
                &[
                    0,
                    0,
                    2,
                    0,
                    0xff,
                    0xff,
                    13,
                    if wide { 2 } else { 1 },
                    if wide { 7 } else { 11 },
                    0,
                    6,
                ],
            );
            out.extend([5, 4, 0, 3, 0, 0]);
            out.extend([195, (limits.len() + 1) as u8, 8 + if wide { 3 } else { 2 }]);
            out.extend(limits);
        } else {
            out.extend([221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0]);
        }
        out.extend(station::wire::six_ghz::tests::selected());
        out
    }
    fn frame(control: u16, body: &[u8], broadcast: bool) -> Mpdu {
        let mut bytes = vec![0; 24];
        bytes[..2].copy_from_slice(&control.to_le_bytes());
        bytes[4..10].copy_from_slice(if broadcast { &[0xff; 6] } else { &LOCAL.0 });
        bytes[10..16].copy_from_slice(&AP.0);
        bytes[16..22].copy_from_slice(&AP.0);
        bytes.extend(body);
        Mpdu::new(
            bytes,
            RadioStatus {
                band: Band::Ghz6,
                channel: 13,
                frequency_mhz: 6015,
                signal_dbm: Some(-45),
                chain_signal_dbm: [None; 4],
                rate: RawRate {
                    layout: 1,
                    words: [0; 4],
                },
                rx_rate: None,
                tsf: None,
            },
            SecurityStatus::default(),
        )
        .unwrap()
    }
    fn client() -> Client {
        let local = station::phy::Capabilities::parse(
            Band::Ghz6,
            station::phy::Role::Station,
            &elements(false, true, &[]),
        )
        .unwrap();
        let request = station::wire::AssociationRequest::new_modern_with_local_pmf(
            0x11,
            10,
            elements(false, true, &[]),
            local.clone(),
            Mode::He,
            Width::Mhz80,
        )
        .unwrap();
        let join = Join {
            bssid: AP,
            channel: channel(),
            policy: PortPolicy::Controlled,
            request,
        };
        struct ListenOnly;
        impl crate::wifi::scan::Policy for ListenOnly {
            fn allow_receive(&mut self, c: Channel) -> bool {
                c == channel()
            }
            fn allow_probe(&mut self, _: Channel) -> bool {
                false
            }
            fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
                (band == Band::Ghz6 && number == 13).then(channel)
            }
        }
        let scan = crate::wifi::scan::Scanner::new(LOCAL)
            .unwrap()
            .begin(
                crate::wifi::scan::Request::new(vec![channel()], vec![], vec![]).unwrap(),
                0,
                100,
                &mut ListenOnly,
            )
            .unwrap();
        let beacon = crate::wifi::scan::result::Bss {
            ticket: scan,
            kind: crate::wifi::scan::result::Kind::Beacon,
            bssid: AP,
            transmitter: AP,
            profile: None,
            timestamp: 100,
            beacon_interval: 100,
            capabilities: 0x11,
            channel: channel(),
            observed: frame(0xb0, &[0; 6], false).radio,
            signal_dbm: Some(-45),
            ssid: Some(vec![b'x']),
            elements: elements(true, true, &[2, 4, 20, 24]),
        };
        let observed = Arc::new(station::NativeBssObservation { bss: beacon });
        let mut station = station::Station::new(LOCAL).unwrap();
        let selection =
            station::wire::six_ghz::Selection::new(station::wire::six_ghz::tests::selected())
                .unwrap();
        let session = station
            .prepare_six_ghz_authentication(observed.clone(), selection, local, None, 0, 1_000_000)
            .unwrap();
        station
            .commit_six_ghz_authentication(session.clone(), 0)
            .unwrap();
        for (transaction, status, now) in [(1, 126, 1), (2, 0, 3)] {
            station
                .external_authentication_transmit(
                    &session,
                    station::external::Frame {
                        transaction,
                        status,
                        data: &[19, 0],
                    },
                    now,
                    &mut Policy(true),
                )
                .unwrap();
            let body = [3, 0, transaction as u8, 0, status as u8, 0, 19, 0];
            station
                .receive_external_authentication(&session, frame(0xb0, &body, false), now + 1)
                .unwrap()
                .unwrap();
        }
        assert!(station.external_authenticated());
        let assoc = station
            .associate_external_pmf(&session, join, observed, 6, &mut Policy(true))
            .unwrap();
        station.submitted(ticket(&assoc)).unwrap();
        let mut body = vec![0x11, 0, 0, 0, 1, 0xc0];
        body.extend(elements(true, true, &[2, 4, 20, 24]));
        let configured = station
            .receive(
                station.association_epoch().unwrap(),
                &frame(0x10, &body, false),
                7,
                &mut Policy(true),
            )
            .unwrap();
        let context = match &configured {
            station::Action::Configure {
                context: Some(context),
                ..
            } => context.clone(),
            _ => panic!("modern context required"),
        };
        station
            .complete_configuration(ticket(&configured), Completion::Accepted, 8)
            .unwrap();
        let mut client = Client::new(station);
        client.context = Some(context);
        client
    }
    fn beacon(wide: bool, limits: &[u8]) -> Mpdu {
        let mut body = vec![0; 12];
        body[..8].copy_from_slice(&100u64.to_le_bytes());
        body[8..10].copy_from_slice(&100u16.to_le_bytes());
        body[10..12].copy_from_slice(&0x11u16.to_le_bytes());
        body.extend(elements(true, wide, limits));
        frame(0x80, &body, true)
    }
    #[test]
    fn widened_beacon_keeps_limits_for_every_newly_used_subchannel() {
        let mut client = client();
        assert!(client.beacon_heard(&beacon(false, &[20, 24]), 10));
        assert_eq!(
            client.tracking.of(AP).unwrap().definition.width,
            Width::Mhz40
        );
        assert!(client.beacon_heard(&beacon(true, &[2, 4, 20, 24]), 11));
        let heard = client.tracking.of(AP).unwrap();
        assert_eq!(heard.definition.width, Width::Mhz80);
        assert_eq!(heard.envelope.psd_local[0].power[..4], [2, 4, 20, 24]);
        assert_eq!(heard.envelope.psd_local[0].mean(4), 6);
        assert!(heard.limited);
    }
    #[test]
    fn unchanged_width_updates_limits_and_identical_beacons_need_no_power_command() {
        let mut client = client();
        assert!(client.beacon_heard(&beacon(true, &[2, 4, 20, 24]), 10));
        assert!(!client.tracking.of(AP).unwrap().limited);
        assert!(client.beacon_heard(&beacon(true, &[2, 4, 8, 12]), 11));
        assert!(client.tracking.of(AP).unwrap().limited);
        client.tracking.links[0].limited = false;
        assert!(client.beacon_heard(&beacon(true, &[2, 4, 8, 12]), 12));
        assert!(!client.tracking.of(AP).unwrap().limited);
    }
}
