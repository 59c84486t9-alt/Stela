// SPDX-License-Identifier: GPL-2.0-only
// Adapted from pinned Linux mac80211/mlme.c: Copyright 2004, Instant802
// Networks, Inc.; 2005, Devicescape Software, Inc.; 2006-2007 Jiri Benc;
// 2007, Michael Wu; 2013-2014 Intel Mobile Communications GmbH; 2018-2026
// Intel Corporation. Full source notices in THIRD_PARTY.md.
//! What mac80211 does for rtw88 once associated. `ieee80211_rx_mgmt_beacon`
//! lets a beacon's slot, EDCA and width replace what association said, and
//! `ieee80211_sta_process_chanswitch` moves the link in software, the host
//! timing the move: rtw88 has no `channel_switch` or `abort_channel_switch`, so
//! a switch once begun runs to its end. After the move silence holds until a
//! beacon is heard, and unlike mac80211, which waits on a beacon for good, the
//! connection monitor runs again to give up on one that never comes.
use super::*;
use crate::wifi::station::{
    csa::{
        self, Announced, Announcement, ChannelSwitch, Frame, Progress, Refusal, Source, Switch,
        Watch,
    },
    monitor::{Monitor, Step},
    phy::Wmm,
};

/// One TU.
const TU_US: u64 = 1024;

/// `ieee80211_handle_bss_capability`'s slot.
pub(super) fn short_slot(band: Band, capabilities: u16) -> bool {
    band != Band::Ghz2 || capabilities & (1 << 10) != 0
}

/// What beacons said of the AP, over what association said.
pub(super) struct Following {
    monitor: Monitor,
    watch: Watch,
    capabilities: u16,
    /// The WMM parameter set count and parameters.
    edca: Option<(u8, [AccessCategory; 4])>,
    definition: ChannelDefinition,
    /// The TX report number the nullfunc awaits.
    probing: Option<u8>,
}

impl Following {
    pub(super) fn new(context: &AssociationContext, now: u64) -> Self {
        Self {
            monitor: Monitor::new(context.beacon().beacon_interval, now),
            watch: Watch {
                committed: true,
                ..Watch::default()
            },
            capabilities: context.beacon().capabilities,
            edca: context
                .negotiated()
                .wmm
                .as_ref()
                .map(|wmm| (wmm.parameter_set_count, wmm.access_categories)),
            definition: context.definition(),
            probing: None,
        }
    }

    /// The width the link runs at.
    pub(super) fn width(&self) -> Width {
        self.definition.width
    }

    /// The AP asked for silence.
    pub(super) fn silent(&self) -> bool {
        self.watch.silent()
    }

    /// A unicast frame came from the AP.
    pub(super) fn heard(&mut self, now: u64) {
        self.monitor.heard(now);
    }

    /// The TX report `number` said whether the AP took a frame.
    pub(super) fn reported(&mut self, number: u8, acknowledged: bool, now: u64) {
        if self.probing == Some(number) {
            self.probing = None;
            self.monitor.acknowledged(acknowledged, now);
        }
    }
}

impl<D: Device> Rtl8822c<D> {
    /// `ieee80211_rx_mgmt_beacon`.
    pub(super) fn beacon_heard(&mut self, frame: &Mpdu, now: u64) -> Result<(), Error> {
        let (Some(context), Some(following)) = (self.context.clone(), &mut self.following) else {
            return Ok(());
        };
        if frame.header().transmitter != Some(context.bssid())
            || self.station.phase() != Peering::Associated
        {
            return Ok(());
        }
        following.monitor.beacon(now);
        let bytes = frame.bytes();
        let (Some(&[low, high]), Some(elements)) = (
            bytes.get(34..36).and_then(|bits| bits.first_chunk()),
            bytes.get(36..),
        ) else {
            return Ok(());
        };
        let band = following.definition.control.band;
        let parsed = csa::parse(elements, Frame::Beacon, None, band, context.negotiated());
        if self.announcement(&context, parsed, Source::Beacon, now) {
            return Ok(());
        }
        let Some(following) = &mut self.following else {
            return Ok(());
        };
        let width = (!following.watch.moving())
            .then(|| context.beacon_definition(elements, following.definition.control));
        if matches!(width, Some(Err(_))) {
            following.watch.drop_connection();
            return Ok(());
        }
        let capabilities = u16::from_le_bytes([low, high]);
        let slot = short_slot(band, capabilities);
        let mut parameters = slot != short_slot(band, following.capabilities);
        following.capabilities = capabilities;
        // ieee80211_sta_wmm_params: a count differs, and 15 to 0 counts.
        if let (Some((count, _)), Some(new)) = (following.edca, Wmm::announced(elements))
            && new.0 != count
        {
            following.edca = Some(new);
            parameters = true;
        }
        let moved = match width {
            Some(Ok(definition)) if definition != following.definition => {
                following.definition = definition;
                true
            }
            _ => false,
        };
        if parameters && let Some((_, edca)) = following.edca {
            Self::hardware(self.device.set_edca(&edca, slot))?;
        }
        if moved {
            self.retune(&context)?;
        }
        Ok(())
    }

    /// What `ieee80211_sta_process_chanswitch` makes of an announcement on
    /// `context`'s link, and whether it gave the link up.
    fn announcement(
        &mut self,
        context: &AssociationContext,
        parsed: Result<Option<ChannelSwitch>, Refusal>,
        source: Source,
        now: u64,
    ) -> bool {
        let Some(following) = &mut self.following else {
            return true;
        };
        let current = following.definition;
        let ap = context.bssid();
        let Announced::Begin(switch) = following.watch.announced(ap, parsed, source, &current)
        else {
            return false;
        };
        following.watch.blocked_tx = switch.block_tx;
        let control = switch.definition.control;
        if !self.channels.iter().any(|(channel, _)| *channel == control) {
            following.watch.drop_connection();
            return true;
        }
        let interval = u64::from(context.beacon().beacon_interval);
        let beacons = u64::from(switch.count.max(1) - 1);
        following.watch.switch = Some(Switch {
            ap,
            announced: switch,
            progress: Progress::Announced,
            tsf: 0,
            due: now + beacons * interval * TU_US,
            silence_ends: None,
            recount: None,
            misbehaved: false,
        });
        false
    }

    /// A Spectrum Management or (Protected Dual of) Public action frame, as
    /// `ieee80211_sta_rx_queued_mgmt` takes it.
    pub(super) fn switch_action(&mut self, body: &[u8], now: u64) {
        let (Some(announcement), Some(context), Some(following)) = (
            Announcement::of(body),
            self.context.clone(),
            &self.following,
        ) else {
            return;
        };
        let band = following.definition.control.band;
        let negotiated = context.negotiated();
        let Announcement {
            elements,
            extended,
            source,
        } = announcement;
        let parsed = csa::parse(elements, Frame::Action, extended, band, negotiated);
        self.announcement(&context, parsed, source, now);
    }

    /// `ieee80211_sta_work`, the monitors' timers and `csa_switch_work`.
    pub(super) fn follow(&mut self, now: u64) -> Result<(), Error> {
        let (Some(context), Some(following)) = (self.context.clone(), &mut self.following) else {
            return Ok(());
        };
        if self.left || self.station.phase() != Peering::Associated {
            return Ok(());
        }
        if core::mem::take(&mut following.watch.dropped) {
            return self.lose();
        }
        if let Some(active) = &mut following.watch.switch
            && active.progress == Progress::Announced
        {
            if now < active.due {
                return Ok(());
            }
            active.progress = Progress::Moved;
            following.definition = active.announced.definition;
            following.monitor.restart(now);
            return self.retune(&context);
        }
        // `ieee80211_offchannel_return` starts the monitors over.
        if self.hop.is_some() {
            following.monitor.restart(now);
            return Ok(());
        }
        match following.monitor.poll(now) {
            Step::Wait => Ok(()),
            Step::Lost => self.lose(),
            Step::Probe => {
                self.probe(&context);
                Ok(())
            }
        }
    }

    /// `ieee80211_sta_connection_lost`, which sends nothing to a lost AP.
    fn lose(&mut self) -> Result<(), Error> {
        self.events.push_back(keeper::Event::ConnectionLost);
        let action = self.station.disconnect().map_err(Error::Station)?;
        self.act(action);
        Ok(())
    }

    /// `rtw_ops_config` of the link's channel, then `rtw_sta_rc_work`.
    fn retune(&mut self, context: &AssociationContext) -> Result<(), Error> {
        let Some(following) = &self.following else {
            return Ok(());
        };
        let definition = following.definition;
        let eirp_mbm = self.eirp_mbm(definition.control.frequency_mhz);
        Self::hardware(self.device.tune(&definition, false, eirp_mbm))?;
        self.tuned = Some(definition.control);
        let info = rate_info(context, definition.width, true, 0);
        Self::hardware(self.device.command(commands::ra_info(info)))
    }

    /// `ieee80211_send_nullfunc`, with its TX report asked for.
    fn probe(&mut self, context: &AssociationContext) {
        let report = self.report;
        self.report = self.report.wrapping_add(4);
        let Some(following) = &mut self.following else {
            return;
        };
        following.probing = Some(report);
        let info = rate_info(context, following.width(), false, 0);
        let mut bytes = alloc::vec![0; 24];
        bytes[..2].copy_from_slice(&[0x48, 1]);
        bytes[4..10].copy_from_slice(&context.bssid().0);
        bytes[10..16].copy_from_slice(&self.address.0);
        bytes[16..22].copy_from_slice(&context.bssid().0);
        let packet = Packet {
            size: bytes.len() as u16,
            mac_id: MAC_ID,
            queue: 7,
            rate_id: info.rate_id,
            rate: highest_rate(context),
            width: info.width,
            ldpc: info.ldpc,
            stbc: u8::from(peer_stbc(context)),
            report: Some(report),
            device_sequence: true,
            ..Packet::default()
        };
        self.held.push_back((Queue::Voice, packet, bytes));
    }
}
