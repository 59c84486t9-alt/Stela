// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! The links an MLD association uses: `_iwl_mld_select_links` picks the better
//! one or both, and `_ieee80211_set_active_links` with
//! `iwl_mld_update_link_stas` puts the association there. An active link holds
//! one seat of firmware's IDs, a PHY, a link and a station under one number. A
//! move fills the other seat before it empties the first, and EMLSR stops
//! between the two. The chain knows only seat 0, so the association returns
//! there before it goes down.
use super::*;

/// What firmware keeps of one link.
pub(super) struct LinkCommands {
    pub(super) wide_ofdma: Option<ChannelDefinition>,
    pub(super) link: Vec<u8>,
    pub(super) rates: Vec<u8>,
    pub(super) peer: Vec<u8>,
}

/// The station's side of `context`'s link.
fn station_link(context: &AssociationContext, address: Mac) -> StationLink {
    context
        .affiliation()
        .map_or(StationLink { address, id: 0 }, |link| StationLink {
            address: link.local,
            id: link.link_id,
        })
}

/// The TIDs with a queue.
fn station_queues<Q: BootIo, B: BiosIo>(queue: &mut Queue<Q, B>) -> Vec<u8> {
    (0..=MANAGEMENT_TID)
        .filter(|&tid| queue.has_queue(tid))
        .collect()
}

impl Client {
    /// Each firmware station of the association.
    pub(super) fn stations(&self) -> u32 {
        if self.emlsr.active { 3 } else { 1 << self.seat }
    }

    /// The link at `seat`, when firmware holds one there.
    pub(super) fn context_at(&self, seat: u8) -> Option<&Arc<AssociationContext>> {
        if seat == self.seat {
            self.context.as_ref()
        } else {
            self.dormant.as_ref().filter(|_| self.emlsr.active)
        }
    }

    /// The seat of the link of `ap`, or of the BSS `ap` transmits for, when
    /// firmware holds it.
    pub(super) fn seat_of(&self, ap: Mac) -> Option<u8> {
        [self.seat, 1 - self.seat].into_iter().find(|&seat| {
            self.context_at(seat)
                .is_some_and(|link| link.bssid() == ap || link.beacon().transmitter == ap)
        })
    }

    /// `iwl_mld_update_sta_resources`: what the AP's firmware stations share
    /// moves from `old` to `new`.
    fn move_resources(&mut self, tids: &[u8], old: u32, new: u32) {
        for &tid in tids {
            self.command(commands::SCHEDULER, commands::modify_queue(tid, old, new));
        }
        let pairwise: Vec<(u8, u32)> = self
            .keys
            .iter()
            .filter(|key| key.pairwise)
            .map(|key| (key.index, key.flags))
            .collect();
        for (index, flags) in pairwise {
            self.command(
                commands::SECURITY_KEY,
                commands::modify_key(index, flags, old, new),
            );
        }
        for tid in self.reception.tids() {
            self.command(
                commands::BLOCK_ACK_ALLOCATION,
                commands::modify_block_ack(tid, old, new),
            );
        }
    }

    /// `ieee80211_key_switch_links`: the group keys of the link of `ap` reach
    /// the firmware stations `stations`.
    fn fit_group_keys(&mut self, ap: Mac, stations: u32) -> Result<(), Error> {
        let mut added = Vec::new();
        for key in self.keys.iter_mut().filter(|key| !key.pairwise) {
            if key.ap == ap && !key.fitted {
                let (material, receive) = key.material.as_ref().ok_or(Error::Refused("key"))?;
                key.fitted = true;
                added.push(
                    commands::add_key(key.index, key.flags, material, *receive, stations)
                        .ok_or(Error::Refused("key material"))?,
                );
            }
        }
        for key in &mut self.management_keys {
            if key.ap == ap && !key.fitted {
                key.fitted = true;
                added.push(
                    commands::add_key(key.index, key.flags, &key.material, key.receive, stations)
                        .ok_or(Error::Refused("key material"))?,
                );
            }
        }
        for bytes in added {
            self.command(commands::SECURITY_KEY, bytes);
        }
        Ok(())
    }

    /// `ieee80211_key_switch_links`: the group keys of the link of `ap` leave
    /// the firmware stations `stations`.
    fn drop_group_keys(&mut self, ap: Mac, stations: u32) {
        let mut removed = Vec::new();
        for key in self.keys.iter_mut().filter(|key| !key.pairwise) {
            if key.ap == ap && core::mem::take(&mut key.fitted) {
                removed.push(commands::remove_key(key.index, key.flags, stations));
            }
        }
        for key in &mut self.management_keys {
            if key.ap == ap && core::mem::take(&mut key.fitted) {
                removed.push(commands::remove_key(key.index, key.flags, stations));
            }
        }
        for bytes in removed {
            self.command(commands::SECURITY_KEY, bytes);
        }
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// `iwl_mld_change_link_in_fw` for `context`'s link and what
    /// `iwl_mld_add_modify_sta_cmd` and `iwl_mld_config_tlc_link` say of its
    /// AP, at `seat`.
    pub(super) fn link_commands(
        &self,
        queue: &mut Queue<Q, B>,
        context: &AssociationContext,
        seat: u8,
        authorized: bool,
    ) -> Result<LinkCommands, Error> {
        let heard = self.client.tracking.of(context.bssid());
        let definition = self.client.link_definition(context);
        let narrowed = (definition.width != context.negotiated().width).then(|| {
            let mut narrowed = context.negotiated().clone();
            narrowed.width = definition.width;
            narrowed
        });
        let negotiated = narrowed.as_ref().unwrap_or(context.negotiated());
        let bss = context.beacon();
        let band = bss.channel.band;
        let capabilities = heard.map_or(bss.capabilities, |heard| heard.capabilities);
        let antennas = queue.antennas();
        // `ieee80211_set_chanreq_ap`: wider OFDMA follows the AP's own channel.
        let wide_ofdma = (negotiated.eht.is_some() && definition.control == bss.channel)
            .then(|| {
                let vht = negotiated
                    .local()
                    .vht()
                    .zip(negotiated.peer().vht())
                    .map(|(own, ap)| (own.capability, ap.capability));
                context
                    .operations()
                    .channel(bss.channel, phy::Mode::Eht, vht)
                    .ok()
            })
            .flatten();
        let firmware = queue.firmware();
        let link_version = firmware
            .command_version(commands::LINK_CONFIG.group, commands::LINK_CONFIG.opcode)
            .map_or(1, |version| version.command_version);
        let peer_version = firmware
            .command_version(3, 0x0a)
            .map_or(0, |version| version.command_version);
        let rate_shape = rate_shape(firmware)?;
        let explicit_mfp = firmware.supports_capability(EXPLICIT_MFP);
        let longest = if firmware.supports_capability(CHECKSUM_OFFLOAD) {
            commands::max_amsdu(negotiated)
        } else {
            0
        };
        let rates = commands::rate_config(
            negotiated, band, antennas, rate_shape, authorized, longest, seat,
        )
        .ok_or(Error::Refused("rates"))?;
        let edca = heard
            .and_then(|heard| heard.edca)
            .map_or_else(|| negotiated.edca(), |(_, edca)| edca);
        let edca = country::limited_edca(self.client.regulatory.as_ref(), &definition, edca);
        let protection = heard.map_or_else(
            || commands::protection(&bss.elements),
            |heard| heard.protection,
        );
        let he = link_he(context).map(|he| LinkHe {
            mu_edca: heard.map_or(he.mu_edca, |heard| {
                heard.mu_edca.map(|(_, records)| records)
            }),
            ..he
        });
        let link = commands::link_config(
            link_version,
            LinkState {
                seat,
                link: station_link(context, self.address),
                band,
                basic_rates: negotiated.legacy.basic,
                short_preamble: capabilities & (1 << 5) != 0,
                short_slot: band != Band::Ghz2 || capabilities & (1 << 10) != 0,
                protection,
                width: negotiated.width,
                qos: negotiated.wmm.is_some(),
                edca: &edca,
                beacon_interval: bss.beacon_interval,
                dtim_period: context.dtim_period(),
                he,
                nontransmitted: bss.profile.map(|profile| (bss.transmitter, profile.index)),
            },
        );
        let peer = commands::station_config(
            peer_version,
            peer_state(context, explicit_mfp, self.client.port_open, seat),
        );
        Ok(LinkCommands {
            wide_ofdma,
            link,
            rates,
            peer,
        })
    }

    /// `iwl_mld_get_link_grade` of `context`'s link as the last scan heard
    /// it: `iwl_mld_set_link_sel_data` ignores what that scan did not see.
    fn heard_link(&self, context: &AssociationContext, by_us: u32) -> Option<emlsr::Graded> {
        let since = self.client.link_scan.started?;
        let heard =
            self.client.observed.iter().find(|heard| {
                heard.observation.bss().bssid == context.bssid() && heard.at >= since
            })?;
        let (bss, definition) = (
            heard.observation.bss(),
            self.client.link_definition(context),
        );
        let band = bss.channel.band;
        Some(emlsr::Graded {
            grade: grade::grade(
                band,
                bss.signal_dbm
                    .map(|signal| grade::data_signal(signal, &bss.elements, &definition)),
                &bss.elements,
                definition.width,
                definition.punctured,
                by_us,
            )?,
            signal: bss.signal_dbm,
            load: grade::load(band, &bss.elements, by_us),
            definition,
        })
    }

    /// `_iwl_mld_select_links`: the best of what the last scan heard.
    pub(super) fn select_link(&mut self, queue: &mut Queue<Q, B>, now: u64) -> Result<(), Error> {
        let (Some(active), Some(dormant)) = (&self.client.context, &self.client.dormant) else {
            return Ok(());
        };
        // `iwl_mld_valid_emlsr_pair`, and mac80211 keeps its links through a switch.
        if self.client.tracking.watch.moving() {
            return Ok(());
        }
        let client = &self.client;
        let (seat, other) = (usize::from(client.seat), usize::from(1 - client.seat));
        let statistics = &client.statistics;
        let in_use = client.emlsr.active;
        let first = self.heard_link(active, statistics.load_by_us[seat]);
        let second = self.heard_link(
            dormant,
            if in_use {
                statistics.load_by_us[other]
            } else {
                0
            },
        );
        let load = [
            statistics.load_not_by_us[seat],
            statistics.load_not_by_us[other],
        ];
        let choice = match (&first, &second) {
            (None, None) => return Ok(()),
            (Some(_), None) => emlsr::Choice::Active,
            (None, Some(_)) => emlsr::Choice::Other,
            (Some(first), Some(second)) => client.emlsr.choose(first, second, load, now),
        };
        let seat = client.seat;
        match (in_use, choice) {
            (false, emlsr::Choice::Active) | (true, emlsr::Choice::Both) => Ok(()),
            (false, emlsr::Choice::Other) => self.switch_link(queue),
            (false, emlsr::Choice::Both) => self.enter_emlsr(queue, now),
            (true, emlsr::Choice::Active) => self.lower_second(queue, seat),
            (true, emlsr::Choice::Other) => self.lower_second(queue, 1 - seat),
        }
    }

    /// `iwl_mld_add_link`, `iwl_mld_update_link_stas` and
    /// `iwl_mld_assign_vif_chanctx` for the dormant link: it comes up at the
    /// empty seat beside the active one, which `quiet` deactivates first.
    /// What the AP's firmware stations share reaches both.
    fn raise_dormant(&mut self, queue: &mut Queue<Q, B>, quiet: bool) -> Result<(), Error> {
        let client = &self.client;
        let from = client.context.clone().ok_or(Error::Refused("no context"))?;
        let to = client.dormant.clone().ok_or(Error::Refused("no link"))?;
        let (old, new) = (client.seat, 1 - client.seat);
        let authorized = client.port_open;
        let before = 1u32 << old;
        let both = before | 1 << new;
        let source = self.link_commands(queue, &from, old, authorized)?;
        let target = self.link_commands(queue, &to, new, authorized)?;
        let definition = client.link_definition(&to);
        let phy = queue
            .phy_context(new, &definition, target.wide_ofdma.as_ref())
            .ok_or(Error::Refused("channel width"))?;
        let dbm = self.regulated_power_dbm(definition.control.frequency_mhz);
        let (power_id, power_limit) = queue
            .transmit_limit(new, dbm)
            .ok_or(Error::Refused("transmit power"))?;
        let constraints = self.six_ghz_power(queue, to.beacon(), new);
        let tids = station_queues(queue);
        let now = self.clock.now_us();
        let client = &mut self.client;
        client.link_scan.activated = now;
        for (id, bytes) in phy {
            client.command(id, bytes);
        }
        client.command(
            commands::LINK_CONFIG,
            commands::add_link(station_link(&to, self.address), new),
        );
        if quiet {
            client.command(
                commands::LINK_CONFIG,
                commands::activation(source.link, false),
            );
        }
        client.command(commands::LINK_CONFIG, target.link.clone());
        client.command(commands::STATION_CONFIG, target.peer);
        client.command(commands::RATE_CONFIG, target.rates);
        client.command(power_id, power_limit);
        if let Some(bytes) = constraints {
            client.command(commands::POWER_CONSTRAINTS, bytes);
        }
        client.move_resources(&tids, before, both);
        client.command(
            commands::LINK_CONFIG,
            commands::activation(target.link, true),
        );
        client.fit_group_keys(to.bssid(), 1 << new)
    }

    /// The link `gone` leaves the firmware seat `seat` and the active link
    /// keeps what they shared; `active` says it still runs.
    fn lower_link(
        &mut self,
        queue: &mut Queue<Q, B>,
        gone: &AssociationContext,
        seat: u8,
        active: bool,
    ) -> Result<(), Error> {
        let client = &self.client;
        let kept = client.context.clone().ok_or(Error::Refused("no context"))?;
        let (before, after) = (1u32 << seat, 1u32 << client.seat);
        let authorized = client.port_open;
        let source = self.link_commands(queue, gone, seat, authorized)?;
        let (phy_id, phy_removal) = queue
            .phy_removal(seat, &client.link_definition(gone))
            .ok_or(Error::Refused("channel width"))?;
        let tids = station_queues(queue);
        let power_version = version_of(queue.firmware(), commands::MAC_POWER);
        let client = &mut self.client;
        if active {
            client.command(
                commands::LINK_CONFIG,
                commands::activation(source.link, false),
            );
        }
        client.drop_group_keys(gone.bssid(), before);
        client.move_resources(&tids, before | after, after);
        client.command(commands::STATION_REMOVE, commands::remove_station(seat));
        client.command(commands::LINK_CONFIG, commands::remove_link(seat));
        client.command(phy_id, phy_removal);
        client.command(
            commands::MAC_POWER,
            commands::power(
                power_version,
                self.save_power,
                kept.beacon().beacon_interval,
                kept.dtim_period(),
            ),
        );
        client.statistics.seat_emptied(seat);
        if let Some(selected) = &mut self.selected {
            let bss = kept.beacon();
            selected.rates = legacy_rates(&bss.elements, bss.channel.band);
        }
        Ok(())
    }

    /// The other link takes the active link's place, in the books.
    fn swap_links(&mut self) -> Result<Arc<AssociationContext>, Error> {
        let client = &mut self.client;
        let gone = client.context.take().ok_or(Error::Refused("no context"))?;
        client.context = client.dormant.take();
        client.dormant = Some(gone.clone());
        client.seat = 1 - client.seat;
        Ok(gone)
    }

    /// `_ieee80211_set_active_links`: the active link gives way to the dormant
    /// one. Frames keep going to their queues, whose station the firmware
    /// changes under them.
    pub(super) fn switch_link(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        self.raise_dormant(queue, true)?;
        let seat = self.client.seat;
        let gone = self.swap_links()?;
        self.lower_link(queue, &gone, seat, false)
    }

    /// `iwl_mld_assign_vif_chanctx` with two links: firmware's EML Operating
    /// Mode Notification tells the AP, and the active link stays primary.
    fn enter_emlsr(&mut self, queue: &mut Queue<Q, B>, now: u64) -> Result<(), Error> {
        self.raise_dormant(queue, false)?;
        self.client.emlsr.entered(now);
        Ok(())
    }

    /// `_ieee80211_set_active_links` from two links to the one at `keep`.
    pub(super) fn lower_second(&mut self, queue: &mut Queue<Q, B>, keep: u8) -> Result<(), Error> {
        let client = &mut self.client;
        client.emlsr.active = false;
        let seat = 1 - keep;
        let gone = if keep == client.seat {
            client.dormant.clone().ok_or(Error::Refused("no link"))?
        } else {
            self.swap_links()?
        };
        self.lower_link(queue, &gone, seat, true)
    }
}
