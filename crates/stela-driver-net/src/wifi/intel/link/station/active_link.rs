// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! The link an MLD association uses: `_iwl_mld_select_links` picks the better
//! one, and `_ieee80211_set_active_links` with `iwl_mld_update_link_stas` moves
//! the association there. The active link holds one seat of firmware's IDs,
//! a PHY, a link and a station under one number, and the move fills the other
//! seat before it empties the first. The chain knows only seat 0, so the
//! association moves back before it goes down.
use super::*;

/// The IDs the link the chain did not raise holds.
const FIRST: u8 = 0;
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

impl Client {
    /// Each firmware station of the association.
    pub(super) fn stations(&self) -> u32 {
        1 << self.seat
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

    /// `ieee80211_key_switch_links`: each link's group keys follow it.
    fn switch_group_keys(&mut self, from: Mac, to: Mac, old: u32, new: u32) -> Result<(), Error> {
        let mut changes = Vec::new();
        for key in self.keys.iter_mut().filter(|key| !key.pairwise) {
            if key.ap == from && key.fitted {
                key.fitted = false;
                changes.push(commands::remove_key(key.index, key.flags, old));
            } else if key.ap == to && !key.fitted {
                let (material, receive) = key.material.as_ref().ok_or(Error::Refused("key"))?;
                key.fitted = true;
                changes.push(
                    commands::add_key(key.index, key.flags, material, *receive, new)
                        .ok_or(Error::Refused("key material"))?,
                );
            }
        }
        for key in &mut self.management_keys {
            if key.ap == from && key.fitted {
                key.fitted = false;
                changes.push(commands::remove_key(key.index, key.flags, old));
            } else if key.ap == to && !key.fitted {
                key.fitted = true;
                changes.push(
                    commands::add_key(key.index, key.flags, &key.material, key.receive, new)
                        .ok_or(Error::Refused("key material"))?,
                );
            }
        }
        for bytes in changes {
            self.command(commands::SECURITY_KEY, bytes);
        }
        Ok(())
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
        let negotiated = context.negotiated();
        let bss = context.beacon();
        let band = bss.channel.band;
        let antennas = queue.antennas();
        // `ieee80211_set_chanreq_ap`: wider OFDMA follows the AP's own channel.
        let wide_ofdma = negotiated
            .eht
            .is_some()
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
        let edca = negotiated.edca();
        let link = commands::link_config(
            link_version,
            LinkState {
                seat,
                link: station_link(context, self.address),
                band,
                basic_rates: negotiated.legacy.basic,
                short_preamble: bss.capabilities & (1 << 5) != 0,
                short_slot: band != Band::Ghz2 || bss.capabilities & (1 << 10) != 0,
                protection: commands::protection(context),
                width: negotiated.width,
                qos: negotiated.wmm.is_some(),
                edca: &edca,
                beacon_interval: bss.beacon_interval,
                dtim_period: context.dtim_period(),
                he: link_he(context),
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
    fn heard_grade(&self, context: &AssociationContext, by_us: u32) -> Option<u32> {
        let since = self.client.link_scan.started?;
        let heard =
            self.client.observed.iter().find(|heard| {
                heard.observation.bss().bssid == context.bssid() && heard.at >= since
            })?;
        let (bss, definition) = (heard.observation.bss(), context.definition());
        grade::grade(
            bss.channel.band,
            bss.signal_dbm,
            &bss.elements,
            definition.width,
            definition.punctured,
            by_us,
        )
    }

    /// `_iwl_mld_select_links` for one active link, the best of those the last
    /// scan heard.
    pub(super) fn select_link(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        let (Some(active), Some(dormant)) = (&self.client.context, &self.client.dormant) else {
            return Ok(());
        };
        let by_us = self.client.statistics.load_by_us;
        match (
            self.heard_grade(active, by_us),
            self.heard_grade(dormant, 0),
        ) {
            (_, None) => Ok(()),
            (Some(active), Some(dormant)) if active >= dormant => Ok(()),
            _ => self.switch_link(queue),
        }
    }

    /// `_ieee80211_set_active_links`: the active link gives way to the dormant
    /// one. Frames keep going to their queues, whose station the firmware
    /// changes under them.
    pub(super) fn switch_link(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        let client = &self.client;
        let from = client.context.clone().ok_or(Error::Refused("no context"))?;
        let to = client.dormant.clone().ok_or(Error::Refused("no link"))?;
        let (old, new) = (client.seat, FIRST + 1 - client.seat);
        let authorized = client.port_open;
        let (before, after) = (1u32 << old, 1u32 << new);
        let both = before | after;
        let source = self.link_commands(queue, &from, old, authorized)?;
        let target = self.link_commands(queue, &to, new, authorized)?;
        let definition = to.definition();
        let refused = Error::Refused("channel width");
        let phy = queue
            .phy_context(new, &definition, target.wide_ofdma.as_ref())
            .ok_or(refused.clone())?;
        let (phy_id, phy_removal) = queue
            .phy_removal(old, &from.definition())
            .ok_or(refused.clone())?;
        let dbm = self.regulated_power_dbm(definition.control.frequency_mhz);
        let (power_id, power_limit) = queue
            .transmit_limit(new, dbm)
            .ok_or(Error::Refused("transmit power"))?;
        let tids: Vec<u8> = (0..=MANAGEMENT_TID)
            .filter(|&tid| queue.has_queue(tid))
            .collect();
        let power_version = version_of(queue.firmware(), commands::MAC_POWER);
        let now = self.clock.now_us();
        let client = &mut self.client;
        client.link_scan.activated = now;
        client.statistics.link_moved();
        for (id, bytes) in phy {
            client.command(id, bytes);
        }
        client.command(
            commands::LINK_CONFIG,
            commands::add_link(station_link(&to, self.address), new),
        );
        client.command(
            commands::LINK_CONFIG,
            commands::activation(source.link, false),
        );
        client.command(commands::LINK_CONFIG, target.link.clone());
        client.command(commands::STATION_CONFIG, target.peer);
        client.command(commands::RATE_CONFIG, target.rates);
        client.command(power_id, power_limit);
        client.move_resources(&tids, before, both);
        client.command(
            commands::LINK_CONFIG,
            commands::activation(target.link, true),
        );
        client.switch_group_keys(from.bssid(), to.bssid(), before, after)?;
        client.move_resources(&tids, both, after);
        client.command(commands::STATION_REMOVE, commands::remove_station(old));
        client.command(commands::LINK_CONFIG, commands::remove_link(old));
        client.command(phy_id, phy_removal);
        client.command(
            commands::MAC_POWER,
            commands::power(
                power_version,
                self.save_power,
                to.beacon().beacon_interval,
                to.dtim_period(),
            ),
        );
        client.seat = new;
        if let Some(selected) = &mut self.selected {
            let bss = to.beacon();
            selected.rates = legacy_rates(&bss.elements, bss.channel.band);
        }
        client.dormant = Some(from);
        client.context = Some(to);
        Ok(())
    }
}
