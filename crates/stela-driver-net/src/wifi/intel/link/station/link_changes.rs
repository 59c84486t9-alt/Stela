// SPDX-License-Identifier: GPL-2.0-only
// Follows pinned Linux net/mac80211/mlme.c (ieee80211_ml_reconfiguration,
// ieee80211_ml_reconf_work, ieee80211_process_adv_ttlm,
// ieee80211_tid_to_link_map_work, ieee80211_ttlm_set_links). Source notices in
// wifi/THIRD_PARTY.md.
//! What an AP MLD does to its links under an association that stays: a link it
//! removes goes for good, and one its advertised mapping leaves out takes no
//! traffic until the mapping ends.
use super::*;
use crate::wifi::station::wire::link_changes::{Mapping, mappings, removals};

const TU_US: u64 = 1024;
/// `IEEE80211_ADV_TTLM_ST_UNDERFLOW`: a time this far off is the last switch
/// still being announced.
const SWITCH_TIME_PASSED: u16 = 0xff00;
/// `IEEE80211_ADV_TTLM_SAFETY_BUFFER_MS`: moving takes time.
const SWITCH_AHEAD_US: u64 = 100_000;
/// The bits of a timestamp a switch time reads.
const PARTIAL_TSF_SHIFT: u32 = 10;

/// `removed_links`, `ttlm_info` and `dormant_links`.
#[derive(Default)]
pub(super) struct LinkChanges {
    /// The links the AP's mapping takes no traffic on.
    barred: u16,
    /// That mapping stands, so its end lets them back.
    mapped: bool,
    /// The links a mapping allows, and when it comes.
    planned: Option<(u16, u64)>,
    /// The links going away, and when.
    removing: Option<(u16, u64)>,
}

impl LinkChanges {
    /// The association response's mapping of the `valid` links, which can only
    /// be the one in force. `None` refuses the association.
    pub(super) fn answered(elements: &[u8], valid: u16) -> Option<Self> {
        match mappings(elements).ok()?.as_slice() {
            [] => Some(Self::default()),
            &[
                Mapping {
                    links,
                    switch_time: 0,
                },
            ] if valid & links != 0 => Some(Self {
                barred: valid & !links,
                mapped: true,
                ..Self::default()
            }),
            _ => None,
        }
    }
}

/// The bit of `context`'s link.
pub(super) fn link_bit(context: &AssociationContext) -> u16 {
    context
        .affiliation()
        .map_or(0, |affiliation| 1 << affiliation.link_id)
}

impl Client {
    pub(super) fn valid_links(&self) -> u16 {
        let bit = |link: &Option<Arc<AssociationContext>>| link.as_deref().map_or(0, link_bit);
        bit(&self.context) | bit(&self.dormant)
    }

    pub(super) fn barred(&self, context: &AssociationContext) -> bool {
        self.changes.barred & link_bit(context) != 0
    }

    /// `ieee80211_ml_reconfiguration` and `ieee80211_process_adv_ttlm` of a
    /// beacon stamped `timestamp`.
    pub(super) fn links_announced(&mut self, elements: &[u8], timestamp: u64, now: u64) {
        if let Some(removed) = removals(elements) {
            self.plan_removal(&removed, now);
        }
        let Ok(mappings) = mappings(elements) else {
            self.tracking.watch.drop_connection();
            return;
        };
        let changes = &mut self.changes;
        if mappings.is_empty() {
            if changes.planned.take().is_none() && changes.mapped {
                changes.barred = 0;
            }
            changes.mapped = false;
            return;
        }
        let Some(mapping) = mappings.iter().find(|mapping| mapping.switch_time != 0) else {
            return;
        };
        let beacon_tu = (timestamp >> PARTIAL_TSF_SHIFT) as u16;
        let delay = mapping.switch_time.wrapping_sub(beacon_tu);
        if delay <= SWITCH_TIME_PASSED {
            let delay_us = u64::from(delay) * TU_US;
            let due = now + delay_us.saturating_sub(SWITCH_AHEAD_US);
            changes.planned = Some((mapping.links, due));
        }
    }

    fn plan_removal(&mut self, removed: &[(u8, u16)], now: u64) {
        let mut links = 0;
        let mut delay = 0;
        for &(link, timer) in removed {
            let context = [&self.context, &self.dormant]
                .into_iter()
                .flatten()
                .find(|context| link_bit(context) == 1 << link);
            let Some(context) = context else {
                continue;
            };
            links |= 1 << link;
            let interval = u64::from(context.beacon().beacon_interval);
            let left = interval * u64::from(timer.saturating_sub(1));
            delay = if delay == 0 { left } else { delay.min(left) };
        }
        self.changes.removing = (links != 0).then_some((links, now + delay * TU_US));
    }

    /// The dormant link is gone: nothing of it is ever needed again.
    fn forget_dormant(&mut self) {
        let Some(gone) = self.dormant.take() else {
            return;
        };
        let ap = gone.bssid();
        self.keys.retain(|key| key.pairwise || key.ap != ap);
        self.tracking.links.retain(|heard| heard.ap != ap);
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// `ieee80211_ml_reconf_work` and `ieee80211_tid_to_link_map_work`, one
    /// step a round while nothing else is in firmware's hands.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    pub(super) fn run_link_changes(
        &mut self,
        queue: &mut Queue<Q, B>,
        now: u64,
    ) -> Result<(), Error> {
        let client = &mut self.client;
        let valid = client.valid_links();
        let moving = client.tracking.watch.moving();
        if valid == 0 || !client.port_open || client.leaving || !client.idle() || moving {
            return Ok(());
        }
        let changes = &mut client.changes;
        if let Some((links, _)) = changes.planned.filter(|&(_, due)| due <= now) {
            changes.planned = None;
            changes.mapped = true;
            changes.barred = valid & !links;
        }
        let due = changes.removing.filter(|&(_, due)| due <= now);
        let removed = due.map_or(0, |(links, _)| links);
        let gone = removed | changes.barred;
        let active = client.context.as_deref().map_or(0, link_bit);
        let dormant = client.dormant.as_deref().map_or(0, link_bit);
        if valid & !gone == 0 {
            changes.removing = None;
            client.tracking.watch.drop_connection();
            return Ok(());
        }
        if client.emlsr.active && valid & gone != 0 {
            let keep = if active & gone == 0 {
                client.seat
            } else {
                1 - client.seat
            };
            return self.lower_second(queue, keep);
        }
        if active & gone != 0 {
            return self.switch_link(queue);
        }
        if dormant & removed != 0 {
            client.forget_dormant();
        }
        if due.is_some() {
            client.changes.removing = None;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn link_count(&self) -> usize {
        usize::from(self.client.context.is_some()) + usize::from(self.client.dormant.is_some())
    }
}
