// SPDX-License-Identifier: GPL-2.0-only
// Adapted from pinned Linux cfg80211 reg.c and chan.c: Copyright 2002-2005,
// Instant802 Networks, Inc.; 2005-2006, Devicescape Software, Inc.; 2007,
// Johannes Berg; 2008, Luis R. Rodriguez; 2018-2026 Intel Corporation. The
// firmware's side follows iwlwifi's mld/mcc.c.
//! `iwl_mld_handle_update_mcc`: firmware says the country it now sees, the
//! host asks it for that country's channels, and what comes back replaces the
//! rules, with `reg_check_channels`' minute before a link they bar goes.
//! `ieee80211_regulatory_limit_wmm_params` holds a link's queues to its rules.
use super::*;
use crate::wifi::{
    intel::{mcc, policy},
    regulatory::wmm,
    station::{
        operations::{ChannelDefinition, mhz},
        phy::{AccessCategory, Width},
    },
};

/// `MCC_SOURCE_WIFI`: what the air said.
const COUNTRY_FROM_WIFI: u8 = 5;
/// `REG_ENFORCE_GRACE_MS`.
const GRACE_US: u64 = 60_000_000;

/// `cfg80211_chandef_usable`: every 20 MHz of `definition` the AP uses is a
/// channel `channels` keep, open to its width.
fn usable(channels: &[(Channel, u32)], definition: &ChannelDefinition) -> bool {
    let flags = |frequency: u32| {
        channels
            .iter()
            .find(|(channel, _)| {
                channel.band == definition.control.band
                    && u32::from(channel.frequency_mhz) == frequency
            })
            .map(|&(_, flags)| flags)
    };
    let control = u32::from(definition.control.frequency_mhz);
    let (closed, sideways) = match definition.width {
        Width::Mhz40 if definition.center1_mhz < control => (0, NO_HT40MINUS),
        Width::Mhz40 => (0, NO_HT40PLUS),
        Width::Mhz80 => (NO_80MHZ, 0),
        Width::Mhz160 => (NO_160MHZ, 0),
        Width::Mhz320 => (NO_320MHZ, 0),
        _ => (0, 0),
    };
    let width = mhz(definition.width);
    let first = definition.center1_mhz - width / 2 + 10;
    flags(control).is_some_and(|flags| flags & sideways == 0)
        && (0..width / 20).all(|index| {
            definition.punctured >> index & 1 != 0
                || flags(first + index * 20).is_some_and(|flags| flags & closed == 0)
        })
}

/// `edca` under the rule of `definition`'s control channel. Parameters that
/// contradict themselves stay the AP's, which `ieee80211_sta_wmm_params`
/// settled before.
pub(super) fn limited_edca(
    country: Option<&database::Country>,
    definition: &ChannelDefinition,
    edca: [AccessCategory; 4],
) -> [AccessCategory; 4] {
    let center = u32::from(definition.control.frequency_mhz) * 1000;
    let limit = country
        .and_then(|country| country.rule(center, 20_000))
        .and_then(|rule| rule.wmm.as_ref());
    wmm::station(&edca, limit).unwrap_or(edca)
}

impl Client {
    /// `reg_leave_invalid_chans`, once the rules' change had its minute.
    pub(super) fn check_links_usable(&mut self, now: u64) {
        if self.grace_ends.is_none_or(|ends| now < ends) {
            return;
        }
        self.grace_ends = None;
        let barred = [0, 1]
            .into_iter()
            .filter_map(|seat| self.context_at(seat))
            .any(|link| !usable(&self.channels, &self.link_definition(link)));
        if barred {
            self.tracking.watch.drop_connection();
        }
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// `iwl_mld_handle_update_mcc`. A country the mount configured stands, so
    /// firmware keeps it too.
    pub(super) fn country_update(&mut self, raw: &[u8]) {
        let &[low, high, source, ..] = raw else {
            return;
        };
        let associated = self.client.station.association_epoch().is_some();
        if associated && source == COUNTRY_FROM_WIFI {
            return;
        }
        if self.network.country.is_some() {
            self.client
                .unsupported("a firmware country update under a configured country");
            return;
        }
        let request = mcc::Request {
            country: [high, low],
            source,
        };
        let Ok(bytes) = request.bytes() else {
            self.client.unsupported("a firmware country with no name");
            return;
        };
        self.client.steps.push_back(Step::Command {
            id: mcc::Request::id(),
            bytes: bytes.to_vec(),
            then: Then::Country,
        });
    }

    /// `iwl_mld_get_regdomain` and `regulatory_set_wiphy_regd`.
    pub(super) fn country_answered(
        &mut self,
        queue: &mut Queue<Q, B>,
        response: &boot::CommandResponse,
    ) -> Result<(), Error> {
        let Ok(profile) = mcc::Response::decode(queue.firmware(), &response.raw) else {
            self.client
                .unsupported("a country answer out of firmware's API");
            return Ok(());
        };
        if !profile.profile_changed() {
            return Ok(());
        }
        let Ok(country) = policy::reported(self.restart.database.clone(), profile.country) else {
            self.client.unsupported("a firmware country without rules");
            return Ok(());
        };
        let Ok(channels) = queue.adopt_country(country.clone(), profile) else {
            self.client
                .unsupported("a country answer past the adapter's channels");
            return Ok(());
        };
        let now = self.clock.now_us();
        let client = &mut self.client;
        client.regulatory = Some(country);
        client.channels = channels;
        if client.station.association_epoch().is_some() {
            client.grace_ends = Some(now + GRACE_US);
        }
        Ok(())
    }

    /// The country whose rules apply.
    #[cfg(test)]
    pub(crate) fn rules(&self) -> Option<[u8; 2]> {
        self.client.regulatory.as_ref().map(|rules| rules.alpha2())
    }

    /// The rules' minute is over: tests have no minute.
    #[cfg(test)]
    pub(crate) fn end_country_grace(&mut self) {
        self.client.grace_ends = Some(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::{Band, intel::policy::tests::regdb_limited};

    fn channel(frequency_mhz: u16) -> Channel {
        Channel {
            band: Band::Ghz5,
            number: (frequency_mhz - 5000) / 5,
            frequency_mhz,
        }
    }

    /// The 80 MHz around channels 36 to 48, on 44.
    fn eighty(punctured: u16) -> ChannelDefinition {
        ChannelDefinition {
            control: channel(5220),
            width: Width::Mhz80,
            center1_mhz: 5210,
            center2_mhz: None,
            punctured,
        }
    }

    #[test]
    fn a_countrys_wmm_rule_holds_the_queues_the_ap_set() {
        // CWmin 31, CWmax 1023, AIFSN 7 and 2 ms of channel occupancy.
        let database = regdb_limited(
            &[(*b"DE", &[(5_170_000, 5_250_000, 0, 2000)])],
            Some([0x5a, 7, 0, 2]),
        );
        let country = database.select(*b"DE").unwrap();
        let edca = [0, 1, 2, 3].map(|aci| AccessCategory {
            aci,
            admission_control: false,
            aifsn: 2 + aci,
            ecw_min: 4,
            ecw_max: 11,
            txop_32us: 94,
        });
        let limited = limited_edca(Some(&country), &eighty(0), edca);
        assert_eq!(limited[0].aifsn, 7);
        assert_eq!(limited[0].ecw_min, 5);
        assert_eq!(limited[0].ecw_max, 11, "what the AP set above the rule");
        assert_eq!(limited[0].txop_32us, 62);
        assert_eq!(limited_edca(None, &eighty(0), edca), edca);
        let elsewhere = ChannelDefinition {
            control: channel(5745),
            center1_mhz: 5745,
            ..eighty(0)
        };
        assert_eq!(limited_edca(Some(&country), &elsewhere, edca), edca);
    }

    #[test]
    fn a_link_needs_every_channel_it_uses_open_to_its_width() {
        let open: Vec<_> = [5180, 5200, 5220, 5240]
            .map(|frequency| (channel(frequency), 0))
            .to_vec();
        assert!(usable(&open, &eighty(0)));
        let without = |frequency| {
            let kept = open.iter().filter(|(c, _)| c.frequency_mhz != frequency);
            kept.copied().collect::<Vec<_>>()
        };
        assert!(!usable(&without(5180), &eighty(0)));
        assert!(usable(&without(5180), &eighty(1)), "the AP left that hole");
        assert!(
            !usable(&without(5220), &eighty(0b100)),
            "the control channel"
        );
        let narrowed: Vec<_> = open.iter().map(|&(c, _)| (c, NO_80MHZ)).collect();
        assert!(!usable(&narrowed, &eighty(0)));
        let forty = ChannelDefinition {
            width: Width::Mhz40,
            center1_mhz: 5230,
            ..eighty(0)
        };
        assert!(usable(&open, &forty));
        let closed: Vec<_> = open.iter().map(|&(c, _)| (c, NO_HT40PLUS)).collect();
        assert!(!usable(&closed, &forty));
    }
}
