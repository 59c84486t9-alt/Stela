// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
//! The OS side of an Intel adapter's regulatory boundary: the country the
//! mount's configuration names, or else the one the firmware reported at
//! `iwl_mvm_init_mcc` (its BIOS country or current MCC), with its rules from
//! the pinned wireless-regdb database. An unlisted firmware country takes the
//! database's world rules "00", the code `iwl_mvm_update_mcc` also gives a
//! firmware answer of 0.
//!
//! A station follows cfg80211's channel rules. Receive, and so a passive
//! scan, needs a rule covering the channel's 20 MHz. Transmit additionally
//! needs that rule to allow OFDM for an OFDM rate and to cover the planned
//! EIRP. Only a probe initiates radiation: like mac80211's scan, it needs the
//! channel free of DFS and of NO-IR, which a beacon heard there lifts while
//! the world rules apply (`handle_reg_beacon`). Authentication, association
//! and data answer the AP, so DFS, NO-IR and indoor-only channels carry them,
//! as `cfg80211_chandef_usable` prohibits only disabled channels for one.
use super::boot::{CountryIo, CountryIoError, SelectedCountry};
use crate::net::wifi::{
    Band, Channel,
    regulatory::{
        LegacyRate, NativeContext, Operation, OsLease, OsPolicy, Purpose,
        database::{self, Country, Database},
    },
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_REVISION: crate::net::wifi::Identities = crate::net::wifi::Identities::new();

/// The database's world rules, which cfg80211 applies without a country.
pub const WORLD: [u8; 2] = *b"00";

/// The channels a beacon was heard on, by band and channel number.
#[derive(Default)]
pub struct Beacons([AtomicU64; 12]);

impl Beacons {
    fn bit(channel: Channel) -> Option<(usize, u64)> {
        let band = match channel.band {
            Band::Ghz2 => 0,
            Band::Ghz5 => 1,
            Band::Ghz6 => 2,
        };
        let number = usize::from(channel.number);
        (number < 256).then(|| (band * 4 + number / 64, 1 << (number % 64)))
    }

    /// Record a beacon heard on `channel`.
    pub fn heard(&self, channel: Channel) {
        if let Some((word, bit)) = Self::bit(channel) {
            self.0[word].fetch_or(bit, Ordering::Relaxed);
        }
    }

    pub fn found(&self, channel: Channel) -> bool {
        Self::bit(channel)
            .is_some_and(|(word, bit)| self.0[word].load(Ordering::Relaxed) & bit != 0)
    }
}

/// One adapter's selected country.
pub struct Regulatory {
    country: Country,
    revision: u64,
    beacons: Arc<Beacons>,
}

impl Regulatory {
    /// `configured` is the mount's `--wifi-country`; without one, `firmware`
    /// is the country the adapter's firmware last reported.
    pub fn select(
        database: Database,
        configured: Option<[u8; 2]>,
        firmware: Option<[u8; 2]>,
    ) -> Result<Self, database::Error> {
        let revision = NEXT_REVISION.next().ok_or(database::Error::NoMemory)?;
        let country = match configured {
            Some(alpha2) => database.select(alpha2)?,
            None => match firmware {
                Some(alpha2) if alpha2 != WORLD => match database.clone().select(alpha2) {
                    Ok(country) => country,
                    Err(database::Error::Country) => database.select(WORLD)?,
                    Err(error) => return Err(error),
                },
                _ => database.select(WORLD)?,
            },
        };
        Ok(Self {
            country,
            revision,
            beacons: Arc::default(),
        })
    }

    pub fn country(&self) -> &Country {
        &self.country
    }

    /// Where the adapter's scans record the beacons they hear.
    pub fn beacons(&self) -> Arc<Beacons> {
        self.beacons.clone()
    }
}

fn cck(rate: LegacyRate) -> bool {
    matches!(
        rate,
        LegacyRate::Cck1 | LegacyRate::Cck2 | LegacyRate::Cck5_5 | LegacyRate::Cck11
    )
}

/// Whether the country admits `operation` for a station that heard the
/// beacons in `beacons`.
pub fn allows(country: &Country, beacons: &Beacons, operation: Operation) -> bool {
    let channel: Channel = operation.channel();
    let Some(rule) = country.rule(u32::from(channel.frequency_mhz) * 1000, 20_000) else {
        return false;
    };
    match operation {
        Operation::Receive(_) => true,
        Operation::Transmit {
            purpose, profile, ..
        } => {
            let hinted = country.alpha2() == WORLD && beacons.found(channel);
            let initiates = purpose == Purpose::Probe;
            (cck(profile.rate) || !rule.no_ofdm)
                && profile.max_eirp_mbm <= i32::from(rule.max_eirp_mbm)
                && !(initiates && (rule.dfs || (rule.no_ir && !hinted)))
        }
    }
}

// SAFETY: the selection is the mount's explicit configuration or the
// adapter's own reported country, fixed for the adapter's life: its revision
// stays current and no other selection exists.
unsafe impl CountryIo for Regulatory {
    fn country(&mut self) -> Result<SelectedCountry, CountryIoError> {
        Ok(SelectedCountry {
            country: self.country.clone(),
            revision: self.revision,
        })
    }
    fn current(&mut self, revision: u64) -> Result<bool, CountryIoError> {
        Ok(revision == self.revision)
    }
}

pub struct Lease<'a> {
    country: &'a Country,
    beacons: &'a Beacons,
    revision: u64,
}

impl OsLease for Lease<'_> {
    fn revision(&self) -> u64 {
        self.revision
    }
    fn allows(&mut self, operation: Operation) -> bool {
        allows(self.country, self.beacons, operation)
    }
}

// SAFETY: the rules never change while the adapter runs, so every lease
// holds the same selection the country phase programmed; a beacon hint only
// lifts NO-IR as cfg80211 does.
unsafe impl OsPolicy for Regulatory {
    type Lease<'a> = Lease<'a>;
    fn acquire(&mut self, _: NativeContext) -> Option<Self::Lease<'_>> {
        Some(Lease {
            country: &self.country,
            beacons: &self.beacons,
            revision: self.revision,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::net::wifi::{
        Band,
        regulatory::{TxProfile, Width},
    };
    use alloc::{sync::Arc, vec::Vec};
    use sha2::{Digest, Sha256};

    /// One rule: start kHz, end kHz, flags, EIRP mBm.
    pub(crate) type Rule = (u32, u32, u8, u16);

    /// A wireless-regdb v20 database of `countries`, each a list of rules
    /// whose maximum width is 80 MHz or the whole rule, if narrower.
    pub(crate) fn regdb(countries: &[([u8; 2], &[Rule])]) -> Database {
        let mut bytes = Vec::from(*b"RGDB");
        bytes.extend(20u32.to_be_bytes());
        let table = bytes.len();
        bytes.resize(table + (countries.len() + 1) * 4, 0);
        for (index, (alpha2, rules)) in countries.iter().enumerate() {
            let collection = bytes.len();
            bytes[table + index * 4..table + index * 4 + 2].copy_from_slice(alpha2);
            bytes[table + index * 4 + 2..table + index * 4 + 4]
                .copy_from_slice(&((collection / 4) as u16).to_be_bytes());
            bytes.extend([3, rules.len() as u8, 0, 0]);
            let pointers = bytes.len();
            bytes.resize((pointers + rules.len() * 2).next_multiple_of(4), 0);
            for (rule, &(start, end, flags, eirp)) in rules.iter().enumerate() {
                let at = bytes.len();
                bytes[pointers + rule * 2..pointers + rule * 2 + 2]
                    .copy_from_slice(&((at / 4) as u16).to_be_bytes());
                bytes.extend([16, flags]);
                bytes.extend(eirp.to_be_bytes());
                bytes.extend(start.to_be_bytes());
                bytes.extend(end.to_be_bytes());
                bytes.extend((end - start).min(80_000).to_be_bytes());
            }
        }
        let digest = Sha256::digest(&bytes).into();
        Database::parse(Arc::from(bytes), digest).unwrap()
    }

    fn database() -> Database {
        regdb(&[
            (*b"00", &[(2_402_000, 2_472_000, 8, 2000)]),
            (
                *b"US",
                &[
                    (2_402_000, 2_472_000, 0, 3000),
                    (5_170_000, 5_250_000, 2, 2300),
                    (5_250_000, 5_330_000, 4, 2300),
                ],
            ),
            (*b"CN", &[(2_402_000, 2_482_000, 8, 2000)]),
        ])
    }

    fn channel(number: u16) -> Channel {
        if number < 15 {
            Channel {
                band: Band::Ghz2,
                number,
                frequency_mhz: 2407 + number * 5,
            }
        } else {
            Channel {
                band: Band::Ghz5,
                number,
                frequency_mhz: 5000 + number * 5,
            }
        }
    }

    fn transmit(number: u16, purpose: Purpose, rate: LegacyRate, mbm: i32) -> Operation {
        Operation::Transmit {
            channel: channel(number),
            purpose,
            profile: TxProfile {
                width: Width::Legacy20,
                rate,
                short_preamble: false,
                max_eirp_mbm: mbm,
            },
        }
    }

    fn probe(number: u16) -> Operation {
        transmit(number, Purpose::Probe, LegacyRate::Ofdm6, 0)
    }

    fn associate(number: u16) -> Operation {
        transmit(number, Purpose::Management, LegacyRate::Ofdm6, 0)
    }

    #[test]
    fn configured_country_wins_and_an_unlisted_firmware_country_takes_world_rules() {
        let us = Regulatory::select(database(), Some(*b"US"), Some(*b"CN")).unwrap();
        assert_eq!(us.country().alpha2(), *b"US");
        assert_eq!(
            Regulatory::select(database(), None, Some(*b"US"))
                .unwrap()
                .country()
                .alpha2(),
            *b"US"
        );
        for firmware in [None, Some(*b"DE"), Some(WORLD)] {
            let world = Regulatory::select(database(), None, firmware).unwrap();
            assert_eq!(world.country().alpha2(), WORLD);
        }
        assert_eq!(
            Regulatory::select(database(), Some(*b"QQ"), None).err(),
            Some(database::Error::Country)
        );
    }

    #[test]
    fn a_beacon_lifts_no_ir_for_probes_only_under_world_rules() {
        for (alpha2, lifted) in [(None, true), (Some(*b"CN"), false)] {
            let regulatory = Regulatory::select(database(), alpha2, None).unwrap();
            let (country, beacons) = (regulatory.country(), regulatory.beacons());
            assert!(!allows(country, &beacons, probe(1)));
            assert!(allows(country, &beacons, associate(1)));
            beacons.heard(channel(1));
            assert_eq!(allows(country, &beacons, probe(1)), lifted);
            assert!(!allows(country, &beacons, probe(6)));
            assert!(allows(country, &beacons, Operation::Receive(channel(6))));
        }
    }

    #[test]
    fn dfs_and_indoor_channels_carry_association_but_dfs_never_probes() {
        let us = Regulatory::select(database(), Some(*b"US"), None).unwrap();
        let (country, beacons) = (us.country(), us.beacons());
        beacons.heard(channel(52));
        assert!(allows(country, &beacons, associate(52)));
        assert!(!allows(country, &beacons, probe(52)));
        assert!(allows(country, &beacons, associate(36)));
        assert!(allows(country, &beacons, probe(36)));
        assert!(allows(country, &beacons, Operation::Receive(channel(52))));
    }

    #[test]
    fn transmit_needs_the_rule_to_cover_its_power() {
        let mut us = Regulatory::select(database(), Some(*b"US"), None).unwrap();
        let mut lease = us
            .acquire(NativeContext {
                device: 1,
                reset_epoch: 1,
                firmware_epoch: 1,
                policy_revision: 1,
            })
            .unwrap();
        let rule = lease.country.rule(2_412_000, 20_000).unwrap().max_eirp_mbm;
        let ceiling = i32::from(rule);
        assert!(lease.allows(transmit(1, Purpose::Management, LegacyRate::Ofdm6, ceiling)));
        assert!(!lease.allows(transmit(
            1,
            Purpose::Management,
            LegacyRate::Ofdm6,
            ceiling + 1
        )));
        assert!(!lease.allows(transmit(14, Purpose::Data, LegacyRate::Cck1, 0)));
    }
}
