// SPDX-License-Identifier: ISC
// Regulatory database format/query follows pinned Linux net/wireless/reg.c.
// Copyright (C) 2002-2005 Instant802 Networks, Inc.
// Copyright (C) 2005-2006 Devicescape Software, Inc.
// Copyright 2007 Johannes Berg; 2008-2011 Luis R. Rodriguez.
// Copyright 2013-2014 Intel Mobile Communications GmbH;
// 2017 Intel Deutschland GmbH; 2018-2026 Intel Corporation.
//! Retained, content-pinned Linux regulatory.db v20 and explicit country input.
//! The setup/OS source selects the digest and country. Parsing never selects a
//! country, establishes location, or silently substitutes a world/default rule.

use crate::firmware::{self, Provider, Requirement, Target};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use sha2::{Digest, Sha256};

/// The catalog name of wireless-regdb's database, which boot places in the
/// handoff firmware catalog from setup's pinned host firmware.
pub const NAME: &str = "regulatory.db";
/// What a Wi-Fi adapter's probe requests: the version-20 database, at least
/// its magic and version.
pub const REQUIREMENT: Requirement<'static> = Requirement {
    name: NAME,
    target: Target {
        driver: "wifi-regulatory",
        hardware: "wireless-regdb",
        revision: "v20",
        board: None,
    },
    minimum_bytes: 8,
};

/// Why no database loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The catalog has no pinned database.
    Resource(Box<firmware::Error>),
    /// The catalog's bytes are no version-20 database.
    Database(Error),
}

/// The database the firmware catalog holds, its catalog SHA-256 the digest
/// it must have. Without one no Wi-Fi adapter scans or transmits: there is
/// no world-rules fallback.
pub fn load(provider: &dyn Provider) -> Result<Database, LoadError> {
    let image = provider
        .load(REQUIREMENT)
        .map_err(|error| LoadError::Resource(Box::new(error)))?;
    Database::parse(Arc::from(image.bytes()), image.sha256()).map_err(LoadError::Database)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Digest,
    Truncated,
    Format,
    Unsupported,
    Country,
    NoMemory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WmmAc {
    pub cw_min: u16,
    pub cw_max: u16,
    pub aifsn: u8,
    /// Exact source 1000×db-COT assignment to cfg80211's u16, including
    /// truncation. The source EDCA clamp subsequently divides this value by 32.
    pub cot_us: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wmm {
    pub client: [WmmAc; 4],
    pub ap: [WmmAc; 4],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub start_khz: u32,
    pub end_khz: u32,
    pub max_bandwidth_khz: u32,
    pub max_eirp_mbm: u16,
    pub no_ofdm: bool,
    pub indoor_only: bool,
    pub dfs: bool,
    pub no_ir: bool,
    pub auto_bandwidth: bool,
    pub dfs_cac_ms: u32,
    pub wmm: Option<Wmm>,
}

/// Immutable source bytes are retained alongside decoded country rules.
pub struct Database {
    bytes: Arc<[u8]>,
    digest: [u8; 32],
}
/// Explicit privileged OS/setup country selection and its source database.
/// This is a data input, not authority to use an unrelated physical radio.
pub struct Country {
    database: Database,
    alpha2: [u8; 2],
    dfs_region: u8,
    rules: Vec<Rule>,
}
fn bytes(data: &[u8], at: usize, n: usize) -> Result<&[u8], Error> {
    data.get(at..at.checked_add(n).ok_or(Error::Truncated)?)
        .ok_or(Error::Truncated)
}
fn be16(data: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(bytes(data, at, 2)?.try_into().unwrap()))
}
fn be32(data: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(bytes(data, at, 4)?.try_into().unwrap()))
}
fn pointer(data: &[u8], at: usize) -> Result<usize, Error> {
    Ok(usize::from(be16(data, at)?) * 4)
}
fn wmm(data: &[u8], at: usize) -> Result<Wmm, Error> {
    let raw = bytes(data, at, 32)?;
    let mut acs = [WmmAc {
        cw_min: 0,
        cw_max: 0,
        aifsn: 0,
        cot_us: 0,
    }; 8];
    for (ac, raw) in acs.iter_mut().zip(raw.as_chunks::<4>().0) {
        *ac = WmmAc {
            cw_min: (1u16 << (raw[0] >> 4)) - 1,
            cw_max: (1u16 << (raw[0] & 15)) - 1,
            aifsn: raw[1],
            cot_us: (1000 * u32::from(u16::from_be_bytes([raw[2], raw[3]]))) as u16,
        };
        if ac.cw_min >= ac.cw_max || ac.aifsn == 0 {
            return Err(Error::Format);
        }
    }
    Ok(Wmm {
        client: acs[..4].try_into().unwrap(),
        ap: acs[4..].try_into().unwrap(),
    })
}
fn rule(data: &[u8], at: usize) -> Result<Rule, Error> {
    let len = usize::from(*data.get(at).ok_or(Error::Truncated)?);
    // Unlike the C validator, bound every mandatory/optional read, including
    // the complete declared extension. No malformed-source OOB equivalence.
    let raw = bytes(data, at, len)?;
    if len < 16 {
        return Err(Error::Format);
    }
    if raw[1] & !31 != 0 {
        return Err(Error::Unsupported);
    }
    let result = Rule {
        start_khz: be32(raw, 4)?,
        end_khz: be32(raw, 8)?,
        max_bandwidth_khz: be32(raw, 12)?,
        max_eirp_mbm: be16(raw, 2)?,
        no_ofdm: raw[1] & 1 != 0,
        indoor_only: raw[1] & 2 != 0,
        dfs: raw[1] & 4 != 0,
        no_ir: raw[1] & 8 != 0,
        auto_bandwidth: raw[1] & 16 != 0,
        dfs_cac_ms: if len >= 18 {
            1000 * u32::from(be16(raw, 16)?)
        } else {
            0
        },
        wmm: if len >= 20 {
            Some(wmm(data, pointer(raw, 18)?)?)
        } else {
            None
        },
    };
    // reg_schedule_apply subsequently validates frequency geometry.
    if result.start_khz == 0
        || result.start_khz >= result.end_khz
        || result.max_bandwidth_khz == 0
        || result.max_bandwidth_khz > result.end_khz - result.start_khz
    {
        return Err(Error::Format);
    }
    Ok(result)
}
fn collection(data: &[u8], at: usize) -> Result<(u8, Vec<Rule>), Error> {
    let raw = bytes(data, at, 3)?;
    let len = usize::from(raw[0]);
    let n = usize::from(raw[1]);
    if len < 3 {
        return Err(Error::Format);
    }
    // Current v20 defines no collection extension. Preserve future refusal.
    if raw[2] > 3 {
        return Err(Error::Unsupported);
    }
    let pointers = bytes(data, at + len.div_ceil(2) * 2, n * 2)?;
    let mut rules = Vec::new();
    rules.try_reserve_exact(n).map_err(|_| Error::NoMemory)?;
    for p in pointers.as_chunks::<2>().0 {
        rules.push(rule(data, usize::from(u16::from_be_bytes(*p)) * 4)?);
    }
    Ok((raw[2], rules))
}
impl Database {
    /// `expected` is the normal trusted firmware/setup manifest input. This
    /// checks content integrity; it does not implement a new signature policy.
    pub fn parse(data: Arc<[u8]>, expected: [u8; 32]) -> Result<Self, Error> {
        let digest: [u8; 32] = Sha256::digest(&data).into();
        if digest != expected {
            return Err(Error::Digest);
        }
        if be32(&data, 0)? != 0x5247_4442 {
            return Err(Error::Format);
        }
        if be32(&data, 4)? != 20 {
            return Err(Error::Unsupported);
        }
        let mut at = 8;
        loop {
            let country = bytes(&data, at, 4)?;
            let ptr = pointer(country, 2)?;
            if ptr == 0 {
                break;
            }
            collection(&data, ptr)?;
            at += 4;
        }
        Ok(Self {
            bytes: data,
            digest,
        })
    }
    pub fn select(self, alpha2: [u8; 2]) -> Result<Country, Error> {
        let mut at = 8;
        loop {
            let raw = bytes(&self.bytes, at, 4)?;
            let ptr = pointer(raw, 2)?;
            if ptr == 0 {
                return Err(Error::Country);
            }
            if raw[..2] == alpha2 {
                let (dfs_region, rules) = collection(&self.bytes, ptr)?;
                return Ok(Country {
                    database: self,
                    alpha2,
                    dfs_region,
                    rules,
                });
            }
            at += 4;
        }
    }
}
impl Country {
    pub fn digest(&self) -> [u8; 32] {
        self.database.digest
    }
    pub fn alpha2(&self) -> [u8; 2] {
        self.alpha2
    }
    pub fn dfs_region(&self) -> u8 {
        self.dfs_region
    }
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
    /// First source rule containing the whole frequency interval, matching
    /// freq_reg_info_regd. AUTO_BW joins source-ordered adjacent ranges only.
    pub fn rule(&self, center_khz: u32, bandwidth_khz: u32) -> Option<&Rule> {
        let start = center_khz.checked_sub(bandwidth_khz / 2)?;
        let end = center_khz.checked_add(bandwidth_khz / 2)?;
        self.rules.iter().enumerate().find_map(|(i, r)| {
            if start < r.start_khz || end > r.end_khz {
                return None;
            }
            let max = if r.auto_bandwidth {
                self.auto_bandwidth(i)
            } else {
                r.max_bandwidth_khz
            };
            (bandwidth_khz <= max).then_some(r)
        })
    }
    /// Effective source AUTO_BW ceiling for an existing rule in this country.
    pub fn bandwidth(&self, rule: &Rule) -> Option<u32> {
        let index = self.rules.iter().position(|r| core::ptr::eq(r, rule))?;
        Some(if rule.auto_bandwidth {
            self.auto_bandwidth(index)
        } else {
            rule.max_bandwidth_khz
        })
    }
    fn auto_bandwidth(&self, index: usize) -> u32 {
        let mut start = self.rules[index].start_khz;
        for r in self.rules[..index].iter().rev() {
            if r.end_khz < start {
                break;
            }
            start = r.start_khz;
        }
        let mut end = self.rules[index].end_khz;
        for r in &self.rules[index + 1..] {
            if r.start_khz > end {
                break;
            }
            end = r.end_khz;
        }
        end.saturating_sub(start)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn the_catalog_database_loads_and_a_missing_one_is_refused() {
        use crate::firmware::{Catalog, HandoffProvider, Provenance, Resource};
        let bytes = fixture();
        let catalog = Catalog::from_handoff(alloc::vec![Resource {
            name: NAME,
            target: REQUIREMENT.target,
            provenance: Provenance {
                source: "https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git",
                revision: "synthetic",
                member: NAME,
                license: "ISC",
            },
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(&bytes).into(),
            bytes: bytes.clone(),
        }])
        .unwrap();
        let database = load(&HandoffProvider::new(Some(&catalog))).unwrap();
        assert!(database.select(*b"US").is_ok());
        assert!(matches!(
            load(&HandoffProvider::new(None)),
            Err(LoadError::Resource(_))
        ));
    }
    /// Deliberate database model, not a shipped regulatory policy/release.
    pub(crate) fn fixture() -> Vec<u8> {
        let mut b = vec![0; 72];
        b[..4].copy_from_slice(b"RGDB");
        b[4..8].copy_from_slice(&20u32.to_be_bytes());
        b[8..10].copy_from_slice(b"US");
        b[10..12].copy_from_slice(&4u16.to_be_bytes());
        b[16..19].copy_from_slice(&[3, 2, 1]);
        b[20..24].copy_from_slice(&[0, 6, 0, 12]);
        for (at, start, end) in [(24, 2_400_000u32, 2_500_000u32), (48, 5_150_000, 5_350_000)] {
            b[at] = 16;
            b[at + 2..at + 4].copy_from_slice(&3000u16.to_be_bytes());
            b[at + 4..at + 8].copy_from_slice(&start.to_be_bytes());
            b[at + 8..at + 12].copy_from_slice(&end.to_be_bytes());
            b[at + 12..at + 16].copy_from_slice(&80_000u32.to_be_bytes());
        }
        b
    }
    pub(crate) fn country() -> Country {
        let b = fixture();
        let hash = Sha256::digest(&b).into();
        Database::parse(Arc::from(b), hash)
            .unwrap()
            .select(*b"US")
            .unwrap()
    }
    #[test]
    fn selected_country_is_pinned_explicit_and_bounds_checked() {
        let c = country();
        assert_eq!(c.alpha2(), *b"US");
        assert_eq!(c.dfs_region(), 1);
        assert!(c.rule(5_180_000, 20_000).is_some());
        assert!(c.rule(5_160_000, 40_000).is_none());
        assert!(c.rule(5_210_000, 160_000).is_none());
        assert!(c.rule(5_400_000, 20_000).is_none());
        let b = fixture();
        assert!(matches!(
            Database::parse(Arc::from(b.clone()), [0; 32]),
            Err(Error::Digest)
        ));
        let db = Database::parse(Arc::from(b.clone()), Sha256::digest(&b).into()).unwrap();
        assert!(matches!(db.select(*b"DE"), Err(Error::Country)));
        for n in 0..64 {
            let b = &b[..n];
            assert!(Database::parse(Arc::from(b), Sha256::digest(b).into()).is_err());
        }
    }
    #[test]
    fn optional_rules_wmm_and_future_restrictions_are_not_discarded() {
        let mut b = fixture();
        b.resize(112, 0);
        b[24] = 20;
        b[25] = 31;
        b[40..42].copy_from_slice(&60u16.to_be_bytes());
        b[42..44].copy_from_slice(&20u16.to_be_bytes());
        for chunk in b[80..112].as_chunks_mut::<4>().0 {
            *chunk = [0x35, 2, 0, 6];
        }
        let db = Database::parse(Arc::from(b.clone()), Sha256::digest(&b).into()).unwrap();
        let c = db.select(*b"US").unwrap();
        let r = &c.rules()[0];
        assert!(r.dfs && r.no_ir && r.no_ofdm && r.indoor_only && r.auto_bandwidth);
        assert_eq!(r.dfs_cac_ms, 60_000);
        assert_eq!(
            r.wmm.unwrap().client[0],
            WmmAc {
                cw_min: 7,
                cw_max: 31,
                aifsn: 2,
                cot_us: 6000
            }
        );
        b[25] |= 32;
        assert!(matches!(
            Database::parse(Arc::from(b.clone()), Sha256::digest(&b).into()),
            Err(Error::Unsupported)
        ));
    }
}

#[cfg(test)]
mod source_matrix {
    use super::*;
    fn fixture(flags: u8, len: u8, region: u8) -> Vec<u8> {
        let mut b = vec![0; 128];
        b[..4].copy_from_slice(b"RGDB");
        b[4..8].copy_from_slice(&20u32.to_be_bytes());
        b[8..12].copy_from_slice(&[b'U', b'S', 0, 4]);
        b[16..19].copy_from_slice(&[3, 2, region]);
        b[20..24].copy_from_slice(&[0, 6, 0, 12]);
        for (at, start, end, mask) in [
            (24, 5_150_000u32, 5_250_000u32, flags),
            (48, 5_250_000, 5_350_000, flags ^ 3),
        ] {
            b[at] = len;
            b[at + 1] = mask;
            b[at + 2..at + 4].copy_from_slice(&(1700 + u16::from(flags)).to_be_bytes());
            b[at + 4..at + 8].copy_from_slice(&start.to_be_bytes());
            b[at + 8..at + 12].copy_from_slice(&end.to_be_bytes());
            b[at + 12..at + 16].copy_from_slice(&80_000u32.to_be_bytes());
            if len >= 18 {
                b[at + 16..at + 18].copy_from_slice(&(60 + u16::from(region)).to_be_bytes());
            }
            if len >= 20 {
                b[at + 18..at + 20].copy_from_slice(&20u16.to_be_bytes());
            }
        }
        for ac in 0..8 {
            b[80 + ac * 4..84 + ac * 4].copy_from_slice(&[
                0x35 + (ac % 2) as u8,
                1 + ac as u8,
                0,
                3 + ac as u8,
            ]);
        }
        b
    }
    fn record(b: Vec<u8>, out: &mut Vec<u8>) {
        let add = |out: &mut Vec<u8>, n: u32| out.extend_from_slice(&n.to_le_bytes());
        let pin = Sha256::digest(&b).into();
        let parsed = Database::parse(Arc::from(b), pin);
        let Ok(database) = parsed else {
            add(out, 0);
            return;
        };
        let c = database.select(*b"US").unwrap();
        add(out, 1);
        for n in [
            u32::from(c.alpha2()[0]),
            u32::from(c.alpha2()[1]),
            u32::from(c.dfs_region()),
            c.rules().len() as u32,
        ] {
            add(out, n);
        }
        for r in c.rules() {
            for n in [
                r.start_khz,
                r.end_khz,
                r.max_bandwidth_khz,
                u32::from(r.max_eirp_mbm),
                u32::from(r.no_ofdm),
                u32::from(r.indoor_only),
                u32::from(r.dfs),
                u32::from(r.no_ir),
                u32::from(r.auto_bandwidth),
                r.dfs_cac_ms,
                u32::from(r.wmm.is_some()),
                c.bandwidth(r).unwrap(),
            ] {
                add(out, n);
            }
            if let Some(w) = r.wmm {
                for ac in w.client.into_iter().chain(w.ap) {
                    for n in [
                        u32::from(ac.cw_min),
                        u32::from(ac.cw_max),
                        u32::from(ac.aifsn),
                        u32::from(ac.cot_us),
                    ] {
                        add(out, n);
                    }
                }
            }
        }
    }
    #[test]
    fn complete_pinned_source_database_country_wmm_and_auto_bw_matrix() {
        let mut trace = Vec::new();
        let mut cases = Vec::new();
        for flags in 0..32 {
            for len in [16, 18, 20] {
                for region in 0..4 {
                    let b = fixture(flags, len, region);
                    cases.extend_from_slice(&b);
                    record(b, &mut trace);
                }
            }
        }
        for mode in 0..5 {
            let mut b = fixture(0, 20, 1);
            match mode {
                0 => b[0] = 0,
                1 => b[7] = 21,
                2 => b[24] = 15,
                3 => b[80] = 0x55,
                _ => b[81] = 0,
            };
            cases.extend_from_slice(&b);
            record(b, &mut trace);
        }
        for cot in [0u16, 1, 65, 66, 255, 1024, 65535] {
            let mut b = fixture(0, 20, 1);
            for ac in 0..8 {
                b[82 + ac * 4..84 + ac * 4].copy_from_slice(&cot.to_be_bytes());
            }
            cases.extend_from_slice(&b);
            record(b, &mut trace);
        }
        // Complete unchanged helpers and target layouts, ASan/UBSan, 396 cases.
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(&cases)),
            "12394dc83371fec18dcb71ed4b2dddf92c87cf1aa5a045ceb3e39e5e901f8ec1"
        );
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(&trace)),
            "0ad88d498bc631e974fb23fc5f092513fc3539b28fbb461da92f1f0c477fa794"
        );
    }
}
