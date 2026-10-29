extern crate std;
use super::*;
use alloc::vec::Vec;
fn fixture(kind: usize, seed: u32, revision: u8, length: usize, mode: u32, count: u32) -> Vec<u8> {
    let mut raw: Vec<u8> = (0..4096).map(|i| (i * 37 + seed as usize) as u8).collect();
    raw[0] = revision;
    raw[1..5].copy_from_slice(&mode.to_le_bytes());
    match kind {
        1 => raw[5..9].copy_from_slice(&count.to_le_bytes()),
        2 => raw[1] = count as u8,
        4 => raw[5] = count as u8,
        _ => (),
    }
    raw.truncate(length);
    raw
}
#[test]
fn exact_sar_shapes_official_profiles_and_bool_mode_conversion() {
    for (kind, k, offset, capacity) in [(SarKind::Wrds, 0, 5, 1), (SarKind::Ewrd, 1, 9, 3)] {
        for revision in [2, 3] {
            let bands = if revision == 2 { 11 } else { 12 };
            let size = offset + capacity * 4 * bands;
            let raw = fixture(k, 4, revision, size, 2, 3);
            let sar = Sar::parse(kind, &raw).unwrap();
            assert_eq!(sar.raw().as_ptr(), raw.as_ptr());
            assert_eq!(sar.subbands(), bands);
            assert_eq!(sar.raw_mode(), 2);
            assert!(sar.source_enabled());
            assert_eq!(sar.declared_profiles(), capacity as u8);
            for index in 0..capacity {
                let official = if kind == SarKind::Wrds {
                    1
                } else {
                    index as u8 + 2
                };
                for chain in 0..4 {
                    for band in 0..bands {
                        assert_eq!(
                            sar.value(official, chain, band),
                            Some(raw[offset + (index * 4 + chain) * bands + band])
                        );
                    }
                }
            }
            assert_eq!(sar.value(0, 0, 0), None);
            assert_eq!(sar.value(5, 0, 0), None);
            assert_eq!(sar.value(1, 4, 0), None);
            assert_eq!(sar.value(1, 0, bands), None);
            for n in 0..size {
                assert!(Sar::parse(kind, &raw[..n]).is_err());
            }
            let mut extra = raw.clone();
            extra.push(0);
            assert!(matches!(
                Sar::parse(kind, &extra),
                Err(Error::ExactSize { .. })
            ));
        }
    }
    for count in 0..=4 {
        let raw = fixture(1, 0, 3, 153, 0, count);
        let result = Sar::parse(SarKind::Ewrd, &raw);
        if count < 4 {
            let sar = result.unwrap();
            assert!(!sar.source_enabled());
            assert_eq!(sar.declared_profiles(), count as u8);
            assert_eq!(sar.value(2 + count as u8, 0, 0), None);
        } else {
            assert!(matches!(result, Err(Error::ProfileCount { .. })));
        }
    }
    for revision in 0..=255 {
        if revision != 2 && revision != 3 {
            assert!(matches!(
                Sar::parse(SarKind::Wrds, &fixture(0, 0, revision, 49, 0, 0)),
                Err(Error::Revision(_))
            ));
        }
    }
}
#[test]
fn geo_full_capacity_and_ppag_size_first_revision_branch_are_exact() {
    for revision in [3, 4] {
        let bands = if revision == 3 { 3 } else { 4 };
        let size = 2 + 8 * bands * 3;
        for count in 0..=9 {
            let raw = fixture(2, 33, revision, size, 0, count);
            let result = Geo::parse(&raw);
            if (3..=8).contains(&count) {
                let geo = result.unwrap();
                assert_eq!(geo.raw().as_ptr(), raw.as_ptr());
                assert_eq!(geo.declared_profiles(), count as u8);
                let value = geo.band(count as usize - 1, bands - 1).unwrap();
                let at = 2 + ((count as usize - 1) * bands + bands - 1) * 3;
                assert_eq!(
                    value,
                    GeoBand {
                        maximum: raw[at],
                        chain_offsets: [raw[at + 1], raw[at + 2]]
                    }
                );
                assert_eq!(geo.band(count as usize, 0), None);
                assert_eq!(geo.band(0, bands), None);
                for n in 0..size {
                    assert!(Geo::parse(&raw[..n]).is_err());
                }
            } else {
                assert!(matches!(result, Err(Error::ProfileCount { .. })));
            }
        }
    }
    for revision in 1..=5 {
        for size in [26, 27, 28, 29, 30, 4096] {
            let mut raw = fixture(3, 0, revision, size, u32::MAX, 0);
            if raw.len() > 5 {
                raw[5] = 0x80;
            }
            let result = Ppag::parse(&raw);
            let valid = size >= 27
                && if size >= 29 {
                    revision == 5
                } else {
                    revision <= 4
                };
            assert_eq!(result.is_ok(), valid, "rev {revision} size {size}");
            if let Ok(ppag) = result {
                assert_eq!(ppag.raw().as_ptr(), raw.as_ptr());
                assert_eq!(ppag.gain(0, 0), Some(-128));
                assert_eq!(ppag.gain(2, 0), None);
                assert_eq!(ppag.gain(0, ppag.subbands()), None);
                assert_eq!(
                    ppag.source_flags(),
                    match revision {
                        1 | 2 => 3,
                        3 => 0x7ff,
                        _ => u32::MAX,
                    }
                );
            }
        }
    }
}
#[test]
fn tas_and_country_maps_keep_raw_fields_without_policy_permission() {
    for revision in [1, 2] {
        for count in 0..=17 {
            let raw = fixture(4, 17, revision, 38, 0x18007, count);
            let result = Tas::parse(&raw);
            if count <= 16 {
                let tas = result.unwrap();
                assert_eq!(tas.raw().as_ptr(), raw.as_ptr());
                assert!(tas.source_enabled());
                assert_eq!(tas.raw_selection(), 0x18007);
                assert_eq!(
                    tas.selection(),
                    TasSelection {
                        override_iec: true,
                        enable_iec: true,
                        usa_uhb: true,
                        canada_uhb: revision == 2
                    }
                );
                assert_eq!(tas.country(count as usize), None);
                if count != 0 {
                    assert_eq!(tas.country(0), Some(u16::from_le_bytes([raw[6], raw[7]])));
                }
            } else {
                assert!(matches!(result, Err(Error::ProfileCount { .. })));
            }
        }
    }
    let mut raw = fixture(5, 0, 1, 4096, 0, 0);
    for (i, value) in raw[1..339].iter_mut().enumerate() {
        *value = i as u8;
    }
    let map = CountryMap::parse(&raw).unwrap();
    assert_eq!(map.raw().as_ptr(), raw.as_ptr());
    assert_eq!(map.raw_map(), &raw[1..339]);
    for profiles in 0..=8 {
        let normalized = map.sgom(profiles).unwrap();
        for (i, value) in normalized.iter().enumerate() {
            let input = i as u8;
            let high = input >> 4;
            let low = input & 15;
            assert_eq!(
                *value,
                (if high <= profiles { high << 4 } else { 0 })
                    | if low <= profiles { low } else { 0 }
            );
        }
    }
    assert!(map.sgom(9).is_err());
    for n in 0..339 {
        assert!(CountryMap::parse(&raw[..n]).is_err());
    }
    raw.push(0);
    assert!(matches!(CountryMap::parse(&raw), Err(Error::Bound(4097))));
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_POWER_TABLES_ORACLE"]
fn unchanged_linux_full_power_table_getters_and_maps_oracle() {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_POWER_TABLES_ORACLE").unwrap()).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "3f510f04b2be94c7b306a1da180eec3ee2020b7d9aae94b8fa49048f1bab189a"
    );
    let hex =
        |v: &[u8]| -> std::string::String { v.iter().map(|b| std::format!("{b:02x}")).collect() };
    let mut cases = [0; 7];
    let mut accepted = [0; 7];
    for line in core::str::from_utf8(&bytes).unwrap().lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        assert_eq!(f[0], "case");
        let kind = f[1].parse::<usize>().unwrap();
        let seed = f[2].parse().unwrap();
        let revision = f[3].parse().unwrap();
        let length = f[4].parse().unwrap();
        let mode = f[5].parse().unwrap();
        let count = f[6].parse().unwrap();
        let geo = f[7].parse().unwrap();
        let ret = f[8].parse::<i32>().unwrap();
        let raw = fixture(kind, seed, revision, length, mode, count);
        let mut meta = [0u32; 8];
        let mut snapshot = Vec::new();
        let result: Result<i32, Error> = (|| {
            Ok(match kind {
                0 | 1 => {
                    let sar = Sar::parse(
                        if kind == 0 {
                            SarKind::Wrds
                        } else {
                            SarKind::Ewrd
                        },
                        &raw,
                    )?;
                    snapshot.resize(196, 0);
                    for p in 0..usize::from(sar.declared_profiles()) {
                        let official = if kind == 0 { 1 } else { p as u8 + 2 };
                        let index = usize::from(official - 1);
                        snapshot[index * 49] = u8::from(sar.source_enabled());
                        for chain in 0..4 {
                            for band in 0..sar.subbands() {
                                snapshot[index * 49 + 1 + chain * 12 + band] =
                                    sar.value(official, chain, band).unwrap();
                            }
                        }
                    }
                    0
                }
                2 => {
                    let table = Geo::parse(&raw)?;
                    meta[..4].copy_from_slice(&[
                        u32::from(revision),
                        2,
                        u32::from(table.declared_profiles()),
                        1,
                    ]);
                    snapshot.resize(96, 0);
                    for p in 0..usize::from(table.declared_profiles()) {
                        for b in 0..table.bands() {
                            let value = table.band(p, b).unwrap();
                            let at = (p * 4 + b) * 3;
                            snapshot[at..at + 3].copy_from_slice(&[
                                value.maximum,
                                value.chain_offsets[0],
                                value.chain_offsets[1],
                            ]);
                        }
                    }
                    0
                }
                3 => {
                    let table = Ppag::parse(&raw)?;
                    meta[..3].copy_from_slice(&[u32::from(revision), table.source_flags(), 2]);
                    snapshot.resize(24, 0);
                    for chain in 0..2 {
                        for band in 0..table.subbands() {
                            snapshot[chain * 12 + band] = table.gain(chain, band).unwrap() as u8;
                        }
                    }
                    0
                }
                4 => {
                    let table = Tas::parse(&raw)?;
                    let sel = table.selection();
                    meta[..5].copy_from_slice(&[
                        u32::from(table.declared_countries()),
                        table.raw_selection(),
                        2,
                        u32::from(revision),
                        u32::from(sel.override_iec)
                            | (u32::from(sel.enable_iec) << 1)
                            | (u32::from(sel.usa_uhb) << 2)
                            | (u32::from(sel.canada_uhb) << 3),
                    ]);
                    snapshot.resize(32, 0);
                    for i in 0..usize::from(table.declared_countries()) {
                        snapshot[i * 2..i * 2 + 2]
                            .copy_from_slice(&table.country(i).unwrap().to_le_bytes());
                    }
                    i32::from(table.source_enabled())
                }
                5 | 6 => {
                    let table = CountryMap::parse(&raw)?;
                    meta[0] = 1;
                    snapshot = if kind == 5 {
                        table.sgom(geo)?.to_vec()
                    } else {
                        table.raw_map().to_vec()
                    };
                    0
                }
                _ => panic!("kind"),
            })
        })();
        if kind >= 5 {
            assert_eq!(result.is_ok(), f[9].parse::<u32>().unwrap() != 0, "{line}");
        } else {
            assert_eq!(result.as_ref().copied().unwrap_or(-1), ret, "{line}");
        }
        cases[kind] += 1;
        if result.is_ok() {
            accepted[kind] += 1;
            let expected: Vec<u32> = f[9..17].iter().map(|v| v.parse().unwrap()).collect();
            assert_eq!(meta.as_slice(), expected, "{line}");
            assert_eq!(hex(&snapshot), f[17], "{line}");
        }
    }
    assert_eq!(cases, [1024; 7]);
    assert!(accepted.iter().all(|v| *v > 10), "{accepted:?}");
}
