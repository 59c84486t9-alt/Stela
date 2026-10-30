use super::super::*;
use super::*;
use crate::board::fixture_support::{flat_fixture_extent, tree_with_io};

#[test]
fn io_access_description_preserves_optional_controls_and_absolute_page_basis() {
    use stela_contracts::adt::encode;
    let chosen = |partial_enable: bool, extra_address_byte: bool| {
        let mut properties: Vec<(String, Vec<u8>)> = vec![
            ("name".into(), b"ioa-ctrr-a\0".to_vec()),
            ("page-size-shift".into(), 14u32.to_le_bytes().to_vec()),
        ];
        for (name, offset, mask, value) in [
            ("lower-limit", 0x220u32, u32::MAX, None),
            ("upper-limit", 0x224, u32::MAX, None),
            ("enable", 0x228, 1, Some(1u32)),
        ] {
            properties.push((format!("{name}-reg-offset"), offset.to_le_bytes().to_vec()));
            properties.push((format!("{name}-reg-mask"), mask.to_le_bytes().to_vec()));
            if let Some(value) = value
                && !partial_enable
            {
                properties.push((format!("{name}-reg-value"), value.to_le_bytes().to_vec()));
            }
        }
        let refs: Vec<_> = properties
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        let group = encode(&refs, &[]);
        let mut addresses = 0x282000000u64.to_le_bytes().to_vec();
        if extra_address_byte {
            addresses.push(0);
        }
        let controller = encode(
            &[
                ("name", b"ioa\0"),
                ("aperture-count", &1u32.to_le_bytes()),
                ("aperture-size", &0x4000u32.to_le_bytes()),
                ("aperture-phys-addr", &addresses),
                ("plane-count", &1u32.to_le_bytes()),
                ("plane-stride", &0u32.to_le_bytes()),
            ],
            &[group],
        );
        let registers = encode(&[("name", b"lock-regs\0")], &[controller]);
        encode(
            &[("dram-base", &0x10000000000u64.to_le_bytes())],
            &[registers],
        )
    };
    let bytes = chosen(false, false);
    let root = Node::root(&bytes).unwrap();
    assert!(memory_controller(&root).unwrap().is_none());
    let ioa = memory_controller_named(&root, "ioa").unwrap().unwrap();
    assert_eq!(ioa.apertures, [0x282000000]);
    assert_eq!(ioa.layout.dram_base, 0);
    assert_eq!(ioa.layout.stride, 0);
    assert_eq!(ioa.layout.cache_status, None);
    assert_eq!(ioa.layout.groups[0].unwrap().lower_limit.offset, 0x220);
    assert_eq!(ioa.layout.groups[0].unwrap().enable.unwrap().offset, 0x228);
    assert_eq!(ioa.layout.groups[0].unwrap().write_disable, None);
    assert_eq!(ioa.layout.groups[0].unwrap().lock, None);
    for bytes in [chosen(true, false), chosen(false, true)] {
        assert!(memory_controller_named(&Node::root(&bytes).unwrap(), "ioa").is_err());
    }
}

#[test]
fn every_filled_amcc_lock_group_is_described() {
    use stela_contracts::adt::encode;
    let word = |value: u32| value.to_le_bytes().to_vec();
    let group = |name: &str, index: u32, filled: bool| {
        let mut properties = vec![("name".to_string(), [name.as_bytes(), &[0]].concat())];
        if filled {
            properties.push(("page-size-shift".into(), word(14)));
            for (field, base, value) in [
                ("lower-limit", 0xaa0, Some(0)),
                ("upper-limit", 0xab0, Some(0)),
                ("enable", 0xac0, Some(1)),
                ("lock", 0xad0, Some(1)),
                ("write-disable", 0xae0, Some(1)),
            ] {
                let mask = if value == Some(0) { u32::MAX } else { 1 };
                properties.push((format!("{field}-reg-offset"), word(base + 4 * index)));
                properties.push((format!("{field}-reg-mask"), word(mask)));
                if let Some(value) = value {
                    properties.push((format!("{field}-reg-value"), word(value)));
                }
            }
        }
        let refs: Vec<_> = properties
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        encode(&refs, &[])
    };
    let chosen = |d_filled: bool| {
        let controller = encode(
            &[
                ("name", b"amcc\0"),
                ("aperture-count", &word(1)),
                ("aperture-size", &word(0x14_0000)),
                ("aperture-phys-addr", &0x2_2000_0000u64.to_le_bytes()),
                ("plane-count", &word(4)),
                ("plane-stride", &word(0x4_0000)),
                ("cache-status-reg-offset", &word(0x82c)),
                ("cache-status-reg-mask", &word(1)),
                ("cache-status-reg-value", &word(1)),
            ],
            &[
                group("amcc-ctrr-a", 0, true),
                group("amcc-ctrr-b", 1, true),
                group("amcc-ctrr-c", 2, true),
                group("amcc-ctrr-d", 3, d_filled),
            ],
        );
        let registers = encode(&[("name", b"lock-regs\0")], &[controller]);
        encode(
            &[("dram-base", &0x100_0000_0000u64.to_le_bytes())],
            &[registers],
        )
    };
    let bytes = chosen(true);
    let amcc = memory_controller(&Node::root(&bytes).unwrap())
        .unwrap()
        .unwrap();
    for (index, group) in amcc.layout.groups.iter().enumerate() {
        let group = group.unwrap();
        assert_eq!(group.lower_limit.offset, 0xaa0 + 4 * index as u64);
        assert_eq!(group.lock.unwrap().offset, 0xad0 + 4 * index as u64);
        assert_eq!(
            group.write_disable.unwrap().offset,
            0xae0 + 4 * index as u64
        );
    }
    let bytes = chosen(false);
    let amcc = memory_controller(&Node::root(&bytes).unwrap())
        .unwrap()
        .unwrap();
    assert!(amcc.layout.groups[2].is_some() && amcc.layout.groups[3].is_none());
}

/// The J473AP's `/arm-io/mcc` and `/arm-io/pmp` registers behind its one
/// AMCC aperture.
#[test]
fn an_mcc_places_its_cache_channels_and_ptd_bank() {
    use stela_contracts::adt::encode;
    const MODELED: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,2"];
    let z = |text: &str| [text.as_bytes(), &[0]].concat();
    let u32s = |cells: &[u32]| {
        cells
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let u64s = |cells: &[u64]| {
        cells
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let mcc = |ptd_offset: u32| {
        encode(
            &[
                ("name", &z("mcc")),
                ("compatible", &z(MCC)),
                (
                    "reg",
                    &u64s(&[
                        0x10_0000,
                        0x8_0000,
                        0,
                        0x10_0000,
                        0x100_0000,
                        0x200_0000,
                        0xf0_0000,
                        0x10_0000,
                        0x3b3c_0000,
                        0x2_0000,
                    ]),
                ),
                ("dcs_num_channels", &u32s(&[8])),
                ("pmp_ptd_reg_idx", &u32s(&[4])),
                ("pmp_ptd_update_space_offset", &u32s(&[ptd_offset])),
            ],
            &[],
        )
    };
    // Two J473AP `ptd-range` records.
    let record = |id: u32, start: u32, count: u32, name: &str| {
        let mut record = [0u8; PTD_RANGE];
        for (at, word) in [id, start, count, 0].into_iter().enumerate() {
            record[4 * at..4 * at + 4].copy_from_slice(&word.to_le_bytes());
        }
        record[16..16 + name.len()].copy_from_slice(name.as_bytes());
        record
    };
    let records = [record(1, 0, 1, "NULL"), record(2, 1, 1, "PMP-STATUS")].concat();
    let nub = encode(&[("name", &z("iop-pmp-nub")), ("ptd-range", &records)], &[]);
    let pmp = encode(
        &[
            ("name", &z("pmp")),
            ("reg", &u64s(&[0x3bc0_0000, 0x6_c000, 0x3b3d_0000, 0x4000])),
            ("ptd-update-reg-index", &u32s(&[1])),
        ],
        &[nub],
    );
    let controller = MemoryController {
        apertures: vec![0x2_0000_0000],
        layout: crate::amcc::Layout {
            aperture_bytes: 0xf4_0000,
            planes: 4,
            stride: 0x4_0000,
            cache_status: Some(crate::amcc::Register {
                offset: 0x424,
                mask: 1,
                value: 1,
            }),
            groups: [
                Some(crate::amcc::LockGroup {
                    page_size_shift: 14,
                    lower_limit: crate::amcc::Register {
                        offset: 0x680,
                        mask: u32::MAX,
                        value: 0,
                    },
                    upper_limit: crate::amcc::Register {
                        offset: 0x684,
                        mask: u32::MAX,
                        value: 0,
                    },
                    enable: Some(crate::amcc::Register {
                        offset: 0x688,
                        mask: 1,
                        value: 1,
                    }),
                    write_disable: Some(crate::amcc::Register {
                        offset: 0x7f0,
                        mask: 1,
                        value: 1,
                    }),
                    lock: Some(crate::amcc::Register {
                        offset: 0x68c,
                        mask: 1,
                        value: 1,
                    }),
                }),
                None,
                None,
                None,
            ],
            dram_base: 0x8_0000_0000,
        },
    };
    let found = |ptd_offset: u32, controller: Option<&MemoryController>| {
        let tree = tree_with_io(
            0x8112,
            "Apple M2",
            MODELED,
            &[],
            &[mcc(ptd_offset), pmp.clone()],
        );
        let io = Node::root(&tree).unwrap().child("arm-io").unwrap();
        memory_cache(
            &io,
            &flat_fixture_extent(&|offset| Some(0x2_0000_0000 + offset)),
            0x8112,
            controller,
        )
    };
    assert_eq!(
        found(0x1_0000, Some(&controller)),
        Ok(Some(MemoryCache {
            cache: crate::amcc::Cache {
                shared: (0x10_0000, 0x8_0000),
                broadcast: 0xf0_0000,
                bytes: 8 << 20,
                ways: 16,
            },
            channels: (0x2_0100_0000, 0x200_0000, 8),
            ptd_updates: (0x2_3b3d_0000, 0x4000),
            ptd_entries: 2048,
            ptd: PtdBank {
                physical: 0x2_3b3c_0000,
                interrupts: vec![0, 0],
                ranges: vec![
                    crate::ptd::Range {
                        id: 1,
                        start: 0,
                        count: 1,
                        name: "NULL".into(),
                    },
                    crate::ptd::Range {
                        id: 2,
                        start: 1,
                        count: 1,
                        name: "PMP-STATUS".into(),
                    },
                ],
            },
        }))
    );
    // The PTD updates must be the bank's, and the planes need the
    // lock-regs aperture.
    assert!(found(0x2_0000, Some(&controller)).is_err());
    assert!(found(0x1_0000, None).is_err());
}

#[test]
fn pmp_range_capacity_is_bounded_by_its_own_update_alias() {
    let bank = (0x23b3c0000, crate::ptd::PTD_BYTES);
    let geometry =
        crate::ptd::Geometry::new(bank, (bank.0 + crate::ptd::UPDATE_OFFSET, 0x4000)).unwrap();
    let mut record = [0u8; PTD_RANGE];
    record[..4].copy_from_slice(&1u32.to_le_bytes());
    record[4..8].copy_from_slice(&2047u32.to_le_bytes());
    record[8..12].copy_from_slice(&1u32.to_le_bytes());
    record[12..16].copy_from_slice(&0x504d_5003u32.to_le_bytes());
    record[16..20].copy_from_slice(b"LAST");
    let (ranges, resources) =
        memory_resources::publication_ranges(&record, geometry.entries()).unwrap();
    assert_eq!(ranges[0].start, 2047);
    assert_eq!(resources, [0x504d_5003]);
    record[8..12].copy_from_slice(&2u32.to_le_bytes());
    assert!(memory_resources::publication_ranges(&record, geometry.entries()).is_err());
    record[4..8].copy_from_slice(&2048u32.to_le_bytes());
    record[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert!(memory_resources::publication_ranges(&record, geometry.entries()).is_err());
    // A nominal half-bank limit cannot bypass the implemented route bitmap.
    assert!(memory_resources::publication_ranges(&record, 8192).is_err());
}

#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_MCC_J473_DT"]
fn original_j473_uses_its_2048_slot_update_alias() {
    use stela_crypto::{Sha256, digest::Digest};
    let path = std::env::var("STELA_TEST_MCC_J473_DT").unwrap();
    let data = std::fs::read(path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&data)),
        "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
    );
    let root = Node::root(&data).unwrap();
    let io = root.child("arm-io").unwrap();
    let mcc = io.child("mcc").unwrap();
    let pmp = io.child("pmp").unwrap();
    assert!(mcc.compatible(MCC));
    let bank = mcc.pairs("reg").unwrap()[mcc.first_u32("pmp_ptd_reg_idx").unwrap() as usize];
    let updates =
        pmp.pairs("reg").unwrap()[pmp.first_u32("ptd-update-reg-index").unwrap() as usize];
    assert_eq!(bank, (0x3b3c0000, 0x20000));
    assert_eq!(updates, (0x3b3d0000, 0x4000));
    let geometry = crate::ptd::Geometry::new(bank, updates).unwrap();
    assert_eq!(geometry.entries(), 2048);
    let records = pmp
        .child("iop-pmp-nub")
        .unwrap()
        .property("ptd-range")
        .unwrap();
    let (ranges, interrupt_resources) =
        memory_resources::publication_ranges(records, geometry.entries()).unwrap();
    assert_eq!(ranges.len(), interrupt_resources.len());
    assert!(ranges.iter().all(|range| range.start + range.count <= 2048));
}
