//! DeviceTree placement and validation for memory topology.
use super::memory_resources;
use super::{MCC, Node, SOCS, String, Vec, amcc, apertures, format, ptd};

/// An `mcc,t8112`: its cache in the AMCC aperture, its DRAM channels and
/// the PMP PTD bank it writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryCache {
    pub cache: amcc::Cache,
    /// The DCS channels (`reg[2]`) in guest PA: base, bytes and the
    /// `dcs_num_channels` that share them evenly.
    pub channels: (u64, u64, usize),
    /// The PMP's PTD bank, `reg[pmp_ptd_reg_idx]`.
    pub ptd: PtdBank,
    /// The PMP's actual 8-byte update alias, not the whole half-bank.
    pub ptd_updates: (u64, u64),
    /// Capacity shared by publication, updates and interrupt routing.
    pub ptd_entries: usize,
}

/// The PMP's PTD bank (`platform::apple::ptd`): its guest PA and the
/// `ptd-range` records of `/arm-io/pmp/iop-pmp-nub`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtdBank {
    pub physical: u64,
    pub ranges: Vec<ptd::Range>,
    /// Original fourth word, in exactly the same order as ranges. Not AIC IDs.
    pub interrupts: Vec<u32>,
}

/// A `ptd-range` record's bytes: id, first entry, entries, interrupt and a
/// 16-byte name.
pub(super) const PTD_RANGE: usize = 32;

/// The AMCC as `/chosen/lock-regs/amcc` describes it: its apertures and
/// each aperture's planes and lock registers (`platform::apple::amcc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryController {
    pub apertures: Vec<u64>,
    pub layout: amcc::Layout,
}

/// The property iBoot's AMCC map always states.
const APERTURE_COUNT: &str = "aperture-count";

/// A `<name>-reg-offset`, `-reg-mask` and, for a bit register,
/// `-reg-value` triple.
fn lock_register(
    node: &Node<'_>,
    path: &str,
    name: &str,
    bit: bool,
) -> Result<amcc::Register, String> {
    let field = |suffix: &str| {
        node.first_u32(&format!("{name}-reg-{suffix}"))
            .ok_or_else(|| format!("{path} has no {name}-reg-{suffix}"))
    };
    let mask = field("mask")?;
    let value = if bit { field("value")? } else { 0 };
    if value & !mask != 0 {
        return Err(format!("{path} {name}-reg-value has bits outside its mask"));
    }
    Ok(amcc::Register {
        offset: u64::from(field("offset")?),
        mask,
        value,
    })
}

fn lock_register_optional(
    node: &Node<'_>,
    path: &str,
    name: &str,
) -> Result<Option<amcc::Register>, String> {
    let present = ["offset", "mask", "value"]
        .iter()
        .any(|suffix| node.property(&format!("{name}-reg-{suffix}")).is_some());
    present
        .then(|| lock_register(node, path, name, true))
        .transpose()
}

/// The lock group at `path` (a child of `node`), or `None` for a template
/// node iBoot left empty (no `page-size-shift`) or none at all.
fn lock_group(node: &Node<'_>, path: &str) -> Result<Option<amcc::LockGroup>, String> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let Some(group) = node.child(name) else {
        return Ok(None);
    };
    let Some(page_size_shift) = group.first_u32("page-size-shift") else {
        return Ok(None);
    };
    let register = |name: &str, bit: bool| lock_register(&group, path, name, bit);
    let optional_register = |name: &str| lock_register_optional(&group, path, name);
    Ok(Some(amcc::LockGroup {
        page_size_shift,
        lower_limit: register("lower-limit", false)?,
        upper_limit: register("upper-limit", false)?,
        enable: optional_register("enable")?,
        write_disable: optional_register("write-disable")?,
        lock: optional_register("lock")?,
    }))
}

pub(super) fn memory_controller(chosen: &Node<'_>) -> Result<Option<MemoryController>, String> {
    memory_controller_named(chosen, "amcc")
}

/// The AMCC map of `/chosen/lock-regs/amcc`, or `None` without one. The
/// IPSW templates carry the node and its group children empty; a node the
/// boot chain left so (no `aperture-count`, on a SoC whose iBoot map the
/// loader lacks, `stela_loader::lock_regs`) describes no controller, and
/// SPTM's own `ctrr_dt_get_lock_group` stops on it.
pub(super) fn memory_controller_named(
    chosen: &Node<'_>,
    controller: &str,
) -> Result<Option<MemoryController>, String> {
    let Some(node) = chosen
        .child("lock-regs")
        .and_then(|regs| regs.child(controller))
        .filter(|node| node.property(APERTURE_COUNT).is_some())
    else {
        return Ok(None);
    };
    let path = format!("/chosen/lock-regs/{controller}");
    let number = |name: &str| {
        node.first_u32(name)
            .ok_or_else(|| format!("{path} has no {name}"))
    };
    let count = number(APERTURE_COUNT)? as usize;
    let apertures: Vec<u64> = node
        .property("aperture-phys-addr")
        .map(|value| {
            value
                .as_chunks::<8>()
                .0
                .iter()
                .map(|cell| u64::from_le_bytes(*cell))
                .collect()
        })
        .unwrap_or_default();
    if count == 0
        || apertures.len() != count
        || node
            .property("aperture-phys-addr")
            .is_none_or(|bytes| bytes.len() != count * 8)
    {
        return Err(format!(
            "{path} aperture-phys-addr does not list aperture-count apertures"
        ));
    }
    if node.child(&format!("{controller}-ctrr-a")).is_none() {
        return Err(format!("missing lock group {path}/{controller}-ctrr-a"));
    }
    let mut groups = [None; amcc::GROUPS];
    for (group, suffix) in groups.iter_mut().zip(["a", "b", "c", "d"]) {
        *group = lock_group(&node, &format!("{path}/{controller}-ctrr-{suffix}"))?;
    }
    if groups[0].is_none() {
        return Err(format!("{path}/{controller}-ctrr-a has no page-size-shift"));
    }
    let dram_base = chosen
        .property("dram-base")
        .and_then(|value| {
            value
                .first_chunk::<8>()
                .map(|cell| u64::from_le_bytes(*cell))
        })
        .ok_or("/chosen has no dram-base")?;
    let layout = amcc::Layout {
        aperture_bytes: u64::from(number("aperture-size")?),
        planes: number("plane-count")?,
        stride: u64::from(number("plane-stride")?),
        cache_status: if controller == "amcc" {
            Some(lock_register(&node, &path, "cache-status", true)?)
        } else {
            lock_register_optional(&node, &path, "cache-status")?
        },
        groups,
        // SPTM normalizes IOA absolute page limits by subtracting the
        // DRAM page base (T6000 26A434 VA 0xfffffff0270d7748..d777c).
        dram_base: if controller == "ioa" { 0 } else { dram_base },
    };
    if layout.aperture_bytes == 0 || (layout.stride == 0 && layout.planes != 1) {
        return Err(format!("{path} has an empty aperture or plane stride"));
    }
    Ok(Some(MemoryController { apertures, layout }))
}

/// `/arm-io/mcc`, if it is a modeled memory cache controller. Its planes
/// (`reg[1]`) are the lock-regs planes of the one AMCC aperture, which also
/// holds its shared registers (`reg[0]`) and broadcast window (`reg[3]`);
/// its PTD slot (`reg[pmp_ptd_reg_idx]` plus `pmp_ptd_update_space_offset`)
/// lies in the PMP's PTD update registers.
pub(super) fn memory_cache(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    chip_id: u32,
    controller: Option<&MemoryController>,
) -> Result<Option<MemoryCache>, String> {
    let Some(node) = io.child("mcc").filter(|node| node.compatible(MCC)) else {
        return Ok(None);
    };
    const PATH: &str = "/arm-io/mcc";
    let controller =
        controller.ok_or_else(|| format!("{PATH} has no /chosen/lock-regs/amcc aperture"))?;
    let [aperture] = controller.apertures[..] else {
        return Err(format!(
            "{PATH} behind several AMCC apertures is not modeled"
        ));
    };
    let layout = &controller.layout;
    let (bytes, ways) = SOCS
        .iter()
        .find(|soc| soc.chip_id == chip_id)
        .and_then(|soc| soc.memory_cache)
        .ok_or_else(|| format!("ApChipID {chip_id:#x} has no memory cache geometry"))?;
    let range = |owner: &Node<'_>, path: &str, index: usize| -> Result<(u64, u64), String> {
        apertures::registers(owner)
            .unwrap_or_default()
            .get(index)
            .and_then(|&(offset, bytes)| Some((translate(offset, bytes)?, bytes)))
            .ok_or_else(|| format!("{path} reg[{index}] is missing or outside /arm-io ranges"))
    };
    let in_aperture = |index: usize| -> Result<(u64, u64), String> {
        let (physical, bytes) = range(&node, PATH, index)?;
        physical
            .checked_sub(aperture)
            .filter(|&offset| offset < layout.aperture_bytes)
            .map(|offset| (offset, bytes))
            .ok_or_else(|| format!("{PATH} reg[{index}] is outside the AMCC aperture"))
    };
    if in_aperture(1)? != (0, layout.stride * u64::from(layout.planes)) {
        return Err(format!("{PATH} reg[1] is not the lock-regs planes"));
    }
    let channels = range(&node, PATH, 2)?;
    let count = node
        .first_u32("dcs_num_channels")
        .filter(|&count| count != 0 && channels.1 % u64::from(count) == 0)
        .ok_or_else(|| format!("{PATH} dcs_num_channels does not divide reg[2]"))?;
    let number = |name: &str| {
        node.first_u32(name)
            .ok_or_else(|| format!("{PATH} has no {name}"))
    };
    let bank = range(&node, PATH, number("pmp_ptd_reg_idx")? as usize)?;
    if bank.1 != ptd::PTD_BYTES
        || u64::from(number("pmp_ptd_update_space_offset")?) != ptd::UPDATE_OFFSET
    {
        return Err(format!("{PATH} PTD registers are not one PTD bank"));
    }
    let pmp = io
        .child("pmp")
        .ok_or_else(|| format!("{PATH} names PTD registers but there is no /arm-io/pmp"))?;
    let index = pmp
        .first_u32("ptd-update-reg-index")
        .ok_or("/arm-io/pmp has no ptd-update-reg-index")?;
    let updates = range(&pmp, "/arm-io/pmp", index as usize)?;
    let geometry = ptd::Geometry::new(bank, updates).map_err(String::from)?;
    let records = pmp
        .child("iop-pmp-nub")
        .and_then(|nub| nub.property("ptd-range"))
        .filter(|records| !records.is_empty() && records.len() % PTD_RANGE == 0)
        .ok_or("/arm-io/pmp/iop-pmp-nub has no whole ptd-range records")?;
    let (ranges, interrupts) = memory_resources::publication_ranges(records, geometry.entries())?;
    let ptd = PtdBank {
        physical: bank.0,
        ranges,
        interrupts,
    };
    Ok(Some(MemoryCache {
        cache: amcc::Cache {
            shared: in_aperture(0)?,
            broadcast: in_aperture(3)?.0,
            bytes,
            ways,
        },
        channels: (channels.0, channels.1, count as usize),
        ptd,
        ptd_updates: geometry.updates(),
        ptd_entries: geometry.entries(),
    }))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{flat_fixture_extent, tree_with_io};
    use super::super::*;
    use super::*;

    #[test]
    fn io_access_description_preserves_optional_controls_and_absolute_page_basis() {
        use crate::machine::adt::encode;
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
        use crate::machine::adt::encode;
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
        use crate::machine::adt::encode;
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
            layout: amcc::Layout {
                aperture_bytes: 0xf4_0000,
                planes: 4,
                stride: 0x4_0000,
                cache_status: Some(amcc::Register {
                    offset: 0x424,
                    mask: 1,
                    value: 1,
                }),
                groups: [
                    Some(amcc::LockGroup {
                        page_size_shift: 14,
                        lower_limit: amcc::Register {
                            offset: 0x680,
                            mask: u32::MAX,
                            value: 0,
                        },
                        upper_limit: amcc::Register {
                            offset: 0x684,
                            mask: u32::MAX,
                            value: 0,
                        },
                        enable: Some(amcc::Register {
                            offset: 0x688,
                            mask: 1,
                            value: 1,
                        }),
                        write_disable: Some(amcc::Register {
                            offset: 0x7f0,
                            mask: 1,
                            value: 1,
                        }),
                        lock: Some(amcc::Register {
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
                cache: amcc::Cache {
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
                        ptd::Range {
                            id: 1,
                            start: 0,
                            count: 1,
                            name: "NULL".into(),
                        },
                        ptd::Range {
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
        let bank = (0x23b3c0000, ptd::PTD_BYTES);
        let geometry = ptd::Geometry::new(bank, (bank.0 + ptd::UPDATE_OFFSET, 0x4000)).unwrap();
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
    #[ignore = "requires pinned original 26A434 J473 DeviceTree via STELA_TEST_MCC_J473_DT"]
    fn original_j473_uses_its_actual_2048_slot_update_alias() {
        use sha2::{Digest, Sha256};
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
        let geometry = ptd::Geometry::new(bank, updates).unwrap();
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
}
