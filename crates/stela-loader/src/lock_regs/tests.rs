use super::*;
use crate::apple_device_tree::Node;

const AMCC_GROUPS: [&str; 4] = ["amcc-ctrr-a", "amcc-ctrr-b", "amcc-ctrr-c", "amcc-ctrr-d"];

/// The IPSW templates' empty `/chosen/lock-regs`: the AMCC's four
/// groups and, from the M1 Pro to the M3 Max, the IOA's CTRR-A.
pub(crate) fn template(tree: &mut DeviceTree, ioa: bool) -> Result<()> {
    tree.ensure_child("/chosen", "lock-regs")?;
    tree.ensure_child("/chosen/lock-regs", "amcc")?;
    for group in AMCC_GROUPS {
        tree.ensure_child(AMCC, group)?;
    }
    if ioa {
        tree.ensure_child("/chosen/lock-regs", "ioa")?;
        tree.ensure_child(IOA, "ioa-ctrr-a")?;
    }
    Ok(())
}

fn chosen(ioa: bool) -> Result<DeviceTree> {
    let mut tree = DeviceTree {
        root: Node::named("device-tree")?,
    };
    tree.ensure_child("/", "chosen")?;
    template(&mut tree, ioa)?;
    Ok(tree)
}

#[test]
fn publishes_the_amcc_map_sptm_reads() -> Result<()> {
    let mut tree = chosen(false)?;
    assert!(publish(&mut tree, &T8112)?);
    let u32_of = |path: &str, name: &str| tree.property(path, name).and_then(|p| p.as_u32());
    assert_eq!(u32_of(AMCC, "aperture-count"), Some(1));
    assert_eq!(u32_of(AMCC, "aperture-size"), Some(0xf4_0000));
    assert_eq!(
        tree.property(AMCC, "aperture-phys-addr").unwrap().as_u64(),
        Some(0x2_0000_0000)
    );
    assert_eq!(u32_of(AMCC, "plane-count"), Some(4));
    assert_eq!(u32_of(AMCC, "plane-stride"), Some(0x4_0000));
    assert_eq!(u32_of(AMCC, "cache-status-reg-offset"), Some(0x424));
    assert_eq!(u32_of(AMCC, "cache-status-reg-value"), Some(1));
    let a = format!("{AMCC}/amcc-ctrr-a");
    assert_eq!(u32_of(&a, "page-size-shift"), Some(14));
    assert_eq!(u32_of(&a, "lower-limit-reg-offset"), Some(0x680));
    assert_eq!(u32_of(&a, "upper-limit-reg-mask"), Some(u32::MAX));
    assert!(tree.property(&a, "upper-limit-reg-value").is_none());
    assert_eq!(u32_of(&a, "lock-reg-offset"), Some(0x68c));
    assert_eq!(u32_of(&a, "write-disable-reg-offset"), Some(0x7f0));
    assert_eq!(u32_of(&a, "enable-reg-value"), Some(1));
    let b = format!("{AMCC}/amcc-ctrr-b");
    assert!(
        tree.node(&b)
            .is_some_and(|node| node.property("page-size-shift").is_none())
    );
    Ok(())
}

#[test]
fn publishes_original_t6000_amcc_and_ioa_without_invented_registers() -> Result<()> {
    let mut tree = chosen(true)?;
    let amcc = table(0x6000, None).unwrap();
    let ioa = ioa_table(0x6000, None).unwrap();
    // Re-publication must remove T8112-only fields, not retain a fake 7f0.
    publish(&mut tree, &T8112)?;
    publish(&mut tree, amcc)?;
    publish_ioa(&mut tree, ioa)?;
    for (path, expected) in [
        (
            AMCC,
            &[
                0x2_0000_0000u64,
                0x2_0100_0000,
                0x2_0200_0000,
                0x2_0300_0000,
            ],
        ),
        (
            IOA,
            &[
                0x2_8200_0000u64,
                0x3_0400_0000,
                0x3_8300_0000,
                0x4_0200_0000,
            ],
        ),
    ] {
        assert_eq!(
            tree.property(path, "aperture-count").unwrap().as_u32(),
            Some(4)
        );
        let addresses = &tree.property(path, "aperture-phys-addr").unwrap().value;
        let actual: Vec<_> = addresses
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bytes| u64::from_le_bytes(*bytes))
            .collect();
        assert_eq!(actual, expected);
    }
    let number = |path: &str, name: &str| tree.property(path, name).and_then(|p| p.as_u32());
    for (path, name, expected) in [
        (AMCC, "aperture-size", 0x20_0000),
        (AMCC, "plane-count", 4),
        (AMCC, "plane-stride", 0x4_0000),
        (AMCC, "broadcast-reg-offset", 0x10_000c),
        (AMCC, "broadcast-reg-mask", 1),
        (AMCC, "broadcast-reg-value", 1),
        (AMCC, "cache-status-reg-offset", 0x1c00),
        (AMCC, "cache-status-reg-mask", 0x1f),
        (AMCC, "cache-status-reg-value", 0),
        (IOA, "aperture-size", 0x4000),
        (IOA, "plane-count", 1),
        (IOA, "plane-stride", 0),
        (IOA, "master-lock-reg-offset", 0),
        (IOA, "master-lock-reg-mask", 1),
        (IOA, "master-lock-reg-value", 1),
    ] {
        assert_eq!(number(path, name), Some(expected), "{path}/{name}");
    }
    for (path, absent) in [(AMCC, "master-lock"), (IOA, "broadcast")] {
        for suffix in ["offset", "mask", "value"] {
            assert!(
                tree.property(path, &format!("{absent}-reg-{suffix}"))
                    .is_none()
            );
        }
    }
    for (path, lower, upper, enable, lock, property_count) in [
        (
            "/chosen/lock-regs/amcc/amcc-ctrr-a",
            0x680,
            0x684,
            0x688,
            Some(0x68c),
            12,
        ),
        (
            "/chosen/lock-regs/ioa/ioa-ctrr-a",
            0x220,
            0x224,
            0x228,
            None,
            9,
        ),
    ] {
        assert_eq!(number(path, "page-size-shift"), Some(14));
        for (name, offset) in [("lower-limit", lower), ("upper-limit", upper)] {
            assert_eq!(number(path, &format!("{name}-reg-offset")), Some(offset));
            assert_eq!(number(path, &format!("{name}-reg-mask")), Some(u32::MAX));
            assert!(tree.property(path, &format!("{name}-reg-value")).is_none());
        }
        assert_eq!(number(path, "enable-reg-offset"), Some(enable));
        assert_eq!(number(path, "enable-reg-mask"), Some(1));
        assert_eq!(number(path, "enable-reg-value"), Some(1));
        assert_eq!(number(path, "lock-reg-offset"), lock);
        for suffix in ["offset", "mask", "value"] {
            assert!(
                tree.property(path, &format!("write-disable-reg-{suffix}"))
                    .is_none()
            );
        }
        assert_eq!(tree.node(path).unwrap().properties.len(), property_count);
    }
    assert_eq!(tree.node(AMCC).unwrap().properties.len(), 12);
    assert_eq!(tree.node(IOA).unwrap().properties.len(), 9);
    assert!(tree.node("/chosen/lock-regs/ioa/ioa-ctrr-b").is_none());
    for name in &AMCC_GROUPS[1..] {
        assert_eq!(
            tree.node(&format!("{AMCC}/{name}"))
                .unwrap()
                .properties
                .len(),
            1
        );
    }
    let bytes = tree.serialize();
    assert_eq!(DeviceTree::parse(&bytes)?, tree);
    let before = bytes;
    publish(&mut tree, amcc)?;
    publish_ioa(&mut tree, ioa)?;
    assert_eq!(tree.serialize(), before);
    Ok(())
}

#[test]
fn every_soc_has_one_well_formed_description() {
    let mut chips: Vec<u32> = FAMILIES.iter().flat_map(|f| f.chips).copied().collect();
    let count = chips.len();
    chips.sort_unstable();
    chips.dedup();
    assert_eq!(chips.len(), count, "a SoC in two families");
    for family in &crate::carveouts::FAMILIES {
        for &chip in family.chips {
            assert!(
                table(chip, None).is_some() && gaps(Some(chip)).is_empty(),
                "{chip:#x}"
            );
        }
    }
    for family in &FAMILIES {
        let controllers = core::iter::once(&family.amcc).chain(&family.ioa);
        for (index, controller) in controllers.enumerate() {
            let mut apertures = controller.apertures.to_vec();
            apertures.sort_unstable();
            apertures.dedup();
            assert_eq!(apertures.len(), controller.apertures.len());
            assert!(!apertures.is_empty());
            let planes = u64::from(controller.plane_count) * u64::from(controller.plane_stride);
            if index == 0 {
                assert!(planes <= u64::from(controller.aperture_size));
                assert!(controller.cache_status.is_some());
            } else {
                assert_eq!((controller.plane_count, planes), (1, 0));
            }
            let first = &controller.groups[0];
            assert!(first.name.ends_with("-ctrr-a") && first.lower_limit.value.is_none());
            for group in controller.groups {
                let registers = [group.lower_limit, group.upper_limit]
                    .into_iter()
                    .chain(group.enable)
                    .chain(group.write_disable)
                    .chain(group.lock);
                for register in registers {
                    let span = controller.plane_stride.max(controller.aperture_size);
                    assert!(register.offset < span, "{:x?}", family.chips);
                }
            }
        }
    }
    assert!(ioa_table(0x8112, None).is_none() && ioa_table(0x8103, None).is_none());
    for chip in [0x8101, 0xdead] {
        assert!(table(chip, None).is_none());
        assert!(ioa_table(chip, None).is_none());
        assert_eq!(gaps(Some(chip)).len(), 1);
    }
    let region = ctrr_a(
        table(0x6000, None).unwrap(),
        0x8_0000_0000,
        0x8_0200_0000,
        0x8_0779_0000,
    )
    .unwrap();
    assert_eq!(
        (region.group.as_str(), region.base, region.bytes),
        ("amcc-ctrr-a", 0x8_0200_0000, 0x579_0000)
    );
}

/// Each T6050 variant's maps are the builder's for its fused MCCs and
/// dies; without a variant the family row is the unbinned Max's.
#[test]
fn t6050_maps_follow_the_fused_mccs_and_dies() {
    use crate::soc_variant::{self, CHIP_ID, Fuses};
    let max = soc_variant::fuses(CHIP_ID, 0x0a).unwrap();
    let fuses = [
        soc_variant::fuses(CHIP_ID, 0x08).unwrap(),
        max,
        Fuses {
            disabled_mccs: 0xff00_0000,
            ..max
        },
        Fuses {
            disabled_mccs: 0xff00,
            ..max
        },
        soc_variant::fuses(CHIP_ID, 0x12).unwrap(),
    ];
    for (fuses, (name, amcc, ioa)) in fuses.into_iter().zip(&T6050_VARIANTS) {
        let variant = soc_variant::decode(fuses).unwrap();
        assert_eq!(variant.name, *name);
        let apertures: Vec<u64> = (0..u64::from(variant.dies))
            .flat_map(|die| {
                (0..8u64)
                    .filter(move |n| variant.mccs >> n & 1 != 0)
                    .map(move |n| (die << 38) + 0x22_2000_0000 + n * 0x200_0000)
            })
            .collect();
        assert_eq!(amcc.apertures, apertures);
        assert_eq!(ioa.apertures.len(), 6 * variant.dies as usize);
        assert_eq!(ioa.apertures[..6], T6050_IOA.apertures[..]);
        assert_eq!(table(CHIP_ID, Some(name)), Some(amcc));
        assert_eq!(ioa_table(CHIP_ID, Some(name)), Some(ioa));
    }
    assert_eq!(table(CHIP_ID, None), Some(&T6050_MAX));
    assert_eq!(table(0x6041, Some("h17s")), table(0x6041, None));
}

#[test]
fn publishes_only_into_the_templates_nodes() -> Result<()> {
    let number = |tree: &DeviceTree, path: &str, name: &str| {
        tree.property(path, name).and_then(|p| p.as_u32())
    };
    // The M4 Max fills all four AMCC groups; its template has no IOA.
    let mut tree = chosen(false)?;
    assert!(publish(&mut tree, table(0x6041, None).unwrap())?);
    assert!(!publish_ioa(&mut tree, ioa_table(0x6041, None).unwrap())?);
    assert!(tree.node(IOA).is_none());
    assert_eq!(number(&tree, AMCC, "aperture-count"), Some(8));
    assert_eq!(number(&tree, AMCC, "cache-status-reg-offset"), Some(0x82c));
    let d = format!("{AMCC}/amcc-ctrr-d");
    assert_eq!(number(&tree, &d, "lower-limit-reg-offset"), Some(0xaac));
    assert_eq!(number(&tree, &d, "lower-limit-reg-value"), Some(0));
    assert_eq!(number(&tree, &d, "write-disable-reg-offset"), Some(0xaec));
    assert_eq!(number(&tree, &d, "lock-reg-offset"), Some(0xadc));
    // The M2 Pro describes IOA-B and -C, which its template lacks.
    let mut tree = chosen(true)?;
    assert!(publish(&mut tree, table(0x6020, None).unwrap())?);
    assert!(publish_ioa(&mut tree, ioa_table(0x6020, None).unwrap())?);
    let a = format!("{IOA}/ioa-ctrr-a");
    assert_eq!(number(&tree, &a, "upper-limit-reg-mask"), Some(0x3fff_ffff));
    assert_eq!(number(&tree, &a, "write-disable-reg-offset"), Some(0x14));
    assert_eq!(number(&tree, &a, "lock-reg-offset"), Some(0x4));
    assert_eq!(tree.node(IOA).unwrap().children.len(), 1);
    let b = format!("{AMCC}/amcc-ctrr-b");
    assert_eq!(tree.node(&b).unwrap().properties.len(), 1);
    // Without a template node nothing is published.
    let mut bare = DeviceTree {
        root: Node::named("device-tree")?,
    };
    bare.ensure_child("/", "chosen")?;
    assert!(!publish(&mut bare, &T8112)?);
    assert!(bare.node("/chosen/lock-regs").is_none());
    Ok(())
}

#[test]
fn the_core_handoff_follows_sptms_region_derivation() {
    // The layout of the 26A434 J773g qemu-sptm trace.
    let layout = [
        ("TXM-ro", 0x100_0193_8000, 0x100_0196_8000),
        ("TXM-rx", 0x100_0196_8000, 0x100_019b_c000),
        ("TXM-bx", 0x100_019b_c000, 0x100_019c_4000),
        ("BootKC-rx", 0x100_019c_c000, 0x100_0548_0000),
        ("BootKC-bx", 0x100_0548_0000, 0x100_054a_4000),
        ("BootKC-rs", 0x100_06f0_0000, 0x100_06fb_8000),
        ("DeviceTree", 0x100_06fb_8000, 0x100_0700_0000),
        ("SPTM-rx", 0x100_070a_4000, 0x100_0710_c000),
        (CL4_DUMMY_PAGE, 0x100_0945_0000, 0x100_0945_4000),
    ];
    let region = |name: &str| {
        layout
            .iter()
            .find(|(n, ..)| *n == name)
            .map(|&(_, start, end)| start..end)
    };
    let handoff = core_handoff(region, true, 0).unwrap();
    let bounds = |wanted| {
        handoff
            .locked
            .iter()
            .find(|locked| locked.region == wanted)
            .map(|locked| (locked.first, locked.last))
    };
    assert_eq!(
        bounds(LockRegion::CtrrC),
        Some((0x100_06fb_8000, 0x100_0710_bfff))
    );
    assert_eq!(
        bounds(LockRegion::CtrrD),
        Some((0x100_0193_8000, 0x100_06fb_7fff))
    );
    assert_eq!(
        bounds(LockRegion::CtxrA),
        Some((0x100_070a_4000, 0x100_0710_bfff))
    );
    assert_eq!(
        bounds(LockRegion::CtxrB),
        Some((0x100_0945_0000, 0x100_0945_3fff))
    );
    assert_eq!(
        bounds(LockRegion::CtxrC),
        Some((0x100_0196_8000, 0x100_019c_3fff))
    );
    assert_eq!(
        bounds(LockRegion::CtxrD),
        Some((0x100_019c_c000, 0x100_054a_3fff))
    );
    assert!(handoff.legacy_locked);
    // Kernel CTRR off leaves CTRR-D unlocked; a missing region refuses.
    assert_eq!(core_handoff(region, false, 0).unwrap().locked.len(), 5);
    assert!(core_handoff(|name| region(name).filter(|_| name != "TXM-rx"), true, 0).is_err());
    let page = cl4_dummy_page();
    assert_eq!(page.len(), CL4_DUMMY_PAGE_BYTES);
    assert_eq!(page[..4], WFI.to_le_bytes());
}

#[test]
fn ctrr_a_takes_whole_pages_above_dram() {
    let base = 0x8_0000_0000;
    let region = ctrr_a(&T8112, base, 0x8_0200_0000, 0x8_0779_0000).unwrap();
    assert_eq!((region.base, region.bytes), (0x8_0200_0000, 0x579_0000));
    assert!(ctrr_a(&T8112, base, 0x8_0200_1000, 0x8_0779_0000).is_err());
    assert!(ctrr_a(&T8112, base, 0x7_ffff_c000, 0x8_0000_4000).is_err());
    assert!(ctrr_a(&T8112, base, 0x8_0200_0000, 0x8_0200_0000).is_err());
}
