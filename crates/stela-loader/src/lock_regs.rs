//! iBoot's memory-controller lock registers: `/chosen/lock-regs`, where SPTM
//! finds the AMCC's register map, and the CTRR-A region iBoot programs into
//! it before SPTM starts.
//!
//! The map is iBoot's own. 26A434 `iBoot.j473.RELEASE` builds a `harr`
//! table (`0x377bc`) that `0x126f34` turns into the `amcc` node: the
//! aperture count, size and physical addresses, the plane count and stride,
//! the cache-status register, and five registers per lock group, each an
//! offset into a plane, a mask and, for the bit registers, the value that
//! means set. Of the template's four groups iBoot fills only `amcc-ctrr-a`;
//! the others stay empty, as it leaves them.
//!
//! T6000 is independently recovered from 26A434 `iBoot.j314s` (decoded
//! SHA256 `20dfa3a5e6d4e4b2844c7558e6d4f8ab74397d11eae63312f00a559cf9612b03`).
//! Its builder at file `0x3848c` and publisher `0x1376d4` describe four AMCC
//! apertures, four planes each, and four single-plane IOA apertures. The MCC
//! count selector `0x514ac` indexes `0x1dfff0` by chip ID minus `0x6000`;
//! IOA selector `0x38220` indexes `0x1d8f24`, with addresses at `0x1d3110`.
//! The AMCC cache-status offset is `0x10000c`, not inside the first plane
//! stride. It also publishes master-lock `(0x1c00, 0x1f, 0)`. IOA publishes
//! broadcast `(0, 1, 1)`; neither is a cache-status substitute. CTRR-A has no
//! write-disable register on either controller, and IOA has no lock register.
//! The builder also contains IOA-B, but the original J314s DeviceTree has no
//! such node: publisher `0x137aa4` uses existing-child lookup `0xe0840`, then
//! skips a missing child at `0x137b28`. Only IOA-A is published here.
//!
//! Original T6000 SPTM (decoded SHA256
//! `dda6be8f5aa266b2a9505269d7152e870e2b610114185a2f60a587782d2af082`)
//! `0xfffffff0270d64f8` selects AMCC and IOA separately. Register reader
//! `0xfffffff0270d6d20` allows absent enable/write-disable/IOA lock fields;
//! `0xfffffff0270d75a0` requires matching limits across apertures/planes.
//! Its CTRR selector requests cache-status only for AMCC and does not consume
//! master-lock or broadcast. Their publication alone qualifies no MMIO effects.
//!
//! SPTM's register reader requires lower/upper limits and AMCC's lock, while
//! enable/write-disable and IOA's lock may be absent. Limits must agree across
//! every aperture and plane; the upper page is inclusive. AMCC limits count
//! pages from the DRAM base. IOA limits count absolute physical pages, which
//! T6000 SPTM `0xfffffff0270d7748..0xfffffff0270d777c` normalizes by subtracting
//! `dram_base >> page-size-shift`. `ctrr_lock_boot` checks the described cache
//! status and present write-disable/lock fields, then writes the present enable,
//! write-disable and lock fields in order, with the cores' matching CTRR range.
//!
//! iBoot's choice of region: the CTRR-A region covers the read-only and
//! executable images, which SPTM requires in one physical run ahead of every
//! writable one (m1n1 `load_macos_sptm`: "Required by SPTM in this order").
//! Public XNU 11215 `arm_init_sptm.c` keeps the AuxKC read-only region
//! "right below the device tree/trustcache so that it can be covered by
//! CTRR". The bundle programs the run from its first region through
//! `SPTM-rx`.
//!
//! On the M4 and later iBoot also locks the cores' per-cluster CTRR-C/D and
//! CTXR-A..D copies, and CTRR-A/B's controls, before SPTM starts
//! ([`core_handoff`]; the contract is in `stela_runtime::machine::ctrr`).
//! M5 iBoot (`iBoot.j813`) writes each region's per-core and per-cluster
//! copies together (`0x31588`, `0x316e0`) and locks them (`0x31658`,
//! `0x317b0`); SPTM 26A434 derives the same six regions from
//! `/chosen/memory-map` and panics unless the per-cluster copies hold them.
//! Without a CL4 image iBoot allocates a 16 KiB page, fills it with `wfi`
//! and publishes it as `CL4-dummypage` (`iBoot.j813` `0x29600..0x29668`),
//! which SPTM then requires as CTXR-B's region.
use crate::apple_device_tree::DeviceTree;
use alloc::{format, string::String, vec::Vec};
use anyhow::{Context, Result, ensure};
use core::ops::Range;
use stela_runtime::machine::ctrr::{Handoff, Locked, Region};

pub const AMCC: &str = "/chosen/lock-regs/amcc";
pub const IOA: &str = "/chosen/lock-regs/ioa";

/// One register of a plane: its offset, the bits that hold it and, for a
/// bit register, the masked value that means set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register {
    pub offset: u32,
    pub mask: u32,
    pub value: Option<u32>,
}

/// A lock group: a region the memory controller protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockGroup {
    pub name: &'static str,
    /// The limits count pages of `1 << page_size_shift` bytes.
    pub page_size_shift: u32,
    pub lower_limit: Register,
    pub upper_limit: Register,
    pub enable: Option<Register>,
    pub write_disable: Option<Register>,
    pub lock: Option<Register>,
}

/// A memory controller as its `/chosen/lock-regs` node describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryController {
    pub apertures: &'static [u64],
    pub aperture_size: u32,
    pub plane_count: u32,
    pub plane_stride: u32,
    /// Reads `value` under `mask` on every plane while the cache is
    /// disabled.
    pub cache_status: Option<Register>,
    /// Optional original control descriptors; their masked values are literal,
    /// including master-lock's zero, not an assumed active-high bit convention.
    pub master_lock: Option<Register>,
    pub broadcast: Option<Register>,
    pub groups: &'static [LockGroup],
}

const fn limit(offset: u32) -> Register {
    Register {
        offset,
        mask: u32::MAX,
        value: None,
    }
}

const fn bit(offset: u32) -> Register {
    Register {
        offset,
        mask: 1,
        value: Some(1),
    }
}

/// The empty groups iBoot leaves in the template tree.
const EMPTY_GROUPS: [&str; 3] = ["amcc-ctrr-b", "amcc-ctrr-c", "amcc-ctrr-d"];

const T8112: MemoryController = MemoryController {
    apertures: &[0x2_0000_0000],
    aperture_size: 0xf4_0000,
    plane_count: 4,
    plane_stride: 0x4_0000,
    cache_status: Some(bit(0x424)),
    master_lock: None,
    broadcast: None,
    groups: &[LockGroup {
        name: "amcc-ctrr-a",
        page_size_shift: 14,
        lower_limit: limit(0x680),
        upper_limit: limit(0x684),
        enable: Some(bit(0x688)),
        write_disable: Some(bit(0x7f0)),
        lock: Some(bit(0x68c)),
    }],
};

// J314s builder 0x385e4..0x38a6c: one die, four MCCs (not T6001/2's
// eight), each a 2 MiB lock aperture in its 16 MiB MCC register window.
const T6000: MemoryController = MemoryController {
    apertures: &[0x2_0000_0000, 0x2_0100_0000, 0x2_0200_0000, 0x2_0300_0000],
    aperture_size: 0x20_0000,
    plane_count: 4,
    plane_stride: 0x4_0000,
    cache_status: Some(bit(0x10_000c)),
    master_lock: Some(Register {
        offset: 0x1c00,
        mask: 0x1f,
        value: Some(0),
    }),
    broadcast: None,
    groups: &[LockGroup {
        name: "amcc-ctrr-a",
        page_size_shift: 14,
        lower_limit: limit(0x680),
        upper_limit: limit(0x684),
        enable: Some(bit(0x688)),
        write_disable: None,
        lock: Some(bit(0x68c)),
    }],
};

// J314s builder 0x38aa4..0x38d10. A single plane needs no stride. The
// original template exposes only IOA-A; no fabricated lock/cache register.
const T6000_IOA: MemoryController = MemoryController {
    apertures: &[0x2_8200_0000, 0x3_0400_0000, 0x3_8300_0000, 0x4_0200_0000],
    aperture_size: 0x4000,
    plane_count: 1,
    plane_stride: 0,
    cache_status: None,
    master_lock: None,
    broadcast: Some(bit(0)),
    groups: &[LockGroup {
        name: "ioa-ctrr-a",
        page_size_shift: 14,
        lower_limit: limit(0x220),
        upper_limit: limit(0x224),
        enable: Some(bit(0x228)),
        write_disable: None,
        lock: None,
    }],
};

/// iBoot's AMCC map for the SoC with `chip_id`; `None` for a SoC whose
/// iBoot has not been read.
pub fn table(chip_id: u32) -> Option<&'static MemoryController> {
    match chip_id {
        0x6000 => Some(&T6000),
        0x8112 => Some(&T8112),
        _ => None,
    }
}

/// The independently qualified IOA companion; absence does not reuse AMCC.
pub fn ioa_table(chip_id: u32) -> Option<&'static MemoryController> {
    match chip_id {
        0x6000 => Some(&T6000_IOA),
        _ => None,
    }
}

fn u32_value(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn set_register(tree: &mut DeviceTree, path: &str, name: &str, register: Register) -> Result<()> {
    tree.set_property(
        path,
        &format!("{name}-reg-offset"),
        u32_value(register.offset),
    )?;
    tree.set_property(path, &format!("{name}-reg-mask"), u32_value(register.mask))?;
    if let Some(value) = register.value {
        tree.set_property(path, &format!("{name}-reg-value"), u32_value(value))?;
    } else {
        tree.node_mut(path)
            .context("lock-register node disappeared")?
            .remove_property(&format!("{name}-reg-value"));
    }
    Ok(())
}

fn set_optional_register(
    tree: &mut DeviceTree,
    path: &str,
    name: &str,
    register: Option<Register>,
) -> Result<()> {
    if let Some(register) = register {
        return set_register(tree, path, name, register);
    }
    let node = tree
        .node_mut(path)
        .context("lock-register node disappeared")?;
    for suffix in ["offset", "mask", "value"] {
        node.remove_property(&format!("{name}-reg-{suffix}"));
    }
    Ok(())
}

/// Writes the map into `/chosen/lock-regs/amcc` and its group nodes, as
/// iBoot does.
pub fn publish(tree: &mut DeviceTree, controller: &MemoryController) -> Result<()> {
    publish_controller(tree, AMCC, "amcc", controller, &EMPTY_GROUPS)
}

/// Publish the independently described IOA companion, when `ioa_table` provides
/// one. It has no cache-status or lock property on T6000.
pub fn publish_ioa(tree: &mut DeviceTree, controller: &MemoryController) -> Result<()> {
    publish_controller(tree, IOA, "ioa", controller, &[])
}

fn publish_controller(
    tree: &mut DeviceTree,
    path: &str,
    name: &str,
    controller: &MemoryController,
    empty_groups: &[&str],
) -> Result<()> {
    tree.ensure_child("/chosen", "lock-regs")?;
    tree.ensure_child("/chosen/lock-regs", name)?;
    let count = u32::try_from(controller.apertures.len())?;
    tree.set_property(path, "aperture-count", u32_value(count))?;
    tree.set_property(path, "aperture-size", u32_value(controller.aperture_size))?;
    let addresses = controller
        .apertures
        .iter()
        .flat_map(|address| address.to_le_bytes())
        .collect();
    tree.set_property(path, "aperture-phys-addr", addresses)?;
    tree.set_property(path, "plane-count", u32_value(controller.plane_count))?;
    tree.set_property(path, "plane-stride", u32_value(controller.plane_stride))?;
    for (name, register) in [
        ("cache-status", controller.cache_status),
        ("master-lock", controller.master_lock),
        ("broadcast", controller.broadcast),
    ] {
        set_optional_register(tree, path, name, register)?;
    }
    for group in controller.groups {
        tree.ensure_child(path, group.name)?;
        let path = format!("{path}/{}", group.name);
        tree.set_property(&path, "page-size-shift", u32_value(group.page_size_shift))?;
        for (name, register) in [
            ("lower-limit", Some(group.lower_limit)),
            ("upper-limit", Some(group.upper_limit)),
            ("enable", group.enable),
            ("write-disable", group.write_disable),
            ("lock", group.lock),
        ] {
            set_optional_register(tree, &path, name, register)?;
        }
    }
    for name in empty_groups {
        tree.ensure_child(path, name)?;
    }
    Ok(())
}

/// A physical range iBoot programs into a lock group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Programmed {
    pub group: &'static str,
    pub base: u64,
    pub bytes: u64,
}

/// The CTRR-A region iBoot programs: `[start, end)`, which must be whole
/// pages of the group above `dram_base`.
pub fn ctrr_a(
    controller: &MemoryController,
    dram_base: u64,
    start: u64,
    end: u64,
) -> Result<Programmed> {
    let group = controller
        .groups
        .iter()
        .find(|group| group.name == "amcc-ctrr-a")
        .context("the AMCC map has no amcc-ctrr-a")?;
    let page = 1u64 << group.page_size_shift;
    ensure!(
        dram_base <= start
            && start < end
            && start.is_multiple_of(page)
            && end.is_multiple_of(page)
            && (end - dram_base) >> group.page_size_shift <= u64::from(group.upper_limit.mask),
        "CTRR-A region {start:#x}..{end:#x} is not whole {page:#x}-byte pages above {dram_base:#x}"
    );
    Ok(Programmed {
        group: group.name,
        base: start,
        bytes: end - start,
    })
}

/// The page iBoot publishes in place of an absent CL4 image.
pub const CL4_DUMMY_PAGE: &str = "CL4-dummypage";
pub const CL4_DUMMY_PAGE_BYTES: usize = 0x4000;
/// `wfi`, the word iBoot fills it with.
const WFI: u32 = 0xd503_207f;

/// The dummy page's contents.
pub fn cl4_dummy_page() -> Vec<u8> {
    WFI.to_le_bytes()
        .repeat(CL4_DUMMY_PAGE_BYTES / size_of::<u32>())
}

/// What iBoot leaves in the core lock registers on the M4 and later, from
/// the placed regions (`region` gives one's `[start, end)`): each region
/// SPTM 26A434 derives (`0x...bebec..0x...bed5c` in the T8132 build), locked
/// into the per-cluster copies, CTRR-D only when `kernel_ctrr`
/// (`/chosen kernel-ctrr-to-be-enabled` is not a present 0), and CTRR-A/B's
/// controls locked, with `tag_offset` (`stela_runtime::machine::tag_storage`).
pub fn core_handoff(
    region: impl Fn(&str) -> Option<Range<u64>>,
    kernel_ctrr: bool,
    tag_offset: u64,
) -> Result<Handoff> {
    let either = |name: &'static str, fallback: &'static str| {
        if region(name).is_some() {
            name
        } else {
            fallback
        }
    };
    let span = |first: &str, last: &str| -> Result<(u64, u64)> {
        let start = region(first)
            .with_context(|| format!("no region {first}"))?
            .start;
        let end = region(last)
            .with_context(|| format!("no region {last}"))?
            .end;
        ensure!(start < end, "{first}..{last} is empty");
        Ok((start, end - 1))
    };
    let secure_kernel = either("CL4-rx", CL4_DUMMY_PAGE);
    let kernel_text = either("AuxKC-rx", "BootKC-rx");
    let mut spans = alloc::vec![
        (
            Region::CtrrC,
            span(either("CL4-rx", "DeviceTree"), "SPTM-rx")?
        ),
        (Region::CtxrA, span("SPTM-rx", "SPTM-rx")?),
        (Region::CtxrB, span(secure_kernel, secure_kernel)?),
        (Region::CtxrC, span("TXM-rx", "TXM-bx")?),
        (Region::CtxrD, span(kernel_text, "BootKC-bx")?),
    ];
    if kernel_ctrr {
        spans.push((Region::CtrrD, span("TXM-ro", "BootKC-rs")?));
    }
    Ok(Handoff {
        locked: spans
            .into_iter()
            .map(|(region, (first, last))| Locked {
                region,
                first,
                last,
            })
            .collect(),
        legacy_locked: true,
        tag_offset,
    })
}

/// What the bundle leaves out of iBoot's lock-register setup.
pub fn gaps(chip_id: Option<u32>) -> Vec<String> {
    match chip_id.and_then(table) {
        Some(_) => Vec::new(),
        None => alloc::vec![format!(
            "{AMCC}: no iBoot AMCC map for this SoC; SPTM's CTRR lockdown cannot find it"
        )],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;

    #[test]
    fn publishes_the_amcc_map_sptm_reads() -> Result<()> {
        let mut tree = DeviceTree {
            root: Node::named("device-tree")?,
        };
        tree.ensure_child("/", "chosen")?;
        publish(&mut tree, &T8112)?;
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
        let mut tree = DeviceTree {
            root: Node::named("device-tree")?,
        };
        tree.ensure_child("/", "chosen")?;
        let amcc = table(0x6000).unwrap();
        let ioa = ioa_table(0x6000).unwrap();
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
            (AMCC, "cache-status-reg-offset", 0x10_000c),
            (AMCC, "cache-status-reg-mask", 1),
            (AMCC, "cache-status-reg-value", 1),
            (AMCC, "master-lock-reg-offset", 0x1c00),
            (AMCC, "master-lock-reg-mask", 0x1f),
            (AMCC, "master-lock-reg-value", 0),
            (IOA, "aperture-size", 0x4000),
            (IOA, "plane-count", 1),
            (IOA, "plane-stride", 0),
            (IOA, "broadcast-reg-offset", 0),
            (IOA, "broadcast-reg-mask", 1),
            (IOA, "broadcast-reg-value", 1),
        ] {
            assert_eq!(number(path, name), Some(expected), "{path}/{name}");
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
        for name in EMPTY_GROUPS {
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
    fn source_qualification_does_not_alias_other_chips_or_ioa() {
        assert!(ioa_table(0x8112).is_none());
        for chip in [0x6001, 0x6002, 0x6020, 0x8103, 0xdead] {
            assert!(table(chip).is_none());
            assert!(ioa_table(chip).is_none());
            assert_eq!(gaps(Some(chip)).len(), 1);
        }
        assert!(gaps(Some(0x6000)).is_empty());
        let region = ctrr_a(
            table(0x6000).unwrap(),
            0x8_0000_0000,
            0x8_0200_0000,
            0x8_0779_0000,
        )
        .unwrap();
        assert_eq!(
            (region.group, region.base, region.bytes),
            ("amcc-ctrr-a", 0x8_0200_0000, 0x579_0000)
        );
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
            bounds(Region::CtrrC),
            Some((0x100_06fb_8000, 0x100_0710_bfff))
        );
        assert_eq!(
            bounds(Region::CtrrD),
            Some((0x100_0193_8000, 0x100_06fb_7fff))
        );
        assert_eq!(
            bounds(Region::CtxrA),
            Some((0x100_070a_4000, 0x100_0710_bfff))
        );
        assert_eq!(
            bounds(Region::CtxrB),
            Some((0x100_0945_0000, 0x100_0945_3fff))
        );
        assert_eq!(
            bounds(Region::CtxrC),
            Some((0x100_0196_8000, 0x100_019c_3fff))
        );
        assert_eq!(
            bounds(Region::CtxrD),
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
}
