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
//! SPTM 26A434 `ctrr_dt_get_lock_group` requires every property listed here
//! but the enable and write-disable registers. `ctrr_map_lock_group` reads
//! each plane's lower and upper limits, which must agree across planes, as
//! the CTRR-A region in pages of `1 << page-size-shift` bytes from the DRAM
//! base, upper inclusive. `ctrr_lock_boot` asserts every plane's cache is
//! disabled and the group neither write-disabled nor locked, then sets
//! enable, write-disable and lock in that order and programs the cores'
//! CTRR registers with the same region.
//!
//! iBoot's choice of region: the CTRR-A region covers the read-only and
//! executable images, which SPTM requires in one physical run ahead of every
//! writable one (m1n1 `load_macos_sptm`: "Required by SPTM in this order").
//! Public XNU 11215 `arm_init_sptm.c` keeps the AuxKC read-only region
//! "right below the device tree/trustcache so that it can be covered by
//! CTRR". The bundle programs the run from its first region through
//! `SPTM-rx`.
use crate::apple_device_tree::DeviceTree;
use alloc::{format, string::String, vec::Vec};
use anyhow::{Context, Result, ensure};

pub const AMCC: &str = "/chosen/lock-regs/amcc";

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
    pub enable: Register,
    pub write_disable: Register,
    pub lock: Register,
}

/// The AMCC as `/chosen/lock-regs/amcc` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryController {
    pub apertures: &'static [u64],
    pub aperture_size: u32,
    pub plane_count: u32,
    pub plane_stride: u32,
    /// Reads `value` under `mask` on every plane while the cache is
    /// disabled.
    pub cache_status: Register,
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
    cache_status: bit(0x424),
    groups: &[LockGroup {
        name: "amcc-ctrr-a",
        page_size_shift: 14,
        lower_limit: limit(0x680),
        upper_limit: limit(0x684),
        enable: bit(0x688),
        write_disable: bit(0x7f0),
        lock: bit(0x68c),
    }],
};

/// iBoot's AMCC map for the SoC with `chip_id`; `None` for a SoC whose
/// iBoot has not been read.
pub fn table(chip_id: u32) -> Option<&'static MemoryController> {
    match chip_id {
        0x8112 => Some(&T8112),
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
    }
    Ok(())
}

/// Writes the map into `/chosen/lock-regs/amcc` and its group nodes, as
/// iBoot does.
pub fn publish(tree: &mut DeviceTree, controller: &MemoryController) -> Result<()> {
    tree.ensure_child("/chosen", "lock-regs")?;
    tree.ensure_child("/chosen/lock-regs", "amcc")?;
    let count = u32::try_from(controller.apertures.len())?;
    tree.set_property(AMCC, "aperture-count", u32_value(count))?;
    tree.set_property(AMCC, "aperture-size", u32_value(controller.aperture_size))?;
    let addresses = controller
        .apertures
        .iter()
        .flat_map(|address| address.to_le_bytes())
        .collect();
    tree.set_property(AMCC, "aperture-phys-addr", addresses)?;
    tree.set_property(AMCC, "plane-count", u32_value(controller.plane_count))?;
    tree.set_property(AMCC, "plane-stride", u32_value(controller.plane_stride))?;
    set_register(tree, AMCC, "cache-status", controller.cache_status)?;
    for group in controller.groups {
        tree.ensure_child(AMCC, group.name)?;
        let path = format!("{AMCC}/{}", group.name);
        tree.set_property(&path, "page-size-shift", u32_value(group.page_size_shift))?;
        for (name, register) in [
            ("lower-limit", group.lower_limit),
            ("upper-limit", group.upper_limit),
            ("enable", group.enable),
            ("write-disable", group.write_disable),
            ("lock", group.lock),
        ] {
            set_register(tree, &path, name, register)?;
        }
    }
    for name in EMPTY_GROUPS {
        tree.ensure_child(AMCC, name)?;
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
    fn ctrr_a_takes_whole_pages_above_dram() {
        let base = 0x8_0000_0000;
        let region = ctrr_a(&T8112, base, 0x8_0200_0000, 0x8_0779_0000).unwrap();
        assert_eq!((region.base, region.bytes), (0x8_0200_0000, 0x579_0000));
        assert!(ctrr_a(&T8112, base, 0x8_0200_1000, 0x8_0779_0000).is_err());
        assert!(ctrr_a(&T8112, base, 0x7_ffff_c000, 0x8_0000_4000).is_err());
        assert!(ctrr_a(&T8112, base, 0x8_0200_0000, 0x8_0200_0000).is_err());
    }
}
