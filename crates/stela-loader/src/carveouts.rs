//! iBoot's DRAM carveouts: memory iBoot reserves for coprocessors and the
//! monitors before SPTM starts. Each carveout is published in
//! `/chosen/carveout-memory-map` as `region-id-<id>`, a u64 base and a u64
//! size, and stays outside the managed range `boot_args` describes
//! (`physBase` to `physBase + memSize`): SPTM's
//! `iommu_bootstrap_register_io_range` refuses a managed page, an unaligned
//! or empty range, or one of 64K pages or more.
//!
//! The table is iBoot's own: 26A434 `iBoot.j473.RELEASE` holds 64-byte
//! records at file offset `0x1d6288` (base `~0` until placed, the size at
//! +0x10, the region ID at +0x18), of which the fixed-size ones are listed
//! here. iBoot sizes the rest at run time (size `~0`) or leaves them empty;
//! those stay absent. iBoot's placement policy is not established, so Stela
//! places carveouts back to back from the DRAM base and starts the managed
//! range at the next 32 MiB boundary, the block size of XNU's physical
//! aperture.
//!
//! The GPU's UAT regions come from four of them. iBoot's sgx setup (26A434
//! iBoot `0xd9328`) looks up regions 8, 0x34, 0xd9 and 0x38 and writes their
//! bases and sizes to `/arm-io/sgx`, which SPTM's `uat_bootstrap_parse_dt`
//! requires: the TTBAT (`gpu-region`), the ASC carveout
//! (`gfx-shared-region`), one page of shared TTBR1 level-2 table
//! (`gfx-shared-l2-region`) and the firmware handoff (`gfx-handoff`). SPTM
//! builds the TTBR1 root and the handoff header itself. iBoot also writes the
//! AGX firmware's loaded data segments (`gfx-data*`), `gptbat-ready`,
//! `ttbat-phys-addr-base` and `rtkit-private-vm-region-*`, which need the
//! firmware loaded and the GPU's MMU programmed, so they stay absent.
use crate::apple_device_tree::DeviceTree;
use crate::kernel_collection::PAGE_BYTES;
use alloc::{format, string::String, vec::Vec};
use anyhow::{Context, Result};

pub const MEMORY_MAP: &str = "/chosen/carveout-memory-map";
const SGX: &str = "/arm-io/sgx";
/// XNU maps its physical aperture in 32 MiB blocks (m1n1 `_write_boot_args`
/// offsets `virtBase` by `physBase` modulo this).
pub const MANAGED_ALIGNMENT: u64 = 32 << 20;

/// One fixed-size entry of iBoot's carveout table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Carveout {
    pub id: u16,
    pub bytes: u64,
}

/// A carveout at its guest physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Placed {
    pub id: u16,
    pub base: u64,
    pub bytes: u64,
}

const fn carveout(id: u16, bytes: u64) -> Carveout {
    Carveout { id, bytes }
}

/// The T8112 table in iBoot's order.
const T8112: [Carveout; 18] = [
    carveout(0x51, 0x40000),
    carveout(0x07, 0x4000),
    carveout(0x08, 0x4000),
    carveout(0x34, 0x40000),
    carveout(0xd9, 0x4000),
    carveout(0x38, 0x4000),
    carveout(0x37, 0x4000),
    carveout(0x5a, 0x4000),
    carveout(0x4c, 0xc000),
    carveout(0x10, 0x40000),
    carveout(0x12, 0x40000),
    carveout(0x11, 0xc000),
    carveout(0x44, 0x40000),
    carveout(0x46, 0x40000),
    carveout(0x45, 0xc000),
    carveout(0x50, 0x18000),
    carveout(0x60, 0x40000),
    carveout(0x61, 0x34000),
];

/// The regions iBoot names in `/arm-io/sgx`, as `<prefix>-base` and
/// `<prefix>-size`.
const SGX_REGIONS: [(u16, &str); 4] = [
    (0x08, "gpu-region"),
    (0x34, "gfx-shared-region"),
    (0xd9, "gfx-shared-l2-region"),
    (0x38, "gfx-handoff"),
];

/// iBoot's fixed-size carveouts for the SoC with `chip_id`; `None` for a SoC
/// whose iBoot has not been read.
pub fn table(chip_id: u32) -> Option<&'static [Carveout]> {
    match chip_id {
        0x8112 => Some(&T8112),
        _ => None,
    }
}

/// The carveouts placed back to back from `dram_base`.
pub fn place(table: &[Carveout], dram_base: u64) -> Vec<Placed> {
    let mut cursor = dram_base;
    table
        .iter()
        .map(|carveout| {
            let placed = Placed {
                id: carveout.id,
                base: cursor,
                bytes: carveout.bytes,
            };
            cursor += carveout.bytes.next_multiple_of(PAGE_BYTES);
            placed
        })
        .collect()
}

/// The first address the managed range may start at: past every carveout,
/// on a [`MANAGED_ALIGNMENT`] boundary.
pub fn managed_floor(placed: &[Placed], dram_base: u64) -> u64 {
    placed
        .iter()
        .map(|carveout| carveout.base + carveout.bytes.next_multiple_of(PAGE_BYTES))
        .max()
        .unwrap_or(dram_base)
        .next_multiple_of(MANAGED_ALIGNMENT)
}

fn range(base: u64, bytes: u64) -> Vec<u8> {
    [base.to_le_bytes(), bytes.to_le_bytes()].concat()
}

/// Publishes the carveouts as iBoot does: every one in
/// `/chosen/carveout-memory-map`, and the GPU's UAT regions in
/// `/arm-io/sgx` when the board has a GPU.
pub fn publish(tree: &mut DeviceTree, placed: &[Placed]) -> Result<()> {
    if placed.is_empty() {
        return Ok(());
    }
    tree.ensure_child("/chosen", "carveout-memory-map")?;
    let map = tree.node_mut(MEMORY_MAP).context("carveout-memory-map")?;
    for carveout in placed {
        map.set_property(
            &format!("region-id-{}", carveout.id),
            range(carveout.base, carveout.bytes),
        )?;
    }
    if tree.node(SGX).is_none() {
        return Ok(());
    }
    for (id, prefix) in SGX_REGIONS {
        let carveout = placed
            .iter()
            .find(|carveout| carveout.id == id)
            .with_context(|| format!("{SGX} needs carveout region {id:#x}"))?;
        tree.set_property(
            SGX,
            &format!("{prefix}-base"),
            carveout.base.to_le_bytes().to_vec(),
        )?;
        tree.set_property(
            SGX,
            &format!("{prefix}-size"),
            carveout.bytes.to_le_bytes().to_vec(),
        )?;
    }
    Ok(())
}

/// What the bundle leaves out of iBoot's carveout setup.
pub fn gaps(tree: &DeviceTree, chip_id: Option<u32>) -> Vec<String> {
    let mut gaps = Vec::new();
    match chip_id.and_then(table) {
        Some(_) => gaps.push(format!(
            "{MEMORY_MAP}: the carveouts iBoot sizes at run time are absent"
        )),
        None => gaps.push(format!(
            "{MEMORY_MAP}: no iBoot carveout table for this SoC; the machine declares no carveouts"
        )),
    }
    if tree.node(SGX).is_some() {
        gaps.push(format!(
            "{SGX}: AGX firmware is not loaded, so gfx-data*, gptbat-ready, ttbat-phys-addr-base and rtkit-private-vm-region-* are absent"
        ));
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carveouts_pack_from_the_dram_base_and_the_managed_range_starts_on_a_block() {
        let placed = place(&T8112, 0x8_0000_0000);
        assert_eq!(placed[0].base, 0x8_0000_0000);
        assert_eq!(placed[1].base, 0x8_0004_0000);
        assert!(placed.iter().all(|c| c.base % PAGE_BYTES == 0));
        let end = placed.last().map(|c| c.base + c.bytes).unwrap();
        assert!(end <= managed_floor(&placed, 0x8_0000_0000));
        assert_eq!(managed_floor(&placed, 0x8_0000_0000), 0x8_0200_0000);
        assert_eq!(managed_floor(&[], 0x8_0000_0000), 0x8_0000_0000);
    }

    #[test]
    fn every_region_meets_sptm_io_range_rules_and_sgx_names_one_page_l2() {
        for c in T8112 {
            assert!(c.bytes > 0 && c.bytes % PAGE_BYTES == 0);
            assert!(c.bytes / PAGE_BYTES < 0x10000);
        }
        let l2 = T8112.iter().find(|c| c.id == 0xd9).unwrap();
        assert_eq!(l2.bytes, PAGE_BYTES);
        for (id, _) in SGX_REGIONS {
            assert!(T8112.iter().any(|c| c.id == id));
        }
    }

    #[test]
    fn publishes_region_ids_and_the_gpu_uat_regions() -> Result<()> {
        let mut tree = DeviceTree {
            root: crate::apple_device_tree::Node::named("device-tree")?,
        };
        tree.ensure_child("/", "chosen")?;
        tree.ensure_child("/chosen", "carveout-memory-map")?;
        tree.ensure_child("/", "arm-io")?;
        tree.ensure_child("/arm-io", "sgx")?;
        let placed = place(&T8112, 0x8_0000_0000);
        publish(&mut tree, &placed)?;
        let handoff = placed.iter().find(|c| c.id == 0x38).unwrap();
        assert_eq!(
            tree.property(MEMORY_MAP, "region-id-56").unwrap().value,
            range(handoff.base, 0x4000)
        );
        assert_eq!(
            tree.property(SGX, "gfx-handoff-base").unwrap().as_u64(),
            Some(handoff.base)
        );
        assert_eq!(
            tree.property(SGX, "gfx-shared-l2-region-size")
                .unwrap()
                .as_u64(),
            Some(0x4000)
        );
        Ok(())
    }
}
