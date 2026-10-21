//! iBoot's DRAM carveouts: memory iBoot reserves for coprocessors and the
//! monitors before SPTM starts. Each carveout is published in
//! `/chosen/carveout-memory-map` as `region-id-<id>`, a u64 base and a u64
//! size, and stays outside the managed range `boot_args` describes
//! (`physBase` to `physBase + memSize`): SPTM's
//! `iommu_bootstrap_register_io_range` refuses a managed page, an unaligned
//! or empty range, or one of 64K pages or more.
//!
//! The tables come from original 26A434 iBoot: J473 at file offset
//! `0x1d6288`, J314s at `0x1ffce8`. Their records are 64 bytes (base `~0`
//! until placed, size at +0x10, region ID at +0x18). Only source-qualified
//! ordinary fixed-size records are listed here. Run-time sizes, empty entries,
//! special attributes and absolute original ranges stay absent, except the
//! panic region below. iBoot's placement policy
//! is not established, so Stela places carveouts back to back from the DRAM
//! base and starts the managed range at the next 32 MiB boundary, the block
//! size of XNU's physical aperture.
//!
//! The panic region, carveout 98, is XNU's panic buffer, and every SoC with
//! hand-off facts gets it ([`PANIC`]; LLB sizes it alike on every SoC,
//! `machine::soc::PANIC_REGION_BYTES`). iBoot writes it as `/pram reg` (base,
//! size; 26A434 J473 iBoot 0x23028 calling 0x24d70, only when `/pram`
//! exists) and its size as the u32 `/chosen embedded-panic-log-size`
//! (0x24420). 26A434 XNU's `check_for_panic_log` (kernel 0xfffffe000c4d8790,
//! called from `PE_create_console` at 0xfffffe000c52d3ac) needs both: it maps
//! `reg[0]` write-combined for `embedded-panic-log-size` bytes as
//! `gPanicBase` (0xfffffe000ca640b0) and `panic_info` (0xfffffe000ca640b8),
//! and `debug_log_init` puts the panic log 0x331 bytes in, past the panic
//! header. Without them `panic_info` stays NULL and the panic path faults
//! writing the header (`docs/research/iboot-handoff.md#panic-region`).
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
use stela_runtime::machine::soc;

pub const MEMORY_MAP: &str = "/chosen/carveout-memory-map";
const SGX: &str = "/arm-io/sgx";
/// The node whose `reg` names the panic region.
pub const PRAM: &str = "/pram";
/// The `/chosen` u32 that bounds XNU's panic buffer.
pub const PANIC_LOG_SIZE: &str = "embedded-panic-log-size";
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

/// Carveout 98, the panic region, at the size LLB gives it on every SoC.
pub const PANIC: Carveout = carveout(soc::PANIC_REGION_ID, soc::PANIC_REGION_BYTES);

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

/// J314s T6000's ordinary fixed-size records in original table order.
/// 26A434 iBoot SHA-256 20dfa3a5e6d4e4b2844c7558e6d4f8ab74397d11eae63312f00a559cf9612b03,
/// table 0x1ffce8, 112 records of 64 bytes. Only unplaced, nonempty fixed
/// records with upper attributes 0x80000009 are qualified here; special and
/// absolute records require separate ownership. See docs/research/j314s-handoff.md.
const T6000: [Carveout; 21] = [
    carveout(0x51, 0x40000),
    carveout(0x07, 0x4000),
    carveout(0x08, 0x4000),
    carveout(0x34, 0x40000),
    carveout(0xd9, 0x4000),
    carveout(0x38, 0x4000),
    carveout(0x37, 0x4000),
    carveout(0x5a, 0x4000),
    carveout(0x4c, 0xc000),
    carveout(0x50, 0x18000),
    carveout(0x10, 0x20000),
    carveout(0x12, 0x20000),
    carveout(0x11, 0x8000),
    carveout(0x44, 0x4000),
    carveout(0x46, 0x10000),
    carveout(0x45, 0x4000),
    carveout(0x53, 0x4000),
    carveout(0x55, 0x10000),
    carveout(0x54, 0x4000),
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
        0x6000 => Some(&T6000),
        0x8112 => Some(&T8112),
        _ => None,
    }
}

/// The carveouts a bundle places for the SoC with `chip_id`: its fixed-size
/// table when read, then the panic region on every SoC with hand-off facts.
pub fn for_chip(chip_id: u32) -> Vec<Carveout> {
    let fixed = table(chip_id).unwrap_or_default();
    let panic = soc::handoff(chip_id).map(|_| PANIC);
    fixed.iter().copied().chain(panic).collect()
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
/// `/chosen/carveout-memory-map`, the panic region in `/pram reg` (when the
/// template has `/pram`) and `/chosen embedded-panic-log-size`, and the GPU's
/// UAT regions in `/arm-io/sgx` when the board has a GPU.
pub fn publish(tree: &mut DeviceTree, placed: &[Placed]) -> Result<()> {
    if placed.is_empty() {
        return Ok(());
    }
    if let Some(panic) = placed.iter().find(|carveout| carveout.id == PANIC.id) {
        if tree.node(PRAM).is_some() {
            tree.set_property(PRAM, "reg", range(panic.base, panic.bytes))?;
        }
        tree.set_property(
            "/chosen",
            PANIC_LOG_SIZE,
            u32::try_from(panic.bytes)?.to_le_bytes().to_vec(),
        )?;
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
    if chip_id == Some(0x6000) {
        gaps.push(format!(
            "{MEMORY_MAP}: T6000 special-attribute and absolute original carveouts, \
             including region 0x108, have no qualified placement or resource ownership"
        ));
    }
    match chip_id.and_then(table) {
        Some(_) => gaps.push(format!(
            "{MEMORY_MAP}: the carveouts iBoot sizes at run time, other than the panic region, \
             are absent"
        )),
        None => gaps.push(format!(
            "{MEMORY_MAP}: no iBoot carveout table for this SoC; its fixed-size carveouts are \
             absent"
        )),
    }
    if chip_id.and_then(soc::handoff).is_none() {
        gaps.push(format!(
            "{PRAM} reg, /chosen {PANIC_LOG_SIZE}: no hand-off facts for this SoC; the kernel \
             keeps no panic buffer"
        ));
    } else if tree.node(PRAM).is_none() {
        gaps.push(format!(
            "{PRAM} reg: the template has no {PRAM} node; the kernel keeps no panic buffer"
        ));
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
        for table in [&T8112[..], &T6000[..]] {
            for c in table {
                assert!(c.bytes > 0 && c.bytes % PAGE_BYTES == 0);
                assert!(c.bytes / PAGE_BYTES < 0x10000);
            }
            let l2 = table.iter().find(|c| c.id == 0xd9).unwrap();
            assert_eq!(l2.bytes, PAGE_BYTES);
            for (id, _) in SGX_REGIONS {
                assert!(table.iter().any(|c| c.id == id));
            }
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

    #[test]
    fn every_soc_with_handoff_facts_gets_the_panic_region_after_its_table() {
        let t8112 = for_chip(0x8112);
        assert_eq!(&t8112[..T8112.len()], &T8112[..]);
        assert_eq!(t8112[T8112.len()..], [PANIC]);
        assert_eq!(PANIC, carveout(98, 0x18_8000));
        // A SoC without a read table still gets it; an unknown SoC none.
        for chip_id in [0x8103, 0x8122, 0x6041, 0x8152] {
            assert_eq!(for_chip(chip_id), [PANIC]);
        }
        assert!(for_chip(0x6050).is_empty());
        // It meets SPTM's I/O range rules and leaves physBase where it was.
        assert!(PANIC.bytes.is_multiple_of(PAGE_BYTES) && PANIC.bytes / PAGE_BYTES < 0x10000);
        let placed = place(&t8112, 0x8_0000_0000);
        assert_eq!(managed_floor(&placed, 0x8_0000_0000), 0x8_0200_0000);
        let alone = place(&[PANIC], 0x10_0000_0000);
        assert_eq!(managed_floor(&alone, 0x10_0000_0000), 0x10_0200_0000);
    }

    #[test]
    fn t6000_places_and_publishes_reserved_nonoverlapping_regions() -> Result<()> {
        let dram = 0x100_0000_0000;
        let table = for_chip(0x6000);
        assert_eq!(table.last(), Some(&PANIC));
        let placed = place(&table, dram);
        let managed = managed_floor(&placed, dram);
        for (index, region) in placed.iter().enumerate() {
            assert!(region.base.is_multiple_of(PAGE_BYTES));
            assert!(region.base >= dram && region.base + region.bytes <= managed);
            assert!(placed[..index].iter().all(|before| {
                before.id != region.id && before.base + before.bytes <= region.base
            }));
        }
        let mut tree = tree_with(&["chosen", "pram", "arm-io"])?;
        tree.ensure_child("/arm-io", "sgx")?;
        publish(&mut tree, &placed)?;
        for (id, name) in SGX_REGIONS {
            let region = placed.iter().find(|region| region.id == id).unwrap();
            assert_eq!(
                tree.property(SGX, &format!("{name}-base"))
                    .unwrap()
                    .as_u64(),
                Some(region.base)
            );
            assert_eq!(
                tree.property(SGX, &format!("{name}-size"))
                    .unwrap()
                    .as_u64(),
                Some(region.bytes)
            );
        }
        assert!(!placed.iter().any(|region| region.id == 0x108));
        assert!(
            gaps(&tree, Some(0x6000))
                .iter()
                .any(|gap| gap.contains("0x108"))
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires the original 26A434 J314s iBoot in STELA_TEST_J314S_IBOOT"]
    fn t6000_fixed_subset_matches_the_exact_original_iboot_table() {
        let path = std::env::var_os("STELA_TEST_J314S_IBOOT").unwrap();
        let input = std::fs::read(path).unwrap();
        assert_eq!(
            stela_runtime::sha256(&input),
            "20dfa3a5e6d4e4b2844c7558e6d4f8ab74397d11eae63312f00a559cf9612b03"
        );
        let mut original = Vec::new();
        for record in input[0x1ffce8..0x1ffce8 + 112 * 64].as_chunks::<64>().0 {
            let word = |offset| u64::from_le_bytes(record[offset..offset + 8].try_into().unwrap());
            let (base, bytes, attributes) = (word(0), word(16), word(24));
            if base == u64::MAX && bytes > 0 && bytes != u64::MAX && attributes >> 16 == 0x80000009
            {
                original.push(carveout(attributes as u16, bytes));
            }
        }
        assert_eq!(table(0x6000).unwrap(), original);
    }

    fn tree_with(nodes: &[&str]) -> Result<DeviceTree> {
        let mut tree = DeviceTree {
            root: crate::apple_device_tree::Node::named("device-tree")?,
        };
        for node in nodes {
            tree.ensure_child("/", node)?;
        }
        Ok(tree)
    }

    #[test]
    fn the_panic_region_is_pram_reg_region_98_and_the_panic_log_size() -> Result<()> {
        let mut tree = tree_with(&["chosen", "pram"])?;
        tree.set_property(PRAM, "reg", vec![0; 16])?;
        let placed = place(&for_chip(0x8112), 0x8_0000_0000);
        publish(&mut tree, &placed)?;
        let panic = placed.last().unwrap();
        assert_eq!(panic.id, 98);
        let reg = range(panic.base, 0x18_8000);
        assert_eq!(tree.property(PRAM, "reg").unwrap().value, reg);
        assert_eq!(
            tree.property(MEMORY_MAP, "region-id-98").unwrap().value,
            reg
        );
        assert_eq!(
            tree.property("/chosen", PANIC_LOG_SIZE).unwrap().as_u32(),
            Some(0x18_8000)
        );
        assert!(!gaps(&tree, Some(0x8112)).iter().any(|g| g.contains(PRAM)));

        // As iBoot, a template without /pram gets no node, only the size.
        let mut bare = tree_with(&["chosen"])?;
        publish(&mut bare, &placed)?;
        assert!(bare.node(PRAM).is_none());
        assert!(bare.property("/chosen", PANIC_LOG_SIZE).is_some());
        assert!(
            gaps(&bare, Some(0x8112))
                .iter()
                .any(|g| g.contains("no /pram node"))
        );
        let unknown = gaps(&bare, Some(0x6050));
        assert!(unknown.iter().any(|g| g.contains("no hand-off facts")));
        Ok(())
    }
}
