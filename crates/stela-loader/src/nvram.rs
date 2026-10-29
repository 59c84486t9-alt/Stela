//! iBoot's NOR hand-off. The IPSW templates supply a zero-filled
//! `/chosen/nvram-proxy-data` slot (64 KiB on J473AP, 8 KiB on the M1 Pro,
//! M2 Pro and M3 Max and later laptop templates such as J414sAP), zero
//! `nvram-bank-*` placeholders and empty `spinor` child `reg`s. iBoot
//! replaces the slot with its NOR's current bank and states that bank's
//! geometry, so the slot's template size is a reservation, not the bank's.
//! Stela assigns its emulated die's partitions and copies its current CHRP
//! bank, whose geometry the published `nvram-bank-*` values state.
//!
//! 26A434 `AppleARMNORNVRAM::getNVRAMProperties` file
//! 0x1c92f48 reads the three 32-bit bank properties; `select` 0x1ca1d40
//! bounds the index and `read` 0x1ca1bd8 addresses bank * bank-size.
//! `AppleARMNORFlashDevice::initDeviceWithProvider` 0x1c5b948 interprets
//! each child's `reg` as 8-byte (u32 offset, u32 length) records. The J473
//! 26A434 `mBoot` table at file 0x1b0110 provides three firmware records,
//! two syscfg records and one NVRAM record.
//! XNU `IONVRAMCHRPHandler.cpp` validates CHRP checksums and Adler-32.
use crate::Result;
use crate::apple_device_tree::DeviceTree;
use alloc::vec::Vec;
use stela_contracts::{refuse, require};
use stela_soc_data::nor::{Image, nvram};

const CHOSEN: &str = "/chosen";
const PROXY: &str = "nvram-proxy-data";
const SPINOR: &str = "/arm-io/spi1/spinor";
// The J473 26A434 DeviceTree still carries the earlier one-MiB placeholder
// geometry even though mBoot's table describes the physical eight-MiB
// layout. Accept only that source template (or an already normalized
// tree), then publish the mBoot-derived regions from `nor`.
const TEMPLATE_CAPACITY: u32 = 0x100000;
const TEMPLATE_FIRMWARE: &[(u32, u32)] = &[(0, 0xc0000)];
const TEMPLATE_ANVRAM: &[(u32, u32)] = &[(0xc0000, 0x20000)];
const TEMPLATE_SYSCFG: &[(u32, u32)] = &[(0xe0000, 0x20000)];

fn reg(regions: &[(u32, u32)]) -> Vec<u8> {
    regions
        .iter()
        .flat_map(|&(offset, bytes)| [offset, bytes])
        .flat_map(u32::to_le_bytes)
        .collect()
}

/// Publish one image's current bank; the engine reconstructs the erased
/// regions and installs these exact proxy bytes into its NOR before entry.
/// A machine with a persistent NOR replaces this bank through the bundle's
/// `nvram` patch slots.
pub fn publish(tree: &mut DeviceTree) -> Result<bool> {
    let Some(slot) = tree.property(CHOSEN, PROXY) else {
        return Ok(false);
    };
    require!(
        !slot.value.is_empty(),
        "NVRAM proxy slot is empty, not a template reservation"
    );
    if let Some(spinor) = tree.node(SPINOR) {
        let assigned_ranges: Vec<u8> = [0u32, 0, stela_soc_data::nor::CAPACITY as u32]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let template_ranges: Vec<u8> = [0u32, 0, TEMPLATE_CAPACITY]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        require!(
            spinor
                .property("ranges")
                .is_some_and(|p| { p.value == template_ranges || p.value == assigned_ranges }),
            "unsupported SPI NOR address ranges"
        );
        for (name, template, assigned) in [
            (
                "firmware",
                reg(TEMPLATE_FIRMWARE),
                reg(&stela_soc_data::nor::FIRMWARE),
            ),
            (
                "anvram",
                reg(TEMPLATE_ANVRAM),
                reg(&[stela_soc_data::nor::ANVRAM]),
            ),
            (
                "syscfg",
                reg(TEMPLATE_SYSCFG),
                reg(&stela_soc_data::nor::SYSCFG),
            ),
        ] {
            let path = alloc::format!("{SPINOR}/{name}");
            let node = tree
                .node(&path)
                .ok_or_else(|| refuse!("missing {path}", path))?;
            require!(
                node.property("reg").is_some_and(|p| {
                    p.value.is_empty() || p.value == template || p.value == assigned
                }),
                "unsupported {path} partition",
                path
            );
        }
        tree.set_property(SPINOR, "ranges", assigned_ranges)?;
        for (name, value) in [
            ("firmware", reg(&stela_soc_data::nor::FIRMWARE)),
            ("anvram", reg(&[stela_soc_data::nor::ANVRAM])),
            ("syscfg", reg(&stela_soc_data::nor::SYSCFG)),
        ] {
            tree.set_property(&alloc::format!("{SPINOR}/{name}"), "reg", value)?;
        }
    }
    let image = Image::fresh();
    tree.set_property(
        CHOSEN,
        PROXY,
        image
            .bank(nvram::CURRENT_BANK)
            .expect("current bank")
            .to_vec(),
    )?;
    for (name, value) in [
        ("nvram-bank-size", nvram::BANK_SIZE as u32),
        ("nvram-bank-count", nvram::BANK_COUNT),
        ("nvram-current-bank", nvram::CURRENT_BANK),
    ] {
        tree.set_property(CHOSEN, name, value.to_le_bytes().to_vec())?;
    }
    // CHRP uses select/erase/write, not the V3 raw-store write protocol.
    if let Some(chosen) = tree.node_mut(CHOSEN) {
        chosen.remove_property("nvram-raw");
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;
    use alloc::vec;
    #[test]
    fn boot_firmware_normalizes_only_the_observed_template_partition_ranges() {
        let mut root = Node::named("device-tree").unwrap();
        let mut chosen = Node::named("chosen").unwrap();
        chosen
            .set_property(PROXY, vec![0; nvram::BANK_SIZE])
            .unwrap();
        let mut flash = Node::named("spinor").unwrap();
        flash
            .set_property(
                "ranges",
                [0u32, 0, TEMPLATE_CAPACITY]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            )
            .unwrap();
        for (name, value) in [
            ("firmware", reg(TEMPLATE_FIRMWARE)),
            ("anvram", reg(TEMPLATE_ANVRAM)),
            ("syscfg", reg(TEMPLATE_SYSCFG)),
        ] {
            let mut n = Node::named(name).unwrap();
            n.set_property("reg", value).unwrap();
            flash.children.push(n);
        }
        let mut spi = Node::named("spi1").unwrap();
        spi.children.push(flash);
        let mut io = Node::named("arm-io").unwrap();
        io.children.push(spi);
        root.children = vec![chosen, io];
        let mut tree = DeviceTree { root };
        assert!(publish(&mut tree).unwrap());
        assert_eq!(
            tree.property(SPINOR, "ranges").unwrap().value,
            [0u32, 0, stela_soc_data::nor::CAPACITY as u32]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            tree.property(&alloc::format!("{SPINOR}/anvram"), "reg")
                .unwrap()
                .value,
            reg(&[stela_soc_data::nor::ANVRAM])
        );
        assert_eq!(
            tree.property(&alloc::format!("{SPINOR}/firmware"), "reg")
                .unwrap()
                .value,
            reg(&stela_soc_data::nor::FIRMWARE)
        );
        assert_eq!(
            tree.property(&alloc::format!("{SPINOR}/syscfg"), "reg")
                .unwrap()
                .value,
            reg(&stela_soc_data::nor::SYSCFG)
        );
        tree.set_property(&alloc::format!("{SPINOR}/syscfg"), "reg", vec![0; 8])
            .unwrap();
        let before = tree.serialize();
        assert!(publish(&mut tree).is_err());
        assert_eq!(tree.serialize(), before);
    }

    #[test]
    fn proxy_is_the_nor_bank_and_chrp_has_no_raw_flag() {
        let mut chosen = Node::named("chosen").unwrap();
        chosen
            .set_property(PROXY, vec![0; nvram::BANK_SIZE])
            .unwrap();
        chosen.set_property("nvram-raw", vec![1, 0, 0, 0]).unwrap();
        let mut root = Node::named("device-tree").unwrap();
        root.children.push(chosen);
        let mut tree = DeviceTree { root };
        assert!(publish(&mut tree).unwrap());
        let image = Image::fresh();
        assert_eq!(
            tree.property(CHOSEN, PROXY).unwrap().value,
            image.bank(0).unwrap()
        );
        assert_eq!(
            tree.property(CHOSEN, "nvram-bank-size").unwrap().as_u32(),
            Some(65536)
        );
        assert_eq!(
            tree.property(CHOSEN, "nvram-bank-count").unwrap().as_u32(),
            Some(2)
        );
        assert_eq!(
            tree.property(CHOSEN, "nvram-current-bank")
                .unwrap()
                .as_u32(),
            Some(0)
        );
        assert!(tree.property(CHOSEN, "nvram-raw").is_none());
    }
    #[test]
    fn absent_proxy_is_unchanged_and_an_empty_slot_refuses() {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        assert!(!publish(&mut tree).unwrap());
        let mut chosen = Node::named("chosen").unwrap();
        chosen.set_property(PROXY, vec![]).unwrap();
        tree.root.children.push(chosen);
        let before = tree.serialize();
        assert!(publish(&mut tree).is_err());
        assert_eq!(tree.serialize(), before);
    }

    #[test]
    fn a_smaller_template_slot_takes_the_dies_whole_bank() {
        /// The slot J414sAP's 26A434 template reserves.
        const J414S_SLOT: usize = 8 << 10;
        let mut chosen = Node::named("chosen").unwrap();
        chosen.set_property(PROXY, vec![0; J414S_SLOT]).unwrap();
        let mut root = Node::named("device-tree").unwrap();
        root.children.push(chosen);
        let mut tree = DeviceTree { root };
        assert!(publish(&mut tree).unwrap());
        assert_eq!(
            tree.property(CHOSEN, PROXY).unwrap().value.len(),
            nvram::BANK_SIZE
        );
    }
}
