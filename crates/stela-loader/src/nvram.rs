//! iBoot's NOR hand-off. The IPSW J473AP template supplies a 64 KiB
//! `/chosen/nvram-proxy-data` slot and empty `spinor` child `reg`s. Stela
//! assigns its emulated die's partitions and copies its current CHRP bank.
//!
//! 26A434 `AppleARMNORNVRAM::getNVRAMProperties` file
//! 0x1c92f48 reads the three 32-bit bank properties; `select` 0x1ca1d40
//! bounds the index and `read` 0x1ca1bd8 addresses bank * bank-size.
//! `AppleARMNORFlashDevice::initDeviceWithProvider` 0x1c5b948 interprets
//! each child's `reg` as 8-byte (u32 offset, u32 length) records.
//! XNU `IONVRAMCHRPHandler.cpp` validates CHRP checksums and Adler-32.
use crate::apple_device_tree::DeviceTree;
use alloc::vec::Vec;
use anyhow::{Result, ensure};
use stela_runtime::machine::apple::nor::{self, Image, nvram};

const CHOSEN: &str = "/chosen";
const PROXY: &str = "nvram-proxy-data";
const SPINOR: &str = "/arm-io/spi1/spinor";

/// Publish one image's current bank; the engine reconstructs the erased
/// regions and installs these exact proxy bytes into its NOR before entry.
/// A machine with a persistent NOR replaces this bank through the bundle's
/// `nvram` patch slots.
pub fn publish(tree: &mut DeviceTree) -> Result<bool> {
    let Some(slot) = tree.property(CHOSEN, PROXY) else {
        return Ok(false);
    };
    ensure!(
        slot.value.len() == nvram::BANK_SIZE,
        "NVRAM proxy is not a 64 KiB bank"
    );
    if let Some(spinor) = tree.node(SPINOR) {
        let ranges: Vec<u8> = [0u32, 0, nor::CAPACITY as u32]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        ensure!(
            spinor.property("ranges").is_some_and(|p| p.value == ranges),
            "unsupported SPI NOR address ranges"
        );
        for (name, (offset, bytes)) in [
            ("firmware", nor::FIRMWARE),
            ("anvram", nor::ANVRAM),
            ("syscfg", nor::SYSCFG),
        ] {
            let path = alloc::format!("{SPINOR}/{name}");
            let reg: Vec<u8> = [offset, bytes]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let node = tree
                .node(&path)
                .ok_or_else(|| anyhow::anyhow!("missing {path}"))?;
            ensure!(
                node.property("reg")
                    .is_some_and(|p| p.value.is_empty() || p.value == reg),
                "unsupported {path} partition"
            );
        }
        for (name, (offset, bytes)) in [
            ("firmware", nor::FIRMWARE),
            ("anvram", nor::ANVRAM),
            ("syscfg", nor::SYSCFG),
        ] {
            tree.set_property(
                &alloc::format!("{SPINOR}/{name}"),
                "reg",
                [offset, bytes]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            )?;
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
    fn boot_firmware_assigns_only_empty_partition_ranges() {
        let mut root = Node::named("device-tree").unwrap();
        let mut chosen = Node::named("chosen").unwrap();
        chosen
            .set_property(PROXY, vec![0; nvram::BANK_SIZE])
            .unwrap();
        let mut flash = Node::named("spinor").unwrap();
        flash
            .set_property(
                "ranges",
                [0u32, 0, nor::CAPACITY as u32]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            )
            .unwrap();
        for name in ["firmware", "anvram", "syscfg"] {
            let mut n = Node::named(name).unwrap();
            n.set_property("reg", vec![]).unwrap();
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
            tree.property(&alloc::format!("{SPINOR}/anvram"), "reg")
                .unwrap()
                .value,
            [nor::ANVRAM.0, nor::ANVRAM.1]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>()
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
    fn absent_proxy_is_unchanged_and_wrong_size_refuses() {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        assert!(!publish(&mut tree).unwrap());
        let mut chosen = Node::named("chosen").unwrap();
        chosen.set_property(PROXY, vec![0; 32]).unwrap();
        tree.root.children.push(chosen);
        let before = tree.serialize();
        assert!(publish(&mut tree).is_err());
        assert_eq!(tree.serialize(), before);
    }
}
