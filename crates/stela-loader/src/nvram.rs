//! The NVRAM iBoot hands the kernel: the current bank of the SPI NOR's NVRAM
//! partition, copied into `/chosen` before the kernel starts.
//!
//! XNU's `IODTNVRAM::initImageFormat` (`IONVRAM.cpp`, `xnu-12377`) reads
//! `/chosen` `nvram-bank-size` and panics when it is 0, then takes
//! `nvram-proxy-data` as the image. `IONVRAMV3Handler` accepts an image whose
//! store header is `NVV3` version 1 and whose size equals the bank size, and
//! also requires `nvram-bank-count`, `nvram-current-bank` and `nvram-raw`
//! (whether its controller writes the NOR in place). The template leaves the
//! three counts 0, has no `nvram-raw`, and sizes `nvram-proxy-data` at
//! 64 KiB, which is taken as the bank size. XNU never writes a store header
//! of its own: it copies the existing one into each bank it rewrites.
//!
//! Stela presents an erased partition of two banks, the layout Asahi's
//! `apple-nvram` reads from M1 and M2 NOR (`PARTITION_SIZE` 0x10000 per bank),
//! with bank 0 current and holding a store header and no variables. The
//! header's generation 1, state 0xfe, flags 0x5a and the 0x4000/0xc000 split
//! between the system and common regions (the common size includes the
//! header) are those of `apple-nvram`'s store fixture; erased NOR reads 0xff.
//! The bank count and `nvram-raw` 1 (the NOR controller writes in place) are
//! inferences pending hardware. Variables persist only once a NOR model backs
//! the partition.
use crate::apple_device_tree::DeviceTree;
use alloc::{vec, vec::Vec};
use anyhow::{Result, ensure};

const CHOSEN: &str = "/chosen";
const PROXY_DATA: &str = "nvram-proxy-data";
const BANK_SIZE: &str = "nvram-bank-size";
const BANK_COUNT: &str = "nvram-bank-count";
const CURRENT_BANK: &str = "nvram-current-bank";
const RAW: &str = "nvram-raw";

const BANKS: u32 = 2;
const SIGNATURE: &[u8; 4] = b"3VVN";
const VERSION: u8 = 1;
const GENERATION: u32 = 1;
const STATE: u8 = 0xfe;
const FLAGS: u8 = 0x5a;
const SYSTEM_BYTES: u32 = 0x4000;
const HEADER_BYTES: usize = 24;
const ERASED: u8 = 0xff;

/// An erased bank of `bytes` with a v3 store header and no variables.
fn empty_bank(bytes: u32) -> Vec<u8> {
    let mut bank = vec![ERASED; bytes as usize];
    let mut header = Vec::with_capacity(HEADER_BYTES);
    header.extend_from_slice(SIGNATURE);
    header.extend_from_slice(&bytes.to_le_bytes());
    header.extend_from_slice(&GENERATION.to_le_bytes());
    header.extend_from_slice(&[STATE, FLAGS, VERSION, 0]);
    header.extend_from_slice(&SYSTEM_BYTES.to_le_bytes());
    header.extend_from_slice(&(bytes - SYSTEM_BYTES).to_le_bytes());
    bank[..HEADER_BYTES].copy_from_slice(&header);
    bank
}

/// Publishes the current NVRAM bank and its geometry in `/chosen`, when the
/// template has a proxy slot; returns whether it did.
pub fn publish(tree: &mut DeviceTree) -> Result<bool> {
    let Some(slot) = tree.property(CHOSEN, PROXY_DATA) else {
        return Ok(false);
    };
    let bytes = u32::try_from(slot.value.len())?;
    ensure!(
        bytes > SYSTEM_BYTES && bytes.is_power_of_two(),
        "{CHOSEN} {PROXY_DATA} is {bytes:#x} bytes, not an NVRAM bank"
    );
    tree.set_property(CHOSEN, PROXY_DATA, empty_bank(bytes))?;
    for (name, value) in [
        (BANK_SIZE, bytes),
        (BANK_COUNT, BANKS),
        (CURRENT_BANK, 0),
        (RAW, 1),
    ] {
        tree.set_property(CHOSEN, name, value.to_le_bytes().to_vec())?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;

    #[test]
    fn the_proxy_slot_becomes_an_empty_v3_bank() {
        let mut chosen = Node::named("chosen").unwrap();
        chosen.set_property(PROXY_DATA, vec![0; 0x10000]).unwrap();
        chosen.set_property(BANK_SIZE, vec![0; 4]).unwrap();
        let mut root = Node::named("device-tree").unwrap();
        root.children.push(chosen);
        let mut tree = DeviceTree { root };
        assert!(publish(&mut tree).unwrap());
        let image = &tree.property(CHOSEN, PROXY_DATA).unwrap().value;
        assert_eq!(image.len(), 0x10000);
        // apple-nvram's store fixture.
        assert_eq!(
            image[..HEADER_BYTES],
            [
                0x33, 0x56, 0x56, 0x4e, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xfe, 0x5a,
                0x01, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00,
            ]
        );
        assert!(image[HEADER_BYTES..].iter().all(|&byte| byte == ERASED));
        let word = |name| tree.property(CHOSEN, name).unwrap().as_u32();
        assert_eq!(word(BANK_SIZE), Some(0x10000));
        assert_eq!(word(BANK_COUNT), Some(2));
        assert_eq!(word(CURRENT_BANK), Some(0));
        assert_eq!(word(RAW), Some(1));
    }

    #[test]
    fn a_tree_without_a_proxy_slot_is_left_alone() {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        assert!(!publish(&mut tree).unwrap());
    }
}
