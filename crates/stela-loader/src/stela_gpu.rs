//! StelaGPU's call gate in the guest's DeviceTree: `/arm-io/stela-gpu`,
//! whose nub the StelaGPU kext matches by `compatible` and maps by `reg`.
//! The window goes in the first gap of `/arm-io`'s `ranges`, aligned to its
//! size, that no `/arm-io` device's registers use, so it collides with
//! nothing the board places; the runtime mounts the gate at the physical
//! address this answers.
use crate::apple_device_tree::{DeviceTree, Node};
use alloc::vec::Vec;
use anyhow::{Context, Result, ensure};

const ARM_IO: &str = "/arm-io";
const NAME: &str = "stela-gpu";
const COMPATIBLE: &[u8] = b"gpu,stela\0";

/// Adds the gate's node for a window of `bytes`, a power of two, and
/// answers the window's physical address.
pub fn place_gpu_gate(tree: &mut DeviceTree, bytes: u64) -> Result<u64> {
    ensure!(bytes.is_power_of_two(), "the gate window is a power of two");
    let arm_io = tree.node(ARM_IO).context("DeviceTree has no /arm-io")?;
    ensure!(arm_io.child(NAME).is_none(), "/arm-io already has a {NAME}");
    for cells in ["#address-cells", "#size-cells"] {
        ensure!(word(arm_io, cells) == Some(2), "/arm-io {cells} is not 2");
    }
    let ranges = quads(arm_io, "ranges", 3).context("/arm-io has no ranges")?;
    let used: Vec<(u64, u64)> = arm_io
        .children
        .iter()
        .filter_map(|child| quads(child, "reg", 2))
        .flatten()
        .map(|reg| (reg[0], reg[0].saturating_add(reg[1])))
        .collect();
    let (offset, physical) = ranges
        .iter()
        .find_map(|range| {
            gap(range[0], range[2], bytes, &used)
                .map(|offset| (offset, range[1] + (offset - range[0])))
        })
        .context("/arm-io has no gap for the StelaGPU gate")?;
    let mut node = Node::named(NAME)?;
    node.set_property("compatible", COMPATIBLE.to_vec())?;
    node.set_property("device_type", b"stela-gpu\0".to_vec())?;
    node.set_property("reg", [offset, bytes].map(u64::to_le_bytes).concat())?;
    tree.node_mut(ARM_IO)
        .context("DeviceTree has no /arm-io")?
        .children
        .push(node);
    Ok(physical)
}

/// The first offset of `start..start + length`, aligned to `bytes`, whose
/// `bytes` miss every `used` extent.
fn gap(start: u64, length: u64, bytes: u64, used: &[(u64, u64)]) -> Option<u64> {
    let end = start.checked_add(length)?;
    let mut candidate = start.checked_next_multiple_of(bytes)?;
    loop {
        let last = candidate.checked_add(bytes)?;
        if last > end {
            return None;
        }
        match used
            .iter()
            .filter(|&&(first, past)| first < last && candidate < past)
            .map(|&(_, past)| past)
            .max()
        {
            None => return Some(candidate),
            Some(past) => candidate = past.checked_next_multiple_of(bytes)?,
        }
    }
}

fn word(node: &Node, name: &str) -> Option<u32> {
    node.property(name)?.as_u32()
}

/// `name`'s value as records of `count` little-endian `u64`s.
fn quads(node: &Node, name: &str, count: usize) -> Option<Vec<Vec<u64>>> {
    let value = &node.property(name)?.value;
    let record = count * 8;
    if value.is_empty() || !value.len().is_multiple_of(record) {
        return None;
    }
    Some(
        value
            .chunks_exact(record)
            .map(|chunk| {
                chunk
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|cell| u64::from_le_bytes(*cell))
                    .collect()
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const WINDOW: u64 = 0x40_0000;

    fn device(name: &str, offset: u64, length: u64) -> Node {
        let mut node = Node::named(name).unwrap();
        node.set_property("reg", [offset, length].map(u64::to_le_bytes).concat())
            .unwrap();
        node
    }

    fn tree(children: Vec<Node>) -> DeviceTree {
        let mut arm_io = Node::named("arm-io").unwrap();
        for cells in ["#address-cells", "#size-cells"] {
            arm_io
                .set_property(cells, 2u32.to_le_bytes().to_vec())
                .unwrap();
        }
        let ranges = [0, 0x2_0000_0000, 0x1000_0000]
            .map(u64::to_le_bytes)
            .concat();
        arm_io.set_property("ranges", ranges).unwrap();
        arm_io.children = children;
        let mut root = Node::named("device-tree").unwrap();
        root.children.push(arm_io);
        DeviceTree { root }
    }

    #[test]
    fn the_gate_takes_the_first_aligned_gap_no_device_uses() {
        let mut tree = tree(vec![
            device("aic", 0, 0x10_0000),
            device("wdt", 0x40_0000, 0x1_0000),
        ]);
        assert_eq!(place_gpu_gate(&mut tree, WINDOW).unwrap(), 0x2_0080_0000);
        let node = tree.node("/arm-io/stela-gpu").unwrap();
        assert_eq!(node.property("compatible").unwrap().value, COMPATIBLE);
        assert_eq!(
            node.property("reg").unwrap().value,
            [0x80_0000, WINDOW].map(u64::to_le_bytes).concat()
        );
        assert!(place_gpu_gate(&mut tree, WINDOW).is_err());
    }

    #[test]
    fn a_full_bus_or_a_foreign_layout_has_no_place_for_the_gate() {
        let mut full = tree(vec![device("everything", 0, 0x1000_0000)]);
        assert!(place_gpu_gate(&mut full, WINDOW).is_err());
        let mut narrow = tree(Vec::new());
        narrow
            .set_property(ARM_IO, "#size-cells", 1u32.to_le_bytes().to_vec())
            .unwrap();
        assert!(place_gpu_gate(&mut narrow, WINDOW).is_err());
        assert!(place_gpu_gate(&mut tree(Vec::new()), 0x3000).is_err());
    }
}
