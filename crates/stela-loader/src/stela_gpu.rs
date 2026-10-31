//! StelaGPU's call gates in the guest's DeviceTree: `/arm-io/stela-gpu<n>` for
//! GPU `n`, whose nub the StelaGPU kext matches by `compatible` and maps by
//! `reg`. A window goes in the first gap of `/arm-io`'s `ranges`, aligned to its
//! size, that no `/arm-io` device's registers use, and the completion
//! interrupt on the AIC input past every one the tree's AIC clients use, so
//! neither collides with anything the board places; the runtime mounts the
//! gate where this answers.
use crate::Result;
use crate::apple_device_tree::{DeviceTree, Node};
use alloc::{format, vec::Vec};
use stela_contracts::{refuse, require};

const ARM_IO: &str = "/arm-io";
const COMPATIBLE: &[u8] = b"gpu,stela\0";

const AIC: &str = "/arm-io/aic";
const PHANDLE: &str = "AAPL,phandle";
const INTERRUPT_PARENT: &str = "interrupt-parent";

/// Where the gate's node places it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    pub physical: u64,
    /// The AIC vector of its completion interrupt.
    pub irq: u32,
}

/// Adds the node of GPU `index`'s gate for a window of `bytes`, a power of two.
pub fn place_gpu_gate(tree: &mut DeviceTree, index: usize, bytes: u64) -> Result<Placement> {
    require!(bytes.is_power_of_two(), "the gate window is a power of two");
    let name = format!("stela-gpu{index}");
    let arm_io = tree
        .node(ARM_IO)
        .ok_or(refuse!("DeviceTree has no /arm-io"))?;
    require!(
        arm_io.child(&name).is_none(),
        "/arm-io already has a {name}",
        name
    );
    for cells in ["#address-cells", "#size-cells"] {
        require!(
            word(arm_io, cells) == Some(2),
            "/arm-io {cells} is not 2",
            cells
        );
    }
    let ranges = quads(arm_io, "ranges", 3).ok_or(refuse!("/arm-io has no ranges"))?;
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
        .ok_or(refuse!("/arm-io has no gap for the StelaGPU gate"))?;
    let aic = tree
        .property(AIC, PHANDLE)
        .and_then(|phandle| phandle.as_u32())
        .ok_or(refuse!("/arm-io/aic has no phandle"))?;
    let mut used = Vec::new();
    interrupts_of(&tree.root, aic, &mut used);
    let irq = used
        .into_iter()
        .max()
        .map_or(Some(0), |last| last.checked_add(1))
        .ok_or(refuse!("the AIC has no input past its clients'"))?;
    let mut node = Node::named(&name)?;
    node.set_property("compatible", COMPATIBLE.to_vec())?;
    node.set_property(INTERRUPT_PARENT, aic.to_le_bytes().to_vec())?;
    node.set_property("interrupts", irq.to_le_bytes().to_vec())?;
    node.set_property("device_type", b"stela-gpu\0".to_vec())?;
    node.set_property("reg", [offset, bytes].map(u64::to_le_bytes).concat())?;
    tree.node_mut(ARM_IO)
        .ok_or(refuse!("DeviceTree has no /arm-io"))?
        .children
        .push(node);
    Ok(Placement { physical, irq })
}

/// Collects the AIC inputs of `node` and its descendants whose interrupt
/// parent is the AIC with phandle `aic`.
fn interrupts_of(node: &Node, aic: u32, used: &mut Vec<u32>) {
    if word(node, INTERRUPT_PARENT) == Some(aic)
        && let Some(interrupts) = node.property("interrupts")
    {
        let (cells, _) = interrupts.value.as_chunks::<4>();
        used.extend(cells.iter().map(|cell| u32::from_le_bytes(*cell)));
    }
    for child in &node.children {
        interrupts_of(child, aic, used);
    }
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

    const AIC_PHANDLE: u32 = 7;

    fn device(name: &str, offset: u64, length: u64) -> Node {
        let mut node = Node::named(name).unwrap();
        node.set_property("reg", [offset, length].map(u64::to_le_bytes).concat())
            .unwrap();
        node
    }

    fn interrupting(mut node: Node, parent: u32, irqs: &[u32]) -> Node {
        node.set_property(INTERRUPT_PARENT, parent.to_le_bytes().to_vec())
            .unwrap();
        let irqs = irqs.iter().flat_map(|irq| irq.to_le_bytes()).collect();
        node.set_property("interrupts", irqs).unwrap();
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
        let mut aic = device("aic", 0x1000_0000 - 0x1_0000, 0x1_0000);
        aic.set_property(PHANDLE, AIC_PHANDLE.to_le_bytes().to_vec())
            .unwrap();
        arm_io.children = children;
        arm_io.children.push(aic);
        let mut root = Node::named("device-tree").unwrap();
        root.children.push(arm_io);
        DeviceTree { root }
    }

    #[test]
    fn the_gate_takes_the_first_aligned_gap_no_device_uses() {
        let mut tree = tree(vec![
            interrupting(device("uart", 0, 0x10_0000), AIC_PHANDLE, &[0x20, 0x31]),
            interrupting(device("wdt", 0x40_0000, 0x1_0000), AIC_PHANDLE, &[0x2c]),
            interrupting(device("gpio", 0x60_0000, 0x1_0000), 99, &[0x400]),
        ]);
        assert_eq!(
            place_gpu_gate(&mut tree, 0, WINDOW).unwrap(),
            Placement {
                physical: 0x2_0080_0000,
                irq: 0x32,
            }
        );
        let node = tree.node("/arm-io/stela-gpu0").unwrap();
        assert_eq!(node.property("compatible").unwrap().value, COMPATIBLE);
        assert_eq!(node.property("interrupts").unwrap().as_u32(), Some(0x32));
        assert_eq!(
            node.property("reg").unwrap().value,
            [0x80_0000, WINDOW].map(u64::to_le_bytes).concat()
        );
        assert!(place_gpu_gate(&mut tree, 0, WINDOW).is_err());
    }

    #[test]
    fn each_gpu_has_a_window_and_an_interrupt_of_its_own() {
        let mut tree = tree(Vec::new());
        let first = place_gpu_gate(&mut tree, 0, WINDOW).unwrap();
        let second = place_gpu_gate(&mut tree, 1, WINDOW).unwrap();
        assert_eq!(second.physical, first.physical + WINDOW);
        assert_eq!(second.irq, first.irq + 1);
        assert!(tree.node("/arm-io/stela-gpu1").is_some());
    }

    #[test]
    fn a_full_bus_or_a_foreign_layout_has_no_place_for_the_gate() {
        let mut full = tree(vec![device("everything", 0, 0x1000_0000)]);
        assert!(place_gpu_gate(&mut full, 0, WINDOW).is_err());
        let mut narrow = tree(Vec::new());
        narrow
            .set_property(ARM_IO, "#size-cells", 1u32.to_le_bytes().to_vec())
            .unwrap();
        assert!(place_gpu_gate(&mut narrow, 0, WINDOW).is_err());
        assert!(place_gpu_gate(&mut tree(Vec::new()), 0, 0x3000).is_err());
    }
}
