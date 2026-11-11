//! StelaGPU's call gates in the guest's DeviceTree: `/arm-io/stela-gpu<n>` for
//! GPU `n`, whose nub the StelaGPU kext matches by `compatible` and maps by
//! `reg`. A window goes in the last gap of `/arm-io`'s `ranges`, aligned to its
//! size, that no `/arm-io` device's registers use, and the completion
//! interrupt on the AIC input past every one the tree's AIC clients use, so
//! neither collides with anything the board places; the runtime mounts the
//! gate where this answers.
use crate::Result;
use crate::apple_device_tree::{DeviceTree, Node};
use alloc::{format, string::String, vec::Vec};
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
/// parent is the AIC with phandle `aic`. A node's `interrupt-parent` is one
/// phandle for all its interrupts, or one per interrupt cell: T6050's
/// `/arm-io/pmgr/clpc` pairs three AIC inputs with thirteen cells of another
/// controller that are four-character names, not AIC inputs.
fn interrupts_of(node: &Node, aic: u32, used: &mut Vec<u32>) {
    if let (Some(parents), Some(interrupts)) =
        (node.property(INTERRUPT_PARENT), node.property("interrupts"))
    {
        let (parents, _) = parents.value.as_chunks::<4>();
        let (cells, _) = interrupts.value.as_chunks::<4>();
        let parent = |index: usize| match parents {
            [only] => Some(u32::from_le_bytes(*only)),
            _ if parents.len() == cells.len() => Some(u32::from_le_bytes(parents[index])),
            _ => None,
        };
        used.extend(
            cells
                .iter()
                .enumerate()
                .filter(|&(index, _)| parent(index) == Some(aic))
                .map(|(_, cell)| u32::from_le_bytes(*cell)),
        );
    }
    for child in &node.children {
        interrupts_of(child, aic, used);
    }
}

/// The last offset of `start..start + length`, aligned to `bytes`, whose
/// `bytes` miss every `used` extent. The tree does not name all of the SoC's
/// registers, the memory controllers' at its bottom among them, and the top of
/// the range is the part none reach.
fn gap(start: u64, length: u64, bytes: u64, used: &[(u64, u64)]) -> Option<u64> {
    let mut past = start.checked_add(length)?;
    loop {
        let candidate = past.checked_sub(bytes)? & !(bytes - 1);
        if candidate < start {
            return None;
        }
        let last = candidate + bytes;
        match used
            .iter()
            .filter(|&&(first, end)| first < last && candidate < end)
            .map(|&(first, _)| first)
            .min()
        {
            None => return Some(candidate),
            Some(first) => past = first,
        }
    }
}

fn word(node: &Node, name: &str) -> Option<u32> {
    node.property(name)?.as_u32()
}

/// The gate node's property holding what the boot knows of the PC, which the
/// StelaGPU kext publishes as its `StelaHost` registry dictionary.
pub const HOST_PROPERTY: &str = "stela-host";
/// The record's first line, naming its format and version. A reader takes
/// only the versions it knows; a new field is a new line, not a new version.
pub const HOST_FORMAT: &str = "stela-host 1";
/// The longest text value; a longer one is cut there.
pub const HOST_TEXT_BYTES: usize = 255;

/// One value of the host record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostValue {
    Text(String),
    Number(u64),
}

/// The `stela-host` record: [`HOST_FORMAT`], then a line per entry, `s Key=text`
/// or `n Key=decimal`, in the order given. Keys are ASCII letters and digits.
/// Text keeps printable ASCII, other bytes becoming `?`, and is cut to
/// [`HOST_TEXT_BYTES`]; it never holds a newline.
pub fn encode_host(entries: &[(String, HostValue)]) -> Result<Vec<u8>> {
    let mut record = format!("{HOST_FORMAT}\n");
    for (key, value) in entries {
        require!(
            !key.is_empty() && key.len() <= 40 && key.bytes().all(|b| b.is_ascii_alphanumeric()),
            "a host record key is not ASCII letters and digits"
        );
        match value {
            HostValue::Number(number) => record.push_str(&format!("n {key}={number}\n")),
            HostValue::Text(text) => {
                // C strings keep their terminator; it is not part of the text.
                let text: String = text
                    .trim_matches(|c: char| c.is_whitespace() || c == '\0')
                    .chars()
                    .map(|c| {
                        if c == ' ' || c.is_ascii_graphic() {
                            c
                        } else {
                            '?'
                        }
                    })
                    .take(HOST_TEXT_BYTES)
                    .collect();
                record.push_str(&format!("s {key}={text}\n"));
            }
        }
    }
    Ok(record.into_bytes())
}

/// The entries of a record [`encode_host`] wrote, in order. A record of
/// another version is refused; a malformed line is skipped.
pub fn decode_host(record: &[u8]) -> Result<Vec<(String, HostValue)>> {
    let text = core::str::from_utf8(record).map_err(|_| refuse!("a host record is not text"))?;
    let mut lines = text.lines();
    require!(
        lines.next() == Some(HOST_FORMAT),
        "a host record is not version 1"
    );
    Ok(lines
        .filter_map(|line| {
            let (kind, rest) = line.split_at_checked(2)?;
            let (key, value) = rest.split_once('=')?;
            if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return None;
            }
            let value = match kind {
                "n " => HostValue::Number(value.parse().ok()?),
                "s " => HostValue::Text(value.into()),
                _ => return None,
            };
            Some((key.into(), value))
        })
        .collect())
}

/// Sets GPU `index`'s gate node's [`HOST_PROPERTY`] to `record`.
pub fn set_host(tree: &mut DeviceTree, index: usize, record: Vec<u8>) -> Result<()> {
    tree.set_property(&format!("{ARM_IO}/stela-gpu{index}"), HOST_PROPERTY, record)
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
    fn the_gate_takes_the_last_aligned_gap_no_device_uses() {
        let mut tree = tree(vec![
            interrupting(device("uart", 0, 0x10_0000), AIC_PHANDLE, &[0x20, 0x31]),
            interrupting(device("wdt", 0xf80_0000, 0x1_0000), AIC_PHANDLE, &[0x2c]),
            interrupting(device("gpio", 0x60_0000, 0x1_0000), 99, &[0x400]),
        ]);
        assert_eq!(
            place_gpu_gate(&mut tree, 0, WINDOW).unwrap(),
            Placement {
                physical: 0x2_0f40_0000,
                irq: 0x32,
            }
        );
        let node = tree.node("/arm-io/stela-gpu0").unwrap();
        assert_eq!(node.property("compatible").unwrap().value, COMPATIBLE);
        assert_eq!(node.property("interrupts").unwrap().as_u32(), Some(0x32));
        assert_eq!(
            node.property("reg").unwrap().value,
            [0xf40_0000, WINDOW].map(u64::to_le_bytes).concat()
        );
        assert!(place_gpu_gate(&mut tree, 0, WINDOW).is_err());
    }

    #[test]
    fn only_the_cells_a_parent_list_gives_the_aic_are_its_inputs() {
        // T6050's clpc: AIC inputs, then another controller's named cells.
        let mut clpc = device("clpc", 0x10_0000, 0x1000);
        let parents = [AIC_PHANDLE, AIC_PHANDLE, 0x31e, 0x31e];
        clpc.set_property(
            INTERRUPT_PARENT,
            parents.iter().flat_map(|p| p.to_le_bytes()).collect(),
        )
        .unwrap();
        let cells = [0x19c, 0xdbc, u32::from_le_bytes(*b"RT0m"), 0];
        clpc.set_property(
            "interrupts",
            cells.iter().flat_map(|c| c.to_le_bytes()).collect(),
        )
        .unwrap();
        let mut tree = tree(vec![clpc]);
        assert_eq!(place_gpu_gate(&mut tree, 0, WINDOW).unwrap().irq, 0xdbd);
    }

    #[test]
    fn each_gpu_has_a_window_and_an_interrupt_of_its_own() {
        let mut tree = tree(Vec::new());
        let first = place_gpu_gate(&mut tree, 0, WINDOW).unwrap();
        let second = place_gpu_gate(&mut tree, 1, WINDOW).unwrap();
        assert_eq!(second.physical, first.physical - WINDOW);
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

    #[test]
    fn the_host_record_is_versioned_typed_lines() {
        let entries = [
            (
                "CPUBrand".into(),
                HostValue::Text("  AMD Ryzen 9 9950X\n16-Core\u{e9}  ".into()),
            ),
            ("HostThreads".into(), HostValue::Number(32)),
        ];
        let record = encode_host(&entries).unwrap();
        assert_eq!(
            core::str::from_utf8(&record).unwrap(),
            "stela-host 1\ns CPUBrand=AMD Ryzen 9 9950X?16-Core?\nn HostThreads=32\n"
        );
        // A kept C terminator is dropped, not shown as a replacement mark.
        assert_eq!(
            encode_host(&[("SystemVendor".into(), HostValue::Text("QEMU\0".into()))]).unwrap(),
            b"stela-host 1\ns SystemVendor=QEMU\n"
        );
        // A full translator target fits whole.
        let target = "x86_64-baseline+ssse3+sse4.1+sse4.2+pclmulqdq+fma+f16c+popcnt+bmi1+aes+sha\
                      +atomic-load16+cx8+cx16+avx2+lzcnt+bmi2+fast-pdep+movbe+gfni+avx512f+avx512bw";
        let entry = [("TranslatorTarget".into(), HostValue::Text(target.into()))];
        assert_eq!(decode_host(&encode_host(&entry).unwrap()).unwrap(), entry);
        let long = [("A".into(), HostValue::Text("x".repeat(500)))];
        assert_eq!(
            encode_host(&long).unwrap().len(),
            13 + 4 + HOST_TEXT_BYTES + 1
        );
        assert!(encode_host(&[("Bad key".into(), HostValue::Number(1))]).is_err());
        assert_eq!(
            decode_host(&record).unwrap(),
            [
                (
                    "CPUBrand".into(),
                    HostValue::Text("AMD Ryzen 9 9950X?16-Core?".into())
                ),
                ("HostThreads".into(), HostValue::Number(32)),
            ]
        );
        assert!(decode_host(b"stela-host 2\nn A=1\n").is_err());
        assert_eq!(
            decode_host(b"stela-host 1\nn A=x\nq B=1\ns =1\ns C=ok\n").unwrap(),
            [("C".into(), HostValue::Text("ok".into()))]
        );
        let mut tree = tree(vec![]);
        place_gpu_gate(&mut tree, 0, WINDOW).unwrap();
        set_host(&mut tree, 0, record.clone()).unwrap();
        assert_eq!(
            tree.property("/arm-io/stela-gpu0", HOST_PROPERTY)
                .unwrap()
                .value,
            record
        );
        assert!(set_host(&mut tree, 1, record).is_err());
    }
}
