//! DART numbering, a hand-off property iBoot adds.
//!
//! The shipped DeviceTree gives no DART a `dart-id`; iBoot (26A434 J473AP,
//! the loop that writes `dart-id` after matching `compatible`) numbers the
//! DARTs of each `compatible` in tree order from 0, one per-compatible
//! counter. SPTM's `t8110dart_bootstrap_instance` reads it as a 32-bit
//! value below 256, unique among its DARTs, and panics without it ("error
//! getting dart-id"); `dart_register_iommu_restriction` reads it from a
//! mapper's DART. The numbering covers every DART, so a DART keeps the
//! number it has on the real board whichever DARTs stay visible.
use crate::apple_device_tree::{DeviceTree, Node};
use alloc::{string::String, vec::Vec};
use anyhow::{Result, ensure};

const DART_ID: &str = "dart-id";
const DEVICE_TYPE: &str = "device_type";

/// Number every node of `device_type` `dart` within its first `compatible`.
pub fn publish(tree: &mut DeviceTree) -> Result<()> {
    let mut counters: Vec<(String, u32)> = Vec::new();
    number(&mut tree.root, &mut counters)
}

fn number(node: &mut Node, counters: &mut Vec<(String, u32)>) -> Result<()> {
    let dart = node
        .property(DEVICE_TYPE)
        .and_then(|property| property.as_str())
        == Some("dart");
    let family = node
        .property("compatible")
        .and_then(|property| property.value.split(|&byte| byte == 0).next())
        .and_then(|name| core::str::from_utf8(name).ok())
        .map(String::from);
    if let (true, Some(family)) = (dart, family) {
        let index = match counters.iter().position(|(name, _)| *name == family) {
            Some(index) => index,
            None => {
                counters.push((family, 0));
                counters.len() - 1
            }
        };
        let id = counters[index].1;
        ensure!(id < 256, "more than 256 DARTs of one compatible");
        node.set_property(DART_ID, id.to_le_bytes().to_vec())?;
        counters[index].1 += 1;
    }
    for child in &mut node.children {
        number(child, counters)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn dart(name: &str, compatible: &[u8]) -> Node {
        let mut node = Node::named(name).unwrap();
        node.set_property("compatible", compatible.to_vec())
            .unwrap();
        node.set_property(DEVICE_TYPE, b"dart\0".to_vec()).unwrap();
        node
    }

    #[test]
    fn darts_are_numbered_per_compatible_in_tree_order() {
        let mut io = Node::named("arm-io").unwrap();
        io.children = vec![
            dart("dart-apcie1", b"dart,t8110\0"),
            dart("dart-other", b"dart,t8020\0"),
            dart("dart-sio", b"dart,t8110\0"),
        ];
        let mut mapper = Node::named("mapper-aes").unwrap();
        mapper
            .set_property(DEVICE_TYPE, b"dart-mapper\0".to_vec())
            .unwrap();
        io.children[2].children.push(mapper);
        let mut root = Node::named("device-tree").unwrap();
        root.children.push(io);
        let mut tree = DeviceTree { root };
        publish(&mut tree).unwrap();
        let id = |path: &str| {
            tree.property(path, DART_ID)
                .map(|property| property.value.clone())
        };
        assert_eq!(id("/arm-io/dart-apcie1"), Some(vec![0, 0, 0, 0]));
        assert_eq!(id("/arm-io/dart-other"), Some(vec![0, 0, 0, 0]));
        assert_eq!(id("/arm-io/dart-sio"), Some(vec![1, 0, 0, 0]));
        assert_eq!(id("/arm-io/dart-sio/mapper-aes"), None);
    }
}
