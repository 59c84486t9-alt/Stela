//! Positive evidence for hiding an original CLPC class the machine does not
//! model. [`CLPC`] stays visible.
use crate::Result;
use alloc::{format, string::String, vec::Vec};
use stela_contracts::refuse;
use stela_loader::apple_device_tree::{DeviceTree, Node};
use stela_soc_data::board::CLPC;

fn class(node: &Node) -> bool {
    node.properties
        .iter()
        .filter(|p| p.name() == "compatible")
        .any(|p| {
            p.value.split(|byte| *byte == 0).any(|token| {
                token.starts_with(b"clpc,")
                    && token.len() > b"clpc,".len()
                    && token != CLPC.as_bytes()
            })
        })
}

fn nodes<'a>(node: &'a Node, path: &str, out: &mut Vec<(String, &'a Node)>) -> Result<()> {
    out.push((
        if path.is_empty() {
            "/".into()
        } else {
            path.into()
        },
        node,
    ));
    for child in &node.children {
        let name = child
            .name()
            .ok_or(refuse!("CLPC evidence tree has an unnamed child"))?;
        nodes(child, &format!("{path}/{name}"), out)?;
    }
    Ok(())
}

fn hidden_node(nodes: &[(String, &Node)], path: &str) -> Result<()> {
    let mut matching = nodes.iter().filter(|(candidate, _)| candidate == path);
    let (_, node) = matching.next().ok_or(refuse!(
        "hidden original CLPC path is absent from live tree"
    ))?;
    if matching.next().is_some() || node.property("compatible").is_some() {
        return Err(refuse!(
            "original CLPC must remain uniquely retained without compatible"
        ));
    }
    Ok(())
}

pub fn verify(
    original: &DeviceTree,
    prepared: &DeviceTree,
    ledger: &[String],
    soc: u32,
    board: u32,
) -> Result<Vec<String>> {
    // Only the selected variant pass proves which overlay paths go.
    // This derived copy supplies CLPC class membership, never CPU provenance:
    // the source CPU indices are still checked against the immutable input.
    let mut projected = original.clone();
    stela_loader::soc_variant::apply(&mut projected, Some(soc), Some(board))
        .map_err(|error| refuse!("CLPC source variant projection: {error}", %error))?;
    let mut source = Vec::new();
    let mut current = Vec::new();
    nodes(&projected.root, "", &mut source)?;
    nodes(&prepared.root, "", &mut current)?;
    let mut hidden: Vec<String> = Vec::new();
    for (path, _) in source.iter().filter(|(_, node)| class(node)) {
        if hidden.contains(path) || ledger.iter().filter(|entry| *entry == path).count() != 1 {
            return Err(refuse!(
                "original CLPC requires exact once-only hidden_devices evidence"
            ));
        }
        hidden_node(&current, path)?;
        hidden.push(path.clone());
    }
    Ok(hidden)
}

pub fn validate_live(tree: &DeviceTree, hidden: &[String]) -> Result<()> {
    let mut current = Vec::new();
    nodes(&tree.root, "", &mut current)?;
    for path in hidden {
        hidden_node(&current, path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn tree() -> DeviceTree {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.ensure_child("/", "arbitrary").unwrap();
        tree.set_property("/arbitrary", "compatible", b"clpc,t6000\0".to_vec())
            .unwrap();
        tree
    }

    #[test]
    fn hidden_clpc_uses_original_class_and_exact_evidence() {
        let original = tree();
        let mut prepared = original.clone();
        let node = prepared.node_mut("/arbitrary").unwrap();
        node.remove_property("compatible");
        let hidden = verify(&original, &prepared, &["/arbitrary".into()], 0x8112, 0x28).unwrap();
        assert_eq!(hidden, ["/arbitrary"]);
        assert!(validate_live(&prepared, &hidden).is_ok());
        for ledger in [
            vec![],
            vec!["/arbitrary +note".into()],
            vec!["/arbitrary".into(), "/arbitrary".into()],
        ] {
            assert!(verify(&original, &prepared, &ledger, 0x8112, 0x28).is_err());
        }
        assert!(verify(&original, &original, &["/arbitrary".into()], 0x8112, 0x28).is_err());
        prepared
            .set_property("/arbitrary", "compatible", b"clpc,t6050\0".to_vec())
            .unwrap();
        assert!(validate_live(&prepared, &hidden).is_err());
    }

    #[test]
    fn the_modeled_clpc_stays_visible_without_evidence() {
        let mut original = tree();
        original
            .set_property("/arbitrary", "compatible", b"clpc,t8112\0".to_vec())
            .unwrap();
        assert!(
            verify(&original, &original, &[], 0x8112, 0x28)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn deleting_an_ordinary_kept_clpc_cannot_waive_its_absence_notice() {
        let original = tree();
        let mut removed = original.clone();
        removed.root.children.clear();
        assert!(verify(&original, &removed, &[], 0x8112, 0x28).is_err());
        assert!(verify(&original, &removed, &["/arbitrary".into()], 0x8112, 0x28).is_err());
        assert!(
            original
                .node("/arbitrary")
                .unwrap()
                .property("compatible")
                .is_some()
        );
    }

    #[test]
    fn a_node_name_or_device_type_does_not_claim_the_clpc_class() {
        let mut original = tree();
        original
            .node_mut("/arbitrary")
            .unwrap()
            .remove_property("compatible");
        original
            .set_property("/arbitrary", "device_type", b"clpc\0".to_vec())
            .unwrap();
        assert!(
            verify(&original, &original, &[], 0x8112, 0x28)
                .unwrap()
                .is_empty()
        );
        original
            .set_property("/arbitrary", "compatible", b"clpc,\0other,clpc\0".to_vec())
            .unwrap();
        assert!(
            verify(&original, &original, &[], 0x8112, 0x28)
                .unwrap()
                .is_empty()
        );
    }
}
