//! Positive evidence for hiding the unsupported original CLPC class.
use alloc::{format, string::String, vec::Vec};
use stela_loader::apple_device_tree::{DeviceTree, Node};

fn class(node: &Node) -> bool {
    node.properties
        .iter()
        .filter(|p| p.name() == "compatible")
        .any(|p| {
            p.value
                .split(|byte| *byte == 0)
                .any(|token| token.starts_with(b"clpc,") && token.len() > b"clpc,".len())
        })
}

fn nodes<'a>(node: &'a Node, path: &str, out: &mut Vec<(String, &'a Node)>) -> Result<(), String> {
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
            .ok_or("CLPC evidence tree has an unnamed child")?;
        nodes(child, &format!("{path}/{name}"), out)?;
    }
    Ok(())
}

fn hidden_node(nodes: &[(String, &Node)], path: &str) -> Result<(), String> {
    let mut matching = nodes.iter().filter(|(candidate, _)| candidate == path);
    let (_, node) = matching
        .next()
        .ok_or("hidden original CLPC path is absent from live tree")?;
    if matching.next().is_some() || node.property("compatible").is_some() {
        return Err("original CLPC must remain uniquely retained without compatible".into());
    }
    Ok(())
}

pub(super) fn verify(
    original: &DeviceTree,
    prepared: &DeviceTree,
    ledger: &[String],
) -> Result<Vec<String>, String> {
    let mut source = Vec::new();
    let mut current = Vec::new();
    nodes(&original.root, "", &mut source)?;
    nodes(&prepared.root, "", &mut current)?;
    let mut hidden: Vec<String> = Vec::new();
    for (path, _) in source.iter().filter(|(_, node)| class(node)) {
        // iBoot variant overlays are not retained devices. Their removed paths
        // carry no runtime class notice; the retained parent's dummy identity
        // independently identifies the T6050 CLPC class.
        if !current.iter().any(|(candidate, _)| candidate == path) {
            continue;
        }
        if hidden.contains(path) || ledger.iter().filter(|entry| *entry == path).count() != 1 {
            return Err("original CLPC requires exact once-only hidden_devices evidence".into());
        }
        hidden_node(&current, path)?;
        hidden.push(path.clone());
    }
    Ok(hidden)
}

pub(super) fn validate_live(tree: &DeviceTree, hidden: &[String]) -> Result<(), String> {
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
        tree.set_property(
            "/arbitrary",
            "compatible",
            b"clpc,dummy\0clpc,t6050\0".to_vec(),
        )
        .unwrap();
        tree.ensure_child("/arbitrary", ":variant").unwrap();
        tree.set_property(
            "/arbitrary/:variant",
            "compatible",
            b"clpc,t6050d\0".to_vec(),
        )
        .unwrap();
        tree
    }

    #[test]
    fn hidden_clpc_uses_original_class_and_exact_evidence_without_variant_notices() {
        let original = tree();
        let mut prepared = original.clone();
        let node = prepared.node_mut("/arbitrary").unwrap();
        node.remove_property("compatible");
        node.children.clear();
        let hidden = verify(&original, &prepared, &["/arbitrary".into()]).unwrap();
        assert_eq!(hidden, ["/arbitrary"]);
        assert!(validate_live(&prepared, &hidden).is_ok());
        for ledger in [
            vec![],
            vec!["/arbitrary +note".into()],
            vec!["/arbitrary".into(), "/arbitrary".into()],
        ] {
            assert!(verify(&original, &prepared, &ledger).is_err());
        }
        assert!(verify(&original, &original, &["/arbitrary".into()]).is_err());
        prepared
            .set_property("/arbitrary", "compatible", b"clpc,t6050\0".to_vec())
            .unwrap();
        assert!(validate_live(&prepared, &hidden).is_err());
    }

    #[test]
    fn a_node_name_or_device_type_does_not_claim_the_clpc_class() {
        let mut original = tree();
        original
            .node_mut("/arbitrary")
            .unwrap()
            .remove_property("compatible");
        original.node_mut("/arbitrary").unwrap().children.clear();
        original
            .set_property("/arbitrary", "device_type", b"clpc\0".to_vec())
            .unwrap();
        assert!(verify(&original, &original, &[]).unwrap().is_empty());
        original
            .set_property("/arbitrary", "compatible", b"clpc,\0other,clpc\0".to_vec())
            .unwrap();
        assert!(verify(&original, &original, &[]).unwrap().is_empty());
    }
}
