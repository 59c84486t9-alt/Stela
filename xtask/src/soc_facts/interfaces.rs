//! Original board interfaces, independently of which models Stela admits.
//!
//! Keep this ledger separate from the historical CPU/SPTM census. A
//! compatible string identifies an input interface, never its implementation
//! status. Property locations refer to the decoded, source-hashed ADT; `reg`
//! and `ranges` stay raw cells because their bus formats are not uniform.
use super::{DEVICE_TREE, Decoded, SocFacts, component, render};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use stela_cli::restore::manifest::{Identity, RestoreManifest};
use stela_runtime::machine::adt::Node;
use stela_runtime::machine::soc;

const OUTPUT: &str = "isa/apple-board-interfaces.json";
/// Values with a generic, format-independent interpretation. Other
/// properties retain their names, original offsets and flagged lengths.
const CELL_PROPERTIES: &[&str] = &[
    "reg",
    "ranges",
    "interrupts",
    "interrupt-parent",
    "AAPL,phandle",
    "#address-cells",
    "#size-cells",
    "#interrupt-cells",
    "dart-options",
    "page-size",
    "vm-base",
    "vm-size",
    "revision",
    "version",
    "tlbi-aperture-offset",
    "instance",
    "iommu-parent",
    "ioa-parent",
    "protection-granularity",
    "retention",
    "sid",
    "sids",
    "sid-count",
    "bus-range",
    "dev-range",
    "#ports",
    "#msi-vectors",
    "msi-address",
    "msi-vector-offset",
    "msi-vector-base",
    "domain-id",
    "port-number",
    "maximum-link-speed",
    "link-speed-default",
    "link-width-default",
    "spec-version",
    "pmgr-ver",
    "chiplet-count",
    "cap0-offset",
    "maxnumirq-offset",
    "rev-offset",
    "aicglbcfg-offset",
    "extint-baseaddress",
    "extintrcfg-stride",
    "intmaskset-stride",
    "intmaskclear-stride",
];

fn strings(value: &[u8]) -> Result<Vec<&str>> {
    value
        .split(|&byte| byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| core::str::from_utf8(part).context("non-UTF8 compatible"))
        .collect()
}

fn property(bytes: &[u8], name: &[u8], value: &[u8]) -> Result<Value> {
    let name = core::str::from_utf8(name).context("non-UTF8 property name")?;
    let offset = (value.as_ptr() as usize)
        .checked_sub(bytes.as_ptr() as usize)
        .context("property is outside its DeviceTree")?;
    ensure!(
        offset >= 4 && offset + value.len() <= bytes.len(),
        "property is outside its DeviceTree"
    );
    let encoded_length = u32::from_le_bytes(bytes[offset - 4..offset].try_into()?);
    let mut row = vec![json!(name), json!(offset), json!(encoded_length)];
    if value.len().is_multiple_of(4) && (CELL_PROPERTIES.contains(&name) || value.len() <= 64) {
        row.push(json!(
            value
                .as_chunks::<4>()
                .0
                .iter()
                .map(|cell| format!("{:#x}", u32::from_le_bytes(*cell)))
                .collect::<Vec<_>>()
        ));
    }
    Ok(json!(row))
}

fn walk(
    bytes: &[u8],
    node: &Node<'_>,
    path: &str,
    rows: &mut Vec<Value>,
    all_nodes: bool,
) -> Result<()> {
    let compatible = node.property("compatible");
    if all_nodes || compatible.is_some() {
        let compatibles = compatible.map(strings).transpose()?.unwrap_or_default();
        ensure!(
            compatible.is_none() || !compatibles.is_empty(),
            "{path}: empty compatible list"
        );
        let properties = node
            .properties()
            .context("truncated DeviceTree properties")?
            .into_iter()
            .filter(|(name, _)| *name != b"name")
            .map(|(name, value)| property(bytes, name, value))
            .collect::<Result<Vec<_>>>()?;
        rows.push(json!({
            "path": path,
            "compatible": compatibles,
            "properties": properties,
        }));
    }
    for child in node.children().context("truncated DeviceTree children")? {
        let name = child
            .property("name")
            .context("DeviceTree child has no name")?;
        let name = name.strip_suffix(&[0]).unwrap_or(name);
        let name = core::str::from_utf8(name).context("non-UTF8 DeviceTree child name")?;
        ensure!(
            !name.contains('/'),
            "DeviceTree child name contains a slash"
        );
        let child_path = if path == "/" {
            format!("/{name}")
        } else {
            format!("{path}/{name}")
        };
        walk(bytes, &child, &child_path, rows, all_nodes)?;
    }
    Ok(())
}

fn inventory(bytes: &[u8], all_nodes: bool) -> Result<Vec<Value>> {
    let tree = Node::root(bytes).context("DeviceTree has no root")?;
    let mut rows = Vec::new();
    walk(bytes, &tree, "/", &mut rows, all_nodes)?;
    Ok(rows)
}

/// Check every declared CPU binding against the original board topology,
/// without assigning an unrecognized SoC to a nearby compiler generation.
fn cpu_binding(bytes: &[u8], id: u32) -> Result<Value> {
    let root = Node::root(bytes).context("DeviceTree has no root")?;
    let name = root
        .child("product")
        .and_then(|node| node.property("product-soc-name"))
        .map(|name| core::str::from_utf8(name.split(|&byte| byte == 0).next().unwrap_or_default()))
        .transpose()?;
    let nodes = root
        .child("cpus")
        .context("SoC has no cpus")?
        .children()
        .context("truncated CPU nodes")?;
    let processors = nodes
        .iter()
        .map(|node| {
            let kind = node
                .property("cluster-type")
                .and_then(|value| value.first())
                .copied()
                .context("CPU has no cluster-type")?;
            Ok(soc::Processor {
                cluster_type: kind,
                reg: node.first_u32("reg").context("CPU has no affinity reg")?,
                l2_bytes: node.first_u32("l2-cache-size"),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let (status, reason) = if soc::chip(id).is_none() {
        (
            "unconfigured",
            Some("SoC has no configured CPU profile".to_owned()),
        )
    } else if let Some(name) = name {
        match soc::cpus(id, name, &processors) {
            Ok(_) => ("configured", None),
            Err(reason) => ("partial", Some(reason)),
        }
    } else {
        (
            "partial",
            Some("configured SoC has no product-soc-name".to_owned()),
        )
    };
    let processors = processors
        .iter()
        .map(|pe| {
            json!({
                "reg": format!("{:#x}", pe.reg),
                "cluster_type": char::from(pe.cluster_type).to_string(),
                "l2_cache_size": pe.l2_bytes,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({ "status": status, "reason": reason, "processors": processors }))
}

pub(super) fn run(
    task: &SocFacts,
    manifest: &RestoreManifest,
    identities: &[&Identity],
) -> Result<()> {
    let mut boards = Vec::new();
    for identity in identities {
        let member = component(identity, DEVICE_TREE).context("board has no DeviceTree")?;
        let decoded = Decoded::read(&task.ipsw, member)?;
        let nodes = inventory(&decoded.bytes, true)
            .with_context(|| format!("{member}: interface inventory"))?;
        let chip_id = identity
            .ap_chip_id
            .as_deref()
            .context("board has no ApChipID")?;
        let id = u32::from_str_radix(chip_id.trim_start_matches("0x"), 16)?;
        let firmware = identity
            .components
            .iter()
            .map(|(name, component)| {
                json!({
                    "component": name,
                    "member": component.path,
                    "declared_digest": component.declared_digest_hex,
                    "declared_hash_method": component.declared_hash_method,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{} ({chip_id}): {} original interfaces",
            identity.device_class,
            nodes.len()
        );
        boards.push(json!({
            "device_class": identity.device_class,
            "product_type": identity.product_type,
            "chip_id": chip_id,
            "board_id": identity.ap_board_id,
            "configured_cpu_profile": soc::chip(id).map(|chip| chip.name()),
            "cpu_binding": cpu_binding(&decoded.bytes, id)?,
            "source": decoded.source(),
            "components": firmware,
            "interfaces": nodes,
        }));
    }
    let mut facts = json!({
        "property_scope": "all_properties",
        "schema_version": 1,
        "kind": "original_apple_board_interface_inventory",
        "generator": "cargo xtask soc-facts --ipsw IPSW --board-interfaces",
        "scope": "Every compatible-bearing or register/range/interrupt-bearing node of each original erase-identity DeviceTree (the optional detailed ledger retains all nodes); inventory is not modeled, tested or boot-qualified support. Raw reg/ranges cells have no inferred address translation. CPU profile names describe configured software bindings, not observed ID register values.",
        "source": {
            "ipsw": task.ipsw.file_name().map(|name| name.to_string_lossy()),
            "product_version": manifest.product_version,
            "product_build": manifest.product_build,
            "manifest_sha256": manifest.manifest_sha256,
        },
        "property_columns": ["name", "value_offset", "encoded_length", "optional_cells32_le"],
        "property_length_mask": "0x7fffffff",
        "property_placeholder_flag": "0x80000000",
        "boards": boards,
    });
    if let Some(path) = &task.interface_details {
        bind_output(path, &manifest.manifest_sha256)?;
        task.update(&path.to_string_lossy(), render(&facts, 0) + "\n")?;
    }
    for board in facts["boards"].as_array_mut().expect("boards") {
        board["interfaces"]
            .as_array_mut()
            .expect("interfaces")
            .retain(|node| {
                !node["compatible"]
                    .as_array()
                    .expect("compatible")
                    .is_empty()
                    || node["properties"]
                        .as_array()
                        .expect("properties")
                        .iter()
                        .any(|row| matches!(row[0].as_str(), Some("reg" | "ranges" | "interrupts")))
            });
        for node in board["interfaces"].as_array_mut().expect("interfaces") {
            node["properties"]
                .as_array_mut()
                .expect("properties")
                .retain(|row| {
                    row[0]
                        .as_str()
                        .is_some_and(|name| name == "compatible" || CELL_PROPERTIES.contains(&name))
                });
        }
    }
    facts["property_scope"] = json!("selected_hardware_capabilities");
    let output = task
        .interface_output
        .as_deref()
        .unwrap_or(std::path::Path::new(OUTPUT));
    bind_output(output, &manifest.manifest_sha256)?;
    task.update(&output.to_string_lossy(), compact(&facts) + "\n")
}

/// One interface per line keeps the complete inventory reviewable without
/// expanding every register cell onto its own line.
fn compact(facts: &Value) -> String {
    let mut fields = Vec::new();
    for (name, value) in facts.as_object().expect("inventory object") {
        let rendered = if name == "boards" {
            let boards = value
                .as_array()
                .expect("boards")
                .iter()
                .map(|board| {
                    let mut fields = Vec::new();
                    for (name, value) in board.as_object().expect("board") {
                        let rendered = if name == "interfaces" {
                            let rows = value
                                .as_array()
                                .expect("interfaces")
                                .iter()
                                .map(|row| format!("        {}", super::inline(row)))
                                .collect::<Vec<_>>();
                            format!("[\n{}\n      ]", rows.join(",\n"))
                        } else {
                            render(value, 6)
                        };
                        fields.push(format!("      {}: {rendered}", json!(name)));
                    }
                    format!("    {{\n{}\n    }}", fields.join(",\n"))
                })
                .collect::<Vec<_>>();
            format!("[\n{}\n  ]", boards.join(",\n"))
        } else {
            render(value, 2)
        };
        fields.push(format!("  {}: {rendered}", json!(name)));
    }
    format!("{{\n{}\n}}", fields.join(",\n"))
}

/// A new input gets a new ledger. Never replace an older source identity
/// just because the command was pointed at another archive.
fn bind_output(path: &std::path::Path, manifest_sha256: &str) -> Result<()> {
    let path = crate::tools::root().join(path);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let previous: Value = serde_json::from_slice(&bytes)
                .with_context(|| format!("cannot read ledger {}", path.display()))?;
            ensure!(
                previous["source"]["manifest_sha256"].as_str() == Some(manifest_sha256),
                "{} belongs to another source manifest; preserve it and choose a fresh --interface-output or --interface-details path",
                path.display()
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("cannot read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_loader::apple_device_tree::{DeviceTree, Node};

    #[test]
    fn inventory_keeps_nested_unknown_interfaces_and_exact_property_provenance() {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.ensure_child("/", "arm-io").unwrap();
        tree.ensure_child("/arm-io", "future-device").unwrap();
        tree.set_property(
            "/arm-io/future-device",
            "compatible",
            b"new,unknown\0fallback\0".to_vec(),
        )
        .unwrap();
        tree.set_property("/arm-io/future-device", "reg", vec![1, 0, 0, 0, 2, 0, 0, 0])
            .unwrap();
        tree.set_property("/arm-io/future-device", "private-capability", vec![1, 2, 3])
            .unwrap();
        let bytes = tree.serialize();
        let rows = inventory(&bytes, false).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["path"], "/arm-io/future-device");
        assert_eq!(rows[0]["compatible"], json!(["new,unknown", "fallback"]));
        let properties = rows[0]["properties"].as_array().unwrap();
        let reg = properties.iter().find(|row| row[0] == "reg").unwrap();
        assert_eq!(reg[3], json!(["0x1", "0x2"]));
        for row in properties {
            let at = row[1].as_u64().unwrap() as usize;
            let len = row[2].as_u64().unwrap() as usize & 0x7fffffff;
            let name = row[0].as_str().unwrap();
            assert_eq!(
                tree.property("/arm-io/future-device", name).unwrap().value,
                bytes[at..at + len]
            );
        }
        assert!(
            properties
                .iter()
                .any(|row| row[0] == "private-capability" && row.as_array().unwrap().len() == 3)
        );
    }

    #[test]
    fn malformed_compatible_is_an_error_instead_of_a_missing_interface() {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.set_property("/", "compatible", vec![0xff]).unwrap();
        assert!(inventory(&tree.serialize(), false).is_err());
        tree.set_property("/", "compatible", vec![0]).unwrap();
        assert!(inventory(&tree.serialize(), false).is_err());
    }
    #[test]
    fn a_new_source_cannot_overwrite_an_existing_ledger() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inventory.json");
        assert!(bind_output(&path, "original").is_ok());
        std::fs::write(&path, br#"{"source":{"manifest_sha256":"original"}}"#).unwrap();
        assert!(bind_output(&path, "original").is_ok());
        assert!(bind_output(&path, "different").is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            br#"{"source":{"manifest_sha256":"original"}}"#
        );
    }

    #[test]
    fn original_padding_and_placeholder_flags_are_preserved() {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.set_property("/", "compatible", b"test,device\0".to_vec())
            .unwrap();
        tree.set_property("/", "private", vec![1, 2, 3]).unwrap();
        tree.root.property_mut("private").unwrap().placeholder = true;
        let at = tree.locate("/", "private").unwrap().value_offset;
        let mut bytes = tree.serialize();
        bytes[at + 3] = 0xab;
        let rows = inventory(&bytes, false).unwrap();
        let row = rows[0]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row[0] == "private")
            .unwrap();
        assert_eq!(row[1], at);
        assert_eq!(row[2], 0x80000003u32);
        assert_eq!(bytes[at + 3], 0xab);
    }
    #[test]
    fn compact_format_keeps_every_interface_as_one_equivalent_json_row() {
        let facts = json!({"source": {"hash": "input"}, "boards": [{"chip_id": "0x1", "interfaces": [
            {"path": "/device", "compatible": ["test,device"], "properties": [["reg", 4, 8, ["0x1", "0x2"]]]}
        ]}]});
        let text = compact(&facts);
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), facts);
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("test,device"))
                .count(),
            1
        );
    }
    #[test]
    fn partial_cpu_binding_preserves_each_original_core_type() {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.ensure_child("/", "product").unwrap();
        tree.set_property("/product", "product-soc-name", b"Apple M6\0".to_vec())
            .unwrap();
        tree.ensure_child("/", "cpus").unwrap();
        for (index, kind) in b"PM".iter().copied().enumerate() {
            let path = format!("/cpus/cpu{index}");
            tree.ensure_child("/cpus", &format!("cpu{index}")).unwrap();
            tree.set_property(&path, "reg", (0x100 + index as u32).to_le_bytes().to_vec())
                .unwrap();
            tree.set_property(&path, "cluster-type", vec![kind, 0])
                .unwrap();
            tree.set_property(&path, "l2-cache-size", (20u32 << 20).to_le_bytes().to_vec())
                .unwrap();
        }
        let bytes = tree.serialize();
        let binding = cpu_binding(&bytes, 0x8152).unwrap();
        assert_eq!(binding["status"], "partial");
        assert!(binding["reason"].as_str().unwrap().contains("type M"));
        assert_eq!(binding["processors"][0]["cluster_type"], "P");
        assert_eq!(binding["processors"][1]["cluster_type"], "M");
        assert_eq!(
            cpu_binding(&bytes, 0x8101).unwrap()["status"],
            "unconfigured"
        );
    }
}
