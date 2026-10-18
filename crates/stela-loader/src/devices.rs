//! The devices a boot bundle presents: only those the machine models.
//!
//! The board's DeviceTree describes every device of the real SoC. SPTM's
//! bootstrap (DART instances by `compatible`, `dart-mapper` restrictions
//! through their DART's `compatible`) and the kernel's drivers bind to a
//! device through its `compatible`, and would then program hardware the
//! machine does not have. A node whose `compatible` names no modeled device
//! (`stela_runtime::machine::soc::models`) loses that property and keeps the
//! rest, so its `reg`, phandle and children stay where software that only
//! reads them expects them. The root, `/arm-io` and each `/cpus` child keep
//! theirs: they describe the board, its I/O fabric and the PEs the engine
//! runs. darwin-vm `dt_fixup.py` (MIT, commit `edfc1943`) boots the same
//! SPTM kernels to a shell in QEMU after removing `compatible` the same way.
//!
//! A selection of a hidden device goes with it: XNU `pe_serial.c` (`xnu-12377`)
//! takes `/defaults` `serial-device`, a phandle, as its console and panics
//! when that node has no `compatible`. On J473AP it names the unmodeled
//! `dockchannel-uart`, so the property is removed and the kernel runs without
//! a console unless the `serial-device-name` boot-arg selects one.
use crate::apple_device_tree::{DeviceTree, Node};
use alloc::{format, string::String, vec::Vec};
use stela_runtime::machine::soc;

const COMPATIBLE: &str = "compatible";
const DEFAULTS: &str = "/defaults";
const SERIAL_DEVICE: &str = "serial-device";
const PHANDLE: &str = "AAPL,phandle";

/// Paths that keep their `compatible` whatever it names.
fn structural(path: &str) -> bool {
    path == "/"
        || path == "/arm-io"
        || path
            .strip_prefix("/cpus/")
            .is_some_and(|cpu| !cpu.contains('/'))
}

fn modeled(node: &Node) -> bool {
    node.property(COMPATIBLE).is_some_and(|property| {
        property
            .value
            .split(|&byte| byte == 0)
            .filter_map(|name| core::str::from_utf8(name).ok())
            .any(soc::models)
    })
}

/// Removes `compatible` from every device the machine does not model, and a
/// `/defaults serial-device` that selects one, and returns their paths in
/// tree order, the selection last.
pub fn hide_unmodeled(tree: &mut DeviceTree) -> Vec<String> {
    let mut hidden = Vec::new();
    visit(&mut tree.root, "", &mut hidden);
    let selected = tree
        .property(DEFAULTS, SERIAL_DEVICE)
        .and_then(|property| property.as_u32())
        .and_then(|phandle| path_of(&tree.root, "", phandle));
    if selected.is_some_and(|path| hidden.contains(&path)) {
        if let Some(defaults) = tree.node_mut(DEFAULTS) {
            defaults.remove_property(SERIAL_DEVICE);
        }
        hidden.push(format!("{DEFAULTS} {SERIAL_DEVICE}"));
    }
    hidden
}

/// The path of the node whose phandle is `phandle`.
fn path_of(node: &Node, path: &str, phandle: u32) -> Option<String> {
    if node.property(PHANDLE).and_then(|p| p.as_u32()) == Some(phandle) {
        return Some(if path.is_empty() {
            "/".into()
        } else {
            path.into()
        });
    }
    node.children.iter().find_map(|child| {
        let name = child.name().unwrap_or("?");
        path_of(child, &format!("{path}/{name}"), phandle)
    })
}

fn visit(node: &mut Node, path: &str, hidden: &mut Vec<String>) {
    let here = if path.is_empty() { "/" } else { path };
    if node.property(COMPATIBLE).is_some() && !structural(here) && !modeled(node) {
        node.remove_property(COMPATIBLE);
        hidden.push(here.into());
    }
    for child in &mut node.children {
        let name = child.name().unwrap_or("?");
        let path = format!("{path}/{name}");
        visit(child, &path, hidden);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, compatible: Option<&[u8]>, children: Vec<Node>) -> Node {
        let mut node = Node::named(name).unwrap();
        if let Some(value) = compatible {
            node.set_property(COMPATIBLE, value.to_vec()).unwrap();
        }
        node.children = children;
        node
    }

    #[test]
    fn keeps_the_board_cpus_fabric_and_modeled_devices_and_hides_the_rest() {
        let mut tree = DeviceTree {
            root: node(
                "device-tree",
                Some(b"J473AP\0AppleARM\0"),
                vec![
                    node(
                        "cpus",
                        None,
                        vec![node("cpu0", Some(b"apple,blizzard\0ARM,v8\0"), vec![])],
                    ),
                    node(
                        "arm-io",
                        Some(b"arm-io,t8110\0"),
                        vec![
                            node("uart0", Some(b"uart-1,samsung\0"), vec![]),
                            node("wdt", Some(b"wdt,t8101\0wdt,s5l8960x\0"), vec![]),
                            node("aic", Some(b"aic,2\0"), vec![]),
                            node(
                                "sep",
                                Some(b"iop-sep,ascwrap-v4\0"),
                                vec![node("iop-sep-nub", Some(b"iop-nub,rtbuddy-v2\0"), vec![])],
                            ),
                            node("dart-sep", Some(b"dart,t8110\0"), vec![]),
                            phandle(
                                node("dockchannel-uart", Some(b"aapl,dock-channels\0"), vec![]),
                                0x4d,
                            ),
                        ],
                    ),
                    node("buttons", Some(b"buttons\0"), vec![]),
                    serial_default(0x4d),
                ],
            ),
        };
        let hidden = hide_unmodeled(&mut tree);
        assert_eq!(
            hidden,
            [
                "/arm-io/sep",
                "/arm-io/sep/iop-sep-nub",
                "/arm-io/dart-sep",
                "/arm-io/dockchannel-uart",
                "/buttons",
                "/defaults serial-device"
            ]
        );
        for kept in [
            "/",
            "/cpus/cpu0",
            "/arm-io",
            "/arm-io/uart0",
            "/arm-io/wdt",
            "/arm-io/aic",
        ] {
            assert!(tree.property(kept, COMPATIBLE).is_some(), "{kept}");
        }
        assert!(tree.property("/arm-io/dart-sep", COMPATIBLE).is_none());
        assert!(tree.node("/arm-io/sep/iop-sep-nub").is_some());
        assert!(tree.property(DEFAULTS, SERIAL_DEVICE).is_none());
    }

    fn phandle(mut node: Node, value: u32) -> Node {
        node.set_property(PHANDLE, value.to_le_bytes().to_vec())
            .unwrap();
        node
    }

    fn serial_default(value: u32) -> Node {
        let mut defaults = node("defaults", None, vec![]);
        defaults
            .set_property(SERIAL_DEVICE, value.to_le_bytes().to_vec())
            .unwrap();
        defaults
    }

    #[test]
    fn a_modeled_serial_device_stays_selected() {
        let mut tree = DeviceTree {
            root: node(
                "device-tree",
                None,
                vec![
                    node(
                        "arm-io",
                        None,
                        vec![phandle(node("uart0", Some(b"uart-1,samsung\0"), vec![]), 7)],
                    ),
                    serial_default(7),
                ],
            ),
        };
        assert!(hide_unmodeled(&mut tree).is_empty());
        assert!(tree.property(DEFAULTS, SERIAL_DEVICE).is_some());
    }
}
