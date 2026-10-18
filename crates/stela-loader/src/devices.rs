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
//! A modeled DART (`dart,t8110`) presents only the streams visible devices
//! use: an `iommu-mapper` child stays only while a device that keeps its
//! `compatible` names it as `iommu-parent`, and the DART itself only while
//! one of its mappers stays. SPTM initializes every DART the tree shows, and
//! XNU starts an IODARTMapper per mapper; a DART no visible device reaches
//! would only be programmed for clients the machine does not have.
//!
//! A selection of a hidden device goes with it: XNU `pe_serial.c` (`xnu-12377`)
//! takes `/defaults` `serial-device`, a phandle, as its console and panics
//! when that node has no `compatible`. On J473AP it names the unmodeled
//! `dockchannel-uart`, so the property is removed and the kernel runs without
//! a console unless the `serial-device-name` boot-arg selects one.
//!
//! So does the root's `secure-root-prefix` once no AES accelerator (a node of
//! `device_type` `aes`) stays visible. `AppleARMPE::start` (26A434 J473AP
//! kernelcache) reads it from the platform node: without it the platform
//! records the root as secure and `SecureRootName` returns at once; with it,
//! `SecureRootName`, which `IOSecureBSDRoot` calls from `bsd_init`, compares
//! the root device's name against the prefix and then sleeps until a
//! `SecureRoot` call without a result buffer consumes the verdict.
//! `IOAESAccelerator::start` makes that call to install its
//! `SecureRootCallBack`, so on J473AP (`aes,s8000`, root `md0`, prefix `md`)
//! a hidden AES engine leaves the kernel asleep before `launchd` forever.
//! Removing the prefix keeps the verdict a matching root gets (secure); only
//! the callback into the absent driver goes.
use crate::apple_device_tree::{DeviceTree, Node};
use alloc::{format, string::String, vec::Vec};
use stela_runtime::machine::soc;

const COMPATIBLE: &str = "compatible";
const DEFAULTS: &str = "/defaults";
const SERIAL_DEVICE: &str = "serial-device";
const PHANDLE: &str = "AAPL,phandle";
const SECURE_ROOT_PREFIX: &str = "secure-root-prefix";
const DEVICE_TYPE: &str = "device_type";
const IOMMU_PARENT: &str = "iommu-parent";

/// Paths that keep their `compatible` whatever it names.
fn structural(path: &str) -> bool {
    path == "/"
        || path == "/arm-io"
        || path
            .strip_prefix("/cpus/")
            .is_some_and(|cpu| !cpu.contains('/'))
}

fn compatibles(node: &Node) -> impl Iterator<Item = &str> {
    node.property(COMPATIBLE)
        .into_iter()
        .flat_map(|property| property.value.split(|&byte| byte == 0))
        .filter_map(|name| core::str::from_utf8(name).ok())
}

fn named(node: &Node, model: &str) -> bool {
    compatibles(node).any(|name| name == model)
}

/// A modeled device that is not part of an IOMMU.
fn modeled_client(node: &Node) -> bool {
    // Only NOR-backed controllers have a modeled SPI slave. Other SPI
    // controllers must not bind drivers for absent peripherals.
    if named(node, soc::SPI) && !node.children.iter().any(|child| named(child, soc::NOR)) {
        return false;
    }
    !named(node, soc::DART) && !named(node, soc::IOMMU_MAPPER) && compatibles(node).any(soc::models)
}

/// The IOMMU and GPIO phandles that visible clients under `node` require.
fn client_providers(node: &Node, parents: &mut Vec<u32>) {
    if modeled_client(node)
        && named(node, soc::SPI)
        && let Some(phandle) = node
            .property("function-spi_cs0")
            .and_then(|p| p.value.get(..4))
    {
        parents.push(u32::from_le_bytes(phandle.try_into().expect("4 bytes")));
    }
    if modeled_client(node)
        && let Some(property) = node.property(IOMMU_PARENT)
    {
        let cells = property.value.as_chunks::<4>().0;
        parents.extend(cells.iter().map(|cell| u32::from_le_bytes(*cell)));
    }
    for child in &node.children {
        client_providers(child, parents);
    }
}

fn kept_mapper(node: &Node, parents: &[u32]) -> bool {
    named(node, soc::IOMMU_MAPPER)
        && node
            .property(PHANDLE)
            .and_then(|property| property.as_u32())
            .is_some_and(|phandle| parents.contains(&phandle))
}

/// Whether the machine models `node` and it serves a visible device.
fn modeled(node: &Node, parents: &[u32]) -> bool {
    if named(node, soc::GPIO) {
        node.property(PHANDLE)
            .and_then(|p| p.as_u32())
            .is_some_and(|p| parents.contains(&p))
    } else if named(node, soc::DART) {
        node.children
            .iter()
            .any(|child| kept_mapper(child, parents))
    } else if named(node, soc::IOMMU_MAPPER) {
        kept_mapper(node, parents)
    } else {
        modeled_client(node)
    }
}

/// Removes `compatible` from every device the machine does not model, a
/// `/defaults serial-device` that selects one and a `secure-root-prefix`
/// that no AES accelerator can acknowledge, and returns their paths in tree
/// order, then the selections.
pub fn hide_unmodeled(tree: &mut DeviceTree) -> Vec<String> {
    let mut parents = Vec::new();
    client_providers(&tree.root, &mut parents);
    let mut hidden = Vec::new();
    visit(&mut tree.root, "", &parents, &mut hidden);
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
    if tree.root.property(SECURE_ROOT_PREFIX).is_some() && !visible_aes(&tree.root) {
        tree.root.remove_property(SECURE_ROOT_PREFIX);
        hidden.push(format!("/ {SECURE_ROOT_PREFIX}"));
    }
    hidden
}

/// Whether an AES accelerator under `node` keeps its `compatible`.
fn visible_aes(node: &Node) -> bool {
    let aes = node
        .property(DEVICE_TYPE)
        .is_some_and(|property| property.value.split(|&byte| byte == 0).next() == Some(b"aes"));
    aes && node.property(COMPATIBLE).is_some() || node.children.iter().any(visible_aes)
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

fn visit(node: &mut Node, path: &str, parents: &[u32], hidden: &mut Vec<String>) {
    let here = if path.is_empty() { "/" } else { path };
    if node.property(COMPATIBLE).is_some() && !structural(here) && !modeled(node, parents) {
        node.remove_property(COMPATIBLE);
        hidden.push(here.into());
    }
    for child in &mut node.children {
        let name = child.name().unwrap_or("?");
        let path = format!("{path}/{name}");
        visit(child, &path, parents, hidden);
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
    fn spi_requires_a_nor_slave_and_retains_its_gpio_provider() {
        let mut gpio = node("gpio", Some(soc::GPIO.as_bytes()), vec![]);
        gpio.set_property(PHANDLE, 106u32.to_le_bytes().to_vec())
            .unwrap();
        let mut spi = node(
            "spi1",
            Some(soc::SPI.as_bytes()),
            vec![node(
                "spinor",
                Some(soc::NOR.as_bytes()),
                vec![node("anvram", Some(soc::NVRAM.as_bytes()), vec![])],
            )],
        );
        spi.set_property(
            "function-spi_cs0",
            [106u32, u32::from_le_bytes(*b"GPIO"), 49, 0x10001]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        )
        .unwrap();
        let mut tree = DeviceTree {
            root: node(
                "device-tree",
                None,
                vec![node(
                    "arm-io",
                    None,
                    vec![gpio, spi, node("spi0", Some(soc::SPI.as_bytes()), vec![])],
                )],
            ),
        };
        assert_eq!(hide_unmodeled(&mut tree), ["/arm-io/spi0"]);
        assert!(tree.property("/arm-io/gpio", COMPATIBLE).is_some());
        tree.node_mut("/arm-io/spi1").unwrap().children.clear();
        assert_eq!(hide_unmodeled(&mut tree), ["/arm-io/gpio", "/arm-io/spi1"]);
    }

    #[test]
    fn keeps_the_board_cpus_fabric_and_modeled_devices_and_hides_the_rest() {
        let mut tree = DeviceTree {
            root: secure_root(node(
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
                            aes(b"aes,s5l8960x\0"),
                            phandle(
                                node("dockchannel-uart", Some(b"aapl,dock-channels\0"), vec![]),
                                0x4d,
                            ),
                        ],
                    ),
                    node("buttons", Some(b"buttons\0"), vec![]),
                    serial_default(0x4d),
                ],
            )),
        };
        let hidden = hide_unmodeled(&mut tree);
        assert_eq!(
            hidden,
            [
                "/arm-io/sep",
                "/arm-io/sep/iop-sep-nub",
                "/arm-io/dart-sep",
                "/arm-io/aes",
                "/arm-io/dockchannel-uart",
                "/buttons",
                "/defaults serial-device",
                "/ secure-root-prefix"
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
        assert!(tree.root.property(SECURE_ROOT_PREFIX).is_none());
    }

    fn secure_root(mut root: Node) -> Node {
        root.set_property(SECURE_ROOT_PREFIX, b"md\0".to_vec())
            .unwrap();
        root
    }

    #[test]
    fn only_an_aes_node_with_its_compatible_is_a_visible_accelerator() {
        let mut root = node(
            "device-tree",
            None,
            vec![node("arm-io", None, vec![aes(b"aes,s8000\0")])],
        );
        assert!(visible_aes(&root));
        root.children[0].children[0].remove_property(COMPATIBLE);
        assert!(!visible_aes(&root));
        let other = node(
            "device-tree",
            None,
            vec![node("sio", Some(b"iop,ascwrap-v4\0"), vec![])],
        );
        assert!(!visible_aes(&other));
    }

    fn aes(compatible: &[u8]) -> Node {
        let mut aes = node("aes", Some(compatible), vec![]);
        aes.set_property(DEVICE_TYPE, b"aes\0".to_vec()).unwrap();
        aes
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

    fn mapper(name: &str, phandle_value: u32) -> Node {
        phandle(node(name, Some(b"iommu-mapper\0"), vec![]), phandle_value)
    }

    /// J473AP's AES engine reaches RAM through `dart-sio` `mapper-aes`
    /// (phandle 0x8a): that DART and mapper stay, its other mappers and the
    /// DARTs no visible device names go.
    #[test]
    fn darts_stay_only_for_the_streams_of_visible_devices() {
        let mut engine = aes(b"aes,s8000\0");
        engine
            .set_property(IOMMU_PARENT, 0x8a_u32.to_le_bytes().to_vec())
            .unwrap();
        let mut sio = node("sio", Some(b"iop,ascwrap-v4\0"), vec![]);
        sio.set_property(IOMMU_PARENT, 0x89_u32.to_le_bytes().to_vec())
            .unwrap();
        let mut tree = DeviceTree {
            root: secure_root(node(
                "device-tree",
                None,
                vec![node(
                    "arm-io",
                    None,
                    vec![
                        node(
                            "dart-sio",
                            Some(b"dart,t8110\0"),
                            vec![mapper("mapper-sio", 0x89), mapper("mapper-aes", 0x8a)],
                        ),
                        node(
                            "dart-sep",
                            Some(b"dart,t8110\0"),
                            vec![mapper("mapper-sep", 0x90)],
                        ),
                        engine,
                        sio,
                    ],
                )],
            )),
        };
        assert_eq!(
            hide_unmodeled(&mut tree),
            [
                "/arm-io/dart-sio/mapper-sio",
                "/arm-io/dart-sep",
                "/arm-io/dart-sep/mapper-sep",
                "/arm-io/sio",
            ]
        );
        for kept in [
            "/arm-io/dart-sio",
            "/arm-io/dart-sio/mapper-aes",
            "/arm-io/aes",
        ] {
            assert!(tree.property(kept, COMPATIBLE).is_some(), "{kept}");
        }
        // A visible AES engine keeps the secure root prefix.
        assert!(tree.root.property(SECURE_ROOT_PREFIX).is_some());
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
