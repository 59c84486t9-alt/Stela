//! The SoC variant iBoot reads from the T6050's fuses, and the DeviceTree it
//! derives from it.
//!
//! The M5 Pro, Max and Ultra boards share ApChipID 0x6050 and one template
//! DeviceTree: both dies' CPUs, no `product-soc-name`, a root `/:sotra`
//! whose `option` lists `h17s`, `h17c`, `h17cr1`, `h17cr2` and `h17d`, a
//! `/:version` of 1, and beside the nodes they extend 48 to 111
//! `:sotra_<variant>_<n>` overlay nodes per variant (`/product`'s names the
//! SoC; `/arm-io/mcc`'s give the enabled MCCs and their registers; the
//! Ultra's add the second die's error handlers, PMGR clusters and ranges).
//! The J714s and J714c templates differ only in identity strings and
//! phandles.
//!
//! 26A434 `iBoot.j714s` (decoded SHA-256
//! `2f0b8037ad7163923a72214e4652baa5c0d8df65aa225cac69400393cee44b07`;
//! offsets in the decoded file) chooses the variant from fuses, not from the
//! board:
//!
//! - `0x50674` reads two die-configuration words at `0x2_8837_4010` and
//!   `0x2_8837_4014` (in `/arm-io/pmgr`'s fuse window). Both `0xa050_c030`:
//!   one Max die, whose disabled-MCC word at `0x23_8837_4020` picks `h17c`
//!   (0), `h17cr1` (`0xff00_0000`) or `h17cr2` (`0xff00`). `0xa55a_c33c`
//!   then `0xa050_c030`: `h17s`. `0xa050_c030` then `0xa55a_c33c`: `h17d`.
//!   Anything else panics. `0x50a5c` counts two dies only for `h17d`.
//!   The names come from the option table at `0x269398` through the index
//!   list at `0x269500`.
//! - The overlay pass `0x196238` (called when the DeviceTree is loaded,
//!   `0x1d8c60`) requires `/:version version` 1 (`0x196ea0`), then
//!   `0x1965e8..0x197450` merges each of the variant's overlay nodes into
//!   its parent: a property other than `name` and `AAPL,…` is appended to
//!   the parent's value of that name, or added; a child node is added. The
//!   other variants' overlays and the group nodes go.
//! - The finalizer's platform pass (`0x408dc`, from `0x264a8`) deletes the
//!   CPU nodes the fuses leave out (`0x40a0c..`, both dies; the second
//!   die's count is 0 on one die) and writes `/cpus` `max_cpus`,
//!   `cpu-cluster-count`, `m-core-count` and `p-core-count`; then
//!   `/arm-io/mcc` `dcs-channel-enable-mask` (the disabled-MCC word
//!   inverted, `0x7b9a8`), `amcc-enable-mask` (`0x7b9d8`) and
//!   `die-enable-mask` (3 for `h17d`, else 1), and for `h17d` with bit 0 of
//!   `0x23_8837_412c` clear, `rank-drop-mask` 0 (`0x40b78..0x40c38`).
//! - The MCC bring-up `0x7b81c` takes the enabled MCCs from the
//!   disabled-MCC word: 0 all eight (`0xff`), `0xff00_0000` six (`0x3f`),
//!   `0xffff_0000` four (`0x0f`), `0xff00` six (`0xf3`); anything else
//!   panics. The lock-register builder (`crate::lock_regs`) places one
//!   AMCC aperture per enabled MCC.
//!
//! The emulated chip's fuses are part of the selected board profile
//! ([`fuses`]). Every board's iBoot carries all five variants, and the
//! templates are identical, so the board's ApBoardID, which board
//! selection and the manifest's `BORD` already bind, is the one input that
//! tells the boards apart. Apple's board names say which die each carries,
//! as on the earlier Pro, Max and Ultra boards: an `s` board an M5 Pro, a
//! `c` board an M5 Max, a `d` board an M5 Ultra. Each takes its full part:
//! the Max's binned `h17cr1` and `h17cr2` and partial core counts are fused
//! states no profile selects.
use crate::{
    apple_device_tree::{DeviceTree, Node},
    boot_policy::Decision,
};
use alloc::{format, string::String, vec, vec::Vec};
use anyhow::{Context, Result, bail, ensure};

/// The ApChipID whose iBoot reads these fuses.
pub const CHIP_ID: u32 = 0x6050;
/// The die-configuration word of a Max-class die.
const MAX_DIE: u32 = 0xa050_c030;
/// The other die-configuration word.
const OTHER_DIE: u32 = 0xa55a_c33c;
/// The template's variant group and its version node.
const GROUP: &str = ":sotra";
/// Every variant's overlay names start so.
const OVERLAY: &str = ":sotra_";
const VERSION: &str = ":version";
const CPUS: &str = "/cpus";
const MCC: &str = "/arm-io/mcc";

/// The fuse words iBoot's T6050 platform code reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fuses {
    /// The words at `0x2_8837_4010` and `0x2_8837_4014`.
    pub die_configuration: [u32; 2],
    /// The disabled-MCC word at `0x23_8837_4020`.
    pub disabled_mccs: u32,
    /// Bit 0 of `0x23_8837_412c`: the Ultra keeps its `rank-drop-mask`.
    pub rank_drop: bool,
}

/// What iBoot derives from [`Fuses`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Variant {
    /// The `/:sotra` option.
    pub name: &'static str,
    pub dies: u32,
    /// One bit per enabled MCC of each die.
    pub mccs: u32,
    pub fuses: Fuses,
}

const PRO: Fuses = Fuses {
    die_configuration: [OTHER_DIE, MAX_DIE],
    disabled_mccs: 0xffff_0000,
    rank_drop: false,
};
const MAX: Fuses = Fuses {
    die_configuration: [MAX_DIE, MAX_DIE],
    disabled_mccs: 0,
    rank_drop: false,
};
/// The template's own `h17d` `rank-drop-mask` is taken as the part's: the
/// fuse bit that keeps it is set.
const ULTRA: Fuses = Fuses {
    die_configuration: [MAX_DIE, OTHER_DIE],
    disabled_mccs: 0,
    rank_drop: true,
};

/// The fuses of the board with `board_id`, by its 26A434 build identities:
/// J873s (2), J714s (8) and J716s (0xc) are M5 Pro boards; J714c (0xa),
/// J716c (0xe) and J775c (0x10) M5 Max; J775d (0x12) M5 Ultra.
pub fn fuses(chip_id: u32, board_id: u32) -> Option<Fuses> {
    if chip_id != CHIP_ID {
        return None;
    }
    match board_id {
        0x02 | 0x08 | 0x0c => Some(PRO),
        0x0a | 0x0e | 0x10 => Some(MAX),
        0x12 => Some(ULTRA),
        _ => None,
    }
}

/// iBoot's reading of `fuses` (`0x50674`, `0x50a5c`, `0x7b81c`).
pub fn decode(fuses: Fuses) -> Result<Variant> {
    let name = match fuses.die_configuration {
        [MAX_DIE, MAX_DIE] => match fuses.disabled_mccs {
            0 => "h17c",
            0xff00_0000 => "h17cr1",
            0xff00 => "h17cr2",
            other => bail!("disabled-MCC fuse {other:#x} names no Max variant"),
        },
        [OTHER_DIE, MAX_DIE] => "h17s",
        [MAX_DIE, OTHER_DIE] => "h17d",
        [low, high] => bail!("die-configuration fuses {low:#x}, {high:#x} name no variant"),
    };
    let mccs = match fuses.disabled_mccs {
        0 => 0xff,
        0xff00_0000 => 0x3f,
        0xffff_0000 => 0x0f,
        0xff00 => 0xf3,
        other => bail!("disabled-MCC fuse {other:#x} names no MCC set"),
    };
    Ok(Variant {
        name,
        dies: if name == "h17d" { 2 } else { 1 },
        mccs,
        fuses,
    })
}

fn decision(path: &str, property: &str, value: &[u8], source: String) -> Decision {
    Decision {
        path: path.into(),
        property: property.into(),
        value_hex: hex::encode(value),
        source,
    }
}

/// Selects the variant of a board with `chip_id` and `board_id` whose
/// template carries `/:sotra`, as iBoot does: merges its overlays, removes
/// the group, and writes the CPU and MCC rows. `None` for any other board.
pub fn apply(
    tree: &mut DeviceTree,
    chip_id: Option<u32>,
    board_id: Option<u32>,
) -> Result<Option<(Variant, Vec<Decision>)>> {
    if chip_id != Some(CHIP_ID) || tree.root.child(GROUP).is_none() {
        return Ok(None);
    }
    let fuses = board_id
        .and_then(|board| fuses(CHIP_ID, board))
        .with_context(|| format!("ApBoardID {board_id:x?} has no ApChipID {CHIP_ID:#x} fuses"))?;
    let variant = decode(fuses)?;
    ensure!(
        tree.property(&format!("/{VERSION}"), "version")
            .and_then(|version| version.as_u32())
            == Some(1),
        "/{VERSION} version is not 1"
    );
    let options = tree
        .property(&format!("/{GROUP}"), "option")
        .context("/:sotra has no option")?;
    ensure!(
        options
            .value
            .split(|&byte| byte == 0)
            .any(|option| option == variant.name.as_bytes()),
        "/{GROUP} option does not list {}",
        variant.name
    );
    let merged = merge(&mut tree.root, &format!("{OVERLAY}{}_", variant.name))?;
    tree.root
        .children
        .retain(|node| !matches!(node.name(), Some(GROUP | VERSION)));
    let mut decisions = vec![decision(
        &format!("/{GROUP}"),
        "option",
        variant.name.as_bytes(),
        format!(
            "the fuses' variant: {merged} overlays merged, the group, /{VERSION} and the other \
             variants' overlays removed"
        ),
    )];
    decisions.extend(prune_cpus(tree, variant.dies)?);
    decisions.extend(mcc_rows(tree, &variant)?);
    Ok(Some((variant, decisions)))
}

/// Merges every overlay below `node` whose name starts with `prefix` into
/// its parent and drops the other variants'; returns the number merged.
fn merge(node: &mut Node, prefix: &str) -> Result<usize> {
    let mut merged = 0;
    let mut overlays = vec![];
    let mut kept = vec![];
    for mut child in core::mem::take(&mut node.children) {
        match child.name() {
            Some(name) if name.starts_with(prefix) => overlays.push(child),
            Some(name) if name.starts_with(OVERLAY) => {}
            _ => {
                merged += merge(&mut child, prefix)?;
                kept.push(child);
            }
        }
    }
    node.children = kept;
    for overlay in overlays {
        for property in overlay.properties {
            let name = property.name();
            if name == "name" || name.starts_with("AAPL,") {
                continue;
            }
            match node.property_mut(name) {
                Some(existing) => existing.value.extend_from_slice(&property.value),
                None => node.properties.push(property),
            }
        }
        for child in overlay.children {
            let name = child.name().unwrap_or_default();
            ensure!(
                node.child(name).is_none(),
                "overlay child {name} is already a node"
            );
            node.children.push(child);
        }
        merged += 1;
    }
    Ok(merged)
}

fn u32_value(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// Deletes the CPUs of absent dies and counts the rest (`0x40a0c..`).
fn prune_cpus(tree: &mut DeviceTree, dies: u32) -> Result<Vec<Decision>> {
    let cpus = tree.node_mut(CPUS).context("no /cpus")?;
    let die = |cpu: &Node| cpu.property("die-id").and_then(|die| die.as_u32());
    ensure!(
        cpus.children.iter().all(|cpu| die(cpu).is_some()),
        "a /cpus node has no die-id"
    );
    cpus.children
        .retain(|cpu| die(cpu).is_some_and(|die| die < dies));
    let mut clusters = vec![];
    let (mut m, mut p) = (0u32, 0u32);
    for cpu in &cpus.children {
        let cluster = (
            die(cpu),
            cpu.property("cluster-id").and_then(|id| id.as_u32()),
        );
        if !clusters.contains(&cluster) {
            clusters.push(cluster);
        }
        match cpu.property("cluster-type").map(|kind| kind.value.first()) {
            Some(Some(b'M')) => m += 1,
            Some(Some(b'P')) => p += 1,
            _ => bail!("{} is neither an M nor a P core", cpu.name().unwrap_or("?")),
        }
    }
    let total = u32::try_from(cpus.children.len())?;
    let source = format!("the fused cores of {dies} die(s)");
    let mut decisions = vec![];
    for (property, count) in [
        ("max_cpus", total),
        ("cpu-cluster-count", u32::try_from(clusters.len())?),
        ("m-core-count", m),
        ("p-core-count", p),
    ] {
        let value = u32_value(count);
        decisions.push(decision(CPUS, property, &value, source.clone()));
        tree.set_property(CPUS, property, value)?;
    }
    Ok(decisions)
}

/// The MCC rows of `0x40b78..0x40c38`.
fn mcc_rows(tree: &mut DeviceTree, variant: &Variant) -> Result<Vec<Decision>> {
    ensure!(tree.node(MCC).is_some(), "no {MCC}");
    let mut rows = vec![
        (
            "dcs-channel-enable-mask",
            !variant.fuses.disabled_mccs,
            "the disabled-MCC fuse inverted",
        ),
        ("amcc-enable-mask", variant.mccs, "the enabled MCCs"),
        (
            "die-enable-mask",
            if variant.dies == 2 { 3 } else { 1 },
            "the fused dies",
        ),
    ];
    if variant.dies == 2 && !variant.fuses.rank_drop {
        rows.push(("rank-drop-mask", 0, "the rank-drop fuse clear"));
    }
    let mut decisions = vec![];
    for (property, value, source) in rows {
        let value = u32_value(value);
        decisions.push(decision(MCC, property, &value, source.into()));
        tree.set_property(MCC, property, value)?;
    }
    Ok(decisions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fuses_select_iboots_variants() {
        let variant = |fuses| decode(fuses).unwrap();
        assert_eq!(
            (variant(PRO).name, variant(PRO).dies, variant(PRO).mccs),
            ("h17s", 1, 0x0f)
        );
        assert_eq!(
            (variant(MAX).name, variant(MAX).dies, variant(MAX).mccs),
            ("h17c", 1, 0xff)
        );
        assert_eq!(
            (
                variant(ULTRA).name,
                variant(ULTRA).dies,
                variant(ULTRA).mccs
            ),
            ("h17d", 2, 0xff)
        );
        for (disabled, name, mccs) in [(0xff00_0000, "h17cr1", 0x3f), (0xff00, "h17cr2", 0xf3)] {
            let binned = variant(Fuses {
                disabled_mccs: disabled,
                ..MAX
            });
            assert_eq!((binned.name, binned.mccs), (name, mccs));
        }
        assert!(
            decode(Fuses {
                disabled_mccs: 1,
                ..MAX
            })
            .is_err()
        );
        assert!(
            decode(Fuses {
                die_configuration: [OTHER_DIE, OTHER_DIE],
                ..MAX
            })
            .is_err()
        );
        assert_eq!(fuses(CHIP_ID, 0x08), Some(PRO));
        assert_eq!(fuses(CHIP_ID, 0x12), Some(ULTRA));
        assert_eq!(fuses(0x6041, 0x08), None);
        assert_eq!(fuses(CHIP_ID, 0x04), None);
    }

    fn named(name: &str, properties: &[(&str, &[u8])], children: Vec<Node>) -> Node {
        let mut node = Node::named(name).unwrap();
        for (property, value) in properties {
            node.set_property(property, value.to_vec()).unwrap();
        }
        node.set_property("AAPL,phandle", vec![9, 0, 0, 0]).unwrap();
        node.children = children;
        node
    }

    fn cpu(index: u32, die: u32, cluster: u32, kind: u8) -> Node {
        named(
            &format!("cpu{index}"),
            &[
                ("die-id", &die.to_le_bytes()),
                ("cluster-id", &cluster.to_le_bytes()),
                ("cluster-type", &[kind, 0]),
            ],
            vec![],
        )
    }

    fn template() -> DeviceTree {
        let overlay = |variant: &str, n: u32, properties: &[(&str, &[u8])], children| {
            named(&format!(":sotra_{variant}_{n}"), properties, children)
        };
        let product = named(
            "product",
            &[],
            vec![
                overlay("h17s", 1, &[("product-soc-name", b"S\0")], vec![]),
                overlay("h17c", 2, &[("product-soc-name", b"C\0")], vec![]),
                overlay("h17d", 3, &[("product-soc-name", b"D\0")], vec![]),
            ],
        );
        let mcc = named(
            "mcc",
            &[("reg", &[1, 2])],
            vec![
                overlay("h17s", 4, &[("reg", &[3])], vec![]),
                overlay(
                    "h17d",
                    5,
                    &[("reg", &[4, 5]), ("rank-drop-mask", &[8, 0, 0, 0])],
                    vec![],
                ),
            ],
        );
        let arm_io = named(
            "arm-io",
            &[],
            vec![
                mcc,
                overlay("h17d", 6, &[], vec![named("apr1", &[], vec![])]),
            ],
        );
        let cpus = named(
            "cpus",
            &[],
            vec![
                cpu(0, 0, 0, b'M'),
                cpu(1, 0, 1, b'P'),
                cpu(2, 1, 16, b'M'),
                cpu(3, 1, 17, b'P'),
            ],
        );
        let mut root = Node::named("device-tree").unwrap();
        root.children = vec![
            named(
                ":sotra",
                &[("option", b"h17s\0h17c\0h17cr1\0h17cr2\0h17d")],
                vec![],
            ),
            named(":version", &[("version", &1u32.to_le_bytes())], vec![]),
            product,
            arm_io,
            cpus,
        ];
        DeviceTree { root }
    }

    fn word(tree: &DeviceTree, path: &str, property: &str) -> Option<u32> {
        tree.property(path, property)?.as_u32()
    }

    #[test]
    fn a_pro_board_takes_the_h17s_overlays_and_one_die() {
        let mut tree = template();
        let (variant, decisions) = apply(&mut tree, Some(CHIP_ID), Some(0x08))
            .unwrap()
            .unwrap();
        assert_eq!(variant.name, "h17s");
        assert_eq!(
            tree.property("/product", "product-soc-name").unwrap().value,
            b"S\0"
        );
        assert!(tree.node("/product").unwrap().children.is_empty());
        assert_eq!(tree.property(MCC, "reg").unwrap().value, [1, 2, 3]);
        assert!(tree.property(MCC, "rank-drop-mask").is_none());
        assert!(tree.node("/arm-io/apr1").is_none());
        assert!(tree.node("/:sotra").is_none() && tree.node("/:version").is_none());
        assert_eq!(tree.node(CPUS).unwrap().children.len(), 2);
        assert_eq!(word(&tree, CPUS, "max_cpus"), Some(2));
        assert_eq!(word(&tree, CPUS, "cpu-cluster-count"), Some(2));
        assert_eq!(word(&tree, CPUS, "m-core-count"), Some(1));
        assert_eq!(word(&tree, CPUS, "p-core-count"), Some(1));
        assert_eq!(word(&tree, MCC, "amcc-enable-mask"), Some(0x0f));
        assert_eq!(word(&tree, MCC, "dcs-channel-enable-mask"), Some(0xffff));
        assert_eq!(word(&tree, MCC, "die-enable-mask"), Some(1));
        assert!(
            decisions
                .iter()
                .any(|row| row.property == "amcc-enable-mask")
        );
    }

    #[test]
    fn an_ultra_board_takes_both_dies_and_the_second_dies_nodes() {
        let mut tree = template();
        let (variant, _) = apply(&mut tree, Some(CHIP_ID), Some(0x12))
            .unwrap()
            .unwrap();
        assert_eq!((variant.name, variant.dies), ("h17d", 2));
        assert_eq!(
            tree.property("/product", "product-soc-name").unwrap().value,
            b"D\0"
        );
        assert_eq!(tree.property(MCC, "reg").unwrap().value, [1, 2, 4, 5]);
        assert_eq!(word(&tree, MCC, "rank-drop-mask"), Some(8));
        assert!(tree.node("/arm-io/apr1").is_some());
        assert_eq!(word(&tree, CPUS, "max_cpus"), Some(4));
        assert_eq!(word(&tree, CPUS, "cpu-cluster-count"), Some(4));
        assert_eq!(word(&tree, MCC, "die-enable-mask"), Some(3));
        assert_eq!(word(&tree, MCC, "dcs-channel-enable-mask"), Some(u32::MAX));
    }

    #[test]
    fn other_boards_and_bad_templates_are_left_or_refused() {
        let mut tree = template();
        assert!(
            apply(&mut tree, Some(0x6041), Some(0x08))
                .unwrap()
                .is_none()
        );
        assert_eq!(tree, template());
        assert!(apply(&mut tree, Some(CHIP_ID), Some(0x04)).is_err());
        assert!(apply(&mut tree, Some(CHIP_ID), None).is_err());
        tree.set_property("/:version", "version", 2u32.to_le_bytes().to_vec())
            .unwrap();
        assert!(apply(&mut tree, Some(CHIP_ID), Some(0x08)).is_err());
        let mut tree = template();
        tree.set_property("/:sotra", "option", b"h17c\0".to_vec())
            .unwrap();
        assert!(apply(&mut tree, Some(CHIP_ID), Some(0x08)).is_err());
        let mut tree = template();
        tree.root
            .children
            .retain(|node| node.name() != Some(":sotra"));
        assert!(
            apply(&mut tree, Some(CHIP_ID), Some(0x08))
                .unwrap()
                .is_none()
        );
    }
}
