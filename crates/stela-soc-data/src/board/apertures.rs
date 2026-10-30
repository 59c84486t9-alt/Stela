//! Physical-controller extent witnesses; slave protocol registers stay local.
use super::Node;
use alloc::vec::Vec;

type Extent<'a> = dyn Fn(u64, u64) -> Option<u64> + 'a;
type Visitor<'a> = dyn FnMut(&Node<'_>, &Extent<'_>) + 'a;

pub(super) fn registers(node: &Node<'_>) -> Option<Vec<(u64, u64)>> {
    let raw = node.property("reg")?;
    if raw.is_empty() || !raw.len().is_multiple_of(16) {
        return None;
    }
    node.pairs("reg")
}

/// Visit in ADT order while keeping every intervening bus's ranges.
/// The supplied root extent capability belongs to `io` itself. A node's own
/// `reg` uses its parent's domain; its `ranges` affects only its descendants.
/// No range decoder or identity fallback is added: each nested translation
/// uses Node::translate_range, then reaches the root's complete witness.
pub(super) fn visit(
    io: &Node<'_>,
    root: &dyn Fn(u64, u64) -> Option<u64>,
    visitor: &mut Visitor<'_>,
) -> Option<()> {
    fn walk<'a>(
        node: &Node<'a>,
        nested: &mut Vec<Node<'a>>,
        root: &dyn Fn(u64, u64) -> Option<u64>,
        visitor: &mut Visitor<'_>,
        is_root: bool,
        protocol: bool,
    ) -> Option<()> {
        let translate = |mut offset: u64, bytes: u64| {
            if protocol {
                return None;
            }
            for bus in nested.iter().rev() {
                offset = bus.translate_range(offset, bytes)?;
            }
            root(offset, bytes)
        };
        visitor(node, &translate);
        let domain = !is_root && node.property("ranges").is_some();
        if domain {
            nested.push(node.clone());
        }
        // An endpoint's slave coordinates need their own checked mapping.
        // A registerless structural node can remain in its ancestor domain;
        // an explicit child bus/endpoint cannot silently inherit root MMIO.
        let unqualified_children = node.property("ranges").is_none()
            && (node.property("reg").is_some() || node.property("#address-cells").is_some());
        let child_protocol = protocol
            || unqualified_children
            || [super::I2C, super::SPI, super::SPMI]
                .iter()
                .any(|kind| node.compatible(kind));
        for child in node.children()? {
            walk(&child, nested, root, visitor, false, child_protocol)?;
        }
        if domain {
            nested.pop();
        }
        Some(())
    }
    walk(io, &mut Vec::new(), root, visitor, true, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use stela_contracts::adt::encode;

    fn ranges(rows: &[(u64, u64, u64)]) -> Vec<u8> {
        rows.iter()
            .flat_map(|&(child, parent, bytes)| [child, parent, bytes])
            .flat_map(u64::to_le_bytes)
            .collect()
    }
    #[test]
    fn controller_reg_uses_parent_and_nested_bus_ranges_compose_inside_out() {
        let leaf = encode(
            &[
                ("name", b"leaf"),
                ("reg", &ranges(&[(0x40, 0x10, 0)])[..16]),
            ],
            &[],
        );
        let bus = encode(
            &[
                ("name", b"bus"),
                ("ranges", &ranges(&[(0, 0x800, 0x100)])),
                ("reg", &0x100u64.to_le_bytes().repeat(2)),
            ],
            &[leaf],
        );
        let bytes = encode(
            &[
                ("name", b"arm-io"),
                ("ranges", &ranges(&[(0, 0x200000000, 0x1000)])),
            ],
            &[bus],
        );
        let io = Node::root(&bytes).unwrap();
        let mut seen = Vec::new();
        visit(&io, &|a, b| io.translate_range(a, b), &mut |node, path| {
            if let Some(regs) = registers(node) {
                let (offset, bytes) = regs[0];
                seen.push((super::super::name_of(node), path(offset, bytes)));
            }
        })
        .unwrap();
        assert_eq!(
            seen,
            [
                ("bus".into(), Some(0x200000100)),
                ("leaf".into(), Some(0x200000840))
            ]
        );
    }
    #[test]
    fn a_nested_gap_never_becomes_an_arm_io_identity_extent() {
        let raw = [0u64, 0x30]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let leaf = encode(&[("name", b"leaf"), ("reg", &raw)], &[]);
        for rows in [
            vec![(0, 0x100, 0x10), (0x20, 0x120, 0x10)],
            vec![(0, 0x100, 0x10), (0x10, 0x200, 0x20)],
        ] {
            let bus = encode(&[("ranges", &ranges(&rows))], core::slice::from_ref(&leaf));
            let bytes = encode(&[("ranges", &ranges(&[(0, 0x200000000, 0x1000)]))], &[bus]);
            let io = Node::root(&bytes).unwrap();
            let mut result = Some(1);
            visit(&io, &|a, b| io.translate_range(a, b), &mut |node, path| {
                if registers(node).is_some() {
                    result = path(0, 0x30)
                }
            })
            .unwrap();
            assert_eq!(result, None);
        }
    }
    #[test]
    fn physical_register_rows_require_complete_pairs() {
        for raw in [vec![], vec![0; 15], vec![0; 17]] {
            let bytes = encode(&[("reg", &raw)], &[]);
            assert!(registers(&Node::root(&bytes).unwrap()).is_none());
        }
    }
    #[test]
    fn slave_registers_are_not_reinterpreted_as_parent_mmio() {
        let reg = [0u64, 0x100]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let slave = encode(&[("name", b"slave"), ("reg", &reg)], &[]);
        for kind in [
            super::super::I2C,
            super::super::SPI,
            super::super::SPMI,
            "unqualified-endpoint",
        ] {
            let controller = encode(
                &[
                    ("name", b"controller"),
                    ("compatible", kind.as_bytes()),
                    ("reg", &reg),
                ],
                core::slice::from_ref(&slave),
            );
            let bytes = encode(
                &[("ranges", &ranges(&[(0, 0x200000000, 0x1000)]))],
                &[controller],
            );
            let io = Node::root(&bytes).unwrap();
            let mut observed = Vec::new();
            visit(&io, &|a, b| io.translate_range(a, b), &mut |node, path| {
                if let Some(regs) = registers(node) {
                    observed.push(path(regs[0].0, regs[0].1));
                }
            })
            .unwrap();
            assert_eq!(observed, [Some(0x200000000), None]);
        }
    }
}
