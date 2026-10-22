//! DeviceTree placement and validation for pmp topology.
use super::{ASC, Node, String, apertures, asc, rtbuddy_nub};

/// The PMP's DT placement: `reg[0]` is the ASC wrapper and its four
/// interrupts the mailbox lines. Its nub is `user-power-managed`; the
/// PTD bank that `ptd-update-reg-index` names is [`MemoryCache`]'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmpController {
    pub wrapper: (u64, u64),
    pub interrupts: [u16; 4],
    pub quiesced: bool,
}

pub(super) fn pmp_controller(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Option<PmpController>, String> {
    let Some(node) = io
        .child("pmp")
        .filter(|n| n.compatible(ASC) && n.property("role") == Some(b"PMP\0".as_slice()))
    else {
        return Ok(None);
    };
    let nub = rtbuddy_nub(&node, "PMP")?;
    if nub.first_u32("user-power-managed") != Some(1) {
        return Err("PMP nub is not user-power-managed".into());
    }
    let &(offset, bytes) = apertures::registers(&node)
        .ok_or("PMP has no reg pairs")?
        .first()
        .filter(|(_, bytes)| *bytes >= asc::WRAPPER_BYTES)
        .ok_or("PMP wrapper bank is absent or too short")?;
    let physical = translate(offset, bytes).ok_or("PMP wrapper outside arm-io ranges")?;
    let irqs = node.cells32("interrupts").ok_or("PMP has no interrupts")?;
    let irq = |index: usize| -> Result<u16, String> {
        irqs.get(index)
            .and_then(|&n| u16::try_from(n).ok())
            .ok_or_else(|| "PMP needs four valid mailbox interrupts".into())
    };
    Ok(Some(PmpController {
        wrapper: (physical, bytes),
        interrupts: [irq(0)?, irq(1)?, irq(2)?, irq(3)?],
        quiesced: nub.property("quiesced").is_some(),
    }))
}

#[cfg(test)]
mod tests {
    use super::super::tests::flat_fixture_extent;
    use super::super::*;
    use super::*;

    #[test]
    fn pmp_placement_reads_its_wrapper_and_needs_a_user_managed_nub() {
        use crate::machine::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        let tree = |managed: u32| {
            let nub = encode(
                &[
                    ("name", &z("iop-pmp-nub")),
                    ("compatible", &z(RTBUDDY)),
                    ("user-power-managed", &cells(&[managed])),
                ],
                &[],
            );
            let pmp = encode(
                &[
                    ("name", &z("pmp")),
                    ("compatible", &z(ASC)),
                    ("role", &z("PMP")),
                    (
                        "reg",
                        &pairs(&[
                            (0x3bc0_0000, 0x6c000),
                            (0x3b85_0000, 0x4000),
                            (0x3b50_0000, 0x80000),
                            (0x3b3d_0000, 0x4000),
                        ]),
                    ),
                    ("interrupts", &cells(&[0x275, 0x274, 0x277, 0x276])),
                ],
                &[nub],
            );
            let io = encode(&[("name", &z("arm-io"))], &[pmp]);
            encode(&[("name", &z("device-tree"))], &[io])
        };
        let translate = |v: u64| v.checked_add(0x2_0000_0000);
        let data = tree(1);
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        assert_eq!(
            pmp_controller(&io, &flat_fixture_extent(&translate)).unwrap(),
            Some(PmpController {
                wrapper: (0x2_3bc0_0000, 0x6c000),
                interrupts: [0x275, 0x274, 0x277, 0x276],
                quiesced: false,
            })
        );
        let data = tree(0);
        let root = Node::root(&data).unwrap();
        assert!(
            pmp_controller(
                &root.child("arm-io").unwrap(),
                &flat_fixture_extent(&translate)
            )
            .is_err()
        );
        assert!(models(ASC, |key| (key == "role").then_some(b"PMP\0".as_slice())));
    }
}
