//! DeviceTree placement and validation for sep topology.
use super::dma_routes::native_mapper_input;
use super::{Iommu, Node, SEP, SEP_NUB, String, apertures, format};

/// SEP's DT-placed register banks, four mailbox IRQs, DART stream and optional
/// iBoot SEPFW source extent. The extent is not proof of firmware acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SepDevice {
    pub ranges: [(u64, u64); 2],
    pub irqs: [u32; 4],
    pub iommu: usize,
    /// Explicit selection of the sole original TRAD, independent of SID count.
    pub instance: usize,
    /// Actual iommu-parent owner and OS context, before native incoming remap.
    pub mapper: u32,
    pub mapper_context: u32,
    pub stream: u32,
    pub firmware: Option<(u64, u64)>,
    /// The AP's effective production status and security mode in `/chosen`,
    /// which the SEP, sharing its fuses, reports as its own.
    pub security: Option<crate::platform::apple::sep::SecurityMode>,
    /// The machine's `/chosen` `unique-chip-id` (Stela's per-machine ECID,
    /// set at setup and written by bundle preparation), bound into the SEP
    /// key hierarchy. `None` when `/chosen` does not carry it.
    pub ecid: Option<u64>,
}

/// J473AP `/arm-io/sep` supplies two ranges and four mailbox lines. Its
/// `iommu-parent` is mapper-sep stream 0; `reg` addresses use arm-io ranges.
/// `AppleSEPManager::start` obtains that mapper (kernel file 0x2d66f64).
pub(super) fn sep_device(
    root: &Node<'_>,
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    darts: &[Iommu],
) -> Result<Option<SepDevice>, String> {
    let Some(node) = io.child("sep").filter(|node| node.compatible(SEP)) else {
        return Ok(None);
    };
    const PATH: &str = "/arm-io/sep";
    if node.property("aarch64").is_none() || node.first_u32("iop-version") != Some(1) {
        return Err(format!("{PATH} requires the modeled AArch64 IOP version 1"));
    }
    if !node
        .child("iop-sep-nub")
        .is_some_and(|nub| nub.compatible(SEP_NUB))
    {
        return Err(format!(
            "{PATH} requires an iop-nub,sep; RTBuddy is not the SEP protocol"
        ));
    }
    let reg = apertures::registers(&node).unwrap_or_default();
    let &[first, second] = reg.as_slice() else {
        return Err(format!("{PATH} requires two register ranges"));
    };
    if first.1 < crate::platform::apple::asc::WRAPPER_BYTES || second.1 == 0 {
        return Err(format!("{PATH} has an incomplete register aperture"));
    }
    let place = |(offset, bytes): (u64, u64)| -> Result<_, String> {
        let physical = translate(offset, bytes)
            .ok_or_else(|| format!("{PATH} lies outside /arm-io ranges"))?;
        Ok((physical, bytes))
    };
    let irqs: [u32; 4] = node
        .cells32("interrupts")
        .unwrap_or_default()
        .try_into()
        .map_err(|_| format!("{PATH} requires four mailbox interrupts"))?;
    if irqs.iter().any(|&irq| u16::try_from(irq).is_err()) {
        return Err(format!(
            "{PATH} mailbox interrupt is outside the AIC input encoding"
        ));
    }
    let parent = node
        .property("iommu-parent")
        .ok_or_else(|| format!("{PATH} has no iommu-parent"))?;
    let parent: [u8; 4] = parent
        .try_into()
        .map_err(|_| format!("{PATH} iommu-parent is not one phandle"))?;
    let parent = u32::from_le_bytes(parent);
    if parent == 0 {
        return Err(format!("{PATH} iommu-parent is zero"));
    }
    let mut matches = darts.iter().enumerate().flat_map(|(index, dart)| {
        dart.mappers
            .iter()
            .filter(move |(phandle, _)| *phandle == parent)
            .map(move |&(_, context)| (index, dart, context))
    });
    let (iommu, dart, mapper_context) = matches
        .next()
        .ok_or_else(|| format!("{PATH} iommu-parent is no modeled DART's mapper"))?;
    if matches.next().is_some() {
        return Err(format!("{PATH} mapper ownership is ambiguous"));
    }
    if dart.instances.len() != 1 {
        return Err(format!(
            "{PATH} DMA owner requires explicit multiple-TRAD selection"
        ));
    }
    if !dart.sids.is_empty() && !dart.sids.contains(&mapper_context) {
        return Err(format!(
            "{PATH} mapper context is absent from the original SID set"
        ));
    }
    let stream =
        native_mapper_input(dart, mapper_context).map_err(|why| format!("{PATH} {why}"))?;
    let firmware = root
        .child("chosen")
        .and_then(|n| n.child("memory-map"))
        .and_then(|n| n.property("SEPFW"))
        .map(|bytes| {
            let cells: &[u8; 16] = bytes
                .try_into()
                .map_err(|_| String::from("SEPFW is not a base/length pair"))?;
            let base = u64::from_le_bytes(cells[..8].try_into().expect("base"));
            let length = u64::from_le_bytes(cells[8..].try_into().expect("length"));
            if length == 0 || base.checked_add(length).is_none() {
                return Err(String::from("SEPFW has an empty or overflowing extent"));
            }
            Ok((base, length))
        })
        .transpose()?;
    let chosen = root.child("chosen");
    let flag = |name| {
        chosen
            .as_ref()
            .and_then(|n| n.first_u32(name))
            .map(|value| value != 0)
    };
    let security = flag("effective-production-status-ap")
        .zip(flag("effective-security-mode-ap"))
        .map(
            |(production, secure)| crate::platform::apple::sep::SecurityMode { production, secure },
        );
    let ecid = chosen
        .as_ref()
        .and_then(|n| n.first_u64("unique-chip-id"))
        .filter(|&value| value != 0);
    Ok(Some(SepDevice {
        ranges: [place(first)?, place(second)?],
        irqs,
        iommu,
        instance: 0,
        mapper: parent,
        mapper_context,
        stream,
        firmware,
        security,
        ecid,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{flat_fixture_extent, tree_with_io};
    use super::super::*;
    use super::*;

    #[test]
    fn sep_placement_uses_the_native_nub_and_is_admitted_by_its_sep_role() {
        use stela_contracts::adt::encode;
        const MODELED: [&str; 3] = [UART, WATCHDOG, "aic,2"];
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let words = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |cells: &[u64]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let tree = |nub: &str, irqs: &[u32], parent: u32, stream: u32| {
            let mapper = encode(
                &[
                    ("name", &z("mapper-sep")),
                    ("compatible", &z(IOMMU_MAPPER)),
                    ("reg", &words(&[stream])),
                    ("AAPL,phandle", &words(&[0x84])),
                ],
                &[],
            );
            let dart = encode(
                &[
                    ("name", &z("dart-sep")),
                    ("compatible", &z(DART)),
                    ("reg", &pairs(&[0x5d2c0000, 0x4000])),
                    ("sid-count", &words(&[1])),
                    ("instance", b"TRAD\0\0\0\0DART\0\0\0\0"),
                    ("interrupts", &words(&[0x11a])),
                ],
                &[mapper],
            );
            let nub = encode(&[("name", &z("iop-sep-nub")), ("compatible", &z(nub))], &[]);
            let sep = encode(
                &[
                    ("name", &z("sep")),
                    ("compatible", &z(SEP)),
                    ("aarch64", &[]),
                    ("iop-version", &words(&[1])),
                    ("iommu-parent", &words(&[parent])),
                    ("interrupts", &words(irqs)),
                    ("reg", &pairs(&[0x5e400000, 0x6c000, 0x5e050000, 0x60000])),
                ],
                &[nub],
            );
            tree_with_io(0x8112, "Apple M2", MODELED, &[], &[dart, sep])
        };
        let irqs = [0x115, 0x114, 0x117, 0x116];
        let bytes = tree(SEP_NUB, &irqs, 0x84, 0);
        let found = board(&bytes).unwrap();
        assert_eq!(
            found.sep,
            Some(SepDevice {
                ranges: [(0x25e400000, 0x6c000), (0x25e050000, 0x60000)],
                irqs,
                iommu: 0,
                instance: 0,
                mapper: 0x84,
                mapper_context: 0,
                stream: 0,
                firmware: None,
                security: None,
                ecid: None,
            })
        );
        assert_eq!(found.darts[0].instances[0].physical, 0x25d2c0000);
        // A sole TRAD's SID capacity is independent of the selected context.
        // Incoming source5 -> context4 remains an explicit native route.
        let root = Node::root(&bytes).unwrap();
        let io = root.child("arm-io").unwrap();
        let place = |darts: &[Iommu]| {
            sep_device(
                &root,
                &io,
                &flat_fixture_extent(&|v| Some(v + 0x200000000)),
                darts,
            )
            .map(|sep| sep.unwrap())
        };
        let mut routed = found.darts.clone();
        routed[0].profile = stela_soc_data::dart::Profile::T6000;
        routed[0].streams = 16;
        routed[0].sids = alloc::vec![0, 4, 15];
        routed[0].mappers = alloc::vec![(0x84, 4)];
        routed[0].remap = alloc::vec![(5, 4)];
        let route = place(&routed).unwrap();
        assert_eq!(
            (
                route.instance,
                route.mapper,
                route.mapper_context,
                route.stream
            ),
            (0, 0x84, 4, 5)
        );
        let good = routed[0].clone();
        routed[0].remap.clear();
        assert_eq!(
            (
                place(&routed).unwrap().mapper_context,
                place(&routed).unwrap().stream
            ),
            (4, 4)
        );
        routed[0] = good.clone();
        routed[0].mappers.push((0x84, 0));
        assert!(place(&routed).unwrap_err().contains("ambiguous"));
        routed[0] = good.clone();
        routed.push(good.clone());
        assert!(place(&routed).unwrap_err().contains("ambiguous"));
        routed.pop();
        routed[0] = good.clone();
        routed[0].instances.push(good.instances[0].clone());
        assert!(place(&routed).unwrap_err().contains("multiple-TRAD"));
        routed[0].instances.clear();
        assert!(place(&routed).unwrap_err().contains("multiple-TRAD"));
        routed[0] = good.clone();
        routed[0].sids = alloc::vec![0, 15];
        assert!(place(&routed).unwrap_err().contains("SID set"));
        routed[0] = good.clone();
        routed[0].mappers[0].1 = 16;
        routed[0].sids.push(16);
        assert!(
            place(&routed)
                .unwrap_err()
                .contains("outside the native profile")
        );
        routed[0] = good.clone();
        routed[0].mappers[0].1 = 5;
        routed[0].sids.push(5);
        assert!(
            place(&routed)
                .unwrap_err()
                .contains("incoming remapped source")
        );
        routed[0] = good;
        routed[0].profile = stela_soc_data::dart::Profile::T8110;
        assert_eq!(place(&routed).unwrap().stream, 5);
        // Admitted only with its distinguishing `role = SEP`; the nub is kept
        // as a modeled child, and neither is a bare flat-list compatible.
        let sep_role = |key: &str| (key == "role").then_some(b"SEP\0".as_slice());
        assert!(models(SEP, sep_role));
        assert!(!models(SEP, |_| None));
        assert!(!models(SEP_NUB, |_| None));
        assert_eq!(
            model_children(SEP, sep_role)
                .iter()
                .map(|child| child.compatible)
                .collect::<Vec<_>>(),
            [SEP_NUB]
        );
        assert!(board(&tree("iop-nub,rtbuddy-v2", &irqs, 0x84, 0)).is_err());
        assert!(board(&tree(SEP_NUB, &irqs[..3], 0x84, 0)).is_err());
        assert!(board(&tree(SEP_NUB, &irqs, 0x85, 0)).is_err());
        assert!(
            board(&tree(SEP_NUB, &irqs, 0, 0))
                .unwrap_err()
                .contains("iommu-parent is zero")
        );
        assert!(board(&tree(SEP_NUB, &irqs, 0x84, 1)).is_err());
        let root = Node::root(&bytes).unwrap();
        let io = root.child("arm-io").unwrap();
        let memory_map =
            |cells: &[u64]| encode(&[("name", &z("memory-map")), ("SEPFW", &pairs(cells))], &[]);
        let root_with_region = |cells: &[u64]| {
            encode(
                &[("name", &z("device-tree"))],
                &[encode(&[("name", &z("chosen"))], &[memory_map(cells)])],
            )
        };
        let region = root_with_region(&[0x81fd54000, 0x5dc000]);
        let placed = sep_device(
            &Node::root(&region).unwrap(),
            &io,
            &flat_fixture_extent(&|v| Some(v + 0x200000000)),
            &found.darts,
        )
        .unwrap()
        .unwrap();
        assert_eq!(placed.firmware, Some((0x81fd54000, 0x5dc000)));
        for cells in [&[0x81fd54000][..], &[0x81fd54000, 0], &[u64::MAX, 2]] {
            let region = root_with_region(cells);
            assert!(
                sep_device(
                    &Node::root(&region).unwrap(),
                    &io,
                    &flat_fixture_extent(&|v| Some(v + 0x200000000)),
                    &found.darts
                )
                .is_err()
            );
        }
    }
}
