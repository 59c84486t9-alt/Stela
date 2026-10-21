//! Original PMGR graph and complete resource inventory. A logical IOMMU
//! mapper is a view of its ancestor DART's stream state, not another power
//! island. Registerless USB root-port views likewise belong to their USB
//! controller. Conversely, sharing an iommu-parent does not make a DMA client's
//! controller part of the DART's physical supply. Hardware resources inherit
//! their ADT ancestors' gates, including nubs and firmware endpoints.
use super::{DART, IOMMU_MAPPER, Node, USB_DRD, name_of, pmgr};
use crate::platform::apple::pmgr::coverage::{self, Consumer, Domain, DomainId, LifecycleSinks};
use alloc::{format, string::String, vec::Vec};

/// Bytes of one m1n1 `struct pmgr_device` record.
pub(super) const PMGR_DEVICE: usize = 48;
pub(super) const PMGR_VIRTUAL: u32 = 0x10;

/// Hardware owners, indexed in the board's corresponding placement vectors.
/// Logical mapper and root-port views share their actual controller owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerOwner {
    Dart(usize),
    Usb(usize),
}

/// One original resource with separate inherited clock/power requirements.
/// Other hardware still has no registered lifecycle sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerResource {
    pub name: String,
    pub clocks: Vec<DomainId>,
    pub power: Vec<DomainId>,
    pub owner: Option<PowerOwner>,
}

/// PMGR blocks, complete original domain graph and all original ADT resources,
/// including nodes whose admission/compatible was removed by the loader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerStates {
    pub blocks: Vec<(u64, u64)>,
    pub registers: Vec<u64>,
    pub domains: Vec<Domain>,
    pub resources: Vec<PowerResource>,
}

/// Current ADT PMGR format uses u16 device/parent IDs. Preserve all bits and
/// reject wider encodings instead of inventing die routing. The original
/// physical register address remains the authority for aliases.
pub(super) fn gate_ids(node: &Node<'_>, path: &str, property: &str) -> Result<Vec<u16>, String> {
    let bytes = node.property(property).unwrap_or_default();
    if !bytes.len().is_multiple_of(4) {
        return Err(format!("{path} {property} contains a partial device ID"));
    }
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| {
            u16::try_from(u32::from_le_bytes(*word))
                .map_err(|_| format!("{path} {property} exceeds PMGR device ID width"))
        })
        .collect()
}

fn domain_id(device: u16) -> DomainId {
    DomainId { die: 0, device }
}

fn inventory(root: &Node<'_>) -> Result<Vec<PowerResource>, String> {
    let path = if name_of(root) == "arm-io" {
        "/arm-io"
    } else {
        ""
    };
    let clocks = gate_ids(root, path, "clock-gates")?
        .into_iter()
        .map(domain_id)
        .collect::<Vec<_>>();
    let power = gate_ids(root, path, "power-gates")?
        .into_iter()
        .map(domain_id)
        .collect::<Vec<_>>();
    let mut resources = alloc::vec![PowerResource {
        name: if path.is_empty() {
            "/".into()
        } else {
            path.into()
        },
        clocks: clocks.clone(),
        power: power.clone(),
        owner: None,
    }];
    let mut pending = root
        .children()
        .ok_or("invalid resource tree")?
        .into_iter()
        .rev()
        .map(|node| {
            (
                String::from(path),
                node,
                clocks.clone(),
                power.clone(),
                None,
            )
        })
        .collect::<Vec<_>>();
    let mut darts = 0;
    let mut dart_streams = Vec::new();
    let mut usbs = 0;
    while let Some((parent, node, mut clocks, mut power, owner)) = pending.pop() {
        let path = format!("{parent}/{}", name_of(&node));
        clocks.extend(
            gate_ids(&node, &path, "clock-gates")?
                .into_iter()
                .map(domain_id),
        );
        power.extend(
            gate_ids(&node, &path, "power-gates")?
                .into_iter()
                .map(domain_id),
        );
        clocks.sort_unstable();
        clocks.dedup();
        power.sort_unstable();
        power.dedup();
        let owner = if path.starts_with("/arm-io/") && node.compatible(DART) {
            let index = darts;
            darts += 1;
            dart_streams.push(node.first_u32("sid-count").unwrap_or(0));
            Some(PowerOwner::Dart(index))
        } else if path.starts_with("/arm-io/") && node.compatible(USB_DRD) {
            let index = usbs;
            usbs += 1;
            Some(PowerOwner::Usb(index))
        } else if node.compatible(IOMMU_MAPPER)
            && node.first_u32("AAPL,phandle").is_some()
            && owner.is_some_and(|owner| match owner {
                PowerOwner::Dart(index) => node.first_u32("reg").is_some_and(|stream| stream < dart_streams[index]),
                PowerOwner::Usb(_) => false,
            })
            || node.property("reg").is_none()
                && node.property("compatible").is_none()
                && node.property("clock-gates").is_none()
                && node.property("power-gates").is_none()
                && node.first_u32("usb-port-number").is_some_and(|number| (1..=2).contains(&number))
                && matches!(owner, Some(PowerOwner::Usb(_)))
        {
            owner
        } else {
            None
        };
        resources.push(PowerResource {
            name: path.clone(),
            clocks: clocks.clone(),
            power: power.clone(),
            owner,
        });
        for child in node
            .children()
            .ok_or_else(|| format!("{path} has an invalid child"))?
            .into_iter()
            .rev()
        {
            pending.push((path.clone(), child, clocks.clone(), power.clone(), owner));
        }
    }
    Ok(resources)
}

pub(super) fn power_states(
    root: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    chip_id: u32,
) -> Result<Option<PowerStates>, String> {
    let io = root.child("arm-io");
    let io = io.as_ref().unwrap_or(root);
    let Some(node) = io
        .child("pmgr")
        .filter(|node| pmgr(chip_id).is_some_and(|model| node.compatible(model)))
    else {
        return Ok(None);
    };
    const PATH: &str = "/arm-io/pmgr";
    let reg = node.pairs("reg").unwrap_or_default();
    let raw_blocks = node.property("ps-regs").unwrap_or_default();
    let blocks = node.cells32("ps-regs").unwrap_or_default();
    let devices = node.property("devices").unwrap_or_default();
    if !raw_blocks.len().is_multiple_of(12) || !devices.len().is_multiple_of(PMGR_DEVICE) {
        return Err(format!("{PATH} ps-regs or devices is not whole entries"));
    }
    let mut spans: Vec<Option<(u64, u64)>> = alloc::vec![None; blocks.len() / 3];
    let mut registers = Vec::new();
    let mut domains = Vec::new();
    for entry in devices.as_chunks::<PMGR_DEVICE>().0 {
        let flags = u32::from_le_bytes(entry[..4].try_into().expect("4 bytes"));
        let device = u16::from_le_bytes(entry[26..28].try_into().expect("device ID"));
        let parents = [
            u16::from_le_bytes(entry[4..6].try_into().expect("parent ID")),
            u16::from_le_bytes(entry[6..8].try_into().expect("parent ID")),
        ]
        .map(|parent| (parent != 0).then(|| domain_id(parent)));
        let address = if flags & PMGR_VIRTUAL != 0 {
            None
        } else {
            let (index, block) = (u64::from(entry[10]), usize::from(entry[11]));
            let cells = blocks
                .get(block * 3..block * 3 + 3)
                .ok_or_else(|| format!("{PATH} device names absent ps-regs block {block}"))?;
            let &(range, bytes) = reg
                .get(cells[0] as usize)
                .ok_or_else(|| format!("{PATH} ps-regs block {block} names absent reg"))?;
            let offset = u64::from(cells[1])
                .checked_add(index * 8)
                .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= bytes))
                .ok_or_else(|| format!("{PATH} power state exceeds reg bank"))?;
            let physical = range
                .checked_add(offset)
                .and_then(translate)
                .filter(|address| {
                    range.checked_add(offset + 3).and_then(translate) == address.checked_add(3)
                })
                .ok_or_else(|| format!("{PATH} power state crosses arm-io ranges"))?;
            let base = range
                .checked_add(u64::from(cells[1]))
                .and_then(translate)
                .ok_or_else(|| format!("{PATH} ps-regs block is outside arm-io ranges"))?;
            let end = physical.checked_add(4).filter(|_| base.checked_add(index * 8) == Some(physical))
                .ok_or_else(|| format!("{PATH} ps-regs block is not one contiguous range"))?;
            let span = spans[block].get_or_insert((base, 0));
            span.1 = span.1.max(end - base);
            if !registers.contains(&physical) {
                registers.push(physical);
            }
            Some(physical)
        };
        domains.push(Domain {
            id: domain_id(device),
            address,
            parents,
        });
    }
    let resources = inventory(root)?;
    let consumers = resources
        .iter()
        .map(|resource| Consumer {
            name: &resource.name,
            clocks: &resource.clocks,
            power: &resource.power,
            sinks: LifecycleSinks::default(),
        })
        .collect::<Vec<_>>();
    // Validate the entire graph even when a broken record is unreferenced.
    coverage::analyze(&domains, &consumers).map_err(|error| format!("PMGR coverage: {error:?}"))?;
    registers.sort_unstable();
    Ok(Some(PowerStates {
        blocks: spans.into_iter().flatten().collect(),
        registers,
        domains,
        resources,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::adt::encode;

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn tree(records: &[(u16, Option<u8>, [u16; 2])], children: &[Vec<u8>]) -> Vec<u8> {
        let devices = records
            .iter()
            .flat_map(|&(id, index, parents)| {
                let mut record = [0; PMGR_DEVICE];
                record[..4].copy_from_slice(
                    &if index.is_none() { PMGR_VIRTUAL } else { 0u32 }.to_le_bytes(),
                );
                record[4..6].copy_from_slice(&parents[0].to_le_bytes());
                record[6..8].copy_from_slice(&parents[1].to_le_bytes());
                record[10] = index.unwrap_or(0);
                record[26..28].copy_from_slice(&id.to_le_bytes());
                record
            })
            .collect::<Vec<_>>();
        let reg = [0x1000u64, 0x1000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let pmgr = encode(
            &[
                ("name", b"pmgr"),
                ("compatible", b"pmgr1,t8112"),
                ("reg", &reg),
                ("ps-regs", &words(&[0, 0, 0])),
                ("devices", &devices),
            ],
            &[],
        );
        let mut children = children.to_vec();
        children.insert(0, pmgr);
        encode(&[("name", b"arm-io")], &children)
    }

    #[test]
    fn complete_inventory_keeps_gate_kinds_and_distinguishes_mapper_ownership_from_dma_dependencies()
     {
        let mapper = encode(
            &[
                ("name", b"mapper"),
                ("compatible", IOMMU_MAPPER.as_bytes()),
                ("AAPL,phandle", &words(&[1])),
                ("reg", &words(&[0])),
            ],
            &[],
        );
        let dart = encode(
            &[
                ("name", b"dart"),
                ("compatible", DART.as_bytes()),
                ("sid-count", &words(&[16])),
                ("clock-gates", &words(&[0x210, 0x210])),
            ],
            &[mapper],
        );
        let endpoint = encode(&[("name", b"endpoint")], &[]);
        let nub = encode(&[("name", b"nub")], &[endpoint]);
        // Hidden hardware remains a consumer, while iommu-parent alone does
        // not make a DMA client share the DART's clock island.
        let client = encode(
            &[
                ("name", b"controller"),
                ("power-gates", &words(&[2])),
                ("iommu-parent", &words(&[1])),
            ],
            &[nub],
        );
        let bytes = tree(
            &[
                (1, Some(0), [0, 0]),
                (2, Some(1), [1, 0]),
                (0x210, None, [2, 0]),
            ],
            &[dart, client],
        );
        let states = power_states(&Node::root(&bytes).unwrap(), &Some, 0x8112)
            .unwrap()
            .unwrap();
        let find = |name| {
            states
                .resources
                .iter()
                .find(|resource| resource.name == name)
                .unwrap()
        };
        for name in ["/arm-io/dart", "/arm-io/dart/mapper"] {
            assert_eq!(find(name).clocks, [domain_id(0x210)]);
            assert!(find(name).power.is_empty());
            assert_eq!(find(name).owner, Some(PowerOwner::Dart(0)));
        }
        for name in [
            "/arm-io/controller",
            "/arm-io/controller/nub",
            "/arm-io/controller/nub/endpoint",
        ] {
            assert!(find(name).clocks.is_empty());
            assert_eq!(find(name).power, [domain_id(2)]);
            assert_eq!(find(name).owner, None);
        }
    }

    #[test]
    fn usb_root_port_views_share_the_controller_and_unknown_children_keep_their_requirements() {
        let port = |number: u32, register: bool| {
            let number = words(&[number]);
            let mut properties = alloc::vec![("name", b"port".as_slice()), ("usb-port-number", number.as_slice())];
            if register { properties.push(("reg", b"\0\0\0\0".as_slice())); }
            encode(&properties, &[])
        };
        for (number, register, owned) in [(1, false, true), (2, false, true), (3, false, false), (1, true, false)] {
            let controller = encode(&[("name", b"usb"), ("compatible", USB_DRD.as_bytes()), ("clock-gates", &words(&[1]))], &[port(number, register)]);
            let bytes = tree(&[(1, Some(0), [0, 0])], &[controller]);
            let states = power_states(&Node::root(&bytes).unwrap(), &Some, 0x8112).unwrap().unwrap();
            let controller = states.resources.iter().find(|resource| resource.name == "/arm-io/usb").unwrap();
            let port = states.resources.iter().find(|resource| resource.name == "/arm-io/usb/port").unwrap();
            assert_eq!(controller.owner, Some(PowerOwner::Usb(0)));
            assert_eq!(port.owner, owned.then_some(PowerOwner::Usb(0)));
            assert_eq!(port.clocks, [domain_id(1)]);
        }
    }

    #[test]
    fn parsing_preserves_physical_aliases_and_parents_and_rejects_broken_complete_graphs() {
        let records = [
            (1, Some(0), [0, 0]),
            (2, Some(1), [0, 0]),
            (3, Some(2), [1, 0]),
            (4, Some(2), [2, 0]),
        ];
        let bytes = tree(&records, &[]);
        let states = power_states(&Node::root(&bytes).unwrap(), &Some, 0x8112)
            .unwrap()
            .unwrap();
        assert_eq!(states.domains.len(), 4);
        assert_eq!(states.registers, [0x1000, 0x1008, 0x1010]);
        assert_eq!(states.domains[2].address, states.domains[3].address);
        assert_eq!(states.domains[2].parents[0], Some(domain_id(1)));
        assert_eq!(states.domains[3].parents[0], Some(domain_id(2)));
        for records in [
            vec![(1, Some(0), [99, 0])],
            vec![(1, Some(0), [2, 0]), (2, Some(1), [1, 0])],
            vec![(1, Some(0), [0, 0]), (1, Some(1), [0, 0])],
            vec![
                (1, Some(0), [2, 0]),
                (2, Some(1), [0, 0]),
                (3, Some(1), [4, 0]),
                (4, Some(0), [0, 0]),
            ],
        ] {
            let bytes = tree(&records, &[]);
            assert!(power_states(&Node::root(&bytes).unwrap(), &Some, 0x8112).is_err());
        }
        for property in ["clock-gates", "power-gates"] {
            let malformed = encode(&[("name", b"controller"), (property, &[1, 0, 0])], &[]);
            let bytes = tree(&records, &[malformed]);
            assert!(power_states(&Node::root(&bytes).unwrap(), &Some, 0x8112).is_err());
        }
    }

    /// Immutable original fixture stays local. Run with STELA_TEST_PMGR_ADT
    /// pointing at decoded UniversalMac 26A434 DeviceTree.j473ap.adt.
    #[test]
    #[ignore = "requires the pinned original J473AP ADT; no Apple image is committed"]
    fn original_j473_resource_graph_keeps_shared_hardware_and_clock_only_usb_darts() {
        use sha2::{Digest, Sha256};
        let path = std::env::var("STELA_TEST_PMGR_ADT").expect("original ADT path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let root = Node::root(&bytes).unwrap();
        let ranges = root.child("arm-io").unwrap().ranges().unwrap();
        let translate = |address| {
            ranges
                .iter()
                .find(|(child, _, size)| (*child..child + size).contains(&address))
                .map(|(child, parent, _)| parent + address - child)
        };
        let states = power_states(&root, &translate, 0x8112).unwrap().unwrap();
        assert_eq!(states.domains.len(), 303);
        assert_eq!(states.resources.len(), 330);
        for (number, id) in [(0, 0x210), (1, 0x211)] {
            let path = format!("/arm-io/dart-usb{number}");
            let resource = states
                .resources
                .iter()
                .find(|resource| resource.name == path)
                .unwrap();
            assert_eq!(resource.clocks, [domain_id(id)]);
            assert!(resource.power.is_empty());
            assert!(resource.owner.is_some());
            let mapper = states
                .resources
                .iter()
                .find(|resource| resource.name == format!("{path}/mapper-usb{number}"))
                .unwrap();
            assert_eq!(mapper.owner, resource.owner);
        }
        let complete = LifecycleSinks {
            clock: true,
            power: true,
            quiesce: true,
            reset: true,
        };
        let consumers = states
            .resources
            .iter()
            .map(|resource| Consumer {
                name: &resource.name,
                clocks: &resource.clocks,
                power: &resource.power,
                sinks: if resource.owner.is_some() {
                    complete
                } else {
                    LifecycleSinks::default()
                },
            })
            .collect::<Vec<_>>();
        let coverage = coverage::analyze(&states.domains, &consumers).unwrap();
        assert_eq!(coverage.len(), 153);
        for device in [0x108, 0x109] {
            let address = states.domains.iter().find(|domain| domain.id == domain_id(device)).unwrap().address.unwrap();
            let leaf = coverage.iter().find(|record| record.address == address).unwrap();
            assert!(leaf.bindable(), "USB leaf {device:#x} has both hardware sinks");
            assert!(leaf.consumers.iter().any(|consumer| consumer.name.contains("/dart-usb")));
            assert!(leaf.consumers.iter().any(|consumer| consumer.name.contains("/usb-drd")));
        }
        let sio_busif = states
            .domains
            .iter()
            .find(|domain| domain.id == domain_id(38))
            .unwrap()
            .address
            .unwrap();
        let shared = coverage
            .iter()
            .find(|record| record.address == sio_busif)
            .unwrap();
        assert!(!shared.bindable());
        assert!(
            shared
                .consumers
                .iter()
                .any(|consumer| consumer.name == "/arm-io/dart-sio" && consumer.sinks.complete())
        );
        assert!(shared.consumers.iter().any(|consumer| consumer.name
            == "/arm-io/sio/iop-sio-nub/sio-dma"
            && !consumer.sinks.complete()));
        std::println!(
            "original PMGR domains={} resources={} physical={} bindable={} SIO_BUSIF-consumers={}",
            states.domains.len(),
            states.resources.len(),
            coverage.len(),
            coverage.iter().filter(|record| record.bindable()).count(),
            shared.consumers.len()
        );
    }
}
