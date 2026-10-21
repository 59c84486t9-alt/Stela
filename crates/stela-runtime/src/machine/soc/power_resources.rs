//! Original PMGR graph and complete resource inventory. A logical IOMMU
//! mapper is a view of its ancestor DART's stream state, not another power
//! island. Registerless USB root-port views likewise belong to their USB
//! controller. Conversely, sharing an iommu-parent does not make a DMA client's
//! controller part of the DART's physical supply. Hardware resources inherit
//! their ADT ancestors' gates, including nubs and firmware endpoints.
use super::{ATC_PHY_LAYOUTS, IOMMU_MAPPER, Node, USB_DRD, name_of, pmgr};
use crate::platform::apple::{
    dart::Profile,
    pmgr::coverage::{self, Admission, Consumer, Domain, DomainId, LifecycleSinks},
};
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};

/// Bytes of one m1n1 `struct pmgr_device` record.
pub(super) const PMGR_DEVICE: usize = 48;
pub(super) const PMGR_VIRTUAL: u32 = 0x10;

/// Hardware owners, indexed in the board's corresponding placement vectors.
/// Logical mapper and root-port views share their actual controller owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerOwner {
    Dart(usize),
    Usb(usize),
    Phy(usize),
    /// Candidate canonical physical aperture; only an actual registered
    /// type-erased lifecycle object can satisfy this ownership key.
    Mmio(u64),
}

/// One original resource with separate inherited clock/power requirements.
/// Other hardware still has no registered lifecycle sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerResource {
    pub name: String,
    pub clocks: Vec<DomainId>,
    pub power: Vec<DomainId>,
    pub owner: Option<PowerOwner>,
    /// Explicit preparation evidence; defaults to required even without owner
    /// or compatible metadata. Unavailable never grants functional support.
    pub admission: Admission,
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

impl PowerStates {
    /// Apply the bundle's existing positive device-admission ledger to the
    /// matching prepared resource inventory. No node/property is removed.
    /// Missing evidence remains required. A hidden controller's registerless
    /// logical descendants follow it, until an independently admitted child
    /// or a placed hardware owner establishes its own obligations.
    pub fn apply_admission(&mut self, prepared: &[u8], hidden: &[String]) -> Result<usize, String> {
        let root = Node::root(prepared).ok_or("PMGR admission tree is invalid")?;
        let expected = inventory(&root)?;
        if expected.len() != self.resources.len()
            || expected
                .iter()
                .zip(&self.resources)
                .any(|(expected, actual)| {
                    expected.name != actual.name
                        || expected.clocks != actual.clocks
                        || expected.power != actual.power
                        || expected.owner != actual.owner
                })
        {
            return Err(
                "PMGR admission evidence differs from the complete resource inventory".into(),
            );
        }
        let mut unavailable = BTreeSet::new();
        let mut evidence = BTreeSet::new();
        for entry in hidden {
            if !evidence.insert(entry.as_str()) {
                return Err(format!("PMGR admission repeats evidence {entry}"));
            }
            // The historical ledger also carries these preparation notes.
            // They establish no unavailable resource and cannot waive sinks.
            if let Some((path, note)) = entry.split_once(' ') {
                let node = node_at(prepared, path)
                    .ok_or_else(|| format!("PMGR admission note names missing {path}"))?;
                let valid = match (path, note) {
                    ("/defaults", "serial-device") => node.property("serial-device").is_none(),
                    ("/", "secure-root-prefix") => node.property("secure-root-prefix").is_none(),
                    (_, "+no-pmu") => node.property("no-pmu").is_some(),
                    (_, "+gptbat-ready") => node.property("gptbat-ready").is_some(),
                    _ => false,
                };
                if !valid {
                    return Err(format!(
                        "PMGR admission has invalid preparation note {entry}"
                    ));
                }
                continue;
            }
            if entry == "/" || entry == "/arm-io" || entry == "/cpus" || entry.starts_with("/cpus/")
            {
                return Err(format!("PMGR admission cannot retire structural {entry}"));
            }
            let node = node_at(prepared, entry)
                .ok_or_else(|| format!("PMGR admission names missing resource {entry}"))?;
            let resource = self
                .resources
                .iter()
                .find(|resource| resource.name == *entry)
                .ok_or_else(|| format!("PMGR admission has no inventory resource {entry}"))?;
            if resource
                .owner
                .is_some_and(|owner| !matches!(owner, PowerOwner::Mmio(_)))
                || node.property("compatible").is_some() && node.property("AAPL,ignore").is_none()
            {
                return Err(format!(
                    "PMGR unavailable admission conflicts with visible hardware {entry}"
                ));
            }
            if !unavailable.insert(entry.as_str()) {
                return Err(format!("PMGR admission repeats resource {entry}"));
            }
        }
        let mut admissions = Vec::with_capacity(self.resources.len());
        for resource in &self.resources {
            let mut retired = false;
            let mut path = String::new();
            for component in resource.name.split('/').filter(|part| !part.is_empty()) {
                path.push('/');
                path.push_str(component);
                let node = node_at(prepared, &path).expect("validated inventory path");
                // A retained compatible starts an independent admitted
                // interface; an unavailable ancestor cannot hide it.
                if ["compatible", "reg", "clock-gates", "power-gates"]
                    .iter()
                    .any(|key| node.property(key).is_some())
                {
                    retired = false;
                }
                if unavailable.contains(path.as_str()) {
                    retired = true;
                }
            }
            if resource
                .owner
                .is_some_and(|owner| !matches!(owner, PowerOwner::Mmio(_)))
            {
                retired = false;
            }
            admissions.push(if retired {
                Admission::Unavailable
            } else {
                Admission::Required
            });
        }
        let count = admissions
            .iter()
            .filter(|&&admission| admission == Admission::Unavailable)
            .count();
        for (resource, admission) in self.resources.iter_mut().zip(admissions) {
            resource.admission = admission;
        }
        Ok(count)
    }
}

fn node_at<'a>(prepared: &'a [u8], path: &str) -> Option<Node<'a>> {
    if !path.starts_with('/') || path != "/" && path.ends_with('/') {
        return None;
    }
    let mut node = Node::root(prepared)?;
    let mut components = path.strip_prefix('/')?.split('/');
    if name_of(&node) == "arm-io" && components.next()? != "arm-io" {
        return None;
    }
    for component in components {
        if component.is_empty() && path == "/" {
            continue;
        }
        if component.is_empty() || component == "." || component == ".." {
            return None;
        }
        node = node.child(component)?;
    }
    Some(node)
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
    let ranges = root
        .child("arm-io")
        .and_then(|io| io.ranges())
        .or_else(|| root.ranges())
        .unwrap_or_default();
    let physical = |node: &Node<'_>| {
        let (address, _) = node.pairs("reg")?.first().copied()?;
        if ranges.is_empty() {
            return Some(address);
        }
        ranges
            .iter()
            .find(|(child, _, size)| address >= *child && address - child < *size)
            .and_then(|(child, parent, _)| parent.checked_add(address - child))
    };
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
        admission: Admission::Required,
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
                Vec::<&'static str>::new(),
            )
        })
        .collect::<Vec<_>>();
    let mut darts = 0;
    let mut dart_streams = Vec::new();
    let mut usbs = 0;
    let mut phys = 0;
    while let Some((parent, node, mut clocks, mut power, owner, views)) = pending.pop() {
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
        let profile = node
            .property("compatible")
            .and_then(Profile::from_compatible);
        let owner = if let Some(profile) = profile
            && path.starts_with("/arm-io/")
        {
            let index = darts;
            darts += 1;
            let default = match profile {
                Profile::T8020 | Profile::T6000 => 16,
                Profile::T8110 => 0,
            };
            dart_streams.push(node.first_u32("sid-count").unwrap_or(default));
            Some(PowerOwner::Dart(index))
        } else if path.starts_with("/arm-io/") && node.compatible(USB_DRD) {
            let index = usbs;
            usbs += 1;
            Some(PowerOwner::Usb(index))
        } else if path.starts_with("/arm-io/")
            && ATC_PHY_LAYOUTS
                .iter()
                .any(|(layout, _)| node.compatible(layout))
        {
            let index = phys;
            phys += 1;
            Some(PowerOwner::Phy(index))
        } else if node.compatible(IOMMU_MAPPER)
            && node.first_u32("AAPL,phandle").is_some()
            && owner.is_some_and(|owner| match owner {
                PowerOwner::Dart(index) => node
                    .first_u32("reg")
                    .is_some_and(|stream| stream < dart_streams[index]),
                PowerOwner::Usb(_) | PowerOwner::Phy(_) | PowerOwner::Mmio(_) => false,
            })
            || node.property("reg").is_none()
                && node.property("compatible").is_none()
                && node.property("clock-gates").is_none()
                && node.property("power-gates").is_none()
                && node
                    .first_u32("usb-port-number")
                    .is_some_and(|number| (1..=2).contains(&number))
                && matches!(owner, Some(PowerOwner::Usb(_)))
        {
            owner
        } else {
            None
        };
        let owner = owner.or_else(|| {
            if !path.starts_with("/arm-io/") {
                return None;
            }
            let modeled = node
                .property("compatible")
                .into_iter()
                .flat_map(|list| list.split(|byte| *byte == 0))
                .filter_map(|name| core::str::from_utf8(name).ok())
                .any(|name| super::models(name, |key| node.property(key)));
            if modeled && let Some(address) = physical(&node) {
                return Some(PowerOwner::Mmio(address));
            }
            if views.iter().any(|view| {
                node.compatible(view)
                    || *view == "debug-console"
                        && name_of(&node) == "debug-console"
                        && ["compatible", "reg", "clock-gates", "power-gates"]
                            .iter()
                            .all(|key| node.property(key).is_none())
            }) {
                return match owner_from_parent(&resources, &parent) {
                    Some(PowerOwner::Mmio(address)) => Some(PowerOwner::Mmio(address)),
                    _ => None,
                };
            }
            None
        });
        let mut views = Vec::new();
        for name in node
            .property("compatible")
            .into_iter()
            .flat_map(|list| list.split(|byte| *byte == 0))
            .filter_map(|name| core::str::from_utf8(name).ok())
        {
            views.extend(
                super::model_children(name, |key| node.property(key))
                    .iter()
                    .map(|view| view.compatible),
            );
            views.extend(match name {
                super::UART => &["debug-console"][..],
                super::SPI => &[super::NOR][..],
                super::NOR => &[super::NVRAM, super::SYSCFG][..],
                super::I2C => &[super::HPM_MANAGER][..],
                super::HPM_MANAGER => &[super::HPM][..],
                _ => &[],
            });
        }
        resources.push(PowerResource {
            name: path.clone(),
            clocks: clocks.clone(),
            power: power.clone(),
            owner,
            admission: Admission::Required,
        });
        for child in node
            .children()
            .ok_or_else(|| format!("{path} has an invalid child"))?
            .into_iter()
            .rev()
        {
            pending.push((
                path.clone(),
                child,
                clocks.clone(),
                power.clone(),
                owner,
                views.clone(),
            ));
        }
    }
    Ok(resources)
}

fn owner_from_parent(resources: &[PowerResource], parent: &str) -> Option<PowerOwner> {
    resources
        .iter()
        .rev()
        .find(|resource| resource.name == parent)
        .and_then(|resource| resource.owner)
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
            let end = physical
                .checked_add(4)
                .filter(|_| base.checked_add(index * 8) == Some(physical))
                .ok_or_else(|| format!("{PATH} ps-regs block is not one contiguous range"))?;
            let span = spans[block].get_or_insert((base, 0));
            span.1 = span.1.max(end - base);
            if !registers.contains(&physical) {
                registers.push(physical);
            }
            Some(physical)
        };
        let raw_name = &entry[32..48];
        let end = raw_name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(raw_name.len());
        let name = core::str::from_utf8(&raw_name[..end])
            .map_err(|_| format!("{PATH} domain {device:#x} has a non-UTF-8 name"))?;
        domains.push(Domain {
            name: name.into(),
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
            admission: resource.admission,
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
    use crate::machine::{adt::encode, soc::DART};

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
    fn physical_candidates_require_actual_registration_and_only_qualified_views_share_ownership() {
        use crate::machine::soc::UART;
        let reg = |address: u64| {
            [address, 0x1000]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        let debug = encode(&[("name", b"debug-console")], &[]);
        let unknown = encode(&[("name", b"firmware-endpoint")], &[]);
        let uart = encode(
            &[
                ("name", b"uart0"),
                ("compatible", UART.as_bytes()),
                ("reg", &reg(0x2000)),
                ("clock-gates", &words(&[1])),
            ],
            &[debug, unknown],
        );
        let independent = encode(&[("name", b"debug-console"), ("reg", &reg(0x4000))], &[]);
        let second = encode(
            &[
                ("name", b"uart1"),
                ("compatible", UART.as_bytes()),
                ("reg", &reg(0x3000)),
                ("clock-gates", &words(&[1])),
            ],
            &[independent],
        );
        let encoded = tree(&[(1, Some(0), [0, 0])], &[uart, second]);
        let resources = inventory(&Node::root(&encoded).unwrap()).unwrap();
        let owner = |name: &str| {
            resources
                .iter()
                .find(|resource| resource.name == name)
                .unwrap()
                .owner
        };
        assert_eq!(owner("/arm-io/uart0"), Some(PowerOwner::Mmio(0x2000)));
        assert_eq!(
            owner("/arm-io/uart0/debug-console"),
            Some(PowerOwner::Mmio(0x2000))
        );
        assert_eq!(owner("/arm-io/uart0/firmware-endpoint"), None);
        assert_eq!(owner("/arm-io/uart1/debug-console"), None);
        assert!(
            resources
                .iter()
                .all(|resource| resource.admission == Admission::Required)
        );
        // A candidate owner is metadata, not evidence of complete sinks.
        let parsed = power_states(&Node::root(&encoded).unwrap(), &Some, 0x8112)
            .unwrap()
            .unwrap();
        let consumers = parsed
            .resources
            .iter()
            .map(|resource| Consumer {
                name: &resource.name,
                clocks: &resource.clocks,
                power: &resource.power,
                sinks: LifecycleSinks::default(),
                admission: resource.admission,
            })
            .collect::<Vec<_>>();
        assert!(!coverage::analyze(&parsed.domains, &consumers).unwrap()[0].bindable());
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
    fn positive_admission_is_atomic_and_preserves_independent_hardware_obligations() {
        let logical = encode(&[("name", b"logical")], &[]);
        let unknown = encode(&[("name", b"unknown"), ("reg", &words(&[0]))], &[]);
        let visible = encode(
            &[("name", b"visible"), ("compatible", b"required,unknown")],
            &[],
        );
        let native = encode(
            &[
                ("name", b"dart"),
                ("compatible", DART.as_bytes()),
                ("sid-count", &words(&[16])),
            ],
            &[],
        );
        let hidden = encode(
            &[("name", b"hidden"), ("clock-gates", &words(&[1]))],
            &[logical, unknown, visible, native],
        );
        let leaf = encode(&[("name", b"leaf"), ("power-gates", &words(&[2]))], &[]);
        let bytes = tree(
            &[(1, Some(0), [0, 0]), (2, Some(1), [0, 0])],
            &[hidden, leaf],
        );
        let mut states = power_states(&Node::root(&bytes).unwrap(), &Some, 0x8112)
            .unwrap()
            .unwrap();
        let original = states.clone();
        assert_eq!(states.apply_admission(&bytes, &[]), Ok(0));
        assert_eq!(
            states.apply_admission(&bytes, &["/arm-io/hidden".into(), "/arm-io/leaf".into()]),
            Ok(3)
        );
        for path in ["/arm-io/hidden", "/arm-io/hidden/logical", "/arm-io/leaf"] {
            assert_eq!(
                states
                    .resources
                    .iter()
                    .find(|r| r.name == path)
                    .unwrap()
                    .admission,
                Admission::Unavailable
            );
        }
        for path in [
            "/arm-io/hidden/unknown",
            "/arm-io/hidden/visible",
            "/arm-io/hidden/dart",
        ] {
            assert_eq!(
                states
                    .resources
                    .iter()
                    .find(|r| r.name == path)
                    .unwrap()
                    .admission,
                Admission::Required
            );
        }
        let accepted = states.clone();
        for ledger in [
            vec!["/arm-io/missing".into()],
            vec!["/arm-io/hidden/visible".into()],
            vec!["/arm-io/hidden/dart".into()],
            vec!["/arm-io".into()],
            vec!["/arm-io/hidden/".into()],
            vec!["/arm-io/hidden/../leaf".into()],
            vec!["/arm-io/hidden".into(), "/arm-io/hidden".into()],
            vec!["/arm-io/hidden +unmodeled".into()],
        ] {
            assert!(states.apply_admission(&bytes, &ledger).is_err());
            assert_eq!(states, accepted);
        }
        let mut mismatched = original;
        mismatched.resources[0].clocks.push(domain_id(1));
        assert!(
            mismatched
                .apply_admission(&bytes, &["/arm-io/leaf".into()])
                .is_err()
        );
    }

    #[test]
    fn preparation_notes_are_validated_without_retiring_resources() {
        let watched = encode(
            &[
                ("name", b"watchdog"),
                ("clock-gates", &words(&[1])),
                ("no-pmu", b""),
            ],
            &[],
        );
        let bytes = tree(&[(1, Some(0), [0, 0])], &[watched]);
        let mut states = power_states(&Node::root(&bytes).unwrap(), &Some, 0x8112)
            .unwrap()
            .unwrap();
        assert_eq!(
            states.apply_admission(&bytes, &["/arm-io/watchdog +no-pmu".into()]),
            Ok(0)
        );
        assert!(
            states
                .resources
                .iter()
                .all(|r| r.admission == Admission::Required)
        );
        assert!(
            states
                .apply_admission(&bytes, &["/arm-io/watchdog +gptbat-ready".into()])
                .is_err()
        );
    }

    #[test]
    #[ignore = "requires the pinned prepared r8 J473 bundle; no Apple input is committed"]
    fn prepared_j473_admission_keeps_complete_graph_and_names_all_remaining_sinks() {
        use sha2::{Digest, Sha256};
        let directory = std::path::PathBuf::from(
            std::env::var("STELA_TEST_PMGR_BUNDLE").expect("prepared bundle directory"),
        );
        let bytes = std::fs::read(directory.join("devicetree.adt")).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "d60dbd13b11a6188f6bfa19a6fe173d49950d5b619197a5a7f4e9d76734d1680"
        );
        let manifest = crate::boot_bundle::Manifest::parse(
            &std::fs::read(directory.join("bundle.json")).unwrap(),
        )
        .unwrap();
        let root = Node::root(&bytes).unwrap();
        let ranges = root.child("arm-io").unwrap().ranges().unwrap();
        let translate = |address| {
            ranges
                .iter()
                .find(|(child, _, size)| (*child..child + size).contains(&address))
                .map(|(child, parent, _)| parent + address - child)
        };
        let mut states = power_states(&root, &translate, 0x8112).unwrap().unwrap();
        let original = states.clone();
        let retired = states
            .apply_admission(&bytes, &manifest.hidden_devices)
            .unwrap();
        assert_eq!(states.domains, original.domains);
        assert_eq!(states.registers, original.registers);
        assert_eq!(states.resources.len(), original.resources.len());
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
                sinks: if matches!(
                    resource.owner,
                    Some(PowerOwner::Dart(_) | PowerOwner::Usb(_) | PowerOwner::Phy(_))
                ) {
                    complete
                } else {
                    LifecycleSinks::default()
                },
                admission: resource.admission,
            })
            .collect::<Vec<_>>();
        let coverage = coverage::analyze(&states.domains, &consumers).unwrap();
        let ave = coverage
            .iter()
            .find(|record| record.address == 0x23b708020)
            .unwrap();
        assert!(ave.bindable());
        assert!(
            ave.consumers
                .iter()
                .all(|c| c.admission == Admission::Unavailable && !c.sinks.complete())
        );
        let mut missing = BTreeSet::new();
        for domain in coverage.iter().filter(|domain| !domain.bindable()) {
            let names = domain
                .consumers
                .iter()
                .filter(|c| c.admission == Admission::Required && !c.sinks.complete())
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>();
            missing.extend(names.iter().map(|name| String::from(*name)));
            std::println!("PMGR unresolved {:#x}: {:?}", domain.address, names);
        }
        std::println!(
            "PMGR retired={} domains={} physical={} bindable={} remaining={:?}",
            retired,
            states.domains.len(),
            coverage.len(),
            coverage.iter().filter(|d| d.bindable()).count(),
            missing
        );
        assert!(!missing.is_empty());
        assert!(missing.contains("/arm-io/ans"));
        assert!(
            coverage
                .iter()
                .filter(|d| d.consumers.is_empty())
                .all(|d| !d.bindable())
        );
    }

    #[test]
    fn inventory_uses_exact_admitted_dart_profiles_and_legacy_mapper_default() {
        let mapper = encode(
            &[
                ("name", b"mapper"),
                ("compatible", IOMMU_MAPPER.as_bytes()),
                ("AAPL,phandle", &words(&[7])),
                ("reg", &words(&[15])),
            ],
            &[],
        );
        let dart = |name: &[u8], compatible: &[u8]| {
            encode(
                &[
                    ("name", name),
                    ("compatible", compatible),
                    ("clock-gates", &words(&[1])),
                ],
                core::slice::from_ref(&mapper),
            )
        };
        let phy = encode(
            &[
                ("name", b"phy"),
                ("compatible", b"atc-phy,t8112"),
                ("clock-gates", &words(&[1])),
            ],
            &[],
        );
        let bytes = tree(
            &[(1, Some(0), [0, 0])],
            &[
                dart(b"legacy", b"dart,t8020"),
                dart(b"unknown", b"dart,t8110\0dart,gen3"),
                dart(b"modern", b"dart,t8110"),
                phy,
            ],
        );
        let states = power_states(&Node::root(&bytes).unwrap(), &Some, 0x8112)
            .unwrap()
            .unwrap();
        let owner = |name| {
            states
                .resources
                .iter()
                .find(|resource| resource.name == name)
                .unwrap()
                .owner
        };
        assert_eq!(owner("/arm-io/legacy"), Some(PowerOwner::Dart(0)));
        assert_eq!(owner("/arm-io/legacy/mapper"), Some(PowerOwner::Dart(0)));
        assert_eq!(owner("/arm-io/unknown"), None);
        assert_eq!(owner("/arm-io/unknown/mapper"), None);
        assert_eq!(owner("/arm-io/modern"), Some(PowerOwner::Dart(1)));
        assert_eq!(owner("/arm-io/modern/mapper"), None); // sid-count required.
        assert_eq!(owner("/arm-io/phy"), Some(PowerOwner::Phy(0)));
    }

    #[test]
    fn usb_root_port_views_share_the_controller_and_unknown_children_keep_their_requirements() {
        let port = |number: u32, register: bool| {
            let number = words(&[number]);
            let mut properties = alloc::vec![
                ("name", b"port".as_slice()),
                ("usb-port-number", number.as_slice())
            ];
            if register {
                properties.push(("reg", b"\0\0\0\0".as_slice()));
            }
            encode(&properties, &[])
        };
        for (number, register, owned) in [
            (1, false, true),
            (2, false, true),
            (3, false, false),
            (1, true, false),
        ] {
            let controller = encode(
                &[
                    ("name", b"usb"),
                    ("compatible", USB_DRD.as_bytes()),
                    ("clock-gates", &words(&[1])),
                ],
                &[port(number, register)],
            );
            let bytes = tree(&[(1, Some(0), [0, 0])], &[controller]);
            let states = power_states(&Node::root(&bytes).unwrap(), &Some, 0x8112)
                .unwrap()
                .unwrap();
            let controller = states
                .resources
                .iter()
                .find(|resource| resource.name == "/arm-io/usb")
                .unwrap();
            let port = states
                .resources
                .iter()
                .find(|resource| resource.name == "/arm-io/usb/port")
                .unwrap();
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
        assert!(states.domains.iter().all(|domain| !domain.name.is_empty()));
        let isp = states
            .domains
            .iter()
            .find(|domain| domain.id == domain_id(0x7a))
            .unwrap();
        assert_eq!(isp.name, "ISP_SYS");
        assert_eq!(isp.address, Some(0x2_3b70_0438));
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
                sinks: if matches!(
                    resource.owner,
                    Some(PowerOwner::Dart(_) | PowerOwner::Usb(_) | PowerOwner::Phy(_))
                ) {
                    complete
                } else {
                    LifecycleSinks::default()
                },
                admission: resource.admission,
            })
            .collect::<Vec<_>>();
        let coverage = coverage::analyze(&states.domains, &consumers).unwrap();
        assert_eq!(coverage.len(), 153);
        for device in [0x108, 0x109] {
            let address = states
                .domains
                .iter()
                .find(|domain| domain.id == domain_id(device))
                .unwrap()
                .address
                .unwrap();
            let leaf = coverage
                .iter()
                .find(|record| record.address == address)
                .unwrap();
            assert!(
                leaf.bindable(),
                "USB leaf {device:#x} has both hardware sinks"
            );
            assert!(
                leaf.consumers
                    .iter()
                    .any(|consumer| consumer.name.contains("/dart-usb"))
            );
            assert!(
                leaf.consumers
                    .iter()
                    .any(|consumer| consumer.name.contains("/usb-drd"))
            );
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
