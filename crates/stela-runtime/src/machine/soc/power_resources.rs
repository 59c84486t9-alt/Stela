//! Original PMGR graph and complete resource inventory. A logical IOMMU
//! mapper is a view of its ancestor DART's stream state, not another power
//! island. Registerless USB root-port views likewise belong to their USB
//! controller. Conversely, sharing an iommu-parent does not make a DMA client's
//! controller part of the DART's physical supply. Hardware resources inherit
//! their ADT ancestors' activated gates, including nubs and firmware endpoints.
//! Source PMGR provider gate-index metadata remains inventoried separately from
//! the consumer dependencies its IOService start actually activates.
use super::{ATC_PHY_LAYOUTS, IOMMU_MAPPER, Node, USB_DRD, name_of, pmgr};
use crate::platform::apple::{
    dart::Profile,
    pmgr::coverage::{self, Admission, Consumer, Domain, DomainId, LifecycleSinks},
};
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};

mod clock_role;
pub use clock_role::{ClockRole, PmgrClockProvider};

mod cpu;
pub use cpu::ProcessorAssociation;
mod records;
use records::{Layout, Record};
mod implicit;

/// Bytes of one m1n1 `struct pmgr_device` record.
pub(super) const PMGR_DEVICE: usize = records::BYTES;
#[cfg(test)]
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
    /// Source-qualified driver use; provider metadata alone activates no gate.
    pub clock_role: ClockRole,
    pub power: Vec<DomainId>,
    pub owner: Option<PowerOwner>,
    /// Explicit preparation evidence; defaults to required even without owner
    /// or compatible metadata. Unavailable never grants functional support.
    pub admission: Admission,
}

impl PowerResource {
    /// Actual start/lifecycle requirements, retaining passive provider indices
    /// in clocks for source accounting and later explicit gate operations.
    pub fn activated_clocks(&self) -> &[DomainId] {
        match &self.clock_role {
            ClockRole::Consumer => &self.clocks,
            ClockRole::PmgrProvider(provider) => provider.ancestors(),
        }
    }
}

/// PMGR blocks, complete original domain graph and all original ADT resources,
/// including nodes whose admission/compatible was removed by the loader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerStates {
    pub blocks: Vec<(u64, u64)>,
    pub registers: Vec<u64>,
    pub domains: Vec<Domain>,
    pub resources: Vec<PowerResource>,
    /// Source-qualified requirements absent from the original gate arrays.
    /// Keep the original inventory unchanged for admission and source review.
    pub(crate) implicit: Vec<implicit::Requirement>,
}

impl PowerStates {
    /// Positively qualified physical CPU owners. The effective harvesting
    /// setting must include supplied start-time overrides; this method supplies
    /// no initial LifecycleState and never registers a participant or ACKs PMGR.
    pub fn processor_associations(
        &self,
        chip: crate::machine::Chip,
        root: &Node<'_>,
        processors: &[crate::machine::registers::Identity],
        acc_harvesting: u32,
    ) -> Result<Vec<ProcessorAssociation>, String> {
        let io = root.child("arm-io").ok_or("CPU PMGR requires arm-io")?;
        let node = io.child("pmgr").ok_or("CPU PMGR requires pmgr")?;
        // Reconstruct every original domain through the existing reader. The
        // association resolver may trust normalized non-CPU locations only
        // after this equality check, including aliases and parent identities.
        let dies = Dies::of(root, &node)?;
        let table = decode_domain_table(&node, dies, &|address, bytes| {
            cpu::physical(&io, address, bytes).ok()
        })?;
        if self.domains != table.domains
            || self.blocks != table.blocks
            || self.registers != table.registers
        {
            return Err("CPU PMGR canonical inventory differs from the source tree".into());
        }
        // Another die's cores power up through that die's PMGR records,
        // whose CPU owners the association resolver does not model.
        if dies.count != 1 {
            return Err(format!(
                "CPU PMGR associations: {:?}",
                cpu::CpuAssociationError::UnsupportedDie(dies.count - 1)
            ));
        }
        let (layout, _) = Layout::select(node.property("ps-regs"), node.property("ps-groups"))
            .map_err(String::from)?;
        let devices = node
            .property("devices")
            .ok_or("CPU PMGR requires devices")?;
        if !devices.len().is_multiple_of(PMGR_DEVICE)
            || devices.len() / PMGR_DEVICE != self.domains.len()
        {
            return Err("CPU PMGR views differ from the complete domain inventory".into());
        }
        let views = devices
            .as_chunks::<PMGR_DEVICE>()
            .0
            .iter()
            .zip(&self.domains)
            .map(|(raw, domain)| {
                let record = Record::parse(layout, raw).map_err(String::from)?;
                if domain.id != domain_id(record.id) || domain.name != record.name {
                    return Err("CPU PMGR record and canonical domain differ".into());
                }
                let location = match (record.location, domain.address) {
                    (Some(location), Some(address)) => Some(cpu::PmgrCpuLocation {
                        group: location.group,
                        index: location.index,
                        address,
                    }),
                    (None, None) => None,
                    _ => return Err("CPU PMGR physical/virtual domain mismatch".into()),
                };
                Ok(cpu::PmgrCpuRecord {
                    id: domain.id,
                    flags: raw[0],
                    perf_domain: raw[2],
                    name: record.name,
                    location,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        cpu::resolve_cpu_power(chip, root, &views, processors, acc_harvesting)
            .map_err(|error| format!("CPU PMGR associations: {error:?}"))
    }

    /// Original power gates plus independently qualified physical ownership.
    /// Stable resource indices also identify the actual lifecycle owner.
    pub(crate) fn power_requirements(&self) -> Result<Vec<Vec<DomainId>>, String> {
        implicit::power_requirements(self)
    }

    /// Apply the bundle's existing positive device-admission ledger to the
    /// matching prepared resource inventory. No node/property is removed.
    /// Missing evidence remains required. A hidden controller's registerless
    /// logical descendants follow it, until an independently admitted child
    /// or a placed hardware owner establishes its own obligations.
    pub fn apply_admission(&mut self, prepared: &[u8], hidden: &[String]) -> Result<usize, String> {
        let root = Node::root(prepared).ok_or("PMGR admission tree is invalid")?;
        let expected = inventory_with_nodes(&root)?;
        let io = root.child("arm-io");
        let pmgr = io.as_ref().unwrap_or(&root).child("pmgr");
        let translate =
            |address, bytes| io.as_ref().unwrap_or(&root).translate_range(address, bytes);
        let implicit = pmgr
            .as_ref()
            .map(|pmgr| implicit::resolve(pmgr, &self.domains, &expected, &translate))
            .transpose()?
            .unwrap_or_default();
        if expected.resources.len() != self.resources.len()
            || implicit != self.implicit
            || expected
                .resources
                .iter()
                .zip(&self.resources)
                .any(|(expected, actual)| {
                    expected.name != actual.name
                        || expected.clocks != actual.clocks
                        || expected.clock_role != actual.clock_role
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
                let node = &expected.nodes[expected.locate(path)?];
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
            let index = expected.locate(entry)?;
            let node = &expected.nodes[index];
            let resource = &self.resources[index];
            if resource
                .owner
                .is_some_and(|owner| !matches!(owner, PowerOwner::Mmio(_)))
                || node.property("compatible").is_some() && node.property("AAPL,ignore").is_none()
            {
                return Err(format!(
                    "PMGR unavailable admission conflicts with visible hardware {entry}"
                ));
            }
            if !unavailable.insert(index) {
                return Err(format!("PMGR admission repeats resource {entry}"));
            }
        }
        let mut admissions = Vec::with_capacity(self.resources.len());
        for (index, resource) in self.resources.iter().enumerate() {
            let mut retired = expected.parents[index]
                .is_some_and(|parent| admissions[parent] == Admission::Unavailable);
            let node = &expected.nodes[index];
            // Resolve ancestry by the original tree position. A display name
            // can repeat among siblings and must not select another node.
            if ["compatible", "reg", "clock-gates", "power-gates"]
                .iter()
                .any(|key| node.property(key).is_some())
            {
                retired = false;
            }
            if unavailable.contains(&index) {
                retired = true;
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

struct ResourceInventory<'a> {
    resources: Vec<PowerResource>,
    nodes: Vec<Node<'a>>,
    parents: Vec<Option<usize>>,
    ranges: Vec<(u64, u64, u64)>,
}

impl ResourceInventory<'_> {
    /// Historical admission ledgers contain paths, not node identities. Such
    /// evidence is usable only when it names exactly one original resource.
    fn locate(&self, path: &str) -> Result<usize, String> {
        let mut matches = self
            .resources
            .iter()
            .enumerate()
            .filter_map(|(index, resource)| (resource.name == path).then_some(index));
        let index = matches
            .next()
            .ok_or_else(|| format!("PMGR admission names missing resource {path}"))?;
        if matches.next().is_some() {
            return Err(format!("PMGR admission path is ambiguous: {path}"));
        }
        Ok(index)
    }
}

/// Die field of a `clock-gates`/`power-gates` word. 26A434 mac14j
/// `ApplePMGRFunctionClockGate::callFunction` takes the die as the word's
/// bits [31:28] (`lsr w22, w20, #28`, KC VA 0xfffffe0009b7e1b0) and the
/// device as the rest (`and x1, x20, #0xfffffff`, 0xfffffe0009b7e25c);
/// `ApplePMGRNub::_enableDeviceStatusChangeNotifications` splits it the same
/// way and passes only `& 0xffff` (0xfffffe0009b8b7d8, 0xfffffe0009b8b82c) to
/// the per-die `(device, die)` entry points such as `_enableDeviceGated`.
const GATE_DIE_SHIFT: u32 = 28;
/// Bits [27:16] reach no 16-bit device record; no qualified meaning.
const GATE_RESERVED: u32 = 0x0fff_0000;

/// Decode each gate word into its die-qualified device. The record tables
/// hold die 0's devices; [`decode_domain_table`] places every other die's
/// copy, so a die without a placed PMGR remains an unknown requirement.
pub(super) fn gate_ids(
    node: &Node<'_>,
    path: &str,
    property: &str,
) -> Result<Vec<DomainId>, String> {
    let bytes = node.property(property).unwrap_or_default();
    if !bytes.len().is_multiple_of(4) {
        return Err(format!("{path} {property} contains a partial device ID"));
    }
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| {
            let word = u32::from_le_bytes(*word);
            if word & GATE_RESERVED != 0 {
                return Err(format!(
                    "{path} {property} {word:#x} sets reserved PMGR device ID bits"
                ));
            }
            Ok(DomainId {
                die: (word >> GATE_DIE_SHIFT) as u8,
                device: word as u16,
            })
        })
        .collect()
}

fn domain_id(device: u16) -> DomainId {
    DomainId { die: 0, device }
}

/// Default die strides of the PMGR drivers that bind these families when
/// `/arm-io/pmgr` has no `die-stride`: `AppleT6000PMGR::getDieStride` in
/// AppleT6001PMGR (26A434 mac13j KC VA 0xfffffe0009f59164) and
/// `AppleT6020PMGR::getDieStride` in AppleT6021PMGR (mac14j 0xfffffe0009f6ceac)
/// both return 0x20_0000_0000, and their `getDieOffset(die)` is `die << 37`.
const DRIVER_DIE_STRIDES: [(&str, u64); 2] = [("pmgr1,t6001", 1 << 37), ("pmgr1,t6021", 1 << 37)];

/// The PMGR instances of a multi-die SoC: die `d`'s power-state registers are
/// die 0's plus `d * stride` (`ApplePMGR::getDieOffset`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Dies {
    count: u8,
    stride: u64,
}

impl Dies {
    /// `ApplePMGR::start` (mac14j KC VA 0xfffffe0009b358e4..0xfffffe0009b35934)
    /// reads `/arm-io/pmgr` `die-stride`, falls back to the driver's virtual
    /// `getDieStride` when it is absent or zero, and refuses a die count above
    /// one without a stride. The die count is the CPU dies (`/cpus/*` `die-id`,
    /// which XNU `ml_parse_cpu_topology` reads), as the `die-count` iBoot sets
    /// at boot (J180D iBoot file 0x39d88) is not in the firmware tree; a tree
    /// without CPU nodes is one die.
    fn of(root: &Node<'_>, pmgr: &Node<'_>) -> Result<Self, String> {
        let cpus = if name_of(root) == "arm-io" {
            None
        } else {
            root.child("cpus")
        };
        let mut highest = 0;
        for cpu in cpus.and_then(|cpus| cpus.children()).unwrap_or_default() {
            if let Some(die) = cpu.first_u32("die-id") {
                highest = highest.max(die);
            }
        }
        let count = highest
            .checked_add(1)
            .filter(|&count| count <= 1 << (32 - GATE_DIE_SHIFT))
            .and_then(|count| u8::try_from(count).ok())
            .ok_or_else(|| format!("CPU die-id {highest} exceeds the PMGR die field"))?;
        if count == 1 {
            return Ok(Self { count, stride: 0 });
        }
        let stride = match pmgr.property("die-stride") {
            Some(bytes) if bytes.len() == 8 => {
                u64::from_le_bytes(bytes.try_into().expect("eight bytes"))
            }
            Some(_) => return Err("/arm-io/pmgr die-stride is not one 64-bit stride".into()),
            None => 0,
        };
        let stride = if stride != 0 {
            stride
        } else {
            DRIVER_DIE_STRIDES
                .iter()
                .find(|(family, _)| pmgr.compatible(family))
                .map(|&(_, stride)| stride)
                .ok_or_else(|| {
                    format!("/arm-io/pmgr spans {count} dies without a qualified die-stride")
                })?
        };
        Ok(Self { count, stride })
    }

    /// Die `die`'s copy of a die-0 physical address.
    fn place(self, die: u8, address: u64) -> Result<u64, String> {
        self.stride
            .checked_mul(u64::from(die))
            .and_then(|offset| address.checked_add(offset))
            .ok_or_else(|| format!("/arm-io/pmgr die {die} power state overflows"))
    }
}

#[cfg(test)]
fn inventory(root: &Node<'_>) -> Result<Vec<PowerResource>, String> {
    Ok(inventory_with_nodes(root)?.resources)
}

fn inventory_with_nodes<'a>(root: &Node<'a>) -> Result<ResourceInventory<'a>, String> {
    let provider = clock_role::provider(root)?;
    let ranges = root
        .child("arm-io")
        .and_then(|io| io.ranges())
        .or_else(|| root.ranges())
        .unwrap_or_default();
    let mut physical_views = Vec::new();
    let io = root.child("arm-io");
    let bus = io.as_ref().unwrap_or(root);
    super::apertures::visit(
        bus,
        &|address, bytes| bus.translate_range(address, bytes),
        &mut |node, translate| {
            if let Some(regs) = super::apertures::registers(node)
                && let Some(&(address, bytes)) = regs.first()
                && let Some(physical) = translate(address, bytes)
            {
                physical_views.push((node.property("reg").unwrap().as_ptr(), physical));
            }
        },
    )
    .ok_or("invalid physical resource tree")?;
    let physical = |node: &Node<'_>| {
        let key = node.property("reg")?.as_ptr();
        physical_views
            .iter()
            .find(|(source, _)| *source == key)
            .map(|(_, physical)| *physical)
    };
    let path = if name_of(root) == "arm-io" {
        "/arm-io"
    } else {
        ""
    };
    let clocks = gate_ids(root, path, "clock-gates")?;
    let power = gate_ids(root, path, "power-gates")?;
    let mut resources = alloc::vec![PowerResource {
        name: if path.is_empty() {
            "/".into()
        } else {
            path.into()
        },
        clocks: clocks.clone(),
        clock_role: ClockRole::Consumer,
        power: power.clone(),
        owner: None,
        admission: Admission::Required,
    }];
    let mut nodes = alloc::vec![root.clone()];
    let mut parents = alloc::vec![None];
    let mut pending = root
        .children()
        .ok_or("invalid resource tree")?
        .into_iter()
        .rev()
        .map(|node| {
            (
                0,
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
        let path = format!(
            "{}/{}",
            resources[parent].name.trim_end_matches('/'),
            name_of(&node)
        );
        let clock_role = provider.as_ref().map_or(ClockRole::Consumer, |provider| {
            provider.role(&node, &clocks)
        });
        let provider_ancestors =
            matches!(clock_role, ClockRole::PmgrProvider(_)).then(|| clocks.clone());
        clocks.extend(gate_ids(&node, &path, "clock-gates")?);
        power.extend(gate_ids(&node, &path, "power-gates")?);
        clocks.sort_unstable();
        clocks.dedup();
        power.sort_unstable();
        power.dedup();
        let dart = node
            .property("compatible")
            .and_then(Profile::from_compatible)
            .is_some();
        let owner = if dart && path.starts_with("/arm-io/") {
            let index = darts;
            darts += 1;
            // SPTM defaults an absent sid-count to 16 on every generation.
            dart_streams.push(node.first_u32("sid-count").unwrap_or(16));
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
                return match resources[parent].owner {
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
        let index = resources.len();
        resources.push(PowerResource {
            name: path.clone(),
            clocks: clocks.clone(),
            clock_role,
            power: power.clone(),
            owner,
            admission: Admission::Required,
        });
        nodes.push(node.clone());
        parents.push(Some(parent));
        for child in node
            .children()
            .ok_or_else(|| format!("{path} has an invalid child"))?
            .into_iter()
            .rev()
        {
            pending.push((
                index,
                child,
                provider_ancestors.as_ref().unwrap_or(&clocks).clone(),
                power.clone(),
                owner,
                views.clone(),
            ));
        }
    }
    Ok(ResourceInventory {
        resources,
        nodes,
        parents,
        ranges,
    })
}

pub(super) fn power_states(
    root: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
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
    decode_power_states(root, &node, translate).map(Some)
}

/// Normalize firmware records without granting a new SoC's native model.
/// `power_states` retains the independent complete-PMGR placement gate.
fn decode_power_states(
    root: &Node<'_>,
    node: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<PowerStates, String> {
    let states = source_power_states(root, node, translate)?;
    validate_power_graph(&states)?;
    Ok(states)
}

/// Complete original metadata, without granting lifecycle coverage. Private
/// resource preparation retains any independent graph requirement explicitly.
pub(super) fn source_power_states(
    root: &Node<'_>,
    node: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<PowerStates, String> {
    let table = decode_domain_table(node, Dies::of(root, node)?, translate)?;
    let inventory = inventory_with_nodes(root)?;
    let implicit = implicit::resolve(node, &table.domains, &inventory, translate)?;
    let states = PowerStates {
        blocks: table.blocks,
        registers: table.registers,
        domains: table.domains,
        resources: inventory.resources,
        implicit,
    };
    Ok(states)
}

pub(super) fn validate_power_graph(states: &PowerStates) -> Result<(), String> {
    let power = states.power_requirements()?;
    let consumers = states
        .resources
        .iter()
        .enumerate()
        .map(|(id, resource)| Consumer {
            id,
            name: &resource.name,
            clocks: resource.activated_clocks(),
            power: &power[id],
            sinks: LifecycleSinks::default(),
            admission: resource.admission,
        })
        .collect::<Vec<_>>();
    // Validate the entire graph even when a broken record is unreferenced.
    coverage::analyze(&states.domains, &consumers)
        .map_err(|error| format!("PMGR coverage: {error:?}"))?;
    Ok(())
}

struct DomainTable {
    blocks: Vec<(u64, u64)>,
    registers: Vec<u64>,
    domains: Vec<Domain>,
}

/// Record normalization is separate from the full resource inventory and
/// coverage checks. This table alone never establishes lifecycle admission.
fn decode_domain_table(
    node: &Node<'_>,
    dies: Dies,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<DomainTable, String> {
    const PATH: &str = "/arm-io/pmgr";
    let reg = super::apertures::registers(node).ok_or("PMGR reg has incomplete pairs")?;
    let (layout, raw_blocks) = Layout::select(node.property("ps-regs"), node.property("ps-groups"))
        .map_err(String::from)?;
    let blocks = raw_blocks
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word))
        .collect::<Vec<_>>();
    let devices = node.property("devices").unwrap_or_default();
    if !raw_blocks.len().is_multiple_of(12) || !devices.len().is_multiple_of(PMGR_DEVICE) {
        return Err(format!(
            "{PATH} power-state groups or devices is not whole entries"
        ));
    }
    let mut spans: Vec<Option<(u64, u64)>> = alloc::vec![None; blocks.len() / 3];
    let mut registers = Vec::new();
    let mut domains = Vec::new();
    for (number, entry) in devices.as_chunks::<PMGR_DEVICE>().0.iter().enumerate() {
        let record = Record::parse(layout, entry)
            .map_err(|error| format!("{PATH} record {number}: {error}"))?;
        let parents = record
            .parents
            .map(|parent| (parent != 0).then(|| domain_id(parent)));
        let address = if let Some(location) = record.location {
            let (index, block) = (u64::from(location.index), location.group);
            let cells = blocks
                .get(block * 3..block * 3 + 3)
                .ok_or_else(|| format!("{PATH} device names absent power-state block {block}"))?;
            let &(range, bytes) = reg
                .get(cells[0] as usize)
                .ok_or_else(|| format!("{PATH} ps-regs block {block} names absent reg"))?;
            let offset = u64::from(cells[1])
                .checked_add(index * 8)
                .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= bytes))
                .ok_or_else(|| format!("{PATH} power state exceeds reg bank"))?;
            let view = translate(range, bytes)
                .ok_or_else(|| format!("{PATH} power-state view crosses its actual bus domain"))?;
            let physical = view
                .checked_add(offset)
                .ok_or_else(|| format!("{PATH} power-state physical word overflows"))?;
            let base = view
                .checked_add(u64::from(cells[1]))
                .ok_or_else(|| format!("{PATH} power-state base overflows"))?;
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
        } else {
            None
        };
        domains.push(Domain {
            name: record.name.into(),
            id: domain_id(record.id),
            address,
            parents,
        });
    }
    // Each further die repeats die 0's records in its own PMGR instance.
    // `_enableDeviceGated(device, ..., die)` (mac14j KC VA 0xfffffe0009b6990c)
    // indexes per-die state by `die * 800 + device` and passes its own die to
    // the parent walk (0xfffffe0009b69ac4), so parents stay on that die.
    let spans = spans.into_iter().flatten().collect::<Vec<_>>();
    let mut blocks = spans.clone();
    let first = domains.len();
    let first_registers = registers.len();
    for die in 1..dies.count {
        for &(base, bytes) in &spans {
            blocks.push((dies.place(die, base)?, bytes));
        }
        for index in 0..first_registers {
            registers.push(dies.place(die, registers[index])?);
        }
        for index in 0..first {
            let domain = &domains[index];
            let copy = Domain {
                name: domain.name.clone(),
                id: DomainId { die, ..domain.id },
                address: domain
                    .address
                    .map(|address| dies.place(die, address))
                    .transpose()?,
                parents: domain
                    .parents
                    .map(|parent| parent.map(|parent| DomainId { die, ..parent })),
            };
            domains.push(copy);
        }
    }
    registers.sort_unstable();
    if registers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(format!(
            "{PATH} die-stride overlaps another die's power states"
        ));
    }
    Ok(DomainTable {
        blocks,
        registers,
        domains,
    })
}

#[cfg(test)]
mod tests {
    /// Explicit physical bus for synthetic full-PA fixture records.
    fn flat_bus(children: &[alloc::vec::Vec<u8>]) -> alloc::vec::Vec<u8> {
        let ranges = [0u64, 0, 1u64 << 40]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<alloc::vec::Vec<_>>();
        crate::machine::adt::encode(&[("name", b"arm-io"), ("ranges", &ranges)], children)
    }

    use super::*;
    use crate::machine::soc::tests::flat_fixture_extent;
    use crate::machine::{adt::encode, soc::DART};

    #[test]
    #[ignore = "requires pinned original 26A434 board DeviceTrees; no Apple image is committed"]
    fn original_v2_board_graphs_preserve_all_parents_and_physical_locations() {
        use sha2::{Digest, Sha256};
        let directory =
            std::env::var("STELA_TEST_PMGR_ADTS").expect("original board ADT directory");
        for (file, expected_sha, domains, registers) in [
            (
                "DeviceTree.j614cap.adt",
                "d91252105f7335211ee5e2a6975cd0602b5de0725c47374aeb29811567de3971",
                490,
                263,
            ),
            (
                "DeviceTree.j700ap.adt",
                "b0fbf661a25626403fa1035ba681d5a7ab8ce13130e2a6d2320d4167255d0a88",
                296,
                138,
            ),
            (
                "DeviceTree.j704ap.adt",
                "66596bdffc33f951d20170b20dfbda79e28b144252144a6a7010ad4fa54bcd2e",
                387,
                141,
            ),
        ] {
            let bytes = std::fs::read(std::path::Path::new(&directory).join(file)).unwrap();
            assert_eq!(hex::encode(Sha256::digest(&bytes)), expected_sha);
            let root = Node::root(&bytes).unwrap();
            let io = root.child("arm-io").unwrap();
            let node = io.child("pmgr").unwrap();
            let states = decode_domain_table(&node, Dies::of(&root, &node).unwrap(), &|a, b| {
                io.translate_range(a, b)
            })
            .unwrap();
            assert_eq!(states.domains.len(), domains);
            assert_eq!(states.registers.len(), registers);
            let coverage = coverage::analyze(&states.domains, &[]).unwrap();
            assert!(coverage.iter().all(|domain| !domain.bindable()));
            // Account for every original resource, including repeated sibling
            // display names. This remains source accounting, not chip/device
            // admission or a lifecycle sink qualification.
            let complete = decode_power_states(&root, &node, &|address, bytes| {
                io.translate_range(address, bytes)
            })
            .unwrap();
            let consumers = complete
                .resources
                .iter()
                .enumerate()
                .map(|(id, resource)| Consumer {
                    id,
                    name: &resource.name,
                    clocks: resource.activated_clocks(),
                    power: &resource.power,
                    sinks: LifecycleSinks::default(),
                    admission: resource.admission,
                })
                .collect::<Vec<_>>();
            assert!(
                coverage::analyze(&complete.domains, &consumers)
                    .unwrap()
                    .iter()
                    .all(|domain| !domain.bindable())
            );
            let mut admissions = complete.clone();
            assert_eq!(admissions.apply_admission(&bytes, &[]), Ok(0));
            assert_eq!(admissions, complete);
            assert!(
                states
                    .domains
                    .iter()
                    .any(|domain| domain.parents[2].is_some())
            );
            if file == "DeviceTree.j704ap.adt" {
                let domain = states
                    .domains
                    .iter()
                    .find(|domain| domain.name == "AFISOCNI0")
                    .unwrap();
                assert_eq!(
                    domain.parents,
                    [53, 55, 36, 35].map(|id| Some(domain_id(id)))
                );
            }
        }
    }

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
        flat_bus(&children)
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
        let parsed = power_states(
            &Node::root(&encoded).unwrap(),
            &flat_fixture_extent(&Some),
            0x8112,
        )
        .unwrap()
        .unwrap();
        let consumers = parsed
            .resources
            .iter()
            .enumerate()
            .map(|(id, resource)| Consumer {
                id,
                name: &resource.name,
                clocks: resource.activated_clocks(),
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
        let states = power_states(
            &Node::root(&bytes).unwrap(),
            &flat_fixture_extent(&Some),
            0x8112,
        )
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
    fn repeated_sibling_names_keep_actual_ancestry_and_ambiguous_admission_is_atomic() {
        let first = encode(&[("name", b"view")], &[]);
        let leaf = encode(&[("name", b"leaf")], &[]);
        let second = encode(&[("name", b"view"), ("reg", &words(&[0]))], &[leaf]);
        let hidden = encode(
            &[("name", b"hidden"), ("clock-gates", &words(&[1]))],
            &[first, second],
        );
        let bytes = tree(&[(1, Some(0), [0, 0])], &[hidden]);
        let mut states = power_states(
            &Node::root(&bytes).unwrap(),
            &flat_fixture_extent(&Some),
            0x8112,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            states.apply_admission(&bytes, &["/arm-io/hidden".into()]),
            Ok(2)
        );
        let repeated = states
            .resources
            .iter()
            .filter(|r| r.name == "/arm-io/hidden/view")
            .map(|r| r.admission)
            .collect::<Vec<_>>();
        assert_eq!(repeated, [Admission::Unavailable, Admission::Required]);
        assert_eq!(
            states.resources.last().unwrap().admission,
            Admission::Required
        );
        let before = states.clone();
        for entry in ["/arm-io/hidden/view", "/arm-io/hidden/view +no-pmu"] {
            assert!(
                states
                    .apply_admission(&bytes, &[entry.into()])
                    .unwrap_err()
                    .contains("ambiguous")
            );
            assert_eq!(states, before);
        }
        // A full path with only one matching node remains usable even when
        // a shorter ancestor path has multiple matches.
        assert_eq!(
            states.apply_admission(&bytes, &["/arm-io/hidden/view/leaf".into()]),
            Ok(1)
        );
        assert_eq!(
            states.resources.last().unwrap().admission,
            Admission::Unavailable
        );
        assert!(
            states.resources[..states.resources.len() - 1]
                .iter()
                .all(|r| r.admission == Admission::Required)
        );
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
        let mut states = power_states(
            &Node::root(&bytes).unwrap(),
            &flat_fixture_extent(&Some),
            0x8112,
        )
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
        let mut states = power_states(
            &Node::root(&bytes).unwrap(),
            &flat_fixture_extent(&Some),
            0x8112,
        )
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
        let mut states = power_states(
            &root,
            &|address, bytes| {
                root.child("arm-io")
                    .unwrap()
                    .translate_range(address, bytes)
            },
            0x8112,
        )
        .unwrap()
        .unwrap();
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
            .enumerate()
            .map(|(id, resource)| Consumer {
                id,
                name: &resource.name,
                clocks: resource.activated_clocks(),
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
        let states = power_states(
            &Node::root(&bytes).unwrap(),
            &flat_fixture_extent(&Some),
            0x8112,
        )
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
        // An absent sid-count is 16 streams, so SID 15 is a native mapper.
        assert_eq!(owner("/arm-io/modern/mapper"), Some(PowerOwner::Dart(1)));
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
            let states = power_states(
                &Node::root(&bytes).unwrap(),
                &flat_fixture_extent(&Some),
                0x8112,
            )
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
        let states = power_states(
            &Node::root(&bytes).unwrap(),
            &flat_fixture_extent(&Some),
            0x8112,
        )
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
            assert!(
                power_states(
                    &Node::root(&bytes).unwrap(),
                    &flat_fixture_extent(&Some),
                    0x8112
                )
                .is_err()
            );
        }
        for property in ["clock-gates", "power-gates"] {
            let malformed = encode(&[("name", b"controller"), (property, &[1, 0, 0])], &[]);
            let bytes = tree(&records, &[malformed]);
            assert!(
                power_states(
                    &Node::root(&bytes).unwrap(),
                    &flat_fixture_extent(&Some),
                    0x8112
                )
                .is_err()
            );
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
        let states = power_states(
            &root,
            &|address, bytes| {
                root.child("arm-io")
                    .unwrap()
                    .translate_range(address, bytes)
            },
            0x8112,
        )
        .unwrap()
        .unwrap();
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
            .enumerate()
            .map(|(id, resource)| Consumer {
                id,
                name: &resource.name,
                clocks: resource.activated_clocks(),
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
    /// A synthetic SoC with CPUs on `dies` dies, two die-0 records (device 2
    /// parented by device 1) and one consumer gating device 2 on each die.
    fn multi_die(dies: u32, compatible: &[u8], stride: Option<u64>) -> Vec<u8> {
        let devices = [(1u16, 0u8, 0u16), (2, 1, 1)]
            .into_iter()
            .flat_map(|(id, index, parent)| {
                let mut record = [0; PMGR_DEVICE];
                record[4..6].copy_from_slice(&parent.to_le_bytes());
                record[10] = index;
                record[26..28].copy_from_slice(&id.to_le_bytes());
                record
            })
            .collect::<Vec<_>>();
        let reg = [0x1000u64, 0x1000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let ps = words(&[0, 0, 0]);
        let stride = stride.map(u64::to_le_bytes);
        let mut properties = alloc::vec![
            ("name", b"pmgr".as_slice()),
            ("compatible", compatible),
            ("reg", &reg),
            ("ps-regs", &ps),
            ("devices", &devices),
        ];
        if let Some(stride) = &stride {
            properties.push(("die-stride", stride));
        }
        let pmgr = encode(&properties, &[]);
        let gates = words(&[2, 0x1000_0002]);
        let usb = encode(&[("name", b"usb"), ("clock-gates", &gates)], &[]);
        let cpus = (0..2)
            .map(|cpu| {
                let die = words(&[cpu * (dies - 1)]);
                encode(&[("name", b"cpu"), ("die-id", &die)], &[])
            })
            .collect::<Vec<_>>();
        encode(
            &[("name", b"device-tree")],
            &[encode(&[("name", b"cpus")], &cpus), flat_bus(&[pmgr, usb])],
        )
    }

    fn multi_die_states(bytes: &[u8]) -> Result<PowerStates, String> {
        let root = Node::root(bytes).unwrap();
        let io = root.child("arm-io").unwrap();
        decode_power_states(&root, &io.child("pmgr").unwrap(), &|address, bytes| {
            io.translate_range(address, bytes)
        })
    }

    #[test]
    fn die_qualified_gates_reach_each_dies_strided_pmgr_records() {
        let id = |die, device| DomainId { die, device };
        for (compatible, property, stride) in [
            (&b"pmgr1,t8112"[..], Some(0x40_0000_0000), 0x40_0000_0000),
            // Without die-stride the bound family driver's stride applies.
            (b"pmgr1,t6001", None, 1 << 37),
            (b"pmgr1,t6021", Some(0), 1 << 37),
        ] {
            let states = multi_die_states(&multi_die(2, compatible, property)).unwrap();
            assert_eq!(
                states.domains.iter().map(|d| d.id).collect::<Vec<_>>(),
                [id(0, 1), id(0, 2), id(1, 1), id(1, 2)]
            );
            assert_eq!(states.domains[2].address, Some(0x1000 + stride));
            assert_eq!(states.domains[3].address, Some(0x1008 + stride));
            assert_eq!(states.domains[3].parents[0], Some(id(1, 1)));
            assert_eq!(
                states.registers,
                [0x1000, 0x1008, 0x1000 + stride, 0x1008 + stride]
            );
            assert_eq!(states.blocks, [(0x1000, 0xc), (0x1000 + stride, 0xc)]);
            let usb = states
                .resources
                .iter()
                .find(|resource| resource.name == "/arm-io/usb")
                .unwrap();
            assert_eq!(usb.clocks, [id(0, 2), id(1, 2)]);
            let consumers = [Consumer {
                id: 0,
                name: &usb.name,
                clocks: &usb.clocks,
                power: &[],
                sinks: LifecycleSinks::default(),
                admission: Admission::Required,
            }];
            // Each die's request reaches that die's register and its parent.
            let coverage = coverage::analyze(&states.domains, &consumers).unwrap();
            assert_eq!(coverage.len(), 4);
            assert!(coverage.iter().all(|domain| domain.consumers.len() == 1));
        }
    }

    #[test]
    fn unplaced_dies_and_reserved_gate_bits_stay_explicit_requirements() {
        // A die without a qualified stride has no placed PMGR instance.
        let error = multi_die_states(&multi_die(2, b"pmgr1,t8112", None)).unwrap_err();
        assert!(error.contains("without a qualified die-stride"), "{error}");
        // A one-die SoC places no die-1 records for a die-1 gate.
        let error = multi_die_states(&multi_die(1, b"pmgr1,t8112", None)).unwrap_err();
        assert!(error.contains("UnknownRequirement"), "{error}");
        // A stride inside one die's bank never aliases two dies' registers.
        let error = multi_die_states(&multi_die(2, b"pmgr1,t8112", Some(8))).unwrap_err();
        assert!(error.contains("overlaps another die"), "{error}");
        // The 4-bit die field reaches 16 dies.
        let error = multi_die_states(&multi_die(17, b"pmgr1,t8112", Some(1))).unwrap_err();
        assert!(error.contains("exceeds the PMGR die field"), "{error}");
        let bytes = encode(&[("clock-gates", &words(&[0x0001_0002]))], &[]);
        assert!(
            gate_ids(&Node::root(&bytes).unwrap(), "/node", "clock-gates")
                .unwrap_err()
                .contains("reserved")
        );
        let bytes = encode(&[("clock-gates", &words(&[0xf000_0002]))], &[]);
        assert_eq!(
            gate_ids(&Node::root(&bytes).unwrap(), "/node", "clock-gates"),
            Ok(alloc::vec![DomainId { die: 15, device: 2 }])
        );
    }

    #[test]
    fn physical_candidates_follow_nested_bus_domains_and_never_alias_protocol_slaves() {
        let reg = [0x100u64, 0x1000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let uart = encode(
            &[
                ("name", b"uart"),
                ("compatible", super::super::UART.as_bytes()),
                ("reg", &reg),
            ],
            &[],
        );
        let ranges = [0u64, 0x2000, 0x2000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let nested = encode(
            &[("name", b"nested"), ("ranges", &ranges)],
            core::slice::from_ref(&uart),
        );
        let protocol = encode(
            &[
                ("name", b"serial"),
                ("compatible", super::super::SPI.as_bytes()),
            ],
            &[uart],
        );
        let root_ranges = [0u64, 0x100000000, 0x10000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let bytes = encode(
            &[("name", b"arm-io"), ("ranges", &root_ranges)],
            &[nested, protocol],
        );
        let resources = inventory(&Node::root(&bytes).unwrap()).unwrap();
        let owner = |path| {
            resources
                .iter()
                .find(|entry| entry.name == path)
                .unwrap()
                .owner
        };
        assert_eq!(
            owner("/arm-io/nested/uart"),
            Some(PowerOwner::Mmio(0x100002100))
        );
        assert_eq!(owner("/arm-io/serial/uart"), None);
    }
}
