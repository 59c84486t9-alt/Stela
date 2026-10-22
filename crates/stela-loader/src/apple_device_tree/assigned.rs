//! Atomic ADT enumeration projection from one checked assigned-core plan.
//!
//! XNU's CPU parser enumerates every `/cpus` child; `state` identifies the
//! boot PE, it does not disable an unassigned PE. Firmware `cpu-id` and
//! `l2-cache-id` are separate from the kernel's dense IDs and our resource
//! IDs. IDs are preserved by default; an explicitly qualified recipe may
//! project CPU IDs and their watchdog records together. Source identities and
//! startup/interrupt/power payloads are preserved in either case.
//! Source coordinates: original 26A434 J314s iBoot SHA-256
//! 20dfa3a5e6d4e4b2844c7558e6d4f8ab74397d11eae63312f00a559cf9612b03,
//! file 0x3ab04..0x3ab7c publishes u32 max_cpus/cpu-cluster-count/E/P
//! counts; 0x3abd4..0x3abf8 publishes running. Original mac13j kernel
//! SHA-256 5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90,
//! VA 0xfffffe000bda7168 CPU parser enumerates the children and derives
//! logical IDs/physical cluster/cache topology. Public XNU xnu-12377.121.6
//! machine_routines.c, IOPlatformExpert.cpp and AppleARMSMP.cpp independently
//! explain these interfaces; that distinct release is not the binary's source.
//! The fixed cluster-count producer alone does not qualify reduced-cluster
//! consumer semantics: callers must supply qualified field rules explicitly.
//!
//! This module does not admit the supplied source/resource bindings or create
//! additional hardware slots, native workers or initial lifecycle authority.
use super::{DeviceTree, Node};
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use stela_runtime::machine::soc::assigned::{
    CacheId, DomainId, GuestSlotId, InterruptId, Plan, PlanIdentity, StartId,
};
mod cpu_ids;
pub use cpu_ids::{CpuIdMapping, CpuIdRecipe, WatchdogProjection};

const CPUS: &str = "/cpus";
const RUNNING: &[u8] = b"running\0";
const WAITING: &[u8] = b"waiting\0";

/// Explicit source-node/resource association supplied by the qualified owner.
/// IDs are not interpreted as firmware IDs, addresses, masks or phandles.
#[derive(Debug, Clone, Copy)]
pub struct NodeBinding<'a> {
    pub slot: GuestSlotId,
    pub name: &'a str,
    pub midr: u64,
    pub cache: CacheId,
    pub interrupt: InterruptId,
    pub start: StartId,
    pub core_power: DomainId,
    pub cluster_power: DomainId,
}
#[derive(Debug, Clone, Copy)]
pub enum Count {
    Pes,
    Clusters,
    CoreType(u8),
}
/// A source-qualified count property. Values have the original u32 encoding.
/// Absent fields are created only when explicitly listed by the caller.
#[derive(Debug, Clone, Copy)]
pub struct CountField<'a> {
    pub path: &'a str,
    pub property: &'a str,
    pub count: Count,
}
#[derive(Debug, Clone, Copy)]
pub enum ReferenceEncoding {
    /// Every u32 cell names a CPU node's AAPL,phandle.
    Phandles,
    /// Every u32 cell names the original firmware cpu-id (not logical ID).
    FirmwareCpuIds,
}
/// A source-qualified external CPU reference list. A reference to a removed
/// CPU refuses projection; its consumers need their own qualified adaptation.
#[derive(Debug, Clone, Copy)]
pub struct ReferenceField<'a> {
    pub path: &'a str,
    pub property: &'a str,
    pub encoding: ReferenceEncoding,
}
/// Immutable input identity and actual retained CPU resource bindings. Every
/// original CPU is independently shape/identity validated before projection;
/// removed CPUs need no invented executor or lifecycle IDs. The source owner
/// must still qualify all topology consumers; arbitrary property bytes
/// are not guessed to be phandles, IDs or CPU masks. This metadata grants no
/// device/executor authority or completeness credit for unqualified consumers.
#[derive(Debug)]
pub struct SourceBindings<'a> {
    pub source_set_sha256: [u8; 32],
    pub tree_sha256: [u8; 32],
    pub nodes: &'a [NodeBinding<'a>],
    pub counts: &'a [CountField<'a>],
    pub references: &'a [ReferenceField<'a>],
    /// Explicitly qualified coordinated consumer recipe; ordinary projections
    /// preserve source IDs and cannot opt into renumbering implicitly.
    pub cpu_ids: CpuIdRecipe<'a>,
}

#[derive(Debug)]
pub struct Projection<'p, 's> {
    plan: &'p Plan<'s>,
    original: DeviceTree,
    projected: DeviceTree,
    receipt: Receipt,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub plan: PlanIdentity,
    pub source_sha256: [u8; 32],
    pub projected_sha256: [u8; 32],
    pub boot_path: String,
    pub removed: Vec<String>,
    pub cpu_ids: Vec<CpuIdMapping>,
    pub watchdog: Option<WatchdogProjection>,
}
fn canonical_path(path: &str) -> bool {
    path == "/"
        || (path.starts_with('/')
            && path[1..]
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."))
}
fn validate_tree(node: &Node, depth: usize) -> Result<()> {
    ensure!(
        depth <= super::MAX_DEPTH,
        "DeviceTree topology nesting is too deep"
    );
    let mut properties = BTreeSet::new();
    for p in &node.properties {
        ensure!(
            properties.insert(p.name()),
            "duplicate DeviceTree property {}",
            p.name()
        );
    }
    let mut children = BTreeSet::new();
    for child in &node.children {
        let name = child.name().context("unnamed DeviceTree child")?;
        ensure!(
            !name.is_empty() && !name.contains('/') && children.insert(name),
            "ambiguous DeviceTree child name"
        );
        validate_tree(child, depth + 1)?;
    }
    Ok(())
}
fn digest(tree: &DeviceTree) -> [u8; 32] {
    Sha256::digest(tree.serialize()).into()
}
fn word(node: &Node, name: &str) -> Result<u32> {
    let p = node
        .property(name)
        .with_context(|| format!("CPU missing {name}"))?;
    ensure!(!p.placeholder, "CPU {name} is an unresolved template value");
    p.as_u32()
        .with_context(|| format!("CPU {name} is not a u32"))
}
fn bytes<'a>(node: &'a Node, name: &str) -> Result<&'a [u8]> {
    let p = node
        .property(name)
        .with_context(|| format!("CPU missing {name}"))?;
    ensure!(!p.placeholder, "CPU {name} is an unresolved template value");
    Ok(&p.value)
}
fn check_range(node: &Node, name: &str, base: u64, size: u64) -> Result<()> {
    let v = bytes(node, name)?;
    ensure!(v.len() == 16, "CPU {name} is not a base/size pair");
    ensure!(
        v[..8] == base.to_le_bytes() && v[8..] == size.to_le_bytes(),
        "CPU {name} differs from the plan's retained resource"
    );
    Ok(())
}
/// T8112's original normal-mode MPIDR/CPU association contract supplies these
/// coordinates from raw reg (apple-socs.md, original J473 CPU power ownership).
/// The original templates omit the three fields; never add them to the ADT.
fn t8112_coordinates(node: &Node, soc: u32) -> Result<Option<[u32; 3]>> {
    if soc != 0x8112 {
        return Ok(None);
    }
    let reg = word(node, "reg")?;
    ensure!(
        reg & !0x103 == 0 && word(node, "cluster-id")? == reg >> 8,
        "unqualified T8112 CPU affinity/cluster coordinates"
    );
    let coordinates = [0, reg >> 8, reg & 3];
    for (field, expected) in ["die-id", "die-cluster-id", "cluster-core-id"]
        .into_iter()
        .zip(coordinates)
    {
        if node.property(field).is_some() {
            ensure!(
                word(node, field)? == expected,
                "T8112 {field} differs from source affinity"
            );
        }
    }
    Ok(Some(coordinates))
}
fn shape(node: &Node, soc: u32) -> Result<()> {
    ensure!(
        node.children.is_empty(),
        "nested CPU topology needs a qualified schema"
    );
    let mut names = BTreeSet::new();
    for p in &node.properties {
        ensure!(
            names.insert(p.name()),
            "duplicate CPU property {}",
            p.name()
        );
    }
    ensure!(
        bytes(node, "device_type")? == b"cpu\0",
        "non-CPU child under /cpus"
    );
    ensure!(
        [WAITING, RUNNING].contains(&bytes(node, "state")?),
        "unqualified CPU state"
    );
    ensure!(
        !bytes(node, "compatible")?.is_empty(),
        "missing CPU ISA compatible"
    );
    ensure!(
        node.property("status").is_none(),
        "CPU status needs a qualified enumeration schema"
    );
    for field in ["l3-cache-size", "l3-cache-id"] {
        if node.property(field).is_some() {
            ensure!(
                word(node, field)? == 0,
                "CPU L3 resources are not represented by this plan"
            );
        }
    }
    word(node, "cpu-id")?;
    ensure!(
        word(node, "AAPL,phandle")? != 0,
        "zero original CPU phandle"
    );
    for field in ["cluster-id", "l2-cache-size"] {
        word(node, field)?;
    }
    if t8112_coordinates(node, soc)?.is_none() {
        for field in ["die-id", "die-cluster-id", "cluster-core-id"] {
            word(node, field)?;
        }
    }
    let kind = bytes(node, "cluster-type")?;
    ensure!(
        !kind.is_empty() && kind[0] != 0 && kind[1..].iter().all(|v| *v == 0),
        "invalid original CPU cluster-type"
    );
    for field in ["cpu-impl-reg", "acc-impl-reg", "cpm-impl-reg"] {
        let raw = bytes(node, field)?;
        ensure!(raw.len() == 16, "CPU {field} is not a base/size pair");
        let base = u64::from_le_bytes(raw[..8].try_into().unwrap());
        let size = u64::from_le_bytes(raw[8..].try_into().unwrap());
        ensure!(
            base != 0 && size != 0 && base.checked_add(size).is_some(),
            "invalid original CPU {field} extent"
        );
    }
    Ok(())
}

impl<'p, 's> Projection<'p, 's> {
    /// Preflight the complete plan and source before creating a candidate.
    /// Source nodes are never cloned into additional slots or renumbered.
    pub fn prepare(
        plan: &'p Plan<'s>,
        tree: &DeviceTree,
        source: &SourceBindings<'_>,
    ) -> Result<Self> {
        plan.revalidate()
            .map_err(|e| anyhow::anyhow!("topology plan changed: {e:?}"))?;
        validate_tree(&tree.root, 0)?;
        ensure!(
            source.source_set_sha256 == plan.profile().input_set_sha256,
            "topology source set differs from plan"
        );
        ensure!(
            source.tree_sha256 != [0; 32] && digest(tree) == source.tree_sha256,
            "original DeviceTree identity mismatch"
        );
        // The pinned public XNU L2-sharing consumer walks a contiguous
        // first_cpu_id..first_cpu_id+num_cpus interval for each cluster.
        // Preserve plan logical IDs; refuse an unsupported order instead of
        // silently changing that identity during projection.
        let mut completed = BTreeSet::new();
        let mut last = None;
        for pe in plan.pes() {
            if last != Some(pe.cluster) {
                ensure!(
                    !completed.contains(&pe.cluster),
                    "noncontiguous cluster enumeration requires a qualified cache consumer"
                );
                if let Some(cluster) = last {
                    completed.insert(cluster);
                }
                last = Some(pe.cluster);
            }
        }
        let cpus = tree.node(CPUS).context("DeviceTree has no /cpus")?;
        ensure!(
            word(cpus, "#address-cells")? == 1 && word(cpus, "#size-cells")? == 0,
            "unqualified /cpus address/size encoding"
        );
        let mut phandles = BTreeSet::new();
        let mut firmware_ids = BTreeSet::new();
        let mut affinities = BTreeSet::new();
        // Source enumeration and native ownership are separate phases. Validate
        // ALL original nodes, including those that will be removed, without
        // requiring fabricated resources for an unassigned hardware slot.
        for node in &cpus.children {
            shape(node, plan.profile().soc)?;
            let reg = word(node, "reg")?;
            ensure!(
                reg <= 0xffff && affinities.insert(reg),
                "invalid or duplicate original CPU affinity"
            );
            ensure!(
                phandles.insert(word(node, "AAPL,phandle")?)
                    && firmware_ids.insert(word(node, "cpu-id")?),
                "duplicate original CPU phandle/firmware ID"
            );
        }
        let mut names = BTreeSet::new();
        let mut slots = BTreeSet::new();
        for binding in source.nodes {
            ensure!(
                !binding.name.contains('/') && !binding.name.is_empty(),
                "invalid CPU source name"
            );
            ensure!(
                names.insert(binding.name) && slots.insert(binding.slot),
                "duplicate CPU source binding"
            );
            cpus.child(binding.name)
                .context("CPU binding has no original node")?;
        }
        let mut projected = tree.clone();
        let mut selected = Vec::with_capacity(plan.pes().len());
        let mut retained_phandles = BTreeSet::new();
        let mut retained_firmware_ids = BTreeSet::new();
        let mut boot_path = String::new();
        for pe in plan.pes() {
            let binding = source
                .nodes
                .iter()
                .find(|b| b.slot == pe.slot)
                .with_context(|| format!("missing declared source CPU slot {:?}", pe.slot))?;
            ensure!(
                binding.midr == pe.identity.midr
                    && binding.cache == pe.cache
                    && binding.interrupt == pe.interrupt
                    && binding.start == pe.start
                    && binding.core_power == pe.core_power
                    && binding.cluster_power == pe.cluster_power,
                "CPU source ISA/resource binding differs from plan slot {:?}",
                pe.slot
            );
            let node = cpus.child(binding.name).unwrap();
            let cluster = plan
                .clusters()
                .iter()
                .find(|c| c.resource.id == pe.cluster)
                .unwrap();
            for (key, expected) in [
                ("reg", pe.reg),
                ("cluster-id", cluster.resource.firmware_id),
                ("l2-cache-size", cluster.cache.geometry.bytes),
            ] {
                ensure!(
                    word(node, key)? == expected,
                    "CPU {key} differs from plan slot {:?}",
                    pe.slot
                );
            }
            let implicit = t8112_coordinates(node, plan.profile().soc)?;
            for (index, (key, expected)) in [
                ("die-id", cluster.resource.die),
                ("die-cluster-id", cluster.resource.die_cluster),
                ("cluster-core-id", pe.cluster_core),
            ]
            .into_iter()
            .enumerate()
            {
                let actual = if node.property(key).is_some() {
                    word(node, key)?
                } else {
                    implicit.context("CPU coordinate has no qualified source schema")?[index]
                };
                ensure!(
                    actual == expected,
                    "CPU {key} differs from plan slot {:?}",
                    pe.slot
                );
            }
            let kind = bytes(node, "cluster-type")?;
            ensure!(
                kind.first() == Some(&pe.cluster_type) && kind[1..].iter().all(|v| *v == 0),
                "CPU cluster-type differs from plan"
            );
            check_range(node, "cpu-impl-reg", pe.cpu_impl.base, pe.cpu_impl.bytes)?;
            check_range(node, "acc-impl-reg", pe.acc_impl.base, pe.acc_impl.bytes)?;
            check_range(node, "cpm-impl-reg", pe.cpm_impl.base, pe.cpm_impl.bytes)?;
            retained_phandles.insert(word(node, "AAPL,phandle")?);
            retained_firmware_ids.insert(word(node, "cpu-id")?);
            let mut node = node.clone();
            node.set_property("state", if pe.boot { RUNNING } else { WAITING }.to_vec())?;
            if pe.boot {
                boot_path = format!("{CPUS}/{}", binding.name);
            }
            selected.push(node);
        }
        let cpu_ids = cpu_ids::Prepared::prepare(plan, tree, source)?;
        // Explicitly typed external lists are checked, never rewritten with
        // guessed mask/ID semantics. Ordinary matching integer values are not
        // evidence of a CPU reference.
        let mut locations = BTreeSet::new();
        for field in source.references {
            ensure!(canonical_path(field.path), "noncanonical CPU consumer path");
            ensure!(
                locations.insert((field.path, field.property)),
                "duplicate CPU consumer location"
            );
            ensure!(
                !field.path.starts_with("/cpus/"),
                "external reference points inside CPU node"
            );
            let p = tree
                .property(field.path, field.property)
                .context("missing CPU reference property")?;
            ensure!(
                !p.placeholder && p.value.len().is_multiple_of(4),
                "invalid CPU reference encoding"
            );
            let retained = match field.encoding {
                ReferenceEncoding::Phandles => &retained_phandles,
                ReferenceEncoding::FirmwareCpuIds => &retained_firmware_ids,
            };
            for cell in p.value.as_chunks::<4>().0 {
                let id = u32::from_le_bytes(*cell);
                ensure!(
                    retained.contains(&id),
                    "CPU consumer {}/{} references removed or unknown CPU {id}",
                    field.path,
                    field.property
                );
                if matches!(field.encoding, ReferenceEncoding::FirmwareCpuIds) {
                    ensure!(
                        cpu_ids.preserves_reference(id),
                        "CPU ID consumer needs a coordinated projection recipe"
                    );
                }
            }
        }
        projected.node_mut(CPUS).unwrap().children = selected;
        for field in source.counts {
            ensure!(canonical_path(field.path), "noncanonical CPU count path");
            ensure!(
                locations.insert((field.path, field.property)),
                "duplicate CPU consumer location"
            );
            ensure!(
                !field.path.starts_with("/cpus/"),
                "count property overwrites a CPU field"
            );
            if let Some(p) = tree.property(field.path, field.property) {
                ensure!(
                    !p.placeholder && p.as_u32().is_some(),
                    "unqualified CPU count encoding"
                );
            }
            let count = match field.count {
                Count::Pes => plan.pes().len(),
                Count::Clusters => plan.clusters().len(),
                Count::CoreType(kind) => plan
                    .pes()
                    .iter()
                    .filter(|pe| pe.cluster_type == kind)
                    .count(),
            };
            projected.set_property(
                field.path,
                field.property,
                u32::try_from(count)?.to_le_bytes().to_vec(),
            )?;
        }
        // Known topology fields cannot silently retain stale counts/masks or
        // unqualified reference schemas. Source owners must list each one.
        fn consumers(node: &Node, path: &str, locations: &BTreeSet<(&str, &str)>) -> Result<()> {
            if !path.starts_with("/cpus/") {
                for p in &node.properties {
                    if matches!(
                        p.name(),
                        "max_cpus"
                            | "e-core-count"
                            | "p-core-count"
                            | "m-core-count"
                            | "cpu-count"
                            | "cpu-cluster-count"
                            | "cluster-count"
                            | "cpu-map"
                            | "cpu-mask"
                            | "cpumask"
                            | "#main-cpus"
                    ) {
                        ensure!(
                            locations.contains(&(path, p.name())),
                            "unqualified CPU consumer {path}/{}",
                            p.name()
                        );
                    }
                }
            }
            for child in &node.children {
                let name = child.name().context("unnamed DeviceTree node")?;
                let next = format!("{}/{name}", path.trim_end_matches('/'));
                consumers(child, &next, locations)?;
            }
            Ok(())
        }
        consumers(&tree.root, "/", &locations)?;
        let (cpu_ids, watchdog) = cpu_ids.apply(&mut projected)?;
        let removed = cpus
            .children
            .iter()
            .filter(|node| {
                !projected
                    .node(CPUS)
                    .unwrap()
                    .children
                    .iter()
                    .any(|selected| selected.name() == node.name())
            })
            .map(|node| format!("{CPUS}/{}", node.name().expect("validated original name")))
            .collect();
        let receipt = Receipt {
            plan: plan.identity(),
            source_sha256: source.tree_sha256,
            projected_sha256: digest(&projected),
            boot_path,
            removed,
            cpu_ids,
            watchdog,
        };
        plan.revalidate()
            .map_err(|e| anyhow::anyhow!("topology plan changed: {e:?}"))?;
        Ok(Self {
            plan,
            original: tree.clone(),
            projected,
            receipt,
        })
    }
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    /// Complete validation precedes this single replacement. No fallible
    /// operation follows mutation; stale source/plan leaves the tree intact.
    pub fn apply(self, tree: &mut DeviceTree) -> Result<Receipt> {
        self.plan
            .revalidate()
            .map_err(|e| anyhow::anyhow!("topology plan changed: {e:?}"))?;
        ensure!(
            *tree == self.original,
            "DeviceTree changed after topology preflight"
        );
        *tree = self.projected;
        Ok(self.receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::cell::Cell;
    use stela_runtime::machine::{
        Chip,
        caches::Cache,
        soc::assigned::{
            AssignedCore, Assignment, Capacity, CapacityKind, ClusterId, ClusterSlot, CoreKind,
            InterruptTarget, KindId, PeSlot, PowerResource, RegisterRange, ResourceProfile,
            Resources, RetainedResources, RetainedRoster, SharedCache, StartResource,
        },
    };
    struct Roster {
        cores: Vec<AssignedCore>,
        revision: Cell<u64>,
    }
    impl RetainedRoster for Roster {
        fn revision(&self) -> u64 {
            self.revision.get()
        }
        fn cores(&self) -> &[AssignedCore] {
            &self.cores
        }
    }
    struct Inventory {
        soc: u32,
        capacities: Vec<Capacity>,
        kinds: Vec<CoreKind>,
        slots: Vec<PeSlot>,
        clusters: Vec<ClusterSlot>,
        caches: Vec<SharedCache>,
        interrupts: Vec<InterruptTarget>,
        starts: Vec<StartResource>,
        powers: Vec<PowerResource>,
    }
    impl RetainedResources for Inventory {
        fn revision(&self) -> u64 {
            1
        }
        fn resources(&self) -> Resources<'_> {
            Resources {
                profile: ResourceProfile {
                    chip: Chip::AppleM1,
                    soc: self.soc,
                    board: 8,
                    input_set_sha256: [1; 32],
                    adapted_set_sha256: None,
                },
                register_granule: 0x4000,
                provenance: "synthetic test resource ownership",
                capacities: &self.capacities,
                kinds: &self.kinds,
                slots: &self.slots,
                clusters: &self.clusters,
                caches: &self.caches,
                interrupts: &self.interrupts,
                starts: &self.starts,
                powers: &self.powers,
            }
        }
    }
    fn power(id: u16) -> DomainId {
        DomainId { die: 0, device: id }
    }
    fn range(index: u64) -> RegisterRange {
        RegisterRange {
            base: 0x1000_0000 + index * 0x10000,
            bytes: 0x9008,
        }
    }
    fn set_word(node: &mut Node, name: &str, value: u32) {
        node.set_property(name, value.to_le_bytes().to_vec())
            .unwrap();
    }
    fn set_range(node: &mut Node, name: &str, range: RegisterRange) {
        let mut v = range.base.to_le_bytes().to_vec();
        v.extend(range.bytes.to_le_bytes());
        node.set_property(name, v).unwrap();
    }
    struct Fixture {
        tree: DeviceTree,
        inventory: Inventory,
        host: Roster,
        assignments: Vec<Assignment>,
        bindings: Vec<NodeBinding<'static>>,
        counts: Vec<CountField<'static>>,
    }
    impl Fixture {
        fn new() -> Self {
            let data = Cache {
                bytes: 64 << 10,
                ways: 4,
                line: 64,
            };
            let mut inventory = Inventory {
                soc: 0x6000,
                capacities: [
                    CapacityKind::KernelCpus,
                    CapacityKind::KernelClusters,
                    CapacityKind::KernelAffinitySpan,
                    CapacityKind::KernelPhysicalCluster,
                    CapacityKind::KernelCpuMask,
                    CapacityKind::MonitorCpus,
                    CapacityKind::PlatformCpus,
                    CapacityKind::PlatformClusters,
                ]
                .into_iter()
                .map(|kind| Capacity {
                    kind,
                    maximum: Some(20),
                    provenance: "synthetic",
                })
                .collect(),
                kinds: vec![],
                slots: vec![],
                clusters: vec![],
                caches: vec![],
                interrupts: vec![],
                starts: vec![],
                powers: vec![],
            };
            for (i, kind) in (*b"EP").into_iter().enumerate() {
                inventory.kinds.push(CoreKind {
                    id: KindId(i as u32),
                    cluster_type: kind,
                    midr: 0x6100_0000 + i as u64,
                    aff2: i as u8,
                    clock: None,
                    instruction: data,
                    data,
                });
                inventory.clusters.push(ClusterSlot {
                    id: ClusterId(i as u32),
                    aff1: i as u8,
                    firmware_id: i as u32 + 10,
                    die: 0,
                    die_cluster: i as u32,
                    cache: Some(CacheId(i as u32)),
                    power: Some(power(10 + i as u16)),
                    acc_impl: Some(range(10 + i as u64 * 2)),
                    cpm_impl: Some(range(11 + i as u64 * 2)),
                });
                inventory.caches.push(SharedCache {
                    id: CacheId(i as u32),
                    cluster: ClusterId(i as u32),
                    geometry: Cache {
                        bytes: (4 << 20) << i,
                        ways: 16,
                        line: 128,
                    },
                });
                inventory.powers.push(PowerResource {
                    id: power(10 + i as u16),
                    cores: vec![],
                    clusters: vec![ClusterId(i as u32)],
                });
            }
            let mut cpus = Node::named("cpus").unwrap();
            set_word(&mut cpus, "#address-cells", 1);
            set_word(&mut cpus, "#size-cells", 0);
            let mut bindings = vec![];
            for (i, name) in ["cpu0", "cpu1", "cpu2"].into_iter().enumerate() {
                let cluster = usize::from(i == 2);
                let kind = inventory.kinds[cluster];
                let reg = if i == 2 { 0x100 } else { i as u32 };
                let id = GuestSlotId(7 + i as u32);
                inventory.slots.push(PeSlot {
                    id,
                    reg,
                    kind: Some(kind.id),
                    cluster: ClusterId(cluster as u32),
                    cluster_core: if i == 2 { 0 } else { i as u32 },
                    interrupt: Some(InterruptId(i as u32)),
                    start: Some(StartId(i as u32)),
                    power: Some(power(i as u16)),
                    cpu_impl: Some(range(i as u64)),
                });
                inventory.interrupts.push(InterruptTarget {
                    id: InterruptId(i as u32),
                    reg,
                });
                inventory.starts.push(StartResource {
                    id: StartId(i as u32),
                    reg,
                });
                inventory.powers.push(PowerResource {
                    id: power(i as u16),
                    cores: vec![id],
                    clusters: vec![],
                });
                let c = inventory.clusters[cluster];
                let mut n = Node::named(name).unwrap();
                for (key, val) in [
                    ("reg", reg),
                    ("cpu-id", 40 + i as u32),
                    ("AAPL,phandle", 100 + i as u32),
                    ("cluster-id", c.firmware_id),
                    ("die-id", c.die),
                    ("die-cluster-id", c.die_cluster),
                    ("cluster-core-id", if i == 2 { 0 } else { i as u32 }),
                    ("l2-cache-size", inventory.caches[cluster].geometry.bytes),
                    ("l2-cache-id", 0),
                ] {
                    set_word(&mut n, key, val);
                }
                for (key, val) in [
                    ("cpu-impl-reg", range(i as u64)),
                    ("acc-impl-reg", c.acc_impl.unwrap()),
                    ("cpm-impl-reg", c.cpm_impl.unwrap()),
                ] {
                    set_range(&mut n, key, val);
                }
                for (key, val) in [
                    ("device_type", b"cpu\0".as_slice()),
                    ("state", WAITING),
                    (
                        "compatible",
                        if i == 2 {
                            b"apple,firestorm\0ARM,v8\0".as_slice()
                        } else {
                            b"apple,icestorm\0ARM,v8\0".as_slice()
                        },
                    ),
                ] {
                    n.set_property(key, val.to_vec()).unwrap();
                }
                n.set_property("cluster-type", vec![kind.cluster_type, 0])
                    .unwrap();
                n.set_property(
                    "function-enable_core",
                    vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                )
                .unwrap();
                cpus.children.push(n);
                bindings.push(NodeBinding {
                    slot: id,
                    name,
                    midr: kind.midr,
                    cache: CacheId(cluster as u32),
                    interrupt: InterruptId(i as u32),
                    start: StartId(i as u32),
                    core_power: power(i as u16),
                    cluster_power: c.power.unwrap(),
                });
            }
            let mut root = Node::named("device-tree").unwrap();
            root.children.push(cpus);
            let host = Roster {
                cores: vec![
                    AssignedCore {
                        worker: 80,
                        package: 0,
                        core: 4,
                        apic: 20,
                        started: true,
                    },
                    AssignedCore {
                        worker: 90,
                        package: 0,
                        core: 5,
                        apic: 22,
                        started: true,
                    },
                ],
                revision: Cell::new(1),
            };
            let assignments = vec![
                Assignment {
                    worker: 90,
                    slot: GuestSlotId(9),
                    boot: false,
                },
                Assignment {
                    worker: 80,
                    slot: GuestSlotId(7),
                    boot: true,
                },
            ];
            let counts = vec![
                CountField {
                    path: CPUS,
                    property: "max_cpus",
                    count: Count::Pes,
                },
                CountField {
                    path: CPUS,
                    property: "e-core-count",
                    count: Count::CoreType(b'E'),
                },
                CountField {
                    path: CPUS,
                    property: "p-core-count",
                    count: Count::CoreType(b'P'),
                },
            ];
            Self {
                tree: DeviceTree { root },
                inventory,
                host,
                assignments,
                bindings,
                counts,
            }
        }
        fn source(&self) -> SourceBindings<'_> {
            SourceBindings {
                source_set_sha256: [1; 32],
                tree_sha256: digest(&self.tree),
                nodes: &self.bindings,
                counts: &self.counts,
                references: &[],
                cpu_ids: CpuIdRecipe::Preserve,
            }
        }
        fn plan(&self) -> Plan<'_> {
            Plan::build(&self.host, &self.inventory, &self.assignments).unwrap()
        }
    }
    #[test]
    fn exact_enumeration_roundtrips_with_one_boot_and_original_ids_and_recipes() {
        let f = Fixture::new();
        let plan = f.plan();
        let mut tree = f.tree.clone();
        let projection = Projection::prepare(&plan, &tree, &f.source()).unwrap();
        assert_eq!(projection.receipt().plan, plan.identity());
        let receipt = projection.apply(&mut tree).unwrap();
        assert_eq!(receipt.boot_path, "/cpus/cpu0");
        assert_eq!(receipt.removed, vec!["/cpus/cpu1"]);
        let cpus = tree.node(CPUS).unwrap();
        assert_eq!(
            cpus.children.iter().map(Node::name).collect::<Vec<_>>(),
            vec![Some("cpu2"), Some("cpu0")]
        );
        assert_eq!(word(cpus, "max_cpus").unwrap(), 2);
        assert_eq!(word(cpus, "e-core-count").unwrap(), 1);
        assert_eq!(word(cpus, "p-core-count").unwrap(), 1);
        for (index, node) in cpus.children.iter().enumerate() {
            let original = f
                .tree
                .node(&format!("/cpus/{}", node.name().unwrap()))
                .unwrap();
            for property in &original.properties {
                if property.name() != "state" {
                    assert_eq!(node.property(property.name()), Some(property));
                }
            }
            assert_eq!(
                bytes(node, "state").unwrap(),
                if index == 1 { RUNNING } else { WAITING }
            );
        }
        assert_eq!(word(&cpus.children[0], "cpu-id").unwrap(), 42);
        assert_eq!(word(&cpus.children[0], "l2-cache-id").unwrap(), 0);
        assert_eq!(digest(&tree), receipt.projected_sha256);
        assert_eq!(DeviceTree::parse(&tree.serialize()).unwrap(), tree);
    }
    #[test]
    fn bad_late_resource_and_unbound_extra_slot_leave_tree_unchanged() {
        let mut f = Fixture::new();
        f.inventory.slots[0].cpu_impl = Some(range(99));
        let plan = f.plan();
        let tree = f.tree.clone();
        assert!(
            Projection::prepare(&plan, &tree, &f.source())
                .unwrap_err()
                .to_string()
                .contains("cpu-impl-reg")
        );
        assert_eq!(tree, f.tree);
        let f = Fixture::new();
        let plan = f.plan();
        let mut source = f.source();
        source.nodes = &f.bindings[..2];
        assert!(Projection::prepare(&plan, &tree, &source).is_err());
    }
    #[test]
    fn removed_source_cpu_needs_no_native_resource_ids_but_retained_cpu_does() {
        let f = Fixture::new();
        let plan = f.plan();
        let bindings = [f.bindings[0], f.bindings[2]];
        let mut source = f.source();
        source.nodes = &bindings;
        let mut tree = f.tree.clone();
        let receipt = Projection::prepare(&plan, &tree, &source)
            .unwrap()
            .apply(&mut tree)
            .unwrap();
        assert_eq!(receipt.removed, vec!["/cpus/cpu1"]);
        assert_eq!(f.tree.node(CPUS).unwrap().children.len(), 3);
        for selected in &tree.node(CPUS).unwrap().children {
            let original = f
                .tree
                .node(CPUS)
                .unwrap()
                .child(selected.name().unwrap())
                .unwrap();
            for property in &original.properties {
                if property.name() != "state" {
                    assert_eq!(selected.property(property.name()), Some(property));
                }
            }
        }
        source.nodes = &bindings[..1];
        let unchanged = f.tree.clone();
        assert!(
            Projection::prepare(&plan, &unchanged, &source)
                .unwrap_err()
                .to_string()
                .contains("missing declared source CPU slot")
        );
        assert_eq!(unchanged, f.tree);
    }
    #[test]
    fn unbound_removed_source_shape_identity_and_affinity_are_still_atomic_requirements() {
        for field in ["state", "AAPL,phandle", "cpu-id", "reg", "cpu-impl-reg"] {
            let mut f = Fixture::new();
            let value = match field {
                "state" => b"disabled\0".to_vec(),
                "AAPL,phandle" => 100u32.to_le_bytes().to_vec(),
                "cpu-id" => 40u32.to_le_bytes().to_vec(),
                "reg" => 0u32.to_le_bytes().to_vec(),
                _ => vec![1; 15],
            };
            f.tree.set_property("/cpus/cpu1", field, value).unwrap();
            let plan = f.plan();
            let bindings = [f.bindings[0], f.bindings[2]];
            let mut source = f.source();
            source.nodes = &bindings;
            let original = f.tree.clone();
            assert!(
                Projection::prepare(&plan, &original, &source).is_err(),
                "{field}"
            );
            assert_eq!(original, f.tree);
        }
    }
    #[test]
    fn stale_source_and_roster_fail_before_the_atomic_replacement() {
        let f = Fixture::new();
        let plan = f.plan();
        let mut tree = f.tree.clone();
        let projection = Projection::prepare(&plan, &tree, &f.source()).unwrap();
        tree.set_property(CPUS, "other", vec![7]).unwrap();
        let changed = tree.clone();
        assert!(projection.apply(&mut tree).is_err());
        assert_eq!(tree, changed);
        let mut tree = f.tree.clone();
        let projection = Projection::prepare(&plan, &tree, &f.source()).unwrap();
        f.host.revision.set(2);
        assert!(projection.apply(&mut tree).is_err());
        assert_eq!(tree, f.tree);
    }
    #[test]
    fn identity_bindings_counts_and_unknown_state_cannot_be_silently_accepted() {
        let mut f = Fixture::new();
        f.bindings[0].midr = 0;
        let plan = f.plan();
        assert!(Projection::prepare(&plan, &f.tree, &f.source()).is_err());
        let f = Fixture::new();
        let plan = f.plan();
        let mut source = f.source();
        source.tree_sha256 = [0; 32];
        assert!(Projection::prepare(&plan, &f.tree, &source).is_err());
        let mut source = f.source();
        source.source_set_sha256 = [2; 32];
        assert!(Projection::prepare(&plan, &f.tree, &source).is_err());
        let mut f = Fixture::new();
        f.tree
            .set_property(CPUS, "cpu-mask", vec![3, 0, 0, 0])
            .unwrap();
        let plan = f.plan();
        assert!(
            Projection::prepare(&plan, &f.tree, &f.source())
                .unwrap_err()
                .to_string()
                .contains("unqualified CPU consumer")
        );
        let mut f = Fixture::new();
        f.tree
            .set_property("/cpus/cpu1", "state", b"disabled\0".to_vec())
            .unwrap();
        let plan = f.plan();
        assert!(
            Projection::prepare(&plan, &f.tree, &f.source())
                .unwrap_err()
                .to_string()
                .contains("unqualified CPU state")
        );
    }
    #[test]
    fn removed_external_references_refuse_instead_of_guessing_an_id_or_mask_rewrite() {
        let mut f = Fixture::new();
        f.tree
            .set_property("/", "cpu-refs", 100u32.to_le_bytes().to_vec())
            .unwrap();
        let plan = f.plan();
        let reference = [ReferenceField {
            path: "/",
            property: "cpu-refs",
            encoding: ReferenceEncoding::Phandles,
        }];
        let mut source = f.source();
        source.references = &reference;
        assert!(Projection::prepare(&plan, &f.tree, &source).is_ok());
        let mut f = Fixture::new();
        f.tree
            .set_property("/", "cpu-refs", 101u32.to_le_bytes().to_vec())
            .unwrap();
        let plan = f.plan();
        let mut source = f.source();
        source.references = &reference;
        assert!(
            Projection::prepare(&plan, &f.tree, &source)
                .unwrap_err()
                .to_string()
                .contains("removed or unknown")
        );
        assert!(f.tree.node("/cpus/cpu1").is_some());
        for (id, accepted) in [(42u32, true), (41, false), (0, false)] {
            let mut f = Fixture::new();
            f.tree
                .set_property("/", "firmware-cpu-refs", id.to_le_bytes().to_vec())
                .unwrap();
            let plan = f.plan();
            let fields = [ReferenceField {
                path: "/",
                property: "firmware-cpu-refs",
                encoding: ReferenceEncoding::FirmwareCpuIds,
            }];
            let mut source = f.source();
            source.references = &fields;
            assert_eq!(
                Projection::prepare(&plan, &f.tree, &source).is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn noncontiguous_clusters_and_unqualified_status_or_cache_consumers_refuse() {
        let mut f = Fixture::new();
        f.host.cores.push(AssignedCore {
            worker: 100,
            package: 0,
            core: 6,
            apic: 24,
            started: true,
        });
        f.assignments = vec![
            Assignment {
                worker: 80,
                slot: GuestSlotId(7),
                boot: true,
            },
            Assignment {
                worker: 90,
                slot: GuestSlotId(9),
                boot: false,
            },
            Assignment {
                worker: 100,
                slot: GuestSlotId(8),
                boot: false,
            },
        ];
        let plan = f.plan();
        assert!(
            Projection::prepare(&plan, &f.tree, &f.source())
                .unwrap_err()
                .to_string()
                .contains("noncontiguous")
        );
        for (path, property, value) in [
            ("/cpus/cpu1", "status", b"okay\0".to_vec()),
            (
                "/cpus/cpu1",
                "l3-cache-size",
                0x10000u32.to_le_bytes().to_vec(),
            ),
            (CPUS, "cpu-cluster-count", 3u32.to_le_bytes().to_vec()),
        ] {
            let mut f = Fixture::new();
            f.tree.set_property(path, property, value).unwrap();
            let plan = f.plan();
            assert!(Projection::prepare(&plan, &f.tree, &f.source()).is_err());
        }
        let mut f = Fixture::new();
        f.counts.push(CountField {
            path: "cpus/cpu0",
            property: "reg",
            count: Count::Pes,
        });
        let plan = f.plan();
        assert!(
            Projection::prepare(&plan, &f.tree, &f.source())
                .unwrap_err()
                .to_string()
                .contains("noncanonical")
        );
        let mut f = Fixture::new();
        f.counts.push(CountField {
            path: CPUS,
            property: "cpu-cluster-count",
            count: Count::Clusters,
        });
        let plan = f.plan();
        let mut tree = f.tree.clone();
        Projection::prepare(&plan, &tree, &f.source())
            .unwrap()
            .apply(&mut tree)
            .unwrap();
        // A mechanical synthetic count test, not qualification of the Apple
        // fixed-count producer's reduced-cluster consumers.
        assert_eq!(
            word(tree.node(CPUS).unwrap(), "cpu-cluster-count").unwrap(),
            2
        );
    }

    #[test]
    fn interrupt_provider_cpu_count_requires_an_explicit_assigned_plan_binding() {
        let mut f = Fixture::new();
        f.tree.root.children.push(Node::named("aic").unwrap());
        f.tree
            .set_property("/aic", "#main-cpus", 10u32.to_le_bytes().to_vec())
            .unwrap();
        let plan = f.plan();
        assert!(
            Projection::prepare(&plan, &f.tree, &f.source())
                .unwrap_err()
                .to_string()
                .contains("#main-cpus")
        );
        f.counts.push(CountField {
            path: "/aic",
            property: "#main-cpus",
            count: Count::Pes,
        });
        let plan = f.plan();
        let mut tree = f.tree.clone();
        Projection::prepare(&plan, &tree, &f.source())
            .unwrap()
            .apply(&mut tree)
            .unwrap();
        assert_eq!(
            word(tree.node("/aic").unwrap(), "#main-cpus").unwrap(),
            plan.pes().len() as u32
        );
    }

    #[test]
    fn t8112_projection_preserves_absent_coordinates_and_checks_affinity_derived_bindings() {
        let mut f = Fixture::new();
        f.inventory.soc = 0x8112;
        for (index, cluster) in f.inventory.clusters.iter_mut().enumerate() {
            cluster.firmware_id = index as u32;
        }
        for node in &mut f.tree.node_mut(CPUS).unwrap().children {
            let reg = word(node, "reg").unwrap();
            set_word(node, "cluster-id", reg >> 8);
            for key in ["die-id", "die-cluster-id", "cluster-core-id"] {
                node.remove_property(key);
            }
        }
        let plan = f.plan();
        let mut projected = f.tree.clone();
        Projection::prepare(&plan, &projected, &f.source())
            .unwrap()
            .apply(&mut projected)
            .unwrap();
        for node in &projected.node(CPUS).unwrap().children {
            for key in ["die-id", "die-cluster-id", "cluster-core-id"] {
                assert!(node.property(key).is_none());
            }
        }
        let mut wrong = f.tree.clone();
        set_word(wrong.node_mut("/cpus/cpu2").unwrap(), "die-cluster-id", 0);
        let mut source = f.source();
        source.tree_sha256 = digest(&wrong);
        assert!(Projection::prepare(&plan, &wrong, &source).is_err());
        drop(plan);
        f.inventory.soc = 0x6000;
        assert!(Projection::prepare(&f.plan(), &f.tree, &f.source()).is_err());
    }

    fn dense_fixture() -> Fixture {
        let mut f = Fixture::new();
        f.inventory.soc = 0x8112;
        for (index, cluster) in f.inventory.clusters.iter_mut().enumerate() {
            cluster.firmware_id = index as u32;
        }
        let mut table = Vec::new();
        for (index, node) in f
            .tree
            .node_mut(CPUS)
            .unwrap()
            .children
            .iter_mut()
            .enumerate()
        {
            let reg = word(node, "reg").unwrap();
            set_word(node, "cluster-id", reg >> 8);
            set_word(node, "cpu-id", index as u32);
            let region = range(100 + index as u64);
            set_range(node, "coresight-reg", region);
            table.extend((region.base + 4).to_le_bytes());
            table.extend(0xfu32.to_le_bytes());
            table.extend(1u32.to_le_bytes());
        }
        let mut wdt = Node::named("watchdog").unwrap();
        wdt.set_property("compatible", b"wdt,s5l8960x\0".to_vec())
            .unwrap();
        set_word(&mut wdt, "AAPL,phandle", 900);
        set_range(&mut wdt, "reg", range(200));
        wdt.set_property("trigger-config", table).unwrap();
        f.tree.root.children.push(wdt);
        f
    }

    #[test]
    fn dense_cpu_ids_and_watchdog_records_follow_one_plan_without_changing_physical_recipes() {
        let f = dense_fixture();
        let original = f.tree.clone();
        let plan = f.plan();
        let mut source = f.source();
        source.cpu_ids = CpuIdRecipe::DenseWithWatchdog {
            original: &original,
            original_sha256: digest(&original),
            watchdog_path: "/watchdog",
        };
        let mut tree = f.tree.clone();
        let receipt = Projection::prepare(&plan, &tree, &source)
            .unwrap()
            .apply(&mut tree)
            .unwrap();
        assert_eq!(word(tree.node(CPUS).unwrap(), "max_cpus").unwrap(), 2);
        assert_eq!(
            receipt
                .cpu_ids
                .iter()
                .map(|m| (m.original_id, m.projected_id))
                .collect::<Vec<_>>(),
            [(2, 0), (0, 1)]
        );
        let old_table = bytes(original.node("/watchdog").unwrap(), "trigger-config").unwrap();
        assert_eq!(
            bytes(tree.node("/watchdog").unwrap(), "trigger-config").unwrap(),
            [&old_table[32..48], &old_table[..16]].concat()
        );
        for mapping in &receipt.cpu_ids {
            let before = original.node(&mapping.path).unwrap();
            let after = tree.node(&mapping.path).unwrap();
            assert_eq!(word(after, "cpu-id").unwrap(), mapping.projected_id);
            for property in &before.properties {
                if !matches!(property.name(), "state" | "cpu-id") {
                    assert_eq!(after.property(property.name()), Some(property));
                }
            }
        }
        let wdt = receipt.watchdog.unwrap();
        assert_eq!((wdt.original_records, wdt.projected_records), (3, 2));
        assert_eq!(wdt.original_tree_sha256, digest(&original));
        assert_eq!(f.tree, original);
        assert_eq!(DeviceTree::parse(&tree.serialize()).unwrap(), tree);
    }

    #[test]
    fn dense_recipe_refuses_bad_sources_tables_ranges_counts_and_references_atomically() {
        let f = dense_fixture();
        let original = f.tree.clone();
        let plan = f.plan();
        let mut source = f.source();
        source.cpu_ids = CpuIdRecipe::DenseWithWatchdog {
            original: &original,
            original_sha256: digest(&original),
            watchdog_path: "/watchdog",
        };
        let mut changed_inputs = Vec::new();
        for len in [0, 16, 47, 64] {
            let mut tree = f.tree.clone();
            tree.set_property("/watchdog", "trigger-config", vec![0; len])
                .unwrap();
            changed_inputs.push(tree);
        }
        let mut missing = f.tree.clone();
        missing
            .node_mut("/watchdog")
            .unwrap()
            .remove_property("trigger-config");
        changed_inputs.push(missing);
        let mut duplicate = f.tree.clone();
        let p = duplicate
            .property("/watchdog", "trigger-config")
            .unwrap()
            .clone();
        duplicate.node_mut("/watchdog").unwrap().properties.push(p);
        changed_inputs.push(duplicate);
        let mut changed = f.tree.clone();
        set_word(changed.node_mut("/cpus/cpu2").unwrap(), "cpu-id", 99);
        changed_inputs.push(changed);
        let mut changed = f.tree.clone();
        let mut table = bytes(changed.node("/watchdog").unwrap(), "trigger-config")
            .unwrap()
            .to_vec();
        table[32] ^= 4;
        changed
            .set_property("/watchdog", "trigger-config", table)
            .unwrap();
        changed_inputs.push(changed);
        for tree in changed_inputs {
            source.tree_sha256 = digest(&tree);
            let before = tree.clone();
            assert!(Projection::prepare(&plan, &tree, &source).is_err());
            assert_eq!(tree, before);
        }
        for (key, value) in [
            ("cpu-id", 3u32.to_le_bytes().to_vec()),
            ("cpu-id", 0u32.to_le_bytes().to_vec()),
            ("coresight-reg", vec![0; 16]),
        ] {
            let mut invalid = original.clone();
            invalid.set_property("/cpus/cpu2", key, value).unwrap();
            let mut invalid_source = f.source();
            invalid_source.tree_sha256 = digest(&invalid);
            invalid_source.cpu_ids = CpuIdRecipe::DenseWithWatchdog {
                original: &invalid,
                original_sha256: digest(&invalid),
                watchdog_path: "/watchdog",
            };
            assert!(Projection::prepare(&plan, &invalid, &invalid_source).is_err());
        }
        source.tree_sha256 = digest(&f.tree);
        source.cpu_ids = CpuIdRecipe::DenseWithWatchdog {
            original: &original,
            original_sha256: [0; 32],
            watchdog_path: "/watchdog",
        };
        assert!(Projection::prepare(&plan, &f.tree, &source).is_err());
        source.cpu_ids = CpuIdRecipe::DenseWithWatchdog {
            original: &original,
            original_sha256: digest(&original),
            watchdog_path: "/watchdog",
        };
        source.counts = &[];
        assert!(Projection::prepare(&plan, &f.tree, &source).is_err());
        let mut referenced = f.tree.clone();
        referenced
            .set_property("/", "cpu-refs", 2u32.to_le_bytes().to_vec())
            .unwrap();
        source.counts = &f.counts;
        source.tree_sha256 = digest(&referenced);
        let references = [ReferenceField {
            path: "/",
            property: "cpu-refs",
            encoding: ReferenceEncoding::FirmwareCpuIds,
        }];
        source.references = &references;
        assert!(Projection::prepare(&plan, &referenced, &source).is_err());
    }

    #[test]
    #[ignore = "requires pinned original T8112 ADTs in STELA_TEST_CPU_DT_DIR"]
    fn original_t8112_source_byte_digests_survive_parse_serialization() {
        let directory = std::path::PathBuf::from(std::env::var("STELA_TEST_CPU_DT_DIR").unwrap());
        let facts: serde_json::Value =
            serde_json::from_str(include_str!("../../../../isa/apple-soc-facts.json")).unwrap();
        let mut count = 0;
        for board in facts["boards"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|b| b["chip_id"] == "0x8112")
        {
            let name = board["device_class"].as_str().unwrap();
            let raw = std::fs::read(directory.join(format!("DeviceTree.{name}.adt"))).unwrap();
            assert_eq!(
                stela_runtime::sha256(&raw),
                board["source"]["decoded_sha256"].as_str().unwrap(),
                "{name}: original identity"
            );
            let parsed = DeviceTree::parse(&raw).unwrap();
            assert_eq!(parsed.serialize(), raw, "{name}: source roundtrip");
            count += 1;
        }
        assert_eq!(count, 4);
    }

    #[test]
    #[ignore = "requires pinned original J473 ADT in STELA_TEST_CPU_DT_DIR"]
    fn original_j473_first_p_projection_keeps_source_fields_and_absent_coordinates() {
        use stela_runtime::machine::soc::assigned::{BspSource, SourceIdentity};
        let file = std::path::PathBuf::from(std::env::var("STELA_TEST_CPU_DT_DIR").unwrap())
            .join("DeviceTree.j473ap.adt");
        let original = std::fs::read(file).unwrap();
        assert_eq!(
            stela_runtime::sha256(&original),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let mut tree = DeviceTree::parse(&original).unwrap();
        tree.set_property("/chosen", "chip-id", 0x8112u32.to_le_bytes().to_vec())
            .unwrap();
        tree.set_property("/chosen", "board-id", 0x24u32.to_le_bytes().to_vec())
            .unwrap();
        tree.set_property("/cpus/cpu4", "state", RUNNING.to_vec())
            .unwrap();
        let prepared = tree.serialize();
        let owner = BspSource::t8112(
            &original,
            &prepared,
            SourceIdentity {
                original_tree_sha256: Sha256::digest(&original).into(),
                profile: ResourceProfile {
                    chip: Chip::AppleM2,
                    soc: 0x8112,
                    board: 0x24,
                    input_set_sha256: [1; 32],
                    adapted_set_sha256: None,
                },
            },
            0x100,
            0,
        )
        .unwrap();
        let roster = Roster {
            revision: Cell::new(1),
            cores: vec![AssignedCore {
                worker: 1,
                package: 0,
                core: 0,
                apic: 0,
                started: true,
            }],
        };
        let assignments = [Assignment {
            worker: 1,
            slot: owner.slot(),
            boot: true,
        }];
        let plan = Plan::build(&roster, &owner, &assignments).unwrap();
        let resources = owner.resources();
        let pe = &plan.pes()[0];
        let bindings = [NodeBinding {
            slot: owner.slot(),
            name: owner.name(),
            midr: pe.identity.midr,
            cache: pe.cache,
            interrupt: pe.interrupt,
            start: pe.start,
            core_power: pe.core_power,
            cluster_power: pe.cluster_power,
        }];
        let counts = [
            CountField {
                path: CPUS,
                property: "max_cpus",
                count: Count::Pes,
            },
            CountField {
                path: CPUS,
                property: "e-core-count",
                count: Count::CoreType(b'E'),
            },
            CountField {
                path: CPUS,
                property: "p-core-count",
                count: Count::CoreType(b'P'),
            },
            CountField {
                path: "/arm-io/aic",
                property: "#main-cpus",
                count: Count::Pes,
            },
        ];
        let source = SourceBindings {
            source_set_sha256: resources.profile.input_set_sha256,
            tree_sha256: Sha256::digest(&prepared).into(),
            nodes: &bindings,
            counts: &counts,
            references: &[],
            cpu_ids: CpuIdRecipe::Preserve,
        };
        let receipt = Projection::prepare(&plan, &tree, &source)
            .unwrap()
            .apply(&mut tree)
            .unwrap();
        assert_eq!(receipt.boot_path, "/cpus/cpu4");
        assert_eq!(tree.node(CPUS).unwrap().children.len(), 1);
        let prior = DeviceTree::parse(&prepared).unwrap();
        assert_eq!(tree.node("/cpus/cpu4"), prior.node("/cpus/cpu4"));
        for key in ["die-id", "die-cluster-id", "cluster-core-id"] {
            assert!(tree.property("/cpus/cpu4", key).is_none());
        }
        assert_eq!(owner.source(), original);
        // The separately selected recipe changes only the driver CPU ID and
        // its coordinated per-PE watchdog record, preserving original source.
        let immutable = DeviceTree::parse(&original).unwrap();
        assert_eq!(immutable.serialize(), original);
        let mut dense_source = source;
        dense_source.cpu_ids = CpuIdRecipe::DenseWithWatchdog {
            original: &immutable,
            original_sha256: Sha256::digest(&original).into(),
            watchdog_path: "/arm-io/wdt",
        };
        let mut dense = prior.clone();
        let dense_receipt = Projection::prepare(&plan, &dense, &dense_source)
            .unwrap()
            .apply(&mut dense)
            .unwrap();
        let selected = dense.node("/cpus/cpu4").unwrap();
        assert_eq!(word(selected, "cpu-id").unwrap(), 0);
        assert_eq!(word(selected, "reg").unwrap(), 0x100);
        assert_eq!(word(dense.node(CPUS).unwrap(), "max_cpus").unwrap(), 1);
        let original_table =
            bytes(immutable.node("/arm-io/wdt").unwrap(), "trigger-config").unwrap();
        assert_eq!(
            stela_runtime::sha256(original_table),
            "e9e9875ee26054ce3129dcb658d3d39b819819ef5bc568ad885d15bca048980c"
        );
        assert_eq!(
            bytes(dense.node("/arm-io/wdt").unwrap(), "trigger-config").unwrap(),
            &original_table[64..80]
        );
        assert_eq!(
            dense_receipt
                .cpu_ids
                .iter()
                .map(|m| (m.original_id, m.projected_id))
                .collect::<Vec<_>>(),
            [(4, 0)]
        );
        for property in &prior.node("/cpus/cpu4").unwrap().properties {
            if property.name() != "cpu-id" {
                assert_eq!(selected.property(property.name()), Some(property));
            }
        }
        assert_eq!(owner.source(), original);
    }
    #[test]
    #[ignore = "requires immutable original 26A434 J314s DT via STELA_TEST_ASSIGNED_DT"]
    fn original_j314s_subsets_roundtrip_without_firmware_id_or_resource_extrapolation() {
        use stela_runtime::machine::soc;
        let path = std::env::var("STELA_TEST_ASSIGNED_DT").unwrap();
        let raw = std::fs::read(path).unwrap();
        let expected = "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad";
        assert_eq!(hex::encode(Sha256::digest(&raw)), expected);
        let tree = DeviceTree::parse(&raw).unwrap();
        assert_eq!(tree.serialize(), raw);
        let nodes = &tree.node(CPUS).unwrap().children;
        let processors: Vec<_> = nodes
            .iter()
            .map(|n| soc::Processor {
                cluster_type: bytes(n, "cluster-type").unwrap()[0],
                reg: word(n, "reg").unwrap(),
                l2_bytes: Some(word(n, "l2-cache-size").unwrap()),
            })
            .collect();
        let identities = soc::cpus(
            0x6000,
            tree.property("/product", "product-soc-name")
                .unwrap()
                .as_str()
                .unwrap(),
            &processors,
        )
        .unwrap()
        .processors;
        let mut inventory = Fixture::new().inventory;
        inventory.kinds.clear();
        inventory.slots.clear();
        inventory.clusters.clear();
        inventory.caches.clear();
        inventory.interrupts.clear();
        inventory.starts.clear();
        inventory.powers.clear();
        let mut bindings = vec![];
        let read_range = |node: &Node, name: &str| {
            let v = bytes(node, name).unwrap();
            assert_eq!(v.len(), 16);
            RegisterRange {
                base: u64::from_le_bytes(v[..8].try_into().unwrap()),
                bytes: u64::from_le_bytes(v[8..].try_into().unwrap()),
            }
        };
        for (i, node) in nodes.iter().enumerate() {
            let kind_letter = processors[i].cluster_type;
            let reg = processors[i].reg;
            let kind = KindId(u32::from(kind_letter));
            let cluster = ClusterId(reg >> 8);
            let identity = identities[i];
            if !inventory.kinds.iter().any(|v| v.id == kind) {
                let (instruction, data) = soc::level1_caches(0x6000, kind_letter).unwrap();
                inventory.kinds.push(CoreKind {
                    id: kind,
                    cluster_type: kind_letter,
                    midr: identity.midr,
                    aff2: (identity.mpidr >> 16 & 7) as u8,
                    clock: identity.clock,
                    instruction,
                    data,
                });
            }
            if !inventory.clusters.iter().any(|v| v.id == cluster) {
                let ccsidr = identity.caches.unwrap().ccsidr(2);
                let line = 16 << (ccsidr & 7);
                let ways = (ccsidr >> 3 & 0x3ff) + 1;
                let sets = (ccsidr >> 13 & 0x7fff) + 1;
                inventory.caches.push(SharedCache {
                    id: CacheId(cluster.0),
                    cluster,
                    geometry: Cache {
                        bytes: (line * ways * sets) as u32,
                        ways: ways as u32,
                        line: line as u32,
                    },
                });
                inventory.clusters.push(ClusterSlot {
                    id: cluster,
                    aff1: (reg >> 8) as u8,
                    firmware_id: word(node, "cluster-id").unwrap(),
                    die: word(node, "die-id").unwrap(),
                    die_cluster: word(node, "die-cluster-id").unwrap(),
                    cache: Some(CacheId(cluster.0)),
                    power: Some(power(100 + cluster.0 as u16)),
                    acc_impl: Some(read_range(node, "acc-impl-reg")),
                    cpm_impl: Some(read_range(node, "cpm-impl-reg")),
                });
                // Test-only association IDs: original PMGR/executor ownership
                // is not manufactured or qualified by a DT projection replay.
                inventory.powers.push(PowerResource {
                    id: power(100 + cluster.0 as u16),
                    cores: vec![],
                    clusters: vec![cluster],
                });
            }
            let slot = GuestSlotId(i as u32);
            inventory.slots.push(PeSlot {
                id: slot,
                reg,
                kind: Some(kind),
                cluster,
                cluster_core: word(node, "cluster-core-id").unwrap(),
                interrupt: Some(InterruptId(i as u32)),
                start: Some(StartId(i as u32)),
                power: Some(power(i as u16)),
                cpu_impl: Some(read_range(node, "cpu-impl-reg")),
            });
            inventory.interrupts.push(InterruptTarget {
                id: InterruptId(i as u32),
                reg,
            });
            inventory.starts.push(StartResource {
                id: StartId(i as u32),
                reg,
            });
            inventory.powers.push(PowerResource {
                id: power(i as u16),
                cores: vec![slot],
                clusters: vec![],
            });
            bindings.push(NodeBinding {
                slot,
                name: node.name().unwrap(),
                midr: identity.midr,
                cache: CacheId(cluster.0),
                interrupt: InterruptId(i as u32),
                start: StartId(i as u32),
                core_power: power(i as u16),
                cluster_power: power(100 + cluster.0 as u16),
            });
        }
        let mut counts = Fixture::new().counts;
        // Original AppleInterruptControllerV2 reads this provider CPU count
        // and iterates that many CPU indices (26A434 KC file0x2822dc4 and
        // 0x282375c). It follows the same assigned PE plan as /cpus.
        counts.push(CountField {
            path: "/arm-io/aic",
            property: "#main-cpus",
            count: Count::Pes,
        });
        for selected in [
            vec![0],
            vec![0, 1, 2, 3],
            vec![0, 1, 2, 3, 4, 6, 7, 8],
            (0..10).collect(),
        ] {
            let host = Roster {
                cores: selected
                    .iter()
                    .enumerate()
                    .map(|(i, _)| AssignedCore {
                        worker: 50 + i,
                        package: 0,
                        core: i as u32,
                        apic: i as u32 * 2,
                        started: true,
                    })
                    .collect(),
                revision: Cell::new(1),
            };
            let assignments: Vec<_> = selected
                .iter()
                .enumerate()
                .map(|(i, slot)| Assignment {
                    worker: 50 + i,
                    slot: GuestSlotId(*slot),
                    boot: i == 0,
                })
                .collect();
            let plan = Plan::build(&host, &inventory, &assignments).unwrap();
            let source = SourceBindings {
                source_set_sha256: [1; 32],
                tree_sha256: Sha256::digest(&raw).into(),
                nodes: &bindings,
                counts: &counts,
                references: &[],
                cpu_ids: CpuIdRecipe::Preserve,
            };
            let mut projected = tree.clone();
            let receipt = Projection::prepare(&plan, &projected, &source)
                .unwrap()
                .apply(&mut projected)
                .unwrap();
            assert_eq!(receipt.plan, plan.identity());
            let cpus = projected.node(CPUS).unwrap();
            assert_eq!(cpus.children.len(), selected.len());
            assert_eq!(word(cpus, "max_cpus").unwrap(), selected.len() as u32);
            assert_eq!(
                DeviceTree::parse(&projected.serialize()).unwrap(),
                projected
            );
            for (i, node) in cpus.children.iter().enumerate() {
                let source = &nodes[selected[i] as usize];
                assert_eq!(
                    word(node, "cpu-id").unwrap(),
                    word(source, "cpu-id").unwrap()
                );
                assert_eq!(word(node, "reg").unwrap(), word(source, "reg").unwrap());
                for prop in &source.properties {
                    if prop.name() != "state" {
                        assert_eq!(node.property(prop.name()), Some(prop));
                    }
                }
            }
        }
    }
}
