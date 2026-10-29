//! Immutable construction from kept roster/resource views. This is a plan,
//! never native execution, CPU-start, PMGR-settlement or backing permission.
//! Root owners must separately admit the same plan against executors and
//! devices. No source addresses, chip counts or limits are inferred here.
mod source;
pub use source::{BspSource, SourceIdentity};

use crate::pmgr::coverage::DomainId;
use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use {
    stela_contracts::Chip, stela_contracts::caches::Cache, stela_contracts::caches::CacheSelection,
    stela_contracts::caches::Caches, stela_contracts::identity::Identity,
};

const AFFINITY_MASK: u32 = 0xffff;
const AFFINITY_PART_MASK: u32 = 0xff;
const CLUSTER_SHIFT: u32 = 8;

macro_rules! ids {
    ($($id:ident),* $(,)?) => {$(
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $id(pub u32);
    )*};
}
ids!(
    GuestSlotId,
    ClusterId,
    CacheId,
    KindId,
    InterruptId,
    StartId
);

/// Host coordinates remain distinct from guest logical IDs and affinities.
/// These observations alone grant no executor permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedCore {
    pub worker: usize,
    pub package: u32,
    pub core: u32,
    pub apic: u32,
    pub started: bool,
}

/// Implemented by the real roster owner. Its borrow must keep the
/// observations and source identity; revisions must advance monotonically
/// without reuse after any change. Revision changes invalidate a plan. This
/// metadata interface cannot create WorkerOwner/NativeLoan or prove native
/// state recovery. Consumers must still use those permission boundaries.
pub trait RetainedRoster {
    fn revision(&self) -> u64;
    fn cores(&self) -> &[AssignedCore];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapacityKind {
    KernelCpus,
    KernelClusters,
    KernelAffinitySpan,
    KernelPhysicalCluster,
    KernelCpuMask,
    MonitorCpus,
    PlatformCpus,
    PlatformClusters,
}
const CAPACITIES: [CapacityKind; 8] = [
    CapacityKind::KernelCpus,
    CapacityKind::KernelClusters,
    CapacityKind::KernelAffinitySpan,
    CapacityKind::KernelPhysicalCluster,
    CapacityKind::KernelCpuMask,
    CapacityKind::MonitorCpus,
    CapacityKind::PlatformCpus,
    CapacityKind::PlatformClusters,
];

/// A caller-checked whole-consumer capacity, not one observed literal.
/// `None` keeps an unknown requirement. Provenance is review metadata, not
/// a cryptographic admission or a substitute for the source owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    pub kind: CapacityKind,
    pub maximum: Option<usize>,
    pub provenance: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterRange {
    pub base: u64,
    pub bytes: u64,
}
impl RegisterRange {
    fn end(self) -> Option<u64> {
        (self.bytes != 0 && self.base != 0).then_some(())?;
        self.base.checked_add(self.bytes)
    }
    fn overlaps(self, other: Self) -> bool {
        self.base < other.end().unwrap_or(0) && other.base < self.end().unwrap_or(0)
    }
}

/// Every identity/cache field comes from supplied checked semantics. Missing
/// future core kinds have no inherited MIDR, affinity, clock or cache fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreKind {
    pub id: KindId,
    pub cluster_type: u8,
    pub midr: u64,
    pub aff2: u8,
    pub clock: Option<u64>,
    pub instruction: Cache,
    pub data: Cache,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedCache {
    pub id: CacheId,
    pub cluster: ClusterId,
    pub geometry: Cache,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterSlot {
    pub id: ClusterId,
    pub aff1: u8,
    /// Firmware coordinates are die-checked; they are not the kernel's
    /// dense logical cluster ID or the global physical Aff1 index.
    pub firmware_id: u32,
    pub die: u32,
    pub die_cluster: u32,
    pub cache: Option<CacheId>,
    pub power: Option<DomainId>,
    pub acc_impl: Option<RegisterRange>,
    pub cpm_impl: Option<RegisterRange>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeSlot {
    pub id: GuestSlotId,
    pub reg: u32,
    pub kind: Option<KindId>,
    pub cluster: ClusterId,
    pub cluster_core: u32,
    pub interrupt: Option<InterruptId>,
    pub start: Option<StartId>,
    pub power: Option<DomainId>,
    pub cpu_impl: Option<RegisterRange>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptTarget {
    pub id: InterruptId,
    pub reg: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartResource {
    pub id: StartId,
    pub reg: u32,
}
/// Explicit physical power-domain membership permits checked shared/aliased
/// owners, but never discovers membership from names or numeric ID formulas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerResource {
    pub id: DomainId,
    pub cores: Vec<GuestSlotId>,
    pub clusters: Vec<ClusterId>,
}
/// Source identity is held as metadata; it never selects behavior or
/// substitutes for validating the source/resource owner at adoption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceProfile {
    pub chip: Chip,
    pub soc: u32,
    pub board: u32,
    pub input_set_sha256: [u8; 32],
    pub adapted_set_sha256: Option<[u8; 32]>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources<'a> {
    pub profile: ResourceProfile,
    pub register_granule: u64,
    pub provenance: &'static str,
    pub capacities: &'a [Capacity],
    pub kinds: &'a [CoreKind],
    pub slots: &'a [PeSlot],
    pub clusters: &'a [ClusterSlot],
    pub caches: &'a [SharedCache],
    pub interrupts: &'a [InterruptTarget],
    pub starts: &'a [StartResource],
    pub powers: &'a [PowerResource],
}
/// Resource-owner adapter. A plan keeps this borrow through use;
/// adopting resources and owning their lifecycle remains the adapter's job.
/// All effective changes must monotonically advance its revision, without
/// reuse, before adoption can resume.
pub trait RetainedResources {
    fn revision(&self) -> u64;
    fn resources(&self) -> Resources<'_>;
}
#[derive(Debug, Clone, Copy)]
pub struct Assignment {
    pub worker: usize,
    pub slot: GuestSlotId,
    pub boot: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    GuestSlot,
    Provenance,
    RegisterGranule,
    CoreKind,
    Cluster,
    Cache,
    Interrupt,
    Start,
    CorePower,
    ClusterPower,
    CpuImplementation,
    AccImplementation,
    CpmImplementation,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    EmptyRoster,
    Cardinality {
        assigned: usize,
        requested: usize,
    },
    DuplicateWorker(usize),
    DuplicatePhysicalCore {
        package: u32,
        core: u32,
    },
    DuplicateApic(u32),
    UnstartedWorker(usize),
    UnknownWorker(usize),
    MissingWorker(usize),
    BootCount(usize),
    DuplicateAssignment(GuestSlotId),
    UnknownSlot(GuestSlotId),
    DuplicateInventory(ResourceKind),
    DuplicateCapacity(CapacityKind),
    MissingCapacity(CapacityKind),
    Capacity {
        kind: CapacityKind,
        required: usize,
        maximum: usize,
    },
    MissingResource {
        slot: GuestSlotId,
        kind: ResourceKind,
    },
    ConflictingResource {
        slot: GuestSlotId,
        kind: ResourceKind,
    },
    InvalidAffinity(GuestSlotId),
    DuplicateAffinity(u32),
    ClusterAffinity(u8),
    ClusterFirmwareId {
        die: u32,
        cluster: u32,
    },
    ClusterCoordinate {
        die: u32,
        cluster: u32,
    },
    DuplicateClusterCore {
        cluster: ClusterId,
        core: u32,
    },
    InvalidCache(GuestSlotId),
    OverlappingRegisters,
    RosterChanged,
    ResourcesChanged,
}

#[derive(Debug)]
struct PlanMarker;
/// Identity for joining views of one plan, not executor or device permission.
#[derive(Debug, Clone)]
pub struct PlanIdentity(Arc<PlanMarker>);
impl PartialEq for PlanIdentity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for PlanIdentity {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPe {
    pub logical: usize,
    pub host: AssignedCore,
    pub slot: GuestSlotId,
    pub reg: u32,
    pub kind: KindId,
    pub cluster_type: u8,
    pub identity: Identity,
    pub cluster: ClusterId,
    pub logical_cluster: usize,
    pub cluster_core: u32,
    pub cache: CacheId,
    pub interrupt: InterruptId,
    pub start: StartId,
    pub core_power: DomainId,
    pub cluster_power: DomainId,
    pub cpu_impl: RegisterRange,
    pub acc_impl: RegisterRange,
    pub cpm_impl: RegisterRange,
    pub boot: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCluster {
    pub logical: usize,
    pub resource: ClusterSlot,
    pub cache: SharedCache,
}
/// All views share this identity and keep the caller-owned roster and
/// resource borrows. No public mutation, truncation or hardware activation API.
pub struct Plan<'a> {
    identity: PlanIdentity,
    roster: &'a dyn RetainedRoster,
    roster_revision: u64,
    resource_owner: &'a dyn RetainedResources,
    resource_revision: u64,
    resources: Resources<'a>,
    pes: Vec<PlannedPe>,
    clusters: Vec<PlannedCluster>,
}
impl core::fmt::Debug for Plan<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plan")
            .field("identity", &self.identity)
            .field("chip", &self.resources.profile.chip)
            .field("pes", &self.pes)
            .finish_non_exhaustive()
    }
}
impl Plan<'_> {
    pub fn identity(&self) -> PlanIdentity {
        self.identity.clone()
    }
    pub fn chip(&self) -> Chip {
        self.resources.profile.chip
    }
    pub fn profile(&self) -> ResourceProfile {
        self.resources.profile
    }
    pub fn provenance(&self) -> &'static str {
        self.resources.provenance
    }
    pub fn pes(&self) -> &[PlannedPe] {
        &self.pes
    }
    pub fn clusters(&self) -> &[PlannedCluster] {
        &self.clusters
    }
    /// Validate freshness immediately before adoption. This checks the
    /// views; it is not a numeric substitute for AP returns.
    pub fn revalidate(&self) -> Result<(), Requirement> {
        if self.roster.revision() != self.roster_revision
            || self.roster.cores().len() != self.pes.len()
            || self
                .roster
                .cores()
                .iter()
                .any(|core| !self.pes.iter().any(|pe| pe.host == *core))
        {
            return Err(Requirement::RosterChanged);
        }
        if self.resource_owner.revision() != self.resource_revision
            || self.resource_owner.resources() != self.resources
        {
            return Err(Requirement::ResourcesChanged);
        }
        Ok(())
    }
}

fn unique<T: Ord>(values: impl Iterator<Item = T>, kind: ResourceKind) -> Result<(), Requirement> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(Requirement::DuplicateInventory(kind));
        }
    }
    Ok(())
}
fn missing(slot: GuestSlotId, kind: ResourceKind) -> Requirement {
    Requirement::MissingResource { slot, kind }
}
fn conflict(slot: GuestSlotId, kind: ResourceKind) -> Requirement {
    Requirement::ConflictingResource { slot, kind }
}
fn range(
    granule: u64,
    value: Option<RegisterRange>,
    slot: GuestSlotId,
    kind: ResourceKind,
) -> Result<RegisterRange, Requirement> {
    let value = value.ok_or_else(|| missing(slot, kind))?;
    if value.end().is_none() || value.base & (granule - 1) != 0 {
        return Err(conflict(slot, kind));
    }
    Ok(value)
}

impl<'a> Plan<'a> {
    pub fn build(
        roster: &'a dyn RetainedRoster,
        owner: &'a dyn RetainedResources,
        assignments: &[Assignment],
    ) -> Result<Self, Requirement> {
        let roster_revision = roster.revision();
        let resource_revision = owner.revision();
        let cores = roster.cores();
        if cores.is_empty() {
            return Err(Requirement::EmptyRoster);
        }
        if assignments.len() != cores.len() {
            return Err(Requirement::Cardinality {
                assigned: cores.len(),
                requested: assignments.len(),
            });
        }
        let mut workers = BTreeSet::new();
        let mut physical = BTreeSet::new();
        let mut apics = BTreeSet::new();
        for core in cores {
            if !workers.insert(core.worker) {
                return Err(Requirement::DuplicateWorker(core.worker));
            }
            if !physical.insert((core.package, core.core)) {
                return Err(Requirement::DuplicatePhysicalCore {
                    package: core.package,
                    core: core.core,
                });
            }
            if !apics.insert(core.apic) {
                return Err(Requirement::DuplicateApic(core.apic));
            }
            if !core.started {
                return Err(Requirement::UnstartedWorker(core.worker));
            }
        }
        let boots = assignments
            .iter()
            .filter(|assignment| assignment.boot)
            .count();
        if boots != 1 {
            return Err(Requirement::BootCount(boots));
        }
        let r = owner.resources();
        if r.provenance.is_empty()
            || r.profile.soc == 0
            || r.profile.input_set_sha256 == [0; 32]
            || r.profile.adapted_set_sha256 == Some([0; 32])
        {
            return Err(missing(assignments[0].slot, ResourceKind::Provenance));
        }
        if !r.register_granule.is_power_of_two() {
            return Err(conflict(assignments[0].slot, ResourceKind::RegisterGranule));
        }
        unique(r.kinds.iter().map(|v| v.id), ResourceKind::CoreKind)?;
        unique(r.slots.iter().map(|v| v.id), ResourceKind::GuestSlot)?;
        unique(r.clusters.iter().map(|v| v.id), ResourceKind::Cluster)?;
        unique(r.caches.iter().map(|v| v.id), ResourceKind::Cache)?;
        unique(r.interrupts.iter().map(|v| v.id), ResourceKind::Interrupt)?;
        unique(r.starts.iter().map(|v| v.id), ResourceKind::Start)?;
        unique(r.powers.iter().map(|v| v.id), ResourceKind::CorePower)?;
        let mut assigned_workers = BTreeSet::new();
        let mut assigned_slots = BTreeSet::new();
        let mut affinities = BTreeSet::new();
        let mut selected_clusters = BTreeSet::new();
        let mut physical_clusters = BTreeSet::new();
        let mut selected_interrupts = BTreeSet::new();
        let mut selected_starts = BTreeSet::new();
        let mut pes = Vec::with_capacity(cores.len());
        let mut clusters: Vec<PlannedCluster> = Vec::new();
        let mut cluster_cores = BTreeSet::new();
        let mut firmware_clusters = BTreeSet::new();
        let mut die_clusters = BTreeSet::new();
        for (logical, assignment) in assignments.iter().enumerate() {
            let core = cores
                .iter()
                .find(|core| core.worker == assignment.worker)
                .ok_or(Requirement::UnknownWorker(assignment.worker))?;
            if !assigned_workers.insert(core.worker) {
                return Err(Requirement::DuplicateWorker(core.worker));
            }
            let id = assignment.slot;
            if !assigned_slots.insert(id) {
                return Err(Requirement::DuplicateAssignment(id));
            }
            let slot = r
                .slots
                .iter()
                .find(|slot| slot.id == id)
                .ok_or(Requirement::UnknownSlot(id))?;
            if slot.reg & !AFFINITY_MASK != 0 {
                return Err(Requirement::InvalidAffinity(id));
            }
            if !affinities.insert(slot.reg) {
                return Err(Requirement::DuplicateAffinity(slot.reg));
            }
            let cluster = r
                .clusters
                .iter()
                .find(|cluster| cluster.id == slot.cluster)
                .ok_or_else(|| missing(id, ResourceKind::Cluster))?;
            if u32::from(cluster.aff1) != slot.reg >> CLUSTER_SHIFT {
                return Err(conflict(id, ResourceKind::Cluster));
            }
            if selected_clusters.insert(cluster.id) {
                if !physical_clusters.insert(cluster.aff1) {
                    return Err(Requirement::ClusterAffinity(cluster.aff1));
                }
                if !firmware_clusters.insert((cluster.die, cluster.firmware_id)) {
                    return Err(Requirement::ClusterFirmwareId {
                        die: cluster.die,
                        cluster: cluster.firmware_id,
                    });
                }
                if !die_clusters.insert((cluster.die, cluster.die_cluster)) {
                    return Err(Requirement::ClusterCoordinate {
                        die: cluster.die,
                        cluster: cluster.die_cluster,
                    });
                }
            }
            if !cluster_cores.insert((cluster.id, slot.cluster_core)) {
                return Err(Requirement::DuplicateClusterCore {
                    cluster: cluster.id,
                    core: slot.cluster_core,
                });
            }
            let kind = slot
                .kind
                .and_then(|id| r.kinds.iter().find(|kind| kind.id == id))
                .ok_or_else(|| missing(id, ResourceKind::CoreKind))?;
            if kind.cluster_type == 0
                || kind.midr == 0
                || kind.midr > u64::from(u32::MAX)
                || kind.aff2 > crate::board::mpidr::CORETYPE_MASK
                || kind.clock == Some(0)
            {
                return Err(conflict(id, ResourceKind::CoreKind));
            }
            let cache = cluster
                .cache
                .and_then(|id| r.caches.iter().find(|cache| cache.id == id))
                .ok_or_else(|| missing(id, ResourceKind::Cache))?;
            if cache.cluster != cluster.id {
                return Err(conflict(id, ResourceKind::Cache));
            }
            let logical_cluster =
                if let Some(index) = clusters.iter().position(|v| v.resource.id == cluster.id) {
                    index
                } else {
                    let logical = clusters.len();
                    clusters.push(PlannedCluster {
                        logical,
                        resource: *cluster,
                        cache: *cache,
                    });
                    logical
                };
            let caches = Caches::split_unified(kind.instruction, kind.data, cache.geometry)
                .map_err(|_| Requirement::InvalidCache(id))?;
            let interrupt = slot
                .interrupt
                .and_then(|id| r.interrupts.iter().find(|v| v.id == id))
                .ok_or_else(|| missing(id, ResourceKind::Interrupt))?;
            if interrupt.reg != slot.reg || !selected_interrupts.insert(interrupt.id) {
                return Err(conflict(id, ResourceKind::Interrupt));
            }
            let start = slot
                .start
                .and_then(|id| r.starts.iter().find(|v| v.id == id))
                .ok_or_else(|| missing(id, ResourceKind::Start))?;
            if start.reg != slot.reg || !selected_starts.insert(start.id) {
                return Err(conflict(id, ResourceKind::Start));
            }
            let power = slot
                .power
                .and_then(|id| r.powers.iter().find(|v| v.id == id))
                .ok_or_else(|| missing(id, ResourceKind::CorePower))?;
            if !power.cores.contains(&id) {
                return Err(conflict(id, ResourceKind::CorePower));
            }
            let cluster_power = cluster
                .power
                .and_then(|id| r.powers.iter().find(|v| v.id == id))
                .ok_or_else(|| missing(id, ResourceKind::ClusterPower))?;
            if !cluster_power.clusters.contains(&cluster.id) {
                return Err(conflict(id, ResourceKind::ClusterPower));
            }
            pes.push(PlannedPe {
                logical,
                host: *core,
                slot: id,
                reg: slot.reg,
                kind: kind.id,
                cluster_type: kind.cluster_type,
                identity: Identity {
                    midr: kind.midr,
                    mpidr: crate::board::mpidr::compose(kind.aff2, slot.reg)
                        .ok_or_else(|| conflict(id, ResourceKind::CoreKind))?,
                    clock: kind.clock,
                    caches: Some(caches),
                },
                cluster: cluster.id,
                logical_cluster,
                cluster_core: slot.cluster_core,
                cache: cache.id,
                interrupt: interrupt.id,
                start: start.id,
                core_power: power.id,
                cluster_power: cluster_power.id,
                cpu_impl: range(
                    r.register_granule,
                    slot.cpu_impl,
                    id,
                    ResourceKind::CpuImplementation,
                )?,
                acc_impl: range(
                    r.register_granule,
                    cluster.acc_impl,
                    id,
                    ResourceKind::AccImplementation,
                )?,
                cpm_impl: range(
                    r.register_granule,
                    cluster.cpm_impl,
                    id,
                    ResourceKind::CpmImplementation,
                )?,
                boot: assignment.boot,
            });
        }
        for core in cores {
            if !assigned_workers.contains(&core.worker) {
                return Err(Requirement::MissingWorker(core.worker));
            }
        }
        // A selected physical domain may explicitly cover several PEs or
        // clusters. Every such participant must exist in this same plan;
        // omitted state cannot become an empty-consumer success later.
        for power in r.powers.iter().filter(|power| {
            pes.iter()
                .any(|pe| pe.core_power == power.id || pe.cluster_power == power.id)
        }) {
            let participant = pes
                .iter()
                .find(|pe| pe.core_power == power.id || pe.cluster_power == power.id)
                .unwrap();
            if power
                .cores
                .iter()
                .any(|core| !assigned_slots.contains(core))
                || power
                    .clusters
                    .iter()
                    .any(|cluster| !selected_clusters.contains(cluster))
            {
                return Err(conflict(participant.slot, ResourceKind::CorePower));
            }
            unique(power.cores.iter().copied(), ResourceKind::CorePower)?;
            unique(power.clusters.iter().copied(), ResourceKind::ClusterPower)?;
        }
        // A shared cluster contributes one range per role, independently of
        // core kind. CPU implementation regions remain per physical PE.
        let mut ranges: Vec<RegisterRange> = pes.iter().map(|pe| pe.cpu_impl).collect();
        for cluster in &selected_clusters {
            let pe = pes.iter().find(|pe| pe.cluster == *cluster).unwrap();
            ranges.extend([pe.acc_impl, pe.cpm_impl]);
        }
        for (index, region) in ranges.iter().enumerate() {
            if ranges[..index]
                .iter()
                .any(|previous| region.overlaps(*previous))
            {
                return Err(Requirement::OverlappingRegisters);
            }
        }
        let span = physical_clusters
            .iter()
            .map(|aff1| {
                pes.iter()
                    .filter(|pe| pe.reg >> CLUSTER_SHIFT == u32::from(*aff1))
                    .map(|pe| (pe.reg & AFFINITY_PART_MASK) as usize + 1)
                    .max()
                    .unwrap_or(0)
            })
            .sum();
        let mut capacity_kinds = BTreeSet::new();
        for capacity in r.capacities {
            if !capacity_kinds.insert(capacity.kind) {
                return Err(Requirement::DuplicateCapacity(capacity.kind));
            }
        }
        for kind in CAPACITIES {
            let capacity = r
                .capacities
                .iter()
                .find(|capacity| capacity.kind == kind)
                .filter(|capacity| !capacity.provenance.is_empty())
                .ok_or(Requirement::MissingCapacity(kind))?;
            let maximum = capacity.maximum.ok_or(Requirement::MissingCapacity(kind))?;
            let required = match kind {
                CapacityKind::KernelCpus
                | CapacityKind::MonitorCpus
                | CapacityKind::PlatformCpus
                | CapacityKind::KernelCpuMask => pes.len(),
                CapacityKind::KernelClusters | CapacityKind::PlatformClusters => {
                    selected_clusters.len()
                }
                CapacityKind::KernelAffinitySpan => span,
                // Maximum physical ID is inclusive; use a count to make the boundary explicit.
                CapacityKind::KernelPhysicalCluster => {
                    usize::from(*physical_clusters.iter().next_back().unwrap()) + 1
                }
            };
            if required > maximum {
                return Err(Requirement::Capacity {
                    kind,
                    required,
                    maximum,
                });
            }
        }
        let plan = Self {
            identity: PlanIdentity(Arc::new(PlanMarker)),
            roster,
            roster_revision,
            resource_owner: owner,
            resource_revision,
            resources: r,
            pes,
            clusters,
        };
        plan.revalidate()?;
        Ok(plan)
    }
}

#[cfg(test)]
mod tests;
