//! Immutable construction from retained roster/resource views. This is a plan,
//! never native execution, CPU-start, PMGR-settlement or backing authority.
//! Root owners must separately admit the same plan against actual executors and
//! devices. No source addresses, chip counts or limits are inferred here.
mod source;
pub use source::{BspSource, SourceIdentity};

pub use crate::platform::apple::pmgr::coverage::DomainId;
use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use {
    stela_contracts::Chip, stela_contracts::caches::Cache, stela_contracts::caches::Caches,
    stela_contracts::identity::Identity,
};

const AFFINITY_MASK: u32 = 0xffff;
const AFFINITY_PART_MASK: u32 = 0xff;
const CLUSTER_SHIFT: u32 = 8;
const CORETYPE_SHIFT: u32 = 16;
const CORETYPE_MASK: u8 = 7;
const MPIDR_RES1: u64 = 1 << 31;

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
/// These observations alone grant no executor authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedCore {
    pub worker: usize,
    pub package: u32,
    pub core: u32,
    pub apic: u32,
    pub started: bool,
}

/// Implemented by the retained real roster owner. Its borrow must retain the
/// observations and source identity; revisions must advance monotonically
/// without reuse after any change. Revision changes invalidate a plan. This
/// metadata interface cannot create WorkerOwner/NativeLoan or prove native
/// state recovery. Consumers must still use those actual authority boundaries.
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

/// A caller-qualified whole-consumer capacity, not merely one observed literal.
/// `None` retains an unknown requirement. Provenance is review metadata, not
/// a cryptographic admission or a substitute for the retained source owner.
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

/// Every identity/cache field comes from supplied qualified semantics. Missing
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
    /// Firmware coordinates are die-qualified; they are not the kernel's
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
/// Explicit physical power-domain membership permits qualified shared/aliased
/// owners, but never discovers membership from names or numeric ID formulas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerResource {
    pub id: DomainId,
    pub cores: Vec<GuestSlotId>,
    pub clusters: Vec<ClusterId>,
}
/// Source identity is retained as metadata; it never selects behavior or
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
/// Actual resource-owner adapter. A plan retains this borrow through use;
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
/// Identity for joining views of one plan, not executor or device authority.
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
/// All views share this identity and retain the actual caller-owned roster and
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
    /// retained views; it is not a numeric substitute for actual AP returns.
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
                || kind.aff2 > CORETYPE_MASK
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
                    mpidr: MPIDR_RES1
                        | u64::from(kind.aff2) << CORETYPE_SHIFT
                        | u64::from(slot.reg),
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
mod tests {
    use super::*;
    use alloc::vec;
    use core::cell::Cell;

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
        profile: ResourceProfile,
        revision: Cell<u64>,
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
            self.revision.get()
        }
        fn resources(&self) -> Resources<'_> {
            Resources {
                profile: self.profile,
                register_granule: 0x4000,
                provenance: "explicit synthetic qualified test inventory; not Apple slot evidence",
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
    fn domain(n: u16) -> DomainId {
        DomainId { die: 0, device: n }
    }
    fn region(n: usize) -> RegisterRange {
        RegisterRange {
            base: 0x1000_0000 + n as u64 * 0x1_0000,
            bytes: 0x9008,
        }
    }
    fn fixture(regs: &[u32]) -> (Roster, Inventory, Vec<Assignment>) {
        let roster = Roster {
            cores: regs
                .iter()
                .enumerate()
                .map(|(i, _)| AssignedCore {
                    worker: 40 + i,
                    package: 3,
                    core: 10 + i as u32,
                    apic: 100 + i as u32 * 2,
                    started: true,
                })
                .collect(),
            revision: Cell::new(7),
        };
        let cache = Cache {
            bytes: 4 << 20,
            ways: 16,
            line: 128,
        };
        let capacities = CAPACITIES
            .into_iter()
            .map(|kind| Capacity {
                kind,
                maximum: Some(match kind {
                    CapacityKind::KernelClusters | CapacityKind::PlatformClusters => 6,
                    CapacityKind::KernelPhysicalCluster => 11,
                    CapacityKind::KernelCpuMask => 64,
                    _ => 20,
                }),
                provenance: "synthetic boundaries; not complete original capacity admission",
            })
            .collect();
        let mut r = Inventory {
            profile: ResourceProfile {
                chip: Chip::AppleM1,
                soc: 0x6000,
                board: 8,
                input_set_sha256: [1; 32],
                adapted_set_sha256: None,
            },
            revision: Cell::new(9),
            capacities,
            kinds: vec![CoreKind {
                id: KindId(1),
                cluster_type: b'E',
                midr: 0x611f0220,
                aff2: 0,
                clock: Some(2_000_000_000),
                instruction: cache,
                data: cache,
            }],
            slots: Vec::new(),
            clusters: Vec::new(),
            caches: Vec::new(),
            interrupts: Vec::new(),
            starts: Vec::new(),
            powers: Vec::new(),
        };
        for (i, reg) in regs.iter().copied().enumerate() {
            let cluster = ClusterId(reg >> 8);
            if !r.clusters.iter().any(|v| v.id == cluster) {
                let index = r.clusters.len();
                r.clusters.push(ClusterSlot {
                    id: cluster,
                    aff1: (reg >> 8) as u8,
                    firmware_id: cluster.0 + 50,
                    die: 3,
                    die_cluster: cluster.0 + 20,
                    cache: Some(CacheId(cluster.0)),
                    power: Some(domain(1000 + cluster.0 as u16)),
                    acc_impl: Some(region(100 + 2 * index)),
                    cpm_impl: Some(region(101 + 2 * index)),
                });
                r.caches.push(SharedCache {
                    id: CacheId(cluster.0),
                    cluster,
                    geometry: cache,
                });
                r.powers.push(PowerResource {
                    id: domain(1000 + cluster.0 as u16),
                    cores: Vec::new(),
                    clusters: vec![cluster],
                });
            }
            r.slots.push(PeSlot {
                id: GuestSlotId(i as u32 + 7),
                reg,
                kind: Some(KindId(1)),
                cluster,
                cluster_core: reg & AFFINITY_PART_MASK,
                interrupt: Some(InterruptId(i as u32)),
                start: Some(StartId(i as u32)),
                power: Some(domain(i as u16)),
                cpu_impl: Some(region(i)),
            });
            r.interrupts.push(InterruptTarget {
                id: InterruptId(i as u32),
                reg,
            });
            r.starts.push(StartResource {
                id: StartId(i as u32),
                reg,
            });
            r.powers.push(PowerResource {
                id: domain(i as u16),
                cores: vec![GuestSlotId(i as u32 + 7)],
                clusters: Vec::new(),
            });
        }
        let assignments = regs
            .iter()
            .enumerate()
            .map(|(i, _)| Assignment {
                worker: 40 + i,
                slot: GuestSlotId(i as u32 + 7),
                boot: i == regs.len() - 1,
            })
            .collect();
        (roster, r, assignments)
    }
    fn contiguous(n: usize) -> Vec<u32> {
        (0..n).map(|i| (((i / 4) << 8) | (i % 4)) as u32).collect()
    }
    fn set(r: &mut Inventory, kind: CapacityKind, maximum: usize) {
        r.capacities
            .iter_mut()
            .find(|v| v.kind == kind)
            .unwrap()
            .maximum = Some(maximum);
    }
    #[test]
    fn exact_assigned_cardinality_constructs_below_and_at_capacity_without_stock_counts() {
        for n in [1, 4, 8, 10, 12, 16, 19, 20] {
            let (host, resources, mut assignments) = fixture(&contiguous(n));
            assignments.reverse();
            let plan = Plan::build(&host, &resources, &assignments).unwrap();
            assert_eq!(plan.pes().len(), n);
            assert_eq!(plan.pes().iter().filter(|pe| pe.boot).count(), 1);
            assert_eq!(plan.pes()[0].logical, 0);
            assert_eq!(plan.pes()[0].host.worker, 40 + n - 1);
            assert_eq!(plan.pes()[0].slot, GuestSlotId(n as u32 + 6));
            assert_eq!(plan.pes()[0].logical_cluster, 0);
            assert_eq!(plan.clusters()[0].logical, 0);
            assert_eq!(plan.clusters()[0].resource.aff1, ((n - 1) / 4) as u8);
            assert_eq!(plan.clusters()[0].resource.die, 3);
            assert_eq!(
                plan.clusters()[0].resource.firmware_id,
                ((n - 1) / 4) as u32 + 50
            );
            for pe in plan.pes() {
                assert_eq!(pe.identity.mpidr & 0xffff, u64::from(pe.reg));
                assert!(pe.identity.caches.is_some());
            }
            assert!(plan.revalidate().is_ok());
            assert_eq!(plan.identity(), plan.identity());
            let independent = Plan::build(&host, &resources, &assignments).unwrap();
            assert_ne!(plan.identity(), independent.identity());
        }
    }
    #[test]
    fn above_capacity_names_the_actual_consumer_and_never_truncates() {
        let (host, mut r, a) = fixture(&contiguous(21));
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::Capacity {
                kind: CapacityKind::KernelCpus,
                required: 21,
                maximum: 20
            }
        );
        set(&mut r, CapacityKind::KernelCpus, 21);
        set(&mut r, CapacityKind::KernelAffinitySpan, 21);
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::Capacity {
                kind: CapacityKind::MonitorCpus,
                required: 21,
                maximum: 20
            }
        );
        set(&mut r, CapacityKind::MonitorCpus, 21);
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::Capacity {
                kind: CapacityKind::PlatformCpus,
                required: 21,
                maximum: 20
            }
        );
        set(&mut r, CapacityKind::PlatformCpus, 21);
        assert_eq!(Plan::build(&host, &r, &a).unwrap().pes().len(), 21);
    }
    #[test]
    fn sparse_affinity_span_and_physical_cluster_boundaries_are_independent_of_count() {
        let (host, mut r, a) = fixture(&[0, 19]);
        assert!(Plan::build(&host, &r, &a).is_ok());
        r.slots[1].reg = 20;
        r.interrupts[1].reg = 20;
        r.starts[1].reg = 20;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::Capacity {
                kind: CapacityKind::KernelAffinitySpan,
                required: 21,
                maximum: 20
            }
        );
        let (host, r, a) = fixture(&[0xa00]);
        assert!(Plan::build(&host, &r, &a).is_ok());
        let (host, r, a) = fixture(&[0xb00]);
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::Capacity {
                kind: CapacityKind::KernelPhysicalCluster,
                required: 12,
                maximum: 11
            }
        );
    }
    #[test]
    fn sixth_and_seventh_cluster_and_64_bit_mask_limits_do_not_alias() {
        for n in [6, 7] {
            let regs: Vec<_> = (0..n).map(|i| i << 8).collect();
            let (host, r, a) = fixture(&regs);
            if n == 6 {
                assert!(Plan::build(&host, &r, &a).is_ok());
            } else {
                assert_eq!(
                    Plan::build(&host, &r, &a).unwrap_err(),
                    Requirement::Capacity {
                        kind: CapacityKind::KernelClusters,
                        required: 7,
                        maximum: 6
                    }
                );
            }
        }
        for n in [63, 64, 65] {
            // Synthetic expanded resource inventory, not a kernel adaptation.
            let regs: Vec<_> = (0..n as u32).collect();
            let (host, mut r, a) = fixture(&regs);
            for kind in [
                CapacityKind::KernelCpus,
                CapacityKind::KernelAffinitySpan,
                CapacityKind::MonitorCpus,
                CapacityKind::PlatformCpus,
            ] {
                set(&mut r, kind, 65);
            }
            if n <= 64 {
                assert_eq!(Plan::build(&host, &r, &a).unwrap().pes().len(), n);
            } else {
                assert_eq!(
                    Plan::build(&host, &r, &a).unwrap_err(),
                    Requirement::Capacity {
                        kind: CapacityKind::KernelCpuMask,
                        required: 65,
                        maximum: 64
                    }
                );
            }
        }
    }
    #[test]
    fn unstarted_smt_duplicate_worker_and_apic_records_cannot_receive_credit() {
        let (mut host, r, a) = fixture(&[0, 1]);
        host.cores[1].started = false;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::UnstartedWorker(41)
        );
        host.cores[1].started = true;
        host.cores[1].core = host.cores[0].core;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::DuplicatePhysicalCore {
                package: 3,
                core: 10
            }
        );
        host.cores[1].core = 11;
        host.cores[1].apic = host.cores[0].apic;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::DuplicateApic(100)
        );
        host.cores[1].apic = 102;
        host.cores[1].worker = 40;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::DuplicateWorker(40)
        );
    }
    #[test]
    fn cardinality_boot_assignment_and_affinity_errors_are_atomic() {
        let (host, mut r, mut a) = fixture(&[0, 1]);
        assert_eq!(
            Plan::build(&host, &r, &a[..1]).unwrap_err(),
            Requirement::Cardinality {
                assigned: 2,
                requested: 1
            }
        );
        a[0].boot = true;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::BootCount(2)
        );
        a[0].boot = false;
        a[1].worker = 40;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::DuplicateWorker(40)
        );
        a[1].worker = 99;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::UnknownWorker(99)
        );
        a[1].worker = 41;
        a[1].slot = a[0].slot;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::DuplicateAssignment(GuestSlotId(7))
        );
        a[1].slot = GuestSlotId(8);
        r.slots[1].reg = 0;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::DuplicateAffinity(0)
        );
        assert_eq!(host.revision(), 7);
        assert_eq!(r.revision(), 9);
    }
    #[test]
    fn all_selected_resources_are_required_and_cross_wired_targets_refuse() {
        let (host, mut r, a) = fixture(&[0]);
        r.slots[0].start = None;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            missing(GuestSlotId(7), ResourceKind::Start)
        );
        r.slots[0].start = Some(StartId(0));
        r.starts[0].reg = 1;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            conflict(GuestSlotId(7), ResourceKind::Start)
        );
        r.starts[0].reg = 0;
        r.interrupts[0].reg = 1;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            conflict(GuestSlotId(7), ResourceKind::Interrupt)
        );
        r.interrupts[0].reg = 0;
        r.powers[1].cores.clear();
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            conflict(GuestSlotId(7), ResourceKind::CorePower)
        );
        r.powers[1].cores.push(GuestSlotId(7));
        r.clusters[0].acc_impl = None;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            missing(GuestSlotId(7), ResourceKind::AccImplementation)
        );
        r.clusters[0].acc_impl = Some(region(100));
        r.slots[0].kind = None;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            missing(GuestSlotId(7), ResourceKind::CoreKind)
        );
    }
    #[test]
    fn cache_cluster_register_and_unknown_capacity_mismatches_cannot_make_a_plan() {
        let (host, mut r, a) = fixture(&[0]);
        r.caches[0].cluster = ClusterId(3);
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            conflict(GuestSlotId(7), ResourceKind::Cache)
        );
        r.caches[0].cluster = ClusterId(0);
        r.caches[0].geometry.bytes = 1;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::InvalidCache(GuestSlotId(7))
        );
        r.caches[0].geometry.bytes = 4 << 20;
        r.slots[0].cpu_impl = Some(region(100));
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::OverlappingRegisters
        );
        r.slots[0].cpu_impl = Some(region(0));
        r.capacities[0].maximum = None;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::MissingCapacity(CapacityKind::KernelCpus)
        );
        r.capacities[0].maximum = Some(20);
        r.capacities.push(r.capacities[0]);
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::DuplicateCapacity(CapacityKind::KernelCpus)
        );
    }
    #[test]
    fn mixed_core_types_share_physical_cluster_cache_and_keep_distinct_aff2() {
        let (host, mut r, a) = fixture(&[0x100, 0x101]);
        let mut other = r.kinds[0];
        other.id = KindId(2);
        other.aff2 = 4;
        other.cluster_type = b'M';
        // Explicit synthetic identity; no unobserved M6 MIDR is inferred.
        other.midr = 0x1234;
        r.kinds.push(other);
        r.slots[1].kind = Some(other.id);
        let plan = Plan::build(&host, &r, &a).unwrap();
        assert_eq!(plan.pes()[0].cluster, plan.pes()[1].cluster);
        assert_eq!(plan.pes()[0].cache, plan.pes()[1].cache);
        assert_eq!(plan.pes()[0].identity.caches, plan.pes()[1].identity.caches);
        assert_eq!(plan.pes()[0].identity.mpidr >> 8 & 0xff, 1);
        assert_eq!(plan.pes()[1].identity.mpidr >> 8 & 0xff, 1);
        assert_eq!(plan.pes()[1].identity.mpidr >> 16 & 7, 4);
    }
    #[test]
    fn same_plan_retains_roster_and_resource_revision_without_native_authority() {
        let (host, r, a) = fixture(&[0, 1]);
        let plan = Plan::build(&host, &r, &a).unwrap();
        host.revision.set(8);
        assert_eq!(plan.revalidate(), Err(Requirement::RosterChanged));
        let current = Plan::build(&host, &r, &a).unwrap();
        r.revision.set(10);
        assert_eq!(current.revalidate(), Err(Requirement::ResourcesChanged));
    }
    #[test]
    fn selected_shared_power_requires_every_explicit_participant_and_complete_ranges() {
        let (host, mut r, a) = fixture(&[0, 1]);
        r.slots[1].power = r.slots[0].power;
        let power = r.powers.iter_mut().find(|v| v.id == domain(0)).unwrap();
        power.cores.push(GuestSlotId(8));
        let plan = Plan::build(&host, &r, &a).unwrap();
        assert_eq!(plan.pes()[0].core_power, plan.pes()[1].core_power);
        drop(plan);
        r.powers
            .iter_mut()
            .find(|v| v.id == domain(0))
            .unwrap()
            .cores
            .push(GuestSlotId(99));
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            conflict(GuestSlotId(7), ResourceKind::CorePower)
        );
        r.powers
            .iter_mut()
            .find(|v| v.id == domain(0))
            .unwrap()
            .cores
            .pop();
        r.slots[0].cpu_impl = Some(RegisterRange {
            base: !0x3fff,
            bytes: 0x10000,
        });
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            conflict(GuestSlotId(7), ResourceKind::CpuImplementation)
        );
    }
    #[test]
    fn changed_resource_view_cannot_reuse_an_unchanged_revision() {
        struct Changing<'a> {
            inventory: &'a Inventory,
            changed: Cell<bool>,
        }
        impl RetainedResources for Changing<'_> {
            fn revision(&self) -> u64 {
                9
            }
            fn resources(&self) -> Resources<'_> {
                let mut r = self.inventory.resources();
                if self.changed.get() {
                    r.provenance = "replacement input view";
                }
                r
            }
        }
        let (host, r, a) = fixture(&[0]);
        let source = Changing {
            inventory: &r,
            changed: Cell::new(false),
        };
        let plan = Plan::build(&host, &source, &a).unwrap();
        source.changed.set(true);
        assert_eq!(plan.revalidate(), Err(Requirement::ResourcesChanged));
    }
    #[test]
    fn cpu_family_never_substitutes_for_explicit_source_variant_or_host_cardinality() {
        for chip in [
            Chip::AppleM1,
            Chip::AppleM2,
            Chip::AppleM3,
            Chip::AppleM4,
            Chip::AppleM5,
            Chip::AppleM6,
        ] {
            // All resources and semantics are synthetic explicit input, not
            // claims that these fields qualify any unobserved silicon.
            let (host, mut r, a) = fixture(&contiguous(12));
            r.profile.chip = chip;
            let plan = Plan::build(&host, &r, &a).unwrap();
            assert_eq!(plan.pes().len(), 12);
            assert_eq!(plan.chip(), chip);
            assert_eq!(plan.profile(), r.profile);
        }
        let (host, mut r, a) = fixture(&[0]);
        r.profile.input_set_sha256 = [0; 32];
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            missing(GuestSlotId(7), ResourceKind::Provenance)
        );
    }
    #[test]
    fn empty_missing_and_ambiguous_inputs_cannot_publish_partial_membership() {
        let (host, mut r, mut a) = fixture(&[0, 1]);
        let empty = Roster {
            cores: Vec::new(),
            revision: Cell::new(0),
        };
        assert_eq!(
            Plan::build(&empty, &r, &[]).unwrap_err(),
            Requirement::EmptyRoster
        );
        a[1].boot = false;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::BootCount(0)
        );
        a[1].boot = true;
        r.slots[1].cluster_core = r.slots[0].cluster_core;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::DuplicateClusterCore {
                cluster: ClusterId(0),
                core: 0
            }
        );
        r.slots[1].cluster_core = 1;
        r.capacities.retain(|v| v.kind != CapacityKind::MonitorCpus);
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::MissingCapacity(CapacityKind::MonitorCpus)
        );
        assert_eq!(host.revision(), 7);
        assert_eq!(r.revision(), 9);
    }
    #[test]
    fn firmware_and_die_cluster_coordinates_cannot_alias_two_physical_clusters() {
        let (host, mut r, a) = fixture(&[0, 0x100]);
        r.clusters[1].firmware_id = r.clusters[0].firmware_id;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::ClusterFirmwareId {
                die: 3,
                cluster: 50
            }
        );
        r.clusters[1].firmware_id = 51;
        r.clusters[1].die_cluster = r.clusters[0].die_cluster;
        assert_eq!(
            Plan::build(&host, &r, &a).unwrap_err(),
            Requirement::ClusterCoordinate {
                die: 3,
                cluster: 20
            }
        );
        r.clusters[1].die = 4;
        assert!(Plan::build(&host, &r, &a).is_ok());
    }
}
