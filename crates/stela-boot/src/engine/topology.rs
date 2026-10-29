//! Runtime assignment, before firmware publication. Metadata is joined to the
//! actual BSP observation and a retained resource owner; it is never a stock
//! SKU count or executor/lifecycle authority. Parent owns RAM/device adoption.
//!
//! Original J314s source contract: iBoot file3ab04..3ab7c publishes max/E/P;
//! mac13j XNU VAfffffe000bda7168 enumerates CPU children, not waiting flags;
//! AppleInterruptControllerV2 file2822dc4/282375c uses #main-cpus. SPTM
//! VAfffffff0270ca10c requires the three implementation ranges. Exact source
//! hashes/coordinates remain in the immutable j314s-single-core-topology audit.
//! No source hash selects production behavior and no capacity is inferred here.
use alloc::{format, string::String, vec::Vec};
use stela_engine::machine::CpuProfile;
use stela_loader::apple_device_tree::{
    DeviceTree,
    assigned::{Count, CountField, CpuIdRecipe, NodeBinding, Projection, Receipt, SourceBindings},
};
use stela_soc_data::board::assigned::AssignedCore;
use stela_soc_data::board::assigned::Assignment;
use stela_soc_data::board::assigned::BspSource;
use stela_soc_data::board::assigned::Plan;
use stela_soc_data::board::assigned::PlanIdentity;
use stela_soc_data::board::assigned::RegisterRange;
use stela_soc_data::board::assigned::RetainedResources;
use stela_soc_data::board::assigned::RetainedRoster;
use stela_soc_data::board::assigned::SourceIdentity;

#[cfg(not(test))]
use super::bundle::live_tree::LiveTree;
#[cfg(test)]
use crate::boot_live_tree::LiveTree;
use stela_boot_core::{record::Capture, topology as native};
#[cfg(test)]
use stela_soc_data::board::assigned::GuestSlotId;

/// These count consumers are independently source-qualified for the retained
/// Apple ARM CPU/AIC schema (original J314s audit). They all use the same Plan.
/// This deliberately adds no cpu-cluster-count or PMGR hardware-cluster rule.
pub(crate) const COUNT_FIELDS: [CountField<'static>; 4] = [
    CountField {
        path: "/cpus",
        property: "max_cpus",
        count: Count::Pes,
    },
    CountField {
        path: "/cpus",
        property: "e-core-count",
        count: Count::CoreType(b'E'),
    },
    CountField {
        path: "/cpus",
        property: "p-core-count",
        count: Count::CoreType(b'P'),
    },
    CountField {
        path: "/arm-io/aic",
        property: "#main-cpus",
        count: Count::Pes,
    },
];

/// Retains the actual immutable pre-EBS observation. Only the executing BSP is
/// started by this adapter. Captured AP observations do not imply AP startup.
pub(crate) struct BspRoster<'a> {
    capture: &'a Capture,
    #[cfg(test)]
    source: native::Processor,
    cores: [AssignedCore; 1],
}
impl<'a> BspRoster<'a> {
    /// `capture` must be the actual record already accepted by native_smp's
    /// reservation/source validation. The supplied owner is the installed BSP
    /// Host, which the caller must retain through subsequent execution. This
    /// view does not bind a runtime WorkerOwner, loan a frame or authorize RAM.
    #[cfg(not(test))]
    pub(crate) fn new(
        capture: &'a Capture,
        _owner: &super::host::HostOwner,
        worker: usize,
    ) -> Result<Self, String> {
        Self::observed(capture, worker, current_apic()?)
    }
    fn observed(capture: &'a Capture, worker: usize, current: u32) -> Result<Self, String> {
        let processors = capture
            .processors
            .get(..capture.processor_count as usize)
            .ok_or("assigned topology has an invalid captured processor count")?;
        let physical =
            native::select(processors).map_err(|e| format!("assigned BSP source roster: {e:?}"))?;
        let selected = physical
            .get(..capture.core_count as usize)
            .ok_or("assigned topology has more captured cores than physical cores")?;
        if physical.len() != capture.physical_count as usize
            || selected
                .iter()
                .enumerate()
                .any(|(slot, &index)| capture.selected[slot] as usize != index)
        {
            return Err(
                "assigned topology differs from the retained physical-core selection".into(),
            );
        }
        let index = *selected
            .first()
            .ok_or("assigned topology has no retained BSP")?;
        let source = processors[index];
        if source.flags & native::BSP == 0
            || !source.available()
            || source.apic_id != u64::from(current)
            || !capture.snapshots[0].matches(source)
        {
            return Err("assigned topology requires the actual executing captured BSP".into());
        }
        Ok(Self {
            capture,
            #[cfg(test)]
            source,
            cores: [AssignedCore {
                worker,
                package: source.location.package,
                core: source.location.core,
                apic: current,
                started: true,
            }],
        })
    }
    #[cfg(test)]
    pub(crate) fn source(&self) -> native::Processor {
        self.source
    }
}
impl RetainedRoster for BspRoster<'_> {
    fn revision(&self) -> u64 {
        1
    }
    fn cores(&self) -> &[AssignedCore] {
        // Keep the actual source allocation borrowed for the entire Plan.
        let _ = self.capture;
        &self.cores
    }
}

/// A retained roster of actual started executors. Captured AP inventory alone
/// cannot construct this view: each selected AP must have acknowledged its
/// private installed Host and CPUID identity through Executors::start.
#[cfg(not(test))]
pub(crate) struct AssignedRoster<'a> {
    _bsp: BspRoster<'a>,
    _executors: &'a crate::native_smp::executor::Executors,
    cores: Vec<AssignedCore>,
}
#[cfg(not(test))]
impl<'a> AssignedRoster<'a> {
    pub(crate) fn new(
        capture: &'a Capture,
        executors: &'a crate::native_smp::executor::Executors,
        owner: &super::host::HostOwner,
    ) -> Result<Self, String> {
        let bsp = BspRoster::new(capture, owner, 0)?;
        let mut cores = bsp.cores.to_vec();
        for worker in 1..=executors.processors().len() {
            let processor = executors
                .processors()
                .iter()
                .find(|processor| processor.slot() == worker)
                .ok_or("assigned started worker roster has a slot gap")?;
            let index = *capture
                .selected
                .get(worker)
                .filter(|_| worker < capture.core_count as usize)
                .ok_or("assigned worker exceeds captured physical cores")?
                as usize;
            let source = *capture
                .processors
                .get(index)
                .filter(|_| index < capture.processor_count as usize)
                .ok_or("assigned worker has no captured source processor")?;
            if !source.available()
                || source.flags & native::BSP != 0
                || processor.apic_id() != source.apic_id
                || !processor.observation().matches(source)
            {
                return Err("assigned worker differs from actual started AP identity".into());
            }
            cores.push(AssignedCore {
                worker,
                package: source.location.package,
                core: source.location.core,
                apic: u32::try_from(source.apic_id)
                    .map_err(|_| "assigned APIC exceeds transport width")?,
                started: true,
            });
        }
        Ok(Self {
            _bsp: bsp,
            _executors: executors,
            cores,
        })
    }
    /// Select actual started workers before any Plan borrows this roster.
    /// Physical IDs stay unchanged; omitted executors remain retained/parked.
    pub(crate) fn select(&mut self, workers: &[usize]) -> Result<(), String> {
        if workers.is_empty()
            || !workers.contains(&0)
            || workers.iter().enumerate().any(|(index, worker)| {
                workers[..index].contains(worker)
                    || !self.cores.iter().any(|core| core.worker == *worker)
            })
        {
            return Err("active source roster exceeds retained physical workers".into());
        }
        self.cores.retain(|core| workers.contains(&core.worker));
        Ok(())
    }
}
#[cfg(not(test))]
impl RetainedRoster for AssignedRoster<'_> {
    fn revision(&self) -> u64 {
        1
    }
    fn cores(&self) -> &[AssignedCore] {
        &self.cores
    }
}

fn current_apic() -> Result<u32, String> {
    use core::arch::x86_64::__cpuid_count;
    // CPUID is unprivileged. Reuse the canonical captured APIC decoder; this
    // observation establishes current identity, not native capability admission.
    current_identity(|leaf, subleaf| {
        let value = __cpuid_count(leaf, subleaf);
        native::Cpuid {
            leaf,
            subleaf,
            eax: value.eax,
            ebx: value.ebx,
            ecx: value.ecx,
            edx: value.edx,
        }
    })
    .apic_id()
    .ok_or("assigned BSP has no actual CPUID APIC identity".into())
}

/// Retain the actual maximum/vendor records together with the leaves they
/// authorize. Keeping maxima only in local variables creates an incomplete
/// Snapshot that the shared identity decoder must correctly refuse. The query
/// seam permits direct collector regression tests without a privileged owner
/// or guessed processor identity; production above queries this actual CPU.
fn current_identity(mut query: impl FnMut(u32, u32) -> native::Cpuid) -> native::Snapshot {
    let identity = query(0, 0);
    let extended = query(0x8000_0000, 0);
    let mut snapshot = native::Snapshot::default();
    snapshot.records[0] = identity;
    snapshot.records[1] = extended;
    snapshot.count = 2;
    for (leaf, subleaf) in [
        (1, 0),
        (0xb, 0),
        (0x1f, 0),
        (0x8000_0001, 0),
        (0x8000_001e, 0),
    ] {
        if (leaf < 0x8000_0000 && leaf > identity.eax)
            || (leaf >= 0x8000_0000 && leaf > extended.eax)
        {
            continue;
        }
        snapshot.records[snapshot.count as usize] = query(leaf, subleaf);
        snapshot.count += 1;
    }
    snapshot
}

/// A source protocol reference, never a DeviceID inferred from its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Function {
    pub phandle: u32,
    pub selector: u32,
    pub argument: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Join {
    pub plan: PlanIdentity,
    pub logical: usize,
    pub worker: usize,
    pub apic: u32,
    pub reg: u32,
    pub cluster: stela_soc_data::board::assigned::ClusterId,
    pub cache: stela_soc_data::board::assigned::CacheId,
    pub interrupt: stela_soc_data::board::assigned::InterruptId,
    /// Original CPU error input, distinct from the PE/IPI routing owner above.
    pub error_interrupt_parent: u32,
    pub error_interrupt: u32,
    pub start: stela_soc_data::board::assigned::StartId,
    pub enable_core: Function,
    pub core_power: stela_soc_data::pmgr::coverage::DomainId,
    pub cluster_power: stela_soc_data::pmgr::coverage::DomainId,
    pub cpu_impl: RegisterRange,
    pub acc_impl: RegisterRange,
    pub cpm_impl: RegisterRange,
}

/// Retained source owner and immutable ADT. Full source power records remain
/// retained independently of the selected PE subset and unknown PS state.
pub(crate) struct Source<'a> {
    pub resources: BspSource<'a>,
    tree: DeviceTree,
    dense_ids: Option<(DeviceTree, [u8; 32])>,
    boot_reg: u32,
    acc_harvesting: u32,
}
impl<'a> Source<'a> {
    #[cfg(test)]
    pub(crate) fn t6000(
        original: &'a [u8],
        prepared: &[u8],
        identity: SourceIdentity,
        boot_reg: u32,
    ) -> Result<Self, String> {
        let tree = DeviceTree::parse(prepared).map_err(|e| format!("assigned source ADT: {e}"))?;
        let resources = BspSource::t6000(original, prepared, identity, boot_reg)?;
        Ok(Self {
            resources,
            tree,
            dense_ids: None,
            boot_reg,
            acc_harvesting: 1,
        })
    }
    /// Normal T6000 mode1 preserves original cluster-discovery order. The
    /// selected boot PE remains the BSP independently of its logical PE.
    pub(crate) fn t6000_assigned(
        original: &'a [u8],
        live: &LiveTree,
        identity: SourceIdentity,
        boot_reg: u32,
        workers: usize,
    ) -> Result<Self, String> {
        live.require_no_harvesting_override()?;
        let tree = DeviceTree::parse(live.bytes())
            .map_err(|e| format!("assigned live source ADT: {e}"))?;
        let resources =
            BspSource::t6000_assigned(original, live.bytes(), identity, boot_reg, 1, workers)?;
        Ok(Self {
            resources,
            tree,
            dense_ids: None,
            boot_reg,
            acc_harvesting: 1,
        })
    }
    /// Explicit source-family adapter. Checks the actual boot_args snapshot
    /// before selecting normal harvesting; no kernel override is interpreted
    /// as a qualified source mode. Physical PMGR/error recipes stay original.
    pub(crate) fn t8112(
        original: &'a [u8],
        live: &LiveTree,
        identity: SourceIdentity,
        boot_reg: u32,
    ) -> Result<Self, String> {
        live.require_no_harvesting_override()?;
        let tree = DeviceTree::parse(live.bytes())
            .map_err(|e| format!("assigned live source ADT: {e}"))?;
        let immutable = DeviceTree::parse(original)
            .map_err(|e| format!("assigned immutable source ADT: {e}"))?;
        let resources = BspSource::t8112(original, live.bytes(), identity, boot_reg, 0)?;
        Ok(Self {
            resources,
            tree,
            dense_ids: Some((immutable, identity.original_tree_sha256)),
            boot_reg,
            acc_harvesting: 0,
        })
    }
    pub(crate) fn acc_harvesting(&self) -> u32 {
        self.acc_harvesting
    }
    /// Full selected-source adapter for the retained started-worker roster.
    pub(crate) fn t8112_assigned(
        original: &'a [u8],
        live: &LiveTree,
        identity: SourceIdentity,
        boot_reg: u32,
        workers: usize,
    ) -> Result<Self, String> {
        let mut source = Self::t8112(original, live, identity, boot_reg)?;
        source.resources =
            BspSource::t8112_assigned(original, live.bytes(), identity, boot_reg, 0, workers)?;
        Ok(source)
    }
    #[cfg(test)]
    pub(crate) fn prepare<'s>(
        &'s self,
        roster: &'s dyn RetainedRoster,
        profile: CpuProfile,
    ) -> Result<Prepared<'s>, String> {
        self.prepare_with_classes(
            roster,
            profile,
            &alloc::vec![native::CoreClass::Unknown; roster.cores().len()],
        )
    }

    #[cfg(not(test))]
    pub(crate) fn prepare_on<'s>(
        &'s self,
        roster: &'s dyn RetainedRoster,
        profile: CpuProfile,
        capture: &Capture,
    ) -> Result<Prepared<'s>, String> {
        let classes = Self::host_classes(roster, capture)?;
        self.prepare_with_classes(roster, profile, &classes)
    }

    #[cfg(not(test))]
    fn host_classes(
        roster: &dyn RetainedRoster,
        capture: &Capture,
    ) -> Result<Vec<native::CoreClass>, String> {
        roster
            .cores()
            .iter()
            .map(|core| {
                let worker = core.worker;
                let index = *capture
                    .selected
                    .get(worker)
                    .filter(|_| worker < capture.core_count as usize)
                    .ok_or("assigned worker has no captured core class")?
                    as usize;
                let processor = capture
                    .processors
                    .get(index)
                    .ok_or("assigned worker has no captured processor")?;
                let snapshot = &capture.snapshots[worker];
                if u64::from(core.apic) != processor.apic_id || !snapshot.matches(*processor) {
                    return Err("assigned core class differs from its processor identity");
                }
                Ok(snapshot.core_class())
            })
            .collect::<Result<Vec<_>, &str>>()
            .map_err(String::from)
    }

    fn guest_classes(&self) -> Result<Vec<native::CoreClass>, String> {
        let resources = self.resources.resources();
        resources
            .slots
            .iter()
            .map(|slot| {
                let kind = resources
                    .kinds
                    .iter()
                    .find(|kind| Some(kind.id) == slot.kind)
                    .ok_or("assigned source core kind is unknown")?;
                Ok(match kind.cluster_type {
                    b'P' => native::CoreClass::Performance,
                    b'E' => native::CoreClass::Efficiency,
                    _ => native::CoreClass::Unknown,
                })
            })
            .collect()
    }

    #[cfg(not(test))]
    pub(crate) fn select_on(
        &self,
        roster: &mut AssignedRoster<'_>,
        capture: &Capture,
    ) -> Result<(), String> {
        let boot = self
            .resources
            .resources()
            .slots
            .iter()
            .position(|slot| slot.reg == self.boot_reg)
            .ok_or("assigned source omits the original boot PE")?;
        let placement = native::placement(
            &self.guest_classes()?,
            &Self::host_classes(roster, capture)?,
            boot,
        )
        .map_err(|error| format!("assigned host core placement: {error:?}"))?;
        let workers = placement
            .iter()
            .map(|index| roster.cores()[*index].worker)
            .collect::<Vec<_>>();
        roster.select(&workers)
    }

    fn prepare_with_classes<'s>(
        &'s self,
        roster: &'s dyn RetainedRoster,
        profile: CpuProfile,
        host: &[native::CoreClass],
    ) -> Result<Prepared<'s>, String> {
        use sha2::Digest;
        use stela_crypto::Sha256;
        let resources = self.resources.resources();
        if resources.slots.len() != roster.cores().len() {
            return Err("assigned source and actual started worker cardinality differ".into());
        }
        let mut nodes = Vec::with_capacity(resources.slots.len());
        let mut assignments = Vec::with_capacity(resources.slots.len());
        let boot = resources
            .slots
            .iter()
            .position(|slot| slot.reg == self.boot_reg)
            .ok_or("assigned source omits the original boot PE")?;
        let guest = self.guest_classes()?;
        let placement = native::placement(&guest, host, boot)
            .map_err(|error| format!("assigned host core placement: {error:?}"))?;
        for (ordinal, slot) in resources.slots.iter().enumerate() {
            // Source PE order retains PMGR's cluster ordinal coupling; only
            // the host worker assigned to each source slot changes.
            let worker = &roster.cores()[placement[ordinal]];
            let kind = resources
                .kinds
                .iter()
                .find(|kind| Some(kind.id) == slot.kind)
                .ok_or("assigned source core kind is unknown")?;
            let cluster = resources
                .clusters
                .iter()
                .find(|cluster| cluster.id == slot.cluster)
                .ok_or("assigned source cluster is unknown")?;
            nodes.push(NodeBinding {
                slot: slot.id,
                name: self.resources.name_for(slot.id)?,
                midr: kind.midr,
                cache: cluster.cache.ok_or("assigned source cache is unknown")?,
                interrupt: slot
                    .interrupt
                    .ok_or("assigned source interrupt owner is unknown")?,
                start: slot.start.ok_or("assigned source start owner is unknown")?,
                core_power: slot
                    .power
                    .ok_or("assigned source power identity is unknown")?,
                cluster_power: cluster
                    .power
                    .ok_or("assigned source complex power identity is unknown")?,
            });
            assignments.push(Assignment {
                worker: worker.worker,
                slot: slot.id,
                boot: ordinal == boot,
            });
        }
        let source = SourceBindings {
            source_set_sha256: resources.profile.input_set_sha256,
            tree_sha256: Sha256::digest(self.tree.serialize()).into(),
            nodes: &nodes,
            counts: &COUNT_FIELDS,
            references: &[],
            cpu_ids: match &self.dense_ids {
                Some((original, original_sha256)) => CpuIdRecipe::DenseWithWatchdog {
                    original,
                    original_sha256: *original_sha256,
                    watchdog_path: "/arm-io/wdt",
                },
                None => CpuIdRecipe::Preserve,
            },
        };
        prepare_assigned(
            roster,
            &self.resources,
            &assignments,
            &self.tree,
            &source,
            profile,
        )
    }
}

/// The Plan, projected ADT and runtime profile are one checked publication cut.
/// Parent must join its exact physical worker, AIC/start/PMGR and canonical-RAM
/// owners before copying this tree into guest memory or executing firmware.
pub(crate) struct Prepared<'a> {
    pub plan: Plan<'a>,
    pub tree: DeviceTree,
    pub profile: CpuProfile,
    pub receipt: Receipt,
    pub joins: Vec<Join>,
}
impl Prepared<'_> {
    /// Exact checked Plan-to-runtime assignment, preserving actual physical
    /// worker identity independently of the projected guest logical index.
    pub(crate) fn worker_bindings(
        &self,
    ) -> Result<Vec<stela_engine::machine::engine::publication::WorkerBinding>, String> {
        use stela_engine::machine::engine::publication::WorkerBinding;
        use stela_engine::machine::engine::publication::WorkerId;
        self.plan
            .revalidate()
            .map_err(|e| format!("assigned worker route is stale: {e:?}"))?;
        Ok(self
            .plan
            .pes()
            .iter()
            .map(|pe| WorkerBinding {
                pe: pe.logical,
                worker: WorkerId(pe.host.worker),
            })
            .collect())
    }
    /// Lookup only; original error/start inputs never manufacture an assigned
    /// PE. The same retained owner revision must still be current at adoption.
    pub(crate) fn join(&self, reg: u32) -> Result<&Join, String> {
        self.plan
            .revalidate()
            .map_err(|e| format!("assigned route is stale: {e:?}"))?;
        self.joins
            .iter()
            .find(|join| join.reg == reg)
            .ok_or_else(|| format!("source PE {reg:#x} is outside the actual assigned plan"))
    }
}
fn word(tree: &DeviceTree, path: &str, field: &str) -> Result<u32, String> {
    tree.property(path, field)
        .filter(|p| !p.placeholder)
        .and_then(|p| p.as_u32())
        .ok_or_else(|| format!("assigned topology requires complete {path}/{field}"))
}
fn matching_count(actual: &CountField<'_>, expected: &CountField<'_>) -> bool {
    actual.path == expected.path
        && actual.property == expected.property
        && match (actual.count, expected.count) {
            (Count::Pes, Count::Pes) | (Count::Clusters, Count::Clusters) => true,
            (Count::CoreType(a), Count::CoreType(b)) => a == b,
            _ => false,
        }
}

/// Does not invent an inventory from the loader's synthetic Fixture. The
/// retained owner must supply actual qualified kinds, slots, cache geometry,
/// interrupt/start/power identities and whole-consumer capacities. Unknown
/// ownership or initial state is not supplied by this topology operation.
#[cfg(test)]
pub(crate) fn prepare<'a>(
    roster: &'a BspRoster<'_>,
    owner: &'a dyn RetainedResources,
    slot: GuestSlotId,
    tree: &DeviceTree,
    source: &SourceBindings<'_>,
    profile: CpuProfile,
) -> Result<Prepared<'a>, String> {
    prepare_assigned(
        roster,
        owner,
        &[Assignment {
            worker: roster.cores[0].worker,
            slot,
            boot: true,
        }],
        tree,
        source,
        profile,
    )
}

/// Additive owner boundary for actual AP executors. A captured snapshot alone
/// cannot establish started workers: the caller must retain the real admitted
/// roster/resources and separately join every native publication/Host owner.
/// BspSource itself remains one-PE only and cannot supply additional resources.
pub(crate) fn prepare_assigned<'a>(
    roster: &'a dyn RetainedRoster,
    owner: &'a dyn RetainedResources,
    assignments: &[Assignment],
    tree: &DeviceTree,
    source: &SourceBindings<'_>,
    mut profile: CpuProfile,
) -> Result<Prepared<'a>, String> {
    for expected in &COUNT_FIELDS {
        if source
            .counts
            .iter()
            .filter(|field| matching_count(field, expected))
            .count()
            != 1
        {
            return Err(format!(
                "assigned topology requires the same-plan {}/{} count rule",
                expected.path, expected.property
            ));
        }
    }
    // The original producer's literal3 does not qualify an absent property's
    // reduced-cluster consumers. Preserve all PMGR hardware descriptors.
    if source.counts.iter().any(|field| {
        field.property == "cpu-cluster-count" && tree.property(field.path, field.property).is_none()
    }) {
        return Err("assigned topology cannot add an unqualified cpu-cluster-count".into());
    }
    let aic_phandle = word(tree, "/arm-io/aic", "AAPL,phandle")?;
    let pmgr_phandle = word(tree, "/arm-io/pmgr", "AAPL,phandle")?;
    let plan = Plan::build(roster, owner, assignments)
        .map_err(|e| format!("assigned topology requires actual retained resources: {e:?}"))?;
    if profile.chip != plan.chip() {
        return Err("assigned runtime profile and resource chip differ".into());
    }
    let mut joins = Vec::with_capacity(plan.pes().len());
    for pe in plan.pes() {
        let binding: &NodeBinding<'_> = source
            .nodes
            .iter()
            .find(|b| b.slot == pe.slot)
            .ok_or("assigned PE has no actual source CPU binding")?;
        let path = format!("/cpus/{}", binding.name);
        let source_index = tree
            .node("/cpus")
            .and_then(|cpus| {
                cpus.children
                    .iter()
                    .position(|node| node.name() == Some(binding.name))
            })
            .ok_or("assigned PE has no unique original CPU index")?;
        if profile.processors.get(source_index) != Some(&pe.identity) {
            return Err("assigned PE identity differs from the actual source board profile".into());
        }
        let parent = word(tree, &path, "interrupt-parent")?;
        if parent == 0 || parent != aic_phandle {
            return Err(
                "assigned CPU error input has a different actual interrupt provider".into(),
            );
        }
        let raw = tree
            .property(&path, "function-enable_core")
            .filter(|p| !p.placeholder && p.value.len() == 12)
            .ok_or("assigned CPU has no complete original enable_core function")?;
        let cells = raw.value.as_chunks::<4>().0;
        let function = Function {
            phandle: u32::from_le_bytes(cells[0]),
            selector: u32::from_le_bytes(cells[1]),
            argument: u32::from_le_bytes(cells[2]),
        };
        if function.phandle == 0
            || function.phandle != pmgr_phandle
            || function.selector != 0x436f7265
            || !function.argument.is_power_of_two()
        {
            return Err("assigned CPU has an empty source start protocol".into());
        }
        joins.push(Join {
            plan: plan.identity(),
            logical: pe.logical,
            worker: pe.host.worker,
            apic: pe.host.apic,
            reg: pe.reg,
            cluster: pe.cluster,
            cache: pe.cache,
            interrupt: pe.interrupt,
            error_interrupt_parent: parent,
            error_interrupt: word(tree, &path, "interrupts")?,
            start: pe.start,
            enable_core: function,
            core_power: pe.core_power,
            cluster_power: pe.cluster_power,
            cpu_impl: pe.cpu_impl,
            acc_impl: pe.acc_impl,
            cpm_impl: pe.cpm_impl,
        });
    }
    let mut projected = tree.clone();
    let receipt = Projection::prepare(&plan, &projected, source)
        .and_then(|projection| projection.apply(&mut projected))
        .map_err(|e| format!("assigned firmware topology: {e}"))?;
    profile.processors = plan.pes().iter().map(|pe| pe.identity).collect();
    plan.revalidate()
        .map_err(|e| format!("assigned topology became stale: {e:?}"))?;
    Ok(Prepared {
        plan,
        tree: projected,
        profile,
        receipt,
        joins,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::cell::Cell;
    use sha2::Digest;
    use stela_crypto::Sha256;
    use stela_loader::apple_device_tree::Node;
    use {
        stela_contracts::Chip, stela_contracts::caches::Cache, stela_contracts::caches::Caches,
        stela_contracts::identity::Identity, stela_soc_data::board::assigned::CacheId,
        stela_soc_data::board::assigned::Capacity, stela_soc_data::board::assigned::CapacityKind,
        stela_soc_data::board::assigned::ClusterId, stela_soc_data::board::assigned::ClusterSlot,
        stela_soc_data::board::assigned::CoreKind, stela_soc_data::board::assigned::InterruptId,
        stela_soc_data::board::assigned::InterruptTarget, stela_soc_data::board::assigned::KindId,
        stela_soc_data::board::assigned::PeSlot, stela_soc_data::board::assigned::PowerResource,
        stela_soc_data::board::assigned::ResourceProfile,
        stela_soc_data::board::assigned::Resources, stela_soc_data::board::assigned::SharedCache,
        stela_soc_data::board::assigned::StartId, stela_soc_data::board::assigned::StartResource,
        stela_soc_data::pmgr::coverage::DomainId,
    };

    fn cpuid_identity(maximum: u32, vendor: [u32; 3]) -> native::Cpuid {
        native::Cpuid {
            leaf: 0,
            eax: maximum,
            ebx: vendor[0],
            edx: vendor[1],
            ecx: vendor[2],
            ..Default::default()
        }
    }

    #[test]
    fn actual_bsp_collector_retains_maxima_and_zero_extended_apic_identity() {
        use stela_compiler::TargetCpu;
        let mut queries = Vec::new();
        let snapshot = current_identity(|leaf, subleaf| {
            queries.push((leaf, subleaf));
            match (leaf, subleaf) {
                (0, 0) => cpuid_identity(0x1f, TargetCpu::INTEL_VENDOR),
                (0x8000_0000, 0) => native::Cpuid {
                    leaf,
                    eax: 0x8000_0001,
                    ..Default::default()
                },
                (1, 0) => native::Cpuid {
                    leaf,
                    ebx: 0x7b << 24,
                    ..Default::default()
                },
                (0xb, 0) | (0x1f, 0) => native::Cpuid {
                    leaf,
                    ebx: 2,
                    ecx: 1 << 8,
                    edx: if leaf == 0x1f { 0 } else { 0x1234 },
                    ..Default::default()
                },
                (0x8000_0001, 0) => native::Cpuid {
                    leaf,
                    ..Default::default()
                },
                _ => panic!("unsupported CPUID query {leaf:#x}/{subleaf}"),
            }
        });
        assert_eq!(snapshot.get(0, 0).unwrap().eax, 0x1f);
        assert_eq!(snapshot.get(0x8000_0000, 0).unwrap().eax, 0x8000_0001);
        assert_eq!(snapshot.apic_id(), Some(0));
        assert_eq!(
            queries,
            vec![
                (0, 0),
                (0x8000_0000, 0),
                (1, 0),
                (0xb, 0),
                (0x1f, 0),
                (0x8000_0001, 0)
            ]
        );
        let mut deficient = snapshot;
        deficient.records[0].leaf = 2;
        assert_eq!(deficient.apic_id(), None); // decoder remains strict
    }

    #[test]
    fn actual_bsp_collector_does_not_probe_beyond_either_observed_maximum() {
        use stela_compiler::TargetCpu;
        for vendor in [TargetCpu::INTEL_VENDOR, TargetCpu::AMD_VENDOR] {
            let mut queries = Vec::new();
            let snapshot = current_identity(|leaf, subleaf| {
                queries.push((leaf, subleaf));
                match (leaf, subleaf) {
                    (0, 0) => cpuid_identity(1, vendor),
                    (0x8000_0000, 0) => native::Cpuid {
                        leaf,
                        eax: 0x8000_0000,
                        ..Default::default()
                    },
                    (1, 0) => native::Cpuid {
                        leaf,
                        ebx: 0x7b << 24,
                        ..Default::default()
                    },
                    _ => panic!("unsupported CPUID query {leaf:#x}/{subleaf}"),
                }
            });
            assert_eq!(snapshot.apic_id(), Some(0x7b));
            assert_eq!(queries, vec![(0, 0), (0x8000_0000, 0), (1, 0)]);
            assert_eq!(snapshot.count, 3);
        }
    }

    #[test]
    fn actual_bsp_collector_keeps_amd_full_width_identity_and_vendor_gate() {
        use stela_compiler::TargetCpu;
        for vendor in [TargetCpu::AMD_VENDOR, TargetCpu::INTEL_VENDOR, [0; 3]] {
            let snapshot = current_identity(|leaf, subleaf| match (leaf, subleaf) {
                (0, 0) => cpuid_identity(1, vendor),
                (0x8000_0000, 0) => native::Cpuid {
                    leaf,
                    eax: 0x8000_001e,
                    ..Default::default()
                },
                (1, 0) => native::Cpuid {
                    leaf,
                    ebx: 0x7b << 24,
                    ..Default::default()
                },
                (0x8000_0001, 0) => native::Cpuid {
                    leaf,
                    ecx: 1 << 22,
                    ..Default::default()
                },
                (0x8000_001e, 0) => native::Cpuid {
                    leaf,
                    eax: 0x1234_5678,
                    ..Default::default()
                },
                _ => panic!("unsupported CPUID query {leaf:#x}/{subleaf}"),
            });
            assert_eq!(
                snapshot.apic_id(),
                Some(if vendor == TargetCpu::AMD_VENDOR {
                    0x1234_5678
                } else {
                    0x7b
                })
            );
            if vendor == TargetCpu::AMD_VENDOR {
                let mut deficient = snapshot;
                deficient.records[1].leaf = 0x8000_0002;
                assert_eq!(deficient.apic_id(), None); // no guessed legacy fallback
            }
        }
    }

    struct Inventory {
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
                profile: ResourceProfile {
                    chip: Chip::AppleM1,
                    soc: 0x6000,
                    board: 8,
                    input_set_sha256: [2; 32],
                    adapted_set_sha256: None,
                },
                register_granule: 0x4000,
                provenance: "synthetic owner; no Apple hardware authority",
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
    fn domain(device: u16) -> DomainId {
        DomainId { die: 0, device }
    }
    fn range(base: u64) -> RegisterRange {
        RegisterRange {
            base,
            bytes: 0x9008,
        }
    }
    fn capture() -> alloc::boxed::Box<Capture> {
        let mut capture = Capture::boxed(2).unwrap();
        capture.processor_count = 2;
        capture.core_count = 2;
        capture.physical_count = 2;
        capture.enabled_count = 2;
        for index in 0..2 {
            capture.processors[index] = native::Processor {
                processor_number: index as u32 + 7,
                apic_id: 42 + index as u64 * 2,
                flags: native::ENABLED | native::HEALTHY | if index == 0 { native::BSP } else { 0 },
                topology_version: 1,
                location: native::Location {
                    package: 3,
                    core: index as u32 + 8,
                    ..Default::default()
                },
                thread: 0,
            };
            capture.selected[index] = index as u32;
            capture.snapshots[index] = native::Snapshot::default();
            capture.snapshots[index].count = 2;
            capture.snapshots[index].records[0] = native::Cpuid {
                leaf: 1,
                ebx: (42 + index as u32 * 2) << 24,
                ..Default::default()
            };
            capture.snapshots[index].records[1] = native::Cpuid {
                leaf: 0,
                eax: 1,
                ..Default::default()
            };
        }
        capture
    }
    fn fixture() -> (DeviceTree, Inventory, Vec<NodeBinding<'static>>, CpuProfile) {
        let cache = Cache {
            bytes: 4 << 20,
            ways: 16,
            line: 128,
        };
        let capacities = [
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
            maximum: Some(2),
            provenance: "explicit synthetic capacity",
        })
        .collect();
        let mut inventory = Inventory {
            revision: Cell::new(1),
            capacities,
            kinds: vec![CoreKind {
                id: KindId(8),
                cluster_type: b'E',
                midr: 0x611f0220,
                aff2: 0,
                clock: None,
                instruction: cache,
                data: cache,
            }],
            slots: vec![],
            clusters: vec![ClusterSlot {
                id: ClusterId(3),
                aff1: 0,
                firmware_id: 0,
                die: 0,
                die_cluster: 0,
                cache: Some(CacheId(9)),
                power: Some(domain(100)),
                acc_impl: Some(range(0x210000000)),
                cpm_impl: Some(range(0x210010000)),
            }],
            caches: vec![SharedCache {
                id: CacheId(9),
                cluster: ClusterId(3),
                geometry: cache,
            }],
            interrupts: vec![],
            starts: vec![],
            powers: vec![PowerResource {
                id: domain(100),
                cores: vec![],
                clusters: vec![ClusterId(3)],
            }],
        };
        let mut root = Node::named("device-tree").unwrap();
        let mut cpus = Node::named("cpus").unwrap();
        cpus.set_property("#address-cells", 1u32.to_le_bytes().to_vec())
            .unwrap();
        cpus.set_property("#size-cells", 0u32.to_le_bytes().to_vec())
            .unwrap();
        let mut bindings = vec![];
        let mut identities = vec![];
        for (index, name) in ["cpu-first", "cpu-second"].into_iter().enumerate() {
            let reg = index as u32;
            let slot = GuestSlotId(90 + index as u32 * 17);
            let id = domain(index as u16 + 200);
            let irq = InterruptId(index as u32 + 600);
            let start = StartId(index as u32 + 700);
            let implementation = range(0x210020000 + index as u64 * 0x10000);
            inventory.slots.push(PeSlot {
                id: slot,
                reg,
                kind: Some(KindId(8)),
                cluster: ClusterId(3),
                cluster_core: reg,
                interrupt: Some(irq),
                start: Some(start),
                power: Some(id),
                cpu_impl: Some(implementation),
            });
            inventory.interrupts.push(InterruptTarget { id: irq, reg });
            inventory.starts.push(StartResource { id: start, reg });
            inventory.powers.push(PowerResource {
                id,
                cores: vec![slot],
                clusters: vec![],
            });
            let mut node = Node::named(name).unwrap();
            for (key, value) in [
                ("reg", reg),
                ("cpu-id", reg + 30),
                ("AAPL,phandle", reg + 50),
                ("cluster-id", 0),
                ("die-id", 0),
                ("die-cluster-id", 0),
                ("cluster-core-id", reg),
                ("l2-cache-size", cache.bytes),
                ("interrupt-parent", 0x99),
                ("interrupts", reg + 110),
            ] {
                node.set_property(key, value.to_le_bytes().to_vec())
                    .unwrap();
            }
            for (key, value) in [
                ("state", &b"waiting\0"[..]),
                ("device_type", &b"cpu\0"[..]),
                ("compatible", &b"synthetic-cpu\0"[..]),
                ("cluster-type", &b"E\0"[..]),
            ] {
                node.set_property(key, value.to_vec()).unwrap();
            }
            for (name, range) in [
                ("cpu-impl-reg", implementation),
                ("acc-impl-reg", inventory.clusters[0].acc_impl.unwrap()),
                ("cpm-impl-reg", inventory.clusters[0].cpm_impl.unwrap()),
            ] {
                node.set_property(
                    name,
                    [range.base, range.bytes]
                        .into_iter()
                        .flat_map(u64::to_le_bytes)
                        .collect(),
                )
                .unwrap();
            }
            node.set_property(
                "function-enable_core",
                [0x88u32, 0x436f7265, 1 << index]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            )
            .unwrap();
            cpus.children.push(node);
            bindings.push(NodeBinding {
                slot,
                name,
                midr: 0x611f0220,
                cache: CacheId(9),
                interrupt: irq,
                start,
                core_power: id,
                cluster_power: domain(100),
            });
            identities.push(Identity {
                midr: 0x611f0220,
                mpidr: 0x80000000 | u64::from(reg),
                clock: None,
                caches: Some(Caches::split_unified(cache, cache, cache).unwrap()),
            });
        }
        let mut io = Node::named("arm-io").unwrap();
        let mut aic = Node::named("aic").unwrap();
        aic.set_property("#main-cpus", 2u32.to_le_bytes().to_vec())
            .unwrap();
        aic.set_property("AAPL,phandle", 0x99u32.to_le_bytes().to_vec())
            .unwrap();
        let mut pmgr = Node::named("pmgr").unwrap();
        pmgr.set_property("AAPL,phandle", 0x88u32.to_le_bytes().to_vec())
            .unwrap();
        pmgr.set_property(
            "clusters",
            [2u32, 4, 4]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        )
        .unwrap();
        io.children.extend([aic, pmgr]);
        root.children.extend([cpus, io]);
        (
            DeviceTree { root },
            inventory,
            bindings,
            CpuProfile {
                name: "synthetic source",
                chip: Chip::AppleM1,
                counter_frequency: 24000000,
                fixed: vec![],
                processors: identities,
            },
        )
    }
    fn source<'a>(tree: &DeviceTree, nodes: &'a [NodeBinding<'a>]) -> SourceBindings<'a> {
        SourceBindings {
            source_set_sha256: [2; 32],
            tree_sha256: Sha256::digest(tree.serialize()).into(),
            nodes,
            counts: &COUNT_FIELDS,
            references: &[],
            cpu_ids: CpuIdRecipe::Preserve,
        }
    }
    fn captured_live_tree(mut tree: DeviceTree, command: &str) -> LiveTree {
        use crate::boot_live_tree::Ram;
        use stela_formats::boot_bundle::LoadedRegion;
        use stela_loader::boot_args::{self, BootArgs, Video};
        const ARGS: u64 = 0x1000;
        const TREE: u64 = 0x10000;
        const BYTES: usize = 1 << 20;
        struct Input(Vec<u8>);
        impl Ram for Input {
            fn read(&mut self, pa: u64, bytes: &mut [u8]) -> bool {
                let Some(range) = usize::try_from(pa)
                    .ok()
                    .and_then(|start| start.checked_add(bytes.len()).map(|end| start..end))
                    .and_then(|range| self.0.get(range))
                else {
                    return false;
                };
                bytes.copy_from_slice(range);
                true
            }
            fn write(&mut self, _: u64, _: &[u8]) -> bool {
                panic!("capture must not write")
            }
            fn fence(&mut self) {
                panic!("capture must not publish")
            }
        }
        tree.set_property(
            "/chosen/memory-map",
            "DeviceTree",
            [TREE.to_le_bytes(), (BYTES as u64 - TREE).to_le_bytes()].concat(),
        )
        .unwrap();
        let bytes = tree.serialize();
        let args = boot_args::encode(&BootArgs {
            revision: boot_args::REVISION,
            version: boot_args::VERSION,
            virt_base: 0xfffffe0000000000,
            phys_base: 0,
            mem_size: BYTES as u64,
            top_of_kernel_data: BYTES as u64,
            video: Video::default(),
            machine_type: 0,
            device_tree: 0xfffffe0000000000 + TREE,
            device_tree_length: bytes.len() as u32,
            command_line: command.into(),
            boot_flags: 0,
            mem_size_actual: BYTES as u64,
        })
        .unwrap();
        let mut input = Input(vec![0; BYTES]);
        input.0[ARGS as usize..ARGS as usize + args.len()].copy_from_slice(&args);
        input.0[TREE as usize..TREE as usize + bytes.len()].copy_from_slice(&bytes);
        let regions = [
            LoadedRegion {
                name: "DeviceTree".into(),
                guest_pa: TREE,
                bytes: bytes.len() as u64,
                memory_bytes: BYTES as u64 - TREE,
            },
            LoadedRegion {
                name: "BootArgs".into(),
                guest_pa: ARGS,
                bytes: args.len() as u64,
                memory_bytes: 4096,
            },
        ];
        LiveTree::capture(&mut input, &regions, ARGS).unwrap()
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_CPU_DT_DIR"]
    fn original_t8112_adapter_joins_dense_driver_ids_to_physical_first_p_resources() {
        use stela_soc_data::board;
        let file = std::path::PathBuf::from(std::env::var("STELA_TEST_CPU_DT_DIR").unwrap())
            .join("DeviceTree.j473ap.adt");
        let original = std::fs::read(file).unwrap();
        assert_eq!(
            stela_formats::sha256(&original),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let mut tree = DeviceTree::parse(&original).unwrap();
        for (key, value) in [("chip-id", 0x8112u32), ("board-id", 0x24)] {
            tree.set_property("/chosen", key, value.to_le_bytes().to_vec())
                .unwrap();
        }
        for cpu in &mut tree.node_mut("/cpus").unwrap().children {
            let running = cpu.name() == Some("cpu4");
            cpu.set_property(
                "state",
                if running {
                    b"running\0".to_vec()
                } else {
                    b"waiting\0".to_vec()
                },
            )
            .unwrap();
        }
        let identity = SourceIdentity {
            original_tree_sha256: Sha256::digest(&original).into(),
            profile: ResourceProfile {
                chip: Chip::AppleM2,
                soc: 0x8112,
                board: 0x24,
                input_set_sha256: [7; 32],
                adapted_set_sha256: None,
            },
        };
        let cpus = tree
            .node("/cpus")
            .unwrap()
            .children
            .iter()
            .map(|cpu| board::Processor {
                reg: cpu.property("reg").unwrap().as_u32().unwrap(),
                cluster_type: cpu.property("cluster-type").unwrap().value[0],
                l2_bytes: cpu.property("l2-cache-size").unwrap().as_u32(),
            })
            .collect::<Vec<_>>();
        let actual = board::cpus(0x8112, "Apple M2", &cpus).unwrap();
        let profile = CpuProfile {
            name: "original component fixture",
            chip: actual.chip,
            processors: actual.processors,
            counter_frequency: 24_000_000,
            fixed: vec![],
        };
        let live = captured_live_tree(tree.clone(), "-v");
        let source = Source::t8112(&original, &live, identity, 0x100).unwrap();
        let capture = capture();
        let roster = BspRoster::observed(&capture, 0, 42).unwrap();
        let prepared = source.prepare(&roster, profile.clone()).unwrap();
        assert_eq!(prepared.plan.pes().len(), 1);
        assert_eq!(prepared.profile.processors.len(), 1);
        let join = prepared.join(0x100).unwrap();
        assert_eq!((join.logical, join.worker, join.apic), (0, 0, 42));
        assert_eq!(
            (join.enable_core.argument, join.error_interrupt),
            (0x10, 0x66)
        );
        assert_eq!((join.core_power.device, join.cluster_power.device), (5, 10));
        assert_eq!(word(&prepared.tree, "/cpus/cpu4", "cpu-id"), Ok(0));
        assert_eq!(word(&prepared.tree, "/cpus/cpu4", "reg"), Ok(0x100));
        assert_eq!(word(&prepared.tree, "/cpus", "max_cpus"), Ok(1));
        assert_eq!(prepared.receipt.cpu_ids[0].original_id, 4);
        assert_eq!(
            prepared.tree.node("/arm-io/pmgr"),
            tree.node("/arm-io/pmgr")
        );
        assert_eq!(source.resources.source(), original);
        // Construction fixture only: exercise the actual selected-source to
        // loader cache-interval/watchdog/profile projection boundary at every
        // admitted cardinality. This does not create an actual AP executor.
        struct Roster(Vec<AssignedCore>);
        impl RetainedRoster for Roster {
            fn revision(&self) -> u64 {
                1
            }
            fn cores(&self) -> &[AssignedCore] {
                &self.0
            }
        }
        for count in 1..=8 {
            let roster = Roster(
                (0..count)
                    .map(|worker| AssignedCore {
                        worker,
                        package: 0,
                        core: worker as u32,
                        apic: 42 + worker as u32,
                        started: true,
                    })
                    .collect(),
            );
            let selected =
                Source::t8112_assigned(&original, &live, identity, 0x100, count).unwrap();
            let prepared = selected.prepare(&roster, profile.clone()).unwrap();
            let board = board::board(&prepared.tree.serialize()).unwrap();
            assert_eq!(board.boot_processor.unwrap().cpu, 0);
            assert_eq!(board.cpus.processors, prepared.profile.processors);
            assert_eq!(prepared.worker_bindings().unwrap().len(), count);
            assert_eq!(
                prepared
                    .tree
                    .node("/cpus")
                    .unwrap()
                    .children
                    .iter()
                    .map(|node| node.property("reg").unwrap().as_u32().unwrap())
                    .collect::<Vec<_>>(),
                [0x100, 0x101, 0x102, 0x103, 0, 1, 2, 3][..count]
            );
            assert_eq!(prepared.receipt.cpu_ids.len(), count);
        }
        let override_live = captured_live_tree(tree, "-v acc-harvesting=0");
        assert!(
            Source::t8112(&original, &override_live, identity, 0x100)
                .err()
                .unwrap()
                .contains("boot-argument override")
        );
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_ASSIGNED_DT, STELA_TEST_ASSIGNED_PREPARED_DT"]
    fn original_mode1_factory_projects_actual_live_tree_without_public_pmgr_admission() {
        use {stela_contracts::adt, stela_soc_data::board};
        let original = std::fs::read(std::env::var("STELA_TEST_ASSIGNED_DT").unwrap()).unwrap();
        let raw = std::fs::read(std::env::var("STELA_TEST_ASSIGNED_PREPARED_DT").unwrap()).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&original)),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&raw)),
            "9acc3e66694a2821356388ee32132064f56aef06c93bcff3d1070721b1111780"
        );
        let identity = SourceIdentity {
            original_tree_sha256: Sha256::digest(&original).into(),
            profile: board::assigned::ResourceProfile {
                chip: Chip::AppleM1,
                soc: 0x6000,
                board: 8,
                input_set_sha256: [3; 32],
                adapted_set_sha256: None,
            },
        };
        // Stand in only for unrelated live runtime patch bytes. Projection
        // happens after those patches and binds THIS tree, not the template.
        let mut live = DeviceTree::parse(&raw).unwrap();
        live.set_property("/chosen", "random-seed", vec![0x31; 64])
            .unwrap();
        let live_bytes = live.serialize();
        let source = Source::t6000(&original, &live_bytes, identity, 0).unwrap();
        let pmgr = source.tree.node("/arm-io/pmgr").unwrap().clone();
        assert!(pmgr.property("compatible").is_none());
        let cpus = source
            .tree
            .node("/cpus")
            .unwrap()
            .children
            .iter()
            .map(|cpu| board::Processor {
                reg: cpu.property("reg").unwrap().as_u32().unwrap(),
                cluster_type: cpu.property("cluster-type").unwrap().value[0],
                l2_bytes: cpu.property("l2-cache-size").unwrap().as_u32(),
            })
            .collect::<Vec<_>>();
        let soc_name = &source
            .tree
            .property("/product", "product-soc-name")
            .unwrap()
            .value;
        let soc_name = core::str::from_utf8(soc_name)
            .unwrap()
            .trim_end_matches('\0');
        let actual = board::cpus(0x6000, soc_name, &cpus).unwrap();
        let profile = CpuProfile {
            name: "source topology regression",
            chip: actual.chip,
            processors: actual.processors,
            counter_frequency: 24_000_000,
            fixed: vec![],
        };
        let capture = capture();
        let roster = BspRoster::observed(&capture, 37, 42).unwrap();
        let prepared = source.prepare(&roster, profile).unwrap();
        assert_eq!(prepared.plan.pes().len(), 1);
        assert_eq!(prepared.profile.processors.len(), 1);
        assert_eq!(prepared.tree.node("/cpus").unwrap().children.len(), 1);
        assert_eq!(prepared.tree.node("/arm-io/pmgr"), Some(&pmgr));
        assert_eq!(
            prepared.tree.property("/chosen", "random-seed"),
            live.property("/chosen", "random-seed")
        );
        for field in &COUNT_FIELDS {
            assert_eq!(
                word(&prepared.tree, field.path, field.property),
                Ok(if field.property == "p-core-count" {
                    0
                } else {
                    1
                })
            );
        }
        assert_eq!(word(&prepared.tree, "/cpus/cpu0", "AAPL,phandle"), Ok(26));
        let join = prepared.join(0).unwrap();
        assert_eq!(
            (join.worker, join.apic, join.error_interrupt),
            (37, 42, 110)
        );
        assert_eq!(
            (join.enable_core.phandle, join.enable_core.argument),
            (0x99, 1)
        );
        assert_eq!((join.core_power.device, join.cluster_power.device), (1, 11));
        assert!(prepared.join(1).is_err());
        assert!(
            prepared
                .tree
                .property("/cpus", "cpu-cluster-count")
                .is_none()
        );
        assert_eq!(source.resources.graph().domains.len(), 355);
        assert_eq!(source.resources.graph().registers.len(), 196);
        let original_root = adt::Node::root(&original).unwrap();
        assert_eq!(
            original_root.child("chosen").unwrap().property("chip-id"),
            Some(&[0; 4][..])
        );
        let mut changed = live.clone();
        changed
            .set_property("/cpus/cpu0", "interrupts", 111u32.to_le_bytes().to_vec())
            .unwrap();
        assert!(Source::t6000(&original, &changed.serialize(), identity, 0).is_err());
        changed = live.clone();
        changed
            .set_property(
                "/arm-io/pmgr",
                "acc-harvesting",
                2u32.to_le_bytes().to_vec(),
            )
            .unwrap();
        assert!(Source::t6000(&original, &changed.serialize(), identity, 0).is_err());
        changed = live.clone();
        changed
            .set_property("/arm-io/pmgr", "power-gates", 197u32.to_le_bytes().to_vec())
            .unwrap();
        assert!(Source::t6000(&original, &changed.serialize(), identity, 0).is_err());
        changed = live.clone();
        changed
            .set_property("/cpus/cpu1", "AAPL,phandle", 26u32.to_le_bytes().to_vec())
            .unwrap();
        assert!(Source::t6000(&original, &changed.serialize(), identity, 0).is_err());
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_ASSIGNED_DT, STELA_TEST_ASSIGNED_PREPARED_DT"]
    fn original_mode1_keeps_discovery_order_with_nonzero_logical_boot_pe() {
        use stela_soc_data::board;
        let original = std::fs::read(std::env::var("STELA_TEST_ASSIGNED_DT").unwrap()).unwrap();
        let raw = std::fs::read(std::env::var("STELA_TEST_ASSIGNED_PREPARED_DT").unwrap()).unwrap();
        let tree = DeviceTree::parse(&raw).unwrap();
        let board = board::board(&raw).unwrap();
        let boot = board.boot_processor.as_ref().unwrap();
        assert_ne!(boot.cpu, 0);
        assert!(stela_runtime::machine::apple::AppleDevices::native_pmp_system_endpoint_refusal(
            &board,
        ).unwrap().unwrap().contains("T8112"));
        let regs = tree
            .node("/cpus")
            .unwrap()
            .children
            .iter()
            .map(|node| node.property("reg").unwrap().as_u32().unwrap())
            .collect::<Vec<_>>();
        let profile = CpuProfile {
            name: "original component projection fixture; no native AP authority",
            chip: board.cpus.chip,
            processors: board.cpus.processors.clone(),
            counter_frequency: 24_000_000,
            fixed: vec![],
        };
        let identity = SourceIdentity {
            original_tree_sha256: Sha256::digest(&original).into(),
            profile: board::assigned::ResourceProfile {
                chip: profile.chip,
                soc: word(&tree, "/chosen", "chip-id").unwrap(),
                board: word(&tree, "/chosen", "board-id").unwrap(),
                input_set_sha256: Sha256::digest(&raw).into(),
                adapted_set_sha256: None,
            },
        };
        struct Roster(Vec<AssignedCore>);
        impl RetainedRoster for Roster {
            fn revision(&self) -> u64 {
                1
            }
            fn cores(&self) -> &[AssignedCore] {
                &self.0
            }
        }
        // Keep a member of every source complex. Shorter selections need the
        // independently reviewed constructor skip rule, not an inferred cap.
        let minimum = regs
            .iter()
            .enumerate()
            .filter(|(i, reg)| !regs[..*i].iter().any(|earlier| earlier >> 8 == **reg >> 8))
            .map(|(i, _)| i + 1)
            .max()
            .unwrap();
        let live = captured_live_tree(tree.clone(), "-v");
        for count in minimum..=regs.len() {
            let roster = Roster(
                (0..count)
                    .map(|worker| AssignedCore {
                        worker,
                        package: 0,
                        core: worker as u32,
                        apic: worker as u32 + 42,
                        started: true,
                    })
                    .collect(),
            );
            let selected =
                Source::t6000_assigned(&original, &live, identity, boot.affinity, count).unwrap();
            let prepared = selected.prepare(&roster, profile.clone()).unwrap();
            let projected = board::board(&prepared.tree.serialize()).unwrap();
            assert_eq!(projected.boot_processor.unwrap().cpu, boot.cpu);
            assert_eq!(projected.cpus.processors, prepared.profile.processors);
            assert_eq!(
                prepared.tree.node("/arm-io/pmgr"),
                tree.node("/arm-io/pmgr")
            );
            assert_eq!(
                prepared
                    .tree
                    .node("/cpus")
                    .unwrap()
                    .children
                    .iter()
                    .map(|node| node.property("reg").unwrap().as_u32().unwrap())
                    .collect::<Vec<_>>(),
                regs[..count]
            );
            for (logical, &reg) in regs[..count].iter().enumerate() {
                let join = prepared.join(reg).unwrap();
                assert_eq!(join.logical, logical);
                let name = selected
                    .resources
                    .name_for(selected.resources.resources().slots[logical].id)
                    .unwrap();
                let path = format!("/cpus/{name}");
                assert_eq!(
                    prepared.tree.property(&path, "cpu-id"),
                    tree.property(&path, "cpu-id")
                );
            }
            assert_eq!(prepared.join(boot.affinity).unwrap().worker, 0);
            let bindings = prepared.worker_bindings().unwrap();
            assert_eq!(bindings.iter().filter(|b| b.worker.0 == 0).count(), 1);
            assert_eq!(
                bindings.iter().find(|b| b.worker.0 == 0).unwrap().pe,
                boot.cpu
            );
        }
    }
    #[test]
    fn actual_selected_bsp_only_does_not_start_captured_aps() {
        let capture = capture();
        let roster = BspRoster::observed(&capture, 37, 42).unwrap();
        assert_eq!(roster.cores().len(), 1);
        assert_eq!(roster.source().processor_number, 7);
        assert_eq!(
            roster.cores()[0],
            AssignedCore {
                worker: 37,
                package: 3,
                core: 8,
                apic: 42,
                started: true
            }
        );
        assert!(BspRoster::observed(&capture, 37, 44).is_err());
        let mut altered = self::capture();
        altered.selected[0] = 1;
        assert!(BspRoster::observed(&altered, 37, 42).is_err());
    }
    #[test]
    fn one_plan_projects_the_source_slot_profile_counts_and_exact_owner_joins() {
        let capture = capture();
        let roster = BspRoster::observed(&capture, 37, 42).unwrap();
        let (tree, owner, nodes, profile) = fixture();
        let original = tree.clone();
        let selected = nodes[1].slot;
        let prepared = prepare(
            &roster,
            &owner,
            selected,
            &tree,
            &source(&tree, &nodes),
            profile.clone(),
        )
        .unwrap();
        assert_eq!(tree, original);
        assert_eq!(prepared.plan.pes().len(), 1);
        assert_eq!(prepared.profile.processors, [profile.processors[1]]);
        assert_eq!(prepared.receipt.plan, prepared.plan.identity());
        assert_eq!(prepared.tree.node("/cpus").unwrap().children.len(), 1);
        assert!(prepared.tree.node("/cpus/cpu-first").is_none());
        assert_eq!(word(&prepared.tree, "/cpus/cpu-second", "cpu-id"), Ok(31));
        for field in &COUNT_FIELDS {
            assert_eq!(
                word(&prepared.tree, field.path, field.property),
                Ok(if field.property == "p-core-count" {
                    0
                } else {
                    1
                })
            );
        }
        assert_eq!(
            prepared.tree.property("/arm-io/pmgr", "clusters"),
            tree.property("/arm-io/pmgr", "clusters")
        );
        assert!(
            prepared
                .tree
                .property("/cpus", "cpu-cluster-count")
                .is_none()
        );
        assert!(prepared.join(0).is_err());
        let join = prepared.join(1).unwrap();
        assert_eq!(join.plan, prepared.plan.identity());
        assert_eq!(join.reg, 1);
        assert_eq!(
            (join.worker, join.apic, join.error_interrupt),
            (37, 42, 111)
        );
        assert_eq!(
            (join.start, join.enable_core.argument, join.core_power),
            (StartId(701), 2, domain(201))
        );
        assert_ne!(join.enable_core.argument, u32::from(join.core_power.device));
        assert_eq!(join.cpu_impl, owner.slots[1].cpu_impl.unwrap());
        owner.revision.set(2);
        assert!(prepared.plan.revalidate().is_err());
        assert!(prepared.join(1).is_err());
    }
    #[test]
    fn missing_owner_capacity_source_counts_or_profile_refuse_before_publication() {
        let capture = capture();
        let roster = BspRoster::observed(&capture, 37, 42).unwrap();
        let (tree, mut owner, nodes, profile) = fixture();
        let original = tree.clone();
        owner.capacities[0].maximum = None;
        assert!(
            prepare(
                &roster,
                &owner,
                nodes[0].slot,
                &tree,
                &source(&tree, &nodes),
                profile.clone()
            )
            .err()
            .unwrap()
            .contains("MissingCapacity")
        );
        owner.capacities[0].maximum = Some(2);
        owner.starts.clear();
        assert!(
            prepare(
                &roster,
                &owner,
                nodes[0].slot,
                &tree,
                &source(&tree, &nodes),
                profile.clone()
            )
            .is_err()
        );
        assert_eq!(tree, original);
        let (tree, owner, nodes, mut profile) = fixture();
        profile.processors[0].midr ^= 1;
        assert!(
            prepare(
                &roster,
                &owner,
                nodes[0].slot,
                &tree,
                &source(&tree, &nodes),
                profile
            )
            .err()
            .unwrap()
            .contains("source board profile")
        );
        let (tree, owner, nodes, profile) = fixture();
        let mut s = source(&tree, &nodes);
        s.counts = &COUNT_FIELDS[..3];
        assert!(
            prepare(&roster, &owner, nodes[0].slot, &tree, &s, profile.clone())
                .err()
                .unwrap()
                .contains("#main-cpus")
        );
        let mut counts = COUNT_FIELDS.to_vec();
        counts.push(CountField {
            path: "/cpus",
            property: "cpu-cluster-count",
            count: Count::Clusters,
        });
        s.counts = &counts;
        assert!(
            prepare(&roster, &owner, nodes[0].slot, &tree, &s, profile)
                .err()
                .unwrap()
                .contains("cannot add")
        );
    }
}
