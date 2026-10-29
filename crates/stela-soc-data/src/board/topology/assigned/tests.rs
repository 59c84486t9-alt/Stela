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
fn above_capacity_names_the_consumer_and_never_truncates() {
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
fn cluster_mask_limits_do_not_alias() {
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
fn same_plan_keeps_roster_and_resource_revision_without_native_permission() {
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
        // claims that these fields check any unobserved silicon.
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
