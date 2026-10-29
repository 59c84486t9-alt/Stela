//! Physical CPU-domain identities projected through one assigned Plan.
use super::*;
use stela_contracts::identity::Identity;
use stela_contracts::processor::ProcessorTarget;
use stela_engine::machine::engine::ProcessorChange;
use stela_engine::machine::engine::Processors;
use stela_soc_data::board::ProcessorAssociation;
use stela_soc_data::board::assigned::PlanIdentity;
use stela_soc_data::board::assigned::PlannedPe;
use {crate::platform::apple::pmgr::DomainTransition, stela_soc_data::pmgr::coverage::DomainId};

struct Domain {
    identity: DomainId,
    address: u64,
    target: Option<ProcessorTarget>,
    state: DomainState,
}

pub(in crate::machine::apple) struct AssignedPower {
    plan: PlanIdentity,
    domains: Vec<Domain>,
}

pub(super) struct Request {
    plan: PlanIdentity,
    domain: usize,
    pub transition: DomainTransition,
    pub value: u32,
    pub change: Option<ProcessorChange>,
}

fn lifecycle(state: DomainState) -> LifecycleState {
    LifecycleState {
        powered: state.power != POWER_GATED,
        clocked: state.power == ACTIVE,
        quiesced: state.disabled,
        reset: state.reset,
        // CPU supply loss/reset has no implemented kept-state contract.
        // This declares that limitation; it is not a sampled PMGR control bit.
        retention: false,
    }
}

impl AssignedPower {
    pub(super) fn prepare(
        plan: PlanIdentity,
        pes: &[PlannedPe],
        original_regs: &[u32],
        full_profile: &[Identity],
        associations: &[ProcessorAssociation],
        pmgr: &Pmgr,
    ) -> Result<Self, String> {
        if pes.is_empty() || original_regs.len() != full_profile.len() {
            return Err("CPU power source/assigned roster is incomplete".into());
        }
        for (index, reg) in original_regs.iter().enumerate() {
            if original_regs[..index].contains(reg) {
                return Err("CPU power source repeats a physical PE".into());
            }
        }
        let source_indices = pes
            .iter()
            .enumerate()
            .map(|(logical, pe)| {
                let source = original_regs
                    .iter()
                    .position(|&reg| reg == pe.reg)
                    .ok_or("assigned CPU power PE has no original physical node")?;
                if pe.logical != logical || full_profile[source] != pe.identity {
                    return Err("assigned CPU power identity differs from the original PE");
                }
                Ok(source)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut domains: Vec<Domain> = Vec::with_capacity(associations.len());
        let mut cores = alloc::vec![0; pes.len()];
        let mut complexes = alloc::vec![0; pes.len()];
        for association in associations {
            if domains.iter().any(|domain| {
                domain.identity == association.domain || domain.address == association.address
            }) {
                return Err("CPU power source repeats a domain identity or address".into());
            }
            let original_members = match &association.target {
                ProcessorTarget::Core { pe } => core::slice::from_ref(pe),
                ProcessorTarget::Cluster { members } => members.as_slice(),
            };
            if original_members.is_empty()
                || original_members
                    .iter()
                    .enumerate()
                    .any(|(i, &pe)| pe >= full_profile.len() || original_members[..i].contains(&pe))
            {
                return Err("CPU power source domain membership is incomplete".into());
            }
            let mut members = Vec::new();
            for (logical, &source) in source_indices.iter().enumerate() {
                if !original_members.contains(&source) {
                    continue;
                }
                let (expected, count) = match &association.target {
                    ProcessorTarget::Core { .. } => (pes[logical].core_power, &mut cores[logical]),
                    ProcessorTarget::Cluster { .. } => {
                        (pes[logical].cluster_power, &mut complexes[logical])
                    }
                };
                if association.domain != expected {
                    return Err("assigned CPU power domain differs from its source Plan".into());
                }
                *count += 1;
                members.push(logical);
            }
            let target = match &association.target {
                _ if members.is_empty() => None,
                ProcessorTarget::Core { .. } => Some(ProcessorTarget::Core { pe: members[0] }),
                ProcessorTarget::Cluster { .. } => Some(ProcessorTarget::Cluster { members }),
            };
            domains.push(Domain {
                identity: association.domain,
                address: association.address,
                target,
                state: pmgr
                    .domain_state(association.address)
                    .ok_or("CPU power domain has no actual placed PMGR state")?,
            });
        }
        if cores.iter().chain(&complexes).any(|&count| count != 1) {
            return Err("assigned CPU requires exactly one original core and complex owner".into());
        }
        let assigned = Self { plan, domains };
        // Purely validate the initial state against the existing CPU boundary.
        // In particular a supply-off/reset model state cannot be hidden
        // by substituting a fixture ACTIVE state before binding the Machine.
        Processors::new(pes.len())
            .and_then(|processors| {
                processors
                    .prepare_bindings(&assigned.bindings())
                    .map(|_| ())
            })
            .map_err(|e| format!("placed initial CPU lifecycle is unsupported: {e:?}"))?;
        Ok(assigned)
    }

    pub(super) fn bindings(&self) -> Vec<ProcessorBinding> {
        self.domains
            .iter()
            .filter_map(|domain| {
                Some(ProcessorBinding {
                    // Preserve the canonical physical domain identity without
                    // conflating a DeviceID/address, source PE or dense PE.
                    domain: u64::from(domain.identity.die) << 16
                        | u64::from(domain.identity.device),
                    target: domain.target.clone()?,
                    initial: lifecycle(domain.state),
                })
            })
            .collect()
    }

    pub(super) fn contains(&self, physical: u64) -> bool {
        self.domains.iter().any(|domain| domain.address == physical)
    }

    pub(super) fn preview(
        &self,
        pmgr: &Pmgr,
        physical: u64,
        value: u32,
    ) -> Result<Request, DeviceError> {
        let domain = self
            .domains
            .iter()
            .position(|d| d.address == physical)
            .expect("classified original CPU domain");
        let bound = &self.domains[domain];
        let transition = pmgr.preview(physical, value).map_err(|reason| {
            DeviceError::Refused(format!(
                "CPU PMGR {:?} at {physical:#x}: {reason}",
                bound.identity
            ))
        })?;
        if transition.before != bound.state {
            return Err(DeviceError::TransferRefused(
                "CPU PMGR model changed outside its actual processor transaction".into(),
            ));
        }
        if bound.target.is_none() && transition.before != transition.after {
            return Err(DeviceError::TransferRefused(format!(
                "CPU PMGR {:?} at {physical:#x} belongs only to unassigned physical PEs",
                bound.identity
            )));
        }
        Ok(Request {
            plan: self.plan.clone(),
            domain,
            transition,
            value,
            change: bound.target.as_ref().map(|_| ProcessorChange {
                domain: u64::from(bound.identity.die) << 16 | u64::from(bound.identity.device),
                state: lifecycle(transition.after),
            }),
        })
    }

    pub(super) fn committed(&mut self, request: &Request) {
        assert_eq!(self.plan, request.plan, "same retained assigned Plan");
        let domain = &mut self.domains[request.domain];
        assert_eq!(
            domain.state, request.transition.before,
            "exclusive CPU PMGR request"
        );
        domain.state = request.transition.after;
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use alloc::vec;
    use {
        stela_contracts::Chip, stela_contracts::caches::Cache, stela_soc_data::board::assigned::*,
    };

    pub const BASE: u64 = 0x1000;
    pub const CORE: u64 = BASE + 8;
    pub const COMPLEX: u64 = BASE + 16;
    pub struct Roster([AssignedCore; 1]);
    impl RetainedRoster for Roster {
        fn revision(&self) -> u64 {
            1
        }
        fn cores(&self) -> &[AssignedCore] {
            &self.0
        }
    }
    pub struct Inventory {
        capacities: Vec<Capacity>,
        kind: [CoreKind; 1],
        slot: [PeSlot; 1],
        cluster: [ClusterSlot; 1],
        cache: [SharedCache; 1],
        interrupt: [InterruptTarget; 1],
        start: [StartResource; 1],
        power: [PowerResource; 2],
    }
    impl RetainedResources for Inventory {
        fn revision(&self) -> u64 {
            1
        }
        fn resources(&self) -> Resources<'_> {
            Resources {
                profile: ResourceProfile {
                    chip: Chip::AppleM2,
                    soc: 0x8112,
                    board: 0x24,
                    input_set_sha256: [1; 32],
                    adapted_set_sha256: None,
                },
                register_granule: 0x4000,
                provenance: "synthetic projection fixture, no firmware/worker authority",
                capacities: &self.capacities,
                kinds: &self.kind,
                slots: &self.slot,
                clusters: &self.cluster,
                caches: &self.cache,
                interrupts: &self.interrupt,
                starts: &self.start,
                powers: &self.power,
            }
        }
    }
    fn id(device: u16) -> DomainId {
        DomainId { die: 0, device }
    }

    pub fn fixture() -> (Roster, Inventory) {
        let cache = Cache {
            bytes: 1 << 20,
            ways: 8,
            line: 128,
        };
        let range = |base| RegisterRange {
            base,
            bytes: 0x4000,
        };
        let inventory = Inventory {
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
            .map(|kind| Capacity {
                kind,
                maximum: Some(8),
                provenance: "synthetic fixture limit",
            })
            .into(),
            kind: [CoreKind {
                id: KindId(0),
                cluster_type: b'P',
                midr: 0x611f0320,
                aff2: 1,
                clock: None,
                instruction: cache,
                data: cache,
            }],
            slot: [PeSlot {
                id: GuestSlotId(4),
                reg: 0x100,
                kind: Some(KindId(0)),
                cluster: ClusterId(1),
                cluster_core: 0,
                interrupt: Some(InterruptId(0)),
                start: Some(StartId(0)),
                power: Some(id(12)),
                cpu_impl: Some(range(0x10000)),
            }],
            cluster: [ClusterSlot {
                id: ClusterId(1),
                aff1: 1,
                firmware_id: 1,
                die: 0,
                die_cluster: 1,
                cache: Some(CacheId(1)),
                power: Some(id(20)),
                acc_impl: Some(range(0x20000)),
                cpm_impl: Some(range(0x30000)),
            }],
            cache: [SharedCache {
                id: CacheId(1),
                cluster: ClusterId(1),
                geometry: cache,
            }],
            interrupt: [InterruptTarget {
                id: InterruptId(0),
                reg: 0x100,
            }],
            start: [StartResource {
                id: StartId(0),
                reg: 0x100,
            }],
            power: [
                PowerResource {
                    id: id(12),
                    cores: vec![GuestSlotId(4)],
                    clusters: vec![],
                },
                PowerResource {
                    id: id(20),
                    cores: vec![],
                    clusters: vec![ClusterId(1)],
                },
            ],
        };
        (
            Roster([AssignedCore {
                worker: 0,
                package: 0,
                core: 7,
                apic: 22,
                started: true,
            }]),
            inventory,
        )
    }
    pub fn plan<'a>(roster: &'a Roster, inventory: &'a Inventory) -> Plan<'a> {
        Plan::build(
            roster,
            inventory,
            &[Assignment {
                worker: 0,
                slot: GuestSlotId(4),
                boot: true,
            }],
        )
        .unwrap()
    }
    pub fn associations() -> Vec<ProcessorAssociation> {
        vec![
            ProcessorAssociation {
                domain: id(11),
                address: BASE,
                target: ProcessorTarget::Core { pe: 0 },
                evidence: "synthetic original core0",
            },
            ProcessorAssociation {
                domain: id(12),
                address: CORE,
                target: ProcessorTarget::Core { pe: 1 },
                evidence: "synthetic original core1",
            },
            ProcessorAssociation {
                domain: id(20),
                address: COMPLEX,
                target: ProcessorTarget::Cluster { members: vec![1] },
                evidence: "synthetic original complex",
            },
        ]
    }
    pub fn model(initial: u8) -> Pmgr {
        let mut pmgr =
            Pmgr::new([BASE, CORE, COMPLEX].map(|address| PowerState { address, initial }))
                .unwrap();
        for address in [BASE, CORE, COMPLEX] {
            pmgr.bind_lifecycle(address).unwrap();
        }
        pmgr
    }
    pub fn assigned(plan: &Plan<'_>, pmgr: &Pmgr) -> AssignedPower {
        let identity = plan.pes()[0].identity;
        AssignedPower::prepare(
            plan.identity(),
            plan.pes(),
            &[0, 0x100],
            &[
                Identity {
                    mpidr: 0x80000000,
                    ..identity
                },
                identity,
            ],
            &associations(),
            pmgr,
        )
        .unwrap()
    }

    #[test]
    fn original_physical_membership_projects_only_assigned_pe_and_samples_placed_state() {
        let (roster, inventory) = fixture();
        let plan = plan(&roster, &inventory);
        let pmgr = model(crate::platform::apple::pmgr::CLOCK_GATED);
        let assigned = assigned(&plan, &pmgr);
        let bindings = assigned.bindings();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].domain, 12);
        assert_eq!(bindings[0].target, ProcessorTarget::Core { pe: 0 });
        assert_eq!(
            bindings[1].target,
            ProcessorTarget::Cluster { members: vec![0] }
        );
        assert!(
            bindings
                .iter()
                .all(|b| b.initial.powered && !b.initial.clocked)
        );
        assert_eq!(
            pmgr.state(CORE),
            Some(crate::platform::apple::pmgr::CLOCK_GATED)
        );
        assert!(assigned.preview(&pmgr, BASE, u32::from(ACTIVE)).is_err());
        assert!(
            assigned
                .preview(
                    &pmgr,
                    BASE,
                    u32::from(crate::platform::apple::pmgr::CLOCK_GATED)
                )
                .is_ok()
        );
    }

    #[test]
    fn missing_identity_duplicate_source_and_unplaced_or_supply_off_states_refuse() {
        let (roster, inventory) = fixture();
        let plan = plan(&roster, &inventory);
        let identity = plan.pes()[0].identity;
        for regs in [[0, 0], [0, 1]] {
            assert!(
                AssignedPower::prepare(
                    plan.identity(),
                    plan.pes(),
                    &regs,
                    &[identity; 2],
                    &associations(),
                    &model(ACTIVE)
                )
                .is_err()
            );
        }
        let mut associations = associations();
        associations[1].domain = id(99);
        assert!(
            AssignedPower::prepare(
                plan.identity(),
                plan.pes(),
                &[0, 0x100],
                &[identity; 2],
                &associations,
                &model(ACTIVE)
            )
            .is_err()
        );
        assert!(
            AssignedPower::prepare(
                plan.identity(),
                plan.pes(),
                &[0, 0x100],
                &[identity; 2],
                &super::tests::associations(),
                &Pmgr::new([]).unwrap()
            )
            .is_err()
        );
        assert!(
            AssignedPower::prepare(
                plan.identity(),
                plan.pes(),
                &[0, 0x100],
                &[identity; 2],
                &super::tests::associations(),
                &model(POWER_GATED)
            )
            .is_err()
        );
    }

    #[test]
    fn stale_model_reserved_fields_and_unassigned_changes_leave_all_words_unchanged() {
        let (roster, inventory) = fixture();
        let plan = plan(&roster, &inventory);
        let mut pmgr = model(ACTIVE);
        let assigned = assigned(&plan, &pmgr);
        let before = [BASE, CORE, COMPLEX].map(|a| pmgr.control_word(a));
        for (address, value) in [(BASE, 4), (CORE, 1 << 31 | 15), (CORE, 3)] {
            assert!(assigned.preview(&pmgr, address, value).is_err());
            assert_eq!([BASE, CORE, COMPLEX].map(|a| pmgr.control_word(a)), before);
        }
        let mut latch = InterruptLatch::new();
        pmgr.write(CORE, Width::Word, 4, &mut Access::new(0, 0, &mut latch))
            .unwrap();
        let after = pmgr.control_word(CORE);
        assert!(assigned.preview(&pmgr, CORE, 15).is_err());
        assert_eq!(pmgr.control_word(CORE), after);
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_CPU_DT_DIR"]
    fn original_j473_first_p_binds_only_actual_core_and_complex_from_placed_state() {
        use sha2::{Digest, Sha256};
        use stela_soc_data::board::assigned::{BspSource, SourceIdentity};
        let directory = std::path::PathBuf::from(std::env::var("STELA_TEST_CPU_DT_DIR").unwrap());
        let raw = std::fs::read(directory.join("DeviceTree.j473ap.adt")).unwrap();
        assert_eq!(
            stela_formats::sha256(&raw),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let mut prepared = raw.clone();
        let replace = |bytes: &mut [u8], path: &[&str], property: &str, value: &[u8]| {
            let mut node = Node::root(bytes).unwrap();
            for name in path {
                node = node.child(name).unwrap();
            }
            let old = node.property(property).unwrap();
            assert_eq!(old.len(), value.len());
            let offset = old.as_ptr() as usize - bytes.as_ptr() as usize;
            bytes[offset..offset + value.len()].copy_from_slice(value);
        };
        replace(
            &mut prepared,
            &["chosen"],
            "chip-id",
            &0x8112u32.to_le_bytes(),
        );
        replace(
            &mut prepared,
            &["chosen"],
            "board-id",
            &0x24u32.to_le_bytes(),
        );
        replace(&mut prepared, &["cpus", "cpu0"], "state", b"waiting\0");
        replace(&mut prepared, &["cpus", "cpu4"], "state", b"running\0");
        let owner = BspSource::t8112(
            &raw,
            &prepared,
            SourceIdentity {
                profile: ResourceProfile {
                    chip: Chip::AppleM2,
                    soc: 0x8112,
                    board: 0x24,
                    input_set_sha256: [1; 32],
                    adapted_set_sha256: None,
                },
                original_tree_sha256: Sha256::digest(&raw).into(),
            },
            0x100,
            0,
        )
        .unwrap();
        let (roster, _) = fixture();
        let plan = Plan::build(
            &roster,
            &owner,
            &[Assignment {
                worker: 0,
                slot: owner.slot(),
                boot: true,
            }],
        )
        .unwrap();
        let root = Node::root(&raw).unwrap();
        let nodes = root.child("cpus").unwrap().children().unwrap();
        let word = |node: &Node<'_>, key| {
            u32::from_le_bytes(node.property(key).unwrap().try_into().unwrap())
        };
        let regs = nodes.iter().map(|n| word(n, "reg")).collect::<Vec<_>>();
        let cpus = nodes
            .iter()
            .map(|node| stela_soc_data::board::Processor {
                cluster_type: node.property("cluster-type").unwrap()[0],
                reg: word(node, "reg"),
                l2_bytes: Some(word(node, "l2-cache-size")),
            })
            .collect::<Vec<_>>();
        let product = root.child("product").unwrap();
        let name = product.property("product-soc-name").unwrap();
        let name = core::str::from_utf8(name.strip_suffix(&[0]).unwrap_or(name)).unwrap();
        let full = stela_soc_data::board::cpus(0x8112, name, &cpus).unwrap();
        let associations = owner
            .graph()
            .processor_associations(Chip::AppleM2, &root, &full.processors, 0)
            .unwrap();
        let pmgr = Pmgr::new(owner.graph().registers.iter().map(|&address| PowerState {
            address,
            initial: crate::platform::apple::pmgr::CLOCK_GATED,
        }))
        .unwrap();
        let assigned = AssignedPower::prepare(
            plan.identity(),
            plan.pes(),
            &regs,
            &full.processors,
            &associations,
            &pmgr,
        )
        .unwrap();
        let bindings = assigned.bindings();
        assert_eq!(bindings.len(), 2);
        assert_eq!(owner.graph().domains.len(), 303);
        assert_eq!(owner.power_addresses(), (0x2_3b70_0020, 0x2_3b70_0048));
        assert!(
            bindings
                .iter()
                .all(|b| !b.initial.clocked && b.initial.powered)
        );
        assert!(assigned.contains(0x2_3b70_0000));
        assert!(assigned.contains(0x2_3b70_0020));
        assert_eq!(
            bindings
                .iter()
                .filter(|b| b.target == ProcessorTarget::Core { pe: 0 })
                .count(),
            1
        );
        assert_eq!(
            bindings
                .iter()
                .filter(|b| b.target == ProcessorTarget::Cluster { members: vec![0] })
                .count(),
            1
        );
    }
}
