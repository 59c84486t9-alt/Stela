//! T8112 normal-mode source membership, through the existing canonical CPU
//! association resolver. See apple-socs.md's original J473 power-ownership
//! proof (26A434 mac14g SHA25606846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d,
//! writers2b75078/2b74b40, MPIDR consumer2b81fb4, vtable13500c0/13500c8).
//! This view supplies neither initial PS state nor a lifecycle/executor owner.
use super::*;
use crate::machine::engine::ProcessorTarget;

impl<'a> BspSource<'a> {
    /// Retains the full original graph but exposes only the selected source PE
    /// for an actual one-worker BSP plan. The caller separately supplies the
    /// effective harvesting setting, including any start-time overrides.
    pub fn t8112(
        original: &'a [u8],
        prepared: &[u8],
        identity: SourceIdentity,
        boot_reg: u32,
        acc_harvesting: u32,
    ) -> Result<Self, String> {
        Self::t8112_member(
            original,
            prepared,
            identity,
            boot_reg,
            boot_reg,
            acc_harvesting,
        )
    }
    // Member metadata retains the actual running BSP independently of the
    // selected waiting PE. This never rewrites source or prepared CPU state.
    pub(super) fn t8112_member(
        original: &'a [u8],
        prepared: &[u8],
        identity: SourceIdentity,
        boot_reg: u32,
        member_reg: u32,
        acc_harvesting: u32,
    ) -> Result<Self, String> {
        let profile = identity.profile;
        if profile.chip != Chip::AppleM2 || profile.soc != 0x8112 || acc_harvesting != 0 {
            return Err("assigned source requires qualified T8112 normal-mode geometry".into());
        }
        if profile.input_set_sha256 == [0; 32]
            || profile.adapted_set_sha256 == Some([0; 32])
            || identity.original_tree_sha256 == [0; 32]
            || <[u8; 32]>::from(Sha256::digest(original)) != identity.original_tree_sha256
        {
            return Err("assigned original source identity/provenance differs".into());
        }
        let root = Node::root(original).ok_or("assigned original source tree is malformed")?;
        let adapted = Node::root(prepared).ok_or("assigned prepared source tree is malformed")?;
        let chosen = root.child("chosen").ok_or("assigned source lacks chosen")?;
        let actual = adapted
            .child("chosen")
            .ok_or("assigned prepared source lacks chosen")?;
        for (key, selected) in [("chip-id", profile.soc), ("board-id", profile.board)] {
            let template = word(&chosen, key)?;
            if (template != 0 && template != selected) || word(&actual, key)? != selected {
                return Err(format!(
                    "assigned selected restore {key} differs from source/prepared identity"
                ));
            }
        }
        let product = root
            .child("product")
            .ok_or("assigned source lacks product")?;
        let prepared_product = adapted
            .child("product")
            .ok_or("assigned prepared source lacks product")?;
        retained(&product, &prepared_product, &[])?;
        let io = root.child("arm-io").ok_or("assigned source lacks arm-io")?;
        let prepared_io = adapted
            .child("arm-io")
            .ok_or("assigned prepared source lacks arm-io")?;
        retained(&io, &prepared_io, &[])?;
        let pmgr = io.child("pmgr").ok_or("assigned source lacks PMGR")?;
        let prepared_pmgr = prepared_io
            .child("pmgr")
            .ok_or("assigned prepared source lacks PMGR")?;
        if property(&io, "compatible")? != b"arm-io,t8110\0"
            || property(&pmgr, "compatible")? != b"pmgr1,t8112\0"
        {
            return Err("assigned source requires exact T8112 fabric/PMGR identities".into());
        }
        retained(&pmgr, &prepared_pmgr, &["compatible"])?;
        for key in [
            "acc-harvesting",
            "clock-gates",
            "power-gates",
            "function-clock_gate",
            "function-power_gate",
            "ps-regs",
            "ps-groups",
            "soc-clusters",
        ] {
            if pmgr.property(key) != prepared_pmgr.property(key) {
                return Err(format!("assigned prepared PMGR dependency {key} differs"));
            }
        }
        if prepared_pmgr.property("compatible").is_some()
            && property(&pmgr, "compatible")? != property(&prepared_pmgr, "compatible")?
        {
            return Err("assigned prepared PMGR family differs".into());
        }
        let aic = io.child("aic").ok_or("assigned source lacks AIC")?;
        let prepared_aic = prepared_io
            .child("aic")
            .ok_or("assigned prepared source lacks AIC")?;
        if property(&aic, "compatible")? != b"aic,2\0" || word(&aic, "AAPL,phandle")? == 0 {
            return Err("assigned source lacks the original T8112 AIC identity".into());
        }
        retained(&aic, &prepared_aic, &["#main-cpus"])?;
        let cpus = root.child("cpus").ok_or("assigned source lacks CPUs")?;
        let prepared_cpus = adapted
            .child("cpus")
            .ok_or("assigned prepared source lacks CPUs")?;
        retained(
            &cpus,
            &prepared_cpus,
            &["max_cpus", "e-core-count", "p-core-count"],
        )?;
        let all = cpus
            .children()
            .ok_or("assigned source CPUs are malformed")?;
        let prepared_all = prepared_cpus
            .children()
            .ok_or("assigned prepared CPUs are malformed")?;
        if all.len() != prepared_all.len() {
            return Err("assigned CPU enumeration changed before projection".into());
        }
        let mut processors = Vec::new();
        for (source, current) in all.iter().zip(&prepared_all) {
            retained(
                source,
                current,
                &[
                    "state",
                    "timebase-frequency",
                    "fixed-frequency",
                    "peripheral-frequency",
                ],
            )?;
            let reg = word(source, "reg")?;
            for (field, expected) in [
                ("die-id", 0),
                ("die-cluster-id", reg >> 8),
                ("cluster-core-id", reg & 3),
            ] {
                if source.property(field) != current.property(field)
                    || source.property(field).is_some() && word(source, field)? != expected
                {
                    return Err(format!(
                        "assigned T8112 {field} differs from original affinity geometry"
                    ));
                }
            }
            let kind = match property(source, "cluster-type")? {
                [kind @ (b'E' | b'P'), 0] => *kind,
                _ => return Err("assigned T8112 core kind is unqualified".into()),
            };
            processors.push(soc::Processor {
                cluster_type: kind,
                reg,
                l2_bytes: Some(word(source, "l2-cache-size")?),
            });
        }
        let identities = soc::cpus(
            profile.soc,
            text(&product, "product-soc-name")?,
            &processors,
        )?;
        let graph = super::super::super::super::power_resources::source_power_states(
            &root,
            &pmgr,
            &|address, bytes| io.translate_range(address, bytes),
        )?;
        super::super::super::super::power_resources::validate_power_graph(&graph)?;
        // The canonical resolver also requires any original acc-harvesting
        // property to be exactly one u32 equal to the declared setting zero.
        // The retained dependency check above binds the prepared value to it.
        let associations = graph.processor_associations(
            profile.chip,
            &root,
            &identities.processors,
            acc_harvesting,
        )?;
        let matches = processors
            .iter()
            .enumerate()
            .filter(|(_, cpu)| cpu.reg == member_reg)
            .map(|(pe, _)| pe)
            .collect::<Vec<_>>();
        let [pe] = matches.as_slice() else {
            return Err("assigned source lacks a unique selected T8112 PE".into());
        };
        let pe = *pe;
        let node = &all[pe];
        if prepared_all
            .iter()
            .filter(|cpu| cpu.property("state") == Some(b"running\0"))
            .count()
            != 1
            || prepared_all
                .iter()
                .filter(|cpu| {
                    word(cpu, "reg") == Ok(boot_reg) && cpu.property("state") == Some(b"running\0")
                })
                .count()
                != 1
            || prepared_all.iter().any(|cpu| {
                ![Some(b"waiting\0".as_slice()), Some(b"running\0".as_slice())]
                    .contains(&cpu.property("state"))
            })
        {
            return Err("assigned selected T8112 PE is not the single prepared running CPU".into());
        }
        let enable = property(node, "function-enable_core")?;
        if enable.len() != 12
            || u32::from_le_bytes(enable[..4].try_into().unwrap()) != word(&pmgr, "AAPL,phandle")?
            || u32::from_le_bytes(enable[4..8].try_into().unwrap()) != 0x436f7265
            || u32::from_le_bytes(enable[8..].try_into().unwrap())
                != 1u32
                    .checked_shl(pe as u32)
                    .ok_or("assigned T8112 start mask overflows")?
            || word(node, "interrupt-parent")? != word(&aic, "AAPL,phandle")?
            || property(node, "interrupts")?.len() != 4
        {
            return Err("assigned T8112 start/error-interrupt reference is unqualified".into());
        }
        let core = associations
            .iter()
            .filter(|owner| owner.target == ProcessorTarget::Core { pe })
            .collect::<Vec<_>>();
        let cluster = associations.iter().filter(|owner| matches!(&owner.target, ProcessorTarget::Cluster { members } if members.contains(&pe))).collect::<Vec<_>>();
        let ([core], [complex]) = (core.as_slice(), cluster.as_slice()) else {
            return Err("assigned T8112 PE lacks unique canonical core/complex owners".into());
        };
        let identity = identities.processors[pe];
        let kind = processors[pe].cluster_type;
        let (instruction, data) = soc::level1_caches(profile.soc, kind)
            .ok_or("assigned T8112 L1 geometry is unqualified")?;
        let encoded = identity
            .caches
            .ok_or("assigned T8112 cache identity is incomplete")?
            .ccsidr(2);
        let slot = GuestSlotId(0);
        let cluster = ClusterId(0);
        let cache = CacheId(0);
        let capacities = CAPACITIES
            .into_iter()
            .map(|kind| Capacity {
                kind,
                maximum: Some(match kind {
                    // The canonical normal-mode resolver proves four Aff0
                    // slots per physical cluster and physical Aff1 0/1.
                    // These indexing spans do not add assigned PEs/clusters.
                    CapacityKind::KernelAffinitySpan => 4,
                    CapacityKind::KernelPhysicalCluster => 2,
                    _ => 1,
                }),
                provenance: "qualified one-BSP envelope; no added owner or hardware/kernel maximum",
            })
            .collect();
        Ok(Self {
            source: original,
            name: text(node, "name")?.into(),
            profile,
            capacities,
            kinds: vec![CoreKind {
                id: KindId(0),
                cluster_type: kind,
                midr: identity.midr,
                aff2: (identity.mpidr >> 16 & 7) as u8,
                clock: identity.clock,
                instruction,
                data,
            }],
            slots: vec![PeSlot {
                id: slot,
                reg: member_reg,
                kind: Some(KindId(0)),
                cluster,
                cluster_core: member_reg & 3,
                interrupt: Some(InterruptId(0)),
                start: Some(StartId(0)),
                power: Some(core.domain),
                cpu_impl: Some(region(node, "cpu-impl-reg")?),
            }],
            clusters: vec![ClusterSlot {
                id: cluster,
                aff1: (member_reg >> 8) as u8,
                firmware_id: word(node, "cluster-id")?,
                die: 0,
                die_cluster: member_reg >> 8,
                cache: Some(cache),
                power: Some(complex.domain),
                acc_impl: Some(region(node, "acc-impl-reg")?),
                cpm_impl: Some(region(node, "cpm-impl-reg")?),
            }],
            caches: vec![SharedCache {
                id: cache,
                cluster,
                geometry: Cache {
                    line: 16 << (encoded & 7),
                    ways: ((encoded >> 3) & 0x3ff) as u32 + 1,
                    bytes: word(node, "l2-cache-size")?,
                },
            }],
            interrupts: vec![InterruptTarget {
                id: InterruptId(0),
                reg: member_reg,
            }],
            starts: vec![StartResource {
                id: StartId(0),
                reg: member_reg,
            }],
            powers: vec![
                PowerResource {
                    id: core.domain,
                    cores: vec![slot],
                    clusters: vec![],
                },
                PowerResource {
                    id: complex.domain,
                    cores: vec![],
                    clusters: vec![cluster],
                },
            ],
            core_address: core.address,
            cluster_address: complex.address,
            graph,
            provenance: "T8112 normal-mode canonical source associations; no lifecycle or native execution admission",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Properties = Vec<(&'static str, Vec<u8>)>;
    fn encode(properties: Properties, children: &[Vec<u8>]) -> Vec<u8> {
        stela_contracts::adt::encode(
            &properties
                .iter()
                .map(|(name, value)| (*name, value.as_slice()))
                .collect::<Vec<_>>(),
            children,
        )
    }
    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }
    fn wide(values: &[u64]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }
    fn authored(prepared: bool) -> Vec<u8> {
        authored_config(prepared, None)
    }
    fn authored_config(prepared: bool, harvesting: Option<&[u8]>) -> Vec<u8> {
        let mut cpus = Vec::new();
        let mut records = Vec::new();
        for pe in 0..8u32 {
            let cluster = pe / 4;
            let base = 0x2_1000_0000 + u64::from(cluster) * 0x100_0000;
            cpus.push(encode(
                vec![
                    ("name", format!("cpu{pe}\0").into_bytes()),
                    ("reg", words(&[(cluster << 8) | (pe & 3)])),
                    ("cpu-id", words(&[pe])),
                    ("cluster-id", words(&[cluster])),
                    (
                        "cluster-type",
                        vec![if cluster == 0 { b'E' } else { b'P' }, 0],
                    ),
                    (
                        "state",
                        if prepared && pe == 4 {
                            b"running\0".to_vec()
                        } else {
                            b"waiting\0".to_vec()
                        },
                    ),
                    (
                        "l2-cache-size",
                        words(&[if cluster == 0 { 4 << 20 } else { 16 << 20 }]),
                    ),
                    (
                        "cpu-impl-reg",
                        wide(&[base + 0x50000 + u64::from(pe & 3) * 0x100000, 0x9010]),
                    ),
                    ("acc-impl-reg", wide(&[base + 0xf00000, 0x40088])),
                    ("cpm-impl-reg", wide(&[base + 0xe40000, 0x9010])),
                    ("function-enable_core", words(&[0x74, 0x436f7265, 1 << pe])),
                    ("interrupt-parent", words(&[0x63])),
                    ("interrupts", words(&[0x47 + pe])),
                ],
                &[],
            ));
            records.push(record(
                pe as u16 + 1,
                if cluster == 0 { 2 } else { 5 },
                pe as u8,
                &format!("CPU{pe}"),
                false,
            ));
        }
        records.push(record(9, 2, 8, "ECPM", false));
        records.push(record(10, 5, 9, "PCPM", false));
        records.push(record(0x163, 2, 0, "ECPM_NRG", true));
        records.push(record(0x164, 5, 0, "PCPM_NRG", true));
        let mut groups = vec![0; 72];
        groups[60..].copy_from_slice(&words(&[0, 0, 0x3ff]));
        let mut perf = vec![0; 56];
        perf[2..4].copy_from_slice(&[1, 2]);
        perf[30..32].copy_from_slice(&[1, 5]);
        let mut properties = vec![
            ("name", b"pmgr\0".to_vec()),
            ("compatible", b"pmgr1,t8112\0".to_vec()),
            ("AAPL,phandle", words(&[0x74])),
            ("reg", wide(&[0x3b700000, 0xcc000])),
            ("ps-regs", groups),
            ("perf-domains", perf),
            ("devices", records.into_iter().flatten().collect()),
        ];
        if let Some(value) = harvesting {
            properties.push(("acc-harvesting", value.to_vec()));
        }
        let pmgr = encode(properties, &[]);
        let aic = encode(
            vec![
                ("name", b"aic\0".to_vec()),
                ("compatible", b"aic,2\0".to_vec()),
                ("AAPL,phandle", words(&[0x63])),
                ("#main-cpus", words(&[8])),
            ],
            &[],
        );
        let io = encode(
            vec![
                ("name", b"arm-io\0".to_vec()),
                ("compatible", b"arm-io,t8110\0".to_vec()),
                ("#address-cells", words(&[2])),
                ("#size-cells", words(&[2])),
                ("ranges", wide(&[0, 0x2_0000_0000, 0x1_0000_0000])),
            ],
            &[pmgr, aic],
        );
        let chosen = encode(
            vec![
                ("name", b"chosen\0".to_vec()),
                ("chip-id", words(&[if prepared { 0x8112 } else { 0 }])),
                ("board-id", words(&[if prepared { 0x24 } else { 0 }])),
            ],
            &[],
        );
        let product = encode(
            vec![
                ("name", b"product\0".to_vec()),
                ("product-soc-name", b"Apple M2\0".to_vec()),
            ],
            &[],
        );
        let cpus = encode(
            vec![
                ("name", b"cpus\0".to_vec()),
                ("#address-cells", words(&[1])),
                ("#size-cells", words(&[0])),
            ],
            &cpus,
        );
        encode(
            vec![
                ("name", b"device-tree\0".to_vec()),
                ("#address-cells", words(&[2])),
                ("#size-cells", words(&[2])),
            ],
            &[chosen, product, io, cpus],
        )
    }
    fn record(id: u16, perf: u8, slot: u8, name: &str, virtual_: bool) -> [u8; 48] {
        let mut row = [0; 48];
        row[0] = if virtual_ { 0x10 } else { 0 };
        row[2] = perf;
        row[10] = slot;
        row[11] = 5;
        row[26..28].copy_from_slice(&id.to_le_bytes());
        row[32..32 + name.len()].copy_from_slice(name.as_bytes());
        row
    }
    fn identity(original: &[u8], board: u32) -> SourceIdentity {
        SourceIdentity {
            original_tree_sha256: Sha256::digest(original).into(),
            profile: ResourceProfile {
                chip: Chip::AppleM2,
                soc: 0x8112,
                board,
                input_set_sha256: [4; 32],
                adapted_set_sha256: None,
            },
        }
    }
    fn replace(bytes: &mut [u8], path: &[&str], field: &str, value: &[u8]) {
        let mut node = Node::root(bytes).unwrap();
        for name in path {
            node = node.child(name).unwrap();
        }
        let source = property(&node, field).unwrap();
        assert_eq!(source.len(), value.len());
        let offset = source.as_ptr() as usize - bytes.as_ptr() as usize;
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }
    #[test]
    fn authored_t8112_nonzero_bsp_retains_canonical_full_graph_and_source_coordinates() {
        let original = authored(false);
        let prepared = authored(true);
        let source =
            BspSource::t8112(&original, &prepared, identity(&original, 0x24), 0x100, 0).unwrap();
        assert_eq!(source.source(), original);
        assert_eq!(source.name(), "cpu4");
        let r = source.resources();
        assert_eq!(r.slots[0].reg, 0x100);
        assert_eq!(r.kinds[0].cluster_type, b'P');
        assert_eq!(r.clusters[0].aff1, 1);
        assert_eq!(r.clusters[0].die_cluster, 1);
        assert_eq!(r.slots[0].cluster_core, 0);
        assert_eq!(r.powers[0].id.device, 5);
        assert_eq!(r.powers[1].id.device, 10);
        assert_eq!(source.power_addresses(), (0x2_3b70_0020, 0x2_3b70_0048));
        assert_eq!(source.graph().domains.len(), 12);
        assert_eq!(r.caches[0].geometry.bytes, 16 << 20);
        struct Roster([AssignedCore; 1]);
        impl RetainedRoster for Roster {
            fn revision(&self) -> u64 {
                1
            }
            fn cores(&self) -> &[AssignedCore] {
                &self.0
            }
        }
        let host = Roster([AssignedCore {
            worker: 1,
            package: 0,
            core: 0,
            apic: 0,
            started: true,
        }]);
        let assignments = [Assignment {
            worker: 1,
            slot: source.slot(),
            boot: true,
        }];
        let plan = Plan::build(&host, &source, &assignments).unwrap();
        assert_eq!(plan.pes()[0].reg, 0x100);
        assert_eq!(plan.pes()[0].logical, 0);
        assert_eq!(plan.clusters()[0].resource.aff1, 1);
        for mode in [1, 2, 3] {
            assert!(
                BspSource::t8112(&original, &prepared, identity(&original, 0x24), 0x100, mode)
                    .is_err()
            );
        }
        assert!(BspSource::t8112(&original, &prepared, identity(&original, 0x24), 0, 0).is_err());
        let mut bad = prepared.clone();
        replace(
            &mut bad,
            &["cpus", "cpu4"],
            "function-enable_core",
            &words(&[0x74, 0x436f7265, 1]),
        );
        assert!(BspSource::t8112(&original, &bad, identity(&original, 0x24), 0x100, 0).is_err());
        let mut bad = prepared.clone();
        replace(
            &mut bad,
            &["cpus", "cpu4"],
            "cpu-impl-reg",
            &wide(&[0x2_1105_0000, 0x8000]),
        );
        assert!(BspSource::t8112(&original, &bad, identity(&original, 0x24), 0x100, 0).is_err());
        let mut wrong = identity(&original, 0x24);
        wrong.original_tree_sha256 = [0; 32];
        assert!(BspSource::t8112(&original, &prepared, wrong, 0x100, 0).is_err());
    }

    #[test]
    fn selected_t8112_resources_cover_each_worker_once_and_retain_actual_boot_state() {
        struct Roster(Vec<AssignedCore>);
        impl RetainedRoster for Roster {
            fn revision(&self) -> u64 {
                1
            }
            fn cores(&self) -> &[AssignedCore] {
                &self.0
            }
        }
        let original = authored(false);
        let prepared = authored(true);
        for count in 1..=8 {
            let source = BspSource::t8112_assigned(
                &original,
                &prepared,
                identity(&original, 0x24),
                0x100,
                0,
                count,
            )
            .unwrap();
            let resources = source.resources();
            assert_eq!(source.source(), original);
            assert_eq!(resources.slots.len(), count);
            assert_eq!(resources.slots[0].reg, 0x100);
            assert_eq!(source.name_for(resources.slots[0].id).unwrap(), "cpu4");
            assert_eq!(source.graph().domains.len(), 12);
            let roster = Roster(
                (0..count)
                    .map(|worker| AssignedCore {
                        worker,
                        package: 0,
                        core: worker as u32,
                        apic: worker as u32 + 10,
                        started: true,
                    })
                    .collect(),
            );
            let assignments = resources
                .slots
                .iter()
                .enumerate()
                .map(|(worker, slot)| Assignment {
                    worker,
                    slot: slot.id,
                    boot: worker == 0,
                })
                .collect::<Vec<_>>();
            let plan = Plan::build(&roster, &source, &assignments).unwrap();
            assert_eq!(plan.pes().len(), count);
            assert_eq!(plan.pes()[0].reg, 0x100);
            assert_eq!(plan.pes()[0].core_power.device, 5);
            let mut completed = BTreeSet::new();
            let mut previous = None;
            for pe in plan.pes() {
                if previous != Some(pe.cluster) {
                    assert!(!completed.contains(&pe.cluster));
                    if let Some(cluster) = previous {
                        completed.insert(cluster);
                    }
                    previous = Some(pe.cluster);
                }
            }
            assert_eq!(
                resources
                    .slots
                    .iter()
                    .map(|slot| slot.reg)
                    .collect::<Vec<_>>(),
                [0x100, 0x101, 0x102, 0x103, 0, 1, 2, 3][..count]
            );
            assert_eq!(resources.clusters.len(), if count <= 4 { 1 } else { 2 });
            assert_eq!(
                resources
                    .powers
                    .iter()
                    .flat_map(|power| &power.cores)
                    .count(),
                count
            );
            assert_eq!(
                resources
                    .powers
                    .iter()
                    .flat_map(|power| &power.clusters)
                    .count(),
                resources.clusters.len()
            );
        }
        for count in [0, 9, usize::MAX] {
            assert!(
                BspSource::t8112_assigned(
                    &original,
                    &prepared,
                    identity(&original, 0x24),
                    0x100,
                    0,
                    count
                )
                .is_err()
            );
        }
        assert!(
            BspSource::t8112_assigned(&original, &prepared, identity(&original, 0x24), 0, 0, 8)
                .is_err()
        );
    }

    #[test]
    fn equal_provider_settings_must_be_an_exact_u32_zero_even_with_declared_normal_mode() {
        let zero = 0u32.to_le_bytes();
        let original = authored_config(false, Some(&zero));
        let prepared = authored_config(true, Some(&zero));
        assert!(
            BspSource::t8112(&original, &prepared, identity(&original, 0x24), 0x100, 0).is_ok()
        );
        for value in [1u32.to_le_bytes().to_vec(), vec![], vec![0], vec![0; 8]] {
            let original = authored_config(false, Some(&value));
            let prepared = authored_config(true, Some(&value));
            assert!(
                BspSource::t8112(&original, &prepared, identity(&original, 0x24), 0x100, 0)
                    .is_err(),
                "provider bytes {value:?}"
            );
        }
    }
}
