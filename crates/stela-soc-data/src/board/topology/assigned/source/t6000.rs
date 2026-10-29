//! Original T6000 normal-mode membership. Kernel discovery, PMGR constructor
//! order and native worker order are separate coordinates. This adapter keeps
//! the first two in original source order; the caller binds the actual BSP to
//! its real worker independently. No PS state or interrupt delivery is granted.
use super::*;
use stela_contracts::processor::ProcessorTarget;

const EVIDENCE: &str = "26A434 mac13j mode1 source-prefix membership; complex file2b16e08/core2b190e4/skip2b19918; no lifecycle, AIC delivery or native execution admission";

impl<'a> BspSource<'a> {
    /// Selects an original-order prefix of actual source PEs. Every original
    /// complex must remain represented and the selected boot PE must be the
    /// sole prepared running CPU. Later records in the last complex are
    /// retained in the full graph, but acquire no assigned owner here.
    pub fn t6000_assigned(
        original: &'a [u8],
        prepared: &[u8],
        identity: SourceIdentity,
        boot_reg: u32,
        effective_acc_harvesting: u32,
        count: usize,
    ) -> Result<Self, String> {
        if effective_acc_harvesting != 1 {
            return Err("assigned T6000 requires effective normal harvesting1".into());
        }
        // Reuse only the established identity, retained-schema and complete
        // original graph checks. That constructor examines original E0 and
        // does not require prepared E0 to be running. Its single-PE metadata
        // is replaced below; no input bytes are changed to pass preflight.
        let mut result = Self::t6000(original, prepared, identity, 0)?;
        let root = Node::root(original).ok_or("assigned original tree is malformed")?;
        let current = Node::root(prepared).ok_or("assigned prepared tree is malformed")?;
        let product = root
            .child("product")
            .ok_or("assigned source lacks product")?;
        let cpus = root.child("cpus").ok_or("assigned source lacks CPUs")?;
        let all = cpus
            .children()
            .ok_or("assigned source CPUs are malformed")?;
        let prepared_cpus = current
            .child("cpus")
            .ok_or("assigned prepared tree lacks CPUs")?;
        let prepared_all = prepared_cpus
            .children()
            .ok_or("assigned prepared CPUs are malformed")?;
        let mut processors = Vec::new();
        for node in &all {
            let kind = match property(node, "cluster-type")? {
                [kind @ (b'E' | b'P'), 0] => *kind,
                _ => return Err("assigned T6000 core kind is unqualified".into()),
            };
            processors.push(board::Processor {
                cluster_type: kind,
                reg: word(node, "reg")?,
                l2_bytes: Some(word(node, "l2-cache-size")?),
            });
        }
        let identities = board::cpus(
            identity.profile.soc,
            text(&product, "product-soc-name")?,
            &processors,
        )?;
        let associations = result.graph.processor_associations(
            identity.profile.chip,
            &root,
            &identities.processors,
            effective_acc_harvesting,
        )?;
        let boot = processors
            .iter()
            .position(|cpu| cpu.reg == boot_reg)
            .ok_or("assigned T6000 source lacks the selected boot PE")?;
        if count == 0 || count > all.len() || boot >= count {
            return Err("assigned T6000 prefix must retain the selected boot PE".into());
        }
        let full_clusters = processors
            .iter()
            .map(|cpu| cpu.reg >> CLUSTER_SHIFT)
            .collect::<BTreeSet<_>>();
        let selected_clusters = processors[..count]
            .iter()
            .map(|cpu| cpu.reg >> CLUSTER_SHIFT)
            .collect::<BTreeSet<_>>();
        if full_clusters != selected_clusters {
            return Err("assigned T6000 prefix must retain every original complex".into());
        }
        if prepared_all
            .iter()
            .filter(|cpu| cpu.property("state") == Some(b"running\0"))
            .count()
            != 1
            || prepared_all.get(boot).is_none_or(|cpu| {
                word(cpu, "reg") != Ok(boot_reg) || cpu.property("state") != Some(b"running\0")
            })
            || prepared_all.iter().any(|cpu| {
                ![Some(b"waiting\0".as_slice()), Some(b"running\0".as_slice())]
                    .contains(&cpu.property("state"))
            })
        {
            return Err("assigned T6000 boot PE is not the sole prepared running CPU".into());
        }
        let io = root.child("arm-io").ok_or("assigned source lacks arm-io")?;
        let aic = io.child("aic").ok_or("assigned source lacks AIC")?;
        let aic_provider = word(&aic, "AAPL,phandle")?;
        if aic_provider == 0 {
            return Err("assigned T6000 AIC provider is absent".into());
        }

        // Validate the full original complex geometry, including unassigned
        // cores. Numeric node/PMGR suffixes supply none of these identities.
        let mut geometry = Vec::new();
        for (pe, (node, cpu)) in all.iter().zip(&processors).enumerate() {
            if word(node, "interrupt-parent")? != aic_provider
                || property(node, "interrupts")?.len() != 4
            {
                return Err("assigned T6000 original CPU error source is unqualified".into());
            }
            let acc = region(node, "acc-impl-reg")?;
            let cpm = region(node, "cpm-impl-reg")?;
            let cpu_impl = region(node, "cpu-impl-reg")?;
            let encoded = identities.processors[pe]
                .caches
                .ok_or("assigned T6000 cache identity is incomplete")?
                .ccsidr(2);
            let cache = Cache {
                line: 16 << (encoded & 7),
                ways: ((encoded >> 3) & 0x3ff) as u32 + 1,
                bytes: word(node, "l2-cache-size")?,
            };
            let cluster = (cpu.reg >> CLUSTER_SHIFT) as usize;
            if geometry.len() == cluster {
                geometry.push((pe, acc, cpm, cpu_impl.bytes, cache));
            } else {
                let &(first, first_acc, first_cpm, cpu_bytes, first_cache) = geometry
                    .get(cluster)
                    .ok_or("assigned T6000 cluster discovery hole")?;
                if acc != first_acc
                    || cpm != first_cpm
                    || cpu_impl.bytes != cpu_bytes
                    || cache != first_cache
                    || identities.processors[pe].midr != identities.processors[first].midr
                    || identities.processors[pe].clock != identities.processors[first].clock
                    || identities.processors[pe].caches != identities.processors[first].caches
                {
                    return Err(
                        "assigned T6000 complex implementation/cache geometry differs".into(),
                    );
                }
            }
        }
        result.kinds.clear();
        result.slots.clear();
        result.clusters.clear();
        result.caches.clear();
        result.interrupts.clear();
        result.starts.clear();
        result.powers.clear();
        for (cluster, &(first, acc, cpm, _, cache)) in geometry.iter().enumerate() {
            let owners = associations.iter().filter(|owner| matches!(&owner.target, ProcessorTarget::Cluster { members } if members.contains(&first))).collect::<Vec<_>>();
            let [owner] = owners.as_slice() else {
                return Err("assigned T6000 complex lacks a unique physical CPM owner".into());
            };
            let id = ClusterId(cluster as u32);
            let cache_id = CacheId(cluster as u32);
            let node = &all[first];
            result.clusters.push(ClusterSlot {
                id,
                aff1: (processors[first].reg >> CLUSTER_SHIFT) as u8,
                firmware_id: word(node, "cluster-id")?,
                die: word(node, "die-id")?,
                die_cluster: word(node, "die-cluster-id")?,
                cache: Some(cache_id),
                power: Some(owner.domain),
                acc_impl: Some(acc),
                cpm_impl: Some(cpm),
            });
            result.caches.push(SharedCache {
                id: cache_id,
                cluster: id,
                geometry: cache,
            });
            result.powers.push(PowerResource {
                id: owner.domain,
                cores: vec![],
                clusters: vec![id],
            });
            if cluster == (boot_reg >> CLUSTER_SHIFT) as usize {
                result.cluster_address = owner.address;
            }
        }
        for (pe, (node, cpu)) in all[..count].iter().zip(&processors[..count]).enumerate() {
            let owners = associations
                .iter()
                .filter(|owner| owner.target == ProcessorTarget::Core { pe })
                .collect::<Vec<_>>();
            let [owner] = owners.as_slice() else {
                return Err("assigned T6000 PE lacks a unique physical core owner".into());
            };
            let id = GuestSlotId(pe as u32);
            let kind_id = KindId(pe as u32);
            let identity = identities.processors[pe];
            let (instruction, data) = board::level1_caches(result.profile.soc, cpu.cluster_type)
                .ok_or("assigned T6000 L1 geometry is unqualified")?;
            result.kinds.push(CoreKind {
                id: kind_id,
                cluster_type: cpu.cluster_type,
                midr: identity.midr,
                aff2: (identity.mpidr >> CORETYPE_SHIFT & u64::from(CORETYPE_MASK)) as u8,
                clock: identity.clock,
                instruction,
                data,
            });
            result.slots.push(PeSlot {
                id,
                reg: cpu.reg,
                kind: Some(kind_id),
                cluster: ClusterId(cpu.reg >> CLUSTER_SHIFT),
                cluster_core: word(node, "cluster-core-id")?,
                interrupt: Some(InterruptId(pe as u32)),
                start: Some(StartId(pe as u32)),
                power: Some(owner.domain),
                cpu_impl: Some(region(node, "cpu-impl-reg")?),
            });
            result.interrupts.push(InterruptTarget {
                id: InterruptId(pe as u32),
                reg: cpu.reg,
            });
            result.starts.push(StartResource {
                id: StartId(pe as u32),
                reg: cpu.reg,
            });
            result.powers.push(PowerResource {
                id: owner.domain,
                cores: vec![id],
                clusters: vec![],
            });
            if pe == boot {
                result.core_address = owner.address;
            }
        }
        // Capacities bound the retained inventory, not a larger fabricated SKU.
        // board::cpus has also checked the reviewed kernel20PE/6complex/physical10
        // envelope; the shared resolver checked source-order contiguous Aff0.
        let physical_span = full_clusters
            .iter()
            .next_back()
            .copied()
            .ok_or("assigned T6000 lacks a complex")? as usize
            + 1;
        result.capacities = CAPACITIES.into_iter().map(|kind| Capacity {
            kind,
            maximum: Some(match kind {
                CapacityKind::KernelClusters | CapacityKind::PlatformClusters => full_clusters.len(),
                CapacityKind::KernelPhysicalCluster => physical_span,
                _ => all.len(),
            }),
            provenance: "complete original T6000 inventory bounded by reviewed kernel limits; no additional execution owner",
        }).collect();
        result.name = text(&all[boot], "name")?.into();
        result.provenance = EVIDENCE;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "oracle: STELA_TEST_ASSIGNED_DT, STELA_TEST_ASSIGNED_PREPARED_DT"]
    fn original_t6000_assigned_prefix_preserves_all_source_coordinates_and_full_power_graph() {
        let original = std::fs::read(std::env::var("STELA_TEST_ASSIGNED_DT").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&original),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let prepared =
            std::fs::read(std::env::var("STELA_TEST_ASSIGNED_PREPARED_DT").unwrap()).unwrap();
        let identity = SourceIdentity {
            original_tree_sha256: Sha256::digest(&original).into(),
            profile: ResourceProfile {
                chip: Chip::AppleM1,
                soc: 0x6000,
                board: 8,
                input_set_sha256: [3; 32],
                adapted_set_sha256: None,
            },
        };
        let original_regs = [0, 1, 0x100, 0x101, 0x102, 0x103, 0x200, 0x201, 0x202, 0x203];
        for count in 7..=10 {
            let source =
                BspSource::t6000_assigned(&original, &prepared, identity, 0x100, 1, count).unwrap();
            let resources = source.resources();
            assert_eq!(
                resources
                    .slots
                    .iter()
                    .map(|slot| slot.reg)
                    .collect::<Vec<_>>(),
                original_regs[..count]
            );
            assert_eq!(
                resources
                    .clusters
                    .iter()
                    .map(|cluster| cluster.aff1)
                    .collect::<Vec<_>>(),
                [0, 1, 2]
            );
            assert_eq!(source.name(), "cpu2");
            assert_eq!(source.power_addresses(), (0x2_8e08_0020, 0x2_8e08_0068));
            assert_eq!(source.graph().domains.len(), 355);
            assert_eq!(source.graph().registers.len(), 196);
            for (pe, slot) in resources.slots.iter().enumerate() {
                assert_eq!(slot.id, GuestSlotId(pe as u32));
                assert_eq!(
                    slot.power,
                    Some(DomainId {
                        die: 0,
                        device: pe as u16 + 1
                    })
                );
                assert_eq!(source.name_for(slot.id).unwrap(), format!("cpu{pe}"));
            }
            for (index, cluster) in resources.clusters.iter().enumerate() {
                assert_eq!(
                    cluster.power,
                    Some(DomainId {
                        die: 0,
                        device: 11 + index as u16
                    })
                );
            }
            for device in count + 1..=10 {
                let id = DomainId {
                    die: 0,
                    device: device as u16,
                };
                assert!(source.graph().domains.iter().any(|domain| domain.id == id));
                assert!(!resources.powers.iter().any(|owner| owner.id == id));
            }
        }
        for count in [0, 1, 2, 3, 4, 5, 6, 11] {
            assert!(
                BspSource::t6000_assigned(&original, &prepared, identity, 0x100, 1, count).is_err()
            );
        }
        assert!(BspSource::t6000_assigned(&original, &prepared, identity, 0, 1, 8).is_err());
        assert!(BspSource::t6000_assigned(&original, &prepared, identity, 0x100, 0, 8).is_err());
        assert!(BspSource::t6000_assigned(&original, &original, identity, 0x100, 1, 8).is_err());
    }
}
