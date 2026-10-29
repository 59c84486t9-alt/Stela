//! T8112 normal-mode source membership, through the existing canonical CPU
//! association resolver. See apple-socs.md's original J473 power-ownership
//! proof (26A434 mac14g SHA25606846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d,
//! writers2b75078/2b74b40, MPIDR consumer2b81fb4, vtable13500c0/13500c8).
//! This view supplies neither initial PS state nor a lifecycle/executor owner.
use super::*;
use stela_contracts::processor::ProcessorTarget;

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
            processors.push(board::Processor {
                cluster_type: kind,
                reg,
                l2_bytes: Some(word(source, "l2-cache-size")?),
            });
        }
        let identities = board::cpus(
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
        let (instruction, data) = board::level1_caches(profile.soc, kind)
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
mod tests;
