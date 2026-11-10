//! Original T6020-family mode-1 membership for a selected worker count.
//! Ownership comes from the mode-1 resolver (`power_resources::cpu::t6020`):
//! each core's PMGR record by its global CPU number, each complex's CPM
//! through its perf domain, die after die. That kernel constructor binds a
//! complex's records in order to the CPUs its kernel cluster lists, so the
//! selection keeps a prefix of every complex, and at least one member in
//! every original complex on every die, so each complex keeps the kernel
//! cluster it binds by order. No lifecycle, PS value or native execution is
//! granted here.
use super::*;
use stela_contracts::processor::ProcessorTarget;

/// The decoded mac14j kernel's limits (`board::soc::rows` `T6020_LIMITS`):
/// 24 CPUs, 6 clusters, highest physical cluster 10.
const MAX_CPUS: usize = 24;
const MAX_CLUSTERS: usize = 6;
const HARVESTING: u32 = 1;
const ENABLE_CORE_SELECTOR: u32 = 0x436f_7265;
/// A die's Aff1 values start at `die << DIE_SHIFT` (J475D die 1 is 8).
const DIE_SHIFT: u32 = 3;
/// The Pro's PMGR family and the Max's, which the Ultra's dies use.
const COMPATIBLES: [&str; 2] = ["pmgr1,t6020", "pmgr1,t6021"];

const EVIDENCE: &str = "26B123 mac14j SHA256 2d6520798a32bee6e377a2906d3dd02a788d4ed396ae9c6c5884dbe909d8a47e; T6020 mode1 per-die record order, core writer 0xfffffe0009b5b7b0; selection keeps a prefix of every original complex";

/// How many cores each complex keeps: one each first, starting with the
/// boot complex, then one more each round in the same order. Each complex
/// keeps its first cores, so the boot PE must lead its complex.
fn select(clusters: &[Vec<usize>], boot: usize, count: usize) -> Result<Vec<usize>> {
    let start = clusters
        .iter()
        .position(|members| members.first() == Some(&boot))
        .ok_or(refuse!("assigned T6020 boot PE does not lead its complex"))?;
    let total: usize = clusters.iter().map(Vec::len).sum();
    if count < clusters.len() || count > total {
        return Err(refuse!(
            "assigned T6020 worker count must give every original complex a member"
        ));
    }
    let mut taken = vec![0usize; clusters.len()];
    let mut left = count;
    while left > 0 {
        for offset in 0..clusters.len() {
            let cluster = (start + offset) % clusters.len();
            if left > 0 && taken[cluster] < clusters[cluster].len() {
                taken[cluster] += 1;
                left -= 1;
            }
        }
    }
    Ok(clusters
        .iter()
        .zip(&taken)
        .flat_map(|(members, &n)| members[..n].iter().copied())
        .collect())
}

impl<'a> BspSource<'a> {
    /// Metadata for `count` assigned workers on a T6020-family board, from
    /// the immutable `original` tree and the bundle's `prepared` one.
    pub fn t6020_assigned(
        original: &'a [u8],
        prepared: &[u8],
        identity: SourceIdentity,
        boot_reg: u32,
        effective_acc_harvesting: u32,
        count: usize,
    ) -> Result<Self> {
        let profile = identity.profile;
        if profile.chip != Chip::AppleM2 || !(0x6020..=0x6022).contains(&profile.soc) {
            return Err(refuse!(
                "assigned source requires qualified T6020-family geometry"
            ));
        }
        if effective_acc_harvesting != HARVESTING {
            return Err(refuse!(
                "assigned T6020 requires effective mode1 harvesting"
            ));
        }
        if profile.input_set_sha256 == [0; 32]
            || profile.adapted_set_sha256 == Some([0; 32])
            || identity.original_tree_sha256 == [0; 32]
            || <[u8; 32]>::from(Sha256::digest(original)) != identity.original_tree_sha256
        {
            return Err(refuse!(
                "assigned original source identity/provenance differs"
            ));
        }
        let root =
            Node::root(original).ok_or(refuse!("assigned original source tree is malformed"))?;
        let adapted =
            Node::root(prepared).ok_or(refuse!("assigned prepared source tree is malformed"))?;

        let chosen = root
            .child("chosen")
            .ok_or(refuse!("assigned source lacks chosen"))?;
        let actual = adapted
            .child("chosen")
            .ok_or(refuse!("assigned prepared source lacks chosen"))?;
        for (key, selected) in [("chip-id", profile.soc), ("board-id", profile.board)] {
            let template = word(&chosen, key)?;
            if (template != 0 && template != selected) || word(&actual, key)? != selected {
                return Err(refuse!(
                    "assigned selected restore {key} differs from source/prepared identity",
                    key
                ));
            }
        }
        let product = root
            .child("product")
            .ok_or(refuse!("assigned source lacks product"))?;
        let prepared_product = adapted
            .child("product")
            .ok_or(refuse!("assigned prepared source lacks product"))?;
        if property(&product, "product-soc-name")?
            != property(&prepared_product, "product-soc-name")?
        {
            return Err(refuse!("assigned prepared product-soc-name differs"));
        }

        let io = root
            .child("arm-io")
            .ok_or(refuse!("assigned source lacks arm-io"))?;
        let prepared_io = adapted
            .child("arm-io")
            .ok_or(refuse!("assigned prepared source lacks arm-io"))?;
        let pmgr = io
            .child("pmgr")
            .ok_or(refuse!("assigned source lacks PMGR"))?;
        let prepared_pmgr = prepared_io
            .child("pmgr")
            .ok_or(refuse!("assigned prepared source lacks PMGR"))?;
        if !COMPATIBLES.iter().any(|family| pmgr.compatible(family))
            || word(&pmgr, "acc-harvesting")? != HARVESTING
        {
            return Err(refuse!(
                "assigned source requires actual T6020 mode1 constructor inputs"
            ));
        }
        for key in [
            "acc-harvesting",
            "clusters",
            "devices",
            "die-stride",
            "perf-domains",
            "ps-regs",
            "soc-clusters",
            "clock-gates",
        ] {
            if pmgr.property(key) != prepared_pmgr.property(key) {
                return Err(refuse!(
                    "assigned prepared PMGR dependency {key} differs",
                    key
                ));
            }
        }
        if prepared_pmgr.property("compatible").is_some()
            && property(&pmgr, "compatible")? != property(&prepared_pmgr, "compatible")?
        {
            return Err(refuse!("assigned prepared PMGR family differs"));
        }
        let aic = io
            .child("aic")
            .ok_or(refuse!("assigned source lacks AIC"))?;
        let aic_provider = word(&aic, "AAPL,phandle")?;
        if !aic.compatible("aic,2") || aic_provider == 0 {
            return Err(refuse!(
                "assigned source lacks the original T6020 AIC identity"
            ));
        }
        let pmgr_provider = word(&pmgr, "AAPL,phandle")?;

        let all = root
            .child("cpus")
            .and_then(|cpus| cpus.children())
            .ok_or(refuse!("assigned source lacks CPUs"))?;
        let prepared_all = adapted
            .child("cpus")
            .and_then(|cpus| cpus.children())
            .ok_or(refuse!("assigned prepared CPUs are malformed"))?;
        if all.is_empty() || all.len() > MAX_CPUS || all.len() != prepared_all.len() {
            return Err(refuse!(
                "assigned CPU enumeration changed before projection"
            ));
        }
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
        }
        let mut processors = Vec::with_capacity(all.len());
        for node in &all {
            let kind = match property(node, "cluster-type")? {
                [kind @ (b'E' | b'P'), 0] => *kind,
                _ => return Err(refuse!("assigned T6020 core kind is unqualified")),
            };
            processors.push(board::Processor {
                cluster_type: kind,
                reg: word(node, "reg")?,
                l2_bytes: Some(word(node, "l2-cache-size")?),
            });
        }
        let boot = processors
            .iter()
            .position(|cpu| cpu.reg == boot_reg)
            .ok_or(refuse!("assigned T6020 source lacks the selected boot PE"))?;
        if prepared_all
            .iter()
            .filter(|cpu| cpu.property("state") == Some(b"running\0"))
            .count()
            != 1
            || word(&prepared_all[boot], "reg") != Ok(boot_reg)
            || prepared_all[boot].property("state") != Some(b"running\0")
            || prepared_all.iter().any(|cpu| {
                ![Some(b"waiting\0".as_slice()), Some(b"running\0".as_slice())]
                    .contains(&cpu.property("state"))
            })
        {
            return Err(refuse!(
                "assigned T6020 boot PE is not the sole prepared running CPU"
            ));
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
        let associations = graph.processor_associations(
            profile.chip,
            &root,
            &identities.processors,
            effective_acc_harvesting,
        )?;

        // Complexes in source order; each core's enable_core bit is its
        // global CPU number.
        let mut clusters: Vec<Vec<usize>> = Vec::new();
        for (pe, (node, cpu)) in all.iter().zip(&processors).enumerate() {
            let die = word(node, "die-id")?;
            let aff1 = cpu.reg >> CLUSTER_SHIFT;
            if aff1 >> DIE_SHIFT != die || word(node, "cluster-id")? != aff1 {
                return Err(refuse!("assigned T6020 die/cluster coordinates differ"));
            }
            let enable = property(node, "function-enable_core")?;
            if enable.len() != 12
                || u32::from_le_bytes(enable[..4].try_into().unwrap()) != pmgr_provider
                || u32::from_le_bytes(enable[4..8].try_into().unwrap()) != ENABLE_CORE_SELECTOR
                || u32::from_le_bytes(enable[8..].try_into().unwrap())
                    != 1u32
                        .checked_shl(pe as u32)
                        .ok_or(refuse!("assigned T6020 start mask overflows"))?
                || word(node, "interrupt-parent")? != aic_provider
                || property(node, "interrupts")?.len() != 4
            {
                return Err(refuse!(
                    "assigned T6020 start/error-interrupt reference is unqualified"
                ));
            }
            match clusters.last_mut() {
                Some(members) if processors[members[0]].reg >> CLUSTER_SHIFT == aff1 => {
                    members.push(pe)
                }
                _ => {
                    if clusters
                        .iter()
                        .any(|members| processors[members[0]].reg >> CLUSTER_SHIFT == aff1)
                    {
                        return Err(refuse!("assigned T6020 complex is not contiguous"));
                    }
                    clusters.push(vec![pe]);
                }
            }
        }
        if clusters.len() > MAX_CLUSTERS {
            return Err(refuse!("assigned T6020 kernel cluster capacity"));
        }
        let selected = select(&clusters, boot, count)?;

        let mut result = Self {
            source: original,
            name: text(&all[boot], "name")?.into(),
            profile,
            capacities: Vec::new(),
            kinds: Vec::new(),
            slots: Vec::new(),
            clusters: Vec::new(),
            caches: Vec::new(),
            interrupts: Vec::new(),
            starts: Vec::new(),
            powers: Vec::new(),
            graph,
            core_address: 0,
            cluster_address: 0,
            provenance: EVIDENCE,
        };
        for members in &clusters {
            let first = members[0];
            let node = &all[first];
            let acc = region(node, "acc-impl-reg")?;
            let cpm = region(node, "cpm-impl-reg")?;
            let cpu_bytes = region(node, "cpu-impl-reg")?.bytes;
            let cache = identities.processors[first]
                .caches
                .ok_or(refuse!("assigned T6020 cache identity is incomplete"))?
                .cache(CacheSelection::L2Unified);
            for &pe in &members[1..] {
                let other = &all[pe];
                if region(other, "acc-impl-reg")? != acc
                    || region(other, "cpm-impl-reg")? != cpm
                    || region(other, "cpu-impl-reg")?.bytes != cpu_bytes
                    || identities.processors[pe].midr != identities.processors[first].midr
                    || identities.processors[pe].clock != identities.processors[first].clock
                    || identities.processors[pe].caches != identities.processors[first].caches
                {
                    return Err(refuse!(
                        "assigned T6020 complex implementation/cache geometry differs"
                    ));
                }
            }
            let owners = associations
                .iter()
                .filter(|owner| matches!(&owner.target, ProcessorTarget::Cluster { members: owned } if owned == members))
                .collect::<Vec<_>>();
            let [owner] = owners.as_slice() else {
                return Err(refuse!(
                    "assigned T6020 complex lacks a unique physical CPM owner"
                ));
            };
            let aff1 = processors[first].reg >> CLUSTER_SHIFT;
            let id = ClusterId(aff1);
            let cache_id = CacheId(aff1);
            result.clusters.push(ClusterSlot {
                id,
                aff1: aff1 as u8,
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
            if members.contains(&boot) {
                result.cluster_address = owner.address;
            }
        }
        for (ordinal, &pe) in selected.iter().enumerate() {
            let node = &all[pe];
            let cpu = processors[pe];
            let owners = associations
                .iter()
                .filter(|owner| owner.target == ProcessorTarget::Core { pe })
                .collect::<Vec<_>>();
            let [owner] = owners.as_slice() else {
                return Err(refuse!(
                    "assigned T6020 PE lacks a unique physical core owner"
                ));
            };
            let id = GuestSlotId(ordinal as u32);
            let kind_id = KindId(ordinal as u32);
            let identity = identities.processors[pe];
            let caches = identity
                .caches
                .ok_or(refuse!("assigned T6020 L1 geometry is unqualified"))?;
            let (instruction, data) = (
                caches.cache(CacheSelection::L1Instruction),
                caches.cache(CacheSelection::L1Data),
            );
            result.kinds.push(CoreKind {
                id: kind_id,
                cluster_type: cpu.cluster_type,
                midr: identity.midr,
                aff2: crate::board::mpidr::coretype(identity.mpidr),
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
                interrupt: Some(InterruptId(ordinal as u32)),
                start: Some(StartId(ordinal as u32)),
                power: Some(owner.domain),
                cpu_impl: Some(region(node, "cpu-impl-reg")?),
            });
            result.interrupts.push(InterruptTarget {
                id: InterruptId(ordinal as u32),
                reg: cpu.reg,
            });
            result.starts.push(StartResource {
                id: StartId(ordinal as u32),
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
        // Capacities bound the complete original inventory, not an invented
        // SKU; board::cpus has checked it against the kernel's limits.
        let physical_span = processors
            .iter()
            .map(|cpu| (cpu.reg >> CLUSTER_SHIFT) as usize + 1)
            .max()
            .unwrap_or(0);
        result.capacities = CAPACITIES
            .into_iter()
            .map(|kind| Capacity {
                kind,
                maximum: Some(match kind {
                    CapacityKind::KernelClusters | CapacityKind::PlatformClusters => {
                        clusters.len()
                    }
                    CapacityKind::KernelPhysicalCluster => physical_span,
                    _ => all.len(),
                }),
                provenance: "complete original T6020 inventory bounded by reviewed kernel limits; no additional execution owner",
            })
            .collect();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_keeps_a_prefix_of_every_complex_from_the_boot_complex_first() {
        let clusters = [
            (0..4).collect::<Vec<_>>(),
            (4..8).collect(),
            (8..12).collect(),
            (12..16).collect(),
            (16..20).collect(),
            (20..24).collect(),
        ];
        assert_eq!(
            select(&clusters, 0, 8).unwrap(),
            [0, 1, 4, 5, 8, 12, 16, 20]
        );
        assert_eq!(
            select(&clusters, 0, 16).unwrap(),
            [0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 16, 17, 20, 21]
        );
        assert_eq!(select(&clusters, 0, 6).unwrap(), [0, 4, 8, 12, 16, 20]);
        assert_eq!(
            select(&clusters, 0, 24).unwrap(),
            (0..24).collect::<Vec<_>>()
        );
        // The kernel binds each complex's first records, so a boot PE that
        // does not lead its complex is refused.
        assert!(select(&clusters, 5, 8).is_err());
        assert!(select(&clusters, 0, 5).is_err());
        assert!(select(&clusters, 0, 25).is_err());
    }
}
