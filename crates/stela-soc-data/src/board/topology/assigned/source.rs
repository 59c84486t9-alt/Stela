//! Source metadata for selected physical-PE construction envelopes. No
//! lifecycle sink, PS value, CPU-start ACK or native worker is created here.
//! T6000 normal mode1 takes the first CPU perf complex and bounds its core
//! records by the derived kernel cluster's one PE. Original26A434 mac13j
//! SHA256 5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90:
//! file2b0bf10 copies table123ae08 to self+1d50; entry123b438 names
//! acc-harvesting, and2b0c54c..570 publishes its u32 at self+238c.
//! Mode1 complex2b16e08..16f68 and core2b190e4..19228 bound
//! perf-complex/core records by kernel topology.2b18acc..18c08 classifies
//! core/CPM prefixes and stores the normalized source DeviceID, independently
//! of the function-enable_core bitmask consumed at2b5686c/2b2dcb0.
//! These are source membership identities, never observations of PS readiness.
mod selected;
mod t6000;
mod t8112;
use super::*;
use alloc::{format, string::String, vec, vec::Vec};
use stela_crypto::{Sha256, digest::Digest};
use {crate::board, crate::board::PowerStates, stela_contracts::adt::Node};

/// Selected restore/bundle identity, supplied by its owner.
/// Original chosen IDs may be templates; this record never observes hardware
/// identity or authenticates a manifest. The digest binds bytes, not behavior.
#[derive(Debug, Clone, Copy)]
pub struct SourceIdentity {
    pub profile: ResourceProfile,
    pub original_tree_sha256: [u8; 32],
}

/// Keeps the immutable source and full original PMGR graph. Opaque local IDs
/// index this view; they are not invented Apple device IDs. Physical
/// PMGR IDs/addresses are copied only from canonical normalized source records.
pub struct BspSource<'a> {
    source: &'a [u8],
    name: String,
    profile: ResourceProfile,
    capacities: Vec<Capacity>,
    kinds: Vec<CoreKind>,
    slots: Vec<PeSlot>,
    clusters: Vec<ClusterSlot>,
    caches: Vec<SharedCache>,
    interrupts: Vec<InterruptTarget>,
    starts: Vec<StartResource>,
    powers: Vec<PowerResource>,
    graph: PowerStates,
    core_address: u64,
    cluster_address: u64,
    provenance: &'static str,
}
fn property<'a>(node: &Node<'a>, key: &str) -> Result<&'a [u8], String> {
    let props = node
        .properties()
        .ok_or("assigned source has malformed properties")?;
    let mut found = props.iter().filter(|(name, _)| *name == key.as_bytes());
    let value = found
        .next()
        .ok_or_else(|| format!("assigned source lacks {key}"))?
        .1;
    if found.next().is_some() {
        return Err(format!("assigned source repeats {key}"));
    }
    Ok(value)
}
fn word(node: &Node<'_>, key: &str) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        property(node, key)?
            .try_into()
            .map_err(|_| format!("assigned source {key} is not a u32"))?,
    ))
}
fn text<'a>(node: &Node<'a>, key: &str) -> Result<&'a str, String> {
    core::str::from_utf8(
        property(node, key)?
            .strip_suffix(&[0])
            .unwrap_or(property(node, key)?),
    )
    .map_err(|_| format!("assigned source {key} is not text"))
}
fn region(node: &Node<'_>, key: &str) -> Result<RegisterRange, String> {
    let raw = property(node, key)?;
    if raw.len() != 16 {
        return Err(format!(
            "assigned source {key} is not one implementation range"
        ));
    }
    let range = RegisterRange {
        base: u64::from_le_bytes(raw[..8].try_into().unwrap()),
        bytes: u64::from_le_bytes(raw[8..].try_into().unwrap()),
    };
    if range.end().is_none() {
        return Err(format!("assigned source {key} extent is invalid"));
    }
    Ok(range)
}
fn starts(name: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| name.starts_with(prefix))
}

// Compare source-owned structural properties before deriving any resource. A
// hidden compatible is permitted only by explicit caller selection of this
// source family; it is never restored or used to admit public PMGR hardware.
fn retained(original: &Node<'_>, prepared: &Node<'_>, mutable: &[&str]) -> Result<(), String> {
    let props = original
        .properties()
        .ok_or("malformed original source properties")?;
    let mut names = BTreeSet::new();
    for (name, value) in props {
        let key = core::str::from_utf8(name).map_err(|_| "nontext source property name")?;
        if !names.insert(name) {
            return Err(format!("assigned original source repeats {key}"));
        }
        if mutable.contains(&key) {
            continue;
        }
        if original.property_is_placeholder(key) == Some(true) {
            if prepared.property_is_placeholder(key) == Some(true) {
                return Err(format!("assigned prepared source retains unresolved {key}"));
            }
            continue;
        }
        if property(prepared, key)? != value {
            return Err(format!("assigned prepared source changed {key}"));
        }
    }
    let mut names = BTreeSet::new();
    for (name, _) in prepared
        .properties()
        .ok_or("malformed prepared source properties")?
    {
        if !names.insert(name) {
            return Err("assigned prepared source repeats a property".into());
        }
    }
    Ok(())
}

impl<'a> BspSource<'a> {
    /// Checks metadata for a one-BSP owner. `original` is held
    /// unchanged input; `prepared` belongs to the selected bundle. The caller
    /// supplies its restore identity, never converts template chosen0
    /// into an observed chip/board, and keeps both sources through adoption.
    /// Mode1 is the original acc-harvesting input before later overrides. Such
    /// an override needs a new checked view. No PS/lifecycle state is granted.
    pub fn t6000(
        original: &'a [u8],
        prepared: &[u8],
        identity: SourceIdentity,
        boot_reg: u32,
    ) -> Result<Self, String> {
        let profile = identity.profile;
        if profile.chip != Chip::AppleM1 || profile.soc != 0x6000 || boot_reg != 0 {
            return Err(
                "assigned source requires qualified T6000 physical-reg0 BSP geometry".into(),
            );
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
        let chosen = root
            .child("chosen")
            .ok_or("assigned source has no chosen node")?;
        let actual = adapted
            .child("chosen")
            .ok_or("assigned prepared source has no chosen node")?;
        for (key, selected) in [("chip-id", profile.soc), ("board-id", profile.board)] {
            let template = word(&chosen, key)?;
            if (template != 0 && template != selected) || word(&actual, key)? != selected {
                return Err(format!(
                    "assigned selected restore {key} differs from source/prepared identity"
                ));
            }
        }
        let chip = profile.soc;
        let product = root
            .child("product")
            .ok_or("assigned source has no product")?;
        let prepared_product = adapted
            .child("product")
            .ok_or("assigned prepared source has no product")?;
        if property(&product, "product-soc-name")?
            != property(&prepared_product, "product-soc-name")?
        {
            return Err("assigned prepared product-soc-name differs".into());
        }
        let io = root
            .child("arm-io")
            .ok_or("assigned source has no arm-io")?;
        let prepared_io = adapted
            .child("arm-io")
            .ok_or("assigned prepared source has no arm-io")?;
        retained(&io, &prepared_io, &[])?;
        let pmgr = io.child("pmgr").ok_or("assigned source has no PMGR")?;
        let prepared_pmgr = prepared_io
            .child("pmgr")
            .ok_or("assigned prepared source has no PMGR")?;
        if !io.compatible("arm-io,t6000")
            || !pmgr.compatible("pmgr1,t6000")
            || word(&pmgr, "acc-harvesting")? != 1
        {
            return Err(
                "assigned source requires actual T6000 normal mode1 constructor inputs".into(),
            );
        }
        retained(&pmgr, &prepared_pmgr, &["compatible"])?;
        // Preserve absent as well as present dependency/function schema.
        // Added boot-owned voltage-state tables are separately accounted by
        // preparation; they cannot add a graph or constructor dependency here.
        for key in [
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
        let aic = io.child("aic").ok_or("assigned source has no AIC")?;
        let prepared_aic = prepared_io
            .child("aic")
            .ok_or("assigned prepared source has no AIC")?;
        retained(&aic, &prepared_aic, &["#main-cpus"])?;
        let cpus = root.child("cpus").ok_or("assigned source has no CPUs")?;
        let all = cpus
            .children()
            .ok_or("assigned source has malformed CPUs")?;
        let prepared_cpus = adapted
            .child("cpus")
            .ok_or("assigned prepared source has no CPUs")?;
        retained(
            &cpus,
            &prepared_cpus,
            &["max_cpus", "e-core-count", "p-core-count"],
        )?;
        let prepared_all = prepared_cpus
            .children()
            .ok_or("assigned prepared CPUs are malformed")?;
        if all.len() != prepared_all.len() {
            return Err("assigned source CPU enumeration changed before projection".into());
        }
        for (source_cpu, prepared_cpu) in all.iter().zip(&prepared_all) {
            retained(
                source_cpu,
                prepared_cpu,
                &[
                    "state",
                    "timebase-frequency",
                    "fixed-frequency",
                    "peripheral-frequency",
                ],
            )?;
        }
        let selected = all
            .iter()
            .filter(|cpu| word(cpu, "reg") == Ok(boot_reg))
            .collect::<Vec<_>>();
        let [node] = selected.as_slice() else {
            return Err("assigned source has no unique physical BSP node".into());
        };
        if word(node, "cluster-id")? != 0
            || word(node, "die-id")? != 0
            || word(node, "die-cluster-id")? != 0
            || word(node, "cluster-core-id")? != 0
            || property(node, "cluster-type")?
                .strip_suffix(&[0])
                .unwrap_or(property(node, "cluster-type")?)
                != b"E"
        {
            return Err(
                "assigned source BSP is outside qualified first E-complex/core geometry".into(),
            );
        }
        let enable = property(node, "function-enable_core")?;
        if enable.len() != 12 {
            return Err("assigned source BSP has incomplete enable_core protocol".into());
        }
        let cells = enable.as_chunks::<4>().0;
        if u32::from_le_bytes(cells[0]) != word(&pmgr, "AAPL,phandle")?
            || u32::from_le_bytes(cells[1]) != 0x436f7265
            || u32::from_le_bytes(cells[2]) != 1
        {
            return Err(
                "assigned source BSP start bitmask does not name the first actual constructor core"
                    .into(),
            );
        }
        let descriptors = property(&pmgr, "perf-domains")?;
        if descriptors.is_empty() || !descriptors.len().is_multiple_of(28) {
            return Err("assigned CPU perf-domain records are incomplete".into());
        }
        let mut ids = BTreeSet::new();
        let mut cpu_domains = Vec::new();
        for row in descriptors.as_chunks::<28>().0 {
            if row[3] == 0 || !ids.insert(row[3]) {
                return Err("assigned CPU perf-domain IDs are invalid or repeated".into());
            }
            if row[2] == 1 {
                cpu_domains.push(row[3]);
            }
        }
        let perf = *cpu_domains
            .first()
            .ok_or("assigned source has no CPU perf complex")?;
        let graph = super::super::super::power_resources::source_power_states(
            &root,
            &pmgr,
            &|address, bytes| io.translate_range(address, bytes),
        )?;
        super::super::super::power_resources::validate_power_graph(&graph)?;
        let raw = property(&pmgr, "devices")?;
        const RECORD: usize = super::super::super::power_resources::PMGR_DEVICE;
        if !raw.len().is_multiple_of(RECORD) || raw.len() / RECORD != graph.domains.len() {
            return Err("assigned source PMGR canonical records differ".into());
        }
        let mut core = None;
        let mut cpm = None;
        for (row, domain) in raw.as_chunks::<RECORD>().0.iter().zip(&graph.domains) {
            if row[2] != perf {
                continue;
            }
            // Original virtual/performance records do not construct physical
            // core or CPM owners (constructor virtual branch2b18c10). Keep
            // their complete requirements in graph; no lifecycle is waived.
            if row[0] == 0x10 && domain.address.is_none() {
                continue;
            }
            // The original prefix comparisons classify source record roles;
            // no suffix, ordinal, bitmask or parent formula supplies an ID.
            let is_core = starts(&domain.name, &["CPU", "ECPU", "PCPU", "MCPU"]);
            let is_cpm = starts(&domain.name, &["CPM", "ECPM", "PCPM", "MCPM"]);
            if !is_core && !is_cpm {
                return Err("assigned CPU perf complex has an unqualified record protocol".into());
            }
            if row[0] != 0 || row[1] != 0 || row[15] != 0 || row[25] != 0 || domain.id.die != 0 {
                return Err(
                    "assigned CPU record flags/replication require qualified constructor semantics"
                        .into(),
                );
            }
            let address = domain
                .address
                .ok_or("assigned physical CPU source domain has no actual PS placement")?;
            if is_core && core.is_none() {
                core = Some((domain.id, address));
            }
            if is_cpm && cpm.replace((domain.id, address)).is_some() {
                return Err("assigned CPU complex repeats its CPM owner".into());
            }
        }
        let (core_id, core_address) = core.ok_or("assigned source has no first CPU domain")?;
        let (cluster_id, cluster_address) =
            cpm.ok_or("assigned source has no actual CPM domain")?;
        if core_id == cluster_id || core_address == cluster_address {
            return Err("assigned CPU/core-complex identities alias unexpectedly".into());
        }
        let processors = [board::Processor {
            cluster_type: b'E',
            reg: boot_reg,
            l2_bytes: Some(word(node, "l2-cache-size")?),
        }];
        let cpus = board::cpus(chip, text(&product, "product-soc-name")?, &processors)?;
        let identity = cpus.processors[0];
        let (instruction, data) = board::level1_caches(chip, b'E')
            .ok_or("assigned source E cache geometry is unqualified")?;
        let encoded = identity
            .caches
            .ok_or("assigned source lacks complete cache identity")?
            .ccsidr(2);
        let geometry = Cache {
            line: 16 << (encoded & 7),
            ways: ((encoded >> 3) & 0x3ff) as u32 + 1,
            bytes: word(node, "l2-cache-size")?,
        };
        let slot = GuestSlotId(0);
        let cluster = ClusterId(0);
        let cache = CacheId(0);
        let capacities=CAPACITIES.into_iter().map(|kind|Capacity {kind,maximum:Some(1),provenance:"source-qualified single-BSP frontend envelope; not the hardware/kernel maximum or an added owner"}).collect();
        Ok(Self {
            source: original,
            name: text(node, "name")?.into(),
            profile,
            capacities,
            kinds: vec![CoreKind {
                id: KindId(0),
                cluster_type: b'E',
                midr: identity.midr,
                aff2: 0,
                clock: identity.clock,
                instruction,
                data,
            }],
            slots: vec![PeSlot {
                id: slot,
                reg: boot_reg,
                kind: Some(KindId(0)),
                cluster,
                cluster_core: 0,
                interrupt: Some(InterruptId(0)),
                start: Some(StartId(0)),
                power: Some(core_id),
                cpu_impl: Some(region(node, "cpu-impl-reg")?),
            }],
            clusters: vec![ClusterSlot {
                id: cluster,
                aff1: 0,
                firmware_id: 0,
                die: 0,
                die_cluster: 0,
                cache: Some(cache),
                power: Some(cluster_id),
                acc_impl: Some(region(node, "acc-impl-reg")?),
                cpm_impl: Some(region(node, "cpm-impl-reg")?),
            }],
            caches: vec![SharedCache {
                id: cache,
                cluster,
                geometry,
            }],
            interrupts: vec![InterruptTarget {
                id: InterruptId(0),
                reg: boot_reg,
            }],
            starts: vec![StartResource {
                id: StartId(0),
                reg: boot_reg,
            }],
            powers: vec![
                PowerResource {
                    id: core_id,
                    cores: vec![slot],
                    clusters: vec![],
                },
                PowerResource {
                    id: cluster_id,
                    cores: vec![],
                    clusters: vec![cluster],
                },
            ],
            graph,
            core_address,
            cluster_address,
            provenance: "T6000 mode1 first-complex/core source; no lifecycle or native execution admission",
        })
    }
    pub fn source(&self) -> &[u8] {
        self.source
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn slot(&self) -> GuestSlotId {
        self.slots[0].id
    }
    /// Complete original graph, including every unassigned physical domain.
    /// This is source accounting; none of these records gains a lifecycle sink.
    pub fn graph(&self) -> &PowerStates {
        &self.graph
    }
    pub fn power_addresses(&self) -> (u64, u64) {
        (self.core_address, self.cluster_address)
    }
}
impl RetainedResources for BspSource<'_> {
    fn revision(&self) -> u64 {
        1
    }
    fn resources(&self) -> Resources<'_> {
        Resources {
            profile: self.profile,
            register_granule: 0x4000,
            provenance: self.provenance,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_retention_distinguishes_fill_in_recipes_from_structural_values() {
        use stela_contracts::adt::encode;
        let fixed = 7u32.to_le_bytes();
        let mut original = encode(&[("fixed", &fixed), ("recipe", b"syscfg/ABCD\0")], &[]);
        let value = Node::root(&original).unwrap().property("recipe").unwrap();
        let length_offset = value.as_ptr() as usize - original.as_ptr() as usize - 4;
        let encoded = u32::from_le_bytes(
            original[length_offset..length_offset + 4]
                .try_into()
                .unwrap(),
        );
        original[length_offset..length_offset + 4]
            .copy_from_slice(&(encoded | 0x8000_0000).to_le_bytes());
        let source = Node::root(&original).unwrap();
        let removed = encode(&[("fixed", &fixed)], &[]);
        let resolved = encode(&[("fixed", &fixed), ("recipe", &[1, 2, 3, 4])], &[]);
        assert_eq!(source.property_is_placeholder("recipe"), Some(true));
        assert!(retained(&source, &Node::root(&removed).unwrap(), &[]).is_ok());
        assert!(retained(&source, &Node::root(&resolved).unwrap(), &[]).is_ok());
        assert!(retained(&source, &source, &[]).is_err());
        let changed = encode(&[("fixed", &8u32.to_le_bytes())], &[]);
        assert!(retained(&source, &Node::root(&changed).unwrap(), &[]).is_err());
        let missing = encode(&[], &[]);
        assert!(retained(&source, &Node::root(&missing).unwrap(), &[]).is_err());
        let ordinary = encode(&[("fixed", &fixed), ("recipe", b"syscfg/ABCD\0")], &[]);
        assert!(
            retained(
                &Node::root(&ordinary).unwrap(),
                &Node::root(&removed).unwrap(),
                &[]
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_ASSIGNED_DT, STELA_TEST_ASSIGNED_PREPARED_DT"]
    fn original_mode1_bsp_uses_canonical_dynamic_domain_ids_without_granting_ps_state() {
        let input = std::env::var("STELA_TEST_ASSIGNED_DT").unwrap();
        let bytes = std::fs::read(input).unwrap();
        assert_eq!(
            stela_formats::sha256(&bytes),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let prepared =
            std::fs::read(std::env::var("STELA_TEST_ASSIGNED_PREPARED_DT").unwrap()).unwrap();
        let identity = |original: &[u8]| SourceIdentity {
            original_tree_sha256: Sha256::digest(original).into(),
            profile: ResourceProfile {
                chip: Chip::AppleM1,
                soc: 0x6000,
                board: 8,
                input_set_sha256: [3; 32],
                adapted_set_sha256: None,
            },
        };
        let selected = identity(&bytes);
        let owner = BspSource::t6000(&bytes, &prepared, selected, 0).unwrap();
        assert!(
            Node::root(&prepared)
                .unwrap()
                .child("arm-io")
                .unwrap()
                .child("pmgr")
                .unwrap()
                .property("compatible")
                .is_none()
        );
        let resources = owner.resources();
        assert_eq!(resources.slots.len(), 1);
        assert_eq!(resources.slots[0].reg, 0);
        assert_eq!(resources.powers[0].id, DomainId { die: 0, device: 1 });
        assert_eq!(resources.powers[1].id, DomainId { die: 0, device: 11 });
        assert_eq!(owner.graph().domains.len(), 355);
        assert_eq!(owner.graph().registers.len(), 196);
        assert_eq!(owner.name(), "cpu0");
        for (id, address) in resources
            .powers
            .iter()
            .zip([owner.core_address, owner.cluster_address])
        {
            assert!(
                owner
                    .graph()
                    .domains
                    .iter()
                    .any(|domain| domain.id == id.id && domain.address == Some(address))
            );
        }
        assert!(
            resources
                .capacities
                .iter()
                .all(|capacity| capacity.maximum == Some(1))
        );
        assert_eq!(owner.source(), bytes);
        assert!(BspSource::t6000(&bytes, &prepared, selected, 1).is_err());
        assert!(
            BspSource::t6000(
                &bytes,
                &prepared,
                SourceIdentity {
                    original_tree_sha256: [0; 32],
                    ..selected
                },
                0
            )
            .is_err()
        );
        let mut wrong_profile = selected;
        wrong_profile.profile.board = 9;
        assert!(BspSource::t6000(&bytes, &prepared, wrong_profile, 0).is_err());
        let root = Node::root(&bytes).unwrap();
        let pmgr = root.child("arm-io").unwrap().child("pmgr").unwrap();
        let harvesting = property(&pmgr, "acc-harvesting").unwrap();
        let offset = harvesting.as_ptr() as usize - bytes.as_ptr() as usize;
        for mode in [0u32, 2, 3] {
            let mut wrong = bytes.clone();
            wrong[offset..offset + 4].copy_from_slice(&mode.to_le_bytes());
            assert!(
                BspSource::t6000(&wrong, &prepared, identity(&wrong), 0)
                    .err()
                    .unwrap()
                    .contains("mode1")
            );
        }
        let raw = property(&pmgr, "devices").unwrap();
        let offset = raw.as_ptr() as usize - bytes.as_ptr() as usize;
        // A different explicitly declared source ID still resolves through the
        // canonical table; no original-ID constant or core-mask formula wins.
        let mut declared = bytes.clone();
        declared[offset + 26..offset + 28].copy_from_slice(&601u16.to_le_bytes());
        let mut declared_prepared = prepared.clone();
        let proot = Node::root(&prepared).unwrap();
        let ppmgr = proot.child("arm-io").unwrap().child("pmgr").unwrap();
        let offset =
            property(&ppmgr, "devices").unwrap().as_ptr() as usize - prepared.as_ptr() as usize;
        declared_prepared[offset + 26..offset + 28].copy_from_slice(&601u16.to_le_bytes());
        assert!(BspSource::t6000(&declared, &prepared, identity(&declared), 0).is_err());
        assert!(BspSource::t6000(&declared, &declared_prepared, selected, 0).is_err());
        let declared =
            BspSource::t6000(&declared, &declared_prepared, identity(&declared), 0).unwrap();
        assert_eq!(declared.resources().powers[0].id.device, 601);
        assert_eq!(declared.core_address, owner.core_address);
    }
}
