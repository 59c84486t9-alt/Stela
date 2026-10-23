//! Source-qualified CPU ownership, independent of lifecycle state or admission.
//!
//! Original 26A434 T8112 normal-mode MPIDR/idle callbacks and T6000 mode1
//! constructor counters establish separate membership rules. See apple-socs.md's
//! J473 proof and the T6000 source module. No input hash or board name dispatches
//! production behavior, and no numeric suffix of a record name selects a PE.
mod t6000;

use super::records::{Layout, Record};
use crate::{
    machine::{Chip, adt::Node, engine::ProcessorTarget, registers::Identity},
    platform::apple::pmgr::coverage::DomainId,
};
use alloc::{collections::BTreeSet, vec::Vec};

/// The existing board reader supplies these normalized views in original
/// record order. This module reuses that reader's record parser to check the
/// ID/name/location provenance, rather than defining another packed layout.
#[derive(Debug, Clone, Copy)]
pub struct PmgrCpuRecord<'a> {
    pub id: DomainId,
    pub flags: u8,
    pub perf_domain: u8,
    pub name: &'a str,
    pub location: Option<PmgrCpuLocation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmgrCpuLocation {
    pub group: usize,
    pub index: u32,
    pub address: u64,
}

/// A positive implicit CPU participant, with the graph's canonical identity.
/// The caller must separately qualify and supply its initial LifecycleState.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessorAssociation {
    pub domain: DomainId,
    pub address: u64,
    pub target: ProcessorTarget,
    pub evidence: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuAssociationError {
    UnsupportedChip(Chip),
    UnsupportedCompatible,
    UnsupportedHarvesting(u32),
    ConflictingHarvesting,
    UnsupportedDie(u8),
    Malformed(&'static str),
    UnqualifiedGeometry(&'static str),
    Topology(&'static str),
    RecordMismatch(usize),
    DuplicateDomain(DomainId),
    UnknownPerfDomain(DomainId),
    UnknownCpuProtocol(DomainId),
    ConflictingAddress(u64),
    IncompleteOwners,
}

/// Provenance identifies reviewed source semantics, never a production key.
pub const CPU_POWER_EVIDENCE: &str = "26A434 kernelcache.mac14g SHA256 \
    06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d; \
    normal core/CPM writers 0x2b75078/0x2b74b40, MPIDR consumer 0x2b81fb4, \
    actual T8112 vtable 0x13500c0/0x13500c8; docs/research/apple-socs.md";

const COMPATIBLE: &[u8] = b"pmgr1,t8112\0";
const CORE_PREFIXES: [&str; 4] = ["CPU", "ECPU", "PCPU", "MCPU"];
const CPM_PREFIXES: [&str; 4] = ["CPM", "ECPM", "PCPM", "MCPM"];
const PROCESSORS: usize = 8;
const COMPLEXES: usize = 2;
const CORES: usize = 4;
const OWNERS: usize = PROCESSORS + COMPLEXES;
const CPU_GROUP: usize = 5;
const PS_STRIDE: u64 = 8;
const PS_BUS_BASE: u64 = 0x3b70_0000;
const PS_BYTES: u64 = 0x000c_c000;
const PS_PHYSICAL_BASE: u64 = 0x2_3b70_0000;
const PERF_DOMAIN_BYTES: usize = 28;
const DEVICE_BYTES: usize = 48;
const DOMAIN_LIMIT: usize = 48;
const VIRTUAL: u8 = 1 << 4;
const PHYSICAL_AFFINITY: u64 = 0xffff;
const CORETYPE_SHIFT: u32 = 16;

type Error = CpuAssociationError;

fn property<'a>(node: &Node<'a>, name: &'static str) -> Result<Option<&'a [u8]>, Error> {
    let mut values = node
        .properties()
        .ok_or(Error::Malformed("ADT properties"))?
        .into_iter()
        .filter_map(|(key, value)| (key == name.as_bytes()).then_some(value));
    let value = values.next();
    if values.next().is_some() {
        return Err(Error::Malformed("duplicate ADT property"));
    }
    Ok(value)
}

fn required<'a>(node: &Node<'a>, name: &'static str) -> Result<&'a [u8], Error> {
    property(node, name)?.ok_or(Error::Malformed(name))
}

fn word(bytes: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| Error::Malformed("u32 cell"))?,
    ))
}

fn child<'a>(node: &Node<'a>, name: &[u8]) -> Result<Node<'a>, Error> {
    let mut found = None;
    for candidate in node.children().ok_or(Error::Malformed("ADT children"))? {
        let own = required(&candidate, "name")?;
        if own.strip_suffix(&[0]).unwrap_or(own) == name {
            if found.is_some() {
                return Err(Error::Malformed("duplicate structural ADT node"));
            }
            found = Some(candidate);
        }
    }
    found.ok_or(Error::Malformed("missing structural ADT node"))
}

pub(super) fn physical(io: &Node<'_>, address: u64, bytes: u64) -> Result<u64, Error> {
    let ranges = required(io, "ranges")?;
    if !ranges.len().is_multiple_of(24) || ranges.is_empty() {
        return Err(Error::Malformed("arm-io ranges"));
    }
    io.translate_range(address, bytes)
        .ok_or(Error::UnqualifiedGeometry(
            "unplaced, split or ambiguous complete PS range",
        ))
}

fn geometry(root: &Node<'_>, io: &Node<'_>, pmgr: &Node<'_>) -> Result<(), Error> {
    for node in [root, io] {
        if word(required(node, "#address-cells")?)? != 2
            || word(required(node, "#size-cells")?)? != 2
        {
            return Err(Error::UnqualifiedGeometry("bus cells"));
        }
    }
    if property(pmgr, "ps-groups")?.is_some() {
        return Err(Error::UnqualifiedGeometry("PMGR v2 groups"));
    }
    let registers = required(pmgr, "reg")?;
    let groups = required(pmgr, "ps-regs")?;
    if !registers.len().is_multiple_of(16)
        || registers.len() < 16
        || !groups.len().is_multiple_of(12)
        || groups.len() < (CPU_GROUP + 1) * 12
    {
        return Err(Error::Malformed("PMGR register/group cells"));
    }
    let first = &registers[..16];
    let base = u64::from_le_bytes(first[..8].try_into().unwrap());
    let bytes = u64::from_le_bytes(first[8..].try_into().unwrap());
    let group = &groups[CPU_GROUP * 12..(CPU_GROUP + 1) * 12];
    if (base, bytes) != (PS_BUS_BASE, PS_BYTES)
        || core::array::from_fn::<_, 3, _>(|i| {
            u32::from_le_bytes(group[i * 4..(i + 1) * 4].try_into().unwrap())
        }) != [0, 0, 0x3ff]
        || physical(io, base, OWNERS as u64 * PS_STRIDE)? != PS_PHYSICAL_BASE
    {
        return Err(Error::UnqualifiedGeometry("T8112 CPU PS bank"));
    }
    Ok(())
}

/// Returns [complex][local core] -> scheduler PE after matching the actual
/// original MPIDR consumer against both the ADT and the admitted CPU profile.
fn topology(
    root: &Node<'_>,
    processors: &[Identity],
) -> Result<[[usize; CORES]; COMPLEXES], Error> {
    let cpus = child(root, b"cpus")?;
    if word(required(&cpus, "#address-cells")?)? != 1 || word(required(&cpus, "#size-cells")?)? != 0
    {
        return Err(Error::Topology("CPU address cells"));
    }
    let nodes = cpus.children().ok_or(Error::Malformed("CPU children"))?;
    if nodes.len() != PROCESSORS || processors.len() != PROCESSORS {
        return Err(Error::Topology("T8112 eight-PE geometry"));
    }
    let mut result = [[usize::MAX; CORES]; COMPLEXES];
    for (pe, (node, identity)) in nodes.iter().zip(processors).enumerate() {
        let reg = word(required(node, "reg")?)?;
        let core = (reg & 3) as usize;
        let complex = (reg >> 8) as usize;
        if reg & !0x103 != 0
            || complex >= COMPLEXES
            || word(required(node, "cpu-id")?)? as usize != pe
            || word(required(node, "cluster-id")?)? as usize != complex
            || result[complex][core] != usize::MAX
        {
            return Err(Error::Topology("CPU affinity/ID membership"));
        }
        let kind = required(node, "cluster-type")?;
        let expected_kind = if complex == 0 { b"E\0" } else { b"P\0" };
        let expected_aff2 = complex as u64;
        if kind != expected_kind
            || identity.mpidr & PHYSICAL_AFFINITY != u64::from(reg)
            || identity.mpidr != (0x8000_0000 | expected_aff2 << CORETYPE_SHIFT | u64::from(reg))
        {
            return Err(Error::Topology(
                "CPU profile differs from original affinity",
            ));
        }
        result[complex][core] = pe;
    }
    if result.iter().flatten().any(|&pe| pe == usize::MAX) {
        return Err(Error::Topology("missing CPU member"));
    }
    Ok(result)
}

/// Resolve all ten positively qualified normal-mode CPU owners or refuse the
/// whole inventory. This neither binds participants nor chooses initial state.
/// `acc_harvesting` must be the separately qualified effective configuration,
/// including any start-time overrides. An absent ADT property alone only
/// establishes the original constructor default, not the effective setting.
pub fn resolve_cpu_power(
    chip: Chip,
    root: &Node<'_>,
    records: &[PmgrCpuRecord<'_>],
    processors: &[Identity],
    acc_harvesting: u32,
) -> Result<Vec<ProcessorAssociation>, Error> {
    if chip == Chip::AppleM1 {
        return t6000::resolve(root, records, processors, acc_harvesting);
    }
    if chip != Chip::AppleM2 {
        return Err(Error::UnsupportedChip(chip));
    }
    let io = child(root, b"arm-io")?;
    let pmgr = child(&io, b"pmgr")?;
    if required(&pmgr, "compatible")? != COMPATIBLE {
        return Err(Error::UnsupportedCompatible);
    }
    if acc_harvesting != 0 {
        return Err(Error::UnsupportedHarvesting(acc_harvesting));
    }
    if let Some(harvesting) = property(&pmgr, "acc-harvesting")? {
        let harvesting = word(harvesting)?;
        if harvesting != acc_harvesting {
            return Err(Error::ConflictingHarvesting);
        }
    }
    geometry(root, &io, &pmgr)?;
    let pes = topology(root, processors)?;
    let descriptors = required(&pmgr, "perf-domains")?;
    if descriptors.is_empty() || !descriptors.len().is_multiple_of(PERF_DOMAIN_BYTES) {
        return Err(Error::Malformed("perf-domains entries"));
    }
    let mut domains = [false; DOMAIN_LIMIT];
    let mut complexes = [None; DOMAIN_LIMIT];
    let mut complex_count = 0;
    for descriptor in descriptors.as_chunks::<PERF_DOMAIN_BYTES>().0 {
        let id = usize::from(descriptor[3]);
        if id == 0 || id >= DOMAIN_LIMIT || domains[id] {
            return Err(Error::Malformed("perf-domain ID lookup"));
        }
        domains[id] = true;
        if descriptor[2] == 1 {
            if complex_count == COMPLEXES {
                return Err(Error::UnqualifiedGeometry("extra CPU complex"));
            }
            complexes[id] = Some(complex_count);
            complex_count += 1;
        }
    }
    if complex_count != COMPLEXES {
        return Err(Error::IncompleteOwners);
    }
    let raw = required(&pmgr, "devices")?;
    if !raw.len().is_multiple_of(DEVICE_BYTES) || raw.len() / DEVICE_BYTES != records.len() {
        return Err(Error::Malformed("complete PMGR record views"));
    }
    let mut ids = BTreeSet::new();
    let mut members: [Vec<usize>; COMPLEXES] = core::array::from_fn(|_| Vec::new());
    let mut cpm = [None; COMPLEXES];
    let mut virtuals = [false; COMPLEXES];
    let mut output = Vec::with_capacity(OWNERS);
    let mut physical_owners = BTreeSet::new();
    for (index, (raw, view)) in raw
        .as_chunks::<DEVICE_BYTES>()
        .0
        .iter()
        .zip(records)
        .enumerate()
    {
        let parsed = Record::parse(Layout::V1, raw).map_err(Error::Malformed)?;
        if view.id.die != 0 {
            return Err(Error::UnsupportedDie(view.id.die));
        }
        if view.id.device == 0 || !ids.insert(view.id) {
            return Err(Error::DuplicateDomain(view.id));
        }
        if view.id.device != parsed.id
            || view.flags != raw[0]
            || view.perf_domain != raw[2]
            || view.name != parsed.name
            || view.location.map(|v| (v.group, v.index))
                != parsed.location.map(|v| (v.group, v.index))
        {
            return Err(Error::RecordMismatch(index));
        }
        let id = usize::from(view.perf_domain);
        if id != 0 && (id >= DOMAIN_LIMIT || !domains[id]) {
            return Err(Error::UnknownPerfDomain(view.id));
        }
        let Some(complex) = complexes.get(id).copied().flatten() else {
            continue;
        };
        // Only the original die-0, non-replicated CPU records are qualified.
        // In particular byte 25 is not converted into an Aff1 cluster number.
        // Other flags/replication/cluster selectors need their own source
        // contract, even when the normalized caller ID says die 0.
        if ![0, VIRTUAL].contains(&view.flags) || raw[1] != 0 || raw[15] != 0 || raw[25] != 0 {
            return Err(Error::UnqualifiedGeometry(
                "CPU record flags or die selectors",
            ));
        }
        if view.flags & VIRTUAL != 0 {
            if core::mem::replace(&mut virtuals[complex], true) {
                return Err(Error::IncompleteOwners);
            }
            continue;
        }
        let location = view.location.ok_or(Error::RecordMismatch(index))?;
        let is_core = CORE_PREFIXES
            .iter()
            .any(|prefix| view.name.starts_with(prefix));
        let slot = if is_core {
            let core = members[complex].len();
            if core >= CORES || output.len() >= PROCESSORS {
                return Err(Error::UnqualifiedGeometry("extra or reordered CPU core"));
            }
            let pe = pes[complex][core];
            // This explicit placement coupling is qualified for T8112;
            // a different table/PS relationship must not inherit it.
            if pe != output.len() {
                return Err(Error::Topology("core table order differs from PE IDs"));
            }
            members[complex].push(pe);
            pe
        } else {
            if !CPM_PREFIXES
                .iter()
                .any(|prefix| view.name.starts_with(prefix))
            {
                return Err(Error::UnknownCpuProtocol(view.id));
            }
            if members[complex].len() != CORES || cpm[complex].replace(view.id).is_some() {
                return Err(Error::IncompleteOwners);
            }
            PROCESSORS + complex
        };
        let address = PS_PHYSICAL_BASE + slot as u64 * PS_STRIDE;
        if location.group != CPU_GROUP
            || location.index as usize != slot
            || location.address != address
        {
            return Err(Error::UnqualifiedGeometry("CPU owner PS placement"));
        }
        if !physical_owners.insert(address) {
            return Err(Error::ConflictingAddress(address));
        }
        output.push(ProcessorAssociation {
            domain: view.id,
            address,
            target: if is_core {
                ProcessorTarget::Core { pe: slot }
            } else {
                ProcessorTarget::Cluster {
                    members: members[complex].clone(),
                }
            },
            evidence: CPU_POWER_EVIDENCE,
        });
    }
    if output.len() != OWNERS
        || members.iter().any(|m| m.len() != CORES)
        || cpm.iter().any(Option::is_none)
        || virtuals.iter().any(|&present| !present)
    {
        return Err(Error::IncompleteOwners);
    }
    for record in records {
        if let Some(location) = record.location
            && physical_owners.contains(&location.address)
            && !output.iter().any(|owner| owner.domain == record.id)
        {
            return Err(Error::ConflictingAddress(location.address));
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};

    type Properties = Vec<(&'static str, Vec<u8>)>;

    fn encode(properties: &Properties, children: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend((properties.len() as u32).to_le_bytes());
        bytes.extend((children.len() as u32).to_le_bytes());
        for (key, value) in properties {
            let mut name = [0; 32];
            name[..key.len()].copy_from_slice(key.as_bytes());
            bytes.extend(name);
            bytes.extend((value.len() as u32).to_le_bytes());
            bytes.extend(value);
            bytes.resize(bytes.len().next_multiple_of(4), 0);
        }
        bytes.extend(children.iter().flatten());
        bytes
    }

    fn set(properties: &mut Properties, key: &'static str, value: Vec<u8>) {
        if let Some((_, original)) = properties.iter_mut().find(|(name, _)| *name == key) {
            *original = value;
        } else {
            properties.push((key, value));
        }
    }

    fn cells32(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn cells64(values: &[u64]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn record(id: u16, perf: u8, slot: u8, name: &str, virtual_: bool) -> [u8; DEVICE_BYTES] {
        let mut raw = [0; DEVICE_BYTES];
        raw[0] = if virtual_ { VIRTUAL } else { 0 };
        raw[2] = perf;
        raw[10] = slot;
        raw[11] = CPU_GROUP as u8;
        raw[26..28].copy_from_slice(&id.to_le_bytes());
        raw[32..32 + name.len()].copy_from_slice(name.as_bytes());
        raw
    }

    fn views(raw: &[[u8; DEVICE_BYTES]]) -> Vec<PmgrCpuRecord<'_>> {
        raw.iter()
            .map(|raw| {
                let parsed = Record::parse(Layout::V1, raw).unwrap();
                PmgrCpuRecord {
                    id: DomainId {
                        die: 0,
                        device: parsed.id,
                    },
                    flags: raw[0],
                    perf_domain: raw[2],
                    name: parsed.name,
                    location: parsed.location.map(|v| PmgrCpuLocation {
                        group: v.group,
                        index: v.index,
                        address: if v.group == CPU_GROUP {
                            PS_PHYSICAL_BASE
                        } else {
                            0x2_4000_0000
                        } + u64::from(v.index) * PS_STRIDE,
                    }),
                }
            })
            .collect()
    }

    struct Fixture {
        root: Properties,
        io: Properties,
        pmgr: Properties,
        cpus: Vec<Properties>,
        identities: Vec<Identity>,
        records: Vec<[u8; DEVICE_BYTES]>,
        descriptors: Vec<[u8; PERF_DOMAIN_BYTES]>,
    }

    impl Fixture {
        fn new() -> Self {
            let cells = || {
                vec![
                    ("#address-cells", cells32(&[2])),
                    ("#size-cells", cells32(&[2])),
                ]
            };
            let mut root = cells();
            root.push(("name", b"device-tree\0".to_vec()));
            let mut io = cells();
            io.extend([
                ("name", b"arm-io\0".to_vec()),
                ("ranges", cells64(&[0, 0x2_0000_0000, 0x1_0000_0000])),
            ]);
            let mut groups = vec![0; (CPU_GROUP + 1) * 12];
            groups[CPU_GROUP * 12..].copy_from_slice(&cells32(&[0, 0, 0x3ff]));
            groups[..12].copy_from_slice(&cells32(&[1, 0, 0x3ff]));
            let pmgr = vec![
                ("name", b"pmgr\0".to_vec()),
                ("compatible", COMPATIBLE.to_vec()),
                (
                    "reg",
                    cells64(&[PS_BUS_BASE, PS_BYTES, 0x4000_0000, PS_BYTES]),
                ),
                ("ps-regs", groups),
            ];
            let mut cpus = Vec::new();
            let mut identities = Vec::new();
            let mut records = Vec::new();
            for pe in 0..PROCESSORS {
                let complex = pe / CORES;
                let reg = ((complex as u32) << 8) | (pe % CORES) as u32;
                let kind = if complex == 0 { b"E\0" } else { b"P\0" };
                cpus.push(vec![
                    ("name", format!("cpu{pe}\0").into_bytes()),
                    ("reg", cells32(&[reg])),
                    ("cpu-id", cells32(&[pe as u32])),
                    ("cluster-id", cells32(&[complex as u32])),
                    ("cluster-type", kind.to_vec()),
                ]);
                identities.push(Identity {
                    midr: 0, // MPIDR membership alone is under test.
                    mpidr: 0x8000_0000 | (complex as u64) << CORETYPE_SHIFT | u64::from(reg),
                    clock: None,
                    caches: None,
                });
                records.push(record(
                    pe as u16 + 1,
                    if complex == 0 { 2 } else { 5 },
                    pe as u8,
                    &format!("{}CPU{}", if complex == 0 { "E" } else { "P" }, pe % CORES),
                    false,
                ));
            }
            for (complex, perf) in [(0, 2), (1, 5)] {
                records.push(record(
                    9 + complex as u16,
                    perf,
                    (8 + complex) as u8,
                    if complex == 0 { "ECPM" } else { "PCPM" },
                    false,
                ));
            }
            // Real CPU-complex virtual IDs are distinct from physical CPM IDs.
            records.push(record(0x163, 2, 0, "ECPM_NRG", true));
            records.push(record(0x164, 5, 0, "PCPM_NRG", true));
            let mut other = record(0x200, 1, 0, "SOC", false);
            other[11] = 0;
            records.push(other);
            let descriptors = [(1, 0), (2, 1), (5, 1)]
                .map(|(id, cpu)| {
                    let mut raw = [0; PERF_DOMAIN_BYTES];
                    raw[2] = cpu;
                    raw[3] = id;
                    raw
                })
                .to_vec();
            Self {
                root,
                io,
                pmgr,
                cpus,
                identities,
                records,
                descriptors,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            let mut pmgr = self.pmgr.clone();
            pmgr.push(("devices", self.records.iter().flatten().copied().collect()));
            pmgr.push((
                "perf-domains",
                self.descriptors.iter().flatten().copied().collect(),
            ));
            let io = encode(&self.io, &[encode(&pmgr, &[])]);
            let cpus = encode(
                &vec![
                    ("name", b"cpus\0".to_vec()),
                    ("#address-cells", cells32(&[1])),
                    ("#size-cells", cells32(&[0])),
                ],
                &self.cpus.iter().map(|p| encode(p, &[])).collect::<Vec<_>>(),
            );
            encode(&self.root, &[io, cpus])
        }

        fn resolve(&self) -> Result<Vec<ProcessorAssociation>, Error> {
            let bytes = self.bytes();
            resolve_cpu_power(
                Chip::AppleM2,
                &Node::root(&bytes).unwrap(),
                &views(&self.records),
                &self.identities,
                0,
            )
        }
    }

    fn canonical_states(root: &Node<'_>) -> super::super::PowerStates {
        let io = root.child("arm-io").unwrap();
        let pmgr = io.child("pmgr").unwrap();
        let dies = super::super::Dies::of(root, &pmgr).unwrap();
        let table = super::super::decode_domain_table(&pmgr, dies, &|address, bytes| {
            physical(&io, address, bytes).ok()
        })
        .unwrap();
        super::super::PowerStates {
            blocks: table.blocks,
            registers: table.registers,
            domains: table.domains,
            resources: Vec::new(),
            implicit: Vec::new(),
        }
    }

    #[test]
    fn parent_adapter_rechecks_the_entire_canonical_inventory_before_cpu_ownership() {
        let fixture = Fixture::new();
        let bytes = fixture.bytes();
        let root = Node::root(&bytes).unwrap();
        let states = canonical_states(&root);
        let expected = fixture.resolve().unwrap();
        assert_eq!(
            states.processor_associations(Chip::AppleM2, &root, &fixture.identities, 0),
            Ok(expected)
        );
        for mutation in 0..6 {
            let mut changed = states.clone();
            match mutation {
                0 => changed.domains[0].address = Some(PS_PHYSICAL_BASE + PS_STRIDE),
                1 => changed.domains.last_mut().unwrap().address = Some(PS_PHYSICAL_BASE),
                2 => changed.domains[0].parents[0] = Some(DomainId { die: 0, device: 9 }),
                3 => changed.domains[0].id.device = 0x700,
                4 => changed.blocks[0].1 += 4,
                _ => {
                    changed.registers.pop().unwrap();
                }
            }
            assert!(
                changed
                    .processor_associations(Chip::AppleM2, &root, &fixture.identities, 0)
                    .is_err(),
                "mutation {mutation} bypassed canonical source identity"
            );
        }
    }

    #[test]
    fn normal_mode_binds_physical_cores_and_cpm_members_only() {
        let owners = Fixture::new().resolve().unwrap();
        assert_eq!(owners.len(), OWNERS);
        for (slot, owner) in owners.iter().enumerate() {
            assert_eq!(
                owner.domain,
                DomainId {
                    die: 0,
                    device: slot as u16 + 1
                }
            );
            assert_eq!(owner.address, PS_PHYSICAL_BASE + slot as u64 * PS_STRIDE);
            assert_eq!(owner.evidence, CPU_POWER_EVIDENCE);
            assert_eq!(
                owner.target,
                if slot < PROCESSORS {
                    ProcessorTarget::Core { pe: slot }
                } else {
                    let start = (slot - PROCESSORS) * CORES;
                    ProcessorTarget::Cluster {
                        members: (start..start + CORES).collect(),
                    }
                }
            );
        }
        assert!(
            !owners
                .iter()
                .any(|o| [0x163, 0x164, 0x200].contains(&o.domain.device))
        );
    }

    #[test]
    fn original_protocol_prefix_does_not_parse_numeric_names_or_assume_fixed_device_ids() {
        let mut f = Fixture::new();
        for (i, raw) in f.records.iter_mut().take(OWNERS).enumerate() {
            raw[26..28].copy_from_slice(&(0x400 + i as u16).to_le_bytes());
            raw[32..].fill(0);
            let name = if i < PROCESSORS { "MCPU999" } else { "MCPM99" };
            raw[32..32 + name.len()].copy_from_slice(name.as_bytes());
        }
        let result = f.resolve().unwrap();
        assert_eq!(result[0].target, ProcessorTarget::Core { pe: 0 });
        assert_eq!(result[7].target, ProcessorTarget::Core { pe: 7 });
        assert_eq!(result[8].domain.device, 0x408);
        assert_eq!(
            result[9].target,
            ProcessorTarget::Cluster {
                members: vec![4, 5, 6, 7]
            }
        );
    }

    #[test]
    fn different_chips_compatibles_or_effective_modes_never_inherit_normal_mode() {
        let f = Fixture::new();
        let bytes = f.bytes();
        let root = Node::root(&bytes).unwrap();
        let views = views(&f.records);
        for chip in [Chip::AppleM3, Chip::AppleM4, Chip::AppleM5, Chip::AppleM6] {
            assert_eq!(
                resolve_cpu_power(chip, &root, &views, &f.identities, 0),
                Err(Error::UnsupportedChip(chip))
            );
        }
        assert_eq!(
            resolve_cpu_power(Chip::AppleM1, &root, &views, &f.identities, 0),
            Err(Error::UnsupportedCompatible)
        );
        for mode in [1, 2, u32::MAX] {
            assert_eq!(
                resolve_cpu_power(Chip::AppleM2, &root, &views, &f.identities, mode),
                Err(Error::UnsupportedHarvesting(mode))
            );
        }
        for compatible in [
            b"pmgr1,t8110\0".as_slice(),
            b"pmgr2,t8112\0",
            b"pmgr1,t8112\0pmgr1\0",
        ] {
            let mut f = Fixture::new();
            set(&mut f.pmgr, "compatible", compatible.to_vec());
            assert_eq!(f.resolve(), Err(Error::UnsupportedCompatible));
        }
        let mut f = Fixture::new();
        set(&mut f.pmgr, "acc-harvesting", cells32(&[0]));
        assert!(f.resolve().is_ok());
        set(&mut f.pmgr, "acc-harvesting", cells32(&[1]));
        assert_eq!(f.resolve(), Err(Error::ConflictingHarvesting));
        set(&mut f.pmgr, "acc-harvesting", vec![0]);
        assert_eq!(f.resolve(), Err(Error::Malformed("u32 cell")));
    }

    #[test]
    fn all_record_views_must_keep_complete_original_provenance() {
        let f = Fixture::new();
        let bytes = f.bytes();
        let root = Node::root(&bytes).unwrap();
        let original = views(&f.records);
        for field in 0..6 {
            let mut changed = original.clone();
            match field {
                0 => changed[7].id.device += 100,
                1 => changed[7].flags ^= 1,
                2 => changed[7].perf_domain = 1,
                3 => changed[7].name = "PCPU0",
                4 => changed[7].location.as_mut().unwrap().group = 1,
                _ => changed[7].location.as_mut().unwrap().index = 0,
            }
            assert_eq!(
                resolve_cpu_power(Chip::AppleM2, &root, &changed, &f.identities, 0),
                Err(Error::RecordMismatch(7))
            );
        }
        assert_eq!(
            resolve_cpu_power(Chip::AppleM2, &root, &original[..12], &f.identities, 0),
            Err(Error::Malformed("complete PMGR record views"))
        );
        let mut changed = original.clone();
        changed[9].id.die = 1;
        assert_eq!(
            resolve_cpu_power(Chip::AppleM2, &root, &changed, &f.identities, 0),
            Err(Error::UnsupportedDie(1))
        );
        changed = original.clone();
        changed[9].location.as_mut().unwrap().address += 8;
        assert_eq!(
            resolve_cpu_power(Chip::AppleM2, &root, &changed, &f.identities, 0),
            Err(Error::UnqualifiedGeometry("CPU owner PS placement"))
        );
        // A later non-CPU physical alias invalidates the entire result.
        changed = original;
        changed[12].location.as_mut().unwrap().address = PS_PHYSICAL_BASE;
        assert_eq!(
            resolve_cpu_power(Chip::AppleM2, &root, &changed, &f.identities, 0),
            Err(Error::ConflictingAddress(PS_PHYSICAL_BASE))
        );
    }

    #[test]
    fn malformed_duplicate_or_incomplete_source_tables_never_return_partial_owners() {
        for mutation in 0..7 {
            let mut f = Fixture::new();
            match mutation {
                0 => {
                    f.records.pop();
                    f.records.pop();
                } // Missing P virtual ID.
                1 => {
                    f.records.remove(7);
                }
                2 => f.records[8][26..28].copy_from_slice(&1u16.to_le_bytes()),
                3 => {
                    f.descriptors.push(f.descriptors[1]);
                }
                4 => f.descriptors[1][2] = 0,
                5 => f.records[7][2] = 47,
                _ => {
                    f.records[9][32..].fill(0);
                    f.records[9][32..37].copy_from_slice(b"OTHER");
                }
            }
            assert!(f.resolve().is_err(), "mutation {mutation} returned owners");
        }
        let mut f = Fixture::new();
        f.descriptors.swap(1, 2);
        assert_eq!(
            f.resolve(),
            Err(Error::Topology("core table order differs from PE IDs"))
        );
        let mut f = Fixture::new();
        f.records.swap(0, 1);
        assert_eq!(
            f.resolve(),
            Err(Error::UnqualifiedGeometry("CPU owner PS placement"))
        );
        for field in [0, 1, 15, 25] {
            let mut f = Fixture::new();
            f.records[7][field] = 1;
            assert_eq!(
                f.resolve(),
                Err(Error::UnqualifiedGeometry(
                    "CPU record flags or die selectors"
                ))
            );
        }
    }

    #[test]
    fn adt_and_live_profile_affinities_must_agree_for_every_pe() {
        for mutation in 0..7 {
            let mut f = Fixture::new();
            match mutation {
                0 => f.identities[7].mpidr ^= 1 << CORETYPE_SHIFT,
                1 => f.identities[7].mpidr ^= 1 << 8,
                2 => {
                    f.identities.pop();
                }
                3 => set(&mut f.cpus[7], "reg", cells32(&[0x102])),
                4 => set(&mut f.cpus[7], "cluster-id", cells32(&[0])),
                5 => set(&mut f.cpus[7], "cpu-id", cells32(&[6])),
                _ => set(&mut f.cpus[7], "cluster-type", b"M\0".to_vec()),
            }
            assert!(
                matches!(f.resolve(), Err(Error::Topology(_))),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn source_geometry_requires_unambiguous_complete_bus_translation() {
        for mutation in 0..7 {
            let mut f = Fixture::new();
            match mutation {
                0 => set(&mut f.root, "#address-cells", cells32(&[1])),
                1 => set(&mut f.pmgr, "reg", cells64(&[PS_BUS_BASE, PS_BYTES - 8])),
                2 => set(&mut f.pmgr, "ps-groups", vec![]),
                3 => set(
                    &mut f.io,
                    "ranges",
                    cells64(&[0, 0x3_0000_0000, 0x1_0000_0000]),
                ),
                4 => set(
                    &mut f.io,
                    "ranges",
                    cells64(&[0, 0x2_0000_0000, PS_BUS_BASE + 8]),
                ),
                5 => set(
                    &mut f.io,
                    "ranges",
                    cells64(&[
                        0,
                        0x2_0000_0000,
                        0x1_0000_0000,
                        // An overlapping row that translates the same
                        // bytes elsewhere.
                        PS_BUS_BASE,
                        PS_PHYSICAL_BASE + 0x1000,
                        80,
                    ]),
                ),
                _ => set(&mut f.io, "ranges", cells64(&[u64::MAX - 1, 0, 10])),
            }
            assert!(
                matches!(f.resolve(), Err(Error::UnqualifiedGeometry(_))),
                "mutation {mutation}"
            );
        }
        let mut f = Fixture::new();
        f.pmgr.push(("compatible", COMPATIBLE.to_vec()));
        assert_eq!(f.resolve(), Err(Error::Malformed("duplicate ADT property")));
        set(&mut f.io, "ranges", vec![0; 23]);
        f.pmgr.pop();
        assert_eq!(f.resolve(), Err(Error::Malformed("arm-io ranges")));
    }

    #[test]
    #[ignore = "requires pinned original 26A434 J473 DeviceTree and kernelcache"]
    fn original_j473_views_resolve_all_ten_source_constructed_owners() {
        use sha2::{Digest, Sha256};
        let tree = std::fs::read(std::env::var("STELA_TEST_CPU_PMGR_ADT").unwrap()).unwrap();
        let kernel = std::fs::read(std::env::var("STELA_TEST_PMGR_KERNEL").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&tree)),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&kernel)),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        let root = Node::root(&tree).unwrap();
        let io = root.child("arm-io").unwrap();
        let pmgr = io.child("pmgr").unwrap();
        assert!(pmgr.property("acc-harvesting").is_none());
        let raw = pmgr
            .property("devices")
            .unwrap()
            .as_chunks::<DEVICE_BYTES>()
            .0;
        let mut records = views(raw);
        // Normalize with the original bank/group/index cells, as the parent
        // inventory does, including every non-CPU record and physical alias.
        let banks = pmgr.pairs("reg").unwrap();
        let groups = pmgr.property("ps-regs").unwrap().as_chunks::<12>().0;
        for record in &mut records {
            if let Some(location) = &mut record.location {
                let group = groups[location.group];
                let bank = word(&group[..4]).unwrap() as usize;
                let offset = u64::from(word(&group[4..8]).unwrap());
                let address = banks[bank].0 + offset + u64::from(location.index) * PS_STRIDE;
                location.address = physical(&io, address, PS_STRIDE).unwrap();
            }
        }
        let processors = root
            .child("cpus")
            .unwrap()
            .children()
            .unwrap()
            .into_iter()
            .map(|node| crate::machine::soc::Processor {
                cluster_type: node.property("cluster-type").unwrap()[0],
                reg: node.first_u32("reg").unwrap(),
                l2_bytes: node.first_u32("l2-cache-size"),
            })
            .collect::<Vec<_>>();
        let cpus = crate::machine::soc::cpus(0x8112, "Apple M2", &processors).unwrap();
        let result = resolve_cpu_power(cpus.chip, &root, &records, &cpus.processors, 0).unwrap();
        assert_eq!(records.len(), 303);
        assert_eq!(result, Fixture::new().resolve().unwrap());
        let states = canonical_states(&root);
        assert_eq!(
            states.processor_associations(cpus.chip, &root, &cpus.processors, 0),
            Ok(result.clone())
        );
        let mut changed = states;
        changed.domains.last_mut().unwrap().address = Some(PS_PHYSICAL_BASE);
        assert!(
            changed
                .processor_associations(cpus.chip, &root, &cpus.processors, 0)
                .is_err()
        );
        // Source-integrity witnesses pin actual normal-mode constructor and
        // consumer instruction spans, independently of synthetic fixtures.
        for (offset, count, expected) in [
            (
                0x2b74a1c,
                0x144,
                "6d728b4eb130366f8381e62f43954dc48042cbefb01d9abd5991c2c52969a2ec",
            ),
            (
                0x2b75078,
                0x104,
                "0c2d7e2eae2e665e662a7e3a6c49bb7813b3b7ef93d82ca6ea8b55a39cbdc905",
            ),
            (
                0x2ba0598,
                0x74,
                "de77b6de0abc4f9ba34e1139eadac75b2bf6549315aebe7a2851797a17f398b3",
            ),
            (
                0x2b81fb4,
                0x90,
                "9a4aa4df5efad86db88697d52edd4ec602a6a1ee9eafff8f6534a78cf9d1726d",
            ),
            (
                0x2ba2c88,
                0x48,
                "eecea147f97d3d915199ad0120a5e5670f5cd860b0705cc335cc344fc053a0f2",
            ),
        ] {
            assert_eq!(
                hex::encode(Sha256::digest(&kernel[offset..offset + count])),
                expected
            );
        }
    }
}
