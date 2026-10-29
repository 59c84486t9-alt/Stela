//! Source-checked CPU ownership, independent of lifecycle state or admission.
//!
//! Original 26A434 T8112 normal-mode MPIDR/idle callbacks and T6000 mode1
//! constructor counters establish separate membership rules. See apple-socs.md's
//! J473 proof and the T6000 source module. No input hash or board name dispatches
//! production behavior, and no numeric suffix of a record name selects a PE.
mod t6000;

use super::records::{Layout, Record};
use crate::pmgr::coverage::DomainId;
use alloc::{collections::BTreeSet, vec::Vec};
use stela_contracts::Chip;
use stela_contracts::adt::Node;
use stela_contracts::identity::Identity;
use stela_contracts::processor::ProcessorTarget;

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
/// The caller must separately check and supply its initial LifecycleState.
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
    Ok(())
}

/// The physical address of PS register `index` in `ps-regs` group `group`:
/// the group names a `reg` range, an offset in it and a mask of the indices
/// it holds, and `arm-io` translates the range.
fn ps_address(io: &Node<'_>, pmgr: &Node<'_>, group: usize, index: u32) -> Result<u64, Error> {
    let groups = required(pmgr, "ps-regs")?;
    let registers = required(pmgr, "reg")?;
    if !groups.len().is_multiple_of(12) || !registers.len().is_multiple_of(16) || index >= 32 {
        return Err(Error::Malformed("PS location cells"));
    }
    let group = groups
        .as_chunks::<12>()
        .0
        .get(group)
        .ok_or(Error::UnqualifiedGeometry("PS group"))?;
    let reg = word(&group[..4])? as usize;
    let offset = u64::from(word(&group[4..8])?) + u64::from(index) * PS_STRIDE;
    if word(&group[8..])? & (1u32 << index) == 0 {
        return Err(Error::UnqualifiedGeometry("PS mask"));
    }
    let range = registers
        .as_chunks::<16>()
        .0
        .get(reg)
        .ok_or(Error::UnqualifiedGeometry("PS register"))?;
    let base = u64::from_le_bytes(range[..8].try_into().unwrap());
    let bytes = u64::from_le_bytes(range[8..].try_into().unwrap());
    if offset.checked_add(PS_STRIDE).is_none_or(|end| end > bytes) {
        return Err(Error::UnqualifiedGeometry("PS extent"));
    }
    physical(
        io,
        base.checked_add(offset)
            .ok_or(Error::UnqualifiedGeometry("PS wraps"))?,
        PS_STRIDE,
    )
}

/// Returns [complex][local core] -> scheduler PE after matching the
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

/// Resolve all ten positively checked normal-mode CPU owners or refuse the
/// whole inventory. This neither binds participants nor chooses initial state.
/// `acc_harvesting` must be the separately checked effective configuration,
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
        // Only the original die-0, non-replicated CPU records are checked.
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
            // This explicit placement coupling is checked for T8112;
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
        let address = location.address;
        if location.group != CPU_GROUP
            || location.index as usize != slot
            || address != ps_address(&io, &pmgr, location.group, location.index)?
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
mod tests;
