//! Original T6000 normal mode1 constructor membership, not lifecycle state.
//! mac13j SHA5109fca5...979af90: complex file2b16e08..16f68;
//! core2b190e4..19228; skip2b19918..19a20; enable2b2dcb0.
//! Full source order must match kernel cluster/core discovery, independently
//! of boot/native worker identity. No source-name suffix selects a member.
use super::*;
use alloc::vec;

// Pinned mac13j kernel topology capacities, not observed SKU counts.
const T6000_KERNEL_MAX_CPUS: usize = 20;
const T6000_KERNEL_MAX_CLUSTERS: usize = 6;
const T6000_KERNEL_MAX_PHYSICAL_CLUSTER: u32 = 10;
const AFFINITY_PART_MASK: u32 = 0xff;
const CLUSTER_SHIFT: u32 = 8;
const MPIDR_RES1: u64 = 1 << 31;
const ENABLE_CORE_SELECTOR: u32 = 0x436f_7265;

pub(super) const EVIDENCE: &str = "26A434 mac13j SHA256 5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90; mode1 complex2b16e08/core2b190e4/skip2b19918, enable2b2dcb0; cpu/t6000-core-membership-r1 source receipt";

pub(super) fn resolve(
    root: &Node<'_>,
    records: &[PmgrCpuRecord<'_>],
    processors: &[Identity],
    harvesting: u32,
) -> Result<Vec<ProcessorAssociation>, Error> {
    let io = child(root, b"arm-io")?;
    let pmgr = child(&io, b"pmgr")?;
    if required(&pmgr, "compatible")? != b"pmgr1,t6000\0"
        || required(&io, "compatible")? != b"arm-io,t6000\0"
    {
        return Err(Error::UnsupportedCompatible);
    }
    if harvesting != 1 {
        return Err(Error::UnsupportedHarvesting(harvesting));
    }
    if word(required(&pmgr, "acc-harvesting")?)? != harvesting {
        return Err(Error::ConflictingHarvesting);
    }
    for node in [root, &io] {
        if word(required(node, "#address-cells")?)? != 2
            || word(required(node, "#size-cells")?)? != 2
        {
            return Err(Error::UnqualifiedGeometry("T6000 bus cells"));
        }
    }
    if property(&pmgr, "ps-groups")?.is_some() {
        return Err(Error::UnqualifiedGeometry("T6000 PMGR v2 groups"));
    }
    let cpus = child(root, b"cpus")?;
    if word(required(&cpus, "#address-cells")?)? != 1 || word(required(&cpus, "#size-cells")?)? != 0
    {
        return Err(Error::Topology("T6000 CPU address cells"));
    }
    let nodes = cpus.children().ok_or(Error::Malformed("CPU children"))?;
    if nodes.is_empty() || nodes.len() != processors.len() || nodes.len() > T6000_KERNEL_MAX_CPUS {
        return Err(Error::Topology("T6000 complete original CPU envelope"));
    }
    let mut members: Vec<Vec<usize>> = Vec::new();
    for (pe, (node, identity)) in nodes.iter().zip(processors).enumerate() {
        let reg = word(required(node, "reg")?)?;
        let aff1 = (reg >> CLUSTER_SHIFT) as usize;
        if u64::from(reg) & !PHYSICAL_AFFINITY != 0
            || reg >> CLUSTER_SHIFT > T6000_KERNEL_MAX_PHYSICAL_CLUSTER
        {
            return Err(Error::Topology("T6000 physical affinity"));
        }
        if members.len() == aff1 {
            members.push(Vec::new());
        }
        if let Some(last) = nodes[..pe].last()
            && word(required(last, "reg")?)? >> CLUSTER_SHIFT > reg >> CLUSTER_SHIFT
        {
            return Err(Error::Topology("T6000 reordered source cluster"));
        }
        let Some(cluster) = members.get_mut(aff1) else {
            return Err(Error::Topology("T6000 missing earlier physical cluster"));
        };
        // Mode1 counters enumerate source records. Holes/reordered clusters
        // cannot inherit a dense ordinal/Aff0 or original enable-mask join.
        if (reg & AFFINITY_PART_MASK) as usize != cluster.len() {
            return Err(Error::Topology("T6000 cluster/core source order"));
        }
        let kind = required(node, "cluster-type")?;
        if let Some(&first) = cluster.first()
            && required(&nodes[first], "cluster-type")? != kind
        {
            return Err(Error::Topology("T6000 mixed core kinds in a complex"));
        }
        let aff2 = match kind {
            b"E\0" => 0,
            b"P\0" => 1,
            _ => return Err(Error::Topology("T6000 CPU kind")),
        };
        if word(required(node, "cpu-id")?)? as usize != pe
            || word(required(node, "cluster-id")?)? as usize != aff1
            || word(required(node, "die-id")?)? != 0
            || word(required(node, "die-cluster-id")?)? as usize != aff1
            || word(required(node, "cluster-core-id")?)? != reg & AFFINITY_PART_MASK
            || identity.mpidr != (MPIDR_RES1 | (aff2 << CORETYPE_SHIFT) | u64::from(reg))
        {
            return Err(Error::Topology("T6000 source/profile coordinate mismatch"));
        }
        let enable = required(node, "function-enable_core")?;
        if enable.len() != 12
            || word(&enable[..4])? != word(required(&pmgr, "AAPL,phandle")?)?
            || word(&enable[4..8])? != ENABLE_CORE_SELECTOR
            || word(&enable[8..])? != 1u32 << pe
        {
            return Err(Error::Topology("T6000 original enable_core global ordinal"));
        }
        cluster.push(pe);
    }
    if members.len() > T6000_KERNEL_MAX_CLUSTERS {
        return Err(Error::Topology("T6000 kernel cluster capacity"));
    }
    let descriptors = required(&pmgr, "perf-domains")?;
    if descriptors.is_empty() || !descriptors.len().is_multiple_of(PERF_DOMAIN_BYTES) {
        return Err(Error::Malformed("T6000 perf descriptors"));
    }
    let mut ids = BTreeSet::new();
    let mut complexes = Vec::new();
    for row in descriptors.as_chunks::<PERF_DOMAIN_BYTES>().0 {
        if row[3] == 0 || usize::from(row[3]) >= DOMAIN_LIMIT || !ids.insert(row[3]) {
            return Err(Error::Malformed("T6000 perf-domain lookup"));
        }
        if row[2] == 1 {
            complexes.push(row[3]);
        }
    }
    if complexes.len() != members.len() {
        return Err(Error::Topology("T6000 perf/kernel cluster order envelope"));
    }
    let raw = required(&pmgr, "devices")?;
    if !raw.len().is_multiple_of(DEVICE_BYTES) || raw.len() / DEVICE_BYTES != records.len() {
        return Err(Error::Malformed("T6000 complete record views"));
    }
    let mut domains = BTreeSet::new();
    let mut physical = BTreeSet::new();
    let mut core_counts = vec![0usize; members.len()];
    let mut cpm = vec![false; members.len()];
    let mut virtuals = vec![false; members.len()];
    let mut global = 0;
    let mut output = Vec::new();
    for (index, (row, view)) in raw
        .as_chunks::<DEVICE_BYTES>()
        .0
        .iter()
        .zip(records)
        .enumerate()
    {
        let parsed = Record::parse(Layout::V1, row).map_err(Error::Malformed)?;
        if view.id.die != 0 {
            return Err(Error::UnsupportedDie(view.id.die));
        }
        if view.id.device == 0 || !domains.insert(view.id) {
            return Err(Error::DuplicateDomain(view.id));
        }
        if view.id.device != parsed.id
            || view.flags != row[0]
            || view.perf_domain != row[2]
            || view.name != parsed.name
            || view.location.map(|v| (v.group, v.index))
                != parsed.location.map(|v| (v.group, v.index))
        {
            return Err(Error::RecordMismatch(index));
        }
        if view.perf_domain != 0 && !ids.contains(&view.perf_domain) {
            return Err(Error::UnknownPerfDomain(view.id));
        }
        let Some(complex) = complexes.iter().position(|&id| id == view.perf_domain) else {
            continue;
        };
        if ![0, VIRTUAL].contains(&row[0]) || row[1] != 0 || row[15] != 0 || row[25] != 0 {
            return Err(Error::UnqualifiedGeometry(
                "T6000 CPU flags/die replication",
            ));
        }
        if row[0] == VIRTUAL {
            if !CORE_PREFIXES
                .iter()
                .any(|prefix| view.name.starts_with(prefix))
            {
                return Err(Error::UnknownCpuProtocol(view.id));
            }
            if core::mem::replace(&mut virtuals[complex], true) || view.location.is_some() {
                return Err(Error::IncompleteOwners);
            }
            continue;
        }
        let location = view.location.ok_or(Error::RecordMismatch(index))?;
        if location.address != ps_address(&io, &pmgr, location.group, location.index)? {
            return Err(Error::RecordMismatch(index));
        }
        let is_core = CORE_PREFIXES
            .iter()
            .any(|prefix| view.name.starts_with(prefix));
        let target = if is_core {
            let local = core_counts[complex];
            let pe = *members[complex]
                .get(local)
                .ok_or(Error::Topology("T6000 extra constructor core"))?;
            if pe != global {
                return Err(Error::Topology("T6000 core record/global CPU order"));
            }
            core_counts[complex] += 1;
            global += 1;
            ProcessorTarget::Core { pe }
        } else {
            if !CPM_PREFIXES
                .iter()
                .any(|prefix| view.name.starts_with(prefix))
            {
                return Err(Error::UnknownCpuProtocol(view.id));
            }
            if core::mem::replace(&mut cpm[complex], true) {
                return Err(Error::IncompleteOwners);
            }
            ProcessorTarget::Cluster {
                members: members[complex].clone(),
            }
        };
        if !physical.insert(location.address) {
            return Err(Error::ConflictingAddress(location.address));
        }
        output.push(ProcessorAssociation {
            domain: view.id,
            address: location.address,
            target,
            evidence: EVIDENCE,
        });
    }
    if global != processors.len()
        || core_counts.iter().zip(&members).any(|(n, m)| *n != m.len())
        || cpm.iter().chain(&virtuals).any(|v| !*v)
    {
        return Err(Error::IncompleteOwners);
    }
    for view in records {
        if let Some(location) = view.location
            && physical.contains(&location.address)
            && !output.iter().any(|o| o.domain == view.id)
        {
            return Err(Error::ConflictingAddress(location.address));
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::String};

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }
    fn wide(values: &[u64]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }
    fn node(properties: Vec<(&str, Vec<u8>)>, children: &[Vec<u8>]) -> Vec<u8> {
        crate::machine::adt::encode(
            &properties
                .iter()
                .map(|(k, v)| (*k, v.as_slice()))
                .collect::<Vec<_>>(),
            children,
        )
    }
    fn row(id: u16, perf: u8, flags: u8, index: u8, name: &str) -> [u8; DEVICE_BYTES] {
        let mut row = [0; DEVICE_BYTES];
        row[0] = flags;
        row[2] = perf;
        row[3] = 77;
        row[10] = index;
        row[11] = 0;
        row[26..28].copy_from_slice(&id.to_le_bytes());
        row[32..32 + name.len()].copy_from_slice(name.as_bytes());
        row
    }
    // Authored geometry deliberately differs from the original J314s SKU.
    // IDs, names and PS indices are independent; only reviewed counter order
    // and the source's actual fields join these records.
    fn authored(mutation: u8) -> (Vec<u8>, Vec<Identity>) {
        let mut cpus = Vec::new();
        let mut profiles = Vec::new();
        let mut rows = Vec::new();
        let perf = [2u8, 5, 13];
        for pe in 0..6u32 {
            let complex = pe / 2;
            let local = pe % 2;
            let reg = complex << 8 | local;
            let kind = if complex == 0 { b'E' } else { b'P' };
            profiles.push(crate::machine::soc::Processor {
                cluster_type: kind,
                reg,
                l2_bytes: Some(if kind == b'E' { 4 << 20 } else { 8 << 20 }),
            });
            cpus.push(node(
                vec![
                    ("name", format!("member{pe}\0").into_bytes()),
                    ("reg", words(&[reg])),
                    ("cpu-id", words(&[pe + u32::from(mutation == 3)])),
                    ("cluster-id", words(&[complex])),
                    ("die-id", words(&[0])),
                    ("die-cluster-id", words(&[complex])),
                    ("cluster-core-id", words(&[local])),
                    ("cluster-type", vec![kind, 0]),
                    ("function-enable_core", words(&[0x99, 0x436f7265, 1 << pe])),
                ],
                &[],
            ));
            let name = if mutation == 7 {
                String::from("CPUarbitrary")
            } else {
                format!("CPUletter{}", char::from(b'a' + pe as u8))
            };
            rows.push(row(
                291 + pe as u16,
                perf[complex as usize],
                u8::from(mutation == 5 && pe == 0),
                (complex * 4 + local) as u8,
                &name,
            ));
        }
        for (complex, &domain) in perf.iter().enumerate() {
            rows.push(row(
                420 + complex as u16,
                domain,
                0,
                12 + complex as u8,
                &format!("CPMletter{}", char::from(b'a' + complex as u8)),
            ));
        }
        for (complex, &domain) in perf.iter().enumerate() {
            if mutation != 6 || complex != 2 {
                rows.push(row(600 + complex as u16, domain, VIRTUAL, 0, "CPUvirtual"));
            }
        }
        let mut descriptors = Vec::new();
        for &id in &perf {
            let mut descriptor = [0; PERF_DOMAIN_BYTES];
            descriptor[2] = 1;
            descriptor[3] = id;
            descriptors.extend_from_slice(&descriptor);
        }
        if mutation == 4 {
            descriptors[..PERF_DOMAIN_BYTES * 2].rotate_left(PERF_DOMAIN_BYTES);
        }
        let pmgr = node(
            vec![
                ("name", b"pmgr\0".to_vec()),
                (
                    "compatible",
                    if mutation == 2 {
                        b"pmgr1,t8103\0".to_vec()
                    } else {
                        b"pmgr1,t6000\0".to_vec()
                    },
                ),
                ("AAPL,phandle", words(&[0x99])),
                ("acc-harvesting", words(&[u32::from(mutation != 1)])),
                ("perf-domains", descriptors),
                ("devices", rows.into_iter().flatten().collect()),
                ("reg", wide(&[0x1000, 0x200])),
                ("ps-regs", words(&[0, 0, 0xffff])),
            ],
            &[],
        );
        let io = node(
            vec![
                ("name", b"arm-io\0".to_vec()),
                ("compatible", b"arm-io,t6000\0".to_vec()),
                ("#address-cells", words(&[2])),
                ("#size-cells", words(&[2])),
                ("ranges", wide(&[0, 0x2_0000_0000, 0x1_0000_0000])),
            ],
            &[pmgr],
        );
        let cpus = node(
            vec![
                ("name", b"cpus\0".to_vec()),
                ("#address-cells", words(&[1])),
                ("#size-cells", words(&[0])),
            ],
            &cpus,
        );
        let bytes = node(
            vec![
                ("#address-cells", words(&[2])),
                ("#size-cells", words(&[2])),
            ],
            &[io, cpus],
        );
        let identities = crate::machine::soc::cpus(0x6000, "Apple M1 Pro", &profiles)
            .unwrap()
            .processors;
        (bytes, identities)
    }
    fn resolve_authored(
        bytes: &[u8],
        identities: &[Identity],
        harvesting: u32,
    ) -> Result<Vec<ProcessorAssociation>, Error> {
        let root = Node::root(bytes).unwrap();
        let io = child(&root, b"arm-io").unwrap();
        let pmgr = child(&io, b"pmgr").unwrap();
        let views = required(&pmgr, "devices")
            .unwrap()
            .as_chunks::<DEVICE_BYTES>()
            .0
            .iter()
            .map(|row| {
                let parsed = Record::parse(Layout::V1, row).unwrap();
                PmgrCpuRecord {
                    id: DomainId {
                        die: 0,
                        device: parsed.id,
                    },
                    flags: row[0],
                    perf_domain: row[2],
                    name: parsed.name,
                    location: parsed.location.map(|location| PmgrCpuLocation {
                        group: location.group,
                        index: location.index,
                        address: ps_address(&io, &pmgr, location.group, location.index).unwrap(),
                    }),
                }
            })
            .collect::<Vec<_>>();
        resolve_cpu_power(Chip::AppleM1, &root, &views, identities, harvesting)
    }
    #[test]
    fn t6000_mode1_uses_actual_order_ids_and_non_dense_ps_locations() {
        let (bytes, identities) = authored(0);
        let owners = resolve_authored(&bytes, &identities, 1).unwrap();
        assert_eq!(owners.len(), 9);
        for (pe, index) in [0u64, 1, 4, 5, 8, 9].into_iter().enumerate() {
            assert_eq!(
                owners[pe].domain,
                DomainId {
                    die: 0,
                    device: 291 + pe as u16
                }
            );
            assert_eq!(owners[pe].address, 0x2_0000_1000 + index * 8);
            assert_eq!(owners[pe].target, ProcessorTarget::Core { pe });
        }
        for complex in 0..3 {
            assert_eq!(owners[6 + complex].domain.device, 420 + complex as u16);
            assert_eq!(
                owners[6 + complex].target,
                ProcessorTarget::Cluster {
                    members: vec![complex * 2, complex * 2 + 1]
                }
            );
        }
        let (renamed, identities) = authored(7);
        assert_eq!(resolve_authored(&renamed, &identities, 1), Ok(owners));
    }
    #[test]
    fn t6000_mode1_refuses_unqualified_source_order_flags_and_settings() {
        for mutation in 1..=6 {
            let (bytes, identities) = authored(mutation);
            assert!(
                resolve_authored(&bytes, &identities, 1).is_err(),
                "mutation {mutation}"
            );
        }
        let (bytes, identities) = authored(0);
        assert_eq!(
            resolve_authored(&bytes, &identities, 0),
            Err(Error::UnsupportedHarvesting(0))
        );
        let mut changed = identities.clone();
        changed[2].mpidr ^= 1 << 16;
        assert!(resolve_authored(&bytes, &changed, 1).is_err());
    }
}
