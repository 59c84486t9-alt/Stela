use super::*;
use alloc::{format, vec};

type Properties = Vec<(&'static str, Vec<u8>)>;

const PS_BUS_BASE: u64 = 0x3b70_0000;
const PS_BYTES: u64 = 0x000c_c000;
const PS_PHYSICAL_BASE: u64 = 0x2_3b70_0000;

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
            1 => set(
                &mut f.pmgr,
                "reg",
                cells64(&[PS_BUS_BASE, OWNERS as u64 * PS_STRIDE - 8]),
            ),
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
#[ignore = "oracle: STELA_TEST_CPU_PMGR_ADT, STELA_TEST_PMGR_KERNEL"]
fn original_j473_views_resolve_all_ten_source_constructed_owners() {
    use stela_crypto::{Sha256, digest::Digest};
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
        .map(|node| crate::board::Processor {
            cluster_type: node.property("cluster-type").unwrap()[0],
            reg: node.first_u32("reg").unwrap(),
            l2_bytes: node.first_u32("l2-cache-size"),
        })
        .collect::<Vec<_>>();
    let cpus = crate::board::cpus(0x8112, "Apple M2", &processors).unwrap();
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
