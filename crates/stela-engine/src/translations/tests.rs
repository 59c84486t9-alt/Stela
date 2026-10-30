use super::*;
use stela_compiler::{TargetCpu, block::BlockProfile, x86_64::MemoryChecks};

const PAGE: u64 = 0x1_0000_4000;

fn words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn compile(source: &[u8], pc: u64) -> CompiledBlock {
    let options = stela_compiler::Options::new(
        BlockProfile::new(Features::SYSTEM_MODE),
        TargetCpu::Baseline,
    )
    .with_memory_checks(MemoryChecks::system(true, false, true, true));
    stela_compiler::compile(source, GuestAddress(pc), &options).unwrap()
}

fn proved(source: &[u8], offset: u64) -> Option<Entry> {
    let pc = PAGE + offset;
    let block = compile(source, pc);
    let [first, second] = probe_displacements(PAGE);
    let probes = [
        compile(source, pc.wrapping_add(first)),
        compile(source, pc.wrapping_add(second)),
    ];
    prove(
        &block,
        source,
        PAGE,
        pc,
        Digest::of(b"context"),
        [&probes[0], &probes[1]],
    )
}

#[test]
fn address_dependent_blocks_rebase_to_what_the_compiler_emits_at_another_page() {
    // adrp x0, 1; add x0, x0, #8; ldr x1, #16; bl +8
    let source = words(&[0x9000_0020, 0x9100_2000, 0x5800_0081, 0x9400_0002]);
    let entry = proved(&source, 0x40).expect("relocatable");
    assert!(entry.relocations.len() >= 3, "{:?}", entry.relocations);
    for other in [0x2_3456_8000u64, 0x4000, 0x7fff_0000_0000] {
        let expected = compile(&source, other + 0x40);
        let rebased = entry.rebase(other, &source).unwrap();
        assert_eq!(
            rebased.native.x86_64_code, expected.native.x86_64_code,
            "page {other:#x}"
        );
        assert_eq!(rebased.native.source_map, expected.native.source_map);
        assert_eq!(rebased.direct_exits, expected.direct_exits);
        assert_eq!(
            rebased.fault_recovery,
            expected
                .fault_recovery
                .iter()
                .map(UnqualifiedFaultRecovery::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(rebased.source_bytes, expected.source_bytes);
    }
}

#[test]
fn stored_source_witness_requires_the_exact_admitted_compiler_prefix() {
    // The compiler stops at B, but the complete offered analysis input is
    // kept. Changing that suffix must not silently change its witness.
    let source = words(&[0x1400_0002, 0xd503_201f, 0xd65f_03c0]);
    let entry = proved(&source, 0x40).expect("relocatable branch");
    assert_eq!(entry.source_bytes, 4);
    assert_eq!(entry.input, source);
    let translator = translator_id();
    let key = Digest::of(b"raw fetch page identity");
    let mut record = Record::new(translator, key);
    record.insert(entry.clone());
    let decoded = Record::decode(&record.encode(), &translator, &key).unwrap();
    let held = &decoded.entries[0];
    assert_eq!(held.input, source);
    assert!(held.rebase(PAGE, &source).is_some());
    for at in 0..source.len() {
        let mut changed = source.clone();
        changed[at] ^= 1;
        assert!(held.rebase(PAGE, &changed).is_none(), "input byte {at}");
    }
    for length in 0..source.len() {
        assert!(held.rebase(PAGE, &source[..length]).is_none());
    }
    let mut longer_window = source.clone();
    longer_window.extend(words(&[0xd503_201f]));
    assert!(held.rebase(PAGE, &longer_window).is_some());
    assert!(held.rebase(u64::MAX - 3, &source).is_none());
    assert!(held.rebase(!(PAGE_BYTES as u64 - 1), &source).is_some());
    assert!(held.rebase(PAGE + 4, &source).is_none());
}

#[test]
fn source_witness_geometry_is_checked_even_with_a_valid_record_checksum() {
    let source = words(&[0x1400_0002, 0xd503_201f, 0xd65f_03c0]);
    let original = proved(&source, 0x40).unwrap();
    let translator = translator_id();
    let key = Digest::of(b"raw fetch page identity");
    for input in [
        vec![],
        vec![0; 3],
        vec![0; PAGE_BYTES],
        vec![0; PAGE_BYTES + 4],
    ] {
        let mut entry = original.clone();
        entry.input = input;
        assert!(!entry.consistent());
        assert!(entry.rebase(PAGE, &source).is_none());
        let mut record = Record::new(translator, key);
        record.insert(entry);
        assert_eq!(
            Record::decode(&record.encode(), &translator, &key),
            Err(FormatError::Entry)
        );
    }
    let mut legacy = Record::new(translator, key);
    legacy.insert(original);
    let mut bytes = legacy.encode();
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    let end = bytes.len() - TRAILER_BYTES;
    let checksum = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&checksum);
    assert_eq!(
        Record::decode(&bytes, &translator, &key),
        Err(FormatError::Schema)
    );
}

#[test]
fn portable_after_phase_requires_the_kept_fallthrough_instruction() {
    use stela_compiler::Lifter as _;
    let source = words(&[0xd503201f, 0xd4000001]);
    let mut entry = proved(&source, 0x40).unwrap();
    let instruction = stela_compiler::aarch64::Decoder
        .lift(GuestAddress(0x40), 0xd503201f)
        .unwrap();
    entry.recovery = vec![UnqualifiedFaultRecovery {
        start: 0,
        end: 1,
        bindings: Vec::new(),
        retirement: RetirementPoint::after_fallthrough(&instruction, 0).unwrap(),
        site: RecoverySiteKind::NativeInternal,
    }];
    let (translator, key) = (translator_id(), Digest::of(b"phase fixture raw page"));
    let encode = |entry| {
        let mut record = Record::new(translator, key);
        record.insert(entry);
        record.encode()
    };
    let decoded = Record::decode(&encode(entry.clone()), &translator, &key).unwrap();
    let row = &decoded.entries[0]
        .rebase(PAGE, &source)
        .unwrap()
        .fault_recovery[0];
    assert_eq!(row.retirement.position().unwrap().pc.0, PAGE + 0x44);
    assert_eq!(
        row.site,
        RecoverySiteKind::NativeInternal,
        "portable decoding never mints a guest site"
    );
    let mut branch = entry.clone();
    branch.input[..4].copy_from_slice(&0xd65f03c0_u32.to_le_bytes());
    assert_eq!(
        Record::decode(&encode(branch), &translator, &key),
        Err(FormatError::Entry),
        "serialized After does not authorize RET fallthrough"
    );
    let mut guest_after = entry;
    guest_after.recovery[0].site = RecoverySiteKind::GuestAccess;
    assert_eq!(
        Record::decode(&encode(guest_after), &translator, &key),
        Err(FormatError::Entry)
    );
}

#[test]
fn portable_before_endpoint_keeps_exact_prefix_count_and_checked_relocation() {
    let source = words(&[0xd503201f, 0xd4000001]);
    let mut entry = proved(&source, 0x40).unwrap();
    let end = u64::from(entry.offset) + u64::from(entry.source_bytes);
    let count = entry.source_bytes / 4;
    entry.recovery = vec![UnqualifiedFaultRecovery {
        start: 0,
        end: 1,
        bindings: Vec::new(),
        retirement: RetirementPoint::before(GuestAddress(end), count).unwrap(),
        site: RecoverySiteKind::NativeInternal,
    }];
    assert!(entry.consistent());
    let rebased = entry.rebase(PAGE, &source).unwrap();
    assert_eq!(
        rebased.fault_recovery[0]
            .retirement
            .position()
            .unwrap()
            .pc
            .0,
        PAGE + end
    );
    assert_eq!(
        rebased.fault_recovery[0]
            .retirement
            .position()
            .unwrap()
            .retired_instructions,
        count
    );
    let (translator, key) = (translator_id(), Digest::of(b"endpoint fixture raw page"));
    let mut record = Record::new(translator, key);
    record.insert(entry.clone());
    assert_eq!(
        Record::decode(&record.encode(), &translator, &key),
        Ok(record)
    );
    entry.recovery[0].retirement = RetirementPoint::before(GuestAddress(end), count - 1).unwrap();
    let mut bad = Record::new(translator, key);
    bad.insert(entry);
    assert_eq!(
        Record::decode(&bad.encode(), &translator, &key),
        Err(FormatError::Entry)
    );
}

#[test]
fn records_reject_malformed_source_geometry_with_a_valid_checksum() {
    let source = words(&[0x9000_0020, 0x9100_2000, 0x5800_0081, 0x9400_0002]);
    let entry = proved(&source, 0x40).expect("actual relocatable four-word block");
    assert_eq!(entry.source_map.len(), 4);
    assert!(entry.consistent());
    assert!(entry.source_map[1].1 > 1);
    let (translator, key) = (translator_id(), Digest::of(&[7; PAGE_BYTES]));
    let mut good = Record::new(translator, key);
    good.insert(entry.clone());
    assert_eq!(
        Record::decode(&good.encode(), &translator, &key),
        Ok(good.clone())
    );
    type Mutation = (&'static str, fn(&mut Entry));
    let mutations: [Mutation; 15] = [
        ("missing word", |entry| {
            entry.source_map.remove(1);
        }),
        ("duplicate guest", |entry| {
            entry.source_map[1].0 = entry.source_map[0].0
        }),
        ("guest gap", |entry| entry.source_map[1].0 += 4),
        ("equal native", |entry| {
            entry.source_map[1].1 = entry.source_map[0].1
        }),
        ("descending native", |entry| {
            entry.source_map[2].1 = entry.source_map[1].1 - 1
        }),
        ("one-past native", |entry| {
            entry.source_map[3].1 = u32::try_from(entry.code.len()).unwrap()
        }),
        ("out-of-range native", |entry| {
            entry.source_map[3].1 = u32::try_from(entry.code.len() + 1).unwrap()
        }),
        ("wrong native entry", |entry| entry.source_map[0].1 = 1),
        ("unaligned source base", |entry| {
            entry.offset += 1;
            for (guest, _) in &mut entry.source_map {
                *guest += 1;
            }
        }),
        ("partial source word", |entry| entry.source_bytes += 1),
        ("empty extent", |entry| {
            entry.source_bytes = 0;
            entry.source_map.clear();
        }),
        ("page crossing", |entry| {
            entry.offset = PAGE_BYTES as u16 - 4;
            for (index, (guest, _)) in entry.source_map.iter_mut().enumerate() {
                *guest = entry.offset + index as u16 * 4;
            }
        }),
        ("wrong first guest", |entry| entry.source_map[0].0 += 4),
        ("overflowing relocation", |entry| {
            entry.relocations = vec![u32::MAX, u32::MAX]
        }),
        ("overlapping relocations", |entry| {
            let first = entry.relocations[0];
            entry.relocations = vec![first, first + FIELD_BYTES as u32 - 1];
        }),
    ];
    for (name, mutate) in mutations {
        let mut bad = entry.clone();
        mutate(&mut bad);
        assert!(!bad.consistent(), "{name}");
        let mut record = Record::new(translator, key);
        record.insert(bad);
        // The writer recomputes lengths and checksum: this reaches
        // the loader's source geometry check, not a checksum failure.
        assert_eq!(
            Record::decode(&record.encode(), &translator, &key),
            Err(FormatError::Entry),
            "{name}"
        );
    }
    assert_eq!(Record::decode(&good.encode(), &translator, &key), Ok(good));
}

#[test]
fn a_narrowed_page_address_is_not_relocatable() {
    // adrp x8, 0; add w9, w8, #0x20 (a 32-bit result of the address); ret
    let source = words(&[0x9000_0008, 0x1100_8109, 0xd65f_03c0]);
    assert_eq!(proved(&source, 0), None);
}

#[test]
fn records_refuse_any_damaged_framing_byte() {
    let source = words(&[0x9000_0020, 0x9400_0002]);
    let entry = proved(&source, 0x10).unwrap();
    let (translator, key) = (translator_id(), Digest::of(&[7; PAGE_BYTES]));
    let mut record = Record::new(translator, key);
    record.insert(entry.clone());
    record.insert(entry);
    assert_eq!(record.entries.len(), 1);
    let bytes = record.encode();
    assert_eq!(
        Record::decode(&bytes, &translator, &key),
        Ok(record.clone())
    );
    assert_eq!(
        Record::decode(&bytes, &Digest::default(), &key),
        Err(FormatError::Translator)
    );
    assert_eq!(
        Record::decode(&bytes, &translator, &Digest::default()),
        Err(FormatError::Key)
    );
    for at in (0..bytes.len()).step_by(7) {
        let mut damaged = bytes.clone();
        damaged[at] ^= 0x40;
        assert!(
            Record::decode(&damaged, &translator, &key).is_err(),
            "byte {at}"
        );
    }
    for length in [0, HEADER_BYTES, bytes.len() - 1] {
        assert!(Record::decode(&bytes[..length], &translator, &key).is_err());
    }
}

#[test]
fn probes_stay_in_the_address_class_of_their_page() {
    for page in [0u64, 0x1_8000_0000, 0x7fff_ffff_c000, 0xffff_fe00_0700_4000] {
        for displacement in probe_displacements(page) {
            let moved = page.wrapping_add(displacement);
            assert_eq!(address_class(moved), address_class(page), "{page:#x}");
            assert_eq!(moved & 0x3fff, page & 0x3fff);
        }
    }
}
