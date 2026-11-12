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
fn system_address_pair_rebases_one_fixed_address_and_both_source_rows() {
    // Both PC-relative encodings retain an eight-byte relocation under
    // page displacement, including when ADRP wraps to zero.
    for first in [0x1000_0000, 0xb000_0000] {
        let source = words(&[first, 0x9100_2000]);
        let entry = proved(&source, 0x40).expect("pinned address pair is relocatable");
        assert_eq!(entry.source_map, [(0x40, 0), (0x44, 1)]);
        assert!(entry.relocations.contains(&3));
        for page in [0x4000, 0x2_3456_8000, 0xffff_ffff_ffff_f000] {
            let expected = compile(&source, page + 0x40);
            let rebased = entry.rebase(page, &source).unwrap();
            assert_eq!(rebased.native.x86_64_code, expected.native.x86_64_code);
            assert_eq!(rebased.native.source_map, expected.native.source_map);
            assert_eq!(rebased.direct_exits, expected.direct_exits);
            assert!(rebased.fault_recovery.is_empty());
            assert_eq!(rebased.source_bytes, source.len());
        }
        assert!(entry.rebase(PAGE, &source[..4]).is_none());
    }
}

#[test]
fn hosted_fused_address_pair_rebases_one_literal_and_both_source_rows() {
    let source = words(&[0x9000_0020, 0x9100_2000, 0xd65f_03c0]); // adrp; add #8; ret
    let options = stela_compiler::Options::new(BlockProfile::ORDINARY, TargetCpu::Baseline);
    let pc = PAGE + 0x40;
    let compile = |pc| stela_compiler::compile(&source, GuestAddress(pc), &options).unwrap();
    let block = compile(pc);
    let probes = probe_displacements(PAGE).map(|delta| compile(pc.wrapping_add(delta)));
    let entry = prove(
        &block,
        &source,
        PAGE,
        pc,
        Digest::of(b"hosted"),
        [&probes[0], &probes[1]],
    )
    .expect("fused address is relocatable");
    assert_eq!(entry.relocations, [2]);
    assert_eq!(entry.source_map[..2], [(0x40, 0), (0x44, 10)]);
    for page in [0x4000, 0x2_3456_8000, 0x7fff_0000_0000] {
        let expected = compile(page + 0x40);
        let rebased = entry.rebase(page, &source).unwrap();
        assert_eq!(rebased.native.x86_64_code, expected.native.x86_64_code);
        assert_eq!(rebased.native.source_map, expected.native.source_map);
        assert_eq!(rebased.source_bytes, source.len());
    }
}

#[test]
fn hosted_fused_wide_constant_rebases_without_numeric_relocations() {
    let source = words(&[
        0x92c0_0000 | (0xabcd << 5), // movn x0, #0xabcd, lsl #32
        0xf2a0_0000 | (0x1234 << 5), // movk x0, #0x1234, lsl #16
        0xf2e0_0000 | (0x5678 << 5), // movk x0, #0x5678, lsl #48
        0xd65f_03c0,                 // ret
    ]);
    let options = stela_compiler::Options::new(BlockProfile::ORDINARY, TargetCpu::Baseline);
    let pc = PAGE + 0x40;
    let compile = |pc| stela_compiler::compile(&source, GuestAddress(pc), &options).unwrap();
    let block = compile(pc);
    let probes = probe_displacements(PAGE).map(|delta| compile(pc.wrapping_add(delta)));
    let entry = prove(
        &block,
        &source,
        PAGE,
        pc,
        Digest::of(b"hosted"),
        [&probes[0], &probes[1]],
    )
    .expect("numeric immediate keeps no address dependency");
    assert!(entry.relocations.is_empty());
    assert_eq!(entry.source_map[..3], [(0x40, 0), (0x44, 1), (0x48, 11)]);
    let page = 0x2_3456_8000;
    let expected = compile(page + 0x40);
    let rebased = entry.rebase(page, &source).unwrap();
    assert_eq!(rebased.native.x86_64_code, expected.native.x86_64_code);
    assert_eq!(rebased.native.source_map, expected.native.source_map);
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
    assert!(entry.source_map[2].1 > entry.source_map[1].1 + 1);
    let (translator, key) = (translator_id(), Digest::of(&[7; PAGE_BYTES]));
    let mut good = Record::new(translator, key);
    good.insert(entry.clone());
    assert_eq!(
        Record::decode(&good.encode(), &translator, &key),
        Ok(good.clone())
    );
    type Mutation = (&'static str, fn(&mut Entry));
    // As in compiled blocks, a prologue may precede the first instruction
    // and an instruction fused into the next shares its native offset.
    let accepted: [Mutation; 2] = [
        ("prologue", |entry| entry.source_map[0].1 = 1),
        ("fused instruction", |entry| {
            entry.source_map[1].1 = entry.source_map[0].1
        }),
    ];
    for (name, mutate) in accepted {
        let mut fine = entry.clone();
        mutate(&mut fine);
        assert!(fine.consistent(), "{name}");
    }
    let mutations: [Mutation; 13] = [
        ("missing word", |entry| {
            entry.source_map.remove(1);
        }),
        ("duplicate guest", |entry| {
            entry.source_map[1].0 = entry.source_map[0].0
        }),
        ("guest gap", |entry| entry.source_map[1].0 += 4),
        ("descending native", |entry| {
            entry.source_map[3].1 = entry.source_map[2].1 - 1
        }),
        ("one-past native", |entry| {
            entry.source_map[3].1 = u32::try_from(entry.code.len()).unwrap()
        }),
        ("out-of-range native", |entry| {
            entry.source_map[3].1 = u32::try_from(entry.code.len() + 1).unwrap()
        }),
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
fn checksummed_record_count_must_fit_the_remaining_bytes() {
    let translator = translator_id();
    let key = Digest::of(b"bounded entry count");
    let mut record = Record::new(translator, key);
    record.insert(proved(&words(&[0x9000_0020, 0x9400_0002]), 0x10).unwrap());
    let mut bytes = record.encode();
    bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    let end = bytes.len() - TRAILER_BYTES;
    let checksum = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&checksum);
    assert_eq!(
        Record::decode(&bytes, &translator, &key),
        Err(FormatError::Truncated)
    );
}

#[test]
fn relocation_for_install_matches_the_rebase_and_reuses_its_buffers() {
    // adrp x0, 1; add x0, x0, #8; ldr x1, #16; bl +8
    let source = words(&[0x9000_0020, 0x9100_2000, 0x5800_0081, 0x9400_0002]);
    let entry = proved(&source, 0x40).expect("relocatable");
    let mut relocated = Relocated::default();
    for other in [0x2_3456_8000u64, 0x4000] {
        let rebased = entry.rebase(other, &source).unwrap();
        assert!(entry.relocate(other, &source, &mut relocated));
        assert_eq!(relocated.code, rebased.native.x86_64_code);
        assert_eq!(relocated.direct_exits, rebased.direct_exits);
    }
    let buffer = relocated.code.as_ptr();
    assert!(entry.relocate(0x4000, &source, &mut relocated));
    assert_eq!(relocated.code.as_ptr(), buffer);
    // Other bytes, or a page not aligned, relocate nothing.
    let mut other = source.clone();
    other[4] ^= 1;
    assert!(!entry.relocate(0x4000, &other, &mut relocated));
    assert!(!entry.relocate(0x4010, &source, &mut relocated));
}

#[test]
fn a_record_decoded_whole_once_decodes_again_without_its_hash() {
    let source = words(&[0x9000_0020, 0x9400_0002]);
    let entry = proved(&source, 0x10).unwrap();
    let (translator, key) = (translator_id(), Digest::of(&[7; PAGE_BYTES]));
    let mut record = Record::new(translator, key);
    record.insert(entry);
    let mut bytes = record.encode();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        Record::decode(&bytes, &translator, &key),
        Err(FormatError::Checksum)
    );
    assert_eq!(
        Record::decode_checked(&bytes, &translator, &key, false),
        Ok(record)
    );
    // The format's bounds are still checked.
    assert!(Record::decode_checked(&bytes[..HEADER_BYTES], &translator, &key, false).is_err());
    assert_eq!(
        Record::decode_checked(&bytes, &Digest::default(), &key, false),
        Err(FormatError::Translator)
    );
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

#[test]
fn unordered_legacy_records_find_the_first_entry_for_each_offset_and_context() {
    let source = words(&[0xd65f_03c0]);
    let low = proved(&source, 0x40).unwrap();
    let high = proved(&source, 0x80).unwrap();
    let mut alternate = low.clone();
    alternate.context = Digest::of(b"alternate");
    let mut duplicate = low.clone();
    duplicate.code.push(0);
    let translator = translator_id();
    let key = Digest::of(b"legacy page");
    let mut legacy = Record {
        translator,
        key,
        entries: vec![high.clone(), alternate.clone(), low.clone(), duplicate],
    };
    for index in 0..32u8 {
        let mut entry = high.clone();
        entry.context = Digest::of(&[index]);
        legacy.entries.push(entry);
    }
    let decoded = Record::decode(&legacy.encode(), &translator, &key).unwrap();
    assert_eq!(decoded.find(low.offset, &low.context), Some(&low));
    assert_eq!(decoded.find(high.offset, &high.context), Some(&high));
    assert_eq!(
        decoded.find(alternate.offset, &alternate.context),
        Some(&alternate)
    );
    assert_eq!(decoded.find(low.offset + 4, &low.context), None);
}

#[test]
fn merge_keeps_current_entries_and_the_first_legacy_duplicate() {
    let source = words(&[0xd65f_03c0]);
    let first = proved(&source, 0x40).unwrap();
    let second = proved(&source, 0x80).unwrap();
    let third = proved(&source, 0xc0).unwrap();
    let mut duplicate = first.clone();
    duplicate.code.push(0);
    let mut older_second = second.clone();
    older_second.code.push(0);
    let translator = translator_id();
    let key = Digest::of(b"merge fixture");
    let mut record = Record::new(translator, key);
    record.insert(second.clone());
    record.merge(Record {
        translator,
        key,
        entries: vec![first.clone(), duplicate, older_second, third.clone()],
    });
    assert_eq!(record.entries(), &[first, second, third]);
}

/// A stored record finds each entry the decoded record finds, the first of
/// a legacy duplicate included, decoding that entry alone.
#[test]
fn stored_records_find_what_decoded_records_find() {
    let source = words(&[0xd65f_03c0]);
    let low = proved(&source, 0x40).unwrap();
    let high = proved(&source, 0x80).unwrap();
    let mut duplicate = low.clone();
    duplicate.code.push(0);
    let translator = translator_id();
    let key = Digest::of(b"stored page");
    let mut legacy = Record {
        translator,
        key,
        entries: vec![high.clone(), low.clone(), duplicate],
    };
    for index in 0..40u8 {
        let mut entry = high.clone();
        entry.context = Digest::of(&[index]);
        legacy.entries.push(entry);
    }
    let bytes = legacy.encode();
    let decoded = Record::decode(&bytes, &translator, &key).unwrap();
    // The first entry of each offset and context, as a decode orders them.
    let mut first = decoded.clone();
    first
        .entries
        .dedup_by_key(|entry| (entry.offset, entry.context));
    for check in [true, false] {
        let mut stored = StoredRecord::new(translator, key);
        stored.add(&bytes, check).unwrap();
        assert_eq!(stored.len(), first.entries().len());
        for entry in first.entries() {
            assert_eq!(
                stored.find(entry.offset, &entry.context).as_ref(),
                Some(entry)
            );
        }
        assert_eq!(stored.find(low.offset, &low.context), Some(low.clone()));
        assert_eq!(stored.find(low.offset + 4, &low.context), None);
        assert_eq!(stored.record().unwrap(), first);
    }
}

/// Records of several segments index as [`Record::merge`] merges them: the
/// earlier segment's entry for a pair both hold.
#[test]
fn stored_records_of_several_segments_keep_the_earlier_entry() {
    let source = words(&[0xd65f_03c0]);
    let first = proved(&source, 0x40).unwrap();
    let second = proved(&source, 0x80).unwrap();
    let mut newer_first = first.clone();
    newer_first.code.push(0);
    let translator = translator_id();
    let key = Digest::of(b"segments");
    let mut older = Record::new(translator, key);
    older.insert(first.clone());
    let mut newer = Record::new(translator, key);
    newer.insert(newer_first);
    newer.insert(second.clone());
    let mut stored = StoredRecord::new(translator, key);
    stored.add(&older.encode(), true).unwrap();
    stored.add(&newer.encode(), true).unwrap();
    let mut merged = older.clone();
    merged.merge(newer);
    assert_eq!(stored.record().unwrap(), merged);
    assert_eq!(stored.find(first.offset, &first.context), Some(first));
    assert_eq!(stored.find(second.offset, &second.context), Some(second));
}

/// A stored record refuses damaged framing as a decode does: the hash when
/// checked, the bounds of every entry always.
#[test]
fn stored_records_refuse_damaged_bytes() {
    let source = words(&[0x9000_0020, 0x9400_0002]);
    let entry = proved(&source, 0x10).unwrap();
    let (translator, key) = (translator_id(), Digest::of(&[7; PAGE_BYTES]));
    let mut record = Record::new(translator, key);
    record.insert(entry);
    let bytes = record.encode();
    let add = |bytes: &[u8], check: bool| StoredRecord::new(translator, key).add(bytes, check);
    let mut flipped = bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert_eq!(add(&flipped, true), Err(FormatError::Checksum));
    assert_eq!(add(&flipped, false), Ok(()));
    assert_eq!(
        StoredRecord::new(Digest::default(), key).add(&bytes, false),
        Err(FormatError::Translator)
    );
    assert_eq!(
        StoredRecord::new(translator, Digest::default()).add(&bytes, false),
        Err(FormatError::Key)
    );
    for length in [0, HEADER_BYTES, bytes.len() - 1] {
        assert!(add(&bytes[..length], false).is_err(), "{length}");
    }
    for at in (0..bytes.len()).step_by(7) {
        let mut damaged = bytes.clone();
        damaged[at] ^= 0x40;
        assert!(add(&damaged, true).is_err(), "byte {at}");
    }
}

/// The engine paths (`super::` and `crate::`) `text` names, as written,
/// with each braced list expanded.
fn engine_paths(text: &str) -> std::collections::BTreeSet<String> {
    let mut paths = std::collections::BTreeSet::new();
    let bytes = text.as_bytes();
    let path_char = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b':';
    let mut at = 0;
    while at < bytes.len() {
        let rest = &text[at..];
        let starts = (rest.starts_with("super::") || rest.starts_with("crate::"))
            && (at == 0 || !path_char(bytes[at - 1]));
        if !starts {
            at += 1;
            continue;
        }
        let mut end = at;
        while end < bytes.len() && path_char(bytes[end]) {
            end += 1;
        }
        let prefix = &text[at..end];
        if bytes.get(end) == Some(&b'{') && prefix.ends_with("::") {
            let close = text[end..].find('}').expect("a closed use list") + end;
            for item in text[end + 1..close].split(',') {
                let item: String = item.split_whitespace().collect();
                if !item.is_empty() {
                    paths.insert(format!("{prefix}{item}"));
                }
            }
            at = close;
        } else if bytes.get(end) == Some(&b'*') {
            paths.insert(format!("{prefix}*"));
            at = end;
        } else {
            paths.insert(prefix.trim_end_matches(':').to_owned());
            at = end;
        }
    }
    paths
}

/// The translator id fingerprints only the engine files `build.rs` names
/// (`STELA_ENGINE_TRANSLATION_INPUTS`). Each engine item those files name is
/// in them, or only consumes what a block compiled to: a new name fails here
/// until it is moved into the inputs or reviewed as a consumer.
#[test]
fn the_translator_id_covers_every_engine_item_its_inputs_name() {
    let inputs = env!("STELA_ENGINE_TRANSLATION_INPUTS");
    for input in [
        "src/machine/engine/block_inputs.rs",
        "src/machine/engine/prepare.rs",
        "src/machine/engine/stored.rs",
        "src/translations.rs",
        "src/translations",
    ] {
        assert!(inputs.split(' ').any(|named| named == input), "{input}");
    }
    let block_inputs = include_str!("../machine/engine/block_inputs.rs");
    for constant in [
        "const PROFILE",
        "const INSTRUCTION",
        "const FETCH_PAGE",
        "const MAX_BLOCK_BYTES",
        "fn is_floating_point",
    ] {
        assert!(block_inputs.contains(constant), "{constant}");
    }
    let cases: [(&str, &str, &[&str]); 5] = [
        (
            "prepare.rs",
            include_str!("../machine/engine/prepare.rs"),
            &[
                // block_inputs.rs, through the engine module.
                "super::FETCH_PAGE",
                "super::INSTRUCTION",
                "super::MAX_BLOCK_BYTES",
                "super::PROFILE",
                "super::is_floating_point",
                "super::*",
                "crate::translations",
                "crate::translations::Digest",
                "crate::machine::test_chip",
            ],
        ),
        (
            "stored.rs",
            include_str!("../machine/engine/stored.rs"),
            &[
                "super::FETCH_PAGE",
                "super::Preparation",
                // Consumers: the machine's kept pages and installs.
                "super::Devices",
                "super::Host",
                "super::Machine",
                "super::Variant",
                "super::recovery::StoredOrigin",
                // Consumers: the page keys the board's PEs memoized, each
                // the SHA-256 of a page's bytes, which a compile never reads.
                "super::known_keys",
                "super::known_keys::DEFAULT_SLOTS",
                "super::known_keys::Known",
                "super::known_keys::MAX_SLOTS",
                "crate::translations",
                "crate::translations::Digest",
                "crate::translations::PAGE_BYTES",
                "crate::translations::StoredRecord",
                "crate::translations::Entry",
                "crate::translations::probe_displacements",
                "crate::translations::prove",
                "crate::translations::address_class",
            ],
        ),
        (
            "translations.rs",
            include_str!("../translations.rs"),
            // A check at lookup with the reading build's rules.
            &["crate::artifact::validate_source_map_geometry"],
        ),
        (
            "pack.rs",
            include_str!("pack.rs"),
            &[
                "super::Digest",
                "super::Entry",
                "super::FormatError",
                "super::Record",
                "super::StoredRecord",
                "super::*",
                "crate::machine::engine::SharedTranslation",
                "crate::machine::Offer",
                "crate::machine::Preparation",
                "crate::machine::Translations",
                "crate::machine::test_preparation",
                "crate::translations::PAGE_BYTES",
                "crate::translations::translator_id",
            ],
        ),
        (
            "codec.rs",
            include_str!("pack/codec.rs"),
            &[
                "super::super::HEADER_BYTESasRECORD_HEADER",
                "super::super::TRAILER_BYTES",
                "super::*",
            ],
        ),
    ];
    for (name, text, allowed) in cases {
        let named = engine_paths(text);
        let unexpected: Vec<_> = named
            .iter()
            .filter(|path| !allowed.contains(&path.as_str()))
            .collect();
        assert!(unexpected.is_empty(), "{name} names {unexpected:?}");
    }
}
