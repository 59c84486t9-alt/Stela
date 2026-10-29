use super::*;
const BASE: u64 = 0x1_0000_0000;
const TRIE_OFFSET: usize = 0x800;

fn encoded(mut value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        result.push(byte | if value != 0 { 0x80 } else { 0 });
        if value == 0 {
            return result;
        }
    }
}
fn trie(entries: &[(&[u8], u64, u64)]) -> Vec<u8> {
    let leaves: Vec<_> = entries
        .iter()
        .map(|(_, flags, value)| {
            let mut payload = encoded(*flags);
            payload.extend(encoded(*value));
            let mut leaf = encoded(payload.len() as u64);
            leaf.extend(payload);
            leaf.push(0);
            leaf
        })
        .collect();
    let mut root_size = 2;
    loop {
        let mut offset = root_size;
        let mut revised = 2;
        for ((name, _, _), leaf) in entries.iter().zip(&leaves) {
            revised += name.len() + 1 + encoded(offset as u64).len();
            offset += leaf.len();
        }
        if revised == root_size {
            break;
        }
        root_size = revised;
    }
    let mut bytes = vec![0, entries.len() as u8];
    let mut offset = root_size;
    for ((name, _, _), leaf) in entries.iter().zip(&leaves) {
        bytes.extend_from_slice(name);
        bytes.push(0);
        bytes.extend(encoded(offset as u64));
        offset += leaf.len();
    }
    for leaf in leaves {
        bytes.extend(leaf);
    }
    bytes
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn fixture(trie: &[u8], legacy: bool) -> (Vec<u8>, LoadPlan) {
    let file_size = (TRIE_OFFSET + trie.len()).max(0x1000);
    let mut bytes = vec![0; file_size];
    let export_command = if legacy { 48 } else { 16 };
    for (index, value) in [
        0xfeedfacf,
        macho::CPU_TYPE_ARM64,
        0,
        macho::MH_EXECUTE,
        4,
        72 + 72 + 24 + export_command,
        0,
        0,
    ]
    .into_iter()
    .enumerate()
    {
        put32(&mut bytes, index * 4, value);
    }
    for (at, name, address, size, files, protection) in [
        (
            32,
            b"__TEXT".as_slice(),
            BASE,
            (file_size as u64).div_ceil(0x1000).max(16) * 0x1000,
            file_size as u64,
            5,
        ),
        (104, b"__BEFORE".as_slice(), BASE - 0x4000, 0x4000, 0, 3),
    ] {
        put32(&mut bytes, at, macho::LC_SEGMENT_64);
        put32(&mut bytes, at + 4, 72);
        bytes[at + 8..at + 8 + name.len()].copy_from_slice(name);
        put64(&mut bytes, at + 24, address);
        put64(&mut bytes, at + 32, size);
        put64(&mut bytes, at + 48, files);
        put32(&mut bytes, at + 56, 7);
        put32(&mut bytes, at + 60, protection);
    }
    put32(&mut bytes, 176, macho::LC_MAIN);
    put32(&mut bytes, 180, 24);
    put64(&mut bytes, 184, 0x300);
    put32(
        &mut bytes,
        200,
        if legacy {
            macho::LC_DYLD_INFO_ONLY
        } else {
            macho::LC_DYLD_EXPORTS_TRIE
        },
    );
    put32(&mut bytes, 204, export_command);
    let fields = if legacy { 240 } else { 208 };
    put32(&mut bytes, fields, TRIE_OFFSET as u32);
    put32(&mut bytes, fields + 4, trie.len() as u32);
    put32(&mut bytes, 0x300, 0xd65f03c0);
    bytes[TRIE_OFFSET..TRIE_OFFSET + trie.len()].copy_from_slice(trie);
    let image = super::super::load_plan::plan(&bytes).unwrap();
    (bytes, image)
}

fn parse_trie(bytes: &[u8]) -> Result<Vec<Export>> {
    let (data, image) = fixture(bytes, false);
    parse(&data, &image, BASE)
}

#[test]
fn exports_keep_flags_and_apply_signed_slide() {
    for legacy in [false, true] {
        let input = trie(&[
            (b"_regular", 0, 0x300),
            (b"_absolute", 2, u64::MAX),
            (b"_weak", 4, (-16i64) as u64),
            (b"_one_past", 0, 0x10000),
        ]);
        let (data, image) = fixture(&input, legacy);
        for loaded in [BASE - 0x100000, BASE, BASE + 0x300000] {
            let exports = parse(&data, &image, loaded).unwrap();
            assert_eq!(
                exports[0],
                Export {
                    name: "_absolute".into(),
                    flags: 2,
                    value: u64::MAX,
                    address: u64::MAX
                }
            );
            assert_eq!(exports[1].address, loaded + 0x10000);
            assert_eq!(exports[2].address, loaded + 0x300);
            assert_eq!(exports[3].flags, 4);
            assert_eq!(exports[3].address, loaded - 16);
        }
    }
}

#[test]
fn payload_absence_and_empty_trie_are_distinct_from_malformed_root() {
    let (data, mut image) = fixture(&[], false);
    assert!(parse(&data, &image, BASE).unwrap().is_empty());
    image.payloads.clear();
    assert!(parse(&data, &image, BASE).unwrap().is_empty());
    assert!(parse_trie(&[0, 0]).unwrap().is_empty());
    assert!(parse_trie(&[0]).is_err());
    assert!(
        parse_trie(&[2, 0, 0, 0])
            .unwrap_err()
            .to_string()
            .contains("empty exported")
    );
}

#[test]
fn rejects_unsupported_terminal_semantics_and_trailing_bytes() {
    for (flags, message) in [
        (1, "thread-local"),
        (3, "kind"),
        (8, "reexport"),
        (16, "resolver"),
        (32, "flags"),
        (64, "flags"),
    ] {
        assert!(
            parse_trie(&trie(&[(b"_unsupported", flags, 0x300)]))
                .unwrap_err()
                .to_string()
                .contains(message)
        );
    }
    assert!(
        parse_trie(&[0, 1, b'a', 0, 5, 3, 0, 0, 0, 0])
            .unwrap_err()
            .to_string()
            .contains("trailing")
    );
}

#[test]
fn validates_node_bounds_cycles_shared_nodes_and_edge_ambiguity() {
    for input in [
        vec![0, 1, b'a', 0, 0],
        vec![0, 1, b'a', 0, 99],
        vec![0, 1, b'a', 0, 2],
        vec![0, 1, b'a', 0, 5, 0, 1, b'b', 0, 5],
    ] {
        assert!(parse_trie(&input).is_err());
    }
    for entries in [
        vec![(b"a".as_slice(), 0, 0x300), (b"a".as_slice(), 0, 0x304)],
        vec![(b"a".as_slice(), 0, 0x300), (b"ab".as_slice(), 0, 0x304)],
    ] {
        assert!(
            parse_trie(&trie(&entries))
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
    }
    // Two disjoint names may share a serialized terminal node.
    let shared = [0, 2, b'a', 0, 8, b'b', 0, 8, 3, 0, 0x80, 6, 0];
    let result = parse_trie(&shared).unwrap();
    assert_eq!(
        result
            .iter()
            .map(|export| export.name.as_str())
            .collect::<Vec<_>>(),
        ["a", "b"]
    );
    assert_eq!(result[0].address, BASE + 0x300);
}

#[test]
fn terminal_prefix_symbols_and_split_utf8_edges_remain_valid() {
    let input = [
        0, 1, b'a', 0, 5, 3, 0, 0x80, 6, 1, b'b', 0, 13, 3, 0, 0x84, 6, 0,
    ];
    let result = parse_trie(&input).unwrap();
    assert_eq!(
        result
            .iter()
            .map(|export| export.name.as_str())
            .collect::<Vec<_>>(),
        ["a", "ab"]
    );
    let utf8 = [0, 1, 0xc3, 0, 5, 0, 1, 0xa9, 0, 10, 3, 0, 0x80, 6, 0];
    assert_eq!(parse_trie(&utf8).unwrap()[0].name, "é");
    assert!(parse_trie(&trie(&[(b"\xff", 0, 0x300)])).is_err());
}

#[test]
fn uleb_rejects_noncanonical_truncated_and_overflowing_values() {
    for input in [
        vec![0x80],
        vec![0x80, 0],
        vec![0xff; 11],
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2],
    ] {
        assert!(uleb(&input, &mut 0).is_err());
    }
    for value in [0, 127, 128, u64::MAX, i64::MIN as u64] {
        let input = encoded(value);
        let mut cursor = 0;
        assert_eq!(uleb(&input, &mut cursor).unwrap(), value);
        assert_eq!(cursor, input.len());
    }
}

#[test]
fn source_payload_identity_and_conflicting_tries_are_checked() {
    let (mut data, mut image) = fixture(&trie(&[(b"a", 0, 0x300)]), false);
    image.payloads[0].sha256 = "wrong".into();
    assert!(parse(&data, &image, BASE).is_err());
    image.payloads[0].sha256 = stela_formats::sha256(
        &data[TRIE_OFFSET..TRIE_OFFSET + image.payloads[0].file.bytes as usize],
    );
    let mut duplicate = image.payloads[0].clone();
    duplicate.command = macho::LC_DYLD_INFO_ONLY;
    duplicate.role = "export".into();
    image.payloads.push(duplicate);
    assert!(
        parse(&data, &image, BASE)
            .unwrap_err()
            .to_string()
            .contains("conflicting")
    );
    image.payloads.pop();
    image.payloads[0].command = macho::LC_FUNCTION_STARTS;
    assert!(parse(&data, &image, BASE).is_err());
    data[0x300] ^= 1;
    assert!(
        parse(&data, &image, BASE)
            .unwrap_err()
            .to_string()
            .contains("image identity")
    );
}

#[test]
fn regular_exports_require_segment_coverage_and_checked_addresses() {
    for value in [0x10001, (-0x4001i64) as u64, i64::MIN as u64] {
        assert!(parse_trie(&trie(&[(b"_outside", 0, value)])).is_err());
    }
    let (data, image) = fixture(&trie(&[(b"a", 0, 0x300)]), false);
    assert!(parse(&data, &image, u64::MAX - 4).is_err());
    let (data, image) = fixture(&trie(&[(b"a", 0, (-16i64) as u64)]), false);
    assert!(parse(&data, &image, 0).is_err());
}

#[test]
fn deep_trie_is_iterative_and_bounded_by_name_length() {
    let count = MAX_NAME_BYTES + 2;
    let mut offsets = vec![0usize; count];
    loop {
        let mut next = vec![0usize; count];
        for index in 1..count {
            next[index] = next[index - 1] + 4 + encoded(offsets[index] as u64).len();
        }
        if offsets == next {
            break;
        }
        offsets = next;
    }
    let mut input = Vec::new();
    for offset in offsets.iter().skip(1) {
        input.extend([0, 1, b'a', 0]);
        input.extend(encoded(*offset as u64));
    }
    input.extend([3, 0, 0x80, 6, 0]);
    assert!(
        parse_trie(&input)
            .unwrap_err()
            .to_string()
            .contains("length limit")
    );
}
