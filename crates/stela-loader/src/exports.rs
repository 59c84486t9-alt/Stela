//! Export-trie decoding (dyld `ExportsTrie.cpp`). Regular and absolute symbols,
//! including weak definitions; re-exports, TLV and resolvers are errors.
use super::load_plan::{LoadPlan, Payload};
use anyhow::{Context, Result, bail, ensure};
use object::macho;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_TRIE_BYTES: usize = 16 * 1024 * 1024;
const MAX_VISITS: usize = 65_536;
const MAX_NAME_BYTES: usize = 4096;
const MAX_TOTAL_NAME_BYTES: usize = 16 * 1024 * 1024;
const KIND_MASK: u64 = 3;
const KIND_THREAD_LOCAL: u64 = 1;
const KIND_ABSOLUTE: u64 = 2;
const KIND_RESERVED: u64 = 3;
const WEAK_DEFINITION: u64 = 4;
const REEXPORT: u64 = 8;
const STUB_AND_RESOLVER: u64 = 0x10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Export {
    pub name: String,
    pub flags: u64,
    /// Original terminal value: a signed image offset for regular exports,
    /// or an unchanged integer for absolute exports.
    pub value: u64,
    pub address: u64,
}

/// A decoded terminal of a supported kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Terminal {
    flags: u64,
    value: u64,
}

#[derive(Debug)]
struct Node {
    terminal: Option<Terminal>,
    edges: Vec<(Vec<u8>, usize)>,
}

enum Action {
    Visit { offset: usize, name: Vec<u8> },
    Leave(usize),
}

fn uleb(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *bytes
            .get(*cursor)
            .context("truncated export-trie ULEB128")?;
        *cursor += 1;
        let part = u64::from(byte & 0x7f);
        ensure!(index != 9 || part <= 1, "export-trie ULEB128 overflows u64");
        value |= part << (index * 7);
        if byte & 0x80 == 0 {
            ensure!(index == 0 || part != 0, "noncanonical export-trie ULEB128");
            return Ok(value);
        }
    }
    bail!("export-trie ULEB128 exceeds ten bytes")
}

fn insert_node_range(ranges: &mut BTreeMap<usize, usize>, start: usize, end: usize) -> Result<()> {
    if let Some((_, previous_end)) = ranges.range(..=start).next_back() {
        ensure!(*previous_end <= start, "overlapping export-trie node bytes");
    }
    if let Some((next_start, _)) = ranges.range(start..).next() {
        ensure!(end <= *next_start, "overlapping export-trie node bytes");
    }
    ranges.insert(start, end);
    Ok(())
}

fn node(bytes: &[u8], offset: usize, ranges: &mut BTreeMap<usize, usize>) -> Result<Node> {
    ensure!(
        offset < bytes.len(),
        "export-trie node offset exceeds payload"
    );
    if let Some((_, end)) = ranges.range(..=offset).next_back() {
        ensure!(
            *end <= offset,
            "export-trie node starts inside another node"
        );
    }
    let mut cursor = offset;
    let terminal_size = usize::try_from(uleb(bytes, &mut cursor)?)?;
    let terminal_end = cursor
        .checked_add(terminal_size)
        .context("export-trie terminal size overflow")?;
    let terminal_bytes = bytes
        .get(cursor..terminal_end)
        .context("export-trie terminal exceeds payload")?;
    let terminal = if terminal_size == 0 {
        None
    } else {
        let mut at = 0;
        let flags = uleb(terminal_bytes, &mut at)?;
        ensure!(
            flags & REEXPORT == 0,
            "unsupported reexport requires dependency/name resolution"
        );
        ensure!(
            flags & STUB_AND_RESOLVER == 0,
            "unsupported stub/resolver export requires resolver execution"
        );
        ensure!(
            flags & !(KIND_MASK | WEAK_DEFINITION) == 0,
            "unsupported export flags {flags:#x}"
        );
        ensure!(
            flags & KIND_MASK != KIND_THREAD_LOCAL,
            "unsupported thread-local export requires TLV setup"
        );
        ensure!(
            flags & KIND_MASK != KIND_RESERVED,
            "unsupported export kind"
        );
        let value = uleb(terminal_bytes, &mut at)?;
        ensure!(
            at == terminal_bytes.len(),
            "unexpected trailing export terminal bytes"
        );
        Some(Terminal { flags, value })
    };
    cursor = terminal_end;
    let children = usize::from(
        *bytes
            .get(cursor)
            .context("missing export-trie child count")?,
    );
    cursor += 1;
    let mut edges = Vec::with_capacity(children);
    for _ in 0..children {
        let tail = &bytes[cursor..];
        let length = tail
            .iter()
            .take(MAX_NAME_BYTES + 1)
            .position(|&byte| byte == 0)
            .context("unterminated or excessive export-trie edge name")?;
        ensure!(length > 0, "empty export-trie edge name");
        let label = tail[..length].to_vec();
        cursor += length + 1;
        let target = usize::try_from(uleb(bytes, &mut cursor)?)?;
        ensure!(
            target > 0 && target < bytes.len(),
            "export-trie child offset is zero or exceeds payload"
        );
        edges.push((label, target));
    }
    // A terminal may prefix a descendant symbol. Sibling edges must instead
    // be disjoint: a shorter matching sibling would make lookup ambiguous.
    edges.sort_by(|a, b| a.0.cmp(&b.0));
    for pair in edges.windows(2) {
        ensure!(
            !pair[1].0.starts_with(&pair[0].0),
            "duplicate or prefix-ambiguous export-trie edges"
        );
    }
    insert_node_range(ranges, offset, cursor)?;
    Ok(Node { terminal, edges })
}

fn payload_bytes<'a>(data: &'a [u8], source: &Payload) -> Result<&'a [u8]> {
    ensure!(
        source.file.bytes <= MAX_TRIE_BYTES as u64,
        "export trie exceeds payload limit"
    );
    let start = usize::try_from(source.file.offset)?;
    let end = usize::try_from(
        source
            .file
            .offset
            .checked_add(source.file.bytes)
            .context("export payload extent overflow")?,
    )?;
    let bytes = data
        .get(start..end)
        .context("export payload exceeds image")?;
    ensure!(
        source.sha256 == stela_runtime::sha256(bytes),
        "export payload differs from load plan"
    );
    Ok(bytes)
}

fn regular_address(image: &LoadPlan, preferred: u64, loaded: u64, value: u64) -> Result<u64> {
    let offset = i128::from(value as i64);
    let original = u64::try_from(i128::from(preferred) + offset)
        .context("regular export preferred address overflow")?;
    let covered = image
        .segments
        .iter()
        .try_fold(false, |found, segment| -> Result<bool> {
            let end = segment
                .guest
                .address
                .checked_add(segment.guest.bytes)
                .context("export segment extent overflow")?;
            // Stored one-past pointers are permitted; they do not authorize a
            // dereference. Unreserved noaccess guards are never export coverage.
            Ok(found
                || (segment.guest.bytes != 0
                    && segment.initial_protection != 0
                    && segment.guest.address <= original
                    && original <= end))
        })?;
    ensure!(
        covered,
        "regular export points outside declared image segments"
    );
    u64::try_from(i128::from(loaded) + offset).context("regular export loaded address overflow")
}

/// Parse a modern or legacy export trie. Regular offsets are signed 64-bit
/// values relocated to `load_base`; absolute values are kept. Shared subtries
/// are allowed; cycles, overlapping nodes and ambiguous edges are errors. Work,
/// payload size and total name length are bounded.
pub fn parse(data: &[u8], image: &LoadPlan, load_base: u64) -> Result<Vec<Export>> {
    ensure!(
        image.slice_bytes == data.len() as u64 && image.slice_sha256 == stela_runtime::sha256(data),
        "export image identity differs from load plan"
    );
    let mut selected = None;
    let mut modern = false;
    let mut legacy = false;
    for source in &image.payloads {
        if source.command != macho::LC_DYLD_EXPORTS_TRIE
            && !matches!(source.role.as_str(), "export" | "exports_trie")
        {
            continue;
        }
        match source.role.as_str() {
            "exports_trie" => {
                ensure!(
                    source.command == macho::LC_DYLD_EXPORTS_TRIE && !modern,
                    "duplicate or mismatched modern export payload"
                );
                modern = true;
            }
            "export" => {
                ensure!(
                    matches!(
                        source.command,
                        macho::LC_DYLD_INFO | macho::LC_DYLD_INFO_ONLY
                    ) && !legacy,
                    "duplicate or mismatched legacy export payload"
                );
                legacy = true;
            }
            _ => bail!("export payload command/role mismatch"),
        }
        let bytes = payload_bytes(data, source)?;
        if !bytes.is_empty() {
            ensure!(selected.is_none(), "conflicting nonempty export tries");
            selected = Some(bytes);
        }
    }
    let Some(bytes) = selected else {
        return Ok(Vec::new());
    };
    let preferred: Vec<_> = image
        .segments
        .iter()
        .filter(|segment| segment.name == "__TEXT")
        .collect();
    ensure!(
        preferred.len() == 1,
        "exports require one preferred __TEXT base"
    );
    let preferred = preferred[0].guest.address;
    decode_trie(bytes)?
        .into_iter()
        .map(|(name, Terminal { flags, value })| {
            let address = if flags & KIND_MASK == KIND_ABSOLUTE {
                value
            } else {
                regular_address(image, preferred, load_base, value)?
            };
            Ok(Export {
                name,
                flags,
                value,
                address,
            })
        })
        .collect()
}

/// Decode every terminal, sorted by name.
fn decode_trie(bytes: &[u8]) -> Result<Vec<(String, Terminal)>> {
    ensure!(
        bytes.len() <= MAX_TRIE_BYTES,
        "export trie exceeds payload limit"
    );
    let mut actions = vec![Action::Visit {
        offset: 0,
        name: Vec::new(),
    }];
    let mut active = BTreeSet::new();
    let mut nodes = BTreeMap::new();
    let mut ranges = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut exports = Vec::new();
    let mut scheduled = 1usize;
    let mut copied_name_bytes = 0usize;
    while let Some(action) = actions.pop() {
        let (offset, name) = match action {
            Action::Leave(offset) => {
                active.remove(&offset);
                continue;
            }
            Action::Visit { offset, name } => (offset, name),
        };
        ensure!(active.insert(offset), "cyclic export trie");
        if let std::collections::btree_map::Entry::Vacant(entry) = nodes.entry(offset) {
            let parsed = node(bytes, offset, &mut ranges)?;
            entry.insert(parsed);
        }
        let current = &nodes[&offset];
        if let Some(terminal) = current.terminal {
            ensure!(!name.is_empty(), "empty exported symbol name");
            let name = std::str::from_utf8(&name)
                .context("unsupported non-UTF-8 export name")?
                .to_owned();
            ensure!(names.insert(name.clone()), "duplicate exported symbol name");
            exports.push((name, terminal));
        }
        actions.push(Action::Leave(offset));
        for (label, child) in current.edges.iter().rev() {
            scheduled += 1;
            ensure!(
                scheduled <= MAX_VISITS,
                "export-trie traversal exceeds visit limit"
            );
            let length = name
                .len()
                .checked_add(label.len())
                .context("export name length overflow")?;
            ensure!(
                length <= MAX_NAME_BYTES,
                "export symbol name exceeds length limit"
            );
            copied_name_bytes = copied_name_bytes
                .checked_add(length)
                .context("export names size overflow")?;
            ensure!(
                copied_name_bytes <= MAX_TOTAL_NAME_BYTES,
                "export-trie cumulative names exceed limit"
            );
            let mut child_name = Vec::with_capacity(length);
            child_name.extend_from_slice(&name);
            child_name.extend_from_slice(label);
            actions.push(Action::Visit {
                offset: *child,
                name: child_name,
            });
        }
    }
    exports.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(exports)
}

#[cfg(test)]
mod tests {
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
    fn modern_and_legacy_exports_preserve_flags_and_apply_signed_slide() {
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
        image.payloads[0].sha256 = stela_runtime::sha256(
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
}
