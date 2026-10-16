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
        source.sha256 == stela_core::sha256(bytes),
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
        image.slice_bytes == data.len() as u64 && image.slice_sha256 == stela_core::sha256(data),
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
mod tests;
