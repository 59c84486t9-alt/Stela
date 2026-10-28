//! Checked native group/revision selection, with input bytes supplied intact.
use super::{OFFSET_MASK, Table, Width};
use crate::coprocessor::configuration::Provenance;
use alloc::{string::String, vec::Vec};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_formats::sha256;

const GROUP_BYTES: usize = 0x38;
const REVISION_BYTES: usize = 0x58;

/// The actual native provider determines kind and group coordinates. The bank
/// contains bounded source pointers, never live pointers into released UEFI RAM.
pub struct Input {
    pub image_base: u64,
    pub groups_file_offset: u64,
    pub groups: usize,
    pub kind: u8,
    pub hardware_id: u32,
    pub revision: u32,
    pub source_provenance: Provenance,
    pub hardware_provenance: Provenance,
    pub filter: Filter,
}
pub enum Filter {
    Absent(Provenance),
    /// Native signed 27-bit offset filtering. Wrapped/empty windows refuse.
    Window {
        first: i32,
        bytes: u32,
        provenance: Provenance,
    },
}
#[derive(Debug, Clone, Serialize)]
pub struct Selection {
    pub input_sha256: String,
    pub source_provenance: Provenance,
    pub hardware_provenance: Provenance,
    pub filter_provenance: Provenance,
    pub filter_window: Option<(i32, i32)>,
    pub kind: u8,
    pub hardware_id: u32,
    pub requested_revision: u32,
    pub selected_revision: u32,
    pub group_file_offset: u64,
    pub revision_file_offset: u64,
    pub table_file_offset: Option<u64>,
    pub table_source_sha256: String,
    pub source_records_including_sentinel: usize,
    pub selected_records: usize,
}

fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..)
            .and_then(|b| b.get(..4))
            .context("truncated native tuning u32")?
            .try_into()?,
    ))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..)
            .and_then(|b| b.get(..8))
            .context("truncated native tuning pointer")?
            .try_into()?,
    ))
}
fn slice(source: &[u8], at: u64, bytes: usize) -> Result<&[u8]> {
    source
        .get(usize::try_from(at)?..)
        .and_then(|b| b.get(..bytes))
        .context("native tuning source span exceeds input")
}
fn span<'a>(source: &'a [u8], raw: &[u8], at: usize, base: u64) -> Result<(Option<u64>, &'a [u8])> {
    let pointer = u64_at(raw, at)?;
    let lower = u64_at(raw, at + 8)?;
    let upper = u64_at(raw, at + 16)?;
    if pointer == 0 {
        ensure!(
            lower == 0 && upper == 0,
            "null native tuning span has nonnull bounds"
        );
        return Ok((None, &[]));
    }
    ensure!(
        lower <= pointer && pointer < upper,
        "native tuning source pointer exceeds its bounds"
    );
    let offset = pointer
        .checked_sub(base)
        .context("native tuning source pointer precedes image")?;
    let lower_offset = lower
        .checked_sub(base)
        .context("native tuning lower bound precedes image")?;
    slice(source, lower_offset, usize::try_from(upper - lower)?)?;
    Ok((
        Some(offset),
        slice(source, offset, usize::try_from(upper - pointer)?)?,
    ))
}

impl Table {
    /// Native 0x6eb8 selects the first row whose revision is <= actual revision
    /// in source order. 0x1136b0 traverses narrow/wide tables to a low 27-bit all-one
    /// sentinel, strips flag bits and optionally filters signed offsets.
    /// Hashes establish source integrity, not hardware/provider selection authority.
    /// No source identity, hardware ID or table contents select Rust behavior.
    pub fn select(source: &[u8], input: Input, width: Width) -> Result<Option<Self>> {
        input.source_provenance.validate()?;
        input.hardware_provenance.validate()?;
        let source_hash = sha256(source);
        ensure!(
            source_hash == input.source_provenance.input_sha256,
            "native tuning source identity mismatch"
        );
        ensure!(
            [1, 3].contains(&input.kind),
            "native tuning source kind is not qualified"
        );
        ensure!(
            input.groups <= 4096,
            "native tuning group count exceeds bound"
        );
        let group_bytes = input
            .groups
            .checked_mul(GROUP_BYTES)
            .context("native tuning group geometry overflows")?;
        let groups = slice(source, input.groups_file_offset, group_bytes)?;
        ensure!(
            sha256(groups) == input.source_provenance.span_sha256,
            "native tuning group span identity mismatch"
        );
        let (filter_window, filter_provenance) = match input.filter {
            Filter::Absent(provenance) => (None, provenance),
            Filter::Window {
                first,
                bytes,
                provenance,
            } => {
                ensure!(bytes != 0, "empty native tuning filter is not qualified");
                let end = i64::from(first) + i64::from(bytes);
                (
                    Some((
                        first,
                        i32::try_from(end)
                            .context("wrapped native tuning filter is not qualified")?,
                    )),
                    provenance,
                )
            }
        };
        filter_provenance.validate()?;
        let mut matching = groups
            .as_chunks::<GROUP_BYTES>()
            .0
            .iter()
            .enumerate()
            .filter(|(_, g)| u32_at(*g, 0x30).is_ok_and(|v| v == input.hardware_id));
        let Some((group_index, group)) = matching.next() else {
            return Ok(None);
        };
        ensure!(
            matching.next().is_none(),
            "ambiguous native tuning hardware group"
        );
        let (revisions_at, revisions) = span(source, group, 0, input.image_base)?;
        let count = usize::try_from(u64_at(group, 0x20)?)?;
        ensure!(
            count <= 4096
                && count
                    .checked_mul(REVISION_BYTES)
                    .is_some_and(|n| n <= revisions.len()),
            "native tuning revision rows exceed bounds"
        );
        let selected = revisions
            .as_chunks::<REVISION_BYTES>()
            .0
            .iter()
            .take(count)
            .enumerate()
            .find(|(_, r)| u32_at(*r, 0).is_ok_and(|v| v <= input.revision));
        let Some((revision_index, row)) = selected else {
            return Ok(None);
        };
        let (table_at, table) = span(
            source,
            row,
            match width {
                Width::Bits32 => 0x10,
                Width::Bits64 => 0x30,
            },
            input.image_base,
        )?;
        let mut records = Vec::new();
        let mut consumed = 0;
        let mut terminated = table.is_empty();
        for entry in table.chunks_exact(width.bytes()) {
            consumed += width.bytes();
            let encoded = u32_at(entry, 0)?;
            if encoded & OFFSET_MASK == OFFSET_MASK {
                terminated = true;
                break;
            }
            let signed = ((encoded << 5) as i32) >> 5;
            if filter_window.is_none_or(|(first, end)| first <= signed && signed < end) {
                ensure!(
                    records.len() / width.bytes() < 255,
                    "native tuning table exceeds byte-count capacity"
                );
                records.extend_from_slice(&(encoded & OFFSET_MASK).to_le_bytes());
                records.extend_from_slice(&entry[4..]);
            }
        }
        ensure!(
            terminated,
            "native tuning source table lacks bounded sentinel"
        );
        let source_bytes = &table[..consumed];
        let selected_records = records.len() / width.bytes();
        Ok(Some(Self {
            width,
            records,
            source: Selection {
                input_sha256: source_hash,
                source_provenance: input.source_provenance,
                hardware_provenance: input.hardware_provenance,
                filter_provenance,
                filter_window,
                kind: input.kind,
                hardware_id: input.hardware_id,
                requested_revision: input.revision,
                selected_revision: u32_at(row, 0)?,
                group_file_offset: input.groups_file_offset + (group_index * GROUP_BYTES) as u64,
                revision_file_offset: revisions_at
                    .context("native tuning revision pointer is null")?
                    + (revision_index * REVISION_BYTES) as u64,
                table_file_offset: table_at,
                table_source_sha256: sha256(source_bytes),
                source_records_including_sentinel: source_bytes.len() / width.bytes(),
                selected_records,
            },
        }))
    }
}

#[cfg(test)]
pub(in crate::coprocessor) mod tests {
    use super::*;
    use crate::coprocessor::{
        configuration::tests::provenance,
        tests::{w32, w64},
    };
    use alloc::vec;

    pub(in crate::coprocessor) fn fixture(width: Width) -> Vec<u8> {
        let mut b = vec![0; 0x500];
        // Group with two rows in descending native source order.
        for (at, value) in [(0, 0x1100), (8, 0x1100), (16, 0x11b0), (32, 2)] {
            w64(&mut b, at, value);
        }
        w32(&mut b, 0x30, 7);
        for (at, version, pointer) in [(0x100, 0x20, 0x1300), (0x158, 0x10, 0x1400)] {
            w32(&mut b, at, version);
            let field = if width == Width::Bits64 { 0x30 } else { 0x10 };
            for (delta, value) in [
                (0, pointer),
                (8, pointer),
                (16, pointer + 2 * width.bytes() as u64),
            ] {
                w64(&mut b, at + field + delta, value);
            }
            let table = (pointer - 0x1000) as usize;
            w32(&mut b, table, 0x4000_0124 + (version == 0x10) as u32 * 4);
            b[table + 4..table + width.bytes()].fill(0xa5);
            b[table + width.bytes()..table + 2 * width.bytes()].fill(0xff);
        }
        b
    }
    pub(in crate::coprocessor) fn input(b: &[u8]) -> Input {
        let mut source = provenance();
        source.input_sha256 = sha256(b);
        source.span_sha256 = sha256(&b[..GROUP_BYTES]);
        Input {
            image_base: 0x1000,
            groups_file_offset: 0,
            groups: 1,
            kind: 1,
            hardware_id: 7,
            revision: 0x20,
            source_provenance: source,
            hardware_provenance: provenance(),
            filter: Filter::Absent(provenance()),
        }
    }
    pub(in crate::coprocessor) fn table(width: Width) -> Result<Table> {
        let b = fixture(width);
        Table::select(&b, input(&b), width)?.context("missing synthetic selected table")
    }
    #[test]
    fn selection_retains_native_order_width_and_masked_offsets() -> Result<()> {
        for width in [Width::Bits32, Width::Bits64] {
            let b = fixture(width);
            let t = Table::select(&b, input(&b), width)?.unwrap();
            assert_eq!(t.records.len(), width.bytes());
            assert_eq!(&t.records[..4], &0x124u32.to_le_bytes());
            assert!(t.records[4..].iter().all(|&v| v == 0xa5));
            assert_eq!(t.source.selected_revision, 0x20);
            let mut policy = input(&b);
            policy.revision = 0x1f;
            let t = Table::select(&b, policy, width)?.unwrap();
            assert_eq!(&t.records[..4], &0x128u32.to_le_bytes());
            assert_eq!(t.source.selected_revision, 0x10);
            let mut policy = input(&b);
            policy.revision = 0xf;
            assert!(Table::select(&b, policy, width)?.is_none());
        }
        Ok(())
    }
    #[test]
    fn source_bounds_identity_sentinel_and_ambiguity_are_checked() -> Result<()> {
        for case in 0..8 {
            let mut b = fixture(Width::Bits64);
            match case {
                0 => w64(&mut b, 16, 0x1101),
                1 => w64(&mut b, 32, 4097),
                2 => w64(&mut b, 0x130, 0xfff),
                3 => w64(&mut b, 0x140, 0x1600),
                4 => b[0x314..0x328].fill(0),
                5 => {
                    let g = b[..GROUP_BYTES].to_vec();
                    b[GROUP_BYTES..2 * GROUP_BYTES].copy_from_slice(&g);
                }
                _ => (),
            }
            let mut policy = input(&b);
            if case == 5 {
                policy.groups = 2;
                policy.source_provenance.span_sha256 = sha256(&b[..2 * GROUP_BYTES]);
            }
            if case == 6 {
                policy.source_provenance.input_sha256 = "3".repeat(64);
            }
            if case == 7 {
                policy.source_provenance.span_sha256 = "3".repeat(64);
            }
            assert!(
                Table::select(&b, policy, Width::Bits64).is_err(),
                "case {case}"
            );
        }
        Ok(())
    }
    #[test]
    fn filtering_is_explicit_and_signed_with_no_invented_entries() -> Result<()> {
        let b = fixture(Width::Bits64);
        let mut policy = input(&b);
        policy.filter = Filter::Window {
            first: 0x125,
            bytes: 4,
            provenance: provenance(),
        };
        let t = Table::select(&b, policy, Width::Bits64)?.unwrap();
        assert!(t.records.is_empty());
        for (first, bytes) in [(0, 0), (i32::MAX, 1)] {
            let mut policy = input(&b);
            policy.filter = Filter::Window {
                first,
                bytes,
                provenance: provenance(),
            };
            assert!(Table::select(&b, policy, Width::Bits64).is_err());
        }
        let mut b = b;
        w32(&mut b, 0x300, 0x47ff_fffc);
        let mut policy = input(&b);
        policy.filter = Filter::Window {
            first: -4,
            bytes: 4,
            provenance: provenance(),
        };
        let t = Table::select(&b, policy, Width::Bits64)?.unwrap();
        assert_eq!(&t.records[..4], &0x07ff_fffcu32.to_le_bytes());
        Ok(())
    }
}
