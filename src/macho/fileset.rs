//! Inspect kernel-collection images while preserving collection-relative offsets.
//! Embedded images are not standalone files and must not be sliced blindly.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_core::sha256;
use std::collections::BTreeSet;

fn range(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let end = offset.checked_add(size).context("fileset range overflow")?;
    data.get(usize::try_from(offset)?..usize::try_from(end)?)
        .context("fileset range exceeds container")
}
fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .context("truncated Mach-O field")?
            .try_into()?,
    ))
}
fn u64_at(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(at..at + 8)
            .context("truncated Mach-O field")?
            .try_into()?,
    ))
}
fn name(data: &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(data.split(|b| *b == 0).next().unwrap_or_default())?.to_owned())
}
fn command_string(data: &[u8], offset: usize, minimum: usize) -> Result<String> {
    ensure!(
        offset >= minimum && offset < data.len(),
        "invalid load-command string offset"
    );
    let bytes = &data[offset..];
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .context("unterminated load-command string")?;
    ensure!(end > 0, "empty load-command string");
    name(&bytes[..end])
}

#[derive(Debug, Serialize)]
pub struct Section {
    pub name: String,
    pub segment: String,
    pub vm_address: u64,
    pub bytes: u64,
    pub file_offset: u64,
    pub flags: u32,
    pub zero_fill: bool,
    pub instructions: bool,
    pub sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Segment {
    pub name: String,
    pub vm_address: u64,
    pub vm_bytes: u64,
    pub file_offset: u64,
    pub file_bytes: u64,
    pub initial_protection: u32,
}

#[derive(Debug, Serialize)]
pub struct Entry {
    pub id: String,
    pub vm_address: u64,
    pub header_offset: u64,
}

#[derive(Debug, Serialize)]
pub struct Image {
    pub id: String,
    pub header_offset: u64,
    pub header_sha256: String,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub file_type: u32,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub dependencies: Vec<String>,
    pub fileset_entries: Vec<Entry>,
    pub symbol_count: u32,
    pub symbol_table_file_offset: Option<u64>,
    pub string_table_file_offset: Option<u64>,
    pub string_table_bytes: Option<u64>,
    pub function_starts_file_offset: Option<u64>,
    pub function_starts_bytes: Option<u64>,
    pub unhandled_load_commands: Vec<u32>,
}

fn image(data: &[u8], offset: u64, id: String) -> Result<Image> {
    let header = range(data, offset, 32)?;
    ensure!(
        u32_at(header, 0)? == 0xfeedfacf,
        "only little-endian 64-bit Mach-O collections are supported"
    );
    let count = u32_at(header, 16)? as usize;
    let size = u32_at(header, 20)? as usize;
    ensure!(
        count <= 65536 && count <= size / 8,
        "invalid Mach-O load-command count"
    );
    let commands = range(
        data,
        offset.checked_add(32).context("header overflow")?,
        size as u64,
    )?;
    let mut result = Image {
        id,
        header_offset: offset,
        header_sha256: sha256(range(data, offset, 32 + size as u64)?),
        cpu_type: u32_at(header, 4)?,
        cpu_subtype: u32_at(header, 8)?,
        file_type: u32_at(header, 12)?,
        segments: vec![],
        sections: vec![],
        dependencies: vec![],
        fileset_entries: vec![],
        symbol_count: 0,
        symbol_table_file_offset: None,
        string_table_file_offset: None,
        string_table_bytes: None,
        function_starts_file_offset: None,
        function_starts_bytes: None,
        unhandled_load_commands: vec![],
    };
    let mut position = 0usize;
    for _ in 0..count {
        let command = u32_at(commands, position)?;
        let length = u32_at(commands, position + 4)? as usize;
        ensure!(
            length >= 8 && length.is_multiple_of(8),
            "invalid load-command size"
        );
        let end = position
            .checked_add(length)
            .context("load-command overflow")?;
        let body = commands
            .get(position..end)
            .context("load command exceeds declared table")?;
        match command {
            0x19 => {
                ensure!(body.len() >= 72, "truncated LC_SEGMENT_64");
                let vm_address = u64_at(body, 24)?;
                let vm_bytes = u64_at(body, 32)?;
                let file_offset = u64_at(body, 40)?;
                let file_bytes = u64_at(body, 48)?;
                ensure!(file_bytes <= vm_bytes, "segment file bytes exceed VM bytes");
                vm_address
                    .checked_add(vm_bytes)
                    .context("segment VM range overflow")?;
                range(data, file_offset, file_bytes)?;
                let segment_name = name(&body[8..24])?;
                let segment_file_offset = file_offset;
                let segment_file_end = file_offset
                    .checked_add(file_bytes)
                    .context("segment file range overflow")?;
                let sections = u32_at(body, 64)? as usize;
                ensure!(
                    sections <= (body.len() - 72) / 80,
                    "truncated segment section table"
                );
                result.segments.push(Segment {
                    name: segment_name.clone(),
                    vm_address,
                    vm_bytes,
                    file_offset,
                    file_bytes,
                    initial_protection: u32_at(body, 60)?,
                });
                for index in 0..sections {
                    let section = &body[72 + index * 80..72 + (index + 1) * 80];
                    let section_name = name(&section[..16])?;
                    let segment = name(&section[16..32])?;
                    let address = u64_at(section, 32)?;
                    let bytes = u64_at(section, 40)?;
                    let file_offset = u64::from(u32_at(section, 48)?);
                    let flags = u32_at(section, 64)?;
                    let zero_fill = matches!(flags & 0xff, 1 | 0xc | 0x12);
                    let instructions = flags & 0x80000400 != 0;
                    ensure!(segment == segment_name, "section/segment name mismatch");
                    ensure!(
                        address >= vm_address
                            && address
                                .checked_add(bytes)
                                .is_some_and(|end| end <= vm_address + vm_bytes),
                        "section exceeds segment VM range"
                    );
                    let hash = if zero_fill {
                        None
                    } else {
                        ensure!(
                            bytes == 0
                                || (file_offset >= segment_file_offset
                                    && file_offset
                                        .checked_add(bytes)
                                        .is_some_and(|end| end <= segment_file_end)),
                            "section exceeds segment file range"
                        );
                        Some(sha256(range(data, file_offset, bytes)?))
                    };
                    result.sections.push(Section {
                        name: section_name,
                        segment,
                        vm_address: address,
                        bytes,
                        file_offset,
                        flags,
                        zero_fill,
                        instructions,
                        sha256: hash,
                    });
                }
            }
            0x80000035 => {
                ensure!(body.len() >= 32, "truncated LC_FILESET_ENTRY");
                let header_offset = u64_at(body, 16)?;
                range(data, header_offset, 32)?;
                result.fileset_entries.push(Entry {
                    id: command_string(body, u32_at(body, 24)? as usize, 32)?,
                    vm_address: u64_at(body, 8)?,
                    header_offset,
                });
            }
            0x2 => {
                ensure!(
                    body.len() >= 24 && result.symbol_table_file_offset.is_none(),
                    "invalid or duplicate symbol table"
                );
                let symoff = u64::from(u32_at(body, 8)?);
                let count = u32_at(body, 12)?;
                let stroff = u64::from(u32_at(body, 16)?);
                let strsize = u64::from(u32_at(body, 20)?);
                range(data, symoff, u64::from(count) * 16)?;
                range(data, stroff, strsize)?;
                result.symbol_count = count;
                result.symbol_table_file_offset = Some(symoff);
                result.string_table_file_offset = Some(stroff);
                result.string_table_bytes = Some(strsize);
            }
            0x26 => {
                ensure!(
                    body.len() >= 16 && result.function_starts_file_offset.is_none(),
                    "invalid or duplicate function starts"
                );
                let offset = u64::from(u32_at(body, 8)?);
                let bytes = u64::from(u32_at(body, 12)?);
                range(data, offset, bytes)?;
                result.function_starts_file_offset = Some(offset);
                result.function_starts_bytes = Some(bytes);
            }
            0xc | 0x80000018 | 0x8000001f | 0x80000023 => {
                ensure!(body.len() >= 24, "truncated dylib dependency");
                result
                    .dependencies
                    .push(command_string(body, u32_at(body, 8)? as usize, 24)?);
            }
            _ => result.unhandled_load_commands.push(command),
        }
        position = end;
    }
    ensure!(
        position == commands.len(),
        "load-command count disagrees with table size"
    );
    Ok(result)
}

#[derive(Debug, Serialize)]
pub struct FileSet {
    pub schema_version: u32,
    pub container_sha256: String,
    pub container_bytes: usize,
    pub root: Image,
    pub images: Vec<Image>,
    pub executable_section_bytes: u64,
    pub unique_executable_file_bytes: u64,
    pub limits: String,
}

pub fn inspect(data: &[u8]) -> Result<FileSet> {
    let root = image(data, 0, "collection".into())?;
    ensure!(root.file_type == 0xc, "expected MH_FILESET");
    let mut ids = BTreeSet::new();
    let mut offsets = BTreeSet::new();
    let mut images = vec![];
    for entry in &root.fileset_entries {
        ensure!(
            entry.header_offset != 0
                && ids.insert(&entry.id)
                && offsets.insert(entry.header_offset),
            "duplicate/recursive fileset entry"
        );
        let child = image(data, entry.header_offset, entry.id.clone())?;
        ensure!(
            child.file_type != 0xc,
            "nested filesets require a separate parser"
        );
        ensure!(
            child.cpu_type == root.cpu_type,
            "mixed CPU types in fileset"
        );
        images.push(child);
    }
    ensure!(!images.is_empty(), "fileset has no embedded images");
    let mut ranges = vec![];
    let mut executable_section_bytes = 0u64;
    for section in images
        .iter()
        .flat_map(|i| &i.sections)
        .filter(|s| s.instructions && !s.zero_fill)
    {
        executable_section_bytes = executable_section_bytes
            .checked_add(section.bytes)
            .context("section byte count overflow")?;
        ranges.push((section.file_offset, section.file_offset + section.bytes));
    }
    ranges.sort_unstable();
    let mut unique = 0;
    let mut previous = None;
    for (start, end) in ranges {
        match previous {
            Some((a, b)) if start <= b => previous = Some((a, b.max(end))),
            Some((a, b)) => {
                unique += b - a;
                previous = Some((start, end));
            }
            None => previous = Some((start, end)),
        }
    }
    if let Some((a, b)) = previous {
        unique += b - a;
    }
    Ok(FileSet { schema_version:1,container_sha256:sha256(data),container_bytes:data.len(),root,images,executable_section_bytes,unique_executable_file_bytes:unique,limits:"Collection-relative section inventory only. Unknown load commands remain listed; no relocations, authenticated pointers, dependencies, translation, or boot behavior are resolved.".into() })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut data = vec![0u8; 160];
        for (index, value) in [0xfeedfacfu32, 0x0100000c, 2, 0xc, 1, 40, 0, 0]
            .iter()
            .enumerate()
        {
            data[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        data[32..36].copy_from_slice(&0x80000035u32.to_le_bytes());
        data[36..40].copy_from_slice(&40u32.to_le_bytes());
        data[48..56].copy_from_slice(&128u64.to_le_bytes());
        data[56..60].copy_from_slice(&32u32.to_le_bytes());
        data[64..70].copy_from_slice(b"image\0");
        for (index, value) in [0xfeedfacfu32, 0x0100000c, 2, 2, 0, 0, 0, 0]
            .iter()
            .enumerate()
        {
            data[128 + index * 4..132 + index * 4].copy_from_slice(&value.to_le_bytes());
        }
        data
    }
    #[test]
    fn keeps_collection_offsets_and_rejects_bad_command_and_child_ranges() -> Result<()> {
        let data = fixture();
        let report = inspect(&data)?;
        assert_eq!(report.images[0].header_offset, 128);
        let mut bad = data.clone();
        bad[48..56].copy_from_slice(&159u64.to_le_bytes());
        assert!(inspect(&bad).is_err());
        let mut bad = data;
        bad[36..40].copy_from_slice(&7u32.to_le_bytes());
        assert!(inspect(&bad).is_err());
        Ok(())
    }
    #[test]
    fn empty_sections_may_have_zero_offsets_but_nonempty_sections_stay_in_segment() {
        let mut data = fixture();
        data.resize(316, 0);
        data[144..148].copy_from_slice(&1u32.to_le_bytes());
        data[148..152].copy_from_slice(&152u32.to_le_bytes());
        data[160..164].copy_from_slice(&0x19u32.to_le_bytes());
        data[164..168].copy_from_slice(&152u32.to_le_bytes());
        data[168..174].copy_from_slice(b"__TEXT");
        data[184..192].copy_from_slice(&0x4000u64.to_le_bytes());
        data[192..200].copy_from_slice(&4u64.to_le_bytes());
        data[200..208].copy_from_slice(&312u64.to_le_bytes());
        data[224..228].copy_from_slice(&1u32.to_le_bytes());
        data[232..238].copy_from_slice(b"__text");
        data[248..254].copy_from_slice(b"__TEXT");
        data[264..272].copy_from_slice(&0x4000u64.to_le_bytes());
        assert!(inspect(&data).is_ok());
        data[208..216].copy_from_slice(&4u64.to_le_bytes());
        data[272..280].copy_from_slice(&4u64.to_le_bytes());
        assert!(inspect(&data).is_err()); // offset 0 lies outside file range 312..316
        data[280..284].copy_from_slice(&312u32.to_le_bytes());
        assert!(inspect(&data).is_ok());
    }
}
