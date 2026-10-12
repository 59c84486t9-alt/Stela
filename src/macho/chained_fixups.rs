//! Checked planning of unauthenticated, image-local Apple chained rebases.
//!
//! Layout/stride facts: Apple's include/mach-o/fixup-chains.h. Validation and
//! address interpretation: common/MachOAnalyzer.cpp, mach_o/ChainedFixups.cpp
//! and common/MachOLoaded.cpp in apple-oss-distributions/dyld. No Apple source
//! is copied here. This module never writes mappings or resolves/signs imports.
use super::load_plan::LoadPlan;
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const COMMAND: u32 = 0x80000034;
const MAX_FIXUPS: usize = 1_048_576;
const MAX_PAYLOAD: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct FixupPlan {
    pub preferred_base: u64,
    pub load_base: u64,
    pub pointer_formats: Vec<u16>,
    pub rebases: Vec<RebaseFixup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RebaseFixup {
    pub segment_index: usize,
    pub file_offset: u64,
    /// Relocated guest address of the eight-byte pointer slot.
    pub guest_address: u64,
    pub raw: u64,
    /// Decoded address including its original high8 bits; never PAC-stripped.
    pub value: u64,
    pub pointer_format: u16,
}

fn bytes(data: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .context("chained-fixup extent overflow")?;
    data.get(offset..end)
        .context("truncated chained-fixup extent")
}
fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(bytes(data, offset, 2)?.try_into()?))
}
fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(data, offset, 4)?.try_into()?))
}
fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes(data, offset, 8)?.try_into()?))
}
fn moved(address: u64, slide: i128, role: &str) -> Result<u64> {
    u64::try_from(i128::from(address) + slide)
        .with_context(|| format!("chained-fixup {role} slide overflows address range"))
}
fn insert_range(
    ranges: &mut BTreeMap<u64, u64>,
    start: u64,
    length: u64,
    role: &str,
) -> Result<()> {
    let end = start
        .checked_add(length)
        .with_context(|| format!("{role} extent overflow"))?;
    if let Some((_, previous_end)) = ranges.range(..=start).next_back() {
        ensure!(*previous_end <= start, "overlapping/duplicate {role}");
    }
    if let Some((next_start, _)) = ranges.range(start..).next() {
        ensure!(end <= *next_start, "overlapping/duplicate {role}");
    }
    ranges.insert(start, end);
    Ok(())
}

fn validate_imports(
    payload: &[u8],
    imports: usize,
    symbols: usize,
    count: u32,
    format: u32,
    libraries: usize,
) -> Result<()> {
    let size = match format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => bail!("unsupported chained-fixup imports format {format}"),
    };
    ensure!(
        count as usize <= MAX_FIXUPS,
        "chained-fixup import count exceeds planner limit"
    );
    let extent = (count as usize)
        .checked_mul(size)
        .context("chained-fixup imports size overflow")?;
    let end = imports
        .checked_add(extent)
        .context("chained-fixup imports extent overflow")?;
    ensure!(
        imports >= 28 && end <= symbols && symbols <= payload.len(),
        "chained-fixup imports/symbol extents overlap or exceed payload"
    );
    let strings = &payload[symbols..];
    let mut names = BTreeSet::new();
    for index in 0..count as usize {
        let at = imports + index * size;
        let (ordinal, name) = if format == 3 {
            let bits = u64_at(payload, at)?;
            ensure!(
                (bits >> 17) & 0x7fff == 0,
                "chained-fixup import {index} has nonzero reserved bits"
            );
            let ordinal = (bits & 0xffff) as i32;
            (
                if ordinal > 0xfff0 {
                    ordinal - 0x10000
                } else {
                    ordinal
                },
                (bits >> 32) as usize,
            )
        } else {
            let bits = u32_at(payload, at)?;
            let ordinal = (bits & 0xff) as i32;
            (
                if ordinal > 0xf0 {
                    ordinal - 0x100
                } else {
                    ordinal
                },
                (bits >> 9) as usize,
            )
        };
        ensure!(
            ordinal >= -3 && (ordinal <= 0 || ordinal as usize <= libraries),
            "chained-fixup import {index} has invalid library ordinal {ordinal}"
        );
        ensure!(
            name < strings.len(),
            "chained-fixup import {index} symbol offset exceeds pool"
        );
        names.insert(name);
    }
    // Sorted offsets allow suffix-interned names while scanning the pool only
    // once, avoiding repeated whole-pool searches on malicious import tables.
    let mut nul = None;
    for name in names {
        let end = match nul {
            Some(end) if end >= name => end,
            _ => {
                name + strings[name..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .context("unterminated chained-fixup import symbol")?
            }
        };
        ensure!(end > name, "empty chained-fixup import symbol");
        nul = Some(end);
    }
    Ok(())
}

fn pointer(raw: u64, format: u16, imports: u32, preferred: u64, loaded: u64) -> Result<(u64, u64)> {
    let arm64e = matches!(format, 1 | 9 | 12);
    let (target, high, next) = if arm64e {
        let bind = raw & (1 << 62) != 0;
        let auth = raw & (1 << 63) != 0;
        if bind {
            let ordinal_bits = if format == 12 { 24 } else { 16 };
            let ordinal = raw & ((1u64 << ordinal_bits) - 1);
            let zero_mask = ((1u64 << 32) - 1) & !((1u64 << ordinal_bits) - 1);
            ensure!(
                raw & zero_mask == 0,
                "chained-fixup ARM64E bind has nonzero reserved bits"
            );
            ensure!(
                ordinal < u64::from(imports),
                "chained-fixup ARM64E bind ordinal {ordinal} exceeds imports count {imports}"
            );
        }
        ensure!(
            !auth,
            "unsupported authenticated chained-fixup pointer (format {format}); PAC representation/signing is required"
        );
        ensure!(
            !bind,
            "unsupported chained-fixup bind (format {format}); dependency/symbol resolution is required"
        );
        (
            raw & ((1 << 43) - 1),
            (raw >> 43) & 0xff,
            ((raw >> 51) & 0x7ff) * 8,
        )
    } else {
        let bind = raw & (1 << 63) != 0;
        if bind {
            let ordinal = raw & 0xffffff;
            ensure!(
                (raw >> 32) & 0x7ffff == 0,
                "chained-fixup 64-bit bind has nonzero reserved bits"
            );
            ensure!(
                ordinal < u64::from(imports),
                "chained-fixup bind ordinal {ordinal} exceeds imports count {imports}"
            );
            bail!(
                "unsupported chained-fixup bind (format {format}); dependency/symbol resolution is required"
            );
        }
        ensure!(
            (raw >> 44) & 0x7f == 0,
            "chained-fixup rebase has nonzero reserved bits"
        );
        (
            raw & ((1 << 36) - 1),
            (raw >> 36) & 0xff,
            ((raw >> 51) & 0xfff) * 4,
        )
    };
    let unpacked = target | (high << 56);
    let value = if matches!(format, 1 | 2) {
        moved(
            unpacked,
            i128::from(loaded) - i128::from(preferred),
            "target",
        )?
    } else {
        unpacked
            .checked_add(loaded)
            .context("chained-fixup offset target overflows address range")?
    };
    Ok((value, next))
}

/// Decode one validated thin image's chained payload into immutable writes.
///
/// Absence of a payload is an empty plan, not proof that other loader work is
/// complete. Binds, authenticated pointers, compressed symbol pools, multi-start
/// 64-bit pages and non-userland formats fail explicitly. Input slots must be
/// disjoint, fully file-backed and contained in their declared chain page.
/// High8 address bits are retained; this plan does not authorize dereferencing
/// tagged/noncanonical addresses under the native direct-RAM profile.
pub fn plan(data: &[u8], image: &LoadPlan, load_base: u64) -> Result<FixupPlan> {
    ensure!(
        image.slice_bytes == data.len() as u64 && image.slice_sha256 == stela_core::sha256(data),
        "chained-fixup image identity differs from load plan"
    );
    let text: Vec<_> = image
        .segments
        .iter()
        .filter(|segment| segment.name == "__TEXT")
        .collect();
    ensure!(
        text.len() == 1,
        "chained-fixup planning requires one preferred __TEXT base"
    );
    let preferred_base = text[0].guest.address;
    let mut result = FixupPlan {
        preferred_base,
        load_base,
        pointer_formats: vec![],
        rebases: vec![],
    };
    let payloads: Vec<_> = image
        .payloads
        .iter()
        .filter(|payload| payload.command == COMMAND || payload.role == "chained_fixups")
        .collect();
    ensure!(payloads.len() <= 1, "duplicate chained-fixup payloads");
    let Some(source) = payloads.first() else {
        return Ok(result);
    };
    ensure!(
        source.command == COMMAND && source.role == "chained_fixups",
        "chained-fixup payload identity mismatch"
    );
    let payload = bytes(
        data,
        usize::try_from(source.file.offset)?,
        usize::try_from(source.file.bytes)?,
    )?;
    ensure!(
        payload.len() <= MAX_PAYLOAD,
        "chained-fixup payload exceeds planner limit"
    );
    ensure!(
        source.sha256 == stela_core::sha256(payload),
        "chained-fixup payload differs from load plan"
    );
    ensure!(
        u32_at(payload, 0)? == 0,
        "unsupported chained-fixup header version"
    );
    let starts = u32_at(payload, 4)? as usize;
    let imports = u32_at(payload, 8)? as usize;
    let symbols = u32_at(payload, 12)? as usize;
    let imports_count = u32_at(payload, 16)?;
    let imports_format = u32_at(payload, 20)?;
    ensure!(
        u32_at(payload, 24)? == 0,
        "unsupported chained-fixup compressed/unknown symbols format"
    );
    ensure!(
        starts >= 28 && starts < imports && imports <= symbols && symbols <= payload.len(),
        "invalid chained-fixup header table offsets"
    );
    validate_imports(
        payload,
        imports,
        symbols,
        imports_count,
        imports_format,
        image.dependencies.len(),
    )?;
    let segment_count = u32_at(payload, starts)? as usize;
    ensure!(
        segment_count == image.segments.len(),
        "unsupported chained-fixup segment count mismatch"
    );
    let table_size = segment_count
        .checked_mul(4)
        .and_then(|value| value.checked_add(4))
        .context("chained-fixup segment table overflow")?;
    let table_end = starts
        .checked_add(table_size)
        .context("chained-fixup starts extent overflow")?;
    ensure!(
        table_end <= imports,
        "chained-fixup segment table overlaps imports"
    );
    let slide = i128::from(load_base) - i128::from(preferred_base);
    let mut metadata = BTreeMap::new();
    let mut slots = BTreeMap::new();
    let mut guest_slots = BTreeMap::new();
    let mut formats = BTreeSet::new();
    let mut segment_files = BTreeMap::new();
    let mut segment_memory = BTreeMap::new();
    for segment in &image.segments {
        ensure!(
            segment.file.bytes <= segment.guest.bytes,
            "chained-fixup segment file extent exceeds memory"
        );
        bytes(
            data,
            usize::try_from(segment.file.offset)?,
            usize::try_from(segment.file.bytes)?,
        )?;
        if segment.file.bytes != 0 {
            insert_range(
                &mut segment_files,
                segment.file.offset,
                segment.file.bytes,
                "segment file ranges",
            )?;
        }
        if segment.guest.bytes != 0 {
            insert_range(
                &mut segment_memory,
                segment.guest.address,
                segment.guest.bytes,
                "segment memory ranges",
            )?;
        }
    }
    for (segment_index, segment) in image.segments.iter().enumerate() {
        let relative = u32_at(payload, starts + 4 + segment_index * 4)? as usize;
        if relative == 0 {
            continue;
        }
        let record = starts
            .checked_add(relative)
            .context("chained-fixup segment record overflow")?;
        ensure!(
            record >= table_end && record < imports,
            "chained-fixup segment record overlaps table or imports"
        );
        let size = u32_at(payload, record)? as usize;
        ensure!(
            size >= 22 && size.is_multiple_of(2),
            "invalid chained-fixup segment record size"
        );
        let record_end = record
            .checked_add(size)
            .context("chained-fixup record extent overflow")?;
        ensure!(
            record_end <= imports,
            "chained-fixup segment record exceeds starts region"
        );
        insert_range(
            &mut metadata,
            record as u64,
            size as u64,
            "chained-fixup segment records",
        )?;
        let record_data = bytes(payload, record, size)?;
        let page_size = u64::from(u16_at(record_data, 4)?);
        ensure!(
            matches!(page_size, 4096 | 16384),
            "unsupported chained-fixup page size {page_size}"
        );
        let format = u16_at(record_data, 6)?;
        ensure!(
            matches!(format, 1 | 2 | 6 | 9 | 12),
            "unsupported chained-fixup pointer format {format}"
        );
        formats.insert(format);
        ensure!(
            formats.len() == 1,
            "chained-fixup pointer formats differ across segments"
        );
        let offset = u64_at(record_data, 8)?;
        ensure!(
            segment.guest.address.checked_sub(preferred_base) == Some(offset),
            "chained-fixup segment offset disagrees with load command"
        );
        ensure!(
            u32_at(record_data, 16)? == 0,
            "unsupported nonzero max_valid_pointer in 64-bit chained fixups"
        );
        let pages = usize::from(u16_at(record_data, 20)?);
        ensure!(
            22 + pages * 2 <= size,
            "chained-fixup page-start table exceeds record"
        );
        ensure!(
            pages as u64 <= segment.guest.bytes.div_ceil(page_size),
            "chained-fixup page count exceeds segment memory"
        );
        let ordinal_limit = if matches!(format, 1 | 9) {
            0xffff
        } else {
            0xffffff
        };
        ensure!(
            imports_count == 0 || imports_count < ordinal_limit,
            "chained-fixup imports count exceeds pointer format limit"
        );
        let stride = if matches!(format, 1 | 9 | 12) {
            8u64
        } else {
            4u64
        };
        for page_index in 0..pages {
            let start = u16_at(record_data, 22 + page_index * 2)?;
            if start == 0xffff {
                continue;
            }
            ensure!(
                start & 0x8000 == 0,
                "unsupported multi-start chain in 64-bit image"
            );
            ensure!(
                u64::from(start).is_multiple_of(stride),
                "misaligned chained-fixup page start"
            );
            let page_offset = page_index as u64 * page_size;
            let mut position = u64::from(start);
            let mut steps = 0usize;
            loop {
                steps += 1;
                ensure!(
                    steps <= (page_size / 8) as usize,
                    "chained-fixup page walk exceeds disjoint-slot bound"
                );
                ensure!(
                    position.checked_add(8).is_some_and(|end| end <= page_size),
                    "chained-fixup slot escapes page"
                );
                let within = page_offset
                    .checked_add(position)
                    .context("chained-fixup segment position overflow")?;
                ensure!(
                    within
                        .checked_add(8)
                        .is_some_and(|end| end <= segment.file.bytes && end <= segment.guest.bytes),
                    "chained-fixup slot is not fully file-backed in segment"
                );
                let file_offset = segment
                    .file
                    .offset
                    .checked_add(within)
                    .context("chained-fixup file offset overflow")?;
                let guest_address = moved(
                    segment
                        .guest
                        .address
                        .checked_add(within)
                        .context("chained-fixup guest slot overflow")?,
                    slide,
                    "slot",
                )?;
                insert_range(&mut slots, file_offset, 8, "chained-fixup file slots")?;
                insert_range(
                    &mut guest_slots,
                    guest_address,
                    8,
                    "chained-fixup guest slots",
                )?;
                ensure!(
                    result.rebases.len() < MAX_FIXUPS,
                    "chained-fixup rebase count exceeds planner limit"
                );
                let raw = u64_at(data, usize::try_from(file_offset)?)?;
                let (value, next) = pointer(raw, format, imports_count, preferred_base, load_base)
                    .with_context(|| format!("chained-fixup segment {segment_index} page {page_index} slot {guest_address:#x}"))?;
                result.rebases.push(RebaseFixup {
                    segment_index,
                    file_offset,
                    guest_address,
                    raw,
                    value,
                    pointer_format: format,
                });
                if next == 0 {
                    break;
                }
                position = position
                    .checked_add(next)
                    .context("chained-fixup next offset overflow")?;
            }
        }
    }
    result.pointer_formats = formats.into_iter().collect();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::load_plan::{
        Dependency, EntryPoint, FileRange, GuestRange, Payload, SegmentPlan,
    };

    const BASE: u64 = 0x100000000;
    const PAYLOAD: usize = 0x5000;
    const SLOT: usize = 0x1028;
    const RECORD: usize = 44;

    fn put16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn refresh(data: &[u8], image: &mut LoadPlan) {
        image.slice_sha256 = stela_core::sha256(data);
        image.slice_bytes = data.len() as u64;
        for payload in &mut image.payloads {
            let start = payload.file.offset as usize;
            payload.sha256 =
                stela_core::sha256(&data[start..start + payload.file.bytes as usize]);
        }
    }
    fn raw(format: u16, target: u64, high: u8, next: u64) -> u64 {
        let shift = if matches!(format, 1 | 9 | 12) { 43 } else { 36 };
        target | (u64::from(high) << shift) | (next << 51)
    }
    fn fixture(format: u16) -> (Vec<u8>, LoadPlan) {
        let mut data = vec![0u8; 0x6000];
        let header = &mut data[PAYLOAD..];
        put32(header, 4, 28);
        put32(header, 8, 68);
        put32(header, 12, 68);
        put32(header, 20, 1);
        put32(header, 28, 3);
        put32(header, 36, 16); // segment 1 record, relative to starts-in-image
        put32(header, RECORD, 24);
        put16(header, RECORD + 4, 4096);
        put16(header, RECORD + 6, format);
        put64(header, RECORD + 8, 0x4000);
        put16(header, RECORD + 20, 1);
        put16(header, RECORD + 22, 0x28);
        let target = if matches!(format, 1 | 2) {
            BASE + 0x4120
        } else {
            0x4120
        };
        put64(&mut data, SLOT, raw(format, target, 0, 0));
        let segment = |name: &str, guest, file, size| SegmentPlan {
            name: name.into(),
            guest: GuestRange {
                address: guest,
                bytes: size,
            },
            file: FileRange {
                offset: file,
                bytes: size,
            },
            zero_fill: GuestRange {
                address: guest + size,
                bytes: 0,
            },
            maximum_protection: 3,
            initial_protection: 3,
            flags: 0,
        };
        let mut image = LoadPlan {
            schema_version: 1,
            slice_sha256: String::new(),
            slice_bytes: 0,
            cpu_type: 0x100000c,
            cpu_subtype: if matches!(format, 1 | 9 | 12) { 2 } else { 0 },
            architecture: if matches!(format, 1 | 9 | 12) {
                "arm64e".into()
            } else {
                "arm64".into()
            },
            header_flags: 0,
            segments: vec![
                segment("__TEXT", BASE, 0, 0x1000),
                segment("__DATA", BASE + 0x4000, 0x1000, 0x4000),
                segment("__LINKEDIT", BASE + 0x8000, PAYLOAD as u64, 0x1000),
            ],
            entry: EntryPoint {
                image_offset: 0,
                file_offset: 0,
                guest_address: BASE,
                stack_size: 0,
            },
            dependencies: vec![],
            dylinker: None,
            rpaths: vec![],
            payloads: vec![Payload {
                command: COMMAND,
                role: "chained_fixups".into(),
                file: FileRange {
                    offset: PAYLOAD as u64,
                    bytes: 68,
                },
                sha256: String::new(),
            }],
            deferred_commands: vec![],
            execution_supported: false,
            unresolved_requirements: vec![],
        };
        refresh(&data, &mut image);
        (data, image)
    }
    fn imports(data: &mut [u8], image: &mut LoadPlan, format: u32, bits: u64, symbol: &[u8]) {
        let size = match format {
            1 => 4,
            2 => 8,
            3 => 16,
            _ => unreachable!(),
        };
        let symbols = 68 + size;
        let header = &mut data[PAYLOAD..];
        put32(header, 12, symbols as u32);
        put32(header, 16, 1);
        put32(header, 20, format);
        put64(header, 68, bits);
        header[symbols..symbols + symbol.len()].copy_from_slice(symbol);
        image.payloads[0].file.bytes = (symbols + symbol.len()) as u64;
        refresh(data, image);
    }
    fn error(data: &[u8], image: &LoadPlan) -> String {
        format!("{:#}", plan(data, image, BASE).unwrap_err())
    }

    #[test]
    fn all_five_formats_relocate_slots_and_targets_in_both_directions() {
        for format in [1, 2, 6, 9, 12] {
            let (data, image) = fixture(format);
            for loaded in [BASE - 0x100000, BASE, BASE + 0x300000] {
                let planned = plan(&data, &image, loaded).unwrap();
                assert_eq!(planned.preferred_base, BASE);
                assert_eq!(planned.load_base, loaded);
                assert_eq!(planned.pointer_formats, [format]);
                assert_eq!(
                    planned.rebases,
                    [RebaseFixup {
                        segment_index: 1,
                        file_offset: SLOT as u64,
                        guest_address: loaded + 0x4028,
                        raw: u64_at(&data, SLOT).unwrap(),
                        value: loaded + 0x4120,
                        pointer_format: format
                    }]
                );
            }
        }
    }

    #[test]
    fn preserves_high8_bits_and_full_target_width() {
        for format in [1, 2, 6, 9, 12] {
            for high in [0u8, 1, 0x7f, 0xff] {
                let (mut data, mut image) = fixture(format);
                let target = if matches!(format, 1 | 2) {
                    BASE + 0x4120
                } else {
                    0x4120
                };
                put64(&mut data, SLOT, raw(format, target, high, 0));
                refresh(&data, &mut image);
                for loaded in [BASE - 0x100000, BASE + 0x100000] {
                    let planned = plan(&data, &image, loaded).unwrap();
                    assert_eq!(
                        planned.rebases[0].value,
                        (u64::from(high) << 56) + loaded + 0x4120
                    );
                }
            }
        }
    }

    #[test]
    fn walks_four_or_eight_byte_stride_and_supports_16k_pages() {
        for format in [1, 2, 6, 9, 12] {
            let (mut data, mut image) = fixture(format);
            let stride = if matches!(format, 1 | 9 | 12) { 8 } else { 4 };
            let gap = if stride == 8 { 16 } else { 12 };
            let target = if matches!(format, 1 | 2) { BASE } else { 0 };
            put64(
                &mut data,
                SLOT,
                raw(format, target + 0x4120, 0, gap / stride),
            );
            put64(
                &mut data,
                SLOT + gap as usize,
                raw(format, target + 0x4130, 0, 0),
            );
            put16(&mut data, PAYLOAD + RECORD + 4, 16384);
            refresh(&data, &mut image);
            let planned = plan(&data, &image, BASE).unwrap();
            assert_eq!(planned.rebases.len(), 2);
            assert_eq!(planned.rebases[1].file_offset, SLOT as u64 + gap);
            assert_eq!(planned.rebases[1].value, BASE + 0x4130);
        }
    }

    #[test]
    fn empty_payload_absence_and_no_start_pages_are_explicit() {
        let (mut data, mut image) = fixture(6);
        put16(&mut data, PAYLOAD + RECORD + 22, 0xffff);
        refresh(&data, &mut image);
        let planned = plan(&data, &image, BASE).unwrap();
        assert!(planned.rebases.is_empty());
        assert_eq!(planned.pointer_formats, [6]);
        image.payloads.clear();
        let planned = plan(&data, &image, BASE + 0x100000).unwrap();
        assert!(planned.rebases.is_empty() && planned.pointer_formats.is_empty());
    }

    #[test]
    fn validates_all_import_metadata_even_without_bind_slots() {
        for format in [1, 2, 3] {
            for ordinal in [0u64, 1, if format == 3 { 0xfffd } else { 0xfd }] {
                let (mut data, mut image) = fixture(6);
                image.dependencies.push(Dependency {
                    command: 0xc,
                    name: "libFixture.dylib".into(),
                    timestamp: 0,
                    current_version: 0,
                    compatibility_version: 0,
                });
                imports(&mut data, &mut image, format, ordinal, b"_fixture\0");
                assert_eq!(plan(&data, &image, BASE).unwrap().rebases.len(), 1);
            }
        }
        for (format, bits, symbol, message) in [
            (1, 2, &b"_valid\0"[..], "library ordinal"),
            (1, 0xfc, &b"_valid\0"[..], "library ordinal"),
            (1, 100 << 9, &b"_valid\0"[..], "symbol offset"),
            (1, 0, &b"missing-nul"[..], "unterminated"),
            (1, 0, &b"\0"[..], "empty"),
            (3, 1 << 17, &b"_valid\0"[..], "reserved"),
        ] {
            let (mut data, mut image) = fixture(6);
            imports(&mut data, &mut image, format, bits, symbol);
            assert!(error(&data, &image).contains(message));
        }
    }

    #[test]
    fn rejects_bind_and_auth_without_fabricating_plain_pointers() {
        for format in [1, 2, 6, 9, 12] {
            let (mut data, mut image) = fixture(format);
            imports(&mut data, &mut image, 1, 0, b"_fixture\0");
            put64(
                &mut data,
                SLOT,
                1 << if matches!(format, 1 | 9 | 12) { 62 } else { 63 },
            );
            refresh(&data, &mut image);
            assert!(error(&data, &image).contains("unsupported chained-fixup bind"));
            put64(
                &mut data,
                SLOT,
                (1 << if matches!(format, 1 | 9 | 12) { 62 } else { 63 }) | 1,
            );
            refresh(&data, &mut image);
            assert!(error(&data, &image).contains("ordinal 1 exceeds imports"));
        }
        for format in [1, 9, 12] {
            let (mut data, mut image) = fixture(format);
            put64(&mut data, SLOT, (1 << 63) | 0x4120);
            refresh(&data, &mut image);
            assert!(error(&data, &image).contains("unsupported authenticated"));
        }
    }

    #[test]
    fn rejects_bad_headers_record_tables_and_unsupported_formats() {
        for (offset, value, message) in [
            (0, 1, "header version"),
            (4, 20, "header table offsets"),
            (8, 40, "segment table overlaps"),
            (12, 0xffff, "header table offsets"),
            (20, 0, "imports format"),
            (24, 1, "symbols format"),
            (28, 4, "segment count mismatch"),
            (36, 4, "record overlaps"),
            (RECORD, 0xffff, "record size"),
            (RECORD + 8, 0x8000, "segment offset"),
            (RECORD + 16, 1, "max_valid_pointer"),
        ] {
            let (mut data, mut image) = fixture(6);
            put32(&mut data, PAYLOAD + offset, value);
            refresh(&data, &mut image);
            assert!(
                error(&data, &image).contains(message),
                "offset={offset} error={}",
                error(&data, &image)
            );
        }
        for (offset, value, message) in [
            (4, 8192, "page size"),
            (6, 7, "pointer format"),
            (20, 0xffff, "page-start table"),
            (22, 0x8001, "multi-start"),
            (22, 0x29, "misaligned"),
        ] {
            let (mut data, mut image) = fixture(6);
            put16(&mut data, PAYLOAD + RECORD + offset, value);
            refresh(&data, &mut image);
            assert!(error(&data, &image).contains(message));
        }
    }

    #[test]
    fn rejects_page_escape_partial_slots_and_overlapping_writes() {
        for start in [4092u16, 4096] {
            let (mut data, mut image) = fixture(6);
            put16(&mut data, PAYLOAD + RECORD + 22, start);
            refresh(&data, &mut image);
            assert!(error(&data, &image).contains("slot escapes page"));
        }
        let (mut data, mut image) = fixture(6);
        put64(&mut data, SLOT, raw(6, 0x4120, 0, 1));
        refresh(&data, &mut image);
        assert!(error(&data, &image).contains("overlapping/duplicate chained-fixup file slots"));
        let (data, mut image) = fixture(6);
        image.segments[1].file.bytes = 0x2c;
        assert!(error(&data, &image).contains("not fully file-backed"));
        let (mut data, mut image) = fixture(6);
        put64(&mut data, SLOT, raw(6, 0x4120, 0, 0xfff));
        refresh(&data, &mut image);
        assert!(error(&data, &image).contains("slot escapes page"));
    }

    #[test]
    fn duplicate_records_payloads_and_changed_identities_fail() {
        let (mut data, mut image) = fixture(6);
        image.payloads.push(image.payloads[0].clone());
        assert!(error(&data, &image).contains("duplicate chained-fixup payloads"));
        image.payloads.pop();
        data[SLOT] ^= 1;
        assert!(error(&data, &image).contains("image identity"));
        refresh(&data, &mut image);
        image.payloads[0].sha256 = "0".repeat(64);
        assert!(error(&data, &image).contains("payload differs"));
        refresh(&data, &mut image);
        put32(&mut data, PAYLOAD + 40, 16); // second metadata use of segment 1 record
        refresh(&data, &mut image);
        assert!(error(&data, &image).contains("duplicate chained-fixup segment records"));
    }

    #[test]
    fn target_slide_and_offset_overflows_fail_without_wrapping() {
        for format in [1, 2] {
            let (mut data, mut image) = fixture(format);
            put64(&mut data, SLOT, 0);
            refresh(&data, &mut image);
            assert!(
                format!("{:#}", plan(&data, &image, BASE - 1).unwrap_err())
                    .contains("target slide overflows")
            );
        }
        for format in [6, 9, 12] {
            let (data, image) = fixture(format);
            assert!(
                format!("{:#}", plan(&data, &image, u64::MAX - 16).unwrap_err())
                    .contains("slide overflows")
                    || format!("{:#}", plan(&data, &image, u64::MAX - 16).unwrap_err())
                        .contains("offset target overflows")
            );
        }
    }

    #[test]
    fn pointer_bit_boundaries_reserved_fields_and_target_overflow_are_checked() {
        for format in [1, 2, 6, 9, 12] {
            let width = if matches!(format, 1 | 9 | 12) { 43 } else { 36 };
            let target = (1u64 << width) - 1;
            let encoded = raw(format, target, 0xa7, 0);
            let preferred = if matches!(format, 1 | 2) { 0 } else { BASE };
            assert_eq!(
                pointer(encoded, format, 0, preferred, 0).unwrap(),
                ((0xa7u64 << 56) | target, 0)
            );
        }
        for format in [2, 6] {
            assert!(
                format!("{:#}", pointer(1 << 44, format, 0, BASE, BASE).unwrap_err())
                    .contains("reserved")
            );
        }
        for format in [6, 9, 12] {
            assert!(
                format!(
                    "{:#}",
                    pointer(raw(format, 32, 0, 0), format, 0, BASE, u64::MAX - 16).unwrap_err()
                )
                .contains("offset target overflows")
            );
        }
    }
}
