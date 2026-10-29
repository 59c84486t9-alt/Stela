//! Decoding of chained rebases and binds, including PAC metadata.
//!
//! Layouts follow `mach-o/fixup-chains.h`; validation follows dyld's
//! `MachOAnalyzer.cpp`, `ChainedFixups.cpp` and `MachOLoaded.cpp`.
use super::load_plan::{LoadPlan, SegmentPlan};
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

/// Decoded imports and pointer slots; binding still requires a real resolver.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedFixups {
    pub preferred_base: u64,
    pub load_base: u64,
    pub pointer_formats: Vec<u16>,
    pub rebases: Vec<RebaseFixup>,
    pub imports: Vec<Import>,
    pub binds: Vec<BindFixup>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authenticated_rebases: Vec<AuthenticatedRebaseFixup>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authenticated_binds: Vec<AuthenticatedBindFixup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Import {
    pub library_ordinal: i32,
    pub weak: bool,
    pub name: String,
    /// Original signed table addend, before the slot's inline addend.
    pub addend: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BindFixup {
    pub segment_index: usize,
    pub file_offset: u64,
    pub guest_address: u64,
    pub raw: u64,
    pub pointer_format: u16,
    pub import_index: u32,
    pub inline_addend: i64,
    /// Checked sum of import-table and inline addends. Apply this exactly once.
    pub addend: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Authentication {
    pub key: stela_contracts::pauth::Key,
    pub diversity: u16,
    pub address_diversity: bool,
}
impl Authentication {
    pub fn modifier(self, slot: u64) -> u64 {
        if self.address_diversity {
            (slot & 0x0000_ffff_ffff_ffff) | (u64::from(self.diversity) << 48)
        } else {
            u64::from(self.diversity)
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedRebaseFixup {
    pub segment_index: usize,
    pub file_offset: u64,
    pub guest_address: u64,
    pub raw: u64,
    pub target: u64,
    pub pointer_format: u16,
    pub authentication: Authentication,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedBindFixup {
    pub segment_index: usize,
    pub file_offset: u64,
    pub guest_address: u64,
    pub raw: u64,
    pub pointer_format: u16,
    pub import_index: u32,
    pub addend: i64,
    pub authentication: Authentication,
}
#[derive(Debug, Clone, Serialize)]
pub struct SignedRebaseFixup {
    pub fixup: AuthenticatedRebaseFixup,
    pub modifier: u64,
    pub value: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct SignedFixupPlan {
    pub preferred_base: u64,
    pub load_base: u64,
    pub pointer_formats: Vec<u16>,
    pub rebases: Vec<RebaseFixup>,
    pub authenticated_rebases: Vec<SignedRebaseFixup>,
    pub address_space: u64,
    pub pauth_profile: &'static str,
}
impl DecodedFixups {
    /// Compute signed values for every rebase under one process key set.
    /// Nothing is written and no bind is resolved.
    pub fn sign_rebases<S: stela_contracts::pauth::Signer>(
        &self,
        context: &S,
    ) -> Result<SignedFixupPlan>
    where
        S::Error: Into<anyhow::Error>,
    {
        ensure!(
            self.binds.is_empty() && self.authenticated_binds.is_empty(),
            "authenticated rebase planning requires explicit bind resolution first"
        );
        let authenticated_rebases = self
            .authenticated_rebases
            .iter()
            .map(|fixup| {
                ensure!(
                    fixup.target < (1 << 47),
                    "authenticated rebase target exceeds lower-user VA47 profile"
                );
                let modifier = fixup.authentication.modifier(fixup.guest_address);
                // dyld's pointer-metadata helper preserves null before selecting
                // a key; the architectural PAC instruction itself signs null.
                let value = if fixup.target == 0 {
                    0
                } else {
                    context
                        .sign(fixup.authentication.key, fixup.target, modifier)
                        .map_err(Into::into)?
                };
                Ok(SignedRebaseFixup {
                    fixup: fixup.clone(),
                    modifier,
                    value,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(SignedFixupPlan {
            preferred_base: self.preferred_base,
            load_base: self.load_base,
            pointer_formats: self.pointer_formats.clone(),
            rebases: self.rebases.clone(),
            authenticated_rebases,
            address_space: context.address_space(),
            pauth_profile: context.profile_id(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pointer {
    Rebase(u64),
    AuthenticatedRebase {
        target: u64,
        authentication: Authentication,
    },
    AuthenticatedBind {
        import_index: u32,
        authentication: Authentication,
    },
    Bind {
        import_index: u32,
        inline_addend: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RebaseFixup {
    pub segment_index: usize,
    pub file_offset: u64,
    /// Relocated guest address of the eight-byte pointer slot.
    pub guest_address: u64,
    pub raw: u64,
    /// The decoded address with its high 8 bits; PAC bits are never stripped.
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

fn decode_imports(
    payload: &[u8],
    imports: usize,
    symbols: usize,
    count: u32,
    format: u32,
    libraries: usize,
) -> Result<Vec<Import>> {
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
    let mut records = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let at = imports + index * size;
        let (ordinal, weak, name, addend) = if format == 3 {
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
                bits & (1 << 16) != 0,
                (bits >> 32) as usize,
                u64_at(payload, at + 8)? as i64,
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
                bits & (1 << 8) != 0,
                (bits >> 9) as usize,
                if format == 2 {
                    i64::from(u32_at(payload, at + 4)? as i32)
                } else {
                    0
                },
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
        records.push((ordinal, weak, name, addend));
    }
    // Sorted offsets allow suffix-interned names while scanning the pool only
    // once, avoiding repeated whole-pool searches on malicious import tables.
    let mut nul = None;
    let mut ends = BTreeMap::new();
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
        ends.insert(name, end);
    }
    let mut result = Vec::with_capacity(count as usize);
    let mut name_bytes = 0usize;
    for (library_ordinal, weak, name, addend) in records {
        let end = ends[&name];
        name_bytes = name_bytes
            .checked_add(end - name)
            .context("chained-fixup decoded symbol bytes overflow")?;
        ensure!(
            name_bytes <= MAX_PAYLOAD,
            "chained-fixup decoded symbol names exceed planner limit"
        );
        let name = std::str::from_utf8(&strings[name..end])
            .context("unsupported non-UTF-8 chained-fixup import symbol")?
            .to_owned();
        result.push(Import {
            library_ordinal,
            weak,
            name,
            addend,
        });
    }
    Ok(result)
}

fn decode_pointer(
    raw: u64,
    format: u16,
    imports: u32,
    preferred: u64,
    loaded: u64,
    allow_authentication: bool,
) -> Result<(Pointer, u64)> {
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
        if auth {
            ensure!(
                allow_authentication,
                "unsupported authenticated chained-fixup pointer (format {format}); explicit PAC decoding/signing is required"
            );
            let authentication = Authentication {
                key: match (raw >> 49) & 3 {
                    0 => stela_contracts::pauth::Key::Ia,
                    1 => stela_contracts::pauth::Key::Ib,
                    2 => stela_contracts::pauth::Key::Da,
                    _ => stela_contracts::pauth::Key::Db,
                },
                diversity: ((raw >> 32) & 0xffff) as u16,
                address_diversity: raw & (1 << 48) != 0,
            };
            let pointer = if bind {
                Pointer::AuthenticatedBind {
                    import_index: (raw & (if format == 12 { 0xffffff } else { 0xffff })) as u32,
                    authentication,
                }
            } else {
                Pointer::AuthenticatedRebase {
                    target: loaded
                        .checked_add(raw & 0xffff_ffff)
                        .context("authenticated rebase target overflows address range")?,
                    authentication,
                }
            };
            return Ok((pointer, ((raw >> 51) & 0x7ff) * 8));
        }
        if bind {
            let ordinal_mask = if format == 12 { 0xffffff } else { 0xffff };
            let encoded = ((raw >> 32) & 0x7ffff) as i64;
            let inline_addend = if encoded & 0x40000 != 0 {
                encoded - 0x80000
            } else {
                encoded
            };
            return Ok((
                Pointer::Bind {
                    import_index: (raw & ordinal_mask) as u32,
                    inline_addend,
                },
                ((raw >> 51) & 0x7ff) * 8,
            ));
        }
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
            return Ok((
                Pointer::Bind {
                    import_index: ordinal as u32,
                    inline_addend: ((raw >> 24) & 0xff) as i64,
                },
                ((raw >> 51) & 0xfff) * 4,
            ));
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
    Ok((Pointer::Rebase(value), next))
}

/// Rebase-only plan; binds still need resolution.
pub fn plan(data: &[u8], image: &LoadPlan, load_base: u64) -> Result<FixupPlan> {
    let decoded = decode(data, image, load_base)?;
    if let Some(bind) = decoded.binds.first() {
        bail!(
            "unsupported chained-fixup bind (format {}) at slot {:#x}; dependency/symbol resolution is required",
            bind.pointer_format,
            bind.guest_address
        );
    }
    Ok(FixupPlan {
        preferred_base: decoded.preferred_base,
        load_base: decoded.load_base,
        pointer_formats: decoded.pointer_formats,
        rebases: decoded.rebases,
    })
}

/// Decode an image's chained-fixup payload without resolving symbols.
///
/// A missing payload decodes as empty. Authenticated pointers, compressed
/// symbol pools, multi-start 64-bit pages and non-userland formats are errors.
/// Every pointer slot is disjoint, fully file-backed and within its chain page.
/// Bind addends combine import and inline values with checked i64 arithmetic.
/// High 8 address bits are kept.
pub fn decode(data: &[u8], image: &LoadPlan, load_base: u64) -> Result<DecodedFixups> {
    decode_impl(data, image, load_base, false)
}

/// Decode authenticated records as metadata; never strip signatures or invent
/// signing keys. Authenticated rebases use image-relative 32-bit targets in all
/// admitted ARM64E formats, including the otherwise absolute format1.
pub fn decode_authenticated(
    data: &[u8],
    image: &LoadPlan,
    load_base: u64,
) -> Result<DecodedFixups> {
    decode_impl(data, image, load_base, true)
}
fn decode_impl(
    data: &[u8],
    image: &LoadPlan,
    load_base: u64,
    allow_authentication: bool,
) -> Result<DecodedFixups> {
    ensure!(
        image.slice_bytes == data.len() as u64 && image.slice_sha256 == stela_formats::sha256(data),
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
    let mut walk = Walk {
        data,
        preferred_base,
        load_base,
        slide: i128::from(load_base) - i128::from(preferred_base),
        allow_authentication,
        imports_count: 0,
        slots: BTreeMap::new(),
        guest_slots: BTreeMap::new(),
        result: DecodedFixups {
            preferred_base,
            load_base,
            pointer_formats: vec![],
            rebases: vec![],
            imports: vec![],
            binds: vec![],
            authenticated_rebases: vec![],
            authenticated_binds: vec![],
        },
    };
    let Some(payload) = payload(data, image)? else {
        return Ok(walk.result);
    };
    let header = Header::read(payload)?;
    walk.imports_count = header.imports_count;
    walk.result.imports = decode_imports(
        payload,
        header.imports,
        header.symbols,
        header.imports_count,
        header.imports_format,
        image.dependencies.len(),
    )?;
    let segment_count = u32_at(payload, header.starts)? as usize;
    ensure!(
        segment_count == image.segments.len(),
        "unsupported chained-fixup segment count mismatch"
    );
    let table_size = segment_count
        .checked_mul(4)
        .and_then(|value| value.checked_add(4))
        .context("chained-fixup segment table overflow")?;
    let table_end = header
        .starts
        .checked_add(table_size)
        .context("chained-fixup starts extent overflow")?;
    ensure!(
        table_end <= header.imports,
        "chained-fixup segment table overlaps imports"
    );
    check_segments(data, image)?;
    let mut records = Records {
        payload,
        starts: header.starts,
        table_end,
        imports: header.imports,
        imports_count: header.imports_count,
        preferred_base,
        metadata: BTreeMap::new(),
        formats: BTreeSet::new(),
    };
    for (segment_index, segment) in image.segments.iter().enumerate() {
        let Some(record) = records.read(segment_index, segment)? else {
            continue;
        };
        for page_index in 0..record.pages {
            let start = u16_at(record.data, 22 + page_index * 2)?;
            if start == 0xffff {
                continue;
            }
            ensure!(
                start & 0x8000 == 0,
                "unsupported multi-start chain in 64-bit image"
            );
            ensure!(
                u64::from(start).is_multiple_of(record.stride()),
                "misaligned chained-fixup page start"
            );
            walk.page(segment_index, segment, &record, page_index, start)?;
        }
    }
    walk.result.pointer_formats = records.formats.into_iter().collect();
    Ok(walk.result)
}

/// The image's chained-fixup payload, checked against its load plan; `None`
/// when the image has none.
fn payload<'a>(data: &'a [u8], image: &LoadPlan) -> Result<Option<&'a [u8]>> {
    let payloads: Vec<_> = image
        .payloads
        .iter()
        .filter(|payload| payload.command == COMMAND || payload.role == "chained_fixups")
        .collect();
    ensure!(payloads.len() <= 1, "duplicate chained-fixup payloads");
    let Some(source) = payloads.first() else {
        return Ok(None);
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
        source.sha256 == stela_formats::sha256(payload),
        "chained-fixup payload differs from load plan"
    );
    Ok(Some(payload))
}

/// `dyld_chained_fixups_header`: the table offsets and the import format.
struct Header {
    starts: usize,
    imports: usize,
    symbols: usize,
    imports_count: u32,
    imports_format: u32,
}

impl Header {
    fn read(payload: &[u8]) -> Result<Self> {
        ensure!(
            u32_at(payload, 0)? == 0,
            "unsupported chained-fixup header version"
        );
        let header = Self {
            starts: u32_at(payload, 4)? as usize,
            imports: u32_at(payload, 8)? as usize,
            symbols: u32_at(payload, 12)? as usize,
            imports_count: u32_at(payload, 16)?,
            imports_format: u32_at(payload, 20)?,
        };
        ensure!(
            u32_at(payload, 24)? == 0,
            "unsupported chained-fixup compressed/unknown symbols format"
        );
        ensure!(
            header.starts >= 28
                && header.starts < header.imports
                && header.imports <= header.symbols
                && header.symbols <= payload.len(),
            "invalid chained-fixup header table offsets"
        );
        Ok(header)
    }
}

/// Every segment's file extent lies within its memory and the file, and no
/// two segments share file bytes or memory.
fn check_segments(data: &[u8], image: &LoadPlan) -> Result<()> {
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
    Ok(())
}

/// The `dyld_chained_starts_in_segment` records of one payload, which must
/// not overlap and must share one pointer format.
struct Records<'a> {
    payload: &'a [u8],
    starts: usize,
    table_end: usize,
    imports: usize,
    imports_count: u32,
    preferred_base: u64,
    metadata: BTreeMap<u64, u64>,
    formats: BTreeSet<u16>,
}

/// One segment's starts record.
struct Record<'a> {
    data: &'a [u8],
    page_size: u64,
    format: u16,
    pages: usize,
}

impl Record<'_> {
    /// The alignment of a chain's slots.
    fn stride(&self) -> u64 {
        if matches!(self.format, 1 | 9 | 12) {
            8
        } else {
            4
        }
    }
}

impl<'a> Records<'a> {
    /// Segment `segment_index`'s record; `None` when it has no chains.
    fn read(&mut self, segment_index: usize, segment: &SegmentPlan) -> Result<Option<Record<'a>>> {
        let payload = self.payload;
        let relative = u32_at(payload, self.starts + 4 + segment_index * 4)? as usize;
        if relative == 0 {
            return Ok(None);
        }
        let record = self
            .starts
            .checked_add(relative)
            .context("chained-fixup segment record overflow")?;
        ensure!(
            record >= self.table_end && record < self.imports,
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
            record_end <= self.imports,
            "chained-fixup segment record exceeds starts region"
        );
        insert_range(
            &mut self.metadata,
            record as u64,
            size as u64,
            "chained-fixup segment records",
        )?;
        let data = bytes(payload, record, size)?;
        let page_size = u64::from(u16_at(data, 4)?);
        ensure!(
            matches!(page_size, 4096 | 16384),
            "unsupported chained-fixup page size {page_size}"
        );
        let format = u16_at(data, 6)?;
        ensure!(
            matches!(format, 1 | 2 | 6 | 9 | 12),
            "unsupported chained-fixup pointer format {format}"
        );
        self.formats.insert(format);
        ensure!(
            self.formats.len() == 1,
            "chained-fixup pointer formats differ across segments"
        );
        let offset = u64_at(data, 8)?;
        ensure!(
            segment.guest.address.checked_sub(self.preferred_base) == Some(offset),
            "chained-fixup segment offset disagrees with load command"
        );
        ensure!(
            u32_at(data, 16)? == 0,
            "unsupported nonzero max_valid_pointer in 64-bit chained fixups"
        );
        let pages = usize::from(u16_at(data, 20)?);
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
            self.imports_count == 0 || self.imports_count < ordinal_limit,
            "chained-fixup imports count exceeds pointer format limit"
        );
        Ok(Some(Record {
            data,
            page_size,
            format,
            pages,
        }))
    }
}

/// The chain walk over one image: the slots seen so far and the fixups
/// decoded from them.
struct Walk<'a> {
    data: &'a [u8],
    preferred_base: u64,
    load_base: u64,
    slide: i128,
    allow_authentication: bool,
    imports_count: u32,
    slots: BTreeMap<u64, u64>,
    guest_slots: BTreeMap<u64, u64>,
    result: DecodedFixups,
}

impl Walk<'_> {
    /// Decodes the chain that starts `start` bytes into page `page_index`.
    fn page(
        &mut self,
        segment_index: usize,
        segment: &SegmentPlan,
        record: &Record<'_>,
        page_index: usize,
        start: u16,
    ) -> Result<()> {
        let page_size = record.page_size;
        let format = record.format;
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
                self.slide,
                "slot",
            )?;
            insert_range(&mut self.slots, file_offset, 8, "chained-fixup file slots")?;
            insert_range(
                &mut self.guest_slots,
                guest_address,
                8,
                "chained-fixup guest slots",
            )?;
            let result = &self.result;
            ensure!(
                result.rebases.len()
                    + result.binds.len()
                    + result.authenticated_rebases.len()
                    + result.authenticated_binds.len()
                    < MAX_FIXUPS,
                "chained-fixup pointer count exceeds planner limit"
            );
            let raw = u64_at(self.data, usize::try_from(file_offset)?)?;
            let (pointer, next) = decode_pointer(
                raw,
                format,
                self.imports_count,
                self.preferred_base,
                self.load_base,
                self.allow_authentication,
            )
            .with_context(|| {
                format!(
                    "chained-fixup segment {segment_index} page {page_index} slot {guest_address:#x}"
                )
            })?;
            self.push(
                pointer,
                segment_index,
                file_offset,
                guest_address,
                raw,
                format,
            )?;
            if next == 0 {
                return Ok(());
            }
            position = position
                .checked_add(next)
                .context("chained-fixup next offset overflow")?;
        }
    }

    fn push(
        &mut self,
        pointer: Pointer,
        segment_index: usize,
        file_offset: u64,
        guest_address: u64,
        raw: u64,
        pointer_format: u16,
    ) -> Result<()> {
        let result = &mut self.result;
        match pointer {
            Pointer::Rebase(value) => result.rebases.push(RebaseFixup {
                segment_index,
                file_offset,
                guest_address,
                raw,
                value,
                pointer_format,
            }),
            Pointer::AuthenticatedRebase {
                target,
                authentication,
            } => result.authenticated_rebases.push(AuthenticatedRebaseFixup {
                segment_index,
                file_offset,
                guest_address,
                raw,
                target,
                pointer_format,
                authentication,
            }),
            Pointer::AuthenticatedBind {
                import_index,
                authentication,
            } => result.authenticated_binds.push(AuthenticatedBindFixup {
                segment_index,
                file_offset,
                guest_address,
                raw,
                pointer_format,
                import_index,
                addend: result.imports[import_index as usize].addend,
                authentication,
            }),
            Pointer::Bind {
                import_index,
                inline_addend,
            } => {
                let addend = result.imports[import_index as usize]
                    .addend
                    .checked_add(inline_addend)
                    .with_context(|| {
                        format!(
                            "chained-fixup bind addend overflows i64 at slot {guest_address:#x}"
                        )
                    })?;
                result.binds.push(BindFixup {
                    segment_index,
                    file_offset,
                    guest_address,
                    raw,
                    pointer_format,
                    import_index,
                    inline_addend,
                    addend,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
