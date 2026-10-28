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
mod tests {
    use super::*;
    use crate::load_plan::{Dependency, EntryPoint, FileRange, GuestRange, Payload, SegmentPlan};

    fn pointer(
        raw: u64,
        format: u16,
        imports: u32,
        preferred: u64,
        loaded: u64,
    ) -> Result<(u64, u64)> {
        let (decoded, next) = decode_pointer(raw, format, imports, preferred, loaded, false)?;
        match decoded {
            Pointer::Rebase(value) => Ok((value, next)),
            _ => bail!("test expected an unauthenticated rebase"),
        }
    }

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
        image.slice_sha256 = stela_formats::sha256(data);
        image.slice_bytes = data.len() as u64;
        for payload in &mut image.payloads {
            let start = payload.file.offset as usize;
            payload.sha256 =
                stela_formats::sha256(&data[start..start + payload.file.bytes as usize]);
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
            file_type: 2,
            dylib_identity: None,
            segments: vec![
                segment("__TEXT", BASE, 0, 0x1000),
                segment("__DATA", BASE + 0x4000, 0x1000, 0x4000),
                segment("__LINKEDIT", BASE + 0x8000, PAYLOAD as u64, 0x1000),
            ],
            entry: Some(EntryPoint {
                image_offset: 0,
                file_offset: 0,
                guest_address: BASE,
                stack_size: 0,
            }),
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

    fn bind_raw(format: u16, import_index: u32, addend: i64, next: u64) -> u64 {
        if matches!(format, 1 | 9 | 12) {
            (1 << 62) | u64::from(import_index) | (((addend as u64) & 0x7ffff) << 32) | (next << 51)
        } else {
            (1 << 63) | u64::from(import_index) | (((addend as u64) & 0xff) << 24) | (next << 51)
        }
    }

    #[test]
    fn decodes_all_bind_formats_import_addends_weak_flags_and_signed_extrema() {
        for pointer_format in [1, 2, 6, 9, 12] {
            let inline: &[i64] = if matches!(pointer_format, 1 | 9 | 12) {
                &[-262144, -1, 0, 1, 262143]
            } else {
                &[0, 1, 127, 128, 255]
            };
            for import_format in [1, 2, 3] {
                let table_addends: &[i64] = match import_format {
                    1 => &[0],
                    2 => &[i32::MIN as i64, -1, 0, i32::MAX as i64],
                    _ => &[i64::MIN, -1, 0, i64::MAX],
                };
                for table_addend in table_addends {
                    for inline_addend in inline {
                        let (mut data, mut image) = fixture(pointer_format);
                        let weak_bit = if import_format == 3 { 16 } else { 8 };
                        imports(
                            &mut data,
                            &mut image,
                            import_format,
                            1 << weak_bit,
                            b"_fixture\0",
                        );
                        match import_format {
                            2 => put32(&mut data, PAYLOAD + 72, *table_addend as u32),
                            3 => put64(&mut data, PAYLOAD + 76, *table_addend as u64),
                            _ => (),
                        }
                        let raw = bind_raw(pointer_format, 0, *inline_addend, 0);
                        put64(&mut data, SLOT, raw);
                        refresh(&data, &mut image);
                        let combined = i128::from(*table_addend) + i128::from(*inline_addend);
                        if let Ok(combined) = i64::try_from(combined) {
                            let decoded = decode(&data, &image, BASE + 0x100000).unwrap();
                            assert_eq!(
                                decoded.imports,
                                [Import {
                                    library_ordinal: 0,
                                    weak: true,
                                    name: "_fixture".into(),
                                    addend: *table_addend
                                }]
                            );
                            assert_eq!(
                                decoded.binds,
                                [BindFixup {
                                    segment_index: 1,
                                    file_offset: SLOT as u64,
                                    guest_address: BASE + 0x104028,
                                    raw,
                                    pointer_format,
                                    import_index: 0,
                                    inline_addend: *inline_addend,
                                    addend: combined
                                }]
                            );
                            assert!(decoded.rebases.is_empty());
                            assert_eq!(decoded.pointer_formats, [pointer_format]);
                            assert!(
                                error(&data, &image).contains("unsupported chained-fixup bind")
                            );
                        } else {
                            assert!(
                                format!("{:#}", decode(&data, &image, BASE).unwrap_err())
                                    .contains("bind addend overflows i64")
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn mixed_bind_rebase_chain_shares_slot_validation_and_retains_import_order() {
        for format in [1, 2, 6, 9, 12] {
            let (mut data, mut image) = fixture(format);
            imports(&mut data, &mut image, 1, 0, b"_fixture\0");
            let next = if matches!(format, 1 | 9 | 12) { 1 } else { 2 };
            let base = if matches!(format, 1 | 2) { BASE } else { 0 };
            put64(&mut data, SLOT, raw(format, base + 0x4120, 0, next));
            put64(&mut data, SLOT + 8, bind_raw(format, 0, 0, next));
            put64(&mut data, SLOT + 16, raw(format, base + 0x4130, 0, 0));
            refresh(&data, &mut image);
            let decoded = decode(&data, &image, BASE - 0x100000).unwrap();
            assert_eq!(decoded.rebases.len(), 2);
            assert_eq!(decoded.rebases[0].value, BASE - 0x100000 + 0x4120);
            assert_eq!(decoded.binds[0].file_offset, SLOT as u64 + 8);
            assert_eq!(decoded.rebases[1].file_offset, SLOT as u64 + 16);
            assert_eq!(decoded.imports[0].name, "_fixture");
            // A bind does not stop validation of later slots in the chain.
            put64(&mut data, SLOT + 8, bind_raw(format, 0, 0, 0xfff));
            refresh(&data, &mut image);
            assert!(
                format!("{:#}", decode(&data, &image, BASE).unwrap_err())
                    .contains("slot escapes page")
            );
        }
    }

    #[test]
    fn import_suffix_names_and_addend_records_keep_original_indices() {
        let (mut data, mut image) = fixture(6);
        let payload = &mut data[PAYLOAD..];
        put32(payload, 12, 84); // two eight-byte import/addend records
        put32(payload, 16, 2);
        put32(payload, 20, 2);
        put32(payload, 68, 1 << 9); // import 0 points to suffix "fixture"
        put32(payload, 72, (-7i32) as u32);
        put32(payload, 76, 1 << 8); // import 1 is weak and names "_fixture"
        put32(payload, 80, 11);
        payload[84..93].copy_from_slice(b"_fixture\0");
        image.payloads[0].file.bytes = 93;
        put64(&mut data, SLOT, bind_raw(6, 1, 255, 0));
        refresh(&data, &mut image);
        let decoded = decode(&data, &image, BASE).unwrap();
        assert_eq!(
            decoded.imports,
            [
                Import {
                    library_ordinal: 0,
                    weak: false,
                    name: "fixture".into(),
                    addend: -7
                },
                Import {
                    library_ordinal: 0,
                    weak: true,
                    name: "_fixture".into(),
                    addend: 11
                }
            ]
        );
        assert_eq!(decoded.binds[0].import_index, 1);
        assert_eq!(decoded.binds[0].inline_addend, 255);
        assert_eq!(decoded.binds[0].addend, 266);
    }

    #[test]
    fn decoded_bind_reserved_bits_ordinals_pac_and_symbol_text_still_fail() {
        for format in [1, 2, 6, 9, 12] {
            let (mut data, mut image) = fixture(format);
            imports(&mut data, &mut image, 1, 0, b"_fixture\0");
            let reserved = match format {
                1 | 9 => 16,
                12 => 24,
                _ => 32,
            };
            put64(&mut data, SLOT, bind_raw(format, 0, 0, 0) | (1 << reserved));
            refresh(&data, &mut image);
            assert!(
                format!("{:#}", decode(&data, &image, BASE).unwrap_err()).contains("reserved bits")
            );
            put64(&mut data, SLOT, bind_raw(format, 1, 0, 0));
            refresh(&data, &mut image);
            assert!(
                format!("{:#}", decode(&data, &image, BASE).unwrap_err())
                    .contains("ordinal 1 exceeds imports")
            );
            if matches!(format, 1 | 9 | 12) {
                put64(&mut data, SLOT, bind_raw(format, 0, 0, 0) | (1 << 63));
                refresh(&data, &mut image);
                assert!(
                    format!("{:#}", decode(&data, &image, BASE).unwrap_err())
                        .contains("unsupported authenticated")
                );
            }
        }
        let (mut data, mut image) = fixture(6);
        imports(&mut data, &mut image, 1, 0, &[0xff, 0]);
        assert!(format!("{:#}", decode(&data, &image, BASE).unwrap_err()).contains("non-UTF-8"));
    }

    fn auth_raw(
        _format: u16,
        target_or_ordinal: u32,
        bind: bool,
        key: u64,
        diversity: u16,
        address_diversity: bool,
        next: u64,
    ) -> u64 {
        (1 << 63)
            | (u64::from(bind) << 62)
            | u64::from(target_or_ordinal)
            | (u64::from(diversity) << 32)
            | (u64::from(address_diversity) << 48)
            | (key << 49)
            | (next << 51)
    }
    #[test]
    fn authenticated_rebases_preserve_all_metadata_and_always_use_image_relative_targets() {
        use stela_contracts::pauth::Key;
        for format in [1, 9, 12] {
            for (key, domain) in [(0, Key::Ia), (1, Key::Ib), (2, Key::Da), (3, Key::Db)] {
                for diversity in [0, 0x1234, u16::MAX] {
                    for address_diversity in [false, true] {
                        let (mut data, mut image) = fixture(format);
                        let raw = auth_raw(
                            format,
                            u32::MAX,
                            false,
                            key,
                            diversity,
                            address_diversity,
                            0,
                        );
                        put64(&mut data, SLOT, raw);
                        refresh(&data, &mut image);
                        assert!(error(&data, &image).contains("unsupported authenticated"));
                        let decoded = decode_authenticated(&data, &image, BASE + 0x100000).unwrap();
                        assert!(
                            decoded.rebases.is_empty()
                                && decoded.binds.is_empty()
                                && decoded.authenticated_binds.is_empty()
                        );
                        assert_eq!(
                            decoded.authenticated_rebases,
                            [AuthenticatedRebaseFixup {
                                segment_index: 1,
                                file_offset: SLOT as u64,
                                guest_address: BASE + 0x104028,
                                raw,
                                target: BASE + 0x100000 + u64::from(u32::MAX),
                                pointer_format: format,
                                authentication: Authentication {
                                    key: domain,
                                    diversity,
                                    address_diversity
                                },
                            }]
                        );
                    }
                }
            }
            let (mut data, mut image) = fixture(format);
            put64(&mut data, SLOT, auth_raw(format, 1, false, 0, 0, false, 0));
            refresh(&data, &mut image);
            assert!(decode_authenticated(&data, &image, u64::MAX).is_err());
        }
    }
    #[test]
    fn authenticated_binds_keep_table_addends_reserved_bits_and_ordinal_checks() {
        for format in [1, 9, 12] {
            let (mut data, mut image) = fixture(format);
            imports(&mut data, &mut image, 2, 0, b"_fixture\0");
            put32(&mut data, PAYLOAD + 72, (-7i32) as u32);
            let raw = auth_raw(format, 0, true, 2, 0xffff, true, 0);
            put64(&mut data, SLOT, raw);
            refresh(&data, &mut image);
            let decoded = decode_authenticated(&data, &image, BASE).unwrap();
            assert!(
                decoded.rebases.is_empty()
                    && decoded.authenticated_rebases.is_empty()
                    && decoded.binds.is_empty()
            );
            assert_eq!(decoded.authenticated_binds[0].addend, -7);
            assert_eq!(
                decoded.authenticated_binds[0].authentication.key,
                stela_contracts::pauth::Key::Da
            );
            assert_eq!(
                decoded.authenticated_binds[0].authentication.diversity,
                u16::MAX
            );
            let context = stela_runtime::pauth::Context::new(
                1,
                stela_runtime::pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]),
            );
            assert!(decoded.sign_rebases(&context).is_err());
            for changed in [raw | 1, raw | (1 << if format == 12 { 24 } else { 16 })] {
                put64(&mut data, SLOT, changed);
                refresh(&data, &mut image);
                assert!(decode_authenticated(&data, &image, BASE).is_err());
            }
        }
    }
    #[test]
    fn mixed_authenticated_chain_is_complete_and_signing_never_strips_or_invents_keys() {
        use stela_runtime::pauth::{Context, Keys};
        let (mut data, mut image) = fixture(12);
        put64(&mut data, SLOT, raw(12, 0x4120, 0, 1));
        put64(
            &mut data,
            SLOT + 8,
            auth_raw(12, 0x4130, false, 0, 0x1234, true, 1),
        );
        put64(
            &mut data,
            SLOT + 16,
            auth_raw(12, 0x4140, false, 2, 0, false, 0),
        );
        refresh(&data, &mut image);
        let decoded = decode_authenticated(&data, &image, BASE).unwrap();
        assert_eq!(decoded.rebases.len(), 1);
        assert_eq!(decoded.authenticated_rebases.len(), 2);
        let ib_only = Context::new(7, Keys::from_ib_words(1, 2));
        assert!(decoded.sign_rebases(&ib_only).is_err());
        let full = Context::new(7, Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]));
        let signed = decoded.sign_rebases(&full).unwrap();
        assert_eq!(signed.rebases.len(), 1);
        assert_eq!(signed.address_space, 7);
        assert_eq!(signed.authenticated_rebases[0].modifier, 0x1234000100004030);
        for record in &signed.authenticated_rebases {
            let result = full
                .authenticate(
                    record.fixup.authentication.key,
                    record.value,
                    record.modifier,
                )
                .unwrap();
            assert!(result.authenticated);
            assert_eq!(result.pointer, record.fixup.target);
        }
        // Null handling belongs to dyld's helper, not the PAC instruction.
        let mut null = decoded.clone();
        null.rebases.clear();
        null.authenticated_rebases.truncate(1);
        null.authenticated_rebases[0].target = 0;
        assert_eq!(
            null.sign_rebases(&ib_only).unwrap().authenticated_rebases[0].value,
            0
        );
        assert_ne!(full.sign(stela_contracts::pauth::Key::Ia, 0, 0).unwrap(), 0);
        assert_eq!(
            Authentication {
                key: stela_contracts::pauth::Key::Ia,
                diversity: 0x4321,
                address_diversity: true
            }
            .modifier(0xeeee123456789abc),
            0x4321123456789abc
        );
    }

    #[test]
    fn library_metadata_needs_no_entry_and_legacy_plan_json_remains_unchanged() {
        let (data, mut image) = fixture(6);
        image.file_type = 6;
        image.entry = None;
        image.dylib_identity = Some(Dependency {
            command: 0xd,
            name: "@rpath/libFixture.dylib".into(),
            timestamp: 0,
            current_version: 0,
            compatibility_version: 0,
        });
        let decoded = decode(&data, &image, BASE).unwrap();
        assert_eq!(decoded.rebases.len(), 1);
        assert!(decoded.imports.is_empty() && decoded.binds.is_empty());
        let legacy = serde_json::to_value(plan(&data, &image, BASE).unwrap()).unwrap();
        let object = legacy.as_object().unwrap();
        assert_eq!(object.len(), 4);
        for field in ["preferred_base", "load_base", "pointer_formats", "rebases"] {
            assert!(object.contains_key(field));
        }
        assert!(!object.contains_key("imports") && !object.contains_key("binds"));
    }
}
