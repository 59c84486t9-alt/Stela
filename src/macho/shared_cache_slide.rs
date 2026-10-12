//! Original-cache slide-chain planning only. No source or mapped pointer is written.
//!
//! Apple dyld fd8d0c4d52320ebf64db34f3cb280310d905c5ae:
//! dyld_cache_format.h (v5 header), fixup-chains.h (cache64e words), and
//! DyldSharedCache.cpp::applyCacheRebases (byte initial offsets / 8-byte next).
use super::shared_cache::{extent, file_identity, hash_file, same_file};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

const SOURCE_PIN: &str = "fd8d0c4d52320ebf64db34f3cb280310d905c5ae";
const PAGE_SIZE: u64 = 16 * 1024;
const NO_REBASE: u16 = 0xffff;
const MAX_FILES: usize = 256;
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_SET_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PAGES: u64 = 262_144;
const MAX_RECORDS: u64 = 64_000_000;
const MAX_SAMPLES: usize = 256;
const ZERO_UUID: &str = "00000000-0000-0000-0000-000000000000";

fn field(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .with_context(|| format!("missing unsigned field {name}"))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("truncated cache metadata")?
            .try_into()?,
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .context("truncated cache metadata")?
            .try_into()?,
    ))
}
fn uuid(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
fn digest(hasher: &Sha256) -> String {
    hex::encode(hasher.clone().finalize())
}

#[derive(Clone, Debug)]
struct Mapping {
    file_index: usize,
    index: usize,
    address: u64,
    size: u64,
    file_offset: u64,
    max_protection: u32,
    initial_protection: u32,
    slide_offset: u64,
    slide_bytes: u64,
    flags: u64,
}
impl Mapping {
    fn value(&self) -> Value {
        json!({"source_cache_index":self.file_index,"mapping_index":self.index,
            "address":self.address,"size":self.size,"file_offset":self.file_offset,
            "max_protection":self.max_protection,"initial_protection":self.initial_protection,
            "slide_info_file_offset":self.slide_offset,"slide_info_bytes":self.slide_bytes,"flags":self.flags})
    }
}
struct Source {
    path: PathBuf,
    file: File,
    identity: Metadata,
    receipt: Value,
    header: Vec<u8>,
    mappings: Vec<Mapping>,
}

fn read_at<R: Read + Seek>(
    reader: &mut R,
    file_bytes: u64,
    offset: u64,
    size: u64,
) -> Result<Vec<u8>> {
    extent(offset, size, file_bytes)?;
    ensure!(
        size <= MAX_METADATA_BYTES,
        "single slide metadata read exceeds bounded budget"
    );
    let mut bytes = vec![0; usize::try_from(size)?];
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn source_mappings(
    source: &mut Source,
    index: usize,
    metadata_bytes: &mut u64,
) -> Result<Vec<Mapping>> {
    let header = &source.header;
    ensure!(
        header.len() >= 460,
        "slide planning requires known modern subcache/mapping header fields"
    );
    let count = u64::from(u32_at(header, 20)?);
    let offset = u64::from(u32_at(header, 16)?);
    ensure!(
        count > 0 && count <= 4096 && offset == header.len() as u64,
        "invalid original cache mapping table"
    );
    let ordinary = read_at(&mut source.file, source.identity.len(), offset, count * 32)?;
    let slide_offset = u64::from(u32_at(header, 312)?);
    let slide_count = u64::from(u32_at(header, 316)?);
    ensure!(
        slide_count == count,
        "original cache slide mapping count differs from mapping table"
    );
    let slide = read_at(
        &mut source.file,
        source.identity.len(),
        slide_offset,
        count * 56,
    )?;
    *metadata_bytes = metadata_bytes
        .checked_add(ordinary.len() as u64 + slide.len() as u64)
        .context("slide metadata byte count overflow")?;
    ensure!(
        *metadata_bytes <= MAX_METADATA_BYTES,
        "slide metadata exceeds 64 MiB budget"
    );
    let declared = source.receipt["mappings"]
        .as_array()
        .context("missing declared mappings")?;
    let declared_slide = source.receipt["slide_mappings"]
        .as_array()
        .context("missing declared slide mappings")?;
    ensure!(
        declared.len() == count as usize && declared_slide.len() == count as usize,
        "manifest mapping tables differ from original file tables"
    );
    let mut result = Vec::new();
    for (mapping_index, (mapping, with_slide)) in ordinary
        .as_chunks::<32>()
        .0
        .iter()
        .zip(slide.as_chunks::<56>().0.iter())
        .enumerate()
    {
        let address = u64_at(mapping, 0)?;
        let size = u64_at(mapping, 8)?;
        let file_offset = u64_at(mapping, 16)?;
        let max_protection = u32_at(mapping, 24)?;
        let initial_protection = u32_at(mapping, 28)?;
        ensure!(
            size > 0 && max_protection & !7 == 0 && initial_protection & !max_protection == 0,
            "invalid original mapping size/protection"
        );
        address
            .checked_add(size)
            .context("mapping VM extent overflow")?;
        extent(file_offset, size, source.identity.len())?;
        ensure!(
            (
                address,
                size,
                file_offset,
                max_protection,
                initial_protection
            ) == (
                u64_at(with_slide, 0)?,
                u64_at(with_slide, 8)?,
                u64_at(with_slide, 16)?,
                u32_at(with_slide, 48)?,
                u32_at(with_slide, 52)?
            ),
            "original slide mapping disagrees with mapping table"
        );
        let slide_offset = u64_at(with_slide, 24)?;
        let slide_bytes = u64_at(with_slide, 32)?;
        let flags = u64_at(with_slide, 40)?;
        ensure!(
            flags & !0x7f == 0,
            "unsupported original cache mapping flags"
        );
        extent(slide_offset, slide_bytes, source.identity.len())?;
        let given = &declared[mapping_index];
        let given_slide = &declared_slide[mapping_index];
        ensure!(
            (
                field(given, "address")?,
                field(given, "size")?,
                field(given, "file_offset")?,
                field(given, "max_protection")?,
                field(given, "initial_protection")?
            ) == (
                address,
                size,
                file_offset,
                u64::from(max_protection),
                u64::from(initial_protection)
            ),
            "manifest mapping metadata does not match original file"
        );
        ensure!(
            (
                field(given_slide, "address")?,
                field(given_slide, "size")?,
                field(given_slide, "file_offset")?,
                field(given_slide, "slide_info_file_offset")?,
                field(given_slide, "slide_info_bytes")?,
                field(given_slide, "flags")?
            ) == (address, size, file_offset, slide_offset, slide_bytes, flags),
            "manifest slide metadata does not match original file"
        );
        ensure!(
            slide_bytes != 0 || given_slide["slide_info_version"].is_null(),
            "manifest invents a slide version for an empty blob"
        );
        if slide_bytes != 0 {
            ensure!(slide_bytes >= 4, "truncated original slide version field");
            let actual = read_at(&mut source.file, source.identity.len(), slide_offset, 4)?;
            ensure!(
                given_slide["slide_info_version"] == u32_at(&actual, 0)?,
                "manifest slide version differs from original blob"
            );
            *metadata_bytes = metadata_bytes
                .checked_add(4)
                .context("metadata byte count overflow")?;
            ensure!(
                *metadata_bytes <= MAX_METADATA_BYTES,
                "slide metadata exceeds 64 MiB budget"
            );
        }
        result.push(Mapping {
            file_index: index,
            index: mapping_index,
            address,
            size,
            file_offset,
            max_protection,
            initial_protection,
            slide_offset,
            slide_bytes,
            flags,
        });
    }
    let mut physical = result
        .iter()
        .map(|mapping| (mapping.file_offset, mapping.size))
        .collect::<Vec<_>>();
    physical.sort_unstable();
    for pair in physical.windows(2) {
        ensure!(
            pair[0].0 + pair[0].1 <= pair[1].0,
            "overlapping original cache physical mappings"
        );
    }
    ensure!(
        result[0].file_offset == 0 && result[0].size >= offset + count * 32,
        "original cache first mapping does not contain its header/table"
    );
    Ok(result)
}

fn open_sources(set: &Value) -> Result<(Vec<Source>, u64)> {
    ensure!(
        set["kind"] == "dyld_shared_cache_set_manifest" && set["cache_set_files_verified"] == true,
        "slide planning requires a verified original cache-set manifest"
    );
    let values = set["files"].as_array().context("cache set has no files")?;
    ensure!(
        !values.is_empty() && values.len() <= MAX_FILES,
        "cache-set file count exceeds bounded profile"
    );
    let mut sources = Vec::new();
    let mut total_bytes = 0u64;
    let mut metadata_bytes = 0u64;
    let mut uuids = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        ensure!(
            field(value, "index")? == index as u64,
            "cache-set file indices are not canonical"
        );
        let path = PathBuf::from(
            value["path"]
                .as_str()
                .context("cache source path is unavailable")?,
        );
        let before = path.symlink_metadata()?;
        ensure!(
            before.file_type().is_file() && !before.file_type().is_symlink(),
            "cache slide source must be a regular nonsymlink file"
        );
        ensure!(
            before.len() <= MAX_FILE_BYTES && before.len() == field(value, "file_bytes")?,
            "cache slide source size differs from receipt or exceeds 32 GiB"
        );
        ensure!(
            file_identity(&before) == value["source_identity"],
            "cache slide source identity differs from manifest"
        );
        total_bytes = total_bytes
            .checked_add(before.len())
            .context("cache-set byte count overflow")?;
        ensure!(
            total_bytes <= MAX_SET_BYTES,
            "cache slide source set exceeds 64 GiB"
        );
        let mut file = File::open(&path)?;
        ensure!(
            same_file(&before, &file.metadata()?),
            "cache slide source changed before opening"
        );
        ensure!(
            value["source_sha256"] == hash_file(&mut file)?,
            "cache slide source SHA256 differs from manifest"
        );
        let prefix = read_at(&mut file, before.len(), 0, 24)?;
        let header_bytes = u64::from(u32_at(&prefix, 16)?);
        ensure!(
            (460..=4096).contains(&header_bytes) && header_bytes.is_multiple_of(8),
            "unsupported slide-planner cache header layout"
        );
        let header = read_at(&mut file, before.len(), 0, header_bytes)?;
        ensure!(
            header.starts_with(b"dyld_v1  arm64e\0") && header[15] == 0,
            "slide planner supports only original dyld_v1 arm64e cache magic"
        );
        ensure!(
            value["header"]["header_sha256"] == stela_core::sha256(&header)
                && value["header"]["uuid"] == uuid(&header[88..104])
                && value["header"]["architecture"] == "arm64e",
            "cache slide source header identity differs from manifest"
        );
        ensure!(
            uuids.insert(uuid(&header[88..104])),
            "duplicate cache slide source UUID"
        );
        ensure!(
            value["header"]["symbol_file_uuid"] == ZERO_UUID
                && header[400..416].iter().all(|byte| *byte == 0),
            "slide planner does not verify a separate symbols-file profile"
        );
        metadata_bytes = metadata_bytes
            .checked_add(24 + header_bytes)
            .context("metadata byte count overflow")?;
        let mut source = Source {
            path,
            file,
            identity: before,
            receipt: value.clone(),
            header,
            mappings: Vec::new(),
        };
        source.mappings = source_mappings(&mut source, index, &mut metadata_bytes)?;
        sources.push(source);
    }
    let base = sources[0].mappings[0].address;
    let header = &sources[0].header;
    let reference_offset = u64::from(u32_at(header, 392)?);
    let count = u64::from(u32_at(header, 396)?);
    ensure!(
        count + 1 == sources.len() as u64 && count < MAX_FILES as u64,
        "cache slide source set does not cover every original subcache reference"
    );
    let base_file_bytes = sources[0].identity.len();
    let references = read_at(
        &mut sources[0].file,
        base_file_bytes,
        reference_offset,
        count * 56,
    )?;
    metadata_bytes = metadata_bytes
        .checked_add(references.len() as u64)
        .context("metadata byte count overflow")?;
    let parent = sources[0]
        .path
        .parent()
        .context("cache source has no parent")?
        .to_owned();
    let name = sources[0]
        .path
        .file_name()
        .context("cache source has no file name")?
        .to_owned();
    for (index, reference) in references.as_chunks::<56>().0.iter().enumerate() {
        let source = &sources[index + 1];
        let suffix_bytes = &reference[24..56];
        let end = suffix_bytes
            .iter()
            .position(|byte| *byte == 0)
            .context("unterminated original subcache suffix")?;
        let suffix =
            std::str::from_utf8(&suffix_bytes[..end]).context("non-UTF8 subcache suffix")?;
        ensure!(
            suffix.starts_with('.') && !suffix.contains(['/', '\\']) && !suffix.contains(".."),
            "unsafe original subcache suffix"
        );
        let mut expected_name = name.clone();
        expected_name.push(suffix);
        ensure!(
            source.path == parent.join(expected_name)
                && source.receipt["declared_file_suffix"] == suffix
                && uuid(&source.header[88..104]) == uuid(&reference[..16]),
            "cache slide source path/UUID does not match original subcache reference"
        );
        let address = base
            .checked_add(u64_at(reference, 16)?)
            .context("subcache VM offset overflow")?;
        ensure!(
            source.mappings[0].address == address && u32_at(&source.header, 396)? == 0,
            "cache slide source has mismatched VM offset or nested references"
        );
    }
    ensure!(
        metadata_bytes <= MAX_METADATA_BYTES,
        "slide metadata exceeds 64 MiB budget"
    );
    Ok((sources, metadata_bytes))
}

#[derive(Debug, PartialEq, Eq)]
struct Decoded {
    target: u64,
    unsigned_target: u64,
    descriptor: u64,
    next: u64,
    authenticated: bool,
    diversity: u16,
    address_diversity: bool,
    key_is_data: bool,
    high8: u8,
}
fn decode(raw: u64, value_add: u64, slide: u64) -> Result<Decoded> {
    let authenticated = raw >> 63 != 0;
    let runtime_offset = raw & ((1u64 << 34) - 1);
    let unsigned_target = value_add
        .checked_add(runtime_offset)
        .and_then(|value| value.checked_add(slide))
        .context("cache slide target arithmetic overflow")?;
    ensure!(
        unsigned_target < 1u64 << 56,
        "cache slide target conflicts with high8 tagging profile"
    );
    let next = (raw >> 52) & 0x7ff;
    if authenticated {
        let diversity = ((raw >> 34) & 0xffff) as u16;
        let address_diversity = raw & (1u64 << 50) != 0;
        let key_is_data = raw & (1u64 << 51) != 0;
        Ok(Decoded {
            target: unsigned_target,
            unsigned_target,
            descriptor: (1u64 << 63)
                | (u64::from(diversity) << 34)
                | ((address_diversity as u64) << 50)
                | ((key_is_data as u64) << 51),
            next,
            authenticated,
            diversity,
            address_diversity,
            key_is_data,
            high8: 0,
        })
    } else {
        ensure!(
            (raw >> 42) & 0x3ff == 0,
            "reserved unauthenticated v5 pointer bits are nonzero"
        );
        let high8 = ((raw >> 34) & 0xff) as u8;
        Ok(Decoded {
            target: unsigned_target | (u64::from(high8) << 56),
            unsigned_target,
            descriptor: u64::from(high8) << 34,
            next,
            authenticated,
            diversity: 0,
            address_diversity: false,
            key_is_data: false,
            high8,
        })
    }
}

#[derive(Default)]
struct Summary {
    pages: u64,
    empty_pages: u64,
    chain_pages: u64,
    records: u64,
    authenticated: u64,
    unauthenticated: u64,
    tagged: u64,
    key_ia: u64,
    key_da: u64,
    address_diversity: u64,
    maximum_chain_length: u64,
    records_hash: Sha256,
    auth_hash: Sha256,
    unauth_hash: Sha256,
    writes_hash: Sha256,
}
impl Summary {
    fn value(&self) -> Value {
        json!({"pages":self.pages,"no_rebase_pages":self.empty_pages,"chain_pages":self.chain_pages,
            "fixup_records":self.records,"authenticated_descriptors":self.authenticated,
            "unauthenticated_values":self.unauthenticated,"tagged_unauthenticated_values":self.tagged,
            "maximum_chain_length":self.maximum_chain_length,"auth_key_ia":self.key_ia,"auth_key_da":self.key_da,
            "auth_address_diversity":self.address_diversity,
            "canonical_records_sha256":digest(&self.records_hash),"authenticated_records_sha256":digest(&self.auth_hash),
            "unauthenticated_records_sha256":digest(&self.unauth_hash),"unauthenticated_writes_sha256":digest(&self.writes_hash)})
    }
}

fn require_mapped_target(target: u64, mappings: &[Mapping]) -> Result<()> {
    let index = mappings
        .partition_point(|mapping| mapping.address <= target)
        .checked_sub(1)
        .context("cache pointer target precedes all cache mappings")?;
    let mapping = &mappings[index];
    let end = mapping
        .address
        .checked_add(mapping.size)
        .context("target mapping extent overflow")?;
    ensure!(
        target < end,
        "cache pointer target is outside strict mapped-cache profile (including one-past)"
    );
    Ok(())
}

fn add_record(
    summary: &mut Summary,
    record: &[u8; 32],
    decoded: &Decoded,
    slid_location: u64,
) -> Result<()> {
    summary.records = summary
        .records
        .checked_add(1)
        .context("fixup count overflow")?;
    ensure!(
        summary.records <= MAX_RECORDS,
        "slide chain exceeds 64-million record budget"
    );
    summary.records_hash.update(record);
    if decoded.authenticated {
        summary.authenticated += 1;
        summary.auth_hash.update(record);
        summary.key_da += u64::from(decoded.key_is_data);
        summary.key_ia += u64::from(!decoded.key_is_data);
        summary.address_diversity += u64::from(decoded.address_diversity);
    } else {
        summary.unauthenticated += 1;
        summary.unauth_hash.update(record);
        summary.tagged += u64::from(decoded.high8 != 0);
        summary.writes_hash.update(slid_location.to_le_bytes());
        summary.writes_hash.update(decoded.target.to_le_bytes());
    }
    Ok(())
}

struct WalkContext<'a> {
    preferred_base: u64,
    slide: u64,
    all_mappings: &'a [Mapping],
    metadata_extents: &'a [(u64, u64)],
    global: &'a mut Summary,
    samples: &'a mut Vec<Value>,
    sample_limit: usize,
}

fn walk<R: Read + Seek>(
    reader: &mut R,
    file_bytes: u64,
    mapping: &Mapping,
    context: &mut WalkContext<'_>,
) -> Result<Value> {
    let mut summary = Summary::default();
    let mut value = mapping.value();
    if mapping.slide_bytes == 0 {
        value["status"] = json!("no_slide_info_declared");
        value["summary"] = summary.value();
        return Ok(value);
    }
    ensure!(
        mapping.size.is_multiple_of(PAGE_SIZE)
            && mapping.address.is_multiple_of(PAGE_SIZE)
            && mapping.file_offset.is_multiple_of(PAGE_SIZE),
        "slide mapping is outside aligned 16-KiB profile"
    );
    ensure!(
        mapping.max_protection & 2 != 0 && mapping.max_protection & 4 == 0,
        "slide mapping is not declared non-executable writable data"
    );
    ensure!(mapping.slide_bytes >= 24, "truncated v5 slide-info header");
    let header = read_at(reader, file_bytes, mapping.slide_offset, 24)?;
    ensure!(
        u32_at(&header, 0)? == 5,
        "unsupported original cache slide-info version"
    );
    ensure!(
        u64::from(u32_at(&header, 4)?) == PAGE_SIZE && u32_at(&header, 12)? == 0,
        "unsupported slide page size or reserved v5 header word"
    );
    let count = u64::from(u32_at(&header, 8)?);
    let value_add = u64_at(&header, 16)?;
    ensure!(
        value_add == context.preferred_base,
        "v5 value_add differs from original shared-cache base"
    );
    ensure!(
        count == mapping.size / PAGE_SIZE && mapping.slide_bytes == 24 + count * 2,
        "v5 page table does not exactly cover its mapping/blob"
    );
    ensure!(
        context
            .global
            .pages
            .checked_add(count)
            .context("slide page count overflow")?
            <= MAX_PAGES,
        "slide plan exceeds 262144-page budget"
    );
    let starts = read_at(reader, file_bytes, mapping.slide_offset + 24, count * 2)?;
    summary.pages = count;
    context.global.pages += count;
    for (page_index, bytes) in starts.as_chunks::<2>().0.iter().enumerate() {
        let start = u16::from_le_bytes(*bytes);
        if start == NO_REBASE {
            summary.empty_pages += 1;
            context.global.empty_pages += 1;
            continue;
        }
        summary.chain_pages += 1;
        context.global.chain_pages += 1;
        let mut offset = u64::from(start);
        ensure!(
            offset.is_multiple_of(8) && offset + 8 <= PAGE_SIZE,
            "invalid initial v5 chain byte offset"
        );
        let page_offset = (page_index as u64)
            .checked_mul(PAGE_SIZE)
            .context("slide page offset overflow")?;
        let page_file_offset = mapping
            .file_offset
            .checked_add(page_offset)
            .context("slide page file offset overflow")?;
        let page = read_at(reader, file_bytes, page_file_offset, PAGE_SIZE)?;
        let mut chain_length = 0u64;
        loop {
            chain_length += 1;
            let pointer_file_offset = page_file_offset
                .checked_add(offset)
                .context("pointer file offset overflow")?;
            let preceding = context
                .metadata_extents
                .partition_point(|(start, _)| *start < pointer_file_offset + 8);
            ensure!(
                preceding == 0 || context.metadata_extents[preceding - 1].1 <= pointer_file_offset,
                "chain pointer overlaps original slide-info metadata"
            );
            let raw = u64_at(&page, offset as usize)?;
            let decoded = decode(raw, value_add, context.slide)?;
            let preferred_target = decoded
                .unsigned_target
                .checked_sub(context.slide)
                .context("preferred target underflow")?;
            require_mapped_target(preferred_target, context.all_mappings)?;
            let location = mapping
                .address
                .checked_add(page_offset)
                .and_then(|value| value.checked_add(offset))
                .context("chain VM location overflow")?;
            let slid_location = location
                .checked_add(context.slide)
                .context("slid chain location overflow")?;
            let mut record = [0u8; 32];
            for (index, number) in [location, raw, decoded.target, decoded.descriptor]
                .iter()
                .enumerate()
            {
                record[index * 8..index * 8 + 8].copy_from_slice(&number.to_le_bytes());
            }
            add_record(&mut summary, &record, &decoded, slid_location)?;
            add_record(context.global, &record, &decoded, slid_location)?;
            if context.samples.len() < context.sample_limit {
                context.samples.push(json!({"source_cache_index":mapping.file_index,"mapping_index":mapping.index,
                    "page_index":page_index,"file_offset":pointer_file_offset,"unslid_location":location,
                    "slid_location":slid_location,"raw":raw,"unsigned_target":decoded.unsigned_target,
                    "target_class":"mapped_cache_address",
                    "unauthenticated_value":if decoded.authenticated {None} else {Some(decoded.target)},
                    "authenticated":decoded.authenticated,"descriptor":decoded.descriptor,
                    "auth":if decoded.authenticated {Some(json!({"diversity":decoded.diversity,
                        "address_diversity":decoded.address_diversity,"key":if decoded.key_is_data {"DA"} else {"IA"},
                        "signed_value":Value::Null,"authentication_performed":false}))} else {None},
                    "high8":decoded.high8,"next_8byte_units":decoded.next}));
            }
            if decoded.next == 0 {
                summary.maximum_chain_length = summary.maximum_chain_length.max(chain_length);
                context.global.maximum_chain_length =
                    context.global.maximum_chain_length.max(chain_length);
                break;
            }
            let next = offset
                .checked_add(decoded.next * 8)
                .context("v5 next pointer offset overflow")?;
            ensure!(
                next > offset && next + 8 <= PAGE_SIZE,
                "v5 next pointer exits page or overlaps a prior slot"
            );
            offset = next;
        }
    }
    value["status"] = json!("v5_chain_metadata_planned");
    value["slide_info_version"] = json!(5);
    value["page_size"] = json!(PAGE_SIZE);
    value["value_add"] = json!(value_add);
    value["summary"] = summary.value();
    Ok(value)
}

/// Plan exact original ARM64e v5 pointer metadata within Apple's declared ASLR
/// range. Authenticated pointers remain descriptors: no PAC is removed or made.
pub fn plan(set: &Value, load_base: u64, sample_limit: usize) -> Result<Value> {
    ensure!(
        sample_limit <= MAX_SAMPLES,
        "slide samples exceed bounded 256-record limit"
    );
    let (mut sources, mut metadata_bytes) = open_sources(set)?;
    let preferred_base = sources[0].mappings[0].address;
    let maximum_slide = u64_at(&sources[0].header, 240)?;
    ensure!(
        preferred_base.is_multiple_of(PAGE_SIZE) && load_base.is_multiple_of(PAGE_SIZE),
        "cache preferred/requested base is not absolutely 16-KiB aligned"
    );
    ensure!(
        u64_at(&sources[0].header, 224)? == preferred_base,
        "original shared-region base differs from first cache mapping"
    );
    ensure!(
        set["files"][0]["header"]["maximum_slide"] == maximum_slide,
        "manifest maximum slide differs from original header"
    );
    let shared_region_bytes = u64_at(&sources[0].header, 232)?;
    ensure!(shared_region_bytes > 0, "original shared region is empty");
    let shared_region_end = preferred_base
        .checked_add(shared_region_bytes)
        .context("original shared-region extent overflow")?;
    shared_region_end
        .checked_add(maximum_slide)
        .context("maximum slid shared-region extent overflow")?;
    let slide = load_base
        .checked_sub(preferred_base)
        .context("cache load base precedes original preferred base")?;
    ensure!(
        slide <= maximum_slide && slide.is_multiple_of(PAGE_SIZE),
        "cache load base exceeds declared maximum slide or 16-KiB alignment"
    );
    let mut all_mappings = sources
        .iter()
        .flat_map(|source| source.mappings.clone())
        .collect::<Vec<_>>();
    all_mappings.sort_by_key(|mapping| mapping.address);
    let mut expected = BTreeSet::new();
    for mapping in &all_mappings {
        let mapping_end = mapping
            .address
            .checked_add(mapping.size)
            .context("mapping VM extent overflow")?;
        ensure!(
            mapping.address >= preferred_base && mapping_end <= shared_region_end,
            "original cache mapping is outside declared shared-region extent"
        );

        mapping
            .address
            .checked_add(mapping.size)
            .and_then(|value| value.checked_add(slide))
            .context("slid cache mapping extent overflow")?;
        ensure!(
            expected.insert((
                mapping.file_index,
                mapping.address,
                mapping.size,
                mapping.file_offset,
                mapping.max_protection,
                mapping.initial_protection
            )),
            "duplicate cache mapping"
        );
    }
    for pair in all_mappings.windows(2) {
        ensure!(
            pair[0].address + pair[0].size <= pair[1].address,
            "overlapping original cache-set VM mappings"
        );
    }
    let mut declared = BTreeSet::new();
    for mapping in set["combined_mappings"]
        .as_array()
        .context("missing combined cache mappings")?
    {
        ensure!(
            declared.insert((
                usize::try_from(field(mapping, "source_cache_index")?)?,
                field(mapping, "address")?,
                field(mapping, "size")?,
                field(mapping, "file_offset")?,
                u32::try_from(field(mapping, "max_protection")?)?,
                u32::try_from(field(mapping, "initial_protection")?)?
            )),
            "duplicate manifest combined mapping"
        );
    }
    ensure!(
        declared == expected,
        "manifest combined mappings differ from original source mappings"
    );
    let mut summaries = Vec::new();
    let mut global = Summary::default();
    let mut samples = Vec::new();
    for source in &mut sources {
        let mut blobs = source
            .mappings
            .iter()
            .filter(|mapping| mapping.slide_bytes != 0)
            .map(|mapping| (mapping.slide_offset, mapping.slide_bytes))
            .collect::<Vec<_>>();
        blobs.sort_unstable();
        for pair in blobs.windows(2) {
            ensure!(
                pair[0].0 + pair[0].1 <= pair[1].0,
                "overlapping original slide-info blobs"
            );
        }
        let metadata_extents = blobs
            .iter()
            .map(|(start, size)| (*start, *start + *size))
            .collect::<Vec<_>>();
        for mapping in &source.mappings {
            metadata_bytes = metadata_bytes
                .checked_add(mapping.slide_bytes)
                .context("slide metadata count overflow")?;
            ensure!(
                metadata_bytes <= MAX_METADATA_BYTES,
                "slide metadata exceeds 64 MiB budget"
            );
            let mut context = WalkContext {
                preferred_base,
                slide,
                all_mappings: &all_mappings,
                metadata_extents: &metadata_extents,
                global: &mut global,
                samples: &mut samples,
                sample_limit,
            };
            summaries.push(walk(
                &mut source.file,
                source.identity.len(),
                mapping,
                &mut context,
            )?);
        }
    }
    for source in &mut sources {
        ensure!(
            source.receipt["source_sha256"] == hash_file(&mut source.file)?,
            "original cache source bytes changed during slide planning"
        );
        let current = source.path.symlink_metadata()?;
        ensure!(
            current.file_type().is_file()
                && !current.file_type().is_symlink()
                && same_file(&source.identity, &source.file.metadata()?)
                && same_file(&source.identity, &current),
            "original cache source identity changed during slide planning"
        );
    }
    let identities=sources.iter().map(|source|json!({"path":source.path.to_string_lossy(),
        "source_sha256":source.receipt["source_sha256"],"uuid":source.receipt["header"]["uuid"],
        "header_sha256":source.receipt["header"]["header_sha256"],"source_identity":file_identity(&source.identity),
        "header_bytes":source.header.len(),"uninterpreted_header_extension_bytes":source.header.len().saturating_sub(552)}))
        .collect::<Vec<_>>();
    Ok(
        json!({"schema_version":1,"kind":"dyld_shared_cache_slide_plan","preferred_base":preferred_base,
        "load_base":load_base,"slide":slide,"maximum_slide":maximum_slide,
        "shared_region_bytes":shared_region_bytes,"shared_region_end":shared_region_end,"pointer_formats":["dyld_cache_slide_info5_arm64e_shared_cache"],
        "sources":identities,"source_set_manifest_sha256":stela_core::sha256(&serde_json::to_vec(set)?),
        "source_stable_during_inspection":true,"cache_set_files_verified":true,"mapping_summaries":summaries,
        "summary":global.value(),"metadata_bytes_read":metadata_bytes,"samples":samples,
        "mapping_count":all_mappings.len(),"slide_mapping_count":all_mappings.iter().filter(|mapping|mapping.slide_bytes!=0).count(),
        "pointer_page_bytes_read":global.chain_pages*PAGE_SIZE,
        "source_file_bytes":sources.iter().map(|source|source.identity.len()).sum::<u64>(),"source_hash_passes_per_file":2,
        "canonical_record_format":"32-byte little-endian <QQQQ>: unslid_location, original_raw, unauthenticated_value_or_unsigned_auth_target, descriptor",
        "canonical_record_order":"file index, original slide mapping-table index, page index, chain order",
        "descriptor_format":"auth:bit63|diversity<<34|addrDiv<<50|keyIsData<<51; unauth:high8<<34",
        "unauthenticated_write_digest_format":"16-byte little-endian <QQ>: slid_location, unauthenticated_value",
        "writes_applied":false,"authentication_performed":false,"execution_ready":false,"complete_binary_verified":false,
        "layout_source":{"repository":"apple-oss-distributions/dyld","commit":SOURCE_PIN},
        "pending":["Original signatures and header extensions remain unverified",
            "Authenticated targets are unsigned descriptors, never signed pointers or stripped PAC results",
            "Tagged pointers remain opaque tagged values; native memory access/TBI semantics are not established",
            "No source bytes or mapped memory were changed and no Apple instructions were executed"]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x180000000;
    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 4 * PAGE_SIZE as usize];
        bytes[..16].copy_from_slice(b"dyld_v1  arm64e\0");
        put32(&mut bytes, 16, 568);
        put32(&mut bytes, 20, 2);
        bytes[88..104].fill(0x11);
        put64(&mut bytes, 224, BASE);
        put64(&mut bytes, 232, 3 * PAGE_SIZE);
        put64(&mut bytes, 240, 2 * PAGE_SIZE);
        put32(&mut bytes, 312, 768);
        put32(&mut bytes, 316, 2);
        for index in 0..2usize {
            let size = if index == 0 { PAGE_SIZE } else { 2 * PAGE_SIZE };
            let address = BASE + index as u64 * PAGE_SIZE;
            let file_offset = index as u64 * PAGE_SIZE;
            let prot = if index == 0 { 5 } else { 3 };
            let ordinary = 568 + index * 32;
            let slide = 768 + index * 56;
            for offset in [ordinary, slide] {
                put64(&mut bytes, offset, address);
                put64(&mut bytes, offset + 8, size);
                put64(&mut bytes, offset + 16, file_offset);
            }
            put32(&mut bytes, ordinary + 24, prot);
            put32(&mut bytes, ordinary + 28, prot);
            put32(&mut bytes, slide + 48, prot);
            put32(&mut bytes, slide + 52, prot);
        }
        put64(&mut bytes, 768 + 56 + 24, 3 * PAGE_SIZE);
        put64(&mut bytes, 768 + 56 + 32, 28);
        let blob = (3 * PAGE_SIZE) as usize;
        put32(&mut bytes, blob, 5);
        put32(&mut bytes, blob + 4, PAGE_SIZE as u32);
        put32(&mut bytes, blob + 8, 2);
        put64(&mut bytes, blob + 16, BASE);
        bytes[blob + 24..blob + 28].copy_from_slice(&[0, 0, 0xff, 0xff]);
        // Known original-format words: next1; tagged next2; auth DA/addrDiv.
        put64(&mut bytes, PAGE_SIZE as usize, 0x0010_0000_0000_0000);
        put64(&mut bytes, PAGE_SIZE as usize + 8, 0x0020_0200_0000_0020);
        put64(&mut bytes, PAGE_SIZE as usize + 24, 0x800c_48d0_0000_0030);
        bytes
    }
    fn temporary_set(bytes: &[u8]) -> (tempfile::TempDir, Value) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache");
        std::fs::write(&path, bytes).unwrap();
        let set = super::super::shared_cache::manifest_set(&path).unwrap();
        (directory, set)
    }
    fn run(bytes: &[u8]) -> Result<Value> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("cache");
        std::fs::write(&path, bytes)?;
        let set = super::super::shared_cache::manifest_set(&path)?;
        plan(&set, BASE, 8)
    }

    #[test]
    fn canonical_records_match_independent_literal_word_oracle_at_two_slides() {
        let (_directory, set) = temporary_set(&fixture());
        for slide in [0, PAGE_SIZE] {
            let value = plan(&set, BASE + slide, 3).unwrap();
            assert_eq!(value["summary"]["fixup_records"], 3);
            assert_eq!(value["summary"]["unauthenticated_values"], 2);
            assert_eq!(value["summary"]["authenticated_descriptors"], 1);
            assert_eq!(value["summary"]["tagged_unauthenticated_values"], 1);
            assert_eq!(value["summary"]["maximum_chain_length"], 3);
            assert_eq!(value["summary"]["pages"], 2);
            assert_eq!(value["summary"]["no_rebase_pages"], 1);
            let records = [
                [BASE + PAGE_SIZE, 0x0010_0000_0000_0000, BASE + slide, 0],
                [
                    BASE + PAGE_SIZE + 8,
                    0x0020_0200_0000_0020,
                    0x8000_0000_0000_0000 | (BASE + 0x20 + slide),
                    0x0000_0200_0000_0000,
                ],
                [
                    BASE + PAGE_SIZE + 24,
                    0x800c_48d0_0000_0030,
                    BASE + 0x30 + slide,
                    0x800c_48d0_0000_0000,
                ],
            ];
            let expected = records
                .into_iter()
                .flatten()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>();
            assert_eq!(
                value["summary"]["canonical_records_sha256"],
                stela_core::sha256(&expected)
            );
            assert_eq!(value["samples"][2]["auth"]["key"], "DA");
            assert_eq!(value["samples"][2]["auth"]["diversity"], 0x1234);
            assert_eq!(value["samples"][2]["auth"]["address_diversity"], true);
            assert!(value["samples"][2]["auth"]["signed_value"].is_null());
            assert!(value["samples"][2]["unauthenticated_value"].is_null());
            assert_eq!(value["writes_applied"], false);
            assert_eq!(value["execution_ready"], false);
            assert_eq!(value["complete_binary_verified"], false);
        }
    }

    #[test]
    fn initial_offsets_are_bytes_and_next_offsets_are_eight_byte_units() {
        let mut bytes = fixture();
        let blob = 3 * PAGE_SIZE as usize;
        bytes[blob + 24..blob + 26].copy_from_slice(&8u16.to_le_bytes());
        let value = run(&bytes).unwrap();
        assert_eq!(value["summary"]["fixup_records"], 2);
        assert_eq!(value["samples"][0]["file_offset"], PAGE_SIZE + 8);
        assert_eq!(value["samples"][1]["file_offset"], PAGE_SIZE + 24);
    }

    #[test]
    fn full_page_2048_slot_chain_and_empty_pages_are_accepted() {
        let mut bytes = fixture();
        for index in 0..2048u64 {
            let next = if index == 2047 { 0 } else { 1u64 << 52 };
            put64(
                &mut bytes,
                PAGE_SIZE as usize + index as usize * 8,
                next + index * 8,
            );
        }
        let value = run(&bytes).unwrap();
        assert_eq!(value["summary"]["fixup_records"], 2048);
        assert_eq!(value["summary"]["maximum_chain_length"], 2048);
        let blob = 3 * PAGE_SIZE as usize;
        bytes[blob + 24..blob + 28].fill(0xff);
        let value = run(&bytes).unwrap();
        assert_eq!(value["summary"]["fixup_records"], 0);
        assert_eq!(value["summary"]["no_rebase_pages"], 2);
        assert_eq!(
            value["summary"]["canonical_records_sha256"],
            stela_core::sha256(&[])
        );
    }

    #[test]
    fn unknown_version_page_shape_reserved_header_and_truncations_decline() {
        for mutation in 0..7 {
            let mut bytes = fixture();
            let blob = 3 * PAGE_SIZE as usize;
            match mutation {
                0 => put32(&mut bytes, blob, 3),
                1 => put32(&mut bytes, blob + 4, 4096),
                2 => put32(&mut bytes, blob + 8, 1),
                3 => put32(&mut bytes, blob + 12, 1),
                4 => put64(&mut bytes, 768 + 56 + 32, 26),
                5 => put64(&mut bytes, blob + 16, BASE + PAGE_SIZE),
                _ => put64(&mut bytes, 768 + 56 + 32, 8),
            }
            assert!(run(&bytes).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn misaligned_initial_and_cross_page_next_decline() {
        for start in [7, PAGE_SIZE as u16] {
            let mut bytes = fixture();
            let blob = 3 * PAGE_SIZE as usize;
            bytes[blob + 24..blob + 26].copy_from_slice(&start.to_le_bytes());
            assert!(run(&bytes).is_err());
        }
        let mut bytes = fixture();
        let blob = 3 * PAGE_SIZE as usize;
        bytes[blob + 24..blob + 26].copy_from_slice(&((PAGE_SIZE - 8) as u16).to_le_bytes());
        put64(&mut bytes, 2 * PAGE_SIZE as usize - 8, 1u64 << 52);
        assert!(run(&bytes).unwrap_err().to_string().contains("exits page"));
    }

    #[test]
    fn reserved_pointer_bits_and_unmapped_one_past_targets_decline() {
        let mut bytes = fixture();
        put64(&mut bytes, PAGE_SIZE as usize, 1u64 << 42);
        assert!(run(&bytes).unwrap_err().to_string().contains("reserved"));
        let mut bytes = fixture();
        put64(&mut bytes, PAGE_SIZE as usize, 3 * PAGE_SIZE);
        assert!(
            run(&bytes)
                .unwrap_err()
                .to_string()
                .contains("strict mapped")
        );
        assert!(decode(1, u64::MAX, 0).is_err());
        assert!(decode(0, 1u64 << 56, 0).is_err());
    }

    #[test]
    fn zero_raw_word_is_cache_base_and_tags_are_never_masked() {
        assert_eq!(decode(0, BASE, PAGE_SIZE).unwrap().target, BASE + PAGE_SIZE);
        for tag in [0xab, 0xff] {
            let raw = (tag as u64) << 34;
            let value = decode(raw, BASE, 0).unwrap();
            assert_eq!(value.target, BASE | ((tag as u64) << 56));
            assert_eq!(value.high8, tag);
        }
        for key in [false, true] {
            for address in [false, true] {
                let raw = (1u64 << 63)
                    | (0xffffu64 << 34)
                    | ((address as u64) << 50)
                    | ((key as u64) << 51);
                let value = decode(raw, BASE, 0).unwrap();
                assert_eq!(value.target, BASE);
                assert_eq!(value.diversity, 0xffff);
                assert_eq!(value.address_diversity, address);
                assert_eq!(value.key_is_data, key);
                assert_eq!(value.high8, 0);
            }
        }
    }

    #[test]
    fn samples_are_bounded_and_load_base_obeys_original_aslr_contract() {
        let (_directory, set) = temporary_set(&fixture());
        assert_eq!(
            plan(&set, BASE, 0).unwrap()["samples"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert!(plan(&set, BASE, 257).is_err());
        for base in [BASE - 1, BASE + 1, BASE + 3 * PAGE_SIZE] {
            assert!(plan(&set, base, 0).is_err());
        }
        assert!(plan(&set, BASE + 2 * PAGE_SIZE, 0).is_ok());
    }

    #[test]
    fn forged_receipt_hash_identity_mapping_and_combined_maps_decline() {
        for mutation in 0..4 {
            let (_directory, mut set) = temporary_set(&fixture());
            match mutation {
                0 => set["files"][0]["source_sha256"] = json!("not-the-original-hash"),
                1 => set["files"][0]["source_identity"]["bytes"] = json!(1),
                2 => set["files"][0]["mappings"][1]["address"] = json!(BASE + PAGE_SIZE + 8),
                _ => set["combined_mappings"][1]["file_offset"] = json!(0),
            }
            assert!(plan(&set, BASE, 0).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn source_mutation_symlink_and_record_budget_are_not_accepted() {
        let (directory, set) = temporary_set(&fixture());
        let path = directory.path().join("cache");
        let mut bytes = fixture();
        bytes[PAGE_SIZE as usize] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(plan(&set, BASE, 0).is_err());
        let decoded = decode(0, BASE, 0).unwrap();
        let mut summary = Summary {
            records: MAX_RECORDS,
            ..Summary::default()
        };
        assert!(add_record(&mut summary, &[0; 32], &decoded, BASE).is_err());
        #[cfg(unix)]
        {
            let (directory, set) = temporary_set(&fixture());
            let path = directory.path().join("cache");
            let target = directory.path().join("original");
            std::fs::rename(&path, &target).unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
            assert!(
                plan(&set, BASE, 0)
                    .unwrap_err()
                    .to_string()
                    .contains("nonsymlink")
            );
        }
    }

    #[test]
    fn mapping_flags_do_not_substitute_for_word_auth_bit() {
        let mut bytes = fixture();
        put64(&mut bytes, 768 + 56 + 40, 1);
        let value = run(&bytes).unwrap();
        assert_eq!(value["summary"]["authenticated_descriptors"], 1);
        assert_eq!(value["summary"]["unauthenticated_values"], 2);
    }

    #[test]
    fn write_locations_never_overlap_original_slide_metadata() {
        let mut bytes = fixture();
        let blob = 3 * PAGE_SIZE as usize;
        let info = bytes[blob..blob + 28].to_vec();
        bytes[PAGE_SIZE as usize..PAGE_SIZE as usize + 28].copy_from_slice(&info);
        put64(&mut bytes, 768 + 56 + 24, PAGE_SIZE);
        assert!(
            run(&bytes)
                .unwrap_err()
                .to_string()
                .contains("overlaps original slide-info")
        );
    }
    #[test]
    fn original_shared_region_containment_and_absolute_base_alignment_are_required() {
        for mutation in 0..4 {
            let mut bytes = fixture();
            match mutation {
                0 => put64(&mut bytes, 232, 2 * PAGE_SIZE),
                1 => put64(&mut bytes, 232, u64::MAX),
                2 => put64(&mut bytes, 232, 0),
                _ => {
                    put64(&mut bytes, 224, BASE + 8);
                    put64(&mut bytes, 568, BASE + 8);
                    put64(&mut bytes, 768, BASE + 8);
                    put64(&mut bytes, 600, BASE + PAGE_SIZE + 8);
                    put64(&mut bytes, 824, BASE + PAGE_SIZE + 8);
                }
            }
            assert!(run(&bytes).is_err(), "mutation {mutation}");
        }
    }
}
