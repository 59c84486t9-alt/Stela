//! Bounded, on-disk metadata inventory; never maps a cache or extracts dylibs.
//!
//! Layout authority: Apple's dyld fd8d0c4d52320ebf64db34f3cb280310d905c5ae,
//! include/mach-o/dyld_cache_format.h and common/DyldSharedCache.cpp.
//! In particular mappingOffset bounds header availability; cacheSubType's
//! availability distinguishes the 24-byte and 56-byte subcache entries.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, Metadata as FileMetadata},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

const SOURCE_PIN: &str = "fd8d0c4d52320ebf64db34f3cb280310d905c5ae";
const METADATA_LIMIT: u64 = 16 * 1024 * 1024;
const HEADER_LIMIT: u64 = 4096;
const MAPPING_LIMIT: u64 = 4096;
const IMAGE_LIMIT: u64 = 1_000_000;
const SUBCACHE_LIMIT: u64 = 4096;
const PATH_LIMIT: u64 = 4096;
const FILE_LIMIT: u64 = 32 * 1024 * 1024 * 1024;

struct Metadata<'a, R> {
    reader: &'a mut R,
    file_bytes: u64,
    bytes_read: u64,
}

impl<R: Read + Seek> Metadata<'_, R> {
    fn read(&mut self, offset: u64, size: u64) -> Result<Vec<u8>> {
        extent(offset, size, self.file_bytes)?;
        self.bytes_read = self
            .bytes_read
            .checked_add(size)
            .context("metadata byte count overflow")?;
        ensure!(
            self.bytes_read <= METADATA_LIMIT,
            "shared-cache metadata exceeds 16 MiB budget"
        );
        let mut bytes = vec![0; usize::try_from(size)?];
        self.reader.seek(SeekFrom::Start(offset))?;
        self.reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn path(&mut self, offset: u64) -> Result<String> {
        ensure!(
            offset < self.file_bytes,
            "image path offset is outside file"
        );
        let mut bytes = Vec::new();
        let available = PATH_LIMIT.min(self.file_bytes - offset);
        while (bytes.len() as u64) < available {
            let size = 64.min(available - bytes.len() as u64);
            let chunk = self.read(offset + bytes.len() as u64, size)?;
            if let Some(end) = chunk.iter().position(|byte| *byte == 0) {
                bytes.extend_from_slice(&chunk[..end]);
                let path = String::from_utf8(bytes).context("image path is not UTF-8")?;
                ensure!(path.starts_with('/'), "image install path is not absolute");
                return Ok(path);
            }
            bytes.extend(chunk);
        }
        bail!("image path has no NUL within bounded 4096-byte extent")
    }
}

pub(super) fn extent(offset: u64, size: u64, limit: u64) -> Result<u64> {
    let end = offset
        .checked_add(size)
        .context("metadata extent overflow")?;
    ensure!(end <= limit, "metadata extent is outside cache file");
    Ok(end)
}

fn table_size(count: u64, width: u64, limit: u64) -> Result<u64> {
    ensure!(count <= limit, "shared-cache table count exceeds limit");
    count
        .checked_mul(width)
        .context("table byte count overflow")
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("shared-cache header field is unavailable")?
            .try_into()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .context("shared-cache header field is unavailable")?
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

#[derive(Clone)]
struct Mapping {
    address: u64,
    size: u64,
    file_offset: u64,
    max_protection: u32,
    initial_protection: u32,
}

impl Mapping {
    fn file_offset_for(&self, address: u64, bytes: u64) -> Option<u64> {
        let relative = address.checked_sub(self.address)?;
        if relative.checked_add(bytes)? > self.size {
            return None;
        }
        self.file_offset.checked_add(relative)
    }

    fn value(&self) -> Value {
        json!({"address":self.address,"size":self.size,"file_offset":self.file_offset,
            "max_protection":self.max_protection,"initial_protection":self.initial_protection,
            "readable":self.initial_protection & 1 != 0,
            "writable":self.initial_protection & 2 != 0,
            "executable":self.initial_protection & 4 != 0})
    }
}

fn mapping(bytes: &[u8], file_bytes: u64) -> Result<Mapping> {
    let result = Mapping {
        address: u64_at(bytes, 0)?,
        size: u64_at(bytes, 8)?,
        file_offset: u64_at(bytes, 16)?,
        max_protection: u32_at(bytes, 24)?,
        initial_protection: u32_at(bytes, 28)?,
    };
    ensure!(result.size != 0, "empty shared-cache mapping");
    result
        .address
        .checked_add(result.size)
        .context("mapping VM extent overflow")?;
    extent(result.file_offset, result.size, file_bytes)?;
    ensure!(
        result.max_protection & !7 == 0 && result.initial_protection & !result.max_protection == 0,
        "invalid mapping protections"
    );
    Ok(result)
}

fn disjoint_mappings(mappings: &[Mapping]) -> Result<()> {
    for by_file in [false, true] {
        let mut extents: Vec<_> = mappings
            .iter()
            .map(|mapping| {
                (
                    if by_file {
                        mapping.file_offset
                    } else {
                        mapping.address
                    },
                    mapping.size,
                )
            })
            .collect();
        extents.sort_unstable();
        for pair in extents.windows(2) {
            ensure!(
                pair[0].0 + pair[0].1 <= pair[1].0,
                "overlapping shared-cache mappings"
            );
        }
    }
    Ok(())
}

fn parse<R: Read + Seek>(reader: &mut R, file_bytes: u64) -> Result<Value> {
    let mut metadata = Metadata {
        reader,
        file_bytes,
        bytes_read: 0,
    };
    let prefix = metadata.read(0, 24)?;
    let magic = &prefix[..16];
    ensure!(
        magic.starts_with(b"dyld_v1"),
        "unsupported shared-cache magic/version"
    );
    let end = magic.iter().position(|byte| *byte == 0).unwrap_or(16);
    ensure!(
        magic[end..].iter().all(|byte| *byte == 0),
        "nonzero bytes after shared-cache magic terminator"
    );
    let magic = std::str::from_utf8(&magic[..end]).context("non-UTF-8 shared-cache magic")?;
    let architecture = match magic {
        "dyld_v1   arm64" => "arm64",
        "dyld_v1  arm64e" => "arm64e",
        _ => bail!("unsupported shared-cache architecture or magic layout: {magic}"),
    };
    let header_bytes = u64::from(u32_at(&prefix, 16)?);
    let mapping_count = u64::from(u32_at(&prefix, 20)?);
    ensure!(
        (104..=HEADER_LIMIT).contains(&header_bytes) && header_bytes.is_multiple_of(8),
        "unsupported or truncated shared-cache header layout"
    );
    ensure!(
        mapping_count > 0,
        "mapping-free/symbol-only caches are not supported by this inventory"
    );
    let header = metadata.read(0, header_bytes)?;
    let has = |end: usize| header.len() >= end;
    let mapping_bytes =
        metadata.read(header_bytes, table_size(mapping_count, 32, MAPPING_LIMIT)?)?;
    let mappings: Vec<_> = mapping_bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|bytes| mapping(bytes, file_bytes))
        .collect::<Result<_>>()?;
    disjoint_mappings(&mappings)?;
    ensure!(
        mappings[0].file_offset == 0 && mappings[0].size >= header_bytes + mapping_count * 32,
        "first cache mapping does not contain header/mapping table at file offset zero"
    );
    let mut unresolved = vec![json!(
        "Subcache files, signatures, fixups and executable readiness are not validated"
    )];
    if header_bytes > 552 {
        unresolved.push(json!(
            "Header extension beyond the pinned 552-byte layout is not interpreted"
        ));
    }
    let (images_offset, images_count, image_layout) = if has(456) {
        (u32_at(&header, 448)?, u32_at(&header, 452)?, "modern")
    } else {
        (u32_at(&header, 24)?, u32_at(&header, 28)?, "legacy")
    };
    let image_size = table_size(u64::from(images_count), 32, IMAGE_LIMIT)?;
    ensure!(
        images_count == 0 || u64::from(images_offset) >= header_bytes,
        "image table overlaps cache header"
    );
    let image_bytes = metadata.read(u64::from(images_offset), image_size)?;
    let mut images = Vec::new();
    let mut unresolved_images = 0usize;
    for bytes in image_bytes.as_chunks::<32>().0 {
        let address = u64_at(bytes, 0)?;
        let path_file_offset = u32_at(bytes, 24)?;
        let path = metadata.path(u64::from(path_file_offset))?;
        let file_offset = mappings
            .iter()
            .find_map(|mapping| mapping.file_offset_for(address, 32));
        if file_offset.is_none() {
            unresolved_images += 1;
        }
        images.push(json!({"address":address,"path":path,"path_file_offset":path_file_offset,
            "mach_header_file_offset":file_offset,
            "mach_header_location":if file_offset.is_some() { "base_file_mapping" } else { "unresolved_other_cache_mapping" }}));
    }
    if unresolved_images != 0 {
        unresolved.push(json!(format!("{unresolved_images} image headers are outside base-file mappings; sibling caches were not opened")));
    }
    let mut subcaches = Vec::new();
    let subcache_layout;
    if has(400) {
        let offset = u64::from(u32_at(&header, 392)?);
        let count = u64::from(u32_at(&header, 396)?);
        let suffixes = has(460);
        subcache_layout = if suffixes {
            "uuid_vm_offset_suffix"
        } else {
            "uuid_vm_offset_v1"
        };
        let width = if suffixes { 56 } else { 24 };
        ensure!(
            count == 0 || offset >= header_bytes,
            "subcache table overlaps cache header"
        );
        let bytes = metadata.read(offset, table_size(count, width, SUBCACHE_LIMIT)?)?;
        for (index, entry) in bytes.chunks_exact(width as usize).enumerate() {
            let vm_offset = u64_at(entry, 16)?;
            let address = mappings[0]
                .address
                .checked_add(vm_offset)
                .context("subcache VM address overflow")?;
            let suffix = if suffixes {
                let raw = &entry[24..56];
                let end = raw
                    .iter()
                    .position(|byte| *byte == 0)
                    .context("subcache suffix has no NUL")?;
                let suffix =
                    std::str::from_utf8(&raw[..end]).context("subcache suffix is not UTF-8")?;
                ensure!(
                    suffix.starts_with('.')
                        && !suffix.contains(['/', '\\'])
                        && !suffix.contains(".."),
                    "unsafe or invalid subcache suffix"
                );
                Some(suffix.to_owned())
            } else {
                None
            };
            subcaches.push(
                json!({"index":index,"uuid":uuid(&entry[..16]),"cache_vm_offset":vm_offset,
                "expected_vm_address":address,"file_suffix":suffix,"status":"reference_only"}),
            );
        }
        if count != 0 && !suffixes {
            unresolved.push(json!(
                "Legacy subcache entries have no file suffix; filename conventions are not inferred"
            ));
        }
    } else {
        subcache_layout = "header_field_unavailable";
        unresolved.push(json!(
            "Subcache table fields are unavailable in this header layout"
        ));
    }
    let mut slide_mappings = Vec::new();
    let slide_mapping_status;
    if has(320) {
        let offset = u64::from(u32_at(&header, 312)?);
        let count = u64::from(u32_at(&header, 316)?);
        let bytes = metadata.read(offset, table_size(count, 56, MAPPING_LIMIT)?)?;
        ensure!(
            count == 0 || offset >= header_bytes,
            "slide mapping table overlaps cache header"
        );
        ensure!(
            count == 0 || count == mapping_count,
            "slide and ordinary mapping counts disagree"
        );
        for (index, entry) in bytes.as_chunks::<56>().0.iter().enumerate() {
            let address = u64_at(entry, 0)?;
            let size = u64_at(entry, 8)?;
            let file_offset = u64_at(entry, 16)?;
            let slide_info_offset = u64_at(entry, 24)?;
            let slide_info_size = u64_at(entry, 32)?;
            let flags = u64_at(entry, 40)?;
            ensure!(
                (
                    address,
                    size,
                    file_offset,
                    u32_at(entry, 48)?,
                    u32_at(entry, 52)?
                ) == (
                    mappings[index].address,
                    mappings[index].size,
                    mappings[index].file_offset,
                    mappings[index].max_protection,
                    mappings[index].initial_protection
                ),
                "slide mapping does not match ordinary mapping"
            );
            extent(slide_info_offset, slide_info_size, file_bytes)?;
            let version = if slide_info_size == 0 {
                None
            } else {
                ensure!(slide_info_size >= 4, "truncated slide-info version");
                Some(u32_at(&metadata.read(slide_info_offset, 4)?, 0)?)
            };
            if let Some(version) = version {
                unresolved.push(json!(format!("Slide-info version {version} at mapping {index} is inventoried but not decoded/applied")));
            }
            slide_mappings.push(json!({"address":address,"size":size,"file_offset":file_offset,
                "flags":flags,"slide_info_file_offset":slide_info_offset,"slide_info_bytes":slide_info_size,
                "slide_info_version":version,"authenticated_data":flags & 1 != 0}));
        }
        slide_mapping_status = if count == 0 {
            "declared_empty"
        } else {
            "metadata_only"
        };
    } else {
        slide_mapping_status = "header_field_unavailable";
        unresolved.push(json!(
            "Mapping-with-slide fields are unavailable; legacy slide-info is not decoded"
        ));
    }
    let symbols_uuid = if has(416) {
        Some(uuid(&header[400..416]))
    } else {
        None
    };
    if !has(416) {
        unresolved.push(json!("Symbol-file UUID field is unavailable"));
    }
    let cache_header = json!({"magic":magic,"architecture":architecture,"uuid":uuid(&header[88..104]),
        "header_bytes":header_bytes,"header_sha256":stela_core::sha256(&header),
        "cache_type":if has(112) {Some(u64_at(&header,104)?)} else {None},
        "format_flags":if has(224) {Some(u32_at(&header,220)?)} else {None},
        "shared_region_start":if has(232) {Some(u64_at(&header,224)?)} else {None},
        "shared_region_bytes":if has(240) {Some(u64_at(&header,232)?)} else {None},
        "maximum_slide":if has(248) {Some(u64_at(&header,240)?)} else {None},
        "dyld_in_cache_address":if has(128) {Some(u64_at(&header,120)?)} else {None},
        "dyld_in_cache_entry":if has(136) {Some(u64_at(&header,128)?)} else {None},
        "symbol_file_uuid":symbols_uuid,"image_table_layout":image_layout,
        "image_table_file_offset":images_offset,"declared_image_count":images_count,
        "subcache_table_layout":subcache_layout,"slide_mapping_status":slide_mapping_status});
    Ok(
        json!({"schema_version":1,"kind":"dyld_shared_cache_manifest","file_bytes":file_bytes,
        "header":cache_header,"mappings":mappings.iter().map(Mapping::value).collect::<Vec<_>>(),
        "images":images,"subcaches":subcaches,"slide_mappings":slide_mappings,
        "metadata_bytes_read":metadata.bytes_read,"unresolved":unresolved,
        "layout_source":{"repository":"apple-oss-distributions/dyld","commit":SOURCE_PIN,
            "header":"include/mach-o/dyld_cache_format.h","implementation":"common/DyldSharedCache.cpp"},
        "metadata_only":true,"cache_set_complete":false,"complete_binary_verified":false}),
    )
}

pub(super) fn hash_file(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Hash and inspect one base cache. Sibling cache files are reference metadata.
/// Both full-file hashes and metadata must remain stable during inspection.
pub fn manifest(path: &Path) -> Result<Value> {
    let mut file = File::open(path).with_context(|| format!("open cache {}", path.display()))?;
    manifest_opened(path, &mut file)
}

fn manifest_opened(path: &Path, file: &mut File) -> Result<Value> {
    let before = file.metadata()?;
    ensure!(before.is_file(), "shared-cache input is not a regular file");
    ensure!(
        before.len() <= FILE_LIMIT,
        "shared-cache input exceeds 32 GiB"
    );
    let first = hash_file(file)?;
    let mut value = parse(file, before.len())?;
    let second = hash_file(file)?;
    ensure!(first == second, "shared-cache file changed while hashing");
    let after = file.metadata()?;
    ensure!(
        before.len() == after.len() && before.modified()? == after.modified()?,
        "shared-cache file metadata changed during inspection"
    );
    let header_bytes = value["header"]["header_bytes"]
        .as_u64()
        .context("missing header size")?;
    file.seek(SeekFrom::Start(0))?;
    let mut header = vec![0; usize::try_from(header_bytes)?];
    file.read_exact(&mut header)?;
    ensure!(
        value["header"]["header_sha256"] == stela_core::sha256(&header),
        "shared-cache header changed during inspection"
    );
    let path_metadata = path.metadata()?;
    ensure!(
        path_metadata.len() == after.len() && path_metadata.modified()? == after.modified()?,
        "shared-cache input path changed during inspection"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            path_metadata.dev() == after.dev() && path_metadata.ino() == after.ino(),
            "shared-cache input path was replaced during inspection"
        );
    }
    value["source_sha256"] = json!(first);
    value["parser_source_sha256"] = json!(stela_core::sha256(include_bytes!("shared_cache.rs")));
    value["path"] = json!(path.to_string_lossy());
    value["source_stable_during_inspection"] = json!(true);
    Ok(value)
}

const SET_FILE_LIMIT: usize = 256;
const SET_BYTES_LIMIT: u64 = 64 * 1024 * 1024 * 1024;
const SET_METADATA_LIMIT: u64 = 64 * 1024 * 1024;
const LOAD_COMMAND_BYTES_LIMIT: u64 = 1024 * 1024;
const LOAD_COMMAND_COUNT_LIMIT: u32 = 4096;
const ZERO_UUID: &str = "00000000-0000-0000-0000-000000000000";

struct CacheFile {
    path: PathBuf,
    file: File,
    identity: FileMetadata,
    value: Value,
}

struct SetMapping {
    file_index: usize,
    mapping: Mapping,
}

pub(super) fn same_file(before: &FileMetadata, after: &FileMetadata) -> bool {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (
            before.dev(),
            before.ino(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (after.dev(), after.ino(), after.ctime(), after.ctime_nsec())
        {
            return false;
        }
    }
    true
}

pub(super) fn file_identity(metadata: &FileMetadata) -> Value {
    let mut result = json!({"bytes":metadata.len()});
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        result["device"] = json!(metadata.dev());
        result["inode"] = json!(metadata.ino());
        result["mtime_seconds"] = json!(metadata.mtime());
        result["mtime_nanoseconds"] = json!(metadata.mtime_nsec());
        result["ctime_seconds"] = json!(metadata.ctime());
        result["ctime_nanoseconds"] = json!(metadata.ctime_nsec());
    }
    result
}

fn open_cache(path: &Path, total_bytes: &mut u64, total_metadata: &mut u64) -> Result<CacheFile> {
    let before = path
        .symlink_metadata()
        .with_context(|| format!("missing cache-set file {}", path.display()))?;
    ensure!(
        before.file_type().is_file() && !before.file_type().is_symlink(),
        "cache-set file must be regular and not a symlink: {}",
        path.display()
    );
    *total_bytes = total_bytes
        .checked_add(before.len())
        .context("cache-set byte count overflow")?;
    ensure!(
        *total_bytes <= SET_BYTES_LIMIT,
        "cache set exceeds 64 GiB byte budget"
    );
    let mut file = File::open(path)?;
    ensure!(
        same_file(&before, &file.metadata()?),
        "cache-set file changed before opening"
    );
    let mut value = manifest_opened(path, &mut file)?;
    let count = value["metadata_bytes_read"]
        .as_u64()
        .context("missing cache metadata byte count")?;
    *total_metadata = total_metadata
        .checked_add(count)
        .context("cache-set metadata count overflow")?;
    ensure!(
        *total_metadata <= SET_METADATA_LIMIT,
        "cache-set metadata exceeds 64 MiB budget"
    );
    value["source_identity"] = file_identity(&before);
    Ok(CacheFile {
        path: path.to_owned(),
        file,
        identity: before,
        value,
    })
}

fn declared_mappings(value: &Value, file_index: usize) -> Result<Vec<SetMapping>> {
    value["mappings"]
        .as_array()
        .context("cache has no mapping array")?
        .iter()
        .map(|value| {
            Ok(SetMapping {
                file_index,
                mapping: Mapping {
                    address: value["address"]
                        .as_u64()
                        .context("missing mapping address")?,
                    size: value["size"].as_u64().context("missing mapping size")?,
                    file_offset: value["file_offset"]
                        .as_u64()
                        .context("missing mapping file offset")?,
                    max_protection: u32::try_from(
                        value["max_protection"]
                            .as_u64()
                            .context("missing max protection")?,
                    )?,
                    initial_protection: u32::try_from(
                        value["initial_protection"]
                            .as_u64()
                            .context("missing initial protection")?,
                    )?,
                },
            })
        })
        .collect()
}

fn read_vm(
    files: &mut [CacheFile],
    mappings: &[SetMapping],
    address: u64,
    size: u64,
    total_metadata: &mut u64,
) -> Result<(Vec<u8>, usize, u64)> {
    *total_metadata = total_metadata
        .checked_add(size)
        .context("cache-set metadata count overflow")?;
    ensure!(
        *total_metadata <= SET_METADATA_LIMIT,
        "cache-set metadata exceeds 64 MiB budget"
    );
    let index = mappings
        .partition_point(|mapping| mapping.mapping.address <= address)
        .checked_sub(1)
        .context("image metadata address is outside the cache set")?;
    let selected = &mappings[index];
    let offset = selected
        .mapping
        .file_offset_for(address, size)
        .context("image metadata straddles a mapping or is outside the cache set")?;
    let file = &mut files[selected.file_index];
    extent(offset, size, file.identity.len())?;
    let mut bytes = vec![0; usize::try_from(size)?];
    file.file.seek(SeekFrom::Start(offset))?;
    file.file.read_exact(&mut bytes)?;
    Ok((bytes, selected.file_index, offset))
}

fn command_string(command: &[u8], field: usize, minimum: u32) -> Result<String> {
    let offset = u32_at(command, field)?;
    ensure!(
        offset >= minimum,
        "Mach-O command string overlaps fixed fields"
    );
    let bytes = command
        .get(usize::try_from(offset)?..)
        .context("Mach-O string offset exceeds command")?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .context("Mach-O command string has no NUL")?;
    ensure!(
        end > 0 && end < PATH_LIMIT as usize,
        "Mach-O command string exceeds path budget"
    );
    Ok(std::str::from_utf8(&bytes[..end])
        .context("Mach-O command string is not UTF-8")?
        .to_owned())
}

fn dylib_command(command: &[u8]) -> Result<Value> {
    ensure!(command.len() >= 24, "truncated dylib command");
    Ok(
        json!({"name":command_string(command,8,24)?,"timestamp":u32_at(command,12)?,
        "current_version":u32_at(command,16)?,"compatibility_version":u32_at(command,20)?}),
    )
}

fn image_manifest(
    files: &mut [CacheFile],
    mappings: &[SetMapping],
    image: &Value,
    architecture: &str,
    total_metadata: &mut u64,
) -> Result<Value> {
    let address = image["address"].as_u64().context("image has no address")?;
    let (header, file_index, file_offset) = read_vm(files, mappings, address, 32, total_metadata)?;
    ensure!(
        u32_at(&header, 0)? == 0xfeedfacf,
        "cache image is not a little-endian 64-bit Mach-O"
    );
    let cpu = u32_at(&header, 4)?;
    let subtype = u32_at(&header, 8)?;
    ensure!(cpu == 0x0100000c, "cache image is not ARM64");
    let base_subtype = subtype & 0x00ff_ffff;
    ensure!(
        (architecture == "arm64e" && base_subtype == 2)
            || (architecture == "arm64" && matches!(base_subtype, 0 | 1)),
        "cache image CPU subtype does not match cache architecture"
    );
    let file_type = u32_at(&header, 12)?;
    ensure!(
        matches!(file_type, 6 | 7),
        "unsupported cache image Mach-O file type"
    );
    let ncmds = u32_at(&header, 16)?;
    let sizeofcmds = u64::from(u32_at(&header, 20)?);
    ensure!(
        ncmds > 0
            && ncmds <= LOAD_COMMAND_COUNT_LIMIT
            && sizeofcmds <= LOAD_COMMAND_BYTES_LIMIT
            && u64::from(ncmds) * 8 <= sizeofcmds,
        "invalid or oversized Mach-O load-command extent"
    );
    let command_address = address
        .checked_add(32)
        .context("Mach-O command address overflow")?;
    let (commands, command_file_index, command_file_offset) =
        read_vm(files, mappings, command_address, sizeofcmds, total_metadata)?;
    ensure!(
        file_index == command_file_index && command_file_offset == file_offset + 32,
        "Mach-O header and load commands cross physical cache mappings"
    );
    let mut position = 0usize;
    let mut image_uuid = None;
    let mut dylib_identity = None;
    let mut dylinker_identity = None;
    let mut dependencies = Vec::new();
    let mut unknown_commands = Vec::new();
    for index in 0..ncmds {
        let cmd = u32_at(&commands, position)?;
        let size = usize::try_from(u32_at(&commands, position + 4)?)?;
        ensure!(
            size >= 8 && size.is_multiple_of(8),
            "invalid Mach-O load-command size/alignment"
        );
        let end = position
            .checked_add(size)
            .context("Mach-O command extent overflow")?;
        let command = commands
            .get(position..end)
            .context("Mach-O load command exceeds sizeofcmds")?;
        match cmd {
            0x1b => {
                ensure!(
                    size == 24 && image_uuid.is_none(),
                    "invalid or duplicate LC_UUID"
                );
                image_uuid = Some(uuid(&command[8..24]));
            }
            0xd => {
                ensure!(dylib_identity.is_none(), "duplicate LC_ID_DYLIB");
                dylib_identity = Some(dylib_command(command)?);
            }
            0xf => {
                ensure!(dylinker_identity.is_none(), "duplicate LC_ID_DYLINKER");
                dylinker_identity = Some(command_string(command, 8, 12)?);
            }
            0xc | 0x80000018 | 0x8000001f | 0x20 | 0x80000023 => {
                let kind = match cmd {
                    0xc => "load_dylib",
                    0x80000018 => "load_weak_dylib",
                    0x8000001f => "reexport_dylib",
                    0x20 => "lazy_load_dylib",
                    _ => "load_upward_dylib",
                };
                let mut dependency = dylib_command(command)?;
                dependency["kind"] = json!(kind);
                dependency["library_ordinal"] = json!(dependencies.len() + 1);
                dependency["load_command_index"] = json!(index);
                dependencies.push(dependency);
            }
            _ => unknown_commands.push(json!({"command":cmd,"bytes":size,"index":index})),
        }
        position = end;
    }
    ensure!(
        position == commands.len(),
        "Mach-O commands do not fill declared sizeofcmds"
    );
    let image_uuid = image_uuid.context("cache image has no LC_UUID")?;
    ensure!(
        (file_type == 6 && dylib_identity.is_some() && dylinker_identity.is_none())
            || (file_type == 7 && dylinker_identity.is_some() && dylib_identity.is_none()),
        "cache image type and install-name command disagree"
    );
    Ok(
        json!({"path":image["path"],"address":address,"source_cache_index":file_index,
        "source_cache_path":files[file_index].path.to_string_lossy(),"cache_file_offset":file_offset,
        "header_and_commands_sha256":stela_core::sha256(&[header.as_slice(),commands.as_slice()].concat()),
        "mach_o":{"cpu_type":cpu,"cpu_subtype":subtype,"file_type":file_type,
            "flags":u32_at(&header,24)?,"load_command_count":ncmds,"load_command_bytes":sizeofcmds,
            "uuid":image_uuid,"dylib_identity":dylib_identity,"dylinker_identity":dylinker_identity,
            "dependencies":dependencies,"uninterpreted_load_commands":unknown_commands},
        "metadata_only":true,"complete_binary_verified":false}),
    )
}

/// Verify one original cache set and resolve its image header/dependency metadata.
/// No cache VM is mapped, no pointers are slid/authenticated, and no dylib is rebuilt.
pub fn manifest_set(path: &Path) -> Result<Value> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let name = path.file_name().context("cache input has no file name")?;
    let base_path = parent.join(name);
    let mut total_bytes = 0u64;
    let mut total_metadata = 0u64;
    let base = open_cache(&base_path, &mut total_bytes, &mut total_metadata)?;
    let architecture = base.value["header"]["architecture"]
        .as_str()
        .context("missing cache architecture")?
        .to_owned();
    let references = base.value["subcaches"]
        .as_array()
        .context("missing subcache reference array")?
        .clone();
    ensure!(
        references.len() < SET_FILE_LIMIT,
        "cache set exceeds 256-file budget"
    );
    let symbol_uuid = base.value["header"]["symbol_file_uuid"]
        .as_str()
        .context("symbol-file UUID field is unavailable; cache-set requirements unresolved")?;
    ensure!(
        symbol_uuid == ZERO_UUID,
        "nonzero symbol-file UUID requires a .symbols verifier, which is unsupported"
    );
    let base_address = base.value["mappings"][0]["address"]
        .as_u64()
        .context("missing base mapping address")?;
    let mut suffixes = BTreeSet::new();
    let mut uuids = BTreeSet::from([base.value["header"]["uuid"]
        .as_str()
        .context("missing cache UUID")?
        .to_owned()]);
    let mut files = vec![base];
    for reference in references {
        let suffix = reference["file_suffix"]
            .as_str()
            .context("legacy subcache filename inference is unsupported")?;
        ensure!(
            suffixes.insert(suffix.to_owned()),
            "duplicate subcache file suffix"
        );
        let mut sibling_name = name.to_os_string();
        sibling_name.push(suffix);
        let sibling_path = parent.join(sibling_name);
        ensure!(
            sibling_path.parent() == Some(parent.as_path()),
            "subcache file escapes cache parent"
        );
        let mut sibling = open_cache(&sibling_path, &mut total_bytes, &mut total_metadata)?;
        ensure!(
            sibling.value["header"]["uuid"] == reference["uuid"],
            "subcache UUID does not match declared reference"
        );
        ensure!(
            sibling.value["header"]["architecture"] == architecture,
            "subcache architecture does not match base cache"
        );
        ensure!(
            sibling.value["header"]["symbol_file_uuid"] == ZERO_UUID,
            "subcache declares unsupported or unavailable symbol-file UUID metadata"
        );
        let uuid = sibling.value["header"]["uuid"]
            .as_str()
            .context("missing subcache UUID")?;
        ensure!(uuids.insert(uuid.to_owned()), "duplicate cache-set UUID");
        let vm_offset = reference["cache_vm_offset"]
            .as_u64()
            .context("missing subcache VM offset")?;
        let expected = base_address
            .checked_add(vm_offset)
            .context("subcache VM address overflow")?;
        ensure!(
            sibling.value["mappings"][0]["address"] == expected,
            "subcache first mapping disagrees with declared VM offset"
        );
        ensure!(
            sibling.value["subcaches"]
                .as_array()
                .context("missing sibling subcache array")?
                .is_empty(),
            "nested subcache references are unsupported"
        );
        sibling.value["declared_file_suffix"] = json!(suffix);
        files.push(sibling);
    }
    let mut mappings = Vec::new();
    let mut images = Vec::new();
    let mut paths = BTreeSet::new();
    for (index, file) in files.iter().enumerate() {
        mappings.extend(declared_mappings(&file.value, index)?);
        for image in file.value["images"]
            .as_array()
            .context("missing image table")?
        {
            let path = image["path"].as_str().context("missing image path")?;
            ensure!(
                paths.insert(path.to_owned()),
                "duplicate cache-set image path"
            );
            images.push(image.clone());
        }
    }
    mappings.sort_by_key(|mapping| mapping.mapping.address);
    let region_start = files[0].value["header"]["shared_region_start"]
        .as_u64()
        .context("original shared region base is unavailable")?;
    let region_bytes = files[0].value["header"]["shared_region_bytes"]
        .as_u64()
        .context("original shared region size is unavailable")?;
    ensure!(
        region_bytes > 0 && region_start == base_address,
        "original shared region is empty or disagrees with the base mapping"
    );
    let region_end = region_start
        .checked_add(region_bytes)
        .context("original shared region extent overflow")?;
    for mapping in &mappings {
        ensure!(
            mapping.mapping.address >= region_start
                && mapping
                    .mapping
                    .address
                    .checked_add(mapping.mapping.size)
                    .context("mapping VM extent overflow")?
                    <= region_end,
            "cache mapping exceeds the original shared region"
        );
    }
    for pair in mappings.windows(2) {
        ensure!(
            pair[0]
                .mapping
                .address
                .checked_add(pair[0].mapping.size)
                .context("mapping VM extent overflow")?
                <= pair[1].mapping.address,
            "overlapping cache-set VM mappings"
        );
    }
    let mut resolved_images = Vec::new();
    for image in &images {
        resolved_images.push(image_manifest(
            &mut files,
            &mappings,
            image,
            &architecture,
            &mut total_metadata,
        )?);
    }
    // Global set guard brackets all later image/header reads, not merely each
    // file's earlier local manifest. Paths must still name those exact inodes.
    for file in &mut files {
        ensure!(
            hash_file(&mut file.file)? == file.value["source_sha256"],
            "cache-set file bytes changed during image inspection"
        );
        ensure!(
            same_file(&file.identity, &file.file.metadata()?),
            "cache-set open file identity changed"
        );
        let current = file.path.symlink_metadata()?;
        ensure!(
            current.file_type().is_file()
                && !current.file_type().is_symlink()
                && same_file(&file.identity, &current),
            "cache-set input path identity changed"
        );
    }
    let combined_mappings = mappings
        .iter()
        .map(|entry| {
            let mut value = entry.mapping.value();
            value["source_cache_index"] = json!(entry.file_index);
            value
        })
        .collect::<Vec<_>>();
    let main_source_sha256 = files[0].value["source_sha256"].clone();
    let file_values = files
        .into_iter()
        .enumerate()
        .map(|(index, file)| {
            let mut value = file.value;
            value["index"] = json!(index);
            value
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"schema_version":1,"kind":"dyld_shared_cache_set_manifest","path":base_path.to_string_lossy(),
        "architecture":architecture,"source_sha256":main_source_sha256,"files":file_values,"file_count":file_values.len(),
        "total_file_bytes":total_bytes,"metadata_bytes_read":total_metadata,
        "combined_mappings":combined_mappings,"images":resolved_images,"image_headers_verified":resolved_images.len(),
        "cache_set_files_verified":true,"source_stable_during_inspection":true,
        "fixups_applied":false,"metadata_only":true,"complete_binary_verified":false,
        "unresolved":["Per-file header extensions and slide/fixup metadata remain unresolved as recorded in files",
            "Signatures, rebasing, pointer authentication, exports, segments, initializers and launch readiness are not verified",
            "Uninterpreted Mach-O load commands are preserved as command numbers/sizes, not implemented"]}),
    )
}

fn apple_map_entries(text: &str) -> Result<BTreeMap<String, u64>> {
    ensure!(!text.contains('\0'), "Apple map contains NUL");
    let mut entries = BTreeMap::new();
    let mut pending = None;
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.starts_with('/') {
            ensure!(
                pending.is_none(),
                "Apple map image has no first __TEXT range"
            );
            ensure!(
                line.len() < PATH_LIMIT as usize,
                "Apple map path exceeds path budget"
            );
            pending = Some(line.to_owned());
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() == Some(&"__TEXT") {
            let path = pending
                .take()
                .context("Apple map __TEXT has no unique image path")?;
            ensure!(
                fields.len() == 4 && fields[2] == "->",
                "malformed Apple map __TEXT range"
            );
            let hex = |value: &str| -> Result<u64> {
                Ok(u64::from_str_radix(
                    value
                        .strip_prefix("0x")
                        .context("Apple map address is not hexadecimal")?,
                    16,
                )?)
            };
            let start = hex(fields[1])?;
            let end = hex(fields[3])?;
            ensure!(start < end, "empty or reversed Apple map __TEXT range");
            ensure!(
                entries.insert(path, start).is_none(),
                "duplicate Apple map image path"
            );
            ensure!(
                entries.len() <= IMAGE_LIMIT as usize,
                "Apple map image count exceeds budget"
            );
        }
    }
    ensure!(
        pending.is_none() && !entries.is_empty(),
        "Apple map lacks complete image ranges"
    );
    Ok(entries)
}

/// Compare original Apple map install names/first __TEXT VAs with a verified
/// set inventory. The map stays an independent hashed text oracle, not a loader.
pub fn verify_apple_map(set: &Value, path: &Path) -> Result<Value> {
    ensure!(
        set["kind"] == "dyld_shared_cache_set_manifest" && set["cache_set_files_verified"] == true,
        "Apple map comparison requires a verified cache-set metadata manifest"
    );
    let before = path.symlink_metadata()?;
    ensure!(
        before.file_type().is_file() && !before.file_type().is_symlink(),
        "Apple map must be a regular nonsymlink file"
    );
    ensure!(
        before.len() <= METADATA_LIMIT,
        "Apple map exceeds 16 MiB text budget"
    );
    let mut file = File::open(path)?;
    ensure!(
        same_file(&before, &file.metadata()?),
        "Apple map changed before opening"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(METADATA_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len(),
        "Apple map size changed while reading"
    );
    let entries =
        apple_map_entries(std::str::from_utf8(&bytes).context("Apple map is not UTF-8")?)?;
    let mut images = BTreeMap::new();
    for image in set["images"]
        .as_array()
        .context("cache set has no images")?
    {
        let name = image["path"]
            .as_str()
            .context("cache image has no path")?
            .to_owned();
        let address = image["address"]
            .as_u64()
            .context("cache image has no address")?;
        ensure!(
            images.insert(name, address).is_none(),
            "duplicate verified cache-set image path"
        );
    }
    ensure!(
        entries == images,
        "original Apple map path/__TEXT address set differs from cache image headers"
    );
    let checksum = stela_core::sha256(&bytes);
    ensure!(
        hash_file(&mut file)? == checksum
            && same_file(&before, &file.metadata()?)
            && same_file(&before, &path.symlink_metadata()?),
        "Apple map changed during comparison"
    );
    let sources=set["files"].as_array().context("cache set has no file receipts")?.iter().map(|value|
        json!({"path":value["path"],"source_sha256":value["source_sha256"],"uuid":value["header"]["uuid"]})
    ).collect::<Vec<_>>();
    Ok(
        json!({"kind":"apple_dyld_map_comparison","passed":true,"map_path":path.to_string_lossy(),
        "map_sha256":checksum,"map_bytes":bytes.len(),"map_source_identity":file_identity(&before),
        "matched_path_and_text_address_pairs":entries.len(),"cache_sources":sources,
        "complete_binary_verified":false,"limits":"Independent original map path/address metadata only; no cache rebasing, authentication or image execution"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        bytes[..15].copy_from_slice(b"dyld_v1  arm64e");
        put32(&mut bytes, 16, 552);
        put32(&mut bytes, 20, 1);
        bytes[88..104].fill(0x12);
        put64(&mut bytes, 224, 0x180000000);
        put64(&mut bytes, 232, 0x10000);
        put64(&mut bytes, 552, 0x180000000);
        put64(&mut bytes, 560, 4096);
        put32(&mut bytes, 576, 5);
        put32(&mut bytes, 580, 5);
        put32(&mut bytes, 448, 640);
        put32(&mut bytes, 452, 2);
        put64(&mut bytes, 640, 0x180000800);
        put32(&mut bytes, 664, 768);
        put64(&mut bytes, 672, 0x180008000);
        put32(&mut bytes, 696, 784);
        bytes[768..778].copy_from_slice(b"/usr/lib/a");
        bytes[784..794].copy_from_slice(b"/usr/lib/b");
        put32(&mut bytes, 392, 896);
        put32(&mut bytes, 396, 1);
        bytes[896..912].fill(0x34);
        put64(&mut bytes, 912, 0x8000);
        bytes[920..928].copy_from_slice(b".01.data");
        bytes
    }
    fn inspect(bytes: Vec<u8>) -> Result<Value> {
        let len = bytes.len() as u64;
        parse(&mut Cursor::new(bytes), len)
    }

    #[test]
    fn modern_header_maps_base_images_and_retains_unresolved_subcache_references() {
        let value = inspect(fixture()).unwrap();
        assert_eq!(value["images"][0]["mach_header_file_offset"], 2048);
        assert!(value["images"][1]["mach_header_file_offset"].is_null());
        assert_eq!(value["subcaches"][0]["file_suffix"], ".01.data");
        assert_eq!(value["subcaches"][0]["expected_vm_address"], 0x180008000u64);
        assert_eq!(value["header"]["architecture"], "arm64e");
        assert_eq!(value["complete_binary_verified"], false);
    }
    #[test]
    fn old_known_header_does_not_claim_optional_fields_are_empty() {
        let mut bytes = fixture();
        put32(&mut bytes, 16, 104);
        let table = bytes[552..584].to_vec();
        bytes[104..136].copy_from_slice(&table);
        put32(&mut bytes, 24, 640);
        put32(&mut bytes, 28, 1);
        let value = inspect(bytes).unwrap();
        assert_eq!(value["header"]["image_table_layout"], "legacy");
        assert_eq!(
            value["header"]["subcache_table_layout"],
            "header_field_unavailable"
        );
        assert!(!value["unresolved"].as_array().unwrap().is_empty());
    }
    #[test]
    fn declines_unknown_magic_architecture_and_truncated_fields() {
        for mutation in [0, 1, 2, 3] {
            let mut bytes = fixture();
            match mutation {
                0 => bytes[6] = b'2',
                1 => bytes[10] = b'x',
                2 => bytes[15] = 1,
                _ => put32(&mut bytes, 16, 96),
            };
            assert!(inspect(bytes).is_err());
        }
        assert!(inspect(vec![0; 23]).is_err());
    }
    #[test]
    fn bounds_counts_offsets_vm_and_file_extents() {
        for mutation in 0..7 {
            let mut bytes = fixture();
            match mutation {
                0 => put32(&mut bytes, 20, 4097),
                1 => put32(&mut bytes, 452, 1_000_001),
                2 => put32(&mut bytes, 448, 4090),
                3 => put64(&mut bytes, 552, u64::MAX - 1),
                4 => put64(&mut bytes, 560, 4097),
                5 => put32(&mut bytes, 396, 4097),
                _ => put64(&mut bytes, 912, u64::MAX),
            };
            assert!(inspect(bytes).is_err(), "mutation {mutation}");
        }
        assert!(extent(u64::MAX, 1, u64::MAX).is_err());
        assert!(table_size(u64::MAX, 56, u64::MAX).is_err());
    }
    #[test]
    fn rejects_unterminated_invalid_utf8_or_relative_image_paths_and_suffixes() {
        for mutation in 0..5 {
            let mut bytes = fixture();
            match mutation {
                0 => bytes[768..].fill(b'a'),
                1 => bytes[769] = 0xff,
                2 => bytes[768] = b'x',
                3 => bytes[920..952].fill(b'a'),
                _ => bytes[920..928].copy_from_slice(b"../evil\0"),
            };
            assert!(inspect(bytes).is_err(), "mutation {mutation}");
        }
    }
    #[test]
    fn rejects_mapping_overlap_protection_and_missing_base_header_coverage() {
        for mutation in 0..4 {
            let mut bytes = fixture();
            match mutation {
                0 => {
                    put32(&mut bytes, 20, 2);
                    let copy = bytes[552..584].to_vec();
                    bytes[584..616].copy_from_slice(&copy);
                }
                1 => put32(&mut bytes, 580, 3),
                2 => put32(&mut bytes, 576, 13),
                _ => put64(&mut bytes, 568, 1),
            };
            assert!(inspect(bytes).is_err());
        }
    }
    #[test]
    fn metadata_budget_is_independent_of_large_logical_file_size() {
        let mut cursor = Cursor::new(vec![0; 128]);
        let mut metadata = Metadata {
            reader: &mut cursor,
            file_bytes: u64::MAX,
            bytes_read: METADATA_LIMIT,
        };
        assert!(
            metadata
                .read(0, 1)
                .unwrap_err()
                .to_string()
                .contains("budget")
        );
    }
    #[test]
    fn file_receipt_hashes_whole_file_and_keeps_metadata_inventory_unverified() {
        let mut temporary = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        let bytes = fixture();
        temporary.write_all(&bytes).unwrap();
        let value = manifest(temporary.path()).unwrap();
        assert_eq!(value["source_sha256"], stela_core::sha256(&bytes));
        assert_eq!(value["source_stable_during_inspection"], true);
        assert_eq!(value["cache_set_complete"], false);
    }

    fn macho(identity: &str, dependencies: &[&str], uuid_byte: u8) -> Vec<u8> {
        let mut commands = Vec::new();
        commands.extend(0x1bu32.to_le_bytes());
        commands.extend(24u32.to_le_bytes());
        commands.extend([uuid_byte; 16]);
        for (kind, name) in std::iter::once((0xdu32, identity))
            .chain(dependencies.iter().map(|name| (0xcu32, *name)))
        {
            let size = (24 + name.len() + 1 + 7) & !7;
            let mut command = vec![0; size];
            put32(&mut command, 0, kind);
            put32(&mut command, 4, size as u32);
            put32(&mut command, 8, 24);
            command[24..24 + name.len()].copy_from_slice(name.as_bytes());
            commands.extend(command);
        }
        let mut header = vec![0; 32];
        put32(&mut header, 0, 0xfeedfacf);
        put32(&mut header, 4, 0x0100000c);
        put32(&mut header, 8, 0x80000002);
        put32(&mut header, 12, 6);
        put32(&mut header, 16, 2 + dependencies.len() as u32);
        put32(&mut header, 20, commands.len() as u32);
        put32(&mut header, 24, 0x80000000);
        header.extend(commands);
        header
    }

    fn set_fixture(directory: &Path) -> PathBuf {
        let path = directory.join("cache");
        let mut main = fixture();
        put64(&mut main, 672, 0x180008800);
        let image = macho("/usr/lib/a", &["/usr/lib/b"], 0x56);
        main[2048..2048 + image.len()].copy_from_slice(&image);
        let mut sibling = fixture();
        sibling[88..104].fill(0x34);
        put64(&mut sibling, 552, 0x180008000);
        put32(&mut sibling, 448, 0);
        put32(&mut sibling, 452, 0);
        put32(&mut sibling, 392, 0);
        put32(&mut sibling, 396, 0);
        let image = macho("/usr/lib/b", &[], 0x78);
        sibling[2048..2048 + image.len()].copy_from_slice(&image);
        std::fs::write(&path, main).unwrap();
        std::fs::write(directory.join("cache.01.data"), sibling).unwrap();
        path
    }

    fn mutate_file(path: &Path, mutation: impl FnOnce(&mut Vec<u8>)) {
        let mut bytes = std::fs::read(path).unwrap();
        mutation(&mut bytes);
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn set_resolves_original_header_offsets_uuids_and_ordered_dependencies() {
        let directory = tempfile::tempdir().unwrap();
        let path = set_fixture(directory.path());
        let value = manifest_set(&path).unwrap();
        assert_eq!(value["file_count"], 2);
        assert_eq!(value["cache_set_files_verified"], true);
        assert_eq!(value["image_headers_verified"], 2);
        assert_eq!(value["complete_binary_verified"], false);
        assert_eq!(value["images"][0]["source_cache_index"], 0);
        assert_eq!(value["images"][1]["source_cache_index"], 1);
        assert_eq!(value["images"][1]["cache_file_offset"], 2048);
        assert_eq!(
            value["images"][0]["mach_o"]["dependencies"][0]["name"],
            "/usr/lib/b"
        );
        assert_eq!(
            value["images"][0]["mach_o"]["dependencies"][0]["library_ordinal"],
            1
        );
        assert_eq!(
            value["images"][0]["mach_o"]["uuid"],
            "56565656-5656-5656-5656-565656565656"
        );
        assert!(value["files"][0]["source_identity"].is_object());
    }

    #[test]
    fn set_checks_original_region_base_extent_and_complete_subcache_containment() {
        for mutation in 0..4 {
            let directory = tempfile::tempdir().unwrap();
            let path = set_fixture(directory.path());
            mutate_file(&path, |bytes| match mutation {
                0 => put64(bytes, 224, 0x180004000),
                1 => put64(bytes, 232, 0),
                2 => put64(bytes, 232, 0x8000),
                _ => put64(bytes, 232, u64::MAX),
            });
            assert!(
                manifest_set(&path)
                    .unwrap_err()
                    .to_string()
                    .contains("shared region")
            );
        }
        let directory = tempfile::tempdir().unwrap();
        let path = set_fixture(directory.path());
        mutate_file(&path, |bytes| put64(bytes, 232, 0x9000));
        assert!(manifest_set(&path).is_ok());
    }

    #[test]
    fn set_rejects_missing_siblings_uuid_swap_architecture_and_vm_mismatch() {
        for mutation in 0..4 {
            let directory = tempfile::tempdir().unwrap();
            let path = set_fixture(directory.path());
            let sibling = directory.path().join("cache.01.data");
            match mutation {
                0 => std::fs::remove_file(&sibling).unwrap(),
                1 => mutate_file(&sibling, |bytes| bytes[88..104].fill(0x99)),
                2 => mutate_file(&sibling, |bytes| {
                    bytes[..15].copy_from_slice(b"dyld_v1   arm64")
                }),
                _ => mutate_file(&sibling, |bytes| put64(bytes, 552, 0x180009000)),
            }
            assert!(manifest_set(&path).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn set_rejects_overlapping_vm_paths_nested_references_and_symbol_requirements() {
        for mutation in 0..4 {
            let directory = tempfile::tempdir().unwrap();
            let path = set_fixture(directory.path());
            let sibling = directory.path().join("cache.01.data");
            match mutation {
                0 => {
                    mutate_file(&path, |bytes| put64(bytes, 912, 0x800));
                    mutate_file(&sibling, |bytes| put64(bytes, 552, 0x180000800));
                }
                1 => mutate_file(&path, |bytes| put32(bytes, 696, 768)),
                2 => mutate_file(&sibling, |bytes| {
                    put32(bytes, 392, 896);
                    put32(bytes, 396, 1);
                }),
                _ => mutate_file(&path, |bytes| bytes[400..416].fill(1)),
            }
            assert!(manifest_set(&path).is_err(), "mutation {mutation}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn set_refuses_symlink_siblings_even_when_target_has_correct_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = set_fixture(directory.path());
        let sibling = directory.path().join("cache.01.data");
        let target = directory.path().join("real");
        std::fs::rename(&sibling, &target).unwrap();
        std::os::unix::fs::symlink(&target, &sibling).unwrap();
        assert!(
            manifest_set(&path)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
    }

    #[test]
    fn set_rejects_bad_macho_type_uuid_count_command_bounds_and_mapping_straddle() {
        for mutation in 0..5 {
            let directory = tempfile::tempdir().unwrap();
            let path = set_fixture(directory.path());
            let sibling = directory.path().join("cache.01.data");
            match mutation {
                0 => mutate_file(&sibling, |bytes| put32(bytes, 2048 + 12, 2)),
                1 => mutate_file(&sibling, |bytes| put32(bytes, 2048 + 32, 0x777)),
                2 => mutate_file(&sibling, |bytes| put32(bytes, 2048 + 20, 1_048_584)),
                3 => mutate_file(&sibling, |bytes| put32(bytes, 2048 + 32 + 4, 7)),
                _ => mutate_file(&sibling, |bytes| put64(bytes, 560, 2064)),
            }
            assert!(manifest_set(&path).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn apple_map_matches_complete_path_address_set_and_binds_original_hashes() {
        let directory = tempfile::tempdir().unwrap();
        let path = set_fixture(directory.path());
        let set = manifest_set(&path).unwrap();
        let map = directory.path().join("cache.map");
        std::fs::write(&map,"mapping EX ignored\n/usr/lib/a\n\t __TEXT 0x180000800 -> 0x180000900\n/usr/lib/b\n\t __TEXT 0x180008800 -> 0x180008900\n").unwrap();
        let value = verify_apple_map(&set, &map).unwrap();
        assert_eq!(value["matched_path_and_text_address_pairs"], 2);
        assert_eq!(value["cache_sources"].as_array().unwrap().len(), 2);
        assert_eq!(
            value["map_sha256"],
            stela_core::sha256(&std::fs::read(&map).unwrap())
        );
        std::fs::write(&map, "/usr/lib/a\n __TEXT 0x180000801 -> 0x180000900\n").unwrap();
        assert!(verify_apple_map(&set, &map).is_err());
    }

    #[test]
    fn apple_map_declines_duplicate_missing_bad_or_reversed_text_ranges() {
        for text in [
            "/a\n/a\n",
            "/a\n __TEXT 0x2 -> 0x1\n",
            "/a\n __TEXT xyz -> 0x4\n",
            "/a\n __TEXT 0x1 -> 0x4\n/a\n __TEXT 0x1 -> 0x4\n",
            "/a\0\n",
        ] {
            assert!(apple_map_entries(text).is_err());
        }
    }

    #[test]
    #[ignore = "Requires original acquired Apple cache set; set STELA_DYLD_CACHE_MAIN"]
    fn acquired_original_cache_set_matches_original_apple_map() {
        let path = PathBuf::from(
            std::env::var_os("STELA_DYLD_CACHE_MAIN").expect("set STELA_DYLD_CACHE_MAIN"),
        );
        let set = manifest_set(&path).unwrap();
        let mut map_name = path.as_os_str().to_os_string();
        map_name.push(".map");
        let comparison = verify_apple_map(&set, Path::new(&map_name)).unwrap();
        assert_eq!(
            comparison["matched_path_and_text_address_pairs"],
            set["image_headers_verified"]
        );
        if let Some(output) = std::env::var_os("STELA_DYLD_CACHE_EVIDENCE") {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)
                .unwrap();
            let report = json!({"kind":"original_apple_cache_set_metadata_evidence","cache_set":set,"original_map":comparison,
                "complete_binary_verified":false});
            serde_json::to_writer_pretty(&mut file, &report).unwrap();
            file.write_all(b"\n").unwrap();
            file.sync_all().unwrap();
        }
    }
}
