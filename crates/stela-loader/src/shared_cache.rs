//! The mappings of a dyld shared cache and its subcaches, as dyld hands them
//! to `shared_region_map_and_slide_2_np`: for every file, each
//! `dyld_cache_mapping_and_slide_info` becomes one `shared_file_mapping_slide_np`
//! (file, file offset, unslid address, size, protections and the file range
//! of its slide info). Layout from dyld-1378 `include/mach-o/dyld_cache_format.h`.
//!
//! Only the headers are read. Subcache UUIDs and VM offsets are checked
//! against the main cache's `dyld_subcache_entry` table, so a mixed set of
//! files is refused before any mapping.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

const MAGIC_PREFIX: &[u8] = b"dyld_v1";
/// The header fields read, through `cacheSubType` (offset 0x1c4).
const HEADER_BYTES: usize = 0x200;
const MAPPING_OFFSET: usize = 0x10;
const MAPPING_COUNT: usize = 0x14;
const UUID: usize = 0x58;
const CACHE_TYPE: usize = 0x68;
const SHARED_REGION_START: usize = 0xe0;
const SHARED_REGION_SIZE: usize = 0xe8;
const MAX_SLIDE: usize = 0xf0;
const MAPPING_WITH_SLIDE_OFFSET: usize = 0x138;
const MAPPING_WITH_SLIDE_COUNT: usize = 0x13c;
const SUBCACHE_ARRAY_OFFSET: usize = 0x188;
const SUBCACHE_ARRAY_COUNT: usize = 0x18c;
/// `dyld_cache_mapping_and_slide_info`.
const MAPPING_WITH_SLIDE_BYTES: usize = 56;
/// `dyld_subcache_entry`: UUID, VM offset and a 32-byte file suffix.
const SUBCACHE_ENTRY_BYTES: usize = 56;
const SUBCACHE_SUFFIX_BYTES: usize = 32;
/// Sanity bounds on header tables, not dyld limits.
const MAX_MAPPINGS: usize = 64;
const MAX_SUBCACHES: usize = 256;

/// One `shared_file_mapping_slide_np`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mapping {
    pub file: usize,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub max_protection: u32,
    pub initial_protection: u32,
    /// The `DYLD_CACHE_MAPPING_*` flags.
    pub flags: u64,
    /// File offset and size of this mapping's slide info, when it has one.
    pub slide_info: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheFile {
    pub path: PathBuf,
    pub uuid: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharedCache {
    pub files: Vec<CacheFile>,
    pub mappings: Vec<Mapping>,
    pub uuid: [u8; 16],
    pub cache_type: u64,
    pub shared_region_start: u64,
    pub shared_region_size: u64,
    pub max_slide: u64,
}

fn u32_at(header: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(header[offset..offset + 4].try_into().expect("four bytes"))
}

fn u64_at(header: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(header[offset..offset + 8].try_into().expect("eight bytes"))
}

fn read_at(file: &mut File, offset: u64, bytes: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0; bytes];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

struct Header {
    bytes: Vec<u8>,
    mappings: Vec<Mapping>,
}

fn header(path: &Path, index: usize) -> Result<Header> {
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let bytes = read_at(&mut file, 0, HEADER_BYTES)
        .with_context(|| format!("{}: truncated cache header", path.display()))?;
    ensure!(
        bytes.starts_with(MAGIC_PREFIX),
        "{}: not a dyld shared cache",
        path.display()
    );
    let offset = u32_at(&bytes, MAPPING_WITH_SLIDE_OFFSET);
    let count = u32_at(&bytes, MAPPING_WITH_SLIDE_COUNT) as usize;
    ensure!(
        offset != 0 && (1..=MAX_MAPPINGS).contains(&count),
        "{}: cache lacks mapping-and-slide records",
        path.display()
    );
    ensure!(
        count == u32_at(&bytes, MAPPING_COUNT) as usize && u32_at(&bytes, MAPPING_OFFSET) != 0,
        "{}: mapping tables disagree",
        path.display()
    );
    let table = read_at(
        &mut file,
        u64::from(offset),
        count * MAPPING_WITH_SLIDE_BYTES,
    )?;
    let mappings = table
        .as_chunks::<MAPPING_WITH_SLIDE_BYTES>()
        .0
        .iter()
        .map(|record| {
            let slide_offset = u64_at(record, 24);
            let slide_size = u64_at(record, 32);
            Mapping {
                file: index,
                address: u64_at(record, 0),
                size: u64_at(record, 8),
                file_offset: u64_at(record, 16),
                flags: u64_at(record, 40),
                max_protection: u32_at(record, 48),
                initial_protection: u32_at(record, 52),
                slide_info: (slide_size != 0).then_some((slide_offset, slide_size)),
            }
        })
        .collect();
    Ok(Header { bytes, mappings })
}

fn uuid_text(uuid: &[u8]) -> String {
    hex::encode(uuid)
}

/// Plan the cache whose main file is `main`, with its subcaches beside it.
pub fn plan(main: &Path) -> Result<SharedCache> {
    let main_header = header(main, 0)?;
    let bytes = &main_header.bytes;
    let uuid: [u8; 16] = bytes[UUID..UUID + 16].try_into()?;
    let mut files = vec![CacheFile {
        path: main.to_path_buf(),
        uuid: uuid_text(&uuid),
    }];
    let mut mappings = main_header.mappings;
    let shared_region_start = u64_at(bytes, SHARED_REGION_START);
    let subcache_offset = u32_at(bytes, SUBCACHE_ARRAY_OFFSET);
    let subcache_count = u32_at(bytes, SUBCACHE_ARRAY_COUNT) as usize;
    ensure!(
        subcache_count <= MAX_SUBCACHES,
        "cache declares too many subcaches"
    );
    if subcache_count != 0 {
        let mut file = File::open(main)?;
        let table = read_at(
            &mut file,
            u64::from(subcache_offset),
            subcache_count * SUBCACHE_ENTRY_BYTES,
        )?;
        let directory = main.parent().context("cache path has no directory")?;
        let name = main
            .file_name()
            .context("cache path has no file name")?
            .to_string_lossy()
            .into_owned();
        for entry in table.as_chunks::<SUBCACHE_ENTRY_BYTES>().0 {
            let expected = &entry[..16];
            let vm_offset = u64_at(entry, 16);
            let suffix = &entry[24..24 + SUBCACHE_SUFFIX_BYTES];
            let suffix = &suffix[..suffix.iter().position(|&b| b == 0).unwrap_or(suffix.len())];
            let path = directory.join(format!("{name}{}", std::str::from_utf8(suffix)?));
            let index = files.len();
            let sub = header(&path, index)?;
            ensure!(
                &sub.bytes[UUID..UUID + 16] == expected,
                "{}: UUID differs from the main cache's subcache entry",
                path.display()
            );
            let first = sub.mappings[0].address;
            ensure!(
                first.checked_sub(shared_region_start) == Some(vm_offset),
                "{}: first mapping is not at its declared VM offset",
                path.display()
            );
            files.push(CacheFile {
                path,
                uuid: uuid_text(expected),
            });
            mappings.extend(sub.mappings);
        }
    }
    let shared_region_size = u64_at(bytes, SHARED_REGION_SIZE);
    let end = shared_region_start
        .checked_add(shared_region_size)
        .context("shared region overflow")?;
    let mut sorted: Vec<&Mapping> = mappings.iter().collect();
    sorted.sort_by_key(|mapping| mapping.address);
    for pair in sorted.windows(2) {
        ensure!(
            pair[0].address + pair[0].size <= pair[1].address,
            "cache mappings overlap at {:#x}",
            pair[1].address
        );
    }
    for mapping in &mappings {
        let Some(last) = mapping.address.checked_add(mapping.size) else {
            bail!("cache mapping overflows");
        };
        ensure!(
            mapping.address >= shared_region_start && last <= end,
            "cache mapping {:#x} is outside the shared region",
            mapping.address
        );
    }
    Ok(SharedCache {
        files,
        mappings,
        uuid,
        cache_type: u64_at(bytes, CACHE_TYPE),
        shared_region_start,
        shared_region_size,
        max_slide: u64_at(bytes, MAX_SLIDE),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(
        mappings: &[(u64, u64, u64)],
        subcaches: &[([u8; 16], u64, &str)],
        uuid: u8,
    ) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[..16].copy_from_slice(b"dyld_v1  arm64e\0");
        let table = 0x200usize;
        bytes[MAPPING_OFFSET..MAPPING_OFFSET + 4].copy_from_slice(&(table as u32).to_le_bytes());
        bytes[MAPPING_COUNT..MAPPING_COUNT + 4]
            .copy_from_slice(&(mappings.len() as u32).to_le_bytes());
        bytes[MAPPING_WITH_SLIDE_OFFSET..MAPPING_WITH_SLIDE_OFFSET + 4]
            .copy_from_slice(&(table as u32).to_le_bytes());
        bytes[MAPPING_WITH_SLIDE_COUNT..MAPPING_WITH_SLIDE_COUNT + 4]
            .copy_from_slice(&(mappings.len() as u32).to_le_bytes());
        bytes[UUID..UUID + 16].fill(uuid);
        bytes[SHARED_REGION_START..SHARED_REGION_START + 8]
            .copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        bytes[SHARED_REGION_SIZE..SHARED_REGION_SIZE + 8]
            .copy_from_slice(&0x10_0000u64.to_le_bytes());
        for (index, (address, size, slide)) in mappings.iter().enumerate() {
            let at = table + index * MAPPING_WITH_SLIDE_BYTES;
            bytes[at..at + 8].copy_from_slice(&address.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&size.to_le_bytes());
            bytes[at + 32..at + 40].copy_from_slice(&slide.to_le_bytes());
            bytes[at + 48..at + 52].copy_from_slice(&3u32.to_le_bytes());
            bytes[at + 52..at + 56].copy_from_slice(&1u32.to_le_bytes());
        }
        let entries = 0x300usize;
        bytes[SUBCACHE_ARRAY_OFFSET..SUBCACHE_ARRAY_OFFSET + 4]
            .copy_from_slice(&(entries as u32).to_le_bytes());
        bytes[SUBCACHE_ARRAY_COUNT..SUBCACHE_ARRAY_COUNT + 4]
            .copy_from_slice(&(subcaches.len() as u32).to_le_bytes());
        for (index, (uuid, offset, suffix)) in subcaches.iter().enumerate() {
            let at = entries + index * SUBCACHE_ENTRY_BYTES;
            bytes[at..at + 16].copy_from_slice(uuid);
            bytes[at + 16..at + 24].copy_from_slice(&offset.to_le_bytes());
            bytes[at + 24..at + 24 + suffix.len()].copy_from_slice(suffix.as_bytes());
        }
        bytes
    }

    #[test]
    fn subcaches_join_the_main_cache_and_mismatches_refuse() {
        let directory = tempfile::tempdir().unwrap();
        let main = directory.path().join("dyld_shared_cache_arm64e");
        std::fs::write(
            &main,
            cache(
                &[(0x1_8000_0000, 0x4000, 0)],
                &[([7; 16], 0x8000, ".01")],
                1,
            ),
        )
        .unwrap();
        let sub = directory.path().join("dyld_shared_cache_arm64e.01");
        std::fs::write(&sub, cache(&[(0x1_8000_8000, 0x4000, 0x20)], &[], 7)).unwrap();
        let plan = plan(&main).unwrap();
        assert_eq!(plan.files.len(), 2);
        assert_eq!(plan.mappings.len(), 2);
        assert_eq!(plan.mappings[1].file, 1);
        assert_eq!(plan.mappings[1].slide_info, Some((0, 0x20)));
        assert_eq!(plan.mappings[0].slide_info, None);
        std::fs::write(&sub, cache(&[(0x1_8000_8000, 0x4000, 0)], &[], 8)).unwrap();
        assert!(super::plan(&main).is_err());
    }
}
