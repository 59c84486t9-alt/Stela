//! Read one partition out of an Apple UDIF disk image (`.dmg`), such as the
//! decrypted BaseSystem image, as raw bytes.
//!
//! A UDIF image ends in a 512-byte `koly` trailer that locates an XML
//! property list. Its `resource-fork` → `blkx` entries describe each
//! partition as a `mish` block table of chunks. Only uncompressed images are
//! read: raw and zero-fill chunks. Compressed chunks are refused explicitly.
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const TRAILER_BYTES: u64 = 512;
const SECTOR: u64 = 512;
const MISH_HEADER_BYTES: usize = 204;
const CHUNK_BYTES: usize = 40;
const MAX_PLIST_BYTES: u64 = 16 * 1024 * 1024;
const CHUNK_ZERO: u32 = 0x0000_0000;
const CHUNK_RAW: u32 = 0x0000_0001;
const CHUNK_IGNORE: u32 = 0x0000_0002;
const CHUNK_COMMENT: u32 = 0x7fff_fffe;
const CHUNK_END: u32 = 0xffff_ffff;

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// One partition's table: where it starts and how its chunks fill it.
struct Partition {
    name: String,
    sectors: u64,
    /// The `mish` data offset, added to every chunk's offset.
    data_offset: u64,
    chunks: Vec<(u32, u64, u64, u64, u64)>,
}

fn partitions(file: &mut File) -> Result<(u64, Vec<Partition>)> {
    let length = file.metadata()?.len();
    ensure!(length >= TRAILER_BYTES, "too short for a UDIF image");
    file.seek(SeekFrom::Start(length - TRAILER_BYTES))?;
    let mut trailer = [0u8; TRAILER_BYTES as usize];
    file.read_exact(&mut trailer)?;
    ensure!(
        &trailer[..4] == b"koly",
        "not a UDIF image: no koly trailer"
    );
    let data_fork = u64_at(&trailer, 0x18);
    let (plist_offset, plist_bytes) = (u64_at(&trailer, 0xd8), u64_at(&trailer, 0xe0));
    ensure!(
        plist_bytes <= MAX_PLIST_BYTES && plist_offset + plist_bytes <= length,
        "UDIF property list is out of range"
    );
    file.seek(SeekFrom::Start(plist_offset))?;
    let mut xml = vec![0u8; plist_bytes as usize];
    file.read_exact(&mut xml)?;
    let root = Value::from_reader(std::io::Cursor::new(xml))?;
    let blocks = root
        .as_dictionary()
        .and_then(|r| r.get("resource-fork"))
        .and_then(Value::as_dictionary)
        .and_then(|r| r.get("blkx"))
        .and_then(Value::as_array)
        .context("UDIF image has no blkx table")?;
    let mut found = Vec::new();
    for block in blocks {
        let block = block.as_dictionary().context("bad blkx entry")?;
        let name = block
            .get("Name")
            .or_else(|| block.get("CFName"))
            .and_then(Value::as_string)
            .unwrap_or_default()
            .to_owned();
        let data = block
            .get("Data")
            .and_then(Value::as_data)
            .context("blkx entry has no Data")?;
        ensure!(
            data.len() >= MISH_HEADER_BYTES && &data[..4] == b"mish",
            "blkx {name} is not a mish table"
        );
        let count = u32_at(data, 200) as usize;
        ensure!(
            data.len() >= MISH_HEADER_BYTES + count * CHUNK_BYTES,
            "blkx {name} chunk table overruns"
        );
        let chunks = (0..count)
            .map(|i| {
                let c = &data[MISH_HEADER_BYTES + i * CHUNK_BYTES..];
                (
                    u32_at(c, 0),
                    u64_at(c, 8),
                    u64_at(c, 16),
                    u64_at(c, 24),
                    u64_at(c, 32),
                )
            })
            .collect();
        found.push(Partition {
            name,
            sectors: u64_at(data, 16),
            data_offset: u64_at(data, 24),
            chunks,
        });
    }
    Ok((data_fork, found))
}

/// The bytes of the one partition whose name contains `name`, such as
/// `Apple_APFS`, up to `limit` bytes.
pub fn partition(image: &Path, name: &str, limit: u64) -> Result<Vec<u8>> {
    let mut file = File::open(image).with_context(|| format!("cannot open {}", image.display()))?;
    let (data_fork, partitions) = partitions(&mut file)?;
    let matching: Vec<&Partition> = partitions
        .iter()
        .filter(|p| p.name.contains(name))
        .collect();
    let [partition] = matching[..] else {
        let names: Vec<_> = partitions.iter().map(|p| p.name.as_str()).collect();
        bail!(
            "expected one {name} partition in {}; found {names:?}",
            image.display()
        );
    };
    let bytes = partition
        .sectors
        .checked_mul(SECTOR)
        .filter(|&b| b <= limit)
        .with_context(|| format!("partition {} exceeds {limit} bytes", partition.name))?;
    let mut out = vec![0u8; bytes as usize];
    for &(kind, sector, count, offset, length) in &partition.chunks {
        let start = sector
            .checked_add(count)
            .filter(|&end| end <= partition.sectors)
            .map(|_| (sector * SECTOR) as usize)
            .with_context(|| format!("chunk outside partition {}", partition.name))?;
        let span = (count * SECTOR) as usize;
        match kind {
            CHUNK_ZERO | CHUNK_IGNORE => {}
            CHUNK_RAW => {
                ensure!(
                    length as usize == span,
                    "raw chunk length differs from its sectors"
                );
                file.seek(SeekFrom::Start(data_fork + partition.data_offset + offset))?;
                file.read_exact(&mut out[start..start + span])?;
            }
            CHUNK_COMMENT | CHUNK_END => {}
            other => bail!(
                "partition {} uses compressed UDIF chunks (type {other:#x}); only raw images \
                 are read",
                partition.name
            ),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn mish(first: u64, sectors: u64, chunks: &[(u32, u64, u64, u64, u64)]) -> Vec<u8> {
        let mut d = vec![0u8; MISH_HEADER_BYTES];
        d[..4].copy_from_slice(b"mish");
        d[8..16].copy_from_slice(&first.to_be_bytes());
        d[16..24].copy_from_slice(&sectors.to_be_bytes());
        d[200..204].copy_from_slice(&(chunks.len() as u32).to_be_bytes());
        for &(kind, sector, count, offset, length) in chunks {
            let mut c = vec![0u8; CHUNK_BYTES];
            c[..4].copy_from_slice(&kind.to_be_bytes());
            c[8..16].copy_from_slice(&sector.to_be_bytes());
            c[16..24].copy_from_slice(&count.to_be_bytes());
            c[24..32].copy_from_slice(&offset.to_be_bytes());
            c[32..40].copy_from_slice(&length.to_be_bytes());
            d.extend(c);
        }
        d
    }

    /// A data fork, then the plist, then the trailer.
    fn image(data: &[u8], blocks: &[(&str, Vec<u8>)]) -> tempfile::NamedTempFile {
        let entries: Vec<Value> = blocks
            .iter()
            .map(|(name, table)| {
                let mut d = plist::Dictionary::new();
                d.insert("Name".into(), (*name).into());
                d.insert("Data".into(), Value::Data(table.clone()));
                d.into()
            })
            .collect();
        let mut fork = plist::Dictionary::new();
        fork.insert("blkx".into(), Value::Array(entries));
        let mut root = plist::Dictionary::new();
        root.insert("resource-fork".into(), fork.into());
        let mut xml = Vec::new();
        Value::from(root).to_writer_xml(&mut xml).unwrap();
        let mut trailer = vec![0u8; TRAILER_BYTES as usize];
        trailer[..4].copy_from_slice(b"koly");
        trailer[0x20..0x28].copy_from_slice(&(data.len() as u64).to_be_bytes());
        trailer[0xd8..0xe0].copy_from_slice(&(data.len() as u64).to_be_bytes());
        trailer[0xe0..0xe8].copy_from_slice(&(xml.len() as u64).to_be_bytes());
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(data).unwrap();
        file.write_all(&xml).unwrap();
        file.write_all(&trailer).unwrap();
        file
    }

    #[test]
    fn raw_and_zero_chunks_rebuild_the_named_partition() {
        let raw: Vec<u8> = (0..1024u32).map(|i| i as u8).collect();
        let data = [vec![0xee; 512], raw.clone()].concat();
        let file = image(
            &data,
            &[
                (
                    "MBR : 0",
                    mish(0, 1, &[(CHUNK_RAW, 0, 1, 0, 512), (CHUNK_END, 1, 0, 0, 0)]),
                ),
                (
                    "Apple_APFS : 3",
                    mish(
                        34,
                        4,
                        &[
                            (CHUNK_RAW, 0, 2, 512, 1024),
                            (CHUNK_IGNORE, 2, 1, 0, 0),
                            (CHUNK_ZERO, 3, 1, 0, 0),
                            (CHUNK_END, 4, 0, 0, 0),
                        ],
                    ),
                ),
            ],
        );
        let apfs = partition(file.path(), "Apple_APFS", 1 << 20).unwrap();
        assert_eq!(apfs.len(), 2048);
        assert_eq!(&apfs[..1024], &raw[..]);
        assert!(apfs[1024..].iter().all(|&b| b == 0));
        assert!(partition(file.path(), "Apple_APFS", 1024).is_err());
        assert!(partition(file.path(), "Missing", 1 << 20).is_err());
    }

    #[test]
    fn compressed_chunks_and_non_udif_files_are_refused() {
        let file = image(
            &[0; 512],
            &[("Apple_APFS", mish(0, 1, &[(0x8000_0005, 0, 1, 0, 10)]))],
        );
        let error = partition(file.path(), "Apple_APFS", 1 << 20).unwrap_err();
        assert!(error.to_string().contains("compressed"), "{error}");
        let mut plain = tempfile::NamedTempFile::new().unwrap();
        plain.write_all(&[0; 1024]).unwrap();
        assert!(partition(plain.path(), "Apple_APFS", 1 << 20).is_err());
    }
}
