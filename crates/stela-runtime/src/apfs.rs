//! A read-only Apple File System reader, in `no_std` with `alloc`.
//!
//! Implemented from Apple's *Apple File System Reference* (revision
//! 2020-06-22), whose structure and constant names this follows. It reads a
//! container through any [`ReadAt`] source: the newest valid checkpoint
//! ("Mounting an Apple File System Partition"), the container and volume
//! object maps, B-trees with physical or virtual children (hashed trees of
//! sealed volumes included), volume superblocks and roles, and file-system
//! records: inodes, directory entries, file extents (or the file-extent tree
//! of a sealed volume), extended attributes, symbolic links and snapshots.
//!
//! Anything this reader cannot interpret faithfully is refused rather than
//! guessed: encrypted volumes and objects, transparently compressed files,
//! Fusion containers, ephemeral B-tree children and B-tree checkpoint
//! descriptor areas each return a distinct [`ApfsError`].
use crate::payload::{ReadAt, gpt};
use alloc::{format, string::String, vec, vec::Vec};
use core::fmt;

pub mod btree;
pub mod container;
pub mod object;
pub mod volume;

pub use container::Container;
pub use volume::{Entry, FileKind, Inode, Volume};

/// The APFS partition type in a GUID partition table.
pub const PARTITION_TYPE: &str = "7C3457EF-0000-11AA-AA11-00306543ECAC";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApfsError {
    /// The source failed to read.
    Io(String),
    /// A structure contradicts the reference.
    Malformed(&'static str),
    /// An object's Fletcher-64 checksum does not match.
    Checksum {
        paddr: u64,
    },
    /// A defined feature this reader does not implement.
    Unsupported(&'static str),
    /// Encrypted volumes and objects are refused; they need keys.
    Encrypted,
    NotFound(String),
}

impl fmt::Display for ApfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(what) => write!(f, "read failed: {what}"),
            Self::Malformed(what) => write!(f, "malformed APFS: {what}"),
            Self::Checksum { paddr } => write!(f, "object at block {paddr:#x} fails its checksum"),
            Self::Unsupported(what) => write!(f, "unsupported APFS feature: {what}"),
            Self::Encrypted => write!(f, "the volume or object is encrypted"),
            Self::NotFound(what) => write!(f, "{what} not found"),
        }
    }
}

impl core::error::Error for ApfsError {}

pub type Result<T> = core::result::Result<T, ApfsError>;

/// Little-endian field readers over a block; out-of-range reads are
/// malformed structures.
pub(crate) fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(ApfsError::Malformed("truncated field"))?
            .try_into()
            .unwrap(),
    ))
}

pub(crate) fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(ApfsError::Malformed("truncated field"))?
            .try_into()
            .unwrap(),
    ))
}

pub(crate) fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(ApfsError::Malformed("truncated field"))?
            .try_into()
            .unwrap(),
    ))
}

pub(crate) fn uuid_at(bytes: &[u8], at: usize) -> Result<[u8; 16]> {
    Ok(bytes
        .get(at..at + 16)
        .ok_or(ApfsError::Malformed("truncated field"))?
        .try_into()
        .unwrap())
}

/// `uuid_t` in its canonical text form.
pub fn uuid_text(uuid: &[u8; 16]) -> String {
    let hex = |range: core::ops::Range<usize>| {
        uuid[range]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(0..4),
        hex(4..6),
        hex(6..8),
        hex(8..10),
        hex(10..16)
    )
}

/// `NX_MAGIC` as stored, at byte 32 of a container's block zero.
const NX_MAGIC: &[u8; 4] = b"NXSB";
/// Logical block sizes a GUID partition table is looked for at.
const SECTOR_SIZES: [u64; 2] = [512, 4096];

/// Byte offsets of the APFS containers in `source`: the source itself when
/// it starts with a container, else every APFS partition of its GUID
/// partition table.
pub fn containers<R: ReadAt>(source: &mut R) -> Result<Vec<u64>> {
    let io = |error: R::Error| ApfsError::Io(format!("{error:?}"));
    let mut head = [0u8; 36];
    if source.len() < head.len() as u64 {
        return Err(ApfsError::NotFound("an APFS container".into()));
    }
    source.read_at(0, &mut head).map_err(io)?;
    if &head[32..36] == NX_MAGIC {
        return Ok(vec![0]);
    }
    let apfs = gpt::Guid::parse(PARTITION_TYPE).expect("constant GUID");
    for sector in SECTOR_SIZES {
        let disk = gpt::Disk {
            block_bytes: sector,
            blocks: source.len() / sector,
        };
        if disk.blocks < 3 {
            continue;
        }
        let mut header = vec![0u8; sector as usize];
        source.read_at(sector, &mut header).map_err(io)?;
        let Ok(Some(info)) = gpt::parse_header(disk, 1, &header) else {
            continue;
        };
        let mut entries = vec![0u8; info.entry_array_bytes() as usize];
        source
            .read_at(info.entries_lba * sector, &mut entries)
            .map_err(io)?;
        let table = gpt::parse_entries(&info, &entries)
            .map_err(|_| ApfsError::Malformed("GUID partition table entries"))?;
        return Ok(table
            .partitions
            .iter()
            .filter(|partition| partition.type_guid == apfs)
            .map(|partition| partition.first_lba * sector)
            .collect());
    }
    Err(ApfsError::NotFound("an APFS container".into()))
}

/// The container's blocks: a [`ReadAt`] source, the byte offset of the
/// partition within it and the container's block size.
pub struct Device<R> {
    source: R,
    base: u64,
    block_size: u32,
}

impl<R: ReadAt> Device<R> {
    pub(crate) fn new(source: R, base: u64, block_size: u32) -> Self {
        Self {
            source,
            base,
            block_size,
        }
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub(crate) fn set_block_size(&mut self, block_size: u32) {
        self.block_size = block_size;
    }

    /// Read bytes at a byte offset inside the container.
    pub fn read_bytes(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let at = self
            .base
            .checked_add(offset)
            .ok_or(ApfsError::Malformed("offset overflows"))?;
        let end = at
            .checked_add(buffer.len() as u64)
            .ok_or(ApfsError::Malformed("offset overflows"))?;
        if end > self.source.len() {
            return Err(ApfsError::Malformed(
                "block lies past the end of the source",
            ));
        }
        self.source
            .read_at(at, buffer)
            .map_err(|error| ApfsError::Io(format!("{error:?}")))
    }

    /// One block by its physical address.
    pub fn read_block(&mut self, paddr: u64) -> Result<Vec<u8>> {
        let mut block = vec![0; self.block_size as usize];
        let offset = paddr
            .checked_mul(u64::from(self.block_size))
            .ok_or(ApfsError::Malformed("block address overflows"))?;
        self.read_bytes(offset, &mut block)?;
        Ok(block)
    }

    /// One object by its physical address, its checksum verified.
    pub fn read_object(&mut self, paddr: u64) -> Result<Vec<u8>> {
        let block = self.read_block(paddr)?;
        if !object::checksum_valid(&block) {
            return Err(ApfsError::Checksum { paddr });
        }
        Ok(block)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// An in-memory source.
    pub(crate) struct Memory(pub Vec<u8>);

    impl ReadAt for Memory {
        type Error = &'static str;
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(
            &mut self,
            offset: u64,
            buffer: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            let start = offset as usize;
            buffer.copy_from_slice(self.0.get(start..start + buffer.len()).ok_or("past end")?);
            Ok(())
        }
    }

    /// The fixture container `tests/fixtures/apfs/preboot.img.gz`, made by
    /// `make-preboot.sh` with `hdiutil` and `diskutil`: one Preboot-role
    /// volume "Stela" holding a Preboot-like tree.
    pub(crate) fn fixture() -> Memory {
        let compressed = include_bytes!("../tests/fixtures/apfs/preboot.img.gz");
        Memory(gunzip(compressed))
    }

    /// A volume sealed by Apple's `apfs_prepare_cryptex`
    /// (`tests/fixtures/apfs/make-sealed.sh`).
    pub(crate) fn sealed_fixture() -> Memory {
        let compressed = include_bytes!("../tests/fixtures/apfs/sealed.img.gz");
        Memory(gunzip(compressed))
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        // RFC 1952: a 10-byte header (no optional fields from gzip -n),
        // a raw deflate stream, then CRC-32 and size.
        assert_eq!(&data[..3], &[0x1f, 0x8b, 8]);
        assert_eq!(data[3] & !0x08, 0, "only FNAME may be set");
        let mut start = 10;
        if data[3] & 0x08 != 0 {
            start += data[start..].iter().position(|&b| b == 0).unwrap() + 1;
        }
        miniz_oxide::inflate::decompress_to_vec(&data[start..data.len() - 8]).unwrap()
    }

    #[test]
    fn uuid_text_is_canonical() {
        let uuid = [
            0x7c, 0x34, 0x57, 0xef, 0, 0, 0x11, 0xaa, 0xaa, 0x11, 0, 0x30, 0x65, 0x43, 0xec, 0xac,
        ];
        assert_eq!(uuid_text(&uuid), PARTITION_TYPE);
    }
}
