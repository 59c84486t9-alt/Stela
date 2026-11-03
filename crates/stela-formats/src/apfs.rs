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
pub mod decmpfs;
pub mod object;
pub mod volume;

pub use container::Container;
pub use volume::{Entry, FileKind, Inode, Volume};

/// The APFS partition type in a GUID partition table.
pub const PARTITION_TYPE: &str = "7C3457EF-0000-11AA-AA11-00306543ECAC";
/// The iBootSystemContainer (`Apple_APFS_ISC`) partition type: iSCPreboot,
/// xART and Hardware.
pub const ISC_PARTITION_TYPE: &str = "69646961-6700-11AA-AA11-00306543ECAC";

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
    Ok(container_partitions(source)?
        .into_iter()
        .map(|(offset, _)| offset)
        .collect())
}

/// [`containers`] with each one's GPT unique partition GUID, `None` for a
/// source that is itself a container.
pub fn container_partitions<R: ReadAt>(source: &mut R) -> Result<Vec<(u64, Option<gpt::Guid>)>> {
    let io = |error: R::Error| ApfsError::Io(format!("{error:?}"));
    let mut head = [0u8; 36];
    if source.len() < head.len() as u64 {
        return Err(ApfsError::NotFound("an APFS container".into()));
    }
    source.read_at(0, &mut head).map_err(io)?;
    if &head[32..36] == NX_MAGIC {
        return Ok(vec![(0, None)]);
    }
    let apfs = gpt::Guid::parse(PARTITION_TYPE).expect("constant GUID");
    Ok(typed_partitions(source, apfs)?
        .ok_or_else(|| ApfsError::NotFound("an APFS container".into()))?
        .into_iter()
        .map(|(offset, unique)| (offset, Some(unique)))
        .collect())
}

/// The byte offsets and unique GUIDs of the partitions of type `type_guid`
/// in `source`'s GUID partition table, found at a 512- or 4096-byte block
/// size; `None` when `source` has no valid table.
pub fn typed_partitions<R: ReadAt>(
    source: &mut R,
    type_guid: gpt::Guid,
) -> Result<Option<Vec<(u64, gpt::Guid)>>> {
    let io = |error: R::Error| ApfsError::Io(format!("{error:?}"));
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
        return Ok(Some(
            table
                .partitions
                .iter()
                .filter(|partition| partition.type_guid == type_guid)
                .map(|partition| (partition.first_lba * sector, partition.unique_guid))
                .collect(),
        ));
    }
    Ok(None)
}

/// Check that a Mac's internal disk `namespace` holds the iBootSystemContainer
/// (`Apple_APFS_ISC`) with its xART volume. A Mac's internal disk carries it
/// from the factory or the restore that creates it (`restored_external`), and
/// recoveryOS needs it: `apfs_boot_util`'s `mount_phase_one` ignores a missing
/// Update volume but aborts the boot without xART (`xART volume mount failed`,
/// recoveryOS boot rec-r7).
pub fn require_system_container<R: ReadAt>(namespace: &mut R) -> Result<()> {
    let isc = gpt::Guid::parse(ISC_PARTITION_TYPE).expect("constant GUID");
    let missing =
        || ApfsError::NotFound("an iBootSystemContainer (Apple_APFS_ISC) partition".into());
    let partitions = typed_partitions(namespace, isc)?.ok_or_else(missing)?;
    let [(offset, _)] = partitions[..] else {
        return Err(if partitions.is_empty() {
            missing()
        } else {
            ApfsError::Malformed("more than one iBootSystemContainer partition")
        });
    };
    // An interrupted restore leaves the partition without its container.
    if !Container::starts_at(&mut *namespace, offset)? {
        return Err(ApfsError::NotFound(
            "an APFS container in the iBootSystemContainer partition".into(),
        ));
    }
    Container::open(namespace, offset)?.volume_with_role(volume::APFS_VOL_ROLE_XART)?;
    Ok(())
}

/// The container's blocks: a [`ReadAt`] source, the byte offset of the
/// partition within it and the container's block size.
///
/// The source must remain stable while the container is open. Reopen it to
/// read a later state of a writable image.
pub struct Device<R> {
    source: R,
    base: u64,
    block_size: u32,
    nodes: btree::NodeCache,
}

impl<R: ReadAt> Device<R> {
    pub(crate) fn new(source: R, base: u64, block_size: u32) -> Self {
        Self {
            source,
            base,
            block_size,
            nodes: btree::NodeCache::default(),
        }
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub(crate) fn set_block_size(&mut self, block_size: u32) {
        self.block_size = block_size;
        self.nodes = btree::NodeCache::default();
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

    /// `container` as the only partition of a synthetic 512-byte-block GPT
    /// disk, starting at block 2048, with unique GUID `unique`.
    pub(crate) fn on_gpt(container: &[u8], unique: gpt::Guid) -> Memory {
        on_typed_gpt(container, unique, PARTITION_TYPE)
    }

    /// [`on_gpt`] with the partition type `type_guid`.
    fn on_typed_gpt(container: &[u8], unique: gpt::Guid, type_guid: &str) -> Memory {
        const BLOCK: u64 = 512;
        const FIRST: u64 = 2048;
        let blocks = FIRST + (container.len() as u64).div_ceil(BLOCK) + FIRST;
        let disk = gpt::Disk {
            block_bytes: BLOCK,
            blocks,
        };
        let table = gpt::Table {
            disk_guid: gpt::Guid::from_entropy([7; 16]),
            partitions: alloc::vec![gpt::Partition {
                type_guid: gpt::Guid::parse(type_guid).unwrap(),
                unique_guid: unique,
                first_lba: FIRST,
                last_lba: FIRST + (container.len() as u64).div_ceil(BLOCK) - 1,
                attributes: 0,
                name: "Container".into(),
            }],
        };
        let mut bytes = alloc::vec![0u8; (blocks * BLOCK) as usize];
        for write in gpt::encode(disk, &table).unwrap() {
            let at = (write.lba * BLOCK) as usize;
            bytes[at..at + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        let at = (FIRST * BLOCK) as usize;
        bytes[at..at + container.len()].copy_from_slice(container);
        Memory(bytes)
    }

    #[test]
    fn containers_are_found_bare_and_in_a_partition_table_with_their_guids() {
        let bare = fixture();
        let unique = gpt::Guid::parse("A1B2C3D4-0000-1111-2222-333344445555").unwrap();
        let mut disk = on_gpt(&bare.0, unique);
        assert_eq!(container_partitions(&mut fixture()).unwrap(), [(0, None)]);
        let found = container_partitions(&mut disk).unwrap();
        assert_eq!(found, [(2048 * 512, Some(unique))]);
        // A borrowed disk opens as the container at that offset.
        let mut container = Container::open(&mut disk, found[0].0).unwrap();
        assert!(!container.volumes().unwrap().is_empty());
    }

    #[test]
    fn recovery_needs_the_system_container_and_its_xart_volume() {
        let unique = gpt::Guid::parse("A1B2C3D4-0000-1111-2222-333344445555").unwrap();
        // A blank namespace and one with only a macOS container lack it.
        let mut blank = Memory(alloc::vec![0; 1 << 20]);
        assert!(matches!(
            require_system_container(&mut blank),
            Err(ApfsError::NotFound(_))
        ));
        let mut macos = on_gpt(&fixture().0, unique);
        assert!(matches!(
            require_system_container(&mut macos),
            Err(ApfsError::NotFound(_))
        ));
        // An ISC container without an xART-role volume is refused too.
        let mut isc = on_typed_gpt(&fixture().0, unique, ISC_PARTITION_TYPE);
        let found = typed_partitions(&mut isc, gpt::Guid::parse(ISC_PARTITION_TYPE).unwrap());
        assert_eq!(found.unwrap(), Some(alloc::vec![(2048 * 512, unique)]));
        let Err(ApfsError::NotFound(what)) = require_system_container(&mut isc) else {
            panic!("an ISC container without xART was accepted");
        };
        assert!(what.contains("0x100"), "{what}");
        // A restore that partitioned the disk but stopped before formatting
        // the container left no system container either.
        let mut unformatted = on_typed_gpt(&[0; 4096], unique, ISC_PARTITION_TYPE);
        let Err(ApfsError::NotFound(what)) = require_system_container(&mut unformatted) else {
            panic!("an unformatted ISC partition was not reported missing");
        };
        assert!(what.contains("APFS container"), "{what}");
    }

    #[test]
    fn uuid_text_is_canonical() {
        let uuid = [
            0x7c, 0x34, 0x57, 0xef, 0, 0, 0x11, 0xaa, 0xaa, 0x11, 0, 0x30, 0x65, 0x43, 0xec, 0xac,
        ];
        assert_eq!(uuid_text(&uuid), PARTITION_TYPE);
    }
}
