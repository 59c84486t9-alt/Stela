//! The container: `nx_superblock_t`, its newest valid checkpoint and the
//! container object map (Apple File System Reference, "Container" and
//! "Mounting an Apple File System Partition").
use super::{
    ApfsError, Device, Result,
    btree::Omap,
    object::{self, Header, OBJECT_TYPE_NX_SUPERBLOCK},
    u32_at, u64_at, uuid_at,
    volume::Volume,
};
use crate::payload::ReadAt;
use alloc::vec::Vec;

/// `NX_MAGIC`, the four-character code 'BSXN' as stored on disk.
const NX_MAGIC: &[u8; 4] = b"NXSB";
const NX_MAX_FILE_SYSTEMS: usize = 100;
const NX_FS_OID_OFFSET: usize = 184;
/// Read first: the smallest block size, which holds the superblock.
const MINIMUM_BLOCK_SIZE: u32 = 4096;
const MAXIMUM_BLOCK_SIZE: u32 = 65536;
/// The top bit of `nx_xp_desc_blocks` marks a B-tree descriptor area.
const XP_DESC_NONCONTIGUOUS: u32 = 0x8000_0000;
const NX_INCOMPAT_VERSION1: u64 = 0x0000_0001;
const NX_INCOMPAT_VERSION2: u64 = 0x0000_0002;
const NX_INCOMPAT_FUSION: u64 = 0x0000_0100;

/// The fields of `nx_superblock_t` this reader uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    pub paddr: u64,
    pub xid: u64,
    pub block_size: u32,
    pub block_count: u64,
    pub features: u64,
    pub readonly_compatible_features: u64,
    pub incompatible_features: u64,
    pub uuid: [u8; 16],
    pub omap_oid: u64,
    /// Virtual identifiers of the volume superblocks, unused slots dropped.
    pub volumes: Vec<u64>,
    pub efi_jumpstart: u64,
}

impl Superblock {
    fn parse(block: &[u8], paddr: u64) -> Result<Self> {
        let header = Header::parse(block)?;
        if header.object_type() != OBJECT_TYPE_NX_SUPERBLOCK || &block[32..36] != NX_MAGIC {
            return Err(ApfsError::Malformed("not a container superblock"));
        }
        let max = (u32_at(block, 180)? as usize).min(NX_MAX_FILE_SYSTEMS);
        let volumes = (0..max)
            .map(|index| u64_at(block, NX_FS_OID_OFFSET + index * 8))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|&oid| oid != 0)
            .collect();
        Ok(Self {
            paddr,
            xid: header.xid,
            block_size: u32_at(block, 36)?,
            block_count: u64_at(block, 40)?,
            features: u64_at(block, 48)?,
            readonly_compatible_features: u64_at(block, 56)?,
            incompatible_features: u64_at(block, 64)?,
            uuid: uuid_at(block, 72)?,
            omap_oid: u64_at(block, 160)?,
            volumes,
            efi_jumpstart: u64_at(block, 1272)?,
        })
    }
}

pub struct Container<R> {
    pub device: Device<R>,
    pub superblock: Superblock,
    pub omap: Omap,
}

impl<R: ReadAt> Container<R> {
    /// Whether a container superblock starts `offset` bytes into `source`:
    /// a partition a restore created but has not formatted yet holds none.
    pub fn starts_at(source: R, offset: u64) -> Result<bool> {
        let block = Device::new(source, offset, MINIMUM_BLOCK_SIZE).read_block(0)?;
        Ok(block.get(32..36) == Some(NX_MAGIC))
    }

    /// Open the container that starts `offset` bytes into `source`, from its
    /// newest valid checkpoint.
    pub fn open(source: R, offset: u64) -> Result<Self> {
        let mut device = Device::new(source, offset, MINIMUM_BLOCK_SIZE);
        let block = device.read_block(0)?;
        if block.get(32..36) != Some(NX_MAGIC) {
            return Err(ApfsError::Malformed(
                "no container superblock at block zero",
            ));
        }
        let block_size = u32_at(&block, 36)?;
        if !block_size.is_power_of_two()
            || !(MINIMUM_BLOCK_SIZE..=MAXIMUM_BLOCK_SIZE).contains(&block_size)
        {
            return Err(ApfsError::Malformed("container block size"));
        }
        device.set_block_size(block_size);
        let zero = Superblock::parse(&device.read_object(0)?, 0)?;
        let descriptor_blocks = u32_at(&device.read_block(0)?, 104)?;
        if descriptor_blocks & XP_DESC_NONCONTIGUOUS != 0 {
            return Err(ApfsError::Unsupported(
                "checkpoint descriptor areas stored as B-trees",
            ));
        }
        let descriptor_base = u64_at(&device.read_block(0)?, 112)?;
        // The newest superblock in the descriptor area that is well formed.
        let mut newest = zero;
        for index in 0..u64::from(descriptor_blocks) {
            let paddr = descriptor_base + index;
            let block = device.read_block(paddr)?;
            if !object::checksum_valid(&block) {
                continue;
            }
            let Ok(candidate) = Superblock::parse(&block, paddr) else {
                continue;
            };
            if candidate.xid > newest.xid {
                newest = candidate;
            }
        }
        let known = NX_INCOMPAT_VERSION1 | NX_INCOMPAT_VERSION2 | NX_INCOMPAT_FUSION;
        if newest.incompatible_features & NX_INCOMPAT_FUSION != 0 {
            return Err(ApfsError::Unsupported("Fusion containers"));
        }
        if newest.incompatible_features & !known != 0 {
            return Err(ApfsError::Unsupported(
                "an unknown incompatible container feature",
            ));
        }
        if newest.block_size != block_size {
            return Err(ApfsError::Malformed(
                "checkpoint block size differs from block zero",
            ));
        }
        let omap = Omap::open(&mut device, newest.omap_oid)?;
        Ok(Self {
            device,
            superblock: newest,
            omap,
        })
    }

    /// Every volume of the container, in `nx_fs_oid` order.
    pub fn volumes(&mut self) -> Result<Vec<Volume>> {
        let oids = self.superblock.volumes.clone();
        oids.into_iter().map(|oid| self.volume(oid)).collect()
    }

    /// The volume whose superblock has virtual identifier `oid`.
    pub fn volume(&mut self, oid: u64) -> Result<Volume> {
        let mapping = self
            .omap
            .lookup(&mut self.device, oid, self.superblock.xid)?;
        Volume::open(&mut self.device, mapping.paddr)
    }

    /// The first volume with this role (`APFS_VOL_ROLE_*`).
    pub fn volume_with_role(&mut self, role: u16) -> Result<Volume> {
        self.volumes()?
            .into_iter()
            .find(|volume| volume.role == role)
            .ok_or_else(|| ApfsError::NotFound(alloc::format!("a volume with role {role:#x}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs::tests::fixture;

    #[test]
    fn opens_the_fixture_from_its_newest_checkpoint() -> Result<()> {
        let mut container = Container::open(fixture(), 0)?;
        assert_eq!(container.superblock.block_size, 4096);
        assert_eq!(container.superblock.volumes.len(), 1);
        assert!(container.superblock.xid > 1);
        let volumes = container.volumes()?;
        assert_eq!(volumes[0].name, "Stela");
        Ok(())
    }

    #[test]
    fn refuses_sources_without_a_container() {
        let mut image = fixture();
        image.0[32] = b'X';
        assert!(matches!(
            Container::open(image, 0),
            Err(ApfsError::Malformed(_))
        ));
    }
}
