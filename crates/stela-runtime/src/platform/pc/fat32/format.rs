//! The FAT32 structures `stela setup` and `cargo xtask boot` write, laid
//! out as Microsoft's FAT specification gives them and as [`super::Fat32`]
//! reads them: its cluster sizes by volume size and its FAT size
//! computation, 32 reserved sectors with the FSInfo sector at 1 and the
//! backup boot sector at 6, two FATs, and the root directory in cluster 2.
//! Callers place the root directory and any files in the clusters.
use alloc::{string::String, vec, vec::Vec};
use core::fmt;

pub const RESERVED_SECTORS: u64 = 32;
pub const FATS: u64 = 2;
pub const ROOT_CLUSTER: u32 = 2;
pub const FSINFO_SECTOR: u64 = 1;
pub const BACKUP_BOOT_SECTOR: u64 = 6;
/// FAT entry 0: the media byte of a fixed disk, the other bits set.
pub const MEDIA_ENTRY: u32 = 0x0fff_fff8;
/// The FAT entry that ends a chain; FAT entry 1 holds it too.
pub const END_OF_CHAIN: u32 = 0x0fff_ffff;
/// The directory entry attribute of the root's volume label.
pub const ATTRIBUTE_VOLUME_ID: u8 = super::ATTRIBUTE_VOLUME_ID;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    SectorSize(u32),
    /// Fewer clusters than FAT32 needs.
    TooFewClusters {
        bytes: u64,
        sector_bytes: u32,
    },
    /// More sectors than a boot sector's 32-bit fields count.
    TooLarge,
    Label(String),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectorSize(bytes) => {
                write!(f, "{bytes}-byte sectors are not a FAT32 sector size")
            }
            Self::TooFewClusters {
                bytes,
                sector_bytes,
            } => write!(
                f,
                "a {bytes}-byte volume of {sector_bytes}-byte sectors has too few clusters for FAT32"
            ),
            Self::TooLarge => f.write_str("the volume is too large for FAT32"),
            Self::Label(label) => write!(
                f,
                "{label:?} is not a FAT volume label: up to 11 letters, digits, spaces, - or _"
            ),
        }
    }
}

impl core::error::Error for FormatError {}

/// A FAT32 volume's size and the specification's layout of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub sector_bytes: u64,
    pub sectors: u64,
    pub cluster_sectors: u64,
    pub fat_sectors: u64,
    /// Data clusters, numbered from 2.
    pub clusters: u64,
}

/// The bytes per cluster the specification's table gives a FAT32 volume
/// this large.
fn cluster_bytes(volume: u64) -> u64 {
    const TABLE: [(u64, u64); 4] = [
        (0x1040_0000, 512),
        (0x2_0000_0000, 4096),
        (0x4_0000_0000, 8192),
        (0x8_0000_0000, 16384),
    ];
    TABLE
        .iter()
        .find(|(most, _)| volume <= *most)
        .map_or(32768, |(_, bytes)| *bytes)
}

impl Geometry {
    /// The layout of `sectors` sectors of `sector_bytes`. A volume too
    /// small for FAT32's cluster count is refused.
    pub fn new(sectors: u64, sector_bytes: u32) -> Result<Self, FormatError> {
        if !matches!(sector_bytes, 512 | 1024 | 2048 | 4096) {
            return Err(FormatError::SectorSize(sector_bytes));
        }
        let sector = u64::from(sector_bytes);
        let too_few = FormatError::TooFewClusters {
            bytes: sectors * sector,
            sector_bytes,
        };
        if u32::try_from(sectors).is_err() {
            return Err(FormatError::TooLarge);
        }
        let cluster_sectors = (cluster_bytes(sectors * sector) / sector).max(1);
        // The specification's FAT size, for four-byte entries: with 512-byte
        // sectors its (256 * SecPerClus + NumFATs) / 2 divisor.
        let divisor = (2 * (sector / 4) * cluster_sectors + FATS) / 2;
        let fat_sectors = sectors
            .checked_sub(RESERVED_SECTORS)
            .ok_or_else(|| too_few.clone())?
            .div_ceil(divisor);
        let clusters = sectors
            .checked_sub(RESERVED_SECTORS + FATS * fat_sectors)
            .ok_or_else(|| too_few.clone())?
            / cluster_sectors;
        if clusters < super::MIN_FAT32_CLUSTERS {
            return Err(too_few);
        }
        // The divisor rounds the FAT up, so at FAT32's cluster counts it
        // maps every cluster.
        debug_assert!(fat_sectors * sector / super::FAT_ENTRY_BYTES >= clusters + 2);
        Ok(Self {
            sector_bytes: sector,
            sectors,
            cluster_sectors,
            fat_sectors,
            clusters,
        })
    }

    pub fn cluster_bytes(&self) -> u64 {
        self.cluster_sectors * self.sector_bytes
    }

    /// The first sector of FAT `copy`.
    pub fn fat_sector(&self, copy: u64) -> u64 {
        RESERVED_SECTORS + copy * self.fat_sectors
    }

    /// The first data sector, cluster 2's.
    pub fn data_sector(&self) -> u64 {
        self.fat_sector(FATS)
    }

    /// The byte offset of `cluster` in the volume.
    pub fn cluster_offset(&self, cluster: u32) -> u64 {
        (self.data_sector() + u64::from(cluster - ROOT_CLUSTER) * self.cluster_sectors)
            * self.sector_bytes
    }

    /// The boot sector, also written at [`BACKUP_BOOT_SECTOR`].
    /// `hidden_sectors` is the partition's first block, 0 for a volume
    /// without a partition table.
    pub fn boot_sector(
        &self,
        hidden_sectors: u64,
        label: &[u8; 11],
        serial: u32,
    ) -> Result<Vec<u8>, FormatError> {
        let field = |value: u64| u32::try_from(value).map_err(|_| FormatError::TooLarge);
        let mut boot = vec![0u8; self.sector_bytes as usize];
        boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"MSWIN4.1");
        boot[11..13].copy_from_slice(&(self.sector_bytes as u16).to_le_bytes());
        boot[13] = self.cluster_sectors as u8;
        boot[14..16].copy_from_slice(&(RESERVED_SECTORS as u16).to_le_bytes());
        boot[16] = FATS as u8;
        // Media: a fixed disk.
        boot[21] = 0xf8;
        boot[24..26].copy_from_slice(&63u16.to_le_bytes());
        boot[26..28].copy_from_slice(&255u16.to_le_bytes());
        boot[28..32].copy_from_slice(&field(hidden_sectors)?.to_le_bytes());
        boot[32..36].copy_from_slice(&field(self.sectors)?.to_le_bytes());
        boot[36..40].copy_from_slice(&field(self.fat_sectors)?.to_le_bytes());
        boot[44..48].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
        boot[48..50].copy_from_slice(&(FSINFO_SECTOR as u16).to_le_bytes());
        boot[50..52].copy_from_slice(&(BACKUP_BOOT_SECTOR as u16).to_le_bytes());
        boot[64] = 0x80;
        boot[66] = 0x29;
        boot[67..71].copy_from_slice(&serial.to_le_bytes());
        boot[71..82].copy_from_slice(label);
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510..512].copy_from_slice(&super::BOOT_SIGNATURE.to_le_bytes());
        Ok(boot)
    }

    /// The FSInfo sector: `free` clusters, and the next to allocate.
    pub fn fsinfo(&self, free: u32, next: u32) -> Vec<u8> {
        let mut info = vec![0u8; self.sector_bytes as usize];
        info[..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
        info[488..492].copy_from_slice(&free.to_le_bytes());
        info[492..496].copy_from_slice(&next.to_le_bytes());
        info[508..512].copy_from_slice(&0xaa55_0000u32.to_le_bytes());
        info
    }
}

/// `label` as a FAT volume label: at most 11 characters a short name may
/// hold, upper case, padded with spaces.
pub fn volume_label(label: &str) -> Result<[u8; 11], FormatError> {
    if label.is_empty()
        || label.len() > 11
        || !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_- ".contains(&b))
    {
        return Err(FormatError::Label(label.into()));
    }
    let mut bytes = [b' '; 11];
    bytes[..label.len()].copy_from_slice(label.to_ascii_uppercase().as_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::{Fat32, tests::Sparse};
    use super::*;
    use alloc::collections::BTreeMap;

    #[test]
    fn cluster_and_fat_sizes_follow_the_specification() {
        // A 64 GB volume: 32 KiB clusters, and a FAT that maps every one.
        let geometry = Geometry::new(64_000_000_000 / 512, 512).unwrap();
        assert_eq!(geometry.cluster_sectors, 64);
        assert!(geometry.fat_sectors * 128 >= geometry.clusters + 2);
        // 520 MiB: 4 KiB clusters.
        assert_eq!(Geometry::new(520 << 11, 512).unwrap().cluster_sectors, 8);
        // 200 MiB of 4 KiB sectors has too few clusters.
        assert_eq!(
            Geometry::new(200 << 8, 4096),
            Err(FormatError::TooFewClusters {
                bytes: 200 << 20,
                sector_bytes: 4096
            })
        );
        assert!(matches!(
            Geometry::new(16, 512),
            Err(FormatError::TooFewClusters { .. })
        ));
        assert_eq!(
            Geometry::new(1 << 20, 520),
            Err(FormatError::SectorSize(520))
        );
        assert!(volume_label("STELA").is_ok());
        assert!(volume_label("TOO LONG NAME").is_err());
        assert!(volume_label("bad/name").is_err());
        assert!(volume_label("").is_err());
    }

    #[test]
    fn an_encoded_volume_reads_back_through_the_reader() {
        let geometry = Geometry::new(300 << 11, 512).unwrap();
        let label = volume_label("Stela").unwrap();
        assert_eq!(&label, b"STELA      ");
        let mut disk = Sparse {
            bytes: geometry.sectors * 512,
            sectors: BTreeMap::new(),
        };
        let boot = geometry.boot_sector(0, &label, 7).unwrap();
        let info = geometry.fsinfo(geometry.clusters as u32 - 1, ROOT_CLUSTER + 1);
        for base in [0, BACKUP_BOOT_SECTOR] {
            disk.write(base * 512, &boot);
            disk.write((base + FSINFO_SECTOR) * 512, &info);
        }
        for copy in 0..FATS {
            let mut fat = Vec::new();
            for entry in [MEDIA_ENTRY, END_OF_CHAIN, END_OF_CHAIN] {
                fat.extend_from_slice(&entry.to_le_bytes());
            }
            disk.write(geometry.fat_sector(copy) * 512, &fat);
        }
        let mut root = [0u8; 32];
        root[..11].copy_from_slice(&label);
        root[11] = ATTRIBUTE_VOLUME_ID;
        disk.write(geometry.cluster_offset(ROOT_CLUSTER), &root);
        let mut volume = Fat32::open(disk).unwrap();
        assert_eq!(volume.cluster_bytes(), geometry.cluster_bytes());
        assert!(volume.file("EFI/BOOT/BOOTX64.EFI").is_err());
    }
}
