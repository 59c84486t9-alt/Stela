//! The bytes that erase a whole disk into the USB layout setup expects, as
//! macOS's `diskutil eraseDisk FAT32 NAME GPT` lays it out: a GPT with a
//! 200 MiB EFI system partition and a FAT32 volume named NAME on the rest,
//! both formatted. Hosts without such a tool write these bytes to the raw
//! disk; Windows's own formatter refuses FAT32 volumes over 32 GB.
//!
//! The FAT32 volumes follow Microsoft's FAT specification ("FAT: General
//! Overview of On-Disk Format"): its cluster sizes by volume size, its FAT
//! size computation, 32 reserved sectors with the FSInfo sector at 1 and
//! the backup boot sector at 6, two FATs, and the root directory in cluster
//! 2, holding only the volume label.
use anyhow::{Result, bail, ensure};
use stela_runtime::pc::gpt::{self, Guid, Partition};

/// The EFI system partition diskutil makes.
pub(super) const ESP_BYTES: u64 = 200 << 20;
/// Partitions start on 1 MiB boundaries.
const ALIGNMENT: u64 = 1 << 20;
/// The Microsoft basic data partition type of a FAT volume.
const BASIC_DATA: &str = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
/// The fewest clusters a FAT32 volume has.
const MIN_CLUSTERS: u64 = 65_525;
const RESERVED_SECTORS: u64 = 32;
const FATS: u64 = 2;
const ROOT_CLUSTER: u32 = 2;
const FSINFO_SECTOR: u64 = 1;
const BACKUP_BOOT_SECTOR: u64 = 6;

/// One write of the layout: bytes, or zeros, at a byte offset of the disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Write {
    Bytes(u64, Vec<u8>),
    Zeros(u64, u64),
}

/// The writes that lay the disk out, in the order they go to it.
#[derive(Debug)]
pub(crate) struct Layout {
    pub(crate) writes: Vec<Write>,
}

/// Erase a `bytes`-long disk of `block_size`-byte logical blocks into an EFI
/// partition and a FAT32 volume labeled `name`. `random` supplies the disk
/// and partition GUIDs and the volume serial numbers.
pub(crate) fn layout(
    bytes: u64,
    block_size: u32,
    name: &str,
    random: &mut dyn FnMut(&mut [u8]) -> Result<()>,
) -> Result<Layout> {
    ensure!(
        matches!(block_size, 512 | 4096),
        "{block_size}-byte blocks are not a disk setup can erase"
    );
    let block = u64::from(block_size);
    let blocks = bytes / block;
    let align = ALIGNMENT / block;
    let esp_first = align;
    let esp_last = esp_first + ESP_BYTES / block - 1;
    let data_first = (esp_last + 1).next_multiple_of(align);
    // The backup GPT takes the last 33 blocks (512-byte) or 5 (4096-byte).
    let reserved_end = 1 + (128 * 128u64).div_ceil(block);
    let Some(data_last) = blocks
        .checked_sub(reserved_end + 1)
        .filter(|last| *last > data_first)
    else {
        bail!(
            "the disk holds {:.1} GB, too little for setup's layout",
            bytes as f64 / 1e9
        )
    };
    let mut guid = || -> Result<Guid> {
        let mut bytes = [0u8; 16];
        random(&mut bytes)?;
        // A random (version 4, RFC 4122 variant) GUID, in its on-disk order.
        bytes[7] = bytes[7] & 0x0f | 0x40;
        bytes[8] = bytes[8] & 0x3f | 0x80;
        Ok(Guid(bytes))
    };
    let esp = Partition {
        kind: Guid::ESP,
        unique: guid()?,
        first_lba: esp_first,
        last_lba: esp_last,
        attributes: 0,
        name: "EFI System Partition".into(),
    };
    let data = Partition {
        kind: BASIC_DATA.parse().expect("a valid GUID"),
        unique: guid()?,
        first_lba: data_first,
        last_lba: data_last,
        attributes: 0,
        name: name.into(),
    };
    let table = gpt::format(blocks, block_size, guid()?, &[esp.clone(), data.clone()])
        .map_err(|error| anyhow::anyhow!("cannot lay out the GPT: {error}"))?;
    // The gaps outside the partitions first, so no signature of the disk's
    // old contents (an ISO 9660 image's, say) is left for a host to find.
    let mut writes = vec![
        Write::Zeros(0, esp_first * block),
        Write::Zeros((data_last + 1) * block, (blocks - data_last - 1) * block),
    ];
    writes.extend(
        table
            .into_iter()
            .map(|(lba, bytes)| Write::Bytes(lba * block, bytes)),
    );
    let mut serial = || -> Result<u32> {
        let mut bytes = [0u8; 4];
        random(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    };
    writes.extend(fat32(&esp, block_size, "EFI", serial()?)?);
    writes.extend(fat32(&data, block_size, name, serial()?)?);
    Ok(Layout { writes })
}

/// The bytes per cluster Microsoft's table gives a FAT32 volume this large.
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

/// The writes that format `partition` as an empty FAT32 volume.
fn fat32(partition: &Partition, block_size: u32, label: &str, serial: u32) -> Result<Vec<Write>> {
    let sector = u64::from(block_size);
    let sectors = partition.blocks();
    let per_cluster = (cluster_bytes(sectors * sector) / sector).max(1);
    // The specification's FAT size, for four-byte entries: with 512-byte
    // sectors its (256 * SecPerClus + NumFATs) / 2 divisor.
    let entries = sector / 4;
    let divisor = (2 * entries * per_cluster + FATS) / 2;
    let fat_sectors = (sectors - RESERVED_SECTORS).div_ceil(divisor);
    let data_start = RESERVED_SECTORS + FATS * fat_sectors;
    let clusters = (sectors - data_start) / per_cluster;
    ensure!(
        clusters >= MIN_CLUSTERS,
        "a {}-byte volume of {block_size}-byte sectors has too few clusters for FAT32",
        sectors * sector
    );
    ensure!(
        fat_sectors * sector / 4 >= clusters + 2,
        "the FAT cannot map every cluster"
    );
    let label = volume_label(label)?;
    let base = partition.first_lba * sector;
    let sector_bytes = usize::try_from(sector)?;

    let mut boot = vec![0u8; sector_bytes];
    boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"MSWIN4.1");
    boot[11..13].copy_from_slice(&u16::try_from(sector)?.to_le_bytes());
    boot[13] = u8::try_from(per_cluster)?;
    boot[14..16].copy_from_slice(&(RESERVED_SECTORS as u16).to_le_bytes());
    boot[16] = FATS as u8;
    // Media: a fixed disk.
    boot[21] = 0xf8;
    boot[24..26].copy_from_slice(&63u16.to_le_bytes());
    boot[26..28].copy_from_slice(&255u16.to_le_bytes());
    boot[28..32].copy_from_slice(&u32::try_from(partition.first_lba)?.to_le_bytes());
    boot[32..36].copy_from_slice(&u32::try_from(sectors)?.to_le_bytes());
    boot[36..40].copy_from_slice(&u32::try_from(fat_sectors)?.to_le_bytes());
    boot[44..48].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
    boot[48..50].copy_from_slice(&(FSINFO_SECTOR as u16).to_le_bytes());
    boot[50..52].copy_from_slice(&(BACKUP_BOOT_SECTOR as u16).to_le_bytes());
    boot[64] = 0x80;
    boot[66] = 0x29;
    boot[67..71].copy_from_slice(&serial.to_le_bytes());
    boot[71..82].copy_from_slice(&label);
    boot[82..90].copy_from_slice(b"FAT32   ");
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);

    let mut fsinfo = vec![0u8; sector_bytes];
    fsinfo[..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    fsinfo[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    // Every cluster but the root directory's is free; the next is 3.
    fsinfo[488..492].copy_from_slice(&u32::try_from(clusters - 1)?.to_le_bytes());
    fsinfo[492..496].copy_from_slice(&(ROOT_CLUSTER + 1).to_le_bytes());
    fsinfo[508..512].copy_from_slice(&0xaa55_0000u32.to_le_bytes());

    // FAT entries 0 and 1 (the media byte and end of chain), and the root
    // directory's one-cluster chain.
    let mut fat = vec![0u8; sector_bytes];
    fat[..4].copy_from_slice(&0x0fff_fff8u32.to_le_bytes());
    fat[4..8].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
    fat[8..12].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());

    let mut root = vec![0u8; usize::try_from(per_cluster * sector)?];
    root[..11].copy_from_slice(&label);
    // The volume label attribute.
    root[11] = 0x08;

    let at = |sector_index: u64| base + sector_index * sector;
    let mut writes = vec![
        Write::Zeros(base, data_start * sector),
        Write::Bytes(at(0), boot.clone()),
        Write::Bytes(at(FSINFO_SECTOR), fsinfo.clone()),
        Write::Bytes(at(BACKUP_BOOT_SECTOR), boot),
        Write::Bytes(at(BACKUP_BOOT_SECTOR + FSINFO_SECTOR), fsinfo),
    ];
    for copy in 0..FATS {
        writes.push(Write::Bytes(
            at(RESERVED_SECTORS + copy * fat_sectors),
            fat.clone(),
        ));
    }
    writes.push(Write::Bytes(at(data_start), root));
    Ok(writes)
}

/// `label` as a FAT volume label: at most 11 characters a short name may
/// hold, upper case, padded with spaces.
fn volume_label(label: &str) -> Result<[u8; 11]> {
    ensure!(
        !label.is_empty()
            && label.len() <= 11
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_- ".contains(&b)),
        "{label:?} is not a FAT volume label: up to 11 letters, digits, spaces, - or _"
    );
    let mut bytes = [b' '; 11];
    bytes[..label.len()].copy_from_slice(label.to_ascii_uppercase().as_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::block::RamDisk;
    use stela_runtime::{payload::ReadAt, pc::fat32::Fat32};

    /// A disk holding the layout's writes over bytes that are not zero.
    fn image(bytes: u64, block_size: u32, layout: &Layout) -> RamDisk {
        let mut disk = RamDisk::new("USB", bytes / u64::from(block_size), block_size);
        disk.bytes.fill(0xa5);
        for write in &layout.writes {
            match write {
                Write::Bytes(at, data) => {
                    let at = *at as usize;
                    disk.bytes[at..at + data.len()].copy_from_slice(data);
                }
                Write::Zeros(at, length) => {
                    disk.bytes[*at as usize..(*at + *length) as usize].fill(0);
                }
            }
        }
        disk
    }

    /// One partition's bytes, as the FAT reader reads them.
    struct Volume<'a>(&'a [u8]);

    impl ReadAt for Volume<'_> {
        type Error = &'static str;
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
            let at = usize::try_from(offset).map_err(|_| "offset")?;
            let bytes = self.0.get(at..at + buffer.len()).ok_or("past the end")?;
            buffer.copy_from_slice(bytes);
            Ok(())
        }
    }

    fn counter() -> impl FnMut(&mut [u8]) -> Result<()> {
        let mut next = 0u8;
        move |bytes: &mut [u8]| {
            for byte in bytes {
                next = next.wrapping_add(37);
                *byte = next;
            }
            Ok(())
        }
    }

    #[test]
    fn an_erased_disk_has_an_esp_and_a_named_fat32_volume_that_stela_efi_reads() {
        let bytes = 2u64 << 30;
        let layout = layout(bytes, 512, "STELA", &mut counter()).unwrap();
        let mut disk = image(bytes, 512, &layout);
        let table = gpt::read(&mut disk).unwrap();
        let [esp, data] = &table.partitions[..] else {
            panic!("{:?}", table.partitions)
        };
        assert_eq!(esp.kind, Guid::ESP);
        assert_eq!(data.kind, BASIC_DATA.parse().unwrap());
        assert_eq!(data.name, "STELA");
        assert_eq!(esp.first_lba * 512, ALIGNMENT);
        assert_eq!(esp.blocks() * 512, ESP_BYTES);
        assert_eq!(data.first_lba * 512 % ALIGNMENT, 0);
        // The backup GPT ends the disk.
        assert!((data.last_lba + 1) * 512 <= bytes - 33 * 512);
        assert_ne!(esp.unique, data.unique);
        // The gap before the ESP is zeroed but for the GPT.
        assert!(
            disk.bytes[34 * 512..ALIGNMENT as usize]
                .iter()
                .all(|b| *b == 0)
        );
        for (partition, label) in [(esp, b"EFI        "), (data, b"STELA      ")] {
            let first = (partition.first_lba * 512) as usize;
            let end = ((partition.last_lba + 1) * 512) as usize;
            let volume = &disk.bytes[first..end];
            assert_eq!(&volume[71..82], label);
            assert_eq!(&volume[82..90], b"FAT32   ");
            // The backup boot sector, and an empty root directory.
            assert_eq!(volume[..512], volume[6 * 512..7 * 512]);
            let mut fat = Fat32::open(Volume(volume)).unwrap();
            assert!(fat.file("EFI/BOOT/BOOTX64.EFI").is_err());
        }
    }

    #[test]
    fn four_kib_sector_esps_are_refused_rather_than_misformatted() {
        // 200 MiB of 4 KiB sectors has too few clusters for FAT32.
        let error = layout(2 << 30, 4096, "STELA", &mut counter()).unwrap_err();
        assert!(error.to_string().contains("too few clusters"), "{error}");
    }

    #[test]
    fn cluster_sizes_and_fat_sizes_follow_the_specification() {
        // A 64 GB stick: 32 KiB clusters, and a FAT that maps every one.
        let partition = Partition {
            kind: Guid::ESP,
            unique: Guid([1; 16]),
            first_lba: 2048,
            last_lba: 2048 + (64_000_000_000 / 512) - 1,
            attributes: 0,
            name: String::new(),
        };
        let writes = fat32(&partition, 512, "STELA", 7).unwrap();
        let Write::Bytes(_, boot) = &writes[1] else {
            panic!("no boot sector")
        };
        assert_eq!(boot[13], 64);
        let fat_sectors = u32::from_le_bytes(boot[36..40].try_into().unwrap());
        let total = u32::from_le_bytes(boot[32..36].try_into().unwrap());
        let clusters = (total - 32 - 2 * fat_sectors) / 64;
        assert!(fat_sectors * 128 >= clusters + 2);
        assert!(volume_label("STELA").is_ok());
        assert!(volume_label("TOO LONG NAME").is_err());
        assert!(volume_label("bad/name").is_err());
    }
}
