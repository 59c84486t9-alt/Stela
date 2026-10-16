//! GUID partition tables, and a block device confined to one partition.
use super::block::{BlockDevice, BlockError, Identity};
use alloc::{format, string::String, vec::Vec};
use core::{fmt, str::FromStr};

const SIGNATURE: &[u8; 8] = b"EFI PART";
const HEADER_BYTES: usize = 92;
const ENTRY_BYTES: usize = 128;
const ENTRIES: usize = 128;
/// The largest entry array read, far above the 16 KiB every tool writes.
const MAX_ENTRY_ARRAY: usize = 1 << 20;

/// A GUID in its on-disk byte order (the first three fields little-endian).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// The EFI system partition type.
    pub const ESP: Self = Self([
        0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9,
        0x3b,
    ]);

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 16]
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9]
        )?;
        b[10..].iter().try_for_each(|byte| write!(f, "{byte:02X}"))
    }
}

impl FromStr for Guid {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        const ERROR: &str = "GUID must be XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";
        let fields: Vec<&str> = text.split('-').collect();
        let lengths = [8, 4, 4, 4, 12];
        if fields.len() != 5
            || fields.iter().zip(lengths).any(|(field, length)| {
                field.len() != length || !field.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(ERROR);
        }
        let hex: String = fields.concat();
        let mut big = [0u8; 16];
        for (index, byte) in big.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).map_err(|_| ERROR)?;
        }
        let mut bytes = big;
        bytes[..4].reverse();
        bytes[4..6].reverse();
        bytes[6..8].reverse();
        Ok(Self(bytes))
    }
}

/// The IEEE CRC-32 that GPT headers and entry arrays carry.
pub fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(u32::MAX, |crc, byte| {
        (0..8).fold(crc ^ u32::from(*byte), |crc, _| {
            (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg())
        })
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    pub kind: Guid,
    pub unique: Guid,
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    pub name: String,
}

impl Partition {
    pub fn blocks(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub disk: Guid,
    pub first_usable: u64,
    pub last_usable: u64,
    pub partitions: Vec<Partition>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GptError {
    Device(BlockError),
    NoTable,
    BadHeader(&'static str),
    BadEntries(&'static str),
}

impl From<BlockError> for GptError {
    fn from(error: BlockError) -> Self {
        Self::Device(error)
    }
}

impl fmt::Display for GptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => write!(f, "GPT read failed: {error}"),
            Self::NoTable => f.write_str("no GPT header at LBA 1"),
            Self::BadHeader(why) => write!(f, "invalid GPT header: {why}"),
            Self::BadEntries(why) => write!(f, "invalid GPT entries: {why}"),
        }
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn guid_at(bytes: &[u8], offset: usize) -> Guid {
    Guid(bytes[offset..offset + 16].try_into().unwrap())
}

/// Read and check the primary GPT of `disk`. A damaged primary table is an
/// error, never silently replaced by the backup.
pub fn read(disk: &mut dyn BlockDevice) -> Result<Table, GptError> {
    let identity = disk.identity();
    let block_size = identity.block_size as usize;
    let capacity = identity.blocks;
    if block_size < 512 || capacity < 3 {
        return Err(GptError::NoTable);
    }
    let mut header = vec![0; block_size];
    disk.read(1, &mut header)?;
    if &header[..8] != SIGNATURE {
        return Err(GptError::NoTable);
    }
    let header_bytes = u32_at(&header, 12) as usize;
    if !(HEADER_BYTES..=block_size).contains(&header_bytes) {
        return Err(GptError::BadHeader("header size"));
    }
    let mut checked = header[..header_bytes].to_vec();
    checked[16..20].fill(0);
    if crc32(&checked) != u32_at(&header, 16) {
        return Err(GptError::BadHeader("header CRC"));
    }
    if u64_at(&header, 24) != 1 {
        return Err(GptError::BadHeader("header is not at LBA 1"));
    }
    let first_usable = u64_at(&header, 40);
    let last_usable = u64_at(&header, 48);
    if first_usable > last_usable || last_usable >= capacity {
        return Err(GptError::BadHeader("usable range"));
    }
    let entries_lba = u64_at(&header, 72);
    let count = u32_at(&header, 80) as usize;
    let entry_bytes = u32_at(&header, 84) as usize;
    if entry_bytes < ENTRY_BYTES || !entry_bytes.is_power_of_two() {
        return Err(GptError::BadEntries("entry size"));
    }
    let array = count
        .checked_mul(entry_bytes)
        .filter(|bytes| *bytes <= MAX_ENTRY_ARRAY)
        .ok_or(GptError::BadEntries("entry array size"))?;
    let array_blocks = array.div_ceil(block_size);
    if entries_lba < 2 || entries_lba.saturating_add(array_blocks as u64) > capacity {
        return Err(GptError::BadEntries("entry array location"));
    }
    let mut entries = vec![0; array_blocks * block_size];
    disk.read(entries_lba, &mut entries)?;
    if crc32(&entries[..array]) != u32_at(&header, 88) {
        return Err(GptError::BadEntries("entry array CRC"));
    }
    let mut partitions = Vec::new();
    for entry in entries[..array].chunks_exact(entry_bytes) {
        let kind = guid_at(entry, 0);
        if kind.is_zero() {
            continue;
        }
        let first_lba = u64_at(entry, 32);
        let last_lba = u64_at(entry, 40);
        if first_lba > last_lba || first_lba < first_usable || last_lba > last_usable {
            return Err(GptError::BadEntries("partition outside the usable range"));
        }
        let name: Vec<u16> = entry[56..128]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .take_while(|unit| *unit != 0)
            .collect();
        partitions.push(Partition {
            kind,
            unique: guid_at(entry, 16),
            first_lba,
            last_lba,
            attributes: u64_at(entry, 48),
            name: String::from_utf16_lossy(&name),
        });
    }
    Ok(Table {
        disk: guid_at(&header, 56),
        first_usable,
        last_usable,
        partitions,
    })
}

/// The blocks of a fresh GPT for a `blocks`-long disk: a protective MBR,
/// both headers and both 128-entry arrays, as `(lba, bytes)` writes.
pub fn format(
    blocks: u64,
    block_size: u32,
    disk: Guid,
    partitions: &[Partition],
) -> Result<Vec<(u64, Vec<u8>)>, &'static str> {
    let size = block_size as usize;
    if size < 512 || !size.is_power_of_two() || partitions.len() > ENTRIES {
        return Err("unsupported GPT geometry");
    }
    let array_blocks = (ENTRIES * ENTRY_BYTES).div_ceil(size) as u64;
    let first_usable = 2 + array_blocks;
    let last_usable = blocks
        .checked_sub(2 + array_blocks)
        .filter(|last| *last >= first_usable)
        .ok_or("disk too small for a GPT")?;
    let mut array = vec![0u8; array_blocks as usize * size];
    for (entry, partition) in array
        .as_chunks_mut::<ENTRY_BYTES>()
        .0
        .iter_mut()
        .zip(partitions)
    {
        if partition.first_lba < first_usable
            || partition.last_lba > last_usable
            || partition.first_lba > partition.last_lba
        {
            return Err("partition outside the usable range");
        }
        entry[..16].copy_from_slice(&partition.kind.0);
        entry[16..32].copy_from_slice(&partition.unique.0);
        entry[32..40].copy_from_slice(&partition.first_lba.to_le_bytes());
        entry[40..48].copy_from_slice(&partition.last_lba.to_le_bytes());
        entry[48..56].copy_from_slice(&partition.attributes.to_le_bytes());
        for (unit, pair) in partition
            .name
            .encode_utf16()
            .take(36)
            .zip(entry[56..].as_chunks_mut::<2>().0)
        {
            pair.copy_from_slice(&unit.to_le_bytes());
        }
    }
    let array_crc = crc32(&array[..ENTRIES * ENTRY_BYTES]);
    let header = |mine: u64, other: u64, entries: u64| {
        let mut block = vec![0u8; size];
        block[..8].copy_from_slice(SIGNATURE);
        block[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        block[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        block[24..32].copy_from_slice(&mine.to_le_bytes());
        block[32..40].copy_from_slice(&other.to_le_bytes());
        block[40..48].copy_from_slice(&first_usable.to_le_bytes());
        block[48..56].copy_from_slice(&last_usable.to_le_bytes());
        block[56..72].copy_from_slice(&disk.0);
        block[72..80].copy_from_slice(&entries.to_le_bytes());
        block[80..84].copy_from_slice(&(ENTRIES as u32).to_le_bytes());
        block[84..88].copy_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
        block[88..92].copy_from_slice(&array_crc.to_le_bytes());
        let crc = crc32(&block[..HEADER_BYTES]);
        block[16..20].copy_from_slice(&crc.to_le_bytes());
        block
    };
    let mut mbr = vec![0u8; size];
    mbr[446 + 1..446 + 4].copy_from_slice(&[0x00, 0x02, 0x00]);
    mbr[446 + 4] = 0xee;
    mbr[446 + 5..446 + 8].copy_from_slice(&[0xff, 0xff, 0xff]);
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    let mbr_blocks = u32::try_from(blocks - 1).unwrap_or(u32::MAX);
    mbr[446 + 12..446 + 16].copy_from_slice(&mbr_blocks.to_le_bytes());
    mbr[510..512].copy_from_slice(&[0x55, 0xaa]);
    let last = blocks - 1;
    Ok(vec![
        (0, mbr),
        (1, header(1, last, 2)),
        (2, array.clone()),
        (last - array_blocks, array),
        (last, header(last, 1, last - array_blocks)),
    ])
}

/// A block device that reaches only the blocks of one partition.
pub struct PartitionDevice<D> {
    disk: D,
    first_lba: u64,
    partition: Partition,
    identity: Identity,
}

impl<D: BlockDevice> PartitionDevice<D> {
    pub fn new(disk: D, partition: Partition) -> Self {
        let mut identity = disk.identity().clone();
        identity.location = format!("{} partition {}", identity.location, partition.unique);
        identity.blocks = partition.blocks();
        Self {
            disk,
            first_lba: partition.first_lba,
            partition,
            identity,
        }
    }

    pub fn partition(&self) -> &Partition {
        &self.partition
    }

    /// The whole disk's identity, as the device reported it.
    pub fn disk(&self) -> &Identity {
        self.disk.identity()
    }
}

impl<D: BlockDevice> BlockDevice for PartitionDevice<D> {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        self.disk.read(self.first_lba + lba, buffer)
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        self.disk.write(self.first_lba + lba, data)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.disk.flush()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::block::tests::RamDisk;
    use super::*;

    pub(crate) const DATA: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

    pub(crate) fn partition(kind: Guid, unique: &str, first: u64, last: u64) -> Partition {
        Partition {
            kind,
            unique: unique.parse().unwrap(),
            first_lba: first,
            last_lba: last,
            attributes: 0,
            name: String::from("test"),
        }
    }

    pub(crate) fn formatted(serial: &str, partitions: &[Partition]) -> RamDisk {
        let mut disk = RamDisk::new(serial, 256, 512);
        let disk_guid = "11111111-2222-3333-4444-555555555555".parse().unwrap();
        for (lba, bytes) in format(256, 512, disk_guid, partitions).unwrap() {
            disk.write(lba, &bytes).unwrap();
        }
        disk
    }

    #[test]
    fn guids_round_trip_in_mixed_endian_order() {
        let text = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
        let guid: Guid = text.parse().unwrap();
        assert_eq!(guid, Guid::ESP);
        assert_eq!(format!("{guid}"), text);
        assert!(
            "C12A7328-F81F-11D2-BA4B-00A0C93EC93"
                .parse::<Guid>()
                .is_err()
        );
        assert!(
            "C12A7328F81F-11D2-BA4B-00A0C93EC93B0"
                .parse::<Guid>()
                .is_err()
        );
        assert!(
            "G12A7328-F81F-11D2-BA4B-00A0C93EC93B"
                .parse::<Guid>()
                .is_err()
        );
    }

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn a_formatted_table_reads_back_and_damage_is_reported() {
        let data = DATA.parse().unwrap();
        let partitions = [
            partition(Guid::ESP, "AAAAAAAA-0000-0000-0000-000000000001", 34, 99),
            partition(data, "AAAAAAAA-0000-0000-0000-000000000002", 100, 199),
        ];
        let mut disk = formatted("s", &partitions);
        let table = read(&mut disk).unwrap();
        assert_eq!(table.first_usable, 34);
        assert_eq!(table.last_usable, 222);
        assert_eq!(table.partitions, partitions);
        // The backup header sits at the last block.
        assert_eq!(&disk.bytes[255 * 512..255 * 512 + 8], SIGNATURE);

        let mut damaged = formatted("s", &partitions);
        damaged.bytes[2 * 512 + 40] ^= 1;
        assert_eq!(
            read(&mut damaged),
            Err(GptError::BadEntries("entry array CRC"))
        );
        let mut damaged = formatted("s", &partitions);
        damaged.bytes[512 + 40] ^= 1;
        assert_eq!(read(&mut damaged), Err(GptError::BadHeader("header CRC")));
        assert_eq!(
            read(&mut RamDisk::new("s", 256, 512)),
            Err(GptError::NoTable)
        );
        assert!(format(256, 512, Guid([0; 16]), &[partition(data, DATA, 20, 30)]).is_err());
    }

    #[test]
    fn a_partition_device_never_reaches_outside_its_partition() {
        let data = DATA.parse().unwrap();
        let target = partition(data, "AAAAAAAA-0000-0000-0000-000000000002", 100, 103);
        let disk = formatted("s", core::slice::from_ref(&target));
        let before = disk.bytes.clone();
        let mut view = PartitionDevice::new(disk, target);
        assert_eq!(view.identity().blocks, 4);
        view.write(0, &[0xa5; 2048]).unwrap();
        assert_eq!(
            view.write(3, &[0; 1024]),
            Err(BlockError::OutOfRange {
                lba: 3,
                blocks: 2,
                capacity: 4
            })
        );
        let mut buffer = [0; 512];
        assert!(view.read(4, &mut buffer).is_err());
        view.read(3, &mut buffer).unwrap();
        assert_eq!(buffer, [0xa5; 512]);
        view.flush().unwrap();
        let after = &view.disk.bytes;
        assert_eq!(after[..100 * 512], before[..100 * 512]);
        assert_eq!(after[104 * 512..], before[104 * 512..]);
        assert_eq!(view.disk.flushes, 1);
    }
}
