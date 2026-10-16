//! The target disk's GUID partition table: read an existing one and plan the
//! partitions Stela adds beside an untouched EFI system partition.
//!
//! The Apple region is the one partition the guest's ANS2 namespace exposes;
//! Apple's restore writes its own nested GPT inside it. Staging, machine
//! state and the translation cache stay outside it, so the host ESP and
//! generated code never mix with Apple bytes.
use super::PayloadError;
use alloc::{string::String, vec, vec::Vec};
use core::fmt;

const SIGNATURE: &[u8; 8] = b"EFI PART";
const REVISION: u32 = 0x0001_0000;
const HEADER_BYTES: u32 = 92;
const ENTRY_BYTES: u32 = 128;
const ENTRY_COUNT: u32 = 128;
/// The entry array always takes 16 KiB, whatever the block size.
const ENTRY_ARRAY_BYTES: u64 = ENTRY_BYTES as u64 * ENTRY_COUNT as u64;
const MIB: u64 = 1024 * 1024;
/// Partitions start and end on 1 MiB boundaries.
pub const ALIGNMENT: u64 = MIB;
/// Left free at the start of a blank disk for an ESP that a later step
/// creates and formats; nothing is written there.
pub const RESERVED_ESP_BYTES: u64 = 512 * MIB;
pub const MACHINE_STATE_BYTES: u64 = 256 * MIB;
pub const DEFAULT_CACHE_BYTES: u64 = 16 * 1024 * MIB;
/// The smallest Apple region a macOS restore can use.
pub const DEFAULT_MIN_APPLE_BYTES: u64 = 64 * 1024 * MIB;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// Parse the canonical text form; the first three groups are stored
    /// little-endian, as on disk.
    pub fn parse(text: &str) -> Option<Self> {
        let groups: Vec<&str> = text.split('-').collect();
        let widths = [8, 4, 4, 4, 12];
        if groups.len() != 5 || groups.iter().zip(widths).any(|(g, w)| g.len() != w) {
            return None;
        }
        let mut raw = [0u8; 16];
        let mut position = 0;
        for group in &groups {
            for pair in group.as_bytes().chunks(2) {
                let text = core::str::from_utf8(pair).ok()?;
                raw[position] = u8::from_str_radix(text, 16).ok()?;
                position += 1;
            }
        }
        raw[0..4].reverse();
        raw[4..6].reverse();
        raw[6..8].reverse();
        Some(Self(raw))
    }

    /// A random-format (version 4) GUID from 16 bytes of identity entropy.
    pub fn from_entropy(mut bytes: [u8; 16]) -> Self {
        bytes[7] = (bytes[7] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(bytes)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 16]
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-",
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6]
        )?;
        for byte in &b[8..10] {
            write!(f, "{byte:02X}")?;
        }
        f.write_str("-")?;
        for byte in &b[10..] {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// What a partition is for, by type GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Esp,
    AppleRegion,
    Staging,
    MachineState,
    Cache,
}

impl Role {
    pub const STELA: [Self; 4] = [
        Self::MachineState,
        Self::Staging,
        Self::Cache,
        Self::AppleRegion,
    ];

    pub fn type_guid(self) -> Guid {
        Guid::parse(match self {
            Self::Esp => "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
            Self::AppleRegion => "09137F55-F9C2-4DE6-B5DE-5A68DF821BDC",
            Self::Staging => "99D6A603-EC02-4167-A0AB-653442B4A265",
            Self::MachineState => "EC61F267-6C83-493C-9BBE-DD26518023BD",
            Self::Cache => "F4F9CDCC-7F4D-4331-A060-8FB3D87B54B8",
        })
        .expect("constant GUID")
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Esp => "EFI System",
            Self::AppleRegion => "Stela Apple region",
            Self::Staging => "Stela staging",
            Self::MachineState => "Stela machine state",
            Self::Cache => "Stela translation cache",
        }
    }

    fn of(type_guid: Guid) -> Option<Self> {
        [Self::Esp]
            .into_iter()
            .chain(Self::STELA)
            .find(|role| role.type_guid() == type_guid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    /// Inclusive, as in the GPT entry.
    pub last_lba: u64,
    pub attributes: u64,
    pub name: String,
}

impl Partition {
    pub fn role(&self) -> Option<Role> {
        Role::of(self.type_guid)
    }

    pub fn blocks(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
}

/// A disk's geometry: logical block size and number of blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disk {
    pub block_bytes: u64,
    pub blocks: u64,
}

impl Disk {
    fn entry_blocks(&self) -> u64 {
        ENTRY_ARRAY_BYTES.div_ceil(self.block_bytes)
    }

    pub fn first_usable(&self) -> u64 {
        2 + self.entry_blocks()
    }

    pub fn last_usable(&self) -> u64 {
        self.blocks - 2 - self.entry_blocks()
    }

    fn validate(&self) -> Result<(), PayloadError> {
        if !matches!(self.block_bytes, 512 | 1024 | 2048 | 4096)
            || self.blocks < 2 * (2 + self.entry_blocks()) + 1
        {
            return Err(PayloadError::Disk("unsupported block size or tiny disk"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub disk_guid: Guid,
    pub partitions: Vec<Partition>,
}

/// The IEEE CRC-32 of GPT headers and entry arrays.
pub fn crc32(bytes: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            table[i] = c;
            i += 1;
        }
        table
    };
    !bytes.iter().fold(!0u32, |c, &b| {
        TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8)
    })
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn guid_at(bytes: &[u8], at: usize) -> Guid {
    Guid(bytes[at..at + 16].try_into().unwrap())
}

/// The location of the entry array a primary header names.
pub struct HeaderInfo {
    pub disk_guid: Guid,
    pub entries_lba: u64,
    pub entry_count: u32,
    pub entry_bytes: u32,
    entries_crc: u32,
}

impl HeaderInfo {
    pub fn entry_array_bytes(&self) -> u64 {
        self.entry_count as u64 * self.entry_bytes as u64
    }
}

/// Parse the header block read from `lba`, the primary (1) or the backup
/// (last). `Ok(None)` means there is no GPT signature; a damaged GPT is an
/// error, never treated as blank.
pub fn parse_header(
    disk: Disk,
    lba: u64,
    block: &[u8],
) -> Result<Option<HeaderInfo>, PayloadError> {
    disk.validate()?;
    if block.len() < HEADER_BYTES as usize || &block[..8] != SIGNATURE {
        return Ok(None);
    }
    let size = u32_at(block, 12);
    if !(HEADER_BYTES..=disk.block_bytes as u32).contains(&size) {
        return Err(PayloadError::Disk("GPT header size"));
    }
    let mut copy = block[..size as usize].to_vec();
    copy[16..20].fill(0);
    if crc32(&copy) != u32_at(block, 16) {
        return Err(PayloadError::Disk("GPT header CRC mismatch"));
    }
    let info = HeaderInfo {
        disk_guid: guid_at(block, 56),
        entries_lba: u64_at(block, 72),
        entry_count: u32_at(block, 80),
        entry_bytes: u32_at(block, 84),
        entries_crc: u32_at(block, 88),
    };
    if u64_at(block, 24) != lba
        || info.entry_bytes < ENTRY_BYTES
        || !info.entry_bytes.is_power_of_two()
        || info.entry_count == 0
        || info.entry_array_bytes() > 1024 * 1024
        || info.entries_lba < 2
    {
        return Err(PayloadError::Disk("unsupported GPT header fields"));
    }
    Ok(Some(info))
}

/// Parse the entry array a header names, checking its CRC.
pub fn parse_entries(info: &HeaderInfo, bytes: &[u8]) -> Result<Table, PayloadError> {
    let length = info.entry_array_bytes() as usize;
    if bytes.len() < length || crc32(&bytes[..length]) != info.entries_crc {
        return Err(PayloadError::Disk("GPT entry array CRC mismatch"));
    }
    let mut partitions = Vec::new();
    for entry in bytes[..length].chunks(info.entry_bytes as usize) {
        let type_guid = guid_at(entry, 0);
        if type_guid.is_zero() {
            continue;
        }
        let units: Vec<u16> = entry[56..128]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let partition = Partition {
            type_guid,
            unique_guid: guid_at(entry, 16),
            first_lba: u64_at(entry, 32),
            last_lba: u64_at(entry, 40),
            attributes: u64_at(entry, 48),
            name: String::from_utf16_lossy(&units),
        };
        if partition.last_lba < partition.first_lba {
            return Err(PayloadError::Disk("GPT entry ends before it starts"));
        }
        partitions.push(partition);
    }
    Ok(Table {
        disk_guid: info.disk_guid,
        partitions,
    })
}

/// Sizes of the partitions Stela adds.
#[derive(Debug, Clone, Copy)]
pub struct Request {
    pub staging_bytes: u64,
    pub machine_state_bytes: u64,
    pub cache_bytes: u64,
    pub min_apple_bytes: u64,
}

/// A planned table, and whether it differs from what is on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub table: Table,
    pub write: bool,
}

impl Plan {
    pub fn partition(&self, role: Role) -> Option<&Partition> {
        self.table
            .partitions
            .iter()
            .find(|partition| partition.role() == Some(role))
    }
}

fn align_up(value: u64, unit: u64) -> u64 {
    value.div_ceil(unit) * unit
}

/// Plan Stela's partitions. An existing table may hold only EFI system
/// partitions and Stela's own; any other partition is refused, so another
/// system's data is never at risk. When all four Stela partitions already
/// exist and staging is large enough, the table is kept as it is. A blank
/// disk (`existing` is `None`) gets a fresh table with a reserved, unwritten
/// gap for a later ESP. `entropy` yields 16 bytes for each new GUID.
pub fn plan(
    disk: Disk,
    existing: Option<&Table>,
    request: Request,
    mut entropy: impl FnMut() -> [u8; 16],
) -> Result<Plan, PayloadError> {
    disk.validate()?;
    let bytes = |blocks: u64| blocks * disk.block_bytes;
    let blocks = |bytes: u64| bytes / disk.block_bytes;
    if let Some(table) = existing {
        if table.partitions.iter().any(|p| p.role().is_none()) {
            return Err(PayloadError::Disk(
                "target disk has a partition that is neither an ESP nor Stela's",
            ));
        }
        let present: Vec<&Partition> = table
            .partitions
            .iter()
            .filter(|p| p.role().is_some_and(|r| r != Role::Esp))
            .collect();
        if !present.is_empty() {
            let complete = Role::STELA.iter().all(|role| {
                table
                    .partitions
                    .iter()
                    .filter(|p| p.role() == Some(*role))
                    .count()
                    == 1
            });
            let staging = table
                .partitions
                .iter()
                .find(|p| p.role() == Some(Role::Staging));
            return match (complete, staging) {
                (true, Some(staging)) if bytes(staging.blocks()) >= request.staging_bytes => {
                    Ok(Plan {
                        table: table.clone(),
                        write: false,
                    })
                }
                (true, Some(_)) => Err(PayloadError::Disk(
                    "existing staging partition is too small for this payload",
                )),
                _ => Err(PayloadError::Disk(
                    "target disk has an incomplete set of Stela partitions",
                )),
            };
        }
    }
    let alignment = blocks(ALIGNMENT).max(1);
    let mut next = match existing {
        Some(table) => table
            .partitions
            .iter()
            .map(|p| p.last_lba + 1)
            .max()
            .unwrap_or(disk.first_usable()),
        None => disk.first_usable() + blocks(RESERVED_ESP_BYTES),
    };
    let end = disk.last_usable() + 1;
    let mut table = match existing {
        Some(table) => table.clone(),
        None => Table {
            disk_guid: Guid::from_entropy(entropy()),
            partitions: Vec::new(),
        },
    };
    let fixed = [
        (Role::MachineState, request.machine_state_bytes),
        (Role::Staging, request.staging_bytes),
        (Role::Cache, request.cache_bytes),
    ];
    for (role, size) in fixed {
        let first = align_up(next, alignment);
        let count = align_up(blocks(align_up(size, disk.block_bytes)), alignment).max(alignment);
        if first + count > end {
            return Err(PayloadError::Disk("target disk is too small"));
        }
        table
            .partitions
            .push(new_partition(role, first, count, &mut entropy));
        next = first + count;
    }
    let first = align_up(next, alignment);
    let last = (end / alignment) * alignment;
    if last <= first || bytes(last - first) < request.min_apple_bytes {
        return Err(PayloadError::Disk(
            "target disk leaves too little space for the Apple region",
        ));
    }
    table.partitions.push(new_partition(
        Role::AppleRegion,
        first,
        last - first,
        &mut entropy,
    ));
    if table.partitions.len() > ENTRY_COUNT as usize {
        return Err(PayloadError::Disk("too many partitions"));
    }
    Ok(Plan { table, write: true })
}

fn new_partition(
    role: Role,
    first: u64,
    count: u64,
    entropy: &mut impl FnMut() -> [u8; 16],
) -> Partition {
    Partition {
        type_guid: role.type_guid(),
        unique_guid: Guid::from_entropy(entropy()),
        first_lba: first,
        last_lba: first + count - 1,
        attributes: 0,
        name: role.name().into(),
    }
}

/// One write of whole blocks at `lba`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write {
    pub lba: u64,
    pub bytes: Vec<u8>,
}

/// Encode a table as the protective MBR, primary header and entries, and
/// the backup entries and header. The backup goes first in the list, then
/// the primary entries and header, then the MBR, so an interrupted write
/// never leaves a valid primary header that names unwritten entries.
pub fn encode(disk: Disk, table: &Table) -> Result<Vec<Write>, PayloadError> {
    disk.validate()?;
    let block = disk.block_bytes as usize;
    let mut entries = vec![0u8; ENTRY_ARRAY_BYTES as usize];
    for (slot, partition) in entries
        .chunks_mut(ENTRY_BYTES as usize)
        .zip(&table.partitions)
    {
        if partition.first_lba < disk.first_usable() || partition.last_lba > disk.last_usable() {
            return Err(PayloadError::Disk("partition outside the usable range"));
        }
        slot[0..16].copy_from_slice(&partition.type_guid.0);
        slot[16..32].copy_from_slice(&partition.unique_guid.0);
        slot[32..40].copy_from_slice(&partition.first_lba.to_le_bytes());
        slot[40..48].copy_from_slice(&partition.last_lba.to_le_bytes());
        slot[48..56].copy_from_slice(&partition.attributes.to_le_bytes());
        for (unit, out) in partition
            .name
            .encode_utf16()
            .take(35)
            .zip(slot[56..].chunks_mut(2))
        {
            out.copy_from_slice(&unit.to_le_bytes());
        }
    }
    let entries_crc = crc32(&entries);
    let entry_blocks = disk.entry_blocks();
    let last = disk.blocks - 1;
    let header = |current: u64, backup: u64, entries_lba: u64| {
        let mut h = vec![0u8; block];
        h[0..8].copy_from_slice(SIGNATURE);
        h[8..12].copy_from_slice(&REVISION.to_le_bytes());
        h[12..16].copy_from_slice(&HEADER_BYTES.to_le_bytes());
        h[24..32].copy_from_slice(&current.to_le_bytes());
        h[32..40].copy_from_slice(&backup.to_le_bytes());
        h[40..48].copy_from_slice(&disk.first_usable().to_le_bytes());
        h[48..56].copy_from_slice(&disk.last_usable().to_le_bytes());
        h[56..72].copy_from_slice(&table.disk_guid.0);
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&ENTRY_COUNT.to_le_bytes());
        h[84..88].copy_from_slice(&ENTRY_BYTES.to_le_bytes());
        h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let crc = crc32(&h[..HEADER_BYTES as usize]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };
    let mut padded = entries;
    padded.resize((entry_blocks * disk.block_bytes) as usize, 0);
    let mut mbr = vec![0u8; block];
    let protective_blocks = (disk.blocks - 1).min(u32::MAX as u64) as u32;
    // One partition of type 0xEE covering the disk, as UEFI specifies.
    mbr[446 + 1..446 + 4].copy_from_slice(&[0x00, 0x02, 0x00]);
    mbr[446 + 4] = 0xee;
    mbr[446 + 5..446 + 8].copy_from_slice(&[0xff, 0xff, 0xff]);
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&protective_blocks.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    Ok(vec![
        Write {
            lba: last - entry_blocks,
            bytes: padded.clone(),
        },
        Write {
            lba: last,
            bytes: header(last, 1, last - entry_blocks),
        },
        Write {
            lba: 2,
            bytes: padded,
        },
        Write {
            lba: 1,
            bytes: header(1, last, 2),
        },
        Write { lba: 0, bytes: mbr },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISK: Disk = Disk {
        block_bytes: 512,
        blocks: 200 * 1024 * 1024 * 1024 / 512,
    };

    fn counter() -> impl FnMut() -> [u8; 16] {
        let mut n = 0u8;
        move || {
            n += 1;
            [n; 16]
        }
    }

    fn request() -> Request {
        Request {
            staging_bytes: 3 * MIB + 5,
            machine_state_bytes: MACHINE_STATE_BYTES,
            cache_bytes: DEFAULT_CACHE_BYTES,
            min_apple_bytes: DEFAULT_MIN_APPLE_BYTES,
        }
    }

    fn read_back(disk: Disk, writes: &[Write]) -> Table {
        let at = |lba: u64| &writes.iter().find(|w| w.lba == lba).unwrap().bytes;
        let info = parse_header(disk, 1, at(1)).unwrap().unwrap();
        parse_entries(&info, at(info.entries_lba)).unwrap()
    }

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn guids_round_trip_in_mixed_endian_form() {
        let text = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
        let guid = Guid::parse(text).unwrap();
        assert_eq!(guid.0[..4], [0x28, 0x73, 0x2a, 0xc1]);
        assert_eq!(alloc::format!("{guid}"), text);
        assert!(Guid::parse("C12A7328F81F11D2BA4B00A0C93EC93B").is_none());
        assert!(Guid::parse("Z12A7328-F81F-11D2-BA4B-00A0C93EC93B").is_none());
        let random = Guid::from_entropy([0xff; 16]);
        assert_eq!(random.0[7] >> 4, 4);
        assert_eq!(random.0[8] >> 6, 2);
    }

    #[test]
    fn a_blank_disk_gets_aligned_stela_partitions_after_a_reserved_esp_gap() {
        let plan = plan(DISK, None, request(), counter()).unwrap();
        assert!(plan.write);
        let roles: Vec<_> = plan.table.partitions.iter().map(|p| p.role()).collect();
        assert_eq!(roles, Role::STELA.map(Some).to_vec());
        let alignment = ALIGNMENT / DISK.block_bytes;
        let first = &plan.table.partitions[0];
        assert!(first.first_lba * DISK.block_bytes >= RESERVED_ESP_BYTES);
        for pair in plan.table.partitions.windows(2) {
            assert!(pair[0].last_lba < pair[1].first_lba);
        }
        for partition in &plan.table.partitions {
            assert_eq!(partition.first_lba % alignment, 0);
            assert_eq!((partition.last_lba + 1) % alignment, 0);
        }
        let staging = plan.partition(Role::Staging).unwrap();
        assert_eq!(staging.blocks() * DISK.block_bytes, 4 * MIB);
        assert!(
            plan.table
                .partitions
                .iter()
                .all(|p| !p.unique_guid.is_zero())
        );
        assert_ne!(plan.table.disk_guid, plan.table.partitions[0].unique_guid);
    }

    #[test]
    fn encoded_tables_parse_back_with_valid_crcs_at_both_block_sizes() {
        for block_bytes in [512, 4096] {
            let disk = Disk {
                block_bytes,
                blocks: DISK.blocks * 512 / block_bytes,
            };
            let plan = plan(disk, None, request(), counter()).unwrap();
            let writes = encode(disk, &plan.table).unwrap();
            assert_eq!(writes.last().unwrap().lba, 0);
            assert_eq!(writes.last().unwrap().bytes[450], 0xee);
            assert_eq!(read_back(disk, &writes), plan.table);
            let backup = &writes[1];
            assert_eq!(backup.lba, disk.blocks - 1);
            let backup = parse_header(disk, disk.blocks - 1, &backup.bytes)
                .unwrap()
                .unwrap();
            assert_eq!(backup.entries_lba, disk.blocks - 1 - 16384 / block_bytes);
        }
    }

    #[test]
    fn an_existing_esp_is_kept_and_foreign_partitions_are_refused() {
        let esp = Partition {
            type_guid: Role::Esp.type_guid(),
            unique_guid: Guid([9; 16]),
            first_lba: 2048,
            last_lba: 2048 + 1024 * 1024 * 2 - 1,
            attributes: 0,
            name: "EFI".into(),
        };
        let table = Table {
            disk_guid: Guid([7; 16]),
            partitions: vec![esp.clone()],
        };
        let planned = plan(DISK, Some(&table), request(), counter()).unwrap();
        assert_eq!(planned.table.disk_guid, table.disk_guid);
        assert_eq!(planned.table.partitions[0], esp);
        assert!(planned.table.partitions[1].first_lba > esp.last_lba);
        // The same layout again is reused without a write.
        let again = plan(DISK, Some(&planned.table), request(), counter()).unwrap();
        assert!(!again.write);
        let bigger = Request {
            staging_bytes: 1024 * MIB,
            ..request()
        };
        assert!(plan(DISK, Some(&planned.table), bigger, counter()).is_err());
        let mut foreign = table.clone();
        foreign.partitions.push(Partition {
            type_guid: Guid([1; 16]),
            ..esp
        });
        assert!(plan(DISK, Some(&foreign), request(), counter()).is_err());
        let mut partial = planned.table.clone();
        partial.partitions.pop();
        assert!(plan(DISK, Some(&partial), request(), counter()).is_err());
    }

    #[test]
    fn small_disks_damaged_headers_and_blank_blocks_are_told_apart() {
        let small = Disk {
            block_bytes: 512,
            blocks: 32 * 1024 * 1024 * 1024 / 512,
        };
        assert!(plan(small, None, request(), counter()).is_err());
        let plan = plan(DISK, None, request(), counter()).unwrap();
        let writes = encode(DISK, &plan.table).unwrap();
        let mut header = writes[3].bytes.clone();
        assert!(parse_header(DISK, 1, &vec![0; 512]).unwrap().is_none());
        header[60] ^= 1;
        assert!(parse_header(DISK, 1, &header).is_err());
        assert!(parse_header(DISK, 2, &writes[3].bytes).is_err());
        let info = parse_header(DISK, 1, &writes[3].bytes).unwrap().unwrap();
        let mut entries = writes[2].bytes.clone();
        entries[40] ^= 1;
        assert!(parse_entries(&info, &entries).is_err());
    }
}
