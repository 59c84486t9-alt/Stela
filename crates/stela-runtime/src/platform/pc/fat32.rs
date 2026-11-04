//! A read-only FAT32 reader that finds a file's bytes on its partition, for
//! reading the install medium after ExitBootServices, when the firmware's
//! own FAT driver is gone.
//!
//! It follows Microsoft's FAT specification (the "FAT: General Overview of
//! On-Disk Format" boot sector, FAT and directory entry layouts): the volume
//! is FAT32 by its cluster count, never by its label, and paths name 8.3
//! short entries, which every FAT driver writes beside a long name. A file
//! comes back as the device extents of its cluster chain, cut to its size.
//! Nothing is written, and a malformed volume or chain is refused.
use crate::Result;
use alloc::{format, string::String, vec, vec::Vec};
use core::fmt;
use {stela_formats::payload::ReadAt, stela_formats::payload::pieces::Extent};

const BOOT_SIGNATURE: u16 = 0xaa55;
/// The fewest clusters a FAT32 volume has.
const MIN_FAT32_CLUSTERS: u64 = 65_525;
const ENTRY_BYTES: usize = 32;
const FAT_ENTRY_BYTES: u64 = 4;
const CLUSTER_MASK: u32 = 0x0fff_ffff;
/// FAT32 cluster values from here up end a chain.
const END_OF_CHAIN: u32 = 0x0fff_fff8;
const BAD_CLUSTER: u32 = 0x0fff_fff7;
const FIRST_CLUSTER: u32 = 2;
const ATTRIBUTE_VOLUME_ID: u8 = 0x08;
const ATTRIBUTE_DIRECTORY: u8 = 0x10;
const ATTRIBUTE_LONG_NAME: u8 = 0x0f;
const ENTRY_FREE: u8 = 0xe5;
const ENTRY_END: u8 = 0x00;
/// A name byte 0x05 stands for 0xe5.
const ENTRY_KANJI_E5: u8 = 0x05;
/// The most extents a file may take: a heavily fragmented copy is refused
/// rather than held in memory.
pub const MAX_EXTENTS: usize = 1 << 16;
/// FAT bytes read at a time while following a chain.
const FAT_WINDOW: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FatError {
    /// The partition is not a FAT32 volume.
    NotFat32(&'static str),
    /// A path component is not an 8.3 name.
    Name(String),
    Missing(String),
    NotDirectory(String),
    NotFile(String),
    /// A cluster chain is malformed.
    Chain(String, &'static str),
    Fragmented(String),
    Io(String),
}

impl fmt::Display for FatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFat32(why) => write!(f, "not a FAT32 volume: {why}"),
            Self::Name(name) => write!(f, "{name} is not an 8.3 name"),
            Self::Missing(path) => write!(f, "{path} is missing"),
            Self::NotDirectory(path) => write!(f, "{path} is not a directory"),
            Self::NotFile(path) => write!(f, "{path} is not a file"),
            Self::Chain(path, why) => write!(f, "{path}: {why}"),
            Self::Fragmented(path) => {
                write!(
                    f,
                    "{path} takes more than {MAX_EXTENTS} extents; copy it again"
                )
            }
            Self::Io(what) => write!(f, "read failed: {what}"),
        }
    }
}

/// A file found on the volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub bytes: u64,
    /// Where its bytes are on the partition, in order.
    pub extents: Vec<Extent>,
}

pub struct Fat32<R> {
    reader: R,
    cluster_bytes: u64,
    fat_offset: u64,
    data_offset: u64,
    /// Data clusters: 2 to `clusters + 1` are valid.
    clusters: u64,
    root: u32,
    /// The FAT bytes last read and their offset in the FAT.
    window: Vec<u8>,
    window_offset: Option<u64>,
    directory_sector: Vec<u8>,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The 11-byte directory form of an 8.3 name, upper case.
fn short_name(name: &str) -> Option<[u8; 11]> {
    let (base, extension) = name.split_once('.').unwrap_or((name, ""));
    let allowed = |b: u8| b.is_ascii_alphanumeric() || b"$%'-_@~`!(){}^#&".contains(&b);
    if base.is_empty()
        || base.len() > 8
        || extension.len() > 3
        || extension.contains('.')
        || !base.bytes().chain(extension.bytes()).all(allowed)
    {
        return None;
    }
    let mut form = [b' '; 11];
    form[..base.len()].copy_from_slice(base.to_ascii_uppercase().as_bytes());
    form[8..8 + extension.len()].copy_from_slice(extension.to_ascii_uppercase().as_bytes());
    Some(form)
}

impl<R: ReadAt> Fat32<R> {
    /// Read the boot sector and check it describes a FAT32 volume that fits
    /// the partition.
    pub fn open(mut reader: R) -> Result<Self, FatError> {
        let mut sector = [0u8; 512];
        reader
            .read_at(0, &mut sector)
            .map_err(|e| FatError::Io(format!("{e:?}")))?;
        if u16_at(&sector, 510) != BOOT_SIGNATURE {
            return Err(FatError::NotFat32("no boot sector signature"));
        }
        let bytes_per_sector = u64::from(u16_at(&sector, 11));
        let sectors_per_cluster = u64::from(sector[13]);
        let reserved = u64::from(u16_at(&sector, 14));
        let fats = u64::from(sector[16]);
        let root_entries = u16_at(&sector, 17);
        let total16 = u64::from(u16_at(&sector, 19));
        let fat16_size = u16_at(&sector, 22);
        let total32 = u64::from(u32_at(&sector, 32));
        let fat_size = u64::from(u32_at(&sector, 36));
        let root = u32_at(&sector, 44);
        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return Err(FatError::NotFat32("bytes per sector"));
        }
        if !sectors_per_cluster.is_power_of_two() || sectors_per_cluster > 128 {
            return Err(FatError::NotFat32("sectors per cluster"));
        }
        if reserved == 0 || fats == 0 || fat_size == 0 {
            return Err(FatError::NotFat32("reserved sectors or FATs"));
        }
        if root_entries != 0 || fat16_size != 0 {
            return Err(FatError::NotFat32("a FAT12 or FAT16 boot sector"));
        }
        let total = if total16 != 0 { total16 } else { total32 };
        let data_sector = reserved + fats * fat_size;
        if total <= data_sector || total * bytes_per_sector > reader.len() {
            return Err(FatError::NotFat32("sector count outside the partition"));
        }
        let clusters = (total - data_sector) / sectors_per_cluster;
        if clusters < MIN_FAT32_CLUSTERS {
            return Err(FatError::NotFat32("too few clusters for FAT32"));
        }
        if fat_size * bytes_per_sector < (clusters + 2) * FAT_ENTRY_BYTES {
            return Err(FatError::NotFat32("the FAT is smaller than its clusters"));
        }
        let volume = Self {
            reader,
            cluster_bytes: sectors_per_cluster * bytes_per_sector,
            fat_offset: reserved * bytes_per_sector,
            data_offset: data_sector * bytes_per_sector,
            clusters,
            root,
            window: vec![0; FAT_WINDOW],
            window_offset: None,
            directory_sector: vec![0; bytes_per_sector as usize],
        };
        if !volume.valid(root) {
            return Err(FatError::NotFat32("root directory cluster"));
        }
        Ok(volume)
    }

    pub fn cluster_bytes(&self) -> u64 {
        self.cluster_bytes
    }

    pub fn into_inner(self) -> R {
        self.reader
    }

    fn valid(&self, cluster: u32) -> bool {
        (FIRST_CLUSTER..).contains(&cluster)
            && u64::from(cluster) < self.clusters + u64::from(FIRST_CLUSTER)
    }

    fn cluster_offset(&self, cluster: u32) -> u64 {
        self.data_offset + u64::from(cluster - FIRST_CLUSTER) * self.cluster_bytes
    }

    /// The FAT entry of `cluster`.
    fn next(&mut self, cluster: u32) -> Result<u32, FatError> {
        let offset = u64::from(cluster) * FAT_ENTRY_BYTES;
        let base = offset - offset % FAT_WINDOW as u64;
        if self.window_offset != Some(base) {
            self.reader
                .read_at(self.fat_offset + base, &mut self.window)
                .map_err(|e| FatError::Io(format!("{e:?}")))?;
            self.window_offset = Some(base);
        }
        Ok(u32_at(&self.window, (offset - base) as usize) & CLUSTER_MASK)
    }

    /// The extents of the chain from `first` holding `bytes` (`None`: the
    /// whole chain, for a directory).
    fn chain(&mut self, path: &str, first: u32, bytes: Option<u64>) -> Result<File, FatError> {
        let fail = |why| FatError::Chain(String::from(path), why);
        let mut extents: Vec<Extent> = Vec::new();
        let mut held = 0u64;
        if bytes == Some(0) {
            return if first == 0 {
                Ok(File { bytes: 0, extents })
            } else {
                Err(fail("an empty file has clusters"))
            };
        }
        let mut cluster = first;
        let mut steps = 0u64;
        loop {
            if !self.valid(cluster) {
                return Err(fail("the chain names a cluster outside the volume"));
            }
            steps += 1;
            if steps > self.clusters {
                return Err(fail("the chain loops"));
            }
            let offset = self.cluster_offset(cluster);
            match extents.last_mut() {
                Some(last) if last.offset + last.bytes == offset => {
                    last.bytes += self.cluster_bytes
                }
                _ => {
                    if extents.len() == MAX_EXTENTS {
                        return Err(FatError::Fragmented(String::from(path)));
                    }
                    extents.push(Extent {
                        offset,
                        bytes: self.cluster_bytes,
                    });
                }
            }
            held += self.cluster_bytes;
            let next = self.next(cluster)?;
            let full = bytes.is_some_and(|bytes| held >= bytes);
            match next {
                next if next >= END_OF_CHAIN && bytes.is_none_or(|_| full) => break,
                next if next >= END_OF_CHAIN => {
                    return Err(fail("the chain ends before the file"));
                }
                BAD_CLUSTER => return Err(fail("the chain names a bad cluster")),
                _ if full => return Err(fail("the chain runs past the file")),
                next => cluster = next,
            }
        }
        let bytes = bytes.unwrap_or(held);
        // Cut the last cluster to the file's size.
        let mut excess = held - bytes;
        while excess > 0 {
            let last = extents.last_mut().expect("a chain has a cluster");
            let cut = excess.min(last.bytes);
            last.bytes -= cut;
            excess -= cut;
            if last.bytes == 0 {
                extents.pop();
            }
        }
        Ok(File { bytes, extents })
    }

    /// The entry named `name` in the directory whose chain starts at
    /// `cluster`: its attributes, first cluster and size.
    fn find(
        &mut self,
        path: &str,
        cluster: u32,
        name: &[u8; 11],
    ) -> Result<Option<(u8, u32, u32)>, FatError> {
        let directory = self.chain(path, cluster, None)?;
        for extent in &directory.extents {
            for at in (0..extent.bytes).step_by(self.directory_sector.len()) {
                self.reader
                    .read_at(extent.offset + at, &mut self.directory_sector)
                    .map_err(|e| FatError::Io(format!("{e:?}")))?;
                for entry in self.directory_sector.as_chunks::<ENTRY_BYTES>().0 {
                    let attributes = entry[11];
                    match entry[0] {
                        ENTRY_END => return Ok(None),
                        ENTRY_FREE => continue,
                        _ if attributes & ATTRIBUTE_LONG_NAME == ATTRIBUTE_LONG_NAME => continue,
                        _ if attributes & ATTRIBUTE_VOLUME_ID != 0 => continue,
                        _ => {}
                    }
                    let mut stored = [0u8; 11];
                    stored.copy_from_slice(&entry[..11]);
                    if stored[0] == ENTRY_KANJI_E5 {
                        stored[0] = ENTRY_FREE;
                    }
                    if stored.to_ascii_uppercase() == *name {
                        let first =
                            u32::from(u16_at(entry, 20)) << 16 | u32::from(u16_at(entry, 26));
                        return Ok(Some((attributes, first, u32_at(entry, 28))));
                    }
                }
            }
        }
        Ok(None)
    }

    /// The file at `path`, `/`-separated 8.3 names from the root.
    pub fn file(&mut self, path: &str) -> Result<File, FatError> {
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let Some((leaf, directories)) = components.split_last() else {
            return Err(FatError::NotFile(String::from(path)));
        };
        let mut cluster = self.root;
        let mut walked = String::new();
        for component in directories {
            walked.push('/');
            walked.push_str(component);
            let name = short_name(component).ok_or_else(|| FatError::Name(walked.clone()))?;
            match self.find(&walked, cluster, &name)? {
                None => return Err(FatError::Missing(walked)),
                Some((attributes, _, _)) if attributes & ATTRIBUTE_DIRECTORY == 0 => {
                    return Err(FatError::NotDirectory(walked));
                }
                // The root is cluster 0 in a `..` entry only.
                Some((_, first, _)) => cluster = first,
            }
        }
        walked.push('/');
        walked.push_str(leaf);
        let name = short_name(leaf).ok_or_else(|| FatError::Name(walked.clone()))?;
        match self.find(&walked, cluster, &name)? {
            None => Err(FatError::Missing(walked)),
            Some((attributes, _, _)) if attributes & ATTRIBUTE_DIRECTORY != 0 => {
                Err(FatError::NotFile(walked))
            }
            Some((_, first, bytes)) => self.chain(&walked, first, Some(u64::from(bytes))),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use stela_contracts::{Refusal, refuse};

    const SECTOR: u64 = 512;
    /// Sectors per cluster of the test volume.
    const SPC: u64 = 1;
    const RESERVED: u64 = 32;
    const FAT_SECTORS: u64 = 600;
    /// 70,000 clusters: just a FAT32 volume.
    const TOTAL: u64 = RESERVED + 2 * FAT_SECTORS + 70_000 * SPC;

    /// A sparse in-memory partition: only written sectors take memory.
    pub(crate) struct Sparse {
        pub(crate) bytes: u64,
        pub(crate) sectors: BTreeMap<u64, [u8; 512]>,
    }

    impl Sparse {
        pub(crate) fn write(&mut self, offset: u64, data: &[u8]) {
            for (i, byte) in data.iter().enumerate() {
                let at = offset + i as u64;
                self.sectors.entry(at / SECTOR).or_insert([0; 512])[(at % SECTOR) as usize] = *byte;
            }
        }
    }

    impl ReadAt for Sparse {
        type Error = Refusal;
        fn len(&self) -> u64 {
            self.bytes
        }
        fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
            if offset + buffer.len() as u64 > self.bytes {
                return Err(refuse!("past end"));
            }
            for (i, byte) in buffer.iter_mut().enumerate() {
                let at = offset + i as u64;
                *byte = self
                    .sectors
                    .get(&(at / SECTOR))
                    .map_or(0, |s| s[(at % SECTOR) as usize]);
            }
            Ok(())
        }
    }

    /// A FAT32 volume builder: a root directory, and files and directories
    /// placed in clusters the test chooses.
    pub(crate) struct Volume {
        pub(crate) disk: Sparse,
        next: u32,
    }

    fn data(cluster: u32) -> u64 {
        (RESERVED + 2 * FAT_SECTORS + u64::from(cluster - 2) * SPC) * SECTOR
    }

    impl Volume {
        pub(crate) fn new() -> Self {
            let mut boot = [0u8; 512];
            boot[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
            boot[13] = SPC as u8;
            boot[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
            boot[16] = 2;
            boot[32..36].copy_from_slice(&(TOTAL as u32).to_le_bytes());
            boot[36..40].copy_from_slice(&(FAT_SECTORS as u32).to_le_bytes());
            boot[44..48].copy_from_slice(&2u32.to_le_bytes());
            boot[510..512].copy_from_slice(&BOOT_SIGNATURE.to_le_bytes());
            let mut disk = Sparse {
                bytes: TOTAL * SECTOR,
                sectors: BTreeMap::new(),
            };
            disk.write(0, &boot);
            let mut volume = Self { disk, next: 3 };
            volume.link(&[2]);
            volume
        }

        /// Link `clusters` into one chain in both FATs.
        pub(crate) fn link(&mut self, clusters: &[u32]) {
            for (i, cluster) in clusters.iter().enumerate() {
                let value = clusters.get(i + 1).copied().unwrap_or(0x0fff_ffff);
                self.set(*cluster, value);
            }
        }

        /// Set `cluster`'s entry in both FATs.
        pub(crate) fn set(&mut self, cluster: u32, value: u32) {
            for fat in 0..2 {
                let at = (RESERVED + fat * FAT_SECTORS) * SECTOR + u64::from(cluster) * 4;
                self.disk.write(at, &value.to_le_bytes());
            }
        }

        /// Fresh clusters for `bytes`, contiguous.
        pub(crate) fn allocate(&mut self, bytes: u64) -> Vec<u32> {
            let count = bytes.div_ceil(SPC * SECTOR) as u32;
            let first = self.next;
            self.next += count;
            (first..first + count).collect()
        }

        /// Add a directory entry in the directory at `parent`'s first
        /// cluster, at slot `slot`.
        pub(crate) fn entry(
            &mut self,
            parent: u32,
            slot: u64,
            name: &[u8; 11],
            attributes: u8,
            first: u32,
            bytes: u32,
        ) {
            let mut entry = [0u8; 32];
            entry[..11].copy_from_slice(name);
            entry[11] = attributes;
            entry[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
            entry[26..28].copy_from_slice(&(first as u16).to_le_bytes());
            entry[28..32].copy_from_slice(&bytes.to_le_bytes());
            self.disk.write(data(parent) + slot * 32, &entry);
        }

        pub(crate) fn directory(&mut self, parent: u32, slot: u64, name: &[u8; 11]) -> u32 {
            let cluster = self.allocate(1)[0];
            self.link(&[cluster]);
            self.entry(parent, slot, name, ATTRIBUTE_DIRECTORY, cluster, 0);
            cluster
        }

        /// A file of `contents` in `clusters`, linked in that order.
        pub(crate) fn file_in(
            &mut self,
            parent: u32,
            slot: u64,
            name: &[u8; 11],
            contents: &[u8],
            clusters: &[u32],
        ) {
            let size = (SPC * SECTOR) as usize;
            for (chunk, cluster) in contents.chunks(size).zip(clusters) {
                self.disk.write(data(*cluster), chunk);
            }
            if !clusters.is_empty() {
                self.link(clusters);
            }
            let first = clusters.first().copied().unwrap_or(0);
            self.entry(parent, slot, name, 0x20, first, contents.len() as u32);
        }

        pub(crate) fn file(&mut self, parent: u32, slot: u64, name: &[u8; 11], contents: &[u8]) {
            let clusters = self.allocate(contents.len() as u64);
            self.file_in(parent, slot, name, contents, &clusters);
        }
    }

    fn read(volume: &mut Fat32<Sparse>, file: &File) -> Vec<u8> {
        let mut bytes = Vec::new();
        for extent in &file.extents {
            let mut chunk = vec![0; extent.bytes as usize];
            volume.reader.read_at(extent.offset, &mut chunk).unwrap();
            bytes.extend(chunk);
        }
        bytes
    }

    #[test]
    fn files_are_found_by_short_name_and_read_through_their_chains() {
        let mut volume = Volume::new();
        let efi = volume.directory(2, 1, b"EFI        ");
        // A long-name entry before the short one is skipped.
        volume.entry(efi, 0, b"\x41s\0t\0e\0l\0a\0", ATTRIBUTE_LONG_NAME, 0, 0);
        let stela = volume.directory(efi, 1, b"STELA      ");
        let contiguous: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
        volume.file(stela, 0, b"IPSW    000", &contiguous);
        // A fragmented file: clusters out of order.
        let scattered: Vec<u8> = (0..1300u32).map(|i| (i * 3) as u8).collect();
        let clusters = volume.allocate(2048);
        volume.file_in(
            stela,
            1,
            b"IPSW    001",
            &scattered,
            &[clusters[3], clusters[0], clusters[1]],
        );
        volume.file(stela, 2, b"EMPTY      ", &[]);
        volume.entry(2, 0, b"STELA      ", ATTRIBUTE_VOLUME_ID, 0, 0);
        let mut fat = Fat32::open(volume.disk).unwrap();
        assert_eq!(fat.cluster_bytes(), 512);
        let file = fat.file("EFI/stela/ipsw.000").unwrap();
        assert_eq!(file.bytes, 2000);
        assert_eq!(file.extents.len(), 1);
        assert_eq!(read(&mut fat, &file), contiguous);
        let file = fat.file("/efi/STELA/Ipsw.001").unwrap();
        assert_eq!(file.extents.len(), 2);
        assert_eq!(read(&mut fat, &file), scattered);
        assert_eq!(fat.file("EFI/stela/empty").unwrap().bytes, 0);
        for (path, error) in [
            ("EFI/stela/ipsw.002", "/EFI/stela/ipsw.002 is missing"),
            ("EFI/other/ipsw.000", "/EFI/other is missing"),
            (
                "EFI/stela/ipsw.000/x",
                "/EFI/stela/ipsw.000 is not a directory",
            ),
            ("EFI/stela", "/EFI/stela is not a file"),
            (
                "EFI/stela/a.long-name",
                "/EFI/stela/a.long-name is not an 8.3 name",
            ),
        ] {
            assert_eq!(fat.file(path).unwrap_err().to_string(), error, "{path}");
        }
    }

    #[test]
    fn directory_lookup_reads_each_needed_sector_once() {
        struct Recorded {
            disk: Sparse,
            directory_reads: Vec<(u64, usize)>,
        }

        impl ReadAt for Recorded {
            type Error = Refusal;

            fn len(&self) -> u64 {
                self.disk.len()
            }

            fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
                if offset >= data(2) {
                    self.directory_reads.push((offset, buffer.len()));
                }
                self.disk.read_at(offset, buffer)
            }
        }

        let mut volume = Volume::new();
        volume.link(&[2, 7, 9]);
        volume.disk.write(data(2), &[ENTRY_FREE; SECTOR as usize]);
        volume.file(7, 0, b"IPSW    000", b"payload");
        let mut fat = Fat32::open(Recorded {
            disk: volume.disk,
            directory_reads: Vec::new(),
        })
        .unwrap();
        let expected = [(data(2), SECTOR as usize), (data(7), SECTOR as usize)];

        assert_eq!(fat.file("ipsw.000").unwrap().bytes, 7);
        assert_eq!(fat.reader.directory_reads, expected);
        fat.reader.directory_reads.clear();

        assert!(matches!(fat.file("absent"), Err(FatError::Missing(_))));
        assert_eq!(fat.reader.directory_reads, expected);
    }

    #[test]
    fn malformed_chains_and_other_volumes_are_refused() {
        let mut volume = Volume::new();
        let short: Vec<u8> = vec![7; 1500];
        let clusters = volume.allocate(1500);
        // The chain ends after two of its three clusters.
        volume.file_in(2, 0, b"SHORT      ", &short, &clusters[..2]);
        let long = volume.allocate(1500);
        volume.file_in(2, 1, b"LONG       ", &short[..100], &long);
        // A directory whose chain comes back to itself.
        let looped = volume.directory(2, 2, b"LOOP       ");
        volume.set(looped, looped);
        let mut fat = Fat32::open(volume.disk).unwrap();
        let error = fat.file("short").unwrap_err().to_string();
        assert_eq!(error, "/short: the chain ends before the file");
        let error = fat.file("long").unwrap_err().to_string();
        assert_eq!(error, "/long: the chain runs past the file");
        assert!(fat.file("loop/x").is_err());

        let mut volume = Volume::new();
        volume.disk.write(17, &512u16.to_le_bytes());
        assert!(matches!(
            Fat32::open(volume.disk),
            Err(FatError::NotFat32("a FAT12 or FAT16 boot sector"))
        ));
        let mut volume = Volume::new();
        volume.disk.write(510, &[0, 0]);
        assert!(Fat32::open(volume.disk).is_err());
        let mut volume = Volume::new();
        volume.disk.bytes = SECTOR * 1000;
        assert!(Fat32::open(volume.disk).is_err());
    }
}
