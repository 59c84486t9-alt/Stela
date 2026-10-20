//! Namespace records from `/arm-io/ans` `namespaces`: three little-endian
//! u32s, namespace ID, Apple type and logical block count (0 uses the
//! remaining medium). `AppleEmbeddedNVMeController::SetNamespacesStruct`
//! (26A434 file 0x3db1a64) checks a multiple of 12 and prefixes the record
//! count. `CreateNamespaces` (0x3db5718) sends those records with admin 0xc6;
//! `DetermineNamespaces` (0x3db50c0) reads Identify byte 0x180 as the type and
//! byte 8 as the capacity. `CheckNameSpaceSizeMismatch` (0x3dc1038) exempts
//! namespace 1 and checks the others against those block counts.
//!
//! Stela's medium layout is an explicit choice, not a recovered Apple NAND
//! layout: fixed namespaces follow the growable namespace, all in DT order,
//! in one selected host partition. Logical blocks are 4 KiB (one LBA format,
//! no metadata); host blocks may be 512 B or 4 KiB. No auxiliary namespace is
//! volatile and no namespace can address bytes outside that partition.
//!
//! Re-creating a namespace erases it, as a controller dropping its FTL
//! mappings does: [`Medium::erase`] marks its extent in [`Erased`], reads
//! of a marked block return zeros, a guest write unmarks what it covers, and
//! [`Medium::zero_erased`] writes zeros to the host for the rest, unmarking
//! a run only after the host flushed it. docs/research/ans2.md owns the
//! design (`Formatting the medium`).
use alloc::{collections::BTreeMap, vec, vec::Vec};
use stela_drivers::block::{BlockDevice, BlockError};

pub const BLOCK_BYTES: u32 = 4096;
const RECORD_BYTES: usize = 12;
/// Logical blocks per host zeroing write: 1 MiB, the largest transfer the
/// guest's own commands already make through the backing (MDTS).
const ZERO_BLOCKS: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Description {
    pub id: u32,
    pub kind: u32,
    pub blocks: u32,
}

impl Description {
    pub fn decode(property: &[u8]) -> Result<Vec<Self>, &'static str> {
        if property.is_empty() || !property.len().is_multiple_of(RECORD_BYTES) {
            return Err("ANS namespaces must be nonempty 12-byte records");
        }
        let mut records = Vec::new();
        for record in property.as_chunks::<RECORD_BYTES>().0 {
            let word = |offset| u32::from_le_bytes(record[offset..offset + 4].try_into().unwrap());
            let entry = Self {
                id: word(0),
                kind: word(4),
                blocks: word(8),
            };
            if entry.id as usize != records.len() + 1 || entry.kind >= 16 {
                return Err("ANS namespaces require consecutive IDs and a four-bit type");
            }
            records.push(entry);
        }
        if records.len() > 255 {
            return Err("ANS has more than 255 namespaces");
        }
        Ok(records)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Namespace {
    pub description: Description,
    pub first: u64,
    pub blocks: u64,
}

/// Medium blocks erased by a namespace re-creation whose host bytes are
/// still stale: disjoint, non-adjacent `[start, end)` runs keyed by start,
/// in 4 KiB medium (not namespace) blocks.
#[derive(Debug, Default)]
struct Erased {
    runs: BTreeMap<u64, u64>,
    blocks: u64,
}

impl Erased {
    fn insert(&mut self, mut start: u64, mut end: u64) {
        if start >= end {
            return;
        }
        if let Some((&s, &e)) = self.runs.range(..=start).next_back()
            && e >= start
        {
            start = s;
            end = end.max(e);
            self.take(s);
        }
        while let Some((&s, &e)) = self.runs.range(start..=end).next() {
            end = end.max(e);
            self.take(s);
        }
        self.runs.insert(start, end);
        self.blocks += end - start;
    }

    fn take(&mut self, start: u64) -> u64 {
        let end = self.runs.remove(&start).expect("an erased run");
        self.blocks -= end - start;
        end
    }

    /// The runs meeting `[start, end)`, clipped to it, highest first.
    fn overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.runs
            .range(..end)
            .rev()
            .take_while(move |(_, e)| **e > start)
            .map(move |(&s, &e)| (s.max(start), e.min(end)))
    }

    fn remove(&mut self, start: u64, end: u64) {
        let hit: Vec<_> = self
            .runs
            .range(..end)
            .rev()
            .take_while(|(_, e)| **e > start)
            .map(|(&s, _)| s)
            .collect();
        for s in hit {
            let e = self.take(s);
            for (a, b) in [(s, start), (end, e)] {
                if a < b {
                    self.runs.insert(a, b);
                    self.blocks += b - a;
                }
            }
        }
    }

    /// Whether one run holds all of `[start, end)`.
    fn covers(&self, start: u64, end: u64) -> bool {
        self.runs
            .range(..=start)
            .next_back()
            .is_some_and(|(_, &e)| e >= end)
    }
}

pub(super) struct Medium {
    pub device: alloc::boxed::Box<dyn BlockDevice>,
    pub namespaces: Vec<Namespace>,
    host_blocks_per_lba: u64,
    erased: Erased,
}

impl Medium {
    pub fn new(
        device: alloc::boxed::Box<dyn BlockDevice>,
        descriptions: &[Description],
    ) -> Result<Self, &'static str> {
        let id = device.identity();
        if !matches!(id.block_size, 512 | BLOCK_BYTES) {
            return Err("ANS backing block size must be 512 or 4096 bytes");
        }
        if descriptions.is_empty() || descriptions.len() > 255 {
            return Err("ANS requires one to 255 namespaces");
        }
        let ratio = u64::from(BLOCK_BYTES / id.block_size);
        if !id.blocks.is_multiple_of(ratio) {
            return Err("ANS partition capacity must be a multiple of 4096 bytes");
        }
        let total = id.blocks / ratio;
        let mut fixed = 0u64;
        let mut grow = 0;
        for (i, description) in descriptions.iter().enumerate() {
            if description.id as usize != i + 1 || description.kind >= 16 {
                return Err("ANS namespace IDs/types are invalid");
            }
            if description.blocks == 0 {
                grow += 1;
            }
            fixed = fixed
                .checked_add(u64::from(description.blocks))
                .ok_or("ANS namespace size overflow")?;
        }
        if grow > 1
            || fixed > total
            || (grow == 1 && fixed == total)
            || (grow == 0 && fixed != total)
        {
            return Err("ANS namespace sizes do not fit the selected partition");
        }
        let mut first = 0;
        let namespaces = descriptions
            .iter()
            .map(|&description| {
                let blocks = if description.blocks == 0 {
                    total - fixed
                } else {
                    u64::from(description.blocks)
                };
                let namespace = Namespace {
                    description,
                    first,
                    blocks,
                };
                first += blocks;
                namespace
            })
            .collect();
        Ok(Self {
            device,
            namespaces,
            host_blocks_per_lba: ratio,
            erased: Erased::default(),
        })
    }

    pub fn namespace(&self, id: u32) -> Option<Namespace> {
        id.checked_sub(1)
            .and_then(|i| self.namespaces.get(i as usize))
            .copied()
    }

    pub fn address(&self, id: u32, lba: u64, blocks: u64) -> Option<u64> {
        let namespace = self.namespace(id)?;
        (lba.checked_add(blocks)? <= namespace.blocks)
            .then(|| (namespace.first + lba) * self.host_blocks_per_lba)
    }

    /// Read `buffer` from namespace `id` at `lba`: erased blocks read as
    /// zeros, without touching their stale host bytes.
    pub fn read(&mut self, id: u32, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let blocks = buffer.len() as u64 / u64::from(BLOCK_BYTES);
        let address = self
            .address(id, lba, blocks)
            .ok_or(BlockError::Unsupported("ANS namespace range"))?;
        let start = address / self.host_blocks_per_lba;
        let end = start + blocks;
        if self.erased.covers(start, end) {
            buffer.fill(0);
            return Ok(());
        }
        self.device.read(address, buffer)?;
        for (s, e) in self.erased.overlapping(start, end) {
            let at = |block: u64| ((block - start) * u64::from(BLOCK_BYTES)) as usize;
            buffer[at(s)..at(e)].fill(0);
        }
        Ok(())
    }

    /// Write `data` to namespace `id` at `lba`. The written blocks hold
    /// guest data from now on, so they leave the erased runs; a failed write
    /// leaves them erased, its effect on the medium indeterminate.
    pub fn write(&mut self, id: u32, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        let blocks = data.len() as u64 / u64::from(BLOCK_BYTES);
        let address = self
            .address(id, lba, blocks)
            .ok_or(BlockError::Unsupported("ANS namespace range"))?;
        self.device.write(address, data)?;
        let start = address / self.host_blocks_per_lba;
        self.erased.remove(start, start + blocks);
        Ok(())
    }

    /// Erase every block of namespace `id`, as re-creating it does. The
    /// effect is immediate for reads; [`Self::zero_erased`] makes it durable.
    pub fn erase(&mut self, id: u32) -> Option<()> {
        let namespace = self.namespace(id)?;
        self.erased
            .insert(namespace.first, namespace.first + namespace.blocks);
        Some(())
    }

    /// Deallocate `blocks` blocks of namespace `id` from `lba`, as Dataset
    /// Management with the Deallocate attribute does: like a namespace
    /// erase, but for one range. The blocks read as zeros at once (the
    /// controller reports DLFEAT 001b) and [`Self::zero_erased`] makes that
    /// durable. `None` when the range leaves the namespace; nothing changes.
    pub fn deallocate(&mut self, id: u32, lba: u64, blocks: u64) -> Option<()> {
        let namespace = self.namespace(id)?;
        let end = lba.checked_add(blocks)?;
        if end > namespace.blocks {
            return None;
        }
        self.erased
            .insert(namespace.first + lba, namespace.first + end);
        Some(())
    }

    /// Erased blocks whose host bytes are still stale.
    pub fn erase_pending(&self) -> u64 {
        self.erased.blocks
    }

    /// Write zeros over up to `budget` erased blocks, lowest first, flush
    /// the host, and only then drop them from the erased runs, so a block
    /// leaves them only once its zeros are durable. Returns the blocks still
    /// pending. A failed write or flush leaves the runs unchanged.
    pub fn zero_erased(&mut self, budget: u64) -> Result<u64, BlockError> {
        let mut segments = Vec::new();
        let mut left = budget;
        for (&start, &end) in &self.erased.runs {
            if left == 0 {
                break;
            }
            let take = (end - start).min(left);
            segments.push((start, start + take));
            left -= take;
        }
        if segments.is_empty() {
            return Ok(self.erased.blocks);
        }
        let zeros = vec![0; (ZERO_BLOCKS * u64::from(BLOCK_BYTES)) as usize];
        for &(start, end) in &segments {
            let mut block = start;
            while block < end {
                let count = (end - block).min(ZERO_BLOCKS);
                self.device.write(
                    block * self.host_blocks_per_lba,
                    &zeros[..(count * u64::from(BLOCK_BYTES)) as usize],
                )?;
                block += count;
            }
        }
        self.device.flush()?;
        for (start, end) in segments {
            self.erased.remove(start, end);
        }
        Ok(self.erased.blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use stela_drivers::block::RamDisk;

    #[test]
    fn records_and_persistent_partition_extents() {
        let records = [
            Description {
                id: 1,
                kind: 1,
                blocks: 0,
            },
            Description {
                id: 2,
                kind: 8,
                blocks: 3,
            },
        ];
        let bytes: Vec<_> = records
            .iter()
            .flat_map(|d| [d.id, d.kind, d.blocks])
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(Description::decode(&bytes).unwrap(), records);
        assert!(Description::decode(&bytes[..23]).is_err());
        for block_size in [512, 4096] {
            let disk = RamDisk::new("medium", 10 * 4096 / u64::from(block_size), block_size);
            let mut medium = Medium::new(Box::new(disk), &records).unwrap();
            assert_eq!(medium.namespace(1).unwrap().blocks, 7);
            assert_eq!(medium.namespace(2).unwrap().first, 7);
            medium.write(2, 0, &[0x5a; 4096]).unwrap();
            let mut data = [0; 4096];
            medium.read(2, 0, &mut data).unwrap();
            assert_eq!(data, [0x5a; 4096]);
            medium.read(1, 6, &mut data).unwrap();
            assert_eq!(data, [0; 4096]);
            assert_eq!(medium.address(1, 7, 1), None);
            assert_eq!(medium.address(2, 3, 1), None);
            assert_eq!(medium.address(2, u64::MAX, 1), None);
            assert_eq!(medium.address(0, 0, 1), None);
        }
    }

    #[test]
    fn erased_runs_merge_split_and_count_blocks() {
        let mut erased = Erased::default();
        erased.insert(10, 20);
        erased.insert(20, 25);
        erased.insert(5, 8);
        erased.insert(7, 11);
        assert_eq!(erased.runs.iter().collect::<Vec<_>>(), [(&5, &25)]);
        assert_eq!(erased.blocks, 20);
        erased.remove(12, 14);
        erased.remove(0, 6);
        erased.remove(24, 30);
        let runs: Vec<_> = erased.runs.iter().map(|(&s, &e)| (s, e)).collect();
        assert_eq!(runs, [(6, 12), (14, 24)]);
        assert_eq!(erased.blocks, 16);
        assert!(erased.covers(14, 24) && !erased.covers(11, 15));
        let hits: Vec<_> = erased.overlapping(10, 16).collect();
        assert_eq!(hits, [(14, 16), (10, 12)]);
        erased.remove(0, 100);
        assert!(erased.runs.is_empty());
        assert_eq!(erased.blocks, 0);
    }

    /// Two namespaces on a shared RAM disk, and a window onto all of it to
    /// look at the host's bytes behind the medium.
    fn erasable(block_size: u32) -> (Medium, stela_drivers::block::Window) {
        let records = [
            Description {
                id: 1,
                kind: 1,
                blocks: 0,
            },
            Description {
                id: 2,
                kind: 8,
                blocks: 300,
            },
        ];
        let blocks = 600 * 4096 / u64::from(block_size);
        let disk =
            stela_drivers::block::Shared::new(Box::new(RamDisk::new("medium", blocks, block_size)));
        let host = disk.window(0, blocks).unwrap();
        let medium = Medium::new(Box::new(disk.window(0, blocks).unwrap()), &records).unwrap();
        (medium, host)
    }

    #[test]
    fn erased_namespace_reads_zero_until_written_and_zeroing_reaches_the_host() {
        for block_size in [512, 4096] {
            let (mut medium, mut host) = erasable(block_size);
            let ratio = u64::from(BLOCK_BYTES / block_size);
            for lba in 0..300 {
                medium.write(1, lba, &[0x11; 4096]).unwrap();
                medium.write(2, lba, &[0x22; 4096]).unwrap();
            }
            medium.erase(2).unwrap();
            assert_eq!(medium.erase(3), None);
            assert_eq!(medium.erase_pending(), 300);
            let mut data = alloc::vec![0xff; 2 * 4096];
            medium.read(2, 0, &mut data).unwrap();
            assert!(data.iter().all(|&b| b == 0));
            // Namespace 1 keeps its data; a read across a block written
            // after the erase returns zeros, then the new data.
            medium.read(1, 299, &mut data[..4096]).unwrap();
            assert_eq!(&data[..4096], &[0x11; 4096]);
            medium.write(2, 7, &[0x5a; 4096]).unwrap();
            medium.read(2, 6, &mut data).unwrap();
            assert_eq!(&data[..4096], &[0; 4096]);
            assert_eq!(&data[4096..], &[0x5a; 4096]);
            assert_eq!(medium.erase_pending(), 299);
            // The host still holds stale bytes until zeroed, in budgets.
            let first = medium.namespace(2).unwrap().first;
            let mut stale = alloc::vec![0; 4096];
            host.read(first * ratio, &mut stale).unwrap();
            assert_eq!(stale, [0x22; 4096]);
            assert_eq!(medium.zero_erased(5).unwrap(), 294);
            host.read(first * ratio, &mut stale).unwrap();
            assert_eq!(stale, [0; 4096]);
            host.read((first + 5) * ratio, &mut stale).unwrap();
            assert_eq!(stale, [0x22; 4096]);
            assert_eq!(medium.zero_erased(u64::MAX).unwrap(), 0);
            assert_eq!(medium.zero_erased(u64::MAX).unwrap(), 0);
            // The host bytes alone, all the next boot sees, hold the
            // erase and the later write; the neighbouring namespace kept
            // its data.
            let mut whole = alloc::vec![0; 300 * 4096];
            host.read(first * ratio, &mut whole).unwrap();
            for (lba, block) in whole.chunks(4096).enumerate() {
                let fill = if lba == 7 { 0x5a } else { 0 };
                assert!(block.iter().all(|&b| b == fill), "block {lba}");
            }
            host.read((first - 1) * ratio, &mut stale).unwrap();
            assert_eq!(stale, [0x11; 4096]);
        }
    }

    #[test]
    fn deallocated_ranges_read_zero_stay_inside_their_namespace_and_reach_the_host() {
        for block_size in [512, 4096] {
            let (mut medium, mut host) = erasable(block_size);
            let ratio = u64::from(BLOCK_BYTES / block_size);
            for lba in 0..300 {
                medium.write(1, lba, &[0x11; 4096]).unwrap();
                medium.write(2, lba, &[0x22; 4096]).unwrap();
            }
            // A range past the namespace, or wrapping, changes nothing.
            assert_eq!(medium.deallocate(2, 299, 2), None);
            assert_eq!(medium.deallocate(2, u64::MAX, 2), None);
            assert_eq!(medium.deallocate(4, 0, 1), None);
            assert_eq!(medium.erase_pending(), 0);
            medium.deallocate(2, 10, 5).unwrap();
            medium.deallocate(2, 0, 0).unwrap();
            assert_eq!(medium.erase_pending(), 5);
            let mut data = alloc::vec![0xff; 7 * 4096];
            medium.read(2, 9, &mut data).unwrap();
            for (i, block) in data.chunks(4096).enumerate() {
                let fill = if (1..6).contains(&i) { 0 } else { 0x22 };
                assert!(block.iter().all(|&b| b == fill), "block {i}");
            }
            // The neighbouring namespace keeps its data.
            medium.read(1, 299, &mut data[..4096]).unwrap();
            assert_eq!(&data[..4096], &[0x11; 4096]);
            assert_eq!(medium.zero_erased(u64::MAX).unwrap(), 0);
            let first = medium.namespace(2).unwrap().first;
            let mut stale = alloc::vec![0; 4096];
            host.read((first + 12) * ratio, &mut stale).unwrap();
            assert_eq!(stale, [0; 4096]);
            host.read((first + 15) * ratio, &mut stale).unwrap();
            assert_eq!(stale, [0x22; 4096]);
        }
    }

    #[test]
    fn insufficient_ambiguous_or_unaligned_backing_refuses() {
        let disk = || Box::new(RamDisk::new("", 8, 512)) as alloc::boxed::Box<dyn BlockDevice>;
        let d = |id, blocks| Description {
            id,
            kind: 1,
            blocks,
        };
        for records in [
            alloc::vec![],
            alloc::vec![d(1, 2)],
            alloc::vec![d(1, 0), d(2, 0)],
            alloc::vec![d(2, 0)],
        ] {
            assert!(Medium::new(disk(), &records).is_err());
        }
        assert!(Medium::new(Box::new(RamDisk::new("", 9, 512)), &[d(1, 0)]).is_err());
    }
}
