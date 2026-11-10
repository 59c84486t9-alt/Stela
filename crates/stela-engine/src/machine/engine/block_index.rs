//! The installed blocks by physical page: a page's sorted slots and page
//! offsets, whose blocks hold the rest of each key. A block costs a few
//! bytes here, and forgetting a page forgets its blocks at once. Each fetch
//! a lookup misses comes here, so a direct-mapped cache of pages answers
//! most without walking the ordered map, which sweeps keep their place in.
//!
//! The index changes under the board's code lock; a [`Finder`] beside it
//! answers a fetch without that lock.
use super::{Block, FETCH_PAGE, VariantId, board::Records};
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::ops::Index;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

const _: () = assert!(FETCH_PAGE <= 1 << u16::BITS);

/// Where [`BlockIndex::sweep`] goes on: past this entry of this page.
pub(super) type Cursor = (u64, usize);

/// The pages [`BlockIndex::front`] holds, a power of two.
const FRONT: usize = 1 << 12;
/// A frame no page has: pages are aligned.
const NO_FRAME: u64 = 1;
/// The entries a forgotten page's list keeps room for.
const KEPT_ENTRIES: usize = 16;

/// One block of a page.
#[derive(Clone, Copy)]
struct Entry {
    offset: u16,
    slot: u32,
}

pub(super) struct BlockIndex {
    /// The same blocks, for reads without the lock.
    finder: Arc<Finder>,
    /// Each physical page's [`Self::entries`].
    pages: BTreeMap<u64, u32>,
    /// A page's blocks, by ascending offset.
    entries: Vec<Vec<Entry>>,
    /// The [`Self::entries`] of forgotten pages.
    free: Vec<u32>,
    /// Recently found pages and their [`Self::entries`].
    front: Box<[(u64, u32)]>,
}

fn split(physical: u64) -> (u64, u16) {
    (
        physical & !(FETCH_PAGE - 1),
        (physical & (FETCH_PAGE - 1)) as u16,
    )
}

impl BlockIndex {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self::with_finder(Arc::new(Finder::new(1 << 16)))
    }

    /// An empty index that keeps `finder` in step with it.
    pub(super) fn with_finder(finder: Arc<Finder>) -> Self {
        Self {
            finder,
            pages: BTreeMap::new(),
            entries: Vec::new(),
            free: Vec::new(),
            front: vec![(NO_FRAME, 0); FRONT].into_boxed_slice(),
        }
    }

    /// The cache slot of the page at `frame`.
    fn front_slot(frame: u64) -> usize {
        (frame / FETCH_PAGE) as usize & (FRONT - 1)
    }

    /// The [`Self::entries`] of the page at `frame`.
    fn page_of(&self, frame: u64) -> Option<usize> {
        let (cached, entries) = self.front[Self::front_slot(frame)];
        if cached == frame {
            return Some(entries as usize);
        }
        self.pages.get(&frame).map(|&entries| entries as usize)
    }

    /// The entries of `physical`'s page at its offset, which blocks of
    /// other PCs or variants may share.
    fn at(&mut self, physical: u64) -> Option<&[Entry]> {
        let (frame, offset) = split(physical);
        let page = self.page_of(frame)?;
        self.front[Self::front_slot(frame)] = (frame, page as u32);
        let entries = &self.entries[page];
        let start = entries.partition_point(|entry| entry.offset < offset);
        let count = entries[start..].partition_point(|entry| entry.offset == offset);
        Some(&entries[start..start + count])
    }

    /// The block at `pc`, `physical` and `variant`.
    pub(super) fn get(
        &mut self,
        blocks: &impl Index<usize, Output = Block>,
        pc: u64,
        physical: u64,
        variant: VariantId,
    ) -> Option<usize> {
        self.at(physical)?
            .iter()
            .map(|entry| entry.slot as usize)
            .find(|&slot| blocks[slot].pc == pc && blocks[slot].variant == variant)
    }

    /// The blocks of the page holding `physical`.
    pub(super) fn page(&self, physical: u64) -> impl Iterator<Item = usize> + '_ {
        let (frame, _) = split(physical);
        BlockIndex::page_of(self, frame)
            .into_iter()
            .flat_map(|page| &self.entries[page])
            .map(|entry| entry.slot as usize)
    }

    /// The blocks of the page holding `physical` at positions `from..` of
    /// its list, at most `most`, and the list's length.
    pub(super) fn page_part(
        &self,
        physical: u64,
        from: usize,
        most: usize,
    ) -> (impl Iterator<Item = usize> + '_, usize) {
        let (frame, _) = split(physical);
        let entries: &[Entry] = self
            .page_of(frame)
            .map_or(&[], |page| self.entries[page].as_slice());
        let part = entries.get(from..).unwrap_or(&[]);
        let part = &part[..part.len().min(most)];
        (part.iter().map(|entry| entry.slot as usize), entries.len())
    }

    /// Find the block in `slot` by its key, in place of any block of the
    /// key: the slot of the block it replaces.
    pub(super) fn insert(
        &mut self,
        blocks: &impl Index<usize, Output = Block>,
        slot: usize,
    ) -> Option<usize> {
        let block = &blocks[slot];
        let (frame, offset) = split(block.physical);
        let page = match self.page_of(frame) {
            Some(page) => page,
            None => {
                let page = self.free.pop().unwrap_or_else(|| {
                    self.entries.push(Vec::new());
                    self.entries.len() as u32 - 1
                });
                self.pages.insert(frame, page);
                self.finder.pages.store(self.pages.len(), Ordering::Relaxed);
                page as usize
            }
        };
        let entries = &mut self.entries[page];
        let start = entries.partition_point(|entry| entry.offset < offset);
        let same = entries[start..]
            .iter()
            .take_while(|entry| entry.offset == offset)
            .position(|entry| {
                let other = &blocks[entry.slot as usize];
                other.pc == block.pc && other.variant == block.variant
            });
        match same {
            Some(position) => {
                let replaced = core::mem::replace(&mut entries[start + position].slot, slot as u32);
                if replaced as usize == slot {
                    return None;
                }
                self.finder.unlink(replaced, block.physical);
                self.finder.link(slot as u32, block.physical);
                Some(replaced as usize)
            }
            None => {
                entries.insert(
                    start,
                    Entry {
                        offset,
                        slot: slot as u32,
                    },
                );
                self.finder.link(slot as u32, block.physical);
                None
            }
        }
    }

    /// Stop finding the block in `slot`, at `physical`: whether it was found.
    #[cfg(test)]
    pub(super) fn forget(&mut self, physical: u64, slot: usize) -> bool {
        let (frame, offset) = split(physical);
        let Some(page) = self.page_of(frame) else {
            return false;
        };
        let entries = &mut self.entries[page];
        let Some(position) = entries
            .iter()
            .position(|entry| entry.offset == offset && entry.slot as usize == slot)
        else {
            return false;
        };
        entries.remove(position);
        self.finder.unlink(slot as u32, physical);
        if entries.is_empty() {
            self.forget_page(frame);
        }
        true
    }

    /// Stop finding the blocks of the page at `frame` whose slots `marked`
    /// names, in one pass over the page.
    pub(super) fn forget_marked(&mut self, frame: u64, marked: impl Fn(u32) -> bool) {
        let Some(page) = self.page_of(frame) else {
            return;
        };
        let entries = &mut self.entries[page];
        let finder = &self.finder;
        entries.retain(|entry| {
            let gone = marked(entry.slot);
            if gone {
                finder.unlink(entry.slot, frame | u64::from(entry.offset));
            }
            !gone
        });
        if entries.is_empty() {
            self.forget_page(frame);
        }
    }

    /// Stop finding the blocks of the page at `frame`: whether it had any.
    /// Its list keeps a small capacity for the next page.
    pub(super) fn forget_page(&mut self, frame: u64) -> bool {
        let Some(page) = self.pages.remove(&frame) else {
            return false;
        };
        self.finder.pages.store(self.pages.len(), Ordering::Relaxed);
        let entries = &mut self.entries[page as usize];
        for entry in entries.iter() {
            self.finder
                .unlink(entry.slot, frame | u64::from(entry.offset));
        }
        entries.clear();
        entries.shrink_to(KEPT_ENTRIES);
        self.free.push(page);
        let cached = &mut self.front[Self::front_slot(frame)];
        if cached.0 == frame {
            cached.0 = NO_FRAME;
        }
        true
    }

    pub(super) fn clear(&mut self) {
        self.finder.clear();
        self.pages.clear();
        self.entries.clear();
        self.free.clear();
        self.front.fill((NO_FRAME, 0));
    }

    /// The indexed blocks, past `cursor`, in page order, with the cursor
    /// that goes on after each.
    pub(super) fn sweep(
        &self,
        cursor: Option<Cursor>,
    ) -> impl Iterator<Item = (Cursor, usize)> + '_ {
        let (first, past) = cursor.map_or((0, None), |(frame, position)| (frame, Some(position)));
        self.pages.range(first..).flat_map(move |(&frame, &page)| {
            let skip = past
                .filter(|_| frame == first)
                .map_or(0, |position| position + 1);
            self.entries[page as usize]
                .iter()
                .enumerate()
                .skip(skip)
                .map(move |(position, entry)| ((frame, position), entry.slot as usize))
        })
    }

    /// The heap bytes it holds.
    pub(super) fn heap_bytes(&self) -> usize {
        let entries: usize = self.entries.iter().map(Vec::capacity).sum();
        entries * size_of::<Entry>()
            + self.entries.capacity() * size_of::<Vec<Entry>>()
            + self.free.capacity() * size_of::<u32>()
            + self.front.len() * size_of::<(u64, u32)>()
            // A B-tree entry and its share of a node about half full.
            + self.pages.len() * 2 * size_of::<(u64, u32)>()
    }

    /// The physical pages that have indexed blocks.
    pub(super) fn frames(&self) -> impl Iterator<Item = u64> + '_ {
        self.pages.keys().copied()
    }

    #[cfg(any(test, all(feature = "std", feature = "native-profile")))]
    pub(super) fn len(&self) -> usize {
        self.entries.iter().map(Vec::len).sum()
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }
}

/// The most list entries [`Finder::find`] walks before it leaves the
/// answer to the locked index.
const FIND_STEPS: usize = 32;

/// The index's blocks by physical address, read without the board's lock:
/// each bucket heads a list of slots (stored plus one, 0 ends it) chained
/// through `next`. Only the index's writer, under the lock, pushes a slot
/// at its bucket's head or unlinks one; an unlinked slot keeps its `next`,
/// so a reader standing on it goes on along its old list. A slot is taken
/// again only after its grace ([`super::board::Slots`]), so a reader inside
/// its section never sees a slot it stands on join another list.
pub(super) struct Finder {
    heads: Box<[AtomicU32]>,
    next: Records<AtomicU32>,
    /// A slot had no room for its link: reads go to the locked index.
    partial: AtomicBool,
    /// The index's pages, for counts read without the lock.
    pages: AtomicUsize,
}

impl Finder {
    /// Buckets for up to `slots` block slots: one per 16 slots, at least
    /// 2^10 and at most 2^20 (4 MiB).
    pub(super) fn new(slots: u32) -> Self {
        let buckets = (slots as usize / 16)
            .next_power_of_two()
            .clamp(1 << 10, 1 << 20);
        let zeroed = vec![0u32; buckets].into_boxed_slice();
        // SAFETY: AtomicU32 has the size, alignment and bit validity of u32.
        let heads = unsafe { Box::from_raw(Box::into_raw(zeroed) as *mut [AtomicU32]) };
        Self {
            heads,
            next: Records::new(slots),
            partial: AtomicBool::new(false),
            pages: AtomicUsize::new(0),
        }
    }

    fn bucket(&self, physical: u64) -> &AtomicU32 {
        let hash = (physical >> 2).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        &self.heads[(hash >> 32) as usize & (self.heads.len() - 1)]
    }

    /// The pages the index holds.
    pub(super) fn pages(&self) -> usize {
        self.pages.load(Ordering::Relaxed)
    }

    /// The block at `pc`, `physical` and `variant` among `blocks`, or
    /// `None` when the lists cannot say (the locked index can). A reader
    /// inside its section, or holding the lock.
    pub(super) fn find(
        &self,
        blocks: &super::board::Blocks,
        pc: u64,
        physical: u64,
        variant: VariantId,
    ) -> Option<Option<usize>> {
        if self.partial.load(Ordering::Relaxed) {
            return None;
        }
        let mut link = self.bucket(physical).load(Ordering::Acquire);
        for _ in 0..FIND_STEPS {
            let Some(slot) = link.checked_sub(1) else {
                return Some(None);
            };
            let found = blocks.get(slot as usize).is_some_and(|block| {
                block.physical == physical && block.pc == pc && block.variant == variant
            });
            if found && blocks.record(slot as usize).live() {
                return Some(Some(slot as usize));
            }
            link = self.next.get(slot)?.load(Ordering::Acquire);
        }
        None
    }

    /// Put `slot` at the head of its bucket's list, unless it is listed.
    fn link(&self, slot: u32, physical: u64) {
        let bucket = self.bucket(physical);
        if self.listed(bucket, slot) {
            return;
        }
        let Some(next) = self.next.try_reserve(slot) else {
            self.partial.store(true, Ordering::Relaxed);
            return;
        };
        next.store(bucket.load(Ordering::Relaxed), Ordering::Relaxed);
        bucket.store(slot + 1, Ordering::Release);
    }

    fn listed(&self, bucket: &AtomicU32, slot: u32) -> bool {
        let mut link = bucket.load(Ordering::Relaxed);
        while let Some(at) = link.checked_sub(1) {
            if at == slot {
                return true;
            }
            link = self
                .next
                .get(at)
                .map_or(0, |next| next.load(Ordering::Relaxed));
        }
        false
    }

    /// Take `slot` out of its bucket's list; it keeps its `next`.
    fn unlink(&self, slot: u32, physical: u64) {
        let mut at = self.bucket(physical);
        loop {
            let link = at.load(Ordering::Relaxed);
            let Some(held) = link.checked_sub(1) else {
                return;
            };
            let Some(next) = self.next.get(held) else {
                return;
            };
            if held == slot {
                at.store(next.load(Ordering::Relaxed), Ordering::Release);
                return;
            }
            at = next;
        }
    }

    /// Empty every list.
    fn clear(&self) {
        for head in &self.heads {
            head.store(0, Ordering::Release);
        }
        self.pages.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::super::NativeCode;
    use super::*;

    fn block(pc: u64, physical: u64, variant: u32) -> Block {
        Block {
            pc,
            physical,
            code: NativeCode(0),
            instructions: 1,
            variant: VariantId(variant),
            successors: Box::default(),
            dynamic_site: None,
            landing: super::super::fetch::Landing::None,
            terminal: 0,
            source_hash: 0,
            installer: 0,
            device_stub: false,
        }
    }

    fn push(blocks: &mut Vec<Block>, block: Block) -> usize {
        blocks.push(block);
        blocks.len() - 1
    }

    fn add(blocks: &mut Vec<Block>, index: &mut BlockIndex, block: Block) -> usize {
        let slot = push(blocks, block);
        assert_eq!(index.insert(blocks, slot), None);
        slot
    }

    #[test]
    fn a_page_finds_its_blocks_by_every_part_of_their_key() {
        const PAGE: u64 = 0x8000_0000;
        let mut blocks = Vec::new();
        let mut index = BlockIndex::new();
        let late = add(&mut blocks, &mut index, block(0x1040, PAGE + 0x40, 0));
        let early = add(&mut blocks, &mut index, block(0x1010, PAGE + 0x10, 0));
        // The same physical word: through another mapping, and in another variant.
        let alias = add(&mut blocks, &mut index, block(0x9010, PAGE + 0x10, 0));
        let variant = add(&mut blocks, &mut index, block(0x1010, PAGE + 0x10, 1));
        let next = add(&mut blocks, &mut index, block(0x5000, PAGE + FETCH_PAGE, 0));
        let id = VariantId;
        assert_eq!(index.get(&blocks, 0x1010, PAGE + 0x10, id(0)), Some(early));
        assert_eq!(index.get(&blocks, 0x9010, PAGE + 0x10, id(0)), Some(alias));
        assert_eq!(
            index.get(&blocks, 0x1010, PAGE + 0x10, id(1)),
            Some(variant)
        );
        assert_eq!(index.get(&blocks, 0x1040, PAGE + 0x40, id(0)), Some(late));
        assert_eq!(index.get(&blocks, 0x1010, PAGE + 0x14, id(0)), None);
        assert_eq!(index.get(&blocks, 0x1010, PAGE + 0x10, id(2)), None);

        // A recompilation of a key takes its place.
        let again = push(&mut blocks, block(0x1040, PAGE + 0x40, 0));
        assert_eq!(index.insert(&blocks, again), Some(late));
        assert_eq!(index.get(&blocks, 0x1040, PAGE + 0x40, id(0)), Some(again));
        assert_eq!(index.sweep(None).count(), 5);
        // Forgetting one block keeps the rest of its page.
        assert!(!index.forget(PAGE + 0x40, late));
        assert!(index.forget(PAGE + 0x40, again));
        assert_eq!(index.get(&blocks, 0x1040, PAGE + 0x40, id(0)), None);
        assert_eq!(index.get(&blocks, 0x1010, PAGE + 0x10, id(0)), Some(early));
        assert_eq!(index.sweep(None).count(), 4);

        // A sweep goes on past its cursor, across pages.
        let order: Vec<usize> = index.sweep(None).map(|(_, slot)| slot).collect();
        assert_eq!(*order.last().unwrap(), next);
        let (cursor, _) = index.sweep(None).nth(1).unwrap();
        let rest: Vec<usize> = index.sweep(Some(cursor)).map(|(_, slot)| slot).collect();
        assert_eq!(rest, order[2..]);

        assert!(index.forget_page(PAGE));
        assert!(!index.forget_page(PAGE));
        assert_eq!(index.get(&blocks, 0x1010, PAGE + 0x10, id(0)), None);
        assert_eq!(
            index.sweep(None).map(|(_, slot)| slot).collect::<Vec<_>>(),
            [next]
        );
        // The page of the last block forgotten goes with it.
        assert!(index.forget(PAGE + FETCH_PAGE, next));
        assert!(index.is_empty());
    }

    #[test]
    fn marked_blocks_leave_their_page_in_one_pass() {
        const PAGE: u64 = 0x8000_0000;
        let mut blocks = Vec::new();
        let mut index = BlockIndex::new();
        let slots: Vec<usize> = [0x10, 0x20, 0x30]
            .iter()
            .map(|&offset| {
                add(
                    &mut blocks,
                    &mut index,
                    block(0x1000 + offset, PAGE + offset, 0),
                )
            })
            .collect();
        index.forget_marked(PAGE, |slot| slot as usize != slots[1]);
        assert_eq!(index.page(PAGE).collect::<Vec<_>>(), [slots[1]]);
        assert_eq!(
            index.get(&blocks, 0x1020, PAGE + 0x20, VariantId(0)),
            Some(slots[1])
        );
        index.forget_marked(PAGE, |_| true);
        assert!(index.is_empty());
        // A page indexed again takes the list the forgotten one left.
        let again = add(&mut blocks, &mut index, block(0x5000, PAGE + FETCH_PAGE, 0));
        assert_eq!(index.page(PAGE + FETCH_PAGE).collect::<Vec<_>>(), [again]);
    }
}
