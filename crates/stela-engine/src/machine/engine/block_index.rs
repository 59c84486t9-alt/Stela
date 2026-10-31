//! The installed blocks by physical page: a page's sorted slots and page
//! offsets, whose blocks hold the rest of each key. A block costs a few
//! bytes here, and forgetting a page forgets its blocks at once. Each fetch
//! a lookup misses comes here, so a direct-mapped cache of pages answers
//! most without walking the ordered map, which sweeps keep their place in.
//! Which blocks lookups went looking for is kept here too, as finding them
//! in the blocks would read each block of a page.
use super::{Block, FETCH_PAGE, VariantId, table::Table};
use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};

const _: () = assert!(FETCH_PAGE <= 1 << u16::BITS);

/// Where [`BlockIndex::sweep`] goes on: past this entry of this page.
pub(super) type Cursor = (u64, usize);

/// The pages [`BlockIndex::front`] holds, a power of two.
const FRONT: usize = 1 << 12;
/// A frame no page has: pages are aligned.
const NO_FRAME: u64 = 1;

/// One block of a page.
#[derive(Clone, Copy)]
struct Entry {
    offset: u16,
    /// A lookup thunk went looking for it, as it will again in each new
    /// context ([`Machine::remember_leaf`](super::Machine)).
    looked_up: bool,
    slot: u32,
}

pub(super) struct BlockIndex {
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
    pub(super) fn new() -> Self {
        Self {
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
    fn page(&self, frame: u64) -> Option<usize> {
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
        let page = self.page(frame)?;
        self.front[Self::front_slot(frame)] = (frame, page as u32);
        let entries = &self.entries[page];
        let start = entries.partition_point(|entry| entry.offset < offset);
        let count = entries[start..].partition_point(|entry| entry.offset == offset);
        Some(&entries[start..start + count])
    }

    /// The block at `pc`, `physical` and `variant`.
    pub(super) fn get(
        &mut self,
        blocks: &Table<Block>,
        pc: u64,
        physical: u64,
        variant: VariantId,
    ) -> Option<usize> {
        self.at(physical)?
            .iter()
            .map(|entry| entry.slot as usize)
            .find(|&slot| blocks[slot].pc == pc && blocks[slot].variant == variant)
    }

    /// Note that a lookup went looking for the block in `slot` at `physical`.
    pub(super) fn looked_up(&mut self, physical: u64, slot: usize) {
        let (frame, offset) = split(physical);
        if let Some(page) = self.page(frame) {
            let entries = &mut self.entries[page];
            let start = entries.partition_point(|entry| entry.offset < offset);
            for entry in entries[start..]
                .iter_mut()
                .take_while(|entry| entry.offset == offset)
                .filter(|entry| entry.slot == slot as u32)
            {
                entry.looked_up = true;
            }
        }
    }

    /// The slots of the blocks of the page at `frame` lookups went looking
    /// for.
    pub(super) fn looked_up_slots(&self, frame: u64) -> impl Iterator<Item = u32> + '_ {
        self.page(frame).into_iter().flat_map(|page| {
            self.entries[page]
                .iter()
                .filter(|entry| entry.looked_up)
                .map(|entry| entry.slot)
        })
    }

    /// Find the block in `slot` by its key, in place of any block of the key.
    pub(super) fn insert(&mut self, blocks: &Table<Block>, slot: usize) {
        let block = &blocks[slot];
        let (frame, offset) = split(block.physical);
        let page = match self.page(frame) {
            Some(page) => page,
            None => {
                let page = self.free.pop().unwrap_or_else(|| {
                    self.entries.push(Vec::new());
                    self.entries.len() as u32 - 1
                });
                self.pages.insert(frame, page);
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
            Some(position) => entries[start + position].slot = slot as u32,
            None => entries.insert(
                start,
                Entry {
                    offset,
                    looked_up: false,
                    slot: slot as u32,
                },
            ),
        }
    }

    /// Stop finding the blocks of the page at `frame`: whether it had any.
    pub(super) fn forget_page(&mut self, frame: u64) -> bool {
        let Some(page) = self.pages.remove(&frame) else {
            return false;
        };
        self.entries[page as usize] = Vec::new();
        self.free.push(page);
        let cached = &mut self.front[Self::front_slot(frame)];
        if cached.0 == frame {
            cached.0 = NO_FRAME;
        }
        true
    }

    pub(super) fn clear(&mut self) {
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

    #[cfg(all(feature = "std", feature = "native-profile"))]
    pub(super) fn pages(&self) -> usize {
        self.pages.len()
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
            first: 0,
            terminal: 0,
            taken: 0,
            source_bytes: 4,
            source_hash: 0,
        }
    }

    fn add(blocks: &mut Table<Block>, index: &mut BlockIndex, block: Block) -> usize {
        let slot = blocks.push(block);
        index.insert(blocks, slot);
        slot
    }

    #[test]
    fn a_page_finds_its_blocks_by_every_part_of_their_key() {
        const PAGE: u64 = 0x8000_0000;
        let mut blocks = Table::new();
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
        let again = add(&mut blocks, &mut index, block(0x1040, PAGE + 0x40, 0));
        assert_eq!(index.get(&blocks, 0x1040, PAGE + 0x40, id(0)), Some(again));
        assert_eq!(index.sweep(None).count(), 5);

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
    }
}
