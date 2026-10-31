//! The installed blocks by physical page: a page's sorted slots and page
//! offsets, whose blocks hold the rest of each key. A block costs a few
//! bytes here, and forgetting a page forgets its blocks at once.
use super::{Block, FETCH_PAGE, VariantId, table::Table};
use alloc::{collections::BTreeMap, vec::Vec};

const _: () = assert!(FETCH_PAGE <= 1 << u16::BITS);

/// Where [`BlockIndex::sweep`] goes on: past this entry of this page.
pub(super) type Cursor = (u64, usize);

pub(super) struct BlockIndex {
    /// Each physical page's blocks: page offsets, ascending, and slots.
    pages: BTreeMap<u64, Vec<(u16, u32)>>,
}

fn split(physical: u64) -> (u64, u16) {
    (
        physical & !(FETCH_PAGE - 1),
        (physical & (FETCH_PAGE - 1)) as u16,
    )
}

impl BlockIndex {
    pub(super) const fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
        }
    }

    /// The entries of `physical`'s page at its offset, which blocks of
    /// other PCs or variants may share.
    fn at(&self, physical: u64) -> Option<&[(u16, u32)]> {
        let (frame, offset) = split(physical);
        let entries = self.pages.get(&frame)?;
        let start = entries.partition_point(|entry| entry.0 < offset);
        let count = entries[start..].partition_point(|entry| entry.0 == offset);
        Some(&entries[start..start + count])
    }

    /// The block at `pc`, `physical` and `variant`.
    pub(super) fn get(
        &self,
        blocks: &Table<Block>,
        pc: u64,
        physical: u64,
        variant: VariantId,
    ) -> Option<usize> {
        self.at(physical)?
            .iter()
            .map(|entry| entry.1 as usize)
            .find(|&slot| blocks[slot].pc == pc && blocks[slot].variant == variant)
    }

    /// Find the block in `slot` by its key, in place of any block of the key.
    pub(super) fn insert(&mut self, blocks: &Table<Block>, slot: usize) {
        let block = &blocks[slot];
        let (frame, offset) = split(block.physical);
        let entries = self.pages.entry(frame).or_default();
        let start = entries.partition_point(|entry| entry.0 < offset);
        let same = entries[start..]
            .iter()
            .take_while(|entry| entry.0 == offset)
            .position(|entry| {
                let other = &blocks[entry.1 as usize];
                other.pc == block.pc && other.variant == block.variant
            });
        match same {
            Some(position) => entries[start + position].1 = slot as u32,
            None => entries.insert(start, (offset, slot as u32)),
        }
    }

    /// Stop finding the blocks of the page at `frame`: whether it had any.
    pub(super) fn forget_page(&mut self, frame: u64) -> bool {
        self.pages.remove(&frame).is_some()
    }

    pub(super) fn clear(&mut self) {
        self.pages.clear();
    }

    /// The indexed blocks, past `cursor`, in page order, with the cursor
    /// that goes on after each.
    pub(super) fn sweep(
        &self,
        cursor: Option<Cursor>,
    ) -> impl Iterator<Item = (Cursor, usize)> + '_ {
        let (first, past) = cursor.map_or((0, None), |(frame, position)| (frame, Some(position)));
        self.pages
            .range(first..)
            .flat_map(move |(&frame, entries)| {
                let skip = past
                    .filter(|_| frame == first)
                    .map_or(0, |position| position + 1);
                entries
                    .iter()
                    .enumerate()
                    .skip(skip)
                    .map(move |(position, entry)| ((frame, position), entry.1 as usize))
            })
    }

    #[cfg(all(feature = "std", feature = "native-profile"))]
    pub(super) fn pages(&self) -> usize {
        self.pages.len()
    }

    #[cfg(any(test, all(feature = "std", feature = "native-profile")))]
    pub(super) fn len(&self) -> usize {
        self.pages.values().map(Vec::len).sum()
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
            successors: Vec::new(),
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
