//! The Allocation Tags of guest physical memory (FEAT_MTE2): four bits for
//! each 16-byte granule, kept apart from RAM, as Arm `PhysMemTagRead` and
//! `PhysMemTagWrite` reach them by the data's physical address. Only pages
//! that ever held a nonzero tag take storage; every other granule's tag is
//! 0, the value Stela gives RAM out of reset (Arm leaves it UNKNOWN). The
//! PEs share the store, as they share RAM.
use alloc::{boxed::Box, collections::BTreeMap};

/// Bytes one Allocation Tag covers (Arm `TAG_GRANULE`).
pub const GRANULE: u64 = 16;
const PAGE_SHIFT: u32 = 12;
const GRANULE_SHIFT: u32 = 4;
/// Two tags to the byte.
const PAGE_BYTES: usize = (1 << (PAGE_SHIFT - GRANULE_SHIFT)) / 2;
const TAG_MASK: u8 = 0xf;

/// Allocation Tags by physical page.
#[derive(Debug, Clone, Default)]
pub struct Store {
    pages: BTreeMap<u64, Box<[u8; PAGE_BYTES]>>,
}

/// The page, byte and nibble shift of the granule holding `physical`.
fn place(physical: u64) -> (u64, usize, u32) {
    let granule = (physical >> GRANULE_SHIFT) as usize & ((1 << (PAGE_SHIFT - GRANULE_SHIFT)) - 1);
    (
        physical >> PAGE_SHIFT,
        granule / 2,
        4 * (granule as u32 % 2),
    )
}

impl Store {
    /// The tag of the granule holding `physical`.
    pub fn get(&self, physical: u64) -> u8 {
        let (page, byte, shift) = place(physical);
        self.pages
            .get(&page)
            .map_or(0, |tags| tags[byte] >> shift & TAG_MASK)
    }

    /// Set the tag of the granule holding `physical` to `tag`'s low four
    /// bits.
    pub fn set(&mut self, physical: u64, tag: u8) {
        let (page, byte, shift) = place(physical);
        let tag = tag & TAG_MASK;
        let tags = match self.pages.get_mut(&page) {
            Some(tags) => tags,
            None if tag == 0 => return,
            None => self
                .pages
                .entry(page)
                .or_insert_with(|| Box::new([0; PAGE_BYTES])),
        };
        tags[byte] = tags[byte] & !(TAG_MASK << shift) | tag << shift;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_granule_holds_its_own_tag_and_untouched_pages_read_zero() {
        let mut store = Store::default();
        assert_eq!(store.get(0x1_0000_0040), 0);
        // Zero tags allocate nothing.
        store.set(0x1_0000_0040, 0x10);
        assert!(store.pages.is_empty());
        // Neighbouring granules share a byte and keep their own tags; every
        // address in a granule reads its tag; only the low nibble is kept.
        store.set(0x1_0000_0040, 0xa);
        store.set(0x1_0000_0050, 0x15);
        assert_eq!(store.get(0x1_0000_004f), 0xa);
        assert_eq!(store.get(0x1_0000_0050), 0x5);
        assert_eq!(store.get(0x1_0000_0060), 0);
        assert_eq!(store.get(0x1_0000_1040), 0, "the next page");
        store.set(0x1_0000_0040, 0);
        assert_eq!((store.get(0x1_0000_0040), store.get(0x1_0000_0050)), (0, 5));
        // The last granule of a page.
        store.set(0x1_0000_0ff0, 0xf);
        assert_eq!(store.get(0x1_0000_0fff), 0xf);
        assert_eq!(store.get(0x1_0000_0fe0), 0);
    }
}
