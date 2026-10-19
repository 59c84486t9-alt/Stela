//! What a host shadow of the current context's translations records beside
//! its page tables, so that a TLBI drops only what it reaches
//! ([`super::tlbi::Reach`]) instead of the whole shadow.
//!
//! A shadow maps host pages of [`PAGE`] bytes from guest leaves of any
//! size, a window of each leaf per fill ([`window`]). A TLBI by address
//! removes the leaf that held the address, whose extent the guest's tables
//! no longer tell after the change it follows. Each half of the address
//! space therefore records the leaves its fills came from: the size of the
//! largest leaf of at most [`SMALL`] bytes, whose aligned extent around an
//! address holds every smaller leaf at that address too, and each larger
//! leaf by its own extent, because a few large blocks (a physical aperture)
//! must not make every TLBI by page drop megabytes.

use super::tlbi::Reach;
use alloc::vec::Vec;

/// The host page a shadow maps.
pub const PAGE: u64 = 1 << 12;
/// Leaves up to this size are recorded by their largest size alone.
pub const SMALL: u64 = 1 << 21;
/// The large leaves one half records; past them its extents are unknown
/// and a TLBI by address drops the whole half.
const LARGE_LEAVES: usize = 512;

/// The first and last byte of the `size`-byte leaf, a power of two of at
/// least a page, holding `address`.
pub fn leaf(address: u64, size: u64) -> (u64, u64) {
    let size = size.max(PAGE).next_power_of_two();
    let first = address & !(size - 1);
    (first, first | (size - 1))
}

/// The bytes one fill at `address` maps from its `size`-byte leaf: the
/// leaf's part of the aligned `window` around the address.
pub fn window(address: u64, size: u64, window: u64) -> (u64, u64) {
    let (first, last) = leaf(address, size);
    let (start, end) = leaf(address, window);
    (first.max(start), last.min(end))
}

/// The leaves one half of a shadow was filled from since it was last
/// emptied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extents {
    /// log2 of the largest leaf of at most [`SMALL`] bytes, 0 for none.
    small: u32,
    /// The larger leaves' first and last bytes, sorted and distinct.
    large: Vec<(u64, u64)>,
    /// More than [`LARGE_LEAVES`] large leaves were filled.
    overflow: bool,
    /// A non-global translation was filled.
    private: bool,
}

impl Extents {
    pub const fn new() -> Self {
        Self {
            small: 0,
            large: Vec::new(),
            overflow: false,
            private: false,
        }
    }

    /// The half was emptied.
    pub fn clear(&mut self) {
        self.small = 0;
        self.large.clear();
        self.overflow = false;
        self.private = false;
    }

    /// A fill at `address` from a leaf of `size` bytes, global or not.
    pub fn record(&mut self, address: u64, size: u64, global: bool) {
        self.private |= !global;
        let (first, last) = leaf(address, size);
        let bytes = last - first + 1;
        if bytes <= SMALL {
            self.small = self.small.max(bytes.trailing_zeros());
            return;
        }
        if let Err(at) = self.large.binary_search(&(first, last)) {
            if self.large.len() == LARGE_LEAVES {
                self.overflow = true;
            } else {
                self.large.insert(at, (first, last));
            }
        }
    }

    /// The half holds a non-global translation, which another ASID would
    /// not use.
    pub fn private(&self) -> bool {
        self.private
    }

    /// The ranges, first and last byte within `bounds` (this half's
    /// addresses), that hold every page this half maps from an entry
    /// `reach` removes; the large leaves among them are forgotten, as the
    /// caller unmaps them. `None` when the whole half must go.
    pub fn ranges(&mut self, reach: Reach, bounds: (u64, u64)) -> Option<Vec<(u64, u64)>> {
        let (first, last) = match reach {
            Reach::Nothing => return Some(Vec::new()),
            Reach::All => return None,
            Reach::Containing(address) => (address, address),
            Reach::Overlapping { first, last } => (first, last),
        };
        let (low, high) = bounds;
        if last < low || first > high || first > last {
            return Some(Vec::new());
        }
        if self.overflow {
            return None;
        }
        let (first, last) = (first.max(low), last.min(high));
        let mut ranges = Vec::new();
        if self.small != 0 {
            let mask = (1u64 << self.small) - 1;
            ranges.push(((first & !mask).max(low), (last | mask).min(high)));
        }
        self.large.retain(|&(start, end)| {
            let overlaps = start <= last && first <= end;
            if overlaps {
                ranges.push((start.max(low), end.min(high)));
            }
            !overlaps
        });
        Some(ranges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOWER: (u64, u64) = (0, (1 << 48) - 1);
    const UPPER: (u64, u64) = (0xffff_0000_0000_0000, u64::MAX);

    #[test]
    fn leaves_and_windows_are_aligned_extents() {
        assert_eq!(leaf(0x1_2345, 1 << 14), (0x1_0000, 0x1_3fff));
        assert_eq!(leaf(0x1_2345, 0), (0x1_2000, 0x1_2fff));
        assert_eq!(leaf(u64::MAX, 1 << 14), (0xffff_ffff_ffff_c000, u64::MAX));
        // A 16 KiB page fills whole within a 64 KiB window; a 32 MiB block
        // fills the window alone.
        assert_eq!(window(0x1_2345, 1 << 14, 1 << 16), (0x1_0000, 0x1_3fff));
        assert_eq!(window(0x1_2345, 1 << 25, 1 << 16), (0x1_0000, 0x1_ffff));
        assert_eq!(window(0x1_2345, 1 << 12, 1 << 16), (0x1_2000, 0x1_2fff));
    }

    #[test]
    fn small_leaves_widen_the_address_and_large_ones_are_named() {
        let mut extents = Extents::new();
        assert_eq!(
            extents.ranges(Reach::Containing(0x8000), LOWER),
            Some(Vec::new())
        );
        extents.record(0x4_1000, 1 << 14, true);
        extents.record(0x10_0000, 1 << 12, true);
        assert!(!extents.private());
        assert_eq!(
            extents.ranges(Reach::Containing(0x8_5000), LOWER),
            Some(alloc::vec![(0x8_4000, 0x8_7fff)])
        );
        let block = 0xffff_fe00_0200_0000;
        extents.record(block + 0x12_3456, 1 << 25, true);
        extents.record(block + 0x45_6789, 1 << 25, false);
        assert!(extents.private());
        assert_eq!(extents.large, alloc::vec![(block, block + (1 << 25) - 1)]);
        // A page of the block drops its 16 KiB neighbourhood and the block,
        // which is then forgotten.
        assert_eq!(
            extents.ranges(Reach::Containing(block + 0x8000), UPPER),
            Some(alloc::vec![
                (block + 0x8000, block + 0xbfff),
                (block, block + (1 << 25) - 1)
            ])
        );
        assert!(extents.large.is_empty());
        // Ranges clamp to the half; other halves and inverted ranges reach
        // nothing; All drops the half.
        assert_eq!(
            extents.ranges(
                Reach::Overlapping {
                    first: 0x1_0000,
                    last: u64::MAX
                },
                LOWER
            ),
            Some(alloc::vec![(0x1_0000, LOWER.1)])
        );
        assert_eq!(
            extents.ranges(Reach::Containing(block), LOWER),
            Some(Vec::new())
        );
        assert_eq!(extents.ranges(Reach::All, LOWER), None);
        extents.clear();
        assert_eq!(extents, Extents::new());
    }

    #[test]
    fn too_many_large_leaves_make_any_address_drop_the_half() {
        let mut extents = Extents::new();
        for block in 0..=LARGE_LEAVES as u64 {
            extents.record(block << 25, 1 << 25, true);
        }
        assert_eq!(extents.ranges(Reach::Containing(0x4000), LOWER), None);
        assert_eq!(
            extents.ranges(Reach::Containing(0xffff_ffff_0000_0000), LOWER),
            Some(Vec::new())
        );
    }

    /// Over random fills of random leaves, every page filled from a leaf a
    /// reach overlaps lies in the returned ranges.
    #[test]
    fn the_ranges_hold_every_page_filled_from_a_reached_leaf() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let sizes = [12, 14, 16, 21, 25, 30];
        for _ in 0..2000 {
            let mut extents = Extents::new();
            let mut fills = Vec::new();
            for _ in 0..1 + next() % 40 {
                let address = next() & 0x3_ffff_ffff;
                let size = 1u64 << sizes[next() as usize % sizes.len()];
                extents.record(address, size, true);
                fills.push((leaf(address, size), window(address, size, 1 << 16)));
            }
            let first = next() & 0x3_ffff_ffff;
            let reach = if next() & 1 == 0 {
                Reach::Containing(first)
            } else {
                Reach::Overlapping {
                    first,
                    last: first + (next() & 0xf_ffff),
                }
            };
            let (start, end) = match reach {
                Reach::Containing(address) => (address, address),
                Reach::Overlapping { first, last } => (first, last),
                _ => unreachable!(),
            };
            let ranges = extents.ranges(reach, LOWER).unwrap();
            for ((leaf_first, leaf_last), (mapped_first, mapped_last)) in fills {
                if leaf_first > end || start > leaf_last {
                    continue;
                }
                let held = |page: u64| ranges.iter().any(|&(a, b)| a <= page && page <= b);
                assert!(
                    held(mapped_first) && held(mapped_last),
                    "{reach:?} {ranges:?}"
                );
            }
        }
    }
}
