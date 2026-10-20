//! Where a system-mode host places the guest's address space beside its
//! own (`docs/design/system.md#host-placement`). Native code addresses guest
//! virtual memory directly, so the guest's natively covered ranges and
//! Stela's window share each x86 root, and every guest access checks its
//! address against those ranges first (`stela_compiler::x86_64`'s guest
//! range check). Five-level paging (LA57) gives the guest both 48-bit
//! halves whole. Four-level paging gives it the lower half and the upper
//! half above `U`, the bottom `slices` 2 TiB slices of the upper half
//! holding Stela's window and, in the top one of them, an unmapped guard.
//! An address outside the native ranges that the guest maps runs in the
//! translated variant, through the software TLB ([`super::translated`]).

/// The upper half of the x86 four-level canonical space, and of an ARM
/// regime's 47-bit TTBR1 range.
pub const UPPER_HALF: u64 = 0xffff_8000_0000_0000;
/// log2 of a four-level slice: 2 TiB.
pub const SLICE_BITS: u32 = 41;
/// A four-level slice's bytes.
pub const SLICE: u64 = 1 << SLICE_BITS;
/// The slices of one 47-bit half.
pub const HALF_SLICES: u8 = 64;
/// The farthest a block's unchecked access lies from a checked one through
/// the same base (`stela_compiler::x86_64::guest_range`). A guard must
/// be at least this large.
pub const ELISION_REACH: u64 = 1 << 35;
/// The five-level check's shift: bits 63:48 all clear or all set.
const FIVE_LEVEL_SHIFT: u8 = 48;
/// Where a mispredicted five-level check sends an access: PML5 entry 1,
/// which no root maps.
const FIVE_LEVEL_MASKED: u64 = 1 << 48;

/// The host's placement of the guest's address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Placement {
    /// LA57: PML5 entries 0 and 511 hold the guest's two halves whole, and
    /// Stela's window is PML5 entry 64.
    FiveLevel,
    /// Four-level paging: the guest's native ranges are `[0, 2^47)` and
    /// `[U, 2^64)` with `U = UPPER_HALF + slices * SLICE`; Stela's window
    /// starts at [`UPPER_HALF`], and the top slice below `U` is its guard.
    FourLevel {
        /// The slices below `U`: at least two (the window and the guard),
        /// fewer than [`HALF_SLICES`].
        slices: u8,
    },
}

/// The native guest range check, as `mov rcx,rax; sar rcx,shift; add
/// ecx,bias; cmp ecx,bound; jbe ok`: an address is native exactly when
/// `(address >> shift) + bias`, arithmetic and taken in 32 bits, is at most
/// `bound` unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeCheck {
    pub shift: u8,
    pub bias: u8,
    pub bound: u8,
    /// Where a mispredicted check's CMOVA sends the access: an address no
    /// root maps, never Stela's.
    pub masked: u64,
}

impl Placement {
    /// Four-level placement with `slices` slices below the guest's native
    /// upper range; `None` unless that leaves room for a window and a
    /// guard and some native upper range.
    pub const fn four_level(slices: u8) -> Option<Self> {
        if slices >= 2 && slices < HALF_SLICES {
            Some(Self::FourLevel { slices })
        } else {
            None
        }
    }

    /// The fewest four-level slices whose window holds `window_bytes` (the
    /// engine's image, heap, stacks, code arena, table pool and physmap)
    /// below a guard slice; `None` when the half cannot.
    pub const fn four_level_for(window_bytes: u64) -> Option<Self> {
        let window = window_bytes.div_ceil(SLICE);
        if window > (HALF_SLICES - 2) as u64 {
            return None;
        }
        // At least one window slice, then the guard.
        let window = if window == 0 { 1 } else { window };
        Self::four_level(window as u8 + 1)
    }

    /// The check native code runs before each guest access.
    pub const fn check(self) -> RangeCheck {
        match self {
            Self::FiveLevel => RangeCheck {
                shift: FIVE_LEVEL_SHIFT,
                bias: 1,
                bound: 1,
                masked: FIVE_LEVEL_MASKED,
            },
            Self::FourLevel { slices } => RangeCheck {
                shift: SLICE_BITS as u8,
                bias: HALF_SLICES - slices,
                bound: 2 * HALF_SLICES - 1 - slices,
                masked: self.native_upper() - SLICE / 2,
            },
        }
    }

    /// Whether native code may access `address` directly: exactly the
    /// addresses [`Self::check`] passes.
    pub const fn native(self, address: u64) -> bool {
        let check = self.check();
        let slice = ((address as i64) >> check.shift) as u32;
        slice.wrapping_add(check.bias as u32) <= check.bound as u32
    }

    /// The start of the guest's native upper range, `U`.
    pub const fn native_upper(self) -> u64 {
        match self {
            Self::FiveLevel => 0u64.wrapping_sub(1 << FIVE_LEVEL_SHIFT),
            Self::FourLevel { slices } => UPPER_HALF + slices as u64 * SLICE,
        }
    }

    /// The four-level guard, the slice below `U` that no root maps; `None`
    /// with LA57, whose guards are the PML5 entries beside the halves.
    pub const fn guard(self) -> Option<(u64, u64)> {
        match self {
            Self::FiveLevel => None,
            Self::FourLevel { .. } => {
                let upper = self.native_upper();
                Some((upper - SLICE, upper - 1))
            }
        }
    }

    /// Whether `address` lies in the four-level guard.
    pub const fn in_guard(self, address: u64) -> bool {
        match self.guard() {
            Some((first, last)) => first <= address && address <= last,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOWER_TOP: u64 = (1 << 47) - 1;

    #[test]
    fn five_level_covers_both_48_bit_halves_whole() {
        let placement = Placement::FiveLevel;
        for address in [0, LOWER_TOP, 1 << 47, (1 << 48) - 1] {
            assert!(placement.native(address), "{address:#x}");
        }
        for address in [0xffff_0000_0000_0000, UPPER_HALF, u64::MAX] {
            assert!(placement.native(address), "{address:#x}");
        }
        for address in [1 << 48, 0x0040_0000_0000_0000, 0xfffe_ffff_ffff_ffff] {
            assert!(!placement.native(address), "{address:#x}");
        }
        assert!(!placement.native(placement.check().masked));
        assert_eq!(placement.guard(), None);
    }

    #[test]
    fn four_level_covers_the_lower_half_and_the_upper_half_above_its_slices() {
        let placement = Placement::four_level(2).unwrap();
        let upper = placement.native_upper();
        assert_eq!(upper, 0xffff_8400_0000_0000);
        assert_eq!(placement.check().bias, 62);
        assert_eq!(placement.check().bound, 125);
        for address in [
            0,
            0x7fff_fe00_0000,
            LOWER_TOP,
            upper,
            0xffff_fe00_0000_0000,
            u64::MAX,
        ] {
            assert!(placement.native(address), "{address:#x}");
        }
        // Stela's window, its guard, non-canonical addresses and the
        // 48-bit ranges a TxSZ of 16 adds.
        for address in [
            UPPER_HALF,
            upper - SLICE - 1,
            upper - SLICE,
            upper - 1,
            1 << 47,
            (1 << 48) - 1,
            0xffff_0000_0000_0000,
            UPPER_HALF - 1,
            0x0040_0000_0000_0000,
        ] {
            assert!(!placement.native(address), "{address:#x}");
        }
        let masked = placement.check().masked;
        assert!(placement.in_guard(masked) && !placement.native(masked));
        let (first, last) = placement.guard().unwrap();
        assert_eq!(last - first + 1, SLICE);
        const { assert!(SLICE >= ELISION_REACH) };
        assert!(placement.in_guard(first) && !placement.in_guard(upper));
    }

    #[test]
    fn four_level_slices_leave_a_window_a_guard_and_a_native_range() {
        assert_eq!(Placement::four_level(1), None);
        assert_eq!(Placement::four_level(HALF_SLICES), None);
        assert!(Placement::four_level(HALF_SLICES - 1).is_some());
        // Up to 2 TiB of window: one window slice and the guard.
        assert_eq!(Placement::four_level_for(0), Placement::four_level(2));
        assert_eq!(Placement::four_level_for(SLICE), Placement::four_level(2));
        assert_eq!(
            Placement::four_level_for(SLICE + 1),
            Placement::four_level(3)
        );
        assert_eq!(Placement::four_level_for(63 * SLICE), None);
        // Every slice count's check agrees with the ranges at each slice
        // boundary of the upper half.
        for slices in 2..HALF_SLICES {
            let placement = Placement::four_level(slices).unwrap();
            for slice in 0..u64::from(HALF_SLICES) {
                let first = UPPER_HALF + slice * SLICE;
                let native = slice >= u64::from(slices);
                assert_eq!(placement.native(first), native, "{slices} {slice}");
                assert_eq!(placement.native(first + (SLICE - 1)), native);
            }
        }
    }
}
