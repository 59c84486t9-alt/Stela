//! Translation granules, lookup levels and address sizes (Arm ARM D8.2 and
//! D8.3): which levels a walk visits, which bits index each level and where
//! blocks are allowed.

use super::PHYSICAL_ADDRESS_BITS;

/// Without FEAT_TTST and FEAT_LVA a region is 25 to 48 bits wide.
pub const MIN_TNSZ: u32 = 16;
pub const MAX_TNSZ: u32 = 39;

/// TnSZ outside 16..=39 is CONSTRAINED UNPREDICTABLE; this implementation
/// makes the FORCE choice (the nearest bound), as pointer authentication does.
pub fn forced_tnsz(tnsz: u32) -> u32 {
    tnsz.clamp(MIN_TNSZ, MAX_TNSZ)
}

/// The output address size of an IPS, PS or VTCR.PS encoding, capped at the
/// implemented PARange. Encodings beyond it, including 52 bits without
/// FEAT_LPA and the reserved 0b111, behave as PARange.
pub fn output_bits(encoding: u64) -> u32 {
    let bits = match encoding & 7 {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        _ => 48,
    };
    bits.min(PHYSICAL_ADDRESS_BITS)
}

/// One walk's shape: granule and input-address size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// log2 of the granule: 12 (4 KiB) or 14 (16 KiB).
    pub granule_bits: u32,
    /// Input address bits translated (64 - TnSZ for stage 1).
    pub input_bits: u32,
    /// The first level visited.
    pub start_level: i8,
}

impl Geometry {
    /// The stage-1 shape: the start level follows from the input size.
    pub fn stage1(granule_bits: u32, input_bits: u32) -> Self {
        let stride = granule_bits - 3;
        let levels = (input_bits - granule_bits).div_ceil(stride);
        Self {
            granule_bits,
            input_bits,
            start_level: 4 - levels as i8,
        }
    }

    fn stride(self) -> u32 {
        self.granule_bits - 3
    }

    /// Lowest input bit resolved at `level`: the size of what one entry maps.
    pub fn shift(self, level: i8) -> u32 {
        self.granule_bits + self.stride() * (3 - level) as u32
    }

    /// Index bits at `level`; the start level takes what remains, which with
    /// stage-2 concatenation may exceed a granule's worth.
    pub fn index_bits(self, level: i8) -> u32 {
        if level == self.start_level {
            self.input_bits - self.shift(level)
        } else {
            self.stride()
        }
    }

    pub fn index(self, address: u64, level: i8) -> u64 {
        (address >> self.shift(level)) & ((1u64 << self.index_bits(level)) - 1)
    }

    /// Bytes of the start-level table (or concatenated tables).
    pub fn start_table_bytes(self) -> u64 {
        8 << self.index_bits(self.start_level)
    }

    /// Block descriptors: 4 KiB at levels 1 and 2, 16 KiB at level 2; level 1
    /// 16 KiB and level 0 blocks need FEAT_LPA2.
    pub fn block_allowed(self, level: i8) -> bool {
        match self.granule_bits {
            12 => level == 1 || level == 2,
            _ => level == 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_index_bits_and_blocks_follow_the_granule() {
        // 4 KiB, 48-bit: levels 0..3 with 9 bits each, blocks of 1 GiB and 2 MiB.
        let four = Geometry::stage1(12, 48);
        assert_eq!(four.start_level, 0);
        assert_eq!(
            (four.shift(0), four.shift(1), four.shift(2), four.shift(3)),
            (39, 30, 21, 12)
        );
        assert_eq!(four.index_bits(0), 9);
        assert!(!four.block_allowed(0) && four.block_allowed(1) && four.block_allowed(2));
        // 4 KiB: a 39-bit region starts at level 1, a 25-bit one at level 2.
        assert_eq!(Geometry::stage1(12, 39).start_level, 1);
        assert_eq!(Geometry::stage1(12, 25).start_level, 2);
        assert_eq!(Geometry::stage1(12, 25).index_bits(2), 4);
        // 16 KiB, 48-bit: a two-entry level 0, then 11 bits per level.
        let sixteen = Geometry::stage1(14, 48);
        assert_eq!((sixteen.start_level, sixteen.index_bits(0)), (0, 1));
        assert_eq!(sixteen.start_table_bytes(), 16);
        assert_eq!(
            (sixteen.shift(1), sixteen.shift(2), sixteen.shift(3)),
            (36, 25, 14)
        );
        assert!(!sixteen.block_allowed(1) && sixteen.block_allowed(2));
        // 16 KiB, 47-bit and 36-bit regions start at levels 1 and 2.
        assert_eq!(Geometry::stage1(14, 47).start_level, 1);
        assert_eq!(Geometry::stage1(14, 36).start_level, 2);
        assert_eq!(Geometry::stage1(14, 36).index(0xf_ffff_c000, 2), 0x7ff);
    }

    #[test]
    fn region_and_output_sizes_are_forced_into_the_profile() {
        assert_eq!(
            (forced_tnsz(0), forced_tnsz(25), forced_tnsz(48)),
            (16, 25, 39)
        );
        let sizes: [u32; 8] = core::array::from_fn(|encoding| output_bits(encoding as u64));
        assert_eq!(sizes, [32, 36, 40, 42, 44, 48, 48, 48]);
    }
}
