//! SME_LUTv2 register lookup and vector-to-ZT0 move. Both require streaming
//! SVE and enabled ZT0; ZA content is untouched. Arm A64 2026-06 facts from
//! luti4_mz4_ztmz2.xml and movt_zt_z.xml. No architectural aliases.

use super::tables::VectorGroup;
use crate::aarch64::scalable::{LOOKUP_TABLE_BYTES, VectorLength};

const SOURCE_SHIFT: u32 = 5;
const SIZE_SHIFT: u32 = 12;
const SIZE_MASK: u32 = 3;
const REGISTER_MASK: u32 = 31;
const FOUR_REGISTER_COUNT: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    LookupPair {
        destination: VectorGroup,
        source: u8,
    },
    MoveToTable {
        source: u8,
        immediate: u8,
    },
}

impl Operand {
    pub const fn canonical_id(self) -> &'static str {
        match self {
            Self::LookupPair { destination, .. } if destination.stride == 1 => "luti4_mz4_ztmz2_1",
            Self::LookupPair { .. } => "luti4_mz4_ztmz2_4",
            Self::MoveToTable { .. } => "movt_zt_z_",
        }
    }

    pub const fn requires_sme2p1(self) -> bool {
        matches!(self, Self::LookupPair { destination, .. } if destination.stride == 4)
    }

    /// Byte offset and transfer byte count; the original immediate, rather than
    /// its reduced offset, decides whether the untouched table bytes are zeroed.
    pub fn table_transfer(self, length: VectorLength) -> Option<(usize, usize, bool)> {
        let Self::MoveToTable { immediate, .. } = self else {
            return None;
        };
        let bytes = length.bytes().min(LOOKUP_TABLE_BYTES);
        let slot = usize::from(immediate) % (LOOKUP_TABLE_BYTES / bytes);
        Some((slot * bytes, bytes, immediate == 0))
    }
}

pub fn decode(word: u32) -> Option<Operand> {
    if word & 0xffff_cfe0 == 0xc04f_03e0 {
        return Some(Operand::MoveToTable {
            source: (word & REGISTER_MASK) as u8,
            immediate: ((word >> SIZE_SHIFT) & SIZE_MASK) as u8,
        });
    }
    let stride = if word & 0xffff_cc23 == 0xc08b_0000 {
        1
    } else if word & 0xffff_cc2c == 0xc09b_0000 {
        4
    } else {
        return None;
    };
    if (word >> SIZE_SHIFT) & SIZE_MASK != 0 {
        return None;
    }
    let first = if stride == 1 {
        (word & REGISTER_MASK) as u8
    } else {
        (word & 0x13) as u8
    };
    Some(Operand::LookupPair {
        destination: VectorGroup {
            first,
            count: FOUR_REGISTER_COUNT,
            stride,
        },
        source: ((word >> SOURCE_SHIFT) & 30) as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_pair_is_byte_only_and_groups_never_wrap() {
        for (base, stride) in [(0xc08b_0000, 1), (0xc09b_0000, 4)] {
            for size in 0..4 {
                for source in (0..32).step_by(2) {
                    for first in 0..32 {
                        let aligned = if stride == 1 {
                            first % 4 == 0
                        } else {
                            first & 12 == 0
                        };
                        if !aligned {
                            continue;
                        }
                        let result =
                            decode(base | (size << SIZE_SHIFT) | (source << SOURCE_SHIFT) | first);
                        if size != 0 {
                            assert_eq!(result, None);
                            continue;
                        }
                        let Operand::LookupPair {
                            destination,
                            source: decoded_source,
                        } = result.unwrap()
                        else {
                            panic!()
                        };
                        assert_eq!(
                            destination,
                            VectorGroup {
                                first: first as u8,
                                count: 4,
                                stride
                            }
                        );
                        assert_eq!(decoded_source, source as u8);
                        assert!(destination.register(3) < 32);
                    }
                }
            }
        }
    }

    #[test]
    fn move_offsets_wrap_and_only_encoded_zero_clears_the_tail() {
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for immediate in 0..4 {
                let operand = decode(0xc04f_03e0 | (immediate << SIZE_SHIFT) | 31).unwrap();
                let transfer = bytes.min(LOOKUP_TABLE_BYTES);
                assert_eq!(
                    operand.table_transfer(length),
                    Some((
                        immediate as usize % (64 / transfer) * transfer,
                        transfer,
                        immediate == 0
                    ))
                );
            }
        }
    }
}
