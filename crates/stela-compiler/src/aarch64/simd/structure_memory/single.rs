//! LD1-4 and ST1-4 (single lane) and LD1R-4R (replicate).
use super::{Direction, Layout, Operand, decode_addressing};

const SINGLE_STRUCTURE_MASK: u32 = 0xbf00_0000;
const SINGLE_STRUCTURE_CLASS: u32 = 0x0d00_0000;
const POST_INDEX_BIT: u32 = 1 << 23;
const LOAD_BIT: u32 = 1 << 22;
const STRUCTURE_LOW_BIT_SHIFT: u32 = 21;
const OFFSET_REGISTER_MASK: u32 = 31 << 16;
const OPCODE_SHIFT: u32 = 13;
const OPCODE_MASK: u32 = 7;
const LANE_BIT_SHIFT: u32 = 12;
const SIZE_SHIFT: u32 = 10;
const SIZE_MASK: u32 = 3;
const Q_SHIFT: u32 = 30;
const VECTOR_MASK: u32 = 31;
const BYTE_SCALE: u8 = 0;
const HALFWORD_SCALE: u8 = 1;
const WORD_SCALE: u8 = 2;
const DOUBLEWORD_SCALE: u8 = 3;
const LOW_VECTOR_BYTES: u8 = 8;

/// None denotes a different class; Err denotes a reserved single structure.
#[allow(clippy::result_unit_err)]
pub(super) fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if word & SINGLE_STRUCTURE_MASK != SINGLE_STRUCTURE_CLASS {
        return None;
    }
    if word & POST_INDEX_BIT == 0 && word & OFFSET_REGISTER_MASK != 0 {
        return Some(Err(()));
    }
    let opcode = ((word >> OPCODE_SHIFT) & OPCODE_MASK) as u8;
    let structures = ((opcode & 1) << 1) + ((word >> STRUCTURE_LOW_BIT_SHIFT) & 1) as u8 + 1;
    let q = ((word >> Q_SHIFT) & 1) as u8;
    let lane_bit = ((word >> LANE_BIT_SHIFT) & 1) as u8;
    let size = ((word >> SIZE_SHIFT) & SIZE_MASK) as u8;
    let direction = if word & LOAD_BIT == 0 {
        Direction::Store
    } else {
        Direction::Load
    };
    let (scale, layout) = match opcode >> 1 {
        BYTE_SCALE => (
            BYTE_SCALE,
            Layout::Lane {
                structures,
                index: (q << 3) | (lane_bit << 2) | size,
            },
        ),
        HALFWORD_SCALE if size & 1 == 0 => (
            HALFWORD_SCALE,
            Layout::Lane {
                structures,
                index: (q << 2) | (lane_bit << 1) | (size >> 1),
            },
        ),
        WORD_SCALE if size == 0 => (
            WORD_SCALE,
            Layout::Lane {
                structures,
                index: (q << 1) | lane_bit,
            },
        ),
        WORD_SCALE if size == 1 && lane_bit == 0 => (
            DOUBLEWORD_SCALE,
            Layout::Lane {
                structures,
                index: q,
            },
        ),
        DOUBLEWORD_SCALE if direction == Direction::Load && lane_bit == 0 => (
            size,
            Layout::Replicate {
                structures,
                vector_bytes: LOW_VECTOR_BYTES << q,
            },
        ),
        _ => return Some(Err(())),
    };
    let (base, post_index) = decode_addressing(word);
    Some(Ok(Operand {
        direction,
        first_vector: (word & VECTOR_MASK) as u8,
        base,
        element_bytes: 1 << scale,
        layout,
        post_index,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{Register, simd::structure_memory::PostIndex};

    const BASE_SHIFT: u32 = 5;
    const POST_REGISTER_SHIFT: u32 = 16;

    #[test]
    fn all_single_shapes_and_reserved_combinations() {
        let mut lane_shapes = 0;
        let mut replicate_shapes = 0;
        for q in 0..2 {
            for load in 0..2 {
                for r in 0..2 {
                    for opcode in 0..8 {
                        for s in 0..2 {
                            for size in 0..4 {
                                for mode in 0..3 {
                                    let word = SINGLE_STRUCTURE_CLASS
                                        | (q << Q_SHIFT)
                                        | (load << 22)
                                        | (r << STRUCTURE_LOW_BIT_SHIFT)
                                        | (opcode << OPCODE_SHIFT)
                                        | (s << LANE_BIT_SHIFT)
                                        | (size << SIZE_SHIFT)
                                        | (31 << BASE_SHIFT)
                                        | 31
                                        | match mode {
                                            0 => 0,
                                            1 => POST_INDEX_BIT | OFFSET_REGISTER_MASK,
                                            _ => POST_INDEX_BIT | (7 << POST_REGISTER_SHIFT),
                                        };
                                    let result = decode(word).unwrap();
                                    let expected = match opcode / 2 {
                                        0 => Some((1, (q * 8 + s * 4 + size) as u8)),
                                        1 if size % 2 == 0 => {
                                            Some((2, (q * 4 + s * 2 + size / 2) as u8))
                                        }
                                        2 if size == 0 => Some((4, (q * 2 + s) as u8)),
                                        2 if size == 1 && s == 0 => Some((8, q as u8)),
                                        3 if load == 1 && s == 0 => Some((1 << size, 0)),
                                        _ => None,
                                    };
                                    let Some((bytes, index)) = expected else {
                                        assert!(result.is_err(), "reserved word {word:08x}");
                                        continue;
                                    };
                                    let operand = result.unwrap();
                                    assert_eq!(operand.element_bytes, bytes);
                                    assert_eq!(operand.first_vector, 31);
                                    assert_eq!(operand.base, Register::Sp);
                                    assert_eq!(
                                        operand.post_index,
                                        match mode {
                                            0 => PostIndex::None,
                                            1 => PostIndex::TransferredBytes,
                                            _ => PostIndex::Register(7),
                                        }
                                    );
                                    let structures = ((opcode % 2) * 2 + r + 1) as u8;
                                    if opcode / 2 == 3 {
                                        replicate_shapes += 1;
                                        assert_eq!(
                                            operand.layout,
                                            Layout::Replicate {
                                                structures,
                                                vector_bytes: 8 << q,
                                            }
                                        );
                                    } else {
                                        lane_shapes += 1;
                                        assert_eq!(
                                            operand.layout,
                                            Layout::Lane { structures, index }
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(lane_shapes, 720);
        assert_eq!(replicate_shapes, 96);
    }

    #[test]
    fn register_fields_and_post_index_roles() {
        for vector in 0..32 {
            for base in 0..32 {
                for index in 0..32 {
                    let word = SINGLE_STRUCTURE_CLASS
                        | LOAD_BIT
                        | POST_INDEX_BIT
                        | (index << POST_REGISTER_SHIFT)
                        | (base << BASE_SHIFT)
                        | vector;
                    let operand = decode(word).unwrap().unwrap();
                    assert_eq!(operand.first_vector, vector as u8);
                    assert_eq!(
                        operand.base,
                        if base == 31 {
                            Register::Sp
                        } else {
                            Register::X(base as u8)
                        }
                    );
                    assert_eq!(
                        operand.post_index,
                        if index == 31 {
                            PostIndex::TransferredBytes
                        } else {
                            PostIndex::Register(index as u8)
                        }
                    );
                    if index != 0 {
                        assert!(decode(word & !POST_INDEX_BIT).unwrap().is_err());
                    }
                }
            }
        }
    }

    #[test]
    fn neighboring_classes_do_not_match() {
        for changed in [31, 29, 28, 27, 26, 25, 24] {
            assert!(decode(SINGLE_STRUCTURE_CLASS ^ (1 << changed)).is_none());
        }
        assert!(decode(0x0c40_7000).is_none()); // multiple structures
        assert!(decode(0x3dc0_0000).is_none()); // ordinary Q load
    }
}
