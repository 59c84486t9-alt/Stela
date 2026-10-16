//! SME loads and stores: ZA slices, ZA vectors, ZT0.
use crate::aarch64::{
    Register, register,
    scalable::{
        ElementSize,
        execution::{GuestMemoryQuantity, ScalableAccessCheck, ScalableAccessRequirements},
    },
};
use alloc::boxed::Box;

const VECTOR_GROUP_MASK: u32 = 0xff80_0000;
const VECTOR_GROUP_CLASS: u32 = 0xa100_0000;
const IMMEDIATE_BIT: u32 = 1 << 22;
const STORE_BIT: u32 = 1 << 21;
const IMMEDIATE_RESERVED_BIT: u32 = 1 << 20;
const FOUR_REGISTERS_BIT: u32 = 1 << 15;
const FOUR_REGISTERS_RESERVED_BIT: u32 = 1 << 2;
const NON_TEMPORAL_BIT: u32 = 1 << 3;
const HIGH_REGISTER_BIT: u32 = 1 << 4;
const SIZE_SHIFT: u32 = 13;
const SIZE_MASK: u32 = 3;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const COUNTER_PREDICATE_BASE: u8 = 8;
const BASE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 31;
const OFFSET_SHIFT: u32 = 16;
const IMMEDIATE_BITS: u32 = 4;
const IMMEDIATE_MASK: u32 = (1 << IMMEDIATE_BITS) - 1;
const TWO_REGISTER_LOW_MASK: u32 = 7;
const FOUR_REGISTER_LOW_MASK: u32 = 3;
const HIGH_REGISTER_BASE: u8 = 16;
const TILE_MASK: u32 = 0xffe0_0010;
const TILE_BYTE_CLASS: u32 = 0xe000_0000;
const TILE_HALFWORD_CLASS: u32 = 0xe040_0000;
const TILE_WORD_CLASS: u32 = 0xe080_0000;
const TILE_DOUBLEWORD_CLASS: u32 = 0xe0c0_0000;
const TILE_QUADWORD_CLASS: u32 = 0xe1c0_0000;
const ZA_VECTOR_MASK: u32 = 0xffff_9c10;
const ZA_VECTOR_CLASS: u32 = 0xe100_0000;
const ZT_MASK: u32 = 0xffff_fc1f;
const ZT_CLASS: u32 = 0xe11f_8000;
const SLICE_SELECTOR_SHIFT: u32 = 13;
const SLICE_SELECTOR_MASK: u32 = 3;
const SLICE_SELECTOR_BASE: u8 = 12;
const VERTICAL_BIT: u32 = 1 << 15;
const TILE_SELECTOR_BITS: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Load,
    Store,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offset {
    /// Signed units of the complete transferred vector group, not bytes.
    VectorGroups(i8),
    /// X31 denotes ZR; scale equals the transferred element size.
    Register(Register),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    pub base: Register,
    pub offset: Offset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorGroup {
    pub first: u8,
    pub count: u8,
    pub stride: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorTransfer {
    pub direction: Direction,
    pub non_temporal: bool,
    pub element: ElementSize,
    pub registers: VectorGroup,
    /// PN8..PN15 supplies a predicate-as-counter encoding in its low 16 bits.
    pub predicate: u8,
    pub address: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TileTransfer {
    pub direction: Direction,
    pub element: ElementSize,
    pub tile: u8,
    pub vertical: bool,
    /// W12..W15; slice = (UInt(Ws) + immediate) modulo SVL/element_bits.
    pub slice_register: u8,
    pub slice_offset: u8,
    /// Ordinary P0..P7, unlike the multi-vector PN operands.
    pub predicate: u8,
    pub address: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZaVectorTransfer {
    pub direction: Direction,
    pub base: Register,
    pub vector_register: u8,
    /// Unsigned SVL-byte memory offset and additive ZA-vector selector.
    pub offset: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZtTransfer {
    pub direction: Direction,
    pub base: Register,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Vectors(VectorTransfer),
    Tile(TileTransfer),
    ZaVector(ZaVectorTransfer),
    Zt(ZtTransfer),
}

impl Operand {
    /// Architectural Mem element quantity, independent of total vector bytes.
    /// Whole-ZA and ZT0 transfers issue byte accesses in the source operation.
    pub(crate) const fn guest_memory_quantity(&self) -> GuestMemoryQuantity {
        let element = match self {
            Self::Vectors(transfer) => transfer.element,
            Self::Tile(transfer) => transfer.element,
            Self::ZaVector(_) | Self::Zt(_) => ElementSize::Byte,
        };
        GuestMemoryQuantity::Maximum(element)
    }

    /// The top-level access checks from the pseudocode; the CPU owner evaluates
    /// them against live state.
    pub(crate) fn execution_access_requirements(&self) -> ScalableAccessRequirements {
        use ScalableAccessCheck::{
            SmeAndZaEnabled, SmeEnabled, SmeZt0Enabled, StreamingSveAndZaEnabled,
            StreamingSveEnabled,
        };

        match self {
            Self::Vectors(_) => ScalableAccessRequirements::Known(Box::new([StreamingSveEnabled])),
            Self::Tile(_) => {
                ScalableAccessRequirements::Known(Box::new([StreamingSveAndZaEnabled]))
            }
            Self::ZaVector(_) => ScalableAccessRequirements::Known(Box::new([SmeAndZaEnabled])),
            Self::Zt(_) => ScalableAccessRequirements::Known(Box::new([SmeEnabled, SmeZt0Enabled])),
        }
    }
}

pub fn decode(word: u32) -> Option<Operand> {
    if word & VECTOR_GROUP_MASK != VECTOR_GROUP_CLASS {
        return decode_za(word);
    }
    let immediate = word & IMMEDIATE_BIT != 0;
    let four = word & FOUR_REGISTERS_BIT != 0;
    if (immediate && word & IMMEDIATE_RESERVED_BIT != 0)
        || (four && word & FOUR_REGISTERS_RESERVED_BIT != 0)
    {
        return None;
    }
    let offset = if immediate {
        let raw = ((word >> OFFSET_SHIFT) & IMMEDIATE_MASK) as i8;
        let shift = i8::BITS - IMMEDIATE_BITS;
        Offset::VectorGroups((raw << shift) >> shift)
    } else {
        Offset::Register(register((word >> OFFSET_SHIFT) & REGISTER_MASK, false))
    };
    let low_mask = if four {
        FOUR_REGISTER_LOW_MASK
    } else {
        TWO_REGISTER_LOW_MASK
    };
    let first = (word & low_mask) as u8
        + if word & HIGH_REGISTER_BIT != 0 {
            HIGH_REGISTER_BASE
        } else {
            0
        };
    Some(Operand::Vectors(VectorTransfer {
        direction: if word & STORE_BIT != 0 {
            Direction::Store
        } else {
            Direction::Load
        },
        non_temporal: word & NON_TEMPORAL_BIT != 0,
        element: match (word >> SIZE_SHIFT) & SIZE_MASK {
            0 => ElementSize::Byte,
            1 => ElementSize::Halfword,
            2 => ElementSize::Word,
            _ => ElementSize::Doubleword,
        },
        registers: VectorGroup {
            first,
            count: if four { 4 } else { 2 },
            stride: if four { 4 } else { 8 },
        },
        predicate: COUNTER_PREDICATE_BASE + ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8,
        address: Address {
            base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
            offset,
        },
    }))
}

fn direction(word: u32) -> Direction {
    if word & STORE_BIT != 0 {
        Direction::Store
    } else {
        Direction::Load
    }
}

fn decode_za(word: u32) -> Option<Operand> {
    let base = register((word >> BASE_SHIFT) & REGISTER_MASK, true);
    let direction = direction(word);
    if word & ZT_MASK & !STORE_BIT == ZT_CLASS {
        return Some(Operand::Zt(ZtTransfer { direction, base }));
    }
    let slice_register =
        SLICE_SELECTOR_BASE + ((word >> SLICE_SELECTOR_SHIFT) & SLICE_SELECTOR_MASK) as u8;
    if word & ZA_VECTOR_MASK & !STORE_BIT == ZA_VECTOR_CLASS {
        return Some(Operand::ZaVector(ZaVectorTransfer {
            direction,
            base,
            vector_register: slice_register,
            offset: (word & IMMEDIATE_MASK) as u8,
        }));
    }
    let element = match word & TILE_MASK & !STORE_BIT {
        TILE_BYTE_CLASS => ElementSize::Byte,
        TILE_HALFWORD_CLASS => ElementSize::Halfword,
        TILE_WORD_CLASS => ElementSize::Word,
        TILE_DOUBLEWORD_CLASS => ElementSize::Doubleword,
        TILE_QUADWORD_CLASS => ElementSize::Quadword,
        _ => return None,
    };
    let offset_bits = TILE_SELECTOR_BITS - element.bytes().trailing_zeros();
    Some(Operand::Tile(TileTransfer {
        direction,
        element,
        tile: ((word & IMMEDIATE_MASK) >> offset_bits) as u8,
        vertical: word & VERTICAL_BIT != 0,
        slice_register,
        slice_offset: (word & ((1 << offset_bits) - 1)) as u8,
        predicate: ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8,
        address: Address {
            base,
            offset: Offset::Register(register((word >> OFFSET_SHIFT) & REGISTER_MASK, false)),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod execution_access {
        use super::*;
        use alloc::vec::Vec;

        const ORIGINAL_SP_BASE: u32 = REGISTER_MASK << BASE_SHIFT;

        #[test]
        fn source_helpers_preserve_group_and_zt_order() {
            use ScalableAccessCheck::{
                SmeAndZaEnabled, SmeEnabled, SmeZt0Enabled, StreamingSveAndZaEnabled,
                StreamingSveEnabled,
            };

            let cases: &[(u32, &[ScalableAccessCheck])] = &[
                (VECTOR_GROUP_CLASS, &[StreamingSveEnabled]),
                (TILE_BYTE_CLASS, &[StreamingSveAndZaEnabled]),
                (ZA_VECTOR_CLASS, &[SmeAndZaEnabled]),
                (ZT_CLASS, &[SmeEnabled, SmeZt0Enabled]),
            ];
            for &(class, expected) in cases {
                for direction in [0, STORE_BIT] {
                    for base in [0, ORIGINAL_SP_BASE] {
                        let operand =
                            decode(class | direction | base).expect("valid memory operand");
                        assert_eq!(
                            operand.execution_access_requirements(),
                            ScalableAccessRequirements::Known(expected.into())
                        );
                    }
                }
            }
        }

        #[test]
        fn guest_quantity_uses_elements_and_whole_transfer_bytes() {
            let mut cases = Vec::new();
            for element in [
                ElementSize::Byte,
                ElementSize::Halfword,
                ElementSize::Word,
                ElementSize::Doubleword,
            ] {
                let encoded_size = element.bytes().trailing_zeros() << SIZE_SHIFT;
                cases.push((VECTOR_GROUP_CLASS | encoded_size, element));
            }
            cases.extend([
                (TILE_BYTE_CLASS, ElementSize::Byte),
                (TILE_HALFWORD_CLASS, ElementSize::Halfword),
                (TILE_WORD_CLASS, ElementSize::Word),
                (TILE_DOUBLEWORD_CLASS, ElementSize::Doubleword),
                (TILE_QUADWORD_CLASS, ElementSize::Quadword),
                (ZA_VECTOR_CLASS, ElementSize::Byte),
                (ZT_CLASS, ElementSize::Byte),
            ]);
            for (class, element) in cases {
                for direction in [0, STORE_BIT] {
                    for base in [0, ORIGINAL_SP_BASE] {
                        let operand =
                            decode(class | direction | base).expect("valid memory operand");
                        assert_eq!(
                            operand.guest_memory_quantity(),
                            GuestMemoryQuantity::Maximum(element)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn vector_group_fields_preserve_nonconsecutive_registers_and_counter_role() {
        for four in [false, true] {
            for high in [false, true] {
                for low in 0..=if four {
                    FOUR_REGISTER_LOW_MASK
                } else {
                    TWO_REGISTER_LOW_MASK
                } {
                    for size in 0..=SIZE_MASK {
                        for predicate in 0..=PREDICATE_MASK {
                            let word = VECTOR_GROUP_CLASS
                                | (size << SIZE_SHIFT)
                                | (predicate << PREDICATE_SHIFT)
                                | (REGISTER_MASK << BASE_SHIFT)
                                | low
                                | if four { FOUR_REGISTERS_BIT } else { 0 }
                                | if high { HIGH_REGISTER_BIT } else { 0 };
                            let Some(Operand::Vectors(transfer)) = decode(word) else {
                                panic!("allocated vector group {word:08x}");
                            };
                            assert_eq!(
                                transfer.registers,
                                VectorGroup {
                                    first: low as u8 + if high { HIGH_REGISTER_BASE } else { 0 },
                                    count: if four { 4 } else { 2 },
                                    stride: if four { 4 } else { 8 },
                                }
                            );
                            assert_eq!(
                                transfer.predicate,
                                COUNTER_PREDICATE_BASE + predicate as u8
                            );
                            assert_eq!(transfer.element.bytes(), 1 << size);
                            assert_eq!(transfer.address.base, Register::Sp);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn signed_group_offsets_and_register_zero_are_distinct() {
        for raw in 0..=IMMEDIATE_MASK {
            let Some(Operand::Vectors(transfer)) =
                decode(VECTOR_GROUP_CLASS | IMMEDIATE_BIT | (raw << OFFSET_SHIFT))
            else {
                panic!()
            };
            let expected = if raw < (1 << (IMMEDIATE_BITS - 1)) {
                raw as i8
            } else {
                raw as i8 - (1 << IMMEDIATE_BITS)
            };
            assert_eq!(transfer.address.offset, Offset::VectorGroups(expected));
        }
        let Some(Operand::Vectors(transfer)) =
            decode(VECTOR_GROUP_CLASS | (REGISTER_MASK << OFFSET_SHIFT))
        else {
            panic!()
        };
        assert_eq!(transfer.address.offset, Offset::Register(Register::Zero));
        assert!(decode(VECTOR_GROUP_CLASS | IMMEDIATE_BIT | IMMEDIATE_RESERVED_BIT).is_none());
        assert!(
            decode(VECTOR_GROUP_CLASS | FOUR_REGISTERS_BIT | FOUR_REGISTERS_RESERVED_BIT).is_none()
        );
    }

    #[test]
    fn za_tiles_split_the_low_selector_by_element_width() {
        for (class, bytes) in [
            (TILE_BYTE_CLASS, 1_u8),
            (TILE_HALFWORD_CLASS, 2),
            (TILE_WORD_CLASS, 4),
            (TILE_DOUBLEWORD_CLASS, 8),
            (TILE_QUADWORD_CLASS, 16),
        ] {
            for store in [0, STORE_BIT] {
                for selector in 0..=IMMEDIATE_MASK {
                    let word = class
                        | store
                        | selector
                        | VERTICAL_BIT
                        | (SLICE_SELECTOR_MASK << SLICE_SELECTOR_SHIFT)
                        | (PREDICATE_MASK << PREDICATE_SHIFT)
                        | (REGISTER_MASK << BASE_SHIFT)
                        | (REGISTER_MASK << OFFSET_SHIFT);
                    let Some(Operand::Tile(tile)) = decode(word) else {
                        panic!()
                    };
                    assert_eq!(tile.element.bytes(), usize::from(bytes));
                    assert_eq!(tile.tile, selector as u8 / (16 / bytes));
                    assert_eq!(tile.slice_offset, selector as u8 % (16 / bytes));
                    assert_eq!(tile.slice_register, 15);
                    assert_eq!(tile.predicate, 7);
                    assert!(tile.vertical);
                    assert_eq!(tile.address.base, Register::Sp);
                    assert_eq!(tile.address.offset, Offset::Register(Register::Zero));
                }
            }
        }
        for reserved in [0xe100_0000, 0xe140_0000, 0xe180_0000] {
            assert!(!matches!(decode(reserved), Some(Operand::Tile(_))));
        }
    }

    #[test]
    fn whole_za_and_zt_transfers_keep_distinct_selector_contracts() {
        for store in [0, STORE_BIT] {
            let direction = direction(store);
            let base = Register::Sp;
            assert_eq!(
                decode(ZT_CLASS | store | (REGISTER_MASK << BASE_SHIFT)),
                Some(Operand::Zt(ZtTransfer { direction, base }))
            );
            assert_eq!(
                decode(
                    ZA_VECTOR_CLASS
                        | store
                        | (REGISTER_MASK << BASE_SHIFT)
                        | (SLICE_SELECTOR_MASK << SLICE_SELECTOR_SHIFT)
                        | IMMEDIATE_MASK
                ),
                Some(Operand::ZaVector(ZaVectorTransfer {
                    direction,
                    base,
                    vector_register: 15,
                    offset: 15,
                }))
            );
        }
    }
}
