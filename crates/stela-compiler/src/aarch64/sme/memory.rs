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
mod tests;
