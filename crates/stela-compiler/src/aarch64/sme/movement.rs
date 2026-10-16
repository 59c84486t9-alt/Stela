//! SME ZA movement and zeroing. Decoding retains mode and debug requirements.
//!
//! ZA vectors are physical byte rows. Tile aliases and vertical slices are
//! interpreted by the shared scalable-state backend, never independent storage.

use crate::aarch64::scalable::{ElementSize, Predication};

const GPR_INDEX_TILE_BASE: u8 = 12;
const GPR_INDEX_VECTOR_BASE: u8 = 8;
const MINIMUM_SVL_BITS: u16 = 128;
const QUAD_DOUBLE_MINIMUM_SVL_BITS: u16 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    Sme,
    Sme2,
    Sme2p1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToZa,
    FromZa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Tile {
        direction: Direction,
        element: ElementSize,
        tile: u8,
        vertical: bool,
        index: u8,
        offset: u8,
        vector: u8,
        count: u8,
        predication: Predication,
        zero_source: bool,
    },
    Vectors {
        direction: Direction,
        index: u8,
        offset: u8,
        vector: u8,
        count: u8,
        zero_source: bool,
    },
    ZeroVectors {
        index: u8,
        offset: u8,
        vectors_per_group: u8,
        groups: u8,
    },
    ZeroTiles {
        mask: u8,
    },
    ZeroTable,
    TableGpr {
        direction: Direction,
        register: u8,
        lane: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirements {
    pub feature: Feature,
    pub streaming: bool,
    pub za: bool,
    pub zt0: bool,
    pub halted: bool,
    pub minimum_implemented_svl_bits: u16,
    pub minimum_current_svl_bits: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub canonical_id: &'static str,
    pub kind: Kind,
    pub requirements: Requirements,
}

const INDEX_SELECTOR_SHIFT: u32 = 13;
const INDEX_SELECTOR_MASK: u32 = 3;
const VERTICAL_SHIFT: u32 = 15;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const VECTOR_SOURCE_SHIFT: u32 = 5;
const VECTOR_REGISTER_MASK: u32 = 31;
const TILE_OPERAND_BITS: u8 = 4;
const TABLE_LANE_SHIFT: u32 = 12;
const TABLE_LANE_MASK: u32 = 7;
const ARRAY_OFFSET_MASK: u32 = 7;

#[derive(Clone, Copy)]
enum Class {
    TileToZa,
    TileFromZa,
    TileFromZaZero,
    VectorToZa,
    VectorFromZa,
    VectorFromZaZero,
    ZeroVectors,
    ZeroTiles,
    ZeroTable,
    TableToGpr,
    GprToTable,
}
#[derive(Clone, Copy)]
struct Encoding {
    id: &'static str,
    mask: u32,
    value: u32,
    class: Class,
    feature: Feature,
    element: ElementSize,
    count: u8,
    groups: u8,
}

pub fn decode(word: u32) -> Option<Operand> {
    let e = ENCODINGS.iter().find(|e| word & e.mask == e.value)?;
    let selector = ((word >> INDEX_SELECTOR_SHIFT) & INDEX_SELECTOR_MASK) as u8;
    let to_za = matches!(e.class, Class::TileToZa | Class::VectorToZa);
    let vector = if to_za {
        word >> VECTOR_SOURCE_SHIFT
    } else {
        word
    };
    let vector = (vector & VECTOR_REGISTER_MASK) as u8;
    let kind = match e.class {
        Class::TileToZa | Class::TileFromZa | Class::TileFromZaZero => {
            let predicated = e.count == 1 && !matches!(e.class, Class::TileFromZaZero);
            let combined = if to_za {
                word
            } else {
                word >> VECTOR_SOURCE_SHIFT
            };
            let element_log = e.element.bytes().trailing_zeros() as u8;
            let count_log = e.count.trailing_zeros() as u8;
            let offset_bits = TILE_OPERAND_BITS.saturating_sub(element_log + count_log);
            let offset_mask = (1_u32 << offset_bits) - 1;
            let tile_mask = (1_u32 << element_log) - 1;
            Kind::Tile {
                direction: if to_za {
                    Direction::ToZa
                } else {
                    Direction::FromZa
                },
                element: e.element,
                tile: ((combined >> offset_bits) & tile_mask) as u8,
                vertical: word & (1 << VERTICAL_SHIFT) != 0,
                index: GPR_INDEX_TILE_BASE + selector,
                offset: (combined & offset_mask) as u8 * e.count,
                vector,
                count: e.count,
                predication: if predicated {
                    Predication::Merging(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8)
                } else {
                    Predication::Unpredicated
                },
                zero_source: matches!(e.class, Class::TileFromZaZero),
            }
        }
        Class::VectorToZa | Class::VectorFromZa | Class::VectorFromZaZero => {
            let offset_word = if to_za {
                word
            } else {
                word >> VECTOR_SOURCE_SHIFT
            };
            Kind::Vectors {
                direction: if to_za {
                    Direction::ToZa
                } else {
                    Direction::FromZa
                },
                index: GPR_INDEX_VECTOR_BASE + selector,
                offset: (offset_word & ARRAY_OFFSET_MASK) as u8,
                vector,
                count: e.count,
                zero_source: matches!(e.class, Class::VectorFromZaZero),
            }
        }
        Class::ZeroVectors => {
            let offset_mask = !e.mask & ARRAY_OFFSET_MASK;
            Kind::ZeroVectors {
                index: GPR_INDEX_VECTOR_BASE + selector,
                offset: (word & offset_mask) as u8 * e.count,
                vectors_per_group: e.count,
                groups: e.groups,
            }
        }
        Class::ZeroTiles => Kind::ZeroTiles { mask: word as u8 },
        Class::ZeroTable => Kind::ZeroTable,
        Class::TableToGpr | Class::GprToTable => Kind::TableGpr {
            direction: if matches!(e.class, Class::GprToTable) {
                Direction::ToZa
            } else {
                Direction::FromZa
            },
            register: vector,
            lane: ((word >> TABLE_LANE_SHIFT) & TABLE_LANE_MASK) as u8,
        },
    };
    let table = matches!(kind, Kind::ZeroTable | Kind::TableGpr { .. });
    let limited = matches!(
        kind,
        Kind::Tile {
            count: 4,
            element: ElementSize::Doubleword,
            ..
        }
    );
    let minimum_svl = if limited {
        QUAD_DOUBLE_MINIMUM_SVL_BITS
    } else {
        MINIMUM_SVL_BITS
    };
    Some(Operand {
        canonical_id: e.id,
        kind,
        requirements: Requirements {
            feature: e.feature,
            streaming: !table && !matches!(kind, Kind::ZeroTiles { .. }),
            za: true,
            zt0: table,
            halted: matches!(kind, Kind::TableGpr { .. }),
            minimum_implemented_svl_bits: minimum_svl,
            minimum_current_svl_bits: minimum_svl,
        },
    })
}

// Fixed encoding facts only; all operand extraction is shared above.
macro_rules! forms {
    ($( $id:ident $mask:literal $value:literal $class:ident $feature:ident $element:ident $count:literal $groups:literal; )*) => {
        &[$(Encoding { id: stringify!($id), mask: $mask, value: $value,
            class: Class::$class, feature: Feature::$feature,
            element: ElementSize::$element, count: $count, groups: $groups }),*]
    };
}
const ENCODINGS: &[Encoding] = forms! {
    mova_mz2_za_b1 0xffff_1f01 0xc006_0000 TileFromZa Sme2 Byte 2 1;
    mova_mz2_za_d1 0xffff_1f01 0xc0c6_0000 TileFromZa Sme2 Doubleword 2 1;
    mova_mz2_za_h1 0xffff_1f01 0xc046_0000 TileFromZa Sme2 Halfword 2 1;
    mova_mz2_za_w1 0xffff_1f01 0xc086_0000 TileFromZa Sme2 Word 2 1;
    mova_mz4_za_b1 0xffff_1f83 0xc006_0400 TileFromZa Sme2 Byte 4 1;
    mova_mz4_za_d1 0xffff_1f03 0xc0c6_0400 TileFromZa Sme2 Doubleword 4 1;
    mova_mz4_za_h1 0xffff_1f83 0xc046_0400 TileFromZa Sme2 Halfword 4 1;
    mova_mz4_za_w1 0xffff_1f83 0xc086_0400 TileFromZa Sme2 Word 4 1;
    mova_mz_za2_1 0xffff_9f01 0xc006_0800 VectorFromZa Sme2 Byte 2 1;
    mova_mz_za4_1 0xffff_9f03 0xc006_0c00 VectorFromZa Sme2 Byte 4 1;
    mova_z_p_rza_b 0xffff_0200 0xc002_0000 TileFromZa Sme Byte 1 1;
    mova_z_p_rza_d 0xffff_0200 0xc0c2_0000 TileFromZa Sme Doubleword 1 1;
    mova_z_p_rza_h 0xffff_0200 0xc042_0000 TileFromZa Sme Halfword 1 1;
    mova_z_p_rza_q 0xffff_0200 0xc0c3_0000 TileFromZa Sme Quadword 1 1;
    mova_z_p_rza_w 0xffff_0200 0xc082_0000 TileFromZa Sme Word 1 1;
    mova_za2_z_b1 0xffff_1c38 0xc004_0000 TileToZa Sme2 Byte 2 1;
    mova_za2_z_d1 0xffff_1c38 0xc0c4_0000 TileToZa Sme2 Doubleword 2 1;
    mova_za2_z_h1 0xffff_1c38 0xc044_0000 TileToZa Sme2 Halfword 2 1;
    mova_za2_z_w1 0xffff_1c38 0xc084_0000 TileToZa Sme2 Word 2 1;
    mova_za4_z_b1 0xffff_1c7c 0xc004_0400 TileToZa Sme2 Byte 4 1;
    mova_za4_z_d1 0xffff_1c78 0xc0c4_0400 TileToZa Sme2 Doubleword 4 1;
    mova_za4_z_h1 0xffff_1c7c 0xc044_0400 TileToZa Sme2 Halfword 4 1;
    mova_za4_z_w1 0xffff_1c7c 0xc084_0400 TileToZa Sme2 Word 4 1;
    mova_za_mz2_1 0xffff_9c38 0xc004_0800 VectorToZa Sme2 Byte 2 1;
    mova_za_mz4_1 0xffff_9c78 0xc004_0c00 VectorToZa Sme2 Byte 4 1;
    mova_za_p_rz_b 0xffff_0010 0xc000_0000 TileToZa Sme Byte 1 1;
    mova_za_p_rz_d 0xffff_0010 0xc0c0_0000 TileToZa Sme Doubleword 1 1;
    mova_za_p_rz_h 0xffff_0010 0xc040_0000 TileToZa Sme Halfword 1 1;
    mova_za_p_rz_q 0xffff_0010 0xc0c1_0000 TileToZa Sme Quadword 1 1;
    mova_za_p_rz_w 0xffff_0010 0xc080_0000 TileToZa Sme Word 1 1;
    movaz_mz2_za_b1 0xffff_1f01 0xc006_0200 TileFromZaZero Sme2p1 Byte 2 1;
    movaz_mz2_za_d1 0xffff_1f01 0xc0c6_0200 TileFromZaZero Sme2p1 Doubleword 2 1;
    movaz_mz2_za_h1 0xffff_1f01 0xc046_0200 TileFromZaZero Sme2p1 Halfword 2 1;
    movaz_mz2_za_w1 0xffff_1f01 0xc086_0200 TileFromZaZero Sme2p1 Word 2 1;
    movaz_mz4_za_b1 0xffff_1f83 0xc006_0600 TileFromZaZero Sme2p1 Byte 4 1;
    movaz_mz4_za_d1 0xffff_1f03 0xc0c6_0600 TileFromZaZero Sme2p1 Doubleword 4 1;
    movaz_mz4_za_h1 0xffff_1f83 0xc046_0600 TileFromZaZero Sme2p1 Halfword 4 1;
    movaz_mz4_za_w1 0xffff_1f83 0xc086_0600 TileFromZaZero Sme2p1 Word 4 1;
    movaz_mz_za2_1 0xffff_9f01 0xc006_0a00 VectorFromZaZero Sme2p1 Byte 2 1;
    movaz_mz_za4_1 0xffff_9f03 0xc006_0e00 VectorFromZaZero Sme2p1 Byte 4 1;
    movaz_z_rza_b 0xffff_1e00 0xc002_0200 TileFromZaZero Sme2p1 Byte 1 1;
    movaz_z_rza_d 0xffff_1e00 0xc0c2_0200 TileFromZaZero Sme2p1 Doubleword 1 1;
    movaz_z_rza_h 0xffff_1e00 0xc042_0200 TileFromZaZero Sme2p1 Halfword 1 1;
    movaz_z_rza_q 0xffff_1e00 0xc0c3_0200 TileFromZaZero Sme2p1 Quadword 1 1;
    movaz_z_rza_w 0xffff_1e00 0xc082_0200 TileFromZaZero Sme2p1 Word 1 1;
    movt_r_zt_ 0xffff_8fe0 0xc04c_03e0 TableToGpr Sme2 Byte 1 1;
    movt_zt_r_ 0xffff_8fe0 0xc04e_03e0 GprToTable Sme2 Byte 1 1;
    zero_za1_ri_2 0xffff_9ff8 0xc00c_0000 ZeroVectors Sme2p1 Byte 1 2;
    zero_za1_ri_4 0xffff_9ff8 0xc00e_0000 ZeroVectors Sme2p1 Byte 1 4;
    zero_za2_ri_1 0xffff_9ff8 0xc00c_8000 ZeroVectors Sme2p1 Byte 2 1;
    zero_za2_ri_2 0xffff_9ffc 0xc00d_0000 ZeroVectors Sme2p1 Byte 2 2;
    zero_za2_ri_4 0xffff_9ffc 0xc00d_8000 ZeroVectors Sme2p1 Byte 2 4;
    zero_za4_ri_1 0xffff_9ffc 0xc00e_8000 ZeroVectors Sme2p1 Byte 4 1;
    zero_za4_ri_2 0xffff_9ffe 0xc00f_0000 ZeroVectors Sme2p1 Byte 4 2;
    zero_za4_ri_4 0xffff_9ffe 0xc00f_8000 ZeroVectors Sme2p1 Byte 4 4;
    zero_za_i_ 0xffff_ff00 0xc008_0000 ZeroTiles Sme Doubleword 1 1;
    zero_zt_i_ 0xffff_ffff 0xc048_0001 ZeroTable Sme2 Byte 1 1;
};

#[cfg(test)]
mod tests;
