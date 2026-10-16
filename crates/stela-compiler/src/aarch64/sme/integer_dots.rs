//! SME2 integer dot products into ZA single-vector groups.
//!
//! This decoder performs structural decoding only. Execution must check
//! streaming mode, ZA enablement, SME2, and I16I64 for 64-bit accumulators.

use crate::aarch64::scalable::ElementSize;

const VECTOR_SEGMENT_BITS: usize = 128;
const SELECTOR_SHIFT: u32 = 13;
const SELECTOR_MASK: u32 = 3;
const FIRST_SELECTOR_REGISTER: u8 = 8;
const OFFSET_MASK: u32 = 7;
const INDEX_SHIFT: u32 = 10;
const SIZE_SHIFT: u32 = 22;
const Z_REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const INDEXED_REGISTER_MASK: u32 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dot,
    VerticalDot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RightSource {
    Vector(u8),
    Group(u8),
    Indexed { register: u8, index: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub accumulator: ElementSize,
    pub terms: u8,
    pub groups: u8,
    pub left_signed: bool,
    pub right_signed: bool,
    pub left: u8,
    pub right: RightSource,
    pub selector: u8,
    pub offset: u8,
}

#[derive(Debug, Clone, Copy)]
struct Encoding {
    mask: u32,
    value: u32,
    accumulator_bits: u8,
    dynamic_size: bool,
    terms: u8,
    groups: u8,
    vertical: bool,
    left_signed: bool,
    right_signed: bool,
    left_shift: u32,
    left_mask: u32,
    left_scale: u8,
    right_shift: u32,
    right_mask: u32,
    right_scale: u8,
    right_kind: SourceKind,
}

#[derive(Debug, Clone, Copy)]
enum SourceKind {
    Vector,
    Group,
    Indexed,
}

#[derive(Debug, Clone, Copy)]
enum Accumulator {
    Word,
    Doubleword,
    Variable,
}

#[derive(Debug, Clone, Copy)]
enum Shape {
    IndexedPair,
    IndexedQuartet,
    VectorPair,
    VectorQuartet,
    GroupPair,
    GroupQuartet,
    VerticalPair,
    VerticalQuartet,
}

#[derive(Debug, Clone, Copy)]
enum Product {
    SignedHalf,
    UnsignedHalf,
    SignedQuarter,
    UnsignedQuarter,
    SignedUnsignedQuarter,
    UnsignedSignedQuarter,
}

impl Encoding {
    const fn new(
        mask: u32,
        value: u32,
        accumulator: Accumulator,
        shape: Shape,
        product: Product,
    ) -> Self {
        let (groups, right_kind, vertical, left_aligned) = match shape {
            Shape::IndexedPair => (2, SourceKind::Indexed, false, true),
            Shape::IndexedQuartet => (4, SourceKind::Indexed, false, true),
            Shape::VectorPair => (2, SourceKind::Vector, false, false),
            Shape::VectorQuartet => (4, SourceKind::Vector, false, false),
            Shape::GroupPair => (2, SourceKind::Group, false, true),
            Shape::GroupQuartet => (4, SourceKind::Group, false, true),
            Shape::VerticalPair => (2, SourceKind::Indexed, true, true),
            Shape::VerticalQuartet => (4, SourceKind::Indexed, true, true),
        };
        let (terms, left_signed, right_signed) = match product {
            Product::SignedHalf => (2, true, true),
            Product::UnsignedHalf => (2, false, false),
            Product::SignedQuarter => (4, true, true),
            Product::UnsignedQuarter => (4, false, false),
            Product::SignedUnsignedQuarter => (4, true, false),
            Product::UnsignedSignedQuarter => (4, false, true),
        };
        let group_shift = if groups == 2 { 1 } else { 2 };
        let left_scale = if left_aligned { groups } else { 1 };
        let right_grouped = matches!(right_kind, SourceKind::Group);
        let right_scale = if right_grouped { groups } else { 1 };
        Self {
            mask,
            value,
            accumulator_bits: if matches!(accumulator, Accumulator::Doubleword) {
                ElementSize::Doubleword.bits() as u8
            } else {
                ElementSize::Word.bits() as u8
            },
            dynamic_size: matches!(accumulator, Accumulator::Variable),
            terms,
            groups,
            vertical,
            left_signed,
            right_signed,
            left_shift: SOURCE_SHIFT + if left_aligned { group_shift } else { 0 },
            left_mask: Z_REGISTER_MASK / left_scale as u32,
            left_scale,
            right_shift: RIGHT_SHIFT + if right_grouped { group_shift } else { 0 },
            right_mask: if right_grouped {
                Z_REGISTER_MASK / groups as u32
            } else {
                INDEXED_REGISTER_MASK
            },
            right_scale,
            right_kind,
        }
    }
}

// The compact table names the operand layout and arithmetic separately; shared
// field derivation does not interpret mnemonic text or modify canonical bits.
macro_rules! encoding {
    ($mask:expr, $value:expr, $acc:ident, $shape:ident, $product:ident) => {
        Encoding::new(
            $mask,
            $value,
            Accumulator::$acc,
            Shape::$shape,
            Product::$product,
        )
    };
}

const ENCODINGS: [Encoding; 46] = [
    encoding!(0xfff0_9038, 0xc150_1000, Word, IndexedPair, SignedHalf), // sdot_za32_zzi_2xi
    encoding!(0xfff0_9078, 0xc150_9000, Word, IndexedQuartet, SignedHalf), // sdot_za32_zzi_4xi
    encoding!(0xfff0_9c18, 0xc160_1408, Word, VectorPair, SignedHalf),  // sdot_za32_zzv_2x1
    encoding!(0xfff0_9c18, 0xc170_1408, Word, VectorQuartet, SignedHalf), // sdot_za32_zzv_4x1
    encoding!(0xffe1_9c38, 0xc1e0_1408, Word, GroupPair, SignedHalf),   // sdot_za32_zzw_2x2
    encoding!(0xffe3_9c78, 0xc1e1_1408, Word, GroupQuartet, SignedHalf), // sdot_za32_zzw_4x4
    encoding!(0xfff0_9038, 0xc150_1020, Word, IndexedPair, SignedQuarter), // sdot_za_zzi_s2xi
    encoding!(
        0xfff0_9838,
        0xc1d0_0008,
        Doubleword,
        IndexedPair,
        SignedQuarter
    ), // sdot_za_zzi_d2xi
    encoding!(
        0xfff0_9078,
        0xc150_9020,
        Word,
        IndexedQuartet,
        SignedQuarter
    ), // sdot_za_zzi_s4xi
    encoding!(
        0xfff0_9878,
        0xc1d0_8008,
        Doubleword,
        IndexedQuartet,
        SignedQuarter
    ), // sdot_za_zzi_d4xi
    encoding!(
        0xffb0_9c18,
        0xc120_1400,
        Variable,
        VectorPair,
        SignedQuarter
    ), // sdot_za_zzv_2x1
    encoding!(
        0xffb0_9c18,
        0xc130_1400,
        Variable,
        VectorQuartet,
        SignedQuarter
    ), // sdot_za_zzv_4x1
    encoding!(0xffa1_9c38, 0xc1a0_1400, Variable, GroupPair, SignedQuarter), // sdot_za_zzw_2x2
    encoding!(
        0xffa3_9c78,
        0xc1a1_1400,
        Variable,
        GroupQuartet,
        SignedQuarter
    ), // sdot_za_zzw_4x4
    encoding!(
        0xfff0_9038,
        0xc150_1038,
        Word,
        IndexedPair,
        SignedUnsignedQuarter
    ), // sudot_za_zzi_s2xi
    encoding!(
        0xfff0_9078,
        0xc150_9038,
        Word,
        IndexedQuartet,
        SignedUnsignedQuarter
    ), // sudot_za_zzi_s4xi
    encoding!(
        0xfff0_9c18,
        0xc120_1418,
        Word,
        VectorPair,
        SignedUnsignedQuarter
    ), // sudot_za_zzv_s2x1
    encoding!(
        0xfff0_9c18,
        0xc130_1418,
        Word,
        VectorQuartet,
        SignedUnsignedQuarter
    ), // sudot_za_zzv_s4x1
    encoding!(
        0xfff0_9078,
        0xc150_8038,
        Word,
        VerticalQuartet,
        SignedUnsignedQuarter
    ), // suvdot_za_zzi_s4xi
    encoding!(0xfff0_9038, 0xc150_0020, Word, VerticalPair, SignedHalf), // svdot_za32_zzi_2xi
    encoding!(
        0xfff0_9078,
        0xc150_8020,
        Word,
        VerticalQuartet,
        SignedQuarter
    ), // svdot_za_zzi_s4xi
    encoding!(
        0xfff0_9878,
        0xc1d0_8808,
        Doubleword,
        VerticalQuartet,
        SignedQuarter
    ), // svdot_za_zzi_d4xi
    encoding!(0xfff0_9038, 0xc150_1010, Word, IndexedPair, UnsignedHalf), // udot_za32_zzi_2xi
    encoding!(0xfff0_9078, 0xc150_9010, Word, IndexedQuartet, UnsignedHalf), // udot_za32_zzi_4xi
    encoding!(0xfff0_9c18, 0xc160_1418, Word, VectorPair, UnsignedHalf), // udot_za32_zzv_2x1
    encoding!(0xfff0_9c18, 0xc170_1418, Word, VectorQuartet, UnsignedHalf), // udot_za32_zzv_4x1
    encoding!(0xffe1_9c38, 0xc1e0_1418, Word, GroupPair, UnsignedHalf), // udot_za32_zzw_2x2
    encoding!(0xffe3_9c78, 0xc1e1_1418, Word, GroupQuartet, UnsignedHalf), // udot_za32_zzw_4x4
    encoding!(0xfff0_9038, 0xc150_1030, Word, IndexedPair, UnsignedQuarter), // udot_za_zzi_s2xi
    encoding!(
        0xfff0_9838,
        0xc1d0_0018,
        Doubleword,
        IndexedPair,
        UnsignedQuarter
    ), // udot_za_zzi_d2xi
    encoding!(
        0xfff0_9078,
        0xc150_9030,
        Word,
        IndexedQuartet,
        UnsignedQuarter
    ), // udot_za_zzi_s4xi
    encoding!(
        0xfff0_9878,
        0xc1d0_8018,
        Doubleword,
        IndexedQuartet,
        UnsignedQuarter
    ), // udot_za_zzi_d4xi
    encoding!(
        0xffb0_9c18,
        0xc120_1410,
        Variable,
        VectorPair,
        UnsignedQuarter
    ), // udot_za_zzv_2x1
    encoding!(
        0xffb0_9c18,
        0xc130_1410,
        Variable,
        VectorQuartet,
        UnsignedQuarter
    ), // udot_za_zzv_4x1
    encoding!(
        0xffa1_9c38,
        0xc1a0_1410,
        Variable,
        GroupPair,
        UnsignedQuarter
    ), // udot_za_zzw_2x2
    encoding!(
        0xffa3_9c78,
        0xc1a1_1410,
        Variable,
        GroupQuartet,
        UnsignedQuarter
    ), // udot_za_zzw_4x4
    encoding!(
        0xfff0_9038,
        0xc150_1028,
        Word,
        IndexedPair,
        UnsignedSignedQuarter
    ), // usdot_za_zzi_s2xi
    encoding!(
        0xfff0_9078,
        0xc150_9028,
        Word,
        IndexedQuartet,
        UnsignedSignedQuarter
    ), // usdot_za_zzi_s4xi
    encoding!(
        0xfff0_9c18,
        0xc120_1408,
        Word,
        VectorPair,
        UnsignedSignedQuarter
    ), // usdot_za_zzv_s2x1
    encoding!(
        0xfff0_9c18,
        0xc130_1408,
        Word,
        VectorQuartet,
        UnsignedSignedQuarter
    ), // usdot_za_zzv_s4x1
    encoding!(
        0xffe1_9c38,
        0xc1a0_1408,
        Word,
        GroupPair,
        UnsignedSignedQuarter
    ), // usdot_za_zzw_s2x2
    encoding!(
        0xffe3_9c78,
        0xc1a1_1408,
        Word,
        GroupQuartet,
        UnsignedSignedQuarter
    ), // usdot_za_zzw_s4x4
    encoding!(
        0xfff0_9078,
        0xc150_8028,
        Word,
        VerticalQuartet,
        UnsignedSignedQuarter
    ), // usvdot_za_zzi_s4xi
    encoding!(0xfff0_9038, 0xc150_0030, Word, VerticalPair, UnsignedHalf), // uvdot_za32_zzi_2xi
    encoding!(
        0xfff0_9078,
        0xc150_8030,
        Word,
        VerticalQuartet,
        UnsignedQuarter
    ), // uvdot_za_zzi_s4xi
    encoding!(
        0xfff0_9878,
        0xc1d0_8818,
        Doubleword,
        VerticalQuartet,
        UnsignedQuarter
    ), // uvdot_za_zzi_d4xi
];

pub fn decode(word: u32) -> Option<Operand> {
    let encoding = ENCODINGS
        .iter()
        .find(|item| word & item.mask == item.value)?;
    let accumulator_bits = if encoding.dynamic_size {
        encoding.accumulator_bits << ((word >> SIZE_SHIFT) & 1)
    } else {
        encoding.accumulator_bits
    };
    let register =
        (((word >> encoding.right_shift) & encoding.right_mask) as u8) * encoding.right_scale;
    let right = match encoding.right_kind {
        SourceKind::Vector => RightSource::Vector(register),
        SourceKind::Group => RightSource::Group(register),
        SourceKind::Indexed => RightSource::Indexed {
            register,
            index: ((word >> INDEX_SHIFT)
                & (VECTOR_SEGMENT_BITS as u32 / u32::from(accumulator_bits) - 1))
                as u8,
        },
    };
    Some(Operand {
        kind: if encoding.vertical {
            Kind::VerticalDot
        } else {
            Kind::Dot
        },
        accumulator: if accumulator_bits == ElementSize::Doubleword.bits() as u8 {
            ElementSize::Doubleword
        } else {
            ElementSize::Word
        },
        terms: encoding.terms,
        groups: encoding.groups,
        left_signed: encoding.left_signed,
        right_signed: encoding.right_signed,
        left: (((word >> encoding.left_shift) & encoding.left_mask) as u8) * encoding.left_scale,
        right,
        selector: FIRST_SELECTOR_REGISTER + ((word >> SELECTOR_SHIFT) & SELECTOR_MASK) as u8,
        offset: (word & OFFSET_MASK) as u8,
    })
}

impl Operand {
    /// First-source groups in vector forms wrap across Z31; aligned groups do not.
    pub fn left_register(self, group: u8, term: u8) -> u8 {
        let index = if self.kind == Kind::VerticalDot {
            term
        } else {
            group
        };
        (u32::from(self.left) + u32::from(index)) as u8 & Z_REGISTER_MASK as u8
    }

    pub fn right_register(self, group: u8) -> u8 {
        match self.right {
            RightSource::Vector(register) | RightSource::Indexed { register, .. } => register,
            RightSource::Group(register) => register + group,
        }
    }
}

#[cfg(test)]
mod tests;
