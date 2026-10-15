//! SME FP8 arithmetic into ZA. Decoding is independent of execution state.
//!
//! The caller checks SME_F8F16/SME_F8F32 according to `accumulator`, then FPMR
//! access and streaming/ZA access, in that order. These forms do not update FPSR.

use crate::aarch64::{
    floating::Format,
    scalable::{VECTOR_CHUNK_BYTES, VECTOR_REGISTER_COUNT, VectorLength},
};

const SELECTOR_SHIFT: u32 = 13;
const SELECTOR_MASK: u32 = 3;
const FIRST_SELECTOR: u8 = 8;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const REGISTER_MASK: u32 = 31;
const SINGLE_RIGHT_MASK: u32 = 15;
const INDEX_HIGH_SHIFT: u32 = 10;
const INDEX_SINGLE_HIGH_SHIFT: u32 = 15;
const INDEX_LOW_SHIFT: u32 = 3;
const INDEX_PAIR_LOW_SHIFT: u32 = 2;
const INDEX_QUARTET_LOW_SHIFT: u32 = 1;
const OFFSET_MASK: u32 = 7;
const MAX_ROWS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorOperation {
    Dot,
    MultiplyAdd,
    /// Half precision uses `top: false`; single precision has bottom/top forms.
    VerticalDot {
        top: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RightSource {
    Vector(u8),
    Group(u8),
    /// Byte, pair, or quartet index within each 128-bit source segment.
    Indexed {
        register: u8,
        index: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorOperand {
    pub operation: VectorOperation,
    pub accumulator: Format,
    /// Number of destination groups, distinct from the number of source Zs.
    pub groups: u8,
    pub left: u8,
    pub right: RightSource,
    pub vector_select: u8,
    /// Decoded byte-vector offset, including the implicit low zero bits.
    pub offset: u8,
}

impl VectorOperand {
    pub const fn accumulator_bytes(self) -> usize {
        match self.accumulator {
            Format::Half => 2,
            Format::Single => 4,
            Format::Double => 8,
        }
    }

    pub const fn rows_per_group(self) -> u8 {
        match self.operation {
            VectorOperation::MultiplyAdd => self.accumulator_bytes() as u8,
            _ => 1,
        }
    }

    pub const fn row_count(self) -> u8 {
        self.groups * self.rows_per_group()
    }

    pub const fn terms(self) -> u8 {
        match self.operation {
            VectorOperation::MultiplyAdd => 1,
            VectorOperation::VerticalDot { .. } => 2,
            VectorOperation::Dot => self.accumulator_bytes() as u8,
        }
    }

    /// Ordered by destination group, then by adjacent row within that group.
    /// The selector addition is mathematical, before modulo and alignment.
    pub fn rows(self, length: VectorLength, selector: u32) -> [u16; MAX_ROWS] {
        let stride = length.bytes() as u16 / u16::from(self.groups);
        let adjacent = u16::from(self.rows_per_group());
        let base = ((u64::from(selector) + u64::from(self.offset)) % u64::from(stride)) as u16;
        let base = base - base % adjacent;
        let mut rows = [0; MAX_ROWS];
        for group in 0..self.groups {
            for row in 0..self.rows_per_group() {
                rows[usize::from(group * self.rows_per_group() + row)] =
                    base + u16::from(group) * stride + u16::from(row);
            }
        }
        rows
    }

    /// Byte locations of one product. `row` is relative to its ZA group.
    /// Source registers are read before writing ZA; Z/ZA aliasing is impossible.
    pub fn source_bytes(
        self,
        group: u8,
        row: u8,
        element: usize,
        term: u8,
    ) -> Option<(SourceByte, SourceByte)> {
        if group >= self.groups || row >= self.rows_per_group() || term >= self.terms() {
            return None;
        }
        let bytes = self.accumulator_bytes();
        let segment = element / (VECTOR_CHUNK_BYTES / bytes) * VECTOR_CHUNK_BYTES;
        let (left_register, left_byte) = match self.operation {
            VectorOperation::VerticalDot { .. } => {
                (self.left + term, bytes * element + usize::from(group))
            }
            VectorOperation::MultiplyAdd => (
                (self.left + group) % VECTOR_REGISTER_COUNT,
                bytes * element + usize::from(row),
            ),
            VectorOperation::Dot => (
                (self.left + group) % VECTOR_REGISTER_COUNT,
                bytes * element + usize::from(term),
            ),
        };
        let (right_register, right_byte) = match self.right {
            RightSource::Vector(register) => (register, left_byte),
            RightSource::Group(register) => (register + group, left_byte),
            RightSource::Indexed { register, index } => {
                let byte = match self.operation {
                    VectorOperation::MultiplyAdd => segment + usize::from(index),
                    VectorOperation::Dot => {
                        segment + bytes * usize::from(index) + usize::from(term)
                    }
                    VectorOperation::VerticalDot { top } => {
                        segment
                            + bytes * usize::from(index)
                            + if top { 2 } else { 0 }
                            + usize::from(term)
                    }
                };
                (register, byte)
            }
        };
        Some((
            SourceByte {
                register: left_register,
                byte: left_byte,
            },
            SourceByte {
                register: right_register,
                byte: right_byte,
            },
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceByte {
    pub register: u8,
    pub byte: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterOperand {
    pub accumulator: Format,
    pub tile: u8,
    pub left: u8,
    pub right: u8,
    pub row_predicate: u8,
    pub column_predicate: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Vector(VectorOperand),
    Outer(OuterOperand),
}

#[derive(Debug, Clone, Copy)]
enum Layout {
    Indexed,
    Vector,
    Group,
}

#[derive(Debug, Clone, Copy)]
struct Encoding {
    mask: u32,
    value: u32,
    accumulator: Format,
    operation: VectorOperation,
    groups: u8,
    layout: Layout,
}

macro_rules! encoding {
    ($mask:expr, $value:expr, $format:ident, $operation:expr, $groups:expr, $layout:ident) => {
        Encoding {
            mask: $mask,
            value: $value,
            accumulator: Format::$format,
            operation: $operation,
            groups: $groups,
            layout: Layout::$layout,
        }
    };
}

// Exact fixed bits from hash-pinned June 2026 XML. No aliases exist on these pages.
const ENCODINGS: [Encoding; 31] = {
    use VectorOperation::{Dot, MultiplyAdd, VerticalDot};
    [
        encoding!(0xfff0_9038, 0xc150_0038, Single, Dot, 2, Indexed), // fdot_za32_z8z8i_2xi
        encoding!(0xfff0_9078, 0xc150_8008, Single, Dot, 4, Indexed), // fdot_za32_z8z8i_4xi
        encoding!(0xfff0_9c18, 0xc120_1018, Single, Dot, 2, Vector),  // fdot_za32_z8z8v_2x1
        encoding!(0xfff0_9c18, 0xc130_1018, Single, Dot, 4, Vector),  // fdot_za32_z8z8v_4x1
        encoding!(0xffe1_9c38, 0xc1a0_1030, Single, Dot, 2, Group),   // fdot_za32_z8z8w_2x2
        encoding!(0xffe3_9c78, 0xc1a1_1030, Single, Dot, 4, Group),   // fdot_za32_z8z8w_4x4
        encoding!(0xfff0_9030, 0xc1d0_0020, Half, Dot, 2, Indexed),   // fdot_za_z8z8i_2xi
        encoding!(0xfff0_9070, 0xc110_9040, Half, Dot, 4, Indexed),   // fdot_za_z8z8i_4xi
        encoding!(0xfff0_9c18, 0xc120_1008, Half, Dot, 2, Vector),    // fdot_za_z8z8v_2x1
        encoding!(0xfff0_9c18, 0xc130_1008, Half, Dot, 4, Vector),    // fdot_za_z8z8v_4x1
        encoding!(0xffe1_9c38, 0xc1a0_1020, Half, Dot, 2, Group),     // fdot_za_z8z8w_2x2
        encoding!(0xffe3_9c78, 0xc1a1_1020, Half, Dot, 4, Group),     // fdot_za_z8z8w_4x4
        encoding!(0xfff0_1010, 0xc1c0_0000, Half, MultiplyAdd, 1, Indexed), // fmlal_za_z8z8i_1
        encoding!(0xfff0_9030, 0xc190_1030, Half, MultiplyAdd, 2, Indexed), // fmlal_za_z8z8i_2xi
        encoding!(0xfff0_9070, 0xc190_9020, Half, MultiplyAdd, 4, Indexed), // fmlal_za_z8z8i_4xi
        encoding!(0xfff0_9c18, 0xc130_0c00, Half, MultiplyAdd, 1, Vector), // fmlal_za_z8z8v_1
        encoding!(0xfff0_9c1c, 0xc120_0804, Half, MultiplyAdd, 2, Vector), // fmlal_za_z8z8v_2x1
        encoding!(0xfff0_9c1c, 0xc130_0804, Half, MultiplyAdd, 4, Vector), // fmlal_za_z8z8v_4x1
        encoding!(0xffe1_9c3c, 0xc1a0_0820, Half, MultiplyAdd, 2, Group), // fmlal_za_z8z8w_2x2
        encoding!(0xffe3_9c7c, 0xc1a1_0820, Half, MultiplyAdd, 4, Group), // fmlal_za_z8z8w_4x4
        encoding!(0xfff0_001c, 0xc140_0000, Single, MultiplyAdd, 1, Indexed), // fmlall_za32_z8z8i_1
        encoding!(0xfff0_9038, 0xc190_0020, Single, MultiplyAdd, 2, Indexed), // fmlall_za32_z8z8i_2xi
        encoding!(0xfff0_9078, 0xc110_8040, Single, MultiplyAdd, 4, Indexed), // fmlall_za32_z8z8i_4xi
        encoding!(0xfff0_9c1c, 0xc130_0400, Single, MultiplyAdd, 1, Vector),  // fmlall_za32_z8z8v_1
        encoding!(0xfff0_9c1e, 0xc120_0002, Single, MultiplyAdd, 2, Vector), // fmlall_za32_z8z8v_2x1
        encoding!(0xfff0_9c1e, 0xc130_0002, Single, MultiplyAdd, 4, Vector), // fmlall_za32_z8z8v_4x1
        encoding!(0xffe1_9c3e, 0xc1a0_0020, Single, MultiplyAdd, 2, Group), // fmlall_za32_z8z8w_2x2
        encoding!(0xffe3_9c7e, 0xc1a1_0020, Single, MultiplyAdd, 4, Group), // fmlall_za32_z8z8w_4x4
        encoding!(
            0xfff0_9030,
            0xc1d0_1020,
            Half,
            VerticalDot { top: false },
            2,
            Indexed
        ), // fvdot_za_z8z8i_2xi
        encoding!(
            0xfff0_9830,
            0xc1d0_0800,
            Single,
            VerticalDot { top: false },
            4,
            Indexed
        ), // fvdotb_za32_z8z8i_2xi
        encoding!(
            0xfff0_9830,
            0xc1d0_0810,
            Single,
            VerticalDot { top: true },
            4,
            Indexed
        ), // fvdott_za32_z8z8i_2xi
    ]
};

fn indexed_element(word: u32, encoding: Encoding) -> u8 {
    let high = word >> INDEX_HIGH_SHIFT;
    let low = word >> INDEX_LOW_SHIFT;
    (match (encoding.operation, encoding.accumulator, encoding.groups) {
        (VectorOperation::MultiplyAdd, Format::Half, 1) => {
            ((word >> INDEX_SINGLE_HIGH_SHIFT & 1) << 3) | ((high & 3) << 1) | (low & 1)
        }
        (VectorOperation::MultiplyAdd, Format::Single, 1) => {
            ((word >> INDEX_SINGLE_HIGH_SHIFT & 1) << 3) | (high & 7)
        }
        (VectorOperation::MultiplyAdd, Format::Half, _) => {
            ((high & 3) << 2) | (word >> INDEX_PAIR_LOW_SHIFT & 3)
        }
        (VectorOperation::MultiplyAdd, Format::Single, _) => {
            ((high & 3) << 2) | (word >> INDEX_QUARTET_LOW_SHIFT & 3)
        }
        (VectorOperation::VerticalDot { .. }, Format::Single, _) => ((high & 1) << 1) | (low & 1),
        (_, Format::Half, _) => ((high & 3) << 1) | (low & 1),
        _ => high & 3,
    }) as u8
}

pub fn decode(word: u32) -> Option<Operand> {
    const OUTER_HALF_MASK: u32 = 0xffe0_001e;
    const OUTER_HALF: u32 = 0x80a0_0008;
    const OUTER_SINGLE_MASK: u32 = 0xffe0_001c;
    const OUTER_SINGLE: u32 = 0x80a0_0000;
    let outer = if word & OUTER_HALF_MASK == OUTER_HALF {
        Some((Format::Half, 1))
    } else if word & OUTER_SINGLE_MASK == OUTER_SINGLE {
        Some((Format::Single, 3))
    } else {
        None
    };
    if let Some((accumulator, tile_mask)) = outer {
        const LEFT_PREDICATE_SHIFT: u32 = 10;
        const RIGHT_PREDICATE_SHIFT: u32 = 13;
        const PREDICATE_MASK: u32 = 7;
        return Some(Operand::Outer(OuterOperand {
            accumulator,
            tile: (word & tile_mask) as u8,
            left: (word >> LEFT_SHIFT & REGISTER_MASK) as u8,
            right: (word >> RIGHT_SHIFT & REGISTER_MASK) as u8,
            row_predicate: (word >> LEFT_PREDICATE_SHIFT & PREDICATE_MASK) as u8,
            column_predicate: (word >> RIGHT_PREDICATE_SHIFT & PREDICATE_MASK) as u8,
        }));
    }
    let encoding = *ENCODINGS
        .iter()
        .find(|encoding| word & encoding.mask == encoding.value)?;
    let source_groups = if matches!(encoding.operation, VectorOperation::VerticalDot { .. }) {
        2
    } else {
        encoding.groups
    };
    let aligned = !matches!(encoding.layout, Layout::Vector);
    let left = (word >> LEFT_SHIFT & REGISTER_MASK) as u8;
    let left = if aligned {
        left / source_groups * source_groups
    } else {
        left
    };
    let right = match encoding.layout {
        Layout::Group => RightSource::Group(
            (word >> RIGHT_SHIFT & REGISTER_MASK) as u8 / source_groups * source_groups,
        ),
        Layout::Vector => RightSource::Vector((word >> RIGHT_SHIFT & SINGLE_RIGHT_MASK) as u8),
        Layout::Indexed => RightSource::Indexed {
            register: (word >> RIGHT_SHIFT & SINGLE_RIGHT_MASK) as u8,
            index: indexed_element(word, encoding),
        },
    };
    let offset = if matches!(encoding.operation, VectorOperation::MultiplyAdd) {
        let bytes = if encoding.accumulator == Format::Half {
            2
        } else {
            4
        };
        let mask = if encoding.groups == 1 {
            OFFSET_MASK / (bytes / 2)
        } else {
            OFFSET_MASK / bytes
        };
        (word & mask) * bytes
    } else {
        word & OFFSET_MASK
    };
    Some(Operand::Vector(VectorOperand {
        operation: encoding.operation,
        accumulator: encoding.accumulator,
        groups: encoding.groups,
        left,
        right,
        vector_select: FIRST_SELECTOR + (word >> SELECTOR_SHIFT & SELECTOR_MASK) as u8,
        offset: offset as u8,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(word: u32) -> VectorOperand {
        let Some(Operand::Vector(operand)) = decode(word) else {
            panic!("expected vector operand for {word:08x}");
        };
        operand
    }

    #[test]
    fn all_canonical_forms_have_disjoint_fixed_bits() {
        assert_eq!(ENCODINGS.len() + 2, 33);
        for (index, encoding) in ENCODINGS.iter().enumerate() {
            assert_eq!(encoding.value & encoding.mask, encoding.value);
            for other in &ENCODINGS[index + 1..] {
                assert_ne!(
                    (encoding.value ^ other.value) & encoding.mask & other.mask,
                    0
                );
            }
            for variable in [0, !encoding.mask] {
                let operand = vector(encoding.value | variable);
                assert_eq!(operand.operation, encoding.operation);
                assert_eq!(operand.accumulator, encoding.accumulator);
                assert_eq!(operand.groups, encoding.groups);
                assert_eq!(operand.vector_select, if variable == 0 { 8 } else { 11 });
                let source_groups =
                    if matches!(encoding.operation, VectorOperation::VerticalDot { .. }) {
                        2
                    } else {
                        encoding.groups
                    };
                assert_eq!(
                    operand.left,
                    if variable == 0 {
                        0
                    } else if matches!(encoding.layout, Layout::Vector) {
                        31
                    } else {
                        32 - source_groups
                    }
                );
                match operand.right {
                    RightSource::Indexed { register, index } => {
                        assert_eq!(register, if variable == 0 { 0 } else { 15 });
                        let maximum = match (encoding.operation, encoding.accumulator) {
                            (VectorOperation::MultiplyAdd, _) => 15,
                            (_, Format::Half) => 7,
                            _ => 3,
                        };
                        assert_eq!(index, if variable == 0 { 0 } else { maximum });
                    }
                    RightSource::Vector(register) => {
                        assert_eq!(register, if variable == 0 { 0 } else { 15 })
                    }
                    RightSource::Group(register) => {
                        assert_eq!(register, if variable == 0 { 0 } else { 32 - source_groups })
                    }
                }
            }
        }
    }

    #[test]
    fn split_immediates_and_implicit_offset_bits() {
        // Each source-index bit independently; the selector and ZA offset do not overlap.
        for (word, bits) in [
            (0xc1c0_0000, [3, 10, 11, 15]),
            (0xc190_1030, [2, 3, 10, 11]),
            (0xc140_0000, [10, 11, 12, 15]),
            (0xc190_0020, [1, 2, 10, 11]),
        ] {
            for index in 0..16 {
                let word = bits.iter().enumerate().fold(word, |word, (bit, shift)| {
                    word | ((index >> bit & 1) << shift)
                });
                assert_eq!(
                    vector(word).right,
                    RightSource::Indexed {
                        register: 0,
                        index: index as u8
                    }
                );
                assert_eq!(vector(word).offset, 0);
            }
        }
        for (word, maximum) in [
            (0xc130_0c00, 14),
            (0xc120_0804, 6),
            (0xc130_0400, 12),
            (0xc120_0002, 4),
        ] {
            let encoding = ENCODINGS.iter().find(|e| e.value == word).unwrap();
            assert_eq!(vector(word | !encoding.mask).offset, maximum);
        }
    }

    #[test]
    fn outer_tile_register_and_predicate_fields() {
        for (word, format, tile_mask) in [
            (0x80a0_0008, Format::Half, 1),
            (0x80a0_0000, Format::Single, 3),
        ] {
            for tile in 0..=tile_mask {
                let Some(Operand::Outer(operand)) =
                    decode(word | (31 << 16) | (6 << 13) | (5 << 10) | (29 << 5) | tile)
                else {
                    panic!()
                };
                assert_eq!(
                    operand,
                    OuterOperand {
                        accumulator: format,
                        tile: tile as u8,
                        left: 29,
                        right: 31,
                        row_predicate: 5,
                        column_predicate: 6
                    }
                );
            }
        }
    }

    #[test]
    fn long_rows_align_after_mathematical_selector_addition() {
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for encoding in ENCODINGS {
                let operand = vector(encoding.value | !encoding.mask);
                for selector in [0, 1, 3, u32::MAX] {
                    let rows = operand.rows(length, selector);
                    let stride = bytes / usize::from(operand.groups);
                    let adjacent = usize::from(operand.rows_per_group());
                    let base = ((u64::from(selector) + u64::from(operand.offset)) % stride as u64)
                        as usize;
                    let base = base / adjacent * adjacent;
                    for group in 0..usize::from(operand.groups) {
                        for row in 0..adjacent {
                            assert_eq!(
                                usize::from(rows[group * adjacent + row]),
                                base + group * stride + row
                            );
                        }
                    }
                    assert!(
                        rows[..usize::from(operand.row_count())]
                            .iter()
                            .all(|&row| usize::from(row) < bytes)
                    );
                }
            }
        }
    }

    #[test]
    fn vector_sources_wrap_and_aligned_sources_end_at_z31() {
        let operand = vector(0xc130_1008 | (31 << 5) | (15 << 16));
        for group in 0..4 {
            let (left, right) = operand.source_bytes(group, 0, 0, 0).unwrap();
            assert_eq!(left.register, (31 + group) % 32);
            assert_eq!(right.register, 15);
        }
        let operand = vector(0xc1a1_1030 | (28 << 5) | (28 << 16));
        assert_eq!(operand.source_bytes(3, 0, 0, 0).unwrap().0.register, 31);
        assert_eq!(operand.source_bytes(3, 0, 0, 0).unwrap().1.register, 31);
    }

    #[test]
    fn indexed_sources_repeat_within_each_128_bit_segment() {
        let half_dot = vector(0xc1d0_0020 | (3 << 10) | (1 << 3));
        assert_eq!(half_dot.source_bytes(0, 0, 8, 1).unwrap().1.byte, 31);
        let single_dot = vector(0xc150_0038 | (3 << 10));
        assert_eq!(single_dot.source_bytes(0, 0, 4, 3).unwrap().1.byte, 31);
        let half_long = vector(0xc190_1030 | (3 << 10) | (3 << 2));
        assert_eq!(half_long.source_bytes(0, 1, 8, 0).unwrap().0.byte, 17);
        assert_eq!(half_long.source_bytes(0, 1, 8, 0).unwrap().1.byte, 31);
        let single_long = vector(0xc190_0020 | (3 << 10) | (3 << 1));
        assert_eq!(single_long.source_bytes(0, 3, 4, 0).unwrap().0.byte, 19);
        assert_eq!(single_long.source_bytes(0, 3, 4, 0).unwrap().1.byte, 31);
    }

    #[test]
    fn vertical_pair_gathers_and_bottom_top_select_distinct_pairs() {
        for (word, groups, bytes, top) in [
            (0xc1d0_1020, 2, 2, false),
            (0xc1d0_0800, 4, 4, false),
            (0xc1d0_0810, 4, 4, true),
        ] {
            let operand = vector(word | (30 << 5) | (1 << 3));
            assert_eq!(operand.groups, groups);
            assert_eq!(operand.row_count(), groups);
            assert_eq!(operand.terms(), 2);
            for group in 0..groups {
                for term in 0..2 {
                    let (left, right) = operand.source_bytes(group, 0, 16 / bytes, term).unwrap();
                    assert_eq!(
                        left,
                        SourceByte {
                            register: 30 + term,
                            byte: 16 + usize::from(group)
                        }
                    );
                    assert_eq!(
                        right.byte,
                        16 + bytes + if top { 2 } else { 0 } + usize::from(term)
                    );
                }
            }
        }
    }

    #[test]
    fn invalid_source_coordinates_and_reserved_encodings_are_explicit() {
        let operand = vector(0xc1a1_0020);
        assert_eq!(operand.row_count(), 16);
        assert_eq!(operand.source_bytes(4, 0, 0, 0), None);
        assert_eq!(operand.source_bytes(0, 4, 0, 0), None);
        assert_eq!(operand.source_bytes(0, 0, 0, 1), None);
        for word in [
            0,
            u32::MAX,
            0x80a0_0018,
            0x80a0_0004,
            0xc1d0_0030,
            0xc1d0_1800,
        ] {
            assert_eq!(decode(word), None, "reserved {word:08x}");
        }
    }
}
