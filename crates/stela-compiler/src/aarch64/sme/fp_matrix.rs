//! SME floating-point outer products and ZA arithmetic.

const VECTOR_SELECT_SHIFT: u32 = 13;
const VECTOR_SELECT_MASK: u32 = 3;
const VECTOR_SELECT_FIRST: u8 = 8;
const ZA_OFFSET_MASK: u32 = 7;
const FORMAT_SIZE_SHIFT: u32 = 22;
const INDEX_HIGH_SHIFT: u32 = 10;
const INDEX_LOW_SHIFT: u32 = 3;

const SOURCE_SHIFT: u32 = 5;
const RIGHT_SOURCE_SHIFT: u32 = 16;
const SOURCE_REGISTER_MASK: u32 = 31;
const SINGLE_RIGHT_REGISTER_MASK: u32 = 15;
const INDEX_PAIR_MASK: u32 = 3;
const INDEX_SINGLE_MASK: u32 = 1;
const ADD_SUBTRACT_BIT: u32 = 1 << 3;
const FMA_SUBTRACT_BIT: u32 = 1 << 4;
const BFADD_ZA_ZW_2X2_16: u32 = 0xc1e4_1c00;
const BFADD_ZA_ZW_4X4_16: u32 = 0xc1e5_1c00;
const BFMLA_ZA_ZZI_H2XI: u32 = 0xc110_1020;
const BFMLA_ZA_ZZI_H4XI: u32 = 0xc110_9020;
const BFMLA_ZA_ZZV_2X1_16: u32 = 0xc160_1c00;
const BFMLA_ZA_ZZV_4X1_16: u32 = 0xc170_1c00;
const BFMLA_ZA_ZZW_2X2_16: u32 = 0xc1e0_1008;
const BFMLA_ZA_ZZW_4X4_16: u32 = 0xc1e1_1008;
const FADD_ZA_ZW_2X2: u32 = 0xc1a0_1c00;
const FADD_ZA_ZW_2X2_16: u32 = 0xc1a4_1c00;
const FADD_ZA_ZW_4X4: u32 = 0xc1a1_1c00;
const FADD_ZA_ZW_4X4_16: u32 = 0xc1a5_1c00;
const FMLA_ZA_ZZI_D2XI: u32 = 0xc1d0_0000;
const FMLA_ZA_ZZI_D4XI: u32 = 0xc1d0_8000;
const FMLA_ZA_ZZI_H2XI: u32 = 0xc110_1000;
const FMLA_ZA_ZZI_H4XI: u32 = 0xc110_9000;
const FMLA_ZA_ZZI_S2XI: u32 = 0xc150_0000;
const FMLA_ZA_ZZI_S4XI: u32 = 0xc150_8000;
const FMLA_ZA_ZZV_2X1: u32 = 0xc120_1800;
const FMLA_ZA_ZZV_2X1_16: u32 = 0xc120_1c00;
const FMLA_ZA_ZZV_4X1: u32 = 0xc130_1800;
const FMLA_ZA_ZZV_4X1_16: u32 = 0xc130_1c00;
const FMLA_ZA_ZZW_2X2: u32 = 0xc1a0_1800;
const FMLA_ZA_ZZW_2X2_16: u32 = 0xc1a0_1008;
const FMLA_ZA_ZZW_4X4: u32 = 0xc1a1_1800;
const FMLA_ZA_ZZW_4X4_16: u32 = 0xc1a1_1008;
const ADDEND_FIXED_TWO_MASK: u32 = 0xffff_9c30;
const ADDEND_FIXED_FOUR_MASK: u32 = 0xffff_9c70;
const INDEXED_HALF_TWO_MASK: u32 = 0xfff0_9020;
const INDEXED_HALF_FOUR_MASK: u32 = 0xfff0_9060;
const SINGLE_FIXED_MASK: u32 = 0xfff0_9c10;
const GROUP_FIXED_TWO_MASK: u32 = 0xffe1_9c28;
const GROUP_FIXED_FOUR_MASK: u32 = 0xffe3_9c68;
const ADDEND_VARIABLE_TWO_MASK: u32 = 0xffbf_9c30;
const ADDEND_VARIABLE_FOUR_MASK: u32 = 0xffbf_9c70;
const INDEXED_DOUBLE_TWO_MASK: u32 = 0xfff0_9828;
const INDEXED_DOUBLE_FOUR_MASK: u32 = 0xfff0_9868;
const INDEXED_SINGLE_TWO_MASK: u32 = 0xfff0_9028;
const INDEXED_SINGLE_FOUR_MASK: u32 = 0xfff0_9068;
const SINGLE_VARIABLE_MASK: u32 = 0xffb0_9c10;
const GROUP_VARIABLE_TWO_MASK: u32 = 0xffa1_9c30;
const GROUP_VARIABLE_FOUR_MASK: u32 = 0xffa3_9c70;

const SEGMENT_BITS: u16 = 128;

use crate::aarch64::{
    floating::Format as FloatingFormat,
    scalable::{ElementSize, VECTOR_REGISTER_COUNT, VectorLength},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixFormat {
    BFloat16,
    Float(FloatingFormat),
}
impl MatrixFormat {
    pub const fn element_size(self) -> ElementSize {
        match self {
            Self::BFloat16 | Self::Float(FloatingFormat::Half) => ElementSize::Halfword,
            Self::Float(FloatingFormat::Single) => ElementSize::Word,
            Self::Float(FloatingFormat::Double) => ElementSize::Doubleword,
        }
    }
    pub const fn bits(self) -> u16 {
        self.element_size().bits() as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    One,
    Two,
    Four,
}
impl Group {
    pub const fn count(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorOperation {
    Add,
    Subtract,
    MultiplyAdd,
    MultiplySubtract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sources {
    AddendGroup { first: u8 },
    Single { left: u8, right: u8 },
    Group { left: u8, right: u8 },
    Indexed { left: u8, right: u8, index: u8 },
}

/// Decode-time requirement, including the extra requirement selected by sz=1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredFeature {
    Sme,
    Sme2,
    F16F16,
    F64F64,
    B16B16,
    F16F16OrF8F16,
    Sme2AndF64F64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorOperand {
    pub format: MatrixFormat,
    pub operation: VectorOperation,
    pub sources: Sources,
    pub vector_select: u8,
    pub offset: u8,
    pub group: Group,
    pub feature: RequiredFeature,
}

impl VectorOperand {
    /// ZA is viewed as SVL/8 horizontal byte-vectors, partitioned by group.
    /// The W selector addition is mathematical, with modulo applied afterward.
    pub fn vectors(self, length: VectorLength, selector: u32) -> [u16; 4] {
        let stride = (length.bytes() / usize::from(self.group.count())) as u16;
        let base = ((u64::from(selector) + u64::from(self.offset)) % u64::from(stride)) as u16;
        let mut vectors = [0; 4];
        for r in 0..self.group.count() {
            vectors[usize::from(r)] = base + u16::from(r) * stride;
        }
        vectors
    }

    pub fn right_element(self, element: u16) -> u16 {
        match self.sources {
            Sources::Indexed { index, .. } => {
                let elements_per_segment = SEGMENT_BITS / self.format.bits();
                element - element % elements_per_segment + u16::from(index)
            }
            _ => element,
        }
    }

    /// Only Single-source groups wrap from Z31 to Z0; aligned groups cannot overflow.
    pub fn left_register(self, group_index: u8) -> Option<u8> {
        if group_index >= self.group.count() {
            return None;
        }
        match self.sources {
            Sources::AddendGroup { .. } => None,
            Sources::Single { left, .. } => Some((left + group_index) % VECTOR_REGISTER_COUNT),
            Sources::Group { left, .. } | Sources::Indexed { left, .. } => Some(left + group_index),
        }
    }
}

#[derive(Clone, Copy)]
enum VectorLayout {
    Addend,
    Single,
    Group,
    Indexed,
}

#[derive(Clone, Copy)]
enum VectorEncoding {
    BFloat16,
    Half,
    Single,
    Double,
    SingleOrDouble,
}
type VectorPattern = (u32, u32, VectorEncoding, Group, VectorLayout);
const VECTOR_PATTERNS: &[VectorPattern] = {
    use Group as G;
    use VectorEncoding as E;
    use VectorLayout as L;
    &[
        (
            BFADD_ZA_ZW_2X2_16,
            ADDEND_FIXED_TWO_MASK,
            E::BFloat16,
            G::Two,
            L::Addend,
        ),
        (
            BFADD_ZA_ZW_4X4_16,
            ADDEND_FIXED_FOUR_MASK,
            E::BFloat16,
            G::Four,
            L::Addend,
        ),
        (
            BFMLA_ZA_ZZI_H2XI,
            INDEXED_HALF_TWO_MASK,
            E::BFloat16,
            G::Two,
            L::Indexed,
        ),
        (
            BFMLA_ZA_ZZI_H4XI,
            INDEXED_HALF_FOUR_MASK,
            E::BFloat16,
            G::Four,
            L::Indexed,
        ),
        (
            BFMLA_ZA_ZZV_2X1_16,
            SINGLE_FIXED_MASK,
            E::BFloat16,
            G::Two,
            L::Single,
        ),
        (
            BFMLA_ZA_ZZV_4X1_16,
            SINGLE_FIXED_MASK,
            E::BFloat16,
            G::Four,
            L::Single,
        ),
        (
            BFMLA_ZA_ZZW_2X2_16,
            GROUP_FIXED_TWO_MASK,
            E::BFloat16,
            G::Two,
            L::Group,
        ),
        (
            BFMLA_ZA_ZZW_4X4_16,
            GROUP_FIXED_FOUR_MASK,
            E::BFloat16,
            G::Four,
            L::Group,
        ),
        (
            FADD_ZA_ZW_2X2,
            ADDEND_VARIABLE_TWO_MASK,
            E::SingleOrDouble,
            G::Two,
            L::Addend,
        ),
        (
            FADD_ZA_ZW_2X2_16,
            ADDEND_FIXED_TWO_MASK,
            E::Half,
            G::Two,
            L::Addend,
        ),
        (
            FADD_ZA_ZW_4X4,
            ADDEND_VARIABLE_FOUR_MASK,
            E::SingleOrDouble,
            G::Four,
            L::Addend,
        ),
        (
            FADD_ZA_ZW_4X4_16,
            ADDEND_FIXED_FOUR_MASK,
            E::Half,
            G::Four,
            L::Addend,
        ),
        (
            FMLA_ZA_ZZI_D2XI,
            INDEXED_DOUBLE_TWO_MASK,
            E::Double,
            G::Two,
            L::Indexed,
        ),
        (
            FMLA_ZA_ZZI_D4XI,
            INDEXED_DOUBLE_FOUR_MASK,
            E::Double,
            G::Four,
            L::Indexed,
        ),
        (
            FMLA_ZA_ZZI_H2XI,
            INDEXED_HALF_TWO_MASK,
            E::Half,
            G::Two,
            L::Indexed,
        ),
        (
            FMLA_ZA_ZZI_H4XI,
            INDEXED_HALF_FOUR_MASK,
            E::Half,
            G::Four,
            L::Indexed,
        ),
        (
            FMLA_ZA_ZZI_S2XI,
            INDEXED_SINGLE_TWO_MASK,
            E::Single,
            G::Two,
            L::Indexed,
        ),
        (
            FMLA_ZA_ZZI_S4XI,
            INDEXED_SINGLE_FOUR_MASK,
            E::Single,
            G::Four,
            L::Indexed,
        ),
        (
            FMLA_ZA_ZZV_2X1,
            SINGLE_VARIABLE_MASK,
            E::SingleOrDouble,
            G::Two,
            L::Single,
        ),
        (
            FMLA_ZA_ZZV_2X1_16,
            SINGLE_FIXED_MASK,
            E::Half,
            G::Two,
            L::Single,
        ),
        (
            FMLA_ZA_ZZV_4X1,
            SINGLE_VARIABLE_MASK,
            E::SingleOrDouble,
            G::Four,
            L::Single,
        ),
        (
            FMLA_ZA_ZZV_4X1_16,
            SINGLE_FIXED_MASK,
            E::Half,
            G::Four,
            L::Single,
        ),
        (
            FMLA_ZA_ZZW_2X2,
            GROUP_VARIABLE_TWO_MASK,
            E::SingleOrDouble,
            G::Two,
            L::Group,
        ),
        (
            FMLA_ZA_ZZW_2X2_16,
            GROUP_FIXED_TWO_MASK,
            E::Half,
            G::Two,
            L::Group,
        ),
        (
            FMLA_ZA_ZZW_4X4,
            GROUP_VARIABLE_FOUR_MASK,
            E::SingleOrDouble,
            G::Four,
            L::Group,
        ),
        (
            FMLA_ZA_ZZW_4X4_16,
            GROUP_FIXED_FOUR_MASK,
            E::Half,
            G::Four,
            L::Group,
        ),
    ]
};

pub fn decode_vector(word: u32) -> Option<VectorOperand> {
    let &(_, _, encoding, group, layout) = VECTOR_PATTERNS
        .iter()
        .find(|(opcode, mask, ..)| word & mask == *opcode)?;
    let format = match encoding {
        VectorEncoding::BFloat16 => MatrixFormat::BFloat16,
        VectorEncoding::Half => MatrixFormat::Float(FloatingFormat::Half),
        VectorEncoding::Single => MatrixFormat::Float(FloatingFormat::Single),
        VectorEncoding::Double => MatrixFormat::Float(FloatingFormat::Double),
        VectorEncoding::SingleOrDouble => {
            MatrixFormat::Float(if word & (1 << FORMAT_SIZE_SHIFT) == 0 {
                FloatingFormat::Single
            } else {
                FloatingFormat::Double
            })
        }
    };
    let feature = match (format, layout) {
        (MatrixFormat::BFloat16, _) => RequiredFeature::B16B16,
        (MatrixFormat::Float(FloatingFormat::Half), VectorLayout::Addend) => {
            RequiredFeature::F16F16OrF8F16
        }
        (MatrixFormat::Float(FloatingFormat::Half), _) => RequiredFeature::F16F16,
        (MatrixFormat::Float(FloatingFormat::Single), _) => RequiredFeature::Sme2,
        (MatrixFormat::Float(FloatingFormat::Double), _) => RequiredFeature::Sme2AndF64F64,
    };
    let subtract_bit = match (layout, format) {
        (VectorLayout::Indexed, _)
        | (
            VectorLayout::Group,
            MatrixFormat::BFloat16 | MatrixFormat::Float(FloatingFormat::Half),
        ) => FMA_SUBTRACT_BIT,
        _ => ADD_SUBTRACT_BIT,
    };
    let subtract = word & subtract_bit != 0;
    let first_group = |shift| {
        ((word >> shift) & (u32::from(VECTOR_REGISTER_COUNT / group.count()) - 1)) as u8
            * group.count()
    };
    let aligned_shift = SOURCE_SHIFT + group.count().trailing_zeros();
    let (sources, operation) = match layout {
        VectorLayout::Addend => (
            Sources::AddendGroup {
                first: first_group(aligned_shift),
            },
            if subtract {
                VectorOperation::Subtract
            } else {
                VectorOperation::Add
            },
        ),
        layout => {
            let right = ((word >> RIGHT_SOURCE_SHIFT) & SINGLE_RIGHT_REGISTER_MASK) as u8;
            let sources = match layout {
                VectorLayout::Single => Sources::Single {
                    left: ((word >> SOURCE_SHIFT) & SOURCE_REGISTER_MASK) as u8,
                    right,
                },
                VectorLayout::Group => Sources::Group {
                    left: first_group(aligned_shift),
                    right: first_group(RIGHT_SOURCE_SHIFT + group.count().trailing_zeros()),
                },
                VectorLayout::Indexed => {
                    let index = match format {
                        MatrixFormat::BFloat16 | MatrixFormat::Float(FloatingFormat::Half) => {
                            (((word >> INDEX_HIGH_SHIFT) & INDEX_PAIR_MASK) << 1
                                | ((word >> INDEX_LOW_SHIFT) & INDEX_SINGLE_MASK))
                                as u8
                        }
                        MatrixFormat::Float(FloatingFormat::Single) => {
                            ((word >> INDEX_HIGH_SHIFT) & INDEX_PAIR_MASK) as u8
                        }
                        MatrixFormat::Float(FloatingFormat::Double) => {
                            ((word >> INDEX_HIGH_SHIFT) & INDEX_SINGLE_MASK) as u8
                        }
                    };
                    Sources::Indexed {
                        left: first_group(aligned_shift),
                        right,
                        index,
                    }
                }
                VectorLayout::Addend => unreachable!("handled outside multiply branch"),
            };
            (
                sources,
                if subtract {
                    VectorOperation::MultiplySubtract
                } else {
                    VectorOperation::MultiplyAdd
                },
            )
        }
    };
    Some(VectorOperand {
        format,
        operation,
        sources,
        vector_select: VECTOR_SELECT_FIRST
            + ((word >> VECTOR_SELECT_SHIFT) & VECTOR_SELECT_MASK) as u8,
        offset: (word & ZA_OFFSET_MASK) as u8,
        group,
        feature,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotFormat {
    BFloat16,
    Half,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DotOperand {
    pub kind: DotFormat,
    pub vertical: bool,
    pub sources: Sources,
    pub group: Group,
    pub vector_select: u8,
    pub offset: u8,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongOperand {
    pub kind: DotFormat,
    pub subtract: bool,
    pub sources: Sources,
    pub group: Group,
    pub vector_select: u8,
    pub offset: u8,
}
#[derive(Clone, Copy)]
struct Field {
    lsb: u32,
    mask: u32,
}
impl Field {
    const fn new(lsb: u32, width: u32) -> Self {
        Self {
            lsb,
            mask: (1 << width) - 1,
        }
    }
    const fn get(self, word: u32) -> u8 {
        ((word >> self.lsb) & self.mask) as u8
    }
}
const ZN: Field = Field::new(5, 5);
const ZM_GROUP: Field = Field::new(16, 5);
const ZM_SINGLE: Field = Field::new(16, 4);
const SELECTOR: Field = Field::new(13, 2);
const OFFSET_THREE: Field = Field::new(0, 3);
const OFFSET_TWO: Field = Field::new(0, 2);
const DOT_INDEX: Field = Field::new(10, 2);
const LONG_SINGLE_INDEX_HIGH: Field = Field::new(15, 1);
const LONG_SINGLE_INDEX_LOW: Field = Field::new(10, 2);
const LONG_GROUP_INDEX_HIGH: Field = Field::new(10, 2);
const LONG_GROUP_INDEX_LOW: Field = Field::new(2, 1);
const LONG_SINGLE_INDEX_LOW_BITS: u8 = 2;
const LONG_GROUP_INDEX_LOW_BITS: u8 = 1;
const SELECTOR_FIRST_REGISTER: u8 = 8;
const DOUBLE_VECTOR_SCALE: u8 = 2;
const BFLOAT_SELECTOR_BIT: u32 = 1 << 4;
const LONG_SUBTRACT_BIT: u32 = 1 << 3;
#[derive(Clone, Copy)]
enum DotClass {
    Dot,
    VerticalDot,
    Long,
}
#[derive(Clone, Copy)]
enum DotSourceLayout {
    Indexed,
    Single,
    Group,
}
type DotPattern = (u32, u32, DotClass, DotSourceLayout, Group);
const FDOT_ZA_ZZI_2XI_MASK: u32 = 0xfff0_9038 & !(BFLOAT_SELECTOR_BIT);
const FDOT_ZA_ZZI_2XI: u32 = 0xc150_1008;
const FDOT_ZA_ZZI_4XI_MASK: u32 = 0xfff0_9078 & !(BFLOAT_SELECTOR_BIT);
const FDOT_ZA_ZZI_4XI: u32 = 0xc150_9008;
const FDOT_ZA_ZZV_2X1_MASK: u32 = 0xfff0_9c18 & !(BFLOAT_SELECTOR_BIT);
const FDOT_ZA_ZZV_2X1: u32 = 0xc120_1000;
const FDOT_ZA_ZZV_4X1_MASK: u32 = 0xfff0_9c18 & !(BFLOAT_SELECTOR_BIT);
const FDOT_ZA_ZZV_4X1: u32 = 0xc130_1000;
const FDOT_ZA_ZZW_2X2_MASK: u32 = 0xffe1_9c38 & !(BFLOAT_SELECTOR_BIT);
const FDOT_ZA_ZZW_2X2: u32 = 0xc1a0_1000;
const FDOT_ZA_ZZW_4X4_MASK: u32 = 0xffe3_9c78 & !(BFLOAT_SELECTOR_BIT);
const FDOT_ZA_ZZW_4X4: u32 = 0xc1a1_1000;
const FMLAL_ZA_ZZI_1_MASK: u32 = 0xfff0_1018 & !(BFLOAT_SELECTOR_BIT | LONG_SUBTRACT_BIT);
const FMLAL_ZA_ZZI_1: u32 = 0xc180_1000;
const FMLAL_ZA_ZZI_2XI_MASK: u32 = 0xfff0_9038 & !(BFLOAT_SELECTOR_BIT | LONG_SUBTRACT_BIT);
const FMLAL_ZA_ZZI_2XI: u32 = 0xc190_1000;
const FMLAL_ZA_ZZI_4XI_MASK: u32 = 0xfff0_9078 & !(BFLOAT_SELECTOR_BIT | LONG_SUBTRACT_BIT);
const FMLAL_ZA_ZZI_4XI: u32 = 0xc190_9000;
const FMLAL_ZA_ZZV_1_MASK: u32 = 0xfff0_9c18 & !(BFLOAT_SELECTOR_BIT | LONG_SUBTRACT_BIT);
const FMLAL_ZA_ZZV_1: u32 = 0xc120_0c00;
const FMLAL_ZA_ZZV_2X1_MASK: u32 = 0xfff0_9c1c & !(BFLOAT_SELECTOR_BIT | LONG_SUBTRACT_BIT);
const FMLAL_ZA_ZZV_2X1: u32 = 0xc120_0800;
const FMLAL_ZA_ZZV_4X1_MASK: u32 = 0xfff0_9c1c & !(BFLOAT_SELECTOR_BIT | LONG_SUBTRACT_BIT);
const FMLAL_ZA_ZZV_4X1: u32 = 0xc130_0800;
const FMLAL_ZA_ZZW_2X2_MASK: u32 = 0xffe1_9c3c & !(BFLOAT_SELECTOR_BIT | LONG_SUBTRACT_BIT);
const FMLAL_ZA_ZZW_2X2: u32 = 0xc1a0_0800;
const FMLAL_ZA_ZZW_4X4_MASK: u32 = 0xffe3_9c7c & !(BFLOAT_SELECTOR_BIT | LONG_SUBTRACT_BIT);
const FMLAL_ZA_ZZW_4X4: u32 = 0xc1a1_0800;
const FVDOT_ZA_ZZI_2XI_MASK: u32 = 0xfff0_9038 & !(BFLOAT_SELECTOR_BIT);
const FVDOT_ZA_ZZI_2XI: u32 = 0xc150_0008;
const DOT_PATTERNS: &[DotPattern] = {
    use DotClass as C;
    use DotSourceLayout as S;
    use Group as G;
    &[
        (
            FDOT_ZA_ZZI_2XI,
            FDOT_ZA_ZZI_2XI_MASK,
            C::Dot,
            S::Indexed,
            G::Two,
        ),
        (
            FDOT_ZA_ZZI_4XI,
            FDOT_ZA_ZZI_4XI_MASK,
            C::Dot,
            S::Indexed,
            G::Four,
        ),
        (
            FDOT_ZA_ZZV_2X1,
            FDOT_ZA_ZZV_2X1_MASK,
            C::Dot,
            S::Single,
            G::Two,
        ),
        (
            FDOT_ZA_ZZV_4X1,
            FDOT_ZA_ZZV_4X1_MASK,
            C::Dot,
            S::Single,
            G::Four,
        ),
        (
            FDOT_ZA_ZZW_2X2,
            FDOT_ZA_ZZW_2X2_MASK,
            C::Dot,
            S::Group,
            G::Two,
        ),
        (
            FDOT_ZA_ZZW_4X4,
            FDOT_ZA_ZZW_4X4_MASK,
            C::Dot,
            S::Group,
            G::Four,
        ),
        (
            FMLAL_ZA_ZZI_1,
            FMLAL_ZA_ZZI_1_MASK,
            C::Long,
            S::Indexed,
            G::One,
        ),
        (
            FMLAL_ZA_ZZI_2XI,
            FMLAL_ZA_ZZI_2XI_MASK,
            C::Long,
            S::Indexed,
            G::Two,
        ),
        (
            FMLAL_ZA_ZZI_4XI,
            FMLAL_ZA_ZZI_4XI_MASK,
            C::Long,
            S::Indexed,
            G::Four,
        ),
        (
            FMLAL_ZA_ZZV_1,
            FMLAL_ZA_ZZV_1_MASK,
            C::Long,
            S::Single,
            G::One,
        ),
        (
            FMLAL_ZA_ZZV_2X1,
            FMLAL_ZA_ZZV_2X1_MASK,
            C::Long,
            S::Single,
            G::Two,
        ),
        (
            FMLAL_ZA_ZZV_4X1,
            FMLAL_ZA_ZZV_4X1_MASK,
            C::Long,
            S::Single,
            G::Four,
        ),
        (
            FMLAL_ZA_ZZW_2X2,
            FMLAL_ZA_ZZW_2X2_MASK,
            C::Long,
            S::Group,
            G::Two,
        ),
        (
            FMLAL_ZA_ZZW_4X4,
            FMLAL_ZA_ZZW_4X4_MASK,
            C::Long,
            S::Group,
            G::Four,
        ),
        (
            FVDOT_ZA_ZZI_2XI,
            FVDOT_ZA_ZZI_2XI_MASK,
            C::VerticalDot,
            S::Indexed,
            G::Two,
        ),
    ]
};

fn decode_dot_or_long(word: u32) -> Option<Operand> {
    let &(_, _, class, layout, group) = DOT_PATTERNS
        .iter()
        .find(|(opcode, mask, ..)| word & mask == *opcode)?;
    let is_long = matches!(class, DotClass::Long);
    let kind = if word & BFLOAT_SELECTOR_BIT == 0 {
        DotFormat::Half
    } else {
        DotFormat::BFloat16
    };
    let index = match layout {
        DotSourceLayout::Indexed => {
            let index = if !is_long {
                DOT_INDEX.get(word)
            } else if matches!(group, Group::One) {
                (LONG_SINGLE_INDEX_HIGH.get(word) << LONG_SINGLE_INDEX_LOW_BITS)
                    | LONG_SINGLE_INDEX_LOW.get(word)
            } else {
                (LONG_GROUP_INDEX_HIGH.get(word) << LONG_GROUP_INDEX_LOW_BITS)
                    | LONG_GROUP_INDEX_LOW.get(word)
            };
            Some(index)
        }
        DotSourceLayout::Single => None,
        DotSourceLayout::Group => None,
    };
    let offset = if !is_long {
        OFFSET_THREE.get(word)
    } else {
        let field = if matches!(group, Group::One) {
            OFFSET_THREE
        } else {
            OFFSET_TWO
        };
        field.get(word) * DOUBLE_VECTOR_SCALE
    };
    let zn = ZN.get(word);
    let zm = match layout {
        DotSourceLayout::Group => ZM_GROUP.get(word) & !(group.count() - 1),
        _ => ZM_SINGLE.get(word),
    };
    let selector = SELECTOR_FIRST_REGISTER + SELECTOR.get(word);
    let sources = match index {
        Some(index) => Sources::Indexed {
            left: zn,
            right: zm,
            index,
        },
        None if matches!(layout, DotSourceLayout::Group) => Sources::Group {
            left: zn,
            right: zm,
        },
        None => Sources::Single {
            left: zn,
            right: zm,
        },
    };
    Some(if is_long {
        Operand::Long(LongOperand {
            kind,
            subtract: word & LONG_SUBTRACT_BIT != 0,
            sources,
            group,
            vector_select: selector,
            offset,
        })
    } else {
        Operand::Dot(DotOperand {
            kind,
            vertical: matches!(class, DotClass::VerticalDot),
            sources,
            group,
            vector_select: selector,
            offset,
        })
    })
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OuterNumericalKind {
    FusedMultiplyAdd,
    HalfDotThenAdd,
    BfloatDotThenAdd,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OuterOperand {
    pub destination: MatrixFormat,
    pub input: MatrixFormat,
    pub tile: u8,
    pub left: u8,
    pub right: u8,
    pub row_predicate: u8,
    pub column_predicate: u8,
    pub subtract: bool,
    pub numerical_kind: OuterNumericalKind,
}
impl OuterOperand {
    pub fn required_feature(self) -> RequiredFeature {
        match (self.destination, self.input) {
            (
                MatrixFormat::Float(FloatingFormat::Half),
                MatrixFormat::Float(FloatingFormat::Half),
            ) => RequiredFeature::F16F16,
            (MatrixFormat::BFloat16, MatrixFormat::BFloat16) => RequiredFeature::B16B16,
            (
                MatrixFormat::Float(FloatingFormat::Double),
                MatrixFormat::Float(FloatingFormat::Double),
            ) => RequiredFeature::F64F64,
            _ => RequiredFeature::Sme,
        }
    }
}
const OUTER_RIGHT_SHIFT: u32 = 16;
const OUTER_COLUMN_PREDICATE_SHIFT: u32 = 13;
const OUTER_ROW_PREDICATE_SHIFT: u32 = 10;
const OUTER_LEFT_SHIFT: u32 = 5;
const OUTER_SUBTRACT_BIT: u32 = 1 << 4;

const PREDICATE_REGISTER_MASK: u32 = 7;
const HALF_TILE_MASK: u32 = 1;
const SINGLE_TILE_MASK: u32 = 3;
const DOUBLE_TILE_MASK: u32 = 7;

pub fn decode_outer(word: u32) -> Option<OuterOperand> {
    // Add/subtract share one class; feature predicates are per format.
    const F16_SAME_MASK: u32 = 0xffe0_000e;
    const F16_SAME_VALUE: u32 = 0x8180_0008;
    const BF16_SAME_MASK: u32 = 0xffe0_000e;
    const BF16_SAME_VALUE: u32 = 0x81a0_0008;
    const F32_SAME_MASK: u32 = 0xffe0_000c;
    const F32_SAME_VALUE: u32 = 0x8080_0000;
    const F64_SAME_MASK: u32 = 0xffe0_0008;
    const F64_SAME_VALUE: u32 = 0x80c0_0000;
    const F16_DOT_MASK: u32 = 0xffe0_000c;
    const F16_DOT_VALUE: u32 = 0x81a0_0000;
    const BF16_DOT_MASK: u32 = 0xffe0_000c;
    const BF16_DOT_VALUE: u32 = 0x8180_0000;
    let (destination, input, numerical_kind, tile_mask) = if word & F16_SAME_MASK == F16_SAME_VALUE
    {
        (
            MatrixFormat::Float(FloatingFormat::Half),
            MatrixFormat::Float(FloatingFormat::Half),
            OuterNumericalKind::FusedMultiplyAdd,
            HALF_TILE_MASK,
        )
    } else if word & BF16_SAME_MASK == BF16_SAME_VALUE {
        (
            MatrixFormat::BFloat16,
            MatrixFormat::BFloat16,
            OuterNumericalKind::FusedMultiplyAdd,
            HALF_TILE_MASK,
        )
    } else if word & F32_SAME_MASK == F32_SAME_VALUE {
        (
            MatrixFormat::Float(FloatingFormat::Single),
            MatrixFormat::Float(FloatingFormat::Single),
            OuterNumericalKind::FusedMultiplyAdd,
            SINGLE_TILE_MASK,
        )
    } else if word & F64_SAME_MASK == F64_SAME_VALUE {
        (
            MatrixFormat::Float(FloatingFormat::Double),
            MatrixFormat::Float(FloatingFormat::Double),
            OuterNumericalKind::FusedMultiplyAdd,
            DOUBLE_TILE_MASK,
        )
    } else if word & F16_DOT_MASK == F16_DOT_VALUE {
        (
            MatrixFormat::Float(FloatingFormat::Single),
            MatrixFormat::Float(FloatingFormat::Half),
            OuterNumericalKind::HalfDotThenAdd,
            SINGLE_TILE_MASK,
        )
    } else if word & BF16_DOT_MASK == BF16_DOT_VALUE {
        (
            MatrixFormat::Float(FloatingFormat::Single),
            MatrixFormat::BFloat16,
            OuterNumericalKind::BfloatDotThenAdd,
            SINGLE_TILE_MASK,
        )
    } else {
        return None;
    };
    Some(OuterOperand {
        destination,
        input,
        numerical_kind,
        tile: (word & tile_mask) as u8,
        left: ((word >> OUTER_LEFT_SHIFT) & SOURCE_REGISTER_MASK) as u8,
        right: ((word >> OUTER_RIGHT_SHIFT) & SOURCE_REGISTER_MASK) as u8,
        row_predicate: ((word >> OUTER_ROW_PREDICATE_SHIFT) & PREDICATE_REGISTER_MASK) as u8,
        column_predicate: ((word >> OUTER_COLUMN_PREDICATE_SHIFT) & PREDICATE_REGISTER_MASK) as u8,
        subtract: word & OUTER_SUBTRACT_BIT != 0,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Vector(VectorOperand),
    Dot(DotOperand),
    Long(LongOperand),
    Outer(OuterOperand),
}

pub fn decode(word: u32) -> Option<Operand> {
    decode_vector(word)
        .map(Operand::Vector)
        .or_else(|| decode_dot_or_long(word))
        .or_else(|| decode_outer(word).map(Operand::Outer))
}

impl Operand {
    pub fn required_feature(self) -> RequiredFeature {
        match self {
            Self::Vector(operand) => operand.feature,
            Self::Dot(_) | Self::Long(_) => RequiredFeature::Sme2,
            Self::Outer(operand) => operand.required_feature(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn subtraction_bits_follow_the_source_layout() {
        for (word, operation) in [
            (
                BFMLA_ZA_ZZV_2X1_16 | ADD_SUBTRACT_BIT,
                VectorOperation::MultiplySubtract,
            ),
            (
                FMLA_ZA_ZZW_2X2 | ADD_SUBTRACT_BIT,
                VectorOperation::MultiplySubtract,
            ),
            (
                BFMLA_ZA_ZZW_2X2_16 | FMA_SUBTRACT_BIT,
                VectorOperation::MultiplySubtract,
            ),
            (
                FMLA_ZA_ZZI_S2XI | FMA_SUBTRACT_BIT,
                VectorOperation::MultiplySubtract,
            ),
        ] {
            assert_eq!(decode_vector(word).unwrap().operation, operation);
        }
    }

    #[test]
    fn indexed_sources_repeat_in_each_128_bit_segment() {
        let operand =
            decode_vector(FMLA_ZA_ZZI_H4XI | (3 << INDEX_HIGH_SHIFT) | (1 << INDEX_LOW_SHIFT))
                .unwrap();
        assert_eq!(operand.right_element(0), 7);
        assert_eq!(operand.right_element(7), 7);
        assert_eq!(operand.right_element(8), 15);
        assert_eq!(operand.right_element(16), 23);
    }

    #[test]
    fn single_source_groups_wrap_and_aligned_groups_do_not() {
        let single = decode_vector(FMLA_ZA_ZZV_4X1 | (31 << SOURCE_SHIFT)).unwrap();
        assert_eq!(
            (0..4).map(|r| single.left_register(r)).collect::<Vec<_>>(),
            [Some(31), Some(0), Some(1), Some(2)]
        );
        let group = decode_vector(FMLA_ZA_ZZW_4X4 | (7 << 7)).unwrap();
        assert_eq!(
            (0..4).map(|r| group.left_register(r)).collect::<Vec<_>>(),
            [Some(28), Some(29), Some(30), Some(31)]
        );
        assert_eq!(group.left_register(4), None);
    }

    #[test]
    fn row_groups_partition_the_streaming_length() {
        let operand = decode_vector(FADD_ZA_ZW_4X4 | ZA_OFFSET_MASK).unwrap();
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            let rows = operand.vectors(length, u32::MAX);
            let stride = (bytes / 4) as u16;
            let base = 6 % stride;
            assert_eq!(
                rows,
                [base, base + stride, base + 2 * stride, base + 3 * stride]
            );
        }
    }

    #[test]
    fn double_size_adds_its_decode_time_feature_requirement() {
        let single = decode_vector(FMLA_ZA_ZZV_2X1).unwrap();
        let double = decode_vector(FMLA_ZA_ZZV_2X1 | (1 << FORMAT_SIZE_SHIFT)).unwrap();
        assert_eq!(single.feature, RequiredFeature::Sme2);
        assert_eq!(double.feature, RequiredFeature::Sme2AndF64F64);
        assert_eq!(double.format, MatrixFormat::Float(FloatingFormat::Double));
        assert_eq!(
            decode_vector(FADD_ZA_ZW_2X2_16).unwrap().feature,
            RequiredFeature::F16F16OrF8F16
        );
    }

    #[test]
    fn dot_group_alignment_excludes_opcode_bits_from_register_indices() {
        let Operand::Dot(operand) = decode(FDOT_ZA_ZZW_4X4 | BFLOAT_SELECTOR_BIT).unwrap() else {
            panic!("dot form");
        };
        assert_eq!(operand.sources, Sources::Group { left: 0, right: 0 });
        assert_eq!(operand.kind, DotFormat::BFloat16);
        let Operand::Long(operand) = decode(FMLAL_ZA_ZZI_4XI | (3 << 10) | (1 << 2) | 3).unwrap()
        else {
            panic!("long form");
        };
        assert_eq!(operand.offset, 6);
        assert_eq!(
            operand.sources,
            Sources::Indexed {
                left: 0,
                right: 0,
                index: 7
            }
        );
    }

    #[test]
    fn outer_products_keep_tile_predicate_and_numerical_shapes() {
        let operand = decode_outer(
            0x80c0_0000
                | (31 << OUTER_RIGHT_SHIFT)
                | (30 << OUTER_LEFT_SHIFT)
                | (7 << OUTER_ROW_PREDICATE_SHIFT)
                | (6 << OUTER_COLUMN_PREDICATE_SHIFT)
                | OUTER_SUBTRACT_BIT
                | DOUBLE_TILE_MASK,
        )
        .unwrap();
        assert_eq!((operand.tile, operand.left, operand.right), (7, 30, 31));
        assert_eq!((operand.row_predicate, operand.column_predicate), (7, 6));
        assert!(operand.subtract);
        assert_eq!(operand.required_feature(), RequiredFeature::F64F64);
        assert_eq!(
            decode_outer(0x81a0_0000).unwrap().numerical_kind,
            OuterNumericalKind::HalfDotThenAdd
        );
        assert_eq!(
            decode_outer(0x81a0_0008).unwrap().numerical_kind,
            OuterNumericalKind::FusedMultiplyAdd
        );
    }

    #[test]
    fn unrelated_words_are_not_matrix_arithmetic() {
        for word in [0, u32::MAX, 0xd503_201f, 0xc120_a300, 0xc1a4_e000] {
            assert_eq!(decode(word), None);
        }
    }
}
