//! SME2 multi-vector integer arithmetic and narrowing. Saturation does not set
//! FPSR.QC.
use crate::aarch64::Unsupported;
use crate::aarch64::scalable::{BITS_PER_BYTE, ElementSize, VECTOR_REGISTER_COUNT};

const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const REGISTER_MASK: u32 = 31;
const SINGLE_SOURCE_SHIFT: u32 = 16;
const PAIR_SOURCE_SHIFT: u32 = 17;
const QUARTET_SOURCE_SHIFT: u32 = 18;
const CLAMP_LOWER_SHIFT: u32 = 5;
const NARROW_PAIR_SOURCE_SHIFT: u32 = 6;
const NARROW_QUARTET_SOURCE_SHIFT: u32 = 7;
const NARROW_SIZE_SHIFT: u32 = 23;
const NARROW_SHIFT_SIZE_SHIFT: u32 = 22;
const NARROW_IMMEDIATE_SHIFT: u32 = 16;
const PAIR_SHIFT_IMMEDIATE_MASK: u32 = 15;
const QUARTET_SHIFT_IMMEDIATE_MASK: u32 = 31;
const PAIR_DESTINATION_BITS: u8 = 16;
const SINGLE_SOURCE_MASK: u32 = 15;
const QUARTET_SIZE_IMMEDIATE_SHIFT: u32 = 5;
const SHIFT_ENCODING_SCALE: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signedness {
    Signed,
    Unsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Pair,
    Quartet,
}

impl Group {
    pub const fn count(self) -> u8 {
        match self {
            Self::Pair => 2,
            Self::Quartet => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticKind {
    Add,
    Minimum(Signedness),
    Maximum(Signedness),
    Clamp(Signedness),
    SaturatingDoublingMultiplyHigh,
    RoundingShift(Signedness),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arithmetic {
    pub kind: ArithmeticKind,
    pub destination: u8,
    pub right: u8,
    pub lower: Option<u8>,
    pub group: Group,
    pub element: ElementSize,
    pub right_grouped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Narrow {
    pub destination: u8,
    pub source: u8,
    pub group: Group,
    pub source_element: ElementSize,
    pub destination_element: ElementSize,
    pub source_signedness: Signedness,
    pub destination_signedness: Signedness,
    pub shift: u8,
    pub interleaved: bool,
    pub streaming_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Arithmetic(Arithmetic),
    Narrow(Narrow),
}

#[derive(Clone, Copy)]
struct ArithmeticEncoding {
    mask: u32,
    opcode: u32,
    kind: ArithmeticKind,
    group: Group,
    right_grouped: bool,
}

#[derive(Clone, Copy)]
struct NarrowEncoding {
    mask: u32,
    opcode: u32,
    group: Group,
    source_signedness: Signedness,
    destination_signedness: Signedness,
    rounded_shift: bool,
    streaming_only: bool,
    interleaved: bool,
}

const CLAMP_PAIR_MASK: u32 = 0xff20_fc01;
const CLAMP_QUARTET_MASK: u32 = 0xff20_fc03;
const SHIFT_NARROW_QUARTET_MASK: u32 = 0xff20_fc60;
const GROUPED_PAIR_MASK: u32 = 0xff21_ffe1;
const GROUPED_QUARTET_MASK: u32 = 0xff23_ffe3;
const SINGLE_PAIR_MASK: u32 = 0xff30_ffe1;
const SINGLE_QUARTET_MASK: u32 = 0xff30_ffe3;
const CONVERT_QUARTET_MASK: u32 = 0xff7f_fc60;
const SHIFT_NARROW_PAIR_MASK: u32 = 0xfff0_fc20;
const CONVERT_PAIR_MASK: u32 = 0xffff_fc20;
const ADD_MZ_ZZV_2X1: u32 = 0xc120_a300;
const ADD_MZ_ZZV_4X1: u32 = 0xc120_ab00;
const SCLAMP_MZ_ZZ_2: u32 = 0xc120_c400;
const SCLAMP_MZ_ZZ_4: u32 = 0xc120_cc00;
const SMAX_MZ_ZZV_2X1: u32 = 0xc120_a000;
const SMAX_MZ_ZZV_4X1: u32 = 0xc120_a800;
const SMAX_MZ_ZZW_2X2: u32 = 0xc120_b000;
const SMAX_MZ_ZZW_4X4: u32 = 0xc120_b800;
const SMIN_MZ_ZZV_2X1: u32 = 0xc120_a020;
const SMIN_MZ_ZZV_4X1: u32 = 0xc120_a820;
const SMIN_MZ_ZZW_2X2: u32 = 0xc120_b020;
const SMIN_MZ_ZZW_4X4: u32 = 0xc120_b820;
const SQCVT_Z_MZ2: u32 = 0xc123_e000;
const SQCVT_Z_MZ4: u32 = 0xc133_e000;
const SQCVTN_Z_MZ4: u32 = 0xc133_e040;
const SQCVTU_Z_MZ2: u32 = 0xc163_e000;
const SQCVTU_Z_MZ4: u32 = 0xc173_e000;
const SQCVTUN_Z_MZ4: u32 = 0xc173_e040;
const SQDMULH_MZ_ZZV_2X1: u32 = 0xc120_a400;
const SQDMULH_MZ_ZZV_4X1: u32 = 0xc120_ac00;
const SQDMULH_MZ_ZZW_2X2: u32 = 0xc120_b400;
const SQDMULH_MZ_ZZW_4X4: u32 = 0xc120_bc00;
const SQRSHR_Z_MZ2: u32 = 0xc1e0_d400;
const SQRSHR_Z_MZ4: u32 = 0xc120_d800;
const SQRSHRN_Z_MZ4: u32 = 0xc120_dc00;
const SQRSHRU_Z_MZ2: u32 = 0xc1f0_d400;
const SQRSHRU_Z_MZ4: u32 = 0xc120_d840;
const SQRSHRUN_Z_MZ4: u32 = 0xc120_dc40;
const SRSHL_MZ_ZZV_2X1: u32 = 0xc120_a220;
const SRSHL_MZ_ZZV_4X1: u32 = 0xc120_aa20;
const SRSHL_MZ_ZZW_2X2: u32 = 0xc120_b220;
const SRSHL_MZ_ZZW_4X4: u32 = 0xc120_ba20;
const UCLAMP_MZ_ZZ_2: u32 = 0xc120_c401;
const UCLAMP_MZ_ZZ_4: u32 = 0xc120_cc01;
const UMAX_MZ_ZZV_2X1: u32 = 0xc120_a001;
const UMAX_MZ_ZZV_4X1: u32 = 0xc120_a801;
const UMAX_MZ_ZZW_2X2: u32 = 0xc120_b001;
const UMAX_MZ_ZZW_4X4: u32 = 0xc120_b801;
const UMIN_MZ_ZZV_2X1: u32 = 0xc120_a021;
const UMIN_MZ_ZZV_4X1: u32 = 0xc120_a821;
const UMIN_MZ_ZZW_2X2: u32 = 0xc120_b021;
const UMIN_MZ_ZZW_4X4: u32 = 0xc120_b821;
const UQCVT_Z_MZ2: u32 = 0xc123_e020;
const UQCVT_Z_MZ4: u32 = 0xc133_e020;
const UQCVTN_Z_MZ4: u32 = 0xc133_e060;
const UQRSHR_Z_MZ2: u32 = 0xc1e0_d420;
const UQRSHR_Z_MZ4: u32 = 0xc120_d820;
const UQRSHRN_Z_MZ4: u32 = 0xc120_dc20;
const URSHL_MZ_ZZV_2X1: u32 = 0xc120_a221;
const URSHL_MZ_ZZV_4X1: u32 = 0xc120_aa21;
const URSHL_MZ_ZZW_2X2: u32 = 0xc120_b221;
const URSHL_MZ_ZZW_4X4: u32 = 0xc120_ba21;

const SQCVTN_Z_MZ2: u32 = 0x4531_4000;
const SQCVTUN_Z_MZ2: u32 = 0x4531_5000;
const SQRSHRN_Z_MZ2: u32 = 0x45b0_2800;
const SQRSHRUN_Z_MZ2: u32 = 0x45b0_0800;
const UQCVTN_Z_MZ2: u32 = 0x4531_4800;
const UQRSHRN_Z_MZ2: u32 = 0x45b0_3800;

const ARITHMETIC_ENCODINGS: [ArithmeticEncoding; 34] = [
    ArithmeticEncoding {
        mask: SINGLE_PAIR_MASK,
        opcode: ADD_MZ_ZZV_2X1,
        kind: ArithmeticKind::Add,
        group: Group::Pair,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: SINGLE_QUARTET_MASK,
        opcode: ADD_MZ_ZZV_4X1,
        kind: ArithmeticKind::Add,
        group: Group::Quartet,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: CLAMP_PAIR_MASK,
        opcode: SCLAMP_MZ_ZZ_2,
        kind: ArithmeticKind::Clamp(Signedness::Signed),
        group: Group::Pair,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: CLAMP_QUARTET_MASK,
        opcode: SCLAMP_MZ_ZZ_4,
        kind: ArithmeticKind::Clamp(Signedness::Signed),
        group: Group::Quartet,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: SINGLE_PAIR_MASK,
        opcode: SMAX_MZ_ZZV_2X1,
        kind: ArithmeticKind::Maximum(Signedness::Signed),
        group: Group::Pair,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: SINGLE_QUARTET_MASK,
        opcode: SMAX_MZ_ZZV_4X1,
        kind: ArithmeticKind::Maximum(Signedness::Signed),
        group: Group::Quartet,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: GROUPED_PAIR_MASK,
        opcode: SMAX_MZ_ZZW_2X2,
        kind: ArithmeticKind::Maximum(Signedness::Signed),
        group: Group::Pair,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: GROUPED_QUARTET_MASK,
        opcode: SMAX_MZ_ZZW_4X4,
        kind: ArithmeticKind::Maximum(Signedness::Signed),
        group: Group::Quartet,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: SINGLE_PAIR_MASK,
        opcode: SMIN_MZ_ZZV_2X1,
        kind: ArithmeticKind::Minimum(Signedness::Signed),
        group: Group::Pair,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: SINGLE_QUARTET_MASK,
        opcode: SMIN_MZ_ZZV_4X1,
        kind: ArithmeticKind::Minimum(Signedness::Signed),
        group: Group::Quartet,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: GROUPED_PAIR_MASK,
        opcode: SMIN_MZ_ZZW_2X2,
        kind: ArithmeticKind::Minimum(Signedness::Signed),
        group: Group::Pair,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: GROUPED_QUARTET_MASK,
        opcode: SMIN_MZ_ZZW_4X4,
        kind: ArithmeticKind::Minimum(Signedness::Signed),
        group: Group::Quartet,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: SINGLE_PAIR_MASK,
        opcode: SQDMULH_MZ_ZZV_2X1,
        kind: ArithmeticKind::SaturatingDoublingMultiplyHigh,
        group: Group::Pair,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: SINGLE_QUARTET_MASK,
        opcode: SQDMULH_MZ_ZZV_4X1,
        kind: ArithmeticKind::SaturatingDoublingMultiplyHigh,
        group: Group::Quartet,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: GROUPED_PAIR_MASK,
        opcode: SQDMULH_MZ_ZZW_2X2,
        kind: ArithmeticKind::SaturatingDoublingMultiplyHigh,
        group: Group::Pair,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: GROUPED_QUARTET_MASK,
        opcode: SQDMULH_MZ_ZZW_4X4,
        kind: ArithmeticKind::SaturatingDoublingMultiplyHigh,
        group: Group::Quartet,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: SINGLE_PAIR_MASK,
        opcode: SRSHL_MZ_ZZV_2X1,
        kind: ArithmeticKind::RoundingShift(Signedness::Signed),
        group: Group::Pair,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: SINGLE_QUARTET_MASK,
        opcode: SRSHL_MZ_ZZV_4X1,
        kind: ArithmeticKind::RoundingShift(Signedness::Signed),
        group: Group::Quartet,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: GROUPED_PAIR_MASK,
        opcode: SRSHL_MZ_ZZW_2X2,
        kind: ArithmeticKind::RoundingShift(Signedness::Signed),
        group: Group::Pair,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: GROUPED_QUARTET_MASK,
        opcode: SRSHL_MZ_ZZW_4X4,
        kind: ArithmeticKind::RoundingShift(Signedness::Signed),
        group: Group::Quartet,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: CLAMP_PAIR_MASK,
        opcode: UCLAMP_MZ_ZZ_2,
        kind: ArithmeticKind::Clamp(Signedness::Unsigned),
        group: Group::Pair,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: CLAMP_QUARTET_MASK,
        opcode: UCLAMP_MZ_ZZ_4,
        kind: ArithmeticKind::Clamp(Signedness::Unsigned),
        group: Group::Quartet,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: SINGLE_PAIR_MASK,
        opcode: UMAX_MZ_ZZV_2X1,
        kind: ArithmeticKind::Maximum(Signedness::Unsigned),
        group: Group::Pair,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: SINGLE_QUARTET_MASK,
        opcode: UMAX_MZ_ZZV_4X1,
        kind: ArithmeticKind::Maximum(Signedness::Unsigned),
        group: Group::Quartet,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: GROUPED_PAIR_MASK,
        opcode: UMAX_MZ_ZZW_2X2,
        kind: ArithmeticKind::Maximum(Signedness::Unsigned),
        group: Group::Pair,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: GROUPED_QUARTET_MASK,
        opcode: UMAX_MZ_ZZW_4X4,
        kind: ArithmeticKind::Maximum(Signedness::Unsigned),
        group: Group::Quartet,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: SINGLE_PAIR_MASK,
        opcode: UMIN_MZ_ZZV_2X1,
        kind: ArithmeticKind::Minimum(Signedness::Unsigned),
        group: Group::Pair,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: SINGLE_QUARTET_MASK,
        opcode: UMIN_MZ_ZZV_4X1,
        kind: ArithmeticKind::Minimum(Signedness::Unsigned),
        group: Group::Quartet,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: GROUPED_PAIR_MASK,
        opcode: UMIN_MZ_ZZW_2X2,
        kind: ArithmeticKind::Minimum(Signedness::Unsigned),
        group: Group::Pair,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: GROUPED_QUARTET_MASK,
        opcode: UMIN_MZ_ZZW_4X4,
        kind: ArithmeticKind::Minimum(Signedness::Unsigned),
        group: Group::Quartet,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: SINGLE_PAIR_MASK,
        opcode: URSHL_MZ_ZZV_2X1,
        kind: ArithmeticKind::RoundingShift(Signedness::Unsigned),
        group: Group::Pair,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: SINGLE_QUARTET_MASK,
        opcode: URSHL_MZ_ZZV_4X1,
        kind: ArithmeticKind::RoundingShift(Signedness::Unsigned),
        group: Group::Quartet,
        right_grouped: false,
    },
    ArithmeticEncoding {
        mask: GROUPED_PAIR_MASK,
        opcode: URSHL_MZ_ZZW_2X2,
        kind: ArithmeticKind::RoundingShift(Signedness::Unsigned),
        group: Group::Pair,
        right_grouped: true,
    },
    ArithmeticEncoding {
        mask: GROUPED_QUARTET_MASK,
        opcode: URSHL_MZ_ZZW_4X4,
        kind: ArithmeticKind::RoundingShift(Signedness::Unsigned),
        group: Group::Quartet,
        right_grouped: true,
    },
];

const NARROW_ENCODINGS: [NarrowEncoding; 24] = [
    NarrowEncoding {
        mask: CONVERT_PAIR_MASK,
        opcode: SQCVT_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Signed,
        rounded_shift: false,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: CONVERT_QUARTET_MASK,
        opcode: SQCVT_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Signed,
        rounded_shift: false,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: CONVERT_QUARTET_MASK,
        opcode: SQCVTN_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Signed,
        rounded_shift: false,
        streaming_only: true,
        interleaved: true,
    },
    NarrowEncoding {
        mask: CONVERT_PAIR_MASK,
        opcode: SQCVTU_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: false,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: CONVERT_QUARTET_MASK,
        opcode: SQCVTU_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: false,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: CONVERT_QUARTET_MASK,
        opcode: SQCVTUN_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: false,
        streaming_only: true,
        interleaved: true,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_PAIR_MASK,
        opcode: SQRSHR_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Signed,
        rounded_shift: true,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_QUARTET_MASK,
        opcode: SQRSHR_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Signed,
        rounded_shift: true,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_QUARTET_MASK,
        opcode: SQRSHRN_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Signed,
        rounded_shift: true,
        streaming_only: true,
        interleaved: true,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_PAIR_MASK,
        opcode: SQRSHRU_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: true,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_QUARTET_MASK,
        opcode: SQRSHRU_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: true,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_QUARTET_MASK,
        opcode: SQRSHRUN_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: true,
        streaming_only: true,
        interleaved: true,
    },
    NarrowEncoding {
        mask: CONVERT_PAIR_MASK,
        opcode: UQCVT_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Unsigned,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: false,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: CONVERT_QUARTET_MASK,
        opcode: UQCVT_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Unsigned,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: false,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: CONVERT_QUARTET_MASK,
        opcode: UQCVTN_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Unsigned,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: false,
        streaming_only: true,
        interleaved: true,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_PAIR_MASK,
        opcode: UQRSHR_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Unsigned,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: true,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_QUARTET_MASK,
        opcode: UQRSHR_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Unsigned,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: true,
        streaming_only: true,
        interleaved: false,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_QUARTET_MASK,
        opcode: UQRSHRN_Z_MZ4,
        group: Group::Quartet,
        source_signedness: Signedness::Unsigned,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: true,
        streaming_only: true,
        interleaved: true,
    },
    NarrowEncoding {
        mask: CONVERT_PAIR_MASK,
        opcode: SQCVTN_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Signed,
        rounded_shift: false,
        streaming_only: false,
        interleaved: true,
    },
    NarrowEncoding {
        mask: CONVERT_PAIR_MASK,
        opcode: SQCVTUN_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: false,
        streaming_only: false,
        interleaved: true,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_PAIR_MASK,
        opcode: SQRSHRN_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Signed,
        rounded_shift: true,
        streaming_only: false,
        interleaved: true,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_PAIR_MASK,
        opcode: SQRSHRUN_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Signed,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: true,
        streaming_only: false,
        interleaved: true,
    },
    NarrowEncoding {
        mask: CONVERT_PAIR_MASK,
        opcode: UQCVTN_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Unsigned,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: false,
        streaming_only: false,
        interleaved: true,
    },
    NarrowEncoding {
        mask: SHIFT_NARROW_PAIR_MASK,
        opcode: UQRSHRN_Z_MZ2,
        group: Group::Pair,
        source_signedness: Signedness::Unsigned,
        destination_signedness: Signedness::Unsigned,
        rounded_shift: true,
        streaming_only: false,
        interleaved: true,
    },
];

fn element(size: u32) -> ElementSize {
    match size {
        0 => ElementSize::Byte,
        1 => ElementSize::Halfword,
        2 => ElementSize::Word,
        3 => ElementSize::Doubleword,
        _ => unreachable!(),
    }
}

pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    for encoding in &ARITHMETIC_ENCODINGS {
        if word & encoding.mask != encoding.opcode {
            continue;
        }
        let register_count = encoding.group.count();
        let destination = (word & (u32::from(VECTOR_REGISTER_COUNT - register_count))) as u8;
        let clamp = matches!(encoding.kind, ArithmeticKind::Clamp(_));
        let right = if clamp {
            ((word >> SINGLE_SOURCE_SHIFT) & REGISTER_MASK) as u8
        } else if encoding.right_grouped {
            let shift = match encoding.group {
                Group::Pair => PAIR_SOURCE_SHIFT,
                Group::Quartet => QUARTET_SOURCE_SHIFT,
            };
            (((word >> shift) & (REGISTER_MASK / u32::from(register_count))) as u8) * register_count
        } else {
            ((word >> SINGLE_SOURCE_SHIFT) & SINGLE_SOURCE_MASK) as u8
        };
        return Some(Ok(Operand::Arithmetic(Arithmetic {
            kind: encoding.kind,
            destination,
            right,
            lower: clamp.then_some(((word >> CLAMP_LOWER_SHIFT) & REGISTER_MASK) as u8),
            group: encoding.group,
            element: element((word >> SIZE_SHIFT) & SIZE_MASK),
            right_grouped: encoding.right_grouped,
        })));
    }
    for encoding in &NARROW_ENCODINGS {
        if word & encoding.mask != encoding.opcode {
            continue;
        }
        let register_count = encoding.group.count();
        let (source_shift, destination_bits, shift) = match encoding.group {
            Group::Pair => (
                NARROW_PAIR_SOURCE_SHIFT,
                PAIR_DESTINATION_BITS,
                if encoding.rounded_shift {
                    PAIR_DESTINATION_BITS
                        - ((word >> NARROW_IMMEDIATE_SHIFT) & PAIR_SHIFT_IMMEDIATE_MASK) as u8
                } else {
                    0
                },
            ),
            Group::Quartet => {
                if encoding.rounded_shift {
                    let size = (word >> NARROW_SHIFT_SIZE_SHIFT) & SIZE_MASK;
                    let destination_bits = match size {
                        0 => return Some(Err(Unsupported)),
                        1 => ElementSize::Byte.bits(),
                        _ => ElementSize::Halfword.bits(),
                    } as u8;
                    let immediate = (size << QUARTET_SIZE_IMMEDIATE_SHIFT)
                        | ((word >> NARROW_IMMEDIATE_SHIFT) & QUARTET_SHIFT_IMMEDIATE_MASK);
                    (
                        NARROW_QUARTET_SOURCE_SHIFT,
                        destination_bits,
                        destination_bits * SHIFT_ENCODING_SCALE - immediate as u8,
                    )
                } else {
                    (
                        NARROW_QUARTET_SOURCE_SHIFT,
                        (ElementSize::Byte.bits() << ((word >> NARROW_SIZE_SHIFT) & 1)) as u8,
                        0,
                    )
                }
            }
        };
        let source = (((word >> source_shift) & (REGISTER_MASK / u32::from(register_count))) as u8)
            * register_count;
        let destination_element =
            ElementSize::from_bytes(usize::from(destination_bits) / BITS_PER_BYTE).unwrap();
        let source_element =
            ElementSize::from_bytes(destination_element.bytes() * usize::from(register_count))
                .unwrap();
        return Some(Ok(Operand::Narrow(Narrow {
            destination: (word & REGISTER_MASK) as u8,
            source,
            group: encoding.group,
            source_element,
            destination_element,
            source_signedness: encoding.source_signedness,
            destination_signedness: encoding.destination_signedness,
            shift,
            interleaved: encoding.interleaved,
            streaming_only: encoding.streaming_only,
        })));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_widths_groups_and_register_edges() {
        for encoding in &ARITHMETIC_ENCODINGS {
            let register_count = encoding.group.count();
            let clamp = matches!(encoding.kind, ArithmeticKind::Clamp(_));
            let right_shift = if clamp || !encoding.right_grouped {
                SINGLE_SOURCE_SHIFT
            } else {
                match encoding.group {
                    Group::Pair => PAIR_SOURCE_SHIFT,
                    Group::Quartet => QUARTET_SOURCE_SHIFT,
                }
            };
            let source_limit = if clamp {
                REGISTER_MASK
            } else if encoding.right_grouped {
                REGISTER_MASK / u32::from(register_count)
            } else {
                SINGLE_SOURCE_MASK
            };
            for size in 0..=SIZE_MASK {
                for destination in (0..VECTOR_REGISTER_COUNT).step_by(usize::from(register_count)) {
                    for right in 0..=source_limit {
                        for lower in if clamp { 0..=REGISTER_MASK } else { 0..=0 } {
                            let word = encoding.opcode
                                | (size << SIZE_SHIFT)
                                | u32::from(destination)
                                | (right << right_shift)
                                | (lower << CLAMP_LOWER_SHIFT);
                            let operand = decode(word).unwrap().unwrap();
                            assert_eq!(
                                operand,
                                Operand::Arithmetic(Arithmetic {
                                    kind: encoding.kind,
                                    destination,
                                    right: (right as u8)
                                        * if encoding.right_grouped {
                                            register_count
                                        } else {
                                            1
                                        },
                                    lower: clamp.then_some(lower as u8),
                                    group: encoding.group,
                                    element: element(size),
                                    right_grouped: encoding.right_grouped,
                                })
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn narrowing_all_destination_aliases_and_source_group_edges() {
        for encoding in &NARROW_ENCODINGS {
            let register_count = encoding.group.count();
            let source_shift = match encoding.group {
                Group::Pair => NARROW_PAIR_SOURCE_SHIFT,
                Group::Quartet => NARROW_QUARTET_SOURCE_SHIFT,
            };
            let source_limit = VECTOR_REGISTER_COUNT / register_count;
            for source in 0..source_limit {
                for destination in 0..VECTOR_REGISTER_COUNT {
                    let word = encoding.opcode
                        | (u32::from(source) << source_shift)
                        | u32::from(destination)
                        | if encoding.rounded_shift && encoding.group == Group::Quartet {
                            1 << NARROW_SHIFT_SIZE_SHIFT
                        } else {
                            0
                        };
                    let operand = decode(word).unwrap().unwrap();
                    let Operand::Narrow(narrow) = operand else {
                        panic!("matched non-narrow operand");
                    };
                    assert_eq!(narrow.source, source * register_count);
                    assert_eq!(narrow.destination, destination);
                    assert_eq!(narrow.group, encoding.group);
                    assert_eq!(
                        narrow.source_element.bytes(),
                        narrow.destination_element.bytes() * usize::from(register_count)
                    );
                    assert_eq!(narrow.interleaved, encoding.interleaved);
                    assert_eq!(narrow.source_signedness, encoding.source_signedness);
                    assert_eq!(
                        narrow.destination_signedness,
                        encoding.destination_signedness
                    );
                }
            }
        }
    }

    #[test]
    fn quartet_narrow_shift_size_and_full_width_rounding() {
        for encoding in NARROW_ENCODINGS
            .into_iter()
            .filter(|encoding| encoding.rounded_shift && encoding.group == Group::Quartet)
        {
            for size in 0..=SIZE_MASK {
                for immediate in 0..=QUARTET_SHIFT_IMMEDIATE_MASK {
                    let word = (encoding.opcode & !(SIZE_MASK << NARROW_SHIFT_SIZE_SHIFT))
                        | (size << NARROW_SHIFT_SIZE_SHIFT)
                        | (immediate << NARROW_IMMEDIATE_SHIFT);
                    if size == 0 {
                        assert_eq!(decode(word), Some(Err(Unsupported)));
                        continue;
                    }
                    let Operand::Narrow(narrow) = decode(word).unwrap().unwrap() else {
                        panic!("matched non-narrow operand");
                    };
                    let (width, shift) = match size {
                        1 => (ElementSize::Byte, 32 - immediate),
                        2 => (ElementSize::Halfword, 64 - immediate),
                        3 => (ElementSize::Halfword, 32 - immediate),
                        _ => unreachable!(),
                    };
                    assert_eq!(narrow.destination_element, width);
                    assert_eq!(u32::from(narrow.shift), shift);
                }
            }
        }
    }

    #[test]
    fn pair_narrow_rounds_from_one_through_sixteen() {
        for encoding in NARROW_ENCODINGS
            .into_iter()
            .filter(|encoding| encoding.rounded_shift && encoding.group == Group::Pair)
        {
            for immediate in 0..=PAIR_SHIFT_IMMEDIATE_MASK {
                let Operand::Narrow(narrow) =
                    decode(encoding.opcode | (immediate << NARROW_IMMEDIATE_SHIFT))
                        .unwrap()
                        .unwrap()
                else {
                    panic!("matched non-narrow operand");
                };
                assert_eq!(narrow.source_element, ElementSize::Word);
                assert_eq!(narrow.destination_element, ElementSize::Halfword);
                assert_eq!(u32::from(narrow.shift), 16 - immediate);
            }
        }
    }

    #[test]
    fn unrelated_words_do_not_enter_this_family() {
        for word in [0, 0xffff_ffff, 0xd503_201f, 0x9100_0400, 0x0420_0000] {
            assert_eq!(decode(word), None);
        }
    }
}
