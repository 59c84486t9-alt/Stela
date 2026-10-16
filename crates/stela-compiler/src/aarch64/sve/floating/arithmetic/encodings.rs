//! Fixed bits and operand layouts of the SVE floating-point arithmetic forms.
use super::{
    BinaryOperation, Encoding, Format, FusedOperation, Immediate, Kind, Layout, MinMaxOperation,
    ResultShape, Rotation, estimate, refinement,
};

// Canonical fixed masks keep indexed H/S/D and merge/zeroing encodings distinct.
pub(super) const ENCODINGS: &[Encoding] = &[
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6508_8000,
        kind: Kind::Binary(BinaryOperation::AbsoluteDifference),
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fabd_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x041c_a000,
        kind: Kind::Absolute,
        layout: Layout::Unary { predicated: true },
    }, // fabs_z_p_z_m
    Encoding {
        mask: 0xff3f_e3c0,
        value: 0x6518_8000,
        kind: Kind::Binary(BinaryOperation::Add),
        layout: Layout::Immediate {
            value: Immediate::HalfOrOne,
            reverse: false,
        },
    }, // fadd_z_p_zs_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6500_8000,
        kind: Kind::Binary(BinaryOperation::Add),
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fadd_z_p_zz_
    Encoding {
        mask: 0xff20_fc00,
        value: 0x6500_0000,
        kind: Kind::Binary(BinaryOperation::Add),
        layout: Layout::Binary,
    }, // fadd_z_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6410_8000,
        kind: Kind::Binary(BinaryOperation::Add),
        layout: Layout::Pairwise,
    }, // faddp_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6410_a000,
        kind: Kind::Binary(BinaryOperation::Add),
        layout: Layout::Reduction(ResultShape::QuadReduction),
    }, // faddqv_z_p_z_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6500_2000,
        kind: Kind::Binary(BinaryOperation::Add),
        layout: Layout::Reduction(ResultShape::ScalarReduction),
    }, // faddv_v_p_z_
    Encoding {
        mask: 0xff3e_e000,
        value: 0x6400_8000,
        kind: Kind::ComplexAdd(Rotation::Degrees0),
        layout: Layout::ComplexAdd,
    }, // fcadd_z_p_zz_
    Encoding {
        mask: 0xff20_fc00,
        value: 0x6420_2400,
        kind: Kind::Clamp,
        layout: Layout::Clamp,
    }, // fclamp_z_zz_
    Encoding {
        mask: 0xff20_8000,
        value: 0x6400_0000,
        kind: Kind::ComplexMultiplyAdd(Rotation::Degrees0),
        layout: Layout::ComplexFused,
    }, // fcmla_z_p_zzz_
    Encoding {
        mask: 0xffe0_f000,
        value: 0x64a0_1000,
        kind: Kind::ComplexMultiplyAdd(Rotation::Degrees0),
        layout: Layout::ComplexIndexed(Format::Half),
    }, // fcmla_z_zzzi_h
    Encoding {
        mask: 0xffe0_f000,
        value: 0x64e0_1000,
        kind: Kind::ComplexMultiplyAdd(Rotation::Degrees0),
        layout: Layout::ComplexIndexed(Format::Single),
    }, // fcmla_z_zzzi_s
    Encoding {
        mask: 0xff3f_e000,
        value: 0x650d_8000,
        kind: Kind::Binary(BinaryOperation::Divide),
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fdiv_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x650c_8000,
        kind: Kind::Binary(BinaryOperation::Divide),
        layout: Layout::PredicatedBinary { reverse: true },
    }, // fdivr_z_p_zz_
    Encoding {
        mask: 0xfff9_e000,
        value: 0x6518_a000,
        kind: Kind::Logb,
        layout: Layout::Logb,
    }, // flogb_z_p_z_m
    Encoding {
        mask: 0xff20_e000,
        value: 0x6520_8000,
        kind: Kind::Fused(FusedOperation::Add),
        layout: Layout::Fused {
            destructive_left: true,
        },
    }, // fmad_z_p_zzz_
    Encoding {
        mask: 0xff3f_e3c0,
        value: 0x651e_8000,
        kind: Kind::MinMax(MinMaxOperation::Maximum),
        layout: Layout::Immediate {
            value: Immediate::ZeroOrOne,
            reverse: false,
        },
    }, // fmax_z_p_zs_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6506_8000,
        kind: Kind::MinMax(MinMaxOperation::Maximum),
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fmax_z_p_zz_
    Encoding {
        mask: 0xff3f_e3c0,
        value: 0x651c_8000,
        kind: Kind::MinMax(MinMaxOperation::MaximumNumber),
        layout: Layout::Immediate {
            value: Immediate::ZeroOrOne,
            reverse: false,
        },
    }, // fmaxnm_z_p_zs_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6504_8000,
        kind: Kind::MinMax(MinMaxOperation::MaximumNumber),
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fmaxnm_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6414_8000,
        kind: Kind::MinMax(MinMaxOperation::MaximumNumber),
        layout: Layout::Pairwise,
    }, // fmaxnmp_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6414_a000,
        kind: Kind::MinMax(MinMaxOperation::MaximumNumber),
        layout: Layout::Reduction(ResultShape::QuadReduction),
    }, // fmaxnmqv_z_p_z_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6504_2000,
        kind: Kind::MinMax(MinMaxOperation::MaximumNumber),
        layout: Layout::Reduction(ResultShape::ScalarReduction),
    }, // fmaxnmv_v_p_z_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6416_8000,
        kind: Kind::MinMax(MinMaxOperation::Maximum),
        layout: Layout::Pairwise,
    }, // fmaxp_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6416_a000,
        kind: Kind::MinMax(MinMaxOperation::Maximum),
        layout: Layout::Reduction(ResultShape::QuadReduction),
    }, // fmaxqv_z_p_z_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6506_2000,
        kind: Kind::MinMax(MinMaxOperation::Maximum),
        layout: Layout::Reduction(ResultShape::ScalarReduction),
    }, // fmaxv_v_p_z_
    Encoding {
        mask: 0xff3f_e3c0,
        value: 0x651f_8000,
        kind: Kind::MinMax(MinMaxOperation::Minimum),
        layout: Layout::Immediate {
            value: Immediate::ZeroOrOne,
            reverse: false,
        },
    }, // fmin_z_p_zs_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6507_8000,
        kind: Kind::MinMax(MinMaxOperation::Minimum),
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fmin_z_p_zz_
    Encoding {
        mask: 0xff3f_e3c0,
        value: 0x651d_8000,
        kind: Kind::MinMax(MinMaxOperation::MinimumNumber),
        layout: Layout::Immediate {
            value: Immediate::ZeroOrOne,
            reverse: false,
        },
    }, // fminnm_z_p_zs_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6505_8000,
        kind: Kind::MinMax(MinMaxOperation::MinimumNumber),
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fminnm_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6415_8000,
        kind: Kind::MinMax(MinMaxOperation::MinimumNumber),
        layout: Layout::Pairwise,
    }, // fminnmp_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6415_a000,
        kind: Kind::MinMax(MinMaxOperation::MinimumNumber),
        layout: Layout::Reduction(ResultShape::QuadReduction),
    }, // fminnmqv_z_p_z_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6505_2000,
        kind: Kind::MinMax(MinMaxOperation::MinimumNumber),
        layout: Layout::Reduction(ResultShape::ScalarReduction),
    }, // fminnmv_v_p_z_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6417_8000,
        kind: Kind::MinMax(MinMaxOperation::Minimum),
        layout: Layout::Pairwise,
    }, // fminp_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6417_a000,
        kind: Kind::MinMax(MinMaxOperation::Minimum),
        layout: Layout::Reduction(ResultShape::QuadReduction),
    }, // fminqv_z_p_z_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6507_2000,
        kind: Kind::MinMax(MinMaxOperation::Minimum),
        layout: Layout::Reduction(ResultShape::ScalarReduction),
    }, // fminv_v_p_z_
    Encoding {
        mask: 0xff20_e000,
        value: 0x6520_0000,
        kind: Kind::Fused(FusedOperation::Add),
        layout: Layout::Fused {
            destructive_left: false,
        },
    }, // fmla_z_p_zzz_
    Encoding {
        mask: 0xffe0_fc00,
        value: 0x64e0_0000,
        kind: Kind::Fused(FusedOperation::Add),
        layout: Layout::IndexedFused(Format::Double),
    }, // fmla_z_zzzi_d
    Encoding {
        mask: 0xffa0_fc00,
        value: 0x6420_0000,
        kind: Kind::Fused(FusedOperation::Add),
        layout: Layout::IndexedFused(Format::Half),
    }, // fmla_z_zzzi_h
    Encoding {
        mask: 0xffe0_fc00,
        value: 0x64a0_0000,
        kind: Kind::Fused(FusedOperation::Add),
        layout: Layout::IndexedFused(Format::Single),
    }, // fmla_z_zzzi_s
    Encoding {
        mask: 0xff20_e000,
        value: 0x6520_2000,
        kind: Kind::Fused(FusedOperation::Subtract),
        layout: Layout::Fused {
            destructive_left: false,
        },
    }, // fmls_z_p_zzz_
    Encoding {
        mask: 0xffe0_fc00,
        value: 0x64e0_0400,
        kind: Kind::Fused(FusedOperation::Subtract),
        layout: Layout::IndexedFused(Format::Double),
    }, // fmls_z_zzzi_d
    Encoding {
        mask: 0xffa0_fc00,
        value: 0x6420_0400,
        kind: Kind::Fused(FusedOperation::Subtract),
        layout: Layout::IndexedFused(Format::Half),
    }, // fmls_z_zzzi_h
    Encoding {
        mask: 0xffe0_fc00,
        value: 0x64a0_0400,
        kind: Kind::Fused(FusedOperation::Subtract),
        layout: Layout::IndexedFused(Format::Single),
    }, // fmls_z_zzzi_s
    Encoding {
        mask: 0xff20_e000,
        value: 0x6520_a000,
        kind: Kind::Fused(FusedOperation::Subtract),
        layout: Layout::Fused {
            destructive_left: true,
        },
    }, // fmsb_z_p_zzz_
    Encoding {
        mask: 0xff3f_e3c0,
        value: 0x651a_8000,
        kind: Kind::Binary(BinaryOperation::Multiply),
        layout: Layout::Immediate {
            value: Immediate::HalfOrTwo,
            reverse: false,
        },
    }, // fmul_z_p_zs_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6502_8000,
        kind: Kind::Binary(BinaryOperation::Multiply),
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fmul_z_p_zz_
    Encoding {
        mask: 0xff20_fc00,
        value: 0x6500_0800,
        kind: Kind::Binary(BinaryOperation::Multiply),
        layout: Layout::Binary,
    }, // fmul_z_zz_
    Encoding {
        mask: 0xffe0_fc00,
        value: 0x64e0_2000,
        kind: Kind::Binary(BinaryOperation::Multiply),
        layout: Layout::IndexedBinary(Format::Double),
    }, // fmul_z_zzi_d
    Encoding {
        mask: 0xffa0_fc00,
        value: 0x6420_2000,
        kind: Kind::Binary(BinaryOperation::Multiply),
        layout: Layout::IndexedBinary(Format::Half),
    }, // fmul_z_zzi_h
    Encoding {
        mask: 0xffe0_fc00,
        value: 0x64a0_2000,
        kind: Kind::Binary(BinaryOperation::Multiply),
        layout: Layout::IndexedBinary(Format::Single),
    }, // fmul_z_zzi_s
    Encoding {
        mask: 0xff3f_e000,
        value: 0x650a_8000,
        kind: Kind::Binary(BinaryOperation::MultiplyExtended),
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fmulx_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x041d_a000,
        kind: Kind::Negate,
        layout: Layout::Unary { predicated: true },
    }, // fneg_z_p_z_m
    Encoding {
        mask: 0xff20_e000,
        value: 0x6520_c000,
        kind: Kind::Fused(FusedOperation::NegatedAdd),
        layout: Layout::Fused {
            destructive_left: true,
        },
    }, // fnmad_z_p_zzz_
    Encoding {
        mask: 0xff20_e000,
        value: 0x6520_4000,
        kind: Kind::Fused(FusedOperation::NegatedAdd),
        layout: Layout::Fused {
            destructive_left: false,
        },
    }, // fnmla_z_p_zzz_
    Encoding {
        mask: 0xff20_e000,
        value: 0x6520_6000,
        kind: Kind::Fused(FusedOperation::NegatedSubtract),
        layout: Layout::Fused {
            destructive_left: false,
        },
    }, // fnmls_z_p_zzz_
    Encoding {
        mask: 0xff20_e000,
        value: 0x6520_e000,
        kind: Kind::Fused(FusedOperation::NegatedSubtract),
        layout: Layout::Fused {
            destructive_left: true,
        },
    }, // fnmsb_z_p_zzz_
    Encoding {
        mask: 0xff3f_fc00,
        value: 0x650e_3000,
        kind: Kind::Estimate(estimate::Kind::Reciprocal),
        layout: Layout::Unary { predicated: false },
    }, // frecpe_z_z_
    Encoding {
        mask: 0xff20_fc00,
        value: 0x6500_1800,
        kind: Kind::Refinement(refinement::Kind::Reciprocal),
        layout: Layout::Binary,
    }, // frecps_z_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x650c_a000,
        kind: Kind::Estimate(estimate::Kind::ReciprocalExponent),
        layout: Layout::Unary { predicated: true },
    }, // frecpx_z_p_z_m
    Encoding {
        mask: 0xff3f_fc00,
        value: 0x650f_3000,
        kind: Kind::Estimate(estimate::Kind::ReciprocalSquareRoot),
        layout: Layout::Unary { predicated: false },
    }, // frsqrte_z_z_
    Encoding {
        mask: 0xff20_fc00,
        value: 0x6500_1c00,
        kind: Kind::Refinement(refinement::Kind::ReciprocalSquareRoot),
        layout: Layout::Binary,
    }, // frsqrts_z_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6509_8000,
        kind: Kind::Scale,
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fscale_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x650d_a000,
        kind: Kind::SquareRoot,
        layout: Layout::Unary { predicated: true },
    }, // fsqrt_z_p_z_m
    Encoding {
        mask: 0xff3f_e3c0,
        value: 0x6519_8000,
        kind: Kind::Binary(BinaryOperation::Subtract),
        layout: Layout::Immediate {
            value: Immediate::HalfOrOne,
            reverse: false,
        },
    }, // fsub_z_p_zs_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6501_8000,
        kind: Kind::Binary(BinaryOperation::Subtract),
        layout: Layout::PredicatedBinary { reverse: false },
    }, // fsub_z_p_zz_
    Encoding {
        mask: 0xff20_fc00,
        value: 0x6500_0400,
        kind: Kind::Binary(BinaryOperation::Subtract),
        layout: Layout::Binary,
    }, // fsub_z_zz_
    Encoding {
        mask: 0xff3f_e3c0,
        value: 0x651b_8000,
        kind: Kind::Binary(BinaryOperation::Subtract),
        layout: Layout::Immediate {
            value: Immediate::HalfOrOne,
            reverse: true,
        },
    }, // fsubr_z_p_zs_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x6503_8000,
        kind: Kind::Binary(BinaryOperation::Subtract),
        layout: Layout::PredicatedBinary { reverse: true },
    }, // fsubr_z_p_zz_
    Encoding {
        mask: 0xff3f_e000,
        value: 0x4400_a000,
        kind: Kind::Estimate(estimate::Kind::UnsignedReciprocal),
        layout: Layout::UnsignedEstimate,
    }, // urecpe_z_p_z_m
    Encoding {
        mask: 0xff3f_e000,
        value: 0x4401_a000,
        kind: Kind::Estimate(estimate::Kind::UnsignedReciprocalSquareRoot),
        layout: Layout::UnsignedEstimate,
    }, // ursqrte_z_p_z_m
];
