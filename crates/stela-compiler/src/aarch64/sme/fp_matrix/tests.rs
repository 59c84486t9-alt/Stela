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
        decode_vector(FMLA_ZA_ZZI_H4XI | (3 << INDEX_HIGH_SHIFT) | (1 << INDEX_LOW_SHIFT)).unwrap();
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
fn row_groups_partition_the_actual_streaming_length() {
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
