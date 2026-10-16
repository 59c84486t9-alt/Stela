use super::*;
use alloc::vec::Vec;

const SINGLE_SIZE: u32 = SINGLE_SIZE_ENCODING << SIZE_SHIFT;
const ALL_REGISTERS_AND_PREDICATES: u32 = REGISTER_MASK
    | (REGISTER_MASK << SOURCE_SHIFT)
    | (REGISTER_MASK << SECOND_SOURCE_SHIFT)
    | (PREDICATE_MASK << PREDICATE_SHIFT);
const FADD_PREDICATED: u32 = 0x6500_8000;
const FADD_UNPREDICATED: u32 = 0x6500_0000;
const FMLA_PREDICATED: u32 = 0x6520_0000;
const FCLAMP: u32 = 0x6420_2400;
const FSUBR_IMMEDIATE: u32 = 0x651b_8000;
const FMLA_HALF_INDEXED: u32 = 0x6420_0000;
const FCMLA_SINGLE_INDEXED: u32 = 0x64e0_1000;
const FLOGB: u32 = 0x6518_a000;
const URECPE: u32 = 0x4400_a000;

#[test]
fn every_selected_encoding_accepts_register_and_width_boundaries() {
    for encoding in ENCODINGS {
        for poison in [0, ALL_REGISTERS_AND_PREDICATES] {
            let mut word = encoding.value | (poison & !encoding.mask);
            match encoding.layout {
                Layout::IndexedBinary(_) | Layout::IndexedFused(_) | Layout::ComplexIndexed(_) => {}
                Layout::Logb => word |= SINGLE_SIZE_ENCODING << LOGB_SIZE_SHIFT,
                _ => word |= SINGLE_SIZE,
            }
            assert!(decode(word).is_some_and(|v| v.is_ok()), "{word:08x}");
        }
    }
}

#[test]
fn bfloat_encodings_are_left_for_their_owner() {
    for opcode in [FADD_PREDICATED, FADD_UNPREDICATED, FMLA_PREDICATED, FCLAMP] {
        assert_eq!(decode(opcode), None);
    }
}

#[test]
fn reverse_immediate_keeps_the_immediate_as_left_operand() {
    let operand = decode(FSUBR_IMMEDIATE | SINGLE_SIZE).unwrap().unwrap();
    assert_eq!(operand.kind, Kind::Binary(BinaryOperation::Subtract));
    assert_eq!(
        operand.inputs,
        Inputs::Binary {
            left: Source::ImmediateBits(0x3f00_0000),
            right: Source::Vector(0),
        }
    );
    assert_eq!(operand.predicate, Some(0));
}

#[test]
fn indexed_forms_keep_narrow_register_fields_and_segment_indices() {
    let half = FMLA_HALF_INDEXED
        | (1 << INDEX_HIGH_SHIFT)
        | (3 << INDEX_LOW_SHIFT)
        | (7 << SECOND_SOURCE_SHIFT)
        | (31 << SOURCE_SHIFT)
        | 31;
    let operand = decode(half).unwrap().unwrap();
    assert_eq!(operand.format, Format::Half);
    assert_eq!(
        operand.inputs,
        Inputs::Fused {
            addend: 31,
            left: 31,
            right: Source::Indexed {
                register: 7,
                index: 7
            },
        }
    );
    let single = FCMLA_SINGLE_INDEXED
        | (1 << INDEX_DOUBLE_SHIFT)
        | (15 << SECOND_SOURCE_SHIFT)
        | (3 << COMPLEX_INDEXED_ROTATION_SHIFT);
    let operand = decode(single).unwrap().unwrap();
    assert_eq!(operand.format, Format::Single);
    assert_eq!(operand.kind, Kind::ComplexMultiplyAdd(Rotation::Degrees270));
    assert_eq!(
        operand.inputs,
        Inputs::Fused {
            addend: 0,
            left: 0,
            right: Source::Indexed {
                register: 15,
                index: 1
            },
        }
    );
}

#[test]
fn logb_has_its_distinct_size_position_and_unsigned_estimates_require_words() {
    for (size, expected) in [(1, Format::Half), (2, Format::Single), (3, Format::Double)] {
        let operand = decode(FLOGB | size << LOGB_SIZE_SHIFT).unwrap().unwrap();
        assert_eq!(operand.format, expected);
    }
    for size in 0..=SIZE_MASK {
        let result = decode(URECPE | size << SIZE_SHIFT).unwrap();
        assert_eq!(result.is_ok(), size == SINGLE_SIZE_ENCODING);
    }
}

#[test]
fn multiplicand_destructive_fused_forms_use_za_in_the_high_source_field() {
    const FMAD: u32 = 0x6520_8000;
    let word = FMAD | SINGLE_SIZE | (3 << SECOND_SOURCE_SHIFT) | (2 << SOURCE_SHIFT) | 1;
    let operand = decode(word).unwrap().unwrap();
    assert_eq!(
        operand.inputs,
        Inputs::Fused {
            addend: 3,
            left: 1,
            right: Source::Vector(2),
        }
    );
}

#[test]
fn unrelated_words_do_not_match() {
    for word in [0, u32::MAX, 0xd503_201f, 0x1e20_2800] {
        assert_eq!(decode(word), None);
    }
}

#[test]
fn core_binary_subset_is_seven_classes_with_all_three_widths() {
    const HALF_SIZE: u32 = 1 << SIZE_SHIFT;
    const DOUBLE_SIZE: u32 = 3 << SIZE_SHIFT;
    let selected: Vec<_> = ENCODINGS
        .iter()
        .filter(|e| core_binary_encoding(e))
        .collect();
    assert_eq!(selected.len(), 7);
    for encoding in selected {
        for size in [HALF_SIZE, SINGLE_SIZE, DOUBLE_SIZE] {
            let word = (encoding.value & !(SIZE_MASK << SIZE_SHIFT)) | size;
            assert!(matches!(decode_core_binary(word), Some(Ok(_))));
            assert_eq!(decode_core_binary(word), decode(word));
        }
    }
}

#[test]
fn core_binary_subset_preserves_canonical_direction_under_register_aliases() {
    for operation in [BinaryOperation::Subtract, BinaryOperation::Divide] {
        let selected = |reverse| {
            ENCODINGS.iter().find(|encoding| {
                encoding.kind == Kind::Binary(operation)
                    && matches!(encoding.layout, Layout::PredicatedBinary { reverse: value } if value == reverse)
            }).expect("both forward and reverse allocations are pinned").value | SINGLE_SIZE
        };
        let forward = selected(false);
        let reverse = selected(true);
        // With every register and Pg zero, the typed operand no longer shows
        // the direction, so the encoding class must.
        assert_eq!(decode(forward), decode(reverse));
        assert!(matches!(decode_core_binary(forward), Some(Ok(_))));
        assert_eq!(decode_core_binary(reverse), None);
    }
}
