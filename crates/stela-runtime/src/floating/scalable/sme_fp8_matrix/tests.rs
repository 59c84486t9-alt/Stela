use super::*;
use stela_compiler::aarch64::{
    floating::{FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, features::NumericalFeatures},
    scalable::{ScalableMode, VectorLength},
};

const TEST_SVL_BYTES: usize = 16;
const E4M3_ONE: u8 = 0x38;
const E4M3_SOURCES: u64 = 1 | (1 << fp8::FPMR_F8S2_SHIFT);
const HALF_ONE: u64 = 0x3c00;
const HALF_TWO: u64 = 0x4000;
const SINGLE_ONE: u64 = 0x3f80_0000;
const SINGLE_FOUR: u64 = 0x4080_0000;

fn state() -> (GuestState, ScalableState) {
    let mut state = GuestState {
        fpcr: FPCR_EXCEPTION_ENABLE_MASK,
        fpsr: 0x0800_009f,
        ..GuestState::default()
    };
    let mut scalable = ScalableState::new(VectorLength::from_bytes(TEST_SVL_BYTES).unwrap(), true);
    scalable
        .apply_mode(&mut state, ScalableMode::new(true, true))
        .unwrap();
    scalable.set_fpmr(E4M3_SOURCES);
    for register in 0..VECTOR_REGISTER_COUNT {
        scalable
            .write_z(&mut state, register, &[E4M3_ONE; TEST_SVL_BYTES])
            .unwrap();
    }
    (state, scalable)
}

fn controls(state: &GuestState) -> NumericalControls {
    NumericalControls::new(state.fpcr, true, NumericalFeatures::default())
}

fn vector(operation: VectorOperation, accumulator: Format, groups: u8) -> VectorOperand {
    VectorOperand {
        operation,
        accumulator,
        groups,
        left: 0,
        right: RightSource::Vector(0),
        vector_select: 8,
        offset: 0,
    }
}

#[test]
fn every_vector_layout_preserves_unselected_rows_and_raw_state() {
    for format in [Format::Half, Format::Single] {
        let bytes = width(format).unwrap();
        for groups in [1, 2, 4] {
            for operation in [VectorOperation::Dot, VectorOperation::MultiplyAdd] {
                if groups == 1 && operation == VectorOperation::Dot {
                    continue;
                }
                for right in [
                    RightSource::Vector(0),
                    RightSource::Group(0),
                    RightSource::Indexed {
                        register: 0,
                        index: 15,
                    },
                ] {
                    if operation == VectorOperation::Dot
                        && matches!(right, RightSource::Indexed { .. })
                    {
                        continue;
                    }
                    if groups == 1 && matches!(right, RightSource::Group(_)) {
                        continue;
                    }
                    let (mut state, mut scalable) = state();
                    let original = state.clone();
                    let mut operand = vector(operation, format, groups);
                    operand.right = right;
                    let selected_rows = usize::from(groups)
                        * if operation == VectorOperation::MultiplyAdd {
                            bytes
                        } else {
                            1
                        };
                    let controls = controls(&state);
                    complete(
                        &mut state,
                        &mut scalable,
                        &Operand::Vector(operand),
                        controls,
                    )
                    .unwrap();
                    assert_eq!(state, original);
                    assert_eq!(scalable.fpmr(), E4M3_SOURCES);
                    let mut za = [0; TEST_SVL_BYTES * TEST_SVL_BYTES];
                    scalable.read_za(0, &mut za).unwrap();
                    let expected = match (operation, format) {
                        (VectorOperation::MultiplyAdd, Format::Half) => HALF_ONE,
                        (VectorOperation::MultiplyAdd, Format::Single) => SINGLE_ONE,
                        (_, Format::Half) => HALF_TWO,
                        (_, Format::Single) => SINGLE_FOUR,
                        (_, Format::Double) => unreachable!(),
                    };
                    let mut changed = 0;
                    for row in za.as_chunks::<TEST_SVL_BYTES>().0 {
                        if row.iter().any(|byte| *byte != 0) {
                            changed += 1;
                            for element in 0..TEST_SVL_BYTES / bytes {
                                assert_eq!(read_lane(row, element, bytes), expected);
                            }
                        }
                    }
                    assert_eq!(changed, selected_rows);
                }
            }
        }
    }
}

#[test]
fn vertical_pairs_cross_source_registers_and_select_bottom_or_top() {
    for (format, top) in [
        (Format::Half, false),
        (Format::Single, false),
        (Format::Single, true),
    ] {
        let (mut state, mut scalable) = state();
        let bytes = width(format).unwrap();
        // The first source contributes1, the second2. A pair with right1 sums3.
        scalable
            .write_z(&mut state, 1, &[0x40; TEST_SVL_BYTES])
            .unwrap();
        if format == Format::Single {
            let mut right = [E4M3_ONE; TEST_SVL_BYTES];
            for quartet in right.as_chunks_mut::<4>().0 {
                quartet[2..].fill(0x40);
            }
            scalable.write_z(&mut state, 2, &right).unwrap();
        }
        let original = state.clone();
        let mut operand = vector(VectorOperation::VerticalDot { top }, format, bytes as u8);
        operand.right = RightSource::Indexed {
            register: 2,
            index: (VECTOR_CHUNK_BYTES / bytes - 1) as u8,
        };
        let controls = controls(&state);
        complete(
            &mut state,
            &mut scalable,
            &Operand::Vector(operand),
            controls,
        )
        .unwrap();
        assert_eq!(state, original);
        let mut row = [0; TEST_SVL_BYTES];
        for group in 0..bytes {
            scalable
                .read_za(group * (TEST_SVL_BYTES / bytes) * TEST_SVL_BYTES, &mut row)
                .unwrap();
            for element in 0..TEST_SVL_BYTES / bytes {
                assert_eq!(
                    read_lane(&row, element, bytes),
                    if format == Format::Half {
                        0x4200
                    } else if top {
                        0x40c0_0000
                    } else {
                        0x4040_0000
                    }
                );
            }
        }
    }
}

#[test]
fn inactive_outer_cells_preserve_signaling_nan_without_classifying() {
    let (mut state, mut scalable) = state();
    state.fpcr |= FPCR_AH;
    let original = state.clone();
    let before = [0x01; TEST_SVL_BYTES * TEST_SVL_BYTES];
    scalable.write_za(0, &before).unwrap();
    scalable
        .write_predicate(0, &[0; TEST_SVL_BYTES / BITS_PER_BYTE])
        .unwrap();
    let operand = OuterOperand {
        accumulator: Format::Single,
        tile: 3,
        left: 0,
        right: 0,
        row_predicate: 0,
        column_predicate: 0,
    };
    let controls = controls(&state);
    complete(
        &mut state,
        &mut scalable,
        &Operand::Outer(operand),
        controls,
    )
    .unwrap();
    let mut actual = [0; TEST_SVL_BYTES * TEST_SVL_BYTES];
    scalable.read_za(0, &mut actual).unwrap();
    assert_eq!(actual, before);
    assert_eq!(state, original);
}

#[test]
fn malformed_sources_fail_without_committing_and_release_scratch() {
    let (mut state, mut scalable) = state();
    let before = [0xa5; TEST_SVL_BYTES * TEST_SVL_BYTES];
    scalable.write_za(0, &before).unwrap();
    let mut operand = vector(VectorOperation::MultiplyAdd, Format::Single, 4);
    operand.right = RightSource::Group(30);
    let controls = controls(&state);
    assert!(
        complete(
            &mut state,
            &mut scalable,
            &Operand::Vector(operand),
            controls
        )
        .is_err()
    );
    let mut actual = [0; TEST_SVL_BYTES * TEST_SVL_BYTES];
    scalable.read_za(0, &mut actual).unwrap();
    assert_eq!(actual, before);
    operand.right = RightSource::Group(0);
    complete(
        &mut state,
        &mut scalable,
        &Operand::Vector(operand),
        controls,
    )
    .unwrap();
}
