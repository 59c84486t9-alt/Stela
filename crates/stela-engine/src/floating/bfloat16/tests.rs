use super::*;
use stela_compiler::aarch64::{
    floating::{
        DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_ROUNDING_SHIFT,
        FPSR_QC, INEXACT, INPUT_DENORMAL, INVALID, OVERFLOW, UNDERFLOW,
    },
    simd::bfloat16::Parity,
};

const LAST_VECTOR_REGISTER: u8 = 31;
const LAST_INDEXED_REGISTER: u8 = 15;
const FPSR_RESERVED_POISON: u32 = 1 << 31;
const RAW_EBF_POISON: u32 = 1 << 13;
const ROUND_POSITIVE: u32 = 1;
const BFLOAT_ONE: u64 = 0x3f80;
const BFLOAT_SIGNALING_NAN: u64 = 0x7f81;
const BFLOAT_VALUES: [u64; 8] = [
    0x3f80, 0x4000, 0x4040, 0x4080, 0x40a0, 0x40c0, 0x40e0, 0x4100,
];
const SINGLE_ONE: u64 = 0x3f80_0000;
const SINGLE_TWO: u64 = 0x4000_0000;
const SINGLE_THREE: u64 = 0x4040_0000;
const SINGLE_FRACTION_BITS: u32 = 23;
const SINGLE_FRACTION_MASK: u64 = (1 << SINGLE_FRACTION_BITS) - 1;
const SINGLE_EXPONENT_BIAS: u64 = 127;
const BFLOAT_MASK: u64 = (1 << BFLOAT16_BITS) - 1;
const OVERLAPPING_ONES: [u64; VECTOR_LIMBS] = [0x3f80_3f80_3f80_3f80; VECTOR_LIMBS];

fn state() -> GuestState {
    GuestState {
        x: std::array::from_fn(|index| 0x1234_5678_9abc_def0 ^ index as u64),
        sp: 0x1111_2222_3333_4444,
        nzcv: 0xa000_0000,
        exclusive_bytes: 0xa5c3_9e71,
        exclusive_address: 0,
        exclusive_value: 0,
        daif: 0,
        pending: 0,
        v: std::array::from_fn(|index| {
            [
                0x0123_4567_89ab_cdef ^ index as u64,
                0xfedc_ba98_7654_3210 ^ index as u64,
            ]
        }),
        fpcr: FPCR_NEP,
        fpsr: FPSR_QC | DIVIDE_BY_ZERO | FPSR_RESERVED_POISON,
        ..Default::default()
    }
}

fn packed(bits: u32, values: &[u64]) -> [u64; VECTOR_LIMBS] {
    let mut result = [0; VECTOR_LIMBS];
    for (lane, value) in values.iter().copied().enumerate() {
        write_lane(&mut result, bits, lane as u32, value);
    }
    result
}

fn single_integer(value: u32) -> u64 {
    // These small positive integer routing witnesses are exactly representable.
    if value == 0 {
        return 0;
    }
    let exponent = value.ilog2();
    let significand = u64::from(value) << (SINGLE_FRACTION_BITS - exponent);
    ((u64::from(exponent) + SINGLE_EXPONENT_BIAS) << SINGLE_FRACTION_BITS)
        | (significand & SINGLE_FRACTION_MASK)
}

fn integer_vector(values: &[u32]) -> [u64; VECTOR_LIMBS] {
    let mut result = [0; VECTOR_LIMBS];
    for (lane, value) in values.iter().copied().enumerate() {
        write_lane(
            &mut result,
            Format::Single.bits(),
            lane as u32,
            single_integer(value),
        );
    }
    result
}

#[test]
fn scalar_conversion_merges_above_bit15_from_original_destination_and_aliases_source() {
    for nep in [0, FPCR_NEP] {
        for source in [0, LAST_VECTOR_REGISTER] {
            let mut actual = state();
            actual.fpcr = nep;
            actual.v[usize::from(source)][0] = 0xdead_beef_3fc0_0000;
            let old = actual.v[usize::from(LAST_VECTOR_REGISTER)];
            let mut expected = actual.clone();
            expected.v[usize::from(LAST_VECTOR_REGISTER)] = if nep == 0 {
                [0x3fc0, 0]
            } else {
                [(old[0] & !BFLOAT_MASK) | 0x3fc0, old[1]]
            };
            complete(
                &mut actual,
                &Operand::Conversion(ConversionOperand {
                    mode: ConversionMode::Scalar,
                    destination: LAST_VECTOR_REGISTER,
                    source,
                }),
            )
            .unwrap();
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn narrowing_aliases_preserve_the_correct_half_and_union_fresh_status() {
    for upper in [false, true] {
        let mut actual = state();
        actual.v[usize::from(LAST_VECTOR_REGISTER)] = packed(
            Format::Single.bits(),
            &[0x7f80_0001, 0x3f80_0001, 0x7f80_0000, 0],
        );
        let old = actual.v[usize::from(LAST_VECTOR_REGISTER)];
        let narrowed = 0x0000_7f80_3f80_7fc0;
        let mut expected = actual.clone();
        expected.v[usize::from(LAST_VECTOR_REGISTER)] = if upper {
            [old[0], narrowed]
        } else {
            [narrowed, 0]
        };
        expected.fpsr |= INVALID | INEXACT;
        complete(
            &mut actual,
            &Operand::Conversion(ConversionOperand {
                mode: ConversionMode::Narrow { upper },
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
            }),
        )
        .unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn dot_routes_ignore_nep_and_inactive_lanes() {
    for shape in [Shape::Vector64, Shape::Vector128] {
        for index in [None, Some(0), Some(1), Some(2), Some(3)] {
            for ah in [0, FPCR_AH] {
                let mut actual = state();
                actual.fpcr |= ah | RAW_EBF_POISON | (EXCEPTIONS << FPCR_EXCEPTION_ENABLE_SHIFT);
                actual.v[0] = packed(BFLOAT16_BITS, &BFLOAT_VALUES);
                actual.v[usize::from(LAST_VECTOR_REGISTER)] = integer_vector(&[10, 20, 30, 40]);
                actual.v[usize::from(LAST_INDEXED_REGISTER)] = if let Some(index) = index {
                    let mut right = packed(BFLOAT16_BITS, &[BFLOAT_SIGNALING_NAN; 8]);
                    for component in 0..PAIR_LANES {
                        write_lane(
                            &mut right,
                            BFLOAT16_BITS,
                            index * PAIR_LANES + component,
                            BFLOAT_VALUES[(index * PAIR_LANES + component) as usize],
                        );
                    }
                    right
                } else {
                    packed(BFLOAT16_BITS, &BFLOAT_VALUES)
                };
                if shape == Shape::Vector64 {
                    actual.v[usize::from(LAST_VECTOR_REGISTER)][1] = 0x7f80_0001_7f80_0001;
                    for lane in UPPER_NARROW_START..UPPER_NARROW_START * 2 {
                        write_lane(&mut actual.v[0], BFLOAT16_BITS, lane, BFLOAT_SIGNALING_NAN);
                        if index.is_none() {
                            write_lane(
                                &mut actual.v[usize::from(LAST_INDEXED_REGISTER)],
                                BFLOAT16_BITS,
                                lane,
                                BFLOAT_SIGNALING_NAN,
                            );
                        }
                    }
                }
                let mut expected = actual.clone();
                let mut result = [0; VECTOR_LIMBS];
                for lane in 0..shape.lane_count(Format::Single) {
                    let n = lane * PAIR_LANES + 1;
                    let m = index.map_or(n, |index| index * PAIR_LANES + 1);
                    let value = (lane + 1) * 10 + n * m + (n + 1) * (m + 1);
                    write_lane(
                        &mut result,
                        Format::Single.bits(),
                        lane,
                        single_integer(value),
                    );
                }
                expected.v[usize::from(LAST_VECTOR_REGISTER)] = result;
                let right = index.map_or(DotSource::Vector(LAST_INDEXED_REGISTER), |index| {
                    DotSource::Indexed {
                        register: LAST_INDEXED_REGISTER,
                        index: index as u8,
                    }
                });
                complete(
                    &mut actual,
                    &Operand::Dot(DotOperand {
                        shape,
                        destination: LAST_VECTOR_REGISTER,
                        left: 0,
                        right,
                    }),
                )
                .unwrap();
                assert_eq!(actual, expected, "{shape:?}, index={index:?}, AH={ah:#x}");
            }
        }
    }
}

#[test]
fn multiply_parity_and_every_index_use_only_selected_bfloat_lanes() {
    for parity in [Parity::Even, Parity::Odd] {
        for index in [
            None,
            Some(0),
            Some(1),
            Some(2),
            Some(3),
            Some(4),
            Some(5),
            Some(6),
            Some(7),
        ] {
            let mut actual = state();
            actual.v[usize::from(LAST_VECTOR_REGISTER)] = integer_vector(&[10, 20, 30, 40]);
            actual.v[0] = packed(BFLOAT16_BITS, &[BFLOAT_SIGNALING_NAN; 8]);
            actual.v[usize::from(LAST_INDEXED_REGISTER)] =
                packed(BFLOAT16_BITS, &[BFLOAT_SIGNALING_NAN; 8]);
            let parity_offset = if parity == Parity::Even { 0 } else { 1 };
            for lane in 0..SINGLE_VECTOR_LANES {
                let source_lane = PAIR_LANES * lane + parity_offset;
                write_lane(
                    &mut actual.v[0],
                    BFLOAT16_BITS,
                    source_lane,
                    BFLOAT_VALUES[source_lane as usize],
                );
                if index.is_none() {
                    write_lane(
                        &mut actual.v[usize::from(LAST_INDEXED_REGISTER)],
                        BFLOAT16_BITS,
                        source_lane,
                        BFLOAT_VALUES[source_lane as usize],
                    );
                }
            }
            if let Some(index) = index {
                write_lane(
                    &mut actual.v[usize::from(LAST_INDEXED_REGISTER)],
                    BFLOAT16_BITS,
                    index,
                    BFLOAT_VALUES[index as usize],
                );
            }
            let mut expected = actual.clone();
            let mut result = [0; VECTOR_LIMBS];
            for lane in 0..SINGLE_VECTOR_LANES {
                let n = PAIR_LANES * lane + parity_offset + 1;
                let m = index.map_or(n, |index| index + 1);
                write_lane(
                    &mut result,
                    Format::Single.bits(),
                    lane,
                    single_integer((lane + 1) * 10 + n * m),
                );
            }
            expected.v[usize::from(LAST_VECTOR_REGISTER)] = result;
            let right = index.map_or(MultiplySource::Vector(LAST_INDEXED_REGISTER), |index| {
                MultiplySource::Indexed {
                    register: LAST_INDEXED_REGISTER,
                    index: index as u8,
                }
            });
            complete(
                &mut actual,
                &Operand::MultiplyAdd(MultiplyOperand {
                    parity,
                    destination: LAST_VECTOR_REGISTER,
                    left: 0,
                    right,
                }),
            )
            .unwrap();
            assert_eq!(actual, expected, "{parity:?}, index={index:?}");
        }
    }
}

#[test]
fn original_accumulators_and_repeated_indexed_sources_survive_all_alias_roles() {
    for (destination, left, right) in [
        (LAST_INDEXED_REGISTER, LAST_INDEXED_REGISTER, 0),
        (LAST_INDEXED_REGISTER, 0, LAST_INDEXED_REGISTER),
        (
            LAST_INDEXED_REGISTER,
            LAST_INDEXED_REGISTER,
            LAST_INDEXED_REGISTER,
        ),
    ] {
        for (operand, value) in [
            (
                Operand::Dot(DotOperand {
                    shape: Shape::Vector128,
                    destination,
                    left,
                    right: DotSource::Indexed {
                        register: right,
                        index: 0,
                    },
                }),
                0x4040_1fc0,
            ),
            (
                Operand::MultiplyAdd(MultiplyOperand {
                    parity: Parity::Odd,
                    destination,
                    left,
                    right: MultiplySource::Indexed {
                        register: right,
                        index: 1,
                    },
                }),
                0x4000_1fc0,
            ),
            (
                Operand::Matrix(MatrixOperand {
                    destination,
                    left,
                    right,
                }),
                0x40a0_0fe0,
            ),
        ] {
            let mut actual = state();
            actual.v[0] = packed(BFLOAT16_BITS, &[BFLOAT_ONE; 8]);
            actual.v[usize::from(LAST_INDEXED_REGISTER)] = OVERLAPPING_ONES;
            let mut expected = actual.clone();
            expected.v[usize::from(destination)] = packed(Format::Single.bits(), &[value; 4]);
            complete(&mut actual, &operand).unwrap();
            assert_eq!(actual, expected, "{operand:?}");
        }
    }
}

#[test]
fn matrix_routes_rows_columns_and_keeps_k_zero_before_k_one() {
    let mut actual = state();
    actual.fpcr = u32::MAX;
    actual.v[0] = packed(BFLOAT16_BITS, &BFLOAT_VALUES);
    actual.v[usize::from(LAST_INDEXED_REGISTER)] = packed(BFLOAT16_BITS, &BFLOAT_VALUES);
    actual.v[usize::from(LAST_VECTOR_REGISTER)] = integer_vector(&[10, 20, 30, 40]);
    let operand = Operand::Matrix(MatrixOperand {
        destination: LAST_VECTOR_REGISTER,
        left: 0,
        right: LAST_INDEXED_REGISTER,
    });
    let mut expected = actual.clone();
    expected.v[usize::from(LAST_VECTOR_REGISTER)] = integer_vector(&[40, 90, 100, 214]);
    complete(&mut actual, &operand).unwrap();
    assert_eq!(actual, expected);

    // 1 + 2^25 rounds to odd as 2^25+4, then subtracting 2^25 yields 4.
    // Reversing the two k steps would instead yield 2.
    actual.v[usize::from(LAST_VECTOR_REGISTER)] =
        packed(Format::Single.bits(), &[SINGLE_ONE, 0, 0, 0]);
    actual.v[0] = packed(BFLOAT16_BITS, &[0x4580, 0, 0xc580, 0, 0, 0, 0, 0]);
    actual.v[usize::from(LAST_INDEXED_REGISTER)] =
        packed(BFLOAT16_BITS, &[0x4600, 0, 0x4600, 0, 0, 0, 0, 0]);
    let mut expected = actual.clone();
    expected.v[usize::from(LAST_VECTOR_REGISTER)] = integer_vector(&[4, 0, 0, 0]);
    complete(&mut actual, &operand).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn multiply_status_union_and_ah_suppression_preserve_complete_state() {
    for ah in [0, FPCR_AH] {
        let mut actual = state();
        actual.fpcr |= ah | RAW_EBF_POISON | (ROUND_POSITIVE << FPCR_ROUNDING_SHIFT);
        actual.v[usize::from(LAST_VECTOR_REGISTER)] = packed(
            Format::Single.bits(),
            &[0, SINGLE_ONE, SINGLE_TWO, SINGLE_THREE],
        );
        actual.v[0] = packed(
            BFLOAT16_BITS,
            &[
                BFLOAT_SIGNALING_NAN,
                BFLOAT_SIGNALING_NAN,
                0x0080,
                BFLOAT_SIGNALING_NAN,
                0,
                BFLOAT_SIGNALING_NAN,
                BFLOAT_ONE,
                BFLOAT_SIGNALING_NAN,
            ],
        );
        actual.v[usize::from(LAST_INDEXED_REGISTER)] = packed(
            BFLOAT16_BITS,
            &[
                BFLOAT_ONE,
                BFLOAT_SIGNALING_NAN,
                BFLOAT_ONE,
                BFLOAT_SIGNALING_NAN,
                BFLOAT_ONE,
                BFLOAT_SIGNALING_NAN,
                BFLOAT_ONE,
                BFLOAT_SIGNALING_NAN,
            ],
        );
        let mut expected = actual.clone();
        expected.v[usize::from(LAST_VECTOR_REGISTER)] = packed(
            Format::Single.bits(),
            &[
                0x7fc1_0000,
                SINGLE_ONE + u64::from(ah == 0),
                SINGLE_TWO,
                0x4080_0000,
            ],
        );
        if ah == 0 {
            expected.fpsr |= INVALID | INEXACT;
        }
        complete(
            &mut actual,
            &Operand::MultiplyAdd(MultiplyOperand {
                parity: Parity::Even,
                destination: LAST_VECTOR_REGISTER,
                left: 0,
                right: MultiplySource::Vector(LAST_INDEXED_REGISTER),
            }),
        )
        .unwrap();
        assert_eq!(actual, expected, "AH={ah:#x}");
    }
}

#[test]
fn conversion_and_multiply_enables_refuse_ah_zero_transactionally_but_accept_ah_one() {
    for enabled in [
        INVALID,
        DIVIDE_BY_ZERO,
        OVERFLOW,
        UNDERFLOW,
        INEXACT,
        INPUT_DENORMAL,
        EXCEPTIONS,
    ] {
        for ah in [0, FPCR_AH] {
            for mode in [
                ConversionMode::Scalar,
                ConversionMode::Narrow { upper: false },
                ConversionMode::Narrow { upper: true },
            ] {
                let mut actual = state();
                actual.fpcr |= ah | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                actual.v[usize::from(LAST_VECTOR_REGISTER)] =
                    packed(Format::Single.bits(), &[SINGLE_ONE; 4]);
                let old = actual.v[usize::from(LAST_VECTOR_REGISTER)];
                let mut expected = actual.clone();
                let operand = Operand::Conversion(ConversionOperand {
                    mode,
                    destination: LAST_VECTOR_REGISTER,
                    source: LAST_VECTOR_REGISTER,
                });
                if ah == 0 {
                    assert_eq!(
                        complete(&mut actual, &operand),
                        Err(UnsupportedControl {
                            enabled_exceptions: enabled
                        })
                    );
                } else {
                    expected.v[usize::from(LAST_VECTOR_REGISTER)] = match mode {
                        ConversionMode::Scalar => [(old[0] & !BFLOAT_MASK) | BFLOAT_ONE, old[1]],
                        ConversionMode::Narrow { upper: false } => [0x3f80_3f80_3f80_3f80, 0],
                        ConversionMode::Narrow { upper: true } => [old[0], 0x3f80_3f80_3f80_3f80],
                    };
                    complete(&mut actual, &operand).unwrap();
                }
                assert_eq!(
                    actual, expected,
                    "{mode:?}, AH={ah:#x}, enabled={enabled:#x}"
                );
            }
            let mut actual = state();
            actual.fpcr |= ah | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
            actual.v[0] = packed(BFLOAT16_BITS, &[BFLOAT_ONE; 8]);
            actual.v[usize::from(LAST_INDEXED_REGISTER)] = OVERLAPPING_ONES;
            let mut expected = actual.clone();
            let operand = Operand::MultiplyAdd(MultiplyOperand {
                parity: Parity::Odd,
                destination: LAST_INDEXED_REGISTER,
                left: 0,
                right: MultiplySource::Indexed {
                    register: LAST_INDEXED_REGISTER,
                    index: 1,
                },
            });
            if ah == 0 {
                assert_eq!(
                    complete(&mut actual, &operand),
                    Err(UnsupportedControl {
                        enabled_exceptions: enabled
                    })
                );
            } else {
                expected.v[usize::from(LAST_INDEXED_REGISTER)] =
                    packed(Format::Single.bits(), &[0x4000_1fc0; 4]);
                complete(&mut actual, &operand).unwrap();
            }
            assert_eq!(actual, expected, "MLA AH={ah:#x}, enabled={enabled:#x}");
        }
    }
}
