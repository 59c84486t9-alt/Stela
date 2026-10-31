use super::*;
use stela_compiler::aarch64::{
    floating::{
        DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_EXCEPTION_ENABLE_SHIFT, FPCR_NEP, FPSR_QC,
        INEXACT, INPUT_DENORMAL, INVALID, OVERFLOW, UNDERFLOW,
        complex::{IMAGINARY, REAL, Rotation},
    },
    simd::arithmetic::Shape,
};

const LAST_VECTOR_REGISTER: u8 = 31;
const RIGHT_REGISTER: u8 = 15;
const FPSR_RESERVED_POISON: u32 = 1 << 31;
const HALF_FIELDS: (u32, u32) = (10, 15);
const SINGLE_FIELDS: (u32, u32) = (23, 127);
const DOUBLE_FIELDS: (u32, u32) = (52, 1023);
const ROTATIONS: [Rotation; 4] = [
    Rotation::Degrees0,
    Rotation::Degrees90,
    Rotation::Degrees180,
    Rotation::Degrees270,
];
const SHAPES: [(Format, Shape); 5] = [
    (Format::Half, Shape::Vector64),
    (Format::Half, Shape::Vector128),
    (Format::Single, Shape::Vector64),
    (Format::Single, Shape::Vector128),
    (Format::Double, Shape::Vector128),
];

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
    }
}

fn fields(format: Format) -> (u32, u32) {
    match format {
        Format::Half => HALF_FIELDS,
        Format::Single => SINGLE_FIELDS,
        Format::Double => DOUBLE_FIELDS,
    }
}

fn integer_bits(format: Format, value: i32) -> u64 {
    if value == 0 {
        return 0;
    }
    let (fraction_bits, bias) = fields(format);
    let magnitude = value.unsigned_abs();
    let exponent = magnitude.ilog2();
    let significand = u64::from(magnitude) << (fraction_bits - exponent);
    let sign = if value < 0 {
        1 << (format.bits() - 1)
    } else {
        0
    };
    sign | (u64::from(exponent + bias) << fraction_bits)
        | (significand & ((1 << fraction_bits) - 1))
}

fn signaling_nan(format: Format) -> u64 {
    let (fraction_bits, _) = fields(format);
    let exponent_bits = format.bits() - fraction_bits - 1;
    (((1 << exponent_bits) - 1) << fraction_bits) | 1
}

fn vector(format: Format, values: &[i32]) -> [u64; VECTOR_LIMBS] {
    let mut result = [0; VECTOR_LIMBS];
    for (lane, value) in values.iter().copied().enumerate() {
        write_lane(
            &mut result,
            format.bits(),
            lane as u32,
            integer_bits(format, value),
        );
    }
    result
}

fn expected_pair(
    kind: Kind,
    rotation: Rotation,
    addend: [i32; COMPONENTS],
    left: [i32; COMPONENTS],
    right: [i32; COMPONENTS],
) -> [i32; COMPONENTS] {
    match (kind, rotation) {
        (Kind::Add, Rotation::Degrees90) => {
            [left[REAL] - right[IMAGINARY], left[IMAGINARY] + right[REAL]]
        }
        (Kind::Add, Rotation::Degrees270) => {
            [left[REAL] + right[IMAGINARY], left[IMAGINARY] - right[REAL]]
        }
        (Kind::MultiplyAdd, Rotation::Degrees0) => [
            addend[REAL] + left[REAL] * right[REAL],
            addend[IMAGINARY] + left[REAL] * right[IMAGINARY],
        ],
        (Kind::MultiplyAdd, Rotation::Degrees90) => [
            addend[REAL] - left[IMAGINARY] * right[IMAGINARY],
            addend[IMAGINARY] + left[IMAGINARY] * right[REAL],
        ],
        (Kind::MultiplyAdd, Rotation::Degrees180) => [
            addend[REAL] - left[REAL] * right[REAL],
            addend[IMAGINARY] - left[REAL] * right[IMAGINARY],
        ],
        (Kind::MultiplyAdd, Rotation::Degrees270) => [
            addend[REAL] + left[IMAGINARY] * right[IMAGINARY],
            addend[IMAGINARY] - left[IMAGINARY] * right[REAL],
        ],
        _ => unreachable!("FCADD only admits ninety or two-hundred-seventy degrees"),
    }
}

fn fixture(operand: Operand) -> (GuestState, GuestState) {
    let mut actual = state();
    let format = operand.format;
    let mut left = [0; VECTOR_LIMBS];
    let mut right = [0; VECTOR_LIMBS];
    let mut addend = [0; VECTOR_LIMBS];
    for lane in 0..Shape::Vector128.lane_count(format) {
        write_lane(&mut left, format.bits(), lane, signaling_nan(format));
        write_lane(&mut right, format.bits(), lane, signaling_nan(format));
        write_lane(&mut addend, format.bits(), lane, signaling_nan(format));
    }
    let pairs = operand.shape.lane_count(format) / PAIR_LANES;
    let indexed_pair = match operand.right {
        Source::Vector(_) => None,
        Source::Indexed { index, .. } => Some(u32::from(index)),
    };
    let mut result = [0; VECTOR_LIMBS];
    for index in 0..pairs {
        let n = index as i32 * COMPONENTS as i32 + 1;
        let m = indexed_pair.unwrap_or(index) as i32 * COMPONENTS as i32 + 9;
        let a = index as i32 * 20 + 20;
        let left_values = [n, n + 1];
        let right_values = [m, m + 1];
        let addend_values = [a, a + 10];
        for component in 0..COMPONENTS {
            if operand.kind == Kind::Add || component == operand.rotation.left_component() {
                write_lane(
                    &mut left,
                    format.bits(),
                    index * PAIR_LANES + component as u32,
                    integer_bits(format, left_values[component]),
                );
            }
            write_lane(
                &mut right,
                format.bits(),
                indexed_pair.unwrap_or(index) * PAIR_LANES + component as u32,
                integer_bits(format, right_values[component]),
            );
            if operand.kind == Kind::MultiplyAdd {
                write_lane(
                    &mut addend,
                    format.bits(),
                    index * PAIR_LANES + component as u32,
                    integer_bits(format, addend_values[component]),
                );
            }
        }
        let expected = expected_pair(
            operand.kind,
            operand.rotation,
            addend_values,
            left_values,
            right_values,
        );
        for (component, value) in expected.into_iter().enumerate() {
            write_lane(
                &mut result,
                format.bits(),
                index * PAIR_LANES + component as u32,
                integer_bits(format, value),
            );
        }
    }
    actual.v[usize::from(operand.destination)] = addend;
    actual.v[usize::from(operand.left)] = left;
    let register = match operand.right {
        Source::Vector(register) | Source::Indexed { register, .. } => register,
    };
    actual.v[usize::from(register)] = right;
    let mut expected = actual.clone();
    expected.v[usize::from(operand.destination)] = result;
    (actual, expected)
}

#[test]
fn register_shapes_ignore_unselected_components() {
    for (format, shape) in SHAPES {
        for kind in [Kind::Add, Kind::MultiplyAdd] {
            for rotation in ROTATIONS {
                if kind == Kind::Add
                    && matches!(rotation, Rotation::Degrees0 | Rotation::Degrees180)
                {
                    continue;
                }
                let operand = Operand {
                    kind,
                    format,
                    shape,
                    rotation,
                    destination: LAST_VECTOR_REGISTER,
                    left: 0,
                    right: Source::Vector(RIGHT_REGISTER),
                };
                let (mut actual, expected) = fixture(operand);
                complete(&mut actual, &operand).unwrap();
                assert_eq!(actual, expected, "{operand:?}");
            }
        }
    }
}

#[test]
fn indexed_layouts_select_whole_original_pairs_including_q0_and_v31() {
    for (format, shape, indices) in [
        (Format::Half, Shape::Vector64, 2),
        (Format::Half, Shape::Vector128, 4),
        (Format::Single, Shape::Vector128, 2),
    ] {
        for index in 0..indices {
            for rotation in ROTATIONS {
                let operand = Operand {
                    kind: Kind::MultiplyAdd,
                    format,
                    shape,
                    rotation,
                    destination: 0,
                    left: RIGHT_REGISTER,
                    right: Source::Indexed {
                        register: LAST_VECTOR_REGISTER,
                        index,
                    },
                };
                let (mut actual, expected) = fixture(operand);
                complete(&mut actual, &operand).unwrap();
                assert_eq!(actual, expected, "{operand:?}");
            }
        }
    }
}

#[test]
fn every_alias_role_uses_old_accumulators_and_repeated_indexed_source_pairs() {
    for (destination, left, right) in [
        (0, 0, LAST_VECTOR_REGISTER),
        (LAST_VECTOR_REGISTER, 0, LAST_VECTOR_REGISTER),
        (
            LAST_VECTOR_REGISTER,
            LAST_VECTOR_REGISTER,
            LAST_VECTOR_REGISTER,
        ),
        (LAST_VECTOR_REGISTER, RIGHT_REGISTER, 0),
        (0, LAST_VECTOR_REGISTER, RIGHT_REGISTER),
    ] {
        for (kind, rotation, source, values) in [
            (
                Kind::Add,
                Rotation::Degrees270,
                Source::Vector(right),
                [3, 1, 7, 1],
            ),
            (
                Kind::MultiplyAdd,
                Rotation::Degrees90,
                Source::Indexed {
                    register: right,
                    index: 0,
                },
                [-3, 4, -5, 8],
            ),
        ] {
            let mut actual = state();
            for register in [destination, left, right] {
                actual.v[usize::from(register)] = vector(Format::Single, &[1, 2, 3, 4]);
            }
            let mut expected = actual.clone();
            expected.v[usize::from(destination)] = vector(Format::Single, &values);
            let operand = Operand {
                kind,
                format: Format::Single,
                shape: Shape::Vector128,
                rotation,
                destination,
                left,
                right: source,
            };
            complete(&mut actual, &operand).unwrap();
            assert_eq!(actual, expected, "{operand:?}");
        }
    }
}

#[test]
fn rotated_nan_signs_and_later_inexact_lanes_union_status_under_both_ah_modes() {
    for ah in [0, FPCR_AH] {
        let mut actual = state();
        actual.fpcr |= ah;
        actual.v[0] = [0x4000_0000_3f80_0000, 0x3f80_0000_3f80_0000];
        actual.v[usize::from(RIGHT_REGISTER)] = [0xff80_0123_4040_0000, 0x3300_0000_0000_0000];
        let mut expected = actual.clone();
        let nan = if ah == 0 { 0x7fc0_0123 } else { 0xffc0_0123 };
        expected.v[usize::from(LAST_VECTOR_REGISTER)] =
            [0x40a0_0000_0000_0000 | nan, 0x3f80_0000_3f80_0000];
        expected.fpsr |= INVALID | INEXACT;
        let operand = Operand {
            kind: Kind::Add,
            format: Format::Single,
            shape: Shape::Vector128,
            rotation: Rotation::Degrees90,
            destination: LAST_VECTOR_REGISTER,
            left: 0,
            right: Source::Vector(RIGHT_REGISTER),
        };
        complete(&mut actual, &operand).unwrap();
        assert_eq!(actual, expected, "AH={ah:#x}");
    }
}

#[test]
fn every_enable_refuses_all_families_without_changing_any_state_byte() {
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
            for (kind, format, shape, rotation, right) in [
                (
                    Kind::Add,
                    Format::Single,
                    Shape::Vector64,
                    Rotation::Degrees90,
                    Source::Vector(RIGHT_REGISTER),
                ),
                (
                    Kind::MultiplyAdd,
                    Format::Double,
                    Shape::Vector128,
                    Rotation::Degrees180,
                    Source::Vector(RIGHT_REGISTER),
                ),
                (
                    Kind::MultiplyAdd,
                    Format::Half,
                    Shape::Vector64,
                    Rotation::Degrees90,
                    Source::Indexed {
                        register: LAST_VECTOR_REGISTER,
                        index: 1,
                    },
                ),
                (
                    Kind::MultiplyAdd,
                    Format::Half,
                    Shape::Vector128,
                    Rotation::Degrees270,
                    Source::Indexed {
                        register: LAST_VECTOR_REGISTER,
                        index: 3,
                    },
                ),
                (
                    Kind::MultiplyAdd,
                    Format::Single,
                    Shape::Vector128,
                    Rotation::Degrees0,
                    Source::Indexed {
                        register: LAST_VECTOR_REGISTER,
                        index: 1,
                    },
                ),
            ] {
                let mut actual = state();
                actual.fpcr |= ah | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                let expected = actual.clone();
                let operand = Operand {
                    kind,
                    format,
                    shape,
                    rotation,
                    destination: LAST_VECTOR_REGISTER,
                    left: LAST_VECTOR_REGISTER,
                    right,
                };
                assert_eq!(
                    complete(&mut actual, &operand),
                    Err(UnsupportedControl {
                        enabled_exceptions: enabled
                    })
                );
                assert_eq!(
                    actual, expected,
                    "{operand:?}, AH={ah:#x}, enabled={enabled:#x}"
                );
            }
        }
    }
}
