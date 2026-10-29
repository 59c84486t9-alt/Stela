//! Typed selection from decoded operands; never re-decodes or evaluates an ISA word.
use super::classes::{Kind, Lanes};
use serde::Serialize;
use stela_compiler::{
    GuestState,
    aarch64::{
        FloatingPointOperation, Register,
        flags::{NZCV_SHIFT, condition_holds},
        floating::Format,
        simd::{
            arithmetic::{Inputs, Shape},
            comparison::{self, CompareSource},
            conversion::{self, IntegerOperand, PrecisionMode},
            minmax::{self, BinaryMode},
        },
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Activity {
    Evaluated,
    SkippedConditional,
    RefusedBeforeEvaluation,
    NotCapturedFamily,
}

#[derive(Debug, Clone, Copy)]
enum Destination {
    Vector {
        register: u8,
        kind: Kind,
        start: u32,
        count: u32,
    },
    General {
        register: Register,
        kind: Kind,
    },
    Nzcv,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Capture {
    pub inputs: [Option<Lanes>; 3],
    destinations: [Option<Destination>; 2],
    pub activity: Activity,
    pub lane_steps: u32,
    pub discarded_result: bool,
    pub frac_bits: Option<u8>,
}

fn ieee(format: Format) -> Kind {
    Kind::Ieee {
        bits: format.bits() as u8,
    }
}

fn lane(value: &[u64; 2], bits: u32, index: u32) -> u64 {
    (value[(index * bits / 64) as usize] >> (index * bits % 64)) & super::classes::mask(bits)
}

fn vector(state: &GuestState, register: u8, kind: Kind, start: u32, count: u32) -> Lanes {
    Lanes::gather(kind, count, |n| {
        lane(&state.v[usize::from(register)], kind.bits(), start + n)
    })
}

fn general(state: &GuestState, register: Register) -> u64 {
    match register {
        Register::X(index) => state.x[usize::from(index)],
        Register::Zero => 0,
        Register::Sp => unreachable!("FP conversions never select SP"),
    }
}

fn pair(state: &GuestState, kind: Kind, count: u32, left: u8, right: u8) -> [Option<Lanes>; 3] {
    let stream = |odd| {
        Lanes::gather(kind, count, |n| {
            let half = count / 2;
            let (register, pair) = if n < half {
                (left, n)
            } else {
                (right, n - half)
            };
            lane(&state.v[usize::from(register)], kind.bits(), pair * 2 + odd)
        })
    };
    [Some(stream(0)), Some(stream(1)), None]
}

fn binary(
    state: &GuestState,
    format: Format,
    shape: Shape,
    destination: u8,
    inputs: Inputs,
) -> Capture {
    let kind = ieee(format);
    let count = shape.lane_count(format);
    let mut capture = Capture::vector(destination, kind, 0, count);
    capture.inputs = match inputs {
        Inputs::Elementwise { left, right } => [
            Some(vector(state, left, kind, 0, count)),
            Some(vector(state, right, kind, 0, count)),
            None,
        ],
        Inputs::Indexed {
            left,
            right,
            right_lane,
        } => [
            Some(vector(state, left, kind, 0, count)),
            Some(Lanes::gather(kind, count, |_| {
                lane(
                    &state.v[usize::from(right)],
                    kind.bits(),
                    u32::from(right_lane),
                )
            })),
            None,
        ],
        Inputs::Pairwise { left, right } => pair(state, kind, count, left, right),
        Inputs::PairwiseScalar { source } => [
            Some(vector(state, source, kind, 0, 1)),
            Some(vector(state, source, kind, 1, 1)),
            None,
        ],
    };
    capture
}

impl Capture {
    fn empty(activity: Activity) -> Self {
        Self {
            inputs: [None; 3],
            destinations: [None; 2],
            activity,
            lane_steps: 0,
            discarded_result: false,
            frac_bits: None,
        }
    }

    fn vector(register: u8, kind: Kind, start: u32, count: u32) -> Self {
        Self {
            destinations: [
                Some(Destination::Vector {
                    register,
                    kind,
                    start,
                    count,
                }),
                None,
            ],
            lane_steps: count,
            ..Self::empty(Activity::Evaluated)
        }
    }

    fn unary(state: &GuestState, destination: u8, source: u8, kind: Kind, count: u32) -> Self {
        let mut capture = Self::vector(destination, kind, 0, count);
        capture.inputs[0] = Some(vector(state, source, kind, 0, count));
        capture
    }

    fn flags(state: &GuestState, format: Format, left: u8, right: CompareSource) -> Self {
        let kind = ieee(format);
        Self {
            inputs: [
                Some(vector(state, left, kind, 0, 1)),
                Some(match right {
                    CompareSource::Register(register) => vector(state, register, kind, 0, 1),
                    CompareSource::Zero => Lanes::gather(kind, 1, |_| 0),
                }),
                None,
            ],
            destinations: [Some(Destination::Nzcv), None],
            lane_steps: 1,
            ..Self::empty(Activity::Evaluated)
        }
    }

    pub(super) fn before(state: &GuestState, operation: &FloatingPointOperation) -> Self {
        match *operation {
            FloatingPointOperation::Binary(ref operand) => binary(
                state,
                operand.format,
                operand.shape,
                operand.destination,
                operand.inputs,
            ),
            FloatingPointOperation::Fused(ref operand) => {
                let mut capture = binary(
                    state,
                    operand.format,
                    operand.shape,
                    operand.destination,
                    operand.right_lane.map_or(
                        Inputs::Elementwise {
                            left: operand.left,
                            right: operand.right,
                        },
                        |right_lane| Inputs::Indexed {
                            left: operand.left,
                            right: operand.right,
                            right_lane,
                        },
                    ),
                );
                capture.inputs[2] = Some(vector(
                    state,
                    operand.addend,
                    ieee(operand.format),
                    0,
                    operand.shape.lane_count(operand.format),
                ));
                capture
            }
            FloatingPointOperation::Conversion(ref operand) => Self::conversion(state, *operand),
            FloatingPointOperation::Comparison(ref operand) => match *operand {
                comparison::Operand::Flags {
                    format,
                    left,
                    right,
                    ..
                } => Self::flags(state, format, left, right),
                comparison::Operand::ConditionalFlags {
                    format,
                    left,
                    right,
                    condition,
                    ..
                } => {
                    if condition_holds(condition, state.nzcv) {
                        Self::flags(state, format, left, CompareSource::Register(right))
                    } else {
                        Self {
                            destinations: [Some(Destination::Nzcv), None],
                            ..Self::empty(Activity::SkippedConditional)
                        }
                    }
                }
                comparison::Operand::Predicate {
                    format,
                    shape,
                    destination,
                    left,
                    right,
                    ..
                } => {
                    let count = shape.lane_count(format);
                    let mut capture = Self::vector(
                        destination,
                        Kind::Predicate {
                            bits: format.bits() as u8,
                        },
                        0,
                        count,
                    );
                    capture.inputs = [
                        Some(vector(state, left, ieee(format), 0, count)),
                        Some(match right {
                            CompareSource::Register(register) => {
                                vector(state, register, ieee(format), 0, count)
                            }
                            CompareSource::Zero => Lanes::gather(ieee(format), count, |_| 0),
                        }),
                        None,
                    ];
                    capture
                }
            },
            FloatingPointOperation::MinMax(ref operand) => {
                let format = operand.format();
                match *operand {
                    minmax::Operand::Binary {
                        shape,
                        mode,
                        destination,
                        left,
                        right,
                        ..
                    } => binary(
                        state,
                        format,
                        shape,
                        destination,
                        match mode {
                            BinaryMode::Elementwise => Inputs::Elementwise { left, right },
                            BinaryMode::Pairwise => Inputs::Pairwise { left, right },
                        },
                    ),
                    minmax::Operand::PairwiseScalar {
                        destination,
                        source,
                        ..
                    } => binary(
                        state,
                        format,
                        Shape::Scalar,
                        destination,
                        Inputs::PairwiseScalar { source },
                    ),
                    minmax::Operand::Reduction {
                        destination,
                        source,
                        shape,
                        ..
                    } => {
                        let mut capture = Self::vector(destination, ieee(format), 0, 1);
                        let count = shape.lane_count(format);
                        capture.inputs[0] = Some(vector(state, source, ieee(format), 0, count));
                        capture.lane_steps = count - 1;
                        capture
                    }
                }
            }
            FloatingPointOperation::Estimate(ref operand) => Self::unary(
                state,
                operand.destination,
                operand.source,
                if operand.kind.is_unsigned() {
                    Kind::Integer {
                        bits: 32,
                        signed: false,
                    }
                } else {
                    ieee(operand.format)
                },
                operand.shape.lane_count(operand.format),
            ),
            FloatingPointOperation::SquareRoot(ref operand) => Self::unary(
                state,
                operand.destination,
                operand.source,
                ieee(operand.format),
                operand.shape.lane_count(operand.format),
            ),
            FloatingPointOperation::Rounding(ref operand) => Self::unary(
                state,
                operand.destination,
                operand.source,
                ieee(operand.format),
                operand.shape.lane_count(operand.format),
            ),
            FloatingPointOperation::Widening(_)
            | FloatingPointOperation::BFloat16(_)
            | FloatingPointOperation::Complex(_)
            | FloatingPointOperation::ExtremaScale(_)
            | FloatingPointOperation::Refinement(_) => Self::empty(Activity::NotCapturedFamily),
        }
    }

    fn conversion(state: &GuestState, operand: conversion::Operand) -> Self {
        let to_integer = matches!(operand, conversion::Operand::ToInteger { .. });
        match operand {
            conversion::Operand::Precision(operand) => {
                let source = operand.mode.source_format();
                let destination = operand.mode.destination_format();
                let (source_start, destination_start, count) = match operand.mode {
                    PrecisionMode::Scalar { .. } => (0, 0, 1),
                    PrecisionMode::Widen { upper, .. } => (
                        if upper { 64 / source.bits() } else { 0 },
                        0,
                        Shape::Vector128.lane_count(destination),
                    ),
                    PrecisionMode::Narrow { upper, .. } => (
                        0,
                        if upper { 64 / destination.bits() } else { 0 },
                        Shape::Vector128.lane_count(source),
                    ),
                };
                let mut capture = Self::vector(
                    operand.destination,
                    ieee(destination),
                    destination_start,
                    count,
                );
                capture.inputs[0] = Some(vector(
                    state,
                    operand.source,
                    ieee(source),
                    source_start,
                    count,
                ));
                capture
            }
            conversion::Operand::FromInteger(operand)
            | conversion::Operand::ToInteger { operand, .. } => {
                let format = operand.integer.format();
                let kind = Kind::Integer {
                    bits: format.width.bits() as u8,
                    signed: format.signed,
                };
                let count = operand.integer.shape().lane_count(operand.format);
                let integer_destination = match operand.integer {
                    IntegerOperand::General { register, .. } => {
                        Destination::General { register, kind }
                    }
                    IntegerOperand::Simd { register, .. } => Destination::Vector {
                        register,
                        kind,
                        start: 0,
                        count,
                    },
                };
                let mut capture = Self::vector(operand.float, ieee(operand.format), 0, count);
                capture.frac_bits = Some(operand.frac_bits);
                if to_integer {
                    capture.inputs[0] =
                        Some(vector(state, operand.float, ieee(operand.format), 0, count));
                    capture.discarded_result = matches!(
                        integer_destination,
                        Destination::General {
                            register: Register::Zero,
                            ..
                        }
                    );
                    capture.destinations = [
                        if capture.discarded_result {
                            None
                        } else {
                            Some(integer_destination)
                        },
                        None,
                    ];
                    return capture;
                }
                capture.inputs[0] = Some(match integer_destination {
                    Destination::General { register, .. } => {
                        Lanes::gather(kind, 1, |_| general(state, register))
                    }
                    Destination::Vector { register, .. } => vector(state, register, kind, 0, count),
                    Destination::Nzcv => unreachable!(),
                });
                capture
            }
            conversion::Operand::JavaScript {
                destination,
                source,
            } => Self {
                inputs: [
                    Some(vector(state, source, ieee(Format::Double), 0, 1)),
                    None,
                    None,
                ],
                destinations: [
                    if destination == Register::Zero {
                        None
                    } else {
                        Some(Destination::General {
                            register: destination,
                            kind: Kind::Integer {
                                bits: 32,
                                signed: true,
                            },
                        })
                    },
                    Some(Destination::Nzcv),
                ],
                lane_steps: 1,
                discarded_result: destination == Register::Zero,
                ..Self::empty(Activity::Evaluated)
            },
        }
    }

    pub(super) fn finish(&mut self, state: &GuestState, succeeded: bool) -> [Option<Lanes>; 2] {
        if !succeeded {
            if self.activity != Activity::NotCapturedFamily {
                self.activity = Activity::RefusedBeforeEvaluation;
            }
            self.lane_steps = 0;
            return [None; 2];
        }
        self.destinations.map(|destination| {
            destination.and_then(|destination| match destination {
                Destination::Vector {
                    register,
                    kind,
                    start,
                    count,
                } => Some(vector(state, register, kind, start, count)),
                Destination::General {
                    register: Register::Zero,
                    ..
                } => None,
                Destination::General { register, kind } => {
                    Some(Lanes::gather(kind, 1, |_| general(state, register)))
                }
                Destination::Nzcv => Some(Lanes::gather(Kind::Nzcv, 1, |_| {
                    u64::from(state.nzcv >> NZCV_SHIFT)
                })),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::{
        floating::{
            BinaryOperation, FPCR_NEP,
            integer::{IntegerFormat, IntegerWidth},
            precision::PrecisionRounding,
        },
        simd::arithmetic,
    };

    fn lanes(value: Option<Lanes>) -> Vec<u64> {
        let value = value.unwrap();
        (0..u32::from(value.count))
            .map(|lane| value.lane(lane))
            .collect()
    }

    fn half_state() -> GuestState {
        let mut state = GuestState {
            fpcr: FPCR_NEP,
            ..Default::default()
        };
        state.v[1] = [0x0004_0003_0002_0001, 0x0008_0007_0006_0005];
        state.v[2] = [0x0014_0013_0012_0011, 0x0018_0017_0016_0015];
        state
    }

    #[test]
    fn captures_hold_only_logical_operands() {
        let state = half_state();
        let make = |shape, inputs| {
            FloatingPointOperation::Binary(arithmetic::Operand {
                operation: BinaryOperation::Add,
                format: Format::Half,
                shape,
                destination: 1,
                inputs,
            })
        };
        let mut capture = Capture::before(
            &state,
            &make(Shape::Vector128, Inputs::Pairwise { left: 1, right: 2 }),
        );
        assert_eq!(
            lanes(capture.inputs[0]),
            [1, 3, 5, 7, 0x11, 0x13, 0x15, 0x17]
        );
        assert_eq!(
            lanes(capture.inputs[1]),
            [2, 4, 6, 8, 0x12, 0x14, 0x16, 0x18]
        );
        assert_eq!(
            lanes(capture.finish(&state, true)[0]),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
        let mut capture = Capture::before(
            &state,
            &make(Shape::Scalar, Inputs::PairwiseScalar { source: 1 }),
        );
        assert_eq!(lanes(capture.inputs[0]), [1]);
        assert_eq!(lanes(capture.inputs[1]), [2]);
        assert_eq!(lanes(capture.finish(&state, true)[0]), [1]);
        let capture = Capture::before(
            &state,
            &make(
                Shape::Vector64,
                Inputs::Indexed {
                    left: 1,
                    right: 2,
                    right_lane: 7,
                },
            ),
        );
        assert_eq!(lanes(capture.inputs[0]), [1, 2, 3, 4]);
        assert_eq!(lanes(capture.inputs[1]), [0x18; 4]);
    }

    #[test]
    fn precision_upper_offsets_and_general_integer_widths_are_typed() {
        let state = half_state();
        let mut capture = Capture::before(
            &state,
            &FloatingPointOperation::Conversion(conversion::Operand::Precision(
                conversion::PrecisionOperand {
                    mode: PrecisionMode::Widen {
                        source: Format::Half,
                        upper: true,
                    },
                    destination: 2,
                    source: 1,
                },
            )),
        );
        assert_eq!(lanes(capture.inputs[0]), [5, 6, 7, 8]);
        assert_eq!(
            capture.finish(&state, true)[0].unwrap().kind,
            Kind::Ieee { bits: 32 }
        );
        let mut capture = Capture::before(
            &state,
            &FloatingPointOperation::Conversion(conversion::Operand::Precision(
                conversion::PrecisionOperand {
                    mode: PrecisionMode::Narrow {
                        destination: Format::Half,
                        upper: true,
                        rounding: PrecisionRounding::Fpcr,
                    },
                    destination: 2,
                    source: 1,
                },
            )),
        );
        assert_eq!(
            lanes(capture.finish(&state, true)[0]),
            [0x15, 0x16, 0x17, 0x18]
        );
        for (width, bits) in [(IntegerWidth::Bits32, 32), (IntegerWidth::Bits64, 64)] {
            let operand = conversion::IntegerConversion {
                integer: IntegerOperand::General {
                    register: Register::Zero,
                    format: IntegerFormat {
                        width,
                        signed: true,
                    },
                },
                float: 1,
                format: Format::Half,
                frac_bits: 7,
            };
            let capture = Capture::before(
                &state,
                &FloatingPointOperation::Conversion(conversion::Operand::FromInteger(operand)),
            );
            assert_eq!(
                capture.inputs[0].unwrap().kind,
                Kind::Integer { bits, signed: true }
            );
            assert_eq!(lanes(capture.inputs[0]), [0]);
            assert_eq!(capture.frac_bits, Some(7));
            let mut capture = Capture::before(
                &state,
                &FloatingPointOperation::Conversion(conversion::Operand::ToInteger {
                    operand,
                    rounding:
                        stela_compiler::aarch64::floating::integer::IntegerRounding::TowardZero,
                }),
            );
            assert!(capture.discarded_result);
            assert_eq!(capture.inputs[0].unwrap().kind, Kind::Ieee { bits: 16 });
            assert_eq!(capture.finish(&state, true), [None; 2]);
        }
    }

    #[test]
    fn false_comparison_refusal_flags_and_predicates_remain_distinct() {
        let mut state = half_state();
        state.nzcv = 0;
        let operation = FloatingPointOperation::Comparison(comparison::Operand::ConditionalFlags {
            format: Format::Half,
            left: 1,
            right: 2,
            signal_all_nans: true,
            condition: 0,
            fallback: 15,
        });
        let mut capture = Capture::before(&state, &operation);
        assert_eq!(capture.activity, Activity::SkippedConditional);
        assert_eq!(capture.lane_steps, 0);
        assert_eq!(capture.inputs, [None; 3]);
        state.nzcv = 15 << NZCV_SHIFT;
        assert_eq!(lanes(capture.finish(&state, true)[0]), [15]);
        let mut capture = Capture::before(&state, &operation);
        assert_eq!(capture.inputs[0].unwrap().count, 1);
        assert_eq!(capture.finish(&state, false), [None; 2]);
        assert_eq!(capture.activity, Activity::RefusedBeforeEvaluation);
        assert_eq!(capture.lane_steps, 0);
        let operation = FloatingPointOperation::Comparison(comparison::Operand::Predicate {
            operation: stela_compiler::aarch64::floating::comparison::Predicate::Equal,
            format: Format::Half,
            shape: Shape::Vector64,
            destination: 1,
            left: 1,
            right: CompareSource::Zero,
        });
        let mut capture = Capture::before(&state, &operation);
        assert_eq!(lanes(capture.inputs[1]), [0; 4]);
        assert_eq!(
            capture.finish(&state, true)[0].unwrap().kind,
            Kind::Predicate { bits: 16 }
        );
    }

    #[test]
    fn fused_alias_reduction_integer_estimate_and_discarded_flags_views_are_exact() {
        use stela_compiler::aarch64::{
            floating::{fused::FusedOperation, minmax::MinMaxOperation},
            simd::{estimate, fused},
        };
        let mut state = half_state();
        let operation = FloatingPointOperation::Fused(fused::Operand {
            operation: FusedOperation::Add,
            format: Format::Half,
            shape: Shape::Vector64,
            destination: 1,
            addend: 1,
            left: 1,
            right: 1,
            right_lane: Some(7),
        });
        let mut capture = Capture::before(&state, &operation);
        state.v[1] = [u64::MAX; 2];
        assert_eq!(lanes(capture.inputs[0]), [1, 2, 3, 4]);
        assert_eq!(lanes(capture.inputs[1]), [8; 4]);
        assert_eq!(lanes(capture.inputs[2]), [1, 2, 3, 4]);
        assert_eq!(lanes(capture.finish(&state, true)[0]), [0xffff; 4]);
        let mut capture = Capture::before(
            &state,
            &FloatingPointOperation::MinMax(minmax::Operand::Reduction {
                operation: MinMaxOperation::MaximumNumber,
                format: Format::Half,
                shape: Shape::Vector128,
                destination: 2,
                source: 1,
            }),
        );
        assert_eq!(capture.inputs[0].unwrap().count, 8);
        assert_eq!(capture.lane_steps, 7);
        assert_eq!(capture.finish(&state, true)[0].unwrap().count, 1);
        let operation = FloatingPointOperation::Estimate(estimate::Operand {
            kind: estimate::Kind::UnsignedReciprocalSquareRoot,
            format: Format::Single,
            shape: Shape::Vector64,
            destination: 1,
            source: 2,
        });
        let mut capture = Capture::before(&state, &operation);
        assert_eq!(
            capture.inputs[0].unwrap().kind,
            Kind::Integer {
                bits: 32,
                signed: false
            }
        );
        assert_eq!(
            capture.finish(&state, true)[0].unwrap().kind,
            Kind::Integer {
                bits: 32,
                signed: false
            }
        );
        state.nzcv = 11 << NZCV_SHIFT;
        let mut capture = Capture::before(
            &state,
            &FloatingPointOperation::Conversion(conversion::Operand::JavaScript {
                destination: Register::Zero,
                source: 1,
            }),
        );
        let outputs = capture.finish(&state, true);
        assert_eq!(outputs[0], None);
        assert_eq!(lanes(outputs[1]), [11]);
        assert!(capture.discarded_result);
    }
}
