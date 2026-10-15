//! Staged streaming numerical completion with complete scalable source snapshots.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{
            self, BinaryOperation, FPCR_AH, Format, Outcome, complex::Rotation,
            fused::FusedOperation, minmax::MinMaxOperation,
        },
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES, VECTOR_CHUNK_BYTES},
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape, Source},
    },
};

use crate::scalable::ScalableState;

const MAX_SOURCES: usize = 3;
const MAX_PREDICATE_BYTES: usize = MAX_VECTOR_BYTES / BITS_PER_BYTE;
const COMPLEX_COMPONENTS: usize = 2;
const REDUCTION_SUBTREES: usize = 2;
const VECTOR_LIMBS: usize = VECTOR_CHUNK_BYTES / size_of::<u64>();
const REAL_COMPONENT: usize = 0;
const IMAGINARY_COMPONENT: usize = 1;
const HALF_INFINITY: u64 = 0x7c00;
const SINGLE_INFINITY: u64 = 0x7f80_0000;
const DOUBLE_INFINITY: u64 = 0x7ff0_0000_0000_0000;
const HALF_QUIET_BIT: u64 = 0x0200;
const SINGLE_QUIET_BIT: u64 = 0x0040_0000;
const DOUBLE_QUIET_BIT: u64 = 0x0008_0000_0000_0000;

use super::{CompletionError, NumericalControls};

fn require(condition: bool, message: &'static str) -> Result<(), CompletionError> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(message).into())
    }
}

struct Sources {
    descriptors: [Source; MAX_SOURCES],
    bytes: [[u8; MAX_VECTOR_BYTES]; MAX_SOURCES],
    count: usize,
}

impl Sources {
    fn snapshot(
        state: &GuestState,
        scalable: &ScalableState,
        operand: &Operand,
    ) -> anyhow::Result<Self> {
        let unused = Source::ImmediateBits(0);
        let (descriptors, count) = match operand.inputs {
            Inputs::Unary { source } => ([Source::Vector(source), unused, unused], 1),
            Inputs::Binary { left, right } => ([left, right, unused], 2),
            Inputs::Fused {
                addend,
                left,
                right,
            } => ([Source::Vector(addend), Source::Vector(left), right], 3),
            Inputs::Pairwise { left, right } => {
                ([Source::Vector(left), Source::Vector(right), unused], 2)
            }
            Inputs::Reduction { source } => ([Source::Vector(source), unused, unused], 1),
            Inputs::Clamp {
                value,
                lower,
                upper,
            } => (
                [
                    Source::Vector(lower),
                    Source::Vector(value),
                    Source::Vector(upper),
                ],
                3,
            ),
        };
        let mut result = Self {
            descriptors,
            bytes: [[0; MAX_VECTOR_BYTES]; MAX_SOURCES],
            count,
        };
        let length = scalable.vector_length().bytes();
        let element_bytes = operand.format.bits() as usize / BITS_PER_BYTE;
        for (descriptor, output) in descriptors.iter().zip(&mut result.bytes).take(count) {
            match *descriptor {
                Source::Vector(register) | Source::Indexed { register, .. } => {
                    scalable.read_z(state, register, &mut output[..length])?;
                }
                Source::ImmediateBits(bits) => {
                    for lane in output[..length].chunks_exact_mut(element_bytes) {
                        lane.copy_from_slice(&bits.to_le_bytes()[..element_bytes]);
                    }
                }
            }
        }
        Ok(result)
    }

    fn raw_lane(&self, source: usize, lane: usize, element_bytes: usize) -> u64 {
        let offset = lane * element_bytes;
        let mut bits = [0; size_of::<u64>()];
        bits[..element_bytes].copy_from_slice(&self.bytes[source][offset..offset + element_bytes]);
        u64::from_le_bytes(bits)
    }

    fn lane(&self, source: usize, lane: usize, element_bytes: usize) -> u64 {
        let index = if let Source::Indexed { index, .. } = self.descriptors[source] {
            let elements = VECTOR_CHUNK_BYTES / element_bytes;
            lane - lane % elements + usize::from(index)
        } else {
            lane
        };
        self.raw_lane(source, index, element_bytes)
    }
}

fn active(predicate: Option<&[u8]>, lane: usize, element_bytes: usize) -> bool {
    predicate.is_none_or(|predicate| {
        let bit = lane * element_bytes;
        predicate[bit / BITS_PER_BYTE] & (1 << (bit % BITS_PER_BYTE)) != 0
    })
}

fn write_lane(output: &mut [u8], lane: usize, element_bytes: usize, bits: u64) {
    let offset = lane * element_bytes;
    output[offset..offset + element_bytes].copy_from_slice(&bits.to_le_bytes()[..element_bytes]);
}

fn evaluate(
    kind: Kind,
    format: Format,
    controls: NumericalControls,
    values: &[u64],
) -> Result<Outcome, CompletionError> {
    let fpcr = controls.fpcr;
    let outcome = match (kind, values) {
        (Kind::Binary(operation), [left, right]) => {
            floating::evaluate(format, operation, fpcr, *left, *right)?
        }
        (Kind::Fused(operation), [addend, left, right]) => {
            floating::fused::evaluate(format, operation, fpcr, *addend, *left, *right)?
        }
        (Kind::MinMax(operation), [left, right]) => {
            floating::minmax::evaluate(format, operation, fpcr, *left, *right)?
        }
        (Kind::Absolute, [bits]) => Outcome {
            bits: floating::sign::absolute(format, fpcr, *bits),
            exceptions: 0,
        },
        (Kind::Negate, [bits]) => Outcome {
            bits: floating::sign::negate(format, fpcr, *bits),
            exceptions: 0,
        },
        (Kind::SquareRoot, [bits]) => floating::sqrt::evaluate(format, fpcr, *bits)?,
        (Kind::Estimate(kind), [bits]) => {
            if controls.features.rpres() && format == Format::Single && fpcr & FPCR_AH != 0 {
                use stela_compiler::aarch64::simd::estimate::Kind as EstimateKind;
                match kind {
                    EstimateKind::Reciprocal => {
                        floating::estimate::precision::reciprocal(fpcr, *bits)
                    }
                    EstimateKind::ReciprocalSquareRoot => {
                        floating::estimate::precision::reciprocal_sqrt(fpcr, *bits)
                    }
                    _ => floating::estimate::evaluate(kind, format, fpcr, *bits)?,
                }
            } else {
                floating::estimate::evaluate(kind, format, fpcr, *bits)?
            }
        }
        (Kind::Refinement(kind), [left, right]) => {
            floating::refinement::evaluate(kind, format, fpcr, *left, *right)?
        }
        (Kind::Logb, [bits]) => floating::exponent::logb(format, fpcr, *bits)?,
        (Kind::Scale, [bits, scale]) => floating::exponent::scale(format, fpcr, *bits, *scale)?,
        (Kind::Clamp, [lower, value, upper]) => {
            let maximum = floating::minmax::evaluate(
                format,
                MinMaxOperation::MaximumNumber,
                fpcr,
                *lower,
                *value,
            )?;
            let minimum = floating::minmax::evaluate(
                format,
                MinMaxOperation::MinimumNumber,
                fpcr,
                maximum.bits,
                *upper,
            )?;
            Outcome {
                bits: minimum.bits,
                exceptions: maximum.exceptions | minimum.exceptions,
            }
        }
        _ => return Err(anyhow!("scalable numerical kind/operand shape differ").into()),
    };
    Ok(outcome)
}

fn identity(kind: Kind, format: Format, fpcr: u32) -> anyhow::Result<u64> {
    if kind == Kind::Binary(BinaryOperation::Add) {
        return Ok(0);
    }
    let (infinity, quiet) = match format {
        Format::Half => (HALF_INFINITY, HALF_QUIET_BIT),
        Format::Single => (SINGLE_INFINITY, SINGLE_QUIET_BIT),
        Format::Double => (DOUBLE_INFINITY, DOUBLE_QUIET_BIT),
    };
    let sign = 1 << (format.bits() - 1);
    Ok(match kind {
        Kind::MinMax(MinMaxOperation::Minimum) => infinity,
        Kind::MinMax(MinMaxOperation::Maximum) => sign | infinity,
        Kind::MinMax(MinMaxOperation::MinimumNumber | MinMaxOperation::MaximumNumber) => {
            infinity | quiet | if fpcr & FPCR_AH != 0 { sign } else { 0 }
        }
        _ => return Err(anyhow!("operation has no scalable reduction identity")),
    })
}

fn reduce_tree(
    values: &[u64],
    kind: Kind,
    format: Format,
    controls: NumericalControls,
    exceptions: &mut u32,
) -> Result<u64, CompletionError> {
    if values.len() == 1 {
        return Ok(values[0]);
    }
    let midpoint = values.len() / REDUCTION_SUBTREES;
    // Arm evaluates the high subtree first, while combining low as operand one.
    let high = reduce_tree(&values[midpoint..], kind, format, controls, exceptions)?;
    let low = reduce_tree(&values[..midpoint], kind, format, controls, exceptions)?;
    let outcome = evaluate(kind, format, controls, &[low, high])?;
    *exceptions |= outcome.exceptions;
    Ok(outcome.bits)
}

fn complex_lane(
    operand: &Operand,
    sources: &Sources,
    lane: usize,
    element_bytes: usize,
    fpcr: u32,
) -> Result<Outcome, CompletionError> {
    let pair = lane / COMPLEX_COMPONENTS;
    let component = lane % COMPLEX_COMPONENTS;
    match operand.kind {
        Kind::ComplexAdd(rotation) => {
            require(sources.count == 2, "complex add requires two sources")?;
            let negate = match rotation {
                Rotation::Degrees90 => component == REAL_COMPONENT,
                Rotation::Degrees270 => component == IMAGINARY_COMPONENT,
                _ => return Err(anyhow!("unallocated complex-add rotation").into()),
            };
            let left = sources.raw_lane(0, lane, element_bytes);
            let mut right = sources.raw_lane(1, lane ^ 1, element_bytes);
            if negate {
                right = floating::sign::negate(operand.format, fpcr, right);
            }
            Ok(floating::evaluate(
                operand.format,
                BinaryOperation::Add,
                fpcr,
                left,
                right,
            )?)
        }
        Kind::ComplexMultiplyAdd(rotation) => {
            require(
                sources.count == 3,
                "complex multiply-add requires three sources",
            )?;
            let (selected, negate_real, negate_imaginary) = match rotation {
                Rotation::Degrees0 => (REAL_COMPONENT, false, false),
                Rotation::Degrees90 => (IMAGINARY_COMPONENT, true, false),
                Rotation::Degrees180 => (REAL_COMPONENT, true, true),
                Rotation::Degrees270 => (IMAGINARY_COMPONENT, false, true),
            };
            let right_pair = if let Source::Indexed { index, .. } = sources.descriptors[2] {
                let pairs = VECTOR_CHUNK_BYTES / (COMPLEX_COMPONENTS * element_bytes);
                pair - pair % pairs + usize::from(index)
            } else {
                pair
            };
            let right_component = if component == REAL_COMPONENT {
                selected
            } else {
                selected ^ 1
            };
            let addend = sources.raw_lane(0, lane, element_bytes);
            let left = sources.raw_lane(1, pair * COMPLEX_COMPONENTS + selected, element_bytes);
            let mut right = sources.raw_lane(
                2,
                right_pair * COMPLEX_COMPONENTS + right_component,
                element_bytes,
            );
            let negate = if component == REAL_COMPONENT {
                negate_real
            } else {
                negate_imaginary
            };
            if negate {
                right = floating::sign::negate(operand.format, fpcr, right);
            }
            Ok(floating::fused::evaluate(
                operand.format,
                FusedOperation::Add,
                fpcr,
                addend,
                left,
                right,
            )?)
        }
        _ => Err(anyhow!("complex lane requires a complex operation").into()),
    }
}

/// Complete one original instruction. Raw FPCR, unrelated registers and RAM stay intact.
/// Enabled traps under FA64 retain the existing precise unsupported-control result.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require(
        scalable.mode().streaming(),
        "scalable arithmetic requires streaming state",
    )?;
    let length = scalable.vector_length().bytes();
    let element_bytes = operand.format.bits() as usize / BITS_PER_BYTE;
    let count = length / element_bytes;
    let sources = Sources::snapshot(state, scalable, operand)?;
    for descriptor in sources.descriptors.iter().take(sources.count) {
        if let Source::Indexed { index, .. } = *descriptor {
            let complex = matches!(operand.kind, Kind::ComplexMultiplyAdd(_));
            let elements =
                VECTOR_CHUNK_BYTES / element_bytes / if complex { COMPLEX_COMPONENTS } else { 1 };
            require(
                usize::from(index) < elements,
                "scalable index outside its segment",
            )?;
        }
    }
    let mut predicate_storage = [0; MAX_PREDICATE_BYTES];
    let predicate = if let Some(register) = operand.predicate {
        let bytes = scalable.vector_length().predicate_bytes();
        scalable.read_predicate(register, &mut predicate_storage[..bytes])?;
        Some(&predicate_storage[..bytes])
    } else {
        None
    };
    let fpcr = controls.fpcr;
    let mut result = [0; MAX_VECTOR_BYTES];
    let mut exceptions = 0;
    if let Inputs::Reduction { .. } = operand.inputs {
        let identity = identity(operand.kind, operand.format, fpcr)?;
        let positions = match operand.shape {
            ResultShape::ScalarReduction => 1,
            ResultShape::QuadReduction => VECTOR_CHUNK_BYTES / element_bytes,
            ResultShape::Vector => return Err(anyhow!("reduction lacks its result shape").into()),
        };
        let mut values = [0; MAX_VECTOR_BYTES / size_of::<u16>()];
        for position in 0..positions {
            let group_count = count / positions;
            for (index, value) in values[..group_count].iter_mut().enumerate() {
                let lane = index * positions + position;
                *value = if active(predicate, lane, element_bytes) {
                    sources.raw_lane(0, lane, element_bytes)
                } else {
                    identity
                };
            }
            let bits = reduce_tree(
                &values[..group_count],
                operand.kind,
                operand.format,
                controls,
                &mut exceptions,
            )?;
            write_lane(&mut result, position, element_bytes, bits);
        }
    } else {
        require(
            operand.shape == ResultShape::Vector,
            "non-reduction has a reduction result shape",
        )?;
        scalable.read_z(state, operand.destination, &mut result[..length])?;
        for lane in 0..count {
            if !active(predicate, lane, element_bytes) {
                continue;
            }
            let outcome = if matches!(
                operand.kind,
                Kind::ComplexAdd(_) | Kind::ComplexMultiplyAdd(_)
            ) {
                complex_lane(operand, &sources, lane, element_bytes, fpcr)?
            } else if matches!(operand.inputs, Inputs::Pairwise { .. }) {
                let (source, first) = if lane % COMPLEX_COMPONENTS == 0 {
                    (0, lane)
                } else {
                    (1, lane - 1)
                };
                evaluate(
                    operand.kind,
                    operand.format,
                    controls,
                    &[
                        sources.raw_lane(source, first, element_bytes),
                        sources.raw_lane(source, first + 1, element_bytes),
                    ],
                )?
            } else {
                let mut values = [0; MAX_SOURCES];
                for (source, value) in values.iter_mut().enumerate().take(sources.count) {
                    *value = sources.lane(source, lane, element_bytes);
                }
                evaluate(
                    operand.kind,
                    operand.format,
                    controls,
                    &values[..sources.count],
                )?
            };
            exceptions |= outcome.exceptions;
            write_lane(&mut result, lane, element_bytes, outcome.bits);
        }
    }
    // Validate/commit the complete architectural destination before sticky status.
    match operand.shape {
        ResultShape::Vector => scalable.write_z(state, operand.destination, &result[..length])?,
        ResultShape::ScalarReduction | ResultShape::QuadReduction => {
            let mut limbs = [0; VECTOR_LIMBS];
            for (limb, source) in limbs.iter_mut().zip(
                result[..VECTOR_CHUNK_BYTES]
                    .as_chunks::<{ size_of::<u64>() }>()
                    .0,
            ) {
                *limb = u64::from_le_bytes(*source);
            }
            scalable.write_v(state, operand.destination, limbs)?;
        }
    }
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, INVALID},
        scalable::{ScalableMode, VectorLength},
    };

    fn complete_profile(
        state: &mut GuestState,
        scalable: &mut ScalableState,
        operand: &Operand,
        full_a64: bool,
    ) -> Result<(), CompletionError> {
        use stela_compiler::aarch64::floating::features::NumericalFeatures;
        let controls = NumericalControls::new(
            state.fpcr,
            true,
            NumericalFeatures::new(full_a64, false, false),
        );
        super::complete(state, scalable, operand, controls)
    }

    const FIRST_SOURCE: u8 = 1;
    const SECOND_SOURCE: u8 = 2;
    const LAST_REGISTER: u8 = 31;
    const SINGLE_ONE: u64 = 0x3f80_0000;
    const SINGLE_TWO: u64 = 0x4000_0000;
    const SINGLE_THREE: u64 = 0x4040_0000;
    const SINGLE_SIGNALING_NAN: u64 = 0x7f80_0001;
    const SINGLE_QUIET_NAN: u64 = 0x7fc0_0001;

    fn setup(length: usize) -> (GuestState, ScalableState) {
        let mut state = GuestState {
            x: std::array::from_fn(|index| 0x1234_0000_0000_0000 | index as u64),
            nzcv: 0xa000_0000,
            sp: 0x1111_2222_3333_4444,
            reserved: 0xaaaa_5555,
            ..GuestState::default()
        };
        let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
        scalable
            .apply_mode(&mut state, ScalableMode::new(true, true))
            .unwrap();
        state.fpsr = FPSR_QC;
        (state, scalable)
    }

    fn put(
        scalable: &mut ScalableState,
        state: &mut GuestState,
        register: u8,
        values: &[u64],
        format: Format,
    ) {
        let element_bytes = format.bits() as usize / BITS_PER_BYTE;
        let mut bytes = vec![0; scalable.vector_length().bytes()];
        for (lane, value) in values.iter().enumerate() {
            write_lane(&mut bytes, lane, element_bytes, *value);
        }
        scalable.write_z(state, register, &bytes).unwrap();
    }

    fn get(scalable: &ScalableState, state: &GuestState, register: u8, format: Format) -> Vec<u64> {
        let element_bytes = format.bits() as usize / BITS_PER_BYTE;
        let mut bytes = vec![0; scalable.vector_length().bytes()];
        scalable.read_z(state, register, &mut bytes).unwrap();
        bytes
            .chunks_exact(element_bytes)
            .map(|source| {
                let mut bits = [0; size_of::<u64>()];
                bits[..element_bytes].copy_from_slice(source);
                u64::from_le_bytes(bits)
            })
            .collect()
    }

    fn binary(destination: u8, predicate: Option<u8>) -> Operand {
        Operand {
            kind: Kind::Binary(BinaryOperation::Add),
            format: Format::Single,
            destination,
            predicate,
            inputs: Inputs::Binary {
                left: Source::Vector(FIRST_SOURCE),
                right: Source::Vector(SECOND_SOURCE),
            },
            shape: ResultShape::Vector,
        }
    }

    fn set_predicate(scalable: &mut ScalableState, lanes: &[usize], format: Format) {
        let element_bytes = format.bits() as usize / BITS_PER_BYTE;
        let mut predicate = vec![0; scalable.vector_length().predicate_bytes()];
        for lane in lanes {
            let bit = lane * element_bytes;
            predicate[bit / BITS_PER_BYTE] |= 1 << (bit % BITS_PER_BYTE);
        }
        scalable.write_predicate(0, &predicate).unwrap();
    }

    #[test]
    fn streaming_enables_accumulate_but_full_a64_refuses_before_effects() {
        let (mut state, mut scalable) = setup(32);
        put(
            &mut scalable,
            &mut state,
            FIRST_SOURCE,
            &[0; 8],
            Format::Single,
        );
        put(
            &mut scalable,
            &mut state,
            SECOND_SOURCE,
            &[0; 8],
            Format::Single,
        );
        state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
        let mut operand = binary(LAST_REGISTER, None);
        operand.kind = Kind::Binary(BinaryOperation::Divide);
        complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
        assert_eq!(
            get(&scalable, &state, LAST_REGISTER, Format::Single),
            vec![SINGLE_INFINITY | SINGLE_QUIET_BIT; 8]
        );
        assert_eq!(state.fpcr, FPCR_EXCEPTION_ENABLE_MASK);
        assert_eq!(state.fpsr, FPSR_QC | INVALID);
        let before = state.clone();
        let upper = get(&scalable, &state, LAST_REGISTER, Format::Single);
        assert!(matches!(
            complete_profile(&mut state, &mut scalable, &operand, true),
            Err(CompletionError::UnsupportedControl(_))
        ));
        assert_eq!(state, before);
        assert_eq!(get(&scalable, &state, LAST_REGISTER, Format::Single), upper);
    }

    #[test]
    fn inactive_numeric_lanes_never_refuse_controls_or_change_status() {
        let (mut state, mut scalable) = setup(64);
        put(
            &mut scalable,
            &mut state,
            LAST_REGISTER,
            &[SINGLE_SIGNALING_NAN; 16],
            Format::Single,
        );
        state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
        let before = state.clone();
        complete_profile(
            &mut state,
            &mut scalable,
            &binary(LAST_REGISTER, Some(0)),
            true,
        )
        .unwrap();
        assert_eq!(state, before);
        assert_eq!(
            get(&scalable, &state, LAST_REGISTER, Format::Single),
            vec![SINGLE_SIGNALING_NAN; 16]
        );
    }

    #[test]
    fn indexed_destination_alias_uses_original_segment_sources() {
        let (mut state, mut scalable) = setup(32);
        put(
            &mut scalable,
            &mut state,
            FIRST_SOURCE,
            &[SINGLE_ONE; 8],
            Format::Single,
        );
        put(
            &mut scalable,
            &mut state,
            LAST_REGISTER,
            &[0, SINGLE_TWO, 0, 0, 0, SINGLE_THREE, 0, 0],
            Format::Single,
        );
        let operand = Operand {
            kind: Kind::Binary(BinaryOperation::Multiply),
            format: Format::Single,
            destination: LAST_REGISTER,
            predicate: None,
            inputs: Inputs::Binary {
                left: Source::Vector(FIRST_SOURCE),
                right: Source::Indexed {
                    register: LAST_REGISTER,
                    index: 1,
                },
            },
            shape: ResultShape::Vector,
        };
        complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
        assert_eq!(
            get(&scalable, &state, LAST_REGISTER, Format::Single),
            vec![
                SINGLE_TWO,
                SINGLE_TWO,
                SINGLE_TWO,
                SINGLE_TWO,
                SINGLE_THREE,
                SINGLE_THREE,
                SINGLE_THREE,
                SINGLE_THREE
            ]
        );
    }

    #[test]
    fn pairwise_predicates_select_output_not_input_lanes() {
        let (mut state, mut scalable) = setup(16);
        put(
            &mut scalable,
            &mut state,
            LAST_REGISTER,
            &[SINGLE_ONE; 4],
            Format::Single,
        );
        put(
            &mut scalable,
            &mut state,
            SECOND_SOURCE,
            &[SINGLE_SIGNALING_NAN, SINGLE_ONE, SINGLE_ONE, SINGLE_ONE],
            Format::Single,
        );
        set_predicate(&mut scalable, &[1], Format::Single);
        let mut operand = binary(LAST_REGISTER, Some(0));
        operand.inputs = Inputs::Pairwise {
            left: LAST_REGISTER,
            right: SECOND_SOURCE,
        };
        complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
        assert_eq!(
            get(&scalable, &state, LAST_REGISTER, Format::Single),
            vec![SINGLE_ONE, SINGLE_QUIET_NAN, SINGLE_ONE, SINGLE_ONE]
        );
        assert_eq!(state.fpsr, FPSR_QC | INVALID);
    }

    #[test]
    fn quad_base_preserves_raw_nan_then_v_write_clears_upper_z() {
        let (mut state, mut scalable) = setup(16);
        put(
            &mut scalable,
            &mut state,
            FIRST_SOURCE,
            &[SINGLE_SIGNALING_NAN; 4],
            Format::Single,
        );
        set_predicate(&mut scalable, &[0, 1, 2, 3], Format::Single);
        state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
        let operand = Operand {
            kind: Kind::Binary(BinaryOperation::Add),
            format: Format::Single,
            destination: LAST_REGISTER,
            predicate: Some(0),
            inputs: Inputs::Reduction {
                source: FIRST_SOURCE,
            },
            shape: ResultShape::QuadReduction,
        };
        complete_profile(&mut state, &mut scalable, &operand, true).unwrap();
        assert_eq!(
            get(&scalable, &state, LAST_REGISTER, Format::Single),
            vec![SINGLE_SIGNALING_NAN; 4]
        );
        assert_eq!(state.fpsr, FPSR_QC);
        let (mut state, mut scalable) = setup(32);
        put(
            &mut scalable,
            &mut state,
            FIRST_SOURCE,
            &[
                SINGLE_ONE, SINGLE_ONE, SINGLE_ONE, SINGLE_ONE, SINGLE_TWO, SINGLE_TWO, SINGLE_TWO,
                SINGLE_TWO,
            ],
            Format::Single,
        );
        set_predicate(&mut scalable, &(0..8).collect::<Vec<_>>(), Format::Single);
        complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
        assert_eq!(
            get(&scalable, &state, LAST_REGISTER, Format::Single),
            vec![
                SINGLE_THREE,
                SINGLE_THREE,
                SINGLE_THREE,
                SINGLE_THREE,
                0,
                0,
                0,
                0
            ]
        );
    }

    #[test]
    fn inactive_complex_component_cannot_raise_invalid() {
        let (mut state, mut scalable) = setup(16);
        put(
            &mut scalable,
            &mut state,
            LAST_REGISTER,
            &[SINGLE_ONE; 4],
            Format::Single,
        );
        put(
            &mut scalable,
            &mut state,
            FIRST_SOURCE,
            &[SINGLE_ONE; 4],
            Format::Single,
        );
        put(
            &mut scalable,
            &mut state,
            SECOND_SOURCE,
            &[
                SINGLE_SIGNALING_NAN,
                SINGLE_ONE,
                SINGLE_SIGNALING_NAN,
                SINGLE_ONE,
            ],
            Format::Single,
        );
        set_predicate(&mut scalable, &[1, 3], Format::Single);
        let operand = Operand {
            kind: Kind::ComplexMultiplyAdd(Rotation::Degrees0),
            format: Format::Single,
            destination: LAST_REGISTER,
            predicate: Some(0),
            inputs: Inputs::Fused {
                addend: LAST_REGISTER,
                left: FIRST_SOURCE,
                right: Source::Vector(SECOND_SOURCE),
            },
            shape: ResultShape::Vector,
        };
        complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
        assert_eq!(
            get(&scalable, &state, LAST_REGISTER, Format::Single),
            vec![SINGLE_ONE, SINGLE_TWO, SINGLE_ONE, SINGLE_TWO]
        );
        assert_eq!(state.fpsr, FPSR_QC);
    }

    #[test]
    fn reciprocal_precision_requires_the_bound_feature_single_width_and_ah() {
        use stela_compiler::aarch64::{
            floating::features::NumericalFeatures, simd::estimate::Kind as EstimateKind,
        };
        const INPUT: u64 = 0x3f81_2345;
        for (kind, standard, enhanced) in [
            (EstimateKind::Reciprocal, 0x3f7d_8000, 0x3f7d_b800),
            (EstimateKind::ReciprocalSquareRoot, 0x3f7e_8000, 0x3f7e_d000),
        ] {
            for ah in [0, FPCR_AH] {
                for rpres in [false, true] {
                    let (mut state, mut scalable) = setup(16);
                    state.fpcr = ah | FPCR_EXCEPTION_ENABLE_MASK;
                    put(
                        &mut scalable,
                        &mut state,
                        FIRST_SOURCE,
                        &[INPUT; 4],
                        Format::Single,
                    );
                    let operand = Operand {
                        kind: Kind::Estimate(kind),
                        format: Format::Single,
                        destination: LAST_REGISTER,
                        predicate: None,
                        inputs: Inputs::Unary {
                            source: FIRST_SOURCE,
                        },
                        shape: ResultShape::Vector,
                    };
                    let controls = NumericalControls::new(
                        state.fpcr,
                        true,
                        NumericalFeatures::new(false, false, rpres),
                    );
                    super::complete(&mut state, &mut scalable, &operand, controls).unwrap();
                    let expected = if rpres && ah != 0 { enhanced } else { standard };
                    assert_eq!(
                        get(&scalable, &state, LAST_REGISTER, Format::Single),
                        vec![expected; 4]
                    );
                    assert_eq!(state.fpcr, ah | FPCR_EXCEPTION_ENABLE_MASK);
                    assert_eq!(state.fpsr, FPSR_QC);
                }
            }
            let (mut state, mut scalable) = setup(16);
            state.fpcr = FPCR_AH;
            const HALF_ONE: u64 = 0x3c00;
            put(
                &mut scalable,
                &mut state,
                FIRST_SOURCE,
                &[HALF_ONE; 8],
                Format::Half,
            );
            let operand = Operand {
                kind: Kind::Estimate(kind),
                format: Format::Half,
                destination: LAST_REGISTER,
                predicate: None,
                inputs: Inputs::Unary {
                    source: FIRST_SOURCE,
                },
                shape: ResultShape::Vector,
            };
            let controls = NumericalControls::new(
                state.fpcr,
                true,
                NumericalFeatures::new(false, false, true),
            );
            super::complete(&mut state, &mut scalable, &operand, controls).unwrap();
            let expected =
                floating::estimate::evaluate(kind, Format::Half, state.fpcr, HALF_ONE).unwrap();
            assert_eq!(
                get(&scalable, &state, LAST_REGISTER, Format::Half),
                vec![expected.bits; 8]
            );
        }
    }

    #[test]
    fn empty_number_reductions_return_default_nan_identity() {
        for fpcr in [0, FPCR_AH] {
            let (mut state, mut scalable) = setup(32);
            state.fpcr = fpcr;
            let operand = Operand {
                kind: Kind::MinMax(MinMaxOperation::MinimumNumber),
                format: Format::Single,
                destination: LAST_REGISTER,
                predicate: Some(0),
                inputs: Inputs::Reduction {
                    source: FIRST_SOURCE,
                },
                shape: ResultShape::QuadReduction,
            };
            complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
            let nan = SINGLE_INFINITY
                | SINGLE_QUIET_BIT
                | if fpcr == 0 {
                    0
                } else {
                    1 << (Format::Single.bits() - 1)
                };
            assert_eq!(
                get(&scalable, &state, LAST_REGISTER, Format::Single),
                vec![nan, nan, nan, nan, 0, 0, 0, 0]
            );
            assert_eq!(state.fpsr, FPSR_QC);
        }
    }
}
