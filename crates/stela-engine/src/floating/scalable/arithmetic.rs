//! Completion of SVE arithmetic from full source snapshots.

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
use stela_contracts::{refuse, require};

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
    ) -> crate::Result<Self> {
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
        _ => return Err(refuse!("scalable numerical kind/operand shape differ").into()),
    };
    Ok(outcome)
}

fn identity(kind: Kind, format: Format, fpcr: u32) -> Result<u64, stela_contracts::Refusal> {
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
        _ => return Err(refuse!("operation has no scalable reduction identity")),
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
            require!(sources.count == 2, "complex add requires two sources");
            let negate = match rotation {
                Rotation::Degrees90 => component == REAL_COMPONENT,
                Rotation::Degrees270 => component == IMAGINARY_COMPONENT,
                _ => return Err(refuse!("unallocated complex-add rotation").into()),
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
            require!(
                sources.count == 3,
                "complex multiply-add requires three sources",
            );
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
        _ => Err(refuse!("complex lane requires a complex operation").into()),
    }
}

/// Complete one instruction. Raw FPCR, unrelated registers and RAM are
/// untouched; with FA64, enabled traps are refused as unsupported controls.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require!(
        scalable.mode().streaming(),
        "scalable arithmetic requires streaming state",
    );
    let length = scalable.vector_length().bytes();
    let element_bytes = operand.format.bits() as usize / BITS_PER_BYTE;
    let count = length / element_bytes;
    let sources = Sources::snapshot(state, scalable, operand)?;
    for descriptor in sources.descriptors.iter().take(sources.count) {
        if let Source::Indexed { index, .. } = *descriptor {
            let complex = matches!(operand.kind, Kind::ComplexMultiplyAdd(_));
            let elements =
                VECTOR_CHUNK_BYTES / element_bytes / if complex { COMPLEX_COMPONENTS } else { 1 };
            require!(
                usize::from(index) < elements,
                "scalable index outside its segment",
            );
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
            ResultShape::Vector => return Err(refuse!("reduction lacks its result shape").into()),
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
        require!(
            operand.shape == ResultShape::Vector,
            "non-reduction has a reduction result shape",
        );
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
mod tests;
