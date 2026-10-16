//! Transactional SME2 FP8 conversions over complete aligned vector groups.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::fp8::{self, ConversionFormat},
        scalable::{MAX_VECTOR_BYTES, VECTOR_REGISTER_COUNT},
        sme::{
            fp_vector::VectorGroup,
            fp8_conversion::{Conversion, ElementFormat, Operand},
        },
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const MAX_GROUP_COUNT: usize = 4;
const PAIR_COUNT: u8 = 2;
const HALF_BYTES: usize = size_of::<u16>();
type GroupBytes = [[u8; MAX_VECTOR_BYTES]; MAX_GROUP_COUNT];

fn require(condition: bool, message: &'static str) -> Result<(), CompletionError> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(message).into())
    }
}

fn validate_group(group: VectorGroup) -> Result<(), CompletionError> {
    require(
        matches!(group.count, 1 | 2 | 4)
            && group.first.is_multiple_of(group.count)
            && usize::from(group.first) + usize::from(group.count)
                <= usize::from(VECTOR_REGISTER_COUNT),
        "invalid SME FP8 vector group",
    )
}

fn snapshot_group(
    state: &GuestState,
    scalable: &ScalableState,
    group: VectorGroup,
) -> Result<GroupBytes, CompletionError> {
    validate_group(group)?;
    let length = scalable.vector_length().bytes();
    let mut result = [[0; MAX_VECTOR_BYTES]; MAX_GROUP_COUNT];
    for (index, output) in result.iter_mut().take(usize::from(group.count)).enumerate() {
        scalable.read_z(state, group.first + index as u8, &mut output[..length])?;
    }
    Ok(result)
}

fn conversion_format(format: ElementFormat) -> ConversionFormat {
    match format {
        ElementFormat::Half => ConversionFormat::Half,
        ElementFormat::BFloat16 => ConversionFormat::BFloat16,
        ElementFormat::Single => ConversionFormat::Single,
    }
}

/// Admission has established SME2, FP8 and FPMR access. Snapshot every source
/// before any destination write. Stage numerical status and full results so
/// unsupported controls leave all state untouched, including aliased V values.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require(
        scalable.mode().streaming(),
        "SME FP8 conversion requires streaming state",
    )?;
    let source = operand.source;
    let destination = operand.destination;
    match operand.conversion {
        Conversion::Widen { .. } => require(
            source.count == 1
                && destination.count == PAIR_COUNT
                && operand.format != ElementFormat::Single,
            "invalid SME FP8 widening shape",
        )?,
        Conversion::Narrow { interleaved } => require(
            usize::from(source.count) == operand.format.bytes()
                && destination.count == 1
                && (!interleaved || operand.format == ElementFormat::Single),
            "invalid SME FP8 narrowing shape",
        )?,
    }
    validate_group(destination)?;
    let sources = snapshot_group(state, scalable, source)?;
    let mut results = [[0; MAX_VECTOR_BYTES]; MAX_GROUP_COUNT];
    let length = scalable.vector_length().bytes();
    let format = conversion_format(operand.format);
    let fpmr = scalable.fpmr();
    let mut exceptions = 0;
    match operand.conversion {
        Conversion::Widen {
            source2,
            deinterleaved,
        } => {
            let output_lanes = length / HALF_BYTES;
            for (lane, &bits) in sources[0][..length].iter().enumerate() {
                let outcome = fp8::from_fp8(format, source2, controls.fpcr, fpmr, bits)?;
                let (register, output_lane) = if deinterleaved {
                    (
                        lane % usize::from(PAIR_COUNT),
                        lane / usize::from(PAIR_COUNT),
                    )
                } else {
                    (lane / output_lanes, lane % output_lanes)
                };
                let offset = output_lane * HALF_BYTES;
                results[register][offset..offset + HALF_BYTES]
                    .copy_from_slice(&(outcome.bits as u16).to_le_bytes());
                exceptions |= outcome.exceptions;
            }
        }
        Conversion::Narrow { interleaved } => {
            let bytes = operand.format.bytes();
            let lanes = length / bytes;
            for (register, input) in sources.iter().take(usize::from(source.count)).enumerate() {
                for lane in 0..lanes {
                    let offset = lane * bytes;
                    let mut bits = [0; size_of::<u64>()];
                    bits[..bytes].copy_from_slice(&input[offset..offset + bytes]);
                    let outcome =
                        fp8::to_fp8(format, controls.fpcr, fpmr, u64::from_le_bytes(bits))?;
                    let output_lane = if interleaved {
                        lane * usize::from(source.count) + register
                    } else {
                        register * lanes + lane
                    };
                    results[0][output_lane] = outcome.bits as u8;
                    exceptions |= outcome.exceptions;
                }
            }
        }
    }
    // Source snapshots checked the shared streaming backing and vector length;
    // destination bounds were validated before evaluation. Writes cannot allocate
    // or introduce numerical failure after the first register commit.
    for (index, result) in results
        .iter()
        .take(usize::from(destination.count))
        .enumerate()
    {
        scalable.write_z(state, destination.first + index as u8, &result[..length])?;
    }
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
