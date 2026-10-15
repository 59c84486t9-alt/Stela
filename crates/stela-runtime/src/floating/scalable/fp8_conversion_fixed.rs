//! Transactional fixed-width FP8 conversion using the owned FPMR context.
use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::fp8::{self, ConversionFormat},
        simd::fp8_conversion::{Kind, Operand},
    },
};

const VECTOR_BYTES: usize = 16;
const HALF_VECTOR_BYTES: usize = 8;
const HALF_BYTES: usize = 2;
const SINGLE_BYTES: usize = 4;

fn bytes(vector: [u64; 2]) -> [u8; VECTOR_BYTES] {
    let mut bytes = [0; VECTOR_BYTES];
    bytes[..HALF_VECTOR_BYTES].copy_from_slice(&vector[0].to_le_bytes());
    bytes[HALF_VECTOR_BYTES..].copy_from_slice(&vector[1].to_le_bytes());
    bytes
}

/// Admission establishes FP/ASIMD and FPMR access, plus FullA64 if streaming.
/// Fixed instructions retain exception enables; effective streaming suppression
/// must never be borrowed from the scalable conversion rules.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    let source = bytes(state.v[usize::from(operand.source)]);
    let second = bytes(state.v[usize::from(operand.second_source)]);
    let old = bytes(state.v[usize::from(operand.destination)]);
    let mut result = [0; VECTOR_BYTES];
    let mut exceptions = 0;
    let fpmr = scalable.fpmr();
    match operand.kind {
        Kind::Widen {
            destination,
            source2,
            upper,
        } => {
            let offset = usize::from(upper) * HALF_VECTOR_BYTES;
            for lane in 0..HALF_VECTOR_BYTES {
                let outcome = fp8::from_fp8(
                    destination,
                    source2,
                    controls.fpcr,
                    fpmr,
                    source[offset + lane],
                )?;
                result[lane * HALF_BYTES..(lane + 1) * HALF_BYTES]
                    .copy_from_slice(&(outcome.bits as u16).to_le_bytes());
                exceptions |= outcome.exceptions;
            }
        }
        Kind::NarrowHalf { vector128 } => {
            let source_bytes = if vector128 {
                VECTOR_BYTES
            } else {
                HALF_VECTOR_BYTES
            };
            let lanes = source_bytes / HALF_BYTES;
            for (group, input) in [source, second].iter().enumerate() {
                for lane in 0..lanes {
                    let start = lane * HALF_BYTES;
                    let bits = u16::from_le_bytes(
                        input[start..start + HALF_BYTES]
                            .try_into()
                            .expect("half lane"),
                    );
                    let outcome =
                        fp8::to_fp8(ConversionFormat::Half, controls.fpcr, fpmr, u64::from(bits))?;
                    result[group * lanes + lane] = outcome.bits as u8;
                    exceptions |= outcome.exceptions;
                }
            }
        }
        Kind::NarrowSingle { upper } => {
            let destination_offset = usize::from(upper) * HALF_VECTOR_BYTES;
            if upper {
                result = old;
            }
            let lanes = VECTOR_BYTES / SINGLE_BYTES;
            for (group, input) in [source, second].iter().enumerate() {
                for lane in 0..lanes {
                    let start = lane * SINGLE_BYTES;
                    let bits = u32::from_le_bytes(
                        input[start..start + SINGLE_BYTES]
                            .try_into()
                            .expect("single lane"),
                    );
                    let outcome = fp8::to_fp8(
                        ConversionFormat::Single,
                        controls.fpcr,
                        fpmr,
                        u64::from(bits),
                    )?;
                    result[destination_offset + group * lanes + lane] = outcome.bits as u8;
                    exceptions |= outcome.exceptions;
                }
            }
        }
    }
    let value = [
        u64::from_le_bytes(result[..HALF_VECTOR_BYTES].try_into().expect("low limb")),
        u64::from_le_bytes(result[HALF_VECTOR_BYTES..].try_into().expect("high limb")),
    ];
    scalable.write_v(state, operand.destination, value)?;
    state.fpsr |= exceptions;
    Ok(())
}
