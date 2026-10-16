//! Transactional whole-Z FP8 conversion. All aliased inputs precede evaluation.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::fp8::{self, ConversionFormat},
        scalable::MAX_VECTOR_BYTES,
        sve::floating::fp8::{Kind, Operand, Precision},
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

fn format(precision: Precision) -> ConversionFormat {
    match precision {
        Precision::Half => ConversionFormat::Half,
        Precision::Bfloat16 => ConversionFormat::BFloat16,
        Precision::Single => ConversionFormat::Single,
    }
}

pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    if !scalable.mode().streaming() {
        return Err(anyhow!("FP8 conversion requires admitted streaming state").into());
    }
    if operand.destination >= 32
        || operand.source >= 32
        || matches!(
            operand.kind,
            Kind::Widen {
                precision: Precision::Single,
                ..
            }
        )
        || matches!(
            operand.kind,
            Kind::Narrow {
                precision: Precision::Half | Precision::Bfloat16,
                top: true
            }
        )
        || matches!(operand.kind, Kind::Narrow { .. }) && operand.source & 1 != 0
    {
        return Err(anyhow!("invalid SVE FP8 conversion descriptor").into());
    }
    let length = scalable.vector_length().bytes();
    let fpmr = scalable.fpmr();
    let mut first = [0; MAX_VECTOR_BYTES];
    let mut second = [0; MAX_VECTOR_BYTES];
    let mut result = [0; MAX_VECTOR_BYTES];
    scalable.read_z(state, operand.source, &mut first[..length])?;
    if matches!(operand.kind, Kind::Narrow { .. }) {
        scalable.read_z(state, operand.source + 1, &mut second[..length])?;
    }
    if matches!(operand.kind, Kind::Narrow { top: true, .. }) {
        scalable.read_z(state, operand.destination, &mut result[..length])?;
    }
    let mut exceptions = 0;
    match operand.kind {
        Kind::Widen {
            precision,
            source2,
            top,
        } => {
            for offset in (0..length).step_by(precision.bytes()) {
                let value = fp8::from_fp8(
                    format(precision),
                    source2,
                    controls.fpcr,
                    fpmr,
                    first[offset + usize::from(top)],
                )?;
                result[offset..offset + precision.bytes()]
                    .copy_from_slice(&value.bits.to_le_bytes()[..precision.bytes()]);
                exceptions |= value.exceptions;
            }
        }
        Kind::Narrow { precision, top } => {
            let source_bytes = precision.bytes();
            let destination_stride = source_bytes / 2;
            for offset in (0..length).step_by(source_bytes) {
                for (register, source) in [&first, &second].into_iter().enumerate() {
                    let mut bits = [0; size_of::<u64>()];
                    bits[..source_bytes].copy_from_slice(&source[offset..offset + source_bytes]);
                    let value = fp8::to_fp8(
                        format(precision),
                        controls.fpcr,
                        fpmr,
                        u64::from_le_bytes(bits),
                    )?;
                    let destination = offset + register * destination_stride + usize::from(top);
                    result[destination] = value.bits as u8;
                    exceptions |= value.exceptions;
                }
            }
        }
    }
    scalable.write_z(state, operand.destination, &result[..length])?;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
