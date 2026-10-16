//! Completion of the SVE predicated conversions.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{
            FPCR_AHP, Format, Outcome, bfloat16,
            integer::{self, IntegerRounding, IntegerWidth},
            precision::{self, PrecisionRounding},
        },
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES},
        sve::floating::conversion::{Kind, Operand, Placement},
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const MAX_PREDICATE_BYTES: usize = MAX_VECTOR_BYTES / BITS_PER_BYTE;

fn require(condition: bool, message: &'static str) -> Result<(), CompletionError> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(message).into())
    }
}

fn active(predicate: &[u8], byte: usize) -> bool {
    predicate[byte / BITS_PER_BYTE] & (1 << (byte % BITS_PER_BYTE)) != 0
}

/// The twenty-eight integer conversion shapes: an H integer pairs only with
/// half precision, W and X with half, single and double.
fn admitted_integer(kind: Kind) -> bool {
    match kind {
        Kind::FromInteger {
            source: integer,
            destination: float,
        }
        | Kind::ToInteger {
            source: float,
            destination: integer,
        } => match float {
            Format::Half => matches!(
                integer.width,
                IntegerWidth::Bits16 | IntegerWidth::Bits32 | IntegerWidth::Bits64
            ),
            Format::Single | Format::Double => {
                matches!(integer.width, IntegerWidth::Bits32 | IntegerWidth::Bits64)
            }
        },
        _ => false,
    }
}

/// Exact precision allocations; manually constructed unallocated shapes fail
/// before state reads or numerical work, including all-inactive instructions.
fn admitted_precision(kind: Kind) -> bool {
    let Kind::Precision {
        source,
        destination,
        rounding,
        placement,
    } = kind
    else {
        return false;
    };
    matches!(
        (source, destination, rounding, placement),
        (
            Format::Half,
            Format::Single | Format::Double,
            PrecisionRounding::Fpcr,
            Placement::Low
        ) | (
            Format::Single,
            Format::Half | Format::Double,
            PrecisionRounding::Fpcr,
            Placement::Low
        ) | (
            Format::Double,
            Format::Half | Format::Single,
            PrecisionRounding::Fpcr,
            Placement::Low
        ) | (
            Format::Half,
            Format::Single,
            PrecisionRounding::Fpcr,
            Placement::UpperSource
        ) | (
            Format::Single,
            Format::Double,
            PrecisionRounding::Fpcr,
            Placement::UpperSource
        ) | (
            Format::Single,
            Format::Half,
            PrecisionRounding::Fpcr,
            Placement::UpperDestination
        ) | (
            Format::Double,
            Format::Single,
            PrecisionRounding::Fpcr | PrecisionRounding::ToOdd,
            Placement::UpperDestination
        ) | (
            Format::Double,
            Format::Single,
            PrecisionRounding::ToOdd,
            Placement::Low
        )
    )
}

/// Only called after the instruction-wide shape guard. Controls are already
/// profile-effective; the mature integer core owns its IEEE/AHP adapter.
fn integer_lane(kind: Kind, fpcr: u32, bits: u64) -> Result<Outcome, CompletionError> {
    let mut outcome = match kind {
        Kind::FromInteger {
            source,
            destination,
        } => integer::from_integer(source, destination, 0, fpcr, bits)?,
        Kind::ToInteger {
            source,
            destination,
        } => integer::to_integer(
            source,
            destination,
            0,
            IntegerRounding::TowardZero,
            fpcr,
            bits,
        )?,
        _ => return Err(anyhow!("expected admitted integer conversion").into()),
    };
    if let Kind::ToInteger { destination, .. } = kind
        && destination.signed
    {
        // FPToFixed narrows to the integer width first, then the result is
        // sign-extended across the full SVE element.
        let shift = u64::BITS - destination.width.bits();
        outcome.bits = (((outcome.bits << shift) as i64) >> shift) as u64;
    }
    Ok(outcome)
}

/// Sources, old destination and governing predicate are captured before any
/// numerical evaluation. Status and the complete Z destination commit together.
/// Raw FPCR remains unchanged when ordinary streaming masks retained enables.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require(
        scalable.mode().streaming(),
        "scalable conversion requires streaming state",
    )?;
    let kind = operand.kind;
    require(
        admitted_integer(kind) || admitted_precision(kind) || matches!(kind, Kind::Bfloat16 { .. }),
        "unadmitted scalable conversion",
    )?;
    let slot_bytes = usize::from(kind.slot_bytes());
    let source_bytes = kind.source_bits() as usize / BITS_PER_BYTE;
    let source_offset = usize::from(kind.source_offset());
    let destination_offset = usize::from(kind.destination_offset());
    let written_bytes = usize::from(kind.written_bytes());
    require(
        source_offset + source_bytes <= slot_bytes
            && destination_offset + written_bytes <= slot_bytes,
        "scalable conversion placement exceeds its slot",
    )?;
    let length = scalable.vector_length().bytes();
    let predicate_bytes = scalable.vector_length().predicate_bytes();
    let mut source = [0; MAX_VECTOR_BYTES];
    let mut result = [0; MAX_VECTOR_BYTES];
    let mut predicate = [0; MAX_PREDICATE_BYTES];
    scalable.read_z(state, operand.source, &mut source[..length])?;
    scalable.read_z(state, operand.destination, &mut result[..length])?;
    scalable.read_predicate(operand.governing, &mut predicate[..predicate_bytes])?;

    let mut exceptions = 0;
    for slot in (0..length).step_by(slot_bytes) {
        if !active(&predicate, slot) {
            continue;
        }
        let start = slot + source_offset;
        let mut bits = [0; size_of::<u64>()];
        bits[..source_bytes].copy_from_slice(&source[start..start + source_bytes]);
        let outcome = match kind {
            Kind::Precision {
                source,
                destination,
                rounding,
                ..
            } => precision::evaluate(
                source,
                destination,
                rounding,
                controls.fpcr & !FPCR_AHP,
                u64::from_le_bytes(bits),
            )?,
            Kind::Bfloat16 { .. } => {
                bfloat16::convert(controls.fpcr, u64::from_le_bytes(bits) as u32)?
            }
            Kind::ToInteger { .. } | Kind::FromInteger { .. } => {
                integer_lane(kind, controls.fpcr, u64::from_le_bytes(bits))?
            }
        };
        exceptions |= outcome.exceptions;
        let start = slot + destination_offset;
        result[start..start + written_bytes]
            .copy_from_slice(&outcome.bits.to_le_bytes()[..written_bytes]);
    }
    scalable.write_z(state, operand.destination, &result[..length])?;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
