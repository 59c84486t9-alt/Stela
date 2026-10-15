//! Staged Single-to-Double SVE widening with whole-instruction completion.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{
            FPCR_AHP, Format,
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
        matches!(
            kind,
            Kind::Precision {
                source: Format::Single,
                destination: Format::Double,
                rounding: PrecisionRounding::Fpcr,
                placement: Placement::Low | Placement::UpperSource
            }
        ),
        "unadmitted scalable widening conversion",
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
        let outcome = precision::evaluate(
            Format::Single,
            Format::Double,
            PrecisionRounding::Fpcr,
            controls.fpcr & !FPCR_AHP,
            u64::from_le_bytes(bits),
        )?;
        exceptions |= outcome.exceptions;
        let start = slot + destination_offset;
        result[start..start + written_bytes]
            .copy_from_slice(&outcome.bits.to_le_bytes()[..written_bytes]);
    }
    scalable.write_z(state, operand.destination, &result[..length])?;
    state.fpsr |= exceptions;
    Ok(())
}
