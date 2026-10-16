//! Re-decoding and admitting the instruction behind a scalable numerical exit.

use anyhow::{Context, Result};
use stela_compiler::{
    GuestAddress,
    aarch64::floating::features::NumericalFeatures,
    block::scalable::{
        AdmittedScalableNumericalInstruction, admit_scalable_numerical_instruction,
        decode_scalable_numerical_instruction,
    },
    extended::ScalableProfile,
};

use super::validate_interior_word;

/// Re-fetch an exit from the registered source before admitting it; operands
/// and continuation PCs from the artifact are not used. The live state must
/// still match the admitted profile at completion.
pub(crate) fn validate_scalable_numerical_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
    profile: ScalableProfile,
    numerical_features: NumericalFeatures,
) -> Result<AdmittedScalableNumericalInstruction> {
    let word = validate_interior_word(entry, exit, source_bytes, region_base, source)?;
    let instruction = decode_scalable_numerical_instruction(exit, word)?
        .context("scalable numerical exit does not identify numerical completion")?;
    Ok(admit_scalable_numerical_instruction(
        instruction,
        profile,
        numerical_features,
    )?)
}

#[cfg(test)]
mod tests;
