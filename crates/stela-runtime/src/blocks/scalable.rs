//! Immutable source recovery and profile admission for scalable numerical exits.
//! This boundary describes the still-unexecuted instruction; it executes no effects.

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

/// Re-fetch an interior exit from registered immutable source before minting its
/// admission proof. Artifact-supplied operands and continuation PCs are not used.
/// Current owned state must separately match the admitted profile at completion.
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
mod tests {
    use super::*;
    use stela_compiler::aarch64::scalable::{
        ScalableMode, VectorLength,
        features::{ScalableFeature as Feature, ScalableFeatures},
        profile::ScalableControls,
    };

    const BASE: u64 = 0x1000;
    const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
    const NOP: u32 = 0xd503_201f;
    const RET: u32 = 0xd65f_03c0;
    const FADD_SINGLE: u32 = 0x6580_8000;
    const BFADD: u32 = 0x6500_8000;
    const SME_MATRIX: u32 = 0xc1a0_1c00;
    const SME_VECTOR: u32 = 0xc1a8_e000;
    const SVL_BYTES: [usize; 5] = [16, 32, 64, 128, 256];

    fn source(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn profile(length: usize, mode: ScalableMode, features: ScalableFeatures) -> ScalableProfile {
        ScalableProfile::new_with_features(
            VectorLength::from_bytes(length).unwrap(),
            mode,
            features,
            ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
        )
        .unwrap()
    }

    #[test]
    fn recovery_uses_exact_interior_source_pc_and_word() {
        let bytes = source(&[RET, NOP, FADD_SINGLE, SME_VECTOR, SME_MATRIX, RET]);
        let before = bytes.clone();
        for length in SVL_BYTES {
            let profile = ScalableProfile::new(
                VectorLength::from_bytes(length).unwrap(),
                ScalableMode::new(true, true),
            );
            for (index, word) in [(2, FADD_SINGLE), (3, SME_VECTOR), (4, SME_MATRIX)] {
                let pc = GuestAddress(BASE + index * INSTRUCTION_BYTES);
                let proof = validate_scalable_numerical_exit(
                    GuestAddress(BASE + INSTRUCTION_BYTES),
                    pc,
                    bytes.len() - size_of::<u32>(),
                    BASE,
                    &bytes,
                    profile,
                    NumericalFeatures::default(),
                )
                .unwrap();
                assert_eq!(proof.instruction_pc(), pc);
                assert_eq!(proof.next_pc(), GuestAddress(pc.0 + INSTRUCTION_BYTES));
                assert_eq!(proof.word(), word);
                assert_eq!(proof.profile(), profile);
                assert_eq!(proof.numerical_features(), NumericalFeatures::default());
            }
        }
        assert_eq!(bytes, before);
    }

    #[test]
    fn forged_extent_alignment_and_nonnumerical_words_fail_without_source_changes() {
        let bytes = source(&[NOP, FADD_SINGLE, RET]);
        let before = bytes.clone();
        let profile = ScalableProfile::new(
            VectorLength::from_bytes(16).unwrap(),
            ScalableMode::new(true, true),
        );
        for (entry, exit, count, region) in [
            (BASE, BASE - INSTRUCTION_BYTES, 12, BASE),
            (BASE, BASE + 12, 12, BASE),
            (BASE, BASE + 5, 12, BASE),
            (BASE + 1, BASE + INSTRUCTION_BYTES, 12, BASE),
            (BASE, BASE + INSTRUCTION_BYTES, 0, BASE),
            (BASE, BASE + INSTRUCTION_BYTES, 10, BASE),
            (BASE, BASE + INSTRUCTION_BYTES, 16, BASE),
            (BASE, BASE + INSTRUCTION_BYTES, 12, BASE + INSTRUCTION_BYTES),
            (BASE, BASE, 12, BASE),
            (BASE, BASE + 8, 12, BASE),
            (u64::MAX - 3, u64::MAX - 3, 4, u64::MAX - 3),
        ] {
            assert!(
                validate_scalable_numerical_exit(
                    GuestAddress(entry),
                    GuestAddress(exit),
                    count,
                    region,
                    &bytes,
                    profile,
                    NumericalFeatures::default(),
                )
                .is_err()
            );
        }
        assert_eq!(bytes, before);
    }

    #[test]
    fn selected_numerical_admission_requires_exact_streaming_and_matrix_za() {
        let sme = ScalableFeatures::of(Feature::Sme);
        let sme2 = sme.with(Feature::Sme2);
        for length in SVL_BYTES {
            for streaming in [false, true] {
                for za in [false, true] {
                    let profile = profile(length, ScalableMode::new(streaming, za), sme2);
                    for word in [FADD_SINGLE, SME_VECTOR, SME_MATRIX] {
                        let bytes = source(&[word]);
                        let admitted = validate_scalable_numerical_exit(
                            GuestAddress(BASE),
                            GuestAddress(BASE),
                            bytes.len(),
                            BASE,
                            &bytes,
                            profile,
                            NumericalFeatures::default(),
                        );
                        assert_eq!(admitted.is_ok(), streaming && (word != SME_MATRIX || za));
                    }
                }
            }
        }
        for (word, features, numerical_features) in [
            (
                BFADD,
                sme.with(Feature::SveB16B16),
                NumericalFeatures::default(),
            ),
            (
                FADD_SINGLE,
                sme2,
                NumericalFeatures::new(true, false, false),
            ),
        ] {
            let bytes = source(&[word]);
            let before = bytes.clone();
            assert!(
                validate_scalable_numerical_exit(
                    GuestAddress(BASE),
                    GuestAddress(BASE),
                    bytes.len(),
                    BASE,
                    &bytes,
                    profile(16, ScalableMode::new(true, true), features),
                    numerical_features,
                )
                .is_err()
            );
            assert_eq!(bytes, before);
        }
    }
}
