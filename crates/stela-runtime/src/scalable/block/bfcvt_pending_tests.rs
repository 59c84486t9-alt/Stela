use super::*;
use stela_compiler::{
    aarch64::{
        floating::features::NumericalFeatures,
        scalable::{
            ScalableMode, VectorLength,
            features::{ScalableFeature as Feature, ScalableFeatures},
            profile::ScalableControls,
        },
        sme::fp8_conversion::{
            self, BF1CVT_MZ2_Z8, BF1CVTL_MZ2_Z8, BF2CVT_MZ2_Z8, BF2CVTL_MZ2_Z8, BFCVT_Z8_MZ2,
            Conversion, ElementFormat,
        },
    },
    block::scalable::{
        ScalableNumericalOperation, admit_scalable_numerical_instruction,
        decode_scalable_numerical_instruction,
    },
    extended::ScalableProfile,
};

const BASE: GuestAddress = GuestAddress(0x1000);
const ADD_X5_X5_ONE: u32 = 0x9100_04a5;
const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];

fn profile(bytes: usize) -> ScalableProfile {
    let length = VectorLength::from_bytes(bytes).unwrap();
    ScalableProfile::new_with_features(
        length,
        ScalableMode::new(true, false),
        ScalableFeatures::of(Feature::Sme)
            .with(Feature::Sme2)
            .with(Feature::Fp8)
            .with(Feature::Fpmr),
        ScalableControls::new(length, false).with_fpmr_enabled(true),
    )
    .unwrap()
}

#[test]
fn bfcvt_pending_original_verification_declines_before_executable_preparation() -> Result<()> {
    let operand = fp8_conversion::decode(BFCVT_Z8_MZ2).unwrap();
    assert_eq!(operand.format, ElementFormat::BFloat16);
    assert!(matches!(operand.conversion, Conversion::Narrow { .. }));
    for bytes in LENGTHS {
        let profile = profile(bytes);
        let source: Vec<_> = [ADD_X5_X5_ONE, BFCVT_Z8_MZ2, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let error = PreparedScalableBlock::prepare(
            &source,
            BASE,
            ExtendedBlockProfile::new(
                profile,
                BlockProfile::Ordinary,
                NumericalFeatures::default(),
            ),
            TargetCpu::Baseline,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("unadmitted SME BF16-to-FP8 narrowing"));
        assert!(message.contains("0x1004"));
        // No executable is returned, so no native prefix can be invoked.
        // Guest state is not an input to preparation.

        let mut decoded = decode_scalable_numerical_instruction(BASE, BFCVT_Z8_MZ2)?.unwrap();
        if let ScalableNumericalOperation::SmeFp8Conversion(ref mut operand) = decoded.operation {
            operand.canonical_id = "bf1cvt_mz2_z8_";
        }
        assert!(
            admit_scalable_numerical_instruction(decoded, profile, NumericalFeatures::default())
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn bfloat_fp8_widening_remains_admitted_at_all_streaming_lengths() -> Result<()> {
    for bytes in LENGTHS {
        for word in [BF1CVT_MZ2_Z8, BF1CVTL_MZ2_Z8, BF2CVT_MZ2_Z8, BF2CVTL_MZ2_Z8] {
            let compiled = PreparedScalableBlock::prepare(
                &word.to_le_bytes(),
                BASE,
                ExtendedBlockProfile::new(
                    profile(bytes),
                    BlockProfile::Ordinary,
                    NumericalFeatures::default(),
                ),
                TargetCpu::Baseline,
            )?;
            assert_eq!(compiled.source(), word.to_le_bytes());
            assert_eq!(
                compiled.source_map(),
                &[(BASE, stela_compiler::extended::CONTEXT_WRAPPER_BYTES)]
            );
        }
    }
    Ok(())
}
