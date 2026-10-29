//! Execution support policy for the immutable CPU feature descriptions.
use stela_contracts::{Chip, Feature};

/// Whether the chip has `feature`: `Ok(false)` without it, `Ok(true)`
/// when the engine implements it, and the reason to stop when the chip
/// has a feature the engine does not implement yet.
pub fn implemented(chip: Chip, feature: Feature) -> Result<bool, &'static str> {
    if !feature.on(chip) {
        Ok(false)
    } else if engine_implements(feature) {
        Ok(true)
    } else {
        Err(feature.unimplemented())
    }
}

/// Whether the engine implements a feature that only some chips have: every
/// feature the M2 has; the M3's FEAT_HCX, FEAT_NV and FEAT_NV2; the M4's
/// Armv8.7 (FEAT_AFP, FEAT_PAN3, FEAT_WFxT and FEAT_XS), the activity
/// monitors FEAT_AMUv1 and FEAT_AMUv1p1 (`machine::amu`) and FEAT_SME with
/// FEAT_SME2, FEAT_SME_F64F64 and FEAT_SME_I16I64, whose streaming mode, ZA,
/// ZT0 and instructions the engine runs (`engine::scalable`); the M5's
/// FEAT_SME2p1, FEAT_SME_B16B16, FEAT_SME_F16F16 and FEAT_SVE_B16B16 too,
/// FEAT_SPECRES2, FEAT_MTE and FEAT_MTE2 (Allocation Tags and synchronous
/// Tag Checks) and the instruction-only FEAT_CSSC and FEAT_HBC; and the M6's
/// FEAT_SME_LUTv2, FEAT_FPACCOMBINE, FEAT_FP8 with FEAT_FPMR (the AdvSIMD
/// FP8 conversions), FEAT_CPA (whose arithmetic the engine completes),
/// FEAT_PAuth_LR with FEAT_SCTLR2 (PACM and the two-modifier PAC forms),
/// FEAT_RASv2 with FEAT_FGT2 (the error record group status and its trap) and
/// the instruction-only FEAT_FAMINMAX and FEAT_LUT, whose forms the
/// system-mode compiler admits.
const fn engine_implements(feature: Feature) -> bool {
    match feature {
        Feature::FEAT_AMUv1p1
        | Feature::FEAT_BF16
        | Feature::FEAT_ECV
        | Feature::FEAT_FGT
        | Feature::FEAT_FPAC
        | Feature::FEAT_I8MM
        | Feature::FEAT_PAuth2
        | Feature::FEAT_SSBS
        | Feature::FEAT_SSBS2
        | Feature::v8Ap6
        | Feature::v8Ap7
        | Feature::FEAT_NV
        | Feature::FEAT_NV2
        | Feature::FEAT_HCX
        | Feature::FEAT_AFP
        | Feature::FEAT_CPA
        | Feature::FEAT_CSSC
        | Feature::FEAT_FAMINMAX
        | Feature::FEAT_HBC
        | Feature::FEAT_FPACCOMBINE
        | Feature::FEAT_LUT
        | Feature::FEAT_PAN3
        | Feature::FEAT_PAuth_LR
        | Feature::FEAT_SCTLR2
        | Feature::FEAT_FGT2
        | Feature::FEAT_RASv2
        | Feature::FEAT_SPECRES2
        | Feature::FEAT_WFxT
        | Feature::FEAT_XS
        | Feature::FEAT_SME
        | Feature::FEAT_SME2
        | Feature::FEAT_AMUv1
        | Feature::FEAT_FP8
        | Feature::FEAT_FPMR
        | Feature::FEAT_MTE
        | Feature::FEAT_MTE2
        | Feature::FEAT_SME2p1
        | Feature::FEAT_SME_B16B16
        | Feature::FEAT_SME_F16F16
        | Feature::FEAT_SME_F64F64
        | Feature::FEAT_SME_I16I64
        | Feature::FEAT_SME_LUTv2
        | Feature::FEAT_SVE_B16B16
        | Feature::FEAT_SME_F8F16
        | Feature::FEAT_SME_F8F32 => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chips_are_ordered_and_the_m2_implements_all_it_has() {
        for (index, chip) in Chip::ALL.into_iter().enumerate() {
            assert_eq!(chip as usize, index);
            assert_eq!(Chip::from_name(chip.name()), Some(chip));
        }
        // The default chip implements every feature it has, as before any
        // other chip was modeled; a later chip's addition stops explicitly.
        for feature in Feature::ALL {
            assert_ne!(
                implemented(Chip::DEFAULT, feature),
                Err(feature.unimplemented())
            );
        }
        assert_eq!(implemented(Chip::AppleM2, Feature::FEAT_HCX), Ok(false));
        assert_eq!(implemented(Chip::AppleM3, Feature::FEAT_HCX), Ok(true));
        assert_eq!(implemented(Chip::AppleM4, Feature::FEAT_SME), Ok(true));
        assert_eq!(implemented(Chip::AppleM4, Feature::FEAT_MTE2), Ok(false));
        assert_eq!(implemented(Chip::AppleM5, Feature::FEAT_MTE2), Ok(true));
        assert_eq!(implemented(Chip::AppleM1, Feature::FEAT_FGT), Ok(false));
    }
}
