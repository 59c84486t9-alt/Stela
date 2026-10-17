//! The Apple CPU a machine models. Each chip's architectural features are
//! Apple clang's export for it (`isa/apple-codegen-profiles.json`), closed
//! under the AARCHMRS implications by `cargo xtask system-matrix`; the
//! generated accessors decide a feature only some chips have through
//! [`Chip::implemented`].
use super::system::generated::{CHIPS, Feature};

/// An Apple CPU, in the order of the generated per-chip tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Chip {
    AppleM1,
    AppleM2,
    AppleM3,
    AppleM4,
    AppleM5,
    AppleM6,
}

impl Chip {
    pub const ALL: [Chip; 6] = [
        Chip::AppleM1,
        Chip::AppleM2,
        Chip::AppleM3,
        Chip::AppleM4,
        Chip::AppleM5,
        Chip::AppleM6,
    ];

    /// The Mac14,3 (J473AP) M2 Mac mini's chip.
    pub const DEFAULT: Chip = Chip::AppleM2;

    /// Apple clang's `-mcpu` name.
    pub const fn name(self) -> &'static str {
        CHIPS[self as usize]
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|chip| chip.name() == name)
    }

    /// Whether the chip has `feature`: `Ok(false)` without it, `Ok(true)`
    /// when the engine implements it, and the reason to stop when the chip
    /// has a feature the engine does not implement yet.
    pub fn implemented(self, feature: Feature) -> Result<bool, &'static str> {
        if !feature.on(self) {
            Ok(false)
        } else if engine_implements(feature) {
            Ok(true)
        } else {
            Err(feature.unimplemented())
        }
    }
}

/// Whether the engine implements a feature that only some chips have. Every
/// feature the M2 has is implemented as the M2 profile has always decided
/// it; the later chips' additions are not implemented yet.
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
        | Feature::v8Ap6 => true,
        Feature::FEAT_AFP
        | Feature::FEAT_CPA
        | Feature::FEAT_CSSC
        | Feature::FEAT_FAMINMAX
        | Feature::FEAT_FGT2
        | Feature::FEAT_FP8
        | Feature::FEAT_FPACCOMBINE
        | Feature::FEAT_FPMR
        | Feature::FEAT_HBC
        | Feature::FEAT_HCX
        | Feature::FEAT_LUT
        | Feature::FEAT_MTE
        | Feature::FEAT_MTE2
        | Feature::FEAT_NV
        | Feature::FEAT_NV2
        | Feature::FEAT_PAN3
        | Feature::FEAT_PAuth_LR
        | Feature::FEAT_RASv2
        | Feature::FEAT_SCTLR2
        | Feature::FEAT_SME
        | Feature::FEAT_SME2
        | Feature::FEAT_SME2p1
        | Feature::FEAT_SME_B16B16
        | Feature::FEAT_SME_F16F16
        | Feature::FEAT_SME_F64F64
        | Feature::FEAT_SME_F8F16
        | Feature::FEAT_SME_F8F32
        | Feature::FEAT_SME_I16I64
        | Feature::FEAT_SME_LUTv2
        | Feature::FEAT_SPECRES2
        | Feature::FEAT_SVE_B16B16
        | Feature::FEAT_WFxT
        | Feature::FEAT_XS
        | Feature::v8Ap7 => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn chips_follow_the_generated_tables_and_the_m2_implements_all_it_has() {
        for (index, chip) in Chip::ALL.into_iter().enumerate() {
            assert_eq!(chip as usize, index);
            assert_eq!(Chip::from_name(chip.name()), Some(chip));
        }
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../isa/apple-codegen-profiles.json");
        let profiles: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for chip in Chip::ALL {
            assert!(profiles["profiles"][chip.name()].is_object(), "{chip:?}");
        }
        // The default chip implements every feature it has, as before any
        // other chip was modeled; a later chip's addition stops explicitly.
        for feature in Feature::ALL {
            assert_ne!(
                Chip::DEFAULT.implemented(feature),
                Err(feature.unimplemented())
            );
        }
        assert_eq!(Chip::AppleM2.implemented(Feature::FEAT_HCX), Ok(false));
        assert_eq!(
            Chip::AppleM3.implemented(Feature::FEAT_HCX),
            Err("FEAT_HCX of the chip is not implemented")
        );
        assert_eq!(Chip::AppleM1.implemented(Feature::FEAT_FGT), Ok(false));
    }
}
