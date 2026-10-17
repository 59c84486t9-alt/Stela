//! The Apple CPU a machine models. Each chip's architectural features are
//! Apple clang's export for it (`isa/apple-codegen-profiles.json`), closed
//! under the AARCHMRS implications by `cargo xtask system-matrix`; the
//! generated accessors decide a feature only some chips have through
//! [`Chip::implemented`], and [`Chip::admit`] makes an instruction form the
//! chip lacks UNDEFINED (or a NOP, where Arm decodes it so).
use super::system::generated::{CAPS, CHIPS, Feature};

#[rustfmt::skip]
mod forms;

/// One A64 form some chips lack (`forms::ABSENT`).
struct AbsentForm {
    value: u32,
    /// Bit `n` set when chip `n` lacks the form.
    chips: u8,
    /// Arm decodes the form as NOP, not UNDEFINED, without its feature.
    nop: bool,
    /// (mask, value, chips): forms those chips have that keep their words.
    unless: &'static [(u32, u32, u8)],
}

/// The absent forms of one encoding mask, sorted by value.
struct AbsentGroup {
    mask: u32,
    forms: &'static [AbsentForm],
}

/// `UDF #0`: an absent form's word is UNDEFINED as UDF is (EC 0x00, ISS 0).
const UDF: u32 = 0;
const NOP: u32 = 0xd503_201f;

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

    /// Apple clang's architectural features for the chip
    /// (`isa/apple-codegen-profiles.json`), the cap of what it advertises.
    pub fn cap(self) -> &'static [&'static str] {
        CAPS[self as usize]
    }

    /// The word the chip executes for `word`: the word itself, `UDF #0` for a
    /// form the chip lacks, or NOP for an absent form Arm decodes as NOP.
    pub fn admit(self, word: u32) -> u32 {
        let bit = 1u8 << self as u8;
        for group in forms::ABSENT {
            let Ok(index) = group
                .forms
                .binary_search_by_key(&(word & group.mask), |form| form.value)
            else {
                continue;
            };
            let form = &group.forms[index];
            let kept = form
                .unless
                .iter()
                .any(|(mask, value, chips)| chips & bit != 0 && word & mask == *value);
            if form.chips & bit != 0 && !kept {
                return if form.nop { NOP } else { UDF };
            }
        }
        word
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

/// Whether the engine implements a feature that only some chips have: every
/// feature the M2 has; the M3's FEAT_HCX, FEAT_NV and FEAT_NV2; the M4's
/// Armv8.7 (FEAT_AFP, FEAT_PAN3, FEAT_WFxT and FEAT_XS); the M5's
/// FEAT_SPECRES2 and the instruction-only FEAT_CSSC and FEAT_HBC; and the M6's
/// FEAT_FPACCOMBINE, FEAT_CPA (whose arithmetic the engine completes) and the
/// instruction-only FEAT_FAMINMAX and FEAT_LUT, whose forms the system-mode
/// compiler admits.
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
        | Feature::FEAT_SPECRES2
        | Feature::FEAT_WFxT
        | Feature::FEAT_XS => true,
        Feature::FEAT_FGT2
        | Feature::FEAT_FP8
        | Feature::FEAT_FPMR
        | Feature::FEAT_MTE
        | Feature::FEAT_MTE2
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
        | Feature::FEAT_SVE_B16B16 => false,
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
            let cap: Vec<&str> = profiles["profiles"][chip.name()]["architectural_features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap())
                .collect();
            assert_eq!(chip.cap(), cap, "{chip:?}");
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
        assert_eq!(Chip::AppleM3.implemented(Feature::FEAT_HCX), Ok(true));
        assert_eq!(
            Chip::AppleM4.implemented(Feature::FEAT_SME),
            Err("FEAT_SME of the chip is not implemented")
        );
        assert_eq!(Chip::AppleM1.implemented(Feature::FEAT_FGT), Ok(false));
    }

    #[test]
    fn a_form_the_chip_lacks_is_undefined_or_its_nop() {
        // bfcvt h0, s1 (FEAT_BF16, from the M2) and abs x0, x1 (FEAT_CSSC,
        // from the M5).
        for (word, first) in [(0x1e63_4020, Chip::AppleM2), (0xdac0_2020, Chip::AppleM5)] {
            for chip in Chip::ALL {
                let expected = if chip < first { UDF } else { word };
                assert_eq!(chip.admit(word), expected, "{word:#x} {chip:?}");
            }
        }
        // PACM (FEAT_PAuth_LR, M6) is a NOP without its feature, as Arm
        // decodes it, though the HINT space it sits in is on every chip.
        assert_eq!(Chip::AppleM2.admit(0xd503_24ff), NOP);
        assert_eq!(Chip::AppleM6.admit(0xd503_24ff), 0xd503_24ff);
        // RETAASPPCR (FEAT_PAuth_LR) is UNDEFINED before the M6, except for
        // the RETAA encoding it overlaps.
        assert_eq!(Chip::AppleM2.admit(0xd65f_0be2), UDF);
        assert_eq!(Chip::AppleM2.admit(0xd65f_0bff), 0xd65f_0bff);
        // Forms every chip has, and words no form claims, pass unchanged.
        for word in [0x8b02_0020, 0xd503_201f, 0xd503_3f9f, 0x0020_1420] {
            for chip in Chip::ALL {
                assert_eq!(chip.admit(word), word, "{word:#x} {chip:?}");
            }
        }
    }
}
