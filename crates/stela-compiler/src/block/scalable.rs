//! Scalable numerical instructions that exit to a runtime service.
use crate::aarch64::Unsupported;

use crate::{
    CompileError, GuestAddress,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::features::{FeatureRequirement, ScalableFeature, ScalableFeatures},
        simd::fp8_conversion as fixed_fp8_conversion,
        sme::{extrema_scale, fp_matrix, fp_vector, fp8_conversion, fp8_matrix},
        sve::floating,
    },
    extended::ScalableProfile,
};
use alloc::format;

const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalableNumericalOperation {
    Sve(floating::Operation),
    FixedFp8Conversion(fixed_fp8_conversion::Operand),
    SmeFp8Conversion(fp8_conversion::Operand),
    SmeFp8Matrix(fp8_matrix::Operand),
    SmeExtremaScale(extrema_scale::Operand),
    SmeVector(fp_vector::Operand),
    SmeMatrix(fp_matrix::Operand),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalableNumericalInstruction {
    pub operation: ScalableNumericalOperation,
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
    pub word: u32,
}

/// A numerical exit admitted under a streaming profile. At completion the
/// runtime re-reads the source word and checks the live state against this
/// profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedScalableNumericalInstruction {
    instruction: ScalableNumericalInstruction,
    profile: ScalableProfile,
    numerical_features: NumericalFeatures,
}

impl AdmittedScalableNumericalInstruction {
    pub const fn operation(&self) -> &ScalableNumericalOperation {
        &self.instruction.operation
    }

    pub const fn profile(self) -> ScalableProfile {
        self.profile
    }
    pub const fn numerical_features(self) -> NumericalFeatures {
        self.numerical_features
    }
    pub const fn instruction_pc(self) -> GuestAddress {
        self.instruction.instruction_pc
    }
    pub const fn next_pc(self) -> GuestAddress {
        self.instruction.next_pc
    }
    pub const fn word(self) -> u32 {
        self.instruction.word
    }
}

impl ScalableNumericalOperation {
    /// This profile declares SME-derived streaming execution, with no ordinary
    /// FEAT_SVE availability. General normal-SVE alternatives are not implied.
    pub fn required_streaming_features(
        self,
        numerical_features: NumericalFeatures,
    ) -> FeatureRequirement {
        use ScalableFeature as Feature;
        let sme = ScalableFeatures::of(Feature::Sme);
        let sme2 = sme.with(Feature::Sme2);
        match self {
            Self::Sve(operation) => operation.required_streaming_features(numerical_features),
            Self::SmeExtremaScale(operand) => {
                FeatureRequirement::all(sme2.with(match operand.kind {
                    extrema_scale::Kind::AbsoluteMinMax(_) => Feature::FaMinMax,
                    extrema_scale::Kind::Scale => Feature::Fp8,
                }))
            }
            Self::FixedFp8Conversion(_) => {
                FeatureRequirement::all(ScalableFeatures::of(Feature::Fp8).with(Feature::Fpmr))
            }
            Self::SmeFp8Conversion(_) => {
                FeatureRequirement::all(sme2.with(Feature::Fp8).with(Feature::Fpmr))
            }
            Self::SmeFp8Matrix(operand) => {
                let accumulator = match operand {
                    fp8_matrix::Operand::Vector(operand) => operand.accumulator,
                    fp8_matrix::Operand::Outer(operand) => operand.accumulator,
                };
                let feature = match accumulator {
                    Format::Half => Feature::SmeF8F16,
                    Format::Single => Feature::SmeF8F32,
                    Format::Double => unreachable!("FP8 matrix decoder allocates Half and Single"),
                };
                FeatureRequirement::all(sme.with(feature).with(Feature::Fpmr))
            }
            Self::SmeVector(operand) => FeatureRequirement::all(match operand.feature {
                fp_vector::Feature::Sme2 => sme2,
                fp_vector::Feature::Sme2SveB16B16 => sme2.with(Feature::SveB16B16),
                fp_vector::Feature::SmeF16F16 => sme.with(Feature::SmeF16F16),
            }),
            Self::SmeMatrix(operand) => match operand.required_feature() {
                fp_matrix::RequiredFeature::Sme => FeatureRequirement::all(sme),
                fp_matrix::RequiredFeature::Sme2 => FeatureRequirement::all(sme2),
                fp_matrix::RequiredFeature::F16F16 => {
                    FeatureRequirement::all(sme.with(Feature::SmeF16F16))
                }
                fp_matrix::RequiredFeature::F64F64 => {
                    FeatureRequirement::all(sme.with(Feature::SmeF64F64))
                }
                fp_matrix::RequiredFeature::B16B16 => {
                    FeatureRequirement::all(sme.with(Feature::SmeB16B16))
                }
                fp_matrix::RequiredFeature::F16F16OrF8F16 => FeatureRequirement::all_and_any(
                    sme,
                    ScalableFeatures::of(Feature::SmeF16F16).with(Feature::SmeF8F16),
                ),
                fp_matrix::RequiredFeature::Sme2AndF64F64 => {
                    FeatureRequirement::all(sme2.with(Feature::SmeF64F64))
                }
            },
        }
    }
}

/// Validate decoded metadata rather than trusting an independently constructed
/// operand. No permission is inferred from opcode allocation or host features.
pub fn admit_scalable_numerical_instruction(
    instruction: ScalableNumericalInstruction,
    profile: ScalableProfile,
    numerical_features: NumericalFeatures,
) -> Result<AdmittedScalableNumericalInstruction, CompileError> {
    if decode_scalable_numerical_instruction(instruction.instruction_pc, instruction.word)?
        != Some(instruction)
    {
        return Err(CompileError(
            "scalable numerical source/descriptor mismatch".into(),
        ));
    }
    if matches!(
        instruction.operation,
        ScalableNumericalOperation::FixedFp8Conversion(_)
            | ScalableNumericalOperation::SmeFp8Conversion(_)
            | ScalableNumericalOperation::Sve(floating::Operation::Fp8(_))
            | ScalableNumericalOperation::SmeFp8Matrix(_)
    ) && !profile.controls().fpmr_enabled()
    {
        return Err(CompileError(
            "indirect FPMR access is not enabled in the declared guest profile".into(),
        ));
    }
    let mode = profile.mode();
    let fixed = matches!(
        instruction.operation,
        ScalableNumericalOperation::FixedFp8Conversion(_)
    );
    if (if fixed {
        mode.streaming() && !numerical_features.full_a64()
    } else {
        !mode.streaming()
    }) || (matches!(
        instruction.operation,
        ScalableNumericalOperation::SmeMatrix(_) | ScalableNumericalOperation::SmeFp8Matrix(_)
    ) && !mode.za_enabled())
    {
        return Err(CompileError(format!(
            "scalable numerical mode unavailable at {:#x}",
            instruction.instruction_pc.0
        )));
    }
    if numerical_features.full_a64() && !profile.features().contains(ScalableFeature::SmeFa64) {
        return Err(CompileError(
            "effective FullA64 requires declared FEAT_SME_FA64".into(),
        ));
    }
    profile.require_features(
        instruction
            .operation
            .required_streaming_features(numerical_features),
        instruction.instruction_pc,
    )?;
    Ok(AdmittedScalableNumericalInstruction {
        instruction,
        profile,
        numerical_features,
    })
}

/// A numerical exit identifies the still-unexecuted instruction, including an
/// interior slow path. The runtime must re-fetch this word from registered
/// immutable source before completing its effects and advancing to next_pc.
pub fn decode_scalable_numerical_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<ScalableNumericalInstruction>, CompileError> {
    if !pc.0.is_multiple_of(INSTRUCTION_BYTES) {
        return Err(CompileError(
            "scalable numerical PC must be aligned to 4 bytes".into(),
        ));
    }
    let operation = if let Some(operand) = fixed_fp8_conversion::decode(word) {
        ScalableNumericalOperation::FixedFp8Conversion(operand)
    } else if let Some(operand) = fp8_conversion::decode(word) {
        ScalableNumericalOperation::SmeFp8Conversion(operand)
    } else if let Some(operand) = fp8_matrix::decode(word) {
        ScalableNumericalOperation::SmeFp8Matrix(operand)
    } else if let Some(operand) = extrema_scale::decode(word) {
        ScalableNumericalOperation::SmeExtremaScale(operand)
    } else if let Some(result) = floating::Operation::decode(word) {
        let operand = result
            .map_err(|Unsupported| CompileError("reserved scalable numerical encoding".into()))?;
        if !operand.requires_numerical_completion() {
            return Ok(None);
        }
        ScalableNumericalOperation::Sve(operand)
    } else if let Some(operand) = fp_vector::decode(word) {
        ScalableNumericalOperation::SmeVector(operand)
    } else if let Some(operand) = fp_matrix::decode(word) {
        ScalableNumericalOperation::SmeMatrix(operand)
    } else {
        return Ok(None);
    };
    let next_pc = GuestAddress(
        pc.0.checked_add(INSTRUCTION_BYTES)
            .ok_or_else(|| CompileError("scalable numerical continuation overflow".into()))?,
    );
    Ok(Some(ScalableNumericalInstruction {
        operation,
        instruction_pc: pc,
        next_pc,
        word,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod fp8_matrix_scope {
        //! SME FP8 matrix and conversion admission.
        use super::*;
        use crate::{
            TargetCpu,
            aarch64::scalable::{ScalableMode, VectorLength, profile::ScalableControls},
            block::BlockProfile,
            extended::block::{ExtendedBlockProfile, compile_for_profile},
        };

        const PC: GuestAddress = GuestAddress(0x1000);
        const BFCVT_WORD: u32 = crate::aarch64::sme::fp8_conversion::BFCVT_Z8_MZ2;
        const BFCVT_HIGH_OPERANDS: u32 = (30 << 5) | 31;
        const NOP_WORD: u32 = 0xd503_201f;
        // Each form: name, lowest-operand encoding, highest-operand encoding.
        const PUBLIC_FORMS: &[(&str, u32, u32)] = &[
            ("fdot_za_z8z8i_2xi", 0xc1d00020, 0xc1df6fef),
            ("fdot_za_z8z8i_4xi", 0xc1109040, 0xc11fffcf),
            ("fdot_za_z8z8v_2x1", 0xc1201008, 0xc12f73ef),
            ("fdot_za_z8z8v_4x1", 0xc1301008, 0xc13f73ef),
            ("fdot_za_z8z8w_2x2", 0xc1a01020, 0xc1be73e7),
            ("fdot_za_z8z8w_4x4", 0xc1a11020, 0xc1bd73a7),
            ("fmlal_za_z8z8i_1", 0xc1c00000, 0xc1cfefef),
            ("fmlal_za_z8z8i_2xi", 0xc1901030, 0xc19f7fff),
            ("fmlal_za_z8z8i_4xi", 0xc1909020, 0xc19fffaf),
            ("fmlal_za_z8z8v_1", 0xc1300c00, 0xc13f6fe7),
            ("fmlal_za_z8z8v_2x1", 0xc1200804, 0xc12f6be7),
            ("fmlal_za_z8z8v_4x1", 0xc1300804, 0xc13f6be7),
            ("fmlal_za_z8z8w_2x2", 0xc1a00820, 0xc1be6be3),
            ("fmlal_za_z8z8w_4x4", 0xc1a10820, 0xc1bd6ba3),
            ("fmopa_za16_pp_z8z8_8", 0x80a00008, 0x80bfffe9),
            ("fmopa_za32_pp_z8z8_8", 0x80a00000, 0x80bfffe3),
            ("fmlall_za32_z8z8i_1", 0xc1400000, 0xc14fffe3),
            ("fmlall_za32_z8z8i_2xi", 0xc1900020, 0xc19f6fe7),
            ("fmlall_za32_z8z8i_4xi", 0xc1108040, 0xc11fefc7),
            ("fmlall_za32_z8z8v_1", 0xc1300400, 0xc13f67e3),
            ("fmlall_za32_z8z8v_2x1", 0xc1200002, 0xc12f63e3),
            ("fmlall_za32_z8z8v_4x1", 0xc1300002, 0xc13f63e3),
            ("fmlall_za32_z8z8w_2x2", 0xc1a00020, 0xc1be63e1),
            ("fmlall_za32_z8z8w_4x4", 0xc1a10020, 0xc1bd63a1),
            ("fdot_za32_z8z8i_2xi", 0xc1500038, 0xc15f6fff),
            ("fdot_za32_z8z8i_4xi", 0xc1508008, 0xc15fef8f),
            ("fdot_za32_z8z8v_2x1", 0xc1201018, 0xc12f73ff),
            ("fdot_za32_z8z8v_4x1", 0xc1301018, 0xc13f73ff),
            ("fdot_za32_z8z8w_2x2", 0xc1a01030, 0xc1be73f7),
            ("fdot_za32_z8z8w_4x4", 0xc1a11030, 0xc1bd73b7),
        ];
        const VERTICAL_FORMS: &[(&str, u32, u32)] = &[
            ("fvdotb_za32_z8z8i_2xi", 0xc1d00800, 0xc1df6fcf),
            ("fvdott_za32_z8z8i_2xi", 0xc1d00810, 0xc1df6fdf),
            ("fvdot_za_z8z8i_2xi", 0xc1d01020, 0xc1df7fef),
        ];

        fn declared_profile(length: usize, available: bool, streaming: bool) -> ScalableProfile {
            let features = if available {
                ScalableFeatures::checked_from_names([
                    "FEAT_SME",
                    "FEAT_SME2",
                    "FEAT_FPMR",
                    "FEAT_FP8",
                    "FEAT_SME_F8F16",
                    "FEAT_SME_F8F32",
                ])
                .unwrap()
            } else {
                ScalableFeatures::of(ScalableFeature::Sme)
            };
            ScalableProfile::new_with_features(
                VectorLength::from_bytes(length).unwrap(),
                ScalableMode::new(streaming, streaming),
                features,
                ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false)
                    .with_fpmr_enabled(available),
            )
            .unwrap()
        }

        #[test]
        fn public_thirty_forms_admit_and_emit_exact_source() {
            assert_eq!(PUBLIC_FORMS.len(), 30);
            let profile = declared_profile(64, true, true);
            let numerical = NumericalFeatures::default();
            for &(id, low, high) in PUBLIC_FORMS {
                for word in [low, high] {
                    let decoded = decode_scalable_numerical_instruction(PC, word)
                        .unwrap()
                        .unwrap();
                    assert!(
                        matches!(
                            decoded.operation,
                            ScalableNumericalOperation::SmeFp8Matrix(_)
                        ),
                        "{id}"
                    );
                    let admitted =
                        admit_scalable_numerical_instruction(decoded, profile, numerical).unwrap();
                    assert_eq!(admitted.word(), word);
                    assert_eq!(admitted.next_pc(), GuestAddress(0x1004));
                    let compiled = compile_for_profile(
                        &word.to_le_bytes(),
                        PC,
                        ExtendedBlockProfile::new(profile, BlockProfile::Ordinary, numerical),
                        TargetCpu::Baseline,
                    )
                    .unwrap();
                    assert_eq!(compiled.source_bytes, size_of::<u32>(), "{id}");
                    assert_eq!(compiled.native.source_map.len(), 1, "{id}");
                    assert_eq!(compiled.native.source_map[0].0, PC, "{id}");
                    assert!(!compiled.native.x86_64_code.is_empty(), "{id}");
                }
            }
        }

        #[test]
        fn newly_reviewed_forms_admit_at_every_streaming_length() {
            for length in [16, 32, 64, 128, 256] {
                let profile = declared_profile(length, true, true);
                for (id, low, high) in VERTICAL_FORMS.iter().copied().chain([(
                    "bfcvt_z8_mz2_",
                    BFCVT_WORD,
                    BFCVT_WORD | BFCVT_HIGH_OPERANDS,
                )]) {
                    for word in [low, high] {
                        let decoded = decode_scalable_numerical_instruction(PC, word)
                            .unwrap()
                            .unwrap();
                        let admitted = admit_scalable_numerical_instruction(
                            decoded,
                            profile,
                            NumericalFeatures::default(),
                        )
                        .unwrap();
                        assert_eq!(admitted.word(), word, "{id}");
                        assert_eq!(admitted.next_pc(), GuestAddress(0x1004), "{id}");
                        let compiled = compile_for_profile(
                            &word.to_le_bytes(),
                            PC,
                            ExtendedBlockProfile::new(
                                profile,
                                BlockProfile::Ordinary,
                                NumericalFeatures::default(),
                            ),
                            TargetCpu::Baseline,
                        )
                        .unwrap();
                        assert_eq!(compiled.source_bytes, size_of::<u32>(), "{id}");
                        assert_eq!(compiled.native.source_map.len(), 1, "{id}");
                        assert_eq!(compiled.native.source_map[0].0, PC, "{id}");
                        assert!(!compiled.native.x86_64_code.is_empty(), "{id}");
                    }
                }
            }
        }

        #[test]
        fn newly_reviewed_forms_keep_fpmr_and_streaming_requirements() {
            for (_, word, _) in
                VERTICAL_FORMS
                    .iter()
                    .copied()
                    .chain([("bfcvt_z8_mz2_", BFCVT_WORD, BFCVT_WORD)])
            {
                let decoded = decode_scalable_numerical_instruction(PC, word)
                    .unwrap()
                    .unwrap();
                for (available, streaming, message) in [
                    (false, true, "FPMR access"),
                    (true, false, "mode unavailable"),
                ] {
                    let error = admit_scalable_numerical_instruction(
                        decoded,
                        declared_profile(16, available, streaming),
                        NumericalFeatures::default(),
                    )
                    .unwrap_err();
                    assert!(error.0.contains(message), "{error}");
                }
            }
        }

        #[test]
        fn source_descriptor_mismatch_precedes_profile_checks() {
            let word = VERTICAL_FORMS[0].1;
            let mut decoded = decode_scalable_numerical_instruction(PC, word)
                .unwrap()
                .unwrap();
            decoded.word = NOP_WORD;
            let error = admit_scalable_numerical_instruction(
                decoded,
                declared_profile(16, false, false),
                NumericalFeatures::default(),
            )
            .unwrap_err();
            assert!(error.0.contains("source/descriptor mismatch"));
        }

        #[test]
        fn supported_forms_retain_fpmr_and_za_access_requirements() {
            let word = PUBLIC_FORMS[0].1;
            let decoded = decode_scalable_numerical_instruction(PC, word)
                .unwrap()
                .unwrap();
            let error = admit_scalable_numerical_instruction(
                decoded,
                declared_profile(16, false, true),
                NumericalFeatures::default(),
            )
            .unwrap_err();
            assert!(error.0.contains("FPMR access"));
            let error = admit_scalable_numerical_instruction(
                decoded,
                declared_profile(16, true, false),
                NumericalFeatures::default(),
            )
            .unwrap_err();
            assert!(error.0.contains("mode unavailable"));
        }

        #[test]
        fn conversion_needs_streaming_but_vertical_dot_also_needs_za() {
            let original = declared_profile(16, true, true);
            let streaming_without_za = ScalableProfile::new_with_features(
                original.vector_length(),
                ScalableMode::new(true, false),
                original.features(),
                original.controls(),
            )
            .unwrap();
            let conversion = decode_scalable_numerical_instruction(PC, BFCVT_WORD)
                .unwrap()
                .unwrap();
            assert!(
                admit_scalable_numerical_instruction(
                    conversion,
                    streaming_without_za,
                    NumericalFeatures::default(),
                )
                .is_ok()
            );
            for &(_, word, _) in VERTICAL_FORMS {
                let decoded = decode_scalable_numerical_instruction(PC, word)
                    .unwrap()
                    .unwrap();
                assert!(
                    admit_scalable_numerical_instruction(
                        decoded,
                        streaming_without_za,
                        NumericalFeatures::default(),
                    )
                    .is_err()
                );
            }
        }
    }
    mod numerical22_scope {
        use super::*;

        // Canonical words retained from the exact June feature-facts ledger.
        const CANONICAL: &[(&str, u32, bool)] = &[
            ("fabd_z_p_zz_", 0x65488040, true),
            ("fabs_z_p_z_m", 0x045ca020, false),
            ("fadd_z_p_zs_", 0x65588000, true),
            ("fadd_z_p_zz_", 0x65408040, true),
            ("fadd_z_zz_", 0x65420020, true),
            ("faddp_z_p_zz_", 0x64508040, true),
            ("faddqv_z_p_z_", 0x6450a020, true),
            ("faddv_v_p_z_", 0x65402020, true),
            ("fcadd_z_p_zz_", 0x64408040, true),
            ("fclamp_z_zz_", 0x64622420, true),
            ("fcmla_z_p_zzz_", 0x64420020, true),
            ("fcmla_z_zzzi_h", 0x64a21020, true),
            ("fcmla_z_zzzi_s", 0x64e21020, true),
            ("fdiv_z_p_zz_", 0x654d8040, true),
            ("fdivr_z_p_zz_", 0x654c8040, true),
            ("flogb_z_p_z_m", 0x651aa020, true),
            ("fmad_z_p_zzz_", 0x65638040, true),
            ("fmax_z_p_zs_", 0x655e8000, true),
            ("fmax_z_p_zz_", 0x65468040, true),
            ("fmaxnm_z_p_zs_", 0x655c8000, true),
            ("fmaxnm_z_p_zz_", 0x65448040, true),
            ("fmaxnmp_z_p_zz_", 0x64548040, true),
            ("fmaxnmqv_z_p_z_", 0x6454a020, true),
            ("fmaxnmv_v_p_z_", 0x65442020, true),
            ("fmaxp_z_p_zz_", 0x64568040, true),
            ("fmaxqv_z_p_z_", 0x6456a020, true),
            ("fmaxv_v_p_z_", 0x65462020, true),
            ("fmin_z_p_zs_", 0x655f8000, true),
            ("fmin_z_p_zz_", 0x65478040, true),
            ("fminnm_z_p_zs_", 0x655d8000, true),
            ("fminnm_z_p_zz_", 0x65458040, true),
            ("fminnmp_z_p_zz_", 0x64558040, true),
            ("fminnmqv_z_p_z_", 0x6455a020, true),
            ("fminnmv_v_p_z_", 0x65452020, true),
            ("fminp_z_p_zz_", 0x64578040, true),
            ("fminqv_z_p_z_", 0x6457a020, true),
            ("fminv_v_p_z_", 0x65472020, true),
            ("fmla_z_p_zzz_", 0x65620020, true),
            ("fmla_z_zzzi_d", 0x64e20020, true),
            ("fmla_z_zzzi_h", 0x64220020, true),
            ("fmla_z_zzzi_s", 0x64a20020, true),
            ("fmls_z_p_zzz_", 0x65622020, true),
            ("fmls_z_zzzi_d", 0x64e20420, true),
            ("fmls_z_zzzi_h", 0x64220420, true),
            ("fmls_z_zzzi_s", 0x64a20420, true),
            ("fmsb_z_p_zzz_", 0x6563a040, true),
            ("fmul_z_p_zs_", 0x655a8000, true),
            ("fmul_z_p_zz_", 0x65428040, true),
            ("fmul_z_zz_", 0x65420820, true),
            ("fmul_z_zzi_d", 0x64e22020, true),
            ("fmul_z_zzi_h", 0x64222020, true),
            ("fmul_z_zzi_s", 0x64a22020, true),
            ("fmulx_z_p_zz_", 0x654a8040, true),
            ("fneg_z_p_z_m", 0x045da020, false),
            ("fnmad_z_p_zzz_", 0x6563c040, true),
            ("fnmla_z_p_zzz_", 0x65624020, true),
            ("fnmls_z_p_zzz_", 0x65626020, true),
            ("fnmsb_z_p_zzz_", 0x6563e040, true),
            ("frecpe_z_z_", 0x654e3020, true),
            ("frecps_z_zz_", 0x65421820, true),
            ("frecpx_z_p_z_m", 0x654ca020, true),
            ("frsqrte_z_z_", 0x654f3020, true),
            ("frsqrts_z_zz_", 0x65421c20, true),
            ("fscale_z_p_zz_", 0x65498040, true),
            ("fsqrt_z_p_z_m", 0x654da020, true),
            ("fsub_z_p_zs_", 0x65598000, true),
            ("fsub_z_p_zz_", 0x65418040, true),
            ("fsub_z_zz_", 0x65420420, true),
            ("fsubr_z_p_zs_", 0x655b8000, true),
            ("fsubr_z_p_zz_", 0x65438040, true),
            ("urecpe_z_p_z_m", 0x4480a020, true),
            ("ursqrte_z_p_z_m", 0x4481a020, true),
            ("bfcvt_z_p_z_s2bf", 0x658aa000, true),
            ("bfcvtnt_z_p_z_s2bf", 0x648aa000, true),
            ("facge_p_p_zz_", 0x6580c010, true),
            ("facgt_p_p_zz_", 0x6580e010, true),
            ("fcmeq_p_p_z0_", 0x65922000, true),
            ("fcmeq_p_p_zz_", 0x65806000, true),
            ("fcmge_p_p_z0_", 0x65902000, true),
            ("fcmge_p_p_zz_", 0x65804000, true),
            ("fcmgt_p_p_z0_", 0x65902010, true),
            ("fcmgt_p_p_zz_", 0x65804010, true),
            ("fcmle_p_p_z0_", 0x65912010, true),
            ("fcmlt_p_p_z0_", 0x65912000, true),
            ("fcmne_p_p_z0_", 0x65932000, true),
            ("fcmne_p_p_zz_", 0x65806010, true),
            ("fcmuo_p_p_zz_", 0x6580c000, true),
            ("fcvt_z_p_z_d2h", 0x65c8a000, true),
            ("fcvt_z_p_z_d2s", 0x65caa000, true),
            ("fcvt_z_p_z_h2d", 0x65c9a000, true),
            ("fcvt_z_p_z_h2s", 0x6589a000, true),
            ("fcvt_z_p_z_s2d", 0x65cba000, true),
            ("fcvt_z_p_z_s2h", 0x6588a000, true),
            ("fcvtlt_z_p_z_h2s", 0x6489a000, true),
            ("fcvtlt_z_p_z_s2d", 0x64cba000, true),
            ("fcvtnt_z_p_z_d2s", 0x64caa000, true),
            ("fcvtnt_z_p_z_s2h", 0x6488a000, true),
            ("fcvtx_z_p_z_d2s", 0x650aa000, true),
            ("fcvtxnt_z_p_z_d2s", 0x640aa000, true),
            ("fcvtzs_z_p_z_d2w", 0x65d8a000, true),
            ("fcvtzs_z_p_z_d2x", 0x65dea000, true),
            ("fcvtzs_z_p_z_fp162h", 0x655aa000, true),
            ("fcvtzs_z_p_z_fp162w", 0x655ca000, true),
            ("fcvtzs_z_p_z_fp162x", 0x655ea000, true),
            ("fcvtzs_z_p_z_s2w", 0x659ca000, true),
            ("fcvtzs_z_p_z_s2x", 0x65dca000, true),
            ("fcvtzu_z_p_z_d2w", 0x65d9a000, true),
            ("fcvtzu_z_p_z_d2x", 0x65dfa000, true),
            ("fcvtzu_z_p_z_fp162h", 0x655ba000, true),
            ("fcvtzu_z_p_z_fp162w", 0x655da000, true),
            ("fcvtzu_z_p_z_fp162x", 0x655fa000, true),
            ("fcvtzu_z_p_z_s2w", 0x659da000, true),
            ("fcvtzu_z_p_z_s2x", 0x65dda000, true),
            ("frinta_z_p_z_m", 0x6584a000, true),
            ("frinti_z_p_z_m", 0x6587a000, true),
            ("frintm_z_p_z_m", 0x6582a000, true),
            ("frintn_z_p_z_m", 0x6580a000, true),
            ("frintp_z_p_z_m", 0x6581a000, true),
            ("frintx_z_p_z_m", 0x6586a000, true),
            ("frintz_z_p_z_m", 0x6583a000, true),
            ("scvtf_z_p_z_h2fp16", 0x6552a000, true),
            ("scvtf_z_p_z_w2d", 0x65d0a000, true),
            ("scvtf_z_p_z_w2fp16", 0x6554a000, true),
            ("scvtf_z_p_z_w2s", 0x6594a000, true),
            ("scvtf_z_p_z_x2d", 0x65d6a000, true),
            ("scvtf_z_p_z_x2fp16", 0x6556a000, true),
            ("scvtf_z_p_z_x2s", 0x65d4a000, true),
            ("ucvtf_z_p_z_h2fp16", 0x6553a000, true),
            ("ucvtf_z_p_z_w2d", 0x65d1a000, true),
            ("ucvtf_z_p_z_w2fp16", 0x6555a000, true),
            ("ucvtf_z_p_z_w2s", 0x6595a000, true),
            ("ucvtf_z_p_z_x2d", 0x65d7a000, true),
            ("ucvtf_z_p_z_x2fp16", 0x6557a000, true),
            ("ucvtf_z_p_z_x2s", 0x65d5a000, true),
            ("fcpy_z_p_i_", 0x0590c000, false),
            ("fdup_z_i_", 0x25b9c000, false),
            ("bfadd_z_p_zz_", 0x65008000, true),
            ("bfadd_z_zz_", 0x65000000, true),
            ("bfclamp_z_zz_", 0x64202400, true),
            ("bfdot_z_zzz_", 0x64608000, true),
            ("bfdot_z_zzzi_", 0x64604000, true),
            ("bfmax_z_p_zz_", 0x65068000, true),
            ("bfmaxnm_z_p_zz_", 0x65048000, true),
            ("bfmin_z_p_zz_", 0x65078000, true),
            ("bfminnm_z_p_zz_", 0x65058000, true),
            ("bfmla_z_p_zzz_", 0x65200000, true),
            ("bfmla_z_zzzi_h", 0x64200800, true),
            ("bfmlalb_z_zzz_", 0x64e08000, true),
            ("bfmlalb_z_zzzi_", 0x64e04000, true),
            ("bfmlalt_z_zzz_", 0x64e08400, true),
            ("bfmlalt_z_zzzi_", 0x64e04400, true),
            ("bfmls_z_p_zzz_", 0x65202000, true),
            ("bfmls_z_zzzi_h", 0x64200c00, true),
            ("bfmlslb_z_zzz_", 0x64e0a000, true),
            ("bfmlslb_z_zzzi_", 0x64e06000, true),
            ("bfmlslt_z_zzz_", 0x64e0a400, true),
            ("bfmlslt_z_zzzi_", 0x64e06400, true),
            ("bfmul_z_p_zz_", 0x65028000, true),
            ("bfmul_z_zz_", 0x65000800, true),
            ("bfmul_z_zzi_h", 0x64202800, true),
            ("bfsub_z_p_zz_", 0x65018000, true),
            ("bfsub_z_zz_", 0x65000400, true),
            ("fdot_z_zzz_", 0x64208000, true),
            ("fdot_z_zzzi_", 0x64204000, true),
            ("fmlalb_z_zzz_", 0x64a08000, true),
            ("fmlalb_z_zzzi_s", 0x64a04000, true),
            ("fmlalt_z_zzz_", 0x64a08400, true),
            ("fmlalt_z_zzzi_s", 0x64a04400, true),
            ("fmlslb_z_zzz_", 0x64a0a000, true),
            ("fmlslb_z_zzzi_s", 0x64a06000, true),
            ("fmlslt_z_zzz_", 0x64a0a400, true),
            ("fmlslt_z_zzzi_s", 0x64a06400, true),
        ];

        #[test]
        fn accepted_and_recovered_canonical_forms_enter_the_common_descriptor() {
            let pc = GuestAddress(0x1000);
            for &(name, word, expected) in CANONICAL {
                let decoded = decode_scalable_numerical_instruction(pc, word).unwrap();
                assert_eq!(decoded.is_some(), expected, "{name}");
                if let Some(instruction) = decoded {
                    assert_eq!(instruction.word, word);
                    assert_eq!(instruction.instruction_pc, pc);
                    assert_eq!(instruction.next_pc, GuestAddress(pc.0 + INSTRUCTION_BYTES));
                }
            }
        }
    }
    mod sme_matrix {
        //! SME matrix family admission and feature requirements.
        use super::*;
        use crate::aarch64::scalable::features::ScalableFeature as Feature;
        use crate::aarch64::scalable::{ScalableMode, VectorLength, profile::ScalableControls};

        const BASE: GuestAddress = GuestAddress(0x1000);
        const SVL_BYTES: [usize; 5] = [16, 32, 64, 128, 256];
        const FADD_ZA_SINGLE: u32 = 0xc1a0_1c00;
        const FMOPA_ZA_SINGLE: u32 = 0x8080_0000;
        const NOP: u32 = 0xd503_201f;
        const MATRIX_SAMPLES: &[(&str, u32, ScalableFeatures, ScalableFeatures)] = &[
            (
                "bfadd_za_zw_2x2_16",
                0xc1e41c00,
                ScalableFeatures::of(Feature::Sme).with(Feature::SmeB16B16),
                ScalableFeatures::empty(),
            ),
            (
                "fadd_za_zw_2x2",
                0xc1a01c00,
                ScalableFeatures::of(Feature::Sme).with(Feature::Sme2),
                ScalableFeatures::empty(),
            ),
            (
                "fadd_za_zw_2x2/sz=1",
                0xc1e01c00,
                ScalableFeatures::of(Feature::Sme)
                    .with(Feature::Sme2)
                    .with(Feature::SmeF64F64),
                ScalableFeatures::empty(),
            ),
            (
                "fadd_za_zw_2x2_16",
                0xc1a41c00,
                ScalableFeatures::of(Feature::Sme),
                ScalableFeatures::of(Feature::SmeF16F16).with(Feature::SmeF8F16),
            ),
            (
                "fmla_za_zzi_h2xi",
                0xc1101000,
                ScalableFeatures::of(Feature::Sme).with(Feature::SmeF16F16),
                ScalableFeatures::empty(),
            ),
            (
                "bfmopa_za32_pp_zz_",
                0x81800000,
                ScalableFeatures::of(Feature::Sme),
                ScalableFeatures::empty(),
            ),
            (
                "fmopa_za_pp_zz_64",
                0x80c00000,
                ScalableFeatures::of(Feature::Sme).with(Feature::SmeF64F64),
                ScalableFeatures::empty(),
            ),
        ];

        fn profile(
            bytes: usize,
            mode: ScalableMode,
            features: ScalableFeatures,
        ) -> ScalableProfile {
            ScalableProfile::new_with_features(
                VectorLength::from_bytes(bytes).unwrap(),
                mode,
                features,
                ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
            )
            .unwrap()
        }

        fn decoded(word: u32) -> ScalableNumericalInstruction {
            decode_scalable_numerical_instruction(BASE, word)
                .unwrap()
                .expect("allocated matrix form")
        }

        #[test]
        fn matrix_predicate_classes_keep_pinned_requirements_and_exact_source() {
            for &(name, word, all, any) in MATRIX_SAMPLES {
                let instruction = decoded(word);
                assert!(
                    matches!(
                        instruction.operation,
                        ScalableNumericalOperation::SmeMatrix(_)
                    ),
                    "{name}"
                );
                let required = instruction
                    .operation
                    .required_streaming_features(NumericalFeatures::default());
                assert_eq!(required.all_features(), all, "{name}");
                assert_eq!(required.any_features(), any, "{name}");
                for bytes in SVL_BYTES {
                    let available = all.union(any);
                    let profile = profile(bytes, ScalableMode::new(true, true), available);
                    let proof = admit_scalable_numerical_instruction(
                        instruction,
                        profile,
                        NumericalFeatures::default(),
                    )
                    .unwrap();
                    assert_eq!(proof.word(), word, "{name}");
                    assert_eq!(proof.instruction_pc(), BASE, "{name}");
                    assert_eq!(
                        proof.next_pc(),
                        GuestAddress(BASE.0 + INSTRUCTION_BYTES),
                        "{name}"
                    );
                    assert_eq!(proof.profile(), profile, "{name}");
                }
            }
        }

        #[test]
        fn matrix_admission_requires_both_streaming_and_za() {
            let features = ScalableFeatures::of(Feature::Sme).with(Feature::Sme2);
            for bytes in SVL_BYTES {
                for streaming in [false, true] {
                    for za in [false, true] {
                        let profile = profile(bytes, ScalableMode::new(streaming, za), features);
                        let admitted = admit_scalable_numerical_instruction(
                            decoded(FADD_ZA_SINGLE),
                            profile,
                            NumericalFeatures::default(),
                        );
                        assert_eq!(admitted.is_ok(), streaming && za);
                    }
                }
            }
        }

        #[test]
        fn matrix_requirements_decline_missing_conjuncts_and_accept_each_alternative() {
            for &(name, word, all, any) in MATRIX_SAMPLES {
                let instruction = decoded(word);
                for missing in all.names() {
                    if missing == Feature::Sme.name() {
                        continue; // Profile construction itself rejects missing FEAT_SME.
                    }
                    let available = ScalableFeatures::checked_from_names(
                        all.union(any)
                            .names()
                            .into_iter()
                            .filter(|&feature| feature != missing),
                    )
                    .unwrap();
                    assert!(
                        admit_scalable_numerical_instruction(
                            instruction,
                            profile(16, ScalableMode::new(true, true), available),
                            NumericalFeatures::default()
                        )
                        .is_err(),
                        "{name}: {missing}"
                    );
                }
                if !any.names().is_empty() {
                    assert!(
                        admit_scalable_numerical_instruction(
                            instruction,
                            profile(16, ScalableMode::new(true, true), all),
                            NumericalFeatures::default()
                        )
                        .is_err(),
                        "{name}: no alternative"
                    );
                    for alternative in any.names() {
                        let available =
                            all.union(ScalableFeatures::checked_from_names([alternative]).unwrap());
                        assert!(
                            admit_scalable_numerical_instruction(
                                instruction,
                                profile(16, ScalableMode::new(true, true), available),
                                NumericalFeatures::default()
                            )
                            .is_ok(),
                            "{name}: {alternative}"
                        );
                    }
                }
            }
        }

        #[test]
        fn matrix_proof_retains_immutable_numerical_features_and_full_a64_permission() {
            let sme = ScalableFeatures::of(Feature::Sme);
            for full_a64 in [false, true] {
                for ebf16 in [false, true] {
                    for rpres in [false, true] {
                        let numerical = NumericalFeatures::new(full_a64, ebf16, rpres);
                        let ordinary = profile(16, ScalableMode::new(true, true), sme);
                        assert_eq!(
                            admit_scalable_numerical_instruction(
                                decoded(FMOPA_ZA_SINGLE),
                                ordinary,
                                numerical
                            )
                            .is_ok(),
                            !full_a64
                        );
                        let declared = profile(
                            16,
                            ScalableMode::new(true, true),
                            sme.with(Feature::SmeFa64),
                        );
                        let proof = admit_scalable_numerical_instruction(
                            decoded(FMOPA_ZA_SINGLE),
                            declared,
                            numerical,
                        )
                        .unwrap();
                        assert_eq!(proof.numerical_features(), numerical);
                    }
                }
            }
        }

        #[test]
        fn matrix_descriptor_mutations_fail_exact_source_redecode() {
            let profile = profile(
                16,
                ScalableMode::new(true, true),
                ScalableFeatures::of(Feature::Sme).with(Feature::Sme2),
            );
            let original = decoded(FADD_ZA_SINGLE);
            for altered in [
                ScalableNumericalInstruction {
                    operation: decoded(FMOPA_ZA_SINGLE).operation,
                    ..original
                },
                ScalableNumericalInstruction {
                    word: NOP,
                    ..original
                },
                ScalableNumericalInstruction {
                    next_pc: BASE,
                    ..original
                },
                ScalableNumericalInstruction {
                    instruction_pc: GuestAddress(BASE.0 + INSTRUCTION_BYTES),
                    ..original
                },
            ] {
                assert!(
                    admit_scalable_numerical_instruction(
                        altered,
                        profile,
                        NumericalFeatures::default()
                    )
                    .is_err()
                );
            }
            assert!(
                decode_scalable_numerical_instruction(GuestAddress(BASE.0 + 1), FADD_ZA_SINGLE)
                    .is_err()
            );
            assert!(
                decode_scalable_numerical_instruction(
                    GuestAddress(u64::MAX - INSTRUCTION_BYTES + 1),
                    FADD_ZA_SINGLE
                )
                .is_err()
            );
        }
    }

    const FADD_Z0_S_P0_Z0_Z0: u32 = 0x6580_8000;
    const NOP: u32 = 0xd503_201f;

    #[test]
    fn numerical_boundary_keeps_exact_source_identity() {
        let pc = GuestAddress(0x1000);
        let instruction = decode_scalable_numerical_instruction(pc, FADD_Z0_S_P0_Z0_Z0)
            .unwrap()
            .expect("allocated floating add");
        assert_eq!(instruction.instruction_pc, pc);
        assert_eq!(instruction.next_pc, GuestAddress(0x1004));
        assert_eq!(instruction.word, FADD_Z0_S_P0_Z0_Z0);
        assert!(matches!(
            instruction.operation,
            ScalableNumericalOperation::Sve(_)
        ));
        assert!(
            decode_scalable_numerical_instruction(pc, NOP)
                .unwrap()
                .is_none()
        );
        assert!(decode_scalable_numerical_instruction(GuestAddress(2), NOP).is_err());
        assert!(
            decode_scalable_numerical_instruction(GuestAddress(u64::MAX - 3), FADD_Z0_S_P0_Z0_Z0)
                .is_err()
        );
    }
}
