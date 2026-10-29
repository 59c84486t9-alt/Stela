use super::*;
use stela_compiler::aarch64::floating::FPCR_EXCEPTION_ENABLE_MASK;

mod sme_vector {
    //! SME2 multi-vector floating-point completion.

    use crate::{floating::scalable as completion, scalable::ScalableState};
    use stela_compiler::{
        GuestAddress, GuestState,
        aarch64::{
            floating::{FPCR_EXCEPTION_ENABLE_MASK, features::NumericalFeatures},
            scalable::{
                ScalableMode, VectorLength,
                features::{ScalableFeature as Feature, ScalableFeatures},
                profile::ScalableControls,
            },
        },
        block::scalable::{
            AdmittedScalableNumericalInstruction, ScalableNumericalOperation,
            admit_scalable_numerical_instruction, decode_scalable_numerical_instruction,
        },
        scalable_context::ScalableProfile,
    };

    const PC: GuestAddress = GuestAddress(0x1008);
    const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
    const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
    const FRINTN_PAIR: u32 = 0xc1a8_e000;
    const NOP: u32 = 0xd503_201f;
    const FPSR_QC: u32 = 1 << 27;

    #[derive(Clone, Copy)]
    enum Requirement {
        Sme2,
        Bfloat,
        HalfWiden,
    }
    #[derive(Clone, Copy)]
    struct Case {
        id: &'static str,
        word: u32,
        required: Requirement,
    }
    const CASES: &[Case] = &[
        Case {
            id: "bfclamp_mz_zz_2",
            word: 0xc120_c000,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfclamp_mz_zz_4",
            word: 0xc120_c800,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfcvt_z_mz2_",
            word: 0xc160_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "bfcvtn_z_mz2_",
            word: 0xc160_e020,
            required: Requirement::Sme2,
        },
        Case {
            id: "bfmax_mz_zzv_2x1",
            word: 0xc120_a100,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmax_mz_zzv_4x1",
            word: 0xc120_a900,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmax_mz_zzw_2x2",
            word: 0xc120_b100,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmax_mz_zzw_4x4",
            word: 0xc120_b900,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmaxnm_mz_zzv_2x1",
            word: 0xc120_a120,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmaxnm_mz_zzv_4x1",
            word: 0xc120_a920,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmaxnm_mz_zzw_2x2",
            word: 0xc120_b120,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmaxnm_mz_zzw_4x4",
            word: 0xc120_b920,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmin_mz_zzv_2x1",
            word: 0xc120_a101,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmin_mz_zzv_4x1",
            word: 0xc120_a901,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmin_mz_zzw_2x2",
            word: 0xc120_b101,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfmin_mz_zzw_4x4",
            word: 0xc120_b901,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfminnm_mz_zzv_2x1",
            word: 0xc120_a121,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfminnm_mz_zzv_4x1",
            word: 0xc120_a921,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfminnm_mz_zzw_2x2",
            word: 0xc120_b121,
            required: Requirement::Bfloat,
        },
        Case {
            id: "bfminnm_mz_zzw_4x4",
            word: 0xc120_b921,
            required: Requirement::Bfloat,
        },
        Case {
            id: "fclamp_mz_zz_2",
            word: 0xc160_c000,
            required: Requirement::Sme2,
        },
        Case {
            id: "fclamp_mz_zz_4",
            word: 0xc160_c800,
            required: Requirement::Sme2,
        },
        Case {
            id: "fcvt_mz2_z_",
            word: 0xc1a0_e000,
            required: Requirement::HalfWiden,
        },
        Case {
            id: "fcvt_z_mz2_",
            word: 0xc120_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "fcvtl_mz2_z_",
            word: 0xc1a0_e001,
            required: Requirement::HalfWiden,
        },
        Case {
            id: "fcvtn_z_mz2_",
            word: 0xc120_e020,
            required: Requirement::Sme2,
        },
        Case {
            id: "fcvtzs_mz_z_2",
            word: 0xc121_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "fcvtzs_mz_z_4",
            word: 0xc131_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "fcvtzu_mz_z_2",
            word: 0xc121_e020,
            required: Requirement::Sme2,
        },
        Case {
            id: "fcvtzu_mz_z_4",
            word: 0xc131_e020,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmax_mz_zzv_2x1",
            word: 0xc160_a100,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmax_mz_zzv_4x1",
            word: 0xc160_a900,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmax_mz_zzw_2x2",
            word: 0xc160_b100,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmax_mz_zzw_4x4",
            word: 0xc160_b900,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmaxnm_mz_zzv_2x1",
            word: 0xc160_a120,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmaxnm_mz_zzv_4x1",
            word: 0xc160_a920,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmaxnm_mz_zzw_2x2",
            word: 0xc160_b120,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmaxnm_mz_zzw_4x4",
            word: 0xc160_b920,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmin_mz_zzv_2x1",
            word: 0xc160_a101,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmin_mz_zzv_4x1",
            word: 0xc160_a901,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmin_mz_zzw_2x2",
            word: 0xc160_b101,
            required: Requirement::Sme2,
        },
        Case {
            id: "fmin_mz_zzw_4x4",
            word: 0xc160_b901,
            required: Requirement::Sme2,
        },
        Case {
            id: "fminnm_mz_zzv_2x1",
            word: 0xc160_a121,
            required: Requirement::Sme2,
        },
        Case {
            id: "fminnm_mz_zzv_4x1",
            word: 0xc160_a921,
            required: Requirement::Sme2,
        },
        Case {
            id: "fminnm_mz_zzw_2x2",
            word: 0xc160_b121,
            required: Requirement::Sme2,
        },
        Case {
            id: "fminnm_mz_zzw_4x4",
            word: 0xc160_b921,
            required: Requirement::Sme2,
        },
        Case {
            id: "frinta_mz_z_2",
            word: 0xc1ac_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "frinta_mz_z_4",
            word: 0xc1bc_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "frintm_mz_z_2",
            word: 0xc1aa_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "frintm_mz_z_4",
            word: 0xc1ba_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "frintn_mz_z_2",
            word: 0xc1a8_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "frintn_mz_z_4",
            word: 0xc1b8_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "frintp_mz_z_2",
            word: 0xc1a9_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "frintp_mz_z_4",
            word: 0xc1b9_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "scvtf_mz_z_2",
            word: 0xc122_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "scvtf_mz_z_4",
            word: 0xc132_e000,
            required: Requirement::Sme2,
        },
        Case {
            id: "ucvtf_mz_z_2",
            word: 0xc122_e020,
            required: Requirement::Sme2,
        },
        Case {
            id: "ucvtf_mz_z_4",
            word: 0xc132_e020,
            required: Requirement::Sme2,
        },
    ];
    fn declared(required: Requirement) -> ScalableFeatures {
        let sme = ScalableFeatures::of(Feature::Sme);
        match required {
            Requirement::Sme2 => sme.with(Feature::Sme2),
            Requirement::Bfloat => sme.with(Feature::Sme2).with(Feature::SveB16B16),
            Requirement::HalfWiden => sme.with(Feature::SmeF16F16),
        }
    }
    fn profile(
        bytes: usize,
        streaming: bool,
        za: bool,
        features: ScalableFeatures,
    ) -> ScalableProfile {
        ScalableProfile::new_with_features(
            VectorLength::from_bytes(bytes).unwrap(),
            ScalableMode::new(streaming, za),
            features,
            ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
        )
        .unwrap()
    }
    fn admit(
        word: u32,
        profile: ScalableProfile,
        numerical: NumericalFeatures,
    ) -> Result<AdmittedScalableNumericalInstruction, stela_compiler::CompileError> {
        let decoded = decode_scalable_numerical_instruction(PC, word)?.unwrap();
        admit_scalable_numerical_instruction(decoded, profile, numerical)
    }
    #[test]
    fn all_fifty_eight_minimal_features_admit_both_za_states_at_every_length() {
        assert_eq!(CASES.len(), 58);
        for case in CASES {
            for bytes in LENGTHS {
                for za in [false, true] {
                    let profile = profile(bytes, true, za, declared(case.required));
                    let proof = admit(case.word, profile, NumericalFeatures::default()).unwrap();
                    assert!(
                        matches!(proof.operation(), ScalableNumericalOperation::SmeVector(_)),
                        "{}",
                        case.id
                    );
                    assert_eq!(proof.profile(), profile);
                    assert_eq!(proof.word(), case.word);
                    assert_eq!(proof.instruction_pc(), PC);
                    assert_eq!(proof.next_pc(), GuestAddress(PC.0 + INSTRUCTION_BYTES));
                }
            }
        }
    }
    #[test]
    fn missing_features_and_nonstreaming_decline_without_inference() {
        let sme = ScalableFeatures::of(Feature::Sme);
        for case in CASES {
            let missing = match case.required {
                Requirement::Sme2 => vec![sme],
                Requirement::Bfloat => {
                    vec![sme.with(Feature::Sme2), sme.with(Feature::SveB16B16)]
                }
                Requirement::HalfWiden => vec![sme, sme.with(Feature::Sme2)],
            };
            for bytes in LENGTHS {
                for za in [false, true] {
                    assert!(
                        admit(
                            case.word,
                            profile(bytes, false, za, declared(case.required)),
                            NumericalFeatures::default()
                        )
                        .is_err(),
                        "{}",
                        case.id
                    );
                    for &features in &missing {
                        assert!(
                            admit(
                                case.word,
                                profile(bytes, true, za, features),
                                NumericalFeatures::default()
                            )
                            .is_err(),
                            "{}",
                            case.id
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn full_a64_requires_its_declared_architectural_feature() {
        let full = NumericalFeatures::new(true, false, false);
        for case in CASES {
            let features = declared(case.required);
            assert!(admit(case.word, profile(16, true, false, features), full).is_err());
            let proof = admit(
                case.word,
                profile(16, true, false, features.with(Feature::SmeFa64)),
                full,
            )
            .unwrap();
            assert_eq!(proof.numerical_features(), full);
        }
    }
    #[test]
    fn forged_descriptors_fail_the_same_source_redecode() {
        for case in CASES {
            let valid = decode_scalable_numerical_instruction(PC, case.word)
                .unwrap()
                .unwrap();
            let profile = profile(16, true, false, declared(case.required));
            let mut wrong_word = valid;
            wrong_word.word = NOP;
            let mut wrong_next = valid;
            wrong_next.next_pc = GuestAddress(PC.0 + 2 * INSTRUCTION_BYTES);
            let mut wrong_pc = valid;
            wrong_pc.instruction_pc = GuestAddress(PC.0 + 1);
            for forged in [wrong_word, wrong_next, wrong_pc] {
                assert!(
                    admit_scalable_numerical_instruction(
                        forged,
                        profile,
                        NumericalFeatures::default()
                    )
                    .is_err()
                );
            }
        }
    }
    fn state(bytes: usize, streaming: bool, za: bool) -> (GuestState, ScalableState) {
        let mut state = GuestState::default();
        let mut scalable = ScalableState::new(VectorLength::from_bytes(bytes).unwrap(), true);
        scalable
            .apply_mode(&mut state, ScalableMode::new(streaming, za))
            .unwrap();
        state.x.fill(0x1234_5678_9abc_def0);
        state.sp = 0x0123_4567_89ab_cdef;
        state.nzcv = 0xa000_0000;
        state.fpsr = FPSR_QC;
        (state, scalable)
    }
    #[test]
    fn current_owned_state_mismatches_fail_before_any_effect() {
        for case in CASES {
            let proof = admit(
                case.word,
                profile(16, true, false, declared(case.required)),
                NumericalFeatures::default(),
            )
            .unwrap();
            for (bytes, streaming, za) in [(32, true, false), (16, false, false), (16, true, true)]
            {
                let (mut state, mut scalable) = state(bytes, streaming, za);
                let before = state.clone();
                let banks = format!("{scalable:?}");
                assert!(completion::complete(&mut state, &mut scalable, &proof).is_err());
                assert_eq!(state, before);
                assert_eq!(format!("{scalable:?}"), banks);
            }
        }
    }
    #[test]
    fn retained_full_a64_trap_enables_fail_transactionally() {
        let features = ScalableFeatures::of(Feature::Sme)
            .with(Feature::Sme2)
            .with(Feature::SmeFa64);
        let proof = admit(
            FRINTN_PAIR,
            profile(16, true, false, features),
            NumericalFeatures::new(true, false, false),
        )
        .unwrap();
        let (mut state, mut scalable) = state(16, true, false);
        state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
        let before = state.clone();
        let banks = format!("{scalable:?}");
        assert!(matches!(
            completion::complete(&mut state, &mut scalable, &proof),
            Err(completion::CompletionError::UnsupportedControl(_))
        ));
        assert_eq!(state, before);
        assert_eq!(format!("{scalable:?}"), banks);
    }
}

#[test]
fn controls_preserve_raw_storage_and_select_actual_feature_availability() {
    let state = GuestState {
        fpcr: u32::MAX,
        ..GuestState::default()
    };
    let ordinary = NumericalControls::new(state.fpcr, true, NumericalFeatures::default());
    assert_eq!(
        ordinary.fpcr,
        state.fpcr & !FPCR_EXCEPTION_ENABLE_MASK & !FPCR_EBF
    );
    let enabled =
        NumericalControls::new(state.fpcr, true, NumericalFeatures::new(true, true, true));
    assert_eq!(enabled.fpcr, state.fpcr);
    assert!(enabled.features.rpres());
    assert_eq!(state.fpcr, u32::MAX);
}
