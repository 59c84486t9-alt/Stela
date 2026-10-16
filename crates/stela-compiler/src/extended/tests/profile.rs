use super::*;

#[test]
fn feature_admission_declines_with_exact_pc_and_missing_clause_names() {
    let length = VectorLength::from_bytes(16).unwrap();
    let features = ScalableFeatures::of(ScalableFeature::Sme);
    let profile = ScalableProfile::new_with_features(
        length,
        ScalableMode::new(true, false),
        features,
        ScalableControls::new(length, false),
    )
    .unwrap();
    let required = ScalableFeatures::of(ScalableFeature::Sme2);
    let alternatives =
        ScalableFeatures::of(ScalableFeature::SmeF16F16).with(ScalableFeature::SmeF8F16);
    let pc = GuestAddress(0x1234);
    let error = profile
        .require_features(FeatureRequirement::all_and_any(required, alternatives), pc)
        .unwrap_err();
    assert_eq!(
        error.0,
        "unavailable guest features at 0x1234: requires FEAT_SME2; requires one of FEAT_SME_F16F16, FEAT_SME_F8F16"
    );
    assert!(
        profile
            .require_features(FeatureRequirement::all(features), pc)
            .is_ok()
    );
    assert!(
        profile
            .require_features(FeatureRequirement::default(), pc)
            .is_ok()
    );
    assert!(
        ScalableProfile::new(length, ScalableMode::default())
            .require_features(FeatureRequirement::all(required), pc)
            .is_ok()
    );
}

#[test]
fn declared_sme1_za_storage_does_not_require_zt0_or_streaming_banks() {
    let length = VectorLength::from_bytes(64).unwrap();
    let mode = ScalableMode::new(false, true);
    let sme = ScalableFeatures::of(ScalableFeature::Sme);
    let mut za = [0_u8; 64 * 64];
    let mut view = ScalableStateView {
        svl_bytes: length.bytes() as u16,
        reserved: [0; 6],
        svcr: mode.svcr(),
        tpidr2_el0: 0,
        fpmr: 0,
        z_upper: core::ptr::null_mut(),
        predicates: core::ptr::null_mut(),
        ffr: core::ptr::null_mut(),
        za: za.as_mut_ptr(),
        zt0: core::ptr::null_mut(),
    };
    let context = ExecutionContext {
        scalable: &mut view,
        ..ExecutionContext::default()
    };
    let profile =
        ScalableProfile::new_with_features(length, mode, sme, ScalableControls::new(length, false))
            .unwrap();
    assert!(profile.validate_view(&context, &view).is_ok());
    assert_eq!(profile.required_dit(), Some(false));
    let zt0_profile = ScalableProfile::new_with_features(
        length,
        mode,
        sme.with(ScalableFeature::Sme2),
        ScalableControls::new(length, true),
    )
    .unwrap();
    assert!(zt0_profile.validate_view(&context, &view).is_err());
    let original = ScalableProfile::new(length, mode);
    assert!(original.validate_view(&context, &view).is_err());
    assert_eq!(original.required_dit(), None);
    let mut zt0 = [0_u8; crate::aarch64::scalable::LOOKUP_TABLE_BYTES];
    view.zt0 = zt0.as_mut_ptr();
    assert!(zt0_profile.validate_view(&context, &view).is_ok());
    assert!(original.validate_view(&context, &view).is_ok());
    view.za = core::ptr::null_mut();
    assert!(profile.validate_view(&context, &view).is_err());
    assert!(zt0_profile.validate_view(&context, &view).is_err());
}

#[test]
fn declared_profile_requires_explicit_dependencies_and_controls() {
    let length = VectorLength::from_bytes(64).unwrap();
    let controls = ScalableControls::new(length, false);
    let sme = ScalableFeatures::of(ScalableFeature::Sme);
    let mode = ScalableMode::new(true, false);
    assert!(
        ScalableProfile::new_with_features(length, mode, ScalableFeatures::empty(), controls)
            .is_err()
    );
    assert!(
        ScalableProfile::new_with_features(
            length,
            mode,
            sme.with(ScalableFeature::Sme2p1),
            controls
        )
        .is_err()
    );
    assert!(
        ScalableProfile::new_with_features(length, mode, sme, ScalableControls::new(length, true))
            .is_err()
    );
    assert!(
        ScalableProfile::new_with_features(
            length,
            mode,
            sme,
            ScalableControls::new(VectorLength::from_bytes(32).unwrap(), false)
        )
        .is_err()
    );
    let profile = ScalableProfile::new_with_features(length, mode, sme, controls).unwrap();
    assert_eq!(profile.id(), DECLARED_PROFILE_ID);
    assert_eq!(profile.features(), sme);
    assert_eq!(profile.declared_features(), Some(sme));
    assert_eq!(profile.controls(), controls);
}

#[test]
fn declared_profile_identity_includes_features_and_controls() {
    let length = VectorLength::from_bytes(32).unwrap();
    let mode = ScalableMode::new(true, true);
    let features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
    let controls = ScalableControls::new(length, false);
    let original = ScalableProfile::new_with_features(length, mode, features, controls).unwrap();
    for (other_features, other_controls) in [
        (features.with(ScalableFeature::Sme2p1), controls),
        (
            features,
            ScalableControls::new(VectorLength::from_bytes(64).unwrap(), false),
        ),
        (features, ScalableControls::new(length, true)),
    ] {
        assert_ne!(
            original,
            ScalableProfile::new_with_features(length, mode, other_features, other_controls)
                .unwrap()
        );
    }
}

#[test]
fn original_profile_retains_fixed_identity_and_manifest_shape() {
    let length = VectorLength::from_bytes(64).unwrap();
    let mode = ScalableMode::new(false, true);
    let original = ScalableProfile::new(length, mode);
    assert_eq!(original.id(), PROFILE_ID);
    assert_eq!(original.vector_length(), length);
    assert_eq!(original.mode(), mode);
    assert_eq!(original.declared_features(), None);
    assert_eq!(original.features().names(), ["FEAT_SME", "FEAT_SME2"]);
    assert_eq!(original.controls(), ScalableControls::new(length, false));
    assert_ne!(
        original,
        ScalableProfile::new_with_features(length, mode, original.features(), original.controls())
            .unwrap()
    );
}

#[test]
fn declared_profiles_keep_base_sme_families_available() {
    const BASE_SME_WORDS: [u32; 6] = [
        0x041a_0040, // AND predicated.
        0x0461_5820, // ADDSPL.
        0x0416_a020, // ABS predicated.
        0x045c_bfff, // FABS predicated.
        0x4500_f820, // SABA.
        0x4482_003f, // Four-product SDOT.
    ];
    for bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(bytes).unwrap();
        let profile = ScalableProfile::new_with_features(
            length,
            ScalableMode::new(true, false),
            ScalableFeatures::of(ScalableFeature::Sme),
            ScalableControls::new(length, false),
        )
        .unwrap();
        for word in BASE_SME_WORDS {
            assert!(
                compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0x1234),
                    profile,
                    TargetCpu::Baseline,
                )
                .is_ok()
            );
        }
    }
}

#[test]
fn declared_dot_features_preserve_v1_scope_and_check_optional_requirements() {
    const TWO_PRODUCT_SDOT: u32 = 0x4402_c820;
    const MIXED_DOT_WORDS: [u32; 3] = [0x4482_7820, 0x44a2_1820, 0x44a2_1c20];
    let length = VectorLength::from_bytes(16).unwrap();
    let mode = ScalableMode::new(true, false);
    let sme = ScalableFeatures::of(ScalableFeature::Sme);
    let declared = |features| {
        ScalableProfile::new_with_features(
            length,
            mode,
            features,
            ScalableControls::new(length, false),
        )
        .unwrap()
    };
    let compile = |word, profile| {
        compile_for_profile(
            &words(&[word, RET_X30]),
            GuestAddress(0x1234),
            profile,
            TargetCpu::Baseline,
        )
    };
    let missing = compile(TWO_PRODUCT_SDOT, declared(sme)).unwrap_err();
    assert!(missing.0.contains("0x1234") && missing.0.contains("requires FEAT_SME2"));
    assert!(compile(TWO_PRODUCT_SDOT, declared(sme.with(ScalableFeature::Sme2))).is_ok());
    assert!(compile(TWO_PRODUCT_SDOT, ScalableProfile::new(length, mode)).is_ok());
    for word in MIXED_DOT_WORDS {
        let legacy = compile(word, ScalableProfile::new(length, mode)).unwrap_err();
        assert!(legacy.0.contains("I8MM is outside") && legacy.0.contains("0x1234"));
        let missing = compile(word, declared(sme.with(ScalableFeature::Sme2))).unwrap_err();
        assert!(missing.0.contains("requires FEAT_I8MM") && missing.0.contains("0x1234"));
        assert!(compile(word, declared(sme.with(ScalableFeature::I8mm))).is_ok());
    }
}
