use super::*;
use crate::aarch64::sme::tables;

fn table_profile(
    bytes: usize,
    mode: ScalableMode,
    features: ScalableFeatures,
    zt0_enabled: bool,
) -> ScalableProfile {
    ScalableProfile::new_with_features(
        VectorLength::from_bytes(bytes).unwrap(),
        mode,
        features,
        ScalableControls::new(VectorLength::from_bytes(256).unwrap(), zt0_enabled),
    )
    .unwrap()
}

fn table_features() -> ScalableFeatures {
    ScalableFeatures::of(ScalableFeature::Sme)
        .with(ScalableFeature::Sme2)
        .with(ScalableFeature::Sme2p1)
}

#[test]
fn fixed_table_routes_keep_compatible_legacy_profiles() {
    let legacy = ScalableProfile::new(
        VectorLength::from_bytes(64).unwrap(),
        ScalableMode::new(true, false),
    );
    for word in [TABLE_SELECT, TABLE_ZIP_PAIR_Q, TABLE_ZIP_QUAD_Q, 0xc165e000] {
        assert!(
            crate::testing::context_leaf(
                &words(&[word, RET_X30]),
                GuestAddress(0x1000),
                legacy,
                TargetCpu::Baseline
            )
            .is_ok()
        );
    }
}

#[test]
fn scalar_lookup_policy_tracks_the_selected_recipe() {
    use crate::aarch64::scalable::ElementSize;
    let mut operand = tables::decode(TABLE_LOOKUP).unwrap();
    let short = VectorLength::from_bytes(16).unwrap();
    let long = VectorLength::from_bytes(64).unwrap();
    operand.element = ElementSize::Word;
    assert!(x86_64::sme::tables::requires_dit_zero(
        &operand,
        short,
        TargetCpu::Baseline
    ));
    assert!(x86_64::sme::tables::requires_dit_zero(
        &operand,
        short,
        TargetCpu::Ssse3
    ));
    assert!(!x86_64::sme::tables::requires_dit_zero(
        &operand,
        long,
        TargetCpu::Ssse3
    ));
    operand.element = ElementSize::Halfword;
    assert!(x86_64::sme::tables::requires_dit_zero(
        &operand,
        short,
        TargetCpu::Baseline
    ));
    assert!(!x86_64::sme::tables::requires_dit_zero(
        &operand,
        long,
        TargetCpu::Baseline
    ));
    assert!(!x86_64::sme::tables::requires_dit_zero(
        &operand,
        short,
        TargetCpu::Ssse3
    ));
    operand.element = ElementSize::Byte;
    assert!(!x86_64::sme::tables::requires_dit_zero(
        &operand,
        short,
        TargetCpu::Baseline
    ));
    let legacy = ScalableProfile::new(short, ScalableMode::new(true, true));
    let scalar_word = TABLE_LOOKUP | (2 << 12);
    let error = crate::testing::context_leaf(
        &words(&[scalar_word, RET_X30]),
        GuestAddress(0x1000),
        legacy,
        TargetCpu::Baseline,
    )
    .unwrap_err();
    assert!(error.to_string().contains("scalar SME lookup"));
}

#[test]
fn table_lookup_requires_za_and_enabled_zt0() {
    for (za_enabled, zt0_enabled) in [(false, false), (false, true), (true, false)] {
        let profile = table_profile(
            16,
            ScalableMode::new(true, za_enabled),
            table_features(),
            zt0_enabled,
        );
        let error = crate::testing::context_leaf(
            &words(&[TABLE_LOOKUP, RET_X30]),
            GuestAddress(0x1000),
            profile,
            TargetCpu::Baseline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("ZA and enabled ZT0"));
    }
    let profile = table_profile(16, ScalableMode::new(true, true), table_features(), true);
    assert!(
        crate::testing::context_leaf(
            &words(&[TABLE_LOOKUP, RET_X30]),
            GuestAddress(0x1000),
            profile,
            TargetCpu::Baseline
        )
        .is_ok()
    );
}

#[test]
fn table_strided_lookups_require_sme2p1() {
    let feature_base = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
    let base = table_profile(16, ScalableMode::new(true, true), feature_base, true);
    let complete = table_profile(16, ScalableMode::new(true, true), table_features(), true);
    for word in [0xc09c4000, 0xc09c8000, 0xc09a4000, 0xc09a9000] {
        let input = words(&[word, RET_X30]);
        let error =
            crate::testing::context_leaf(&input, GuestAddress(0x1000), base, TargetCpu::Baseline)
                .unwrap_err();
        assert!(error.to_string().contains("FEAT_SME2p1"));
        assert!(
            crate::testing::context_leaf(
                &input,
                GuestAddress(0x1000),
                complete,
                TargetCpu::Baseline
            )
            .is_ok()
        );
    }
}

#[test]
fn table_permutations_validate_current_length_despite_larger_maximum() {
    for (word, too_short, minimum) in [(TABLE_ZIP_PAIR_Q, 16, 32), (TABLE_ZIP_QUAD_Q, 32, 64)] {
        let input = words(&[word, RET_X30]);
        let short = table_profile(
            too_short,
            ScalableMode::new(true, false),
            table_features(),
            false,
        );
        let error =
            crate::testing::context_leaf(&input, GuestAddress(0x1000), short, TargetCpu::Baseline)
                .unwrap_err();
        assert!(error.to_string().contains("require SVL"));
        let valid = table_profile(
            minimum,
            ScalableMode::new(true, false),
            table_features(),
            false,
        );
        assert!(
            crate::testing::context_leaf(&input, GuestAddress(0x1000), valid, TargetCpu::Baseline)
                .is_ok()
        );
    }
}

#[test]
fn every_table_family_routes_through_the_shared_context_entry() {
    let profile = table_profile(64, ScalableMode::new(true, true), table_features(), true);
    for word in [
        0xc08c4000, 0xc09c4000, 0xc08c8000, 0xc09c8000, 0xc0cc0000, 0xc08a4000, 0xc09a4000,
        0xc08a9000, 0xc09a9000, 0xc0ca0000, 0xc1208000, 0xc1218000, 0xc165e000, 0xc175e000,
        0xc165e001, 0xc175e001, 0xc136e002, 0xc137e002, 0xc120d001, 0xc120d401, 0xc136e000,
        0xc137e000, 0xc120d000, 0xc120d400,
    ] {
        let result = crate::testing::context_leaf(
            &words(&[word, RET_X30]),
            GuestAddress(0x1000),
            profile,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(result.source_map.len(), 2);
        assert_eq!(
            result.source_map[0],
            (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES)
        );
        assert_eq!(result.source_map[1].0, GuestAddress(0x1004));
        assert!(result.source_map[1].1 > result.source_map[0].1);
    }
}

#[test]
fn table_admission_requires_sme2_and_streaming() {
    let sme_only = table_profile(
        16,
        ScalableMode::new(true, false),
        ScalableFeatures::of(ScalableFeature::Sme),
        false,
    );
    let error = crate::testing::context_leaf(
        &words(&[TABLE_SELECT, RET_X30]),
        GuestAddress(0x1000),
        sme_only,
        TargetCpu::Baseline,
    )
    .unwrap_err();
    assert!(error.to_string().contains("FEAT_SME2"));
    let non_streaming = table_profile(16, ScalableMode::new(false, false), table_features(), false);
    let error = crate::testing::context_leaf(
        &words(&[TABLE_SELECT, RET_X30]),
        GuestAddress(0x1000),
        non_streaming,
        TargetCpu::Baseline,
    )
    .unwrap_err();
    assert!(error.to_string().contains("streaming mode required"));
}
