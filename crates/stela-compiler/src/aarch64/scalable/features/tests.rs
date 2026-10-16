use super::*;

#[test]
fn strict_names_round_trip_in_architectural_order() {
    let mut features = ScalableFeatures::empty();
    for &feature in FEATURES_BY_NAME.iter().rev() {
        assert!(!features.contains(feature));
        features = features.with(feature);
    }
    let names = features.names();
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(ScalableFeatures::checked_from_names(names), Ok(features));
    assert_eq!(
        ScalableFeatures::checked_from_names(["FEAT_SME", "FEAT_SME"]),
        Err(FeatureNameError::Duplicate(ScalableFeature::Sme))
    );
    for name in ["SME", "FEAT_SME2P1", "FEAT_future", ""] {
        assert_eq!(
            ScalableFeatures::checked_from_names([name]),
            Err(FeatureNameError::Unknown(name.into()))
        );
    }
}

#[test]
fn declarations_do_not_imply_dependencies() {
    let sme2 = ScalableFeatures::of(ScalableFeature::Sme2);
    assert!(!sme2.contains(ScalableFeature::Sme));
    assert!(!sme2.contains(ScalableFeature::Sme2p1));
    assert_eq!(sme2.names(), ["FEAT_SME2"]);
    let sme = ScalableFeatures::of(ScalableFeature::Sme);
    assert_eq!(sme2.union(sme), sme.with(ScalableFeature::Sme2));
    assert!(sme2.contains_all(ScalableFeatures::empty()));
}

#[test]
fn requirements_apply_both_clauses_for_every_subset() {
    let sme = ScalableFeatures::of(ScalableFeature::Sme);
    let alternatives =
        ScalableFeatures::of(ScalableFeature::SmeF16F16).with(ScalableFeature::SmeF8F16);
    let requirement = FeatureRequirement::all_and_any(sme, alternatives);
    for has_sme in [false, true] {
        for has_f16 in [false, true] {
            for has_f8 in [false, true] {
                let mut features = ScalableFeatures::empty();
                if has_sme {
                    features = features.with(ScalableFeature::Sme);
                }
                if has_f16 {
                    features = features.with(ScalableFeature::SmeF16F16);
                }
                if has_f8 {
                    features = features.with(ScalableFeature::SmeF8F16);
                }
                assert_eq!(
                    requirement.is_satisfied_by(features),
                    has_sme && (has_f16 || has_f8)
                );
                assert_eq!(
                    FeatureRequirement::all(sme).is_satisfied_by(features),
                    has_sme
                );
                assert_eq!(
                    FeatureRequirement::any(alternatives).is_satisfied_by(features),
                    has_f16 || has_f8
                );
                assert!(FeatureRequirement::default().is_satisfied_by(features));
                assert!(
                    FeatureRequirement::any(ScalableFeatures::empty()).is_satisfied_by(features)
                );
            }
        }
    }
    assert_eq!(requirement.all_features(), sme);
    assert_eq!(requirement.any_features(), alternatives);
}
