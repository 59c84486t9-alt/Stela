use super::*;

fn scalable() -> ScalableEntryAbsence {
    ScalableEntryAbsence::from_id_registers(0, 0).unwrap()
}

#[test]
fn pfar_requires_explicit_absence_and_present_or_unreviewed_declines() {
    let absent = SystemEntryFeatures::declared_absent();
    assert!(!absent.contains(SystemEntryFeature::Pfar));
    assert!(EntryProfile::base(absent, scalable()).is_ok());
    let present_or_unreviewed = absent.with(SystemEntryFeature::Pfar);
    assert_eq!(
        EntryProfile::base(present_or_unreviewed, scalable()),
        Err(EntryProfileError::UnsupportedSystemFeature(
            SystemEntryFeature::Pfar
        ))
    );
    // Constructors have no storage argument: absent PFAR storage cannot erase
    // an authoritative present/unreviewed feature declaration. The Snapshot
    // owner separately rejects missing PFR1 and every nonzero PFAR field.
    assert_eq!(SystemEntryFeature::Pfar.name(), "FEAT_PFAR");
}

#[test]
fn pfar_append_preserves_all_existing_feature_discriminants_and_masks() {
    let prior = [
        SystemEntryFeature::Brbe,
        SystemEntryFeature::Bti,
        SystemEntryFeature::Dit,
        SystemEntryFeature::DoubleFault,
        SystemEntryFeature::Ebep,
        SystemEntryFeature::Exs,
        SystemEntryFeature::Gcs,
        SystemEntryFeature::Iesb,
        SystemEntryFeature::Mops,
        SystemEntryFeature::Mte,
        SystemEntryFeature::Nmi,
        SystemEntryFeature::Pan,
        SystemEntryFeature::PauthLr,
        SystemEntryFeature::SpeExc,
        SystemEntryFeature::Ssbs,
        SystemEntryFeature::TrbeExc,
        SystemEntryFeature::Uao,
        SystemEntryFeature::Uinj,
    ];
    for (index, feature) in prior.into_iter().enumerate() {
        assert_eq!(usize::from(feature as u8), index);
        assert_eq!(feature.mask(), 1 << index);
        assert!(
            !SystemEntryFeatures::declared_absent()
                .with(feature)
                .contains(SystemEntryFeature::Pfar)
        );
    }
    assert_eq!(usize::from(SystemEntryFeature::Pfar as u8), prior.len());
    assert_eq!(SystemEntryFeature::Pfar.mask(), 1 << prior.len());
}
