use super::*;

#[test]
fn exact_lr_tuple_rejects_other_algorithm_versions() {
    for apa in 0..=ID_FIELD_MASK {
        for api in 0..=ID_FIELD_MASK {
            for apa3 in 0..=ID_FIELD_MASK {
                let isar1 = (apa << ISAR1_APA_SHIFT) | (api << ISAR1_API_SHIFT);
                let isar2 = apa3 << ISAR2_APA3_SHIFT;
                assert_eq!(
                    check_ids_for(isar1, isar2, APA_QARMA5_PAUTH_LR).is_ok(),
                    apa == APA_QARMA5_PAUTH_LR
                        && api == AUTHENTICATION_ALGORITHM_ABSENT
                        && apa3 == AUTHENTICATION_ALGORITHM_ABSENT
                );
            }
        }
    }
}

#[test]
fn lr_capability_retains_exact_shared_snapshot_and_named_missing_ids_decline() {
    let values = [
        (
            Register::IdAa64Isar1El1,
            APA_QARMA5_PAUTH_LR << ISAR1_APA_SHIFT,
        ),
        (Register::IdAa64Isar2El1, 0),
        (
            Register::IdAa64Isar3El1,
            PACM_FULL_IMPLEMENTATION << ISAR3_PACM_SHIFT,
        ),
    ];
    for missing in [
        Register::IdAa64Isar1El1,
        Register::IdAa64Isar2El1,
        Register::IdAa64Isar3El1,
    ] {
        let present: Vec<_> = values
            .into_iter()
            .filter(|(register, _)| *register != missing)
            .collect();
        let source = Snapshot::declared("lr-capability-missing-id", &present).unwrap();
        assert!(matches!(
            LinkRegisterPauthCapability::from_profile(&source),
            Err(UnsupportedInstructionProfile::MissingId(register)) if register == missing
        ));
    }
    let source = Snapshot::declared("lr-capability-declared-profile", &values).unwrap();
    let capability = LinkRegisterPauthCapability::from_profile(&source).unwrap();
    assert!(std::ptr::eq(capability.snapshot(), &source));
    assert_eq!(capability.version(), Version::FaultingCombined);
}

#[test]
fn qarma5_lr_requires_actual_full_pacm_and_rejects_absent_trivial_reserved_values() {
    for pacm in 0..=ID_FIELD_MASK {
        let source = Snapshot::declared(
            "lr-capability-pacm-coherence",
            &[
                (
                    Register::IdAa64Isar1El1,
                    APA_QARMA5_PAUTH_LR << ISAR1_APA_SHIFT,
                ),
                (Register::IdAa64Isar2El1, 0),
                (Register::IdAa64Isar3El1, pacm << ISAR3_PACM_SHIFT),
            ],
        )
        .unwrap();
        let result = LinkRegisterPauthCapability::from_profile(&source);
        if pacm == PACM_FULL_IMPLEMENTATION {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(UnsupportedInstructionProfile::PacmImplementation(value))
                    if value == pacm as u8
            ));
        }
    }
}
