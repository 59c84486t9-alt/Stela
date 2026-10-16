use super::*;

mod base_spe;
mod pfar;

fn no_scalable_state() -> ScalableEntryAbsence {
    ScalableEntryAbsence::from_id_registers(0, 0).unwrap()
}

#[test]
fn base_token_requires_explicit_absence_and_rejects_each_optional_effect() {
    let absent = SystemEntryFeatures::declared_absent();
    let profile = EntryProfile::base(absent, no_scalable_state()).unwrap();
    assert_eq!(profile.features(), absent);
    for &feature in SYSTEM_ENTRY_FEATURES {
        assert_eq!(
            EntryProfile::base(absent.with(feature), no_scalable_state()),
            Err(EntryProfileError::UnsupportedSystemFeature(feature))
        );
    }
}

#[test]
fn every_nonzero_scalable_id_value_declines_instead_of_becoming_absent() {
    for sve in 0..=ID_FIELD_MASK {
        for sme in 0..=ID_FIELD_MASK {
            let result = ScalableEntryAbsence::from_id_registers(
                sve << PFR0_SVE_SHIFT,
                sme << PFR1_SME_SHIFT,
            );
            assert_eq!(result.is_ok(), sve == 0 && sme == 0);
            if sve != 0 {
                assert_eq!(
                    result,
                    Err(EntryProfileError::UnsupportedScalableState {
                        feature: "FEAT_SVE",
                        id_value: sve as u8,
                    })
                );
            } else if sme != 0 {
                assert_eq!(
                    result,
                    Err(EntryProfileError::UnsupportedScalableState {
                        feature: "FEAT_SME",
                        id_value: sme as u8,
                    })
                );
            }
        }
    }
}

#[test]
fn scalable_witness_does_not_claim_other_cpu_features_absent() {
    let other_pfr0_fields = !(ID_FIELD_MASK << PFR0_SVE_SHIFT);
    let other_pfr1_fields = !(ID_FIELD_MASK << PFR1_SME_SHIFT);
    assert_eq!(
        ScalableEntryAbsence::from_id_registers(other_pfr0_fields, other_pfr1_fields),
        Ok(no_scalable_state())
    );
}

#[test]
fn tagged_branch_and_debug_controls_must_be_checked_independently() {
    let profile =
        EntryProfile::base(SystemEntryFeatures::declared_absent(), no_scalable_state()).unwrap();
    for tbi in [TCR_TBI0, TCR_TBI1, TCR_TOP_BYTE_IGNORE_MASK] {
        assert_eq!(
            profile.check_controls(tbi, 0),
            Err(EntryProfileError::UnsupportedControl {
                register: "TCR_EL1",
                value: tbi,
            })
        );
    }
    for debug in [
        MDSCR_SOFTWARE_STEP,
        MDSCR_KERNEL_DEBUG_ENABLE,
        MDSCR_MONITOR_DEBUG_ENABLE,
        MDSCR_ACTIVE_DEBUG_MASK,
    ] {
        assert_eq!(
            profile.check_controls(0, debug),
            Err(EntryProfileError::UnsupportedControl {
                register: "MDSCR_EL1",
                value: debug,
            })
        );
    }
    assert_eq!(
        profile.check_controls(!TCR_TOP_BYTE_IGNORE_MASK, !MDSCR_ACTIVE_DEBUG_MASK),
        Ok(())
    );
}
