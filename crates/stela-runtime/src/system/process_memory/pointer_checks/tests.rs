use super::*;

fn ids(feature: u64, additional: &[(Register, u64)]) -> Snapshot {
    let mut entries = vec![(Register::IdAa64Isar3El1, feature)];
    entries.extend_from_slice(additional);
    Snapshot::declared("CPA-resolution-source-component", &entries).unwrap()
}

#[test]
fn early_off_does_not_read_missing_debug_regime_or_extended_controls() {
    for feature in [CPA_ABSENT, CPA_ARITHMETIC] {
        let snapshot = ids(u64::from(feature), &[]);
        assert_eq!(
            resolve(&snapshot, None, None),
            Ok(ResolvedPointerChecks::unchecked(
                CpaFeature::from_raw(u64::from(feature)).unwrap()
            ))
        );
    }
    assert!(matches!(
        resolve(&ids(u64::from(CPA_CHECKED), &[]), None, None),
        Err(Error::ActualDebugRequired)
    ));
}

#[test]
fn halted_early_off_precedes_missing_regime_but_running_cannot_guess_it() {
    let snapshot = ids(u64::from(CPA_CHECKED), &[]);
    let debug = DebugControls {
        halted: true,
        ..Default::default()
    };
    assert_eq!(
        resolve(&snapshot, Some(&debug), None),
        Ok(ResolvedPointerChecks::unchecked(CpaFeature::Checked))
    );
    assert!(matches!(
        resolve(&snapshot, Some(&DebugControls::default()), None),
        Err(Error::Identification(Unsupported::MissingRegister(
            Register::IdAa64Pfr0El1
        )))
    ));
}

#[test]
fn absent_sctlr2_is_a_source_fact_and_present_sctlr2_requires_original_bank() {
    const A64_EL10_NO_HIGHER_EL: u64 = 0x11;
    let debug = DebugControls::default();
    for (sctlrx, expected) in [
        (
            SCTLR2_ABSENT,
            Ok(ResolvedPointerChecks::unchecked(CpaFeature::Checked)),
        ),
        (SCTLR2_PRESENT, Err(Error::ActualExtendedControlsRequired)),
    ] {
        let snapshot = ids(
            u64::from(CPA_CHECKED),
            &[
                (Register::IdAa64Pfr0El1, A64_EL10_NO_HIGHER_EL),
                (
                    Register::IdAa64Mmfr3El1,
                    u64::from(sctlrx) << MMFR3_SCTLRX_SHIFT,
                ),
            ],
        );
        assert_eq!(resolve(&snapshot, Some(&debug), None), expected);
    }
}
