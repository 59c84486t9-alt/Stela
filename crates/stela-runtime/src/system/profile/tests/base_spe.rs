use super::*;

#[test]
fn base_spe_absence_requires_exact_zero_and_preserves_unknown_values() {
    for version in 0..=ID_FIELD_MASK {
        let raw = version << DFR0_PMS_VERSION_SHIFT;
        let result = BaseSpeAbsence::from_id_aa64dfr0_el1(raw);
        if version == SPE_NOT_IMPLEMENTED {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err().pms_version, version as u8);
        }
    }
    // Unrelated ID fields do not stand in for PMSVer.
    assert!(
        BaseSpeAbsence::from_id_aa64dfr0_el1(!(ID_FIELD_MASK << DFR0_PMS_VERSION_SHIFT)).is_ok()
    );
}
