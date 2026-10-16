use super::*;

#[test]
fn id_availability_and_control_enable_remain_distinct() {
    let extended = NumericalFeatures::from_id_registers(
        BF16_EXTENDED << ISAR1_BF16_SHIFT,
        RPRES_IMPLEMENTED << ISAR2_RPRES_SHIFT,
        1 << SMFR0_FA64_SHIFT,
        true,
    )
    .unwrap();
    assert_eq!(extended, NumericalFeatures::new(true, true, true));
    let disabled = NumericalFeatures::from_id_registers(
        BF16_EXTENDED << ISAR1_BF16_SHIFT,
        RPRES_IMPLEMENTED << ISAR2_RPRES_SHIFT,
        1 << SMFR0_FA64_SHIFT,
        false,
    )
    .unwrap();
    assert_eq!(disabled, NumericalFeatures::new(false, true, true));
    let absent =
        NumericalFeatures::from_id_registers(BF16_STANDARD << ISAR1_BF16_SHIFT, 0, 0, true)
            .unwrap();
    assert_eq!(absent, NumericalFeatures::default());
    assert!(!absent.full_a64());
    assert!(!absent.ebf16());
    assert!(!absent.rpres());
}

#[test]
fn unrelated_id_bits_do_not_enable_numerical_capabilities() {
    let isar1 = !(ID_FIELD_MASK << ISAR1_BF16_SHIFT);
    let isar2 = !(ID_FIELD_MASK << ISAR2_RPRES_SHIFT);
    let smfr0 = !(1 << SMFR0_FA64_SHIFT);
    assert_eq!(
        NumericalFeatures::from_id_registers(isar1, isar2, smfr0, true),
        Some(NumericalFeatures::default())
    );
    for value in BF16_EXTENDED + 1..=ID_FIELD_MASK {
        assert!(
            NumericalFeatures::from_id_registers(value << ISAR1_BF16_SHIFT, 0, 0, false).is_none()
        );
    }
    for value in RPRES_IMPLEMENTED + 1..=ID_FIELD_MASK {
        assert!(
            NumericalFeatures::from_id_registers(0, value << ISAR2_RPRES_SHIFT, 0, false).is_none()
        );
    }
}
