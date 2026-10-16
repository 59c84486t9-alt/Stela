use super::*;

#[test]
fn xs_preserves_unrelated_raw_fields_and_refuses_reserved_encodings() {
    let opaque = !(ID_FIELD_MASK << XS_SHIFT);
    for value in XS_ABSENT..=ID_FIELD_MASK as u8 {
        let raw = opaque | (u64::from(value) << XS_SHIFT);
        let original =
            Snapshot::declared("xs-field-test", &[(Register::IdAa64Isar1El1, raw)]).unwrap();
        match value {
            XS_ABSENT => assert_eq!(original.xs(), Ok(Xs::Absent)),
            XS_IMPLEMENTED => assert_eq!(original.xs(), Ok(Xs::Present)),
            _ => assert_eq!(
                original.xs(),
                Err(Unsupported::Field {
                    register: Register::IdAa64Isar1El1,
                    field: "XS",
                    value,
                })
            ),
        }
        assert_eq!(original.read(Register::IdAa64Isar1El1), Ok(raw));
    }
}

#[test]
fn missing_xs_readback_never_becomes_feature_absence() {
    let original = Snapshot::declared("xs-missing-test", &[(Register::IdAa64Isar2El1, 0)]).unwrap();
    assert_eq!(
        original.xs(),
        Err(Unsupported::MissingRegister(Register::IdAa64Isar1El1))
    );
}
