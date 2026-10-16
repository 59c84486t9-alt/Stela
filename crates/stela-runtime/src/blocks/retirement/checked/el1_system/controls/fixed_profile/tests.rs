use super::super::El1PlatformControls;
use super::*;
use crate::blocks::retirement::checked::software_el1::{
    SoftwareEl1Declaration, SoftwareEl1Security,
};
use std::sync::Arc;

fn fields() -> Vec<(Register, u64)> {
    let base = El1PlatformControls::declared_base().unwrap();
    [
        Register::IdAa64Pfr0El1,
        Register::IdAa64Pfr1El1,
        Register::IdAa64Pfr2El1,
        Register::IdAa64Dfr0El1,
        Register::IdAa64Dfr1El1,
        Register::IdAa64Mmfr0El1,
        Register::IdAa64Mmfr1El1,
        Register::IdAa64Mmfr2El1,
        Register::IdAa64Isar1El1,
        Register::IdAa64Isar2El1,
        Register::IdAa64Isar3El1,
    ]
    .into_iter()
    .map(|register| (register, base.identification().read(register).unwrap()))
    .collect()
}

#[test]
fn fixed_consumer_refuses_every_mismatched_consumed_field() {
    for field in FIXED_CONTROL_FIELDS {
        for value in 0..=ID_FIELD_MASK {
            let mut fields = fields();
            let raw = &mut fields
                .iter_mut()
                .find(|(register, _)| *register == field.register)
                .unwrap()
                .1;
            *raw = (*raw & !(ID_FIELD_MASK << field.shift)) | (value << field.shift);
            let original = Snapshot::declared("fixed-control-field-boundary", &fields).unwrap();
            assert_eq!(
                check(&original).is_ok(),
                value == field.value,
                "{}={value}",
                field.name
            );
            let declaration =
                SoftwareEl1Declaration::new(Arc::new(original), SoftwareEl1Security::NonSecureOnly)
                    .unwrap();
            assert_eq!(
                El1PlatformControls::from_declaration(declaration).is_ok(),
                value == field.value,
                "constructor {}={value}",
                field.name
            );
        }
    }
}

#[test]
fn constructor_preserves_same_snapshot_xs_and_unrelated_fields() {
    let mut fields = fields();
    let isar1 = &mut fields
        .iter_mut()
        .find(|(register, _)| *register == Register::IdAa64Isar1El1)
        .unwrap()
        .1;
    // XS present and an unrelated SB field are kept as facts; they do not
    // change controls or enable a service.
    *isar1 = (1 << 56) | (1 << 36);
    let original = Arc::new(Snapshot::declared("fixed-control-xs-opaque-fields", &fields).unwrap());
    let declaration =
        SoftwareEl1Declaration::new(Arc::clone(&original), SoftwareEl1Security::NonSecureOnly)
            .unwrap();
    let controls = El1PlatformControls::from_declaration(declaration).unwrap();
    assert!(controls.identification().same_snapshot(&original));
    assert_eq!(
        controls
            .identification()
            .read(Register::IdAa64Isar1El1)
            .unwrap(),
        (1 << 56) | (1 << 36)
    );
}

#[test]
fn constructor_refuses_pauth_and_missing_fixed_memory_readback() {
    for apa in [1_u64, 5] {
        let mut fields = fields();
        fields
            .iter_mut()
            .find(|(register, _)| *register == Register::IdAa64Isar1El1)
            .unwrap()
            .1 = apa << 4;
        let original = Arc::new(Snapshot::declared("fixed-control-no-key-owner", &fields).unwrap());
        let declaration =
            SoftwareEl1Declaration::new(original, SoftwareEl1Security::NonSecureOnly).unwrap();
        let error = El1PlatformControls::from_declaration(declaration)
            .err()
            .unwrap();
        assert!(error.to_string().contains("APA"));
    }
    for missing in [
        Register::IdAa64Mmfr0El1,
        Register::IdAa64Isar1El1,
        Register::IdAa64Isar2El1,
    ] {
        let mut fields = fields();
        fields.retain(|(register, _)| *register != missing);
        let original =
            Arc::new(Snapshot::declared("fixed-control-missing-consumed-facts", &fields).unwrap());
        let declaration =
            SoftwareEl1Declaration::new(original, SoftwareEl1Security::NonSecureOnly).unwrap();
        let error = El1PlatformControls::from_declaration(declaration)
            .err()
            .unwrap();
        assert!(error.to_string().contains(&format!("{missing:?}")));
    }
}
