use super::*;
use crate::system::profile::{EntryProfile, ScalableEntryAbsence, SystemEntryFeatures};

const IDENTITY: &str = "declared-bounded-el01-auth2-test";
const APA_SHIFT: u32 = 4;
const API_SHIFT: u32 = 8;
const APA3_SHIFT: u32 = 12;
const APA_FAULTING_COMBINED: u64 = 5;
const A64_EL0_EL1_NO_HIGHER_EL: u64 = 0x11;
const FIELD_MAX: u64 = 0xf;
const PFAR_SHIFT: u32 = 60;
const REGISTER_VALUE_BYTES: usize = std::mem::size_of::<u64>();

fn entries() -> Vec<(Register, u64)> {
    vec![
        (Register::IdAa64Isar1El1, APA_FAULTING_COMBINED << APA_SHIFT),
        (Register::IdAa64Isar2El1, 0),
        (Register::IdAa64Pfr0El1, A64_EL0_EL1_NO_HIGHER_EL),
        (Register::IdAa64Pfr1El1, 0),
        (Register::IdAa64Pfr2El1, 0),
        (Register::IdAa64Dfr0El1, 0),
        (Register::IdAa64Dfr1El1, 0),
        (Register::IdAa64Mmfr0El1, 0),
        (Register::IdAa64Mmfr1El1, 0),
        (Register::IdAa64Mmfr2El1, 0),
        (Register::IdAa64Mmfr3El1, 0),
    ]
}
fn replace(entries: &mut [(Register, u64)], register: Register, value: u64) {
    entries
        .iter_mut()
        .find(|(candidate, _)| *candidate == register)
        .unwrap()
        .1 = value;
}

#[test]
fn partial_readbacks_are_exact_and_missing_never_becomes_zero() {
    let snapshot = Snapshot::declared(IDENTITY, &[(Register::IdAa64Isar1El1, u64::MAX)]).unwrap();
    assert_eq!(snapshot.read(Register::IdAa64Isar1El1), Ok(u64::MAX));
    assert_eq!(
        snapshot.read(Register::IdAa64Isar2El1),
        Err(Unsupported::MissingRegister(Register::IdAa64Isar2El1))
    );
    assert_eq!(
        Readbacks::readback(&snapshot, Readback::Register(Register::IdAa64Isar1El1)),
        Some(u64::MAX)
    );
    assert_eq!(
        Readbacks::readback(&snapshot, Readback::Register(Register::IdAa64Isar2El1)),
        None
    );
    assert_eq!(Readbacks::readback(&snapshot, Readback::DynamicDczid), None);
    assert_eq!(
        Readbacks::readback(&snapshot, Readback::SelectedCache(Register::CcsidrEl1)),
        None
    );
    assert_eq!(snapshot.provenance().origin(), Origin::DeclaredGuest);
}

#[test]
fn duplicate_dynamic_and_ambiguous_machine_identity_initialization_rejects() {
    assert!(matches!(
        Snapshot::declared(
            IDENTITY,
            &[(Register::IdAa64Pfr0El1, 0), (Register::IdAa64Pfr0El1, 1)]
        ),
        Err(InitializationError::DuplicateRegister(_))
    ));
    assert!(matches!(
        Snapshot::declared(IDENTITY, &[(Register::CsselrEl1, 0)]),
        Err(InitializationError::UnownedRegister(Register::CsselrEl1))
    ));
    assert!(matches!(
        Snapshot::declared("", &[]),
        Err(InitializationError::EmptyIdentity)
    ));
    assert!(matches!(
        Snapshot::declared("ambiguous\0machine", &[]),
        Err(InitializationError::EmbeddedIdentityNul)
    ));
}

#[test]
fn declaration_digest_binds_named_values_and_identity_without_order_dependence() {
    let forward = entries();
    let mut reverse = forward.clone();
    reverse.reverse();
    let first = Snapshot::declared(IDENTITY, &forward).unwrap();
    let same_values = Snapshot::declared(IDENTITY, &reverse).unwrap();
    assert_eq!(
        first.provenance().input_sha256(),
        same_values.provenance().input_sha256()
    );
    assert!(!first.same_snapshot(&same_values));
    assert!(first.same_snapshot(&first));
    let other_machine = Snapshot::declared("another-declared-machine", &forward).unwrap();
    assert_ne!(
        first.provenance().input_sha256(),
        other_machine.provenance().input_sha256()
    );
    let mut changed = forward;
    replace(&mut changed, Register::IdAa64Isar2El1, 1);
    let changed = Snapshot::declared(IDENTITY, &changed).unwrap();
    assert_ne!(
        first.provenance().input_sha256(),
        changed.provenance().input_sha256()
    );
}

#[test]
fn captured_readbacks_are_extracted_from_and_retain_actual_immutable_input() {
    let mut bytes = Vec::new();
    bytes.extend(0x0123_4567_89ab_cdef_u64.to_le_bytes());
    bytes.extend(u64::MAX.to_le_bytes());
    let input: Arc<[u8]> = bytes.into();
    let fields = [
        (Register::IdAa64Isar1El1, 0),
        (Register::IdAa64Isar2El1, REGISTER_VALUE_BYTES),
    ];
    let snapshot = Snapshot::captured(
        "verified-acquisition-fixture-not-hardware-proof",
        Arc::clone(&input),
        &fields,
    )
    .unwrap();
    assert_eq!(
        snapshot.read(Register::IdAa64Isar1El1),
        Ok(0x0123_4567_89ab_cdef)
    );
    assert_eq!(snapshot.read(Register::IdAa64Isar2El1), Ok(u64::MAX));
    assert_eq!(snapshot.provenance().origin(), Origin::CapturedHardware);
    assert_eq!(snapshot.provenance().input(), input.as_ref());
    assert_eq!(snapshot.provenance().input_sha256(), crate::sha256(&input));
    assert_eq!(snapshot.provenance().captured_fields(), fields);
    assert!(Arc::ptr_eq(&input, &snapshot.provenance.input));
    assert!(matches!(
        Snapshot::captured(
            "fixture",
            Arc::clone(&input),
            &[(Register::IdAa64Isar1El1, usize::MAX)]
        ),
        Err(InitializationError::CaptureBounds { .. })
    ));
    assert!(matches!(
        Snapshot::captured(
            "fixture",
            input,
            &[
                (Register::IdAa64Isar1El1, 0),
                (Register::IdAa64Isar1El1, REGISTER_VALUE_BYTES)
            ]
        ),
        Err(InitializationError::DuplicateRegister(_))
    ));
}

#[test]
fn entry_spe_and_regime_qualifiers_consume_the_same_explicit_named_readbacks() {
    let snapshot = Snapshot::declared(IDENTITY, &entries()).unwrap();
    let expected = EntryProfile::base(
        SystemEntryFeatures::declared_absent(),
        ScalableEntryAbsence::from_id_registers(A64_EL0_EL1_NO_HIGHER_EL, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(snapshot.entry_profile(), Ok(expected));
    assert_eq!(snapshot.check_entry_profile(expected), Ok(()));
    assert!(snapshot.base_spe_absence().is_ok());
    assert_eq!(snapshot.check_base_el10_4k(), Ok(()));
    for missing in [
        Register::IdAa64Isar2El1,
        Register::IdAa64Pfr0El1,
        Register::IdAa64Dfr0El1,
    ] {
        let mut partial = entries();
        partial.retain(|(register, _)| *register != missing);
        assert_eq!(
            Snapshot::declared(IDENTITY, &partial)
                .unwrap()
                .entry_profile(),
            Err(Unsupported::MissingRegister(missing))
        );
    }
}

#[test]
fn invalid_higher_el_granule_d128_and_spe_facts_never_mint_absence() {
    for (register, shift) in [
        (Register::IdAa64Pfr0El1, 8),
        (Register::IdAa64Pfr0El1, 12),
        (Register::IdAa64Mmfr0El1, 28),
        (Register::IdAa64Mmfr3El1, 32),
    ] {
        for value in 1..=FIELD_MAX {
            let mut raw = entries();
            let prior = raw
                .iter()
                .find(|(candidate, _)| *candidate == register)
                .unwrap()
                .1;
            replace(
                &mut raw,
                register,
                (prior & !(FIELD_MAX << shift)) | (value << shift),
            );
            assert!(
                Snapshot::declared(IDENTITY, &raw)
                    .unwrap()
                    .check_base_el10_4k()
                    .is_err()
            );
        }
    }
    for value in 1..=FIELD_MAX {
        let mut raw = entries();
        replace(&mut raw, Register::IdAa64Dfr0El1, value << 32);
        let snapshot = Snapshot::declared(IDENTITY, &raw).unwrap();
        assert!(snapshot.base_spe_absence().is_err());
        assert!(snapshot.entry_profile().is_err());
    }
    let mut raw = entries();
    replace(&mut raw, Register::IdAa64Pfr0El1, 0);
    assert!(
        Snapshot::declared(IDENTITY, &raw)
            .unwrap()
            .entry_profile()
            .is_err()
    );
}

#[test]
fn doublefault_sve_sme_and_pauth_lr_are_not_inferred_from_unrelated_absences() {
    for (register, shift, value) in [
        (Register::IdAa64Pfr0El1, 28, 2),
        (Register::IdAa64Pfr0El1, 32, 1),
        (Register::IdAa64Pfr1El1, 24, 1),
        (Register::IdAa64Isar1El1, APA_SHIFT, 6),
        (Register::IdAa64Isar1El1, API_SHIFT, 1),
        (Register::IdAa64Isar2El1, APA3_SHIFT, 1),
    ] {
        let mut raw = entries();
        let prior = raw
            .iter()
            .find(|(candidate, _)| *candidate == register)
            .unwrap()
            .1;
        replace(
            &mut raw,
            register,
            (prior & !(FIELD_MAX << shift)) | (value << shift),
        );
        assert!(
            Snapshot::declared(IDENTITY, &raw)
                .unwrap()
                .entry_profile()
                .is_err()
        );
    }
}

#[test]
fn opaque_unrelated_fields_are_preserved_and_invalid_mte_fraction_not_interpreted() {
    let mut raw = entries();
    // Under primary MTE=0, MTE_frac/MTEX are invalid and not absence indicators.
    let opaque = (FIELD_MAX << 40) | (FIELD_MAX << 52);
    replace(&mut raw, Register::IdAa64Pfr1El1, opaque);
    let snapshot = Snapshot::declared(IDENTITY, &raw).unwrap();
    assert_eq!(snapshot.read(Register::IdAa64Pfr1El1), Ok(opaque));
    assert!(snapshot.entry_profile().is_ok());
}

#[test]
fn pfar_absence_requires_a_named_readback_and_rejects_present_or_reserved_values() {
    let mut raw = entries();
    raw.retain(|(register, _)| *register != Register::IdAa64Pfr1El1);
    let missing = Snapshot::declared(IDENTITY, &raw).unwrap();
    assert_eq!(
        missing.entry_profile(),
        Err(Unsupported::MissingRegister(Register::IdAa64Pfr1El1))
    );
    assert_eq!(
        Readbacks::readback(&missing, Readback::Register(Register::IdAa64Pfr1El1)),
        None
    );

    let absent = Snapshot::declared(IDENTITY, &entries()).unwrap();
    let profile = absent.entry_profile().unwrap();
    assert_eq!(absent.check_entry_profile(profile), Ok(()));
    for value in 1..=FIELD_MAX {
        let mut raw = entries();
        let pfr1 = value << PFAR_SHIFT;
        replace(&mut raw, Register::IdAa64Pfr1El1, pfr1);
        let snapshot = Snapshot::declared(IDENTITY, &raw).unwrap();
        assert_eq!(snapshot.read(Register::IdAa64Pfr1El1), Ok(pfr1));
        assert_eq!(
            Readbacks::readback(&snapshot, Readback::Register(Register::IdAa64Pfr1El1)),
            Some(pfr1)
        );
        let expected = Err(Unsupported::Field {
            register: Register::IdAa64Pfr1El1,
            field: "PFAR",
            value: value as u8,
        });
        assert_eq!(snapshot.entry_profile(), expected);
        assert_eq!(snapshot.check_entry_profile(profile), expected.map(|_| ()));
    }
}

#[test]
fn classic_qarma5_tuple_preserves_the_bounded_entry_absence_contract() {
    const APA_QARMA5_CLASSIC: u64 = 1;
    let mut raw = entries();
    replace(
        &mut raw,
        Register::IdAa64Isar1El1,
        APA_QARMA5_CLASSIC << APA_SHIFT,
    );
    let classic = Snapshot::declared(IDENTITY, &raw).unwrap();
    assert_eq!(
        classic.entry_profile(),
        Snapshot::declared(IDENTITY, &entries())
            .unwrap()
            .entry_profile()
    );
    for (register, shift) in [
        (Register::IdAa64Isar1El1, API_SHIFT),
        (Register::IdAa64Isar2El1, APA3_SHIFT),
    ] {
        let mut invalid = raw.clone();
        let value = invalid
            .iter()
            .find(|(candidate, _)| *candidate == register)
            .unwrap()
            .1
            | (1 << shift);
        replace(&mut invalid, register, value);
        assert!(
            Snapshot::declared(IDENTITY, &invalid)
                .unwrap()
                .entry_profile()
                .is_err()
        );
    }
}
