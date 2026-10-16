//! FEAT_PAuth_LR key configuration and cryptography.
use super::*;
use crate::{
    pauth::{Keys, Version},
    system::identification::Register,
};

const ADDRESS_SPACE: u64 = 0x243;
const POINTER: u64 = 0x1234;
const MODIFIER1: u64 = 0x1234_5678_9abc_def0;
const MODIFIER2: u64 = 0xfedc_ba98_7654_3210;
// Independent literal selection of June modifier2[36:5]::modifier1[35:4].
const PACKED: u64 = 0xc3b2_a190_89ab_cdef;
const CORRUPT_PAC: u64 = 1 << 47;

fn snapshot() -> Snapshot {
    Snapshot::declared(
        "explicit-lr-context-component-v1",
        &[
            (Register::IdAa64Isar1El1, 6 << 4),
            (Register::IdAa64Isar2El1, 0),
            (Register::IdAa64Isar3El1, 2 << 12),
        ],
    )
    .unwrap()
}
fn context(version: Version) -> Context {
    Context::new_with_version(
        ADDRESS_SPACE,
        Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]),
        version,
    )
}

#[test]
fn both_keys_borrow_canonical_context_and_same_snapshot_without_state_commit() {
    let ids = snapshot();
    let capability = LinkRegisterPauthCapability::from_profile(&ids).unwrap();
    let context = context(Version::FaultingCombined);
    let loan = LinkRegisterContext::new(&ids, ADDRESS_SPACE, &capability, &context).unwrap();
    assert!(loan.snapshot().same_snapshot(&ids));
    for key in [InstructionKey::A, InstructionKey::B] {
        for pointer in [
            0,
            POINTER,
            0x7fff_ffff_ffff,
            0xffff_8000_0000_1234,
            u64::MAX,
        ] {
            let signed = loan.sign(key, pointer, MODIFIER1, MODIFIER2).unwrap();
            assert_eq!(signed, context.sign(key.key(), pointer, PACKED).unwrap());
            for kind in [AuthenticationKind::Standalone, AuthenticationKind::Return] {
                assert_eq!(
                    loan.authenticate(key, signed, MODIFIER1, MODIFIER2, kind),
                    Ok(AuthResult {
                        pointer,
                        authenticated: true
                    })
                );
                assert_eq!(
                    loan.authenticate(key, signed ^ CORRUPT_PAC, MODIFIER1, MODIFIER2, kind),
                    Err(Error::Authentication(AuthenticationError::Failure {
                        code: u8::from(key == InstructionKey::B)
                    }))
                );
            }
        }
    }
}

#[test]
fn equal_readbacks_from_a_foreign_snapshot_never_gain_the_loan() {
    let ids = snapshot();
    let foreign = snapshot();
    let capability = LinkRegisterPauthCapability::from_profile(&ids).unwrap();
    let context = context(Version::FaultingCombined);
    assert!(matches!(
        LinkRegisterContext::new(&foreign, ADDRESS_SPACE, &capability, &context),
        Err(Error::WrongSnapshot)
    ));
}

#[test]
fn foreign_address_space_and_old_policy_decline_before_crypto() {
    let ids = snapshot();
    let capability = LinkRegisterPauthCapability::from_profile(&ids).unwrap();
    let valid = context(Version::FaultingCombined);
    assert!(matches!(
        LinkRegisterContext::new(&ids, ADDRESS_SPACE + 1, &capability, &valid),
        Err(Error::WrongAddressSpace)
    ));
    for version in [Version::Classic, Version::Enhanced, Version::Faulting] {
        let wrong = context(version);
        assert!(matches!(
            LinkRegisterContext::new(&ids, ADDRESS_SPACE, &capability, &wrong),
            Err(Error::WrongVersion)
        ));
    }
}

#[test]
fn absent_selected_key_is_configuration_and_never_a_zero_key() {
    let ids = snapshot();
    let capability = LinkRegisterPauthCapability::from_profile(&ids).unwrap();
    let context = Context::new_with_version(
        ADDRESS_SPACE,
        Keys::from_ib_words(3, 4),
        Version::FaultingCombined,
    );
    let loan = LinkRegisterContext::new(&ids, ADDRESS_SPACE, &capability, &context).unwrap();
    let expected = Error::Configuration(TwoModifierError::KeyUnavailable { key: Key::Ia });
    assert_eq!(
        loan.sign(InstructionKey::A, POINTER, MODIFIER1, MODIFIER2),
        Err(expected)
    );
    for kind in [AuthenticationKind::Standalone, AuthenticationKind::Return] {
        assert_eq!(
            loan.authenticate(InstructionKey::A, POINTER, MODIFIER1, MODIFIER2, kind),
            Err(expected)
        );
    }
    assert!(
        loan.sign(InstructionKey::B, POINTER, MODIFIER1, MODIFIER2)
            .is_ok()
    );
}

#[test]
fn old_algorithm_snapshot_cannot_create_lr_capability() {
    let ids = Snapshot::declared(
        "explicit-old-pauth-component-v1",
        &[
            (Register::IdAa64Isar1El1, 5 << 4),
            (Register::IdAa64Isar2El1, 0),
        ],
    )
    .unwrap();
    assert!(LinkRegisterPauthCapability::from_profile(&ids).is_err());
}
