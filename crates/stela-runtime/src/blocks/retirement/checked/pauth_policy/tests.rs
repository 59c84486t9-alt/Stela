use super::*;
use stela_compiler::block::PointerAuthenticationModifier as Modifier;

const ADDRESS_SPACE: u64 = 1;
const ENABLE_ALL_KEYS: u64 = SCTLR_ENIA | SCTLR_ENIB | SCTLR_ENDA | SCTLR_ENDB;
const TAGGED_DATA_UNTAGGED_INSTRUCTIONS: u64 =
    TCR_VA47_T0SZ | TCR_TBI0 | TCR_TBI1 | TCR_TBID0 | TCR_TBID1;
const TEST_KEYS: [u64; 2] = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];

fn ids(apa: u64, api: u64, apa3: u64) -> Snapshot {
    Snapshot::declared(
        "retained-pauth-policy-software-test",
        &[
            (
                Register::IdAa64Isar1El1,
                (apa << APA_SHIFT) | (api << API_SHIFT),
            ),
            (Register::IdAa64Isar2El1, apa3 << APA3_SHIFT),
        ],
    )
    .unwrap()
}
fn context(version: pauth::Version) -> pauth::Context {
    pauth::Context::new_with_version(
        ADDRESS_SPACE,
        pauth::Keys::from_words(TEST_KEYS, TEST_KEYS, TEST_KEYS, TEST_KEYS),
        version,
    )
}
fn sign(key: Key) -> Op {
    Op::Sign {
        key,
        destination: 0,
        modifier: Modifier::Zero,
    }
}

#[test]
fn algorithm_tuple_and_actual_key_version_must_match() {
    for (apa, version) in [
        (APA_QARMA5_CLASSIC, pauth::Version::Classic),
        (
            APA_QARMA5_FAULTING_COMBINED,
            pauth::Version::FaultingCombined,
        ),
    ] {
        let context = context(version);
        assert!(
            qualify(
                &ids(apa, 0, 0),
                ENABLE_ALL_KEYS,
                TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                &context,
                Op::SignIbSp
            )
            .is_ok()
        );
        for other_apa in 0..=ID_FIELD_MASK {
            assert_eq!(
                qualify(
                    &ids(other_apa, 0, 0),
                    ENABLE_ALL_KEYS,
                    TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                    &context,
                    Op::SignIbSp
                )
                .is_ok(),
                other_apa == apa
            );
        }
        assert!(
            qualify(
                &ids(apa, 1, 0),
                ENABLE_ALL_KEYS,
                TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                &context,
                Op::SignIbSp
            )
            .is_err()
        );
        assert!(
            qualify(
                &ids(apa, 0, 1),
                ENABLE_ALL_KEYS,
                TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                &context,
                Op::SignIbSp
            )
            .is_err()
        );
    }
    let missing = Snapshot::declared(
        "missing-PAuth-ID",
        &[(Register::IdAa64Isar1El1, APA_QARMA5_CLASSIC << APA_SHIFT)],
    )
    .unwrap();
    assert!(
        qualify(
            &missing,
            ENABLE_ALL_KEYS,
            TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
            &context(pauth::Version::Classic),
            Op::SignIbSp
        )
        .is_err()
    );
}

#[test]
fn instruction_global_tbi_and_data_lower_tbi_are_distinct() {
    let ids = ids(APA_QARMA5_CLASSIC, 0, 0);
    let context = context(pauth::Version::Classic);
    for bits in 0..16 {
        let tbi0 = bits & 1 != 0;
        let tbi1 = bits & 2 != 0;
        let tbid0 = bits & 4 != 0;
        let tbid1 = bits & 8 != 0;
        let tcr = TCR_VA47_T0SZ
            | if tbi0 { TCR_TBI0 } else { 0 }
            | if tbi1 { TCR_TBI1 } else { 0 }
            | if tbid0 { TCR_TBID0 } else { 0 }
            | if tbid1 { TCR_TBID1 } else { 0 };
        for operation in [
            sign(Key::Ia),
            Op::Strip {
                data: false,
                destination: 0,
            },
        ] {
            assert_eq!(
                qualify(&ids, ENABLE_ALL_KEYS, tcr, &context, operation).is_ok(),
                (!tbi0 || tbid0) && (!tbi1 || tbid1)
            );
        }
        for operation in [
            sign(Key::Da),
            Op::Strip {
                data: true,
                destination: 0,
            },
        ] {
            assert_eq!(
                qualify(&ids, ENABLE_ALL_KEYS, tcr, &context, operation).is_ok(),
                tbi0
            );
        }
    }
    for t0sz in 0..=TCR_T0SZ_MASK {
        assert_eq!(
            qualify(&ids, ENABLE_ALL_KEYS, t0sz, &context, Op::SignIbSp).is_ok(),
            t0sz == TCR_VA47_T0SZ
        );
    }
}

#[test]
fn actual_enable_and_key_presence_are_required_while_strip_is_keyless() {
    let ids = ids(APA_QARMA5_CLASSIC, 0, 0);
    let context = context(pauth::Version::Classic);
    for (key, enable) in [
        (Key::Ia, SCTLR_ENIA),
        (Key::Ib, SCTLR_ENIB),
        (Key::Da, SCTLR_ENDA),
        (Key::Db, SCTLR_ENDB),
    ] {
        assert!(
            qualify(
                &ids,
                ENABLE_ALL_KEYS,
                TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                &context,
                sign(key)
            )
            .is_ok()
        );
        assert!(
            qualify(
                &ids,
                ENABLE_ALL_KEYS & !enable,
                TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                &context,
                sign(key)
            )
            .is_err()
        );
    }
    let ib_only = pauth::Context::new(
        ADDRESS_SPACE,
        pauth::Keys::from_ib_words(TEST_KEYS[0], TEST_KEYS[1]),
    );
    assert!(
        qualify(
            &ids,
            ENABLE_ALL_KEYS,
            TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
            &ib_only,
            sign(Key::Da)
        )
        .is_err()
    );
    for data in [false, true] {
        assert!(
            qualify(
                &ids,
                0,
                TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                &ib_only,
                Op::Strip {
                    data,
                    destination: 0
                }
            )
            .is_ok()
        );
    }
}

#[test]
fn actual_pointer_admission_is_read_only_and_keeps_signing_conservative() {
    const LOWER_VA47: u64 = (1 << 47) - 1;
    const TOP_BYTE_TAG: u64 = 0xa5 << 56;
    const UPPER_REGION: u64 = 1 << 55;
    let mut actual = stela_compiler::GuestState::default();
    for pointer in [0, LOWER_VA47, 1 << 47, TOP_BYTE_TAG | 0x1234, UPPER_REGION] {
        actual.x[0] = pointer;
        actual.x[30] = pointer;
        let before = actual.clone();
        for operation in [sign(Key::Ia), sign(Key::Da), Op::SignIbSp] {
            assert_eq!(
                qualify_pointer(operation, &actual).is_ok(),
                pointer <= LOWER_VA47
            );
        }
        for operation in [
            Op::Strip {
                data: true,
                destination: 0,
            },
            Op::Authenticate {
                key: Key::Da,
                destination: 0,
                modifier: Modifier::Zero,
            },
            Op::ReturnIbSp,
        ] {
            assert_eq!(
                qualify_pointer(operation, &actual).is_ok(),
                pointer & UPPER_REGION == 0
            );
        }
        assert_eq!(actual, before);
    }
    actual.x[0] = u64::MAX;
    assert!(
        qualify_pointer(
            Op::Sign {
                key: Key::Ia,
                destination: 31,
                modifier: Modifier::Zero
            },
            &actual
        )
        .is_ok()
    );
    assert!(
        qualify_pointer(
            Op::Strip {
                data: false,
                destination: 32
            },
            &actual
        )
        .is_err()
    );
}
