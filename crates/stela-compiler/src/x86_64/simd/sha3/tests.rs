use super::*;
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn staging_cost_accounts_for_complete_state_access_and_immediate_specializations() {
    for (kind, expected_bytes) in [
        (Kind::Eor3 { third: 31 }, 40),
        (Kind::Bcax { third: 31 }, 40),
        (Kind::Rax1, 45),
        (Kind::Xar { rotation: 0 }, 28),
        (Kind::Xar { rotation: 16 }, 38),
        (Kind::Xar { rotation: 32 }, 33),
        (Kind::Xar { rotation: 48 }, 38),
        (Kind::Xar { rotation: 63 }, 46),
    ] {
        let mut code = Vec::new();
        emit(
            &mut code,
            &Operand {
                kind,
                destination: 31,
                left: 31,
                right: 31,
            },
        );
        assert_eq!(code.len(), expected_bytes, "{kind:?}");
        // MOVDQU is the only write and covers all of V31.
        let mut expected_store = vec![0xf3, 0x0f, 0x7f, 0x87];
        expected_store.extend(super::super::vector_offset(31).to_le_bytes());
        assert!(code.ends_with(&expected_store), "{kind:?}");
    }
}
