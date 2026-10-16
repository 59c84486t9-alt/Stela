use super::*;

mod pstate_immediate;
mod register_access;

#[test]
fn every_checked_field_tuple_has_a_unique_selector() {
    let mut seen = [false; SELECTOR_COUNT];
    for op0 in 0..=OP0_MASK {
        for op1 in 0..=OP1_MASK {
            for crn in 0..=CRN_MASK {
                for crm in 0..=CRM_MASK {
                    for op2 in 0..=OP2_MASK {
                        let selector = Encoding::new(op0, op1, crn, crm, op2).selector();
                        assert!(!core::mem::replace(&mut seen[usize::from(selector)], true));
                    }
                }
            }
        }
    }
    assert!(seen.into_iter().all(|present| present));
}

#[test]
fn overwide_fields_fail_instead_of_aliasing_another_encoding() {
    for fields in [
        (4, 0, 0, 0, 0),
        (0, 8, 0, 0, 0),
        (0, 0, 16, 0, 0),
        (0, 0, 0, 16, 0),
        (0, 0, 0, 0, 8),
    ] {
        assert!(
            std::panic::catch_unwind(|| Encoding::new(
                fields.0, fields.1, fields.2, fields.3, fields.4
            ))
            .is_err()
        );
    }
}
