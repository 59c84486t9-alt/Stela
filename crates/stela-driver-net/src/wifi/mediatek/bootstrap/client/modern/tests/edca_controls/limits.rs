// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek EDCA limits fixtures.
use super::*;

#[test]
fn regulatory_limits_clamp_queue_bytes() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut driver, model, mut owner, state) = secure_modern();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let rules = core::array::from_fn(|index| WmmAc {
        cw_min: (1 << (5 + index)) - 1,
        cw_max: (1 << (8 + index)) - 1,
        aifsn: 7 + index as u8,
        cot_us: (31 + 31 * index as u16) * 32,
    });
    let limit = Wmm {
        client: rules,
        ap: rules,
    };
    update(&mut driver, &mut owner, Some(&limit)).unwrap();
    let mut expected = vec![0, 0, 4, 0];
    for record in [
        [0, 0, 12, 0, 0, 15, 5, 8, 31, 0, 7, 0],
        [0, 0, 12, 0, 1, 15, 6, 9, 62, 0, 8, 0],
        [0, 0, 12, 0, 2, 15, 7, 10, 0, 0, 9, 0],
        [0, 0, 12, 0, 3, 15, 8, 11, 0, 0, 10, 0],
    ] {
        expected.extend_from_slice(&record);
    }
    assert_eq!(bytes(&model), expected);
    assert_eq!(
        driver.applied_edca().unwrap().access_categories[3].txop_32us,
        31
    );
    let inspections = state.edca_inspections.borrow();
    assert_eq!(inspections.len(), 2);
    assert!(inspections[0].hardware);
    assert!(!inspections[1].hardware);
    for inspection in inspections.iter() {
        assert_eq!(inspection.count, 1);
        assert_eq!(
            inspection.observed,
            driver
                .modern_context()
                .unwrap()
                .negotiated()
                .wmm
                .as_ref()
                .unwrap()
                .access_categories
        );
        assert_eq!(
            inspection.effective,
            driver.applied_edca().unwrap().access_categories
        );
        assert_ne!(inspection.observed, inspection.effective);
    }
}
