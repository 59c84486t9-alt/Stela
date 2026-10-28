// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek EDCA observations fixtures.
use super::*;

#[test]
fn associated_native_beacon_applies_new_baseline_only_after_actual_ack_and_dma() {
    let (mut driver, model, mut owner, state) = secure_modern();
    let context = driver.modern_context().unwrap().clone();
    let original = context.negotiated().clone();
    let old = *driver.applied_edca().unwrap();
    let frame = beacon(&driver, 1, |w| {
        // A valid later AP may relax earlier queues; original negotiation is
        // not the baseline against which a current regulatory clamp is checked.
        w[8] = 2;
        w[9] = 0x52;
        w[10..12].copy_from_slice(&100u16.to_le_bytes());
    });
    let before = commands(&model);
    let events = observe(&mut driver, &model, &frame).unwrap();
    assert!(matches!(events.as_slice(), [Event::Raw(_)]));
    assert!(driver.pending_edca());
    assert_eq!(*driver.applied_edca().unwrap(), old);
    assert_eq!(commands(&model), before);
    update(&mut driver, &mut owner, None).unwrap();
    assert_eq!(commands(&model), before + 1);
    let mut expected = vec![0, 0, 4, 0];
    for record in [
        [0, 0, 12, 0, 0, 15, 2, 3, 47, 0, 2, 0],
        [0, 0, 12, 0, 1, 15, 3, 4, 94, 0, 2, 0],
        [0, 0, 12, 0, 2, 15, 2, 5, 100, 0, 2, 0],
        [0, 0, 12, 0, 3, 15, 4, 10, 0, 0, 7, 0],
    ] {
        expected.extend_from_slice(&record);
    }
    assert_eq!(bytes(&model), expected);
    assert_eq!(driver.phase(), ClientPhase::Associated);
    assert!(!driver.pending_edca());
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 1);
    assert_eq!(
        driver.applied_edca().unwrap().access_categories[0].txop_32us,
        100
    );
    assert!(Arc::ptr_eq(driver.modern_context().unwrap(), &context));
    assert_eq!(context.negotiated(), &original);
    assert!(
        state
            .windows
            .borrow()
            .iter()
            .any(|&(a, b)| a == before && b == before + 1)
    );
    let reply = driver.replies().last().unwrap();
    assert_eq!(reply.status, 0);
    assert!(reply.dma_released);
    assert!(
        driver
            .state()
            .controller
            .state()
            .mailbox
            .as_ref()
            .unwrap()
            .receive_idle()
    );
}

#[test]
fn beacon_admission_control_changes_apply_like_ieee80211_sta_wmm_params() {
    let (mut driver, model, mut owner, _) = secure_modern();
    let frame = beacon(&driver, 1, |w| {
        for record in (8..24).step_by(4) {
            w[record] |= 0x10;
        }
    });
    observe(&mut driver, &model, &frame).unwrap();
    update(&mut driver, &mut owner, None).unwrap();
    let applied = driver.applied_edca().unwrap();
    assert!(
        applied
            .access_categories
            .iter()
            .all(|ac| ac.admission_control)
    );
}

#[test]
fn unchanged_count_and_four_bit_wrap_use_source_equality_not_ordering() {
    let (mut driver, model, mut owner, _) = secure_modern();
    let before = commands(&model);
    let frame = beacon(&driver, 0, |w| w[9] = 0x52);
    observe(&mut driver, &model, &frame).unwrap();
    assert!(!driver.pending_edca());
    assert_eq!(commands(&model), before);
    for count in [15, 0, 7, 2] {
        let frame = beacon(&driver, count, |_| {});
        observe(&mut driver, &model, &frame).unwrap();
        assert!(driver.pending_edca());
        update(&mut driver, &mut owner, None).unwrap();
        assert_eq!(driver.applied_edca().unwrap().parameter_set_count, count);
    }
    let frame = beacon(&driver, 2, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    assert!(!driver.pending_edca());
    assert_eq!(commands(&model), before + 4);
}

#[test]
fn latest_completed_native_observation_replaces_only_unpublished_cpu_update() {
    let (mut driver, model, mut owner, _) = secure_modern();
    let before = commands(&model);
    for count in [1, 2] {
        let frame = beacon(&driver, count, |w| {
            w[10..12].copy_from_slice(&(u16::from(count) * 10).to_le_bytes())
        });
        observe(&mut driver, &model, &frame).unwrap();
    }
    assert_eq!(commands(&model), before);
    update(&mut driver, &mut owner, None).unwrap();
    assert_eq!(commands(&model), before + 1);
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 2);
    assert_eq!(
        driver.applied_edca().unwrap().access_categories[0].txop_32us,
        20
    );
}
