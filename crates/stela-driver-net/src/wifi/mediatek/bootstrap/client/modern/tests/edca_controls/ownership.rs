// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek EDCA ownership fixtures.
use super::*;

#[test]
fn update_keeps_outstanding_packet() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut driver, model, mut owner, state) = secure_modern();
    let permit = admit(&mut owner, &driver, AssociationUse::Data);
    let epoch = driver.station().association_epoch().unwrap();
    // SAFETY: The current association/key epoch and native owners remain held
    // under fresh data guards. The frame is borrowed only for submission; its queued
    // DMA owner survives the later independent EDCA update.
    unsafe {
        driver.transmit_modern(
            &mut owner,
            permit,
            epoch,
            Msdu {
                ethernet: &eth(0x0800),
                class: TxClass::Data,
                tid: Some(6),
            },
            &GuardedSource(state),
            &mut Policy(true),
        )
    }
    .unwrap();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    update(&mut driver, &mut owner, None).unwrap();
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 1);
    assert_eq!(driver.phase(), ClientPhase::Associated);
    assert_eq!(finish_tx(&model).len(), 1);
    driver.poll(NOW + 1, &Source, &mut Policy(true)).unwrap();
    let released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].context.association_epoch(), epoch);
}

#[test]
fn uncertain_ack_quarantines_owner() {
    if crate::test_process::isolate_model() {
        return;
    }
    for failure in 0..3 {
        let (mut driver, model, mut owner, _) = secure_modern();
        let context = driver.modern_context().unwrap().clone();
        let old = *driver.applied_edca().unwrap();
        let frame = beacon(&driver, 1, |_| {});
        observe(&mut driver, &model, &frame).unwrap();
        let before = commands(&model);
        match failure {
            0 => model.response.lock().unwrap().edca_status = Some(0xbad),
            1 => model.response.lock().unwrap().pause_next_index_us = 3_100_000,
            _ => model.response.lock().unwrap().command_delta = 1, // Unmatched ACK.
        }
        assert!(update(&mut driver, &mut owner, None).is_err());
        assert_eq!(commands(&model), before + 1);
        assert_eq!(driver.phase(), ClientPhase::Quarantined);
        assert_eq!(*driver.applied_edca().unwrap(), old);
        assert!(driver.pending_edca());
        assert!(Arc::ptr_eq(driver.modern_context().unwrap(), &context));
        let count = commands(&model);
        assert!(update(&mut driver, &mut owner, None).is_err());
        assert_eq!(commands(&model), count);
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
}

#[test]
fn update_preserves_pending_block_ack() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut driver, model, mut owner, _) = secure_modern();
    let parameters: u16 = 1 | 2 | (6 << 2) | (8 << 6);
    let mut body = vec![3, 0, 7];
    body.extend_from_slice(&parameters.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(17u16 << 4).to_le_bytes());
    incoming(&model, &response(0xd0, &body), None, false);
    driver.poll(NOW - 1, &Source, &mut Policy(true)).unwrap();
    assert!(driver.pending_block_ack());
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let before = commands(&model);
    update(&mut driver, &mut owner, None).unwrap();
    assert_eq!(commands(&model), before + 1);
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 1);
    assert!(!driver.pending_edca());
    assert!(driver.pending_block_ack());
    assert_eq!(driver.phase(), ClientPhase::Associated);
}
