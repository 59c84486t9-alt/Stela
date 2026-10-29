// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Sole owning link frontends use the real key command and bounded notice path.
use super::*;

fn stop(link: &mut TestLink, model: &Model) {
    depart(link, model);
    // SAFETY: model removal ACK and independent RX/IRQ/work drain.
    unsafe { link.retire_peer_after_drain() }.unwrap();
    link.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    // SAFETY: independently quiesced whole modeled controller/DMA/IRQ.
    unsafe { link.stop_after_quiesce() }.unwrap();
}

#[test]
fn owning_live_igtk_rotation_preserves_buffered_notice_then_revokes_taken_envelope() {
    let (mut link, model, first, drops) = prepared();
    incoming(&model, &response(0x40c0, &[7, 0]), Some((1, 0, 9)), false);
    link.service().unwrap();
    assert_eq!(link.queues().notices, 1);
    let before = model.response.lock().unwrap().client_commands.len();
    assert!(matches!(
        // SAFETY: deliberate pending frontend user must refuse before publication.
        unsafe {
            link.rotate_management_key(&first, 5, &[0x66; 16], PacketNumber::new(200).unwrap())
        },
        Err(LinkControlError::Backpressure)
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(link.queues().notices, 1);
    let delayed = take_management(&mut link);
    // SAFETY: model users/queues and independent RX/IRQ fence drained;
    // taken observation is historical and consuming permission will be revoked.
    let second = unsafe {
        link.rotate_management_key(&first, 5, &[0x66; 16], PacketNumber::new(200).unwrap())
    }
    .unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(
        model.response.lock().unwrap().keys[&19],
        [vec![0x44; 16], vec![0x66; 16]].concat()
    );
    assert!(
        link.with_management(delayed, |_, _, _| panic!(
            "old frontend observation inherited rotation"
        ))
        .is_err()
    );
    incoming(&model, &response(0x40c0, &[7, 0]), Some((1, 0, 10)), false);
    link.service().unwrap();
    let current = take_management(&mut link);
    assert!(Arc::ptr_eq(current.session(), &second));
    assert_eq!(
        link.with_management(current, |_, _, pn| pn.value())
            .unwrap(),
        10
    );
    assert!(!link.carrier());
    stop(&mut link, &model);
    drop(link);
    drop(first);
    drop(second);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn owning_live_igtk_rotation_waits_for_released_tx_notice_and_exact_retry_is_effect_free() {
    let (mut link, model, first, drops) = prepared();
    link.transmit_management(&first, Transmit::SaQueryRequest([1, 2]))
        .unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    assert!(
        // SAFETY: pending real native TX makes the supposedly drained update refuse.
        unsafe {
            link.rotate_management_key(&first, 5, &[0x66; 16], PacketNumber::new(200).unwrap())
        }
        .is_err()
    );
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(finish_tx(&model).len(), 1);
    link.service().unwrap();
    assert_ne!(link.queues().notices, 0);
    assert!(matches!(
        // SAFETY: completed but kept frontend TX notice is still an old-key user.
        unsafe {
            link.rotate_management_key(&first, 5, &[0x66; 16], PacketNumber::new(200).unwrap())
        },
        Err(LinkControlError::Backpressure)
    ));
    drop(drain_notices(&mut link));
    // SAFETY: model TX-free/unmap and all native/frontend/external users drained.
    let second = unsafe {
        link.rotate_management_key(&first, 5, &[0x66; 16], PacketNumber::new(200).unwrap())
    }
    .unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    // SAFETY: exact retry in same independently drained model namespace.
    let retry = unsafe {
        link.rotate_management_key(&second, 4, &[0x55; 16], PacketNumber::new(0).unwrap())
    }
    .unwrap();
    assert!(Arc::ptr_eq(&retry, &second));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert!(!link.carrier());
    stop(&mut link, &model);
    drop(link);
    drop(first);
    drop(second);
    drop(retry);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}
