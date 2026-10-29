// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Sole-owning frontend over actual modeled scan/association/key/DMA commands.
use super::*;
use crate::net::wifi::mediatek::bootstrap::client::management::{Received, Session, Transmit};

fn prepared() -> (TestLink, Model, Arc<Session>, Arc<AtomicUsize>) {
    let (mut link, model, join, bss, drops) = setup_link();
    associate(&mut link, &model, join, bss);
    link.install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
        .unwrap();
    link.install_key(false, 2, &[0x44; 16], ReplaySeed::ZERO)
        .unwrap();
    let epoch = link.station().association_epoch().unwrap();
    // Association/scan/release notices are actual retained old-key users, so the
    // owning frontend must refuse initial installation until they are consumed.
    let before = model.response.lock().unwrap().client_commands.len();
    assert!(matches!(
        // SAFETY: the test's model owns this key slot alone; no other worker programs the hardware
        // key.
        unsafe {
            link.install_management_key(epoch, 4, &[0x55; 16], PacketNumber::new(100).unwrap())
        },
        Err(LinkControlError::Backpressure)
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    drop(drain_notices(&mut link));
    // SAFETY: actual modeled queues/notices and independent old RX/IRQ/users
    // are drained. The model OS provided this association's authentic IGTK.
    let session = unsafe {
        link.install_management_key(epoch, 4, &[0x55; 16], PacketNumber::new(100).unwrap())
    }
    .unwrap();
    assert!(!link.carrier());
    assert!(core::ptr::eq(
        session.association_context().unwrap(),
        link.state()
            .client
            .client
            .modern_context()
            .unwrap()
            .as_ref()
    ));
    (link, model, session, drops)
}
fn take_management(link: &mut TestLink) -> Received {
    match link.take_notice().unwrap().event {
        LinkEvent::Controller(Event::ProtectedManagement(rx)) => rx,
        _ => panic!("original authenticated envelope must reach OS notice"),
    }
}
fn pending_descriptor(model: &Model) -> (u16, u16, Vec<u8>) {
    let queue = model.queues[&0xd4520].lock().unwrap();
    let memory = model.memory.lock().unwrap();
    let offset = usize::from((queue.index + queue.count - 1) % queue.count) * 16;
    let pointer = (memory.mappings[&queue.base].1 + offset) as *const u8;
    // SAFETY: the actual completed model descriptor remains mapped and owned.
    let bytes = unsafe { core::slice::from_raw_parts(pointer, 16) }.to_vec();
    assert_ne!(
        u32::from_le_bytes(bytes[4..8].try_into().unwrap()) & (1 << 31),
        0
    );
    (queue.head, queue.index, bytes)
}

#[test]
fn owning_management_notices_preserve_the_65th_actual_ddone_and_consume_original_context() {
    let (mut link, model, session, drops) = prepared();
    for pn in 1..=64 {
        incoming(&model, &response(0x40c0, &[7, 0]), Some((1, 0, pn)), false);
        link.service().unwrap();
        assert_eq!(link.phase(), Phase::Associated);
    }
    assert_eq!(link.queues().notices, 64);
    incoming(&model, &response(0x40c0, &[7, 0]), Some((1, 0, 65)), false);
    let before = pending_descriptor(&model);
    let head = model.queues[&0xd4300].lock().unwrap().head;
    assert!(link.service().unwrap().backpressured);
    assert_eq!(pending_descriptor(&model), before);
    assert!(matches!(
        link.transmit_management(&session, Transmit::SaQueryResponse([1, 2])),
        Err(LinkControlError::Backpressure)
    ));
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    let first = take_management(&mut link);
    assert!(Arc::ptr_eq(first.session(), &session));
    assert_eq!(
        link.with_management(first, |_, body, pn| {
            assert_eq!(body, [7, 0]);
            pn.value()
        })
        .unwrap(),
        1
    );
    link.service().unwrap();
    let mut last = None;
    for pn in 2..=65 {
        let rx = take_management(&mut link);
        assert_eq!(rx.packet_number().value(), pn);
        assert!(Arc::ptr_eq(rx.session(), &session));
        last = Some(rx);
    }
    let deferred = last.unwrap();
    assert_eq!(link.phase(), Phase::Associated);
    assert!(!link.carrier());
    link.revoke().unwrap();
    assert!(matches!(
        link.with_management(deferred, |_, _, _| panic!("revoked original OS envelope")),
        Err(LinkControlError::Policy(PolicyError::Revoked))
    ));
    // SAFETY: all actual modeled descriptors/notifications and old users drained.
    unsafe { link.retire_peer_after_drain() }.unwrap();
    // Revoked policy retirement already sent the actual interface/DMA stop.
    // A second stop is refused rather than republishing native commands; this
    // state still requires the independent whole-controller quiescence below.
    assert_eq!(link.phase(), Phase::ControllerDrain);
    let commands = model.response.lock().unwrap().client_commands.len();
    let log = model.bar.0.lock().unwrap().log.len();
    assert!(matches!(
        link.stop(),
        Err(LinkControlError::Policy(PolicyError::Client(Error::Busy)))
    ));
    assert_eq!(link.phase(), Phase::ControllerDrain);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    // SAFETY: independent whole-model controller/DMA/IRQ quiescence.
    unsafe { link.stop_after_quiesce() }.unwrap();
    drop(link);
    drop(session);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn a_beacon_slot_time_change_keeps_the_management_session() {
    let (mut link, model, session, _) = prepared();
    drop(drain_notices(&mut link));
    // As update_slot_time_modern leaves the profile after the AP's change.
    let s = link.state_mut().client.client.state_mut();
    let mut profile = s.profile.unwrap();
    profile.slot_time = 20;
    s.profile = Some(profile);
    incoming(&model, &response(0x40c0, &[7, 0]), Some((1, 0, 1)), false);
    link.service().unwrap();
    assert!(Arc::ptr_eq(take_management(&mut link).session(), &session));
    stop(&mut link, &model);
}

#[test]
fn owning_management_tx_releases_original_keys_and_rejects_deferred_envelope_after_removal() {
    let (mut link, model, session, drops) = prepared();
    let receipt = link
        .transmit_management(&session, Transmit::SaQueryRequest([0xa5, 0x5a]))
        .unwrap();
    assert_eq!(finish_tx(&model)[0][24..], [8, 0, 0xa5, 0x5a]);
    link.service().unwrap();
    let mut released = None;
    while let Some(notice) = link.take_notice() {
        if let LinkEvent::Released(packet) = notice.event {
            released = Some(packet);
        }
    }
    let packet = released.unwrap();
    assert_eq!(packet.receipt, receipt);
    assert!(Arc::ptr_eq(
        packet.context.management_session().unwrap(),
        &session
    ));
    incoming(&model, &response(0x40c0, &[7, 0]), Some((1, 0, 9)), false);
    link.service().unwrap();
    let deferred = take_management(&mut link);
    depart(&mut link, &model);
    let log = model.bar.0.lock().unwrap().log.len();
    assert!(
        link.with_management(deferred, |_, _, _| panic!("removed native peer"))
            .is_err()
    );
    assert!(
        link.transmit_management(&session, Transmit::Deauthenticate(7))
            .is_err()
    );
    assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    // SAFETY: actual removal ACK and independent model old-user drain.
    unsafe { link.retire_peer_after_drain() }.unwrap();
    link.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    // SAFETY: independent whole-model controller/DMA/IRQ quiescence.
    unsafe { link.stop_after_quiesce() }.unwrap();
    drop(link);
    drop(session);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    drop(packet);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    assert!(model.memory.lock().unwrap().mappings.is_empty());
}

mod rotation_controls;
