// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Native software peers: firmware ACKs, requester-owned RX/TX DMA, key replay
//! and descriptor/TX-free/unmap lifetimes.
use super::*;
use crate::net::wifi::mediatek::{
    bootstrap::{
        client::tests::{
            AP, LOCAL, Model, Policy, associated, data, finish_tx, incoming, incoming_bytes,
            response, setup,
        },
        tests::{Bar, NativeGuard, Q},
    },
    ring::{rx::tests::device_receive, tests::Source},
};
use core::sync::atomic::Ordering;

type Native = Client<Bar, Q, NativeGuard>;

fn keys(driver: &mut Native) -> (u64, KeyIdentity, KeyIdentity) {
    let ptk = driver
        .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
        .unwrap();
    let gtk = driver
        .install_key(false, 2, &[0x44; 16], ReplaySeed::ZERO)
        .unwrap();
    (driver.station().association_epoch().unwrap(), ptk, gtk)
}
fn attach(driver: &mut Native, epoch: u64) -> Arc<Session> {
    // SAFETY: model peer/key commands and both TX retirement
    // receipts are drained; no old hardware RX/IRQ/deferred GTK user exists.
    unsafe { driver.install_management_key(epoch, 4, &[0x55; 16], PacketNumber::new(100).unwrap()) }
        .unwrap()
}
fn completed(driver: &mut Native, model: &Model, bytes: &[u8]) -> Result<Vec<Event>, Error> {
    device_receive(&model.queues[&0xd4520], bytes, true, 0);
    driver.poll(1_000_000, &Source, &mut Policy(true))
}
fn unicast(pn: u64) -> Vec<u8> {
    incoming_bytes(&response(0x40c0, &[7, 0]), Some((1, 0, pn)), false)
}
fn received(driver: &mut Native, model: &Model, pn: u64) -> Received {
    let mut events = completed(driver, model, &unicast(pn)).unwrap();
    assert_eq!(events.len(), 1);
    match events.pop().unwrap() {
        Event::ProtectedManagement(received) => received,
        _ => panic!("actual management RX must remain an OS observation"),
    }
}
fn group() -> Vec<u8> {
    // Unchanged source CMAC-helper native.trace vector, as in mailbox/key/bip.rs;
    // original parent GTK0x44, IGTK0x55, index4, IPN101, reason7.
    let bytes = alloc::vec![
        0xc0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 2, 6, 7, 8, 9, 10, 2, 6, 7, 8, 9, 10, 0, 0, 7,
        0, 76, 16, 4, 0, 101, 0, 0, 0, 0, 0, 0xc4, 0x80, 0xa2, 0x3a, 0x2c, 0x44, 0x77, 0x70,
    ];
    let mut raw = incoming_bytes(&bytes, None, false);
    // Native source lookup is the peer WCID, mapped through its kept
    // VIF to the GTK slot; a copied BCMC slot is not a peer lookup.
    raw[4] = 1;
    raw
}
fn stop(driver: &mut Native, model: &Model) {
    if driver.phase() == Phase::Associated {
        driver.disconnect().unwrap();
    }
    // SAFETY: model removal ACKs and both queue receipts drained;
    // CPU observations are inert and every later use revalidates.
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    driver.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    // SAFETY: model controller/IRQ/radio/DMA/work independently quiesced.
    unsafe { driver.stop_after_quiesce() }.unwrap();
}

#[test]
fn initial_igtk_batch_binds_original_peer_keys_and_preserves_exact_retry() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, ptk, gtk) = keys(&mut driver);
    let commands = model.response.lock().unwrap().client_commands.len();
    let session = attach(&mut driver, epoch);
    assert_eq!(session.association_epoch(), epoch);
    assert_eq!(session.pairwise_key(), ptk);
    assert_eq!(session.group_key(), gtk);
    assert_eq!(session.management_key().gtk(), gtk);
    assert_eq!(
        model.response.lock().unwrap().keys[&19],
        [alloc::vec![0x44; 16], alloc::vec![0x55; 16]].concat()
    );
    assert!(!driver.station().port_open(
        Some(driver.state().ptk.as_ref().unwrap().slot()),
        Some(driver.state().gtk.as_ref().unwrap().slot())
    ));
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands + 1
    );
    let again = attach(&mut driver, epoch);
    assert!(Arc::ptr_eq(&session, &again));
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands + 1
    );
    assert!(matches!(
        // SAFETY: unchanged drained namespace; stale OS epoch must not publish.
        unsafe {
            driver.install_management_key(epoch + 1, 4, &[0x55; 16], PacketNumber::new(0).unwrap())
        },
        Err(Error::Station(station::Error::Stale))
    ));
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands + 1
    );
    stop(&mut driver, &model);
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    drop(again);
    drop(session);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    assert!(model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn unicast_management_rx_authenticates_without_automatic_departure_or_data_replay() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, _, _) = keys(&mut driver);
    let session = attach(&mut driver, epoch);
    driver.authorize_port(epoch).unwrap();
    let observation = received(&mut driver, &model, 9);
    assert!(Arc::ptr_eq(observation.session(), &session));
    assert_eq!(observation.body(), [7, 0]);
    assert!(!observation.group());
    assert_eq!(observation.packet_number().value(), 9);
    assert_eq!(driver.phase(), Phase::Associated);
    assert_eq!(driver.station().phase(), station::Phase::Associated);
    assert_eq!(
        driver
            .with_management(observation, |frame, body, pn| {
                assert_eq!(frame.header().transmitter, Some(AP));
                assert_eq!(body, [7, 0]);
                pn.value()
            })
            .unwrap(),
        9
    );
    assert!(matches!(
        completed(&mut driver, &model, &unicast(9)),
        Err(Error::Key(mailbox::key::Error::Security(
            wifi::security::Error::Replay
        )))
    ));
    // Management counter16 must not consume the ordinary data/non-QoS floor.
    incoming(&model, &data(false), Some((1, 0, 9)), false);
    assert!(matches!(
        driver
            .poll(1_000_001, &Source, &mut Policy(true))
            .unwrap()
            .as_slice(),
        [Event::Ingress(Ingress::Data(_))]
    ));
    stop(&mut driver, &model);
    drop(driver);
    drop(session);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn group_bip_rx_enforces_original_mic_ipn_and_peer_lookup_before_os_consumption() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, _, _) = keys(&mut driver);
    let session = attach(&mut driver, epoch);
    for fault in 0..5 {
        let mut raw = group();
        match fault {
            0 => raw[4] = 19, // copied BCMC slot is not a peer lookup
            1 => raw[32 + 10] ^= 2,
            2 => raw[32 + 16] ^= 2,
            3 => {
                let end = raw.len();
                raw[end - 1] ^= 1;
            }
            _ => raw[32 + 28] = 5,
        }
        assert!(completed(&mut driver, &model, &raw).is_err());
        assert_eq!(
            driver
                .state()
                .gtk
                .as_ref()
                .unwrap()
                .igtk_receive_floor()
                .unwrap()
                .value(),
            100
        );
    }
    let mut events = completed(&mut driver, &model, &group()).unwrap();
    let Event::ProtectedManagement(proof) = events.pop().unwrap() else {
        panic!("BIP must be delivered as an authenticated observation");
    };
    assert!(proof.group());
    assert_eq!(proof.body(), [7, 0]);
    assert_eq!(proof.packet_number().value(), 101);
    assert_eq!(driver.phase(), Phase::Associated);
    assert_eq!(
        driver
            .with_management(proof, |_, body, _| body.to_vec())
            .unwrap(),
        [7, 0]
    );
    assert!(matches!(
        completed(&mut driver, &model, &group()),
        Err(Error::Key(mailbox::key::Error::Bip(
            bip::Error::Authentication(wifi::security::management::Error::Replay)
        )))
    ));
    assert!(Arc::ptr_eq(&session, &attach(&mut driver, epoch)));
    assert_eq!(
        driver
            .state()
            .gtk
            .as_ref()
            .unwrap()
            .igtk_receive_floor()
            .unwrap()
            .value(),
        101
    );
    stop(&mut driver, &model);
    drop(driver);
    drop(session);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn protected_tx_keeps_session_until_descriptor_free_and_unmap_before_peer_removal() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, ptk, _) = keys(&mut driver);
    let session = attach(&mut driver, epoch);
    let head = model.queues[&0xd4300].lock().unwrap().head;
    assert!(matches!(
        driver.transmit_management(
            &session,
            Transmit::SaQueryResponse([0xa5, 0x5a]),
            &Source,
            &mut Policy(false)
        ),
        Err(Error::Station(station::Error::Regulatory))
    ));
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    let receipt = driver
        .transmit_management(
            &session,
            Transmit::SaQueryResponse([0xa5, 0x5a]),
            &Source,
            &mut Policy(true),
        )
        .unwrap();
    let queue = model.queues[&0xd4300].lock().unwrap();
    let memory = model.memory.lock().unwrap();
    // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and nothing
    // accesses it concurrently.
    let desc = unsafe {
        core::slice::from_raw_parts(
            super::super::tests::pointer(
                &memory,
                queue.base + u64::from(receipt.descriptor) * 16,
                16,
            ),
            16,
        )
    };
    let address = u32::from_le_bytes(desc[..4].try_into().unwrap()) as u64;
    // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and nothing
    // accesses it concurrently.
    let txwi = unsafe {
        core::slice::from_raw_parts(super::super::tests::pointer(&memory, address, 32), 32)
    };
    let word =
        |index: usize| u32::from_le_bytes(txwi[index * 4..index * 4 + 4].try_into().unwrap());
    assert_eq!(word(0) >> 25, 16); // source management queue
    assert_eq!((word(1) >> 21) & 15, 0); // ordinary management, not ADDBA TID2
    assert_eq!(word(3) & 2, 2); // selected PTK hardware protection
    assert_eq!(word(3) & (1 << 30), 0); // no invented host PN/IV
    assert_eq!(word(4), 0);
    drop(memory);
    drop(queue);
    assert!(matches!(
        // SAFETY: the independently required external drain has not occurred; the queued
        // descriptor/token must refuse even a same-key retry.
        unsafe {
            driver.install_management_key(epoch, 4, &[0x55; 16], PacketNumber::new(0).unwrap())
        },
        Err(Error::NeedsDrain)
    ));
    driver.disconnect().unwrap();
    assert_eq!(driver.phase(), Phase::Removing);
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0][..2], &[0xd0, 0x40]);
    assert_eq!(&sent[0][24..], &[8, 1, 0xa5, 0x5a]);
    // Descriptor consumption alone cannot release the key/session owner.
    assert!(driver.poll_released().unwrap().is_empty());
    assert_eq!(driver.phase(), Phase::Removing);
    driver.poll(1_000_001, &Source, &mut Policy(true)).unwrap();
    let mut released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    let packet = released.pop().unwrap();
    assert_eq!(packet.receipt, receipt);
    assert_eq!(packet.context.key(), Some(ptk));
    assert!(Arc::ptr_eq(
        packet.context.management_session().unwrap(),
        &session
    ));
    assert_eq!(driver.phase(), Phase::NeedsDrain);
    stop(&mut driver, &model);
    drop(driver);
    drop(session);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    drop(packet);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    assert!(model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn deferred_management_and_os_reply_are_revoked_before_mmio_after_disconnect_and_reconnect() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, _, _) = keys(&mut driver);
    let session = attach(&mut driver, epoch);
    let first = received(&mut driver, &model, 9);
    let second = received(&mut driver, &model, 10);
    driver.disconnect().unwrap();
    let commands = model.response.lock().unwrap().client_commands.len();
    let head = model.queues[&0xd4300].lock().unwrap().head;
    assert!(
        driver
            .with_management(first, |_, _, _| panic!(
                "revoked RX must not reach OS effects"
            ))
            .is_err()
    );
    assert!(
        driver
            .transmit_management(
                &session,
                Transmit::Deauthenticate(7),
                &Source,
                &mut Policy(true)
            )
            .is_err()
    );
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands
    );
    // SAFETY: all old model hardware/DMA/work drained; held CPU-only
    // observations are inert and their consumption always revalidates ownership.
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    associated(&mut driver, &model, 30);
    let next = driver
        .install_key(true, 0, &[3; 16], ReplaySeed::ZERO)
        .unwrap();
    driver
        .install_key(false, 2, &[0x66; 16], ReplaySeed::ZERO)
        .unwrap();
    assert_ne!(next, session.pairwise_key());
    let commands = model.response.lock().unwrap().client_commands.len();
    let head = model.queues[&0xd4300].lock().unwrap().head;
    assert!(
        driver
            .with_management(second, |_, _, _| panic!(
                "old RX cannot acquire new peer keys"
            ))
            .is_err()
    );
    assert!(
        driver
            .transmit_management(
                &session,
                Transmit::SaQueryRequest([0, 1]),
                &Source,
                &mut Policy(true)
            )
            .is_err()
    );
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands
    );
    stop(&mut driver, &model);
    drop(driver);
    drop(session);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn uncertain_igtk_publication_quarantines_complete_owner_without_transport_or_drop() {
    for dropped in [false, true] {
        let (mut driver, model) = setup();
        associated(&mut driver, &model, 0);
        let (epoch, _, _) = keys(&mut driver);
        if dropped {
            model.response.lock().unwrap().drop = true;
        } else {
            model.response.lock().unwrap().status = 9;
        }
        assert!(
            // SAFETY: initial model GTK drain; firmware failure/late ACK must keep
            // the entire native namespace, never mint a Session.
            unsafe {
                driver.install_management_key(
                    epoch,
                    4,
                    &[0x55; 16],
                    PacketNumber::new(100).unwrap(),
                )
            }
            .is_err()
        );
        assert_eq!(driver.phase(), Phase::Quarantined);
        assert!(driver.state().management.is_none());
        assert!(
            driver
                .state()
                .gtk
                .as_ref()
                .unwrap()
                .slot()
                .installed()
                .is_none()
        );
        assert_eq!(
            model.response.lock().unwrap().keys[&19],
            [alloc::vec![0x44; 16], alloc::vec![0x55; 16]].concat()
        );
        assert!(completed(&mut driver, &model, &unicast(1)).is_err());
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
}

#[test]
fn hostile_completed_unicast_never_emits_management_or_advances_the_original_pn() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, _, _) = keys(&mut driver);
    let session = attach(&mut driver, epoch);
    for fault in 0..10 {
        let mut raw = unicast(9);
        match fault {
            0 => raw[4] = 2,
            1 => raw[6] |= 1 << 5,
            2 => raw[10] = (raw[10] & !31) | 11,
            3 => raw[7] |= 1 << 1,
            4 => raw[48 + 10] ^= 2,
            5 => raw[48 + 16] ^= 2,
            6 => raw[48 + 4] ^= 2,
            7 => raw[13] = 40,
            8 => raw[48 + 22] |= 1,
            _ => {
                raw.pop();
            }
        }
        assert!(
            completed(&mut driver, &model, &raw).is_err(),
            "fault {fault}"
        );
        assert_eq!(driver.phase(), Phase::Associated);
        assert_eq!(driver.station().phase(), station::Phase::Associated);
    }
    let proof = received(&mut driver, &model, 9);
    driver
        .with_management(proof, |_, body, _| assert_eq!(body, [7, 0]))
        .unwrap();
    stop(&mut driver, &model);
    drop(driver);
    drop(session);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn foreign_native_session_and_current_modern_owner_are_refused_without_hardware_effects() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, _, _) = keys(&mut driver);
    let session = attach(&mut driver, epoch);
    let (mut other, other_model) = setup();
    associated(&mut other, &other_model, 0);
    let (other_epoch, _, _) = keys(&mut other);
    let other_session = attach(&mut other, other_epoch);
    let commands = other_model.response.lock().unwrap().client_commands.len();
    let log = other_model.bar.0.lock().unwrap().log.len();
    let head = other_model.queues[&0xd4300].lock().unwrap().head;
    assert!(
        other
            .transmit_management(
                &session,
                Transmit::Disassociate(8),
                &Source,
                &mut Policy(true)
            )
            .is_err()
    );
    assert_eq!(
        other_model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert_eq!(other_model.bar.0.lock().unwrap().log.len(), log);
    assert_eq!(other_model.queues[&0xd4300].lock().unwrap().head, head);
    let mut modern = super::super::modern::tests::TxFixture::new();
    let epoch = modern.driver.station().association_epoch().unwrap();
    let commands = modern.model.response.lock().unwrap().client_commands.len();
    let log = modern.model.bar.0.lock().unwrap().log.len();
    let head = modern.model.queues[&0xd4300].lock().unwrap().head;
    assert!(matches!(
        // SAFETY: the current model is drained. This API lacks the modern canonical
        // management admission, so no initial batch may be published.
        unsafe {
            modern.driver.install_management_key(
                epoch,
                4,
                &[0x55; 16],
                PacketNumber::new(100).unwrap(),
            )
        },
        Err(Error::ModernAdmissionRequired)
    ));
    assert!(
        modern
            .driver
            .transmit_management(
                &session,
                Transmit::SaQueryRequest([1, 2]),
                &Source,
                &mut Policy(true)
            )
            .is_err()
    );
    assert_eq!(
        modern.model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert_eq!(modern.model.bar.0.lock().unwrap().log.len(), log);
    assert_eq!(modern.model.queues[&0xd4300].lock().unwrap().head, head);
    stop(&mut modern.driver, &modern.model);
    stop(&mut other, &other_model);
    stop(&mut driver, &model);
    drop(modern);
    drop(other);
    drop(driver);
    drop(other_session);
    drop(session);
    assert_eq!(other_model.drops.load(Ordering::Relaxed), 1);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn protected_departure_and_query_request_bytes_use_current_ptk_without_local_policy_effects() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, _, _) = keys(&mut driver);
    let session = attach(&mut driver, epoch);
    for (message, control, body) in [
        (Transmit::Deauthenticate(7), 0x40c0u16, alloc::vec![7, 0]),
        (Transmit::Disassociate(8), 0x40a0u16, alloc::vec![8, 0]),
        (
            Transmit::SaQueryRequest([1, 2]),
            0x40d0u16,
            alloc::vec![8, 0, 1, 2],
        ),
    ] {
        let receipt = driver
            .transmit_management(&session, message, &Source, &mut Policy(true))
            .unwrap();
        let sent = finish_tx(&model);
        assert_eq!(sent.len(), 1);
        assert_eq!(&sent[0][..2], &control.to_le_bytes());
        assert_eq!(&sent[0][4..10], AP.0);
        assert_eq!(&sent[0][10..16], LOCAL.0);
        assert_eq!(&sent[0][16..22], AP.0);
        assert_eq!(&sent[0][24..], body);
        driver.poll(1_000_000, &Source, &mut Policy(true)).unwrap();
        let mut released = driver.poll_released().unwrap();
        assert_eq!(released.len(), 1);
        assert_eq!(released.pop().unwrap().receipt, receipt);
        assert_eq!(driver.phase(), Phase::Associated);
        assert_eq!(driver.station().phase(), station::Phase::Associated);
    }
    stop(&mut driver, &model);
    drop(driver);
    drop(session);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn protected_tx_unmap_failure_keeps_session_and_refuses_further_management() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, _, _) = keys(&mut driver);
    let session = attach(&mut driver, epoch);
    let proof = received(&mut driver, &model, 9);
    driver
        .transmit_management(
            &session,
            Transmit::SaQueryRequest([1, 2]),
            &Source,
            &mut Policy(true),
        )
        .unwrap();
    assert_eq!(finish_tx(&model).len(), 1);
    driver.poll(1_000_001, &Source, &mut Policy(true)).unwrap();
    model.memory.lock().unwrap().fail_unmap = true;
    assert!(driver.poll_released().is_err());
    let queue = driver.state().controller.state().data_tx.as_ref().unwrap();
    assert!(queue.is_poisoned());
    assert_eq!(queue.outstanding_tokens(), 1);
    assert!(
        driver
            .with_management(proof, |_, _, _| panic!(
                "poisoned actual queue revokes effects"
            ))
            .is_err()
    );
    let head = model.queues[&0xd4300].lock().unwrap().head;
    assert!(
        driver
            .transmit_management(
                &session,
                Transmit::Disassociate(8),
                &Source,
                &mut Policy(true)
            )
            .is_err()
    );
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    let retained = Arc::downgrade(&session);
    drop(driver);
    drop(session);
    assert!(retained.upgrade().is_some());
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}

mod rotation_controls;
