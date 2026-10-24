// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2023 MediaTek Inc.
//! Stateful native peer controls: real management RX, queue publication,
//! descriptor/TX-free/unmap retirement and firmware disable replies.
use super::*;
use crate::net::wifi::mediatek::bootstrap::client::{
    modern::tests::TxFixture,
    tests::{Policy, finish_tx, incoming, response},
};
use crate::net::wifi::mediatek::ring::tests::Source;
use core::sync::atomic::Ordering;

const NOW: u64 = 1_000_200;
const TID: u8 = 6;

fn delba(f: &mut TxFixture, now: u64) {
    // Recipient DELBA: initiator bit clear cancels our TX agreement.
    let mut body = alloc::vec![3, 2];
    body.extend_from_slice(&(u16::from(TID) << 12).to_le_bytes());
    body.extend_from_slice(&37u16.to_le_bytes());
    incoming(&f.model, &response(0xd0, &body), None, false);
    f.driver.poll(now, &Source, &mut Policy(true)).unwrap();
}

fn queued_request(f: &mut TxFixture) -> Arc<Session> {
    f.driver.begin_tx_block_ack(TID, 0, NOW).unwrap();
    f.progress(NOW + 1).unwrap();
    let Some(BaAction::Tx(Action::Transmit { session, bytes, .. })) =
        f.driver.state().ba_actions.front()
    else {
        panic!("actual preparation must queue ADDBA");
    };
    assert_eq!(&bytes[24..27], &[3, 0, session.dialog()]);
    session.clone()
}

fn queued_operational(f: &mut TxFixture) -> Arc<Session> {
    let session = queued_request(f);
    f.progress(NOW + 2).unwrap();
    let sent = finish_tx(&f.model);
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0][24..27], &[3, 0, session.dialog()]);
    f.driver.poll(NOW + 3, &Source, &mut Policy(true)).unwrap();
    assert_eq!(f.driver.poll_released().unwrap().len(), 1);
    let mut body = alloc::vec![3, 1, session.dialog(), 0, 0];
    let parameters = 3 | (u16::from(TID) << 2) | (32 << 6);
    body.extend_from_slice(&parameters.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    incoming(&f.model, &response(0xd0, &body), None, false);
    f.driver.poll(NOW + 4, &Source, &mut Policy(true)).unwrap();
    assert!(matches!(
        f.driver.state().ba_actions.front(),
        Some(BaAction::Tx(Action::Program {
            agreement: Some(_),
            ..
        }))
    ));
    assert!(f.driver.station().active_tx_block_ack(TID).is_none());
    session
}

fn assert_stop(f: &TxFixture, session: &Arc<Session>) {
    let Some(BaAction::Tx(Action::Program {
        session: retained,
        agreement: None,
        ..
    })) = f.driver.state().ba_actions.front()
    else {
        panic!("canonical cancellation must retain actual disable");
    };
    assert!(Arc::ptr_eq(retained, session));
    let native = f.driver.state().transmit_ba[usize::from(TID)]
        .as_ref()
        .unwrap();
    assert!(Arc::ptr_eq(&native.session, session));
    assert!(native.blocked);
}

fn assert_disabled(f: &TxFixture, commands_before: usize) {
    assert!(!f.driver.pending_block_ack());
    assert!(f.driver.state().transmit_ba[usize::from(TID)].is_none());
    assert!(!f.driver.station().tx_block_ack_blocks_data(TID));
    let r = f.model.response.lock().unwrap();
    assert_eq!(r.client_commands.len(), commands_before + 1);
    let body = &r.client_commands.last().unwrap()[48..];
    assert_eq!(&body[8..20], &[6, 0, 16, 0, TID, 1, 0, 0, 0, 0, 1, 0]);
    assert!(!r.transmit_ba.contains_key(&(1, TID)));
    assert!(r.receive_ba.is_empty());
}

#[test]
fn peer_delba_retires_never_started_native_prepare_without_radio_publication() {
    let mut f = TxFixture::new();
    f.driver.begin_tx_block_ack(TID, 0, NOW).unwrap();
    let commands = f.model.response.lock().unwrap().client_commands.len();
    let head = f.model.queues[&0xd4300].lock().unwrap().head;
    delba(&mut f, NOW + 1);
    assert!(!f.driver.pending_block_ack());
    assert!(f.driver.state().transmit_ba[usize::from(TID)].is_none());
    assert!(!f.driver.station().tx_block_ack_blocks_data(TID));
    assert_eq!(
        f.model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert_eq!(f.model.queues[&0xd4300].lock().unwrap().head, head);
    f.driver.begin_tx_block_ack(TID, 0, NOW + 2).unwrap();
}

#[test]
fn peer_delba_replaces_queued_addba_with_disable_even_after_policy_revocation() {
    let mut f = TxFixture::new();
    let session = queued_request(&mut f);
    let commands = f.model.response.lock().unwrap().client_commands.len();
    let head = f.model.queues[&0xd4300].lock().unwrap().head;
    delba(&mut f, NOW + 2);
    assert_stop(&f, &session);
    assert_eq!(f.model.queues[&0xd4300].lock().unwrap().head, head);
    f.revoke();
    f.driver.progress_block_ack_stop().unwrap();
    assert_disabled(&f, commands);
    assert_eq!(f.model.queues[&0xd4300].lock().unwrap().head, head);
}

#[test]
fn peer_delba_cancels_queued_operational_without_enabling_firmware_aggregation() {
    let mut f = TxFixture::new();
    let session = queued_operational(&mut f);
    let commands = f.model.response.lock().unwrap().client_commands.len();
    let head = f.model.queues[&0xd4300].lock().unwrap().head;
    delba(&mut f, NOW + 5);
    assert_stop(&f, &session);
    assert!(f.model.response.lock().unwrap().transmit_ba.is_empty());
    f.revoke();
    f.driver.progress_block_ack_stop().unwrap();
    assert_disabled(&f, commands);
    assert_eq!(f.model.queues[&0xd4300].lock().unwrap().head, head);
}

#[test]
fn canceled_prepare_retains_previous_qos_until_descriptor_txfree_and_unmap() {
    let mut f = TxFixture::new();
    f.transmit();
    f.driver.begin_tx_block_ack(TID, 0, NOW).unwrap();
    let resource = f.driver.state().controller.state().resource.clone();
    let native = f.driver.state().transmit_ba[usize::from(TID)]
        .as_ref()
        .unwrap()
        .session
        .clone();
    let commands = f.model.response.lock().unwrap().client_commands.len();
    let maps = f.model.memory.lock().unwrap().mappings.len();
    delba(&mut f, NOW + 1);
    assert!(matches!(
        f.driver.progress_block_ack_stop(),
        Err(Error::NeedsDrain)
    ));
    assert!(Arc::ptr_eq(
        &f.driver.state().transmit_ba[usize::from(TID)]
            .as_ref()
            .unwrap()
            .session,
        &native
    ));
    assert_eq!(f.model.memory.lock().unwrap().mappings.len(), maps);
    let sent = finish_tx(&f.model);
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0][24..26], &[TID, 0]);
    // Descriptor consumption alone does not consume the as-yet unpolled TX-free.
    assert!(f.driver.poll_released().unwrap().is_empty());
    assert!(matches!(
        f.driver.progress_block_ack_stop(),
        Err(Error::NeedsDrain)
    ));
    f.driver.poll(NOW + 2, &Source, &mut Policy(true)).unwrap();
    // Actual firmware TX-free without successful unmap still retains context.
    assert!(matches!(
        f.driver.progress_block_ack_stop(),
        Err(Error::NeedsDrain)
    ));
    let released = f.driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].context.tid(), Some(TID));
    f.revoke();
    f.driver.progress_block_ack_stop().unwrap();
    assert!(!f.driver.pending_block_ack());
    assert!(f.driver.state().transmit_ba[usize::from(TID)].is_none());
    assert!(!f.driver.station().tx_block_ack_blocks_data(TID));
    assert_eq!(
        f.model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert!(Arc::ptr_eq(
        &resource,
        &f.driver.state().controller.state().resource
    ));
}

#[test]
fn failed_actual_disable_quarantines_exact_session_and_all_native_owners() {
    let mut f = TxFixture::new();
    let session = queued_operational(&mut f);
    delba(&mut f, NOW + 5);
    assert_stop(&f, &session);
    let context = f.driver.modern_context().unwrap().clone();
    let maps = f.model.memory.lock().unwrap().mappings.len();
    let commands = f.model.response.lock().unwrap().client_commands.len();
    f.model.response.lock().unwrap().status = 42;
    f.revoke();
    assert!(matches!(
        f.driver.progress_block_ack_stop(),
        Err(Error::Firmware(42))
    ));
    assert_eq!(f.driver.phase(), Phase::Quarantined);
    assert_stop(&f, &session);
    assert!(f.driver.station().tx_block_ack_blocks_data(TID));
    assert!(Arc::ptr_eq(f.driver.modern_context().unwrap(), &context));
    assert_eq!(
        f.model.response.lock().unwrap().client_commands.len(),
        commands + 1
    );
    assert_eq!(f.model.memory.lock().unwrap().mappings.len(), maps);
    drop(f.driver);
    assert_eq!(f.model.drops.load(Ordering::Relaxed), 0);
    assert_eq!(f.model.memory.lock().unwrap().mappings.len(), maps);
}

#[test]
fn queued_operational_cancel_also_drains_original_session_management_packet() {
    let mut f = TxFixture::new();
    let session = queued_request(&mut f);
    f.progress(NOW + 2).unwrap();
    assert_eq!(finish_tx(&f.model).len(), 1);
    let mut body = alloc::vec![3, 1, session.dialog(), 0, 0];
    let parameters = 3 | (u16::from(TID) << 2) | (32 << 6);
    body.extend_from_slice(&parameters.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    incoming(&f.model, &response(0xd0, &body), None, false);
    f.driver.poll(NOW + 3, &Source, &mut Policy(true)).unwrap();
    // The management context has no data TID, but it retains this exact BA
    // session until successful unmap. It cannot disappear under a disable.
    assert!(
        f.driver
            .state()
            .controller
            .state()
            .data_tx
            .as_ref()
            .unwrap()
            .has_pending_context(|p| p.tid.is_none()
                && p.tx_ba
                    .as_ref()
                    .is_some_and(|old| Arc::ptr_eq(old, &session)))
    );
    delba(&mut f, NOW + 4);
    let commands = f.model.response.lock().unwrap().client_commands.len();
    assert!(matches!(
        f.driver.progress_block_ack_stop(),
        Err(Error::NeedsDrain)
    ));
    assert!(f.driver.pending_block_ack());
    assert_eq!(
        f.model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert_eq!(f.driver.poll_released().unwrap().len(), 1);
    f.revoke();
    f.driver.progress_block_ack_stop().unwrap();
    assert_disabled(&f, commands);
}
