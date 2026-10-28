// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Actual source-modeled native peers. These providers authorize only the retained
// simulated requester, never a physical device or a real OS management service.
use super::*;
use crate::net::wifi::mediatek::bootstrap::client::management::{Received, Session, Transmit};
use crate::net::wifi::{mediatek::mailbox, security::PacketNumber};

type Native = Client<Bar, Q, NativeGuard>;
const NOW: u64 = 1_000_200;

fn fixture() -> (Native, Model, Owner, Rc<AuthorityState>) {
    let (mut driver, model, _) = awaiting();
    let (mut owner, state) = authority(&driver, &model);
    let permit = admit(&mut owner, &driver, AssociationUse::Configure);
    // SAFETY: only this exact modeled requester and its actually retained guards.
    unsafe { driver.configure_modern(&mut owner, permit, 105) }.unwrap();
    for (pairwise, index, material) in [(true, 0, 1), (false, 2, 0x44)] {
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        // SAFETY: same actual modeled requester, source policy and key exchange.
        unsafe {
            driver.install_key_modern(
                &mut owner,
                permit,
                pairwise,
                index,
                &[material; 16],
                ReplaySeed::ZERO,
            )
        }
        .unwrap();
    }
    (driver, model, owner, state)
}
fn attach(driver: &mut Native, owner: &mut Owner) -> Arc<Session> {
    let permit = admit(owner, driver, AssociationUse::Management);
    let epoch = driver.station().association_epoch().unwrap();
    // SAFETY: modeled native queues, BA owners, actual RX/IRQ and external users
    // are drained; these bytes represent this model OS's authenticated exchange.
    unsafe {
        driver.install_management_key_modern(
            owner,
            permit,
            epoch,
            4,
            &[0x55; 16],
            PacketNumber::new(100).unwrap(),
        )
    }
    .unwrap()
}
fn received(driver: &mut Native, model: &Model, pn: u64) -> Received {
    incoming(model, &response(0x40c0, &[7, 0]), Some((1, 0, pn)), false);
    let mut events = driver.poll(NOW, &Source, &mut Policy(true)).unwrap();
    assert_eq!(events.len(), 1);
    match events.pop().unwrap() {
        Event::ProtectedManagement(received) => received,
        _ => panic!("actual authenticated RX remains an OS observation"),
    }
}
fn stop(driver: &mut Native, model: &Model) {
    if driver.phase() == ClientPhase::Associated {
        driver.disconnect().unwrap();
    }
    // SAFETY: actual model removal ACK and independent old RX/IRQ/work drain;
    // retained observations are inert and every consuming use revalidates them.
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    driver.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    // SAFETY: whole actual modeled controller/DMA/IRQ quiesced independently.
    unsafe { driver.stop_after_quiesce() }.unwrap();
}

mod rotation_controls;

mod block_ack_controls;

mod admission;
mod context;
mod dma_lifetime;
mod key_installation;
