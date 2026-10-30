// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Original completed native RX, firmware commands and packet retirement.
//! These modeled OS permissions never check a physical or production OS peer.
use super::*;

const TID: u8 = 6;

fn request() -> Vec<u8> {
    let mut body = vec![3, 0, 7];
    body.extend_from_slice(&(3u16 | (u16::from(TID) << 2) | (8 << 6)).to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(17u16 << 4).to_le_bytes());
    body
}
fn delete(initiator: bool) -> Vec<u8> {
    let mut body = vec![3, 2];
    body.extend_from_slice(&(u16::from(TID) << 12 | u16::from(initiator) << 11).to_le_bytes());
    body.extend_from_slice(&37u16.to_le_bytes());
    body
}
fn observe(driver: &mut Native, model: &Model, body: &[u8], pn: u64, now: u64) -> Received {
    incoming(model, &response(0x40d0, body), Some((1, 0, pn)), false);
    let mut events = driver.poll(now, &Source, &mut Policy(true)).unwrap();
    assert_eq!(events.len(), 1);
    let Event::ProtectedManagement(received) = events.pop().unwrap() else {
        panic!("actual authenticated native management envelope");
    };
    assert!(received.frame().header().protected());
    assert_eq!(received.body(), body);
    received
}
fn consume(driver: &mut Native, owner: &mut Owner, received: Received, now: u64) {
    let permit = admit(owner, driver, AssociationUse::Management);
    // SAFETY: this modeled OS explicitly selects protected BA MLME for its
    // original authenticated envelope and subsequent guarded response/teardown.
    let mut retained = Some(received);
    // SAFETY: The envelope owns this current session and requester. Fresh hardware/OS
    // guards serialize protected BA consumption, and kept state owns any deferred
    // response or teardown after the call.
    unsafe { driver.receive_management_block_ack(owner, permit, &mut retained, now) }.unwrap();
    assert!(retained.is_none());
}
fn progress(driver: &mut Native, owner: &mut Owner, state: &Rc<AuthorityState>, now: u64) {
    let permit = admit(owner, driver, AssociationUse::Management);
    // SAFETY: modeled requester and original OS policy cover all deferred effects.
    unsafe { driver.progress_block_ack(owner, permit, &GuardedSource(state.clone()), now) }
        .unwrap();
}
fn begin(driver: &mut Native, owner: &mut Owner, session: &Arc<Session>, now: u64) {
    let permit = admit(owner, driver, AssociationUse::Management);
    // SAFETY: explicitly selected protected BA MLME in this modeled OS only.
    unsafe { driver.begin_management_block_ack(owner, permit, session, TID, 0, now) }.unwrap();
}
fn assert_cipher_descriptor(model: &Model, session: &Session, request: bool) {
    let queue = model.queues[&0xd4300].lock().unwrap();
    assert_ne!(queue.index, queue.head);
    let memory = model.memory.lock().unwrap();
    let pointer = crate::wifi::mediatek::bootstrap::client::tests::pointer;
    let descriptor =
    // SAFETY: The queue guard fixes this live descriptor index and the memory guard
    // keeps its mapping. pointer validates the complete 16-byte readable range; no
    // model peer writes it concurrently.
    unsafe {
        core::slice::from_raw_parts(
            pointer(&memory, queue.base + u64::from(queue.index) * 16, 16),
            16,
        )
    };
    let address = u32::from_le_bytes(descriptor[..4].try_into().unwrap()) as u64;
    let actual =
    // SAFETY: The memory guard keeps the mapped TXWI/payload backing, and pointer
    // checks the entire 64-byte readable range. All bytes were initialized before
    // queueing; no physical DMA or concurrent writer exists.
    unsafe { core::slice::from_raw_parts(pointer(&memory, address, 64), 64) };
    let word1 = u32::from_le_bytes(actual[4..8].try_into().unwrap());
    let word3 = u32::from_le_bytes(actual[12..16].try_into().unwrap());
    assert_eq!(word3 & 2, 2); // MT_TXD3_PROTECT_FRAME
    assert_eq!(word1 & 0xfff, u32::from(session.pairwise_key().slot()));
    assert_eq!((word1 >> 21) & 15, if request { 2 } else { 0 });
}

fn rotate_refused(driver: &mut Native, owner: &mut Owner, session: &Session) {
    let permit = admit(owner, driver, AssociationUse::Management);
    // SAFETY: negative drain control; no old user may be released here.
    assert!(matches!(
        // SAFETY: The current session and pending BA/packet owners remain held in
        // this software model. Rotation must refuse the undrained user before
        // changing or releasing its key namespace.
        unsafe {
            driver.rotate_management_key_modern(
                owner,
                permit,
                session,
                5,
                &[0x66; 16],
                PacketNumber::new(200).unwrap(),
            )
        },
        Err(ClientError::NeedsDrain)
    ));
}

mod originator;
mod policy;
mod provenance;
mod recipient;
mod retention;
