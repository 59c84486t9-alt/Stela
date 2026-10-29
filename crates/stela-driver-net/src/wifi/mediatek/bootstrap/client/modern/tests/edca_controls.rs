// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Completed RX and native EDCA command peers; no physical-radio grant.
use super::*;
use crate::wifi::regulatory::database::{Wmm, WmmAc};

type Native = Client<Bar, Q, NativeGuard>;
const NOW: u64 = 1_000_210;

fn beacon(driver: &Native, count: u8, edit: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut elements = driver.modern_context().unwrap().beacon().elements.clone();
    let mut at = 0;
    loop {
        let n = usize::from(elements[at + 1]);
        if elements[at] == 221 && elements[at + 2..at + 6] == [0, 0x50, 0xf2, 2] {
            let wmm = &mut elements[at + 2..at + 2 + n];
            wmm[6] = (wmm[6] & 0xf0) | (count & 15);
            edit(wmm);
            break;
        }
        at += 2 + n;
    }
    let mut fixed = vec![0; 8];
    fixed.extend_from_slice(&100u16.to_le_bytes());
    fixed.extend_from_slice(&0x11u16.to_le_bytes());
    fixed.extend_from_slice(&elements);
    let mut frame = response(0x80, &fixed);
    frame[4..10].copy_from_slice(&crate::Mac::BROADCAST.0);
    frame
}
fn observe(driver: &mut Native, model: &Model, frame: &[u8]) -> Result<Vec<Event>, ClientError> {
    incoming(model, frame, None, false);
    driver.poll(NOW, &Source, &mut Policy(true))
}
fn update(driver: &mut Native, owner: &mut Owner, limit: Option<&Wmm>) -> Result<(), ClientError> {
    let permit = admit(owner, driver, AssociationUse::Management);
    // SAFETY: same modeled requester; held guards serialize publication,
    // native queue drain and fixed model OS country/queue rule are explicit.
    unsafe { driver.update_edca_modern(owner, permit, limit) }
}
fn commands(model: &Model) -> usize {
    model.response.lock().unwrap().client_commands.len()
}
fn bytes(model: &Model) -> Vec<u8> {
    model
        .response
        .lock()
        .unwrap()
        .client_commands
        .last()
        .unwrap()[48..]
        .to_vec()
}

mod limits;
mod observations;
mod ownership;
mod policy;
mod validation;
