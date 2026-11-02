// SPDX-License-Identifier: GPL-2.0-only
//! Isolated bounded queue-pressure controls, never native permissions.
use super::*;

pub fn saturate_transmit<C: Configuration, R: Registers, T: Time>(owner: &mut Native<C, R, T>) {
    assert_eq!(owner.engine.inputs.len(), 33);
    assert!(owner.engine.connected());
    // Real queued validated inputs already suppressed a new receive credit.
    // Fill the same bounded production queue while the model mailbox is busy.
    let mut queued = 0;
    loop {
        match owner.engine.management(2, &[]) {
            Ok(()) => queued += 1,
            Err(error) => {
                assert_eq!(error, Error::Protocol("bounded IPC transmit queue"));
                break;
            }
        }
    }
    assert!(queued > 0);
}
