// SPDX-License-Identifier: MIT AND GPL-2.0-only
//! Configured native peers for the xHCI generation admission regressions.
use super::super::*;
use crate::usb::xhci::{Found, model::bind};

pub(crate) fn peer(controller: Shared, dma: &mut dyn DmaAllocator) -> UsbNet {
    let device = super::super::tests::cdc_device(&controller, None);
    let mut found = Found::default();
    bind(&controller, device, dma, &mut found);
    assert!(found.failures.is_empty(), "{:?}", found.failures);
    assert_eq!(found.links.len(), 1);
    found.links.pop().unwrap()
}

pub(crate) fn queue(peer: &mut UsbNet) {
    assert!(peer.carrier());
    assert_eq!(peer.connected, Some(true));
    assert_eq!(peer.receive().unwrap(), None);
    assert!(peer.queued.is_some());
    assert!(peer.notify_queued.is_some());
    peer.pending.push_back(vec![0x53; 60]);
    peer.send.bytes_mut().fill(0xa5);
}

pub(crate) fn refuse(peer: &mut UsbNet, target: &Shared) {
    // Production keeps its original Shared. Substituting another
    // addressed controller here tests that the separately identity,
    // rather than a matching slot number or descriptor, is the credential.
    peer.controller = target.clone();
    let before_id = peer.id;
    let before_pending = peer.pending.clone();
    let before_send = peer.send.bytes().to_vec();
    let before_receive = peer.receive.bytes().to_vec();
    let before_status = peer.status.bytes().to_vec();
    assert!(peer.notifications().is_err());
    assert!(!peer.carrier());
    assert!(peer.transmit(&[0x88; 60]).is_err());
    assert!(peer.receive().is_err());
    assert_eq!(peer.id, before_id);
    assert_eq!(peer.pending, before_pending);
    assert_eq!(peer.send.bytes(), before_send);
    assert_eq!(peer.receive.bytes(), before_receive);
    assert_eq!(peer.status.bytes(), before_status);
    assert!(peer.queued.is_some());
    assert!(peer.notify_queued.is_some());
}
