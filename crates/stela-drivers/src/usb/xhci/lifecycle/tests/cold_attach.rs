// SPDX-License-Identifier: GPL-2.0-only
//! A USB 3 root port that shows Cold Attach Status after the controller
//! started: Linux's port_event warm-resets it and binds the device.
use super::super::*;
use crate::bus::dma::TestRegion;
use alloc::collections::BTreeMap;

const RX_DETECT: u32 = 5;

#[test]
fn a_usb3_device_left_untrained_after_the_start_is_warm_reset_and_added_once() {
    let mut dma = TestRegion::new(512 * 1024 * 8);
    // A vendor-class leaf: only its enumeration is under test.
    let mut leaf = hub::model::Node::leaf(SUPER_SPEED);
    leaf.interface_class = Some(0xff);
    let nodes = BTreeMap::from([(0, leaf)]);
    let (mut controller, hardware) = hub::tests::controller(&mut dma, 32, nodes);
    hardware.borrow_mut().root_status = Some(PP | RX_DETECT << PLS_SHIFT);
    let mut failures = Vec::new();
    let devices = controller.enumerate(&mut dma, &mut failures);
    assert!(devices.is_empty() && failures.is_empty(), "{failures:?}");
    let shared = Rc::new(RefCell::new(controller));
    let mut host = Host::new(shared, &devices, &mut dma, &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    let firmware = crate::firmware::HandoffProvider::new(None);
    let changes = host.poll(&mut dma, &firmware);
    assert!(changes.added.devices.is_empty() && changes.added.failures.is_empty());
    // Terminations seen, the link never trained: no connection, only CAS.
    hardware.borrow_mut().root_status = Some(PP | CAS | RX_DETECT << PLS_SHIFT);
    let changes = host.poll(&mut dma, &firmware);
    assert!(
        changes.added.failures.is_empty(),
        "{:?}",
        changes.added.failures
    );
    assert_eq!(changes.added.devices.len(), 1);
    assert_eq!(changes.added.devices[0].speed, SUPER_SPEED);
    let status = hardware.borrow().root_status.unwrap();
    assert_eq!(status & (CAS | CCS | PED), CCS | PED);
    // The trained port is the new baseline: the device stays as it is.
    let changes = host.poll(&mut dma, &firmware);
    assert!(changes.added.devices.is_empty() && changes.removed.is_empty());
    assert_eq!(host.devices.len(), 1);
}
