// SPDX-License-Identifier: GPL-2.0-only
//! A class's queued reset serviced by the topology owner, on the
//! command/context/port model.
use super::super::*;
use crate::block::BlockDevice;
use crate::bus::dma::TestRegion;
use alloc::collections::BTreeMap;
use hub::model::{Hardware, Node, RegistersModel};

#[test]
fn a_queued_reset_rebinds_the_class_on_a_fresh_generation_like_usb_queue_reset_device() {
    let mut dma = TestRegion::new(512 * 1024 * 8);
    let nodes = BTreeMap::from([(0, Node::bot_disk(HIGH_SPEED))]);
    let hardware = Rc::new(RefCell::new(Hardware::new(64, nodes)));
    hardware.borrow_mut().root_status =
        Some(PP | CCS | PED | u32::from(HIGH_SPEED) << PORT_SPEED_SHIFT);
    let mut c = Controller::new(
        Box::new(RegistersModel(hardware.clone())),
        Clock {
            ticks_per_microsecond: 1,
        },
        &mut dma,
        "queued reset model".into(),
        crate::minimum_model::owned(Clock {
            ticks_per_microsecond: 1,
        }),
    )
    .unwrap();
    let mut failures = Vec::new();
    let devices = c.enumerate(&mut dma, &mut failures);
    let shared = Rc::new(RefCell::new(c));
    let mut host = Host::new(shared.clone(), &devices, &mut dma, &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    let old = devices[0].id;
    // Only the device's native class owner may ask.
    assert!(shared.borrow_mut().queue_reset(old).is_err());
    let mut original = Found::default();
    bind::bind(&shared, devices[0].clone(), &mut dma, &mut original);
    assert_eq!(original.disks.len(), 1);
    let firmware = crate::firmware::HandoffProvider::new(None);
    // The first look takes what enumeration left; then nothing is due.
    let first = host.poll(&mut dma, &firmware);
    assert!(first.removed.is_empty() && first.added.devices.is_empty());
    assert!(!host.due());
    shared.borrow_mut().queue_reset(old).unwrap();
    shared.borrow_mut().queue_reset(old).unwrap();
    assert!(host.due());

    let changes = host.poll(&mut dma, &firmware);
    assert!(
        changes.added.failures.is_empty(),
        "{:?}",
        changes.added.failures
    );
    assert_eq!(
        changes.removed.iter().map(|d| d.id).collect::<Vec<_>>(),
        [old]
    );
    assert_eq!(changes.added.devices.len(), 1);
    assert_ne!(changes.added.devices[0].id, old);
    assert_eq!(changes.added.disks.len(), 1);
    let mut sector = [0; 512];
    assert!(original.disks[0].read(0, &mut sector).is_err());
    let mut fresh = changes.added;
    fresh.disks[0].read(0, &mut sector).unwrap();
    assert!(shared.borrow_mut().queue_reset(old).is_err());

    assert!(!host.due());
    let quiet = host.poll(&mut dma, &firmware);
    assert!(quiet.removed.is_empty() && quiet.added.devices.is_empty());
    assert!(
        quiet.added.failures.is_empty(),
        "{:?}",
        quiet.added.failures
    );
}
