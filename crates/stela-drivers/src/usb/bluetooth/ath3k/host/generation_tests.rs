// SPDX-License-Identifier: GPL-2.0-or-later
//! Native pre-HCI initializer admission, with a genuinely retained device ID.
use super::*;
use crate::usb::xhci::{self, Device};

pub(crate) fn configuration() -> Vec<u8> {
    vec![
        9, 2, 25, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 0xff, 0, 0, 0, 7, 5, 2, 2, 0, 2, 0,
    ]
}

pub(crate) fn peer(controller: Shared, dma: &mut dyn DmaAllocator) -> Bootloader<Host> {
    let configuration = configuration();
    let device = Device {
        id: controller.borrow().test_device_id(1).unwrap(),
        slot: 1,
        speed: xhci::HIGH_SPEED,
        location: "actual ATH3K initializer generation peer".into(),
        descriptor: [
            18, 1, 0, 2, 0, 0, 0, 64, 0xf3, 0x0c, 0, 0x30, 0, 1, 0, 0, 0, 1,
        ],
        configurations: vec![configuration.clone()],
        configuration,
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
        vendor_ethernet_tcr: None,
        vendor_ethernet_revision: None,
    };
    let binding = Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap();
    controller
        .borrow_mut()
        .device(device.id)
        .unwrap()
        .set_configuration(1)
        .unwrap();
    controller
        .borrow_mut()
        .device(device.id)
        .unwrap()
        .configure(&binding.endpoints(), None, dma)
        .unwrap();
    let mut peer = Bootloader::attach(controller, binding, dma).unwrap();
    peer.io.clock.ticks_per_microsecond = 1000;
    peer.io
        .control(xhci::setup(0x40, 1, 0, 0, 1), &[0x5a])
        .unwrap();
    assert_eq!(
        peer.io
            .control_read(xhci::setup(0xc0, 5, 0, 0, 1))
            .unwrap()
            .len(),
        1
    );
    peer.io.write_firmware(&[0xa5; 64], 3_000_000).unwrap();
    assert!(!peer.io.pending && !peer.io.control_pending);
    // Raw transport use does not manufacture an initialization result or a
    // runtime HCI identity, and leaves the one-attempt policy untouched.
    assert!(peer.initialization().is_none());
    peer
}

pub(crate) fn refuse(peer: &mut Bootloader<Host>, target: &Shared) {
    peer.io.controller = target.clone();
    let before = peer.io.buffer.bytes().to_vec();
    assert!(
        peer.io
            .control(xhci::setup(0x40, 1, 0, 0, 1), &[0x7a])
            .is_err()
    );
    assert!(peer.io.control_read(xhci::setup(0xc0, 5, 0, 0, 1)).is_err());
    assert!(peer.io.write_firmware(&[0x7a; 64], 3_000_000).is_err());
    assert!(peer.io.write_firmware(&[], 0).is_err());
    assert!(peer.io.quiesce_bulk().is_err());
    assert!(peer.io.close().is_err());
    assert!(!peer.io.pending && !peer.io.control_pending && !peer.io.closed);
    assert_eq!(peer.io.buffer.bytes(), before);
    assert!(peer.initialization().is_none());
}
