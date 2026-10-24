// SPDX-License-Identifier: MIT AND ISC
//! Genuine addressed MT7925 HCI/media owners, never fabricated ready evidence.
use super::*;
use crate::usb::xhci::{self, Found};

pub(crate) fn configuration() -> Vec<u8> {
    crate::usb::bluetooth::mediatek::media::tests::binding()
        .device()
        .configuration
        .clone()
}

pub(crate) fn peer(controller: Shared, dma: &mut dyn DmaAllocator) -> Hci<Host> {
    let binding = crate::usb::bluetooth::mediatek::media::tests::binding();
    let mut device = binding.device().clone();
    device.id = controller.borrow().test_device_id(device.slot).unwrap();
    let mut found = Found::default();
    xhci::model::bind(&controller, device, dma, &mut found);
    assert!(found.failures.is_empty(), "{:?}", found.failures);
    assert_eq!(found.bluetooth.len(), 1);
    let mut peer = found.bluetooth.pop().unwrap();
    // Actual class request/ordinary receives and interface/profile commands.
    // No firmware initialization, command-credit or radio success is invented.
    peer.io
        .control(xhci::setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0])
        .unwrap();
    assert_eq!(peer.io.receive(Pipe::Event).unwrap(), None);
    assert_eq!(peer.io.receive(Pipe::Acl).unwrap(), None);
    assert!(peer.io.events.queued.is_some());
    assert!(peer.io.input.queued.is_some());
    let binding = peer.binding().clone();
    media::generation_prepare(&mut peer.io, &binding, dma);
    peer
}

pub(crate) fn refuse(peer: &mut Hci<Host>, target: &Shared) {
    struct NoDma;
    impl DmaAllocator for NoDma {
        fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
            panic!("retired Bluetooth owner reached DMA allocation")
        }
    }
    peer.io.controller = target.clone();
    let before_events = peer.io.events.buffer.bytes().to_vec();
    let before_input = peer.io.input.buffer.bytes().to_vec();
    let before_transmit = peer.io.transmit.bytes().to_vec();
    assert!(
        peer.io
            .control(xhci::setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0])
            .is_err()
    );
    assert!(
        peer.io
            .control_read(xhci::setup(0xc0, 1, 0, 0, 64))
            .is_err()
    );
    assert!(peer.io.receive(Pipe::Event).is_err());
    assert!(peer.io.receive(Pipe::Acl).is_err());
    assert!(peer.io.write_acl(&[0x7a; 64]).is_err());
    assert!(peer.io.write_firmware(&[0x7a; 64], 100).is_err());
    assert!(peer.io.quiesce_bulk().is_err());
    media::generation_refuse(&mut peer.io, &mut NoDma);
    assert!(peer.io.close().is_err());
    assert!(!peer.io.closed);
    assert!(peer.io.events.queued.is_some());
    assert!(peer.io.input.queued.is_some());
    assert!(!peer.io.transmit_pending && !peer.io.control_pending);
    assert_eq!(peer.io.events.buffer.bytes(), before_events);
    assert_eq!(peer.io.input.buffer.bytes(), before_input);
    assert_eq!(peer.io.transmit.bytes(), before_transmit);
}
