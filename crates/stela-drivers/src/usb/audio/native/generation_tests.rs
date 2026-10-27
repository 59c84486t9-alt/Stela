// SPDX-License-Identifier: GPL-2.0-or-later
//! Real configured UAC2 owners for xHCI generation admission tests.
use super::*;
use crate::usb::xhci::{self, Found};

pub(crate) struct Peer {
    owner: UsbAudio,
    endpoint: Endpoint,
    ticket: IsoTransfer,
    data: DmaBuffer,
}

pub(crate) fn configuration() -> Vec<u8> {
    crate::usb::audio::test_configuration()
}

pub(crate) fn peer(shared: Shared, dma: &mut dyn DmaAllocator) -> Peer {
    let configuration = configuration();
    let device = Device {
        id: shared.borrow().test_device_id(1).unwrap(),
        slot: 1,
        speed: xhci::HIGH_SPEED,
        location: "representative ASUS UAC2 actual native generation peer".into(),
        descriptor: [
            18, 1, 0, 2, 0, 0, 0, 64, 5, 0x0b, 0xe1, 0x1b, 0, 1, 0, 0, 0, 1,
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
    let mut found = Found::default();
    xhci::model::bind(&shared, device, dma, &mut found);
    assert!(found.failures.is_empty(), "{:?}", found.failures);
    assert_eq!(found.audio.len(), 1);
    let mut owner = found.audio.pop().unwrap();
    assert_eq!(owner.binding().graph.protocol, crate::usb::audio::UAC2);
    let format = owner
        .binding()
        .formats
        .iter()
        .find(|f| f.direction == Direction::Playback)
        .unwrap()
        .clone();
    let endpoint = format.data;
    let native = owner.generation_transport();
    native.validate().unwrap();
    native.preflight(&[endpoint]).unwrap();
    native
        .alternate(format.interface, format.alternate)
        .unwrap();
    native.configure(Direction::Playback, &[endpoint]).unwrap();
    let mut data = dma.allocate(4096, 4096).unwrap();
    data.bytes_mut().fill(0xa5);
    let ticket = native.submit(&endpoint, data.physical(), 192).unwrap();
    Peer {
        owner,
        endpoint,
        ticket,
        data,
    }
}

pub(crate) fn refuse(peer: &mut Peer, target: &Shared) {
    let expected = target
        .borrow_mut()
        .device(peer.owner.generation_transport().id)
        .err()
        .unwrap();
    let before_frontend = peer.owner.generation_snapshot();
    let before_progress = peer.owner.progress();
    let native = peer.owner.generation_transport();
    native.shared = target.clone();
    let before_playback = native.playback.endpoints.clone();
    let before_capture = native.capture.endpoints.clone();
    let before_allocators = (
        native.playback.allocator.remaining(),
        native.capture.allocator.remaining(),
    );
    let before_data = peer.data.bytes().to_vec();
    assert!(native.validate().is_err());
    assert!(native.control(xhci::setup(0x80, 8, 0, 0, 1), &[]).is_err());
    assert!(native.preflight(&[peer.endpoint]).is_err());
    assert!(
        native
            .configure(Direction::Capture, &[peer.endpoint])
            .is_err()
    );
    assert!(
        native
            .deconfigure(Direction::Playback, &[peer.endpoint])
            .is_err()
    );
    assert!(native.deconfigure(Direction::Capture, &[]).is_err()); // Empty cached owner is fenced too.
    assert!(
        native
            .submit(&peer.endpoint, peer.data.physical(), 192)
            .is_err()
    );
    assert!(matches!(native.completed(&peer.ticket), Some(Err(_))));
    assert_eq!(native.playback.endpoints, before_playback);
    assert_eq!(native.capture.endpoints, before_capture);
    assert_eq!(
        (
            native.playback.allocator.remaining(),
            native.capture.allocator.remaining()
        ),
        before_allocators
    );
    assert_eq!(peer.data.bytes(), before_data);
    // An exact identity error distinguishes the new frontend guard from the
    // pre-existing NotRunning/Busy refusals of this idle PCM owner.
    macro_rules! refused {
        ($result:expr) => {
            assert_eq!(
                $result,
                Err(crate::usb::audio::Error::Transport(expected.clone()))
            );
        };
    }
    refused!(peer.owner.start_playback(0, 48_000, &[0; 192], false));
    refused!(peer.owner.write_playback(&[0; 192]));
    refused!(peer.owner.finish_playback());
    refused!(peer.owner.connector_status(3));
    refused!(peer.owner.start_capture(0, 48_000));
    let mut output = [0xa5; 192];
    refused!(peer.owner.read_capture(&mut output));
    refused!(
        peer.owner
            .feature_value(2, 0, crate::usb::audio::FeatureControl::Bass)
    );
    refused!(
        peer.owner
            .feature_range(2, 0, crate::usb::audio::FeatureControl::Delay)
    );
    refused!(peer.owner.set_feature_value(
        2,
        0,
        crate::usb::audio::FeatureControl::AutomaticGain,
        crate::usb::audio::FeatureValue::Enabled(true)
    ));
    assert_eq!(output, [0xa5; 192]);
    refused!(peer.owner.poll());
    refused!(peer.owner.stop_playback());
    refused!(peer.owner.stop_capture());
    refused!(peer.owner.shutdown());
    assert_eq!(peer.owner.generation_snapshot(), before_frontend);
    assert_eq!(peer.owner.progress(), before_progress);
}
