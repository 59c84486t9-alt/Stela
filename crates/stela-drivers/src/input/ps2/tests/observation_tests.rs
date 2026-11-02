//! Single-controller controls retain actual scan bytes without Linux policy guesses.
use super::*;
mod closed;
use crate::input::observation::{Item, Knowledge, Payload, Status, StopCause};

fn scan_bytes(polled: &crate::input::observation::NativePoll<Error>) -> Vec<u8> {
    polled
        .observations
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Report(report) => match &report.payload {
                Payload::ScanSet2 { bytes } => Some(bytes.as_slice()),
                _ => None,
            },
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

#[test]
fn same_poll_preserves_raw_repeat_bytes_and_guest_suppression_without_fake_state() {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    let source = c.observation_sources().pop().unwrap();
    assert_eq!(source.initial_state(), InitialState::unknown());
    assert!(matches!(source.description().format, Format::ScanSet2));
    for byte in [0x1c, 0x1c, 0xf0, 0x1c] {
        h.borrow_mut().emit(Port::Keyboard, byte);
    }
    let before = h.borrow().consumed;
    let polled = c.poll_observed();
    assert!(polled.first_error.is_none());
    assert_eq!(
        h.borrow().consumed - before,
        4,
        "the same physical poll consumes each original byte once"
    );
    assert_eq!(
        polled.inputs,
        vec![
            Input::Key {
                usage: 4,
                pressed: true
            },
            Input::Key {
                usage: 4,
                pressed: false
            }
        ]
    );
    assert_eq!(scan_bytes(&polled), [0x1c, 0x1c, 0xf0, 0x1c]);
    assert_eq!(source.initial_state().keys, Knowledge::Unknown);
}

#[test]
fn partial_prefix_and_guest_hid_refusal_keep_actual_bytes_and_source_identity() {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    let source = c.observation_sources().pop().unwrap();
    h.borrow_mut().emit(Port::Keyboard, 0xe0);
    let prefix = c.poll_observed();
    assert!(prefix.first_error.is_none());
    assert_eq!(scan_bytes(&prefix), [0xe0]);
    assert!(prefix.inputs.is_empty());
    h.borrow_mut().emit(Port::Keyboard, 0x50);
    let polled = c.poll_observed();
    assert_eq!(
        polled.first_error.unwrap().kind,
        ErrorKind::UnsupportedScanCode(208)
    );
    assert_eq!(scan_bytes(&polled), [0x50]);
    assert!(polled.inputs.is_empty());
    assert_eq!(source.status(), Status::Producing);
    assert_eq!(source.producer_frontier(), 2);
    assert!(source.same_object(&c.observation_sources()[0]));
}

#[test]
fn guest_pause_pulse_is_not_fabricated_as_linux_press_release_or_syn() {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    let raw = [0xe1, 0x14, 0x77, 0xe1, 0xf0, 0x14, 0xf0, 0x77];
    for byte in raw {
        h.borrow_mut().emit(Port::Keyboard, byte);
    }
    let polled = c.poll_observed();
    assert!(polled.first_error.is_none());
    assert_eq!(scan_bytes(&polled), raw);
    assert_eq!(
        polled.inputs,
        vec![
            Input::Key {
                usage: 0x48,
                pressed: true
            },
            Input::Key {
                usage: 0x48,
                pressed: false
            }
        ]
    );
    assert!(!polled.observations.items.iter().any(|item| matches!(item, Item::Report(report) if matches!(&report.payload, Payload::Linux { .. }))));
}

#[test]
fn fatal_byte_keeps_consumed_prefix_before_stop_and_original_first_cause() {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    for byte in [0x1c, 0xff] {
        h.borrow_mut().emit(Port::Keyboard, byte);
    }
    let polled = c.poll_observed();
    assert_eq!(
        polled.first_error.unwrap().kind,
        ErrorKind::KeyboardSequence
    );
    assert_eq!(
        polled.inputs,
        vec![Input::Key {
            usage: 4,
            pressed: true
        }]
    );
    let report = polled
        .observations
        .items
        .iter()
        .position(|item| matches!(item, Item::Report(_)))
        .unwrap();
    let stopped = polled
        .observations
        .items
        .iter()
        .position(|item| {
            matches!(
                item,
                Item::Change(Change::Stopped {
                    cause: StopCause::TransportFailed,
                    next_order: 1,
                    ..
                })
            )
        })
        .unwrap();
    assert!(report < stopped);
    assert_eq!(scan_bytes(&polled), [0x1c, 0xff]);
    assert_eq!(
        c.observation_sources()[0].status(),
        Status::Stopped(StopCause::TransportFailed)
    );
    assert_eq!(
        c.release_inputs(),
        vec![Input::Key {
            usage: 4,
            pressed: false
        }]
    );
    assert!(c.close_observation().items.is_empty());
}

#[test]
fn physical_stop_preserves_pending_bytes_but_not_guest_synthetic_release() {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    h.borrow_mut().emit(Port::Keyboard, 0x1c);
    let polled = c.stop_observed();
    assert!(polled.first_error.is_none());
    assert_eq!(
        polled.inputs,
        vec![
            Input::Key {
                usage: 4,
                pressed: true
            },
            Input::Key {
                usage: 4,
                pressed: false
            }
        ]
    );
    assert_eq!(scan_bytes(&polled), [0x1c]);
    assert!(matches!(
        polled.observations.items.last(),
        Some(Item::Change(Change::Stopped { next_order: 1, .. }))
    ));
}

#[test]
fn metadata_close_preserves_guest_owner_and_old_source_never_reopens() {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    let old = c.observation_sources().pop().unwrap();
    let writes = h.borrow().writes.len();
    let batch = c.close_observation();
    assert_eq!(h.borrow().writes.len(), writes);
    assert!(c.is_ready());
    assert!(matches!(
        batch.items.last(),
        Some(Item::Change(Change::Stopped { next_order: 0, .. }))
    ));
    h.borrow_mut().emit(Port::Keyboard, 0x1c);
    assert_eq!(
        c.poll().unwrap(),
        vec![Input::Key {
            usage: 4,
            pressed: true
        }]
    );
    assert_eq!(old.status(), Status::Stopped(StopCause::ObservationClosed));
    assert!(old.same_object(&c.observation_sources()[0]));
    c.stop().unwrap();
    c.initialize().unwrap();
    let fresh = c.observation_sources().pop().unwrap();
    assert!(!fresh.same_object(&old));
    assert_eq!(fresh.initial_state(), InitialState::unknown());
}

#[test]
fn legacy_wrappers_capture_existing_raw_prefix_before_retained_stop() {
    for stop in [false, true] {
        let (mut c, _h) = controller(Config::default());
        c.initialize().unwrap();
        let old = c.observation_sources().pop().unwrap();
        // This is the SAME original decoder, not reconstructed guest events.
        c.keyboard
            .feed(0x1c, 0, c.config.packet_timeout_us, &mut c.events, true)
            .unwrap();
        if stop {
            c.stop().unwrap();
        } else {
            c.poll().unwrap();
        }
        let batch = c.close_observation();
        let report = batch
            .items
            .iter()
            .position(|item| matches!(item, Item::Report(_)))
            .unwrap();
        let frontier = batch
            .items
            .iter()
            .position(|item| matches!(item, Item::Change(Change::Stopped { next_order: 1, .. })))
            .unwrap();
        assert!(report < frontier);
        let Item::Report(report) = &batch.items[report] else {
            unreachable!()
        };
        assert!(matches!(&report.payload, Payload::ScanSet2 { bytes } if bytes == &[0x1c]));
        assert!(report.source.same_object(&old));
        assert_eq!(old.status(), Status::Stopped(StopCause::ObservationClosed));
        assert!(c.close_observation().items.is_empty());
    }
}
