//! Closed raw-byte tap stays bounded while guest polling/LED/stop/fault continues.
use super::*;

#[test]
fn repeated_closed_polling_and_led_commands_keep_guest_input_without_observer_growth() {
    for observed in [false, true] {
        let (mut c, h) = controller(Config::default());
        c.initialize().unwrap();
        h.borrow_mut().emit(Port::Keyboard, 0x1c);
        let prefix = c.poll_observed();
        assert_eq!(scan_bytes(&prefix), [0x1c]);
        let source = c.observation_sources().pop().unwrap();
        let closed = c.close_observation();
        assert!(matches!(
            closed.items.as_slice(),
            [Item::Change(Change::Stopped { next_order: 1, .. })]
        ));
        for index in 0..128 {
            h.borrow_mut().inject_led = vec![
                (Port::Keyboard, 0xf0),
                (Port::Keyboard, 0x1c),
                (Port::Keyboard, 0x1c),
            ];
            c.set_leds(index & 7).unwrap();
            let expected = vec![
                Input::Key {
                    usage: 4,
                    pressed: false,
                },
                Input::Key {
                    usage: 4,
                    pressed: true,
                },
            ];
            if observed {
                let polled = c.poll_observed();
                assert!(polled.first_error.is_none());
                assert_eq!(polled.inputs, expected);
                assert!(polled.observations.items.is_empty());
            } else {
                assert_eq!(c.poll().unwrap(), expected);
            }
            assert!(c.keyboard.drain_observed().is_empty());
            assert!(c.pending_observations.items.is_empty());
            assert_eq!(source.producer_frontier(), 1);
        }
        let stopped = c.stop_observed();
        assert!(stopped.first_error.is_none());
        assert_eq!(
            stopped.inputs,
            vec![Input::Key {
                usage: 4,
                pressed: false
            }]
        );
        assert!(stopped.observations.items.is_empty());
        assert!(c.close_observation().items.is_empty());
        assert_eq!(scan_bytes(&prefix), [0x1c]);
        assert_eq!(
            source.status(),
            Status::Stopped(StopCause::ObservationClosed)
        );
    }
}

#[test]
fn fault_and_repeated_refusal_after_close_do_not_capture_new_raw_payloads() {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    h.borrow_mut().emit(Port::Keyboard, 0x1c);
    let prefix = c.poll_observed();
    let closed = c.close_observation();
    assert_eq!(closed.items.len(), 1);
    h.borrow_mut().emit(Port::Keyboard, 0xff);
    let failed = c.poll_observed();
    assert_eq!(
        failed.first_error.unwrap().kind,
        ErrorKind::KeyboardSequence
    );
    assert!(failed.observations.items.is_empty());
    assert!(c.keyboard.drain_observed().is_empty());
    for _ in 0..16 {
        let polled = c.poll_observed();
        assert_eq!(polled.first_error.unwrap().kind, ErrorKind::NeedsReset);
        assert!(polled.observations.items.is_empty());
        assert!(c.pending_observations.items.is_empty());
    }
    assert!(c.close_observation().items.is_empty());
    assert_eq!(scan_bytes(&prefix), [0x1c]);
}
