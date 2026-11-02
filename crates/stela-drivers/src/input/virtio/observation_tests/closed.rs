//! Closed observation never adds guest events to pending/refused observer work.
use super::*;

fn complete_next(input: &mut VirtioInput, value: i32) {
    let slot = USED + 4 + 8 * usize::from(input.used % input.entries);
    input.events.write(0, 1u16);
    input.events.write(2, 30u16);
    input.events.write(4, value);
    input.queue.write(slot, 0u32);
    input.queue.write(slot + 4, EVENT_BYTES as u32);
    input.queue.write(USED + 2, input.used.wrapping_add(1));
}

#[test]
fn closed_polling_preserves_guest_stream_without_new_observer_payloads() {
    for observed in [false, true] {
        model(|input| {
            complete(
                input,
                &[Event {
                    kind: 1,
                    code: 30,
                    value: 1,
                }],
            );
            let prefix = input.poll_observed();
            assert_eq!(prefix.observations.items.len(), 1);
            let source = input.observation_sources().pop().unwrap();
            let closed = input.close_observation();
            assert_eq!(input.used, 1, "close must not poll hardware");
            assert!(matches!(
                closed.items.as_slice(),
                [Item::Change(Change::Stopped { next_order: 1, .. })]
            ));
            for index in 0..256 {
                let value = index & 1;
                complete_next(input, value);
                if observed {
                    let polled = input.poll_observed();
                    assert!(polled.first_error.is_none());
                    assert_eq!(
                        polled.inputs,
                        vec![Input::Key {
                            usage: 4,
                            pressed: value != 0
                        }]
                    );
                    assert!(polled.observations.items.is_empty());
                } else {
                    let raw = input.poll();
                    assert_eq!(raw.len(), 1);
                    assert_eq!((raw[0].kind, raw[0].code, raw[0].value), (1, 30, value));
                }
                assert!(input.pending_observations.items.is_empty());
                assert_eq!(source.producer_frontier(), 1);
            }
            assert_eq!(
                input.used, 257,
                "every same physical completion consumed exactly once"
            );
            assert!(input.close_observation().items.is_empty());
            let Item::Report(report) = &prefix.observations.items[0] else {
                panic!("preclose prefix lost")
            };
            assert!(
                matches!(&report.payload, Payload::Linux { events } if events.len() == 1 && events[0].value == 1)
            );
            assert_eq!(
                source.status(),
                Status::Stopped(StopCause::ObservationClosed)
            );
        });
    }
}

#[test]
fn physical_queue_fault_after_close_keeps_typed_error_without_new_stop_or_payload() {
    model(|input| {
        let closed = input.close_observation();
        assert_eq!(closed.items.len(), 1);
        input.queue.write(USED + 4, u32::from(QUEUE_ENTRIES));
        input.queue.write(USED + 2, 1u16);
        let polled = input.poll_observed();
        assert_eq!(polled.first_error, Some(PollError::BrokenQueue));
        assert!(polled.observations.items.is_empty());
        assert!(input.pending_observations.items.is_empty());
        assert!(input.close_observation().items.is_empty());
    });
}
