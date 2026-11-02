//! Existing DMA/register fixtures exercise the actual virtio used-ring poll.
use super::*;
use crate::bus::dma::TestRegion;
use crate::input::observation::{Item, Payload};
use alloc::{boxed::Box, vec};

pub(super) fn model(run: impl FnOnce(&mut VirtioInput)) {
    let mut memory = TestRegion::new(8192);
    let mut notify = Box::new(0u16);
    // SAFETY: this model owns the sole aligned volatile notification register;
    // no device, interrupt worker or second driver accesses it.
    let mmio = unsafe { Mmio::new((&mut *notify as *mut u16) as u64) };
    let producer = Producer::new(
        Description {
            origin: Origin::Virtio,
            format: Format::Linux {
                capabilities: Capabilities {
                    keys: vec![30, 247],
                    switches: vec![3],
                },
            },
        },
        InitialState::unknown(),
    );
    let mut input = VirtioInput {
        notify: mmio,
        queue: memory.allocate(4096, 4096).unwrap(),
        events: memory.allocate(4096, 4096).unwrap(),
        entries: QUEUE_ENTRIES,
        used: 0,
        available: QUEUE_ENTRIES,
        broken: false,
        name: String::from("fixture"),
        translator: Translator::new(None),
        observation: Some(producer),
        pending_observations: Batch::default(),
        capability_reads: core::array::from_fn(|_| CapabilityRead::Refused(None)),
    };
    run(&mut input);
    drop(input);
    // The original backing allocations/register storage outlive all model use.
    drop(notify);
    drop(memory);
}

pub(super) fn complete(input: &mut VirtioInput, raw: &[Event]) {
    for (slot, event) in raw.iter().enumerate() {
        let at = slot * EVENT_BYTES;
        input.events.write(at, event.kind);
        input.events.write(at + 2, event.code);
        input.events.write(at + 4, event.value);
        input.queue.write(USED + 4 + 8 * slot, slot as u32);
        input.queue.write(USED + 8 + 8 * slot, EVENT_BYTES as u32);
    }
    input.queue.write(USED + 2, raw.len() as u16);
}

#[test]
fn raw_key_switch_repeat_and_syn_survive_the_same_guest_poll() {
    model(|input| {
        let raw = [
            Event {
                kind: 1,
                code: 247,
                value: 1,
            },
            Event {
                kind: 0,
                code: 0,
                value: 0,
            },
            Event {
                kind: 1,
                code: 247,
                value: 2,
            },
            Event {
                kind: 1,
                code: 30,
                value: 1,
            },
            Event {
                kind: 5,
                code: 3,
                value: -1,
            },
            Event {
                kind: 0,
                code: 0,
                value: 0,
            },
        ];
        let source = input.observation_sources().pop().unwrap();
        let mut expected = Translator::new(None);
        let guest: Vec<_> = raw
            .iter()
            .flat_map(|event| expected.translate(*event))
            .collect();
        complete(input, &raw);
        let polled = input.poll_observed();
        assert!(polled.first_error.is_none());
        assert_eq!(input.used, raw.len() as u16);
        assert_eq!(input.available, QUEUE_ENTRIES + raw.len() as u16);
        assert_eq!(polled.inputs, guest);
        let Item::Report(report) = &polled.observations.items[0] else {
            panic!("raw report lost")
        };
        assert!(report.source.same_object(&source));
        let Payload::Linux { events } = &report.payload else {
            panic!("wrong payload")
        };
        assert_eq!(
            events
                .iter()
                .map(|event| (event.kind, event.code, event.value))
                .collect::<Vec<_>>(),
            raw.iter()
                .map(|event| (event.kind, event.code, event.value))
                .collect::<Vec<_>>()
        );
        assert_eq!(source.initial_state(), InitialState::unknown());
    });
}

#[test]
fn malformed_used_id_keeps_decoded_prefix_before_typed_fault_and_stop() {
    model(|input| {
        complete(
            input,
            &[Event {
                kind: 1,
                code: 30,
                value: 1,
            }],
        );
        input.queue.write(USED + 12, u32::from(QUEUE_ENTRIES));
        input.queue.write(USED + 2, 2u16);
        let polled = input.poll_observed();
        assert_eq!(polled.first_error, Some(PollError::BrokenQueue));
        assert_eq!(input.used, 1);
        assert!(input.broken);
        assert_eq!(
            polled.inputs,
            vec![Input::Key {
                usage: 4,
                pressed: true
            }]
        );
        let [
            Item::Report(report),
            Item::Change(Change::Stopped {
                next_order: 1,
                cause: StopCause::TransportFailed,
                ..
            }),
        ] = polled.observations.items.as_slice()
        else {
            panic!("prefix/stop order lost")
        };
        let Payload::Linux { events } = &report.payload else {
            panic!("wrong payload")
        };
        assert_eq!(
            events.len(),
            1,
            "no SYN invented at an incomplete poll prefix"
        );
    });
}

mod closed;

#[test]
fn legacy_raw_poll_closes_observer_instead_of_reopening_skipped_controls() {
    model(|input| {
        complete(
            input,
            &[Event {
                kind: 1,
                code: 247,
                value: 1,
            }],
        );
        assert_eq!(input.poll().len(), 1);
        assert_eq!(
            input.observation_sources()[0].status(),
            Status::Stopped(StopCause::ObservationClosed)
        );
        assert_eq!(input.used, 1);
    });
}

#[test]
fn config_bitmap_is_data_and_preserves_wide_positions_without_state_inference() {
    let mut bits = [0u8; 128];
    for code in [30usize, 247, 767, 1023] {
        bits[code / 8] |= 1 << (code % 8);
    }
    assert_eq!(bitmap_codes(&bits), vec![30, 247, 767, 1023]);
    assert!(bitmap_codes(&[]).is_empty());
}

#[test]
fn legacy_poll_retains_prior_accepted_prefix_and_stop_for_owner_drain() {
    model(|input| {
        let producer = input.observation.as_mut().unwrap();
        input.pending_observations.publish(
            producer,
            Payload::Linux {
                events: vec![observation::Event {
                    kind: 1,
                    code: 247,
                    value: 1,
                }],
            },
        );
        complete(
            input,
            &[Event {
                kind: 1,
                code: 30,
                value: 1,
            }],
        );
        assert_eq!(input.poll().len(), 1);
        let batch = input.close_observation();
        let [
            Item::Report(report),
            Item::Change(Change::Stopped {
                next_order: 1,
                cause: StopCause::ObservationClosed,
                ..
            }),
        ] = batch.items.as_slice()
        else {
            panic!("legacy poll lost accepted prefix/stop")
        };
        assert!(
            matches!(&report.payload, Payload::Linux { events } if events.len() == 1 && events[0].code == 247)
        );
        assert!(input.close_observation().items.is_empty());
    });
}
