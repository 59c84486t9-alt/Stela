// SPDX-License-Identifier: GPL-2.0-or-later
//! Authored software-peer controls; no physical receiver descriptor is implied.
use super::super::*;
use crate::usb::xhci::model::{self, RegionAllocator};
use alloc::{rc::Rc, vec};
use core::cell::RefCell;

// Two numbered reports. Common + preferred keyboard usages are E0,4,5;
// the second branch's Consumer aliases do not become extra keyboard fields.
// Report 2 does the converse: preferred Consumer E9, alternate Keyboard 4.
const ALTERNATIVES: &[u8] = &[
    5, 1, 9, 6, 0xa1, 1, 0x85, 1, 0x15, 0, 0x25, 1, 0x75, 1, 0x95, 3, 5, 7, 9, 0xe0, 0xa9, 1, 0x19,
    4, 0x29, 5, 0xa9, 0, 0xa9, 1, 0x1b, 0xe9, 0, 0x0c, 0, 0x2b, 0xea, 0, 0x0c, 0, 0xa9, 0, 0x81, 2,
    0x75, 5, 0x95, 1, 0x81, 1, 5, 8, 9, 1, 0xa9, 1, 9, 2, 0xa9, 0, 0xa9, 1, 9, 3, 0xa9, 0, 0x75, 1,
    0x95, 2, 0x91, 2, 0x75, 6, 0x95, 1, 0x91, 1, 5, 0x0c, 0xa9, 1, 9, 0xe9, 0xa9, 0, 0xa9, 1, 9,
    0xea, 0xa9, 0, 0x75, 8, 0x95, 1, 0xb1, 2, 0xc0, 5, 0x0c, 9, 1, 0xa1, 1, 0x85, 2, 0xa9, 1, 0x0b,
    0xe9, 0, 0x0c, 0, 0xa9, 0, 0xa9, 1, 0x0b, 4, 0, 7, 0, 0xa9, 0, 0x81, 2, 0xc0,
];

#[test]
fn selected_keyboard_and_consumer_branches_keep_report_bits_and_control_metadata() {
    let descriptor = Descriptor::parse(ALTERNATIVES).unwrap();
    let legacy = report::parse(ALTERNATIVES).unwrap();
    assert_eq!(descriptor.input_bytes(), 2);
    assert_eq!(legacy.input_bytes, descriptor.input_bytes());
    assert!(legacy.pointer.is_none());
    let keys = legacy.keys.unwrap();
    assert_eq!(keys.report, Some(1));
    assert_eq!(keys.pressed(&[7]), Some(vec![0xe0, 4, 5]));
    let input = descriptor.layout(ReportType::Input, 1).unwrap();
    assert_eq!(input.bits, 8);
    assert_eq!(input.fields.len(), 1);
    assert_eq!(
        input.fields[0].usages,
        [0x0007_00e0, 0x0007_0004, 0x0007_0005]
    );
    let frame = descriptor.decode(&[1, 7]).unwrap();
    assert_eq!(frame.bytes, [1, 7]);
    assert_eq!(
        frame.samples.iter().map(|s| s.usage).collect::<Vec<_>>(),
        [Some(0x0007_00e0), Some(0x0007_0004), Some(0x0007_0005)]
    );
    for (element, sample) in frame.samples.iter().enumerate() {
        assert_eq!(
            (sample.field, sample.element, sample.collection),
            (0, element, Some(0))
        );
        assert_eq!(sample.value, descriptor::Value::Scalar(1));
    }
    let output = descriptor.layout(ReportType::Output, 1).unwrap();
    assert_eq!((output.bits, output.wire_bytes()), (8, 2));
    assert_eq!(output.fields[0].usages, [0x0008_0001, 0x0008_0002]);
    let feature = descriptor.layout(ReportType::Feature, 1).unwrap();
    assert_eq!((feature.bits, feature.wire_bytes()), (8, 2));
    assert_eq!(feature.fields[0].usages, [0x000c_00e9]);
    let consumer = descriptor.decode(&[2, 1]).unwrap();
    assert_eq!(
        (consumer.samples[0].usage, consumer.samples[0].collection),
        (Some(0x000c_00e9), Some(1))
    );
    let mut events = events::Decoder::default();
    assert_eq!(
        events.update(&descriptor, &consumer),
        [events::Event::Consumer {
            report: 2,
            usage: 0xe9,
            pressed: true
        }]
    );
}

#[test]
fn delimiter_local_state_resets_at_all_main_items_and_ignores_global_push_pop() {
    let bytes = [
        5, 1, 9, 6, 0xa1, 1, 0x85, 4, 0x15, 0, 0x25, 1, 0x75, 1, 0x95, 2, 5, 7, 0xa9, 1, 0x19, 4,
        0x29, 5, 0xa9, 0, 0xa9, 1, 0xa4, 5, 0x0c, 9, 0xe9, 0xb4, 0xa9, 0, 0x81, 2,
        // Output resets the alternative counter just like Input and Feature.
        5, 8, 0xa9, 1, 9, 1, 0xa9, 0, 0x95, 1, 0x91, 2, 5, 7, 0xa9, 1, 9, 6, 0xa9, 0, 0x81, 2, 0xa9,
        1, 9, 7, 0xa9, 0, 0xb1, 2, 0xa9, 1, 9, 8, 0xa9, 0, 0x81, 2,
        // Physical Collection may have delimited aliases; its Main resets.
        5, 1, 0xa9, 1, 9, 1, 0xa9, 0, 0xa1, 0, 5, 7, 0xa9, 1, 9, 9, 0xa9, 0, 0x81, 2, 0xc0, 0xa9, 1,
        9, 10, 0xa9, 0, 0x81, 2, 0xc0,
    ];
    let d = Descriptor::parse(&bytes).unwrap();
    let legacy = report::parse(&bytes).unwrap();
    assert_eq!(legacy.input_bytes, d.input_bytes());
    let frame = d.decode(&[4, 0x7f]).unwrap();
    assert_eq!(
        frame
            .samples
            .iter()
            .map(|s| s.usage.unwrap() & 0xffff)
            .collect::<Vec<_>>(),
        [4, 5, 6, 8, 9, 10]
    );
    assert_eq!(
        legacy.keys.unwrap().pressed(&[0x7f]),
        Some(vec![4, 5, 6, 8, 9, 10])
    );
    assert_eq!(d.collections[1].usage, 0x0001_0001);
}

#[test]
fn short_trailing_and_extended_usages_follow_pinned_linux_page_completion() {
    let bytes = [
        5, 1, 9, 6, 0xa1, 1, 0x15, 0, 0x25, 1, 0x75, 1, 0x95, 3, 5, 7, 0xa9, 1, 9, 4, 0x0b, 5, 0,
        7, 0, 9, 6, 0xa9, 0,
        // Ignored aliases still mutate the global environment. Extended
        // preferred usage5 must keep page7; trailing short4/6 complete pageC.
        0xa9, 1, 5, 0x0c, 9, 0xe9, 0xa9, 0, 0x81, 2, 0xc0,
    ];
    let d = Descriptor::parse(&bytes).unwrap();
    assert_eq!(
        d.layout(ReportType::Input, 0).unwrap().fields[0].usages,
        [0x000c_0004, 0x0007_0005, 0x000c_0006]
    );
    assert_eq!(
        report::parse(&bytes).unwrap().keys.unwrap().pressed(&[7]),
        Some(vec![5])
    );
}

#[test]
fn extended_preferred_pointer_range_keeps_signed_fields_and_ignores_keyboard_aliases() {
    let bytes = [
        5, 1, 9, 2, 0xa1, 1, 0x85, 6, 0x15, 0x81, 0x25, 0x7f, 0x75, 8, 0x95, 2, 0xa9, 1, 0x1b,
        0x30, 0, 1, 0, 0x2b, 0x31, 0, 1, 0, 0xa9, 0, 0xa9, 1, 0x1b, 4, 0, 7, 0, 0x2b, 5, 0, 7, 0,
        0xa9, 0, 0x81, 6, 0xc0,
    ];
    let d = Descriptor::parse(&bytes).unwrap();
    let legacy = report::parse(&bytes).unwrap();
    assert_eq!(legacy.input_bytes, 3);
    assert_eq!(legacy.input_bytes, d.input_bytes());
    assert!(legacy.keys.is_none());
    let pointer = legacy.pointer.unwrap();
    assert_eq!(pointer.report, Some(6));
    assert_eq!(pointer.x.unwrap().offset, 0);
    assert_eq!(pointer.y.unwrap().offset, 8);
    assert_eq!(pointer.x.unwrap().read(&[0xff, 2]), Some(-1));
    assert_eq!(pointer.y.unwrap().read(&[0xff, 2]), Some(2));
    let frame = d.decode(&[6, 0xff, 2]).unwrap();
    assert_eq!(frame.samples[0].usage, Some(0x0001_0030));
    assert_eq!(frame.samples[1].usage, Some(0x0001_0031));
    assert_eq!(frame.samples[0].value, descriptor::Value::Scalar(-1));
    assert_eq!(frame.samples[1].value, descriptor::Value::Scalar(2));
}

#[test]
fn balanced_empty_sets_do_not_invent_usages_or_select_a_later_alias() {
    let bytes = [
        5, 7, 0x15, 0, 0x25, 1, 0x75, 1, 0x95, 1, 0xa9, 1, 0xa9, 0, 0xa9, 1, 9, 4, 0xa9, 0, 0x81,
        2, 0xa9, 1, 9, 5, 0xa9, 0, 0x81, 2,
    ];
    let d = Descriptor::parse(&bytes).unwrap();
    let frame = d.decode(&[3]).unwrap();
    assert_eq!(frame.samples[0].usage, None);
    assert_eq!(frame.samples[1].usage, Some(0x0007_0005));
    assert_eq!(
        report::parse(&bytes).unwrap().keys.unwrap().pressed(&[3]),
        Some(vec![5])
    );
}

fn malformed() -> Vec<Vec<u8>> {
    let mut cases = vec![
        vec![0xa9, 0],
        vec![0xa9, 2],
        vec![0xa8],
        vec![0xa9],
        vec![0xaa, 1],
        vec![0xa9, 1],
        vec![0xa9, 1, 0xa9, 1],
        vec![0xa9, 1, 0x81, 2],
        vec![0xa9, 1, 0xa1, 0],
        vec![0xa9, 1, 0x19, 4, 0xa9, 0],
        vec![0x19, 4, 0xa9, 1],
        vec![0xa9, 1, 0x29, 4, 0xa9, 0],
        vec![0xa9, 1, 0x19, 5, 0x29, 4, 0xa9, 0],
        vec![0xa9, 1, 0x1b, 4, 0, 7, 0, 0x29, 5, 0xa9, 0],
        vec![0xa9, 1, 0x1b, 4, 0, 7, 0, 0x2b, 5, 0, 0x0c, 0, 0xa9, 0],
        vec![0xa9, 1, 9, 4, 0xa9, 0, 0xa9, 1, 0x19, 6, 0x29, 5, 0xa9, 0],
        vec![0xa9, 1, 9, 4, 0xa9, 0, 0xa9, 1, 0x19, 6, 0xa9, 0],
        vec![0xa9, 1, 9, 4, 0xa9, 0, 0x00],
    ];
    // HID1.11 prohibits delimiter usages on Application Collections and all
    // three Array Main kinds, independently of the eventual input consumer.
    for main in [[0xa1, 1], [0x81, 0], [0x91, 0], [0xb1, 0]] {
        let mut b = vec![0xa9, 1, 9, 4, 0xa9, 0];
        b.extend(main);
        cases.push(b);
    }
    cases
}

#[test]
fn malformed_delimiters_and_ignored_ranges_are_refused_by_both_readers() {
    for bytes in malformed() {
        assert!(
            Descriptor::parse(&bytes).is_err(),
            "complete reader accepted {bytes:x?}"
        );
        assert!(
            report::parse(&bytes).is_err(),
            "legacy reader accepted {bytes:x?}"
        );
    }
}

#[test]
fn usage_and_empty_branch_limits_include_ignored_alternatives() {
    for bytes in [
        vec![5, 7, 0xa9, 1, 0x19, 0, 0x2a, 0, 0x30, 0xa9, 0],
        vec![
            5, 7, 0xa9, 1, 9, 4, 0xa9, 0, 0xa9, 1, 0x19, 0, 0x2a, 0, 0x30, 0xa9, 0,
        ],
        vec![
            5, 7, 0xa9, 1, 0x19, 0, 0x2a, 0xdf, 0x2e, 0xa9, 0, 0xa9, 1, 0x19, 0, 0x2a, 0xe7, 3,
            0xa9, 0,
        ],
        [0xa9, 1, 0xa9, 0].repeat(12_289),
    ] {
        assert!(Descriptor::parse(&bytes).is_err());
        assert!(report::parse(&bytes).is_err());
    }
}

fn interface(bytes: &[u8], boot: bool) -> Interface {
    let length = bytes.len() as u16;
    Interface {
        number: 4,
        alternate: 0,
        class: CLASS,
        subclass: u8::from(boot),
        protocol: u8::from(boot),
        endpoints: vec![Endpoint {
            address: 0x81,
            attributes: 3,
            max_packet: 16,
            interval: 1,
            companion: None,
        }],
        extra: vec![vec![
            9,
            HID_DESCRIPTOR,
            0x11,
            1,
            0,
            1,
            REPORT_DESCRIPTOR,
            length as u8,
            (length >> 8) as u8,
        ]],
    }
}

#[test]
fn get_descriptor_dma_poll_and_control_use_only_selected_aliases() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: backing outlives every native DMA owner in this test.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (controller, hardware) = model::cancellation_controller(&mut dma);
    hardware
        .borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, ALTERNATIVES.to_vec()));
    let shared: Shared = Rc::new(RefCell::new(controller));
    let mut device = model::device(Vec::new());
    device.id = shared.borrow().test_device_id(1).unwrap();
    let interface = interface(ALTERNATIVES, false);
    let mut input = UsbInput::new(
        shared,
        &device,
        &interface,
        interface.endpoints[0],
        &mut dma,
    )
    .unwrap()
    .unwrap();
    assert_eq!(input.report_descriptor(), ALTERNATIVES);
    assert!(hardware.borrow().setup.iter().any(|(r, _)| *r
        == [
            0x81,
            GET_DESCRIPTOR,
            0,
            REPORT_DESCRIPTOR,
            4,
            0,
            ALTERNATIVES.len() as u8,
            0
        ]));
    assert!(input.poll_hid().reports.is_empty());
    let ticket = input.queued.unwrap();
    input.buffer.bytes_mut().fill(0xa5);
    hardware.borrow_mut().push_event(vec![1, 7]);
    let first = input.poll_hid();
    assert_eq!(&input.buffer.bytes()[..2], &[1, 7]);
    assert_ne!(input.queued, Some(ticket));
    assert_eq!(
        first.inputs,
        [
            Input::Key {
                usage: 0xe0,
                pressed: true
            },
            Input::Key {
                usage: 4,
                pressed: true
            },
            Input::Key {
                usage: 5,
                pressed: true
            }
        ]
    );
    assert!(
        first
            .events
            .iter()
            .all(|event| matches!(event, events::Event::Keyboard { .. }))
    );
    let ReceivedReport::Data(frame) = &first.reports[0] else {
        panic!("actual DMA report required")
    };
    assert_eq!(frame.bytes, [1, 7]);
    hardware.borrow_mut().push_event(vec![2, 1]);
    let second = input.poll_hid();
    assert!(second.inputs.is_empty());
    assert_eq!(
        second.events,
        [events::Event::Consumer {
            report: 2,
            usage: 0xe9,
            pressed: true
        }]
    );
    input.set_report(ReportType::Output, 1, &[1, 3]).unwrap();
    assert_eq!(
        hardware.borrow().setup.last().unwrap(),
        &([0x21, SET_REPORT, 1, 2, 4, 0, 2, 0], vec![1, 3])
    );
    hardware
        .borrow_mut()
        .control_replies
        .push_back(([0xa1, GET_REPORT, 1, 3, 4, 0, 2, 0], vec![1, 1]));
    assert_eq!(input.get_report(ReportType::Feature, 1).unwrap(), [1, 1]);
    input.stop_hid().unwrap();
}

#[test]
fn malformed_ordinary_descriptors_refuse_before_hid_allocation_or_input_publication() {
    for bytes in malformed() {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives the native controller and DMA owners.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (controller, hardware) = model::cancellation_controller(&mut dma);
        hardware
            .borrow_mut()
            .descriptors
            .push((REPORT_DESCRIPTOR, 0, bytes.clone()));
        hardware.borrow_mut().push_event(vec![0xa5]);
        let shared: Shared = Rc::new(RefCell::new(controller));
        let mut device = model::device(Vec::new());
        device.id = shared.borrow().test_device_id(1).unwrap();
        let interface = interface(&bytes, false);
        let remaining = dma.remaining();
        let seen = hardware.borrow().seen.clone();
        let ring = hardware.borrow().rings[3];
        let index = hardware.borrow().indices[3];
        let active = hardware.borrow().active[3];
        let state = hardware.borrow().state(3);
        let poisoned = shared.borrow().endpoint_poisoned(1, 3);
        shared
            .borrow_mut()
            .device(device.id)
            .unwrap()
            .endpoint_ready(3)
            .unwrap();
        assert!(
            UsbInput::new(
                shared.clone(),
                &device,
                &interface,
                interface.endpoints[0],
                &mut dma
            )
            .is_err()
        );
        assert_eq!(dma.remaining(), remaining);
        assert_eq!(shared.borrow().test_device_id(1).unwrap(), device.id);
        assert_eq!(shared.borrow().endpoint_poisoned(1, 3), poisoned);
        shared
            .borrow_mut()
            .device(device.id)
            .unwrap()
            .endpoint_ready(3)
            .unwrap();
        let h = hardware.borrow();
        assert_eq!(h.state(3), state);
        assert_eq!(h.seen, seen);
        assert_eq!(
            (h.rings[3], h.indices[3], h.active[3]),
            (ring, index, active)
        );
        assert_eq!(h.incoming_events.front().unwrap(), &[0xa5]);
        assert!(
            !h.setup
                .iter()
                .any(|(r, _)| matches!(r[1], SET_PROTOCOL | SET_IDLE))
        );
        assert!(
            h.setup
                .iter()
                .any(|(r, _)| r[1] == GET_DESCRIPTOR && r[3] == REPORT_DESCRIPTOR)
        );
    }
}

#[test]
fn boot_subclass_keeps_existing_fallback_and_original_rejected_bytes() {
    let bytes = [0xa9, 1, 9, 4, 0xa9, 0, 0x81, 0]; // prohibited Array aliases
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: backing remains live throughout native DMA and endpoint shutdown.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (controller, hardware) = model::cancellation_controller(&mut dma);
    hardware
        .borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, bytes.to_vec()));
    let shared: Shared = Rc::new(RefCell::new(controller));
    let mut device = model::device(Vec::new());
    device.id = shared.borrow().test_device_id(1).unwrap();
    let interface = interface(&bytes, true);
    let mut input = UsbInput::new(
        shared,
        &device,
        &interface,
        interface.endpoints[0],
        &mut dma,
    )
    .unwrap()
    .unwrap();
    assert!(input.descriptor().is_none());
    assert_eq!(input.report_descriptor(), bytes);
    assert!(
        hardware
            .borrow()
            .setup
            .iter()
            .any(|(r, _)| *r == [0x21, SET_PROTOCOL, 0, 0, 4, 0, 0, 0])
    );
    hardware
        .borrow_mut()
        .push_event(vec![0, 0, 4, 0, 0, 0, 0, 0]);
    assert_eq!(
        input.poll(),
        [Input::Key {
            usage: 4,
            pressed: true
        }]
    );
    input.stop_hid().unwrap();
}
