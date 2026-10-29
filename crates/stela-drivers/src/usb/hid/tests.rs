use super::*;
use crate::input::POINTER_MAX;

/// A boot keyboard whose descriptor numbers its 8-byte report 1.
pub(super) const NUMBERED_KEYBOARD: [u8; 43] = [
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, // keyboard, report 1
    0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81,
    0x02, // modifiers
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01, // reserved
    0x95, 0x06, 0x75, 0x08, 0x25, 0x65, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, // keys
    0xc0,
];

#[test]
fn transfer_errors_retry_with_linux_backoff_for_one_second() {
    let first = Retry::first(1_000);
    assert_eq!(
        (first.delay_ms, first.at_us, first.stop_us),
        (13, 14_000, 1_001_000)
    );
    let delays: Vec<u64> = core::iter::successors(Some(first), |retry| retry.next(retry.at_us))
        .map(|retry| retry.delay_ms)
        .take(6)
        .collect();
    assert_eq!(delays, [13, 26, 52, 104, 104, 104]);
    assert_eq!(first.next(1_001_001), None);
}

#[test]
fn a_boot_keyboard_with_report_ids_is_read_through_its_descriptor() {
    let boot = || Reports {
        keys: Some(Keys::boot()),
        pointer: None,
        input_bytes: BOOT_REPORT_BYTES,
    };
    let usable = |reports: &Reports| reports.keys.is_some();
    let described =
        report::parse(&NUMBERED_KEYBOARD).map_err(|error| BlockError::Unsupported(error.message()));
    let (protocol, reports) = boot_interface(described, boot(), usable);
    assert_eq!(protocol, REPORT_PROTOCOL);
    assert!(reports.numbered());
    // Y held, after the report ID.
    let report = [0x01, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 0];
    let keys = reports.keys.unwrap();
    assert_eq!(keys.pressed(&report[1..]), Some(alloc::vec![0x1c]));
    // Read as the boot report, the ID byte is Left Control.
    assert_eq!(
        Keys::boot().pressed(&report[..8]),
        Some(alloc::vec![0xe0, 0x1c])
    );
    // Without a usable descriptor the boot report is read.
    let (protocol, reports) = boot_interface(
        Err(BlockError::Unsupported("no descriptor")),
        boot(),
        usable,
    );
    assert_eq!((protocol, reports), (BOOT_PROTOCOL, boot()));
    let pointer_only = report::parse(&[
        0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x02, 0x81,
        0x06,
    ])
    .map_err(|error| BlockError::Unsupported(error.message()));
    assert_eq!(
        boot_interface(pointer_only, boot(), usable).0,
        BOOT_PROTOCOL
    );
}
use crate::usb::xhci::{
    self,
    model::{self, RegionAllocator},
};
use alloc::{rc::Rc, vec};
use core::cell::RefCell;

const GAMEPAD: &[u8] = &[
    5, 1, 9, 5, 0xa1, 1, 0x85, 2, 9, 0x30, 9, 0x31, 0x15, 0x81, 0x25, 0x7f, 0x75, 8, 0x95, 2, 0x81,
    2, 5, 9, 0x19, 1, 0x29, 8, 0x15, 0, 0x25, 1, 0x75, 1, 0x95, 8, 0x81, 2, 5, 8, 9, 1, 0x75, 8,
    0x95, 1, 0x91, 2, 5, 0x0d, 9, 0x55, 0xb1, 2, 0xc0,
];

fn interface(bytes: &[u8], subclass: u8, protocol: u8) -> Interface {
    let length = bytes.len() as u16;
    Interface {
        number: 4,
        alternate: 0,
        class: CLASS,
        subclass,
        protocol,
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

fn device(controller: &Shared) -> Device {
    let mut device = model::device(Vec::new());
    device.id = controller.borrow().test_device_id(1).unwrap();
    device
}

/// A keyboard whose output report holds five LEDs and three pad bits.
const LED_KEYBOARD: [u8; 55] = [
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, // keyboard
    0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81,
    0x02, // modifiers
    0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, // LEDs
    0x95, 0x01, 0x75, 0x03, 0x91, 0x01, // padding
    0x95, 0x06, 0x75, 0x08, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81,
    0x00, // keys
    0xc0,
];

#[test]
fn leds_set_the_first_led_report_like_hidinput_led_worker() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: this allocation outlives all model/controller DMA references.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (controller, hardware) = model::cancellation_controller(&mut dma);
    hardware
        .borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, LED_KEYBOARD.to_vec()));
    let shared: Shared = Rc::new(RefCell::new(controller));
    let interface = interface(&LED_KEYBOARD, 0, 0);
    let mut input = UsbInput::new(
        shared.clone(),
        &device(&shared),
        &interface,
        interface.endpoints[0],
        &mut dma,
    )
    .unwrap()
    .unwrap();
    // Num Lock, Caps Lock and Stand-By, which this keyboard lacks.
    input.set_leds(1 << 0 | 1 << 1 | 1 << 5).unwrap();
    assert_eq!(
        hardware.borrow().setup.last().unwrap(),
        &([0x21, SET_REPORT, 0, 2, 4, 0, 1, 0], vec![3])
    );
    input.set_leds(1 << 2).unwrap();
    assert_eq!(hardware.borrow().setup.last().unwrap().1, [4]);
}

#[test]
fn output_reports_take_the_interrupt_out_endpoint_like_usbhid_output_report() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: this allocation outlives all model/controller DMA references.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (controller, hardware) = model::cancellation_controller(&mut dma);
    hardware
        .borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, GAMEPAD.to_vec()));
    let shared: Shared = Rc::new(RefCell::new(controller));
    let mut interface = interface(GAMEPAD, 0, 0);
    // The model's slot owns endpoint 2 OUT.
    interface.endpoints.push(Endpoint {
        address: 0x02,
        attributes: 3,
        max_packet: 16,
        interval: 1,
        companion: None,
    });
    assert!(matches!(plan(&interface), Ok(Plan::Hid(_, Some(out))) if out.address == 2));
    let mut input = UsbInput::new(
        shared.clone(),
        &device(&shared),
        &interface,
        interface.endpoints[0],
        &mut dma,
    )
    .unwrap()
    .unwrap();
    let setups = hardware.borrow().setup.len();
    assert_eq!(input.output_report(2, &[2, 0x41]), Ok(2));
    assert_eq!(hardware.borrow().outgoing, [vec![2, 0x41]]);
    assert!(input.output_report(3, &[3, 0x41]).is_err());
    assert_eq!(hardware.borrow().setup.len(), setups);
    // Without the endpoint, SET_REPORT carries it.
    input.output = None;
    assert_eq!(input.output_report(2, &[2, 0x42]), Ok(2));
    assert_eq!(
        hardware.borrow().setup.last().unwrap(),
        &([0x21, SET_REPORT, 2, 2, 4, 0, 2, 0], vec![2, 0x42])
    );
}

#[test]
fn real_descriptor_fetch_initialization_input_control_and_restart() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: this allocation outlives all model/controller DMA references.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (controller, hardware) = model::cancellation_controller(&mut dma);
    hardware
        .borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, GAMEPAD.to_vec()));
    let shared: Shared = Rc::new(RefCell::new(controller));
    let interface = interface(GAMEPAD, 0, 0);
    let mut input = UsbInput::new(
        shared.clone(),
        &device(&shared),
        &interface,
        interface.endpoints[0],
        &mut dma,
    )
    .unwrap()
    .unwrap();
    assert_eq!(input.report_descriptor(), GAMEPAD);
    assert_eq!(
        hardware.borrow().setup[1].0,
        [0x81, 6, 0, 0x22, 4, 0, GAMEPAD.len() as u8, 0]
    );
    assert!(
        !hardware
            .borrow()
            .setup
            .iter()
            .any(|(request, _)| request[1] == SET_PROTOCOL)
    );
    assert!(input.poll_hid().reports.is_empty()); // Actual queued TD remains NAKed.
    let ticket = input.queued;
    assert!(ticket.is_some());
    assert!(input.poll_hid().reports.is_empty());
    assert_eq!(input.queued, ticket);
    hardware.borrow_mut().push_event(vec![2, 0xff, 5, 0x80]);
    let polled = input.poll_hid();
    assert!(
        polled.inputs.is_empty(),
        "gamepad axes must not become pointer motion"
    );
    assert_eq!(polled.reports.len(), 1);
    let ReceivedReport::Data(frame) = &polled.reports[0] else {
        panic!("actual HID frame");
    };
    assert_eq!(frame.id, 2);
    assert_eq!(frame.samples[0].value, descriptor::Value::Scalar(-1));
    assert_eq!(polled.events.len(), 11);
    input.set_report(ReportType::Output, 2, &[2, 0x41]).unwrap();
    assert_eq!(
        hardware.borrow().setup.last().unwrap(),
        &([0x21, SET_REPORT, 2, 2, 4, 0, 2, 0], vec![2, 0x41])
    );
    let count = hardware.borrow().setup.len();
    assert!(input.set_report(ReportType::Output, 2, &[3, 0x41]).is_err());
    assert!(input.set_report(ReportType::Output, 7, &[7, 0x41]).is_err());
    assert!(
        input
            .set_report(ReportType::Input, 2, &[2, 0, 0, 0])
            .is_err()
    );
    assert_eq!(hardware.borrow().setup.len(), count);
    hardware
        .borrow_mut()
        .control_replies
        .push_back(([0xa1, GET_REPORT, 2, 3, 4, 0, 2, 0], vec![2, 5]));
    assert_eq!(input.get_report(ReportType::Feature, 2).unwrap(), [2, 5]);
    input.set_idle(2, 10).unwrap();
    assert_eq!(
        hardware.borrow().setup.last().unwrap().0,
        [0x21, SET_IDLE, 2, 10, 4, 0, 0, 0]
    );
    assert!(input.stop().unwrap().is_empty());
    assert_eq!(input.state(), State::Stopped);
    assert!(input.queued.is_none());
    assert!(hardware.borrow().seen.contains(&xhci::STOP_ENDPOINT));
    assert!(hardware.borrow().seen.contains(&xhci::SET_DEQUEUE));
    assert!(input.poll_hid().reports.is_empty());
    input.restart().unwrap();
    hardware.borrow_mut().push_event(vec![2, 1, 2, 0]);
    assert_eq!(input.poll_hid().reports.len(), 1);
}

#[test]
fn unresolved_stop_keeps_ticket_buffer_first_error_and_refuses_control_or_restart() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: backing remains live until all users below have been dropped.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (controller, hardware) = model::cancellation_controller(&mut dma);
    hardware
        .borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, GAMEPAD.to_vec()));
    let shared: Shared = Rc::new(RefCell::new(controller));
    let interface = interface(GAMEPAD, 0, 0);
    let mut input = UsbInput::new(
        shared.clone(),
        &device(&shared),
        &interface,
        interface.endpoints[0],
        &mut dma,
    )
    .unwrap()
    .unwrap();
    input.poll_hid();
    let ticket = input.queued;
    let buffer = input.buffer.physical();
    hardware.borrow_mut().fail = Some((xhci::STOP_ENDPOINT, 19));
    assert!(input.stop().is_err());
    assert_eq!(input.state(), State::Faulted);
    assert_eq!(input.queued, ticket);
    assert_eq!(input.buffer.physical(), buffer);
    let error = input.first_error();
    let commands = hardware.borrow().seen.len();
    assert!(input.restart().is_err());
    assert!(input.set_report(ReportType::Output, 2, &[2, 0]).is_err());
    assert!(input.poll_hid().reports.is_empty());
    assert_eq!(hardware.borrow().seen.len(), commands);
    assert_eq!(input.first_error(), error);
    assert!(shared.borrow().endpoint_poisoned(1, 3));
}

#[test]
fn a_refused_report_protocol_switch_keeps_the_interface_but_boot_fallback_fails() {
    let keyboard = super::tests::NUMBERED_KEYBOARD;
    for described in [true, false] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: live exclusive test allocation bounds every controller DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (controller, hardware) = model::cancellation_controller(&mut dma);
        if described {
            hardware
                .borrow_mut()
                .descriptors
                .push((REPORT_DESCRIPTOR, 0, keyboard.to_vec()));
        }
        hardware.borrow_mut().stall_control = Some(SET_PROTOCOL);
        let shared: Shared = Rc::new(RefCell::new(controller));
        let interface = interface(&keyboard, BOOT, KEYBOARD);
        let input = UsbInput::new(
            shared.clone(),
            &device(&shared),
            &interface,
            interface.endpoints[0],
            &mut dma,
        );
        if !described {
            // Without a usable descriptor only boot reports can be read.
            assert_eq!(input.err(), Some(BlockError::Device { status: STALL }));
            continue;
        }
        let mut input = input.unwrap().unwrap();
        hardware.borrow_mut().stall_control = None;
        hardware
            .borrow_mut()
            .push_event(vec![1, 0, 0, 4, 0, 0, 0, 0, 0]);
        assert_eq!(
            input.poll(),
            [Input::Key {
                usage: 4,
                pressed: true
            }]
        );
    }
}

#[test]
fn malformed_reports_do_not_release_held_keys_and_boot_qemu_path_remains() {
    let keyboard = super::tests::NUMBERED_KEYBOARD;
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: live exclusive test allocation bounds every controller DMA.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (controller, hardware) = model::cancellation_controller(&mut dma);
    hardware
        .borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, keyboard.to_vec()));
    let shared: Shared = Rc::new(RefCell::new(controller));
    let interface = interface(&keyboard, BOOT, KEYBOARD);
    let mut input = UsbInput::new(
        shared.clone(),
        &device(&shared),
        &interface,
        interface.endpoints[0],
        &mut dma,
    )
    .unwrap()
    .unwrap();
    assert!(
        hardware
            .borrow()
            .setup
            .iter()
            .any(|(r, _)| *r == [0x21, SET_PROTOCOL, 1, 0, 4, 0, 0, 0])
    );
    hardware
        .borrow_mut()
        .push_event(vec![1, 0, 0, 4, 0, 0, 0, 0, 0]);
    assert_eq!(
        input.poll(),
        [Input::Key {
            usage: 4,
            pressed: true
        }]
    );
    hardware.borrow_mut().push_event(vec![1, 0]);
    let bad = input.poll_hid();
    assert!(bad.inputs.is_empty());
    assert!(matches!(
        bad.reports[0],
        ReceivedReport::Rejected {
            error: DecodeError::Length { .. },
            ..
        }
    ));
    hardware
        .borrow_mut()
        .push_event(vec![1, 0, 0, 1, 1, 1, 1, 1, 1]);
    assert!(input.poll().is_empty());
    assert_eq!(
        input.stop().unwrap(),
        [Input::Key {
            usage: 4,
            pressed: false
        }]
    );
}

#[test]
fn report_descriptor_header_walks_every_entry_and_bounds_length() {
    let mut interface = interface(GAMEPAD, 0, 0);
    interface.extra[0] = vec![
        12,
        HID_DESCRIPTOR,
        0x11,
        1,
        0,
        2,
        0x23,
        7,
        0,
        REPORT_DESCRIPTOR,
        12,
        0,
    ];
    assert_eq!(descriptor_length(&interface), Ok(12));
    interface.extra[0][0] = 9;
    assert!(descriptor_length(&interface).is_err());
    interface.extra[0] = vec![9, HID_DESCRIPTOR, 0x11, 1, 0, 1, REPORT_DESCRIPTOR, 1, 0x10];
    assert!(descriptor_length(&interface).is_err());
}

#[test]
fn actual_relative_and_absolute_pointer_reports_preserve_qemu_native_inputs() {
    for relative in [true, false] {
        let pointer = [
            5,
            1,
            9,
            2,
            0xa1,
            1,
            9,
            1,
            0xa1,
            0,
            5,
            9,
            0x19,
            1,
            0x29,
            5,
            0x15,
            0,
            0x25,
            1,
            0x75,
            1,
            0x95,
            5,
            0x81,
            2,
            0x75,
            3,
            0x95,
            1,
            0x81,
            1,
            5,
            1,
            9,
            0x30,
            9,
            0x31,
            0x15,
            if relative { 0x81 } else { 0 },
            0x25,
            0x7f,
            0x75,
            8,
            0x95,
            2,
            0x81,
            if relative { 6 } else { 2 },
            9,
            0x38,
            0x15,
            0x81,
            0x95,
            1,
            0x81,
            6,
            5,
            0x0c,
            0x0a,
            0x38,
            2, // AC Pan
            0x81,
            6,
            0xc0,
            0xc0,
        ];
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: this exclusive model allocation outlives all DMA users.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (controller, hardware) = model::cancellation_controller(&mut dma);
        hardware
            .borrow_mut()
            .descriptors
            .push((REPORT_DESCRIPTOR, 0, pointer.to_vec()));
        let shared: Shared = Rc::new(RefCell::new(controller));
        let interface = interface(&pointer, 0, 0);
        let mut input = UsbInput::new(
            shared.clone(),
            &device(&shared),
            &interface,
            interface.endpoints[0],
            &mut dma,
        )
        .unwrap()
        .unwrap();
        hardware
            .borrow_mut()
            .push_event(vec![0x11, 127, 0, 1, 0xfe]);
        let polled = input.poll_hid();
        let expected = if relative {
            vec![
                Input::Motion { dx: 127, dy: 0 },
                Input::MouseButtons(0x11),
                Input::MouseWheel(1),
                Input::MouseHWheel(-2),
            ]
        } else {
            vec![
                Input::Move {
                    x: POINTER_MAX,
                    y: 0,
                },
                Input::Buttons(1),
                Input::Wheel(1),
                Input::HWheel(-2),
            ]
        };
        assert_eq!(polled.inputs, expected);
        assert!(matches!(&polled.reports[0], ReceivedReport::Data(_)));
    }
}

#[test]
fn actual_boot_fallback_is_explicit_and_uses_standard_boot_bytes() {
    let descriptor = [0xfe, 0, 0];
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: this exclusive model allocation outlives all DMA users.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (controller, hardware) = model::cancellation_controller(&mut dma);
    hardware
        .borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, descriptor.to_vec()));
    let shared: Shared = Rc::new(RefCell::new(controller));
    let interface = interface(&descriptor, BOOT, KEYBOARD);
    let mut input = UsbInput::new(
        shared.clone(),
        &device(&shared),
        &interface,
        interface.endpoints[0],
        &mut dma,
    )
    .unwrap()
    .unwrap();
    assert!(input.descriptor().is_none());
    assert_eq!(input.report_descriptor(), descriptor);
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
    let polled = input.poll_hid();
    assert_eq!(
        polled.inputs,
        [Input::Key {
            usage: 4,
            pressed: true
        }]
    );
    assert!(matches!(&polled.reports[0], ReceivedReport::Boot(_)));
}

#[test]
fn retired_identity_refuses_old_hid_control_poll_and_restart_without_dma_mutation() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: this exclusive model allocation outlives all DMA users.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (controller, hardware) = model::cancellation_controller(&mut dma);
    hardware
        .borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, GAMEPAD.to_vec()));
    let shared: Shared = Rc::new(RefCell::new(controller));
    let interface = interface(GAMEPAD, 0, 0);
    let mut input = UsbInput::new(
        shared.clone(),
        &device(&shared),
        &interface,
        interface.endpoints[0],
        &mut dma,
    )
    .unwrap()
    .unwrap();
    input.poll_hid();
    let ticket = input.queued;
    let memory = input.buffer.bytes().to_vec();
    shared.borrow_mut().quarantine_slot(1);
    let commands = hardware.borrow().seen.clone();
    let requests = hardware.borrow().setup.clone();
    assert!(input.set_report(ReportType::Output, 2, &[2, 0]).is_err());
    assert!(input.get_report(ReportType::Feature, 2).is_err());
    assert!(input.poll_hid().reports.is_empty());
    assert_eq!(input.state(), State::Faulted);
    assert_eq!(input.queued, ticket);
    assert_eq!(input.buffer.bytes(), memory);
    assert!(input.stop_hid().is_err());
    assert!(input.restart().is_err());
    assert_eq!(hardware.borrow().seen, commands);
    assert_eq!(hardware.borrow().setup, requests);
}
