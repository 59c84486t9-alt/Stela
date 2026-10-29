// SPDX-License-Identifier: GPL-2.0-or-later
//! Authored software peer reports, never a claim about a physical touch device.
use super::*;
use crate::{
    bus::pci::{Address, ConfigSpace, Function},
    usb::xhci::{self, Registers, model},
};
use alloc::{boxed::Box, rc::Rc, vec};
use core::cell::{Cell, RefCell};

// Pinned Linux xhci.h TRB_RESET_EP: Reset Endpoint Command TRB type.
// Keep this test wire expectation independent of production item visibility.
const RESET_ENDPOINT_COMMAND: u32 = 14;

pub(super) const SINGLE: &[u8] = &[
    5, 0x0d, 9, 4, 0xa1, 1, 0x85, 1, 9, 0x22, 0xa1, 2, 0x15, 0, 0x25, 127, 0x75, 8, 0x95, 1, 9,
    0x51, 0x81, 2, 0x25, 1, 9, 0x42, 0x81, 2, 5, 1, 0x26, 0xff, 0x7f, 0x75, 16, 9, 0x30, 0x81, 2,
    9, 0x31, 0x81, 2, 0xc0, 5, 0x0d, 0x25, 8, 0x75, 8, 9, 0x54, 0x81, 2, 0x26, 0xff, 0xff, 0x75,
    16, 9, 0x56, 0x81, 2, 0x85, 2, 0x25, 8, 0x75, 8, 9, 0x55, 0xb1, 2, 0xc0,
];
fn packet(id: u8, tip: bool, count: u8, scan: u16) -> Vec<u8> {
    vec![
        1,
        id,
        u8::from(tip),
        10,
        0,
        20,
        0,
        count,
        scan as u8,
        (scan >> 8) as u8,
    ]
}
struct Config;
impl ConfigSpace for Config {
    fn read32(&self, at: u16) -> u32 {
        match at {
            0 => 0x0014_1b36,
            8 => 0x0c03_3001,
            _ => 0,
        }
    }
    fn write32(&mut self, _: u16, _: u32) {
        panic!("read-only qualification")
    }
}
struct Trap {
    original: Box<dyn Registers>,
    active: Rc<Cell<bool>>,
}
impl Registers for Trap {
    fn read32(&mut self, at: usize) -> u32 {
        assert!(!self.active.get(), "stale touch MMIO read");
        self.original.read32(at)
    }
    fn write32(&mut self, at: usize, value: u32) {
        assert!(!self.active.get(), "stale touch MMIO write");
        self.original.write32(at, value);
    }
}
fn fixture(
    dma: &mut dyn DmaAllocator,
) -> (UsbInput, Rc<RefCell<model::CancelModel>>, Rc<Cell<bool>>) {
    fixture_descriptor(dma, SINGLE)
}
fn fixture_descriptor(
    dma: &mut dyn DmaAllocator,
    report: &[u8],
) -> (UsbInput, Rc<RefCell<model::CancelModel>>, Rc<Cell<bool>>) {
    let mut function = Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 1,
            function: 0,
        },
        Config,
    )
    .unwrap();
    let trap = Rc::new(Cell::new(false));
    let (controller, peer) = model::forwarding_fixture(
        dma,
        &[vec![9, 2, 9, 0, 0, 1, 0, 0x80, 50]],
        xhci::FULL_SPEED,
        &mut function,
        |original, _| {
            Box::new(Trap {
                original,
                active: trap.clone(),
            })
        },
    );
    let shared: Shared = Rc::new(RefCell::new(controller));
    let mut physical = model::device(Vec::new());
    physical.id = shared.borrow().test_device_id(1).unwrap();
    let endpoint = Endpoint {
        address: 0x81,
        attributes: 3,
        max_packet: 16,
        interval: 1,
        companion: None,
    };
    {
        let mut c = shared.borrow_mut();
        let mut access = c.device(physical.id).unwrap();
        access.set_configuration(1).unwrap();
        access.configure(&[endpoint], None, dma).unwrap();
    }
    peer.borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, report.to_vec()));
    let interface = Interface {
        number: 4,
        alternate: 0,
        class: CLASS,
        subclass: 0,
        protocol: 0,
        endpoints: vec![endpoint],
        extra: vec![vec![
            9,
            HID_DESCRIPTOR,
            0x11,
            1,
            0,
            1,
            REPORT_DESCRIPTOR,
            report.len() as u8,
            0,
        ]],
    };
    let input = UsbInput::new(shared, &physical, &interface, endpoint, dma)
        .unwrap()
        .unwrap();
    (input, peer, trap)
}
fn enable(
    input: &mut UsbInput,
    peer: &Rc<RefCell<model::CancelModel>>,
    maximum: u8,
) -> Result<(), BlockError> {
    peer.borrow_mut()
        .control_replies
        .push_back(([0xa1, GET_REPORT, 2, 3, 4, 0, 2, 0], vec![2, maximum]));
    input.enable_touch_frames(1, 0)
}
fn feed(input: &mut UsbInput, peer: &Rc<RefCell<model::CancelModel>>, raw: Vec<u8>) -> TouchPoll {
    peer.borrow_mut().push_event(raw);
    input.poll_touch_hid()
}

#[test]
fn actual_descriptor_feature_ack_and_dma_reports_assemble_without_changing_raw_events() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: RAM outlives the controller and every DMA owner.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let mut composite = SINGLE.to_vec();
    let mut other = SINGLE.to_vec();
    for at in 0..other.len() - 1 {
        if other[at] == 0x85 {
            other[at + 1] += 2;
        }
    }
    composite.extend_from_slice(&other);
    let (mut input, peer, _) = fixture_descriptor(&mut dma, &composite);
    assert_eq!(input.report_descriptor(), composite);
    assert!(peer.borrow().setup.iter().any(|(r, _)| *r
        == [
            0x81,
            GET_DESCRIPTOR,
            0,
            REPORT_DESCRIPTOR,
            4,
            0,
            composite.len() as u8,
            0
        ]));
    enable(&mut input, &peer, 3).unwrap();
    // The control log records the device's feature reply: ID 2, maximum 3.
    assert_eq!(
        peer.borrow().setup.last().unwrap(),
        &([0xa1, GET_REPORT, 2, 3, 4, 0, 2, 0], vec![2, 3])
    );
    assert!(input.poll_touch_hid().hid.reports.is_empty());
    let original = input.queued.unwrap();
    input.buffer.bytes_mut().fill(0xa5);
    let first = packet(70, true, 2, 65535);
    let second = packet(91, false, 0, 65535);
    let a = feed(&mut input, &peer, first.clone());
    assert!(a.frames.is_empty());
    assert!(a.discarded.is_empty());
    assert_ne!(input.queued, Some(original));
    assert_eq!(&input.buffer.bytes()[..first.len()], first.as_slice());
    let ReceivedReport::Data(raw) = &a.hid.reports[0] else {
        panic!("genuine DMA report")
    };
    assert_eq!(raw.bytes, first);
    // A second app/report passes the native decoder without taking
    // over the pending report1/app0 prefix or becoming its continuation.
    let mut foreign = packet(70, true, 1, 65535);
    foreign[0] = 3;
    let independent = feed(&mut input, &peer, foreign.clone());
    assert!(independent.frames.is_empty());
    assert!(independent.discarded.is_empty());
    let [events::Event::Touch(other)] = independent.hid.events.as_slice() else {
        panic!("second actual touch app")
    };
    assert_eq!((other.report, other.application), (3, 2));
    let ReceivedReport::Data(frame) = &independent.hid.reports[0] else {
        panic!("second DMA report")
    };
    assert_eq!(frame.bytes, foreign);
    let b = feed(&mut input, &peer, second.clone());
    assert!(b.discarded.is_empty());
    assert_eq!(b.frames.len(), 1);
    let complete = &b.frames[0];
    assert_eq!(
        (complete.report, complete.application, complete.scan_time),
        (1, 0, 65535)
    );
    assert_eq!(complete.reports, [first, second]);
    assert_eq!(
        complete
            .contacts
            .iter()
            .map(|c| (c.id, c.tip))
            .collect::<Vec<_>>(),
        [(Some(70), Some(true)), (Some(91), Some(false))]
    );
    for (poll, index) in [(&a, 0), (&b, 1)] {
        assert!(poll.hid.inputs.is_empty());
        let [events::Event::Touch(raw)] = poll.hid.events.as_slice() else {
            panic!("original touch event")
        };
        assert_eq!(raw.contacts, [complete.contacts[index].clone()]);
    }
    // Counter wrap is a new observed token, not a regressing host clock.
    assert_eq!(
        feed(&mut input, &peer, packet(127, true, 1, 0))
            .frames
            .len(),
        1
    );
    input.stop_hid().unwrap();
}

#[test]
fn actual_maximum_refusal_keeps_raw_poll_and_requires_fresh_ack_after_set_report() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: controller owners are dropped before RAM.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut input, peer, _) = fixture(&mut dma);
    for value in [0, 9, 65] {
        assert!(enable(&mut input, &peer, value).is_err());
        assert!(input.touch.is_none());
    }
    enable(&mut input, &peer, 2).unwrap();
    assert!(
        feed(&mut input, &peer, packet(1, true, 2, 1))
            .frames
            .is_empty()
    );
    input.set_report(ReportType::Feature, 2, &[2, 2]).unwrap();
    assert!(input.touch.is_none());
    let raw = feed(&mut input, &peer, packet(2, true, 0, 1));
    assert!(raw.frames.is_empty());
    assert_eq!(raw.hid.reports.len(), 1);
    assert_eq!(raw.hid.events.len(), 1);
    enable(&mut input, &peer, 2).unwrap();
    assert_eq!(
        feed(&mut input, &peer, packet(2, true, 0, 1)).discarded,
        [TouchDiscard::OrphanContinuation]
    );
    assert_eq!(
        feed(&mut input, &peer, packet(2, true, 1, 2)).frames.len(),
        1
    );
    input.stop_hid().unwrap();
}

#[test]
fn actual_truncation_and_acknowledged_stop_restart_cannot_finish_old_hybrid_frame() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: controller owners are dropped before RAM.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut input, peer, _) = fixture(&mut dma);
    enable(&mut input, &peer, 2).unwrap();
    assert!(
        feed(&mut input, &peer, packet(1, true, 2, 8))
            .frames
            .is_empty()
    );
    let rejected = feed(&mut input, &peer, vec![1, 99]);
    assert!(
        matches!(&rejected.hid.reports[0],ReceivedReport::Rejected { bytes,.. } if bytes == &[1,99])
    );
    assert_eq!(
        feed(&mut input, &peer, packet(2, true, 0, 8)).discarded,
        [TouchDiscard::OrphanContinuation]
    );
    assert!(
        feed(&mut input, &peer, packet(1, true, 2, 9))
            .frames
            .is_empty()
    );
    let queued = input.queued;
    assert!(queued.is_some());
    input.stop_hid().unwrap();
    assert_eq!(input.state(), State::Stopped);
    assert!(input.queued.is_none());
    assert!(input.poll_touch_hid().frames.is_empty());
    input.restart().unwrap();
    assert_eq!(
        feed(&mut input, &peer, packet(2, true, 0, 9)).discarded,
        [TouchDiscard::OrphanContinuation]
    );
    assert_eq!(
        feed(&mut input, &peer, packet(2, true, 1, 10)).frames.len(),
        1
    );
    input.stop_hid().unwrap();
}

#[test]
fn stale_native_identity_discards_pending_before_mmio_or_current_completion() {
    let mut ram = vec![0u64; 1024 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: both controller owners keep this exclusive live RAM.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut old, old_peer, _) = fixture(&mut dma);
    let (mut current, peer, trap) = fixture(&mut dma);
    assert_ne!(old.id, current.id);
    enable(&mut old, &old_peer, 2).unwrap();
    assert!(
        feed(&mut old, &old_peer, packet(1, true, 2, 11))
            .frames
            .is_empty()
    );
    assert!(current.poll_hid().reports.is_empty());
    peer.borrow_mut().push_event(packet(2, true, 1, 12));
    peer.borrow_mut().receive(3);
    let original = old.controller.clone();
    old.controller = current.controller.clone();
    let before = ram.clone();
    let commands = peer.borrow().seen.clone();
    trap.set(true);
    assert!(old.poll_touch_hid().frames.is_empty());
    assert_eq!(old.touch.as_ref().unwrap().pending_contacts(), 0);
    assert!(old.enable_touch_frames(1, 0).is_err());
    assert!(old.stop_hid().is_err());
    assert!(old.restart().is_err());
    assert_eq!(ram, before);
    assert_eq!(peer.borrow().seen, commands);
    trap.set(false);
    assert_eq!(current.poll_hid().reports.len(), 1);
    old.controller = original;
    // No cached old frame can finish even when the original owner is restored.
    assert!(
        feed(&mut old, &old_peer, packet(2, true, 0, 11))
            .frames
            .is_empty()
    );
    old.stop_hid().unwrap();
    current.stop_hid().unwrap();
}

#[test]
fn actual_feature_length_id_and_descriptor_minimum_are_checked_before_authority() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: RAM outlives all kept native DMA owners.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let mut bytes = SINGLE.to_vec();
    let id = bytes
        .windows(4)
        .position(|w| w == [9, 0x51, 0x81, 2])
        .unwrap();
    bytes.splice(id..id, [0x15, 64]);
    let tip = bytes
        .windows(4)
        .position(|w| w == [0x25, 1, 9, 0x42])
        .unwrap();
    bytes.splice(tip..tip, [0x15, 0]);
    let (mut input, peer, _) = fixture_descriptor(&mut dma, &bytes);
    for reply in [vec![2], vec![9, 2]] {
        peer.borrow_mut()
            .control_replies
            .push_back(([0xa1, GET_REPORT, 2, 3, 4, 0, 2, 0], reply));
        assert!(input.enable_touch_frames(1, 0).is_err());
        assert!(input.touch.is_none());
    }
    enable(&mut input, &peer, 2).unwrap();
    assert_eq!(
        feed(&mut input, &peer, packet(63, true, 1, 0)).discarded,
        [TouchDiscard::InvalidValue]
    );
    assert!(
        feed(&mut input, &peer, packet(70, true, 2, 1))
            .frames
            .is_empty()
    );
    let complete = feed(&mut input, &peer, packet(91, false, 0, 1));
    assert_eq!(
        complete.frames[0]
            .contacts
            .iter()
            .map(|c| c.id)
            .collect::<Vec<_>>(),
        [Some(70), Some(91)]
    );
    input.stop_hid().unwrap();
}

#[test]
fn actual_stall_recovery_abandons_pending_frame_and_retains_original_dma_owner() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: RAM outlives all kept native DMA owners.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut input, peer, _) = fixture(&mut dma);
    enable(&mut input, &peer, 2).unwrap();
    assert!(input.poll_hid().reports.is_empty());
    let physical = input.buffer.physical();
    // The existing TD completes the first contact. The next
    // submission stalls, so endpoint reset/dequeue must invalidate that prefix.
    peer.borrow_mut().halt_transfer = Some(3);
    let first = feed(&mut input, &peer, packet(70, true, 2, 1));
    assert_eq!(first.hid.reports.len(), 1);
    assert!(first.frames.is_empty());
    assert_eq!(input.touch.as_ref().unwrap().pending_contacts(), 0);
    assert_eq!(input.buffer.physical(), physical);
    assert!(input.retry.is_some());
    assert!(peer.borrow().seen.contains(&RESET_ENDPOINT_COMMAND));
    assert!(peer.borrow().seen.contains(&xhci::SET_DEQUEUE));
    peer.borrow_mut().halt_transfer = None;
    input.stop_hid().unwrap();
    input.restart().unwrap();
    assert_eq!(
        feed(&mut input, &peer, packet(91, true, 0, 1)).discarded,
        [TouchDiscard::OrphanContinuation]
    );
    input.stop_hid().unwrap();
}
