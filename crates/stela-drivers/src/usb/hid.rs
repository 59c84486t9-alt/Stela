// SPDX-License-Identifier: GPL-2.0-or-later
// Linux HID reference: Copyright (c) 1999 Andreas Gal;
// 2000-2005 Vojtech Pavlik; 2005 Michael Haboustak for Concept2, Inc;
// 2006-2012 Jiri Kosina; 2007-2008 Oliver Neukum.
// Retained source identities and adaptation scope: usb/THIRD_PARTY.md.
//! Native USB HID report transport and descriptor-qualified input.
//!
//! The original report descriptor and every received report retain IDs,
//! collections, usages and values through `poll_hid`, including consumer keys,
//! gamepads, extra buttons and multitouch. No contact/axis semantics or receiver
//! identity is synthesized. Delimiter sets select their primary usage branch;
//! vendor protocols require explicit additional support. Existing `poll` exposes
//! the legacy keyboard/pointer input vocabulary and standard boot fallback for
//! actual boot-subclass interfaces.
//! EP0 controls use actual descriptor lengths and status-stage acknowledgements;
//! endpoint stop/restart shares the controller's DMA retirement authority.
mod control;
#[cfg(test)]
mod delimiter_tests;
pub mod descriptor;
pub mod events;
mod lifecycle;
mod report;
mod usages;

pub use descriptor::{DecodeError, Descriptor, Frame, ReportType};

use super::xhci::{
    Controller, DEVICE_TO_HOST, Device, Endpoint, GET_DESCRIPTOR, Interface, Plan,
    RECIPIENT_INTERFACE, STALL, Shared, SlotId, TYPE_CLASS, setup,
};
use crate::{
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer},
    input::{Input, POINTER_MAX},
};
use alloc::{format, string::String, vec::Vec};
use report::{Field, Keys, Pointer, Reports};

pub const CLASS: u8 = 3;
const BOOT: u8 = 1;
const KEYBOARD: u8 = 1;
const MOUSE: u8 = 2;
const GET_REPORT: u8 = 0x01;
const SET_REPORT: u8 = 0x09;
const SET_IDLE: u8 = 0x0a;
const MAX_DESCRIPTOR_BYTES: usize = 4096;
const SET_PROTOCOL: u8 = 0x0b;
const HID_DESCRIPTOR: u8 = 0x21;
const REPORT_DESCRIPTOR: u8 = 0x22;
/// Boot reports fit eight bytes (HID 1.11 Appendix B); Linux `usbmouse`
/// caps its transfer there.
const BOOT_REPORT_BYTES: usize = 8;
/// An interrupt endpoint's wMaxPacketSize payload bits.
const MAX_PACKET_SIZE: u16 = 0x7ff;
/// Linux `hid_io_error`: retry after 13 ms, doubling to at least 100 ms,
/// and give up after a second of failures.
const FIRST_RETRY_MS: u64 = 13;
const LONGEST_RETRY_MS: u64 = 100;
const RETRY_WINDOW_US: u64 = 1_000_000;
const MICROSECONDS_PER_MILLISECOND: u64 = 1_000;
const BOOT_PROTOCOL: u16 = 0;
const REPORT_PROTOCOL: u16 = 1;
/// The Keyboard/Keypad usages the native keyboard reports.
const KEY_USAGES: core::ops::RangeInclusive<u32> = 0x04..=0xdd;
const MODIFIER_USAGES: core::ops::RangeInclusive<u32> = 0xe0..=0xe7;

pub(super) fn plan(interface: &Interface) -> Result<Plan, &'static str> {
    let endpoint = interface
        .endpoints
        .iter()
        .copied()
        .find(|e| e.kind() == 3 && e.is_in())
        .ok_or("HID interface without an interrupt IN endpoint")?;
    Ok(Plan::Hid(endpoint))
}

/// Fetch the exact descriptor named by this interface's HID descriptor.
fn read_descriptor(
    c: &mut Controller,
    device: &Device,
    interface: &Interface,
) -> Result<Vec<u8>, BlockError> {
    let length = descriptor_length(interface).map_err(BlockError::Unsupported)?;
    let request = setup(
        DEVICE_TO_HOST | RECIPIENT_INTERFACE,
        GET_DESCRIPTOR,
        u16::from(REPORT_DESCRIPTOR) << 8,
        u16::from(interface.number),
        length,
    );
    let bytes = c.device(device.id)?.control(request, &[])?;
    if bytes.len() != usize::from(length) {
        return Err(BlockError::Protocol("short USB HID report descriptor"));
    }
    Ok(bytes)
}

fn descriptor_length(interface: &Interface) -> Result<u16, &'static str> {
    let descriptor = interface
        .extra
        .iter()
        .find(|d| d.get(1) == Some(&HID_DESCRIPTOR))
        .ok_or("HID interface without a HID descriptor")?;
    if descriptor.len() < 6
        || usize::from(descriptor[0]) != descriptor.len()
        || descriptor.len() != 6 + usize::from(descriptor[5]) * 3
    {
        return Err("malformed USB HID descriptor");
    }
    let mut reports = descriptor[6..]
        .as_chunks::<3>()
        .0
        .iter()
        .filter(|entry| entry[0] == REPORT_DESCRIPTOR);
    let entry = reports
        .next()
        .ok_or("HID interface without a report descriptor")?;
    if reports.next().is_some() {
        return Err("multiple HID report descriptors on one interface");
    }
    let length = u16::from_le_bytes([entry[1], entry[2]]);
    if length == 0 || usize::from(length) > MAX_DESCRIPTOR_BYTES {
        return Err("USB HID report descriptor length outside 1..4096");
    }
    Ok(length)
}

/// Why an interface is left unused.
pub const NO_REPORTS: &str = "HID interface without an input report";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Running,
    Stopped,
    /// A transport/cancellation failed. Retain the TD and DMA until the shared
    /// controller can actually acknowledge retirement.
    Faulted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceivedReport {
    Data(Frame),
    /// A standard boot-protocol report; the original descriptor could not be
    /// used. `Poll::inputs` carries the Appendix B keyboard/mouse events.
    Boot(Vec<u8>),
    Rejected {
        bytes: Vec<u8>,
        error: DecodeError,
    },
}

/// One bounded service pass: native compatibility inputs and every received
/// descriptor-qualified HID report. Frontends must consume `reports` to expose
/// consumer controls, extra buttons, gamepads and touch to the guest.
#[derive(Debug, Default)]
pub struct Poll {
    pub inputs: Vec<Input>,
    pub events: Vec<events::Event>,
    pub reports: Vec<ReceivedReport>,
}

/// The protocol and layout to read a boot interface with: its report
/// descriptor's, in the report protocol, when that is `usable` (describes
/// the keyboard or pointer the interface is), else `boot` in the boot
/// protocol.
fn boot_interface(
    described: Result<Reports, BlockError>,
    boot: Reports,
    usable: impl Fn(&Reports) -> bool,
) -> (u16, Reports) {
    match described {
        Ok(reports) if usable(&reports) => (REPORT_PROTOCOL, reports),
        _ => (BOOT_PROTOCOL, boot),
    }
}

/// Failed transfers being retried, as Linux `hid_io_error` retries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Retry {
    delay_ms: u64,
    /// When the next transfer may go out, and when retrying stops.
    at_us: u64,
    stop_us: u64,
}

impl Retry {
    fn first(now_us: u64) -> Self {
        Self {
            delay_ms: FIRST_RETRY_MS,
            at_us: now_us + FIRST_RETRY_MS * MICROSECONDS_PER_MILLISECOND,
            stop_us: now_us + RETRY_WINDOW_US,
        }
    }

    /// The next retry after another failure, or none once retrying has run
    /// a second without a report.
    fn next(self, now_us: u64) -> Option<Self> {
        if now_us > self.stop_us {
            return None;
        }
        let delay_ms = match self.delay_ms < LONGEST_RETRY_MS {
            true => self.delay_ms * 2,
            false => self.delay_ms,
        };
        Some(Self {
            delay_ms,
            at_us: now_us + delay_ms * MICROSECONDS_PER_MILLISECOND,
            ..self
        })
    }
}

/// One HID interface the host polls.
pub struct UsbInput {
    controller: Shared,
    id: SlotId,
    interface: u8,
    descriptor: Option<Descriptor>,
    report_descriptor: Vec<u8>,
    state: State,
    /// The original first transport failure, never replaced by a later error.
    error: Option<BlockError>,
    endpoint: Endpoint,
    buffer: DmaBuffer,
    /// Bytes one interrupt transfer asks for: the longest input report.
    length: usize,
    /// The queued TD, if one is out.
    queued: Option<u64>,
    /// Transfer errors being retried.
    retry: Option<Retry>,
    reports: Reports,
    events: events::Decoder,
    /// The keyboard usages the last keyboard report held.
    held: Vec<u32>,
    buttons: u8,
    /// The absolute pointer's last position.
    position: Option<(u16, u16)>,
    /// Keyboard reports holding usages the native keyboard cannot report.
    pub dropped: u64,
    /// The first transfer failure, reported once.
    failed: bool,
    /// The last report received, as it arrived.
    last_report: Vec<u8>,
    pub name: String,
}

impl UsbInput {
    pub(super) fn new(
        controller: Shared,
        device: &Device,
        interface: &Interface,
        endpoint: Endpoint,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Option<Self>, BlockError> {
        let index = u16::from(interface.number);
        let (chosen, reports, descriptor, report_descriptor) = {
            let mut c = controller.borrow_mut();
            let protocol = |c: &mut Controller, protocol: u16| -> Result<(), BlockError> {
                let request = setup(
                    TYPE_CLASS | RECIPIENT_INTERFACE,
                    SET_PROTOCOL,
                    protocol,
                    index,
                    0,
                );
                c.device(device.id)?.control(request, &[])?;
                // Reports on change only; a device may refuse.
                match c.device(device.id)?.control(
                    setup(TYPE_CLASS | RECIPIENT_INTERFACE, SET_IDLE, 0, index, 0),
                    &[],
                ) {
                    Ok(_) | Err(BlockError::Device { status: STALL }) => {}
                    Err(error) => return Err(error),
                }
                Ok(())
            };
            // The generic layout is authoritative for all report kinds. Boot
            // fallback is allowed only for an actual boot subclass interface.
            let raw = read_descriptor(&mut c, device, interface);
            let described = raw.as_ref().map_err(Clone::clone).and_then(|bytes| {
                let descriptor = Descriptor::parse(bytes).map_err(BlockError::Unsupported)?;
                let reports = report::parse(bytes).map_err(BlockError::Unsupported)?;
                Ok((descriptor, reports))
            });
            let legacy = described
                .as_ref()
                .map(|(_, reports)| reports.clone())
                .map_err(Clone::clone);
            let boot = match (interface.subclass, interface.protocol) {
                (BOOT, KEYBOARD) => Some(boot_interface(
                    legacy.clone(),
                    Reports {
                        keys: Some(Keys::boot()),
                        pointer: None,
                        input_bytes: BOOT_REPORT_BYTES,
                    },
                    |reports| reports.keys.is_some(),
                )),
                (BOOT, MOUSE) => Some(boot_interface(
                    legacy.clone(),
                    Reports {
                        keys: None,
                        pointer: Some(Pointer::boot()),
                        input_bytes: BOOT_REPORT_BYTES,
                    },
                    |reports| reports.pointer.is_some(),
                )),
                _ => None,
            };
            match boot {
                Some((chosen, reports)) => {
                    protocol(&mut c, chosen)?;
                    let descriptor = if chosen == REPORT_PROTOCOL {
                        Some(described?.0)
                    } else {
                        None
                    };
                    (chosen, reports, descriptor, raw.unwrap_or_default())
                }
                None => {
                    let (descriptor, reports) = described?;
                    // SET_PROTOCOL is only defined for boot-subclass devices.
                    // SET_IDLE is optional for an ordinary report interface.
                    let idle = setup(TYPE_CLASS | RECIPIENT_INTERFACE, SET_IDLE, 0, index, 0);
                    match c.device(device.id)?.control(idle, &[]) {
                        Ok(_) | Err(BlockError::Device { status: STALL }) => {}
                        Err(error) => return Err(error),
                    }
                    (REPORT_PROTOCOL, reports, Some(descriptor), raw?)
                }
            }
        };
        if chosen == REPORT_PROTOCOL && descriptor.as_ref().is_none_or(|d| d.input_bytes() == 0) {
            return Ok(None);
        }
        if let Some(pointer) = &reports.pointer
            && pointer.x.map(|f| f.relative) != pointer.y.map(|f| f.relative)
        {
            return Err(BlockError::Unsupported(
                "HID pointer with one absolute and one relative axis",
            ));
        }
        let length = match chosen {
            REPORT_PROTOCOL => descriptor.as_ref().unwrap().input_bytes(),
            _ => usize::from(endpoint.max_packet & MAX_PACKET_SIZE).min(BOOT_REPORT_BYTES),
        };
        if length == 0 {
            return Err(BlockError::Unsupported("HID input report without data"));
        }
        let buffer = dma.allocate(length, length.next_power_of_two())?;
        Ok(Some(Self {
            controller,
            id: device.id,
            interface: interface.number,
            descriptor,
            report_descriptor,
            state: State::Running,
            error: None,
            endpoint,
            buffer,
            length,
            queued: None,
            retry: None,
            reports,
            events: events::Decoder::default(),
            held: Vec::new(),
            buttons: 0,
            position: None,
            dropped: 0,
            failed: false,
            last_report: Vec::new(),
            name: format!("{} ({})", device.name(), device.location),
        }))
    }

    /// Legacy keyboard/pointer service. Use `poll_hid` for the complete report
    /// stream; this adapter exposes only the native `Input` vocabulary.
    pub fn poll(&mut self) -> Vec<Input> {
        self.poll_hid().inputs
    }

    /// Service the actual owned interrupt-IN endpoint, bounded to 16 reports.
    pub fn poll_hid(&mut self) -> Poll {
        let mut polled = Poll::default();
        let now = self.controller.borrow().clock.now_us();
        if self.state != State::Running || self.retry.is_some_and(|retry| now < retry.at_us) {
            return polled;
        }
        for _ in 0..16 {
            let length = self.length;
            let trb = match self.queued {
                Some(trb) => trb,
                None => {
                    let submitted =
                        self.controller
                            .borrow_mut()
                            .device(self.id)
                            .and_then(|mut device| {
                                device.submit(self.endpoint.dci(), self.buffer.physical(), length)
                            });
                    match submitted {
                        Ok(trb) => {
                            self.queued = Some(trb);
                            trb
                        }
                        Err(error) => {
                            self.fault(error);
                            break;
                        }
                    }
                }
            };
            let result = match self.controller.borrow_mut().device(self.id) {
                Ok(mut device) => device.completed(self.endpoint.dci(), trb, length),
                Err(error) => Some(Err(error)),
            };
            let Some(result) = result else {
                break;
            };
            match result {
                Ok(bytes) => {
                    self.queued = None;
                    self.retry = None;
                    let bytes = self.buffer.bytes()[..bytes].to_vec();
                    let events_at = polled.events.len();
                    let received = match &self.descriptor {
                        Some(descriptor) => match descriptor.decode(&bytes) {
                            Ok(frame) => {
                                polled.events.extend(self.events.update(descriptor, &frame));
                                ReceivedReport::Data(frame)
                            }
                            Err(error) => ReceivedReport::Rejected {
                                bytes: bytes.clone(),
                                error,
                            },
                        },
                        None => ReceivedReport::Boot(bytes.clone()),
                    };
                    // Native keys merge every actual report ID; a receiver's
                    // second keyboard cannot release the first one's keys.
                    let mut dropped = false;
                    for event in &polled.events[events_at..] {
                        if let events::Event::Keyboard { usage, pressed } = event {
                            if KEY_USAGES.contains(usage) || MODIFIER_USAGES.contains(usage) {
                                let was = self.held.contains(usage);
                                if was != *pressed {
                                    polled.inputs.push(Input::Key {
                                        usage: *usage as u8,
                                        pressed: *pressed,
                                    });
                                    if *pressed {
                                        self.held.push(*usage);
                                    } else {
                                        self.held.retain(|u| u != usage);
                                    }
                                }
                            } else {
                                dropped = true;
                            }
                        }
                    }
                    if dropped {
                        self.dropped += 1;
                    }
                    // Never partially mutate legacy state for a malformed report.
                    if !matches!(received, ReceivedReport::Rejected { .. }) {
                        self.report(&bytes, &mut polled.inputs);
                    } else {
                        self.last_report = bytes;
                    }
                    polled.reports.push(received);
                    continue;
                }
                Err(error) => {
                    self.error.get_or_insert_with(|| error.clone());
                    let recovered =
                        self.controller
                            .borrow_mut()
                            .device(self.id)
                            .and_then(|mut device| {
                                if error == (BlockError::Device { status: STALL }) {
                                    device.clear(&self.endpoint)
                                } else {
                                    device.reset_endpoint(&self.endpoint)
                                }
                            });
                    if recovered.is_ok() {
                        self.queued = None;
                    }
                    self.retry = match self.retry {
                        None => Some(Retry::first(now)),
                        Some(retry) => retry.next(now),
                    };
                    if let Err(error) = recovered {
                        self.fault(error);
                    } else if self.retry.is_none() {
                        self.fault(error);
                    }
                    break;
                }
            }
        }
        polled
    }

    fn fault(&mut self, error: BlockError) {
        self.error.get_or_insert(error);
        self.failed = true;
        self.state = State::Faulted;
    }

    /// The last report received, as it arrived, for diagnostics.
    pub fn last_report(&self) -> &[u8] {
        &self.last_report
    }

    /// Whether polling stopped on a transfer failure.
    pub fn failed(&self) -> bool {
        self.failed
    }

    fn report(&mut self, report: &[u8], inputs: &mut Vec<Input>) {
        self.last_report = report.to_vec();
        let (id, body) = if self.reports.numbered() {
            match report.split_first() {
                Some((&id, body)) => (Some(id), body),
                None => return,
            }
        } else {
            (None, report)
        };
        if self.descriptor.is_none()
            && let Some(keys) = &self.reports.keys
            && keys.report == id
        {
            self.keys(body, inputs);
        }
        if let Some(pointer) = &self.reports.pointer
            && pointer.report == id
        {
            let pointer = pointer.clone();
            self.pointer(&pointer, body, inputs);
        }
    }

    /// Key presses and releases since the last keyboard report: modifiers,
    /// then releases, then presses, each in report order.
    fn keys(&mut self, body: &[u8], inputs: &mut Vec<Input>) {
        let Some(keys) = &self.reports.keys else {
            return;
        };
        let Some(mut held) = keys.pressed(body) else {
            return;
        };
        let before = held.len();
        held.retain(|usage| KEY_USAGES.contains(usage) || MODIFIER_USAGES.contains(usage));
        // Count each report that holds usages the native keyboard lacks.
        if held.len() != before {
            self.dropped += 1;
        }
        let key = |usage: u32, pressed| Input::Key {
            usage: usage as u8,
            pressed,
        };
        for usage in MODIFIER_USAGES {
            let (was, is) = (self.held.contains(&usage), held.contains(&usage));
            if was != is {
                inputs.push(key(usage, is));
            }
        }
        let modifier = |usage: &&u32| MODIFIER_USAGES.contains(*usage);
        for usage in self.held.iter().filter(|u| !modifier(u)) {
            if !held.contains(usage) {
                inputs.push(key(*usage, false));
            }
        }
        for usage in held.iter().filter(|u| !modifier(u)) {
            if !self.held.contains(usage) {
                inputs.push(key(*usage, true));
            }
        }
        self.held = held;
    }

    fn pointer(&mut self, layout: &Pointer, body: &[u8], inputs: &mut Vec<Input>) {
        let mouse = layout.x.is_some_and(|f| f.relative);
        let value = |field: Option<Field>| field.and_then(|f| f.read(body));
        if value(layout.x).is_none() || value(layout.y).is_none() {
            return;
        }
        if mouse {
            let counts = |v: i32| v.clamp(i16::MIN.into(), i16::MAX.into()) as i16;
            let (dx, dy) = (value(layout.x), value(layout.y));
            if let (Some(dx), Some(dy)) = (dx, dy)
                && (dx, dy) != (0, 0)
            {
                inputs.push(Input::Motion {
                    dx: counts(dx),
                    dy: counts(dy),
                });
            }
        } else {
            let axis = |field: Option<Field>| -> Option<u16> {
                let field = field?;
                let value = field.read(body)?;
                let max = i64::from(POINTER_MAX);
                let span = i64::from(field.maximum) - i64::from(field.minimum);
                if span <= 0 {
                    return None;
                }
                let scaled = (i64::from(value) - i64::from(field.minimum)) * max / span;
                Some(scaled.clamp(0, max) as u16)
            };
            if let (Some(x), Some(y)) = (axis(layout.x), axis(layout.y))
                && Some((x, y)) != self.position
            {
                self.position = Some((x, y));
                inputs.push(Input::Move { x, y });
            }
        }
        let mut buttons = 0;
        for (n, field) in layout.buttons.iter().enumerate() {
            if value(*field).is_some_and(|v| v != 0) {
                buttons |= 1 << n;
            }
        }
        // The legacy absolute-pointer frontend has three buttons. Complete
        // extra-button values remain in poll_hid's descriptor samples.
        if !mouse {
            buttons &= 7;
        }
        if buttons != self.buttons {
            self.buttons = buttons;
            inputs.push(if mouse {
                Input::MouseButtons(buttons)
            } else {
                Input::Buttons(buttons)
            });
        }
        if let Some(wheel) = value(layout.wheel)
            && wheel != 0
        {
            let detents = wheel.clamp(-127, 127) as i8;
            inputs.push(if mouse {
                Input::MouseWheel(detents)
            } else {
                Input::Wheel(detents)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let described = report::parse(&NUMBERED_KEYBOARD).map_err(BlockError::Unsupported);
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
            0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x02,
            0x81, 0x06,
        ])
        .map_err(BlockError::Unsupported);
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
        5, 1, 9, 5, 0xa1, 1, 0x85, 2, 9, 0x30, 9, 0x31, 0x15, 0x81, 0x25, 0x7f, 0x75, 8, 0x95, 2,
        0x81, 2, 5, 9, 0x19, 1, 0x29, 8, 0x15, 0, 0x25, 1, 0x75, 1, 0x95, 8, 0x81, 2, 5, 8, 9, 1,
        0x75, 8, 0x95, 1, 0x91, 2, 5, 0x0d, 9, 0x55, 0xb1, 2, 0xc0,
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
        hardware
            .borrow_mut()
            .incoming_events
            .push_back(vec![2, 0xff, 5, 0x80]);
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
        hardware
            .borrow_mut()
            .incoming_events
            .push_back(vec![2, 1, 2, 0]);
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
            .incoming_events
            .push_back(vec![1, 0, 0, 4, 0, 0, 0, 0, 0]);
        assert_eq!(
            input.poll(),
            [Input::Key {
                usage: 4,
                pressed: true
            }]
        );
        hardware.borrow_mut().incoming_events.push_back(vec![1, 0]);
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
            .incoming_events
            .push_back(vec![1, 0, 0, 1, 1, 1, 1, 1, 1]);
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
                .incoming_events
                .push_back(vec![0x11, 127, 0, 1]);
            let polled = input.poll_hid();
            let expected = if relative {
                vec![
                    Input::Motion { dx: 127, dy: 0 },
                    Input::MouseButtons(0x11),
                    Input::MouseWheel(1),
                ]
            } else {
                vec![
                    Input::Move {
                        x: POINTER_MAX,
                        y: 0,
                    },
                    Input::Buttons(1),
                    Input::Wheel(1),
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
            .incoming_events
            .push_back(vec![0, 0, 4, 0, 0, 0, 0, 0]);
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
}
