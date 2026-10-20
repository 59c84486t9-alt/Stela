//! USB HID keyboards and pointers (HID 1.11) as sources of the native
//! peripheral's inputs.
//!
//! Every HID interface runs the report protocol, read through its report
//! descriptor ([`report`]), and may carry a keyboard report, a pointer
//! report or both, told apart by report ID. A boot keyboard (subclass 1,
//! protocol 1) whose descriptor describes no keyboard runs the boot
//! protocol, read as the boot report (Appendix B.1): a device that keeps
//! report IDs, or ignores SET_PROTOCOL, is read correctly only through its
//! descriptor. A keyboard report's held Keyboard/Keypad usages, compared
//! with the previous report's, become key presses and releases; a report
//! in an error state (ErrorRollOver and the like) changes nothing, and
//! usages the native keyboard does not report (beyond DDh, other than the
//! modifiers) are counted and dropped. Absolute pointer axes (tablets, as
//! QEMU's `usb-tablet`) drive the native absolute pointer; relative ones
//! (mice) drive the native mouse with their own counts, so macOS applies
//! its pointer acceleration. A boot mouse (subclass 1, protocol 2) is set
//! to the report protocol so that its wheel reaches the guest; one whose
//! report descriptor this driver cannot read runs the boot protocol
//! (Appendix B.2: buttons, X and Y). A pointer with one absolute and one
//! relative axis is refused; an interface with neither report (a vendor
//! control interface) is left unused.
mod report;

use super::xhci::{Controller, Device, Endpoint, Interface, Plan, STALL, Shared, setup};
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
const SET_IDLE: u8 = 0x0a;
const SET_PROTOCOL: u8 = 0x0b;
const HID_DESCRIPTOR: u8 = 0x21;
const REPORT_DESCRIPTOR: u8 = 0x22;
const REPORT_BYTES: usize = 64;
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

/// The keyboard and pointer reports of `interface`'s report descriptor.
fn read_reports(
    c: &mut Controller,
    device: &Device,
    interface: &Interface,
) -> Result<Reports, BlockError> {
    let length = interface
        .extra
        .iter()
        .find(|d| d.len() >= 9 && d[1] == HID_DESCRIPTOR && d[6] == REPORT_DESCRIPTOR)
        .map(|d| u16::from_le_bytes([d[7], d[8]]))
        .ok_or(BlockError::Unsupported(
            "HID interface without a report descriptor",
        ))?;
    let index = u16::from(interface.number);
    let request = setup(0x81, 6, u16::from(REPORT_DESCRIPTOR) << 8, index, length);
    let descriptor = c.control(device.slot, request, &[])?;
    report::parse(&descriptor).map_err(BlockError::Unsupported)
}

/// Why an interface is left unused.
pub const NO_REPORTS: &str = "HID interface with neither a keyboard nor a pointer report";

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

/// One HID interface the host polls.
pub struct UsbInput {
    controller: Shared,
    slot: u8,
    endpoint: Endpoint,
    buffer: DmaBuffer,
    /// The queued TD, if one is out.
    queued: Option<u64>,
    reports: Reports,
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
        let reports = {
            let mut c = controller.borrow_mut();
            let protocol = |c: &mut Controller, protocol: u16| -> Result<(), BlockError> {
                let request = setup(0x21, SET_PROTOCOL, protocol, index, 0);
                c.control(device.slot, request, &[])?;
                // Reports on change only; a device may refuse.
                let _ = c.control(device.slot, setup(0x21, SET_IDLE, 0, index, 0), &[]);
                Ok(())
            };
            let boot = match (interface.subclass, interface.protocol) {
                (BOOT, KEYBOARD) => Some(boot_interface(
                    read_reports(&mut c, device, interface),
                    Reports {
                        keys: Some(Keys::boot()),
                        pointer: None,
                    },
                    |reports| reports.keys.is_some(),
                )),
                (BOOT, MOUSE) => Some(boot_interface(
                    read_reports(&mut c, device, interface),
                    Reports {
                        keys: None,
                        pointer: Some(Pointer::boot()),
                    },
                    |reports| reports.pointer.is_some(),
                )),
                _ => None,
            };
            match boot {
                Some((chosen, reports)) => {
                    protocol(&mut c, chosen)?;
                    reports
                }
                None => read_reports(&mut c, device, interface)?,
            }
        };
        if reports.keys.is_none() && reports.pointer.is_none() {
            return Ok(None);
        }
        if let Some(pointer) = &reports.pointer
            && pointer.x.map(|f| f.relative) != pointer.y.map(|f| f.relative)
        {
            return Err(BlockError::Unsupported(
                "HID pointer with one absolute and one relative axis",
            ));
        }
        let buffer = dma.allocate(REPORT_BYTES, REPORT_BYTES)?;
        Ok(Some(Self {
            controller,
            slot: device.slot,
            endpoint,
            buffer,
            queued: None,
            reports,
            held: Vec::new(),
            buttons: 0,
            position: None,
            dropped: 0,
            failed: false,
            last_report: Vec::new(),
            name: format!("{} ({})", device.name(), device.location),
        }))
    }

    fn length(&self) -> usize {
        usize::from(self.endpoint.max_packet & 0x7ff).min(REPORT_BYTES)
    }

    /// The inputs of every report that arrived since the last poll.
    pub fn poll(&mut self) -> Vec<Input> {
        let mut inputs = Vec::new();
        for _ in 0..16 {
            let length = self.length();
            let trb = match self.queued {
                Some(trb) => trb,
                None => {
                    let submitted = self.controller.borrow_mut().submit(
                        self.slot,
                        self.endpoint.dci(),
                        self.buffer.physical(),
                        length,
                    );
                    match submitted {
                        Ok(trb) => {
                            self.queued = Some(trb);
                            trb
                        }
                        Err(_) => {
                            self.failed = true;
                            break;
                        }
                    }
                }
            };
            let result =
                self.controller
                    .borrow_mut()
                    .completed(self.slot, self.endpoint.dci(), trb, length);
            let Some(result) = result else {
                break;
            };
            self.queued = None;
            match result {
                Ok(bytes) => {
                    let report = self.buffer.bytes()[..bytes].to_vec();
                    self.report(&report, &mut inputs);
                }
                Err(BlockError::Device { status: STALL }) => {
                    let endpoint = self.endpoint;
                    if self
                        .controller
                        .borrow_mut()
                        .clear(self.slot, &endpoint)
                        .is_err()
                    {
                        self.failed = true;
                        break;
                    }
                }
                Err(_) => {
                    self.failed = true;
                    break;
                }
            }
        }
        inputs
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
        if let Some(keys) = &self.reports.keys
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
    const NUMBERED_KEYBOARD: [u8; 43] = [
        0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, // keyboard, report 1
        0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81,
        0x02, // modifiers
        0x95, 0x01, 0x75, 0x08, 0x81, 0x01, // reserved
        0x95, 0x06, 0x75, 0x08, 0x25, 0x65, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, // keys
        0xc0,
    ];

    #[test]
    fn a_boot_keyboard_with_report_ids_is_read_through_its_descriptor() {
        let boot = || Reports {
            keys: Some(Keys::boot()),
            pointer: None,
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
}
