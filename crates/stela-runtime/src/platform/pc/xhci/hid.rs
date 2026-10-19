//! USB HID keyboards and pointers (HID 1.11) as sources of the native
//! peripheral's inputs.
//!
//! Boot keyboards (subclass 1, protocol 1) run the boot protocol: each
//! report's modifier bits and six-key array, compared with the previous
//! report, become key presses and releases (Appendix B.1); a report of
//! ErrorRollOver changes nothing. Boot mice (subclass 1, protocol 2) run
//! the boot protocol too (Appendix B.2): buttons, and relative motion that
//! moves a pointer position kept here, since the native pointer is
//! absolute. Other HID interfaces run the report protocol, read through
//! their report descriptor (6.2.2): a pointer is a report with Generic
//! Desktop X and Y, absolute (tablets, as QEMU's `usb-tablet`) or
//! relative, with Button 1-3 and the wheel when present. Report-protocol
//! keyboards and other HID devices are refused: no driver here reads their
//! reports. Long items, Push and Pop are refused in report descriptors.
use super::{
    super::{
        block::BlockError,
        dma::{DmaAllocator, DmaBuffer},
    },
    Device, Endpoint, Interface, Plan, STALL, Shared, setup,
};
use crate::platform::usb::hid::{Input, POINTER_MAX};
use alloc::{format, string::String, vec::Vec};

pub const CLASS: u8 = 3;
const BOOT: u8 = 1;
const KEYBOARD: u8 = 1;
const MOUSE: u8 = 2;
const SET_IDLE: u8 = 0x0a;
const SET_PROTOCOL: u8 = 0x0b;
const HID_DESCRIPTOR: u8 = 0x21;
const REPORT_DESCRIPTOR: u8 = 0x22;
const REPORT_BYTES: usize = 64;
const ERROR_ROLLOVER: u8 = 1;
/// Pointer units per boot-mouse count: about 1/2000 of the range.
const MOTION_SCALE: i32 = 16;

pub(super) fn plan(interface: &Interface) -> Result<Plan, &'static str> {
    let endpoint = interface
        .endpoints
        .iter()
        .copied()
        .find(|e| e.kind() == 3 && e.is_in())
        .ok_or("HID interface without an interrupt IN endpoint")?;
    Ok(Plan::Hid(endpoint))
}

/// One field of a report: where it is and how to read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Field {
    /// Bit offset in the report, after any report ID byte.
    offset: usize,
    size: usize,
    minimum: i32,
    maximum: i32,
    relative: bool,
}

impl Field {
    fn read(&self, report: &[u8]) -> Option<i32> {
        if self.size == 0 || self.size > 32 || (self.offset + self.size).div_ceil(8) > report.len()
        {
            return None;
        }
        let mut value: u64 = 0;
        for bit in 0..self.size {
            let at = self.offset + bit;
            if report[at / 8] >> (at % 8) & 1 != 0 {
                value |= 1 << bit;
            }
        }
        // Signed when the logical minimum is negative (6.2.2.7).
        Some(
            if self.minimum < 0 && self.size < 32 && value >> (self.size - 1) & 1 != 0 {
                (value as i64 - (1i64 << self.size)) as i32
            } else {
                value as i32
            },
        )
    }
}

/// A pointer report's layout.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Layout {
    report: Option<u8>,
    x: Option<Field>,
    y: Option<Field>,
    wheel: Option<Field>,
    buttons: [Option<Field>; 3],
}

/// The first pointer report a report descriptor describes: one with X and
/// Y on the Generic Desktop page.
fn pointer_layout(descriptor: &[u8]) -> Result<Layout, &'static str> {
    #[derive(Clone, Copy, Default)]
    struct Global {
        page: u32,
        minimum: i32,
        maximum: i32,
        size: usize,
        count: usize,
        report: Option<u8>,
    }
    let mut global = Global::default();
    let mut usages: Vec<u32> = Vec::new();
    let mut range: Option<(u32, u32)> = None;
    let mut offsets: Vec<(Option<u8>, usize)> = Vec::new();
    let mut layouts: Vec<Layout> = Vec::new();
    let mut at = 0;
    while at < descriptor.len() {
        let prefix = descriptor[at];
        if prefix == 0xfe {
            return Err("long items in a report descriptor");
        }
        let size = match prefix & 3 {
            3 => 4,
            n => usize::from(n),
        };
        let Some(data) = descriptor.get(at + 1..at + 1 + size) else {
            return Err("truncated report descriptor");
        };
        at += 1 + size;
        let unsigned = data
            .iter()
            .enumerate()
            .fold(0u32, |value, (n, byte)| value | u32::from(*byte) << (8 * n));
        let signed = match size {
            1 => i32::from(data[0] as i8),
            2 => i32::from(i16::from_le_bytes([data[0], data[1]])),
            4 => unsigned as i32,
            _ => 0,
        };
        let full_usage = |usage: u32| {
            if size == 4 {
                usage
            } else {
                global.page << 16 | usage
            }
        };
        match prefix & 0xfc {
            // Main items.
            0x80 => {
                let flags = unsigned;
                let offset = match offsets.iter_mut().find(|(id, _)| *id == global.report) {
                    Some((_, offset)) => offset,
                    None => {
                        offsets.push((global.report, 0));
                        &mut offsets.last_mut().unwrap().1
                    }
                };
                let start = *offset;
                *offset += global.size * global.count;
                if flags & 1 == 0 {
                    for n in 0..global.count {
                        let usage = match range {
                            Some((first, last)) => (first + n as u32).min(last),
                            None => match usages.get(n).or(usages.last()) {
                                Some(usage) => *usage,
                                None => continue,
                            },
                        };
                        let field = Field {
                            offset: start + n * global.size,
                            size: global.size,
                            minimum: global.minimum,
                            maximum: global.maximum,
                            relative: flags & 4 != 0,
                        };
                        let layout = match layouts.iter_mut().find(|l| l.report == global.report) {
                            Some(layout) => layout,
                            None => {
                                layouts.push(Layout {
                                    report: global.report,
                                    ..Layout::default()
                                });
                                layouts.last_mut().unwrap()
                            }
                        };
                        match usage {
                            0x0001_0030 => layout.x = layout.x.or(Some(field)),
                            0x0001_0031 => layout.y = layout.y.or(Some(field)),
                            0x0001_0038 => layout.wheel = layout.wheel.or(Some(field)),
                            0x0009_0001..=0x0009_0003 => {
                                let button = &mut layout.buttons[(usage - 0x0009_0001) as usize];
                                *button = button.or(Some(field));
                            }
                            _ => {}
                        }
                    }
                }
                usages.clear();
                range = None;
            }
            0x90 | 0xb0 => {
                // Output and Feature reports have their own offsets; this
                // driver reads neither.
                usages.clear();
                range = None;
            }
            0xa0 | 0xc0 => {
                usages.clear();
                range = None;
            }
            // Global items.
            0x04 => global.page = unsigned,
            0x14 => global.minimum = signed,
            0x24 => {
                // A maximum that only fits unsigned (8-bit 0xff) stays positive.
                global.maximum = if global.minimum >= 0 {
                    unsigned as i32
                } else {
                    signed
                };
            }
            0x74 => global.size = unsigned as usize,
            0x84 => global.report = Some(unsigned as u8),
            0x94 => global.count = unsigned as usize,
            0xa4 | 0xb4 => return Err("Push and Pop in a report descriptor"),
            0x34 | 0x44 | 0x54 | 0x64 => {}
            // Local items.
            0x08 => usages.push(full_usage(unsigned)),
            0x18 => range = Some((full_usage(unsigned), range.map_or(0, |r| r.1))),
            0x28 => range = Some((range.map_or(0, |r| r.0), full_usage(unsigned))),
            _ => {}
        }
    }
    layouts
        .into_iter()
        .find(|layout| layout.x.is_some() && layout.y.is_some())
        .ok_or("HID report descriptor without a pointer")
}

enum Kind {
    Keyboard { previous: [u8; 8] },
    Pointer(Layout),
}

/// One HID interface the host polls.
pub struct UsbInput {
    controller: Shared,
    slot: u8,
    endpoint: Endpoint,
    buffer: DmaBuffer,
    /// The queued TD, if one is out.
    queued: Option<u64>,
    kind: Kind,
    position: (i32, i32),
    buttons: u8,
    /// The first transfer failure, reported once.
    failed: bool,
    pub name: String,
}

impl UsbInput {
    pub(super) fn new(
        controller: Shared,
        device: &Device,
        interface: &Interface,
        endpoint: Endpoint,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let index = u16::from(interface.number);
        let kind = {
            let mut c = controller.borrow_mut();
            match (interface.subclass, interface.protocol) {
                (BOOT, KEYBOARD | MOUSE) => {
                    c.control(device.slot, setup(0x21, SET_PROTOCOL, 0, index, 0), &[])?;
                    // Reports on change only; a device may refuse.
                    let _ = c.control(device.slot, setup(0x21, SET_IDLE, 0, index, 0), &[]);
                    if interface.protocol == KEYBOARD {
                        Kind::Keyboard { previous: [0; 8] }
                    } else {
                        let field = |offset, size, minimum: i32, relative| {
                            Some(Field {
                                offset,
                                size,
                                minimum,
                                maximum: if minimum < 0 { 127 } else { 1 },
                                relative,
                            })
                        };
                        Kind::Pointer(Layout {
                            report: None,
                            x: field(8, 8, -127, true),
                            y: field(16, 8, -127, true),
                            wheel: None,
                            buttons: [
                                field(0, 1, 0, false),
                                field(1, 1, 0, false),
                                field(2, 1, 0, false),
                            ],
                        })
                    }
                }
                _ => {
                    let length = interface
                        .extra
                        .iter()
                        .find(|d| {
                            d.len() >= 9 && d[1] == HID_DESCRIPTOR && d[6] == REPORT_DESCRIPTOR
                        })
                        .map(|d| u16::from_le_bytes([d[7], d[8]]))
                        .ok_or(BlockError::Unsupported(
                            "HID interface without a report descriptor",
                        ))?;
                    let request = setup(0x81, 6, u16::from(REPORT_DESCRIPTOR) << 8, index, length);
                    let descriptor = c.control(device.slot, request, &[])?;
                    let layout = pointer_layout(&descriptor).map_err(BlockError::Unsupported)?;
                    Kind::Pointer(layout)
                }
            }
        };
        let buffer = dma.allocate(REPORT_BYTES, REPORT_BYTES)?;
        let center = i32::from(POINTER_MAX / 2);
        Ok(Self {
            controller,
            slot: device.slot,
            endpoint,
            buffer,
            queued: None,
            kind,
            position: (center, center),
            buttons: 0,
            failed: false,
            name: format!("{} ({})", device.name(), device.location),
        })
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

    /// Whether polling stopped on a transfer failure.
    pub fn failed(&self) -> bool {
        self.failed
    }

    fn report(&mut self, report: &[u8], inputs: &mut Vec<Input>) {
        match &mut self.kind {
            Kind::Keyboard { previous } => {
                if report.len() < 8 || report[2..8].contains(&ERROR_ROLLOVER) {
                    return;
                }
                let current: [u8; 8] = report[..8].try_into().unwrap();
                for bit in 0..8 {
                    let (was, is) = (previous[0] >> bit & 1, current[0] >> bit & 1);
                    if was != is {
                        inputs.push(Input::Key {
                            usage: 0xe0 + bit,
                            pressed: is != 0,
                        });
                    }
                }
                for &usage in previous[2..].iter().filter(|u| **u >= 4) {
                    if !current[2..].contains(&usage) {
                        inputs.push(Input::Key {
                            usage,
                            pressed: false,
                        });
                    }
                }
                for &usage in current[2..].iter().filter(|u| **u >= 4) {
                    if !previous[2..].contains(&usage) {
                        inputs.push(Input::Key {
                            usage,
                            pressed: true,
                        });
                    }
                }
                *previous = current;
            }
            Kind::Pointer(layout) => {
                let body = match layout.report {
                    Some(id) => match report.split_first() {
                        Some((&first, rest)) if first == id => rest,
                        _ => return,
                    },
                    None => report,
                };
                let axis = |field: Option<Field>, position: i32| -> Option<i32> {
                    let field = field?;
                    let value = field.read(body)?;
                    let max = i32::from(POINTER_MAX);
                    Some(if field.relative {
                        (position + value * MOTION_SCALE).clamp(0, max)
                    } else {
                        let span = i64::from(field.maximum) - i64::from(field.minimum);
                        if span <= 0 {
                            return None;
                        }
                        let scaled =
                            (i64::from(value) - i64::from(field.minimum)) * i64::from(max) / span;
                        scaled.clamp(0, i64::from(max)) as i32
                    })
                };
                let x = axis(layout.x, self.position.0);
                let y = axis(layout.y, self.position.1);
                if let (Some(x), Some(y)) = (x, y)
                    && (x, y) != self.position
                {
                    self.position = (x, y);
                    inputs.push(Input::Move {
                        x: x as u16,
                        y: y as u16,
                    });
                }
                let mut buttons = 0;
                for (n, field) in layout.buttons.iter().enumerate() {
                    if field.and_then(|f| f.read(body)).is_some_and(|v| v != 0) {
                        buttons |= 1 << n;
                    }
                }
                if buttons != self.buttons {
                    self.buttons = buttons;
                    inputs.push(Input::Buttons(buttons));
                }
                if let Some(wheel) = layout.wheel.and_then(|f| f.read(body))
                    && wheel != 0
                {
                    inputs.push(Input::Wheel(wheel.clamp(-127, 127) as i8));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{bench, run};
    use super::*;
    use crate::platform::usb::{
        Function, Speed,
        hid::Peripheral,
        hub::{Hub, Ports},
    };

    struct One(Peripheral);
    impl Ports for One {
        fn count(&self) -> usize {
            1
        }
        fn speed(&self, _: usize) -> Speed {
            Speed::Full
        }
        fn function(&mut self, _: usize) -> &mut dyn Function {
            &mut self.0
        }
        fn function_ref(&self, _: usize) -> &dyn Function {
            &self.0
        }
    }

    #[test]
    fn report_descriptors_yield_pointer_fields() {
        // A relative report-protocol mouse with a report ID.
        let descriptor = [
            0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x85, 0x02, 0x09, 0x01, 0xa1, 0x00, 0x05, 0x09,
            0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02,
            0x95, 0x01, 0x75, 0x05, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38,
            0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06, 0xc0, 0xc0,
        ];
        let layout = pointer_layout(&descriptor).unwrap();
        assert_eq!(layout.report, Some(2));
        let x = layout.x.unwrap();
        assert_eq!(
            (x.offset, x.size, x.relative, x.minimum),
            (8, 8, true, -127)
        );
        assert_eq!(layout.wheel.unwrap().offset, 24);
        assert_eq!(layout.buttons[2].unwrap().offset, 2);
        assert_eq!(x.read(&[0, 0xff]), Some(-1));
        assert!(pointer_layout(&[0x05, 0x01, 0xa4]).is_err());
        assert!(pointer_layout(&[0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0xc0]).is_err());
    }

    #[test]
    fn the_native_keyboard_and_pointer_reach_the_host_through_a_hub() {
        let hub = Hub::new(One(Peripheral::new()), "HUB").unwrap();
        let mut bench = bench(hub);
        let mut found = run(&mut bench);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        assert_eq!(found.inputs.len(), 2);
        let mut keyboard = found.inputs.remove(0);
        let mut pointer = found.inputs.remove(0);
        assert!(keyboard.poll().is_empty());
        assert!(pointer.poll().is_empty());
        let feed = |input: Input| {
            bench
                .model
                .borrow_mut()
                .function
                .ports
                .0
                .input(input)
                .unwrap();
        };
        feed(Input::Key {
            usage: 0x04,
            pressed: true,
        });
        feed(Input::Key {
            usage: 0xe1,
            pressed: true,
        });
        feed(Input::Move { x: 100, y: 0x7000 });
        feed(Input::Buttons(1));
        let mut keys = Vec::new();
        let mut motion = Vec::new();
        for _ in 0..50 {
            keys.extend(keyboard.poll());
            motion.extend(pointer.poll());
        }
        assert_eq!(
            keys,
            [
                Input::Key {
                    usage: 0x04,
                    pressed: true
                },
                Input::Key {
                    usage: 0xe1,
                    pressed: true
                },
            ]
        );
        assert!(
            motion.contains(&Input::Move { x: 100, y: 0x7000 }),
            "{motion:?}"
        );
        assert_eq!(motion.last(), Some(&Input::Buttons(1)));
        bench
            .model
            .borrow_mut()
            .function
            .ports
            .0
            .input(Input::Key {
                usage: 0x04,
                pressed: false,
            })
            .unwrap();
        let mut released = Vec::new();
        for _ in 0..50 {
            released.extend(keyboard.poll());
        }
        assert_eq!(
            released,
            [Input::Key {
                usage: 0x04,
                pressed: false
            }]
        );
        assert!(!keyboard.failed() && !pointer.failed());
    }
}
