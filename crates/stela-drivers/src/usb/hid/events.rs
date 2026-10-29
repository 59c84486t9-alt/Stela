// SPDX-License-Identifier: GPL-2.0-or-later
// Linux HID reference: Copyright (c) 1999 Andreas Gal;
// 2000-2005 Vojtech Pavlik; 2005 Michael Haboustak for Concept2, Inc;
// 2006-2012 Jiri Kosina; 2007-2008 Oliver Neukum.
// Source identities and adaptation scope: ../THIRD_PARTY.md.
//! Usage-driven native consumers of HID frames. The descriptor remains
//! authoritative; no VID/PID, device name or caller-supplied capability selects
//! a control. Touch packets keep count/time and contact IDs; hybrid packets
//! are not silently combined into an invented complete touch frame.
use super::descriptor::{Descriptor, Frame, ReportType, Sample, Value};
use alloc::vec::Vec;

const CONSUMER_PAGE: u32 = 0x0c;
const FINGER: u32 = 0x000d_0022;
const STYLUS: u32 = 0x000d_0020;
const CONTACT_ID: u32 = 0x000d_0051;
const CONTACT_COUNT: u32 = 0x000d_0054;
const SCAN_TIME: u32 = 0x000d_0056;
const X: u32 = 0x0001_0030;
const Y: u32 = 0x0001_0031;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Keyboard {
        usage: u32,
        pressed: bool,
    },
    Consumer {
        report: u8,
        usage: u16,
        pressed: bool,
    },
    /// Absolute values change only on observed changes; relative values keep
    /// every nonzero report. The field index disambiguates repeated controls.
    Gamepad(Control),
    Touch(TouchPacket),
    /// Complete observed gamepad state for this report ID, including arrays.
    /// Array membership changes must be applied from this snapshot, rather
    /// than assuming that an omitted usage is still held.
    GamepadState {
        report: u8,
        controls: Vec<Control>,
    },
    /// An acknowledged endpoint stop retires all consumer/contact state.
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    pub report: u8,
    pub collection: usize,
    pub field: usize,
    pub element: usize,
    pub usage: u32,
    /// Hat switches keep their logical range and null state. Axes are
    /// not normalized or clamped; button values keep their descriptor width.
    pub value: i64,
    pub minimum: i64,
    pub maximum: i64,
    pub relative: bool,
    pub null: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub collection: usize,
    pub id: Option<i64>,
    pub tip: Option<bool>,
    pub in_range: Option<bool>,
    pub confidence: Option<bool>,
    pub x: Option<i64>,
    pub y: Option<i64>,
    pub pressure: Option<i64>,
    pub width: Option<i64>,
    pub height: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TouchPacket {
    pub report: u8,
    pub application: usize,
    pub contact_count: Option<i64>,
    pub scan_time: Option<i64>,
    /// Only contacts present in this packet. A missing field is None,
    /// never zero, and count zero does not invent releases for omitted IDs.
    pub contacts: Vec<Contact>,
}

#[derive(Default)]
pub struct Decoder {
    consumer: Vec<(u8, Vec<u16>)>,
    keyboards: Vec<(u8, Vec<u32>)>,
    gamepads: Vec<(u8, Vec<Control>)>,
}

fn scalar(sample: &Sample) -> Option<i64> {
    match sample.value {
        Value::Scalar(value) if !sample.null => Some(value),
        _ => None,
    }
}

fn application(descriptor: &Descriptor, mut collection: Option<usize>) -> Option<usize> {
    while let Some(index) = collection {
        let current = descriptor.collections.get(index)?;
        if current.kind == 1 {
            return Some(index);
        }
        collection = current.parent;
    }
    None
}

fn ancestor(
    descriptor: &Descriptor,
    mut collection: Option<usize>,
    usages: &[u32],
) -> Option<usize> {
    while let Some(index) = collection {
        let current = descriptor.collections.get(index)?;
        if usages.contains(&current.usage) {
            return Some(index);
        }
        collection = current.parent;
    }
    None
}

impl Decoder {
    pub(super) fn stop(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        for (report, held) in self.consumer.drain(..) {
            for usage in held {
                events.push(Event::Consumer {
                    report,
                    usage,
                    pressed: false,
                });
            }
        }
        for usage in self.keyboard_usages() {
            events.push(Event::Keyboard {
                usage,
                pressed: false,
            });
        }
        self.keyboards.clear();
        self.gamepads.clear();
        events.push(Event::Stopped);
        events
    }

    fn keyboard_usages(&self) -> Vec<u32> {
        let mut usages = Vec::new();
        for (_, held) in &self.keyboards {
            for usage in held {
                if !usages.contains(usage) {
                    usages.push(*usage);
                }
            }
        }
        usages
    }

    /// Update only the state belonging to this report ID. Wireless receiver
    /// reports and composite controls therefore cannot release each other.
    pub fn update(&mut self, descriptor: &Descriptor, frame: &Frame) -> Vec<Event> {
        let Some(layout) = descriptor.layout(ReportType::Input, frame.id) else {
            return Vec::new();
        };
        let mut events = Vec::new();
        let mut consumers = Vec::new();
        let mut keyboard = Vec::new();
        let mut gamepads = Vec::new();
        let mut touch: Vec<TouchPacket> = Vec::new();
        for sample in &frame.samples {
            let Some(usage) = sample.usage else {
                continue;
            };
            let Some(field) = layout.fields.get(sample.field) else {
                continue;
            };
            if usage >> 16 == 7 && usage as u16 != 0 {
                let selected = scalar(sample).is_some_and(|v| v != 0 || field.flags & 2 == 0);
                if selected && !keyboard.contains(&(usage & 0xffff)) {
                    keyboard.push(usage & 0xffff);
                }
            }
            if usage >> 16 == CONSUMER_PAGE && usage as u16 != 0 {
                let selected = scalar(sample).is_some_and(|v| v != 0 || field.flags & 2 == 0);
                if selected && !consumers.contains(&(usage as u16)) {
                    consumers.push(usage as u16);
                }
            }
            let Some(app) = application(descriptor, sample.collection) else {
                continue;
            };
            let app_usage = descriptor.collections[app].usage;
            if matches!(app_usage, 0x0001_0004 | 0x0001_0005 | 0x0001_0008)
                && let Value::Scalar(value) = sample.value
            {
                gamepads.push(Control {
                    report: frame.id,
                    collection: app,
                    field: sample.field,
                    element: sample.element,
                    usage,
                    value,
                    minimum: field.minimum,
                    maximum: field.maximum,
                    relative: sample.relative,
                    null: sample.null,
                });
            }
            if !matches!(app_usage, 0x000d_0002 | 0x000d_0004 | 0x000d_0005) {
                continue;
            }
            let index = touch
                .iter()
                .position(|packet| packet.application == app)
                .unwrap_or_else(|| {
                    touch.push(TouchPacket {
                        report: frame.id,
                        application: app,
                        contact_count: None,
                        scan_time: None,
                        contacts: Vec::new(),
                    });
                    touch.len() - 1
                });
            let packet = &mut touch[index];
            if usage == CONTACT_COUNT {
                packet.contact_count = scalar(sample);
                continue;
            }
            if usage == SCAN_TIME {
                packet.scan_time = scalar(sample);
                continue;
            }
            let Some(finger) = ancestor(descriptor, sample.collection, &[FINGER, STYLUS]) else {
                continue;
            };
            let contact = packet
                .contacts
                .iter()
                .position(|contact| contact.collection == finger)
                .unwrap_or_else(|| {
                    packet.contacts.push(Contact {
                        collection: finger,
                        id: None,
                        tip: None,
                        in_range: None,
                        confidence: None,
                        x: None,
                        y: None,
                        pressure: None,
                        width: None,
                        height: None,
                    });
                    packet.contacts.len() - 1
                });
            let contact = &mut packet.contacts[contact];
            let value = scalar(sample);
            match usage {
                CONTACT_ID => contact.id = value,
                0x000d_0042 => contact.tip = value.map(|v| v != 0),
                0x000d_0032 => contact.in_range = value.map(|v| v != 0),
                0x000d_0047 => contact.confidence = value.map(|v| v != 0),
                X => contact.x = value,
                Y => contact.y = value,
                0x000d_0030 => contact.pressure = value,
                0x000d_0048 => contact.width = value,
                0x000d_0049 => contact.height = value,
                _ => {}
            }
        }
        let before = self.keyboard_usages();
        match self.keyboards.iter_mut().find(|(id, _)| *id == frame.id) {
            Some((_, held)) => *held = keyboard,
            None => self.keyboards.push((frame.id, keyboard)),
        }
        let after = self.keyboard_usages();
        for usage in 0xe0..=0xe7 {
            if before.contains(&usage) != after.contains(&usage) {
                events.push(Event::Keyboard {
                    usage,
                    pressed: after.contains(&usage),
                });
            }
        }
        for usage in before.iter().filter(|u| !(0xe0..=0xe7).contains(*u)) {
            if !after.contains(usage) {
                events.push(Event::Keyboard {
                    usage: *usage,
                    pressed: false,
                });
            }
        }
        for usage in after.iter().filter(|u| !(0xe0..=0xe7).contains(*u)) {
            if !before.contains(usage) {
                events.push(Event::Keyboard {
                    usage: *usage,
                    pressed: true,
                });
            }
        }
        let held = match self.consumer.iter_mut().find(|(id, _)| *id == frame.id) {
            Some((_, held)) => held,
            None => {
                self.consumer.push((frame.id, Vec::new()));
                &mut self.consumer.last_mut().unwrap().1
            }
        };
        for usage in held.iter().filter(|usage| !consumers.contains(usage)) {
            events.push(Event::Consumer {
                report: frame.id,
                usage: *usage,
                pressed: false,
            });
        }
        for usage in consumers.iter().filter(|usage| !held.contains(usage)) {
            events.push(Event::Consumer {
                report: frame.id,
                usage: *usage,
                pressed: true,
            });
        }
        *held = consumers;
        let previous = match self.gamepads.iter_mut().find(|(id, _)| *id == frame.id) {
            Some((_, held)) => held,
            None => {
                self.gamepads.push((frame.id, Vec::new()));
                &mut self.gamepads.last_mut().unwrap().1
            }
        };
        for control in &gamepads {
            if (control.relative && control.value != 0)
                || (!control.relative && !previous.contains(control))
            {
                events.push(Event::Gamepad(control.clone()));
            }
        }
        if !gamepads.is_empty() || !previous.is_empty() {
            events.push(Event::GamepadState {
                report: frame.id,
                controls: gamepads.clone(),
            });
        }
        *previous = gamepads;
        events.extend(touch.into_iter().map(Event::Touch));
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_report_ids_and_consumer_releases_are_independent() {
        let mut bytes = Vec::new();
        for id in 1..=2 {
            bytes.extend_from_slice(&[
                5, 0x0c, 9, 1, 0xa1, 1, 0x85, id, 0x19, 0, 0x2a, 0xff, 3, 0x15, 0, 0x26, 0xff, 3,
                0x75, 16, 0x95, 1, 0x81, 0, 0xc0,
            ]);
        }
        let descriptor = Descriptor::parse(&bytes).unwrap();
        let mut decoder = Decoder::default();
        for id in 1..=2 {
            assert_eq!(
                decoder.update(&descriptor, &descriptor.decode(&[id, 0xe9, 0]).unwrap()),
                [Event::Consumer {
                    report: id,
                    usage: 0xe9,
                    pressed: true
                }]
            );
        }
        assert!(
            decoder
                .update(&descriptor, &descriptor.decode(&[2, 0xe9, 0]).unwrap())
                .is_empty()
        );
        assert_eq!(
            decoder.update(&descriptor, &descriptor.decode(&[1, 0, 0]).unwrap()),
            [Event::Consumer {
                report: 1,
                usage: 0xe9,
                pressed: false
            }]
        );
    }

    #[test]
    fn gamepad_changes_and_relative_axes_follow_actual_reports() {
        let descriptor = Descriptor::parse(&[
            5, 1, 9, 5, 0xa1, 1, 9, 0x30, 0x15, 0x81, 0x25, 0x7f, 0x75, 8, 0x95, 1, 0x81, 2, 9,
            0x31, 0x81, 6, 0xc0,
        ])
        .unwrap();
        let mut decoder = Decoder::default();
        let frame = descriptor.decode(&[5, 2]).unwrap();
        assert_eq!(decoder.update(&descriptor, &frame).len(), 3);
        let events = decoder.update(&descriptor, &frame);
        assert_eq!(events.len(), 2);
        let Event::Gamepad(control) = &events[0] else {
            panic!("relative axis");
        };
        assert_eq!((control.usage, control.value), (Y, 2));
    }

    #[test]
    fn touch_packets_preserve_contacts_and_zero_count_without_fake_releases() {
        let descriptor = Descriptor::parse(&[
            5, 0x0d, 9, 4, 0xa1, 1, 9, 0x22, 0xa1, 2, 9, 0x51, 0x15, 0, 0x25, 127, 0x75, 8, 0x95,
            1, 0x81, 2, 9, 0x42, 0x25, 1, 0x81, 2, 5, 1, 9, 0x30, 9, 0x31, 0x26, 0xff, 0x7f, 0x75,
            16, 0x95, 2, 0x81, 2, 0xc0, 5, 0x0d, 9, 0x54, 0x25, 5, 0x75, 8, 0x95, 1, 0x81, 2, 0xc0,
        ])
        .unwrap();
        let mut decoder = Decoder::default();
        let frame = descriptor.decode(&[9, 1, 10, 0, 20, 0, 0]).unwrap();
        let Event::Touch(packet) = &decoder.update(&descriptor, &frame)[0] else {
            panic!("touch");
        };
        assert_eq!(packet.contact_count, Some(0));
        assert_eq!(packet.contacts[0].id, Some(9));
        assert_eq!(packet.contacts[0].tip, Some(true));
        assert_eq!(
            (packet.contacts[0].x, packet.contacts[0].y),
            (Some(10), Some(20))
        );
    }

    #[test]
    fn receiver_keyboard_ids_merge_held_usages_and_stop_retires_state() {
        let mut bytes = Vec::new();
        for id in 1..=2 {
            bytes.extend_from_slice(&[
                5, 1, 9, 6, 0xa1, 1, 0x85, id, 5, 7, 0x19, 0, 0x29, 0x65, 0x15, 0, 0x25, 0x65,
                0x75, 8, 0x95, 1, 0x81, 0, 0xc0,
            ]);
        }
        let descriptor = Descriptor::parse(&bytes).unwrap();
        let mut decoder = Decoder::default();
        assert_eq!(
            decoder.update(&descriptor, &descriptor.decode(&[1, 4]).unwrap()),
            [Event::Keyboard {
                usage: 4,
                pressed: true
            }]
        );
        assert!(
            decoder
                .update(&descriptor, &descriptor.decode(&[2, 4]).unwrap())
                .is_empty()
        );
        assert!(
            decoder
                .update(&descriptor, &descriptor.decode(&[1, 0]).unwrap())
                .is_empty()
        );
        assert_eq!(
            decoder.stop(),
            [
                Event::Keyboard {
                    usage: 4,
                    pressed: false
                },
                Event::Stopped
            ]
        );
    }
}
