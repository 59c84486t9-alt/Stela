// SPDX-License-Identifier: GPL-2.0-only
//! PIP touch/button/proximity/wake records and complete raw packets.
use super::{Capabilities, ErrorKind, Packet};
use alloc::boxed::Box;
const TOUCH_HEADER: usize = 7;
const TOUCH_RECORD: usize = 12;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContactType {
    Finger,
    Proximity,
    Hover,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    None,
    Touchdown,
    Displace,
    Liftoff,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contact {
    pub kind: ContactType,
    pub id: u8,
    pub event: Event,
    pub tip_liftoff: bool,
    pub raw_x: u16,
    pub raw_y: u16,
    pub x: u16,
    pub y: u16,
    /// Pressure for a finger, distance for a proximity record.
    pub z: u8,
    pub axes: (u8, u8),
    pub tool_axes: (u8, u8),
    pub orientation_raw: u8,
    pub orientation: i8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    Contact(Contact),
    /// The donor consumes only the tracking ID/event on liftoff. Other fields
    /// may be unavailable; keep bytes without inventing coordinates.
    Liftoff {
        id: u8,
        tip_liftoff: bool,
        raw: [u8; 12],
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Touches {
    pub count: u8,
    pub records: [Option<Record>; 10],
    /// Source event-code activity; the independently preserved tip flag is
    /// available to the platform frontend without inventing a reconciliation.
    pub active: [Option<Contact>; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Touches {
        raw: Packet,
        touches: Box<Touches>,
    },
    Buttons {
        raw: Packet,
        raw_buttons: u8,
        buttons: u8,
    },
    Proximity {
        raw: Packet,
        distance: u8,
    },
    Wake(Packet),
    /// Reset header observed during the completed startup/wake sequence.
    ResetNotice(Packet),
    /// A real control response drained before the next command. It never
    /// acknowledges a later command and is not routed as a touch report.
    StaleResponse(Packet),
}
pub(super) fn decode(raw: Packet, c: &Capabilities) -> Result<Frame, ErrorKind> {
    let bytes = raw.as_bytes();
    if bytes.len() == 2 && raw.declared_length() == 0 {
        return Ok(Frame::ResetNotice(raw));
    }
    let id = bytes[2];
    let bad_length = || ErrorKind::ReportLength {
        id,
        actual: bytes.len() as u16,
    };
    match id {
        1 => {
            if !(7..=127).contains(&bytes.len()) {
                return Err(bad_length());
            }
            let count = bytes[5] & 31;
            if count > 10 {
                return Err(ErrorKind::ContactCount(count));
            }
            if bytes.len() < TOUCH_HEADER + usize::from(count) * TOUCH_RECORD {
                return Err(bad_length());
            }
            let mut records = [None; 10];
            let mut active = [None; 32];
            let mut seen = 0u32;
            for (index, record) in records.iter_mut().enumerate().take(usize::from(count)) {
                let offset = TOUCH_HEADER + index * TOUCH_RECORD;
                let data = &bytes[offset..offset + TOUCH_RECORD];
                let id = data[1] & 31;
                if seen & (1 << id) != 0 {
                    return Err(ErrorKind::DuplicateId(id));
                }
                seen |= 1 << id;
                let event = match (data[1] >> 5) & 3 {
                    0 => Event::None,
                    1 => Event::Touchdown,
                    2 => Event::Displace,
                    _ => Event::Liftoff,
                };
                if event == Event::Liftoff {
                    let mut wire = [0; 12];
                    wire.copy_from_slice(data);
                    *record = Some(Record::Liftoff {
                        id,
                        tip_liftoff: data[1] & 0x80 != 0,
                        raw: wire,
                    });
                    continue;
                }
                let kind = match data[0] & 7 {
                    0 => ContactType::Finger,
                    1 => ContactType::Proximity,
                    2 => ContactType::Hover,
                    value => return Err(ErrorKind::ContactType(value)),
                };
                let raw_x = u16::from_le_bytes([data[2], data[3]]);
                let raw_y = u16::from_le_bytes([data[4], data[5]]);
                if raw_x > c.maximum.0 || raw_y > c.maximum.1 {
                    return Err(ErrorKind::Coordinate {
                        id,
                        x: raw_x,
                        y: raw_y,
                    });
                }
                // The donor record comment declares signed -127..=127, but
                // its u8 callback loses the sign. Preserve both wire and value.
                if data[11] == 0x80 {
                    return Err(ErrorKind::Orientation(data[11]));
                }
                let contact = Contact {
                    kind,
                    id,
                    event,
                    tip_liftoff: data[1] & 0x80 != 0,
                    raw_x,
                    raw_y,
                    x: if c.origins.0 {
                        c.maximum.0 - raw_x
                    } else {
                        raw_x
                    },
                    y: if c.origins.1 {
                        c.maximum.1 - raw_y
                    } else {
                        raw_y
                    },
                    z: data[6],
                    axes: (data[7], data[8]),
                    tool_axes: (data[9], data[10]),
                    orientation_raw: data[11],
                    orientation: data[11] as i8,
                };
                *record = Some(Record::Contact(contact));
                active[usize::from(id)] = Some(contact);
            }
            Ok(Frame::Touches {
                raw,
                touches: Box::new(Touches {
                    count,
                    records,
                    active,
                }),
            })
        }
        3 | 5 | 6 => {
            if !(6..=14).contains(&bytes.len()) {
                return Err(bad_length());
            }
            let raw_buttons = bytes[5] & 15;
            let buttons = raw_buttons & (c.button_capabilities >> 3);
            Ok(Frame::Buttons {
                raw,
                raw_buttons,
                buttons,
            })
        }
        7 => {
            if bytes.len() != 6 {
                return Err(bad_length());
            }
            let distance = bytes[5] & 1;
            Ok(Frame::Proximity { raw, distance })
        }
        4 => {
            if bytes.len() != 4 {
                return Err(bad_length());
            }
            Ok(Frame::Wake(raw))
        }
        0x1f | 0x30 | 0xf0 | 0xf7 | 0xff => Ok(Frame::StaleResponse(raw)),
        id => Err(ErrorKind::UnsupportedReport(id)),
    }
}
