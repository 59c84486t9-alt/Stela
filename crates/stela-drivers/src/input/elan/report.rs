// SPDX-License-Identifier: GPL-2.0-only
//! Ordinary compressed contact arrays and optional trackpoint reports.
use super::{Capabilities, ErrorKind};
const CONTACT_OFFSET: usize = 4;
const CONTACT_BYTES: usize = 5;
const HOVER_OFFSET: usize = 30;
const WIDTH_REDUCTION: u32 = 90;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contact {
    pub x: u16,
    pub y: u16,
    pub y_top_down: u16,
    pub raw_pressure: u8,
    pub pressure: u8,
    pub width_marks: (u8, u8),
    pub areas: (u32, u32),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Absolute {
    pub raw: [u8; 34],
    /// Hardware slots; only present slots consume five-byte wire records.
    pub contacts: [Option<Contact>; 5],
    /// Actual left/right/middle bits0..2, without logical mapping changes.
    pub buttons: u8,
    pub hover: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trackpoint {
    pub raw: [u8; 34],
    pub buttons: u8,
    /// Some packets carry only buttons; their absent motion is explicit.
    pub motion: Option<(i16, i16)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Absolute(Absolute),
    Trackpoint(Trackpoint),
}
pub(super) fn decode(raw: [u8; 34], c: &Capabilities) -> Result<Frame, ErrorKind> {
    match raw[2] {
        0x5d => {
            let mut contacts = [None; 5];
            let mut offset = CONTACT_OFFSET;
            for (slot, contact) in contacts.iter_mut().enumerate() {
                if raw[3] & (1 << (slot + 3)) == 0 {
                    continue;
                }
                let bytes = &raw[offset..offset + CONTACT_BYTES];
                offset += CONTACT_BYTES;
                let x = (u16::from(bytes[0] & 0xf0) << 4) | u16::from(bytes[1]);
                let y = (u16::from(bytes[0] & 15) << 8) | u16::from(bytes[2]);
                if x > c.maximum.0 || y > c.maximum.1 {
                    return Err(ErrorKind::Coordinate {
                        slot: slot as u8,
                        x,
                        y,
                    });
                }
                let marks = (bytes[3] & 15, bytes[3] >> 4);
                let width_x =
                    u32::from(c.maximum.0 / u16::from(c.traces.0)).saturating_sub(WIDTH_REDUCTION);
                let width_y =
                    u32::from(c.maximum.1 / u16::from(c.traces.1)).saturating_sub(WIDTH_REDUCTION);
                *contact = Some(Contact {
                    x,
                    y,
                    y_top_down: c.maximum.1 - y,
                    raw_pressure: bytes[4],
                    pressure: bytes[4].saturating_add(c.pressure_adjustment),
                    width_marks: marks,
                    areas: (u32::from(marks.0) * width_x, u32::from(marks.1) * width_y),
                });
            }
            Ok(Frame::Absolute(Absolute {
                buttons: raw[3] & 7,
                hover: raw[HOVER_OFFSET] & 64 != 0,
                contacts,
                raw,
            }))
        }
        0x5e | 0x5f => {
            let packet = &raw[3..];
            let motion = if packet[3] & 15 == 6 {
                Some((
                    i16::from(packet[4]) - (i16::from(packet[1] ^ 0x80) << 1),
                    (i16::from(packet[2] ^ 0x80) << 1) - i16::from(packet[5]),
                ))
            } else {
                None
            };
            Ok(Frame::Trackpoint(Trackpoint {
                buttons: packet[0] & 7,
                motion,
                raw,
            }))
        }
        0 if raw[..2] == [0, 0] => Err(ErrorKind::UnexpectedReset),
        id => Err(ErrorKind::ReportId(id)),
    }
}
