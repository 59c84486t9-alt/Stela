// SPDX-License-Identifier: GPL-2.0-only
//! Compressed ordinary/high-precision contacts and optional trackpoint reports.
use super::{Capabilities, ErrorKind};
pub(super) const STANDARD_REPORT_BYTES: usize = 34;
pub(super) const EXTENDED_REPORT_BYTES: usize = 39;
const WIDTH_MARKS_OFFSET: usize = 33;
const CONTACT_OFFSET: usize = 4;
const CONTACT_BYTES: usize = 5;
const HOVER_OFFSET: usize = 30;
const WIDTH_REDUCTION: u32 = 90;
/// Complete actual transfer. Packet ID, rather than length alone, selects
/// ordinary twelve-bit or high-precision sixteen-bit contact encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    Standard([u8; STANDARD_REPORT_BYTES]),
    Extended([u8; EXTENDED_REPORT_BYTES]),
}
impl Packet {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Standard(bytes) => bytes,
            Self::Extended(bytes) => bytes,
        }
    }
}
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
    pub raw: Packet,
    /// Hardware slots; only present slots consume five-byte wire records.
    pub contacts: [Option<Contact>; 5],
    /// Actual left/right/middle bits0..2, without logical mapping changes.
    pub buttons: u8,
    pub hover: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trackpoint {
    pub raw: Packet,
    pub buttons: u8,
    /// Some packets carry only buttons; their absent motion is explicit.
    pub motion: Option<(i16, i16)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Absolute(Absolute),
    Trackpoint(Trackpoint),
}
pub(super) fn decode(raw: Packet, c: &Capabilities) -> Result<Frame, ErrorKind> {
    let packet = raw.as_bytes();
    match packet[2] {
        id @ (0x5d | 0x60) => {
            let high_precision = id == 0x60;
            if high_precision && packet.len() != EXTENDED_REPORT_BYTES {
                return Err(ErrorKind::ReportId(id));
            }
            let mut contacts = [None; 5];
            let mut offset = CONTACT_OFFSET;
            for (slot, contact) in contacts.iter_mut().enumerate() {
                if packet[3] & (1 << (slot + 3)) == 0 {
                    continue;
                }
                let bytes = &packet[offset..offset + CONTACT_BYTES];
                offset += CONTACT_BYTES;
                let (x, y) = if high_precision {
                    (
                        u16::from_be_bytes([bytes[0], bytes[1]]),
                        u16::from_be_bytes([bytes[2], bytes[3]]),
                    )
                } else {
                    (
                        (u16::from(bytes[0] & 0xf0) << 4) | u16::from(bytes[1]),
                        (u16::from(bytes[0] & 15) << 8) | u16::from(bytes[2]),
                    )
                };
                if x > c.maximum.0 || y > c.maximum.1 {
                    return Err(ErrorKind::Coordinate {
                        slot: slot as u8,
                        x,
                        y,
                    });
                }
                let width = if high_precision {
                    packet[WIDTH_MARKS_OFFSET + slot]
                } else {
                    bytes[3]
                };
                let marks = (width & 15, width >> 4);
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
                buttons: packet[3] & 7,
                hover: packet[HOVER_OFFSET] & 64 != 0,
                contacts,
                raw,
            }))
        }
        0x5e | 0x5f => {
            let packet = &packet[3..];
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
        0 if packet[..2] == [0, 0] => Err(ErrorKind::UnexpectedReset),
        id => Err(ErrorKind::ReportId(id)),
    }
}
