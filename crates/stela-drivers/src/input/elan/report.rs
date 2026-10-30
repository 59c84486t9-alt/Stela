// SPDX-License-Identifier: GPL-2.0-only
//! Compressed ordinary/high-precision contacts and optional trackpoint reports.
use super::{Capabilities, ErrorKind};
use crate::bus::smbus::Block;
pub(super) const STANDARD_REPORT_BYTES: usize = 34;
pub(super) const EXTENDED_REPORT_BYTES: usize = 39;
const WIDTH_MARKS_OFFSET: usize = 31;
const CONTACT_OFFSET: usize = 2;
const CONTACT_BYTES: usize = 5;
const HOVER_OFFSET: usize = 28;
const WIDTH_REDUCTION: u32 = 90;
/// Complete transfer. Packet ID, rather than length alone, selects
/// ordinary twelve-bit or high-precision sixteen-bit contact encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    Standard([u8; STANDARD_REPORT_BYTES]),
    Extended([u8; EXTENDED_REPORT_BYTES]),
    /// Exact count-bearing SMBus payload, without an invented I2C prefix.
    Smbus(Block),
}
impl Packet {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Standard(bytes) => bytes,
            Self::Extended(bytes) => bytes,
            Self::Smbus(block) => block.as_slice(),
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
    /// Left/right/middle bits0..2, without logical mapping changes.
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
pub(super) struct Geometry {
    pub maximum: (u16, u16),
    pub traces: (u8, u8),
    pub pressure_adjustment: u8,
}
impl From<&Capabilities> for Geometry {
    fn from(c: &Capabilities) -> Self {
        Self {
            maximum: c.maximum,
            traces: c.traces,
            pressure_adjustment: c.pressure_adjustment,
        }
    }
}
pub(super) fn decode(raw: Packet, c: Geometry) -> Result<Frame, ErrorKind> {
    let (packet, reset) = match &raw {
        Packet::Smbus(block) => (block.as_slice(), false),
        _ => (&raw.as_bytes()[2..], raw.as_bytes()[..2] == [0, 0]),
    };
    match packet[0] {
        id @ (0x5d | 0x60) => {
            let high_precision = id == 0x60;
            if high_precision && packet.len() != EXTENDED_REPORT_BYTES - 2 {
                return Err(ErrorKind::ReportId(id));
            }
            let mut contacts = [None; 5];
            let mut offset = CONTACT_OFFSET;
            for (slot, contact) in contacts.iter_mut().enumerate() {
                if packet[1] & (1 << (slot + 3)) == 0 {
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
                buttons: packet[1] & 7,
                hover: packet[HOVER_OFFSET] & 64 != 0,
                contacts,
                raw,
            }))
        }
        0x5e | 0x5f => {
            let packet = &packet[1..];
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
        0 if reset => Err(ErrorKind::UnexpectedReset),
        id => Err(ErrorKind::ReportId(id)),
    }
}
