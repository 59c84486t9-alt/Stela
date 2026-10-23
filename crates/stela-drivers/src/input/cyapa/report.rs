// SPDX-License-Identifier: GPL-2.0-only
//! Gen3 fixed contact records, hardware tracking IDs and button capabilities.
use super::{Capabilities, ErrorKind};
pub(super) const REPORT_BYTES: usize = 27;
const CONTACT_OFFSET: usize = 2;
const CONTACT_BYTES: usize = 5;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contact {
    pub id: u8,
    pub x: u16,
    pub y: u16,
    pub pressure: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub raw: [u8; REPORT_BYTES],
    /// Hardware IDs 1..=15 map to slots 0..14. Absent IDs are inactive.
    pub contacts: [Option<Contact>; 15],
    pub count: u8,
    pub raw_buttons: u8,
    pub buttons: u8,
}
pub(super) fn decode(raw: [u8; REPORT_BYTES], c: &Capabilities) -> Result<Frame, ErrorKind> {
    if raw[0] & 0x80 == 0 || raw[0] & 3 != 3 || raw[1] & 8 == 0 {
        return Err(ErrorKind::InvalidReportStatus([raw[0], raw[1]]));
    }
    let count = raw[1] >> 4;
    if count > 5 {
        return Err(ErrorKind::ContactCount(count));
    }
    let mut contacts = [None; 15];
    for index in 0..usize::from(count) {
        let offset = CONTACT_OFFSET + index * CONTACT_BYTES;
        let record = &raw[offset..offset + CONTACT_BYTES];
        let id = record[4];
        if !(1..=15).contains(&id) {
            return Err(ErrorKind::ContactId(id));
        }
        let slot = &mut contacts[usize::from(id - 1)];
        if slot.is_some() {
            return Err(ErrorKind::DuplicateId(id));
        }
        let x = (u16::from(record[0] & 0xf0) << 4) | u16::from(record[1]);
        let y = (u16::from(record[0] & 15) << 8) | u16::from(record[2]);
        if x > c.maximum.0 || y > c.maximum.1 {
            return Err(ErrorKind::Coordinate { id, x, y });
        }
        *slot = Some(Contact {
            id,
            x,
            y,
            pressure: record[3],
        });
    }
    Ok(Frame {
        raw_buttons: raw[1] & 7,
        buttons: (raw[1] & 7) & (c.button_capabilities >> 3),
        raw,
        contacts,
        count,
    })
}
