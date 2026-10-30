// SPDX-License-Identifier: GPL-2.0-only
// Synaptics source copyrights and adaptation scope: ../synaptics.rs and
// input/THIRD_PARTY.md.
//! Secondary-contact/count records from the source advanced gesture mode.
//! Native sequence numbers preserve interleaving with ordinary touch records;
//! they are host ordering tokens, never device timestamps or scan identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Data {
    /// Source half-resolution fields expanded by two, without coordinate wrap
    /// or invented independent tracking IDs or per-contact width.
    Secondary {
        x: u16,
        y: u16,
        pressure: u8,
    },
    Count(u8),
    /// The source has no state effect for these types. Preserve the packet and
    /// explicit type rather than manufacturing a contact or silently dropping it.
    Unrecognized(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub raw: [u8; 6],
    pub native_sequence: u64,
    pub data: Data,
}
pub(super) fn decode(raw: [u8; 6], native_sequence: u64) -> Record {
    let kind = (raw[5] & 0x30) >> 4;
    let data = match kind {
        1 => Data::Secondary {
            x: ((u16::from(raw[4] & 15) << 8) | u16::from(raw[1])) << 1,
            y: ((u16::from(raw[4] & 0xf0) << 4) | u16::from(raw[2])) << 1,
            pressure: ((raw[3] & 0x30) | (raw[5] & 15)) << 1,
        },
        2 => Data::Count(raw[1]),
        _ => Data::Unrecognized(kind),
    };
    Record {
        raw,
        native_sequence,
        data,
    }
}
