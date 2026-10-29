// SPDX-License-Identifier: GPL-2.0-or-later
// Linux HID reference: Copyright (c) 1999 Andreas Gal;
// 2000-2005 Vojtech Pavlik; 2005 Michael Haboustak for Concept2, Inc;
// 2006-2012 Jiri Kosina; 2007-2008 Oliver Neukum.
// Source identities and adaptation scope: ../THIRD_PARTY.md.
//! Descriptor-checked HID reports, including consumer, gamepad and digitizer
//! collections. Values keep their wire field and collection identity: contact
//! IDs, tip/in-range/confidence, scan time and contact count are never guessed.
use super::{
    error::{ParseError, ParseErrorKind, Reader},
    usages::Local,
};
use alloc::vec::Vec;

const MAX_BITS: usize = (16_384 - 1) * 8;
const MAX_USAGES: usize = 12_288;
const MAX_COLLECTIONS: usize = 128;
const MAX_FIELDS: usize = 12_288;
const CONSTANT: u32 = 1;
const VARIABLE: u32 = 2;
const RELATIVE: u32 = 4;
const NULL_STATE: u32 = 0x40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReportType {
    Input = 1,
    Output = 2,
    Feature = 3,
}

/// One Collection main item, with its index in `Descriptor::collections`
/// providing a stable identity even for repeated Finger collections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub parent: Option<usize>,
    pub usage: u32,
    pub kind: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportField {
    pub offset: usize,
    pub size: usize,
    pub count: usize,
    pub flags: u32,
    pub minimum: i64,
    pub maximum: i64,
    pub physical_minimum: i64,
    pub physical_maximum: i64,
    pub unit: u32,
    pub unit_exponent: i8,
    pub collection: Option<usize>,
    /// Ordered primary Usage list (common and first delimiter branch).
    /// Arrays index this list from logical min;
    /// variables repeat its final usage when Report Count is greater.
    pub usages: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportLayout {
    pub kind: ReportType,
    /// Zero denotes an unnumbered report; zero is never a wire prefix.
    pub id: u8,
    pub bits: usize,
    pub fields: Vec<ReportField>,
}
impl ReportLayout {
    pub fn wire_bytes(&self) -> usize {
        self.bits.div_ceil(8) + usize::from(self.id != 0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub collections: Vec<Collection>,
    pub reports: Vec<ReportLayout>,
    numbered: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Scalar(i64),
    /// Values wider than 32 bits remain complete little-endian bit strings.
    Bits(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    pub field: usize,
    pub element: usize,
    pub collection: Option<usize>,
    /// Arrays with an out-of-range/null index have no selected usage.
    pub usage: Option<u32>,
    pub value: Value,
    pub relative: bool,
    pub null: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub id: u8,
    pub samples: Vec<Sample>,
    /// Exact received bytes, including the ID prefix when numbered.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    MissingId,
    UnknownId(u8),
    Length { expected: usize, actual: usize },
    KeyboardError(u32),
}

#[derive(Clone, Default)]
struct Global {
    page: u32,
    minimum: i64,
    maximum: i64,
    physical_minimum: i64,
    physical_maximum: i64,
    unit: u32,
    unit_exponent: i8,
    size: usize,
    count: usize,
    id: u8,
}

impl Descriptor {
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut descriptor = Self {
            collections: Vec::new(),
            reports: Vec::new(),
            numbered: false,
        };
        let mut global = Global::default();
        let mut globals = Vec::new();
        let mut collections = Vec::new();
        let mut local = Local::default();
        let mut fields = 0usize;
        let mut at = 0;
        while at < bytes.len() {
            let item_offset = at;
            let prefix = bytes[at];
            if prefix == 0xfe {
                return Err(ParseError::at(
                    Reader::Descriptor,
                    item_offset,
                    ParseErrorKind::LongItem,
                ));
            }
            let size = match prefix & 3 {
                3 => 4,
                size => usize::from(size),
            };
            let data = bytes.get(at + 1..at + 1 + size).ok_or(ParseError::at(
                Reader::Descriptor,
                item_offset,
                ParseErrorKind::TruncatedItem {
                    needed: size,
                    available: bytes.len() - at - 1,
                },
            ))?;
            at += 1 + size;
            let unsigned = data
                .iter()
                .enumerate()
                .fold(0u32, |v, (i, b)| v | u32::from(*b) << (i * 8));
            let signed = match size {
                1 => i64::from(data[0] as i8),
                2 => i64::from(i16::from_le_bytes([data[0], data[1]])),
                4 => i64::from(unsigned as i32),
                _ => 0,
            };
            let tag = prefix & 0xfc;
            let usages = if matches!(tag, 0x80 | 0x90 | 0xa0 | 0xb0 | 0xc0) {
                local.main(tag, unsigned, global.page).map_err(|error| {
                    ParseError::at(
                        Reader::Descriptor,
                        item_offset,
                        ParseErrorKind::Usage(error),
                    )
                })?
            } else {
                Vec::new()
            };
            match prefix & 0xfc {
                0x04 => {
                    if unsigned > 0xffff {
                        return Err(ParseError::at(
                            Reader::Descriptor,
                            item_offset,
                            ParseErrorKind::UsagePage { value: unsigned },
                        ));
                    }
                    global.page = unsigned;
                }
                0x14 => global.minimum = signed,
                0x24 => {
                    global.maximum = if global.minimum < 0 {
                        signed
                    } else {
                        i64::from(unsigned)
                    }
                }
                0x34 => global.physical_minimum = signed,
                0x44 => {
                    global.physical_maximum = if global.physical_minimum < 0 {
                        signed
                    } else {
                        i64::from(unsigned)
                    }
                }
                0x54 => {
                    // HID encodes a signed nibble, including one-byte 0x0e = -2.
                    let nibble = (unsigned & 15) as i8;
                    global.unit_exponent = if nibble & 8 != 0 { nibble - 16 } else { nibble };
                }
                0x64 => global.unit = unsigned,
                0x74 => {
                    if unsigned > 256 {
                        return Err(ParseError::at(
                            Reader::Descriptor,
                            item_offset,
                            ParseErrorKind::ReportSize { bits: unsigned },
                        ));
                    }
                    global.size = unsigned as usize;
                }
                0x84 => {
                    global.id =
                        u8::try_from(unsigned)
                            .ok()
                            .filter(|id| *id != 0)
                            .ok_or(ParseError::at(
                                Reader::Descriptor,
                                item_offset,
                                ParseErrorKind::ReportId { value: unsigned },
                            ))?;
                    descriptor.numbered = true;
                }
                0x94 => {
                    if unsigned as usize > MAX_USAGES {
                        return Err(ParseError::at(
                            Reader::Descriptor,
                            item_offset,
                            ParseErrorKind::ReportCount { count: unsigned },
                        ));
                    }
                    global.count = unsigned as usize;
                }
                0xa4 => {
                    if globals.len() == 4 {
                        return Err(ParseError::at(
                            Reader::Descriptor,
                            item_offset,
                            ParseErrorKind::GlobalStackOverflow { limit: 4 },
                        ));
                    }
                    globals.push(global.clone());
                }
                0xb4 => {
                    global = globals.pop().ok_or(ParseError::at(
                        Reader::Descriptor,
                        item_offset,
                        ParseErrorKind::GlobalStackUnderflow,
                    ))?
                }
                0x08 => local.usage(unsigned, size, global.page).map_err(|error| {
                    ParseError::at(
                        Reader::Descriptor,
                        item_offset,
                        ParseErrorKind::Usage(error),
                    )
                })?,
                0x18 => local
                    .minimum(unsigned, size, global.page)
                    .map_err(|error| {
                        ParseError::at(
                            Reader::Descriptor,
                            item_offset,
                            ParseErrorKind::Usage(error),
                        )
                    })?,
                0x28 => local
                    .maximum(unsigned, size, global.page)
                    .map_err(|error| {
                        ParseError::at(
                            Reader::Descriptor,
                            item_offset,
                            ParseErrorKind::Usage(error),
                        )
                    })?,
                0xa0 => {
                    if descriptor.collections.len() == MAX_COLLECTIONS {
                        return Err(ParseError::at(
                            Reader::Descriptor,
                            item_offset,
                            ParseErrorKind::CollectionLimit {
                                limit: MAX_COLLECTIONS,
                            },
                        ));
                    }
                    let index = descriptor.collections.len();
                    descriptor.collections.push(Collection {
                        parent: collections.last().copied(),
                        usage: usages.first().copied().unwrap_or(0),
                        kind: u8::try_from(unsigned).map_err(|_| {
                            ParseError::at(
                                Reader::Descriptor,
                                item_offset,
                                ParseErrorKind::CollectionType { value: unsigned },
                            )
                        })?,
                    });
                    collections.push(index);
                }
                0xc0 => {
                    collections.pop().ok_or(ParseError::at(
                        Reader::Descriptor,
                        item_offset,
                        ParseErrorKind::CollectionUnderflow,
                    ))?;
                }
                tag @ (0x80 | 0x90 | 0xb0) => {
                    if global.count != 0 && global.size == 0 {
                        return Err(ParseError::at(
                            Reader::Descriptor,
                            item_offset,
                            ParseErrorKind::ZeroSizeField {
                                count: global.count,
                            },
                        ));
                    }
                    if global.minimum > global.maximum {
                        return Err(ParseError::at(
                            Reader::Descriptor,
                            item_offset,
                            ParseErrorKind::LogicalRange {
                                minimum: global.minimum,
                                maximum: global.maximum,
                            },
                        ));
                    }
                    let kind = match tag {
                        0x80 => ReportType::Input,
                        0x90 => ReportType::Output,
                        _ => ReportType::Feature,
                    };
                    let index = descriptor
                        .reports
                        .iter()
                        .position(|r| r.kind == kind && r.id == global.id)
                        .unwrap_or_else(|| {
                            descriptor.reports.push(ReportLayout {
                                kind,
                                id: global.id,
                                bits: 0,
                                fields: Vec::new(),
                            });
                            descriptor.reports.len() - 1
                        });
                    let layout = &mut descriptor.reports[index];
                    let offset = layout.bits;
                    layout.bits = layout
                        .bits
                        .checked_add(global.size * global.count)
                        .filter(|b| *b <= MAX_BITS)
                        .ok_or(ParseError::at(
                            Reader::Descriptor,
                            item_offset,
                            ParseErrorKind::ReportBits {
                                existing: offset,
                                size: global.size,
                                count: global.count,
                                limit: MAX_BITS,
                            },
                        ))?;
                    if unsigned & CONSTANT == 0 && global.count != 0 {
                        fields = fields
                            .checked_add(global.count)
                            .filter(|n| *n <= MAX_FIELDS)
                            .ok_or(ParseError::at(
                                Reader::Descriptor,
                                item_offset,
                                ParseErrorKind::FieldCount {
                                    existing: fields,
                                    added: global.count,
                                    limit: MAX_FIELDS,
                                },
                            ))?;
                        layout.fields.push(ReportField {
                            offset,
                            size: global.size,
                            count: global.count,
                            flags: unsigned,
                            minimum: global.minimum,
                            maximum: global.maximum,
                            physical_minimum: global.physical_minimum,
                            physical_maximum: global.physical_maximum,
                            unit: global.unit,
                            unit_exponent: global.unit_exponent,
                            collection: collections.last().copied(),
                            usages,
                        });
                    }
                }
                0xa8 => local.delimiter(unsigned, size).map_err(|error| {
                    ParseError::at(
                        Reader::Descriptor,
                        item_offset,
                        ParseErrorKind::Usage(error),
                    )
                })?,
                // Designators and string indices carry no field semantics.
                0x38 | 0x48 | 0x58 | 0x78 | 0x88 | 0x98 => {}
                _ => {
                    return Err(ParseError::at(
                        Reader::Descriptor,
                        item_offset,
                        ParseErrorKind::ReservedItem { prefix },
                    ));
                }
            }
        }
        local.complete().map_err(|error| {
            ParseError::at(
                Reader::Descriptor,
                bytes.len(),
                ParseErrorKind::Usage(error),
            )
        })?;
        if !collections.is_empty() {
            return Err(ParseError::at(
                Reader::Descriptor,
                bytes.len(),
                ParseErrorKind::UnfinishedCollections {
                    depth: collections.len(),
                },
            ));
        }
        if descriptor.numbered && descriptor.reports.iter().any(|r| r.id == 0 && r.bits != 0) {
            return Err(ParseError::at(
                Reader::Descriptor,
                bytes.len(),
                ParseErrorKind::MixedReportIds,
            ));
        }
        Ok(descriptor)
    }

    pub fn layout(&self, kind: ReportType, id: u8) -> Option<&ReportLayout> {
        self.reports.iter().find(|r| r.kind == kind && r.id == id)
    }

    pub fn input_bytes(&self) -> usize {
        self.reports
            .iter()
            .filter(|r| r.kind == ReportType::Input)
            .map(ReportLayout::wire_bytes)
            .max()
            .unwrap_or(0)
    }

    /// Decode one complete interrupt input. A short/overlong/unknown report is
    /// diagnostic evidence, never an invented release or contact update.
    pub fn decode(&self, bytes: &[u8]) -> Result<Frame, DecodeError> {
        let (id, body) = if self.numbered {
            let (&id, body) = bytes.split_first().ok_or(DecodeError::MissingId)?;
            (id, body)
        } else {
            (0, bytes)
        };
        let layout = self
            .layout(ReportType::Input, id)
            .ok_or(DecodeError::UnknownId(id))?;
        if bytes.len() != layout.wire_bytes() {
            return Err(DecodeError::Length {
                expected: layout.wire_bytes(),
                actual: bytes.len(),
            });
        }
        let mut samples = Vec::new();
        for (index, field) in layout.fields.iter().enumerate() {
            for element in 0..field.count {
                let offset = field.offset + element * field.size;
                let mut raw = alloc::vec![0u8; field.size.div_ceil(8)];
                for bit in 0..field.size {
                    raw[bit / 8] |=
                        ((body[(offset + bit) / 8] >> ((offset + bit) % 8)) & 1) << (bit % 8);
                }
                let scalar = if field.size <= 32 {
                    let unsigned = raw
                        .iter()
                        .enumerate()
                        .fold(0i64, |v, (i, b)| v | i64::from(*b) << (i * 8));
                    Some(
                        if field.minimum < 0 && unsigned & (1i64 << (field.size - 1)) != 0 {
                            unsigned - (1i64 << field.size)
                        } else {
                            unsigned
                        },
                    )
                } else {
                    None
                };
                let variable = field.flags & VARIABLE != 0;
                let usage = if variable {
                    field.usages.get(element).or(field.usages.last()).copied()
                } else {
                    scalar
                        .filter(|v| (field.minimum..=field.maximum).contains(v))
                        .and_then(|v| usize::try_from(v - field.minimum).ok())
                        .and_then(|i| field.usages.get(i).copied())
                };
                if !variable && usage.is_some_and(|u| (0x0007_0001..=0x0007_0003).contains(&u)) {
                    return Err(DecodeError::KeyboardError(usage.unwrap()));
                }
                samples.push(Sample {
                    field: index,
                    element,
                    collection: field.collection,
                    usage,
                    value: scalar.map_or_else(|| Value::Bits(raw), Value::Scalar),
                    relative: field.flags & RELATIVE != 0,
                    null: field.flags & NULL_STATE != 0
                        && scalar.is_some_and(|v| !(field.minimum..=field.maximum).contains(&v)),
                });
            }
        }
        Ok(Frame {
            id,
            samples,
            bytes: bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumer_arrays_use_the_actual_discontiguous_usage_list() {
        let descriptor = Descriptor::parse(&[
            0x05, 0x0c, 0x09, 0x01, 0xa1, 1, 0x85, 3, 0x09, 0xe9, 0x09, 0xea, 0x0a, 0x23, 0x02,
            0x15, 1, 0x25, 3, 0x75, 8, 0x95, 1, 0x81, 0, 0xc0,
        ])
        .unwrap();
        let frame = descriptor.decode(&[3, 3]).unwrap();
        assert_eq!(frame.samples[0].usage, Some(0x000c_0223));
        assert_eq!(
            descriptor.decode(&[3]),
            Err(DecodeError::Length {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(descriptor.decode(&[9, 1]), Err(DecodeError::UnknownId(9)));
    }

    #[test]
    fn gamepad_axes_hat_extra_buttons_and_output_have_separate_offsets() {
        let descriptor = Descriptor::parse(&[
            5, 1, 9, 5, 0xa1, 1, 0x85, 2, 9, 0x30, 9, 0x31, 0x15, 0x81, 0x25, 0x7f, 0x75, 8, 0x95,
            2, 0x81, 2, 9, 0x39, 0x15, 0, 0x25, 7, 0x75, 4, 0x95, 1, 0x81, 0x42, 5, 9, 0x19, 1,
            0x29, 12, 0x25, 1, 0x75, 1, 0x95, 12, 0x81, 2, 5, 8, 0x19, 1, 0x29, 5, 0x75, 1, 0x95,
            5, 0x91, 2, 0x75, 3, 0x95, 1, 0x91, 1, 0xc0,
        ])
        .unwrap();
        assert_eq!(
            descriptor
                .layout(ReportType::Output, 2)
                .unwrap()
                .wire_bytes(),
            2
        );
        let frame = descriptor.decode(&[2, 0xff, 0x7f, 0x0f, 0x80]).unwrap();
        assert_eq!(frame.samples[0].value, Value::Scalar(-1));
        assert!(frame.samples[2].null);
        assert_eq!(frame.samples.last().unwrap().usage, Some(0x0009_000c));
        assert_eq!(frame.samples.last().unwrap().value, Value::Scalar(1));
    }

    #[test]
    fn repeated_finger_collections_retain_contact_identity_and_units() {
        let mut bytes = alloc::vec![5, 0x0d, 9, 4, 0xa1, 1, 0x85, 7];
        for _ in 0..2 {
            bytes.extend_from_slice(&[
                9, 0x22, 0xa1, 2, 9, 0x51, 0x15, 0, 0x25, 0x7f, 0x75, 8, 0x95, 1, 0x81, 2, 9, 0x42,
                0x25, 1, 0x75, 1, 0x81, 2, 0x75, 7, 0x81, 1, 5, 1, 9, 0x30, 9, 0x31, 0x26, 0xff,
                0x7f, 0x75, 16, 0x95, 2, 0x55, 0x0e, 0x65, 0x11, 0x81, 2, 0xc0, 5, 0x0d,
            ]);
        }
        bytes.extend_from_slice(&[9, 0x54, 0x25, 2, 0x75, 8, 0x95, 1, 0x81, 2, 0xc0]);
        let descriptor = Descriptor::parse(&bytes).unwrap();
        let frame = descriptor
            .decode(&[7, 8, 1, 10, 0, 20, 0, 9, 0, 30, 0, 40, 0, 1])
            .unwrap();
        assert_eq!(frame.samples[0].collection, Some(1));
        assert_eq!(frame.samples[4].collection, Some(2));
        assert_eq!(frame.samples[0].usage, Some(0x000d_0051));
        assert_eq!(frame.samples[4].value, Value::Scalar(9));
        assert_eq!(descriptor.reports[0].fields[2].unit_exponent, -2);
        assert_eq!(descriptor.collections[2].parent, Some(0));
    }

    #[test]
    fn unsupported_or_ambiguous_descriptors_are_explicit() {
        for bytes in [
            &[0x05][..],
            &[0xc0],
            &[0xa8, 1],
            &[0x19, 9, 0x29, 1],
            &[0x85, 0],
            &[0xa1, 1],
            &[0xfe, 0, 0],
            &[0x75, 8, 0x95, 1, 0x81, 1, 0x85, 2, 0x81, 1],
        ] {
            assert!(Descriptor::parse(bytes).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn unsigned_32_bit_and_wide_fields_preserve_every_bit() {
        let descriptor = Descriptor::parse(&[
            0x06, 0, 0xff, 9, 1, 0x15, 0, 0x27, 0xff, 0xff, 0xff, 0xff, 0x75, 32, 0x95, 1, 0x81, 2,
            9, 2, 0x75, 40, 0x81, 2,
        ])
        .unwrap();
        let frame = descriptor
            .decode(&[0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4, 5])
            .unwrap();
        assert_eq!(frame.samples[0].value, Value::Scalar(4_294_967_295));
        assert_eq!(
            frame.samples[1].value,
            Value::Bits(alloc::vec![1, 2, 3, 4, 5])
        );
    }
}
