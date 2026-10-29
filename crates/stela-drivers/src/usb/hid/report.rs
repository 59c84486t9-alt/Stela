// SPDX-License-Identifier: GPL-2.0-or-later
// Linux HID reference: Copyright (c) 1999 Andreas Gal;
// 2000-2005 Vojtech Pavlik; 2005 Michael Haboustak for Concept2, Inc;
// 2006-2012 Jiri Kosina; 2007-2008 Oliver Neukum.
// Source identities and adaptation scope: ../THIRD_PARTY.md.
//! HID report descriptors (HID 1.11 6.2.2) as the input fields they
//! describe, and the pointer and keyboard reports read from those fields.
//!
//! Each Input main item lays out Report Count fields of Report Size bits,
//! at offsets counted per report ID. A variable item's fields each carry
//! one usage (6.2.2.4, Usage or a Usage Minimum..Maximum range); an array
//! item's fields each hold an index into its ordered usage list (6.2.2.5), where a
//! value outside the logical range names no usage. Constant items pad.
//! Output and Feature items have offsets of their own and are not read.
//! Long items are refused. Push and Pop keep a four-deep global stack, and
//! sizes, counts and report lengths are bounded as Linux `hid-core.c` bounds
//! them (`hid_parser_global`, `hid_add_field`).
//!
//! A pointer is the first report with Generic Desktop X and Y, its Button
//! 1-3 and wheel when present. A keyboard is the first report with
//! Keyboard/Keypad page (07h) fields: modifier and key bitmaps (variable
//! items) and key arrays. As Linux `hid_input_array_field`, an array item
//! holding ErrorRollOver (usage 01h) is ignored and keeps its previous keys
//! while the report's bitmaps still apply; POSTFail and ErrorUndefined
//! (02h-03h, HID Usage Tables 10) are not keys.
use super::{
    error::{ParseError, ParseErrorKind, Reader},
    usages::Local,
};
use alloc::{sync::Arc, vec::Vec};

#[cfg(test)]
mod sparse_tests;

const GENERIC_DESKTOP_X: u32 = 0x0001_0030;
const GENERIC_DESKTOP_Y: u32 = 0x0001_0031;
const GENERIC_DESKTOP_WHEEL: u32 = 0x0001_0038;
/// Consumer AC Pan, which `hidinput_configure_usage` maps to REL_HWHEEL.
const CONSUMER_AC_PAN: u32 = 0x000c_0238;
const BUTTON_1: u32 = 0x0009_0001;
const BUTTON_5: u32 = 0x0009_0005;
const KEYBOARD_PAGE: u32 = 0x07;
const ERROR_ROLL_OVER: u32 = 0x01;
/// Array values that are no key: none, ErrorRollOver, POSTFail, ErrorUndefined.
const NOT_KEYS: core::ops::RangeInclusive<u32> = 0x00..=0x03;

/// A long item's prefix (6.2.2.3).
const LONG_ITEM: u8 = 0xfe;
/// A short item prefix's size field (6.2.2.2), and its code for four bytes.
const SIZE_MASK: u8 = 0x03;
const SIZE_FOUR: u8 = 3;
/// A short item prefix's tag and type (6.2.2.4-6.2.2.8).
const TAG_MASK: u8 = 0xfc;
const INPUT: u8 = 0x80;
const OUTPUT: u8 = 0x90;
const COLLECTION: u8 = 0xa0;
const FEATURE: u8 = 0xb0;
const END_COLLECTION: u8 = 0xc0;
const USAGE_PAGE: u8 = 0x04;
const LOGICAL_MINIMUM: u8 = 0x14;
const LOGICAL_MAXIMUM: u8 = 0x24;
const PHYSICAL_MINIMUM: u8 = 0x34;
const PHYSICAL_MAXIMUM: u8 = 0x44;
const UNIT_EXPONENT: u8 = 0x54;
const UNIT: u8 = 0x64;
const REPORT_SIZE: u8 = 0x74;
const REPORT_ID: u8 = 0x84;
const REPORT_COUNT: u8 = 0x94;
const PUSH: u8 = 0xa4;
const POP: u8 = 0xb4;
const USAGE: u8 = 0x08;
const USAGE_MINIMUM: u8 = 0x18;
const USAGE_MAXIMUM: u8 = 0x28;
/// Linux `HID_GLOBAL_STACK_SIZE`, the largest Report Size and Report Count
/// (`HID_MAX_USAGES`) it takes, and `HID_MAX_BUFFER_SIZE` in bits.
const GLOBAL_STACK: usize = 4;
const MAX_REPORT_SIZE: u32 = 256;
const MAX_REPORT_COUNT: u32 = 12_288;
const MAX_REPORT_BITS: usize = (16_384 - 1) * 8;
/// Input item flags (6.2.2.5).
const CONSTANT: u32 = 1 << 0;
const VARIABLE: u32 = 1 << 1;
const RELATIVE: u32 = 1 << 2;

/// One field of a report: where it is and how to read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    /// Bit offset in the report, after any report ID byte.
    pub offset: usize,
    pub size: usize,
    pub minimum: i32,
    pub maximum: i32,
    pub relative: bool,
}

impl Field {
    pub fn read(&self, report: &[u8]) -> Option<i32> {
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

/// What one input field reports: a usage of its own, or an index into
/// the Main item's exact ordered usage table.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Usage {
    Variable(u32),
    Array(Array),
}

/// Selector bounds stay private and wide; public pointer Field keeps its API.
/// Every field of one Array Main item shares one immutable checked table.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Array {
    usages: Arc<[u32]>,
    has_keyboard: bool,
    minimum: i64,
    maximum: i64,
}
impl Array {
    fn select(&self, raw: i32, size: usize) -> Option<u32> {
        let value = if self.minimum >= 0 && size == 32 {
            i64::from(raw as u32)
        } else {
            i64::from(raw)
        };
        if !(self.minimum..=self.maximum).contains(&value) {
            return None;
        }
        let index = usize::try_from(value.checked_sub(self.minimum)?).ok()?;
        self.usages.get(index).copied()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Item {
    report: Option<u8>,
    field: Field,
    usage: Usage,
    application: u32,
}

/// A pointer report's layout.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pointer {
    pub report: Option<u8>,
    pub x: Option<Field>,
    pub y: Option<Field>,
    pub wheel: Option<Field>,
    pub pan: Option<Field>,
    pub buttons: [Option<Field>; 5],
}

impl Pointer {
    /// The boot mouse report (Appendix B.2): buttons, then X and Y.
    pub fn boot() -> Self {
        let field = |offset, size, minimum: i32, relative| {
            Some(Field {
                offset,
                size,
                minimum,
                maximum: if minimum < 0 { 127 } else { 1 },
                relative,
            })
        };
        Self {
            report: None,
            x: field(8, 8, -127, true),
            y: field(16, 8, -127, true),
            wheel: None,
            pan: None,
            buttons: [
                field(0, 1, 0, false),
                field(1, 1, 0, false),
                field(2, 1, 0, false),
                None,
                None,
            ],
        }
    }
}

/// A keyboard report's layout: Keyboard/Keypad page bitmaps and arrays.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Keys {
    pub report: Option<u8>,
    /// Bitmap fields and the usage each one reports.
    variables: Vec<(Field, u32)>,
    /// Array fields and shared exact checked usage tables.
    arrays: Vec<(Field, Array)>,
}

impl Keys {
    /// The boot keyboard report (Appendix B.1): eight modifier bits, a
    /// reserved byte and six key bytes over usages 00h-FFh.
    pub fn boot() -> Self {
        let field = |offset, size, maximum| Field {
            offset,
            size,
            minimum: 0,
            maximum,
            relative: false,
        };
        let usages: Arc<[u32]> = (0..=0xff)
            .map(|usage| KEYBOARD_PAGE << 16 | usage)
            .collect::<Vec<_>>()
            .into();
        Self {
            report: None,
            variables: (0..8)
                .map(|bit| (field(bit, 1, 1), 0xe0 + bit as u32))
                .collect(),
            arrays: (0..6)
                .map(|n| {
                    (
                        field(16 + 8 * n, 8, 0xff),
                        Array {
                            usages: Arc::clone(&usages),
                            has_keyboard: true,
                            minimum: 0,
                            maximum: 0xff,
                        },
                    )
                })
                .collect(),
        }
    }

    /// The Keyboard/Keypad usages `body` reports held, or `None` for a
    /// report too short to read. `before` is what the previous report held.
    pub fn pressed_after(&self, body: &[u8], before: &[u32]) -> Option<Vec<u32>> {
        let mut held = Vec::new();
        for (field, usage) in &self.variables {
            if field.read(body)? != 0 {
                held.push(*usage);
            }
        }
        // The slots of one array main item share its usage table.
        for item in self
            .arrays
            .chunk_by(|(_, a), (_, b)| Arc::ptr_eq(&a.usages, &b.usages))
        {
            let mut keys = Vec::new();
            let mut rolled_over = false;
            for (field, array) in item {
                let raw = field.read(body)?;
                let Some(qualified) = array.select(raw, field.size) else {
                    continue;
                };
                if qualified >> 16 != KEYBOARD_PAGE {
                    continue;
                }
                let usage = qualified & 0xffff;
                rolled_over |= usage == ERROR_ROLL_OVER;
                if !NOT_KEYS.contains(&usage) && !keys.contains(&usage) {
                    keys.push(usage);
                }
            }
            if rolled_over {
                let table = &item[0].1.usages;
                keys = before
                    .iter()
                    .copied()
                    .filter(|usage| {
                        table.contains(&(KEYBOARD_PAGE << 16 | usage))
                            && !self.variables.iter().any(|(_, v)| v == usage)
                    })
                    .collect();
            }
            for usage in keys {
                if !held.contains(&usage) {
                    held.push(usage);
                }
            }
        }
        Some(held)
    }
    /// `pressed_after` from an empty previous report.
    #[cfg(test)]
    pub fn pressed(&self, body: &[u8]) -> Option<Vec<u32>> {
        self.pressed_after(body, &[])
    }
}

/// The pointer and keyboard reports a descriptor describes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reports {
    pub pointer: Option<Pointer>,
    pub keys: Option<Keys>,
    /// The longest input report, including its report ID byte: what one
    /// interrupt transfer must hold (Linux `hid_find_max_report`).
    pub input_bytes: usize,
}

impl Reports {
    /// The report ID byte that starts each report, when the descriptor
    /// uses report IDs.
    pub fn numbered(&self) -> bool {
        self.pointer.as_ref().is_some_and(|p| p.report.is_some())
            || self.keys.as_ref().is_some_and(|k| k.report.is_some())
    }
}

/// The input fields of a report descriptor, and its longest input report.
fn items(descriptor: &[u8]) -> Result<(Vec<Item>, usize), ParseError> {
    #[derive(Clone, Copy, Default)]
    struct Global {
        page: u32,
        minimum: i32,
        maximum: i64,
        size: usize,
        count: usize,
        report: Option<u8>,
    }
    let mut global = Global::default();
    let mut stack: Vec<Global> = Vec::new();
    let mut local = Local::default();
    let mut offsets: Vec<(Option<u8>, usize)> = Vec::new();
    let mut items = Vec::new();
    let mut collections: Vec<(u32, bool)> = Vec::new();
    let mut at = 0;
    while at < descriptor.len() {
        let item_offset = at;
        let prefix = descriptor[at];
        if prefix == LONG_ITEM {
            return Err(ParseError::at(
                Reader::InputReports,
                item_offset,
                ParseErrorKind::LongItem,
            ));
        }
        let size = match prefix & SIZE_MASK {
            SIZE_FOUR => 4,
            n => usize::from(n),
        };
        let Some(data) = descriptor.get(at + 1..at + 1 + size) else {
            return Err(ParseError::at(
                Reader::InputReports,
                item_offset,
                ParseErrorKind::TruncatedItem {
                    needed: size,
                    available: descriptor.len() - at - 1,
                },
            ));
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
        let tag = prefix & TAG_MASK;
        let mut usages = if matches!(tag, INPUT | OUTPUT | COLLECTION | FEATURE | END_COLLECTION) {
            local.main(tag, unsigned, global.page).map_err(|error| {
                ParseError::at(
                    Reader::InputReports,
                    item_offset,
                    ParseErrorKind::Usage(error),
                )
            })?
        } else {
            Vec::new()
        };
        match prefix & TAG_MASK {
            INPUT => {
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
                if *offset > MAX_REPORT_BITS {
                    return Err(ParseError::at(
                        Reader::InputReports,
                        item_offset,
                        ParseErrorKind::ReportBits {
                            existing: start,
                            size: global.size,
                            count: global.count,
                            limit: MAX_REPORT_BITS,
                        },
                    ));
                }
                let constant = flags & CONSTANT != 0;
                let variable = flags & VARIABLE != 0;
                let array = if !constant && !variable && global.count != 0 && !usages.is_empty() {
                    if i64::from(global.minimum) > global.maximum {
                        return Err(ParseError::at(
                            Reader::InputReports,
                            item_offset,
                            ParseErrorKind::LogicalRange {
                                minimum: i64::from(global.minimum),
                                maximum: global.maximum,
                            },
                        ));
                    }
                    let has_keyboard = usages.iter().any(|usage| usage >> 16 == KEYBOARD_PAGE);
                    Some(Array {
                        usages: core::mem::take(&mut usages).into(),
                        has_keyboard,
                        minimum: i64::from(global.minimum),
                        maximum: global.maximum,
                    })
                } else {
                    None
                };
                for n in 0..global.count {
                    if constant {
                        break;
                    }
                    let usage = if variable {
                        match usages.get(n).or(usages.last()) {
                            Some(usage) => Usage::Variable(*usage),
                            None => continue,
                        }
                    } else {
                        match &array {
                            Some(array) => Usage::Array(array.clone()),
                            None => continue,
                        }
                    };
                    items.push(Item {
                        report: global.report,
                        application: collections
                            .iter()
                            .rev()
                            .find(|(_, app)| *app)
                            .map_or(0, |(usage, _)| *usage),
                        field: Field {
                            offset: start + n * global.size,
                            size: global.size,
                            minimum: global.minimum,
                            maximum: global.maximum as i32,
                            relative: flags & RELATIVE != 0,
                        },
                        usage,
                    });
                }
            }
            COLLECTION => {
                collections.push((usages.first().copied().unwrap_or(0), unsigned == 1));
            }
            END_COLLECTION => {
                collections.pop().ok_or(ParseError::at(
                    Reader::InputReports,
                    item_offset,
                    ParseErrorKind::CollectionUnderflow,
                ))?;
            }
            OUTPUT | FEATURE => {}
            USAGE_PAGE => {
                if unsigned > 0xffff {
                    return Err(ParseError::at(
                        Reader::InputReports,
                        item_offset,
                        ParseErrorKind::UsagePage { value: unsigned },
                    ));
                }
                global.page = unsigned;
            }
            LOGICAL_MINIMUM => global.minimum = signed,
            LOGICAL_MAXIMUM => {
                // A maximum that only fits unsigned (8-bit 0xff) stays positive.
                global.maximum = if global.minimum >= 0 {
                    i64::from(unsigned)
                } else {
                    i64::from(signed)
                };
            }
            REPORT_SIZE if unsigned > MAX_REPORT_SIZE => {
                return Err(ParseError::at(
                    Reader::InputReports,
                    item_offset,
                    ParseErrorKind::ReportSize { bits: unsigned },
                ));
            }
            REPORT_SIZE => global.size = unsigned as usize,
            REPORT_ID => match u8::try_from(unsigned) {
                Ok(id) if id != 0 => global.report = Some(id),
                _ => {
                    return Err(ParseError::at(
                        Reader::InputReports,
                        item_offset,
                        ParseErrorKind::ReportId { value: unsigned },
                    ));
                }
            },
            REPORT_COUNT if unsigned > MAX_REPORT_COUNT => {
                return Err(ParseError::at(
                    Reader::InputReports,
                    item_offset,
                    ParseErrorKind::ReportCount { count: unsigned },
                ));
            }
            REPORT_COUNT => global.count = unsigned as usize,
            PUSH if stack.len() == GLOBAL_STACK => {
                return Err(ParseError::at(
                    Reader::InputReports,
                    item_offset,
                    ParseErrorKind::GlobalStackOverflow {
                        limit: GLOBAL_STACK,
                    },
                ));
            }
            PUSH => stack.push(global),
            POP => {
                global = stack.pop().ok_or(ParseError::at(
                    Reader::InputReports,
                    item_offset,
                    ParseErrorKind::GlobalStackUnderflow,
                ))?
            }
            // Physical extents and units do not change a field's value.
            PHYSICAL_MINIMUM | PHYSICAL_MAXIMUM | UNIT_EXPONENT | UNIT => {}
            USAGE => local.usage(unsigned, size, global.page).map_err(|error| {
                ParseError::at(
                    Reader::InputReports,
                    item_offset,
                    ParseErrorKind::Usage(error),
                )
            })?,
            USAGE_MINIMUM => local
                .minimum(unsigned, size, global.page)
                .map_err(|error| {
                    ParseError::at(
                        Reader::InputReports,
                        item_offset,
                        ParseErrorKind::Usage(error),
                    )
                })?,
            USAGE_MAXIMUM => local
                .maximum(unsigned, size, global.page)
                .map_err(|error| {
                    ParseError::at(
                        Reader::InputReports,
                        item_offset,
                        ParseErrorKind::Usage(error),
                    )
                })?,
            0xa8 => local.delimiter(unsigned, size).map_err(|error| {
                ParseError::at(
                    Reader::InputReports,
                    item_offset,
                    ParseErrorKind::Usage(error),
                )
            })?,
            // Designators and strings do not change this reader's fields.
            _ if prefix & 0x0c == 0 => {
                return Err(ParseError::at(
                    Reader::InputReports,
                    item_offset,
                    ParseErrorKind::ReservedItem { prefix },
                ));
            }
            _ => {}
        }
    }
    local.complete().map_err(|error| {
        ParseError::at(
            Reader::InputReports,
            descriptor.len(),
            ParseErrorKind::Usage(error),
        )
    })?;
    if !collections.is_empty() {
        return Err(ParseError::at(
            Reader::InputReports,
            descriptor.len(),
            ParseErrorKind::UnfinishedCollections {
                depth: collections.len(),
            },
        ));
    }
    let numbered = offsets.iter().any(|(id, _)| id.is_some());
    let longest = offsets.iter().map(|(_, bits)| bits.div_ceil(8)).max();
    Ok((items, longest.unwrap_or(0) + usize::from(numbered)))
}

fn pointer(items: &[Item]) -> Option<Pointer> {
    let mut layouts: Vec<Pointer> = Vec::new();
    for item in items {
        // Gamepad and Finger X/Y are not a native mouse. Uncollected fields
        // remain accepted for existing standalone descriptor-reader users.
        if !matches!(
            item.application,
            0 | 0x0001_0001 | 0x0001_0002 | 0x000d_0002
        ) {
            continue;
        }
        let Usage::Variable(usage) = &item.usage else {
            continue;
        };
        let layout = match layouts.iter_mut().position(|l| l.report == item.report) {
            Some(n) => &mut layouts[n],
            None => {
                layouts.push(Pointer {
                    report: item.report,
                    ..Pointer::default()
                });
                layouts.last_mut().unwrap()
            }
        };
        let field = Some(item.field);
        match *usage {
            GENERIC_DESKTOP_X => layout.x = layout.x.or(field),
            GENERIC_DESKTOP_Y => layout.y = layout.y.or(field),
            GENERIC_DESKTOP_WHEEL => layout.wheel = layout.wheel.or(field),
            CONSUMER_AC_PAN => layout.pan = layout.pan.or(field),
            BUTTON_1..=BUTTON_5 => {
                let button = &mut layout.buttons[(*usage - BUTTON_1) as usize];
                *button = button.or(field);
            }
            _ => {}
        }
    }
    layouts
        .into_iter()
        .find(|layout| layout.x.is_some() && layout.y.is_some())
}

fn keys(items: &[Item]) -> Option<Keys> {
    let report = items
        .iter()
        .find(|item| match &item.usage {
            Usage::Variable(usage) => usage >> 16 == KEYBOARD_PAGE,
            Usage::Array(array) => array.has_keyboard,
        })?
        .report;
    let mut keys = Keys {
        report,
        ..Keys::default()
    };
    for item in items.iter().filter(|item| item.report == report) {
        match &item.usage {
            Usage::Variable(usage) if usage >> 16 == KEYBOARD_PAGE => {
                keys.variables.push((item.field, usage & 0xffff));
            }
            Usage::Array(array) if array.has_keyboard => {
                keys.arrays.push((item.field, array.clone()));
            }
            _ => {}
        }
    }
    Some(keys)
}

/// The pointer and keyboard reports of `descriptor`.
pub fn parse(descriptor: &[u8]) -> Result<Reports, ParseError> {
    let (items, input_bytes) = items(descriptor)?;
    Ok(Reports {
        pointer: pointer(&items),
        keys: keys(&items),
        input_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_descriptors_yield_pointer_fields() {
        // A relative report-protocol mouse with a report ID.
        let descriptor = [
            0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x85, 0x02, 0x09, 0x01, 0xa1, 0x00, 0x05, 0x09,
            0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02,
            0x95, 0x01, 0x75, 0x05, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38,
            0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06, 0xc0, 0xc0,
        ];
        let reports = parse(&descriptor).unwrap();
        assert!(reports.keys.is_none() && reports.numbered());
        let layout = reports.pointer.unwrap();
        assert_eq!(layout.report, Some(2));
        let x = layout.x.unwrap();
        assert_eq!(
            (x.offset, x.size, x.relative, x.minimum),
            (8, 8, true, -127)
        );
        assert_eq!(layout.wheel.unwrap().offset, 24);
        assert_eq!(layout.buttons[2].unwrap().offset, 2);
        assert_eq!(x.read(&[0, 0xff]), Some(-1));
        // Three bytes of fields after the ID byte.
        assert_eq!(reports.input_bytes, 5);
        let collection_only = parse(&[0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0xc0]).unwrap();
        assert_eq!(collection_only, Reports::default());
    }

    #[test]
    fn global_stack_and_field_bounds_follow_linux() {
        // Push saves the page; Pop restores it, so X keeps Generic Desktop.
        let pushed = [
            0x05, 0x01, 0xa4, 0x05, 0x09, 0xb4, 0x09, 0x30, 0x09, 0x31, 0x15, 0x81, 0x25, 0x7f,
            0x75, 0x08, 0x95, 0x02, 0x81, 0x06,
        ];
        let pointer = parse(&pushed).unwrap().pointer.unwrap();
        assert_eq!(pointer.x.unwrap().offset, 0);
        assert_eq!(
            parse(&[0xa4; 5]).map_err(ParseError::message),
            Err("global item stack overflow")
        );
        assert_eq!(
            parse(&[0xb4]).map_err(ParseError::message),
            Err("Pop without Push")
        );
        // Report Size 257, Report Count 12289 and Report ID 0 are refused.
        assert_eq!(
            parse(&[0x76, 0x01, 0x01]).map_err(ParseError::message),
            Err("Report Size over 256 bits")
        );
        assert_eq!(
            parse(&[0x96, 0x01, 0x30]).map_err(ParseError::message),
            Err("Report Count over 12288")
        );
        assert_eq!(
            parse(&[0x85, 0x00]).map_err(ParseError::message),
            Err("Report ID outside 1-255")
        );
        // 256 bits times 12288 fields cannot fit 16 KiB.
        assert_eq!(
            parse(&[0x76, 0x00, 0x01, 0x96, 0x00, 0x30, 0x81, 0x01]).map_err(ParseError::message),
            Err("input report longer than 16384 bytes")
        );
    }

    /// An NKRO keyboard: report 1 holds a modifier bitmap and a bitmap of
    /// usages 04h-73h; report 3 is a consumer control array.
    const NKRO: [u8; 53] = [
        0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, // keyboard, report 1
        0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81,
        0x02, // modifiers
        0x19, 0x04, 0x29, 0x73, 0x95, 0x70, 0x81, 0x02, // key bitmap
        0xc0, //
        0x05, 0x0c, 0x09, 0x01, 0xa1, 0x01, 0x85, 0x03, // consumer, report 3
        0x19, 0x00, 0x2a, 0x3c, 0x02, 0x75, 0x10, 0x95, 0x01, 0x81, 0x00, // array
        0xc0,
    ];

    #[test]
    fn keyboard_bitmaps_and_arrays_report_held_usages() {
        let reports = parse(&NKRO).unwrap();
        assert!(reports.pointer.is_none());
        let keys = reports.keys.unwrap();
        assert_eq!(
            (keys.report, keys.variables.len(), keys.arrays.len()),
            (Some(1), 120, 0)
        );
        // Left Shift and A (usage 04h, bit 8 of the body).
        let mut body = [0u8; 15];
        body[0] = 0x02;
        body[1] = 0x01;
        assert_eq!(keys.pressed(&body), Some(alloc::vec![0xe1, 0x04]));
        // The boot layout: Z and an out-of-range zero, then rollover.
        let boot = Keys::boot();
        assert_eq!(
            boot.pressed(&[0, 0, 0x1d, 0, 0, 0, 0, 0]),
            Some(alloc::vec![0x1d])
        );
        assert_eq!(boot.pressed(&[0, 0, 1, 1, 1, 1, 1, 1]), Some(alloc::vec![]));
        // Rollover keeps the array's keys, but the modifier bitmap applies:
        // Left Control releases and Left Shift presses.
        assert_eq!(
            boot.pressed_after(&[2, 0, 1, 1, 1, 1, 1, 1], &[0xe0, 0x04]),
            Some(alloc::vec![0xe1, 0x04])
        );
        assert_eq!(boot.pressed(&[0; 4]), None, "a short report holds no state");
    }

    #[test]
    fn array_values_index_their_usage_range() {
        // A keyboard array over usages 00h-65h with logical 0..=101.
        let descriptor = [
            0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x15, 0x00, 0x25, 0x65, 0x75, 0x08, 0x95, 0x02,
            0x81, 0x00,
        ];
        let keys = parse(&descriptor).unwrap().keys.unwrap();
        assert_eq!(keys.pressed(&[0x04, 0x04]), Some(alloc::vec![0x04]));
        // 0x66 is past the logical maximum: no usage.
        assert_eq!(keys.pressed(&[0x66, 0x05]), Some(alloc::vec![0x05]));
        assert_eq!(
            keys.pressed(&[0x02, 0x05]),
            Some(alloc::vec![0x05]),
            "POSTFail"
        );
    }
}
