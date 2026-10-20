//! HID report descriptors (HID 1.11 6.2.2) as the input fields they
//! describe, and the pointer and keyboard reports read from those fields.
//!
//! Each Input main item lays out Report Count fields of Report Size bits,
//! at offsets counted per report ID. A variable item's fields each carry
//! one usage (6.2.2.4, Usage or a Usage Minimum..Maximum range); an array
//! item's fields each hold an index into its usage range (6.2.2.5), where a
//! value outside the logical range names no usage. Constant items pad.
//! Output and Feature items have offsets of their own and are not read.
//! Long items, Push and Pop are refused.
//!
//! A pointer is the first report with Generic Desktop X and Y, its Button
//! 1-3 and wheel when present. A keyboard is the first report with
//! Keyboard/Keypad page (07h) fields: modifier and key bitmaps (variable
//! items) and key arrays. The arrays' ErrorRollOver, POSTFail and
//! ErrorUndefined (usages 01h-03h, HID Usage Tables 10) say the report
//! holds no key state, so such a report changes nothing.
use alloc::vec::Vec;

const GENERIC_DESKTOP_X: u32 = 0x0001_0030;
const GENERIC_DESKTOP_Y: u32 = 0x0001_0031;
const GENERIC_DESKTOP_WHEEL: u32 = 0x0001_0038;
const BUTTON_1: u32 = 0x0009_0001;
const BUTTON_3: u32 = 0x0009_0003;
const KEYBOARD_PAGE: u32 = 0x07;
/// The array usages that report an error state instead of keys.
const KEY_ERRORS: core::ops::RangeInclusive<u32> = 0x01..=0x03;

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

/// What one input field reports: a usage of its own, or an index into a
/// usage range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Usage {
    Variable(u32),
    Array { first: u32, last: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Item {
    report: Option<u8>,
    field: Field,
    usage: Usage,
}

/// A pointer report's layout.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pointer {
    pub report: Option<u8>,
    pub x: Option<Field>,
    pub y: Option<Field>,
    pub wheel: Option<Field>,
    pub buttons: [Option<Field>; 3],
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
            buttons: [
                field(0, 1, 0, false),
                field(1, 1, 0, false),
                field(2, 1, 0, false),
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
    /// Array fields and the usage range their values index.
    arrays: Vec<(Field, u32, u32)>,
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
        Self {
            report: None,
            variables: (0..8)
                .map(|bit| (field(bit, 1, 1), 0xe0 + bit as u32))
                .collect(),
            arrays: (0..6)
                .map(|n| (field(16 + 8 * n, 8, 0xff), 0, 0xff))
                .collect(),
        }
    }

    /// The Keyboard/Keypad usages `body` reports held, or `None` for a
    /// report in an error state.
    pub fn pressed(&self, body: &[u8]) -> Option<Vec<u32>> {
        let mut held = Vec::new();
        for (field, usage) in &self.variables {
            if field.read(body)? != 0 {
                held.push(*usage);
            }
        }
        for (field, first, last) in &self.arrays {
            let value = field.read(body)?;
            if !(field.minimum..=field.maximum).contains(&value) {
                continue;
            }
            let usage = i64::from(*first) + i64::from(value) - i64::from(field.minimum);
            let Ok(usage) = u32::try_from(usage) else {
                continue;
            };
            if usage > *last || usage == 0 {
                continue;
            }
            if KEY_ERRORS.contains(&usage) {
                return None;
            }
            if !held.contains(&usage) {
                held.push(usage);
            }
        }
        Some(held)
    }
}

/// The pointer and keyboard reports a descriptor describes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reports {
    pub pointer: Option<Pointer>,
    pub keys: Option<Keys>,
}

impl Reports {
    /// The report ID byte that starts each report, when the descriptor
    /// uses report IDs.
    pub fn numbered(&self) -> bool {
        self.pointer.as_ref().is_some_and(|p| p.report.is_some())
            || self.keys.as_ref().is_some_and(|k| k.report.is_some())
    }
}

/// The input fields of a report descriptor.
fn items(descriptor: &[u8]) -> Result<Vec<Item>, &'static str> {
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
    let mut items = Vec::new();
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
            // Input main items.
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
                let constant = flags & 1 != 0;
                let variable = flags & 2 != 0;
                for n in 0..global.count {
                    if constant {
                        break;
                    }
                    let usage = if variable {
                        match range {
                            Some((first, last)) => Usage::Variable((first + n as u32).min(last)),
                            None => match usages.get(n).or(usages.last()) {
                                Some(usage) => Usage::Variable(*usage),
                                None => continue,
                            },
                        }
                    } else {
                        match (range, usages.first(), usages.last()) {
                            (Some((first, last)), _, _) => Usage::Array { first, last },
                            (None, Some(first), Some(last)) => Usage::Array {
                                first: *first,
                                last: *last,
                            },
                            _ => continue,
                        }
                    };
                    items.push(Item {
                        report: global.report,
                        field: Field {
                            offset: start + n * global.size,
                            size: global.size,
                            minimum: global.minimum,
                            maximum: global.maximum,
                            relative: flags & 4 != 0,
                        },
                        usage,
                    });
                }
                usages.clear();
                range = None;
            }
            // Output, Feature, Collection and End Collection.
            0x90 | 0xb0 | 0xa0 | 0xc0 => {
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
    Ok(items)
}

fn pointer(items: &[Item]) -> Option<Pointer> {
    let mut layouts: Vec<Pointer> = Vec::new();
    for item in items {
        let Usage::Variable(usage) = item.usage else {
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
        match usage {
            GENERIC_DESKTOP_X => layout.x = layout.x.or(field),
            GENERIC_DESKTOP_Y => layout.y = layout.y.or(field),
            GENERIC_DESKTOP_WHEEL => layout.wheel = layout.wheel.or(field),
            BUTTON_1..=BUTTON_3 => {
                let button = &mut layout.buttons[(usage - BUTTON_1) as usize];
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
        .find(|item| match item.usage {
            Usage::Variable(usage) => usage >> 16 == KEYBOARD_PAGE,
            Usage::Array { first, last } => {
                first >> 16 == KEYBOARD_PAGE && last >> 16 == first >> 16
            }
        })?
        .report;
    let mut keys = Keys {
        report,
        ..Keys::default()
    };
    for item in items.iter().filter(|item| item.report == report) {
        match item.usage {
            Usage::Variable(usage) if usage >> 16 == KEYBOARD_PAGE => {
                keys.variables.push((item.field, usage & 0xffff));
            }
            Usage::Array { first, last } if first >> 16 == KEYBOARD_PAGE => {
                keys.arrays
                    .push((item.field, first & 0xffff, last & 0xffff));
            }
            _ => {}
        }
    }
    Some(keys)
}

/// The pointer and keyboard reports of `descriptor`.
pub fn parse(descriptor: &[u8]) -> Result<Reports, &'static str> {
    let items = items(descriptor)?;
    Ok(Reports {
        pointer: pointer(&items),
        keys: keys(&items),
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
        assert!(parse(&[0x05, 0x01, 0xa4]).is_err());
        let collection_only = parse(&[0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0xc0]).unwrap();
        assert_eq!(collection_only, Reports::default());
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
        assert_eq!(boot.pressed(&[0, 0, 1, 1, 1, 1, 1, 1]), None);
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
        assert_eq!(keys.pressed(&[0x02, 0x00]), None, "POSTFail");
    }
}
