// SPDX-License-Identifier: MIT
// Wire layouts follow the pinned ACPICA amlresrc.h/rsserial.c/rsirq.c.
use super::*;
use alloc::string::String;

const MAX_BYTES: usize = 65536;
const MAX_RESOURCES: usize = 4096;

fn word(bytes: &[u8], at: usize, width: usize) -> Result<u64, Error> {
    let slice = bytes.get(at..at + width).ok_or(Error::Truncated)?;
    Ok(slice
        .iter()
        .enumerate()
        .fold(0, |n, (i, b)| n | (u64::from(*b) << (i * 8))))
}
fn source(bytes: &[u8], index: u8) -> Result<Source, Error> {
    let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
        return Err(Error::Malformed);
    };
    if end == 0 {
        return Err(Error::Malformed);
    }
    let path = core::str::from_utf8(&bytes[..end]).map_err(|_| Error::Malformed)?;
    if !path.is_ascii() {
        return Err(Error::Malformed);
    }
    Ok(Source {
        index,
        path: String::from(path),
    })
}
fn optional_source(bytes: &[u8]) -> Result<Option<Source>, Error> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        source(&bytes[1..], bytes[0]).map(Some)
    }
}
fn exact(bytes: &[u8], length: usize) -> Result<(), Error> {
    if bytes.len() == length {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}
fn trigger(edge: bool) -> Trigger {
    if edge { Trigger::Edge } else { Trigger::Level }
}
fn polarity(bits: u8) -> Result<Polarity, Error> {
    match bits {
        0 => Ok(Polarity::High),
        1 => Ok(Polarity::Low),
        2 => Ok(Polarity::Both),
        _ => Err(Error::Malformed),
    }
}

/// Decode a complete `_CRS`/`_AEI` template. EndTag is mandatory and its
/// optional checksum is validated. Dependent alternatives stay unsupported.
pub fn parse(bytes: &[u8]) -> Result<Vec<Descriptor>, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Limit);
    }
    let mut result = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let tag = bytes[at];
        let (header, length) = if tag & 0x80 != 0 {
            (3, word(bytes, at + 1, 2)? as usize)
        } else {
            (1, usize::from(tag & 7))
        };
        let end = at.checked_add(header + length).ok_or(Error::Limit)?;
        let raw = bytes.get(at..end).ok_or(Error::Truncated)?;
        if tag == 0x79 {
            if end != bytes.len() {
                return Err(Error::Malformed);
            }
            if raw[1] != 0 && bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
                return Err(Error::Checksum);
            }
            return Ok(result);
        }
        if tag & 0xf8 == 0x78 {
            return Err(Error::Malformed);
        }
        if result.len() == MAX_RESOURCES {
            return Err(Error::Limit);
        }
        let resource = descriptor(raw)?;
        result.push(Descriptor {
            ordinal: result.len(),
            offset: at,
            bytes: raw.to_vec(),
            resource,
        });
        at = end;
    }
    Err(Error::MissingEnd)
}

/// Connection() contains a single raw GPIO descriptor, without an EndTag.
pub fn parse_gpio_connection(bytes: &[u8]) -> Result<Gpio, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Limit);
    }
    if bytes.first() != Some(&0x8c) {
        return Err(Error::Malformed);
    }
    exact(bytes, 3 + word(bytes, 1, 2)? as usize)?;
    gpio(bytes)
}

fn fixed(space: Space, minimum: u64, length: u64, flags: u8) -> Result<Resource, Error> {
    let maximum = minimum
        .checked_add(length)
        .and_then(|end| end.checked_sub(1))
        .ok_or(Error::Malformed)?;
    if length == 0 {
        return Err(Error::Unassigned);
    }
    Ok(Resource::Address(Address {
        space,
        consumer: true,
        subtractive: false,
        minimum_fixed: true,
        maximum_fixed: true,
        specific_flags: flags,
        granularity: 0,
        minimum,
        maximum,
        translation: 0,
        length,
        source: None,
    }))
}

fn descriptor(raw: &[u8]) -> Result<Resource, Error> {
    let tag = raw[0];
    // Alternatives require selection before any contained address is assigned.
    // Never expose their interior descriptors to a native reservation consumer.
    if tag & 0x80 == 0 && matches!(tag & 0xf8, 0x30 | 0x38) {
        return Err(Error::DependentFunctions);
    }
    match tag {
        0x22 | 0x23 => {
            let mask = word(raw, 1, 2)? as u16;
            let flags = if tag == 0x23 { raw[3] } else { 1 };
            if flags & !0x39 != 0 || mask == 0 {
                return Err(Error::Malformed);
            }
            Ok(Resource::Interrupt(Interrupt {
                consumer: true,
                trigger: trigger(flags & 1 != 0),
                polarity: if flags & 8 != 0 {
                    Polarity::Low
                } else {
                    Polarity::High
                },
                shared: flags & 0x10 != 0,
                wake: flags & 0x20 != 0,
                pins: (0..16).filter(|pin| mask & (1 << pin) != 0).collect(),
                source: None,
            }))
        }
        0x47 => {
            let minimum = word(raw, 2, 2)?;
            let maximum = word(raw, 4, 2)?;
            if raw[1] & !1 != 0 || minimum > maximum {
                return Err(Error::Malformed);
            }
            Ok(Resource::Address(Address {
                space: Space::Io,
                consumer: true,
                subtractive: false,
                minimum_fixed: minimum == maximum,
                maximum_fixed: minimum == maximum,
                specific_flags: raw[1],
                granularity: u64::from(raw[6]),
                minimum,
                maximum,
                translation: 0,
                length: u64::from(raw[7]),
                source: None,
            }))
        }
        0x4b => fixed(Space::Io, word(raw, 1, 2)?, u64::from(raw[3]), 1),
        0x86 => {
            exact(raw, 12)?;
            if raw[3] & !1 != 0 {
                return Err(Error::Malformed);
            }
            fixed(Space::Memory, word(raw, 4, 4)?, word(raw, 8, 4)?, raw[3])
        }
        0x87 | 0x88 | 0x8a => address(raw),
        0x89 => {
            if raw.len() < 5 || raw[3] & !0x1f != 0 || raw[4] == 0 {
                return Err(Error::Malformed);
            }
            let count = usize::from(raw[4]);
            let mut pins = Vec::with_capacity(count);
            for i in 0..count {
                pins.push(word(raw, 5 + i * 4, 4)? as u32);
            }
            let source = optional_source(raw.get(5 + count * 4..).ok_or(Error::Truncated)?)?;
            Ok(Resource::Interrupt(Interrupt {
                consumer: raw[3] & 1 != 0,
                trigger: trigger(raw[3] & 2 != 0),
                polarity: if raw[3] & 4 != 0 {
                    Polarity::Low
                } else {
                    Polarity::High
                },
                shared: raw[3] & 8 != 0,
                wake: raw[3] & 16 != 0,
                pins,
                source,
            }))
        }
        0x8c => gpio(raw).map(Resource::Gpio),
        0x8e => serial(raw).map(Resource::Serial),
        _ => Ok(Resource::Unsupported {
            tag,
            bytes: raw.to_vec(),
        }),
    }
}

fn address(raw: &[u8]) -> Result<Resource, Error> {
    let width = match raw[0] {
        0x88 => 2,
        0x87 => 4,
        _ => 8,
    };
    if raw.len() < 6 + 5 * width {
        return Err(Error::Truncated);
    }
    if raw[4] & !15 != 0 {
        return Err(Error::Malformed);
    }
    let space = match raw[3] {
        0 => Space::Memory,
        1 => Space::Io,
        2 => Space::Bus,
        _ => {
            return Ok(Resource::Unsupported {
                tag: raw[0],
                bytes: raw.to_vec(),
            });
        }
    };
    let minimum = word(raw, 6 + width, width)?;
    let maximum = word(raw, 6 + 2 * width, width)?;
    if minimum > maximum {
        return Err(Error::Malformed);
    }
    Ok(Resource::Address(Address {
        space,
        consumer: raw[4] & 1 != 0,
        subtractive: raw[4] & 2 != 0,
        minimum_fixed: raw[4] & 4 != 0,
        maximum_fixed: raw[4] & 8 != 0,
        specific_flags: raw[5],
        granularity: word(raw, 6, width)?,
        minimum,
        maximum,
        translation: word(raw, 6 + 3 * width, width)?,
        length: word(raw, 6 + 4 * width, width)?,
        source: optional_source(&raw[6 + 5 * width..])?,
    }))
}

fn gpio(raw: &[u8]) -> Result<Gpio, Error> {
    if raw.len() < 23 {
        return Err(Error::Truncated);
    }
    if raw[3] != 1 {
        return Err(Error::Unsupported {
            tag: 0x8c,
            revision: raw[3],
        });
    }
    let flags = word(raw, 5, 2)?;
    let int_flags = word(raw, 7, 2)? as u8;
    if flags & !1 != 0 || raw[8] != 0 {
        return Err(Error::Malformed);
    }
    let kind = match raw[4] {
        0 => {
            if int_flags & !0x1f != 0 {
                return Err(Error::Malformed);
            }
            let polarity = polarity((int_flags >> 1) & 3)?;
            let trigger = trigger(int_flags & 1 != 0);
            if polarity == Polarity::Both && trigger == Trigger::Level {
                return Err(Error::Malformed);
            }
            GpioKind::Interrupt { trigger, polarity }
        }
        1 => {
            if int_flags & !0x0b != 0 {
                return Err(Error::Malformed);
            }
            GpioKind::Io(match int_flags & 3 {
                0 => IoRestriction::None,
                1 => IoRestriction::Input,
                2 => IoRestriction::Output,
                _ => IoRestriction::Preserve,
            })
        }
        _ => {
            return Err(Error::Unsupported {
                tag: 0x8c,
                revision: raw[4],
            });
        }
    };
    let pins_at = word(raw, 14, 2)? as usize;
    let source_at = word(raw, 17, 2)? as usize;
    let vendor_at = word(raw, 19, 2)? as usize;
    let vendor_len = word(raw, 21, 2)? as usize;
    let source_end = if vendor_len == 0 {
        if vendor_at != 0 && vendor_at != raw.len() {
            return Err(Error::Malformed);
        }
        raw.len()
    } else {
        if vendor_at.checked_add(vendor_len) != Some(raw.len()) {
            return Err(Error::Malformed);
        }
        vendor_at
    };
    if pins_at < 23
        || source_at <= pins_at
        || !(source_at - pins_at).is_multiple_of(2)
        || source_end <= source_at
    {
        return Err(Error::Malformed);
    }
    let source = source(
        raw.get(source_at..source_end).ok_or(Error::Truncated)?,
        raw[16],
    )?;
    let mut pins = Vec::new();
    for at in (pins_at..source_at).step_by(2) {
        pins.push(word(raw, at, 2)? as u16);
    }
    Ok(Gpio {
        consumer: flags & 1 != 0,
        kind,
        shared: int_flags & 8 != 0,
        wake: int_flags & 16 != 0,
        pull: raw[9],
        drive_strength: word(raw, 10, 2)? as u16,
        debounce: word(raw, 12, 2)? as u16,
        pins,
        source,
        vendor: if vendor_len == 0 {
            Vec::new()
        } else {
            raw[vendor_at..].to_vec()
        },
    })
}

fn serial(raw: &[u8]) -> Result<Serial, Error> {
    if raw.len() < 12 {
        return Err(Error::Truncated);
    }
    if !(1..=2).contains(&raw[3]) || raw[9] != 1 {
        return Err(Error::Unsupported {
            tag: 0x8e,
            revision: raw[3],
        });
    }
    if raw[6] & !7 != 0 || (raw[3] == 1 && raw[6] & 4 != 0) {
        return Err(Error::Malformed);
    }
    let flags = word(raw, 7, 2)?;
    let data_len = word(raw, 10, 2)? as usize;
    let minimum = match raw[5] {
        1 => 6,
        2 => 9,
        _ => {
            return Err(Error::Unsupported {
                tag: 0x8e,
                revision: raw[5],
            });
        }
    };
    if data_len < minimum {
        return Err(Error::Malformed);
    }
    let source_at = 12 + data_len;
    let source = source(raw.get(source_at..).ok_or(Error::Truncated)?, raw[4])?;
    let kind = if raw[5] == 1 {
        if flags & !1 != 0 {
            return Err(Error::Malformed);
        }
        let address = word(raw, 16, 2)? as u16;
        if address >= if flags & 1 != 0 { 1024 } else { 128 } {
            return Err(Error::Malformed);
        }
        SerialKind::I2c {
            address,
            ten_bit: flags & 1 != 0,
        }
    } else {
        if flags & !3 != 0 || raw[17] > 1 || raw[18] > 1 || raw[16] == 0 {
            return Err(Error::Malformed);
        }
        SerialKind::Spi {
            selection: word(raw, 19, 2)? as u16,
            three_wire: flags & 1 != 0,
            active_high: flags & 2 != 0,
            bits: raw[16],
            clock_phase: raw[17],
            clock_polarity: raw[18],
        }
    };
    let speed = word(raw, 12, 4)? as u32;
    if speed == 0 {
        return Err(Error::Malformed);
    }
    Ok(Serial {
        consumer: raw[6] & 2 != 0,
        controller_initiated: raw[6] & 1 == 0,
        shared: raw[6] & 4 != 0,
        speed,
        kind,
        source,
        vendor: raw[12 + minimum..source_at].to_vec(),
    })
}

#[cfg(test)]
mod tests;
