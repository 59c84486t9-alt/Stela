// SPDX-License-Identifier: GPL-2.0-only
//! Wire descriptor bounds and source-checked i2c-hid-core.c device quirks.
//! Upstream notices are in input/THIRD_PARTY.md.
use super::{DESCRIPTOR_BYTES, ErrorKind, MAX_BUFFER, MAX_DESCRIPTOR};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub report_descriptor_length: u16,
    pub report_descriptor_register: u16,
    pub input_register: u16,
    pub max_input_length: u16,
    pub output_register: u16,
    pub max_output_length: u16,
    pub command_register: u16,
    pub data_register: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}
impl Descriptor {
    pub(super) fn parse(bytes: &[u8; DESCRIPTOR_BYTES]) -> Result<Self, ErrorKind> {
        let word = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        if word(0) != DESCRIPTOR_BYTES as u16 {
            return Err(ErrorKind::DescriptorLength(word(0)));
        }
        if word(2) != 0x0100 {
            return Err(ErrorKind::Version(word(2)));
        }
        if word(4) == 0 || usize::from(word(4)) > MAX_DESCRIPTOR {
            return Err(ErrorKind::ReportDescriptorLength(word(4)));
        }
        for length in [word(10), word(14)] {
            if usize::from(length) > MAX_BUFFER || (length != 0 && length < 2) {
                return Err(ErrorKind::BufferLength(length));
            }
        }
        if word(10) < 2 {
            return Err(ErrorKind::BufferLength(word(10)));
        }
        Ok(Self {
            report_descriptor_length: word(4),
            report_descriptor_register: word(6),
            input_register: word(8),
            max_input_length: word(10),
            output_register: word(12),
            max_output_length: word(14),
            command_register: word(16),
            data_register: word(18),
            vendor: word(20),
            product: word(22),
            version: word(24),
        })
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Quirks {
    pub(super) elan: bool,
    pub(super) reset_resume: bool,
    pub(super) delayed_resume: bool,
    pub(super) no_sleep: bool,
    pub(super) repower: bool,
    pub(super) no_reset_irq: bool,
    pub(super) bad_input_size: bool,
}
impl Quirks {
    pub(super) fn for_device(d: Descriptor) -> Self {
        Self {
            elan: d.vendor == 0x04f3,
            reset_resume: d.vendor == 0x044e || (d.vendor, d.product) == (0x06cb, 0x7a13),
            delayed_resume: (d.vendor, d.product) == (0x27c6, 0x0d42),
            no_sleep: (d.vendor, d.product) == (0x0488, 0x1063),
            repower: d.vendor == 0x6243,
            no_reset_irq: matches!(
                (d.vendor, d.product),
                (0x0911, 0x5288)
                    | (0x103c, 0x184f)
                    | (0x048d, 0x83db)
                    | (0x2386, 0x3118)
                    | (0x0488, 0xd0c1)
                    | (0x36b6, 0xc001)
            ),
            bad_input_size: matches!((d.vendor, d.product), (0x0911, 0x5288) | (0x048d, 0x837a)),
        }
    }
}
