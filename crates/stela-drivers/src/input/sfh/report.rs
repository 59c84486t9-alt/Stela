// SPDX-License-Identifier: GPL-2.0-or-later
//! AMD SFHv2 sensor report layouts, following the pinned Linux descriptor port.
//! Copyright 2020-2021 Advanced Micro Devices, Inc.
//! Authors: Nehal Bakulchandra Shah, Sandeep Singh, Basavaraj Natikar.
use super::{Error, PERIOD_MS, Sensor, descriptor::*};
// HID array values are indices from each descriptor's logical minimum (zero),
// not the low byte of its Usage selector. These correct the donor constants.
const CONNECTION_INTEGRATED: u8 = 0;
const REPORTING_ALL_EVENTS: u8 = 1;
const POWER_D0: u8 = 1;
const STATE_INITIALIZING: u8 = 4;
pub(super) const STATE_READY: u8 = 1;
const EVENT_DATA_UPDATED: u8 = 3;
const EVENT_POLL_RESPONSE: u8 = 4;

/// One sequence of coherent per-word observations. SFHv2 supplies no sample
/// counter or record seqlock: this does not claim atomic vector/freshness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputReport {
    bytes: [u8; 19],
    len: usize,
}
impl InputReport {
    pub(super) fn mark_poll_response(&mut self) {
        self.bytes[2] = EVENT_POLL_RESPONSE;
    }
    pub fn wire_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl Sensor {
    pub fn report_id(self) -> Option<u8> {
        Some(match self {
            Self::Accelerometer => 1,
            Self::Gyroscope => 2,
            Self::Magnetometer => 3,
            Self::AmbientLight | Self::AmbientColor => 4,
            Self::HumanPresence => 5,
            Self::OperatingMode => return None,
        })
    }
    pub fn report_descriptor(self) -> Result<&'static [u8], Error> {
        Ok(match self {
            Self::Accelerometer => ACCEL3_REPORT_DESCRIPTOR,
            Self::Gyroscope => GYRO3_REPORT_DESCRIPTOR,
            Self::Magnetometer => COMP3_REPORT_DESCRIPTOR,
            Self::AmbientLight => ALS_REPORT_DESCRIPTOR,
            Self::AmbientColor => ACS_REPORT_DESCRIPTOR,
            Self::HumanPresence => HPD_REPORT_DESCRIPTOR,
            Self::OperatingMode => return Err(Error::NoHidSchema(self)),
        })
    }
    pub fn input_bytes(self) -> Result<usize, Error> {
        Ok(match self {
            Self::Accelerometer => 15,
            Self::Gyroscope => 15,
            Self::Magnetometer | Self::AmbientColor => 19,
            Self::AmbientLight => 7,
            Self::HumanPresence => 4,
            Self::OperatingMode => return Err(Error::NoHidSchema(self)),
        })
    }
    /// Read-only source sensitivity defaults and the fixed programmed period.
    /// SET_REPORT is explicitly unsupported rather than claiming a discarded
    /// write changed sensor period, sensitivity or power state.
    pub fn feature_report(self, output: &mut [u8]) -> Result<usize, Error> {
        let id = self.report_id().ok_or(Error::NoHidSchema(self))?;
        let len = match self {
            Self::HumanPresence => 9,
            Self::Magnetometer => 21,
            _ => 15,
        };
        if output.len() < len {
            return Err(Error::ReportBuffer { needed: len });
        }
        output[..len].fill(0);
        output[..9].copy_from_slice(&[
            id,
            CONNECTION_INTEGRATED,
            REPORTING_ALL_EVENTS,
            POWER_D0,
            STATE_INITIALIZING,
            PERIOD_MS,
            0,
            0,
            0,
        ]);
        if self == Self::Magnetometer {
            for (i, word) in [0x7fu16, 0x80, 0x7f, 0x7f, 0x80, 0x7f].iter().enumerate() {
                output[9 + 2 * i..11 + 2 * i].copy_from_slice(&word.to_le_bytes());
            }
        } else if self != Self::HumanPresence {
            for (i, word) in [0x7fu16, 0x80, 0x7f].iter().enumerate() {
                output[9 + 2 * i..11 + 2 * i].copy_from_slice(&word.to_le_bytes());
            }
        }
        Ok(len)
    }
}

pub(super) fn input(
    sensor: Sensor,
    words: [u32; 4],
    illuminance: u32,
    hpd: u32,
) -> Result<InputReport, Error> {
    let mut report = InputReport {
        bytes: [0; 19],
        len: sensor.input_bytes()?,
    };
    report.bytes[..3].copy_from_slice(&[
        sensor.report_id().ok_or(Error::NoHidSchema(sensor))?,
        STATE_READY,
        EVENT_DATA_UPDATED,
    ]);
    let mut put = |index: usize, word: u32| {
        report.bytes[3 + index * 4..7 + index * 4].copy_from_slice(&word.to_le_bytes())
    };
    match sensor {
        Sensor::Accelerometer | Sensor::Gyroscope | Sensor::Magnetometer => {
            for (index, word) in words[..3].iter().enumerate() {
                put(index, ((*word as i32) / 1000) as u32);
            }
            if sensor == Sensor::Magnetometer {
                put(3, u32::from(words[3] as u16) / 1000);
            }
        }
        Sensor::AmbientLight | Sensor::AmbientColor => {
            put(0, illuminance & 0x7fff);
            if sensor == Sensor::AmbientColor {
                for (index, word) in words[1..4].iter().enumerate() {
                    put(index + 1, *word);
                }
            }
        }
        Sensor::HumanPresence => {
            let presence = ((hpd >> 24) & 15) as u8;
            if presence > 1 {
                return Err(Error::InvalidPresence(presence));
            }
            report.bytes[3] = presence;
        }
        Sensor::OperatingMode => return Err(Error::NoHidSchema(sensor)),
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_axes_unsigned_accuracy_and_color_words_keep_source_widths() {
        let gyro = input(
            Sensor::Gyroscope,
            [(-1999i32) as u32, i32::MIN as u32, 999, 0],
            0,
            0,
        )
        .unwrap();
        assert_eq!(
            gyro.wire_bytes(),
            &[2, 1, 3, 255, 255, 255, 255, 101, 59, 223, 255, 0, 0, 0, 0]
        );
        let mag = input(Sensor::Magnetometer, [0, 0, 0, 0xffff_fa00], 0, 0).unwrap();
        assert_eq!(&mag.wire_bytes()[15..], &64u32.to_le_bytes());
        let color = input(
            Sensor::AmbientColor,
            [0, 0x12345678, 0x89abcdef, 0xfedcba98],
            0xffff_ffff,
            0,
        )
        .unwrap();
        assert_eq!(&color.wire_bytes()[3..7], &32767u32.to_le_bytes());
        assert_eq!(&color.wire_bytes()[7..11], &0x12345678u32.to_le_bytes());
        assert_eq!(
            input(Sensor::HumanPresence, [0; 4], 0, 0xa1000000)
                .unwrap()
                .wire_bytes(),
            &[5, 1, 3, 1]
        );
    }
    #[test]
    fn unsupported_optional_usages_are_omitted_instead_of_invented() {
        assert_eq!(
            input(Sensor::HumanPresence, [0; 4], 0, 0xa7000000),
            Err(Error::InvalidPresence(7))
        );
        assert_eq!(
            input(Sensor::Accelerometer, [1000; 4], 0, 0)
                .unwrap()
                .wire_bytes()
                .len(),
            15
        );
        assert_eq!(
            input(Sensor::AmbientLight, [0; 4], 123, 0)
                .unwrap()
                .wire_bytes(),
            &[4, 1, 3, 123, 0, 0, 0]
        );
        assert_eq!(
            Sensor::OperatingMode.report_descriptor(),
            Err(Error::NoHidSchema(Sensor::OperatingMode))
        );
    }
    #[test]
    fn feature_order_and_buffer_refusal_are_explicit() {
        let mut bytes = [0xa5; 21];
        assert_eq!(Sensor::Accelerometer.feature_report(&mut bytes), Ok(15));
        assert_eq!(
            &bytes[..15],
            &[1, 0, 1, 1, 4, PERIOD_MS, 0, 0, 0, 0x7f, 0, 0x80, 0, 0x7f, 0]
        );
        Sensor::Magnetometer.feature_report(&mut bytes).unwrap();
        assert_eq!(
            &bytes[9..],
            &[0x7f, 0, 0x80, 0, 0x7f, 0, 0x7f, 0, 0x80, 0, 0x7f, 0]
        );
        let mut small = [0xa5; 14];
        assert_eq!(
            Sensor::Gyroscope.feature_report(&mut small),
            Err(Error::ReportBuffer { needed: 15 })
        );
        assert_eq!(small, [0xa5; 14]);
    }
    #[test]
    fn descriptors_declare_exact_complete_input_and_feature_lengths() {
        // Independently walk HID short items; derive sizes from descriptor
        // globals and main items, rather than mirroring struct byte constants.
        for sensor in [
            Sensor::Accelerometer,
            Sensor::Gyroscope,
            Sensor::Magnetometer,
            Sensor::AmbientLight,
            Sensor::AmbientColor,
            Sensor::HumanPresence,
        ] {
            let descriptor = sensor.report_descriptor().unwrap();
            let mut offset = 0;
            let (mut size, mut count, mut input_bits, mut feature_bits) = (0, 0, 0, 0);
            let mut report_id = 0;
            while offset < descriptor.len() {
                let prefix = descriptor[offset];
                offset += 1;
                assert_ne!(prefix, 0xfe, "no unparsed long items");
                let bytes = match prefix & 3 {
                    3 => 4,
                    n => usize::from(n),
                };
                let mut value = 0u32;
                for index in 0..bytes {
                    value |= u32::from(descriptor[offset + index]) << (index * 8);
                }
                offset += bytes;
                match ((prefix >> 2) & 3, prefix >> 4) {
                    (1, 7) => size = value,
                    (1, 8) => report_id = value,
                    (1, 9) => count = value,
                    (0, 8) => input_bits += size * count,
                    (0, 11) => feature_bits += size * count,
                    (0, 9) => panic!("no invented output report"),
                    _ => (),
                }
            }
            assert_eq!(report_id, u32::from(sensor.report_id().unwrap()));
            assert_eq!(input_bits as usize, (sensor.input_bytes().unwrap() - 1) * 8);
            let mut feature = [0; 21];
            assert_eq!(
                feature_bits as usize,
                (sensor.feature_report(&mut feature).unwrap() - 1) * 8
            );
        }
    }
    #[test]
    fn serialized_selector_indices_resolve_to_the_declared_hid_usages() {
        for sensor in [
            Sensor::Accelerometer,
            Sensor::Gyroscope,
            Sensor::Magnetometer,
            Sensor::AmbientLight,
            Sensor::AmbientColor,
            Sensor::HumanPresence,
        ] {
            let descriptor = sensor.report_descriptor().unwrap();
            let (mut offset, mut minimum) = (0, 0);
            let mut usages = alloc::vec::Vec::new();
            let mut features = alloc::vec::Vec::new();
            let mut inputs = alloc::vec::Vec::new();
            while offset < descriptor.len() {
                let prefix = descriptor[offset];
                offset += 1;
                let bytes = match prefix & 3 {
                    3 => 4,
                    n => usize::from(n),
                };
                let mut value = 0u32;
                for index in 0..bytes {
                    value |= u32::from(descriptor[offset + index]) << (index * 8);
                }
                offset += bytes;
                let kind = (prefix >> 2) & 3;
                let tag = prefix >> 4;
                match (kind, tag) {
                    (1, 1) => minimum = value,
                    (2, 0) => usages.push(value),
                    (0, 8 | 11) if value & 3 == 0 => {
                        assert_eq!(minimum, 0, "array indices start at logical minimum");
                        if tag == 8 {
                            inputs.push(usages.clone());
                        } else {
                            features.push(usages.clone());
                        }
                    }
                    _ => (),
                }
                if kind == 0 {
                    usages.clear();
                }
            }
            assert_eq!(features[0][usize::from(CONNECTION_INTEGRATED)], 0x830);
            assert_eq!(features[1][usize::from(REPORTING_ALL_EVENTS)], 0x841);
            assert_eq!(features[2][usize::from(POWER_D0)], 0x851);
            assert_eq!(features[3][usize::from(STATE_INITIALIZING)], 0x804);
            assert_eq!(inputs[0][usize::from(STATE_READY)], 0x801);
            assert_eq!(inputs[1][usize::from(EVENT_DATA_UPDATED)], 0x813);
            assert_eq!(inputs[1][usize::from(EVENT_POLL_RESPONSE)], 0x814);
        }
    }
    #[test]
    fn signed_axis_descriptors_admit_positive_and_negative_firmware_values() {
        for sensor in [
            Sensor::Accelerometer,
            Sensor::Gyroscope,
            Sensor::Magnetometer,
        ] {
            let descriptor = sensor.report_descriptor().unwrap();
            let (mut offset, mut minimum, mut maximum, mut size, mut axes) = (0, 0, 0, 0, 0);
            while offset < descriptor.len() {
                let prefix = descriptor[offset];
                offset += 1;
                let bytes = match prefix & 3 {
                    3 => 4,
                    n => usize::from(n),
                };
                let mut value = 0u32;
                for index in 0..bytes {
                    value |= u32::from(descriptor[offset + index]) << (index * 8);
                }
                offset += bytes;
                match ((prefix >> 2) & 3, prefix >> 4) {
                    (1, 1) => minimum = value,
                    (1, 2) => maximum = value,
                    (1, 7) => size = value,
                    (0, 8) if value & 3 == 2 && size == 32 => {
                        assert!((minimum as i32) <= i32::MIN / 1000);
                        assert!((maximum as i32) >= i32::MAX / 1000);
                        axes += 1;
                    }
                    _ => (),
                }
            }
            assert!(axes >= 3);
            let mut feature = [0; 21];
            sensor.feature_report(&mut feature).unwrap();
            assert_eq!(u16::from_le_bytes(feature[11..13].try_into().unwrap()), 128);
            assert_eq!(u16::from_le_bytes(feature[13..15].try_into().unwrap()), 127);
        }
    }
}
