// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Pure source BIOS LARI/extension wire preparation, not a BIOS observation,
//! trusted source selector, actual command completion or regulatory authority.
use super::super::{command::Id, firmware::Firmware};
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Acpi,
    Uefi,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Value {
    pub value: u32,
    pub source: Source,
    pub revision: u8,
}
/// Unavailable means the actual qualified BIOS selection was exhausted;
/// NotObserved must not be converted to it by missing capture/AML support.
/// These public pure inputs themselves prove neither condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    NotObserved,
    Unavailable,
    Observed(Value),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub dsm: [Observation; 15],
    pub wide_bandwidth: Observation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    Dsm(u8),
    WideBandwidth,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MissingApi,
    Version(u8),
    ExtensionVersion(u8),
    NotObserved(Input),
}
fn observed(input: Input, observation: Observation) -> Result<Option<Value>, Error> {
    match observation {
        Observation::NotObserved => Err(Error::NotObserved(input)),
        Observation::Unavailable => Ok(None),
        Observation::Observed(value) => Ok(Some(value)),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    schema: u8,
    inputs: Inputs,
    words: [u32; 9],
    extension: Option<[u8; 48]>,
    change: Option<Vec<u8>>,
}
impl Plan {
    pub fn prepare(firmware: &Firmware<'_>, radio_id: u32, inputs: Inputs) -> Result<Self, Error> {
        let schema = firmware
            .command_version(12, 1)
            .ok_or(Error::MissingApi)?
            .command_version;
        let bytes = match schema {
            1 => 4,
            6 => 24,
            8 => 28,
            12 => 36,
            other => return Err(Error::Version(other)),
        };
        let extension_version = firmware
            .command_version(12, 8)
            .map_or(0, |v| v.command_version);
        if extension_version > 1 {
            return Err(Error::ExtensionVersion(extension_version));
        }
        let dsm = |index: u8| observed(Input::Dsm(index), inputs.dsm[usize::from(index)]);
        let mut extension = None;
        if extension_version == 1
            && let Some(value) = dsm(4)?
        {
            let mut data = [0; 48];
            data[0] = match value.source {
                Source::Acpi => 1,
                Source::Uefi => 2,
            };
            data[1] = value.revision;
            data[4..8].copy_from_slice(&value.value.to_le_bytes());
            extension = Some(data);
        }
        let mut words = [0u32; 9];
        let rf = (radio_id >> 12) & 0xfff;
        if matches!(rf, 0x10c | 0x10a | 0x108 | 0x105) && dsm(2)?.is_some_and(|v| v.value == 1) {
            words[0] |= 1 << 3;
        }
        if let Some(value) = dsm(1)? {
            words[0] |= match value.value {
                1 => 1 << 1,
                2 => 1 << 2,
                _ => 0,
            };
        }
        if firmware.supports_capability(117) && dsm(4)?.is_none_or(|v| v.value & (1 << 2) != 0) {
            words[0] |= 1 << 7;
        }
        let raw = firmware.supports_capability(129);
        if let Some(value) = dsm(6)? {
            words[2] = if raw { value.value } else { value.value & 0xf };
        }
        if let Some(value) = dsm(7)? {
            words[3] = if raw { value.value } else { value.value & 0x3f };
            if !raw && schema < 12 && !firmware.supports_capability(123) {
                words[3] &= !0x30;
            }
        }
        if let Some(value) = dsm(8)? {
            words[4] = if raw { value.value } else { value.value & 0x7f };
            if !raw && schema < 8 {
                words[4] &= !(1 << 4);
            }
            if !raw && schema < 12 && !firmware.supports_capability(96) {
                words[4] &= 0x1f;
            }
        }
        if let Some(value) = dsm(3)? {
            words[1] = value.value;
        }
        if let Some(value) = dsm(9)? {
            words[5] = if raw {
                value.value
            } else {
                value.value & 0x7ff
            };
        }
        if let Some(value) = dsm(10)? {
            words[6] = if raw {
                value.value
            } else {
                value.value & 0x7ffff0
            };
        }
        if let Some(value) = observed(Input::WideBandwidth, inputs.wide_bandwidth)? {
            words[7] = value.value;
        }
        if let Some(value) = dsm(12)? {
            words[8] = value.value;
        }
        // Exact donor predicate includes fields beyond older payload prefixes.
        // Retain the complete semantic words even when only that prefix sends.
        let change = words.iter().any(|v| *v != 0).then(|| {
            words
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .take(bytes)
                .collect()
        });
        Ok(Self {
            schema,
            inputs,
            words,
            extension,
            change,
        })
    }
    pub fn schema(&self) -> u8 {
        self.schema
    }
    pub fn inputs(&self) -> &Inputs {
        &self.inputs
    }
    pub fn words(&self) -> &[u32; 9] {
        &self.words
    }
    /// Source extension precedes LARI_CONFIG_CHANGE because change triggers
    /// a profile update. Neither encoded request is an execution/ACK receipt.
    pub fn commands(&self) -> impl Iterator<Item = (Id, &[u8])> {
        self.extension
            .iter()
            .map(|data| {
                (
                    Id {
                        group: 12,
                        opcode: 8,
                        version: 0,
                    },
                    data.as_slice(),
                )
            })
            .chain(self.change.iter().map(|data| {
                (
                    Id {
                        group: 12,
                        opcode: 1,
                        version: 0,
                    },
                    data.as_slice(),
                )
            }))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::net::wifi::intel::{command::Command, firmware::Family};
    fn firmware(schema: Option<u8>, extension: u8, caps: u8) -> Vec<u8> {
        let mut b = alloc::vec![0;88];
        b[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
        let mut tlv = |kind: u32, d: &[u8]| {
            b.extend(kind.to_le_bytes());
            b.extend((d.len() as u32).to_le_bytes());
            b.extend(d);
            b.resize(b.len().next_multiple_of(4), 0);
        };
        let mut versions = Vec::new();
        if let Some(v) = schema {
            versions.extend([1, 12, v, 0]);
        }
        if extension != 0 {
            versions.extend([8, 12, extension, 0]);
        }
        if !versions.is_empty() {
            tlv(48, &versions);
        }
        let flags = if caps & 1 != 0 { 1u32 << 21 } else { 0 }
            | if caps & 2 != 0 { 1u32 << 27 } else { 0 }
            | if caps & 4 != 0 { 1 } else { 0 };
        if flags != 0 {
            let mut bytes = 3u32.to_le_bytes().to_vec();
            bytes.extend(flags.to_le_bytes());
            tlv(30, &bytes);
        }
        if caps & 8 != 0 {
            tlv(30, &[4, 0, 0, 0, 2, 0, 0, 0]);
        }
        b
    }
    fn unavailable() -> Inputs {
        Inputs {
            dsm: [Observation::Unavailable; 15],
            wide_bandwidth: Observation::Unavailable,
        }
    }
    fn value(value: u32) -> Observation {
        Observation::Observed(Value {
            value,
            source: Source::Uefi,
            revision: 4,
        })
    }
    fn scene(scene: u32) -> Inputs {
        let masks = [
            0,
            0x7fff,
            0x5555,
            0x2aaa,
            1 << 4,
            1 << 2,
            (1 << 1) | (1 << 4),
            (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 12),
        ];
        let mask = masks[scene as usize % 8];
        let source = if scene % 2 == 1 {
            Source::Uefi
        } else {
            Source::Acpi
        };
        let revision = if source == Source::Uefi { 4 } else { 0 };
        let mut values = core::array::from_fn::<u32, 15, _>(|i| {
            if scene < 8 {
                0
            } else {
                u32::MAX
                    ^ (scene
                        .wrapping_mul(0x01234567)
                        .wrapping_add((i as u32).wrapping_mul(0x10203)))
            }
        });
        values[1] = scene % 4;
        values[2] = scene % 3;
        values[4] = if scene & 1 != 0 { 4 } else { 0 };
        Inputs {
            dsm: core::array::from_fn(|i| {
                if mask & (1 << i) != 0 {
                    Observation::Observed(Value {
                        value: values[i],
                        source,
                        revision,
                    })
                } else {
                    Observation::Unavailable
                }
            }),
            wide_bandwidth: if scene & 4 != 0 {
                Observation::Observed(Value {
                    value: if scene & 8 != 0 { 3 } else { 0 },
                    source,
                    revision,
                })
            } else {
                Observation::Unavailable
            },
        }
    }
    #[test]
    fn missing_observations_never_become_default_china_or_source_success() {
        let b = firmware(Some(6), 0, 1);
        let fw = Firmware::parse(&b).unwrap();
        assert_eq!(
            Plan::prepare(&fw, 0x10a000, unavailable()).unwrap().words()[0],
            1 << 7
        );
        for function in [1, 2, 3, 4, 6, 7, 8, 9, 10, 12] {
            let mut inputs = unavailable();
            inputs.dsm[function] = Observation::NotObserved;
            assert_eq!(
                Plan::prepare(&fw, 0x10a000, inputs),
                Err(Error::NotObserved(Input::Dsm(function as u8)))
            );
        }
        for function in [0, 5, 11, 13, 14] {
            let mut inputs = unavailable();
            inputs.dsm[function] = Observation::NotObserved;
            assert!(Plan::prepare(&fw, 0x10a000, inputs).is_ok());
        }
        let mut inputs = unavailable();
        inputs.wide_bandwidth = Observation::NotObserved;
        assert_eq!(
            Plan::prepare(&fw, 0x10a000, inputs),
            Err(Error::NotObserved(Input::WideBandwidth))
        );
        inputs = unavailable();
        inputs.dsm[2] = Observation::NotObserved;
        assert!(Plan::prepare(&fw, 0x10d000, inputs).is_ok()); // no Indonesia query for GF.
        let b = firmware(Some(8), 0, 0);
        let fw = Firmware::parse(&b).unwrap();
        inputs = unavailable();
        inputs.dsm[4] = Observation::NotObserved;
        assert!(Plan::prepare(&fw, 0x10d000, inputs).is_ok()); // neither extension nor China capability reads it.
    }
    #[test]
    fn exact_extension_order_zero_reserved_and_unknown_schemas_are_explicit() {
        for schema in 0..=255 {
            let b = firmware(Some(schema), 1, 15);
            let fw = Firmware::parse(&b).unwrap();
            let result = Plan::prepare(&fw, 0x10a000, scene(9));
            if [1, 6, 8, 12].contains(&schema) {
                let plan = result.unwrap();
                let commands: Vec<_> = plan.commands().collect();
                assert_eq!((commands[0].0.opcode, commands[1].0.opcode), (8, 1));
                assert_eq!(&commands[0].1[..8], &[2, 4, 0, 0, 4, 0, 0, 0]);
                assert!(commands[0].1[8..].iter().all(|b| *b == 0));
                assert_eq!(
                    commands[1].1.len(),
                    match schema {
                        1 => 4,
                        6 => 24,
                        8 => 28,
                        12 => 36,
                        _ => unreachable!(),
                    }
                );
                for (id, bytes) in commands {
                    assert_eq!(Command::encode(id, 0, 0, bytes).unwrap().bytes()[7], 0);
                }
            } else {
                assert_eq!(result, Err(Error::Version(schema)));
            }
        }
        let b = firmware(None, 1, 0);
        let fw = Firmware::parse(&b).unwrap();
        assert_eq!(Plan::prepare(&fw, 0, unavailable()), Err(Error::MissingApi));
        let b = firmware(Some(8), 2, 0);
        let fw = Firmware::parse(&b).unwrap();
        assert_eq!(
            Plan::prepare(&fw, 0, unavailable()),
            Err(Error::ExtensionVersion(2))
        );
        // Exact source predicate can send an old all-zero prefix when only a
        // later semantic field is nonzero; retain that distinction explicitly.
        let b = firmware(Some(1), 0, 0);
        let fw = Firmware::parse(&b).unwrap();
        let mut inputs = unavailable();
        inputs.wide_bandwidth = value(3);
        let plan = Plan::prepare(&fw, 0, inputs).unwrap();
        assert_eq!(plan.words()[7], 3);
        assert_eq!(plan.commands().next().unwrap().1, [0; 4]);
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
    fn actual_images_select_source_lari6_and_lari8_with_frozen_extension() {
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        for family in [Family::Ax200, Family::Ax210] {
            let b =
                std::fs::read(std::path::Path::new(&root).join(family.firmware_name())).unwrap();
            let fw = Firmware::parse(&b).unwrap();
            let inputs = scene(9);
            let plan = Plan::prepare(
                &fw,
                if family == Family::Ax200 {
                    0x10a000
                } else {
                    0x10d000
                },
                inputs,
            )
            .unwrap();
            assert_eq!(plan.schema(), if family == Family::Ax200 { 6 } else { 8 });
            let commands: Vec<_> = plan.commands().collect();
            assert_eq!(commands.len(), if family == Family::Ax200 { 1 } else { 2 });
            assert_eq!(
                commands.last().unwrap().1.len(),
                if family == Family::Ax200 { 24 } else { 28 }
            );
            assert_eq!(plan.inputs(), &inputs);
        }
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_LARI_ORACLE"]
    fn unchanged_linux_lari_full_preparation_and_ordered_send_oracle() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_LARI_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "855f0563097d905db9f44bf07c4ce4231659352543d53ecf828ea0853c91c40f"
        );
        let hex = |v: &[u8]| -> std::string::String {
            v.iter().map(|b| std::format!("{b:02x}")).collect()
        };
        let mut cases = 0;
        for line in core::str::from_utf8(&bytes).unwrap().lines() {
            let f: Vec<_> = line.split_whitespace().collect();
            assert_eq!(f[0], "case");
            let schema = f[1].parse().unwrap();
            let extension = f[2].parse().unwrap();
            let caps = f[3].parse().unwrap();
            let radio = f[4].parse().unwrap();
            let inputs = scene(f[5].parse().unwrap());
            let b = firmware(Some(schema), extension, caps);
            let fw = Firmware::parse(&b).unwrap();
            let plan = Plan::prepare(&fw, radio, inputs).unwrap();
            let words: Vec<u8> = plan.words().iter().flat_map(|v| v.to_le_bytes()).collect();
            assert_eq!(hex(&words), f[8], "{line}");
            assert_eq!(u8::from(plan.change.is_none()), f[6].parse::<u8>().unwrap());
            let size = f[7].parse::<usize>().unwrap();
            assert_eq!(
                size,
                match schema {
                    1 => 4,
                    6 => 24,
                    8 => 28,
                    12 => 36,
                    _ => unreachable!(),
                }
            );
            let count = f[9].parse::<usize>().unwrap();
            let commands: Vec<_> = plan.commands().collect();
            assert_eq!(commands.len(), count, "{line}");
            for (i, (id, data)) in commands.iter().enumerate() {
                let at = 10 + i * 3;
                assert_eq!(
                    u32::from(id.group) * 256 + u32::from(id.opcode),
                    f[at].parse::<u32>().unwrap()
                );
                assert_eq!(data.len(), f[at + 1].parse::<usize>().unwrap());
                assert_eq!(hex(data), f[at + 2], "{line}");
            }
            cases += 1;
        }
        assert_eq!(cases, 4 * 2 * 16 * 6 * 16);
    }
}
