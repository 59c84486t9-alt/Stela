// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2017 Intel Deutschland GmbH
// Copyright (C) 2018-2026 Intel Corporation
//! AX200 ROM self-load context wire format from pcie/ctxt-info.c and
//! pcie/iwl-context-info.h. AX210 uses a distinct gen3 context/IML protocol.
//!
//! This encoder neither allocates nor publishes DMA. All addresses must come
//! from retained device-domain mappings, payload copies and RX descriptors must
//! be visible before the context doorbell, and rings/paging must remain pinned
//! until their actual hardware completion. A valid layout is not radio readiness.
use super::{
    firmware::{Family, SelfLoadPlan},
    identity::Profile,
};

pub const CONTEXT_BYTES: usize = 1792;
const IMAGE_ENTRIES: usize = 64;
const MAX_CHUNK: usize = 32768;

/// A device IOVA and the exact payload length, not a CPU or physical address.
/// This is serialization input, not a DMA ownership or visibility receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub address: u64,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct Queues {
    /// AX200 MQ free descriptors are 8 bytes each.
    pub free: Region,
    /// AX200 used descriptors are 4 bytes each.
    pub used: Region,
    /// struct iwl_rb_status is 12 bytes.
    pub status: Region,
    /// 32 long TFH TFDs, 256 bytes each.
    pub command: Region,
    pub receive_entries: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Images<'a> {
    pub lmac: &'a [Region],
    pub umac: &'a [Region],
    pub paging: &'a [Region],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Gen3Required,
    FirmwareApi,
    QueueSize,
    ImageCount,
    PayloadLength,
    Address,
    Alignment,
    FourGiBoundary,
    AliasedRegion,
}

/// Retains the donor's *end-exclusive* check: a transfer ending exactly on a
/// 4GiB boundary is hazardous too. Addition overflow is always refused.
pub fn crosses_4g_boundary(address: u64, bytes: u16) -> bool {
    address
        .checked_add(u64::from(bytes))
        .is_none_or(|end| address >> 32 != end >> 32)
}

pub(super) fn validate(region: Region, expected: usize, alignment: u64) -> Result<(), Error> {
    if region.bytes != expected || expected == 0 || expected > u16::MAX as usize {
        return Err(Error::PayloadLength);
    }
    if region.address == 0 || region.address.checked_add(expected as u64).is_none() {
        return Err(Error::Address);
    }
    if !region.address.is_multiple_of(alignment) {
        return Err(Error::Alignment);
    }
    if crosses_4g_boundary(region.address, expected as u16) {
        return Err(Error::FourGiBoundary);
    }
    Ok(())
}

/// The AX200 context format fixes command queue size at 32 entries and uses
/// 4KiB RX buffers. Other receive-buffer sizes require their own transport
/// configuration; this does not silently select a fallback.
#[derive(Debug)]
pub struct Ax200Context {
    bytes: [u8; CONTEXT_BYTES],
}

impl Ax200Context {
    pub fn encode(
        profile: &Profile,
        plan: &SelfLoadPlan<'_>,
        queues: Queues,
        images: Images<'_>,
    ) -> Result<Self, Error> {
        if profile.family() != Family::Ax200 {
            return Err(Error::Gen3Required);
        }
        if plan.firmware_api() != Family::Ax200.firmware_api() {
            return Err(Error::FirmwareApi);
        }
        let entries = usize::from(queues.receive_entries);
        if !(8..=2048).contains(&entries) || !entries.is_power_of_two() {
            return Err(Error::QueueSize);
        }
        validate(queues.free, entries * 8, 256)?;
        validate(queues.used, entries * 4, 256)?;
        validate(queues.status, 12, 16)?;
        validate(queues.command, 32 * 256, 256)?;
        let groups = [
            (plan.umac(), images.umac, 192),
            (plan.lmac(), images.lmac, 704),
            (plan.paging(), images.paging, 1216),
        ];
        for (sections, regions, _) in groups {
            if sections.len() != regions.len()
                || regions.is_empty()
                || regions.len() > IMAGE_ENTRIES
            {
                return Err(Error::ImageCount);
            }
            for (section, region) in sections.iter().zip(regions) {
                if section.data.len() > MAX_CHUNK {
                    return Err(Error::PayloadLength);
                }
                validate(*region, section.data.len(), 4)?;
            }
        }
        // Reject aliases between queues and sections, including within a bank.
        // Checked above: every span has a nonzero length and a nonwrapping end.
        let all = [queues.free, queues.used, queues.status, queues.command];
        let regions = all
            .iter()
            .chain(images.umac)
            .chain(images.lmac)
            .chain(images.paging);
        for (index, a) in regions.clone().enumerate() {
            for b in regions.clone().skip(index + 1) {
                if a.address < b.address + b.bytes as u64 && b.address < a.address + a.bytes as u64
                {
                    return Err(Error::AliasedRegion);
                }
            }
        }
        let mut bytes = [0; CONTEXT_BYTES];
        bytes[..2].copy_from_slice(&(profile.observed().hardware_revision as u16).to_le_bytes());
        bytes[4..6].copy_from_slice(&((CONTEXT_BYTES / 4) as u16).to_le_bytes());
        // LONG_TFD | FIELD_PREP(RB_CB_SIZE, ilog2(entries)) |
        // FIELD_PREP(RB_SIZE, RB_SIZE_4K). Reserved/debug/PNVM fields stay zero.
        let flags = 0x100 | (entries.ilog2() << 4) | (4 << 9);
        bytes[8..12].copy_from_slice(&flags.to_le_bytes());
        for (at, region) in [
            (24, queues.free),
            (32, queues.used),
            (40, queues.status),
            (48, queues.command),
        ] {
            bytes[at..at + 8].copy_from_slice(&region.address.to_le_bytes());
        }
        bytes[56] = 2; // ilog2(IWL_CMD_QUEUE_SIZE=32) - 3
        for (_, regions, base) in groups {
            for (index, region) in regions.iter().enumerate() {
                let at = base + index * 8;
                bytes[at..at + 8].copy_from_slice(&region.address.to_le_bytes());
            }
        }
        Ok(Self { bytes })
    }

    pub fn bytes(&self) -> &[u8; CONTEXT_BYTES] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::super::{firmware::Firmware, identity::Observed};
    use super::*;
    use alloc::vec::Vec;

    fn profile(device: u16) -> Profile {
        Profile::select(Observed {
            vendor: 0x8086,
            device,
            subsystem_vendor: 0x8086,
            subsystem_device: 0x0084,
            pci_revision: 0x1a,
            hardware_revision: if device == 0x2723 { 0x340 } else { 0x420 },
            radio_id: if device == 0x2723 { 0x10a000 } else { 0x10d000 },
        })
        .unwrap()
    }
    fn image() -> Vec<u8> {
        let mut bytes = vec![0; 88];
        bytes[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
        bytes[72..76].copy_from_slice(&(77u32 << 8).to_le_bytes());
        let mut tlv = |kind: u32, data: &[u8]| {
            bytes.extend_from_slice(&kind.to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(data);
            while !bytes.len().is_multiple_of(4) {
                bytes.push(0);
            }
        };
        tlv(27, &2u32.to_le_bytes());
        tlv(32, &4096u32.to_le_bytes());
        for (offset, len) in [
            (0u32, 16),
            (0xffffcccc, 0),
            (0x1000, 16),
            (0xaaaabbbb, 0),
            (0, 16),
            (0x2000, 4096),
        ] {
            let mut data = offset.to_le_bytes().to_vec();
            data.resize(4 + len, 0x5a);
            tlv(19, &data);
        }
        bytes
    }
    fn queues(entries: u16) -> Queues {
        Queues {
            free: Region {
                address: 0x10000,
                bytes: usize::from(entries) * 8,
            },
            used: Region {
                address: 0x20000,
                bytes: usize::from(entries) * 4,
            },
            status: Region {
                address: 0x30000,
                bytes: 12,
            },
            command: Region {
                address: 0x40000,
                bytes: 8192,
            },
            receive_entries: entries,
        }
    }
    #[test]
    fn strict_end_exclusive_erratum_and_overflow() {
        for length in [1, 4, 12, 1792, 32768, 65535] {
            assert!(crosses_4g_boundary(
                (1u64 << 32) - u64::from(length),
                length
            ));
            assert!(!crosses_4g_boundary(
                (1u64 << 32) - u64::from(length) - 1,
                length
            ));
            assert!(crosses_4g_boundary(u64::MAX, length));
        }
    }
    #[test]
    fn exact_wire_offsets_zero_reserved_and_bank_order() {
        let image = image();
        let fw = Firmware::parse(&image).unwrap();
        let plan = fw.self_load_plan().unwrap();
        let lmac = [Region {
            address: 0x50000,
            bytes: 16,
        }];
        let umac = [Region {
            address: 0x60000,
            bytes: 16,
        }];
        let paging = [
            Region {
                address: 0x70000,
                bytes: 16,
            },
            Region {
                address: 0x80000,
                bytes: 4096,
            },
        ];
        let images = Images {
            lmac: &lmac,
            umac: &umac,
            paging: &paging,
        };
        for count in [8, 16, 256, 512, 1024, 2048] {
            let context =
                Ax200Context::encode(&profile(0x2723), &plan, queues(count), images).unwrap();
            let b = context.bytes();
            let d = |at| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
            assert_eq!(&b[..8], &[0x40, 3, 0, 0, 0xc0, 1, 0, 0]);
            assert_eq!(
                u32::from_le_bytes(b[8..12].try_into().unwrap()),
                0x900 | (u32::from(count).ilog2() << 4)
            );
            assert_eq!(
                [d(24), d(32), d(40), d(48)],
                [0x10000, 0x20000, 0x30000, 0x40000]
            );
            assert_eq!(b[56], 2);
            assert_eq!(
                [d(192), d(704), d(1216), d(1224)],
                [0x60000, 0x50000, 0x70000, 0x80000]
            );
            for range in [12..24, 57..192, 200..704, 712..1216, 1232..1792] {
                assert!(b[range].iter().all(|x| *x == 0));
            }
        }
        assert_eq!(
            Ax200Context::encode(&profile(0x2725), &plan, queues(512), images).unwrap_err(),
            Error::Gen3Required
        );
        assert_eq!(
            Ax200Context::encode(&profile(0x2723), &plan, queues(7), images).unwrap_err(),
            Error::QueueSize
        );
        let mut bad = queues(512);
        bad.free.address = 0x60000;
        assert_eq!(
            Ax200Context::encode(&profile(0x2723), &plan, bad, images).unwrap_err(),
            Error::AliasedRegion
        );
        let mut bad = queues(512);
        bad.status.address = 0xfffffff0;
        assert!(Ax200Context::encode(&profile(0x2723), &plan, bad, images).is_ok());
        bad.status.bytes = 16;
        assert_eq!(
            Ax200Context::encode(&profile(0x2723), &plan, bad, images).unwrap_err(),
            Error::PayloadLength
        );
        let mut bad = queues(512);
        bad.free.address = 0xfffff000;
        assert_eq!(
            Ax200Context::encode(&profile(0x2723), &plan, bad, images).unwrap_err(),
            Error::FourGiBoundary
        );
    }

    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_CONTEXT_ORACLE, STELA_IWLWIFI_IMAGES"]
    fn unchanged_linux_context_and_payload_copy_oracle() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let oracle = std::env::var("STELA_IWLWIFI_CONTEXT_ORACLE").expect("oracle trace");
        let image_dir = std::env::var("STELA_IWLWIFI_IMAGES").expect("firmware directory");
        let trace = std::fs::read(oracle).unwrap();
        let hex = |data: &[u8]| -> alloc::string::String {
            data.iter().map(|x| alloc::format!("{x:02x}")).collect()
        };
        assert_eq!(
            hex(&Sha256::digest(&trace)),
            "f4a4f9d6f8493e75ddfda682a4da6efb9cdf7c1fe6989932f508220176ffade0"
        );
        let image =
            std::fs::read(std::path::Path::new(&image_dir).join(Family::Ax200.firmware_name()))
                .unwrap();
        assert_eq!(
            hex(&Sha256::digest(&image)),
            "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
        );
        let firmware = Firmware::parse(&image).unwrap();
        let plan = firmware.self_load_plan().unwrap();
        let text = core::str::from_utf8(&trace).unwrap();
        let mut lines = text.lines();
        assert_eq!(lines.next().unwrap(), "counts 14 15 19");
        let mut contexts = 0;
        let mut boundaries = 0;
        while let Some(line) = lines.next() {
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields[0] {
                "context" => {
                    let entries = fields[1].parse().unwrap();
                    let expected = fields[2];
                    let mut lmac = Vec::new();
                    let mut umac = Vec::new();
                    let mut paging = Vec::new();
                    for (bank, sections, regions) in [
                        ("L", plan.lmac(), &mut lmac),
                        ("U", plan.umac(), &mut umac),
                        ("P", plan.paging(), &mut paging),
                    ] {
                        for (index, section) in sections.iter().enumerate() {
                            let row: Vec<_> = lines.next().unwrap().split_whitespace().collect();
                            assert_eq!(&row[..3], &["section", fields[1], bank]);
                            assert_eq!(row[3].parse::<usize>().unwrap(), index);
                            assert_eq!(row[4].parse::<usize>().unwrap(), section.data.len());
                            let fnv = section.data.iter().fold(0xcbf29ce484222325u64, |h, b| {
                                (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
                            });
                            assert_eq!(u64::from_str_radix(row[5], 16).unwrap(), fnv);
                            regions.push(Region {
                                address: u64::from_str_radix(row[6], 16).unwrap(),
                                bytes: section.data.len(),
                            });
                        }
                    }
                    let context = Ax200Context::encode(
                        &profile(0x2723),
                        &plan,
                        queues(entries),
                        Images {
                            lmac: &lmac,
                            umac: &umac,
                            paging: &paging,
                        },
                    )
                    .unwrap();
                    assert_eq!(hex(context.bytes()), expected);
                    contexts += 1;
                }
                "boundary" => {
                    let len = fields[1].parse::<u16>().unwrap();
                    let address = (1u64 << 32) - u64::from(len);
                    let results = [address - 1, address, address + 1].map(|a| {
                        if crosses_4g_boundary(a, len) {
                            b'1'
                        } else {
                            b'0'
                        }
                    });
                    assert_eq!(results, fields[2].as_bytes());
                    boundaries += 3;
                }
                other => panic!("unexpected oracle record {other}"),
            }
        }
        assert_eq!(contexts, 9);
        assert_eq!(boundaries, 196605);
    }
}
