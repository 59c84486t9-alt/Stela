// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2003-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Gen2 host-command wire preparation from iwl-trans.c, fw/api/cmdhdr.h and
//! pcie/gen1_2/tx-gen2.c. Encoding is not publication or command completion.
use super::context::{Region, crosses_4g_boundary};
use alloc::vec::Vec;

pub const TFD_BYTES: usize = 256;
pub const FIRST_TB_BYTES: usize = 20;
/// One owned contiguous command body under the existing32KiB allocator profile.
pub const MAX_PAYLOAD_BYTES: usize = 32760;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Id {
    pub group: u8,
    pub opcode: u8,
    pub version: u8,
}
impl Id {
    /// Wide-header MVM translates legacy group0 to always-long group1, except
    /// REPLY_ERROR. Version bits remain unchanged, as DEF_ID(cmd->id) does.
    pub fn wire(self) -> Self {
        if self.group == 0 && !(self.opcode == 2 && self.version == 0) {
            Self { group: 1, ..self }
        } else {
            self
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    PayloadSize,
    Queue,
    BufferCount,
    BufferLength,
    Address,
    Boundary,
    Split,
}
#[derive(Debug)]
pub struct Command {
    id: Id,
    sequence: u16,
    bytes: Vec<u8>,
}
impl Command {
    /// Caller selects the actual negotiated command API. No missing command
    /// version is replaced with a guessed default here. queue/index are the
    /// source queue/host write pointer; only its low8 bits enter the sequence.
    pub fn encode(id: Id, queue: u8, index: u16, payload: &[u8]) -> Result<Self, Error> {
        if queue > 31 {
            return Err(Error::Queue);
        }
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::PayloadSize);
        }
        let id = id.wire();
        let sequence = (u16::from(queue) << 8) | (index & 0xff);
        let mut bytes = Vec::with_capacity(8 + payload.len());
        bytes.extend([id.opcode, id.group]);
        bytes.extend(sequence.to_le_bytes());
        bytes.extend((payload.len() as u16).to_le_bytes());
        bytes.extend([0, id.version]);
        bytes.extend(payload);
        Ok(Self {
            id,
            sequence,
            bytes,
        })
    }
    pub fn id(&self) -> Id {
        self.id
    }
    pub fn sequence(&self) -> u16 {
        self.sequence
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// TB0 is actual coherent bidirectional DMA, up to20 copied header/body
    /// bytes. The remaining command bytes use a separate ToDevice mapping.
    pub fn first_tb(&self) -> &[u8] {
        &self.bytes[..self.bytes.len().min(FIRST_TB_BYTES)]
    }
    pub fn remainder(&self) -> &[u8] {
        &self.bytes[self.bytes.len().min(FIRST_TB_BYTES)..]
    }
    /// Match exact lengths to this command, with no fabricated padding/TB.
    /// These Regions are serialization inputs, never mapping/visibility proof.
    pub fn tfd(&self, first: Region, remainder: Option<Region>) -> Result<Tfd, Error> {
        if first.bytes != self.first_tb().len() {
            return Err(Error::Split);
        }
        match (self.remainder().is_empty(), remainder) {
            (true, None) => Tfd::encode(&[first]),
            (false, Some(rest)) if rest.bytes == self.remainder().len() => {
                Tfd::encode(&[first, rest])
            }
            _ => Err(Error::Split),
        }
    }
}
#[derive(Debug)]
pub struct Tfd {
    bytes: [u8; TFD_BYTES],
}
impl Tfd {
    /// Exact iwl_tfh_tfd: LE16 count,25 packed {LE16 len,LE64 address}
    /// entries and the trailing reserved word. No alignment is invented for a
    /// TB address; actual streaming offsets need not be page aligned.
    pub fn encode(regions: &[Region]) -> Result<Self, Error> {
        if regions.is_empty() || regions.len() > 25 {
            return Err(Error::BufferCount);
        }
        let mut bytes = [0; TFD_BYTES];
        bytes[..2].copy_from_slice(&(regions.len() as u16).to_le_bytes());
        for (index, region) in regions.iter().enumerate() {
            if region.bytes == 0 || region.bytes > u16::MAX as usize {
                return Err(Error::BufferLength);
            }
            if region.address.checked_add(region.bytes as u64).is_none() {
                return Err(Error::Address);
            }
            if crosses_4g_boundary(region.address, region.bytes as u16) {
                return Err(Error::Boundary);
            }
            let at = 2 + index * 10;
            bytes[at..at + 2].copy_from_slice(&(region.bytes as u16).to_le_bytes());
            bytes[at + 2..at + 10].copy_from_slice(&region.address.to_le_bytes());
        }
        Ok(Self { bytes })
    }
    pub fn bytes(&self) -> &[u8; TFD_BYTES] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_wide_header_legacy_conversion_sequence_and_real_twenty_byte_split() {
        for len in (0..=129).chain([316, 317, MAX_PAYLOAD_BYTES]) {
            let payload: Vec<_> = (0..len).map(|n| n as u8).collect();
            let command = Command::encode(
                Id {
                    group: 0,
                    opcode: 0x80,
                    version: 7,
                },
                31,
                0x12ab,
                &payload,
            )
            .unwrap();
            assert_eq!(
                command.id(),
                Id {
                    group: 1,
                    opcode: 0x80,
                    version: 7
                }
            );
            assert_eq!(command.sequence(), 0x1fab);
            assert_eq!(
                &command.bytes()[..8],
                &[0x80, 1, 0xab, 0x1f, len as u8, (len >> 8) as u8, 0, 7]
            );
            assert_eq!(&command.bytes()[8..], payload);
            assert_eq!(command.first_tb().len(), (len + 8).min(20));
            assert_eq!(
                [command.first_tb(), command.remainder()].concat(),
                command.bytes()
            );
            let first = Region {
                address: 0x110000,
                bytes: command.first_tb().len(),
            };
            let rest = (!command.remainder().is_empty()).then_some(Region {
                address: 0x120000,
                bytes: command.remainder().len(),
            });
            let tfd = command.tfd(first, rest).unwrap();
            assert_eq!(
                u16::from_le_bytes(tfd.bytes()[..2].try_into().unwrap()),
                if rest.is_some() { 2 } else { 1 }
            );
            assert!(
                command
                    .tfd(
                        Region {
                            bytes: first.bytes + 1,
                            ..first
                        },
                        rest
                    )
                    .is_err()
            );
            if let Some(rest) = rest {
                assert!(command.tfd(first, None).is_err());
                assert!(
                    command
                        .tfd(
                            first,
                            Some(Region {
                                bytes: rest.bytes + 1,
                                ..rest
                            })
                        )
                        .is_err()
                );
            } else {
                assert!(
                    command
                        .tfd(
                            first,
                            Some(Region {
                                address: 0x120000,
                                bytes: 1
                            })
                        )
                        .is_err()
                );
            }
        }
        assert_eq!(
            Id {
                group: 0,
                opcode: 2,
                version: 0
            }
            .wire()
            .group,
            0
        );
        assert_eq!(
            Id {
                group: 0,
                opcode: 2,
                version: 1
            }
            .wire()
            .group,
            1
        );
        assert_eq!(
            Command::encode(
                Id {
                    group: 5,
                    opcode: 3,
                    version: 1
                },
                32,
                0,
                &[]
            )
            .unwrap_err(),
            Error::Queue
        );
        assert_eq!(
            Command::encode(
                Id {
                    group: 5,
                    opcode: 3,
                    version: 1
                },
                0,
                0,
                &vec![0; MAX_PAYLOAD_BYTES + 1]
            )
            .unwrap_err(),
            Error::PayloadSize
        );
    }
    #[test]
    fn packed_tfh_entries_full_width_unaligned_iovas_reserved_zero_and_refusals() {
        for count in 1..=25 {
            let regions: Vec<_> = (0..count)
                .map(|i| Region {
                    address: 0x123400000003 + i as u64 * 0x10000,
                    bytes: 1 + i * 197,
                })
                .collect();
            let tfd = Tfd::encode(&regions).unwrap();
            for (i, region) in regions.iter().enumerate() {
                let at = 2 + i * 10;
                assert_eq!(
                    u16::from_le_bytes(tfd.bytes()[at..at + 2].try_into().unwrap()) as usize,
                    region.bytes
                );
                assert_eq!(
                    u64::from_le_bytes(tfd.bytes()[at + 2..at + 10].try_into().unwrap()),
                    region.address
                );
            }
            assert!(tfd.bytes()[2 + count * 10..].iter().all(|b| *b == 0));
        }
        for regions in [
            vec![],
            vec![
                Region {
                    address: 0,
                    bytes: 1
                };
                26
            ],
        ] {
            assert_eq!(Tfd::encode(&regions).unwrap_err(), Error::BufferCount);
        }
        for bytes in [0, 65536] {
            assert_eq!(
                Tfd::encode(&[Region {
                    address: 0x100000,
                    bytes
                }])
                .unwrap_err(),
                Error::BufferLength
            );
        }
        assert_eq!(
            Tfd::encode(&[Region {
                address: u64::MAX - 3,
                bytes: 8
            }])
            .unwrap_err(),
            Error::Address
        );
        for bytes in [16, 17] {
            assert_eq!(
                Tfd::encode(&[Region {
                    address: 0xfffffff0,
                    bytes
                }])
                .unwrap_err(),
                Error::Boundary
            );
        }
        Tfd::encode(&[Region {
            address: 0xfffffff0,
            bytes: 15,
        }])
        .unwrap();
        // An actual attached domain may legitimately assign IOVA0. A TB uses
        // its explicit nonzero length/count, not a null-pointer convention.
        Tfd::encode(&[Region {
            address: 0,
            bytes: 8,
        }])
        .unwrap();
    }
    fn hex(bytes: &[u8]) -> alloc::string::String {
        bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
    }
    #[test]
    #[ignore = "requires pinned unchanged Linux command helper oracle; see THIRD_PARTY.md"]
    fn unchanged_linux_command_id_normalization_header_layout_and_tfh_descriptors() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_COMMAND_ORACLE").unwrap()).unwrap();
        assert_eq!(
            hex(&Sha256::digest(&trace)),
            "08104fa131012c135693eea7674fab90cc1dd9092f78d3bb9f8daacd806bd72b"
        );
        let mut lines = core::str::from_utf8(&trace).unwrap().lines();
        assert_eq!(lines.next().unwrap(), "layout 8 4 7 10 256");
        let mut headers = 0;
        let mut descriptors = 0;
        for line in lines {
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields[0] {
                "header" => {
                    let id = Id {
                        group: fields[1].parse().unwrap(),
                        version: fields[2].parse().unwrap(),
                        opcode: fields[3].parse().unwrap(),
                    };
                    let cmd = Command::encode(id, 31, 0xabcd, &vec![0x5a; 0x1234]).unwrap();
                    assert_eq!(hex(&cmd.bytes()[..8]), fields[4]);
                    headers += 1;
                }
                "tfd" => {
                    let count = fields[1].parse::<usize>().unwrap();
                    let regions: Vec<_> = (0..count)
                        .map(|i| Region {
                            address: 0x123400000003 + i as u64 * 0x10000,
                            bytes: 1 + i * 197,
                        })
                        .collect();
                    assert_eq!(hex(Tfd::encode(&regions).unwrap().bytes()), fields[2]);
                    descriptors += 1;
                }
                other => panic!("unexpected oracle record {other}"),
            }
        }
        assert_eq!(headers, 3072);
        assert_eq!(descriptors, 25);
    }
}
