// SPDX-License-Identifier: GPL-2.0-only
//! SCSI command effects on the modeled target and its media.
use super::*;

impl Target {
    pub(super) fn prepare(&mut self, iu: &[u8]) -> Reply {
        let lun = Lun::from_bytes(iu[8..16].try_into().unwrap());
        let cdb = &iu[16..];
        if cdb[0] == crate::usb::storage::scsi::MODE_SENSE_6
            && cdb[2] == crate::usb::storage::scsi::CACHING_PAGE
            && let Some(cache) = self.cache_reply.take()
        {
            let (sense, data) = match cache {
                CacheReply::Replace {
                    sense,
                    blocks,
                    read_only,
                } => {
                    let media = self
                        .media
                        .iter_mut()
                        .find(|media| media.lun == lun)
                        .unwrap();
                    media.blocks = blocks;
                    media.read_only = read_only;
                    media.empty = (sense >> 8) & 0xff == 0x3a;
                    (Some(sense), Vec::new())
                }
                CacheReply::Sense(sense) => (Some(sense), Vec::new()),
                CacheReply::Data(data) => (None, data),
            };
            return Reply {
                requested: usize::from(cdb[4]),
                input: true,
                data,
                sense,
                wrong_tag: false,
            };
        }
        if cdb[..10] == [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]
            && let Some((unit, blocks)) = self.block_zero_change
            && unit == lun
        {
            self.block_zero_change = None;
            self.media[0].blocks = blocks;
            return Reply {
                requested: 0,
                input: true,
                data: Vec::new(),
                sense: Some(0x063f0e),
                wrong_tag: false,
            };
        }
        let media = self.media.iter().find(|media| media.lun == lun);
        let mut reply = Reply {
            requested: 0,
            input: true,
            data: Vec::new(),
            sense: None,
            wrong_tag: self.poison_lun == Some(lun),
        };
        if cdb[0] == 0
            && let Some(sense) = self.unit_attention.take()
        {
            reply.sense = Some(sense);
            return reply;
        }
        match cdb[0] {
            0x12 => {
                assert_eq!(&cdb[..6], &[0x12, 0, 0, 0, 36, 0]);
                reply.requested = 36;
                reply.data = vec![0; 36];
                // RMB: the target's medium can be removed and replaced.
                reply.data[1] = 0x80;
                reply.data[2] = media.map_or(6, |media| media.version);
                reply.data[4] = 31;
                reply.data[8..16].copy_from_slice(b"STELAUSB");
                reply.data[16..32].copy_from_slice(b"UAS TARGET MODEL");
                if media.is_none() {
                    reply.data[0] = 0x7f;
                }
            }
            0xa0 => {
                assert_eq!(&cdb[1..6], &[0; 5]);
                assert_eq!(&cdb[10..12], &[0; 2]);
                reply.requested = u32::from_be_bytes(cdb[6..10].try_into().unwrap()) as usize;
                if self.report_attention > 0 {
                    self.report_attention -= 1;
                    if let Some(blocks) = self.report_change_blocks.take() {
                        self.media[0].blocks = blocks;
                    }
                    reply.sense = Some(0x063f0e);
                } else if self.report_illegal {
                    reply.sense = Some(0x052000);
                } else if let Some(bytes) = &self.report_override {
                    reply.data = bytes.clone();
                } else {
                    reply.data = vec![0; 8];
                    reply.data[..4]
                        .copy_from_slice(&((self.reported.len() * 8) as u32).to_be_bytes());
                    for lun in &self.reported {
                        reply.data.extend_from_slice(&lun.bytes());
                    }
                }
                reply.data.truncate(reply.requested);
            }
            _ => {
                let Some(media) = media else {
                    reply.sense = Some(0x052500);
                    return reply;
                };
                match cdb[0] {
                    0 => {
                        assert_eq!(&cdb[..6], &[0; 6]);
                        if media.empty {
                            reply.sense = Some(0x023a00);
                        }
                    }
                    0x25 => {
                        reply.requested = 8;
                        let last = u32::try_from(media.blocks - 1).unwrap_or(u32::MAX);
                        reply.data.extend_from_slice(&last.to_be_bytes());
                        reply
                            .data
                            .extend_from_slice(&media.block_size.to_be_bytes());
                    }
                    0x9e => {
                        assert_eq!(cdb[1], 0x10);
                        assert_eq!(cdb[13], 32);
                        reply.requested = 32;
                        reply.data = vec![0; 32];
                        reply.data[..8].copy_from_slice(&(media.blocks - 1).to_be_bytes());
                        reply.data[8..12].copy_from_slice(&media.block_size.to_be_bytes());
                    }
                    0x1a => {
                        assert!(matches!(cdb[2], 0x08 | 0x3f));
                        assert_eq!(
                            usize::from(cdb[4]),
                            crate::usb::storage::scsi::MODE_SENSE_BYTES
                        );
                        let protect = if media.read_only { 0x80 } else { 0 };
                        // A write-back Caching page follows the header.
                        reply.data = vec![7, 0, protect, 0, 0x08, 0x12, 0x04, 0];
                        reply.requested = usize::from(cdb[4]);
                    }
                    0x28 | 0x2a | 0x88 | 0x8a => {
                        let (lba, count) = Self::range(cdb);
                        assert!(
                            lba.checked_add(u64::from(count))
                                .is_some_and(|end| end <= media.blocks)
                        );
                        reply.requested = count as usize * media.block_size as usize;
                        reply.input = matches!(cdb[0], 0x28 | 0x88);
                        if reply.input {
                            reply.data = self
                                .writes
                                .iter()
                                .rev()
                                .find(|(unit, at, bytes)| {
                                    *unit == lun && *at == lba && bytes.len() == reply.requested
                                })
                                .map_or_else(
                                    || vec![media.marker; reply.requested],
                                    |(_, _, bytes)| bytes.clone(),
                                );
                        } else {
                            assert!(!media.read_only, "write reached protected medium");
                        }
                    }
                    0x35 => {
                        assert_eq!(&cdb[..10], &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                        self.flushes.push(lun);
                    }
                    op => panic!("unmodeled discovery/block opcode {op:#x}"),
                }
            }
        }
        reply
    }

    pub(super) fn write(&mut self, iu: &[u8], bytes: Vec<u8>) {
        let lun = Lun::from_bytes(iu[8..16].try_into().unwrap());
        let cdb = &iu[16..];
        assert!(matches!(cdb[0], 0x2a | 0x8a));
        let (lba, _) = Self::range(cdb);
        self.writes.push((lun, lba, bytes));
    }
}
