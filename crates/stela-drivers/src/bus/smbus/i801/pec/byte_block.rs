// SPDX-License-Identifier: GPL-2.0-or-later
// Adapted from Linux i2c-i801.c, cc9de5d4b5ab6459f5774946aa3195ad51236fa8.
// Copyright (c) 1998-2002 Frodo Looijaard, Philip Edelbrock, Mark D. Studebaker;
// (c) 2007-2014 Jean Delvare; (c) 2010 Intel Corporation, David Woodhouse.
//! Payload handshakes while hardware generates/verifies the packet CRC.
use super::*;

impl<R: Registers, T: Timer> I801<R, T> {
    /// The caller has already enabled CRC and started this block transaction.
    /// Return only private payload; the common PEC finish and actual PCI guard
    /// still own cleanup, the final deadline and caller publication.
    pub(super) fn pec_block_bytes(
        &mut self,
        start: u64,
        write: Option<&[u8]>,
    ) -> Result<Block, Error> {
        let mut result = Block::default();
        let mut count = write.map_or(MAX_BLOCK + 1, <[u8]>::len);
        let mut index = 0;
        while index < count {
            self.wait(start, Phase::ByteDone)?;
            if let Some(bytes) = write {
                if index + 1 < count {
                    self.registers.write8(BLOCK_DATA, bytes[index + 1]);
                }
            } else {
                if index == 0 {
                    count = usize::from(self.registers.read8(HOST_DATA0));
                    if !(1..=MAX_BLOCK).contains(&count) {
                        return Err(Self::error(
                            ErrorKind::InvalidBlockLength(count),
                            self.registers.read8(HOST_STATUS),
                        ));
                    }
                    result.length = count as u8;
                }
                result.bytes[index] = self.registers.read8(BLOCK_DATA);
                if index + 2 == count {
                    self.registers
                        .write8(HOST_CONTROL, PROTOCOL_BLOCK | LAST_BYTE);
                }
            }
            self.registers.write8(HOST_STATUS, BYTE_DONE);
            index += 1;
        }
        self.wait(start, Phase::Completion)?;
        Ok(result)
    }
}
