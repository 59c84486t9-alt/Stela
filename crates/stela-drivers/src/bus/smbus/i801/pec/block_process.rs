// SPDX-License-Identifier: GPL-2.0-or-later
// Adapted from Linux i2c-i801.c, cc9de5d4b5ab6459f5774946aa3195ad51236fa8.
// Copyright (c) 1998-2002 Frodo Looijaard, Philip Edelbrock, Mark D. Studebaker;
// (c) 2007-2014 Jean Delvare; (c) 2010 Intel Corporation, David Woodhouse.
//! One E32B request/repeated-read exchange, optionally covered by hardware PEC.
use super::*;

impl<R: Registers, T: Timer> I801<R, T> {
    /// The kept controller checks capability, count and buffer-mode policy
    /// before calling this; its final configuration guard still owns publication.
    pub(in crate::bus::smbus::i801) fn block_process_until(
        &mut self,
        address: Address,
        command: u8,
        request: &[u8],
        pec: bool,
        start: u64,
    ) -> Result<Block, Error> {
        if !self.ready {
            return Err(ErrorKind::NeedsReset.into());
        }
        if let Err(error) = self.prepare() {
            if error.kind == ErrorKind::BufferModeRejected {
                self.ready = false;
            }
            return Err(error);
        }
        let auxiliary = self.registers.read8(AUX_CONTROL);
        let mut response = Block::default();
        let transfer = (|| {
            if self.registers.read8(AUX_STATUS) & AUX_CRC_ERROR != 0 {
                return Err(ErrorKind::PecStatusStuck.into());
            }
            let enabled = auxiliary | AUX_BUFFER | if pec { AUX_CRC } else { 0 };
            self.registers.write8(AUX_CONTROL, enabled);
            if self.registers.read8(AUX_CONTROL) != enabled {
                return Err(ErrorKind::PecModeRejected.into());
            }
            self.set_target(address, false, Some(command));
            self.registers.write8(HOST_DATA0, request.len() as u8);
            self.registers.read8(HOST_CONTROL);
            for &byte in request {
                self.registers.write8(BLOCK_DATA, byte);
            }
            self.start_transfer(PROTOCOL_BLOCK_PROCESS_CALL, start)?;
            self.wait(start, Phase::Completion)?;
            let count = usize::from(self.registers.read8(HOST_DATA0));
            if !(1..=MAX_BLOCK).contains(&count) {
                return Err(Self::error(
                    ErrorKind::InvalidBlockLength(count),
                    self.registers.read8(HOST_STATUS),
                ));
            }
            self.registers.read8(HOST_CONTROL);
            for byte in &mut response.bytes[..count] {
                *byte = self.registers.read8(BLOCK_DATA);
            }
            response.length = count as u8;
            Ok(())
        })();
        self.finish_pec(transfer.err(), auxiliary)?;
        self.completed_deadline(start)?;
        Ok(response)
    }
}
