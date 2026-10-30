// SPDX-License-Identifier: GPL-2.0-or-later
// I801 hardware PEC adapted from Linux i2c-i801.c at
// a804c5742bff224d4cb4d25dd383554d598be32b (see bus/THIRD_PARTY.md).
// Copyright (c) 1998-2002 Frodo Looijaard, Philip Edelbrock,
// Mark D. Studebaker; (c) 2007-2014 Jean Delvare; (c) 2010 Intel Corporation,
// David Woodhouse.
//! Hardware CRC is available only through the configuration owner.
//!
//! The pinned donor enables AUXCTL.CRC, not HOSTCNT.PEC_EN. Generation and
//! verification belong to the controller; payload buffers contain no software
//! CRC byte. This finite implementation admits byte/byte-data/word-data and
//! process calls and E32B or BYTE_DONE SMBus blocks on ICH4+ profiles.
//! Process-call sequencing also follows the unchanged simple/access functions
//! at cc9de5d4b5ab6459f5774946aa3195ad51236fa8; prior evidence stays separate.
use super::*;
mod block_process;
mod byte_block;

impl<R: Registers, T: Timer> I801<R, T> {
    pub(super) fn pec_supported(&self, transaction: &Transaction<'_>) -> Result<(), Error> {
        // At the pinned source all exact PCI profiles with E32B also carry
        // FEATURE_SMBUS_PEC (ICH4+); ICH3 and earlier do not.
        if !self.info.has_hardware_pec() {
            return Err(ErrorKind::UnsupportedPec.into());
        }
        if let Transaction::WriteBlock { data, .. } = transaction
            && !(1..=MAX_BLOCK).contains(&data.len())
        {
            return Err(ErrorKind::InvalidBlockLength(data.len()).into());
        }
        Ok(())
    }

    fn finish_pec(&mut self, mut error: Option<Error>, auxiliary: u8) -> Result<(), Error> {
        // Snapshot both original status registers before finish clears them.
        let status = self.registers.read8(HOST_STATUS);
        let crc = self.registers.read8(AUX_STATUS);
        // Preserve timeout/malformed-transfer causes. Hardware precedence uses
        // samples, never an invented OR of two status bytes:
        // BUS_ERR > DEV_ERR (+CRCE means bad packet) > FAILED. A CRCE-only
        // completion also refuses publication even without the required DEV_ERR.
        if error.is_none()
            || error.as_ref().is_some_and(|e| {
                matches!(
                    e.kind,
                    ErrorKind::ArbitrationLost | ErrorKind::Device | ErrorKind::Failed
                )
            })
        {
            let before = error.as_ref().map_or(0, |e| e.status);
            let sample = |mask| {
                if status & mask != 0 {
                    Some(status)
                } else if before & mask != 0 {
                    Some(before)
                } else {
                    None
                }
            };
            error = if let Some(raw) = sample(BUS_ERR) {
                Some(Self::error(ErrorKind::ArbitrationLost, raw))
            } else if crc & AUX_CRC_ERROR != 0 {
                Some(Self::error(
                    ErrorKind::PecMismatch {
                        auxiliary_status: crc,
                    },
                    sample(DEV_ERR).unwrap_or(status),
                ))
            } else if let Some(raw) = sample(DEV_ERR) {
                Some(Self::error(ErrorKind::Device, raw))
            } else {
                sample(FAILED).map(|raw| Self::error(ErrorKind::Failed, raw))
            };
        }
        let result = self.finish(error);
        // Exact unrelated AUXCTL bits must survive CRC/E32B cleanup as well.
        // A W1C write is not proof that CRCE cleared.
        let restored = self.registers.read8(AUX_CONTROL);
        let remaining = self.registers.read8(AUX_STATUS);
        if restored != auxiliary || remaining & AUX_CRC_ERROR != 0 {
            self.ready = false;
            let mut error = result.err().unwrap_or_else(|| {
                Self::error(
                    if restored != auxiliary {
                        ErrorKind::PecModeRejected
                    } else {
                        ErrorKind::PecStatusStuck
                    },
                    status,
                )
            });
            error.recovery = Recovery::Failed;
            return Err(error);
        }
        result
    }

    pub(super) fn pec_transaction_until(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        start: u64,
    ) -> Result<(), Error> {
        self.pec_supported(&transaction)?;
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
        let block = matches!(
            transaction,
            Transaction::WriteBlock { .. } | Transaction::ReadBlock { .. }
        );
        let buffered = block && self.config.use_block_buffer;
        let mut bytes = Block::default();
        let mut word = [0; 2];
        let transfer = (|| {
            if self.registers.read8(AUX_STATUS) & AUX_CRC_ERROR != 0 {
                return Err(ErrorKind::PecStatusStuck.into());
            }
            let enabled = auxiliary | AUX_CRC | if buffered { AUX_BUFFER } else { 0 };
            self.registers.write8(AUX_CONTROL, enabled);
            if self.registers.read8(AUX_CONTROL) != enabled {
                return Err(ErrorKind::PecModeRejected.into());
            }
            let protocol = match &transaction {
                Transaction::SendByte(byte) => {
                    self.set_target(address, false, Some(*byte));
                    PROTOCOL_BYTE
                }
                Transaction::ReceiveByte(_) => {
                    self.set_target(address, true, None);
                    PROTOCOL_BYTE
                }
                Transaction::WriteByte { command, data } => {
                    self.set_target(address, false, Some(*command));
                    self.registers.write8(HOST_DATA0, *data);
                    PROTOCOL_BYTE_DATA
                }
                Transaction::ReadByte { command, .. } => {
                    self.set_target(address, true, Some(*command));
                    PROTOCOL_BYTE_DATA
                }
                Transaction::WriteWord { command, data } => {
                    self.set_target(address, false, Some(*command));
                    let [low, high] = data.to_le_bytes();
                    self.registers.write8(HOST_DATA0, low);
                    self.registers.write8(HOST_DATA1, high);
                    PROTOCOL_WORD_DATA
                }
                Transaction::ReadWord { command, .. } => {
                    self.set_target(address, true, Some(*command));
                    PROTOCOL_WORD_DATA
                }
                Transaction::WriteBlock { command, data } => {
                    self.set_target(address, false, Some(*command));
                    self.registers.write8(HOST_DATA0, data.len() as u8);
                    if buffered {
                        self.registers.read8(HOST_CONTROL); // real E32B index reset
                        for &byte in *data {
                            self.registers.write8(BLOCK_DATA, byte);
                        }
                    } else {
                        self.registers.write8(BLOCK_DATA, data[0]);
                    }
                    PROTOCOL_BLOCK
                }
                Transaction::ReadBlock { command, .. } => {
                    self.set_target(address, true, Some(*command));
                    PROTOCOL_BLOCK
                }
                Transaction::ProcessCall {
                    command, request, ..
                } => {
                    // One combined write/repeated-read; hardware PEC covers
                    // both address phases and request/response words.
                    self.set_target(address, false, Some(*command));
                    let [low, high] = request.to_le_bytes();
                    self.registers.write8(HOST_DATA0, low);
                    self.registers.write8(HOST_DATA1, high);
                    PROTOCOL_PROCESS_CALL
                }
            };
            self.start_transfer(protocol, start)?;
            if block && !buffered {
                bytes = self.pec_block_bytes(
                    start,
                    match &transaction {
                        Transaction::WriteBlock { data, .. } => Some(*data),
                        _ => None,
                    },
                )?;
                return Ok(());
            }
            self.wait(start, Phase::Completion)?;
            match &transaction {
                Transaction::ReceiveByte(_) | Transaction::ReadByte { .. } => {
                    word[0] = self.registers.read8(HOST_DATA0);
                }
                Transaction::ReadWord { .. } | Transaction::ProcessCall { .. } => {
                    word[0] = self.registers.read8(HOST_DATA0);
                    word[1] = self.registers.read8(HOST_DATA1);
                }
                Transaction::ReadBlock { .. } => {
                    let length = usize::from(self.registers.read8(HOST_DATA0));
                    if !(1..=MAX_BLOCK).contains(&length) {
                        return Err(Self::error(
                            ErrorKind::InvalidBlockLength(length),
                            self.registers.read8(HOST_STATUS),
                        ));
                    }
                    self.registers.read8(HOST_CONTROL);
                    for byte in &mut bytes.bytes[..length] {
                        *byte = self.registers.read8(BLOCK_DATA);
                    }
                    bytes.length = length as u8;
                }
                _ => {}
            }
            Ok(())
        })();
        self.finish_pec(transfer.err(), auxiliary)?;
        self.completed_deadline(start)?;
        // The outer kept configuration owner stages these again until its
        // PCI identity/configuration and final deadline checks succeed.
        match transaction {
            Transaction::ReceiveByte(output) | Transaction::ReadByte { data: output, .. } => {
                *output = word[0];
            }
            Transaction::ReadWord { data, .. } => *data = u16::from_le_bytes(word),
            Transaction::ProcessCall { response, .. } => *response = u16::from_le_bytes(word),
            Transaction::ReadBlock { data, .. } => *data = bytes,
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
