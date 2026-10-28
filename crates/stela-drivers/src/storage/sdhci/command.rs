// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual command, response, FIFO and ADMA2 completion; no inferred DMA stop.
use super::*;

pub(super) use crate::storage::mmc::wire::*;

impl Response {
    fn flags(self) -> u16 {
        match self {
            Self::None => 0,
            Self::Long => 1 | 8,
            Self::Ocr => 2,
            Self::Busy => 3 | 8 | 16,
            _ => 2 | 8 | 16,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Data {
    pub bytes: usize,
    pub block: u16,
    pub read: bool,
    pub pio: bool,
}

pub(super) fn adma_address(registers: &mut dyn Registers, address: u64, wide: bool) {
    registers.write32(ADMA_ADDRESS, address as u32);
    if wide {
        registers.write32(ADMA_ADDRESS_HIGH, (address >> 32) as u32);
    }
}

impl Engine {
    pub(super) fn clear_command_status(&mut self) -> Result<(), BlockError> {
        // Power faults may latch between the preceding observation and this
        // W1C store. Preserve them and observe before publishing a new command.
        let preserve = CARD_INSERT
            | CARD_REMOVE
            | if matches!(self.profile, Profile::Gli9755 | Profile::Gli9767) {
                BUS_POWER
            } else {
                0
            };
        self.registers.write32(INTERRUPT, !preserve);
        self.gli55_power_event()
    }
    pub(super) fn execute(
        &mut self,
        command: Opcode,
        argument: u32,
        response: Response,
        data: Option<Data>,
    ) -> Result<[u32; 4], BlockError> {
        self.healthy()?;
        let result = self.execute_inner(command, argument, response, data, false, false);
        if let Err(error) = result {
            if command == SD_SWITCH_VOLTAGE {
                // CMD11 may have taken effect even without a completion. An
                // ordinary command/data reset cannot restore the card voltage.
                return Err(self.uhs_failure(error));
            }
            // Fence publication before retirement. A failed reset poisons the
            // controller permanently and preserves the complete DMA allocation.
            return Err(self.retire_error(error));
        }
        result
    }
    fn execute_inner(
        &mut self,
        command: Opcode,
        argument: u32,
        response: Response,
        data: Option<Data>,
        tolerate_response_crc: bool,
        defer: bool,
    ) -> Result<[u32; 4], BlockError> {
        self.check_card()?;
        let inhibit = INHIBIT_COMMAND
            | if command != STOP_TRANSMISSION && (data.is_some() || response == Response::Busy) {
                INHIBIT_DATA
            } else {
                0
            };
        let deadline = self.clock.deadline(COMMAND_US);
        while self.registers.read32(PRESENT) & inhibit != 0 {
            self.check_card()?;
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            core::hint::spin_loop();
        }
        self.clear_command_status()?;
        let dma = data.is_some_and(|data| !data.pio) && self.dma_mode.is_some();
        let mut mode = 0;
        if let Some(data) = data {
            if data.bytes == 0
                || data.bytes > self.data.len()
                || data.block == 0
                || data.block > 2048
                || !data.bytes.is_multiple_of(usize::from(data.block))
            {
                return Err(BlockError::Unsupported("SDHCI invalid transfer geometry"));
            }
            let blocks = data.bytes / usize::from(data.block);
            let count = u16::try_from(blocks)
                .map_err(|_| BlockError::Unsupported("SDHCI transfer block count"))?;
            let mut control = self.registers.read8(HOST_CONTROL) & !DMA_MASK;
            if dma {
                if let Err(error) = self.registers.dma_ready() {
                    // An unacknowledged native PCI grant cannot be recovered
                    // by an SD command/data reset. Retain its original epoch.
                    self.fault = Some(error.clone());
                    return Err(error);
                }
                let wide = self.dma_mode.unwrap();
                if self.profile.gli() {
                    control = gli::dma::configure(self.registers.as_mut(), wide)?;
                    gli::dma::descriptor(
                        &mut self.descriptors,
                        self.data.physical(),
                        data.bytes,
                        wide,
                    );
                } else {
                    control |= if wide { ADMA64 } else { ADMA32 };
                    // One aligned descriptor covers the retained contiguous bounce
                    // range. A zero16-bit length encodes exactly65536bytes.
                    self.descriptors.write(0, 0x23u16); // VALID | END | TRAN
                    self.descriptors.write(2, data.bytes as u16);
                    self.descriptors.write(4, self.data.physical() as u32);
                    if wide {
                        self.descriptors
                            .write(8, (self.data.physical() >> 32) as u32);
                    }
                }
                fence(Ordering::Release);
                adma_address(self.registers.as_mut(), self.descriptors.physical(), wide);
                mode |= DMA;
            }
            self.registers.write8(HOST_CONTROL, control);
            if self.profile.gli()
                && self.registers.read8(HOST_CONTROL) & DMA_MASK != control & DMA_MASK
            {
                return Err(BlockError::Unsupported(
                    "GL9750 DMA selection did not acknowledge",
                ));
            }
            self.registers.write16(BLOCK_SIZE, data.block);
            self.registers.write16(BLOCK_COUNT, count);
            mode |= BLOCK_COUNT_ENABLE;
            if blocks > 1 {
                mode |= MULTIPLE;
            }
            if data.read {
                mode |= READ;
            }
        }
        self.registers.write16(TRANSFER_MODE, mode);
        self.registers.write32(ARGUMENT, argument);
        let flags = response.flags()
            | if data.is_some() { 0x20 } else { 0 }
            | if command == STOP_TRANSMISSION {
                0xc0
            } else {
                0
            };
        fence(Ordering::Release);
        self.registers
            .write16(COMMAND, u16::from(command.number()) << 8 | flags);
        if let Err(error) = self.wait_interrupt(RESPONSE_END, COMMAND_US) {
            let response_check = (1 << 17) | (1 << 18) | (1 << 19);
            if tolerate_response_crc
                && matches!(error, BlockError::Device { status }
                    if status & response_check != 0
                        && status & ERROR & !(response_check | (1 << 15)) == 0)
            {
                // Linux maps response CRC/end/index checks to EILSEQ;
                // mmc_switch_status(false) alone permits that response error.
                // This branch precedes card R1 decoding, so an R1 error can
                // never be mistaken for an SDHCI interrupt with equal bits.
                self.reset(RESET_COMMAND | RESET_DATA)?;
                self.check_card()?;
                return Ok([0; 4]);
            }
            return Err(error);
        }
        self.registers.write32(INTERRUPT, RESPONSE_END);
        let mut result = [0; 4];
        if response == Response::Long {
            // SDHCI strips the eight CRC/end bits of a136-bit response. This
            // is Linux sdhci_read_rsp_136's reversed-word reconstruction.
            let raw: [u32; 4] =
                core::array::from_fn(|i| self.registers.read32(RESPONSE + (3 - i) * 4));
            for i in 0..4 {
                result[i] = raw[i] << 8 | if i < 3 { raw[i + 1] >> 24 } else { 0 };
            }
        } else if response != Response::None {
            result[0] = self.registers.read32(RESPONSE);
        }
        let errors = if matches!(response, Response::Status | Response::Busy) {
            result[0] & R1_ERRORS
        } else if response == Response::Rca {
            result[0] & 0xe000
        } else {
            0
        };
        if errors != 0 {
            return Err(BlockError::Device { status: result[0] });
        }
        if defer && (dma || (data.is_none() && response == Response::Busy)) {
            return Ok(result);
        }
        if let Some(data) = data {
            if !dma {
                self.pio(data)?;
            }
            self.wait_interrupt(DATA_END, DATA_US)?;
            self.registers.write32(INTERRUPT, DATA_END | DMA_END);
            fence(Ordering::Acquire);
        } else if response == Response::Busy {
            // R1b completion requires actual busy release, including DAT0.
            self.wait_interrupt(DATA_END, DATA_US)?;
            self.registers.write32(INTERRUPT, DATA_END);
            if self.registers.read32(PRESENT) & (INHIBIT_DATA | DATA0) != DATA0 {
                return Err(BlockError::Unsupported(
                    "SDHCI busy response did not release DAT0",
                ));
            }
        }
        self.check_card()?;
        Ok(result)
    }
    pub(super) fn mmc_mode_status(&mut self, rca: u16, crc_fatal: bool) -> Result<(), BlockError> {
        self.healthy()?;
        let result = self.execute_inner(
            SEND_STATUS,
            u32::from(rca) << 16,
            Response::Status,
            None,
            !crc_fatal,
            false,
        );
        result.map(|_| ()).map_err(|error| self.retire_error(error))
    }
    pub(super) fn check_card(&mut self) -> Result<(), BlockError> {
        self.check_authority()?;
        self.gli55_power_event()?;
        if self.profile.nonremovable() {
            return Ok(());
        }
        let interrupt = self.registers.read32(INTERRUPT);
        let state = self.registers.read32(PRESENT);
        if interrupt & (CARD_INSERT | CARD_REMOVE) != 0 || state & CARD_PRESENT == 0 {
            self.medium = None;
            return Err(BlockError::Unsupported(
                "SDHCI card removed during operation",
            ));
        }
        Ok(())
    }
    pub(super) fn wait_interrupt(&mut self, wanted: u32, timeout: u64) -> Result<u32, BlockError> {
        let deadline = self.clock.deadline(timeout);
        loop {
            if let Some(result) = self.poll_interrupt(wanted, deadline) {
                return result;
            }
            core::hint::spin_loop();
        }
    }
    /// One look for `wanted` or an error interrupt, or the deadline.
    pub(super) fn poll_interrupt(
        &mut self,
        wanted: u32,
        deadline: Deadline,
    ) -> Option<Result<u32, BlockError>> {
        if let Err(error) = self.check_card() {
            return Some(Err(error));
        }
        let status = self.registers.read32(INTERRUPT);
        if status & ERROR != 0 {
            return Some(if status & ERROR == COMMAND_TIMEOUT | (1 << 15) {
                Err(BlockError::Timeout)
            } else {
                Err(BlockError::Device { status })
            });
        }
        if status & wanted != 0 {
            return Some(Ok(status));
        }
        deadline.passed().then_some(Err(BlockError::Timeout))
    }
    /// Issue a block command's DMA transfer, or an R1b command, up to its
    /// response, leaving the data or busy phase to [`Self::poll_end`]. A
    /// PIO transfer runs whole.
    pub(super) fn issue_deferred(
        &mut self,
        command: Opcode,
        argument: u32,
        response: Response,
        data: Option<Data>,
    ) -> Result<(), BlockError> {
        self.healthy()?;
        self.execute_inner(command, argument, response, data, false, true)
            .map(drop)
            .map_err(|error| self.retire_error(error))
    }
    /// One look at the deferred data or busy phase: its end, an error, or
    /// its deadline.
    pub(super) fn poll_end(
        &mut self,
        busy: bool,
        deadline: Deadline,
    ) -> Option<Result<(), BlockError>> {
        let result = self.poll_interrupt(DATA_END, deadline)?.and_then(|_| {
            self.registers.write32(INTERRUPT, DATA_END | DMA_END);
            fence(Ordering::Acquire);
            if busy && self.registers.read32(PRESENT) & (INHIBIT_DATA | DATA0) != DATA0 {
                return Err(BlockError::Unsupported(
                    "SDHCI busy response did not release DAT0",
                ));
            }
            self.check_card()
        });
        Some(result.map_err(|error| self.retire_error(error)))
    }
    fn pio(&mut self, data: Data) -> Result<(), BlockError> {
        let interrupt = if data.read { READ_READY } else { WRITE_READY };
        let available = if data.read {
            DATA_AVAILABLE
        } else {
            SPACE_AVAILABLE
        };
        for block in (0..data.bytes).step_by(usize::from(data.block)) {
            self.wait_interrupt(interrupt, DATA_US)?;
            if self.registers.read32(PRESENT) & available == 0 {
                return Err(BlockError::Unsupported(
                    "SDHCI FIFO interrupt without actual buffer readiness",
                ));
            }
            self.registers.write32(INTERRUPT, interrupt);
            for offset in (0..usize::from(data.block)).step_by(4) {
                let at = block + offset;
                let count = (usize::from(data.block) - offset).min(4);
                if data.read {
                    let bytes = self.registers.read32(BUFFER).to_le_bytes();
                    self.data.bytes_mut()[at..at + count].copy_from_slice(&bytes[..count]);
                } else {
                    let mut bytes = [0; 4];
                    bytes[..count].copy_from_slice(&self.data.bytes()[at..at + count]);
                    self.registers.write32(BUFFER, u32::from_le_bytes(bytes));
                }
            }
        }
        Ok(())
    }
    pub(super) fn block_transfer(
        &mut self,
        id: u64,
        lba: u64,
        bytes: usize,
        read: bool,
    ) -> Result<(), BlockError> {
        self.live(id)?;
        let (command, address) = self.block_command(lba, bytes, read)?;
        self.execute(
            command,
            address,
            Response::Status,
            Some(Data {
                bytes,
                block: 512,
                read,
                pio: false,
            }),
        )?;
        if bytes > 512 {
            self.execute(STOP_TRANSMISSION, 0, Response::Busy, None)?;
        }
        self.wait_card_ready()?;
        self.live(id)
    }
    /// The read or write command for `bytes` from `lba`, and its argument.
    fn block_command(
        &self,
        lba: u64,
        bytes: usize,
        read: bool,
    ) -> Result<(Opcode, u32), BlockError> {
        let medium = self.medium.as_ref().unwrap();
        let address = if medium.sector_addressed {
            lba
        } else {
            lba.checked_mul(512)
                .ok_or(BlockError::Unsupported("SDHCI byte address overflow"))?
        };
        let address = u32::try_from(address)
            .map_err(|_| BlockError::Unsupported("SDHCI card address exceeds32bits"))?;
        let command = match (read, bytes > 512) {
            (true, false) => READ_SINGLE,
            (true, true) => READ_MULTIPLE,
            (false, false) => WRITE_SINGLE,
            (false, true) => WRITE_MULTIPLE,
        };
        Ok((command, address))
    }
    /// Run the started block command to its result.
    pub(super) fn settle(&mut self) {
        while self
            .running
            .as_ref()
            .is_some_and(|running| running.result.is_none() && running.transfer.is_some())
        {
            self.advance();
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    /// Move the started block command on as far as it goes without waiting.
    pub(super) fn advance(&mut self) {
        let Some(mut running) = self.running.take() else {
            return;
        };
        if running.result.is_none()
            && let Some(transfer) = running.transfer.as_mut()
        {
            running.result = loop {
                match self.step(transfer) {
                    None => break None,
                    Some(Ok(false)) => {}
                    Some(Ok(true)) => {
                        let data = core::mem::take(&mut transfer.data);
                        break Some(Ok(transfer.read.then_some(data)));
                    }
                    Some(Err(error)) => break Some(Err(error)),
                }
            };
        }
        self.running = Some(running);
    }
    /// One move of `transfer` without waiting: `true` once all of it is
    /// done, `false` when it moved on, `None` while it waits. Each part is
    /// Linux's `mmc_blk_mq_issue_rw_rq` and `mmc_blk_card_busy`: the
    /// transfer, STOP_TRANSMISSION after more than one block, then CMD13
    /// until the card is ready again.
    fn step(&mut self, transfer: &mut Transfer) -> Option<Result<bool, BlockError>> {
        let timer = |clock: Clock, us| clock.try_deadline(us).map_err(|_| BlockError::Timeout);
        let phase = match transfer.phase {
            None => {
                if transfer.done == transfer.bytes {
                    return Some(Ok(true));
                }
                let part = (transfer.bytes - transfer.done).min(TRANSFER_BYTES);
                let lba = transfer.lba + (transfer.done / 512) as u64;
                let read = transfer.read;
                if !read {
                    self.data.bytes_mut()[..part]
                        .copy_from_slice(&transfer.data[transfer.done..transfer.done + part]);
                }
                self.live(transfer.generation)
                    .and_then(|()| self.block_command(lba, part, read))
                    .and_then(|(command, address)| {
                        let data = Data {
                            bytes: part,
                            block: 512,
                            read,
                            pio: false,
                        };
                        self.issue_deferred(command, address, Response::Status, Some(data))
                    })
                    .and_then(|()| {
                        Ok(Phase::Data {
                            deadline: timer(self.clock, DATA_US)?,
                            part,
                        })
                    })
            }
            Some(Phase::Data { deadline, part }) => {
                self.poll_end(false, deadline)?.and_then(|()| {
                    let deadline = timer(self.clock, DATA_US)?;
                    if part > 512 {
                        self.issue_deferred(STOP_TRANSMISSION, 0, Response::Busy, None)?;
                        Ok(Phase::Stop { deadline, part })
                    } else {
                        Ok(Phase::Ready {
                            deadline,
                            next: None,
                            part,
                        })
                    }
                })
            }
            Some(Phase::Stop { deadline, part }) => self.poll_end(true, deadline)?.and_then(|()| {
                Ok(Phase::Ready {
                    deadline: timer(self.clock, DATA_US)?,
                    next: None,
                    part,
                })
            }),
            Some(Phase::Ready {
                deadline,
                next,
                part,
            }) => {
                if next.is_some_and(|next| !next.passed()) {
                    return None;
                }
                if deadline.passed() {
                    return Some(Err(self.retire_error(BlockError::Timeout)));
                }
                let status = match self.execute(
                    SEND_STATUS,
                    u32::from(self.rca) << 16,
                    Response::Status,
                    None,
                ) {
                    Ok(response) => response[0],
                    Err(error) => return Some(Err(error)),
                };
                if status & (1 << 8) == 0 || status >> 9 & 15 != 4 {
                    return match timer(self.clock, 1000) {
                        Ok(next) => {
                            transfer.phase = Some(Phase::Ready {
                                deadline,
                                next: Some(next),
                                part,
                            });
                            None
                        }
                        Err(error) => Some(Err(error)),
                    };
                }
                if let Err(error) = self.live(transfer.generation) {
                    return Some(Err(error));
                }
                if transfer.read {
                    transfer.data.extend_from_slice(&self.data.bytes()[..part]);
                }
                transfer.done += part;
                transfer.phase = None;
                return Some(Ok(false));
            }
        };
        match phase {
            Ok(phase) => {
                transfer.phase = Some(phase);
                Some(Ok(false))
            }
            Err(error) => Some(Err(error)),
        }
    }
}
