// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of rtsx_pci_sdmmc.c, Copyright 2009-2013 Realtek.
//! SD_TRANSFER predicates and ping-pong ownership, never HAIMR ACK as
//! card-command completion. No HCB/HDB command or data DMA is started here.
use super::*;
use crate::mmc::protocol::{Host as CardHost, OCR_330};

const COMMAND_US: u64 = 1_000_000;
const DATA_US: u64 = 5_000_000;
const SD_COMMAND_START: u8 = 0x40;
const SD_CRC_TIMEOUT: u8 = 0x02;

#[derive(Clone, Copy)]
pub(super) struct Budget {
    phase: crate::Deadline,
    request: Option<crate::Deadline>,
}
impl Budget {
    pub(super) fn new(engine: &Engine, microseconds: u64) -> Self {
        Self {
            phase: engine.clock.deadline(microseconds),
            request: engine.request_deadline,
        }
    }
    pub(super) fn retirement(engine: &Engine) -> Self {
        Self {
            phase: engine.clock.deadline(COMMAND_US),
            request: None,
        }
    }
    pub(super) fn expired(self) -> bool {
        self.phase.passed() || self.request.is_some_and(|deadline| deadline.passed())
    }
    pub(super) fn check(self) -> Result<(), BlockError> {
        if self.expired() {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
}

impl Engine {
    pub(super) fn begin_request(&mut self) {
        debug_assert!(self.request_deadline.is_none());
        self.request_deadline = Some(self.clock.deadline(DATA_US));
    }
    pub(super) fn check_request(&self) -> Result<(), BlockError> {
        if self
            .request_deadline
            .is_some_and(|deadline| deadline.passed())
        {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    pub(super) fn end_request(&mut self, result: Result<(), BlockError>) -> Result<(), BlockError> {
        self.request_deadline = None;
        result.map_err(|error| {
            if self.medium.is_some() {
                self.retire_error(error)
            } else {
                error
            }
        })
    }
    fn retire_error(&mut self, primary: BlockError) -> BlockError {
        // A nested emergency cleanup has already finalized this command,
        // including successful power-off. Do not follow it with Stop or replace
        // its diagnostic. New commands reset the marker, preserving history
        // without confusing a prior command's failure with current retirement.
        if self.failure_finalized
            && self
                .last_failure
                .as_ref()
                .is_some_and(|failure| failure.primary == primary)
        {
            return primary;
        }
        self.finish_failure(primary, false, false)
    }
    pub(super) fn emergency_off(&mut self, primary: BlockError, permanent: bool) -> BlockError {
        self.finish_failure(primary, true, permanent)
    }
    fn finish_failure(
        &mut self,
        primary: BlockError,
        power_off: bool,
        permanent: bool,
    ) -> BlockError {
        self.medium = None;
        let retirement = if self.fault.is_none() {
            if power_off {
                self.power_off().err()
            } else {
                self.stop_card().err()
            }
        } else {
            None
        };
        let quarantined = permanent || self.fault.is_some() || retirement.is_some();
        if quarantined {
            self.fault = Some(primary.clone());
        }
        self.failure_finalized = true;
        self.last_failure = Some(Failure {
            primary: primary.clone(),
            restoration: self.restoration_failure.take(),
            retirement,
            quarantined,
        });
        primary
    }
    fn rd(&mut self, budget: Budget, at: u16) -> Result<u8, BlockError> {
        self.read_reg_before(at, Some(budget))
    }
    fn wr(&mut self, budget: Budget, at: u16, mask: u8, value: u8) -> Result<(), BlockError> {
        self.write_reg_before(at, mask, value, Some(budget))
    }
    pub(super) fn check_card_before(&mut self, budget: Budget) -> Result<(), BlockError> {
        budget.check()?;
        self.healthy()?;
        budget.check()?;
        let status = self.status()?;
        self.check_presence(status)?;
        budget.check()
    }
    fn check_presence(&mut self, status: u32) -> Result<(), BlockError> {
        if status & MS_EXIST != 0 {
            let primary =
                BlockError::Unsupported("RTSX shared PMOS observed Memory Stick during command");
            return Err(self.emergency_off(primary, false));
        }
        if status & SD_EXIST == 0 || status & SD_INT != 0 {
            self.medium = None;
            return Err(BlockError::Unsupported(
                "RTSX card changed during operation",
            ));
        }
        Ok(())
    }
    fn ack_completion(&mut self, budget: Budget) -> Result<(), BlockError> {
        budget.check()?;
        self.registers.write32(BIPR, COMPLETION_INTERRUPTS);
        budget.check()
    }

    pub(super) fn stop_card(&mut self) -> Result<(), BlockError> {
        let budget = Budget::retirement(self);
        let result = (|| {
            self.wr(
                budget,
                CARD_STOP,
                SD_STOP | SD_CLR_ERR,
                SD_STOP | SD_CLR_ERR,
            )?;
            loop {
                let transfer = self.rd(budget, SD_TRANSFER)?;
                budget.check()?;
                if transfer & SD_TRANSFER_START == 0 {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
        })();
        if let Err(error) = result {
            self.failed(error)
        } else {
            Ok(())
        }
    }
    pub(super) fn execute(
        &mut self,
        opcode: Opcode,
        argument: u32,
        response: Response,
        read_bytes: Option<usize>,
    ) -> Result<[u32; 4], BlockError> {
        let budget = Budget::new(
            self,
            if opcode == SD_SEND_TUNING {
                100_000
            } else if read_bytes.is_some() || response == Response::Busy {
                DATA_US
            } else {
                COMMAND_US
            },
        );
        self.restoration_failure = None;
        self.failure_finalized = false;
        self.tuning_rejection_observed = false;
        let result = self.execute_inner(opcode, argument, response, read_bytes, budget);
        result.map_err(|error| self.retire_error(error))
    }
    fn execute_inner(
        &mut self,
        opcode: Opcode,
        argument: u32,
        response: Response,
        read_bytes: Option<usize>,
        budget: Budget,
    ) -> Result<[u32; 4], BlockError> {
        self.check_card_before(budget)?;
        if let Some(bytes) = read_bytes {
            if bytes == 0 || bytes > 512 {
                return Err(BlockError::Protocol(
                    "RTSX ping-pong read exceeds actual buffer",
                ));
            }
            if response != Response::Status {
                return Err(BlockError::Protocol("RTSX unsupported data response"));
            }
            let initial = self.rd(budget, SD_CFG1)? & SD_CLK_DIVIDE_MASK == SD_CLK_DIVIDE_128;
            if initial {
                self.wr(budget, SD_CFG1, SD_CLK_DIVIDE_MASK, SD_CLK_DIVIDE_0)?;
            }
            let result = self.read_data(opcode, argument, bytes, budget);
            // Never replace the first card/data failure with a later restore
            // error, or publish another HAIMR after ownership became uncertain.
            let restoration = if initial && self.fault.is_none() && !self.failure_finalized {
                self.wr(budget, SD_CFG1, SD_CLK_DIVIDE_MASK, SD_CLK_DIVIDE_128)
                    .err()
            } else {
                None
            };
            match result {
                Err(primary) => {
                    self.restoration_failure = restoration;
                    Err(primary)
                }
                Ok(words) => restoration.map_or(Ok(words), Err),
            }
        } else {
            self.send_command(opcode, argument, response, budget)
        }
    }
    fn read_data(
        &mut self,
        opcode: Opcode,
        argument: u32,
        bytes: usize,
        budget: Budget,
    ) -> Result<[u32; 4], BlockError> {
        self.set_command(opcode, argument, budget)?;
        self.data_length(bytes, budget)?;
        self.wr(budget, SD_CFG2, 0xff, SD_RSP_LEN_6)?;
        let tuning = opcode == SD_SEND_TUNING;
        if !tuning {
            self.wr(budget, CARD_DATA_SOURCE, 1, PINGPONG_BUFFER)?;
        }
        self.wr(
            budget,
            SD_TRANSFER,
            0xff,
            if tuning {
                SD_TM_AUTO_TUNING
            } else {
                SD_TM_NORMAL_READ
            } | SD_TRANSFER_START,
        )?;
        self.wait_transfer(SD_TRANSFER_END, true, budget)?;
        // sd_read_data consumes END and PPBUF, not an inferred R1 in SD_CMDx.
        // Hardware CRC/status and the later CMD13 readiness own errors.
        if !tuning {
            for index in 0..bytes {
                self.scratch[index] = self.rd(budget, PPBUF_BASE2 + index as u16)?;
            }
        }
        self.check_card_before(budget)?;
        Ok([0; 4])
    }
    fn set_command(
        &mut self,
        opcode: Opcode,
        argument: u32,
        budget: Budget,
    ) -> Result<(), BlockError> {
        // Completion IRQs are sticky. Retire only the prior command/data bits;
        // card-change/overcurrent/de-link evidence must survive this operation.
        self.ack_completion(budget)?;
        self.wr(budget, SD_CMD0, 0xff, SD_COMMAND_START | opcode.number())?;
        for (index, value) in argument.to_be_bytes().into_iter().enumerate() {
            self.wr(budget, SD_CMD1 + index as u16, 0xff, value)?;
        }
        Ok(())
    }
    fn data_length(&mut self, bytes: usize, budget: Budget) -> Result<(), BlockError> {
        self.wr(budget, SD_BLOCK_CNT_L, 0xff, 1)?;
        self.wr(budget, SD_BLOCK_CNT_H, 0xff, 0)?;
        self.wr(budget, SD_BYTE_CNT_L, 0xff, bytes as u8)?;
        self.wr(budget, SD_BYTE_CNT_H, 0xff, (bytes >> 8) as u8)
    }
    fn send_command(
        &mut self,
        opcode: Opcode,
        argument: u32,
        response: Response,
        budget: Budget,
    ) -> Result<[u32; 4], BlockError> {
        self.set_command(opcode, argument, budget)?;
        let config = match response {
            Response::None => SD_RSP_TYPE_R0,
            Response::Long => SD_RSP_TYPE_R2,
            Response::Ocr => SD_RSP_TYPE_R3,
            Response::Busy => SD_RSP_TYPE_R1B,
            _ => SD_RSP_TYPE_R1,
        };
        self.wr(budget, SD_CFG2, 0xff, config)?;
        self.wr(budget, CARD_DATA_SOURCE, 1, PINGPONG_BUFFER)?;
        self.wr(budget, SD_TRANSFER, 0xff, SD_TM_CMD_RSP | SD_TRANSFER_START)?;
        self.wait_transfer(
            SD_TRANSFER_END | SD_STAT_IDLE,
            config & SD_NO_CHECK_CRC7 == 0,
            budget,
        )?;
        let result = self.response(response, budget)?;
        if response == Response::Busy && self.rd(budget, SD_BUS_STAT)? & SD_DAT0_STATUS == 0 {
            return Err(BlockError::Unsupported(
                "RTSX busy response did not release DAT0",
            ));
        }
        self.check_card_before(budget)?;
        Ok(result)
    }
    fn response(&mut self, response: Response, budget: Budget) -> Result<[u32; 4], BlockError> {
        let mut result = [0; 4];
        if response == Response::None {
            return Ok(result);
        }
        let mut bytes = [0u8; 17];
        let length = if response == Response::Long { 16 } else { 5 };
        let mut late = false;
        for (index, byte) in bytes.iter_mut().enumerate().take(length) {
            let (value, expired) = self.observe_reg_before(
                if response == Response::Long {
                    PPBUF_BASE2 + index as u16
                } else {
                    SD_CMD0 + index as u16
                },
                Some(budget),
            )?;
            *byte = value;
            if index == 0 && value & 0xc0 != 0 {
                return Err(BlockError::Protocol(
                    "RTSX response start/transmission bits",
                ));
            }
            // An incomplete late frame cannot authorize additional reads. The
            // final completed frame still decodes R1/R6 errors first.
            if expired && index + 1 < length {
                return Err(BlockError::Timeout);
            }
            late |= expired;
        }
        if response == Response::Long {
            // Native RTSX strips the final CRC/end byte, exactly as the source
            // reconstructs it before decoding the card's 127..0 fields.
            bytes[16] = 1;
            for (index, word) in result.iter_mut().enumerate() {
                *word = u32::from_be_bytes(bytes[1 + index * 4..5 + index * 4].try_into().unwrap());
            }
        } else {
            result[0] = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
        }
        let errors = match response {
            Response::Status | Response::Busy => result[0] & R1_ERRORS,
            Response::Rca => result[0] & 0xe000,
            _ => 0,
        };
        if errors != 0 {
            return Err(BlockError::Device { status: result[0] });
        }
        if late {
            return Err(BlockError::Timeout);
        }
        Ok(result)
    }
    fn wait_transfer(
        &mut self,
        wanted: u8,
        check_crc7: bool,
        budget: Budget,
    ) -> Result<(), BlockError> {
        loop {
            self.check_card_before(budget)?;
            let (transfer, late) = self.observe_reg_before(SD_TRANSFER, Some(budget))?;
            if transfer & SD_TRANSFER_ERR != 0 {
                self.tuning_rejection_observed = !late && !budget.expired();
                return Err(BlockError::Device {
                    status: u32::from(transfer),
                });
            }
            if late {
                return Err(BlockError::Timeout);
            }
            let (status1, late) = self.observe_reg_before(SD_STAT1, Some(budget))?;
            let crc = SD_CRC16_ERR | SD_CRC_WRITE_ERR | if check_crc7 { SD_CRC7_ERR } else { 0 };
            if status1 & SD_CRC_TIMEOUT != 0 {
                self.tuning_rejection_observed = !late && !budget.expired();
                return Err(BlockError::Timeout);
            }
            if status1 & crc != 0 {
                self.tuning_rejection_observed = !late && !budget.expired();
                return Err(BlockError::Device {
                    status: u32::from(transfer) | u32::from(status1) << 8,
                });
            }
            if late {
                return Err(BlockError::Timeout);
            }
            let (status2, late) = self.observe_reg_before(SD_STAT2, Some(budget))?;
            if status2 & SD_RSP_80CLK_TIMEOUT != 0 {
                self.tuning_rejection_observed = !late && !budget.expired();
                return Err(BlockError::Timeout);
            }
            if late {
                return Err(BlockError::Timeout);
            }
            budget.check()?;
            let interrupts = self.registers.read32(BIPR);
            self.accept_status(interrupts)?;
            self.check_presence(interrupts)?;
            if interrupts & TRANS_FAIL_INT != 0 {
                return Err(BlockError::Device { status: interrupts });
            }
            budget.check()?;
            if transfer & wanted == wanted {
                return Ok(());
            }
            core::hint::spin_loop();
        }
    }
    pub(super) fn write_block(&mut self, argument: u32, bytes: &[u8]) -> Result<(), BlockError> {
        self.tuning_rejection_observed = false;
        self.restoration_failure = None;
        self.failure_finalized = false;
        let budget = Budget::new(self, DATA_US);
        let result = (|| {
            self.check_card_before(budget)?;
            if bytes.len() != 512 {
                return Err(BlockError::Protocol("RTSX single-block PIO length"));
            }
            // Source sd_write_data first completes the real R1 command, then
            // transfers a filled PPBUF with AUTO_WRITE3 and no second command.
            self.send_command(
                WRITE_SINGLE,
                argument,
                Response::Status,
                Budget::new(self, COMMAND_US),
            )?;
            for (index, value) in bytes.iter().enumerate() {
                self.wr(budget, PPBUF_BASE2 + index as u16, 0xff, *value)?;
            }
            self.ack_completion(budget)?;
            self.data_length(bytes.len(), budget)?;
            self.wr(budget, SD_CFG2, 0xff, SD_RSP_LEN_0)?;
            self.wr(
                budget,
                SD_TRANSFER,
                0xff,
                SD_TM_AUTO_WRITE_3 | SD_TRANSFER_START,
            )?;
            self.wait_transfer(SD_TRANSFER_END, true, budget)?;
            self.check_card_before(budget)
        })();
        result.map_err(|error| self.retire_error(error))
    }
}

impl CardHost for Engine {
    fn command(
        &mut self,
        opcode: Opcode,
        argument: u32,
        response: Response,
        bytes: Option<usize>,
    ) -> Result<[u32; 4], BlockError> {
        self.execute(opcode, argument, response, bytes)
    }
    fn clock(&self) -> Clock {
        self.clock
    }
    fn location(&self) -> &str {
        &self.location
    }
    fn voltage(&mut self) -> Result<u32, BlockError> {
        Ok(OCR_330)
    }
    fn writable(&mut self) -> Result<bool, BlockError> {
        Ok(self.status()? & SD_WRITE_PROTECT == 0)
    }
    fn allow_kind(&self, kind: Kind) -> Result<(), BlockError> {
        if kind == Kind::Mmc && self.config.no_mmc {
            return Err(BlockError::Unsupported(
                "RTSX board configuration does not wire MMC",
            ));
        }
        Ok(())
    }
    fn minimum_data_hz(&self) -> u32 {
        // Source normal-read bypasses /128 while the SSC remains 30MHz and
        // standard SD20 uses the double-clock route: the card sees 15MHz.
        15_000_000
    }
    fn high_speed_supported(&self) -> bool {
        true
    }
    fn sd_uhs_modes(&self) -> crate::mmc::SdUhsModes {
        let supported = self.config.profile.supports_sd_uhs();
        crate::mmc::SdUhsModes {
            sdr12: supported,
            sdr25: supported,
            sdr50: supported,
            sdr104: supported,
        }
    }
    fn sd_max_current_ma(&self) -> u32 {
        // The board still supplies3.3V VCC; CMD11 changes signaling only.
        if self.config.profile.supports_sd_uhs() {
            400
        } else {
            0
        }
    }
    fn switch_sd_signal_voltage(&mut self) -> Result<(), BlockError> {
        self.switch_uhs_signal()
    }
    fn set_sd_uhs_timing(&mut self, timing: Timing) -> Result<(), BlockError> {
        self.set_uhs_timing(timing)
    }
    fn tune_sd(&mut self) -> Result<(), BlockError> {
        self.tune_uhs()
    }
    fn mmc_width(&self) -> u8 {
        4
    }
    fn set_bus_width(&mut self, width: u8) -> Result<(), BlockError> {
        let encoding = match width {
            1 => SD_BUS_WIDTH_1BIT,
            4 => SD_BUS_WIDTH_4BIT,
            _ => {
                return Err(BlockError::Unsupported(
                    "RTSX unqualified physical data width",
                ));
            }
        };
        self.write_reg(SD_CFG1, 3, encoding)
    }
    fn set_high_speed(&mut self) -> Result<(), BlockError> {
        self.timing(true)
    }
    fn set_clock(&mut self, requested: u32) -> Result<u32, BlockError> {
        Engine::set_clock(self, requested)
    }
    fn scratch(&self) -> &[u8] {
        &self.scratch
    }
    fn retire(&mut self, primary: BlockError) -> BlockError {
        self.retire_error(primary)
    }
}
