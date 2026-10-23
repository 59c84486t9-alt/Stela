// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of rtsx_pci_sdmmc.c, Copyright 2009-2013 Realtek.
//! Actual SD_TRANSFER predicates and ping-pong ownership, never HAIMR ACK as
//! card-command completion. No HCB/HDB command or data DMA is started here.
use super::*;
use crate::storage::mmc::protocol::{Host as CardHost, OCR_330};

const COMMAND_US: u64 = 1_000_000;
const DATA_US: u64 = 5_000_000;
const SD_COMMAND_START: u8 = 0x40;
const SD_CRC_TIMEOUT: u8 = 0x02;

impl Engine {
    pub(super) fn check_card(&mut self) -> Result<(), BlockError> {
        self.healthy()?;
        let status = self.status()?;
        if status & MS_EXIST != 0 {
            self.medium = None;
            self.power_off()?;
            return Err(BlockError::Unsupported(
                "RTSX shared PMOS observed Memory Stick during command",
            ));
        }
        if status & SD_EXIST == 0 || status & SD_INT != 0 {
            self.medium = None;
            return Err(BlockError::Unsupported(
                "RTSX card changed during operation",
            ));
        }
        Ok(())
    }
    pub(super) fn stop_card(&mut self) -> Result<(), BlockError> {
        self.write_reg(CARD_STOP, SD_STOP | SD_CLR_ERR, SD_STOP | SD_CLR_ERR)?;
        let deadline = self.clock.deadline(COMMAND_US);
        while self.read_reg(SD_TRANSFER)? & SD_TRANSFER_START != 0 {
            if deadline.passed() {
                return self.failed(BlockError::Timeout);
            }
        }
        Ok(())
    }
    pub(super) fn execute(
        &mut self,
        opcode: Opcode,
        argument: u32,
        response: Response,
        read_bytes: Option<usize>,
    ) -> Result<[u32; 4], BlockError> {
        self.healthy()?;
        let result = self.execute_inner(opcode, argument, response, read_bytes);
        if let Err(error) = result {
            self.medium = None;
            if self.fault.is_none() {
                self.stop_card()?;
            }
            return Err(error);
        }
        result
    }
    fn execute_inner(
        &mut self,
        opcode: Opcode,
        argument: u32,
        response: Response,
        read_bytes: Option<usize>,
    ) -> Result<[u32; 4], BlockError> {
        self.check_card()?;
        if let Some(bytes) = read_bytes {
            if bytes == 0 || bytes > 512 {
                return Err(BlockError::Protocol(
                    "RTSX ping-pong read exceeds actual buffer",
                ));
            }
            if response != Response::Status {
                return Err(BlockError::Protocol("RTSX unsupported data response"));
            }
            let initial = self.read_reg(SD_CFG1)? & SD_CLK_DIVIDE_MASK == SD_CLK_DIVIDE_128;
            if initial {
                self.write_reg(SD_CFG1, SD_CLK_DIVIDE_MASK, SD_CLK_DIVIDE_0)?;
            }
            let result = self.read_data(opcode, argument, bytes);
            if initial {
                self.write_reg(SD_CFG1, SD_CLK_DIVIDE_MASK, SD_CLK_DIVIDE_128)?;
            }
            result
        } else {
            self.send_command(opcode, argument, response)
        }
    }
    fn read_data(
        &mut self,
        opcode: Opcode,
        argument: u32,
        bytes: usize,
    ) -> Result<[u32; 4], BlockError> {
        self.set_command(opcode, argument)?;
        self.data_length(bytes)?;
        self.write_reg(SD_CFG2, 0xff, SD_RSP_LEN_6)?;
        self.write_reg(CARD_DATA_SOURCE, 1, PINGPONG_BUFFER)?;
        self.write_reg(SD_TRANSFER, 0xff, SD_TM_NORMAL_READ | SD_TRANSFER_START)?;
        self.wait_transfer(SD_TRANSFER_END, DATA_US, true)?;
        // sd_read_data consumes END and PPBUF, not an inferred R1 in SD_CMDx.
        // Hardware CRC/status and the later actual CMD13 readiness own errors.
        for index in 0..bytes {
            self.scratch[index] = self.read_reg(PPBUF_BASE2 + index as u16)?;
        }
        self.check_card()?;
        Ok([0; 4])
    }
    fn set_command(&mut self, opcode: Opcode, argument: u32) -> Result<(), BlockError> {
        // Completion IRQs are sticky. Retire only the prior command/data bits;
        // card-change/overcurrent/de-link evidence must survive this operation.
        self.registers.write32(BIPR, COMPLETION_INTERRUPTS);
        self.write_reg(SD_CMD0, 0xff, SD_COMMAND_START | opcode.number())?;
        for (index, value) in argument.to_be_bytes().into_iter().enumerate() {
            self.write_reg(SD_CMD1 + index as u16, 0xff, value)?;
        }
        Ok(())
    }
    fn data_length(&mut self, bytes: usize) -> Result<(), BlockError> {
        self.write_reg(SD_BLOCK_CNT_L, 0xff, 1)?;
        self.write_reg(SD_BLOCK_CNT_H, 0xff, 0)?;
        self.write_reg(SD_BYTE_CNT_L, 0xff, bytes as u8)?;
        self.write_reg(SD_BYTE_CNT_H, 0xff, (bytes >> 8) as u8)
    }
    fn send_command(
        &mut self,
        opcode: Opcode,
        argument: u32,
        response: Response,
    ) -> Result<[u32; 4], BlockError> {
        self.set_command(opcode, argument)?;
        let config = match response {
            Response::None => SD_RSP_TYPE_R0,
            Response::Long => SD_RSP_TYPE_R2,
            Response::Ocr => SD_RSP_TYPE_R3,
            Response::Busy => SD_RSP_TYPE_R1b,
            _ => SD_RSP_TYPE_R1,
        };
        self.write_reg(SD_CFG2, 0xff, config)?;
        self.write_reg(CARD_DATA_SOURCE, 1, PINGPONG_BUFFER)?;
        self.write_reg(SD_TRANSFER, 0xff, SD_TM_CMD_RSP | SD_TRANSFER_START)?;
        self.wait_transfer(
            SD_TRANSFER_END | SD_STAT_IDLE,
            if response == Response::Busy {
                DATA_US
            } else {
                COMMAND_US
            },
            config & SD_NO_CHECK_CRC7 == 0,
        )?;
        let result = self.response(response)?;
        if response == Response::Busy && self.read_reg(SD_BUS_STAT)? & SD_DAT0_STATUS == 0 {
            return Err(BlockError::Unsupported(
                "RTSX busy response did not release DAT0",
            ));
        }
        self.check_card()?;
        Ok(result)
    }
    fn response(&mut self, response: Response) -> Result<[u32; 4], BlockError> {
        let mut result = [0; 4];
        if response == Response::None {
            return Ok(result);
        }
        let mut bytes = [0u8; 17];
        let length = if response == Response::Long { 16 } else { 5 };
        for (index, byte) in bytes.iter_mut().enumerate().take(length) {
            *byte = self.read_reg(if response == Response::Long {
                PPBUF_BASE2 + index as u16
            } else {
                SD_CMD0 + index as u16
            })?;
        }
        if bytes[0] & 0xc0 != 0 {
            return Err(BlockError::Protocol(
                "RTSX response start/transmission bits",
            ));
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
        Ok(result)
    }
    fn wait_transfer(
        &mut self,
        wanted: u8,
        timeout: u64,
        check_crc7: bool,
    ) -> Result<(), BlockError> {
        let deadline = self.clock.deadline(timeout);
        loop {
            self.check_card()?;
            let transfer = self.read_reg(SD_TRANSFER)?;
            let status1 = self.read_reg(SD_STAT1)?;
            let status2 = self.read_reg(SD_STAT2)?;
            let crc = SD_CRC16_ERR | SD_CRC_WRITE_ERR | if check_crc7 { SD_CRC7_ERR } else { 0 };
            if status2 & SD_RSP_80CLK_TIMEOUT != 0 || status1 & SD_CRC_TIMEOUT != 0 {
                return Err(BlockError::Timeout);
            }
            if transfer & SD_TRANSFER_ERR != 0
                || status1 & crc != 0
                || self.registers.read32(BIPR) & TRANS_FAIL_INT != 0
            {
                return Err(BlockError::Device {
                    status: u32::from(transfer)
                        | u32::from(status1) << 8
                        | u32::from(status2) << 16,
                });
            }
            if transfer & wanted == wanted {
                return Ok(());
            }
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            core::hint::spin_loop();
        }
    }
    pub(super) fn write_block(&mut self, argument: u32, bytes: &[u8]) -> Result<(), BlockError> {
        self.healthy()?;
        let result = (|| {
            self.check_card()?;
            if bytes.len() != 512 {
                return Err(BlockError::Protocol("RTSX single-block PIO length"));
            }
            // Source sd_write_data first completes the real R1 command, then
            // transfers a filled PPBUF with AUTO_WRITE3 and no second command.
            self.send_command(WRITE_SINGLE, argument, Response::Status)?;
            for (index, value) in bytes.iter().enumerate() {
                self.write_reg(PPBUF_BASE2 + index as u16, 0xff, *value)?;
            }
            self.registers.write32(BIPR, COMPLETION_INTERRUPTS);
            self.data_length(bytes.len())?;
            self.write_reg(SD_CFG2, 0xff, SD_RSP_LEN_0)?;
            self.write_reg(SD_TRANSFER, 0xff, SD_TM_AUTO_WRITE_3 | SD_TRANSFER_START)?;
            self.wait_transfer(SD_TRANSFER_END, DATA_US, true)?;
            self.check_card()
        })();
        if let Err(error) = result {
            self.medium = None;
            if self.fault.is_none() {
                self.stop_card()?;
            }
            return Err(error);
        }
        result
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
    fn retire(&mut self) -> Result<(), BlockError> {
        self.medium = None;
        self.stop_card()
    }
}
