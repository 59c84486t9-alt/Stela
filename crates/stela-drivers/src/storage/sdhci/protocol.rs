// SPDX-License-Identifier: GPL-2.0-only
//! Actual SDHCI effects behind the shared SD/MMC card protocol.
use super::{command::*, *};
pub(super) use crate::storage::mmc::capacity;
use crate::storage::mmc::protocol::{Host, OCR_180, OCR_300, OCR_330, Session};

impl Host for Engine {
    fn command(
        &mut self,
        opcode: Opcode,
        argument: u32,
        response: Response,
        read_bytes: Option<usize>,
    ) -> Result<[u32; 4], BlockError> {
        self.execute(
            opcode,
            argument,
            response,
            read_bytes.map(|bytes| Data {
                bytes,
                block: bytes as u16,
                read: true,
                pio: true,
            }),
        )
    }
    fn clock(&self) -> Clock {
        self.clock
    }
    fn location(&self) -> &str {
        &self.location
    }
    fn voltage(&mut self) -> Result<u32, BlockError> {
        match self.registers.read8(POWER) & !POWER_ON {
            POWER_330 => Ok(OCR_330),
            POWER_300 => Ok(OCR_300),
            POWER_180 => Ok(OCR_180),
            _ => Err(BlockError::Unsupported("SDHCI actual power supply")),
        }
    }
    fn writable(&mut self) -> Result<bool, BlockError> {
        Ok(self.registers.read32(PRESENT) & WRITE_ALLOWED != 0)
    }
    fn allow_kind(&self, _: Kind) -> Result<(), BlockError> {
        Ok(())
    }
    fn high_speed_supported(&self) -> bool {
        self.capabilities & CAP_HIGH_SPEED != 0
    }
    fn mmc_width(&self) -> u8 {
        self.profile.mmc_width()
    }
    fn set_bus_width(&mut self, width: u8) -> Result<(), BlockError> {
        let control = self.registers.read8(HOST_CONTROL) & !(BUS4 | BUS8);
        self.set_ios_control(
            control
                | match width {
                    1 => 0,
                    4 => BUS4,
                    8 => BUS8,
                    _ => return Err(BlockError::Unsupported("SDHCI unsupported data width")),
                },
        )
    }
    fn set_high_speed(&mut self) -> Result<(), BlockError> {
        self.set_high_speed_host()
    }
    fn set_clock(&mut self, requested: u32) -> Result<u32, BlockError> {
        Engine::set_clock(self, requested)?;
        Ok(clock_divisor(self.version, self.base_hz, requested)?.1)
    }
    fn scratch(&self) -> &[u8] {
        self.data.bytes()
    }
    fn retire(&mut self) -> Result<(), BlockError> {
        self.medium = None;
        self.reset(RESET_COMMAND | RESET_DATA)
    }
}
impl Engine {
    pub(super) fn identify(&mut self) -> Result<Medium, BlockError> {
        self.rca = 0;
        let card = Session::new(self, 0).identify()?;
        self.rca = card.rca;
        Ok(Medium {
            id: generation()?,
            identity: card.identity,
            kind: card.kind,
            sector_addressed: card.sector_addressed,
            cache: card.cache,
            info: card.info,
            notify: card.notify,
        })
    }
    pub(super) fn mmc_switch(&mut self, index: u8, value: u8) -> Result<(), BlockError> {
        let rca = self.rca;
        Session::new(self, rca).mmc_switch(index, value)
    }
    pub(super) fn wait_card_ready(&mut self) -> Result<(), BlockError> {
        let rca = self.rca;
        Session::new(self, rca).wait_card_ready()
    }
    pub(super) fn power_off_notify(&mut self) -> Result<(), BlockError> {
        let rca = self.rca;
        Session::new(self, rca).power_off_notify()
    }
}
