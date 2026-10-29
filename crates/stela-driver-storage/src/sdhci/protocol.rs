// SPDX-License-Identifier: GPL-2.0-only
//! SDHCI effects behind the shared SD/MMC card protocol.
use super::{command::*, *};
#[cfg(test)]
pub(super) use crate::mmc::capacity;
use crate::mmc::protocol::{Host, OCR_180, OCR_300, OCR_330, Session};

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
        let supply = self.registers.read8(POWER);
        match supply
            & if self.profile == Profile::Gli9755 {
                0x0e
            } else {
                !POWER_ON
            } {
            POWER_330 => Ok(OCR_330),
            POWER_300 => Ok(OCR_300),
            POWER_180 => Ok(OCR_180),
            _ => Err(BlockError::Unsupported("SDHCI actual power supply")),
        }
    }
    fn writable(&mut self) -> Result<bool, BlockError> {
        Ok(self.registers.read32(PRESENT) & WRITE_ALLOWED != 0)
    }
    fn allow_kind(&self, kind: Kind) -> Result<(), BlockError> {
        if self.profile == Profile::Gli9763e && kind != Kind::Mmc {
            return Err(BlockError::Unsupported(
                "GL9763E is an embedded MMC-only transport",
            ));
        }
        Ok(())
    }
    fn probe_sd(&self) -> bool {
        self.profile != Profile::Gli9763e
    }
    fn high_speed_supported(&self) -> bool {
        self.capabilities & CAP_HIGH_SPEED != 0
    }
    fn mmc_fast_modes(&self) -> bool {
        Engine::mmc_fast_modes(self)
    }
    fn set_mmc_signal_voltage(&mut self) -> Result<(), BlockError> {
        self.mmc_signal_180()
    }
    fn set_mmc_timing(&mut self, timing: Timing) -> Result<(), BlockError> {
        self.mmc_timing(timing)
    }
    fn set_mmc_strobe(&mut self, enable: bool) -> Result<(), BlockError> {
        self.mmc_strobe(enable)
    }
    fn tune_mmc(&mut self) -> Result<(), BlockError> {
        self.tune()
    }
    fn mmc_switch_status(&mut self, rca: u16, crc_fatal: bool) -> Result<(), BlockError> {
        self.mmc_mode_status(rca, crc_fatal)
    }
    fn mmc_mode_failure(&mut self, error: BlockError) -> BlockError {
        self.mmc_failure(error)
    }
    fn sd_uhs_modes(&self) -> super::super::mmc::SdUhsModes {
        self.uhs_modes()
    }
    fn switch_sd_signal_voltage(&mut self) -> Result<(), BlockError> {
        self.switch_signal_voltage()
    }
    fn set_sd_uhs_timing(&mut self, timing: Timing) -> Result<(), BlockError> {
        self.set_uhs_timing(timing)
    }
    fn tune_sd(&mut self) -> Result<(), BlockError> {
        self.tune()
    }
    fn sd_max_current_ma(&self) -> u32 {
        // Captured from the selected VCC supply's MAX_CURRENT field.
        self.max_current_ma
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
        Ok(self.actual_hz)
    }
    fn scratch(&self) -> &[u8] {
        self.data.bytes()
    }
    fn retire(&mut self, primary: BlockError) -> BlockError {
        self.retire_error(primary)
    }
}
impl Engine {
    pub(super) fn retire_error(&mut self, primary: BlockError) -> BlockError {
        if self.uhs_failed {
            // The electrical path already powered off and kept both cleanup
            // outcomes. Shared card-protocol unwinding must not replace them.
            return primary;
        }
        self.medium = None;
        let retirement = if self.healthy().is_ok() {
            self.reset(RESET_COMMAND | RESET_DATA).err()
        } else {
            None
        };
        let quarantined = self.healthy().is_err() || retirement.is_some();
        if quarantined {
            self.fault = Some(primary.clone());
        }
        self.last_failure = Some(Failure {
            primary: primary.clone(),
            restoration: None,
            retirement,
            quarantined,
        });
        primary
    }
    pub(super) fn identify(&mut self) -> Result<Medium, BlockError> {
        self.rca = 0;
        let card = Session::new(self, 0).identify()?;
        self.rca = card.rca;
        Ok(Medium {
            id: generation()?,
            identity: card.identity,
            sector_addressed: card.sector_addressed,
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

#[cfg(test)]
mod tests {
    use super::super::{
        Host as SdhciHost,
        model::{CLOCK_TICKS_PER_US, Hardware, Port},
    };
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use alloc::vec;

    #[test]
    fn crc_and_failed_reset_keep_primary_failure() {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing and the model remain alive through every alias and
        // refused operation, including uncertain native DMA retirement.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let hardware = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
        let mut host = SdhciHost::new(
            Box::new(Port(hardware.clone())),
            Clock {
                ticks_per_microsecond: CLOCK_TICKS_PER_US,
            },
            "SDHCI primary/retirement model".into(),
            &mut dma,
            Profile::Standard,
        )
        .unwrap();
        let mut card = host.poll().unwrap().unwrap();
        hardware.borrow_mut().data_error = true;
        hardware.borrow_mut().reset_stuck = true;
        let mut poison = [0xa5; 512];
        let primary = card.read(5, &mut poison).unwrap_err();
        assert!(matches!(primary, BlockError::Device { .. }));
        let failure = host.last_failure().unwrap();
        assert_eq!(failure.primary, primary);
        assert!(matches!(
            failure.retirement,
            Some(BlockError::Unsupported(_))
        ));
        assert!(failure.quarantined);
        assert_eq!(poison, [0xa5; 512]);
        let accesses = (hardware.borrow().reads, hardware.borrow().writes.len());
        assert_eq!(card.flush_cache(), Err(BlockError::Unsupported(STALE)));
        assert_eq!(host.poll().err(), Some(primary));
        assert_eq!(
            (hardware.borrow().reads, hardware.borrow().writes.len()),
            accesses
        );
    }
}
