//! Consumed scalar writes retain peripheral prefixes and settlement separately.
//! A bus error never proves that an earlier RTC/lifecycle/device effect vanished.
use super::*;
use crate::machine::engine::{CanonicalDeviceMemory, ConsumedWrite, DeviceReadShape};

impl AppleDevices {
    pub(super) fn consume_scalar_write(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
        mut memory: Option<&mut dyn CanonicalDeviceMemory>,
    ) -> Result<ConsumedWrite, DeviceError> {
        self.check_raw_processor_power_write(physical, bytes, value)?;
        let width = width(bytes)?;
        let canonical = self.read_needs_ram(physical, DeviceReadShape::Scalar { bytes })
            || self.empty_cache_flush_needs_ram(physical, width);
        if canonical && memory.is_none() {
            return Err(DeviceError::TransferRefused(
                "memory controller write requires the actual live canonical RAM service".into(),
            ));
        }
        let reached: Result<Option<Reset>, DeviceError> = (|| {
            self.publish_rtc_time(now)?;
            self.settle_lifecycle(cpu, now);
            // Validate the NOR CS edge before the GPIO word changes. This keeps
            // an incomplete-command refusal atomic across the two devices.
            for wire in self
                .selects
                .iter()
                .filter(|w| w.physical == physical && width == Width::Word)
            {
                let high = Gpio::driven_level(value as u32).ok_or_else(|| {
                    DeviceError::Refused("SPI CS must remain a GPIO output".into())
                })?;
                self.bus
                    .device::<Spi>(wire.spi)
                    .expect("SPI wire")
                    .check_cs(high)
                    .map_err(|e| DeviceError::Refused(e.into()))?;
            }
            if width == Width::Word {
                self.check_power_request(physical, value)?;
            }
            let mut access = Access::new(cpu, now, &mut self.latch);
            let written = if canonical {
                let memory = memory
                    .as_mut()
                    .expect("canonical write requires its live service");
                let (device, offset) = self.bus.route(physical, width).map_err(describe)?;
                if let Some(owner) = self
                    .bus
                    .device_mut::<memory_resources::t8112::cache::EmptyResource>(device)
                {
                    owner
                        .write_ram_flush(offset, width, value, now, &mut **memory)
                        .map_err(|reason| DeviceError::TransferRefused(reason.into()))
                } else {
                    let owner = memory_resources::resource_for(&self.bus, device)
                        .expect("exclusive board borrow retains the classified prepared owner");
                    // SAFETY: the sealed consuming owner retains the whole stopped
                    // native cohort and closed synchronous RAM producer set. No RAM
                    // publication, new submission or native resume occurs here.
                    unsafe { owner.write_ram_drain(offset, width, value, now, memory.memory()) }
                        .map_err(|reason| DeviceError::TransferRefused(reason.into()))
                }
            } else {
                self.bus
                    .write(physical, width, value, &mut access)
                    .map_err(describe)
            };
            let reset = reset_reason(&access);
            let result = written.map_err(|error| {
                if let Some((_, reason)) = self
                    .power_refusals
                    .iter()
                    .find(|(address, _)| *address == physical)
                {
                    DeviceError::Refused(format!(
                        "PMGR domain {physical:#x}: {reason}; {:?}",
                        error
                    ))
                } else {
                    error
                }
            });
            if let Err(error) = result {
                self.capture_reached(cpu, now, reset);
                return Err(error);
            }
            for wire in self.selects.iter().filter(|w| w.physical == physical) {
                let result = self
                    .bus
                    .device_mut::<Spi>(wire.spi)
                    .expect("SPI wire")
                    .set_cs(value & 1 != 0);
                if let Err(error) = result {
                    self.capture_reached(cpu, now, reset);
                    return Err(DeviceError::Refused(error.into()));
                }
            }
            Ok(reset)
        })();
        Ok(match reached {
            Ok(reset) => ConsumedWrite::Complete {
                settlement: self.settle(cpu, now, reset),
            },
            Err(error) => {
                // Early RTC/lifecycle refusals can also have reached wires.
                // A second capture after the register error is empty, never a
                // replay, and preserves the first reset already retained.
                self.capture_reached(cpu, now, None);
                ConsumedWrite::Unknown { error }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use core::cell::Cell;
    use stela_contracts::interrupt::Wire;

    struct Writer {
        count: Rc<Cell<usize>>,
        refuse_after_effect: bool,
    }
    impl MmioDevice for Writer {
        fn name(&self) -> &'static str {
            "consuming test writer"
        }
        fn read(
            &mut self,
            offset: u64,
            width: Width,
            _: &mut Access<'_>,
        ) -> Result<u64, MmioError> {
            Err(stela_contracts::bus::refuse(
                self.name(),
                offset,
                width,
                stela_contracts::bus::Direction::Read,
                "write-only test register",
            ))
        }
        fn write(
            &mut self,
            offset: u64,
            width: Width,
            _: u64,
            access: &mut Access<'_>,
        ) -> Result<(), MmioError> {
            self.count.set(self.count.get() + 1);
            if self.refuse_after_effect {
                access.request_reset(self.name(), "reached before refusal");
                access
                    .interrupts
                    .set_level(Wire::Aic(AicInput::new(0, 1)), true);
                return Err(stela_contracts::bus::refuse(
                    self.name(),
                    offset,
                    width,
                    stela_contracts::bus::Direction::Write,
                    "retained peripheral prefix",
                ));
            }
            access
                .interrupts
                .set_level(Wire::Aic(AicInput::new(0, 1)), true);
            Ok(())
        }
    }
    fn board(refuse_after_effect: bool) -> (AppleDevices, Rc<Cell<usize>>) {
        let mut board = AppleDevices::new();
        let count = Rc::new(Cell::new(0));
        board
            .bus
            .install(
                Box::new(Writer {
                    count: count.clone(),
                    refuse_after_effect,
                }),
                &[(0x1000, 4, 0)],
            )
            .unwrap();
        (board, count)
    }

    #[test]
    fn consumed_write_survives_failed_wire_settlement_without_replay() {
        let (mut board, count) = board(false);
        let consumed = board
            .consume_scalar_write(0, 0x1000, 4, 7, 9, None)
            .unwrap();
        assert!(matches!(
            consumed,
            ConsumedWrite::Complete { settlement: Err(_) }
        ));
        assert_eq!(count.get(), 1);
        assert_eq!(board.pending_service().unwrap().committed(), 0);
        board
            .add_aic(0x10000, 32, AicLayout::aic2(0x8000, 1))
            .unwrap();
        board.settle(0, 10, None).unwrap();
        assert!(board.pending_service().is_none());
        assert_eq!(count.get(), 1);
    }

    #[test]
    fn a_bus_error_after_effects_is_unknown_not_effect_free() {
        let (mut board, count) = board(true);
        let consumed = board
            .consume_scalar_write(3, 0x1000, 4, 7, 9, None)
            .unwrap();
        assert!(matches!(consumed, ConsumedWrite::Unknown { .. }));
        assert_eq!(count.get(), 1);
        let pending = board.pending_service().unwrap();
        assert_eq!(pending.committed(), 0);
        assert_eq!(pending.resets().len(), 1);
        assert_eq!(
            pending.inputs(),
            &[ServiceInput::Aic(AicDelivery {
                input: AicInput::new(0, 1),
                level: true,
                cpu: 3,
                now: 9,
            })]
        );
        let reset = board.take_reset().unwrap();
        assert_eq!(reset.transition, Transition::Restart);
        assert!(reset.reason.contains("reached before refusal"));
        assert!(
            board
                .consume_scalar_write(0, 0x1000, 3, 7, 9, None)
                .is_err()
        );
        assert_eq!(count.get(), 1);
    }
}
