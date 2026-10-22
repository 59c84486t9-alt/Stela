//! Consumed scalar results and the live canonical RAM boundary for MCC drains.
use super::*;
use crate::machine::engine::{CanonicalDeviceMemory, ConsumedScalar, DeviceReadShape};

impl AppleDevices {
    pub(super) fn read_needs_ram(&self, physical: u64, shape: DeviceReadShape) -> bool {
        let bytes = match shape {
            DeviceReadShape::Scalar { bytes } | DeviceReadShape::Pair { bytes } => bytes,
        };
        let Some(width) = Width::from_bytes(u64::from(bytes)) else {
            return false;
        };
        let needs = |physical| {
            self.bus
                .route(physical, width)
                .ok()
                .is_some_and(|(device, offset)| {
                    self.bus
                        .device::<memory_resources::Prepared>(device)
                        .is_some_and(|owner| owner.requires_ram_read(offset, width))
                })
        };
        needs(physical)
            || matches!(shape, DeviceReadShape::Pair { .. })
                && physical.checked_add(u64::from(bytes)).is_some_and(needs)
    }

    pub(super) fn consume_scalar_read(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
        memory: Option<&mut dyn CanonicalDeviceMemory>,
    ) -> Result<ConsumedScalar, DeviceError> {
        let width = width(bytes)?;
        let canonical = self.read_needs_ram(physical, DeviceReadShape::Scalar { bytes });
        if canonical && memory.is_none() {
            return Err(DeviceError::TransferRefused(
                "MCC drain requires the actual live canonical RAM service".into(),
            ));
        }
        if let Err(error) = self.publish_rtc_time(now) {
            self.capture_reached(cpu, now, None);
            return Err(error);
        }
        self.settle_lifecycle(cpu, now);
        let mut access = Access::new(cpu, now, &mut self.latch);
        let value = if canonical {
            let memory = memory.expect("canonical read preflight requires its live service");
            memory.fence_cpu_memory();
            let (device, offset) = self.bus.route(physical, width)
                .expect("exclusive board borrow retains the classified prepared route");
            let owner = self.bus.device::<memory_resources::Prepared>(device)
                .expect("exclusive board borrow retains the classified prepared owner");
            // SAFETY: only the engine's held native/all-writer service can
            // implement this sealed interface. Its consuming continuation
            // requires the closed synchronous producer set; this path performs
            // no RAM copy, new submission or native resume while it is held.
            // Prepared also checks this exact RAM identity and generation.
            unsafe { owner.read_ram_drain(offset, width, memory.memory()) }
                .map_err(|reason| DeviceError::TransferRefused(reason.into()))
        } else {
            self.bus
                .read(physical, width, &mut access)
                .map_err(describe)
        };
        let reset = reset_reason(&access);
        let value = match value {
            Ok(value) => value,
            Err(error) => {
                self.capture_reached(cpu, now, reset);
                return Err(error);
            }
        };
        let settlement = self.settle(cpu, now, reset);
        Ok(ConsumedScalar { value, settlement })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::Wire;
    use alloc::rc::Rc;
    use core::cell::Cell;

    struct Reader(Rc<Cell<u32>>, bool);
    impl MmioDevice for Reader {
        fn name(&self) -> &'static str {
            "consuming test register"
        }
        fn read(
            &mut self,
            offset: u64,
            width: Width,
            access: &mut Access<'_>,
        ) -> Result<u64, MmioError> {
            assert_eq!((offset, width), (0, Width::Word));
            let value = self.0.get();
            self.0.set(value + 1);
            access
                .interrupts
                .set_level(Wire::Aic(AicInput::new(0, 1)), true);
            if self.1 {
                access.request_reset(self.name(), "reached read before refusal");
                return Err(crate::platform::apple::bus::refuse(
                    self.name(), offset, width,
                    crate::platform::apple::bus::Direction::Read, "retained read prefix",
                ));
            }
            Ok(u64::from(value))
        }
        fn write(
            &mut self,
            offset: u64,
            width: Width,
            _value: u64,
            _access: &mut Access<'_>,
        ) -> Result<(), MmioError> {
            Err(crate::platform::apple::bus::refuse(
                self.name(),
                offset,
                width,
                crate::platform::apple::bus::Direction::Write,
                "read-only consuming test register",
            ))
        }
    }

    #[test]
    fn consumed_scalar_survives_failed_wire_delivery_without_repeating_the_read() {
        let mut board = AppleDevices::new();
        let reads = Rc::new(Cell::new(7));
        board
            .bus
            .install(Box::new(Reader(reads.clone(), false)), &[(0x1000, 4, 0)])
            .unwrap();
        let consumed = board.consume_scalar_read(0, 0x1000, 4, 9, None).unwrap();
        assert_eq!(consumed.value, 7);
        assert!(consumed.settlement.is_err());
        assert_eq!(reads.get(), 8);
        assert_eq!(board.pending_service().unwrap().committed(), 0);
        board
            .add_aic(0x10000, 32, AicLayout::aic2(0x8000, 1))
            .unwrap();
        board.settle(0, 10, None).unwrap();
        assert!(board.pending_service().is_none());
        assert_eq!(reads.get(), 8);
    }
    #[test]
    fn refused_read_keeps_its_reached_reset_and_original_wire_context() {
        let mut board = AppleDevices::new();
        let reads = Rc::new(Cell::new(7));
        board.bus.install(Box::new(Reader(reads.clone(), true)), &[(0x1000, 4, 0)]).unwrap();
        assert!(board.consume_scalar_read(5, 0x1000, 4, 0x55, None).is_err());
        assert_eq!(reads.get(), 8);
        let pending = board.pending_service().unwrap();
        assert_eq!(pending.committed(), 0);
        assert_eq!(pending.inputs(), &[ServiceInput::Aic(AicDelivery {
            input: AicInput::new(0, 1), level: true, cpu: 5, now: 0x55,
        })]);
        assert_eq!(pending.resets().len(), 1);
        assert!(board.take_reset().unwrap().reason.contains("reached read before refusal"));
        assert_eq!(reads.get(), 8);
    }

}
