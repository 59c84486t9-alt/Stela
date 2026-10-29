//! Native calibration refusal must precede bus, IRQ and companion effects.
use super::super::*;
use crate::{
    Clock, ClockError,
    bus::{i2c, smbus},
};

struct Bus;
impl i2c::Bus for Bus {
    fn transaction(
        &mut self,
        _: i2c::Address,
        _: &mut [i2c::Operation<'_>],
    ) -> Result<(), i2c::Error> {
        panic!("invalid native clock reached actual I2C effects")
    }
}
impl smbus::Bus for Bus {
    fn transaction(
        &mut self,
        _: smbus::Address,
        _: smbus::Transaction<'_>,
        _: bool,
    ) -> Result<(), smbus::Error> {
        panic!("invalid native clock reached actual SMBus effects")
    }
}
impl smbus::I2cBlockBus for Bus {
    fn read_i2c_block(
        &mut self,
        _: smbus::Address,
        _: u8,
        _: &mut [u8],
    ) -> Result<(), smbus::Error> {
        panic!("I2C block read")
    }
    fn write_i2c_block(&mut self, _: smbus::Address, _: u8, _: &[u8]) -> Result<(), smbus::Error> {
        panic!("I2C block write")
    }
}
struct Pin;
impl hid_i2c::Interrupt for Pin {
    fn mask_and_drain(&mut self) -> Result<(), hid_i2c::InterruptError> {
        panic!("invalid native clock changed IRQ")
    }
    fn asserted(&mut self) -> Result<bool, hid_i2c::InterruptError> {
        panic!("invalid native clock read IRQ")
    }
}
impl rmi::Attention for Pin {
    fn mask_and_drain(&mut self) -> Result<(), rmi::AttentionError> {
        panic!("invalid native clock changed attention")
    }
    fn pending(&mut self) -> Result<bool, rmi::AttentionError> {
        panic!("invalid native clock read attention")
    }
    fn acknowledge(&mut self) -> Result<(), rmi::AttentionError> {
        panic!("invalid native clock retired attention")
    }
}
impl rmi::transport::Companion for Pin {
    fn reset_for_smbus(&mut self) -> Result<(), rmi::transport::CompanionError> {
        panic!("invalid native clock reset companion")
    }
    fn restore_ps2(&mut self) -> Result<(), rmi::transport::CompanionError> {
        panic!("invalid native clock restored companion")
    }
}

#[test]
fn native_input_calibration_and_interval_failures_precede_transport_and_irq_effects() {
    for (rate, expected) in [
        (0, ClockError::Uncalibrated),
        (u64::MAX, ClockError::DurationOverflow),
    ] {
        let clock = Clock {
            ticks_per_microsecond: rate,
        };
        let address = i2c::Address::SevenBit(0x15);
        assert_eq!(
            hid_i2c::Device::new(Bus, Pin, clock, address, 1, 100_000)
                .err()
                .unwrap()
                .kind,
            hid_i2c::ErrorKind::Clock(expected)
        );
        assert_eq!(
            elan::I2cDevice::new(Bus, Pin, clock, address)
                .err()
                .unwrap()
                .kind,
            elan::ErrorKind::Clock(expected)
        );
        assert_eq!(
            cyapa::Device::new(Bus, Pin, clock, address)
                .err()
                .unwrap()
                .kind,
            cyapa::ErrorKind::Clock(expected)
        );
        assert_eq!(
            cyapa::pip::Device::new_gen6(Bus, Pin, clock, address)
                .err()
                .unwrap()
                .kind,
            cyapa::pip::ErrorKind::Clock(expected)
        );
        assert_eq!(
            cyapa::Device::new_smbus(Bus, Pin, clock, smbus::Address::new(0x15).unwrap())
                .err()
                .unwrap()
                .kind,
            cyapa::ErrorKind::Clock(expected)
        );
        let mut device =
            elan::smbus::Device::new(Bus, Pin, clock, smbus::Address::new(0x15).unwrap());
        assert_eq!(
            device.initialize().unwrap_err().kind,
            elan::ErrorKind::Clock(expected)
        );
        assert_eq!(device.state(), elan::State::Fresh);
        let transport = rmi::transport::I2c::new(Bus, address).unwrap();
        assert_eq!(
            rmi::Device::new(transport, Pin, clock, rmi::Configuration::default()).err(),
            Some(rmi::Error::Clock(expected))
        );
        assert_eq!(
            rmi::transport::Smbus::new(
                Bus,
                smbus::Address::new(0x15).unwrap(),
                Pin,
                clock,
                100_000
            )
            .err(),
            Some(rmi::Error::Clock(expected))
        );
    }
}
