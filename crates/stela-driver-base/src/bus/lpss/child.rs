// SPDX-License-Identifier: GPL-2.0-only
//! Real DesignWare PIO child, keeping the original LPSS resources on failure.
use super::*;
use crate::bus::i2c::{self, Bus, DesignWare, Operation, Timer};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachError {
    Platform(Error),
    I2c(i2c::Error),
}
pub struct AttachFailure {
    pub error: AttachError,
    /// Owners rejected before any hardware programming. None means the
    /// original resources are quarantined after possible effects.
    pub unmodified: Option<NativeResources>,
}
/// A disabled/reset owner produced only by successful retirement.
pub struct Retired<R: Registers> {
    pub(super) registers: R,
}
impl Retired<NativeRegisters> {
    pub fn into_resources(self) -> NativeResources {
        self.registers.into_resources()
    }
}
struct Child<R: ChildAccess>(Controller<R>);
impl<R: ChildAccess> i2c::Registers for Child<R> {
    fn read32(&mut self, offset: usize) -> u32 {
        self.0.registers.as_mut().unwrap().child_read32(offset)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.0
            .registers
            .as_mut()
            .unwrap()
            .child_write32(offset, value);
    }
}
/// The existing PIO FIFO engine. Drop keeps the whole live engine;
/// explicit acknowledged shutdown returns the original disabled/reset owners.
pub struct I2c<R: ChildAccess, T: Timer + 'static> {
    engine: Option<DesignWare<Child<R>, T>>,
}
impl<R: ChildAccess> Controller<R> {
    /// # Safety
    /// Timing counts are firmware/board-derived values for this exact
    /// source profile's input clock, rise/fall/hold wiring and power epoch.
    /// Neither this source clock nor its hold/falling properties authorize
    /// guessed SCL counts. SDA_HOLD must include RX hold requirements
    /// as well as TX hold; source nanoseconds alone are not that register.
    /// This owner is the sole child; no iDMA/IRQ is enabled.
    pub unsafe fn into_i2c<T: Timer + 'static>(
        self,
        timer: T,
        config: i2c::Config,
    ) -> Result<I2c<R, T>, i2c::Error> {
        let engine = DesignWare::new(Child(self), timer, config)?;
        Ok(I2c {
            engine: Some(engine),
        })
    }
}
impl<T: Timer + 'static> I2c<NativeRegisters, T> {
    /// # Safety
    /// All NativeRegisters mapping/stopped epoch and Controller board-timing
    /// contracts hold for the same native Function. No generic alias or
    /// firmware resource override is allowed, including the Surface Go quirks.
    #[expect(
        clippy::result_large_err,
        reason = "native refusal returns the complete original config and BAR graph without allocating"
    )]
    pub unsafe fn attach_native(
        requester: StoppedRequester,
        mapping: Mapping,
        timer: T,
        config: i2c::Config,
    ) -> Result<Self, AttachFailure> {
        if config.timeout_us == 0
            || config.recovery_timeout_us == 0
            || timer.check_duration(config.timeout_us).is_err()
            || timer.check_duration(config.recovery_timeout_us).is_err()
        {
            return Err(AttachFailure {
                error: AttachError::I2c(i2c::ErrorKind::InvalidConfiguration.into()),
                unmodified: Some((requester.into_function(), mapping)),
            });
        }
        // SAFETY: same mapped/stopped function permission as this entry.
        let registers = unsafe { NativeRegisters::claim(requester, mapping) }.map_err(
            |(error, resources)| AttachFailure {
                error: AttachError::Platform(error),
                unmodified: Some(resources),
            },
        )?;
        let owner =
            Controller::initialize(registers).map_err(|(error, registers)| AttachFailure {
                error: AttachError::Platform(error),
                unmodified: registers.map(NativeRegisters::into_resources),
            })?;
        // SAFETY: this entry requires observed board timing/clock grants.
        unsafe { owner.into_i2c(timer, config) }.map_err(|error| AttachFailure {
            error: AttachError::I2c(error),
            unmodified: None,
        })
    }
}
impl<R: ChildAccess, T: Timer + 'static> Bus for I2c<R, T> {
    fn transaction(
        &mut self,
        address: i2c::Address,
        operations: &mut [Operation<'_>],
    ) -> Result<(), i2c::Error> {
        self.engine
            .as_mut()
            .unwrap()
            .transaction(address, operations)
    }
}
impl<R: ChildAccess, T: Timer + 'static> I2c<R, T> {
    pub fn shutdown(mut self) -> Result<(Retired<R>, T), AttachError> {
        let (child, timer) = self
            .engine
            .take()
            .unwrap()
            .shutdown()
            .map_err(AttachError::I2c)?;
        // SAFETY: the same child acknowledged disable; no mutable or
        // shared child escape exists and this owner never enabled DMA/IRQs.
        let retired = unsafe { child.0.retire() }.map_err(AttachError::Platform)?;
        Ok((retired, timer))
    }
}
impl<R: ChildAccess, T: Timer + 'static> Drop for I2c<R, T> {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.take() {
            core::mem::forget(engine);
        }
    }
}
