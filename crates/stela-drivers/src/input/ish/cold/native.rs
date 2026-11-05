// SPDX-License-Identifier: GPL-2.0-only
//! Keep original ISH ownership while preparing source DMA containment.
use super::{
    super::{Error as ControllerError, MappedRegisters, NativeClock},
    StopAttempt,
};
use crate::bus::pci::{ConfigSpace, requester::preparation::PreparingRequester};
use alloc::boxed::Box;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Prerequisite {
    OriginalNotificationOwner,
    InheritedAddressInvalidation,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Controller(ControllerError),
    Power(crate::block::BlockError),
    Missing([Prerequisite; 2]),
    Interrupted,
    Terminal,
}
impl From<crate::bus::pci::ConfigError> for Error {
    fn from(error: crate::bus::pci::ConfigError) -> Self {
        Self::Controller(ControllerError::ConfigAccess(error))
    }
}
impl From<crate::bus::pci::CapabilityError> for Error {
    fn from(error: crate::bus::pci::CapabilityError) -> Self {
        Self::Controller(ControllerError::Capability(error))
    }
}
struct Resources<R, T> {
    requester: PreparingRequester,
    registers: R,
    clock: T,
}
pub struct Original<
    R: super::super::Registers = MappedRegisters,
    T: super::super::Time = NativeClock,
> {
    resources: Option<Box<Resources<R, T>>>,
    stop: StopAttempt,
    attempted: bool,
    failure: Option<Error>,
}
impl<R: super::super::Registers, T: super::super::Time> Drop for Original<R, T> {
    fn drop(&mut self) {
        core::mem::forget(self.resources.take());
    }
}
impl<R: super::super::Registers, T: super::super::Time> Original<R, T> {
    /// # Safety
    /// Actual original requester/root/config and complete UC BAR0 belong to the
    /// same kept exclusive epoch. Prior conflicting reset/source writers cannot
    /// race. The clock meets NativeClock's advancing process-context contract.
    pub unsafe fn new(requester: PreparingRequester, registers: R, clock: T) -> Self {
        Self {
            resources: Some(Box::new(Resources {
                requester,
                registers,
                clock,
            })),
            stop: StopAttempt::new(),
            attempted: false,
            failure: None,
        }
    }
    pub fn prepare(&mut self) -> Result<(), Error> {
        if self.attempted {
            return Err(self.failure.clone().unwrap_or(Error::Terminal));
        }
        self.attempted = true;
        self.failure = Some(Error::Interrupted);
        let result = (|| {
            let r = self.resources.as_mut().unwrap();
            let function = r.requester.function_mut();
            let address = function.address;
            let metadata = (function.vendor, function.device, function.class);
            let config = function.config();
            let class = config.read32(8)?;
            if config.address() != address
                || metadata
                    != (
                        0x8086,
                        0x9d35,
                        [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
                    )
                || class == u32::MAX
                || config.read8(0x0e)? & 0x7f != 0
                || config.read32(0)? != 0x9d35_8086
                || config.read16(4)? & 0x406 != 0x402
                || !crate::bus::pci::capability::stopped_in_d0(config)?
            {
                return Err(Error::Controller(ControllerError::Requirement(
                    "same gated original ISH requester",
                )));
            }
            let bar = config.read32(0x10)?;
            let wide = bar & 7 == 4;
            let high = if wide { config.read32(0x14)? } else { 0 };
            if bar == u32::MAX
                || bar & 15 != if wide { 4 } else { 0 }
                || (u64::from(bar & !15) | (u64::from(high) << 32)) != r.registers.span().start()
                || r.registers.span().bytes() < 0x400
            {
                return Err(Error::Controller(ControllerError::Requirement(
                    "same original ISH BAR0",
                )));
            }
            self.stop
                .stop(&r.registers, &r.clock)
                .map_err(Error::Controller)
        })();
        self.failure = result.as_ref().err().cloned();
        result
    }
    /// Both prerequisites are independent of register stop and source masking.
    /// No successful caller path acknowledges a quiescence receipt here.
    pub const fn migration_prerequisites() -> [Prerequisite; 2] {
        [
            Prerequisite::OriginalNotificationOwner,
            Prerequisite::InheritedAddressInvalidation,
        ]
    }
}
