// SPDX-License-Identifier: MIT
//! Owned minimum intervals, distinct from nominal polling deadlines.
use super::*;
use crate::bus::pci::power::{Error, Timer};
use core::{cell::Cell, mem::ManuallyDrop, sync::atomic::AtomicU64};

static RETAINED: AtomicU64 = AtomicU64::new(0);
struct State {
    timer: ManuallyDrop<Rc<dyn Timer>>,
    failure: Cell<Option<Error>>,
}
impl Drop for State {
    fn drop(&mut self) {
        // No generic controller teardown proves the native timer's CPU/source
        // retirement. Keep the actual provider even on abandoned failure.
        let _ = RETAINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(1))
        });
    }
}
#[derive(Clone)]
pub(super) struct Minimum(Rc<State>);
impl Minimum {
    pub fn retain(timer: Rc<dyn Timer>) -> Self {
        Self(Rc::new(State {
            timer: ManuallyDrop::new(timer),
            failure: Cell::new(None),
        }))
    }
    pub fn error(&self) -> Option<Error> {
        self.0.failure.get()
    }
    pub fn source_result<T>(&self, result: Result<T, Error>) -> Result<T, BlockError> {
        if let Err(error) = &result
            && self.0.failure.get().is_none()
        {
            self.0.failure.set(Some(*error));
        }
        if let Some(error) = self.error() {
            return Err(BlockError::PciPower(error));
        }
        result.map_err(BlockError::PciPower)
    }
    pub fn check(&self) -> Result<(), BlockError> {
        if let Some(error) = self.error() {
            return Err(BlockError::PciPower(error));
        }
        self.source_result(self.0.timer.check())
    }
    pub fn wait_us(&self, microseconds: u64) -> Result<(), BlockError> {
        self.check()?;
        self.source_result(self.0.timer.wait_us(microseconds))?;
        self.check()
    }
    pub fn timer(&self) -> &Rc<dyn Timer> {
        &self.0.timer
    }
}
pub(super) fn retained() -> u64 {
    RETAINED.load(Ordering::Relaxed)
}
/// A latched minimum failure blocks every later register effect, including
/// internal cleanup paths that have no fallible register ABI. It never
/// substitutes successful retirement: owner/DMA retention remains mandatory.
pub(super) struct Gate {
    registers: ManuallyDrop<Box<dyn Registers>>,
    pub minimum: Minimum,
}
impl Gate {
    pub fn retain(registers: Box<dyn Registers>, minimum: Minimum) -> Self {
        Self {
            registers: ManuallyDrop::new(registers),
            minimum,
        }
    }
}
// The raw register ABI has no acknowledged retirement operation. Neither an
// abandoned constructor nor Controller Drop proves that backend destruction
// may release MMIO/configuration authority. Keep that original owner.
impl Registers for Gate {
    fn read32(&mut self, at: usize) -> u32 {
        if self.minimum.error().is_some() {
            u32::MAX
        } else {
            self.registers.read32(at)
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        if self.minimum.error().is_none() {
            self.registers.write32(at, value);
        }
    }
    fn size(&self) -> Option<usize> {
        self.registers.size()
    }
}
#[cfg(test)]
pub(super) fn fixture(clock: Clock) -> Minimum {
    Minimum::retain(crate::minimum_model::owned(clock))
}

#[cfg(test)]
mod tests;
