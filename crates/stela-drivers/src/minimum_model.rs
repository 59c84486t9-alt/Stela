//! Private device-fixture minimum time: owns the current thread's virtual clock.
//! This module is compiled only for tests and creates no native timing permit.
extern crate std;
use crate::{
    Clock,
    bus::pci::power::{Error, Timer},
    test_clock,
};
use alloc::rc::Rc;
use std::thread::{self, ThreadId};
struct Minimum {
    _clock: test_clock::Guard,
    owner: ThreadId,
    scale: Clock,
    refused: bool,
}
// SAFETY: this test-only producer owns its actual thread-local virtual clock
// guard. Waits advance that same fixture clock; no physical device is admitted.
unsafe impl Timer for Minimum {
    fn check(&self) -> Result<(), Error> {
        if self.refused || thread::current().id() != self.owner || test_clock::read().is_none() {
            return Err(Error::Clock);
        }
        self.scale.check_duration(0).map_err(|_| Error::Clock)
    }
    fn wait_us(&self, microseconds: u64) -> Result<(), Error> {
        self.check()?;
        self.scale
            .check_duration(microseconds)
            .map_err(|_| Error::Clock)?;
        test_clock::advance(self.scale, microseconds);
        Ok(())
    }
}
pub(crate) fn owned(scale: Clock) -> Rc<dyn Timer> {
    Rc::new(Minimum {
        _clock: test_clock::virtualize(),
        owner: thread::current().id(),
        scale,
        refused: false,
    })
}
pub(crate) fn refusing(scale: Clock) -> Rc<dyn Timer> {
    Rc::new(Minimum {
        _clock: test_clock::virtualize(),
        owner: thread::current().id(),
        scale,
        refused: true,
    })
}
