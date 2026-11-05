//! Private device-fixture minimum time: owns the current thread's virtual clock.
//! This module is compiled only for tests and creates no native timing permit.
extern crate std;
use crate::{
    Clock, Deadline,
    bus::pci::power::{Error, Interval, Timer},
    test_clock,
};
use alloc::{boxed::Box, rc::Rc};
use std::thread::{self, ThreadId};
struct Minimum {
    _clock: test_clock::Guard,
    owner: ThreadId,
    scale: Clock,
    refused: bool,
}
struct ModelInterval {
    _clock: test_clock::Guard,
    owner: ThreadId,
    deadline: Deadline,
}
impl Interval for ModelInterval {
    fn elapsed(&self) -> Result<bool, Error> {
        if thread::current().id() != self.owner {
            return Err(Error::Clock);
        }
        Ok(self.deadline.passed())
    }
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
    fn begin_interval(&self, microseconds: u64) -> Result<Option<Box<dyn Interval>>, Error> {
        self.check()?;
        let deadline = self
            .scale
            .try_deadline(microseconds)
            .map_err(|_| Error::Clock)?;
        Ok(Some(Box::new(ModelInterval {
            _clock: test_clock::virtualize(),
            owner: self.owner,
            deadline,
        })))
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
