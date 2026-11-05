//! Device minimum delays on the invariant TSC: one unprivileged read, the
//! same on bare metal and in a VM, with no controller to own.
use super::fenced as now;
use alloc::{boxed::Box, rc::Rc};
use stela_boot_core::tsc::NominalRate;
use stela_drivers::bus::pci::power::{Error, Interval, Timer};

/// The longest interval accepted, far past PCI's 60 s readiness bound, so a
/// raw counter difference never wraps inside one.
const LONGEST_US: u64 = 3_600_000_000;

pub(crate) struct Minimum(NominalRate);

impl Minimum {
    /// A timer on `hz`, the boot's calibrated TSC rate, when the counter is
    /// invariant: it then runs at that rate through P-, C- and T-states.
    pub(crate) fn timer(hz: u64, invariant: bool) -> Option<Rc<dyn Timer>> {
        let rate = NominalRate::new(hz).ok()?;
        invariant.then(|| Rc::new(Self(rate)) as Rc<dyn Timer>)
    }

    fn ticks(&self, microseconds: u64) -> Result<u64, Error> {
        if microseconds > LONGEST_US {
            return Err(Error::Clock);
        }
        self.0
            .ticks_for_minimum_ns(microseconds * 1000)
            .map_err(|_| Error::Clock)
    }
}

struct Deadline {
    start: u64,
    ticks: u64,
}

impl Interval for Deadline {
    fn elapsed(&self) -> Result<bool, Error> {
        Ok(now().wrapping_sub(self.start) >= self.ticks)
    }
}

// SAFETY: an invariant TSC counts real time at the calibrated rate, whose
// error the rate's margin covers, and every wait rounds up. Waits count
// from a fenced start, and an interval holds its own start.
unsafe impl Timer for Minimum {
    fn check(&self) -> Result<(), Error> {
        self.ticks(0).map(|_| ())
    }

    fn wait_us(&self, microseconds: u64) -> Result<(), Error> {
        let deadline = Deadline {
            ticks: self.ticks(microseconds)?,
            start: now(),
        };
        while !deadline.elapsed()? {
            crate::status::tick();
            core::hint::spin_loop();
        }
        Ok(())
    }

    fn begin_interval(&self, microseconds: u64) -> Result<Option<Box<dyn Interval>>, Error> {
        Ok(Some(Box::new(Deadline {
            ticks: self.ticks(microseconds)?,
            start: now(),
        })))
    }
}
