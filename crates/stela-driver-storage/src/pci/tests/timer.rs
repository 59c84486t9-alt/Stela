// SPDX-License-Identifier: GPL-2.0-or-later
//! Private PCI-layout model time; no native minimum-delay permission.
use super::Clock;
use crate::bus::pci::power::{Error, Timer};
pub(super) struct Minimum(pub(super) Clock);
// SAFETY: only software PCI layout tests use this checked counter boundary.
unsafe impl Timer for Minimum {
    fn check(&self) -> Result<(), Error> {
        self.0.check_duration(60_000_000).map_err(|_| Error::Clock)
    }
    fn wait_us(&self, microseconds: u64) -> Result<(), Error> {
        self.check()?;
        self.0.try_delay(microseconds).map_err(|_| Error::Clock)
    }
}
