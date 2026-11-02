// SPDX-License-Identifier: GPL-2.0-or-later
//! Genuine minimum-provider failures fence physical access and retain ownership.
use super::*;
use crate::bus::pci::power::{Error, Timer};
use core::cell::Cell;

struct Minimum {
    fail: Cell<bool>,
    waits: Cell<usize>,
}
// SAFETY: This test-only boundary models provider success/failure. It never
// supplies a native grant; successful intervals use the existing model clock.
unsafe impl Timer for Minimum {
    fn check(&self) -> Result<(), Error> {
        Ok(())
    }
    fn wait_us(&self, us: u64) -> Result<(), Error> {
        self.waits.set(self.waits.get() + 1);
        if self.fail.get() {
            return Err(Error::Clock);
        }
        ModelTimer(Clock {
            ticks_per_microsecond: 1000,
        })
        .wait_us(us)
    }
}
fn effects(chip: &Rc<RefCell<Chip>>) -> (usize, usize) {
    let chip = chip.borrow();
    (chip.accesses, chip.effects.len())
}
#[test]
fn constructor_quiet_failure_keeps_original_graph_without_publishing_a_host() {
    let chip = Chip::new(false, true);
    let minimum = Rc::new(Minimum {
        fail: Cell::new(true),
        waits: Cell::new(0),
    });
    let retained = Rc::downgrade(&minimum);
    let before = Rc::strong_count(&chip);
    assert_eq!(
        make_host_with_minimum(&chip, false, minimum.clone()).err(),
        Some(BlockError::PciPower(Error::Clock))
    );
    drop(minimum);
    assert!(
        retained.upgrade().is_some(),
        "failed preparation owns same actual minimum"
    );
    assert!(
        Rc::strong_count(&chip) > before,
        "same original PCI and MMIO model owners remain held even after refusal is dropped"
    );
    assert_eq!(retained.upgrade().unwrap().waits.get(), 1);
}

#[test]
fn pll_quiet_failure_never_releases_low_frequency_clock_or_retries() {
    let chip = Chip::new(false, true);
    let minimum = Rc::new(Minimum {
        fail: Cell::new(false),
        waits: Cell::new(0),
    });
    let mut host = make_host_with_minimum(&chip, false, minimum.clone()).unwrap();
    minimum.fail.set(true);
    assert_eq!(
        host.inner.borrow_mut().set_clock(400_000).err(),
        Some(BlockError::PciPower(Error::Clock))
    );
    let before = effects(&chip);
    assert_eq!(host.poll().err(), Some(BlockError::PciPower(Error::Clock)));
    assert_eq!(
        host.inner.borrow_mut().power_off().err(),
        Some(BlockError::PciPower(Error::Clock))
    );
    assert_eq!(effects(&chip), before);
}
