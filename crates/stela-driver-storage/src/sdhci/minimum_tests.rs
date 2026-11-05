// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual minimum failures retain preparation/Host ownership and fence effects.
use super::model::{CLOCK_TICKS_PER_US, Hardware, O2Chip, Port};
use super::*;
use crate::{
    bus::dma::TestRegion,
    bus::pci::power::{Error, Timer},
};
use core::cell::Cell;
struct Minimum {
    unavailable: Cell<bool>,
    fail: Cell<bool>,
}
// SAFETY: private software hardware model boundary; never a native provider.
unsafe impl Timer for Minimum {
    fn check(&self) -> Result<(), Error> {
        if self.unavailable.get() {
            Err(Error::Clock)
        } else {
            Ok(())
        }
    }
    fn wait_us(&self, us: u64) -> Result<(), Error> {
        self.check()?;
        if self.fail.get() {
            return Err(Error::Clock);
        }
        model::minimum().wait_us(us)
    }
}
fn minimum(fail: bool) -> Rc<Minimum> {
    Rc::new(Minimum {
        unavailable: Cell::new(false),
        fail: Cell::new(fail),
    })
}
fn clock() -> Clock {
    Clock {
        ticks_per_microsecond: CLOCK_TICKS_PER_US,
    }
}
#[test]
fn unavailable_minimum_returns_the_original_slot_before_allocation_or_mmio() {
    let hardware = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    let minimum = minimum(false);
    minimum.unavailable.set(true);
    let weak = Rc::downgrade(&minimum);
    struct NoAllocation;
    impl DmaAllocator for NoAllocation {
        fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
            panic!("no allocation before actual minimum admission")
        }
    }
    let refusal = Host::new(
        Box::new(Port(hardware.clone())),
        clock(),
        minimum.clone(),
        "unavailable minimum".into(),
        &mut NoAllocation,
        Profile::Standard,
    )
    .err()
    .expect("typed refusal");
    assert_eq!(refusal.error, BlockError::PciPower(Error::Clock));
    assert!(matches!(&*refusal.owner, FailedHost::Preparation(_)));
    drop(minimum);
    assert!(
        weak.upgrade().is_some(),
        "original provider belongs to returned preparation"
    );
    assert_eq!(hardware.borrow().reads, 0);
    assert!(hardware.borrow().writes.is_empty());
}
#[test]
fn late_power_quiet_failure_returns_fenced_host_with_both_dma_allocations() {
    let hardware = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    let minimum = minimum(true);
    let weak = Rc::downgrade(&minimum);
    let mut dma = TestRegion::new(128 * 1024 * 8);
    let refusal = Host::new(
        Box::new(Port(hardware.clone())),
        clock(),
        minimum.clone(),
        "late minimum".into(),
        &mut dma,
        Profile::Standard,
    )
    .err()
    .expect("typed owning refusal");
    assert_eq!(refusal.error, BlockError::PciPower(Error::Clock));
    let FailedHost::Host(mut owner) = refusal.owner.into_inner() else {
        panic!("actual formed Host must remain owned")
    };
    drop(minimum);
    assert!(weak.upgrade().is_some());
    assert_eq!(owner.inner.borrow().data.len(), TRANSFER_BYTES);
    assert_eq!(owner.inner.borrow().descriptors.len(), 4096);
    let before = (hardware.borrow().reads, hardware.borrow().writes.len());
    assert_eq!(owner.poll().err(), Some(BlockError::PciPower(Error::Clock)));
    assert_eq!(
        owner.inner.borrow_mut().power_off(),
        Err(BlockError::PciPower(Error::Clock))
    );
    assert_eq!(
        (hardware.borrow().reads, hardware.borrow().writes.len()),
        before,
        "no compensating accesses or retries"
    );
}
#[test]
fn o2_failed_assertion_minimum_never_releases_or_cleans_the_pll() {
    let chip = Rc::new(RefCell::new(O2Chip::new(0x8320)));
    let hardware = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    hardware.borrow_mut().o2_chip = Some(chip);
    let result = pci::o2_stabilize(&mut Port(hardware.clone()), clock(), minimum(true).as_ref());
    assert_eq!(result, Err(BlockError::PciPower(Error::Clock)));
    let writes = &hardware.borrow().writes;
    assert_eq!(
        writes.len(),
        1,
        "one assertion only: neither release, force-active nor cleanup"
    );
    assert_eq!(writes[0].0, 0x1cc);
    assert_ne!(writes[0].2 & (1 << 12), 0);
}

mod shared;
mod unwind;
