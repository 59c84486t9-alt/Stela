// SPDX-License-Identifier: GPL-2.0-or-later
//! The actual shared O2 control is fenced before any minimum callback/effect.
use super::super::model::O2ConfigPort;
use super::*;
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn slot(chip: &Rc<RefCell<O2Chip>>) -> Rc<RefCell<Hardware>> {
    let slot = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    {
        let mut s = slot.borrow_mut();
        s.o2_chip = Some(chip.clone());
        s.adma_broken = true;
        s.caps = (s.caps & !(255 << 8)) | 200 << 8;
    }
    chip.borrow_mut().slots.push(Rc::downgrade(&slot));
    slot
}
#[expect(
    clippy::result_large_err,
    reason = "Return the same affine device, mapping and timer graph without a fallible failure-path allocation."
)]
fn host(
    slot: &Rc<RefCell<Hardware>>,
    control: &Control,
    minimum: Rc<dyn Timer>,
    dma: &mut dyn DmaAllocator,
) -> Result<Host, HostFailure> {
    Host::new_with_controller(
        Box::new(Port(slot.clone())),
        clock(),
        minimum,
        "shared actual O2 control".into(),
        dma,
        Profile::O2Legacy,
        Some(control.clone()),
    )
}
struct Probe {
    control: Control,
    denied: Rc<Cell<bool>>,
}
// SAFETY: software callback/reentry test, never a native minimum grant.
unsafe impl Timer for Probe {
    fn check(&self) -> Result<(), Error> {
        Ok(())
    }
    fn wait_us(&self, _: u64) -> Result<(), Error> {
        self.denied.set(self.control.borrow().healthy().is_err());
        panic!("minimum provider callback unwind")
    }
}
#[test]
fn shared_gate_precedes_provider_callback_and_stays_closed_after_unwind() {
    let chip = Rc::new(RefCell::new(O2Chip::new(0x8320)));
    let slot = slot(&chip);
    let control = Controller::model(Box::new(O2ConfigPort(chip.clone())), 0x8320_1217);
    control.borrow_mut().prepare().unwrap();
    let mut dma = TestRegion::new(128 * 1024 * 8);
    let mut owner = host(&slot, &control, model::minimum(), &mut dma).unwrap();
    let denied = Rc::new(Cell::new(false));
    owner.inner.borrow_mut().minimum = Rc::new(Probe {
        control: control.clone(),
        denied: denied.clone(),
    });
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = owner.inner.borrow_mut().o2_card_present();
        }))
        .is_err()
    );
    assert!(
        denied.get(),
        "same actual shared owner denies reentry before callback"
    );
    assert!(control.borrow().healthy().is_err());
    let before = (
        slot.borrow().reads,
        slot.borrow().writes.len(),
        chip.borrow().reads,
        chip.borrow().writes.len(),
    );
    assert!(owner.poll().is_err());
    assert_eq!(
        (
            slot.borrow().reads,
            slot.borrow().writes.len(),
            chip.borrow().reads,
            chip.borrow().writes.len()
        ),
        before
    );
}
#[test]
fn later_slot_failure_removes_prior_shared_card_and_host_from_ready_inventory() {
    let chip = Rc::new(RefCell::new(O2Chip::new(0x8320)));
    let first = slot(&chip);
    let second = slot(&chip);
    let control = Controller::model(Box::new(O2ConfigPort(chip)), 0x8320_1217);
    control.borrow_mut().prepare().unwrap();
    let mut dma = TestRegion::new(128 * 1024 * 8);
    let mut first_host = host(&first, &control, model::minimum(), &mut dma).unwrap();
    let card = first_host.poll().unwrap().unwrap();
    let failure = host(&second, &control, minimum(true), &mut dma)
        .err()
        .expect("later actual slot failure");
    let FailedHost::Host(second_host) = failure.owner.into_inner() else {
        panic!("formed second slot owner")
    };
    let mut attached = Attached {
        hosts: alloc::vec![first_host],
        failed_hosts: alloc::vec![second_host],
        failed_slots: Vec::new(),
        cards: alloc::vec![card],
        failures: alloc::vec![(1, failure.error)],
    };
    fence_failed_shared_hosts(&mut attached, Some(&control));
    assert!(attached.hosts.is_empty());
    assert!(attached.cards.is_empty());
    assert_eq!(attached.failed_hosts.len(), 2);
}
