//! The physical quiet interval and nominal poll domain are independent.
extern crate std;
use super::*;
use crate::bus::pci::power::{Error as TimeError, Timer as MinimumTimer};
use alloc::rc::Rc;
use core::cell::{Cell, RefCell};
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Minimum {
    wall: Arc<AtomicU64>,
    checks: Cell<usize>,
    waits: RefCell<Vec<u64>>,
    check_error: Cell<Option<TimeError>>,
    wait_error: Cell<Option<TimeError>>,
    panic_check: Cell<bool>,
    panic_wait: Cell<bool>,
}
impl Minimum {
    fn new(model: &Model) -> Rc<Self> {
        Rc::new(Self {
            wall: model.wall.clone(),
            checks: Cell::new(0),
            waits: RefCell::new(Vec::new()),
            check_error: Cell::new(None),
            wait_error: Cell::new(None),
            panic_check: Cell::new(false),
            panic_wait: Cell::new(false),
        })
    }
}
// SAFETY: this explicit device fixture owns its separate modeled physical wall
// counter. Only successful waits advance it by the complete requested interval;
// no caller-supplied nominal milliseconds or production Clock grants a wait.
unsafe impl MinimumTimer for Minimum {
    fn check(&self) -> Result<(), TimeError> {
        self.checks.set(self.checks.get() + 1);
        assert!(
            !self.panic_check.get(),
            "injected pre-effect minimum callback panic"
        );
        self.check_error.get().map_or(Ok(()), Err)
    }
    fn wait_us(&self, us: u64) -> Result<(), TimeError> {
        self.check()?;
        self.waits.borrow_mut().push(us);
        assert!(
            !self.panic_wait.get(),
            "injected post-HRR minimum callback panic"
        );
        if let Some(error) = self.wait_error.get() {
            return Err(error);
        }
        let now = self
            .wall
            .load(Ordering::Relaxed)
            .checked_add(us)
            .ok_or(TimeError::Clock)?;
        self.wall.store(now, Ordering::Relaxed);
        Ok(())
    }
}
pub(super) fn minimum(model: &Model) -> Rc<dyn MinimumTimer> {
    Minimum::new(model)
}

#[test]
fn first_hrr_read_follows_real_minimum_even_when_nominal_time_does_not_advance() {
    let (mut pci, model) = fixture(0x1022, 0x1668, 0x0c0340, 0x40, 8);
    model.state.lock().unwrap().reset_delay = 0;
    let minimum = Minimum::new(&model);
    // SAFETY: same exclusive synthetic function/BAR/epoch with original R owning
    // its real modeled configuration state; no DMA/IRQ or sibling owner exists.
    let mut controller =
        unsafe { Controller::new(&mut pci, model.clone(), minimum.clone()) }.unwrap();
    assert_eq!(poll(&mut controller, 0).unwrap(), None);
    assert!(model.state.lock().unwrap().reset_read_wall.is_empty());
    assert!(poll(&mut controller, 0).unwrap().is_some());
    let state = model.state.lock().unwrap();
    assert_eq!(*minimum.waits.borrow(), vec![100_000]);
    assert_eq!(state.reset_read_wall.len(), 1);
    assert!(state.reset_read_wall[0] - state.reset_write_wall.unwrap() >= 100_000);
    drop(state);
    drop(controller);
    assert_eq!(Rc::strong_count(&minimum), 1);
}
#[test]
fn unavailable_minimum_prevents_hrr_and_terminally_keeps_the_same_graph() {
    let (mut pci, model) = fixture(0x1022, 0x1668, 0x0c0340, 0x40, 8);
    let minimum = Minimum::new(&model);
    // SAFETY: the exact synthetic requester and stopped resources above.
    let mut controller =
        unsafe { Controller::new(&mut pci, model.clone(), minimum.clone()) }.unwrap();
    minimum.check_error.set(Some(TimeError::Clock));
    assert_eq!(
        poll(&mut controller, 0),
        Err(Error::Minimum(TimeError::Clock))
    );
    assert!(model.state.lock().unwrap().writes.is_empty());
    assert!(model.state.lock().unwrap().reset_read_wall.is_empty());
    assert_eq!(pci_write_count(&controller), 0);
    assert_eq!(poll(&mut controller, 1000), Err(Error::Poisoned));
    drop(controller);
    assert_eq!(Arc::strong_count(&model), 2);
    assert_eq!(Rc::strong_count(&minimum), 2);
}
fn pci_write_count(controller: &Controller<'_, Pci, Model>) -> usize {
    controller
        .resources
        .configuration
        .state
        .lock()
        .unwrap()
        .writes
        .len()
}
#[test]
fn failed_or_unwound_post_hrr_wait_never_reads_completion_or_releases_any_owner() {
    for panics in [false, true] {
        let (mut pci, model) = fixture(0x1022, 0x1668, 0x0c0340, 0x40, 8);
        let minimum = Minimum::new(&model);
        // SAFETY: same exclusively owned fixture graph, no live DMA or IRQ.
        let mut controller =
            unsafe { Controller::new(&mut pci, model.clone(), minimum.clone()) }.unwrap();
        if panics {
            minimum.panic_wait.set(true);
        } else {
            minimum.wait_error.set(Some(TimeError::NotReady));
        }
        if panics {
            assert!(catch_unwind(AssertUnwindSafe(|| poll(&mut controller, 0))).is_err());
        } else {
            assert_eq!(
                poll(&mut controller, 0),
                Err(Error::Minimum(TimeError::NotReady))
            );
        }
        assert_eq!(model.state.lock().unwrap().writes, vec![(RESET, 1)]);
        assert!(model.state.lock().unwrap().reset_read_wall.is_empty());
        assert_eq!(poll(&mut controller, 1000), Err(Error::Poisoned));
        drop(controller);
        assert_eq!(Arc::strong_count(&model), 2);
        assert_eq!(Rc::strong_count(&minimum), 2);
    }
}
#[test]
fn pre_effect_callback_unwind_keeps_resources_before_any_store() {
    let (mut pci, model) = fixture(0x1022, 0x1668, 0x0c0340, 0x40, 8);
    let minimum = Minimum::new(&model);
    // SAFETY: same complete owned device model, with no outside actors.
    let mut controller =
        unsafe { Controller::new(&mut pci, model.clone(), minimum.clone()) }.unwrap();
    minimum.panic_check.set(true);
    assert!(catch_unwind(AssertUnwindSafe(|| poll(&mut controller, 0))).is_err());
    assert!(model.state.lock().unwrap().writes.is_empty());
    assert_eq!(poll(&mut controller, 1000), Err(Error::Poisoned));
    drop(controller);
    assert_eq!(Arc::strong_count(&model), 2);
    assert_eq!(Rc::strong_count(&minimum), 2);
}
#[test]
fn constructor_owns_original_graph_before_first_minimum_callback() {
    let (mut pci, model) = fixture(0x1022, 0x1668, 0x0c0340, 0x40, 8);
    let minimum = Minimum::new(&model);
    minimum.panic_check.set(true);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: the same original fixture graph; callback intentionally unwinds.
            let _controller = unsafe { Controller::new(&mut pci, model.clone(), minimum.clone()) };
        }))
        .is_err()
    );
    assert!(model.state.lock().unwrap().writes.is_empty());
    assert_eq!(Arc::strong_count(&model), 2);
    assert_eq!(Rc::strong_count(&minimum), 2);
}
#[test]
fn successful_softfail_config_response_is_not_a_transport_error_or_early_reset_receipt() {
    let (mut pci, model) = fixture(0x1022, 0x1668, 0x0c0340, 0x40, 8);
    model.state.lock().unwrap().reset_delay = 0;
    pci.state.lock().unwrap().softfail_reset_read = true;
    let minimum = Minimum::new(&model);
    // SAFETY: same current synthetic configuration transport and physical
    // requester; the bridge returns all-ones data while completing the read.
    let mut controller =
        unsafe { Controller::new(&mut pci, model.clone(), minimum.clone()) }.unwrap();
    assert_eq!(poll(&mut controller, 0).unwrap(), None);
    assert!(model.state.lock().unwrap().reset_read_wall.is_empty());
    assert_eq!(*minimum.waits.borrow(), vec![100_000]);
    assert!(poll(&mut controller, 0).unwrap().is_some());
}
