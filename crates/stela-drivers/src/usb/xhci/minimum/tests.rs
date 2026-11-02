// SPDX-License-Identifier: MIT
//! Isolated protocol timing/failure controls, not native physical permits.
use super::*;
use crate::bus::dma::TestRegion;

struct Counts {
    checks: Cell<usize>,
    waits: RefCell<Vec<u64>>,
    fault: Cell<Option<Error>>,
    drops: Rc<Cell<usize>>,
}
struct FaultTimer {
    counts: Rc<Counts>,
    fixture: Rc<dyn Timer>,
}
// SAFETY: test-only actual current-thread virtual fixture owns time. Failure
// returns without claiming elapsed time; no native device/clock is admitted.
unsafe impl Timer for FaultTimer {
    fn check(&self) -> Result<(), Error> {
        self.counts.checks.set(self.counts.checks.get() + 1);
        self.fixture.check()
    }
    fn wait_us(&self, us: u64) -> Result<(), Error> {
        self.counts.waits.borrow_mut().push(us);
        if let Some(error) = self.counts.fault.get() {
            return Err(error);
        }
        self.fixture.wait_us(us)
    }
}
impl Drop for FaultTimer {
    fn drop(&mut self) {
        self.counts.drops.set(self.counts.drops.get() + 1);
    }
}
fn fault_timer() -> (Rc<dyn Timer>, Rc<Counts>) {
    let counts = Rc::new(Counts {
        checks: Cell::new(0),
        waits: RefCell::new(Vec::new()),
        fault: Cell::new(None),
        drops: Rc::new(Cell::new(0)),
    });
    let timer = Rc::new(FaultTimer {
        counts: counts.clone(),
        fixture: crate::minimum_model::owned(Clock {
            ticks_per_microsecond: 1,
        }),
    });
    (timer, counts)
}
#[test]
fn minimum_failure_latches_exact_error_and_keeps_the_provider() {
    let (timer, counts) = fault_timer();
    let minimum = Minimum::retain(timer.clone());
    minimum.wait_us(73).unwrap();
    assert_eq!(*counts.waits.borrow(), [73]);
    counts.fault.set(Some(Error::Interrupted));
    assert_eq!(
        minimum.wait_us(1000),
        Err(BlockError::PciPower(Error::Interrupted))
    );
    let checks = counts.checks.get();
    counts.fault.set(None);
    assert_eq!(
        minimum.wait_us(2000),
        Err(BlockError::PciPower(Error::Interrupted))
    );
    assert_eq!(counts.checks.get(), checks);
    assert_eq!(*counts.waits.borrow(), [73, 1000]);
    drop(minimum);
    drop(timer);
    assert_eq!(
        counts.drops.get(),
        0,
        "abandoned owner must keep actual provider"
    );
}
#[test]
fn debounce_failed_minimum_never_resamples_or_mints_stable_time() {
    let (timer, counts) = fault_timer();
    counts.fault.set(Some(Error::Interrupted));
    let minimum = Minimum::retain(timer);
    let samples = Cell::new(0);
    let sample = || {
        samples.set(samples.get() + 1);
        Ok((true, false))
    };
    assert_eq!(
        enumerate::debounce(minimum.clone(), sample),
        Err(BlockError::PciPower(Error::Interrupted))
    );
    assert_eq!(samples.get(), 1);
    assert_eq!(*counts.waits.borrow(), [DEBOUNCE_STEP_US]);
    counts.fault.set(None);
    assert_eq!(
        enumerate::debounce(minimum, || panic!("closed timing source resampled port")),
        Err(BlockError::PciPower(Error::Interrupted))
    );
}
type Effects = Rc<RefCell<Vec<(bool, usize, u32)>>>;
struct RegistersPeer(Effects);
impl Registers for RegistersPeer {
    fn read32(&mut self, at: usize) -> u32 {
        self.0.borrow_mut().push((false, at, 0));
        if at == USBSTS { HCH } else { 0 }
    }
    fn write32(&mut self, at: usize, value: u32) {
        self.0.borrow_mut().push((true, at, value));
    }
}
#[test]
fn failed_hcrst_settle_does_not_read_or_publish_after_the_write() {
    let (timer, counts) = fault_timer();
    counts.fault.set(Some(Error::Interrupted));
    let minimum = Minimum::retain(timer);
    let effects = Rc::new(RefCell::new(Vec::new()));
    let mut registers = RegistersPeer(effects.clone());
    assert_eq!(
        hardware::reset(
            &mut registers,
            Clock {
                ticks_per_microsecond: 1
            },
            0,
            1000,
            &minimum
        ),
        Err(BlockError::PciPower(Error::Interrupted))
    );
    assert_eq!(
        *effects.borrow(),
        [
            (false, USBSTS, 0),
            (false, USBCMD, 0),
            (true, USBCMD, HCRST)
        ]
    );
}
#[test]
fn a_latched_minimum_blocks_later_register_effects_and_controller_commands() {
    let (timer, counts) = fault_timer();
    let minimum = Minimum::retain(timer);
    let effects = Rc::new(RefCell::new(Vec::new()));
    let mut gate = Gate::retain(Box::new(RegistersPeer(effects.clone())), minimum.clone());
    gate.write32(USBCMD, 2);
    counts.fault.set(Some(Error::Interrupted));
    assert!(minimum.wait_us(1).is_err());
    let before = effects.borrow().len();
    gate.write64(DCBAAP, 0x1234);
    assert_eq!(gate.read32(USBSTS), u32::MAX);
    assert_eq!(effects.borrow().len(), before);
    let mut dma = TestRegion::new(16 * 1024 * 8);
    let (mut controller, _) = model::address_controller(&mut dma, SUCCESS);
    controller.minimum = minimum;
    assert!(matches!(
        controller.command(0, 0, ENABLE_SLOT << 10),
        Err(BlockError::PciPower(Error::Interrupted))
    ));
    assert_eq!(controller.minimum_error(), Some(Error::Interrupted));
}

#[test]
fn unavailable_minimum_refuses_before_registers_or_dma_even_with_valid_nominal_clock() {
    struct Trap;
    impl Registers for Trap {
        fn read32(&mut self, _: usize) -> u32 {
            panic!("minimum refusal read register")
        }
        fn write32(&mut self, _: usize, _: u32) {
            panic!("minimum refusal wrote register")
        }
    }
    impl DmaAllocator for Trap {
        fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
            panic!("minimum refusal allocated DMA")
        }
    }
    let clock = Clock {
        ticks_per_microsecond: 1,
    };
    let result = Controller::new(
        Box::new(Trap),
        clock,
        &mut Trap,
        "minimum-refused model".into(),
        crate::minimum_model::refusing(clock),
    );
    assert!(matches!(result, Err(BlockError::PciPower(Error::Clock))));
}

#[test]
fn minimum_failure_keeps_the_unacknowledged_command_and_never_credits_a_late_event() {
    let (timer, counts) = fault_timer();
    let minimum = Minimum::retain(timer);
    let mut dma = TestRegion::new(16 * 1024 * 8);
    let (mut controller, _) = model::address_controller(&mut dma, SUCCESS);
    controller.minimum = minimum;
    let address = controller.start_command(0, 0, ENABLE_SLOT << 10).unwrap();
    assert!(controller.outstanding.is_some());
    counts.fault.set(Some(Error::Interrupted));
    assert_eq!(
        controller.minimum_wait(1000),
        Err(BlockError::PciPower(Error::Interrupted))
    );
    let ring = controller.commands.buffer.bytes().to_vec();
    let queued = controller.finished.len();
    assert!(matches!(
        controller.finish_command(address),
        Some(Err(BlockError::PciPower(Error::Interrupted)))
    ));
    controller.settle_command();
    assert!(controller.outstanding.is_some());
    assert_eq!(controller.finished.len(), queued);
    assert_eq!(controller.commands.buffer.bytes(), ring);
    assert!(controller.command_poisoned && matches!(controller.hardware, hardware::State::Failed));
}

mod owner;
