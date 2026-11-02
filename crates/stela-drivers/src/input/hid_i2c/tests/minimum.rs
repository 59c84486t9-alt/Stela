use super::*;
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[derive(Clone, Copy)]
enum Fault {
    None,
    Check,
    Wait,
    PanicWait,
}
struct Quiet {
    time: Rc<Cell<u64>>,
    fault: Rc<Cell<Fault>>,
    waits: Rc<RefCell<Vec<u64>>>,
}
// SAFETY: a model of the peripheral's separate progressing minimum provider.
// Returned success advances that observed clock by the entire requested wait.
unsafe impl Minimum for Quiet {
    fn check(&self) -> Result<(), power::Error> {
        if matches!(self.fault.get(), Fault::Check) {
            Err(power::Error::Clock)
        } else {
            Ok(())
        }
    }
    fn wait_us(&self, us: u64) -> Result<(), power::Error> {
        self.waits.borrow_mut().push(us);
        match self.fault.get() {
            Fault::Wait => Err(power::Error::Interrupted),
            Fault::PanicWait => panic!("minimum wait interrupted"),
            _ => {
                self.time.set(self.time.get().checked_add(us).unwrap());
                Ok(())
            }
        }
    }
}
fn install(
    d: &mut Device<Model, Pin, Time>,
    h: &Rc<RefCell<Hardware>>,
    fault: Fault,
) -> Rc<RefCell<Vec<u64>>> {
    let waits = Rc::new(RefCell::new(Vec::new()));
    let minimum: Rc<dyn Minimum> = Rc::new(Quiet {
        time: h.borrow().time.clone(),
        fault: Rc::new(Cell::new(fault)),
        waits: waits.clone(),
    });
    d.minimum = minimum.clone();
    assert!(Rc::ptr_eq(&minimum, &d.minimum));
    waits
}

#[test]
fn unavailable_minimum_precedes_irq_and_bus_and_stays_denied() {
    let (mut d, h) = device(0x06cb, 0x1234);
    install(&mut d, &h, Fault::Check);
    let error = d.initialize().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Minimum(power::Error::Clock));
    assert_eq!(error.recovery, Recovery::NotAttempted);
    assert_eq!(d.first_error(), Some(error));
    assert!(d.needs_reset());
    assert_eq!(h.borrow().mask_count, 0);
    assert!(h.borrow().commands.is_empty());
    assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(h.borrow().mask_count, 0);
}

#[test]
fn failed_quiet_after_power_write_does_not_cleanup_reset_retry_or_publish_ready() {
    let (mut d, h) = device(0x06cb, 0x1234);
    let waits = install(&mut d, &h, Fault::Wait);
    let error = d.initialize().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Minimum(power::Error::Interrupted));
    assert_eq!(error.recovery, Recovery::NotAttempted);
    assert_eq!(*waits.borrow(), [WAKE_DELAY_US]);
    let h = h.borrow();
    assert!(
        h.power_on,
        "the accepted power write is not undone or replayed"
    );
    assert_eq!(h.commands.len(), 1);
    assert_eq!(h.reset_count, 0);
    assert_eq!(h.mask_count, 1, "no cleanup callback after uncertainty");
    assert_eq!(d.power_state(), PowerState::Uncertain);
    assert_eq!(d.first_error(), Some(error));
}

#[test]
fn callback_unwind_leaves_denial_before_a_second_effect() {
    let (mut d, h) = device(0x06cb, 0x1234);
    let waits = install(&mut d, &h, Fault::PanicWait);
    assert!(catch_unwind(AssertUnwindSafe(|| d.initialize())).is_err());
    assert_eq!(d.first_error().unwrap().kind, ErrorKind::Interrupted);
    assert!(d.needs_reset());
    assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(d.stop().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(*waits.borrow(), [WAKE_DELAY_US]);
    assert_eq!(h.borrow().commands.len(), 1);
    assert_eq!(h.borrow().mask_count, 1);
}

#[test]
fn required_quiets_use_the_minimum_provider_with_a_frozen_nominal_clock() {
    struct Frozen;
    impl Timer for Frozen {
        fn now_us(&self) -> u64 {
            0
        }
        fn relax(&self) {
            panic!("nominal clock used for a minimum quiet")
        }
    }
    for (vendor, product, no_irq) in [(0x27c6, 0x0d42, false), (0x2386, 0x3118, true)] {
        let time = Rc::new(Cell::new(0));
        let h = Rc::new(RefCell::new(Hardware::new(time.clone(), vendor, product)));
        h.borrow_mut().no_reset_ack = no_irq;
        let waits = Rc::new(RefCell::new(Vec::new()));
        let mut d = Device::new(
            Model(h.clone()),
            Pin(h.clone()),
            Frozen,
            Rc::new(Quiet {
                time,
                fault: Rc::new(Cell::new(Fault::None)),
                waits: waits.clone(),
            }),
            Address::SevenBit(0x2c),
            0x20,
            100,
        )
        .unwrap();
        d.initialize().unwrap();
        assert!(waits.borrow().contains(&WAKE_DELAY_US));
        if no_irq {
            assert!(waits.borrow().contains(&QUIRK_RESET_DELAY_US));
            assert_eq!(
                d.reset_completion(),
                Some(ResetCompletion::DeviceQuirkDelay)
            );
        } else {
            d.sleep().unwrap();
            d.wake().unwrap();
            assert!(waits.borrow().contains(&GOODIX_RESUME_DELAY_US));
        }
        assert!(d.is_ready());
    }
}

#[test]
fn cleanup_unwind_keeps_the_original_bus_cause_and_uncertain_cleanup() {
    struct CutPin {
        pin: Pin,
        cut: Rc<Cell<bool>>,
    }
    impl Interrupt for CutPin {
        fn mask_and_drain(&mut self) -> Result<(), InterruptError> {
            assert!(!self.cut.replace(false), "mask callback interrupted");
            self.pin.mask_and_drain()
        }
        fn asserted(&mut self) -> Result<bool, InterruptError> {
            self.pin.asserted()
        }
    }
    let time = Rc::new(Cell::new(0));
    let h = Rc::new(RefCell::new(Hardware::new(time.clone(), 0x06cb, 0x1234)));
    let cut = Rc::new(Cell::new(false));
    let mut d = Device::new(
        Model(h.clone()),
        CutPin {
            pin: Pin(h.clone()),
            cut: cut.clone(),
        },
        Time(time.clone()),
        Rc::new(MinimumTime(time)),
        Address::SevenBit(0x2c),
        0x20,
        100,
    )
    .unwrap();
    d.initialize().unwrap();
    h.borrow_mut().input.push_back(Hardware::frame(&[17, 1, 2]));
    h.borrow_mut().fail_next = true;
    cut.set(true);
    assert!(catch_unwind(AssertUnwindSafe(|| d.poll())).is_err());
    let error = d.first_error().unwrap();
    assert_eq!(
        error.kind,
        ErrorKind::Bus(bus_error(i2c::AbortKind::DataNack))
    );
    assert_eq!(error.recovery, Recovery::Interrupted);
    assert!(d.needs_reset());
    assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(d.first_error(), Some(error));
}
