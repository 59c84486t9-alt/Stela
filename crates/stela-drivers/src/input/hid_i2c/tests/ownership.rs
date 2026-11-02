use super::*;
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Tracked<T> {
    inner: T,
    drops: Rc<Cell<u8>>,
    bit: u8,
}
impl<T> Drop for Tracked<T> {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() | self.bit);
    }
}
impl<T: Bus> Bus for Tracked<T> {
    fn transaction(
        &mut self,
        address: Address,
        ops: &mut [Operation<'_>],
    ) -> Result<(), i2c::Error> {
        self.inner.transaction(address, ops)
    }
}
impl<T: Interrupt> Interrupt for Tracked<T> {
    fn mask_and_drain(&mut self) -> Result<(), InterruptError> {
        self.inner.mask_and_drain()
    }
    fn asserted(&mut self) -> Result<bool, InterruptError> {
        self.inner.asserted()
    }
}
impl<T: Timer> Timer for Tracked<T> {
    fn now_us(&self) -> u64 {
        self.inner.now_us()
    }
    fn start(&self) -> u64 {
        self.inner.start()
    }
    fn elapsed_us(&self, start: u64) -> u64 {
        self.inner.elapsed_us(start)
    }
    fn relax(&self) {
        self.inner.relax();
    }
    fn check_duration(&self, us: u64) -> Result<(), crate::ClockError> {
        self.inner.check_duration(us)
    }
}
// SAFETY: forward to the same original provider without changing timing or
// admission. Drop observation is independent of that provider's behavior.
unsafe impl<T: Minimum> Minimum for Tracked<T> {
    fn check(&self) -> Result<(), power::Error> {
        self.inner.check()
    }
    fn wait_us(&self, us: u64) -> Result<(), power::Error> {
        self.inner.wait_us(us)
    }
}
fn track<T>(inner: T, drops: &Rc<Cell<u8>>, bit: u8) -> Tracked<T> {
    Tracked {
        inner,
        drops: drops.clone(),
        bit,
    }
}

#[test]
fn constructor_initialization_and_descriptor_refusals_retain_all_four_original_providers() {
    for stage in 0..3 {
        let time = Rc::new(Cell::new(0));
        let h = Rc::new(RefCell::new(Hardware::new(time.clone(), 0x06cb, 0x1234)));
        let drops = Rc::new(Cell::new(0));
        let minimum: Rc<dyn Minimum> = Rc::new(track(MinimumTime(time.clone()), &drops, 8));
        let original_minimum = Rc::downgrade(&minimum);
        let result = Device::new(
            track(Model(h.clone()), &drops, 1),
            track(Pin(h.clone()), &drops, 2),
            track(Time(time), &drops, 4),
            minimum,
            Address::SevenBit(if stage == 0 { 0 } else { 0x2c }),
            0x20,
            100,
        );
        let refusal = if stage == 0 {
            let refusal = result.err().unwrap();
            assert_eq!(
                refusal.error,
                RefusalCause::Transport(ErrorKind::InvalidAddress.into())
            );
            refusal
        } else if stage == 1 {
            h.borrow_mut().fail_next = true;
            let refusal = result.unwrap().initialize_owned().err().unwrap();
            assert!(matches!(
                refusal.error,
                RefusalCause::Transport(Error {
                    kind: ErrorKind::Bus(_),
                    ..
                })
            ));
            refusal
        } else {
            h.borrow_mut().report_desc = vec![0xfe];
            h.borrow_mut().desc[4..6].copy_from_slice(&1u16.to_le_bytes());
            let device = result.unwrap().initialize_owned().unwrap();
            let cause = Translator::describe(device.report_descriptor())
                .err()
                .unwrap();
            let refusal = HidInput::new(device, String::from("model")).err().unwrap();
            assert_eq!(refusal.error, RefusalCause::Descriptor(cause));
            assert_eq!(refusal.device().report_descriptor(), [0xfe]);
            refusal
        };
        assert_eq!(drops.get(), 0);
        assert!(original_minimum.upgrade().is_some());
        #[expect(
            clippy::drop_non_drop,
            reason = "exercise abandonment of the opaque carrier with actual provider Drop witnesses"
        )]
        drop(refusal);
        assert_eq!(drops.get(), 0, "abandonment is not physical detach");
        assert!(
            original_minimum.upgrade().is_some(),
            "same timing root retained"
        );
    }
}

#[test]
fn preflight_unwind_cannot_release_any_original_provider() {
    struct PanicTime;
    impl Timer for PanicTime {
        fn now_us(&self) -> u64 {
            0
        }
        fn check_duration(&self, _: u64) -> Result<(), crate::ClockError> {
            panic!("preflight cut")
        }
    }
    let time = Rc::new(Cell::new(0));
    let h = Rc::new(RefCell::new(Hardware::new(time.clone(), 0x06cb, 0x1234)));
    let drops = Rc::new(Cell::new(0));
    let cut = catch_unwind(AssertUnwindSafe(|| {
        let _device = Device::new(
            track(Model(h.clone()), &drops, 1),
            track(Pin(h.clone()), &drops, 2),
            track(PanicTime, &drops, 4),
            Rc::new(track(MinimumTime(time), &drops, 8)),
            Address::SevenBit(0x2c),
            0x20,
            100,
        );
    }));
    assert!(cut.is_err());
    assert_eq!(drops.get(), 0);
    assert_eq!(h.borrow().mask_count, 0);
    assert!(h.borrow().commands.is_empty());
}

#[test]
fn successful_wrapper_abandonment_keeps_the_device_until_real_retirement() {
    let time = Rc::new(Cell::new(0));
    let h = Rc::new(RefCell::new(Hardware::new(time.clone(), 0x06cb, 0x1234)));
    let drops = Rc::new(Cell::new(0));
    let device = Device::new(
        track(Model(h.clone()), &drops, 1),
        track(Pin(h), &drops, 2),
        track(Time(time.clone()), &drops, 4),
        Rc::new(track(MinimumTime(time), &drops, 8)),
        Address::SevenBit(0x2c),
        0x20,
        100,
    )
    .unwrap()
    .initialize_owned()
    .unwrap();
    let input = HidInput::new(device, String::from("model")).unwrap();
    assert!(input.device().is_ready());
    drop(input);
    assert_eq!(drops.get(), 0);
}
