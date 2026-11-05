//! No native timing or hardware qualification follows from these peers.
extern crate std;

use super::*;
struct MinimumTime {
    nominal: Time,
    mode: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    waits: Arc<Mutex<Vec<u64>>>,
}
impl Drop for MinimumTime {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
impl crate::bus::i2c::Timer for MinimumTime {
    fn now_us(&self) -> u64 {
        self.nominal.now_us()
    }
    fn relax(&self) {
        self.nominal.relax();
    }
}
// SAFETY: explicit model microseconds; no nominal frequency grants physical time.
unsafe impl crate::bus::pci::power::Timer for MinimumTime {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        match self.mode.load(Ordering::Relaxed) {
            1 => Err(crate::bus::pci::power::Error::Clock),
            3 => panic!("DSP minimum check interrupted"),
            _ => Ok(()),
        }
    }
    fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.waits.lock().unwrap().push(us);
        match self.mode.load(Ordering::Relaxed) {
            2 => return Err(crate::bus::pci::power::Error::Clock),
            4 => panic!("DSP minimum wait interrupted"),
            _ => {}
        }
        self.nominal.now.fetch_add(us, Ordering::Relaxed);
        Ok(())
    }
}
type MinimumFixture = (
    MinimumTime,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<u64>>>,
);
fn minimum() -> MinimumFixture {
    let mode = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let waits = Arc::new(Mutex::new(Vec::new()));
    (
        MinimumTime {
            nominal: Time::new(),
            mode: mode.clone(),
            drops: drops.clone(),
            waits: waits.clone(),
        },
        mode,
        drops,
        waits,
    )
}
#[test]
fn claim_missing_minimum_returns_same_inputs_and_check_unwind_keeps_them() {
    for mode_value in [1, 3] {
        let model = Arc::new(Mutex::new(Model::new()));
        let (timer, mode, drops, waits) = minimum();
        mode.store(mode_value, Ordering::Relaxed);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Controller::claim(
                Regs(model.clone()),
                timer,
                Config {
                    dma_address_bits: 64,
                },
            )
        }));
        if mode_value == 1 {
            let (error, registers, timer) = match caught.unwrap() {
                Err(f) => f,
                Ok(_) => panic!("missing minimum accepted"),
            };
            assert_eq!(
                error,
                Error::MinimumDelay(crate::bus::pci::power::Error::Clock)
            );
            assert!(Arc::ptr_eq(&registers.0, &model));
            core::mem::forget((registers, timer));
        } else {
            assert!(caught.is_err());
        }
        assert!(model.lock().unwrap().writes.is_empty());
        assert_eq!(model.lock().unwrap().accesses, 0);
        assert!(waits.lock().unwrap().is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(Arc::strong_count(&model), 2);
    }
}
#[test]
fn init_minimum_fault_or_unwind_prevents_later_physical_effects_and_release() {
    for fault in [1, 2, 3, 4] {
        let model = Arc::new(Mutex::new(Model::new()));
        let (timer, mode, drops, waits) = minimum();
        let mut controller = match Controller::claim(
            Regs(model.clone()),
            timer,
            Config {
                dma_address_bits: 64,
            },
        ) {
            Ok(c) => c,
            Err((e, _, _)) => panic!("claim {e:?}"),
        };
        mode.store(fault, Ordering::Relaxed);
        let caught =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| controller.initialize()));
        let error = if matches!(fault, 3 | 4) {
            assert!(caught.is_err());
            Error::Interrupted
        } else {
            let error = Error::MinimumDelay(crate::bus::pci::power::Error::Clock);
            assert_eq!(caught.unwrap(), Err(error));
            error
        };
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(controller.first_minimum_error(), Some(error));
        if matches!(fault, 2 | 4) {
            assert!(!model.lock().unwrap().writes.is_empty());
        } else {
            assert!(model.lock().unwrap().writes.is_empty());
        }
        mode.store(0, Ordering::Relaxed);
        let effects = model.lock().unwrap().writes.len();
        let accesses = model.lock().unwrap().accesses;
        let prior_waits = waits.lock().unwrap().len();
        assert_eq!(controller.initialize(), Err(error));
        assert_eq!(controller.shutdown(), Err(error));
        assert_eq!(
            controller.install_dmic(topology::tests::topology()),
            Err(error)
        );
        assert_eq!(controller.start_capture(), Err(error));
        assert_eq!(controller.stop_capture(), Err(error));
        assert_eq!(controller.capture_position(), Err(error));
        assert_eq!(controller.read_capture(0, &mut [0; 4]), Err(error));
        let retained = match controller.into_stopped_resources() {
            Err(c) => c,
            Ok(_) => panic!("faulted controller released actual owners"),
        };
        drop(retained);
        assert_eq!(model.lock().unwrap().writes.len(), effects);
        assert_eq!(model.lock().unwrap().accesses, accesses);
        assert_eq!(waits.lock().unwrap().len(), prior_waits);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(Arc::strong_count(&model), 2);
    }
}
#[test]
fn successful_dsp_reset_uses_real_minimum_provider_and_active_drop_has_no_effects() {
    let model = Arc::new(Mutex::new(Model::new()));
    let (timer, _, drops, waits) = minimum();
    let mut controller = match Controller::claim(
        Regs(model.clone()),
        timer,
        Config {
            dma_address_bits: 64,
        },
    ) {
        Ok(c) => c,
        Err((e, _, _)) => panic!("claim {e:?}"),
    };
    controller.initialize().unwrap();
    assert_eq!(*waits.lock().unwrap(), [500, 1000]);
    let effects = model.lock().unwrap().writes.len();
    drop(controller);
    assert_eq!(model.lock().unwrap().writes.len(), effects);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(Arc::strong_count(&model), 2);
}

#[test]
fn active_drop_keeps_published_and_unpublished_dma_siblings_without_unmap() {
    let (mut controller, model, source, domain) = fixture();
    controller.pcm = Some(
        Stream::allocate(
            &source,
            domain.clone(),
            4096,
            u64::MAX,
            0,
            1,
            crate::Direction::Capture,
        )
        .unwrap(),
    );
    let before_unmaps = model.lock().unwrap().unmaps;
    let before_drops = source.drops.load(Ordering::Relaxed);
    let effects = model.lock().unwrap().accesses;
    controller.timer.refused.store(true, Ordering::Relaxed);
    let error = Error::MinimumDelay(crate::bus::pci::power::Error::Clock);
    assert_eq!(controller.start_capture(), Err(error));
    assert_eq!(model.lock().unwrap().accesses, effects);
    assert_eq!(controller.first_minimum_error(), Some(error));
    drop(controller);
    assert_eq!(model.lock().unwrap().accesses, effects);
    assert_eq!(
        model.lock().unwrap().unmaps,
        before_unmaps,
        "Drop retried a private sibling unmap"
    );
    assert_eq!(
        source.drops.load(Ordering::Relaxed),
        before_drops,
        "Drop released actual DMA backing"
    );
}
