//! Minimum timing is independent of nominal deadlines and keeps real owners.
extern crate std;

use super::*;
mod hooks;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Check,
    Wait,
    CheckPanic,
    WaitPanic,
}
struct MinimumState {
    fault: Cell<Fault>,
    checks: Cell<usize>,
    waits: RefCell<Vec<u64>>,
    elapsed: Cell<u64>,
    drops: Cell<usize>,
}
struct TimingPeer {
    nominal: ModelClock,
    minimum: Rc<MinimumState>,
}
impl Drop for TimingPeer {
    fn drop(&mut self) {
        self.minimum.drops.set(self.minimum.drops.get() + 1);
    }
}
impl crate::bus::i2c::Timer for TimingPeer {
    fn now_us(&self) -> u64 {
        self.nominal.now_us()
    }
    fn relax(&self) {
        self.nominal.relax();
    }
}
// SAFETY: explicit diagnostic peer; elapsed measures its independently modeled
// minimum duration. It grants no production clock, mapping or hardware receipt.
unsafe impl crate::bus::pci::power::Timer for TimingPeer {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        self.minimum.checks.set(self.minimum.checks.get() + 1);
        match self.minimum.fault.get() {
            Fault::Check => Err(crate::bus::pci::power::Error::Clock),
            Fault::CheckPanic => panic!("minimum provider check interrupted"),
            _ => Ok(()),
        }
    }
    fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.minimum.waits.borrow_mut().push(us);
        match self.minimum.fault.get() {
            Fault::Wait => return Err(crate::bus::pci::power::Error::Clock),
            Fault::WaitPanic => panic!("minimum provider wait interrupted"),
            _ => {}
        }
        self.minimum.elapsed.set(self.minimum.elapsed.get() + us);
        self.nominal.0.set(self.nominal.0.get() + us);
        Ok(())
    }
}
struct RegisterOwner {
    original: ModelRegisters,
    drops: Rc<Cell<usize>>,
}
impl Drop for RegisterOwner {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl Registers for RegisterOwner {
    fn read8(&mut self, o: usize) -> u8 {
        self.original.read8(o)
    }
    fn read16(&mut self, o: usize) -> u16 {
        self.original.read16(o)
    }
    fn read32(&mut self, o: usize) -> u32 {
        self.original.read32(o)
    }
    fn write8(&mut self, o: usize, v: u8) {
        self.original.write8(o, v);
    }
    fn write16(&mut self, o: usize, v: u16) {
        self.original.write16(o, v);
    }
    fn write32(&mut self, o: usize, v: u32) {
        self.original.write32(o, v);
    }
}
type OwnedTimingInputs = (RegisterOwner, TimingPeer, Rc<Cell<usize>>, Rc<MinimumState>);
fn inputs(model: &Rc<RefCell<Model>>) -> OwnedTimingInputs {
    let drops = Rc::new(Cell::new(0));
    let minimum = Rc::new(MinimumState {
        fault: Cell::new(Fault::None),
        checks: Cell::new(0),
        waits: RefCell::new(Vec::new()),
        elapsed: Cell::new(0),
        drops: Cell::new(0),
    });
    (
        RegisterOwner {
            original: ModelRegisters(model.clone()),
            drops: drops.clone(),
        },
        TimingPeer {
            nominal: model.borrow().clock.clone(),
            minimum: minimum.clone(),
        },
        drops,
        minimum,
    )
}
#[test]
fn missing_minimum_refuses_before_registers_dma_and_retains_original_inputs() {
    let model = Model::new(16);
    let mut ram = Fixture::new();
    let (registers, timer, drops, minimum) = inputs(&model);
    minimum.fault.set(Fault::Check);
    let remaining = ram.allocator.remaining();
    // SAFETY: explicit isolated conventional controller/RAM ownership.
    let failure = match unsafe { Controller::new(registers, timer, &mut ram.allocator, config()) } {
        Err(failure) => failure,
        Ok(_) => panic!("unavailable minimum accepted"),
    };
    assert_eq!(
        failure.error,
        Error::MinimumDelay(crate::bus::pci::power::Error::Clock)
    );
    assert_eq!(access_counts(&model), (0, 0, 0));
    assert_eq!(ram.allocator.remaining(), remaining);
    assert!(minimum.waits.borrow().is_empty());
    drop(failure);
    assert_eq!(drops.get(), 0);
    assert_eq!(minimum.drops.get(), 0);
}
#[test]
fn reset_consumes_independent_minimums_and_active_drop_retires_nothing() {
    let model = Model::new(16);
    let mut ram = Fixture::new();
    let (registers, timer, drops, minimum) = inputs(&model);
    // SAFETY: isolated actual RAM owner and synchronous device peer.
    let controller =
        unsafe { Controller::new(registers, timer, &mut ram.allocator, config()) }.unwrap();
    assert_eq!(*minimum.waits.borrow(), [500, 1000]);
    assert_eq!(minimum.elapsed.get(), 1500);
    let effects = access_counts(&model);
    drop(controller);
    assert_eq!(access_counts(&model), effects);
    assert_eq!(drops.get(), 0);
    assert_eq!(minimum.drops.get(), 0);
    // Active-drop quarantine keeps the actual descriptor backing in this peer.
    core::mem::forget(ram);
}
#[test]
fn failed_or_interrupted_minimum_preflight_and_wait_close_every_later_effect() {
    for fault in [
        Fault::Check,
        Fault::Wait,
        Fault::CheckPanic,
        Fault::WaitPanic,
    ] {
        let model = Model::new(16);
        let mut ram = Fixture::new();
        let (registers, timer, drops, minimum) = inputs(&model);
        // SAFETY: independently owned synchronous controller and coherent RAM.
        let mut controller =
            unsafe { Controller::new(registers, timer, &mut ram.allocator, config()) }.unwrap();
        minimum.fault.set(fault);
        let before = access_counts(&model);
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| controller.reinitialize()));
        let expected = if matches!(fault, Fault::CheckPanic | Fault::WaitPanic) {
            assert!(result.is_err());
            Error::Interrupted
        } else {
            let expected = Error::MinimumDelay(crate::bus::pci::power::Error::Clock);
            assert_eq!(result.unwrap(), Err(expected));
            expected
        };
        if matches!(fault, Fault::Wait | Fault::WaitPanic) {
            assert_ne!(
                access_counts(&model),
                before,
                "wait fault must follow actual reset effects"
            );
        } else {
            assert_eq!(
                access_counts(&model),
                before,
                "missing minimum must refuse before effects"
            );
        }
        assert_eq!(controller.first_minimum_error(), Some(expected));
        minimum.fault.set(Fault::None);
        let effects = access_counts(&model);
        let checks = minimum.checks.get();
        let waits = minimum.waits.borrow().len();
        let remaining = ram.allocator.remaining();
        assert_eq!(controller.verb(verb()), Err(expected));
        assert_eq!(controller.shutdown(), Err(expected));
        assert_eq!(controller.reinitialize(), Err(expected));
        assert_eq!(controller.discover_codecs().unwrap_err().error, expected);
        assert_eq!(
            controller.allocate_stream(Direction::Playback, pcm(), 128, 2, &mut ram.allocator),
            Err(expected)
        );
        assert_eq!(access_counts(&model), effects);
        assert_eq!(minimum.checks.get(), checks);
        assert_eq!(minimum.waits.borrow().len(), waits);
        assert_eq!(ram.allocator.remaining(), remaining);
        drop(controller);
        assert_eq!(access_counts(&model), effects);
        assert_eq!(drops.get(), 0);
        assert_eq!(minimum.drops.get(), 0);
        core::mem::forget(ram);
    }
}
#[test]
fn failed_constructor_minimum_keeps_the_whole_allocated_core_and_cause() {
    let model = Model::new(16);
    let mut ram = Fixture::new();
    let (registers, timer, drops, minimum) = inputs(&model);
    minimum.fault.set(Fault::Wait);
    // SAFETY: independent stopped model; failed minimum occurs after reset write.
    let mut failure =
        match unsafe { Controller::new(registers, timer, &mut ram.allocator, config()) } {
            Err(failure) => failure,
            Ok(_) => panic!("failed minimum published a ready controller"),
        };
    let error = Error::MinimumDelay(crate::bus::pci::power::Error::Clock);
    assert_eq!(failure.error, error);
    let core = failure
        .owner
        .controller
        .as_mut()
        .expect("whole core retained after ring allocation");
    assert_eq!(core.first_minimum_error(), Some(error));
    let effects = access_counts(&model);
    assert_eq!(core.shutdown(), Err(error));
    assert_eq!(core.reinitialize(), Err(error));
    assert_eq!(access_counts(&model), effects);
    drop(failure);
    assert_eq!(drops.get(), 0);
    assert_eq!(minimum.drops.get(), 0);
    core::mem::forget(ram);
}
struct SecondAllocation<'a> {
    inner: &'a mut RegionAllocator,
    calls: usize,
}
impl DmaAllocator for SecondAllocation<'_> {
    fn allocate(
        &mut self,
        bytes: usize,
        align: usize,
    ) -> Result<DmaBuffer, stela_driver_base::block::BlockError> {
        self.calls += 1;
        if self.calls == 2 {
            return Err(stela_driver_base::block::BlockError::Unsupported(
                "second diagnostic allocation refused",
            ));
        }
        self.inner.allocate(bytes, align)
    }
}
#[test]
fn partial_ring_allocation_refusal_keeps_exact_inputs_buffer_and_allocator_cause() {
    let model = Model::new(16);
    let mut ram = Fixture::new();
    let (registers, timer, drops, minimum) = inputs(&model);
    let mut allocator = SecondAllocation {
        inner: &mut ram.allocator,
        calls: 0,
    };
    // SAFETY: isolated model, with no DMA publication before allocation completes.
    let failure = match unsafe { Controller::new(registers, timer, &mut allocator, config()) } {
        Err(failure) => failure,
        Ok(_) => panic!("second allocation refusal ignored"),
    };
    assert_eq!(failure.error, Error::NoDmaMemory);
    assert_eq!(
        failure.owner.allocation_error,
        Some(stela_driver_base::block::BlockError::Unsupported(
            "second diagnostic allocation refused"
        ))
    );
    assert!(failure.owner.registers.is_some() && failure.owner.timer.is_some());
    assert!(failure.owner.corb.is_some() && failure.owner.rirb.is_none());
    assert!(failure.owner.controller.is_none());
    assert!(minimum.waits.borrow().is_empty());
    let effects = access_counts(&model);
    drop(failure);
    assert_eq!(access_counts(&model), effects);
    assert_eq!(drops.get(), 0);
    assert_eq!(minimum.drops.get(), 0);
    core::mem::forget(ram);
}
