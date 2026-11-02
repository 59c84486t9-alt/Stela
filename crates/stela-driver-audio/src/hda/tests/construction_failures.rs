//! Ordinary constructor quiescence preserves the primary and every original owner.
extern crate std;

use super::*;

type EffectCut = (usize, usize, usize);

struct RegisterOwner {
    model: Rc<RefCell<Model>>,
    drops: Rc<Cell<usize>>,
    panic_cleanup: bool,
    cut: Rc<Cell<Option<EffectCut>>>,
}
impl Drop for RegisterOwner {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl Registers for RegisterOwner {
    fn read8(&mut self, offset: usize) -> u8 {
        ModelRegisters(self.model.clone()).read8(offset)
    }
    fn read16(&mut self, offset: usize) -> u16 {
        ModelRegisters(self.model.clone()).read16(offset)
    }
    fn read32(&mut self, offset: usize) -> u32 {
        ModelRegisters(self.model.clone()).read32(offset)
    }
    fn write8(&mut self, offset: usize, value: u8) {
        if self.panic_cleanup
            && offset == CORBCTL
            && value == 0
            && self.model.borrow().command_started_once
        {
            self.cut.set(Some(access_counts(&self.model)));
            panic!("constructor shutdown interrupted");
        }
        ModelRegisters(self.model.clone()).write8(offset, value);
    }
    fn write16(&mut self, offset: usize, value: u16) {
        ModelRegisters(self.model.clone()).write16(offset, value);
    }
    fn write32(&mut self, offset: usize, value: u32) {
        ModelRegisters(self.model.clone()).write32(offset, value);
    }
}

#[test]
fn ordinary_constructor_failure_keeps_primary_and_distinct_shutdown_failure_without_drop_effects() {
    let model = Model::new(256);
    model.borrow_mut().command_start_read_failure = Some(CORBCTL);
    let drops = Rc::new(Cell::new(0));
    let registers = RegisterOwner {
        model: model.clone(),
        drops: drops.clone(),
        panic_cleanup: false,
        cut: Rc::new(Cell::new(None)),
    };
    let timer = model.borrow().clock.clone();
    let mut ram = Fixture::new();
    let remaining = ram.allocator.remaining();
    // SAFETY: isolated synchronous controller with original coherent RAM kept alive.
    let failure = match unsafe { Controller::new(registers, timer, &mut ram.allocator, config()) } {
        Err(failure) => failure,
        Ok(_) => panic!("unacknowledged command start accepted"),
    };
    assert_eq!(failure.error, Error::Timeout(Phase::CommandStart));
    let core = failure
        .owner
        .controller
        .as_ref()
        .expect("same whole core retained");
    assert_eq!(
        core.reset_error(),
        Some(Error::Timeout(Phase::CommandStart))
    );
    assert_eq!(
        core.reset_cleanup_error(),
        Some(Error::Timeout(Phase::CommandStop))
    );
    assert_eq!(core.first_effect_error(), None);
    assert!(core.lifecycle_failed && !core.stopped);
    assert!(ram.allocator.remaining() < remaining);
    assert_eq!(model.borrow().get(CORBCTL, 1), 0);
    assert_eq!(model.borrow().get(RIRBCTL, 1), 0);
    assert!(model.borrow().commands.is_empty());
    let effects = access_counts(&model);
    drop(failure);
    assert_eq!(access_counts(&model), effects);
    assert_eq!(drops.get(), 0);
    core::mem::forget(ram);
}

#[test]
#[expect(
    clippy::result_large_err,
    reason = "The unwind control returns the same complete refusal without allocating on failure"
)]
fn constructor_shutdown_unwind_retains_the_same_register_and_dma_graph_without_hidden_retry() {
    let model = Model::new(256);
    model.borrow_mut().command_start_read_failure = Some(CORBCTL);
    let drops = Rc::new(Cell::new(0));
    let cut = Rc::new(Cell::new(None));
    let registers = RegisterOwner {
        model: model.clone(),
        drops: drops.clone(),
        panic_cleanup: true,
        cut: cut.clone(),
    };
    let timer = model.borrow().clock.clone();
    let mut ram = Fixture::new();
    let remaining = ram.allocator.remaining();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: isolated controller and coherent RAM; original graph outlives unwind.
        unsafe { Controller::new(registers, timer, &mut ram.allocator, config()) }
    }));
    assert!(caught.is_err());
    assert_eq!(Some(access_counts(&model)), cut.get());
    assert!(ram.allocator.remaining() < remaining);
    assert_eq!(drops.get(), 0);
    assert!(model.borrow().commands.is_empty());
    drop(caught);
    assert_eq!(Some(access_counts(&model)), cut.get());
    assert_eq!(drops.get(), 0);
    core::mem::forget(ram);
}
