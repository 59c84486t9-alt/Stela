//! Returned reset-hook denial and unwind must fence outer cleanup itself.
extern crate std;

use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cut {
    registers: (usize, usize, usize),
    checks: usize,
    waits: usize,
    hooks: usize,
}
struct HookState {
    failure: Cell<Option<(bool, Option<Error>)>>,
    disable_hardware_error: Cell<bool>,
    calls: RefCell<Vec<bool>>,
    cut: Cell<Option<Cut>>,
}
struct HookRegisters {
    inner: RegisterOwner,
    model: Rc<RefCell<Model>>,
    minimum: Rc<MinimumState>,
    hook: Rc<HookState>,
}
impl Registers for HookRegisters {
    fn region_bytes(&self) -> usize {
        self.inner.original.region_bytes()
    }
    fn validate_config(&self, config: &Config) -> Result<(), Error> {
        if config.reset_policy == ResetPolicy::IntelClockGate {
            Ok(())
        } else {
            Err(Error::InvalidConfiguration)
        }
    }
    fn reset_clock_gate(&mut self, enabled: bool) -> Result<(), Error> {
        self.hook.calls.borrow_mut().push(enabled);
        if !enabled && self.hook.disable_hardware_error.get() {
            return Err(Error::PciResetControl { offset: 0x48 });
        }
        if let Some((target, error)) = self.hook.failure.get()
            && target == enabled
        {
            self.hook.cut.set(Some(Cut {
                registers: access_counts(&self.model),
                checks: self.minimum.checks.get(),
                waits: self.minimum.waits.borrow().len(),
                hooks: self.hook.calls.borrow().len(),
            }));
            return match error {
                Some(error) => Err(error),
                None => panic!("actual reset hook interrupted"),
            };
        }
        Ok(())
    }
    fn read8(&mut self, o: usize) -> u8 {
        self.inner.read8(o)
    }
    fn read16(&mut self, o: usize) -> u16 {
        self.inner.read16(o)
    }
    fn read32(&mut self, o: usize) -> u32 {
        self.inner.read32(o)
    }
    fn write8(&mut self, o: usize, v: u8) {
        self.inner.write8(o, v);
    }
    fn write16(&mut self, o: usize, v: u16) {
        self.inner.write16(o, v);
    }
    fn write32(&mut self, o: usize, v: u32) {
        self.inner.write32(o, v);
    }
}
struct HookFixture {
    controller: Controller<HookRegisters, TimingPeer>,
    model: Rc<RefCell<Model>>,
    drops: Rc<Cell<usize>>,
    minimum: Rc<MinimumState>,
    hook: Rc<HookState>,
    ram: Fixture,
}
fn fixture() -> HookFixture {
    let model = graph_model();
    let mut ram = Fixture::new();
    let (inner, timer, drops, minimum) = inputs(&model);
    let hook = Rc::new(HookState {
        failure: Cell::new(None),
        disable_hardware_error: Cell::new(false),
        calls: RefCell::new(Vec::new()),
        cut: Cell::new(None),
    });
    let registers = HookRegisters {
        inner,
        model: model.clone(),
        minimum: minimum.clone(),
        hook: hook.clone(),
    };
    // SAFETY: isolated conventional RAM/register peer; the hook has no native
    // config, timer, ownership or hardware-completion authority.
    let controller =
        unsafe { Controller::new(registers, timer, &mut ram.allocator, modern_config()) }.unwrap();
    HookFixture {
        controller,
        model,
        drops,
        minimum,
        hook,
        ram,
    }
}
fn cut(f: &HookFixture) -> Cut {
    Cut {
        registers: access_counts(&f.model),
        checks: f.minimum.checks.get(),
        waits: f.minimum.waits.borrow().len(),
        hooks: f.hook.calls.borrow().len(),
    }
}
fn assert_closed(f: &mut HookFixture, error: Error) {
    let stopped_at = f.hook.cut.get().expect("the actual fault hook ran");
    assert_eq!(
        cut(f),
        stopped_at,
        "outer cleanup ran after hook denial/unwind"
    );
    // Restoring the peer cannot reopen the original failed controller epoch.
    f.hook.failure.set(None);
    f.hook.disable_hardware_error.set(false);
    f.model.borrow_mut().reset_exit_stuck = false;
    assert_eq!(f.controller.reinitialize(), Err(error));
    assert_eq!(f.controller.shutdown(), Err(error));
    assert_eq!(f.controller.verb(verb()), Err(error));
    assert_eq!(f.controller.discover_codecs().unwrap_err().error, error);
    assert_eq!(
        f.controller
            .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut f.ram.allocator),
        Err(error)
    );
    assert_eq!(
        cut(f),
        stopped_at,
        "later admission reached registers, timer or hook"
    );
}
#[test]
fn returned_reset_hook_errors_fence_both_brackets_and_preserve_primary_and_cleanup() {
    let config = crate::bus::pci::ConfigError::write_may_have_applied(
        0x48,
        4,
        crate::bus::pci::ConfigFailure::Mapping(crate::bus::mmio::owned::Error::Unavailable),
    );
    for error in [
        Error::Config(config),
        Error::PciCapability(crate::bus::pci::CapabilityError::OutOfRange { offset: 0xfc }),
        Error::MinimumDelay(crate::bus::pci::power::Error::Clock),
        Error::Interrupted,
    ] {
        // Disable refusal; enable refusal after reset success, reset timeout,
        // or an ordinary first-hook hardware error. Every hook call site runs.
        for (enabled, reset_fault, disable_hardware) in [
            (false, false, false),
            (true, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            let mut f = fixture();
            f.hook.failure.set(Some((enabled, Some(error))));
            f.model.borrow_mut().reset_exit_stuck = reset_fault;
            f.hook.disable_hardware_error.set(disable_hardware);
            let primary = if disable_hardware {
                Error::PciResetControl { offset: 0x48 }
            } else if reset_fault {
                Error::Timeout(Phase::LinkResetExit)
            } else {
                error
            };
            assert_eq!(f.controller.reinitialize(), Err(primary));
            assert_eq!(f.controller.reset_error(), Some(primary));
            assert_eq!(
                f.controller.reset_cleanup_error(),
                if reset_fault || disable_hardware {
                    Some(error)
                } else {
                    None
                }
            );
            assert_eq!(f.controller.first_effect_error(), Some(error));
            assert_eq!(
                f.controller.first_minimum_error(),
                if matches!(error, Error::MinimumDelay(_) | Error::Interrupted) {
                    Some(error)
                } else {
                    None
                }
            );
            assert_closed(&mut f, error);
            let expected = f.hook.cut.get().unwrap();
            drop(f.controller);
            assert_eq!(access_counts(&f.model), expected.registers);
            assert_eq!(f.minimum.checks.get(), expected.checks);
            assert_eq!(f.minimum.waits.borrow().len(), expected.waits);
            assert_eq!(f.hook.calls.borrow().len(), expected.hooks);
            assert_eq!(f.drops.get(), 0);
            assert_eq!(f.minimum.drops.get(), 0);
            core::mem::forget(f.ram);
        }
    }
}
#[test]
fn reset_hook_unwind_fences_outer_cleanup_and_keeps_any_prior_primary_error() {
    for (enabled, reset_fault, disable_hardware) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        let mut f = fixture();
        f.hook.failure.set(Some((enabled, None)));
        f.model.borrow_mut().reset_exit_stuck = reset_fault;
        f.hook.disable_hardware_error.set(disable_hardware);
        let caught =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.controller.reinitialize()));
        assert!(caught.is_err());
        assert_eq!(
            f.controller.reset_error(),
            if disable_hardware {
                Some(Error::PciResetControl { offset: 0x48 })
            } else if reset_fault {
                Some(Error::Timeout(Phase::LinkResetExit))
            } else {
                None
            }
        );
        assert_eq!(f.controller.first_effect_error(), Some(Error::Interrupted));
        // An arbitrary hook unwind does not certify a minimum-provider fault.
        assert_eq!(f.controller.first_minimum_error(), None);
        assert_closed(&mut f, Error::Interrupted);
        let expected = f.hook.cut.get().unwrap();
        drop(f.controller);
        assert_eq!(access_counts(&f.model), expected.registers);
        assert_eq!(f.minimum.checks.get(), expected.checks);
        assert_eq!(f.minimum.waits.borrow().len(), expected.waits);
        assert_eq!(f.hook.calls.borrow().len(), expected.hooks);
        assert_eq!(f.drops.get(), 0);
        assert_eq!(f.minimum.drops.get(), 0);
        core::mem::forget(f.ram);
    }
}
