// SPDX-License-Identifier: GPL-2.0-or-later
//! Same actual owner retention and terminal callback/transport failure controls.
use super::*;
extern crate std;
use crate::bus::pci::{
    ConfigError, ConfigFailure, assignment,
    power::{Error, Timer},
};
use core::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
struct DropFlag(Rc<Cell<usize>>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
struct PciOwner {
    inner: Function<Config>,
    denied: Rc<Cell<bool>>,
    accesses: Rc<Cell<usize>>,
    _drop: DropFlag,
}
impl PciOwner {
    fn enter(&self) -> Result<(), ConfigError> {
        self.accesses.set(self.accesses.get() + 1);
        if self.denied.get() {
            Err(ConfigError::before_effect(ConfigFailure::Ownership(
                assignment::Error::Closed,
            )))
        } else {
            Ok(())
        }
    }
}
impl Pci for PciOwner {
    fn read8(&mut self, a: u16) -> Result<u8, ConfigError> {
        self.enter()?;
        self.inner.config().read8(a)
    }
    fn read16(&mut self, a: u16) -> Result<u16, ConfigError> {
        self.enter()?;
        self.inner.config().read16(a)
    }
    fn read32(&mut self, a: u16) -> Result<u32, ConfigError> {
        self.enter()?;
        self.inner.config().read32(a)
    }
    fn write8(&mut self, a: u16, v: u8) -> Result<(), ConfigError> {
        self.enter()?;
        self.inner.config().write8(a, v)
    }
    fn write16(&mut self, a: u16, v: u16) -> Result<(), ConfigError> {
        self.enter()?;
        self.inner.config().write16(a, v)
    }
}
struct MmioOwner {
    inner: Mmio,
    _drop: DropFlag,
}
impl Registers for MmioOwner {
    fn read32(&mut self, a: usize) -> u32 {
        self.inner.read32(a)
    }
    fn write32(&mut self, a: usize, v: u32) {
        self.inner.write32(a, v);
    }
}
struct Minimum {
    mode: Cell<u8>,
    _drop: DropFlag,
}
// SAFETY: private protocol model provider/fault injection, never native permission.
unsafe impl Timer for Minimum {
    fn check(&self) -> Result<(), Error> {
        if self.mode.get() == 3 {
            panic!("check provider unwind")
        }
        Ok(())
    }
    fn wait_us(&self, us: u64) -> Result<(), Error> {
        match self.mode.get() {
            1 => panic!("wait provider unwind"),
            2 => Err(Error::Clock),
            _ => ModelTimer(Clock {
                ticks_per_microsecond: 1000,
            })
            .wait_us(us),
        }
    }
}
struct Controls {
    pci: Rc<Cell<usize>>,
    mmio: Rc<Cell<usize>>,
    timer: Rc<Cell<usize>>,
    denied: Rc<Cell<bool>>,
    accesses: Rc<Cell<usize>>,
}
impl Controls {
    fn new() -> Self {
        Self {
            pci: Rc::new(Cell::new(0)),
            mmio: Rc::new(Cell::new(0)),
            timer: Rc::new(Cell::new(0)),
            denied: Rc::new(Cell::new(false)),
            accesses: Rc::new(Cell::new(0)),
        }
    }
    fn minimum(&self, mode: u8) -> Rc<Minimum> {
        Rc::new(Minimum {
            mode: Cell::new(mode),
            _drop: DropFlag(self.timer.clone()),
        })
    }
    fn assert_kept(&self) {
        assert_eq!(self.pci.get(), 0);
        assert_eq!(self.mmio.get(), 0);
        assert_eq!(self.timer.get(), 0);
    }
}
#[expect(
    clippy::result_large_err,
    reason = "Return the same affine device, mapping and timer graph without a fallible failure-path allocation."
)]
fn owned_host(
    chip: &Rc<RefCell<Chip>>,
    controls: &Controls,
    minimum: Rc<dyn Timer>,
) -> Result<Host, HostFailure> {
    let mut function = function(chip);
    let admission = controller::admission(&mut function).unwrap();
    super::super::super::pci::quiesce_pio(&mut function).unwrap();
    let clock = Clock {
        ticks_per_microsecond: 1000,
    };
    function.power_up(&ModelTimer(clock)).unwrap();
    let config = controller::Configuration::capture(&mut function, admission).unwrap();
    super::super::super::pci::set_pio_command(&mut function, true).unwrap();
    Host::new(
        Box::new(PciOwner {
            inner: function,
            denied: controls.denied.clone(),
            accesses: controls.accesses.clone(),
            _drop: DropFlag(controls.pci.clone()),
        }),
        Box::new(MmioOwner {
            inner: Mmio(chip.clone()),
            _drop: DropFlag(controls.mmio.clone()),
        }),
        config,
        clock,
        minimum,
        "actual RTSX ownership controls".into(),
    )
}
#[test]
fn abandoned_typed_refusal_keeps_original_pci_mmio_and_minimum() {
    let chip = Chip::new(false, true);
    let controls = Controls::new();
    {
        let minimum = controls.minimum(2);
        let refusal = owned_host(&chip, &controls, minimum)
            .err()
            .expect("owning refusal");
        assert_eq!(refusal.error, BlockError::PciPower(Error::Clock));
    }
    controls.assert_kept();
}
#[test]
fn constructor_check_and_wait_unwind_keep_all_original_inputs() {
    for mode in [1, 3] {
        let chip = Chip::new(false, true);
        let controls = Controls::new();
        let minimum = controls.minimum(mode);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = owned_host(&chip, &controls, minimum);
            }))
            .is_err()
        );
        controls.assert_kept();
    }
}
#[test]
fn public_operation_unwind_terminally_fences_retry_and_preserves_original_inputs() {
    let chip = Chip::new(false, true);
    let controls = Controls::new();
    let minimum = controls.minimum(0);
    let mut host = owned_host(&chip, &controls, minimum.clone()).unwrap();
    minimum.mode.set(1);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = host.poll();
        }))
        .is_err()
    );
    let before = (
        chip.borrow().accesses,
        chip.borrow().effects.len(),
        controls.accesses.get(),
    );
    assert!(matches!(host.poll(), Err(BlockError::Protocol(_))));
    assert_eq!(
        (
            chip.borrow().accesses,
            chip.borrow().effects.len(),
            controls.accesses.get()
        ),
        before
    );
    drop(host);
    drop(minimum);
    controls.assert_kept();
}
#[test]
fn denied_original_config_latches_typed_cause_before_any_retirement_or_retry() {
    let chip = Chip::new(false, true);
    let controls = Controls::new();
    let mut host = owned_host(&chip, &controls, controls.minimum(0)).unwrap();
    controls.denied.set(true);
    let before = (chip.borrow().accesses, chip.borrow().effects.len());
    let first = host.poll().err().expect("configuration failure");
    assert!(matches!(first, BlockError::Config(_)));
    assert_eq!(
        (chip.borrow().accesses, chip.borrow().effects.len()),
        before
    );
    let accesses = controls.accesses.get();
    assert_eq!(host.poll().err(), Some(first));
    assert_eq!(controls.accesses.get(), accesses);
    drop(host);
    controls.assert_kept();
}
