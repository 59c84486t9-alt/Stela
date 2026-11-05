// SPDX-License-Identifier: GPL-2.0-or-later
//! Abandonment/unwind keeps every actual owned input, including partial buffers.
use super::*;
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};
struct Drops(Rc<Cell<usize>>);
impl Drop for Drops {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
struct RegisterOwner {
    port: Port,
    _drops: Drops,
}
impl Registers for RegisterOwner {
    fn read8(&mut self, a: usize) -> u8 {
        self.port.read8(a)
    }
    fn read16(&mut self, a: usize) -> u16 {
        self.port.read16(a)
    }
    fn read32(&mut self, a: usize) -> u32 {
        self.port.read32(a)
    }
    fn write8(&mut self, a: usize, v: u8) {
        self.port.write8(a, v);
    }
    fn write16(&mut self, a: usize, v: u16) {
        self.port.write16(a, v);
    }
    fn write32(&mut self, a: usize, v: u32) {
        self.port.write32(a, v);
    }
}
struct PanicMinimum {
    _drops: Drops,
    at_check: bool,
}
// SAFETY: private model failure/unwind injection, never native permission.
unsafe impl Timer for PanicMinimum {
    fn check(&self) -> Result<(), Error> {
        if self.at_check {
            panic!("minimum check callback")
        } else {
            Ok(())
        }
    }
    fn wait_us(&self, _: u64) -> Result<(), Error> {
        panic!("minimum wait callback")
    }
}
#[test]
fn provider_check_and_late_wait_unwind_never_drop_original_registers_or_minimum() {
    for at_check in [true, false] {
        let registers = Rc::new(Cell::new(0));
        let timer = Rc::new(Cell::new(0));
        let hardware = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
        let mut dma = TestRegion::new(128 * 1024 * 8);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = Host::new(
                Box::new(RegisterOwner {
                    port: Port(hardware.clone()),
                    _drops: Drops(registers.clone()),
                }),
                clock(),
                Rc::new(PanicMinimum {
                    _drops: Drops(timer.clone()),
                    at_check,
                }),
                "panic callback".into(),
                &mut dma,
                Profile::Standard,
            );
        }));
        assert!(result.is_err());
        assert_eq!(registers.get(), 0);
        assert_eq!(timer.get(), 0);
    }
}
struct Allocator {
    inner: TestRegion,
    calls: usize,
}
impl DmaAllocator for Allocator {
    fn allocate(&mut self, bytes: usize, align: usize) -> Result<DmaBuffer, BlockError> {
        self.calls += 1;
        if self.calls == 2 {
            panic!("second allocator callback")
        }
        self.inner.allocate(bytes, align)
    }
}
#[test]
fn second_allocation_unwind_keeps_original_slot_and_provider() {
    let registers = Rc::new(Cell::new(0));
    let hardware = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    let minimum = minimum(false);
    let weak = Rc::downgrade(&minimum);
    let mut dma = Allocator {
        inner: TestRegion::new(128 * 1024 * 8),
        calls: 0,
    };
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = Host::new(
                Box::new(RegisterOwner {
                    port: Port(hardware),
                    _drops: Drops(registers.clone()),
                }),
                clock(),
                minimum.clone(),
                "allocator unwind".into(),
                &mut dma,
                Profile::Standard,
            );
        }))
        .is_err()
    );
    drop(minimum);
    assert!(weak.upgrade().is_some());
    assert_eq!(registers.get(), 0);
    assert_eq!(dma.calls, 2);
}
#[test]
fn abandoned_refusal_and_host_keep_the_same_actual_input_graph() {
    let registers = Rc::new(Cell::new(0));
    let hardware = Rc::new(RefCell::new(Hardware::new(Kind::Sd, true)));
    let minimum = minimum(true);
    let weak = Rc::downgrade(&minimum);
    let mut dma = TestRegion::new(128 * 1024 * 8);
    {
        let refusal = Host::new(
            Box::new(RegisterOwner {
                port: Port(hardware),
                _drops: Drops(registers.clone()),
            }),
            clock(),
            minimum.clone(),
            "abandoned failure".into(),
            &mut dma,
            Profile::Standard,
        )
        .err()
        .expect("owning failure");
        assert_eq!(refusal.error, BlockError::PciPower(Error::Clock));
    }
    drop(minimum);
    assert!(weak.upgrade().is_some());
    assert_eq!(registers.get(), 0);
}

#[test]
fn earliest_attach_provider_callback_unwind_retains_original_function_and_timer() {
    use crate::bus::pci::{EcamConfig, owned::test_support};
    use core::sync::atomic::Ordering;
    let timer_drops = Rc::new(Cell::new(0));
    let address = crate::bus::pci::Address {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    let (mut config, counters) = test_support::fixture(address);
    config.write32(0, 0x0001_1234).unwrap();
    config.write32(8, 0x0805_0000).unwrap();
    // Observe the SAME original source epoch and mapping, not another writer.
    // Function below still owns the affine DriverGrant and original mapping.
    let retention = config.retain_epoch().unwrap();
    assert_eq!(config.matches_retention(&retention), Ok(true));
    let function = Function::new(address, EcamConfig::from_owned(config)).unwrap();
    let before = counters.contexts.load(Ordering::Relaxed);
    let handoff = Handoff {
        ecam: Vec::new(),
        mapped: Vec::new(),
        dma: 0..0,
        clock: clock(),
        firmware: None,
        completion: None,
    };
    let mut dma = TestRegion::new(128 * 1024 * 8);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = attach(
                function,
                &handoff,
                &mut dma,
                Rc::new(PanicMinimum {
                    _drops: Drops(timer_drops.clone()),
                    at_check: true,
                }),
            );
        }))
        .is_err()
    );
    assert_eq!(timer_drops.get(), 0);
    assert_eq!(
        counters.contexts.load(Ordering::Relaxed),
        before,
        "no config observation follows failed minimum admission"
    );
    assert_eq!(
        retention.check_live(),
        Ok(()),
        "same concrete EcamConfig mapping owner was not dropped or quarantined"
    );
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn epoch_observer_cannot_hide_dropped_original_function() {
    use crate::bus::{
        mmio::owned::Error as MappingError,
        pci::{EcamConfig, assignment, owned::test_support},
    };
    use core::sync::atomic::Ordering;
    let address = crate::bus::pci::Address {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    let (mut config, counters) = test_support::fixture(address);
    config.write32(0, 0x0001_1234).unwrap();
    config.write32(8, 0x0805_0000).unwrap();
    let retention = config.retain_epoch().unwrap();
    assert_eq!(config.matches_retention(&retention), Ok(true));
    let function = Function::new(address, EcamConfig::from_owned(config)).unwrap();
    assert_eq!(retention.check_live(), Ok(()));
    // Negative control: keeping this actual read-only observer retains storage,
    // but cannot conceal loss of the affine original config/source owner.
    drop(function);
    assert_eq!(
        retention.check_live(),
        Err(MappingError::Assignment(assignment::Error::Closed))
    );
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
}
