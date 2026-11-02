// SPDX-License-Identifier: GPL-2.0-only
//! Actual owned function/register storage across association failure/unwind.
extern crate std;
use super::*;
use alloc::boxed::Box;
use core::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Config {
    inner: Model,
    drops: Rc<Cell<usize>>,
    panic_read: Rc<Cell<bool>>,
}
impl Drop for Config {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl ConfigSpace for Config {
    fn read32(&self, o: u16) -> Result<u32, crate::bus::pci::ConfigError> {
        let value = {
            assert!(!self.panic_read.get(), "modeled original config callback");
            self.inner.read32(o)?
        };
        Ok(value)
    }
    fn write32(&mut self, o: u16, v: u32) -> Result<(), crate::bus::pci::ConfigError> {
        self.inner.write32(o, v)?;

        Ok(())
    }

    fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }

    fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }

    fn write8(&mut self, _: u16, _: u8) -> Result<(), crate::bus::pci::ConfigError> {
        panic!("unexpected narrow PCI store in identity/reset fixture");
    }

    fn write16(&mut self, _: u16, _: u16) -> Result<(), crate::bus::pci::ConfigError> {
        panic!("unexpected narrow PCI store in identity/reset fixture");
    }
}
struct RegistersOwner {
    drops: Rc<Cell<usize>>,
    panic_span: bool,
}
impl Drop for RegistersOwner {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl Registers for RegistersOwner {
    fn region_bytes(&self) -> usize {
        assert!(!self.panic_span, "modeled BAR callback");
        0x440
    }
    fn read8(&mut self, _: usize) -> u8 {
        0
    }
    fn read16(&mut self, _: usize) -> u16 {
        0
    }
    fn read32(&mut self, _: usize) -> u32 {
        0
    }
    fn write8(&mut self, _: usize, _: u8) {
        panic!("association never changes MMIO");
    }
    fn write16(&mut self, _: usize, _: u16) {
        panic!("association never changes MMIO");
    }
    fn write32(&mut self, _: usize, _: u32) {
        panic!("association never changes MMIO");
    }
}
struct OwnedFixture {
    prepared: Prepared,
    function: Box<Function<Config>>,
    registers: RegistersOwner,
    function_drops: Rc<Cell<usize>>,
    register_drops: Rc<Cell<usize>>,
    panic_read: Rc<Cell<bool>>,
}
fn owned_fixture() -> OwnedFixture {
    let (mut function, clock, bar) = fixture(0);
    // SAFETY: exclusively owned symbolic conventional config with no actual
    // DMA/IRQ users. This is a PCI association model, not native root proof.
    let prepared =
        unsafe { prepare(&mut function, bar, &clock, Ownership::ExclusiveLegacy) }.unwrap();
    let address = function.address;
    let function_drops = Rc::new(Cell::new(0));
    let register_drops = Rc::new(Cell::new(0));
    let panic_read = Rc::new(Cell::new(false));
    let config = Config {
        inner: function.into_config(),
        drops: function_drops.clone(),
        panic_read: panic_read.clone(),
    };
    let function = Box::new(Function::new(address, config).unwrap());
    OwnedFixture {
        prepared,
        function,
        registers: RegistersOwner {
            drops: register_drops.clone(),
            panic_span: false,
        },
        function_drops,
        register_drops,
        panic_read,
    }
}
#[test]
fn owning_association_keeps_real_function_without_static_borrow_and_returns_both_owners() {
    let f = owned_fixture();
    // SAFETY: same exclusively owned symbolic config/BAR, no users/DMA.
    let registers = match unsafe { f.prepared.bind_owned_registers(f.function, f.registers) } {
        Ok(r) => r,
        Err(e) => panic!("{:?}", e.error),
    };
    assert_eq!(f.function_drops.get(), 0);
    assert_eq!(f.register_drops.get(), 0);
    let (_, function, bar) = registers.into_parts();
    drop(function);
    drop(bar);
    assert_eq!(f.function_drops.get(), 1);
    assert_eq!(f.register_drops.get(), 1);
}
#[test]
fn owning_association_failure_retains_both_original_owners_on_error_and_drop() {
    let mut f = owned_fixture();
    f.function.config().inner.words[0] ^= 1 << 16;
    // SAFETY: diagnostic negative identity mismatch; reject before effects and
    // retain actual arguments, which have no DMA/IRQ users in this model.
    let failure = match unsafe { f.prepared.bind_owned_registers(f.function, f.registers) } {
        Ok(_) => panic!("foreign identity accepted"),
        Err(e) => e,
    };
    assert_eq!(failure.error, AttachError::IdentityChanged);
    drop(failure);
    assert_eq!(f.function_drops.get(), 0);
    assert_eq!(f.register_drops.get(), 0);
}
#[test]
fn callback_unwind_during_owned_association_retains_config_and_bar_without_retry() {
    for span in [false, true] {
        let mut f = owned_fixture();
        if span {
            f.registers.panic_span = true;
        } else {
            f.panic_read.set(true);
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: only a symbolic callback panics; the exact original
            // owners must survive caught unwind without cleanup or replay.
            unsafe { f.prepared.bind_owned_registers(f.function, f.registers) }
        }));
        assert!(result.is_err());
        assert_eq!(f.function_drops.get(), 0);
        assert_eq!(f.register_drops.get(), 0);
    }
}
