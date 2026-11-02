//! Typed config failures stop setup and retain owning HDA association inputs.
use super::super::*;
use crate::bus::pci::{ConfigEffect, ConfigError, ConfigFailure, assignment};
use alloc::{boxed::Box, rc::Rc};
use core::cell::Cell;

struct State {
    armed: Cell<bool>,
    after_write: Cell<bool>,
    writes: Cell<usize>,
    config_drops: Cell<usize>,
    bar_drops: Cell<usize>,
}
struct Access {
    bytes: Box<[u8; 256]>,
    state: Rc<State>,
}
impl Access {
    fn read(&self, at: u16, width: usize) -> Result<u32, ConfigError> {
        if self.state.armed.get() {
            return Err(ConfigError::before_effect(ConfigFailure::Ownership(
                assignment::Error::Closed,
            )));
        }
        let mut bytes = [0; 4];
        bytes[..width].copy_from_slice(&self.bytes[usize::from(at)..usize::from(at) + width]);
        Ok(u32::from_le_bytes(bytes))
    }
    fn write(&mut self, at: u16, width: u8, value: u32) -> Result<(), ConfigError> {
        if self.state.armed.get() {
            return Err(ConfigError::before_effect(ConfigFailure::Ownership(
                assignment::Error::Closed,
            )));
        }
        self.state.writes.set(self.state.writes.get() + 1);
        self.bytes[usize::from(at)..usize::from(at) + usize::from(width)]
            .copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
        if self.state.after_write.get() {
            self.state.armed.set(true);
            return Err(ConfigError::write_may_have_applied(
                at,
                width,
                ConfigFailure::Ownership(assignment::Error::Closed),
            ));
        }
        Ok(())
    }
}
impl Drop for Access {
    fn drop(&mut self) {
        self.state
            .config_drops
            .set(self.state.config_drops.get() + 1);
    }
}
impl ConfigSpace for Access {
    fn read8(&self, at: u16) -> Result<u8, ConfigError> {
        self.read(at, 1).map(|value| value as u8)
    }
    fn read16(&self, at: u16) -> Result<u16, ConfigError> {
        self.read(at, 2).map(|value| value as u16)
    }
    fn read32(&self, at: u16) -> Result<u32, ConfigError> {
        self.read(at, 4)
    }
    fn write8(&mut self, at: u16, value: u8) -> Result<(), ConfigError> {
        self.write(at, 1, u32::from(value))
    }
    fn write16(&mut self, at: u16, value: u16) -> Result<(), ConfigError> {
        self.write(at, 2, u32::from(value))
    }
    fn write32(&mut self, at: u16, value: u32) -> Result<(), ConfigError> {
        self.write(at, 4, value)
    }
}
fn fixture() -> (Access, Rc<State>) {
    let state = Rc::new(State {
        armed: Cell::new(false),
        after_write: Cell::new(false),
        writes: Cell::new(0),
        config_drops: Cell::new(0),
        bar_drops: Cell::new(0),
    });
    let mut bytes = Box::new([0; 256]);
    bytes[..4].copy_from_slice(&0xa170_8086u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&0x0403_0000u32.to_le_bytes());
    bytes[0x10..0x14].copy_from_slice(&0x4000u32.to_le_bytes());
    bytes[usize::from(TCSEL)] = 7;
    (
        Access {
            bytes,
            state: state.clone(),
        },
        state,
    )
}
#[test]
fn setup_denial_keeps_typed_cause_without_a_vendor_write() {
    let (mut config, state) = fixture();
    state.armed.set(true);
    let expected = ConfigError::before_effect(ConfigFailure::Ownership(assignment::Error::Closed));
    assert_eq!(
        Setup::IntelIch.controls()[0].apply(&mut config),
        Err(AttachError::Config(expected))
    );
    assert_eq!(state.writes.get(), 0);
    assert_eq!(state.config_drops.get(), 0);
}
#[test]
fn uncertain_vendor_write_is_not_retried_or_converted_to_readback_failure() {
    let (mut config, state) = fixture();
    state.after_write.set(true);
    let expected = ConfigError::write_may_have_applied(
        TCSEL,
        1,
        ConfigFailure::Ownership(assignment::Error::Closed),
    );
    assert_eq!(
        Setup::IntelIch.controls()[0].apply(&mut config),
        Err(AttachError::Config(expected))
    );
    assert_eq!(state.writes.get(), 1);
    assert_eq!(config.bytes[usize::from(TCSEL)] & TCSEL_MASK, 0);
    assert!(matches!(
        expected.effect,
        ConfigEffect::WriteMayHaveApplied {
            offset: TCSEL,
            width: 1
        }
    ));
}
struct BarOwner {
    _bytes: Box<[u8; 4096]>,
    state: Rc<State>,
}
impl Drop for BarOwner {
    fn drop(&mut self) {
        self.state.bar_drops.set(self.state.bar_drops.get() + 1);
    }
}
impl Registers for BarOwner {
    fn region_bytes(&self) -> usize {
        4096
    }
    fn read8(&mut self, _: usize) -> u8 {
        panic!("binding must not access MMIO");
    }
    fn read16(&mut self, _: usize) -> u16 {
        panic!("binding must not access MMIO");
    }
    fn read32(&mut self, _: usize) -> u32 {
        panic!("binding must not access MMIO");
    }
    fn write8(&mut self, _: usize, _: u8) {
        panic!("binding must not access MMIO");
    }
    fn write16(&mut self, _: usize, _: u16) {
        panic!("binding must not access MMIO");
    }
    fn write32(&mut self, _: usize, _: u32) {
        panic!("binding must not access MMIO");
    }
}
#[test]
fn denied_owned_binding_keeps_both_original_function_and_bar_allocations() {
    let (config, state) = fixture();
    let address = Address {
        segment: 0,
        bus: 0,
        device: 27,
        function: 0,
    };
    let function = Box::new(Function::new(address, config).unwrap());
    let identity = identity(0x8086, 0xa170, CLASS).unwrap();
    let prepared = Prepared {
        address,
        identity,
        base: 0x4000,
        bytes: 4096,
    };
    let bar = BarOwner {
        _bytes: Box::new([0; 4096]),
        state: state.clone(),
    };
    state.armed.set(true);
    // SAFETY: the test exclusively owns these actual model allocations. No
    // DMA, IRQ, aliases, firmware or MMIO user exists; association must fail
    // on the actual ConfigSpace boundary before touching BAR storage.
    let failure = match unsafe { prepared.bind_owned_registers(function, bar) } {
        Err(failure) => failure,
        Ok(_) => panic!("closed config permission cannot bind an HDA owner"),
    };
    assert_eq!(
        failure.error,
        AttachError::Config(ConfigError::before_effect(ConfigFailure::Ownership(
            assignment::Error::Closed
        )))
    );
    drop(failure);
    assert_eq!(state.config_drops.get(), 0);
    assert_eq!(state.bar_drops.get(), 0);
    assert_eq!(state.writes.get(), 0);
}
