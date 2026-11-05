//! Transport denial stays distinct from hardware responses during PIO admission.
use super::super::*;
use crate::bus::pci::{
    Address, CapabilityError, ConfigEffect, ConfigError, ConfigFailure, FunctionError, assignment,
};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Read(u16, u8),
    Write(u16, u8),
}
struct State {
    denied: Cell<Option<(Access, bool)>>,
    accesses: RefCell<Vec<Access>>,
    drops: Cell<usize>,
}
struct Config {
    bytes: Box<[u8; 4096]>,
    state: Rc<State>,
}
impl Config {
    fn error(&self, access: Access) -> Option<ConfigError> {
        self.state.accesses.borrow_mut().push(access);
        let (denied, after) = self.state.denied.get()?;
        if access != denied {
            return None;
        }
        let reason = ConfigFailure::Ownership(assignment::Error::Closed);
        Some(match (access, after) {
            (Access::Write(offset, width), true) => {
                ConfigError::write_may_have_applied(offset, width, reason)
            }
            _ => ConfigError::before_effect(reason),
        })
    }
    fn read(&self, at: u16, width: u8) -> Result<u32, ConfigError> {
        if let Some(error) = self.error(Access::Read(at, width)) {
            return Err(error);
        }
        let mut bytes = [0; 4];
        bytes[..usize::from(width)]
            .copy_from_slice(&self.bytes[usize::from(at)..usize::from(at) + usize::from(width)]);
        Ok(u32::from_le_bytes(bytes))
    }
    fn write(&mut self, at: u16, width: u8, value: u32) -> Result<(), ConfigError> {
        let error = self.error(Access::Write(at, width));
        if error.is_none_or(|error| error.effect != ConfigEffect::None) {
            self.bytes[usize::from(at)..usize::from(at) + usize::from(width)]
                .copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
        }
        error.map_or(Ok(()), Err)
    }
}
impl Drop for Config {
    fn drop(&mut self) {
        self.state.drops.set(self.state.drops.get() + 1);
    }
}
impl ConfigSpace for Config {
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
fn fixture() -> (Function<Config>, Rc<State>) {
    let state = Rc::new(State {
        denied: Cell::new(None),
        accesses: RefCell::new(Vec::new()),
        drops: Cell::new(0),
    });
    let mut bytes = Box::new([0; 4096]);
    bytes[..4].copy_from_slice(&0x8220_1217u32.to_le_bytes());
    bytes[4..6].copy_from_slice(&7u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&0x10u16.to_le_bytes());
    bytes[8..12].copy_from_slice(&0x0805_0100u32.to_le_bytes());
    bytes[0x34] = 0x40;
    bytes[0x40] = 5;
    bytes[0x42] = 1;
    let function = Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 1,
            function: 0,
        },
        Config {
            bytes,
            state: state.clone(),
        },
    )
    .unwrap();
    state.accesses.borrow_mut().clear();
    (function, state)
}
#[test]
fn pio_denied_identity_read_keeps_owner_and_emits_no_command() {
    let (mut function, state) = fixture();
    state.denied.set(Some((Access::Read(0, 4), false)));
    let error = ConfigError::before_effect(ConfigFailure::Ownership(assignment::Error::Closed));
    assert_eq!(quiesce_pio(&mut function), Err(BlockError::Config(error)));
    assert_eq!(&*state.accesses.borrow(), &[Access::Read(0, 4)]);
    assert_eq!(state.drops.get(), 0);
    drop(function);
    assert_eq!(state.drops.get(), 1);
}
#[test]
fn pio_uncertain_command_write_keeps_cause_and_never_touches_msi() {
    let (mut function, state) = fixture();
    state.denied.set(Some((Access::Write(4, 2), true)));
    let error = ConfigError::write_may_have_applied(
        4,
        2,
        ConfigFailure::Ownership(assignment::Error::Closed),
    );
    assert_eq!(quiesce_pio(&mut function), Err(BlockError::Config(error)));
    assert_eq!(state.accesses.borrow().last(), Some(&Access::Write(4, 2)));
    assert!(
        !state
            .accesses
            .borrow()
            .iter()
            .any(|access| matches!(access, Access::Write(at, _) if *at != 4))
    );
    assert_eq!(state.drops.get(), 0);
    assert_eq!(
        u16::from_le_bytes(function.config().bytes[4..6].try_into().unwrap()),
        0x401
    );
    assert_eq!(
        u16::from_le_bytes(function.config().bytes[0x42..0x44].try_into().unwrap()),
        1
    );
}
#[test]
fn capability_denial_preserves_walk_offset_and_access_cause() {
    let (mut function, state) = fixture();
    state.denied.set(Some((Access::Read(0x34, 1), false)));
    let error = ConfigError::before_effect(ConfigFailure::Ownership(assignment::Error::Closed));
    assert_eq!(
        capability(function.config(), 5),
        Err(BlockError::PciCapability(CapabilityError::Config {
            offset: 0x34,
            error
        }))
    );
    assert!(
        !state
            .accesses
            .borrow()
            .iter()
            .any(|access| matches!(access, Access::Write(..)))
    );
}
#[test]
fn all_ones_remains_hardware_data_and_absent_function_returns_original_config() {
    let (function, state) = fixture();
    drop(function);
    let config = Config {
        bytes: Box::new([0xff; 4096]),
        state: state.clone(),
    };
    assert_eq!(config.read32(0), Ok(u32::MAX));
    let refusal = match Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 1,
            function: 0,
        },
        config,
    ) {
        Err(refusal) => refusal,
        Ok(_) => panic!("absent hardware cannot construct a function"),
    };
    assert_eq!(refusal.reason, FunctionError::Absent);
    assert_eq!(state.drops.get(), 1);
    assert_eq!(refusal.config.read32(0), Ok(u32::MAX));
    drop(refusal);
    assert_eq!(state.drops.get(), 2);
}
