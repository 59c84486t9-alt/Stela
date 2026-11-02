//! Real configuration errors survive the kept I801 mode owner and fault latch.
use super::*;
use crate::bus::pci::{ConfigError, ConfigFailure, assignment};
use alloc::boxed::Box;

struct NativeSpace {
    byte: Rc<Cell<u8>>,
    read_error: Rc<Cell<Option<ConfigError>>>,
    write_error: Rc<Cell<Option<ConfigError>>>,
    writes: Rc<Cell<usize>>,
    drops: Rc<Cell<usize>>,
}
impl Drop for NativeSpace {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl NativeSpace {
    fn word(&self, at: u16) -> Result<u32, ConfigError> {
        if let Some(error) = self.read_error.get() {
            return Err(error);
        }
        Ok(match at {
            0 => 0x7e22_8086,
            8 => 0x0c05_0000,
            0x40 => u32::from(self.byte.get()),
            _ => 0,
        })
    }
}
impl ConfigSpace for NativeSpace {
    fn read8(&self, at: u16) -> Result<u8, ConfigError> {
        Ok((self.word(at & !3)? >> ((at & 3) * 8)) as u8)
    }
    fn read16(&self, at: u16) -> Result<u16, ConfigError> {
        Ok((self.word(at & !3)? >> ((at & 2) * 8)) as u16)
    }
    fn read32(&self, at: u16) -> Result<u32, ConfigError> {
        self.word(at)
    }
    fn write8(&mut self, at: u16, value: u8) -> Result<(), ConfigError> {
        assert_eq!(at, PCI_HOST_CONFIGURATION);
        self.writes.set(self.writes.get() + 1);
        self.byte.set(value);
        self.write_error.get().map_or(Ok(()), Err)
    }
    fn write16(&mut self, _: u16, _: u16) -> Result<(), ConfigError> {
        panic!("host mode requires a byte store");
    }
    fn write32(&mut self, _: u16, _: u32) -> Result<(), ConfigError> {
        panic!("host mode requires a byte store");
    }
}
struct Guard {
    _allocation: Box<[u8; 4096]>,
    drops: Rc<Cell<usize>>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
struct NativeFixture {
    configuration: OwnedConfiguration<NativeSpace, Guard>,
    byte: Rc<Cell<u8>>,
    read_error: Rc<Cell<Option<ConfigError>>>,
    write_error: Rc<Cell<Option<ConfigError>>>,
    writes: Rc<Cell<usize>>,
    drops: Rc<Cell<usize>>,
}
fn native_fixture() -> NativeFixture {
    let byte = Rc::new(Cell::new(HOST_ENABLED));
    let read_error = Rc::new(Cell::new(None));
    let write_error = Rc::new(Cell::new(None));
    let writes = Rc::new(Cell::new(0));
    let drops = Rc::new(Cell::new(0));
    let space = NativeSpace {
        byte: byte.clone(),
        read_error: read_error.clone(),
        write_error: write_error.clone(),
        writes: writes.clone(),
        drops: drops.clone(),
    };
    let function = Function::new(
        crate::bus::pci::Address {
            segment: 0,
            bus: 0,
            device: 31,
            function: 4,
        },
        space,
    )
    .unwrap();
    let guard = Guard {
        _allocation: Box::new([0; 4096]),
        drops: drops.clone(),
    };
    // SAFETY: actual unique model function and owned allocation, with no I/O,
    // firmware, IRQ or other engine user. This supplies no physical hardware grant.
    let configuration = match unsafe { OwnedConfiguration::claim(function, guard) } {
        Ok(configuration) => configuration,
        Err(owners) => {
            core::mem::forget(owners);
            panic!("valid exclusive model rejected");
        }
    };
    NativeFixture {
        configuration,
        byte,
        read_error,
        write_error,
        writes,
        drops,
    }
}
#[test]
fn native_read_denial_keeps_config_cause_and_both_original_owners() {
    let mut f = native_fixture();
    let error = ConfigError::before_effect(ConfigFailure::Ownership(assignment::Error::Context));
    f.read_error.set(Some(error));
    assert_eq!(
        f.configuration.read(),
        Err(ConfigurationError::Config(error))
    );
    assert_eq!(
        f.configuration.write(HOST_ENABLED),
        Err(ConfigurationError::Config(error))
    );
    assert_eq!(f.writes.get(), 0);
    assert_eq!(f.drops.get(), 0);
    drop(f.configuration);
    assert_eq!(f.drops.get(), 2);
}
#[test]
fn uncertain_native_mode_write_is_not_acknowledged_or_replayed() {
    let mut f = native_fixture();
    let wanted = HOST_ENABLED | HOST_I2C;
    let error = ConfigError::write_may_have_applied(
        PCI_HOST_CONFIGURATION,
        1,
        ConfigFailure::Readback {
            offset: PCI_HOST_CONFIGURATION,
            width: 1,
            expected: u32::from(wanted),
            observed: 0,
        },
    );
    f.write_error.set(Some(error));
    assert_eq!(
        f.configuration.write(wanted),
        Err(ConfigurationError::Config(error))
    );
    assert_eq!(f.byte.get(), wanted);
    assert_eq!(f.writes.get(), 1);
    assert_eq!(f.drops.get(), 0);
}
struct Fault<C> {
    inner: C,
    error: Rc<Cell<Option<ConfigurationError>>>,
}
// SAFETY: the same actual owned configuration/guard stays in inner. The
// test injects denial only; it creates no hardware/resource permission.
unsafe impl<C: HostConfiguration> HostConfiguration for Fault<C> {
    fn device_id(&self) -> u16 {
        self.inner.device_id()
    }
    fn read(&mut self) -> Result<u8, ConfigurationError> {
        match self.error.get() {
            Some(error) => Err(error),
            None => self.inner.read(),
        }
    }
    fn write(&mut self, value: u8) -> Result<(), ConfigurationError> {
        match self.error.get() {
            Some(error) => Err(error),
            None => self.inner.write(value),
        }
    }
}
#[test]
fn config_denial_latches_exact_failure_without_start_or_retry_and_keeps_owners() {
    let f = fixture(0x7e22, false);
    let (host, configuration) = match f.host.release() {
        Ok(owners) => owners,
        Err(_) => panic!("fresh fixture must release"),
    };
    let injected = Rc::new(Cell::new(None));
    let configuration = Fault {
        inner: configuration,
        error: injected.clone(),
    };
    // SAFETY: the same owned host and configuration remain paired; the
    // fault injector does not add a competing owner or an active transaction.
    let mut host = match unsafe { Controller::claim(host, configuration) } {
        Ok(host) => host,
        Err(_) => panic!("fresh paired fixture must claim"),
    };
    let error = ConfigError::before_effect(ConfigFailure::Ownership(assignment::Error::Closed));
    injected.set(Some(ConfigurationError::Config(error)));
    let mut bytes = [0xa5];
    let result = host
        .read_i2c_block(address(), 0xa7, &mut bytes)
        .unwrap_err();
    assert_eq!(
        result.kind,
        ErrorKind::Configuration(ConfigurationError::Config(error))
    );
    assert_eq!(
        host.failure().unwrap().configuration.unwrap().error,
        Some(ConfigurationError::Config(error))
    );
    assert_eq!(bytes, [0xa5]);
    assert!(f.state.borrow().starts.is_empty());
    let count = f.state.borrow().config_count;
    assert_eq!(
        host.read_i2c_block(address(), 0xa7, &mut bytes)
            .unwrap_err()
            .kind,
        ErrorKind::NeedsReset
    );
    assert_eq!(f.state.borrow().config_count, count);
    drop(host);
    assert_eq!(f.register_drop.get(), 0);
    assert_eq!(f.config_drop.get(), 0);
}
#[test]
fn failed_composite_claim_returns_exact_config_cause_and_unmodified_owners() {
    let f = fixture(0x7e22, false);
    let (host, configuration) = match f.host.release() {
        Ok(owners) => owners,
        Err(_) => panic!("fresh fixture must release"),
    };
    let error = ConfigError::before_effect(ConfigFailure::Ownership(assignment::Error::Context));
    let configuration = Fault {
        inner: configuration,
        error: Rc::new(Cell::new(Some(ConfigurationError::Config(error)))),
    };
    // SAFETY: original fixture owners remain paired and have no pending I/O.
    let (kind, owners) = match unsafe { Controller::claim(host, configuration) } {
        Err(failure) => failure,
        Ok(_) => panic!("denied source cannot claim"),
    };
    assert_eq!(
        kind,
        ErrorKind::Configuration(ConfigurationError::Config(error))
    );
    assert!(f.state.borrow().starts.is_empty());
    assert_eq!(f.register_drop.get(), 0);
    assert_eq!(f.config_drop.get(), 0);
    drop(owners);
    assert_eq!(f.register_drop.get(), 1);
    assert_eq!(f.config_drop.get(), 1);
}
