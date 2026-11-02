//! PCI transport failures stop the original NHI preparation state machine.
use super::*;
use crate::bus::pci::{ConfigError, ConfigFailure, assignment};
use core::cell::Cell;

struct FaultPci {
    inner: Pci,
    read: Cell<Option<ConfigError>>,
    fail_force: bool,
    hrr_error: Option<ConfigError>,
}
impl ConfigSpace for FaultPci {
    fn read8(&self, at: u16) -> Result<u8, ConfigError> {
        match self.read.get() {
            Some(error) => Err(error),
            None => self.inner.read8(at),
        }
    }
    fn read16(&self, at: u16) -> Result<u16, ConfigError> {
        match self.read.get() {
            Some(error) => Err(error),
            None => self.inner.read16(at),
        }
    }
    fn read32(&self, at: u16) -> Result<u32, ConfigError> {
        if let Some(error) = self.hrr_error {
            let flusher = self.inner.state.lock().unwrap().reset_flush.clone();
            if flusher
                .and_then(|model| model.upgrade())
                .is_some_and(|model| {
                    let state = model.state.lock().unwrap();
                    state.reset_posted
                })
            {
                return Err(error);
            }
        }
        match self.read.get() {
            Some(error) => Err(error),
            None => self.inner.read32(at),
        }
    }
    fn write8(&mut self, at: u16, value: u8) -> Result<(), ConfigError> {
        self.inner.write8(at, value)
    }
    fn write16(&mut self, at: u16, value: u16) -> Result<(), ConfigError> {
        self.inner.write16(at, value)
    }
    fn write32(&mut self, at: u16, value: u32) -> Result<(), ConfigError> {
        self.inner.write32(at, value)?;
        if self.fail_force && at == VS_FORCE {
            return Err(ConfigError::write_may_have_applied(
                at,
                4,
                ConfigFailure::Readback {
                    offset: at,
                    width: 4,
                    expected: value,
                    observed: value ^ FORCE,
                },
            ));
        }
        Ok(())
    }
}
#[test]
fn denied_config_read_prevents_nhi_mutation_and_returns_exact_cause() {
    let (pci, model) = fixture(0x8086, 0x9a1b, 0x0c0340, 0x20, 8);
    let state = pci.state.clone();
    let error = ConfigError::before_effect(ConfigFailure::Ownership(assignment::Error::Context));
    let mut pci = FaultPci {
        inner: pci,
        read: Cell::new(Some(error)),
        fail_force: false,
        hrr_error: None,
    };
    // SAFETY: both model surfaces belong to this unique synthetic requester;
    // no DMA, IRQ, firmware or other user exists. Denial creates no permission.
    let result = unsafe { Controller::new(&mut pci, model.clone(), minimum(&model)) };
    assert!(matches!(result, Err(Error::Config(actual)) if actual == error));
    assert!(state.lock().unwrap().writes.is_empty());
    assert!(model.state.lock().unwrap().writes.is_empty());
    assert_eq!(Arc::strong_count(&model), 1);
}
#[test]
fn uncertain_force_write_poisoning_prevents_retry_and_retains_same_register_owner() {
    let (pci, model) = fixture(0x8086, 0x9a1b, 0x0c0340, 0x20, 8);
    let state = pci.state.clone();
    let mut pci = FaultPci {
        inner: pci,
        read: Cell::new(None),
        fail_force: true,
        hrr_error: None,
    };
    // SAFETY: same actual owned model resources/epoch, D0/decode, no prior
    // DMA or IRQ. The test injects failure after the native-width PCI effect.
    let mut controller =
        unsafe { Controller::new(&mut pci, model.clone(), minimum(&model)) }.unwrap();
    model.clock.store(0, Ordering::Relaxed);
    let error = controller.poll(0).unwrap_err();
    let Error::Config(error) = error else {
        panic!("config failure lost");
    };
    assert!(matches!(
        error.effect,
        crate::bus::pci::ConfigEffect::WriteMayHaveApplied {
            offset: VS_FORCE,
            width: 4
        }
    ));
    assert_eq!(state.lock().unwrap().writes.len(), 1);
    let mmio = model.state.lock().unwrap().writes.clone();
    assert_eq!(controller.poll(1), Err(Error::Poisoned));
    assert_eq!(state.lock().unwrap().writes.len(), 1);
    assert_eq!(model.state.lock().unwrap().writes, mmio);
    drop(controller);
    assert_eq!(Arc::strong_count(&model), 2);
}

#[test]
fn typed_post_hrr_transport_failure_stops_before_minimum_or_reset_observation() {
    let (pci, model) = fixture(0x1022, 0x1668, 0x0c0340, 0x40, 8);
    let error = ConfigError::before_effect(ConfigFailure::Ownership(assignment::Error::Context));
    let mut pci = FaultPci {
        inner: pci,
        read: Cell::new(None),
        fail_force: false,
        hrr_error: Some(error),
    };
    let source = minimum(&model);
    // SAFETY: one actual model requester/configuration/BAR; failure is injected
    // only after its original posted HRR store, never a replacement requester.
    let mut controller =
        unsafe { Controller::new(&mut pci, model.clone(), source.clone()) }.unwrap();
    assert_eq!(controller.poll(0), Err(Error::Config(error)));
    assert_eq!(model.state.lock().unwrap().writes, vec![(RESET, 1)]);
    assert!(model.state.lock().unwrap().reset_read_wall.is_empty());
    assert_eq!(model.wall.load(Ordering::Relaxed), 0);
    assert_eq!(controller.poll(1000), Err(Error::Poisoned));
    drop(controller);
    assert_eq!(Arc::strong_count(&model), 2);
    assert_eq!(alloc::rc::Rc::strong_count(&source), 2);
}
