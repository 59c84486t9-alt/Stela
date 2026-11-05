//! Source-selected reset qualification controls; no native root success fixture.
use super::*;
use crate::bus::pci::{Address, ConfigSpace};
use core::cell::Cell;

struct ModelTimer {
    available: bool,
    elapsed: Cell<u64>,
}
// SAFETY: private protocol model only. wait_us advances the model's elapsed
// duration by the full requested amount; this grants no native clock authority.
unsafe impl crate::bus::pci::power::Timer for ModelTimer {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        if self.available {
            Ok(())
        } else {
            Err(crate::bus::pci::power::Error::Clock)
        }
    }
    fn wait_us(&self, microseconds: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.check()?;
        self.elapsed.set(
            self.elapsed
                .get()
                .checked_add(microseconds)
                .ok_or(crate::bus::pci::power::Error::Clock)?,
        );
        Ok(())
    }
}
fn timer() -> ModelTimer {
    ModelTimer {
        available: true,
        elapsed: Cell::new(0),
    }
}

struct Config {
    words: [u32; 128],
    reads: Cell<usize>,
    resets: usize,
}
impl ConfigSpace for Config {
    fn read32(&self, offset: u16) -> Result<u32, crate::bus::pci::ConfigError> {
        let value = {
            self.reads.set(self.reads.get() + 1);
            self.words[usize::from(offset / 4)]
        };
        Ok(value)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), crate::bus::pci::ConfigError> {
        self.words[usize::from(offset / 4)] = value;
        if offset == 0x48 && value & (1 << 15) != 0 {
            self.resets += 1;
            self.words[0x48 / 4] = 0;
            self.words[4] = 0;
        }

        Ok(())
    }

    fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }

    fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }

    fn write8(&mut self, _: u16, _: u8) -> Result<(), crate::bus::pci::ConfigError> {
        panic!("unexpected narrow PCI store in controller fixture");
    }

    fn write16(&mut self, offset: u16, value: u16) -> Result<(), crate::bus::pci::ConfigError> {
        let shift = (offset & 2) * 8;
        let word = &mut self.words[usize::from(offset / 4)];
        *word = (*word & !(0xffff << shift)) | u32::from(value) << shift;
        if offset == 0x48 && value & (1 << 15) != 0 {
            self.resets += 1;
            self.words[0x48 / 4] = 0;
            self.words[4] = 0;
        }
        Ok(())
    }
}
fn function(vendor: u16, device: u16, revision: u8) -> Function<Config> {
    let mut words = [0; 128];
    words[0] = u32::from(vendor) | u32::from(device) << 16;
    words[1] = 0x0010_0402;
    words[2] = 0x0c03_4000 | u32::from(revision);
    words[4] = 0xf000_0000;
    words[0x34 / 4] = 0x40;
    words[0x40 / 4] = 0x0002_0010;
    words[0x44 / 4] = 1 << 28;
    Function::new(
        Address {
            segment: 0,
            bus: 1,
            device: 0,
            function: 0,
        },
        Config {
            words,
            reads: Cell::new(0),
            resets: 0,
        },
    )
    .unwrap()
}
#[test]
fn uncalibrated_nhi_never_observes_config_or_attempts_reset() {
    let mut function = function(0x8086, 0x9a1b, 1);
    function.config().reads.set(0);
    assert_eq!(
        check_flr(
            &mut function,
            &ModelTimer {
                available: false,
                elapsed: Cell::new(0)
            }
        ),
        Err(Error::Reset(crate::block::BlockError::PciPower(
            crate::bus::pci::power::Error::Clock
        )))
    );
    assert_eq!(function.config().reads.get(), 0);
    assert_eq!(function.config().resets, 0);
}
#[test]
fn generic_usb4_matching_never_bypasses_native_donor_no_flr_quirks() {
    for (vendor, devices) in [
        (
            0x1022,
            &[0x1487, 0x148c, 0x149c, 0x7901, 0x1502, 0x17f0][..],
        ),
        (0x8086, &[0x1502, 0x1503]),
        (0x14c3, &[0x0616, 0x7925]),
        (0xd063, &[0x1000]),
    ] {
        for device in devices {
            let mut function = function(vendor, *device, 1);
            assert_eq!(check_flr(&mut function, &timer()), Err(Error::ResetQuirk));
            assert_eq!(function.config().resets, 0);
        }
    }
}
#[test]
fn absent_flr_and_active_busmaster_do_not_create_stopped_authority() {
    let timer = timer();
    let mut absent = function(0x8086, 0x9a1b, 1);
    absent.config().words[0x44 / 4] = 0;
    assert_eq!(check_flr(&mut absent, &timer), Err(Error::ResetRequired));
    assert_eq!(absent.config().resets, 0);
    let mut active = function(0x8086, 0x9a1b, 1);
    active.config().words[1] |= 4;
    assert!(matches!(
        check_flr(&mut active, &timer),
        Err(Error::Claim(_))
    ));
    assert_eq!(active.config().resets, 0);
}
#[test]
fn actual_supported_reset_restores_contained_header_before_revalidation() {
    let mut function = function(0x8086, 0x9a1b, 1);
    reset(&mut function, &timer()).unwrap();
    assert_eq!(function.config().resets, 1);
    assert_eq!(function.config().words[4], 0xf000_0000);
    assert_eq!(function.config().words[1] & 4, 0);
}
