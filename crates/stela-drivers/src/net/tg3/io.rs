// SPDX-License-Identifier: GPL-2.0-only
//! Retained native same-function MAC and APE mappings; no physical-address casts.
use super::{Error, Registers};
use crate::bus::pci::{ConfigSpace, Function};
use alloc::sync::Arc;
use core::ptr::NonNull;

struct Window {
    base: NonNull<u8>,
    bytes: usize,
}
impl Window {
    fn new(base: NonNull<u8>, bytes: usize, minimum: usize) -> Result<Self, Error> {
        if base.as_ptr() as usize & 3 != 0
            || bytes < minimum
            || (base.as_ptr() as usize).checked_add(bytes).is_none()
        {
            return Err(Error::Bounds);
        }
        Ok(Self { base, bytes })
    }
    fn pointer(&self, at: u32) -> Result<*mut u32, Error> {
        let at = at as usize;
        if at & 3 != 0 || at.checked_add(4).is_none_or(|end| end > self.bytes) {
            return Err(Error::Bounds);
        }
        // SAFETY: constructor's actual retained mapping and complete bounds.
        Ok(unsafe { self.base.as_ptr().add(at).cast() })
    }
    fn read(&self, at: u32) -> Result<u32, Error> {
        // SAFETY: pointer checks alignment and the entire native access.
        Ok(u32::from_le(unsafe { self.pointer(at)?.read_volatile() }))
    }
    fn write(&mut self, at: u32, value: u32) -> Result<(), Error> {
        // SAFETY: same actual retained UC mapping and checked aligned word.
        unsafe { self.pointer(at)?.write_volatile(value.to_le()) };
        Ok(())
    }
}

pub struct Mmio<C: ConfigSpace> {
    function: Function<C>,
    mac: Window,
    ape: Window,
    _owner: Arc<dyn core::any::Any>,
}
impl<C: ConfigSpace> Mmio<C> {
    /// # Safety
    /// `function` is the actual exclusively reserved powered PCI function.
    /// `mac` and `ape` are its actual complete UC BAR0/BAR2 mappings, and `owner`
    /// retains both mappings, PCI reservation and power. The whole `Registers`
    /// contract holds. Firmware and IRQ users are excluded. Config access must
    /// remain usable while core reset temporarily disables MAC memory decoding.
    /// The function and mapped windows must never be rebound by another owner.
    pub unsafe fn from_owned_windows(
        function: Function<C>,
        mac: NonNull<u8>,
        mac_bytes: usize,
        ape: NonNull<u8>,
        ape_bytes: usize,
        owner: Arc<dyn core::any::Any>,
    ) -> Result<Self, Error> {
        Ok(Self {
            function,
            mac: Window::new(mac, mac_bytes, 0x8000)?,
            ape: Window::new(ape, ape_bytes, 0x8440)?,
            _owner: owner,
        })
    }
}
// SAFETY: construction requires the retained actual same-function ownership;
// consuming it keeps the sole config access and checked UC windows together.
unsafe impl<C: ConfigSpace> Registers for Mmio<C> {
    fn function_number(&self) -> u8 {
        self.function.address.function
    }
    fn config_read32(&mut self, at: u16) -> Result<u32, Error> {
        if at & 3 != 0 || at > 4092 {
            return Err(Error::Bounds);
        }
        let value = self.function.config().read32(at);
        if value == u32::MAX {
            Err(Error::Removed)
        } else {
            Ok(value)
        }
    }
    fn config_write32(&mut self, at: u16, value: u32) -> Result<(), Error> {
        if at & 3 != 0 || at > 4092 {
            return Err(Error::Bounds);
        }
        self.function.config().write32(at, value);
        self.config_read32(0)?; // Real config remains reachable after a write.
        Ok(())
    }
    fn config_write16(&mut self, at: u16, value: u16) -> Result<(), Error> {
        if at & 1 != 0 || at > 4094 {
            return Err(Error::Bounds);
        }
        // Native ConfigSpace overrides this with an actual narrow store,
        // never a dword RMW that could acknowledge adjacent W1C status.
        self.function.config().write16(at, value);
        self.config_read32(0)?;
        Ok(())
    }
    fn read32(&mut self, at: u32) -> Result<u32, Error> {
        self.mac.read(at)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.mac.write(at, value)
    }
    fn ape_read32(&mut self, at: u32) -> Result<u32, Error> {
        self.ape.read(at)
    }
    fn ape_write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.ape.write(at, value)
    }
}
