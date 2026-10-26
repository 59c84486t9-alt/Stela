// SPDX-License-Identifier: GPL-2.0-only
//! Actual bounded, volatile access through retained native UC mappings.
use super::Error;
use crate::bus::mmio::owned::{CacheAttribute, Mapping, Protection};

pub(super) mod sealed {
    pub trait Sealed {}
}

/// Sealed register transport: external callers cannot replace actual owned
/// MMIO with numeric addresses or implement a fabricated native grant.
pub trait RegisterIo: sealed::Sealed {
    fn bytes(&self) -> usize;
    fn read32(&mut self, offset: usize) -> Result<u32, Error>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error>;
    fn read_mux(&mut self, pad: u8) -> Result<u8, Error>;
    fn write_mux(&mut self, pad: u8, value: u8) -> Result<(), Error>;
    /// Retire the original transport only after all register users stop.
    fn finish(&mut self) -> Result<(), Error>;
}

/// Original mapping owners stay retained through failures/quarantine. There is
/// deliberately no public raw constructor: the native adapter retains actual
/// ACPI reservations and claims. A Mapping alone is not that authority.
pub struct NativeRegisters {
    gpio: Mapping,
    mux: Option<Mapping>,
    gpio_retired: bool,
    mux_retired: bool,
}
impl sealed::Sealed for NativeRegisters {}
impl NativeRegisters {
    #[allow(dead_code)] // Raw construction stays internal to native admission.
    pub(in crate::bus::gpio) fn from_owned_mappings(
        gpio: Mapping,
        mux: Option<Mapping>,
    ) -> Result<Self, Error> {
        for mapping in core::iter::once(&gpio).chain(mux.iter()) {
            if mapping.attribute().map_err(|_| Error::Mapping)? != CacheAttribute::Uncached
                || mapping.protection().map_err(|_| Error::Mapping)? != Protection::ReadWrite
            {
                return Err(Error::Mapping);
            }
        }
        if gpio.bytes().map_err(|_| Error::Mapping)? < 0x300
            || mux
                .as_ref()
                .is_some_and(|m| !m.bytes().is_ok_and(|n| n >= 145))
        {
            return Err(Error::Mapping);
        }
        Ok(Self {
            gpio,
            mux,
            gpio_retired: false,
            mux_retired: false,
        })
    }
}
impl RegisterIo for NativeRegisters {
    fn bytes(&self) -> usize {
        self.gpio.bytes().unwrap_or(0)
    }
    fn read32(&mut self, offset: usize) -> Result<u32, Error> {
        if offset & 3 != 0 {
            return Err(Error::Access);
        }
        let ptr = self.gpio.address(offset, 4).map_err(|_| Error::Mapping)?;
        if ptr.as_ptr() as usize & 3 != 0 {
            return Err(Error::Mapping);
        }
        // SAFETY: checked live original UC mapping, aligned bounded word.
        Ok(u32::from_le(unsafe {
            ptr.as_ptr().cast::<u32>().read_volatile()
        }))
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        if offset & 3 != 0 {
            return Err(Error::Access);
        }
        let ptr = self.gpio.address(offset, 4).map_err(|_| Error::Mapping)?;
        if ptr.as_ptr() as usize & 3 != 0 {
            return Err(Error::Mapping);
        }
        // SAFETY: checked live original UC mapping; driver serializes writes.
        unsafe { ptr.as_ptr().cast::<u32>().write_volatile(value.to_le()) };
        Ok(())
    }
    fn read_mux(&mut self, pad: u8) -> Result<u8, Error> {
        let mapping = self.mux.as_ref().ok_or(Error::MissingMux)?;
        let ptr = mapping
            .address(usize::from(pad), 1)
            .map_err(|_| Error::Mapping)?;
        // SAFETY: checked bounded live original UC byte window.
        Ok(unsafe { ptr.as_ptr().read_volatile() })
    }
    fn write_mux(&mut self, pad: u8, value: u8) -> Result<(), Error> {
        let mapping = self.mux.as_ref().ok_or(Error::MissingMux)?;
        let ptr = mapping
            .address(usize::from(pad), 1)
            .map_err(|_| Error::Mapping)?;
        // SAFETY: checked bounded live original UC byte window, serialized.
        unsafe { ptr.as_ptr().write_volatile(value) };
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Error> {
        // This sealed transport is only retired by Controller after its final
        // acknowledged control restoration. A failed/Busy unmap retains the
        // actual reservation; progress is monotonic for retry after one window
        // has already retired. No numeric address authorizes an unmap.
        if !self.gpio_retired {
            // SAFETY: serialized GPIO users stopped; UC writes read back; no
            // DMA, registered callbacks or cached raw pointers exist here.
            unsafe { self.gpio.retire() }.map_err(|_| Error::Mapping)?;
            self.gpio_retired = true;
        }
        if !self.mux_retired {
            if let Some(mux) = self.mux.as_mut() {
                // SAFETY: same stopped consumers and final byte readbacks.
                unsafe { mux.retire() }.map_err(|_| Error::Mapping)?;
            }
            self.mux_retired = true;
        }
        Ok(())
    }
}
