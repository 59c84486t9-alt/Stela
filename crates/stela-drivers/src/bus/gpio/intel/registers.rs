// SPDX-License-Identifier: GPL-2.0
//! Actual retained UC mappings. MMIO alone never authorizes native pad access.
use super::Error;
use crate::bus::mmio::owned::{CacheAttribute, Mapping, Protection};
use alloc::vec::Vec;

pub(super) mod sealed {
    pub trait Sealed {}
}
pub trait RegisterIo: sealed::Sealed {
    fn bytes(&self, bar: u8) -> Result<usize, Error>;
    fn read32(&mut self, bar: u8, offset: usize) -> Result<u32, Error>;
    fn write32(&mut self, bar: u8, offset: usize, value: u32) -> Result<(), Error>;
    fn finish(&mut self) -> Result<(), Error>;
}

pub struct NativeRegisters {
    windows: Vec<(u8, Mapping, bool)>,
}
impl sealed::Sealed for NativeRegisters {}
impl NativeRegisters {
    #[allow(dead_code)] // Raw construction stays internal to native admission.
    pub(in crate::bus::gpio) fn from_owned_mappings(
        windows: Vec<(u8, Mapping)>,
    ) -> Result<Self, Error> {
        let mut result = Vec::new();
        result
            .try_reserve_exact(windows.len())
            .map_err(|_| Error::Allocation)?;
        for (bar, mapping) in windows {
            if result.iter().any(|(number, _, _)| *number == bar)
                || mapping.attribute().map_err(|_| Error::Mapping)? != CacheAttribute::Uncached
                || mapping.protection().map_err(|_| Error::Mapping)? != Protection::ReadWrite
            {
                return Err(Error::Mapping);
            }
            result.push((bar, mapping, false));
        }
        Ok(Self { windows: result })
    }
    fn mapping(&self, bar: u8) -> Result<&Mapping, Error> {
        self.windows
            .iter()
            .find_map(|(number, mapping, retired)| (*number == bar && !*retired).then_some(mapping))
            .ok_or(Error::Mapping)
    }
}
impl RegisterIo for NativeRegisters {
    fn bytes(&self, bar: u8) -> Result<usize, Error> {
        self.mapping(bar)?.bytes().map_err(|_| Error::Mapping)
    }
    fn read32(&mut self, bar: u8, offset: usize) -> Result<u32, Error> {
        let pointer = self
            .mapping(bar)?
            .address(offset, 4)
            .map_err(|_| Error::Mapping)?;
        if offset & 3 != 0 || pointer.as_ptr() as usize & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: original live bounded UC mapping and aligned four-byte word.
        Ok(u32::from_le(unsafe {
            pointer.as_ptr().cast::<u32>().read_volatile()
        }))
    }
    fn write32(&mut self, bar: u8, offset: usize, value: u32) -> Result<(), Error> {
        let pointer = self
            .mapping(bar)?
            .address(offset, 4)
            .map_err(|_| Error::Mapping)?;
        if offset & 3 != 0 || pointer.as_ptr() as usize & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: original live bounded UC mapping; controller serializes writes.
        unsafe { pointer.as_ptr().cast::<u32>().write_volatile(value.to_le()) };
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Error> {
        for (_, mapping, retired) in &mut self.windows {
            if !*retired {
                // SAFETY: private controller calls only after stopped consumers,
                // masked owned IRQs and final acknowledged pad restoration.
                unsafe { mapping.retire() }.map_err(|_| Error::Mapping)?;
                *retired = true;
            }
        }
        Ok(())
    }
}
