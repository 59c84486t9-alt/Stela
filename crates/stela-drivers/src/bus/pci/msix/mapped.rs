// SPDX-License-Identifier: GPL-2.0-only
//! Uncached mappings of the MSI-X table and pending-bit array windows of one BAR.
use super::*;
use crate::bus::mmio::owned::{CacheAttribute, Mapping, Protection};
use core::ptr::NonNull;

/// Actual UC mappings of at most two disjoint windows of one whole BAR resource.
/// The windows allow a small table/PBA without mapping a huge device aperture.
pub struct MappedBar {
    bar: PhysicalSpan,
    mappings: [Option<Mapping>; 2],
}
impl MappedBar {
    /// # Safety
    /// `bar` is this actual function's complete reserved memory BAR at the
    /// retained reset/assignment epoch. Mappings are actual owned mappings of
    /// its table/PBA registers with PCI DWORD access and UC ordering qualified
    /// for this device. Their resource owner must retain that full BAR grant.
    /// No firmware/driver/CPU alias may mutate or revoke the table/resources.
    /// Errors return the exact mappings; no device access is performed here.
    pub unsafe fn new(
        bar: PhysicalSpan,
        mappings: [Option<Mapping>; 2],
    ) -> Result<Self, (Error, [Option<Mapping>; 2])> {
        let valid = (|| {
            let mut seen = None;
            for mapping in mappings.iter().flatten() {
                let span = mapping.physical_span().map_err(|_| Error::Mapping)?;
                if mapping.attribute().map_err(|_| Error::Mapping)? != CacheAttribute::Uncached
                    || mapping.protection().map_err(|_| Error::Mapping)? != Protection::ReadWrite
                    || span.start() < bar.start()
                    || span.end() > bar.end()
                    || seen.is_some_and(|old: PhysicalSpan| {
                        old.start() < span.end() && span.start() < old.end()
                    })
                {
                    return Err(Error::Mapping);
                }
                seen = Some(span);
            }
            if seen.is_none() {
                return Err(Error::Mapping);
            }
            Ok(())
        })();
        match valid {
            Ok(()) => Ok(Self { bar, mappings }),
            Err(error) => Err((error, mappings)),
        }
    }
    fn pointer(&self, offset: u64) -> Result<NonNull<u32>, IoError> {
        if !offset.is_multiple_of(4) {
            return Err(IoError);
        }
        let physical = self.bar.start().checked_add(offset).ok_or(IoError)?;
        let end = physical.checked_add(4).ok_or(IoError)?;
        for mapping in self.mappings.iter().flatten() {
            let span = mapping.physical_span().map_err(|_| IoError)?;
            if span.start() <= physical && end <= span.end() {
                let local = usize::try_from(physical - span.start()).map_err(|_| IoError)?;
                let pointer = mapping.address(local, 4).map_err(|_| IoError)?;
                if !(pointer.as_ptr() as usize).is_multiple_of(4) {
                    return Err(IoError);
                }
                return Ok(pointer.cast());
            }
        }
        Err(IoError)
    }
    /// Returned mappings still require actual acknowledged retirement, after all
    /// native source/callback/CPU users have drained; this does not retire them.
    pub fn into_mappings(self) -> [Option<Mapping>; 2] {
        self.mappings
    }
}
// SAFETY: unsafe construction binds actual retained resources/UC mappings;
// checked pointers and native volatile DWORDs implement the access contract.
unsafe impl BarAccess for MappedBar {
    fn physical_span(&self) -> PhysicalSpan {
        self.bar
    }
    fn accessible(&self, offset: u64, bytes: u64) -> bool {
        let Some(start) = self.bar.start().checked_add(offset) else {
            return false;
        };
        let Some(end) = start.checked_add(bytes) else {
            return false;
        };
        self.mappings.iter().flatten().any(|m| {
            m.physical_span()
                .is_ok_and(|span| span.start() <= start && end <= span.end())
        })
    }
    fn read32(&self, offset: u64) -> Result<u32, IoError> {
        let pointer = self.pointer(offset)?;
        // SAFETY: pointer validates actual retained aligned UC register mapping.
        Ok(unsafe { core::ptr::read_volatile(pointer.as_ptr()) })
    }
    fn write32(&mut self, offset: u64, value: u32) -> Result<(), IoError> {
        let pointer = self.pointer(offset)?;
        // SAFETY: same checked owned mapping, native DWORD store effect.
        unsafe { core::ptr::write_volatile(pointer.as_ptr(), value) };
        Ok(())
    }
}
