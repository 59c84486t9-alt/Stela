// SPDX-License-Identifier: GPL-2.0-only
//! The MSI-X table and pending-bit array windows of one BAR, as views of the
//! driver's own uncached mappings of that BAR.
use super::*;
use crate::bus::mmio::owned::{CacheAttribute, Mapping, MappingView, Protection};

/// Views of at most two disjoint UC mappings inside one whole BAR resource.
/// A driver maps its BAR once for its registers and hands the same mapping
/// here, since owned mappings of one resource may not overlap; two windows
/// allow a small table/PBA without mapping a huge device aperture.
pub struct MappedBar {
    bar: PhysicalSpan,
    windows: [Option<(PhysicalSpan, MappingView)>; 2],
}
impl MappedBar {
    /// # Safety
    /// `bar` is this function's complete reserved memory BAR at the
    /// reset/assignment epoch. `mappings` are owned mappings of its table/PBA
    /// registers with PCI DWORD access and UC ordering checked for this device,
    /// and their owner keeps them installed for as long as this value is used.
    /// No firmware/driver/CPU alias may mutate or revoke the table/resources.
    pub unsafe fn new(bar: PhysicalSpan, mappings: [Option<&Mapping>; 2]) -> Result<Self, Error> {
        let mut windows = [None, None];
        for (window, mapping) in windows.iter_mut().zip(mappings) {
            let Some(mapping) = mapping else { continue };
            let span = mapping.physical_span().map_err(|_| Error::Mapping)?;
            if mapping.attribute().map_err(|_| Error::Mapping)? != CacheAttribute::Uncached
                || mapping.protection().map_err(|_| Error::Mapping)? != Protection::ReadWrite
                || span.start() < bar.start()
                || span.end() > bar.end()
            {
                return Err(Error::Mapping);
            }
            let view = mapping.view(0..mapping.bytes().map_err(|_| Error::Mapping)?);
            *window = Some((span, view.map_err(|_| Error::Mapping)?));
        }
        match &windows {
            [None, None] => Err(Error::Mapping),
            [Some((a, _)), Some((b, _))] if a.start() < b.end() && b.start() < a.end() => {
                Err(Error::Mapping)
            }
            _ => Ok(Self { bar, windows }),
        }
    }
    /// The view and offset in it of the DWORD at BAR `offset`.
    fn window(&self, offset: u64) -> Result<(&MappingView, usize), IoError> {
        if !offset.is_multiple_of(4) {
            return Err(IoError);
        }
        let physical = self.bar.start().checked_add(offset).ok_or(IoError)?;
        let end = physical.checked_add(4).ok_or(IoError)?;
        self.windows
            .iter()
            .flatten()
            .find(|(span, _)| span.start() <= physical && end <= span.end())
            .map(|(span, view)| (view, (physical - span.start()) as usize))
            .ok_or(IoError)
    }
}
// SAFETY: unsafe construction binds kept resources/UC mappings; checked views
// and native volatile DWORDs implement the access contract.
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
        self.windows
            .iter()
            .flatten()
            .any(|(span, _)| span.start() <= start && end <= span.end())
    }
    fn read32(&self, offset: u64) -> Result<u32, IoError> {
        let (view, local) = self.window(offset)?;
        view.read32(local).map_err(|_| IoError)
    }
    fn write32(&mut self, offset: u64, value: u32) -> Result<(), IoError> {
        let (view, local) = self.window(offset)?;
        view.write32(local, value).map_err(|_| IoError)
    }
}
