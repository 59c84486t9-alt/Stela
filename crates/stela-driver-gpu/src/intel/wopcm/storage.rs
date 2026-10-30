//! Pinned system-RAM backing after native WOPCM preparation.
//! This copies the complete selected image, as xe_managed_bo_create_from_data
//! does, but supplies neither a Linux BO nor GGTT binding, upload or authentication.
use super::Preparation;
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping},
    memory::{CacheAttribute, MemoryError, PageSource},
};
use alloc::sync::Arc;

const PAGE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Device(crate::intel::activation::Error),
    Memory(MemoryError),
    Dma(DmaError),
    InvalidAllocation,
    InvalidDevice,
}
impl From<MemoryError> for Error {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}
impl From<DmaError> for Error {
    fn from(value: DmaError) -> Self {
        Self::Dma(value)
    }
}

struct Backing {
    // The canonical mapping itself keeps the exact page pin/CPU mapping
    // through failed invalidation. No second pin or public CPU writer is needed.
    mapping: DmaMapping,
}
impl Backing {
    fn allocate(
        bytes: &[u8],
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        address_limit: u64,
    ) -> Result<Self, Error> {
        let rounded = bytes
            .len()
            .checked_add(PAGE_BYTES - 1)
            .map(|value| value & !(PAGE_BYTES - 1))
            .filter(|value| *value != 0)
            .ok_or(Error::InvalidAllocation)?;
        if !source.page_geometry()?.supports(12) {
            return Err(Error::InvalidAllocation);
        }
        let pages = source.allocate(rounded, PAGE_BYTES, CacheAttribute::WriteBack)?;
        if pages.logical_bytes() != rounded
            || pages.bytes() != rounded
            || pages.page_shift() != 12
            || pages.cache_attribute() != CacheAttribute::WriteBack
        {
            return Err(Error::InvalidAllocation);
        }
        let cpu = pages.cpu_mapping(CacheAttribute::WriteBack)?;
        let destination = cpu.address(0, bytes.len())?;
        // SAFETY: newly allocated exclusive native RAM is zeroed/pinned by the
        // PageSource. The immutable provider image cannot alias that new
        // allocation. The complete checked span has no device address or writer.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination.as_ptr(), bytes.len());
        }
        let mapping = DmaMapping::map(domain, pages, Direction::ToDevice, address_limit)?;
        Ok(Self { mapping })
    }
    fn publish(&self) -> Result<(), Error> {
        self.mapping.sync_for_device(0..self.mapping.bytes())?;
        Ok(())
    }
    /// # Safety
    /// Every device/GGTT/IRQ/submission reference has ended; no new
    /// access can begin. The domain's process/context restrictions still apply.
    unsafe fn retire(&mut self) -> Result<(), Error> {
        // SAFETY: caller keeps the same native preparation and establishes
        // complete quiescence, or has never exposed any IOVA through this API.
        unsafe { self.mapping.unmap()? };
        Ok(())
    }
}

/// Complete selected image in WB RAM and a private requester mapping.
/// No IOVA has escaped this API. Drop keeps an uncertain mapping through the
/// canonical DMA quarantine; explicit rollback can return the same preparation.
pub struct Unpublished<'device, 'provider> {
    preparation: Preparation<'device, 'provider>,
    backing: Backing,
}
impl<'device, 'provider> Preparation<'device, 'provider> {
    /// Preserve the WOPCM/device/provider ownership on every failure.
    /// The image includes the original CSS, microcode, RSA and trailing bytes;
    /// the rounded page tail stays zero. Neither IOVA nor GGTT address escapes.
    ///
    /// # Safety
    /// `domain` is the isolated requester domain of this SAME device,
    /// WOPCM/power/reset epoch and kept native owner, not another function
    /// with matching PCI IDs. Its ownership remains stable through retirement
    /// or canonical quarantine. Page/domain operations run in their real allowed
    /// CPU/process context. No other owner publishes these allocations/IOVAs or
    /// starts device/firmware accesses. The canonical domain has no checked
    /// device-identity query: a native producer must establish this
    /// relationship; caller booleans or numeric-address agreement cannot do so.
    #[allow(
        clippy::result_large_err,
        reason = "Failure must return the retained native owner without allocating or inventing rollback."
    )]
    pub unsafe fn pin_firmware(
        self,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        address_limit: u64,
    ) -> Result<Unpublished<'device, 'provider>, (Self, Error)> {
        if let Err(error) = self._device.gsm_check_context() {
            return Err((self, Error::Device(error)));
        }
        let limit = match self.facts().dma_bits {
            bits @ 1..=63 => address_limit.min((1u64 << bits) - 1),
            64 => address_limit,
            _ => return Err((self, Error::InvalidDevice)),
        };
        match Backing::allocate(self.image().bytes(), source, domain, limit) {
            Ok(backing) => Ok(Unpublished {
                preparation: self,
                backing,
            }),
            Err(error) => Err((self, error)),
        }
    }
}
impl<'device, 'provider> Unpublished<'device, 'provider> {
    pub fn preparation(&self) -> &Preparation<'device, 'provider> {
        &self.preparation
    }
    /// Cache/ordering visibility precedes publication of the IOVA.
    /// Failure keeps the same mapping/preparation for retry or rollback.
    #[allow(
        clippy::result_large_err,
        reason = "Failure must return the retained native owner without allocating or inventing rollback."
    )]
    pub fn publish(self) -> Result<Published<'device, 'provider>, (Self, Error)> {
        if let Err(error) = self.preparation._device.gsm_check_context() {
            return Err((self, Error::Device(error)));
        }
        match self.backing.publish() {
            Ok(()) => Ok(Published {
                preparation: Some(self.preparation),
                backing: Some(self.backing),
            }),
            Err(error) => Err((self, error)),
        }
    }
    /// Remove the never-published mapping, then return the same WOPCM
    /// preparation. Failed invalidation keeps every lease for a real retry.
    #[allow(
        clippy::result_large_err,
        reason = "Failure must return the retained native owner without allocating or inventing rollback."
    )]
    pub fn rollback(mut self) -> Result<Preparation<'device, 'provider>, (Self, Error)> {
        if let Err(error) = self.preparation._device.gsm_check_context() {
            return Err((self, Error::Device(error)));
        }
        // SAFETY: this type exposes neither the mapping nor any IOVA/GGTT.
        if let Err(error) = unsafe { self.backing.retire() } {
            return Err((self, error));
        }
        Ok(self.preparation)
    }
}

/// Published requester IOVA, never a GuC GGTT virtual address. A successor
/// bootstrap owner must install real GGTT mappings with completed invalidation
/// and carry this exact preparation through upload/authentication/retirement.
/// No firmware readiness or hardware-completion capability is manufactured.
pub struct Published<'device, 'provider> {
    preparation: Option<Preparation<'device, 'provider>>,
    backing: Option<Backing>,
}
impl<'device, 'provider> Published<'device, 'provider> {
    pub fn preparation(&self) -> &Preparation<'device, 'provider> {
        self.preparation
            .as_ref()
            .expect("live firmware preparation")
    }
    pub fn mapping(&self) -> &DmaMapping {
        &self
            .backing
            .as_ref()
            .expect("live firmware backing")
            .mapping
    }
    /// # Safety
    /// Original upload/authentication and every device access have completed;
    /// firmware/engines, submissions and IRQ/work users are stopped/drained,
    /// restoring the probe owner's no-DMA/no-firmware-access contract.
    /// The same WOPCM/power/reset epoch remains valid. Real GGTT mappings
    /// are removed with acknowledged GT invalidation, no future use can begin,
    /// and the device/domain context restrictions are satisfied.
    /// Errors keep the whole owner for retry. No reset/drain is synthesized.
    #[allow(
        clippy::result_large_err,
        reason = "Failure must return the retained native owner without allocating or inventing rollback."
    )]
    pub unsafe fn retire_after_quiescence(
        mut self,
    ) -> Result<Preparation<'device, 'provider>, (Self, Error)> {
        if let Err(error) = self.preparation()._device.gsm_check_context() {
            return Err((self, Error::Device(error)));
        }
        // SAFETY: caller establishes complete device/GGTT/user quiescence.
        if let Err(error) = unsafe { self.backing.as_mut().expect("live firmware").retire() } {
            return Err((self, error));
        }
        drop(self.backing.take());
        Ok(self.preparation.take().expect("retained preparation"))
    }
}
impl Drop for Published<'_, '_> {
    fn drop(&mut self) {
        if self.backing.is_some() {
            // An escaped IOVA cannot certify device/GGTT completion. Close the
            // same device epoch before its mutable borrow ends; Device
            // Drop keeps its native power/reset/MMIO owner. DmaMapping Drop
            // independently quarantines the requester mapping and pins.
            self.preparation
                .as_mut()
                .expect("retained preparation")
                ._device
                .gsm_poison();
        }
    }
}

#[cfg(test)]
mod tests;
