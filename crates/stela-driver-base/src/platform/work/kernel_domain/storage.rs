//! Domain-local storage observations; a CPU address is never native authority.
use super::{Domain, NativeDomain};
use crate::bus::dma::memory::{MemoryError, PinnedPages};
use core::{marker::PhantomData, ptr::NonNull};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageShape {
    pub bytes: usize,
    pub alignment: usize,
    pub page_shift: u8,
}
/// A checked nonempty CPU span kept by the actual borrowed allocation/view.
/// No Rust payload slice or native physical/cache/root/DMA permission is given.
pub struct CpuSpan<'storage, D: Domain> {
    address: NonNull<u8>,
    bytes: usize,
    _storage: PhantomData<&'storage D>,
}
impl<D: Domain> CpuSpan<'_, D> {
    pub fn address(&self) -> NonNull<u8> {
        self.address
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}
/// Sealed borrowed storage. There is no raw/label constructor, From/Deref or
/// generic extractor yielding PinnedPages, CpuMapping or a physical-address list.
pub struct StorageView<'storage, D: Domain> {
    inner: D::Storage<'storage>,
    _domain: PhantomData<&'storage D>,
}
impl<D: Domain> StorageView<'_, D> {
    pub fn shape(&self) -> StorageShape {
        D::shape(&self.inner)
    }
    pub fn cpu_span(&self, offset: usize, bytes: usize) -> Result<CpuSpan<'_, D>, MemoryError> {
        check_range(self.shape().bytes, offset, bytes)?;
        let address = D::span(&self.inner, offset, bytes)?;
        Ok(CpuSpan {
            address,
            bytes,
            _storage: PhantomData,
        })
    }
}
impl<'storage> StorageView<'storage, NativeDomain> {
    /// Borrow only the existing actual native pin. No mapping is invented.
    pub fn borrow(pages: &'storage PinnedPages) -> Self {
        Self {
            inner: pages,
            _domain: PhantomData,
        }
    }
    /// Native-only projection of its original real-RAM input. This method does
    /// not exist for HostedDomain or for a generic domain caller.
    pub fn native_pin(&self) -> &'storage PinnedPages {
        self.inner
    }
}
pub(super) fn check_range(total: usize, offset: usize, bytes: usize) -> Result<(), MemoryError> {
    if bytes == 0 || offset.checked_add(bytes).is_none_or(|end| end > total) {
        Err(MemoryError::InvalidSize)
    } else {
        Ok(())
    }
}
