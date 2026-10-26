//! Distinct CPU and device views for xHCI-owned storage.
//!
//! The boot allocator remains an explicitly separate lifetime. Native storage
//! retains the original domain and pins; no IOVA is interpreted as a pointer.
use super::*;
use crate::bus::dma::{
    DmaValue,
    mapping::{Direction, DmaDomain},
    memory::{CacheAttribute, PageSource},
    region::{self, DmaRegion},
};
use alloc::sync::Arc;
use core::{any::Any, cell::Cell, ops::Range};

pub(super) struct Native {
    pub(super) pages: Arc<dyn PageSource>,
    pub(super) domain: Arc<dyn DmaDomain>,
    // The real requester/configuration/UC/IRQ owner, independent of RAM pins.
    pub(super) _owner: Rc<dyn Any>,
    register_failure: Rc<Cell<Option<usize>>>,
    failure: RefCell<Option<region::Error>>,
}

impl Native {
    pub(super) fn new(
        pages: Arc<dyn PageSource>,
        domain: Arc<dyn DmaDomain>,
        owner: Rc<dyn Any>,
        register_failure: Rc<Cell<Option<usize>>>,
    ) -> Self {
        Self {
            pages,
            domain,
            _owner: owner,
            register_failure,
            failure: RefCell::new(None),
        }
    }

    fn result<T>(&self, result: Result<T, region::Error>) -> Result<T, BlockError> {
        result.map_err(|error| {
            self.failure.borrow_mut().get_or_insert(error);
            BlockError::Unsupported("xHCI original DMA mapping or visibility failed")
        })
    }

    pub(super) fn ready(&self) -> Result<(), BlockError> {
        if self.register_failure.get().is_some() {
            return Err(BlockError::Unsupported(
                "xHCI original register mapping is uncertain",
            ));
        }
        if self.failure.borrow().is_some() {
            Err(BlockError::Unsupported(
                "xHCI original DMA owner is uncertain",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn error(&self) -> Option<region::Error> {
        *self.failure.borrow()
    }

    pub(super) fn allocate(
        self: &Rc<Self>,
        bytes: usize,
        align: usize,
        limit: u64,
    ) -> Result<Buffer, BlockError> {
        self.ready()?;
        let region = self.result(DmaRegion::allocate(
            &*self.pages,
            self.domain.clone(),
            bytes,
            align,
            CacheAttribute::WriteBack,
            Direction::Bidirectional,
            limit,
        ))?;
        let pointer = self.result(region.cpu_address(0, bytes))?;
        // SAFETY: the native attachment grants exclusive fresh RAM ownership.
        // Mapping does not itself zero pages. No device pointer is published.
        unsafe {
            pointer.as_ptr().write_bytes(0, bytes);
        }
        Ok(Buffer {
            backing: Backing::Native(Box::new(region), self.clone()),
            dirty: Cell::new(true),
        })
    }
}

enum Backing {
    Boot(DmaBuffer),
    Native(Box<DmaRegion>, Rc<Native>),
}

pub(super) struct Buffer {
    backing: Backing,
    dirty: Cell<bool>,
}

impl From<DmaBuffer> for Buffer {
    fn from(buffer: DmaBuffer) -> Self {
        Self {
            backing: Backing::Boot(buffer),
            dirty: Cell::new(false),
        }
    }
}

impl Buffer {
    pub(super) fn len(&self) -> usize {
        match &self.backing {
            Backing::Boot(b) => b.len(),
            Backing::Native(b, _) => b.bytes(),
        }
    }

    pub(super) fn device_address(&self) -> u64 {
        match &self.backing {
            Backing::Boot(b) => b.physical(),
            Backing::Native(b, _) => b
                .device_address(0, b.bytes())
                .expect("live private xHCI mapping"),
        }
    }

    // Legacy test peers use their model address as the CPU/physical label.
    #[cfg(test)]
    pub(super) fn physical(&self) -> u64 {
        self.device_address()
    }

    pub(super) fn as_ptr(&self) -> *mut u8 {
        match &self.backing {
            Backing::Boot(b) => b.as_ptr(),
            Backing::Native(b, _) => b
                .cpu_address(0, b.bytes())
                .expect("retained CPU pin")
                .as_ptr(),
        }
    }

    pub(super) fn bytes(&self) -> &[u8] {
        // SAFETY: private users must establish completed CPU ownership before
        // borrowing. This never uses the device address as a CPU address.
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.len()) }
    }

    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        self.dirty.set(true);
        // SAFETY: private users hold exclusive stopped/unpublished CPU storage.
        unsafe { core::slice::from_raw_parts_mut(self.as_ptr(), self.len()) }
    }

    fn word<T: DmaValue>(&self, at: usize) -> *mut T {
        assert!(at <= self.len() && size_of::<T>() <= self.len() - at);
        // SAFETY: checked complete range into the actual CPU mapping.
        let pointer = unsafe { self.as_ptr().add(at) }.cast::<T>();
        assert!((pointer as usize).is_multiple_of(align_of::<T>()));
        pointer
    }

    pub(super) fn read<T: DmaValue>(&self, at: usize) -> T {
        // SAFETY: checked CPU word; callers supply ownership, not a timeout.
        unsafe { self.word::<T>(at).read_volatile() }
    }

    pub(super) fn write<T: DmaValue>(&mut self, at: usize, value: T) {
        // SAFETY: checked exclusive software-owned CPU word.
        unsafe {
            self.word::<T>(at).write_volatile(value);
        }
        self.dirty.set(true);
    }

    pub(super) fn coherent_u32(&self, at: usize) -> Result<u32, BlockError> {
        match &self.backing {
            Backing::Boot(_) => Ok(self.read(at)),
            Backing::Native(b, owner) => owner.result(b.read_coherent_u32(at)),
        }
    }

    pub(super) fn sync_device(&self, range: Range<usize>) -> Result<(), BlockError> {
        match &self.backing {
            Backing::Boot(_) => Ok(()),
            Backing::Native(b, owner) => owner.result(b.sync_for_device(range)),
        }
    }

    pub(super) fn sync_dirty(&self) -> Result<(), BlockError> {
        if self.dirty.get() {
            self.sync_device(0..self.len())?;
            self.dirty.set(false);
        }
        Ok(())
    }

    /// Actual completion establishes CPU ownership of this exact range.
    pub(super) unsafe fn sync_cpu(&self, range: Range<usize>) -> Result<(), BlockError> {
        match &self.backing {
            Backing::Boot(_) => Ok(()),
            // SAFETY: caller supplies original hardware completion.
            Backing::Native(b, owner) => owner.result(unsafe { b.sync_for_cpu(range) }),
        }
    }
}

#[cfg(test)]
mod tests;
