//! The mount's native page source over its heap, and the Linux page catalog
//! bound to it. The source itself is `stela_boot_core::native_memory`.
use core::ptr::NonNull;
use stela_boot_core::native_memory::{NativeMemory, PAGE};
use stela_drivers::bus::dma::memory::{CacheAttribute, MemoryError, PageSource, PinnedPages};

pub(crate) mod cache;

pub static SOURCE: NativeMemory = NativeMemory::new(&crate::ALLOCATOR, cache::verify_writeback);

/// Register the heap's CPU/physical mapping (`NativeMemory::initialize`).
///
/// # Safety
/// As `NativeMemory::initialize`, for the mount's heap.
pub unsafe fn initialize(cpu: usize, physical: u64, bytes: usize, table_offset: u64) {
    // SAFETY: the caller's contract.
    unsafe { SOURCE.initialize(cpu, physical, bytes, table_offset) }
}

/// Keeps one source generation registered while Linux descriptors can refer
/// to it. Registration does not import ordinary heap bytes as Linux pages.
pub struct LinuxPages {
    generation: u64,
}

impl Drop for LinuxPages {
    fn drop(&mut self) {
        SOURCE.release_catalog();
    }
}

// SAFETY: initialize registered the heap and its WB mapping. The catalog
// count prevents retargeting the generation; each allocation goes through the
// zeroed page source and keeps its backing until the last drop. Unsupported
// flags and contexts are refused before any heap or cache work.
unsafe impl stela_drivers::gpu::linux::pages::Provider for LinuxPages {
    fn validate(
        &self,
        request: stela_drivers::gpu::linux::pages::Request,
    ) -> Result<(), MemoryError> {
        if SOURCE.registration().generation != self.generation
            || request.atomic
            || !request.basic_ram()
            || !request.may_block()
        {
            return Err(MemoryError::Unavailable);
        }
        request.bytes().ok_or(MemoryError::InvalidSize)?;
        Ok(())
    }

    fn allocate(
        &self,
        request: stela_drivers::gpu::linux::pages::Request,
    ) -> Result<PinnedPages, MemoryError> {
        self.validate(request)?;
        let bytes = request.bytes().ok_or(MemoryError::InvalidSize)?;
        SOURCE.allocate(bytes, bytes, CacheAttribute::WriteBack)
    }
}

/// Bind the registered heap to Linux's native page service.
///
/// # Safety
/// Process or deferred-work context excludes migration, root and cache
/// writers and native IRQ reentry for registration, use and retirement. The
/// heap and its mapping stay registered through every pin and any quarantined
/// catalog; the caller retires the catalog before re-registering the heap.
pub unsafe fn linux_pages() -> Result<
    stela_drivers::gpu::linux::pages::Catalog<LinuxPages>,
    stela_drivers::gpu::linux::pages::Error,
> {
    // SAFETY: the caller's contract.
    let (provider, reservation) = unsafe { linux_page_source() }?;
    // SAFETY: the provider holds the catalog count for this generation.
    unsafe { stela_drivers::gpu::linux::pages::Catalog::register(provider, reservation) }
}

/// The heap generation and extent for one composed catalog. Returning the
/// reservation allocates nothing.
///
/// # Safety
/// As `linux_pages`.
pub(crate) unsafe fn linux_page_source() -> Result<
    (LinuxPages, stela_drivers::gpu::linux::pages::Reservation),
    stela_drivers::gpu::linux::pages::Error,
> {
    use stela_drivers::gpu::linux::pages::{Error, Reservation};
    let registration = SOURCE.registration();
    if registration.generation == 0 || registration.bytes == 0 {
        return Err(Error::InvalidReservation);
    }
    let cpu = NonNull::new(registration.cpu as *mut u8).ok_or(Error::InvalidReservation)?;
    // SAFETY: the registration records this mapping of the heap's RAM.
    let reservation =
        unsafe { Reservation::new(registration.physical, cpu, registration.bytes / PAGE)? };
    SOURCE.retain_catalog().map_err(|_| Error::OutOfMemory)?;
    let provider = LinuxPages {
        generation: registration.generation,
    };
    Ok((provider, reservation))
}

/// Check that a loader reservation is mapped write-back, with the decoder
/// native pages use. This allocates nothing and adds no alias.
///
/// # Safety
/// The reservation and its CPU mapping last for the boot; root, cache
/// controls and physical ownership do not change during the check.
pub(crate) unsafe fn qualify_reserved_writeback(
    cpu: u64,
    physical: u64,
    bytes: usize,
) -> Result<(), MemoryError> {
    cache::verify_writeback(cpu, physical, bytes, SOURCE.table_offset())
}

/// Exercise the registered mapping and allocator through the Linux page
/// catalog and the page source. Called by the mount's host check.
pub fn verify() -> Result<(), MemoryError> {
    // SAFETY: the host check runs in process context, with root and cache
    // writers excluded.
    let mut catalog = unsafe { linux_pages() }.map_err(|_| MemoryError::Unavailable)?;
    catalog.verify().map_err(|error| {
        crate::output::arguments(format_args!("CHECK Linux page catalog FAIL {error:?}\n"));
        MemoryError::InvalidPageList
    })?;
    catalog.try_retire().map_err(|_| MemoryError::Unavailable)?;
    SOURCE.verify()
}
