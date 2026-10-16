//! Read-only guest regions the runtime publishes through a private writable alias.
use super::binding::SharedBinding;
#[cfg(feature = "std")]
use super::page_rounded;
#[cfg(feature = "std")]
use super::storage::NativeMapping;
use super::storage::NativeStorage;
#[cfg(feature = "std")]
use super::{DIRECT_RAM_USER_END, host_page_size};
use super::{MemoryRegion, SharedBindingError, backing, domain};
use alloc::rc::Rc;
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use anyhow::{Context, bail};
use anyhow::{Result, ensure};
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::os::fd::AsRawFd;

/// Runtime-published data with a permanently read-only, non-executable guest
/// view and an unexposed writable alias. Publication and translated accesses
/// must be serialized by the caller; this is not a concurrent kernel seqlock.
pub struct PublishedReadOnlyRegion {
    pub(super) shared: Option<Arc<SharedBinding>>,
    pub(super) shared_backing: Option<Arc<backing::MemoryBacking>>,
    pub(super) region: MemoryRegion,
    pub(super) storage: Arc<NativeStorage>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl core::fmt::Debug for PublishedReadOnlyRegion {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PublishedReadOnlyRegion")
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl PublishedReadOnlyRegion {
    /// Create a private unlinked backing object; no external file descriptor,
    /// writable guest address or Rust reference into either mapping escapes.
    #[cfg(feature = "std")]
    pub fn map(guest_base: u64, initial: &[u8]) -> Result<Self> {
        use std::io::Write;
        ensure!(
            cfg!(all(
                target_arch = "x86_64",
                any(target_os = "linux", target_os = "macos")
            )),
            "published guest mappings require an x86-64 Linux or macOS host"
        );
        let page = host_page_size()? as u64;
        ensure!(
            !initial.is_empty() && initial.len() <= 65536,
            "published read-only region requires 1..65536 bytes"
        );
        let bytes = page_rounded(initial.len() as u64, page)?;
        ensure!(
            guest_base.is_multiple_of(page)
                && guest_base >= page
                && guest_base
                    .checked_add(bytes)
                    .is_some_and(|end| end <= DIRECT_RAM_USER_END),
            "published region requires an aligned lower-user guest range"
        );
        let mut backing = tempfile::tempfile()?;
        backing.set_len(bytes)?;
        backing.write_all(initial)?;
        // Reserve the guest view first so the kernel-chosen alias cannot take
        // the requested guest address. Neither call may replace host memory.
        let requested = guest_base as usize as *mut libc::c_void;
        let flags = libc::MAP_SHARED;
        #[cfg(target_os = "linux")]
        let flags = flags | libc::MAP_FIXED_NOREPLACE;
        // SAFETY: the live backing covers the extent; exact placement is checked.
        let guest = unsafe {
            libc::mmap(
                requested,
                bytes as usize,
                libc::PROT_READ,
                flags,
                backing.as_raw_fd(),
                0,
            )
        };
        if guest == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()).context("cannot map published guest view");
        }
        if guest != requested {
            // SAFETY: release only this newly substituted allocation.
            unsafe { libc::munmap(guest, bytes as usize) };
            bail!("published guest address {guest_base:#x} is unavailable");
        }
        // SAFETY: newly owned read-only pages with a checked extent; accesses
        // are serialized and no guest references escape.
        let guest_mapping = unsafe {
            NativeMapping::adopt(
                core::ptr::NonNull::new(guest.cast()).expect("nonzero exact mapping"),
                bytes as usize,
            )
        };
        // SAFETY: the kernel creates a new, separate mapping of the owned
        // backing.
        let publisher = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                bytes as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                backing.as_raw_fd(),
                0,
            )
        };
        if publisher == libc::MAP_FAILED {
            let error = std::io::Error::last_os_error();
            // The retained guest-mapping guard rolls back this failed pair.
            return Err(error).context("cannot map runtime publication alias");
        }
        let Some(publisher_mapping) = core::ptr::NonNull::new(publisher) else {
            // SAFETY: release only this newly created null publisher alias;
            // the retained guest guard rolls back the other mapping.
            unsafe { libc::munmap(publisher, bytes as usize) };
            bail!("null publication mapping is unsupported");
        };
        // SAFETY: the second complete mapping aliases this same private file at
        // the same offset; both aliases and the file now share one retained owner.
        let storage = unsafe {
            NativeStorage::published_aliases(
                guest_mapping,
                NativeMapping::adopt(publisher_mapping.cast(), bytes as usize),
                backing,
            )
        }?;
        Ok(Self {
            shared: None,
            shared_backing: None,
            region: MemoryRegion {
                guest_address: guest_base,
                virtual_bytes: initial.len() as u64,
                mapped_bytes: bytes,
                initial_bytes: initial.len(),
                readable: true,
                writable: false,
                executable: false,
            },
            storage,
            _not_send_sync: PhantomData,
        })
    }

    #[cfg(not(feature = "std"))]
    pub fn map(guest_base: u64, initial: &[u8]) -> Result<Self> {
        let _ = (guest_base, initial);
        anyhow::bail!("freestanding publication aliases are not mounted")
    }

    pub fn region(&self) -> &MemoryRegion {
        &self.region
    }

    pub(super) fn extent(&self, offset: usize, bytes: usize) -> Result<()> {
        ensure!(
            offset
                .checked_add(bytes)
                .is_some_and(|end| end <= self.region.virtual_bytes as usize),
            "published region access exceeds logical bytes"
        );
        Ok(())
    }

    pub fn read_snapshot(&self, offset: usize, bytes: usize) -> Result<Vec<u8>> {
        self.extent(offset, bytes)?;
        if let Some(shared) = &self.shared {
            return shared
                .domain
                .service_loan()
                .map_err(SharedBindingError::Domain)?
                .snapshot(self.region.guest_address + offset as u64, bytes)
                .map_err(SharedBindingError::Domain)
                .map_err(Into::into);
        }
        let mut result = vec![0; bytes];
        // SAFETY: a live read-only mapping, a bounded copy and a separate
        // destination; this owner is neither Send nor Sync, so publication
        // cannot run concurrently.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.region.guest_address as usize as *const u8).add(offset),
                result.as_mut_ptr(),
                bytes,
            )
        };
        Ok(result)
    }

    pub fn publish(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        self.extent(offset, bytes.len())?;
        if let Some(shared) = &self.shared {
            shared.check().map_err(|status| domain::PublicationFault {
                status,
                completed: 0,
            })?;
            shared.publish(
                self.shared_backing
                    .as_ref()
                    .expect("canonical publisher backing"),
                offset,
                bytes,
            )?;
            return Ok(());
        }
        // SAFETY: private live RW alias and fully checked extent. No guest code
        // may execute concurrently, and safe APIs expose no mapping references.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.storage
                    .publisher_base()
                    .expect("publication alias")
                    .as_ptr()
                    .add(offset),
                bytes.len(),
            )
        };
        Ok(())
    }
}
