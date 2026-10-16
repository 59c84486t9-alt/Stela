//! Lifetime of native mappings, independent of guest views.

use alloc::sync::Arc;
use core::ptr::NonNull;
#[cfg(feature = "std")]
use std::fs::File;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StorageKind {
    Anonymous,
    #[cfg(feature = "std")]
    PrivateFile,
    PublishedAliases,
}

/// One complete native mapping with one exclusive unmap obligation.
#[derive(Debug)]
pub(super) struct NativeMapping {
    #[cfg(not(feature = "std"))]
    _boot: crate::execution::boot_frames::BootRam,
    base: NonNull<u8>,
    bytes: usize,
}

impl NativeMapping {
    /// Take over the unmap obligation of an existing native mapping.
    ///
    /// # Safety
    /// `base..base+bytes` must be a non-empty, whole, page-aligned live mapping
    /// whose unmap obligation the caller owns. The storage is coherent
    /// write-back RAM, never device memory or MMIO. No Rust reference to its
    /// bytes may escape. Raw accesses and protection changes need external
    /// synchronization, and every access must finish before rights are revoked,
    /// pages are remapped or the last owner is released. File mappings
    /// additionally require stable files. Adoption changes no rights.
    #[cfg(feature = "std")]
    pub(super) unsafe fn adopt(base: NonNull<u8>, bytes: usize) -> Self {
        Self { base, bytes }
    }
}

// SAFETY: this owner only retains an immutable raw mapping descriptor and its
// unmap obligation. It provides no safe byte access/protection/remap operation;
// adoption requires stable storage and externally synchronized raw accesses.
unsafe impl Send for NativeMapping {}
// SAFETY: sharing the descriptor hands out no references or mutation rights;
// the mapping lives until the last owner drops.
unsafe impl Sync for NativeMapping {}

#[cfg(feature = "std")]
impl Drop for NativeMapping {
    fn drop(&mut self) {
        // SAFETY: adoption transferred the unmap obligation for this exact
        // extent.
        unsafe { libc::munmap(self.base.as_ptr().cast(), self.bytes) };
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StorageError {
    AliasExtentMismatch,
    AliasesOverlap,
}

#[cfg(feature = "std")]
impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "retained native storage failed: {self:?}")
    }
}
#[cfg(feature = "std")]
impl core::error::Error for StorageError {}

/// One physical storage lifetime, optionally with its two native aliases. A
/// `MemoryBacking` holds this owner; this owner must never hold the backing,
/// which would form a reference cycle.
pub(super) struct NativeStorage {
    primary: NativeMapping,
    publisher: Option<NativeMapping>,
    #[cfg(feature = "std")]
    _file: Option<File>,
    kind: StorageKind,
}

impl core::fmt::Debug for NativeStorage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeStorage")
            .field("primary", &self.primary_base())
            .field("publisher", &self.publisher_base())
            .field("bytes", &self.bytes())
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl NativeStorage {
    /// Initialize private loader RAM before publishing any backing/view. Final
    /// host permissions never include Execute; guest source fetch uses Read.
    #[cfg(feature = "std")]
    pub(super) fn initialized_ram(
        initial: &[u8],
        leading: usize,
        bytes: usize,
        readable: bool,
        writable: bool,
    ) -> Result<Arc<Self>, crate::platform::memory::Error> {
        let page =
            super::host_page_size().map_err(|error| std::io::Error::other(error.to_string()))?;
        if initial.is_empty()
            || bytes == 0
            || !bytes.is_multiple_of(page)
            || bytes > isize::MAX as usize
            || leading
                .checked_add(initial.len())
                .is_none_or(|end| end > bytes)
            || writable && !readable
        {
            return Err(std::io::Error::other(
                "invalid private source RAM allocation",
            ));
        }
        // SAFETY: OS-selected fresh private anonymous storage, never MAP_FIXED
        // or an alias. No reference into this allocation escapes initialization.
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let Some(base) = NonNull::new(raw.cast::<u8>()) else {
            // SAFETY: mmap succeeded at zero; NonNull cannot represent its owner.
            unsafe { libc::munmap(raw, bytes) };
            return Err(std::io::Error::other("source RAM allocation has null base"));
        };
        // SAFETY: mmap returned this whole page-aligned extent, and the mapping
        // owner now unmaps it on every error path.
        let mapping = unsafe { NativeMapping::adopt(base, bytes) };
        // SAFETY: validated destination extent, private mapping and independent
        // input bytes; no native access or source binding has been published.
        unsafe {
            core::ptr::copy_nonoverlapping(
                initial.as_ptr(),
                base.as_ptr().add(leading),
                initial.len(),
            )
        };
        let protection = if readable {
            libc::PROT_READ
        } else {
            libc::PROT_NONE
        } | if writable { libc::PROT_WRITE } else { 0 };
        // SAFETY: factory exclusively owns the complete allocation. Final host
        // RO is established before immutable-code or physical binding publication.
        if unsafe { libc::mprotect(base.as_ptr().cast(), bytes, protection) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self::anonymous(mapping))
    }

    #[cfg(not(feature = "std"))]
    pub(super) fn initialized_ram(
        initial: &[u8],
        leading: usize,
        bytes: usize,
        readable: bool,
        writable: bool,
    ) -> Result<Arc<Self>, crate::platform::memory::Error> {
        let owner = crate::platform::boot::ram(initial, leading, bytes, readable, writable)?;
        owner.revalidate().map_err(|error| {
            crate::platform::memory::Error::Boot(crate::platform::boot::MountError::Storage(error))
        })?;
        let mapping = NativeMapping {
            base: owner.base(),
            bytes: owner.bytes(),
            _boot: owner,
        };
        Ok(Self::anonymous(mapping))
    }

    pub(super) fn anonymous(primary: NativeMapping) -> Arc<Self> {
        Arc::new(Self {
            primary,
            publisher: None,
            #[cfg(feature = "std")]
            _file: None,
            kind: StorageKind::Anonymous,
        })
    }

    #[cfg(feature = "std")]
    pub(super) fn private_file(primary: NativeMapping, file: File) -> Arc<Self> {
        Arc::new(Self {
            primary,
            publisher: None,
            _file: Some(file),
            kind: StorageKind::PrivateFile,
        })
    }

    /// Retain equal-sized guest/publisher aliases of the same private backing.
    ///
    /// # Safety
    /// If the checked lengths match and native ranges do not overlap, both
    /// mappings must alias the same complete physical byte extent of `file`,
    /// at the same offset. The file is private: no external writable
    /// descriptor or mapping can modify/truncate it. Address/length checks alone
    /// cannot establish physical alias identity. The guest alias stays read-only;
    /// publisher mutation obeys the enclosing serialized writer contract.
    #[cfg(feature = "std")]
    pub(super) unsafe fn published_aliases(
        primary: NativeMapping,
        publisher: NativeMapping,
        file: File,
    ) -> Result<Arc<Self>, StorageError> {
        if primary.bytes != publisher.bytes {
            return Err(StorageError::AliasExtentMismatch);
        }
        let primary_start = primary.base.as_ptr() as usize;
        let publisher_start = publisher.base.as_ptr() as usize;
        // Adoption guarantees checked native range arithmetic.
        if primary_start < publisher_start + publisher.bytes
            && publisher_start < primary_start + primary.bytes
        {
            return Err(StorageError::AliasesOverlap);
        }
        Ok(Arc::new(Self {
            primary,
            publisher: Some(publisher),
            _file: Some(file),
            kind: StorageKind::PublishedAliases,
        }))
    }

    pub(super) fn primary_base(&self) -> NonNull<u8> {
        self.primary.base
    }

    pub(super) fn publisher_base(&self) -> Option<NonNull<u8>> {
        self.publisher.as_ref().map(|mapping| mapping.base)
    }

    pub(super) fn bytes(&self) -> usize {
        self.primary.bytes
    }

    pub(super) fn kind(&self) -> StorageKind {
        self.kind
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests;
