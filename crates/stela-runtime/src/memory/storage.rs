//! Retained native mapping lifetime, independent of logical guest views.
//!
//! These owners expose raw descriptors only. Retaining storage does not pin its
//! current host rights, admit concurrent execution, or register memory writers.

use std::fs::File;
use std::ptr::NonNull;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StorageKind {
    Anonymous,
    PrivateFile,
    PublishedAliases,
}

/// One complete native mapping with one exclusive unmap obligation.
#[derive(Debug)]
pub(super) struct NativeMapping {
    base: NonNull<u8>,
    bytes: usize,
}

impl NativeMapping {
    /// Transfer an existing native mapping's unmap obligation into this owner.
    ///
    /// # Safety
    /// `base..base+bytes` must be a nonempty, complete, page-aligned live native
    /// mapping, with checked extent arithmetic and sole unmap authority. The
    /// storage is coherent Normal-WB RAM, never device/MMIO memory. No Rust byte
    /// references may escape. Raw accesses and host protection changes require
    /// external synchronization; all accesses must finish before rights are
    /// revoked, pages remapped, or the last owner released. File mappings retain
    /// their separate source-stability contract. Adoption itself changes no rights.
    pub(super) unsafe fn adopt(base: NonNull<u8>, bytes: usize) -> Self {
        Self { base, bytes }
    }
}

// SAFETY: this owner only retains an immutable raw mapping descriptor and its
// unmap obligation. It provides no safe byte access/protection/remap operation;
// adoption requires stable storage and externally synchronized raw accesses.
unsafe impl Send for NativeMapping {}
// SAFETY: sharing the descriptor lends no Rust byte references or mutation
// authority. The mapping remains live until the final retained owner is dropped.
unsafe impl Sync for NativeMapping {}

impl Drop for NativeMapping {
    fn drop(&mut self) {
        // SAFETY: adoption transferred the sole obligation for this exact extent.
        unsafe { libc::munmap(self.base.as_ptr().cast(), self.bytes) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StorageError {
    AliasExtentMismatch,
    AliasesOverlap,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "retained native storage failed: {self:?}")
    }
}
impl std::error::Error for StorageError {}

/// One physical storage lifetime, optionally retaining its two native aliases.
/// A canonical `MemoryBacking` retains this owner; this owner must never retain
/// that backing, which would create a strong-reference cycle.
pub(super) struct NativeStorage {
    primary: NativeMapping,
    publisher: Option<NativeMapping>,
    _file: Option<File>,
    kind: StorageKind,
}

impl std::fmt::Debug for NativeStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    pub(super) fn initialized_ram(
        initial: &[u8],
        leading: usize,
        bytes: usize,
        readable: bool,
        writable: bool,
    ) -> std::io::Result<Arc<Self>> {
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
                std::ptr::null_mut(),
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
        // SAFETY: mmap returned this complete checked page-aligned extent. The
        // mapping owner now owns its sole unmap obligation on every error path.
        let mapping = unsafe { NativeMapping::adopt(base, bytes) };
        // SAFETY: validated destination extent, private mapping and independent
        // input bytes; no native access or source binding has been published.
        unsafe {
            std::ptr::copy_nonoverlapping(
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

    pub(super) fn anonymous(primary: NativeMapping) -> Arc<Self> {
        Arc::new(Self {
            primary,
            publisher: None,
            _file: None,
            kind: StorageKind::Anonymous,
        })
    }

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
#[path = "storage/tests.rs"]
mod tests;
