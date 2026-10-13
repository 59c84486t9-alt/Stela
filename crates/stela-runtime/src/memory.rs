//! Owned guest-address mappings for the direct-RAM native execution profile.
//!
//! Original Arm instructions are data to the x86 host: a guest executable
//! region never receives host execute permission. Mapping must succeed at the
//! requested address without replacing any existing allocation.

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::fs::File;
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::rc::Rc;

pub const MAX_IMAGE_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
/// File-backed research mappings have a separate virtual-space budget. Safe
/// snapshot/write operations retain the smaller MAX_IMAGE_MEMORY_BYTES bound.
pub const MAX_FILE_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
// The initial x86-64 profile uses the lower, 48-bit canonical address range.
const USER_ADDRESS_END: u64 = 1 << 47;

#[derive(Debug, Clone)]
pub struct MemoryRegionSpec {
    pub guest_address: u64,
    pub virtual_bytes: u64,
    pub initial_bytes: Vec<u8>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Exact-address private mapping of existing ordinary file bytes, without a
/// heap copy or implicit guest-visible BSS. The logical extent must fit the file;
/// host-page rounding may include the file's final partial page, whose padding
/// is never exposed through the safe guest-memory API.
///
/// OwnedMemory retains the file descriptor. MAP_PRIVATE prevents our writes
/// from modifying the file; it does not freeze unrelated writes/truncation to
/// that inode. Source identity, provenance and stability for the entire mapping
/// lifetime are the caller's responsibility. Truncation can cause native faults.
#[derive(Debug)]
pub struct FileMemoryRegionSpec {
    pub guest_address: u64,
    pub virtual_bytes: u64,
    pub file: File,
    pub file_offset: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

enum InitialMemory {
    Anonymous(Vec<u8>),
    File { file: File, offset: u64 },
}

struct MappingSpec {
    guest_address: u64,
    virtual_bytes: u64,
    readable: bool,
    writable: bool,
    executable: bool,
    initial: InitialMemory,
}

impl From<MemoryRegionSpec> for MappingSpec {
    fn from(spec: MemoryRegionSpec) -> Self {
        Self {
            guest_address: spec.guest_address,
            virtual_bytes: spec.virtual_bytes,
            readable: spec.readable,
            writable: spec.writable,
            executable: spec.executable,
            initial: InitialMemory::Anonymous(spec.initial_bytes),
        }
    }
}

impl From<FileMemoryRegionSpec> for MappingSpec {
    fn from(spec: FileMemoryRegionSpec) -> Self {
        Self {
            guest_address: spec.guest_address,
            virtual_bytes: spec.virtual_bytes,
            readable: spec.readable,
            writable: spec.writable,
            executable: spec.executable,
            initial: InitialMemory::File {
                file: spec.file,
                offset: spec.file_offset,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryRegion {
    pub guest_address: u64,
    /// Exact guest-visible extent. Allocation padding is not guest memory.
    pub virtual_bytes: u64,
    /// Host-page-rounded allocation owned by this region.
    pub mapped_bytes: u64,
    pub initial_bytes: usize,
    pub readable: bool,
    pub writable: bool,
    /// Guest instruction-fetch permission, never host execute permission.
    pub executable: bool,
}

impl MemoryRegion {
    fn end(&self) -> u64 {
        // Construction checks addition and the native address range.
        self.guest_address + self.virtual_bytes
    }
}

/// Private, non-shareable mappings, released together on failure or drop.
///
/// Safe operations copy bytes; they never lend Rust references into memory that
/// native guest code may mutate. Callers executing native code remain responsible
/// for its unsafe execution contract and must keep this owner alive throughout.
#[derive(Debug)]
pub struct OwnedMemory {
    regions: Vec<MemoryRegion>,
    backing_files: Vec<File>,
    _not_send_sync: PhantomData<Rc<()>>,
}

pub fn host_page_size() -> Result<usize> {
    // SAFETY: sysconf has no pointer arguments or mutable Rust state.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(page > 0, "cannot determine host page size");
    let page = usize::try_from(page)?;
    ensure!(page.is_power_of_two(), "unsupported host page size");
    Ok(page)
}

fn page_rounded(bytes: u64, page: u64) -> Result<u64> {
    Ok(bytes
        .checked_add(page - 1)
        .context("guest mapping size overflow")?
        & !(page - 1))
}

impl OwnedMemory {
    pub fn map(specs: Vec<MemoryRegionSpec>) -> Result<Self> {
        Self::map_specs(
            specs.into_iter().map(MappingSpec::from).collect(),
            MAX_IMAGE_MEMORY_BYTES,
        )
    }

    /// Map owned file-backed regions without copying their contents.
    ///
    /// # Safety
    /// Every backing inode's contents and length must remain unchanged for the
    /// complete lifetime of the returned owner, including during construction.
    /// This excludes writes/truncation through other descriptors or processes;
    /// private COW writes through this owner do not modify the backing inode.
    /// Retained File handles and pre/post hashes cannot enforce this condition.
    /// Changing a pathname to name another inode does not change the mapped one.
    pub unsafe fn map_files(specs: Vec<FileMemoryRegionSpec>) -> Result<Self> {
        Self::map_specs(
            specs.into_iter().map(MappingSpec::from).collect(),
            MAX_FILE_MEMORY_BYTES,
        )
    }

    fn map_specs(mut specs: Vec<MappingSpec>, limit: u64) -> Result<Self> {
        ensure!(
            cfg!(all(
                target_arch = "x86_64",
                any(target_os = "linux", target_os = "macos")
            )),
            "exact guest mappings require an x86-64 Linux or macOS host"
        );
        let page = host_page_size()? as u64;
        specs.sort_by_key(|spec| spec.guest_address);
        let mut total = 0u64;
        let mut previous_end = 0u64;
        // Validate the complete set before changing the process address space.
        for spec in &specs {
            ensure!(
                spec.guest_address >= page && spec.guest_address.is_multiple_of(page),
                "guest address must be nonzero and host-page aligned"
            );
            ensure!(
                spec.virtual_bytes > 0,
                "guest virtual size must be positive"
            );
            let mapped_bytes = page_rounded(spec.virtual_bytes, page)?;
            let end = spec
                .guest_address
                .checked_add(mapped_bytes)
                .context("guest mapping address overflow")?;
            ensure!(
                end <= USER_ADDRESS_END,
                "guest mapping exceeds canonical user range"
            );
            usize::try_from(end).context("guest mapping exceeds native address range")?;
            ensure!(spec.guest_address >= previous_end, "guest mappings overlap");
            match &spec.initial {
                InitialMemory::Anonymous(bytes) => ensure!(
                    bytes.len() as u64 <= spec.virtual_bytes,
                    "initial bytes exceed guest virtual size"
                ),
                InitialMemory::File { file, offset } => {
                    ensure!(
                        offset.is_multiple_of(page),
                        "file mapping offset must be host-page aligned"
                    );
                    libc::off_t::try_from(*offset)
                        .context("file mapping offset exceeds native range")?;
                    let metadata = file.metadata().context("cannot inspect backing file")?;
                    ensure!(metadata.is_file(), "file mapping requires an ordinary file");
                    let file_end = offset
                        .checked_add(spec.virtual_bytes)
                        .context("file mapping extent overflow")?;
                    ensure!(
                        file_end <= metadata.len(),
                        "file mapping exceeds backing file bytes"
                    );
                    // SAFETY: File owns a live descriptor; F_GETFL has no extra
                    // arguments and does not mutate file contents or position.
                    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
                    if flags == -1 {
                        return Err(std::io::Error::last_os_error())
                            .context("cannot inspect backing file access mode");
                    }
                    ensure!(
                        flags & libc::O_ACCMODE != libc::O_WRONLY,
                        "backing file descriptor is not readable"
                    );
                }
            }
            ensure!(
                !(spec.writable && spec.executable),
                "writable guest code is unsupported"
            );
            ensure!(
                !spec.writable || spec.readable,
                "write-only guest memory is unsupported by the x86-64 protection profile"
            );
            total = total
                .checked_add(mapped_bytes)
                .context("guest mapping size overflow")?;
            ensure!(total <= limit, "guest mappings exceed memory limit");
            previous_end = end;
        }

        let mut memory = Self {
            regions: Vec::new(),
            backing_files: Vec::new(),
            _not_send_sync: PhantomData,
        };
        for spec in specs {
            let mapped_bytes = page_rounded(spec.virtual_bytes, page)?;
            let length = mapped_bytes as usize;
            let requested = spec.guest_address as usize as *mut libc::c_void;
            let (source_flags, descriptor, file_offset, initial_bytes) = match &spec.initial {
                InitialMemory::Anonymous(bytes) => (libc::MAP_ANON, -1, 0, bytes.len()),
                InitialMemory::File { file, offset } => (
                    0,
                    file.as_raw_fd(),
                    libc::off_t::try_from(*offset)
                        .context("file mapping offset exceeds native range")?,
                    usize::try_from(spec.virtual_bytes)?,
                ),
            };
            let flags = libc::MAP_PRIVATE | source_flags;
            #[cfg(target_os = "linux")]
            // Linux >=4.17 refuses occupied addresses atomically. Older
            // kernels may ignore this flag; the exact-address check below
            // also handles that case without ever using MAP_FIXED.
            let flags = flags | libc::MAP_FIXED_NOREPLACE;
            // SAFETY: private allocation with no host mapping replacement and
            // validated size/source extent. File descriptors remain owned and
            // live. The returned pointer is checked before any byte access.
            let mapped = unsafe {
                libc::mmap(
                    requested,
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    flags,
                    descriptor,
                    file_offset,
                )
            };
            if mapped == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!("cannot map guest range at {:#x}", spec.guest_address)
                });
            }
            if mapped != requested {
                // SAFETY: this allocation belongs to this call, including when
                // macOS substituted a non-overlapping address for an occupied hint.
                unsafe { libc::munmap(mapped, length) };
                bail!(
                    "requested guest address {:#x} is unavailable",
                    spec.guest_address
                );
            }
            // Register ownership before anything else may fail, so Drop rolls
            // back both this range and all previously successful mappings.
            memory.regions.push(MemoryRegion {
                guest_address: spec.guest_address,
                virtual_bytes: spec.virtual_bytes,
                mapped_bytes,
                initial_bytes,
                readable: spec.readable,
                writable: spec.writable,
                executable: spec.executable,
            });
            match spec.initial {
                InitialMemory::Anonymous(bytes) => {
                    // SAFETY: this exact anonymous allocation is RW, bytes fit,
                    // and the independent source Vec cannot overlap it.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            mapped.cast::<u8>(),
                            bytes.len(),
                        );
                    }
                    // Anonymous mmap supplies zeros for the virtual tail.
                }
                InitialMemory::File { file, .. } => memory.backing_files.push(file),
            }
            let protection = if spec.readable {
                libc::PROT_READ
            } else {
                libc::PROT_NONE
            } | if spec.writable { libc::PROT_WRITE } else { 0 };
            // SAFETY: this owner exclusively owns the validated mapped range.
            if unsafe { libc::mprotect(mapped, length, protection) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("cannot protect guest mapping");
            }
        }
        Ok(memory)
    }

    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    fn validate_access(&self, address: u64, length: usize, write: bool) -> Result<()> {
        ensure!(
            length as u64 <= MAX_IMAGE_MEMORY_BYTES,
            "guest access exceeds memory limit"
        );
        let end = address
            .checked_add(length as u64)
            .context("guest access address overflow")?;
        if length == 0 {
            return Ok(());
        }
        let mut cursor = address;
        for region in &self.regions {
            if region.end() <= cursor {
                continue;
            }
            ensure!(
                region.guest_address <= cursor,
                "guest access reaches unmapped memory"
            );
            ensure!(
                if write {
                    region.writable
                } else {
                    region.readable
                },
                "guest access violates region permissions"
            );
            cursor = region.end().min(end);
            if cursor == end {
                return Ok(());
            }
        }
        bail!("guest access reaches unmapped memory")
    }

    pub fn read_snapshot(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        self.validate_access(address, length, false)?;
        let mut bytes = vec![0; length];
        for (start, count, offset) in self.access_spans(address, length) {
            // SAFETY: all requested bytes belong to live readable regions, the
            // destination is independent, and this owner cannot cross threads.
            // Each copy stays within one mmap allocation.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    start as usize as *const u8,
                    bytes.as_mut_ptr().add(offset),
                    count,
                )
            };
        }
        Ok(bytes)
    }

    /// Validate the entire write first, including crossings of adjacent regions.
    pub fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        self.validate_access(address, bytes.len(), true)?;
        for (start, count, offset) in self.access_spans(address, bytes.len()) {
            // SAFETY: the exclusive owner validated every byte as writable;
            // callers cannot obtain references into these allocations safely.
            // Each copy stays within one mmap allocation.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(offset),
                    start as usize as *mut u8,
                    count,
                )
            };
        }
        Ok(())
    }

    // Only called after validate_access has checked the end and permissions.
    fn access_spans(
        &self,
        address: u64,
        length: usize,
    ) -> impl Iterator<Item = (u64, usize, usize)> + '_ {
        let end = address + length as u64;
        self.regions.iter().filter_map(move |region| {
            let start = address.max(region.guest_address);
            let stop = end.min(region.end());
            (start < stop).then(|| (start, (stop - start) as usize, (start - address) as usize))
        })
    }
}

impl Drop for OwnedMemory {
    fn drop(&mut self) {
        for region in &self.regions {
            // SAFETY: only exact allocations successfully owned by this object
            // are recorded; no methods transfer or partially release ownership.
            unsafe {
                libc::munmap(
                    region.guest_address as usize as *mut libc::c_void,
                    region.mapped_bytes as usize,
                )
            };
        }
    }
}

/// Runtime-published data with a permanently read-only, non-executable guest
/// view and an unexposed writable alias. Publication and translated accesses
/// must be serialized by the caller; this is not a concurrent kernel seqlock.
pub struct PublishedReadOnlyRegion {
    region: MemoryRegion,
    guest_mapping: Option<std::ptr::NonNull<libc::c_void>>,
    publisher_mapping: std::ptr::NonNull<libc::c_void>,
    _backing: File,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl std::fmt::Debug for PublishedReadOnlyRegion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublishedReadOnlyRegion")
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl PublishedReadOnlyRegion {
    /// Create a private unlinked backing object; no external file descriptor,
    /// writable guest address or Rust reference into either mapping escapes.
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
                    .is_some_and(|end| end <= USER_ADDRESS_END),
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
        // SAFETY: the kernel chooses a separate new mapping of the owned backing.
        let publisher = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                backing.as_raw_fd(),
                0,
            )
        };
        if publisher == libc::MAP_FAILED {
            let error = std::io::Error::last_os_error();
            // SAFETY: rollback only the guest view created above.
            unsafe { libc::munmap(guest, bytes as usize) };
            return Err(error).context("cannot map runtime publication alias");
        }
        let Some(publisher_mapping) = std::ptr::NonNull::new(publisher) else {
            // SAFETY: rollback both allocations created above.
            unsafe {
                libc::munmap(publisher, bytes as usize);
                libc::munmap(guest, bytes as usize);
            }
            bail!("null publication mapping is unsupported");
        };
        Ok(Self {
            region: MemoryRegion {
                guest_address: guest_base,
                virtual_bytes: initial.len() as u64,
                mapped_bytes: bytes,
                initial_bytes: initial.len(),
                readable: true,
                writable: false,
                executable: false,
            },
            guest_mapping: std::ptr::NonNull::new(guest),
            publisher_mapping,
            _backing: backing,
            _not_send_sync: PhantomData,
        })
    }

    pub fn region(&self) -> &MemoryRegion {
        &self.region
    }

    fn extent(&self, offset: usize, bytes: usize) -> Result<()> {
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
        let mut result = vec![0; bytes];
        // SAFETY: live RO mapping, bounded copy, independent owned destination;
        // publication cannot run concurrently through this non-Send/Sync owner.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (self.region.guest_address as usize as *const u8).add(offset),
                result.as_mut_ptr(),
                bytes,
            )
        };
        Ok(result)
    }

    pub fn publish(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        self.extent(offset, bytes.len())?;
        // SAFETY: private live RW alias and fully checked extent. No guest code
        // may execute concurrently, and safe APIs expose no mapping references.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.publisher_mapping.as_ptr().cast::<u8>().add(offset),
                bytes.len(),
            )
        };
        Ok(())
    }
}

impl Drop for PublishedReadOnlyRegion {
    fn drop(&mut self) {
        // SAFETY: both allocations were created and retained exclusively here.
        unsafe {
            if let Some(guest) = self.guest_mapping {
                libc::munmap(guest.as_ptr(), self.region.mapped_bytes as usize);
            }
            libc::munmap(
                self.publisher_mapping.as_ptr(),
                self.region.mapped_bytes as usize,
            );
        }
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    fn spec(address: u64, size: u64) -> MemoryRegionSpec {
        MemoryRegionSpec {
            guest_address: address,
            virtual_bytes: size,
            initial_bytes: vec![7, 8, 9],
            readable: true,
            writable: true,
            executable: false,
        }
    }

    // The OS chooses a candidate; a racing allocation can only cause a safe
    // failure. No test assumes a hardcoded address is free.
    fn candidate(size: usize) -> u64 {
        // SAFETY: a temporary ordinary anonymous mapping.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        let address = pointer as usize as u64;
        // SAFETY: release only the temporary allocation just created.
        assert_eq!(unsafe { libc::munmap(pointer, size) }, 0);
        address
    }

    fn allocate(
        mut make: impl FnMut(u64, u64) -> Vec<MemoryRegionSpec>,
        pages: usize,
    ) -> OwnedMemory {
        let page = host_page_size().unwrap();
        for _ in 0..32 {
            let address = candidate(page * pages);
            if let Ok(memory) = OwnedMemory::map(make(address, page as u64)) {
                return memory;
            }
        }
        panic!("cannot allocate test guest mapping after 32 attempts");
    }

    fn file_spec(address: u64, size: u64, file: File, offset: u64) -> FileMemoryRegionSpec {
        FileMemoryRegionSpec {
            guest_address: address,
            virtual_bytes: size,
            file,
            file_offset: offset,
            readable: true,
            writable: true,
            executable: false,
        }
    }

    fn backing_file(bytes: &[u8], size: u64) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file.set_len(size).unwrap();
        file
    }

    fn allocate_files(
        mut make: impl FnMut(u64, u64) -> Vec<FileMemoryRegionSpec>,
        pages: usize,
    ) -> OwnedMemory {
        let page = host_page_size().unwrap();
        for _ in 0..32 {
            let address = candidate(page * pages);
            // SAFETY: callers provide exclusively owned temporary backing files;
            // no test modifies/truncates their mapped inodes while owners live.
            if let Ok(memory) = unsafe { OwnedMemory::map_files(make(address, page as u64)) } {
                return memory;
            }
        }
        panic!("cannot allocate test file mapping after 32 attempts");
    }

    #[test]
    fn publication_preserves_guest_permissions_and_logical_bounds() {
        let page = host_page_size().unwrap();
        let mut published = (0..32)
            .find_map(|_| PublishedReadOnlyRegion::map(candidate(page), &[7; 13]).ok())
            .unwrap();
        let address = published.region().guest_address;
        let alias = published.publisher_mapping.as_ptr() as usize as u64;
        assert_eq!(os_protection(address), libc::PROT_READ);
        assert_eq!(os_protection(alias), libc::PROT_READ | libc::PROT_WRITE);
        published.publish(4, &[1, 2, 3]).unwrap();
        assert_eq!(
            published.read_snapshot(0, 13).unwrap(),
            [7, 7, 7, 7, 1, 2, 3, 7, 7, 7, 7, 7, 7]
        );
        assert!(published.publish(13, &[1]).is_err());
        assert!(published.read_snapshot(usize::MAX, 2).is_err());
        assert_eq!(os_protection(address), libc::PROT_READ);
        assert_eq!(os_protection(alias), libc::PROT_READ | libc::PROT_WRITE);
        assert!(PublishedReadOnlyRegion::map(address, &[9; 13]).is_err());
        assert_eq!(published.read_snapshot(4, 3).unwrap(), [1, 2, 3]);
        drop(published);
        // A parallel test can claim the released address immediately.
        let reused = (0..32)
            .find_map(|_| PublishedReadOnlyRegion::map(candidate(page), &[8; 13]).ok())
            .unwrap();
        assert_eq!(reused.read_snapshot(0, 13).unwrap(), [8; 13]);
    }

    #[test]
    fn file_offset_and_private_writes_preserve_original_file_bytes() {
        let page = host_page_size().unwrap();
        let mut bytes = vec![0xa5; page * 2];
        bytes[page..page + 3].copy_from_slice(&[1, 2, 3]);
        let mut file = backing_file(&bytes, bytes.len() as u64);
        let mut memory = allocate_files(
            |address, page| vec![file_spec(address, page, file.try_clone().unwrap(), page)],
            1,
        );
        let address = memory.regions()[0].guest_address;
        assert_eq!(memory.regions()[0].initial_bytes, page);
        assert_eq!(memory.backing_files.len(), 1);
        assert_eq!(memory.read_snapshot(address, 4).unwrap(), [1, 2, 3, 0xa5]);
        memory.write(address + 1, &[8, 9]).unwrap();
        assert_eq!(memory.read_snapshot(address, 4).unwrap(), [1, 8, 9, 0xa5]);
        file.seek(SeekFrom::Start(page as u64)).unwrap();
        let mut source = [0; 4];
        file.read_exact(&mut source).unwrap();
        assert_eq!(source, [1, 2, 3, 0xa5]);
    }

    #[test]
    fn file_partial_page_eof_keeps_logical_guest_bounds() {
        let page = host_page_size().unwrap();
        let mut bytes = vec![0x6b; page + 3];
        bytes[page..].copy_from_slice(&[4, 5, 6]);
        let file = backing_file(&bytes, bytes.len() as u64);
        let mut memory = allocate_files(
            |address, page| vec![file_spec(address, page + 3, file.try_clone().unwrap(), 0)],
            2,
        );
        let region = &memory.regions()[0];
        let address = region.guest_address;
        assert_eq!(region.mapped_bytes, 2 * page as u64);
        assert_eq!(
            memory.read_snapshot(address + page as u64, 3).unwrap(),
            [4, 5, 6]
        );
        assert!(memory.read_snapshot(address + page as u64 + 3, 1).is_err());
        assert!(memory.write(address + page as u64 + 3, &[1]).is_err());
        memory.write(address + page as u64 + 2, &[42]).unwrap();
        assert_eq!(
            memory.read_snapshot(address + page as u64 + 2, 1).unwrap(),
            [42]
        );
    }

    #[test]
    fn file_guest_code_and_noaccess_regions_never_receive_host_execute() {
        let page = host_page_size().unwrap() as u64;
        let file = backing_file(&[0x1f, 0x20, 0x03, 0xd5], page);
        let mut memory = allocate_files(
            |address, page| {
                let mut code = file_spec(address, page, file.try_clone().unwrap(), 0);
                code.writable = false;
                code.executable = true;
                let mut guard = file_spec(address + page, page, file.try_clone().unwrap(), 0);
                guard.readable = false;
                guard.writable = false;
                vec![code, guard]
            },
            2,
        );
        let address = memory.regions()[0].guest_address;
        assert_eq!(os_protection(address), libc::PROT_READ);
        assert_eq!(os_protection(address + page), libc::PROT_NONE);
        assert_eq!(
            memory.read_snapshot(address, 4).unwrap(),
            [0x1f, 0x20, 0x03, 0xd5]
        );
        assert!(memory.write(address, &[0]).is_err());
        assert!(memory.read_snapshot(address + page, 1).is_err());
        assert!(memory.write(address + page, &[0]).is_err());
        assert!(memory.write(address + page - 1, &[1, 2]).is_err());
        assert_eq!(memory.read_snapshot(address + page - 1, 1).unwrap(), [0]);
    }

    #[test]
    fn file_mapping_budget_is_separate_from_bounded_copy_access() {
        let page = host_page_size().unwrap();
        let bytes = MAX_IMAGE_MEMORY_BYTES + page as u64;
        let file = backing_file(&[], bytes);
        let memory = allocate_files(
            |address, _| vec![file_spec(address, bytes, file.try_clone().unwrap(), 0)],
            bytes as usize / page,
        );
        let address = memory.regions()[0].guest_address;
        assert_eq!(memory.regions()[0].virtual_bytes, bytes);
        assert_eq!(memory.read_snapshot(address + bytes - 1, 1).unwrap(), [0]);
        assert!(
            memory
                .read_snapshot(address, MAX_IMAGE_MEMORY_BYTES as usize + 1)
                .is_err()
        );
        // SAFETY: an empty mapping set has no backing-inode lifetime obligation.
        let empty = unsafe { OwnedMemory::map_files(vec![]) }.unwrap();
        assert!(empty.regions().is_empty() && empty.backing_files.is_empty());
    }

    #[test]
    fn invalid_file_extents_offsets_types_and_access_decline_before_mapping() {
        let page = host_page_size().unwrap() as u64;
        let file = backing_file(&[1, 2, 3], page);
        let address = candidate(page as usize);
        for (base, bytes, offset) in [
            (0, page, 0),
            (address + 1, page, 0),
            (address, 0, 0),
            (USER_ADDRESS_END, page, 0),
            (address, page, 1),
            (address, page + 1, 0),
            (address, page, page),
            (address, page, u64::MAX - page + 1),
        ] {
            // SAFETY: this test exclusively owns the unchanged temporary inode.
            assert!(
                unsafe {
                    OwnedMemory::map_files(vec![file_spec(
                        base,
                        bytes,
                        file.try_clone().unwrap(),
                        offset,
                    )])
                }
                .is_err()
            );
        }
        let mut rwx = file_spec(address, page, file.try_clone().unwrap(), 0);
        rwx.executable = true;
        // SAFETY: this test exclusively owns the unchanged temporary inode.
        assert!(unsafe { OwnedMemory::map_files(vec![rwx]) }.is_err());
        let mut write_only_memory = file_spec(address, page, file.try_clone().unwrap(), 0);
        write_only_memory.readable = false;
        // SAFETY: this test exclusively owns the unchanged temporary inode.
        assert!(unsafe { OwnedMemory::map_files(vec![write_only_memory]) }.is_err());
        // SAFETY: the non-regular descriptor is declined before mapping.
        assert!(
            unsafe {
                OwnedMemory::map_files(vec![file_spec(
                    address,
                    page,
                    File::open("/dev/null").unwrap(),
                    0,
                )])
            }
            .is_err()
        );
        let temporary = tempfile::NamedTempFile::new().unwrap();
        temporary.as_file().set_len(page).unwrap();
        let write_only_file = std::fs::OpenOptions::new()
            .write(true)
            .open(temporary.path())
            .unwrap();
        // SAFETY: this test exclusively owns the unchanged temporary inode.
        assert!(
            unsafe { OwnedMemory::map_files(vec![file_spec(address, page, write_only_file, 0)]) }
                .is_err()
        );
        // SAFETY: the cloned descriptors refer to one unchanged temporary inode.
        assert!(
            unsafe {
                OwnedMemory::map_files(vec![
                    file_spec(address, page, file.try_clone().unwrap(), 0),
                    file_spec(address, page, file.try_clone().unwrap(), 0),
                ])
            }
            .is_err()
        );
        let too_large = backing_file(&[], MAX_FILE_MEMORY_BYTES + page);
        // SAFETY: this test exclusively owns the unchanged sparse temporary inode.
        let error = unsafe {
            OwnedMemory::map_files(vec![file_spec(
                page,
                MAX_FILE_MEMORY_BYTES + page,
                too_large,
                0,
            )])
        }
        .unwrap_err();
        assert!(format!("{error:#}").contains("guest mappings exceed memory limit"));
    }

    #[test]
    fn file_collision_preserves_existing_mapping_and_source() {
        let occupied = allocate(|address, page| vec![spec(address, page)], 1);
        let region = &occupied.regions()[0];
        let file = backing_file(&[1, 2, 3], region.virtual_bytes);
        // SAFETY: this test exclusively owns the unchanged temporary inode.
        assert!(
            unsafe {
                OwnedMemory::map_files(vec![file_spec(
                    region.guest_address,
                    region.virtual_bytes,
                    file,
                    0,
                )])
            }
            .is_err()
        );
        assert_eq!(
            occupied.read_snapshot(region.guest_address, 3).unwrap(),
            [7, 8, 9]
        );
    }

    #[test]
    fn partial_file_mapping_failure_rolls_back_owned_ranges() {
        for _ in 0..32 {
            let occupied = allocate(|address, page| vec![spec(address + page, page)], 2);
            let page = occupied.regions()[0].virtual_bytes;
            let address = occupied.regions()[0].guest_address - page;
            let file = backing_file(&[1, 2, 3], page);
            // SAFETY: this test exclusively owns the unchanged temporary inode.
            let error = unsafe {
                OwnedMemory::map_files(vec![
                    file_spec(address, page, file.try_clone().unwrap(), 0),
                    file_spec(address + page, page, file.try_clone().unwrap(), 0),
                ])
            }
            .unwrap_err();
            assert_eq!(
                occupied.read_snapshot(address + page, 3).unwrap(),
                [7, 8, 9]
            );
            if !format!("{error:#}").contains(&format!("{:#x}", address + page)) {
                continue;
            }
            // SAFETY: the temporary inode remains unchanged until restored drops.
            if let Ok(restored) =
                unsafe { OwnedMemory::map_files(vec![file_spec(address, page, file, 0)]) }
            {
                assert_eq!(restored.read_snapshot(address, 3).unwrap(), [1, 2, 3]);
                return;
            }
        }
        panic!("cannot verify file mapping rollback after 32 attempts");
    }

    #[test]
    fn retained_file_descriptor_maps_original_inode_after_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache");
        let mut file = File::create(&path).unwrap();
        file.write_all(&[1, 2, 3]).unwrap();
        file.set_len(host_page_size().unwrap() as u64).unwrap();
        drop(file);
        let source = File::open(&path).unwrap();
        let memory = allocate_files(
            |address, page| vec![file_spec(address, page, source.try_clone().unwrap(), 0)],
            1,
        );
        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, [4, 5, 6]).unwrap();
        std::fs::rename(replacement, &path).unwrap();
        assert_eq!(
            memory
                .read_snapshot(memory.regions()[0].guest_address, 3)
                .unwrap(),
            [1, 2, 3]
        );
        assert_eq!(std::fs::read(path).unwrap(), [4, 5, 6]);
        // This only proves descriptor ownership. External writes/truncation to
        // the original inode still require caller-side lifetime guards.
    }

    #[test]
    fn exact_address_zero_tail_and_exclusive_writes() {
        let mut memory = allocate(|address, page| vec![spec(address, page)], 1);
        let address = memory.regions()[0].guest_address;
        assert_eq!(memory.read_snapshot(address, 5).unwrap(), [7, 8, 9, 0, 0]);
        memory.write(address + 2, &[10, 11]).unwrap();
        assert_eq!(memory.read_snapshot(address, 5).unwrap(), [7, 8, 10, 11, 0]);
        assert!(
            memory
                .read_snapshot(address + memory.regions()[0].virtual_bytes - 1, 2)
                .is_err()
        );
        assert!(memory.read_snapshot(u64::MAX, 2).is_err());
    }

    #[test]
    fn collision_preserves_existing_mapping_and_bytes() {
        let memory = allocate(|address, page| vec![spec(address, page)], 1);
        let existing = &memory.regions()[0];
        assert!(
            OwnedMemory::map(vec![spec(existing.guest_address, existing.virtual_bytes)]).is_err()
        );
        assert_eq!(
            memory.read_snapshot(existing.guest_address, 4).unwrap(),
            [7, 8, 9, 0]
        );
    }

    #[test]
    fn partial_mapping_failure_rolls_back_all_owned_ranges() {
        for _ in 0..32 {
            let occupied = allocate(|address, page| vec![spec(address + page, page)], 2);
            let page = occupied.regions()[0].virtual_bytes;
            let address = occupied.regions()[0].guest_address - page;
            let error = OwnedMemory::map(vec![spec(address, page), spec(address + page, page)])
                .unwrap_err();
            assert_eq!(
                occupied.read_snapshot(address + page, 3).unwrap(),
                [7, 8, 9]
            );
            // A parallel allocation can acquire the first free page. Require
            // failure at the occupied second page to prove partial allocation.
            if !format!("{error:#}").contains(&format!("{:#x}", address + page)) {
                continue;
            }
            // Success proves the earlier range was released by rollback. A
            // racing allocation after rollback can only force a safe retry.
            if let Ok(restored) = OwnedMemory::map(vec![spec(address, page)]) {
                assert_eq!(restored.regions()[0].guest_address, address);
                return;
            }
        }
        panic!("cannot verify mapping rollback after 32 attempts");
    }

    #[test]
    fn reject_invalid_or_excessive_mapping_sets_before_allocation() {
        let page = host_page_size().unwrap() as u64;
        let address = candidate(page as usize);
        let mut invalid = vec![
            spec(0, page),
            spec(address + 1, page),
            spec(address, 0),
            spec(USER_ADDRESS_END, page),
            spec(u64::MAX - page + 1, page),
            spec(address, MAX_IMAGE_MEMORY_BYTES + page),
        ];
        let mut oversized = spec(address, page);
        oversized.initial_bytes = vec![0; page as usize + 1];
        invalid.push(oversized);
        let mut rwx = spec(address, page);
        rwx.executable = true;
        invalid.push(rwx);
        let mut write_only = spec(address, page);
        write_only.readable = false;
        invalid.push(write_only);
        for item in invalid {
            assert!(OwnedMemory::map(vec![item]).is_err());
        }
        assert!(OwnedMemory::map(vec![spec(address, page), spec(address, page)]).is_err());
        assert!(
            OwnedMemory::map(vec![
                spec(address, MAX_IMAGE_MEMORY_BYTES),
                spec(address + MAX_IMAGE_MEMORY_BYTES, page)
            ])
            .is_err()
        );
    }

    #[test]
    fn partial_page_tail_is_mapped_but_outside_guest_bounds() {
        let mut memory = allocate(|address, page| vec![spec(address, page + 3)], 2);
        let region = &memory.regions()[0];
        let address = region.guest_address;
        let virtual_bytes = region.virtual_bytes;
        assert_eq!(region.mapped_bytes, 2 * host_page_size().unwrap() as u64);
        assert_eq!(
            memory
                .read_snapshot(address + virtual_bytes - 1, 1)
                .unwrap(),
            [0]
        );
        assert!(memory.read_snapshot(address + virtual_bytes, 1).is_err());
        assert!(memory.write(address + virtual_bytes, &[1]).is_err());
        memory.write(address + virtual_bytes - 1, &[42]).unwrap();
        assert_eq!(
            memory
                .read_snapshot(address + virtual_bytes - 1, 1)
                .unwrap(),
            [42]
        );
        assert!(
            OwnedMemory::map(vec![
                spec(address, virtual_bytes),
                spec(address + host_page_size().unwrap() as u64, 1)
            ])
            .is_err()
        );
    }

    #[test]
    fn adjacent_access_checks_every_region_before_mutating() {
        let mut memory = allocate(
            |address, page| {
                let mut second = spec(address + page, page);
                second.writable = false;
                vec![spec(address, page), second]
            },
            2,
        );
        let first = &memory.regions()[0];
        let boundary = first.guest_address + first.virtual_bytes;
        assert_eq!(memory.read_snapshot(boundary - 1, 4).unwrap(), [0, 7, 8, 9]);
        assert!(memory.write(boundary - 1, &[1, 2]).is_err());
        assert_eq!(memory.read_snapshot(boundary - 1, 4).unwrap(), [0, 7, 8, 9]);
    }

    #[test]
    fn adjacent_writable_regions_copy_across_allocation_boundary() {
        let mut memory = allocate(
            |address, page| vec![spec(address, page), spec(address + page, page)],
            2,
        );
        let boundary = memory.regions()[1].guest_address;
        memory.write(boundary - 2, &[1, 2, 3, 4]).unwrap();
        assert_eq!(memory.read_snapshot(boundary - 2, 4).unwrap(), [1, 2, 3, 4]);
    }

    #[test]
    fn executable_guest_bytes_are_readonly_host_data() {
        let mut memory = allocate(
            |address, page| {
                let mut code = spec(address, page);
                code.writable = false;
                code.executable = true;
                vec![code]
            },
            1,
        );
        let address = memory.regions()[0].guest_address;
        assert_eq!(memory.read_snapshot(address, 3).unwrap(), [7, 8, 9]);
        assert!(memory.write(address, &[0]).is_err());
        assert_eq!(os_protection(address), libc::PROT_READ);
    }

    #[test]
    fn noaccess_guest_region_has_no_host_access() {
        let mut memory = allocate(
            |address, page| {
                let mut region = spec(address, page);
                region.readable = false;
                region.writable = false;
                vec![region]
            },
            1,
        );
        let address = memory.regions()[0].guest_address;
        assert!(memory.read_snapshot(address, 1).is_err());
        assert!(memory.write(address, &[0]).is_err());
        assert_eq!(os_protection(address), libc::PROT_NONE);
    }

    #[cfg(target_os = "linux")]
    fn os_protection(address: u64) -> i32 {
        for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
            let mut fields = line.split_whitespace();
            let (start, end) = fields.next().unwrap().split_once('-').unwrap();
            if (u64::from_str_radix(start, 16).unwrap()..u64::from_str_radix(end, 16).unwrap())
                .contains(&address)
            {
                let permissions = fields.next().unwrap().as_bytes();
                return if permissions[0] == b'r' {
                    libc::PROT_READ
                } else {
                    0
                } | if permissions[1] == b'w' {
                    libc::PROT_WRITE
                } else {
                    0
                } | if permissions[2] == b'x' {
                    libc::PROT_EXEC
                } else {
                    0
                };
            }
        }
        panic!("test mapping not found in /proc/self/maps");
    }

    #[cfg(target_os = "macos")]
    fn os_protection(mut address: u64) -> i32 {
        unsafe extern "C" {
            static mach_task_self_: u32;
            fn mach_vm_region(
                task: libc::mach_port_t,
                address: *mut u64,
                size: *mut u64,
                flavor: i32,
                info: *mut i32,
                count: *mut u32,
                object: *mut libc::mach_port_t,
            ) -> i32;
            fn mach_port_deallocate(task: u32, name: u32) -> i32;
        }
        // SDK mach/vm_region.h: VM_REGION_BASIC_INFO_64=9, packed-4
        // vm_region_basic_info_64 is nine i32 words; protection is first.
        let mut info = [0i32; 9];
        let mut count = info.len() as u32;
        let mut size = 0u64;
        let mut object = 0;
        // SAFETY: pointers reference correctly sized writable output storage.
        let result = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut address,
                &mut size,
                9,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        if object != 0 {
            // SAFETY: release only the object-name right returned by the query.
            unsafe { mach_port_deallocate(mach_task_self_, object) };
        }
        assert_eq!(result, 0);
        assert_eq!(count, 9);
        info[0]
    }
}
