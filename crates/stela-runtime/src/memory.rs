//! Owned guest mappings with explicit direct-RAM or canonical domain binding.
//!
//! Original Arm instructions are data to the x86 host: a guest executable
//! region never receives host execute permission. Mapping must succeed at the
//! requested address without replacing any existing allocation.
//! Opt-in binding retains actual storage in one canonical physical domain.
//! Serialized service loans govern snapshots, publication and mapping changes.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
mod access;
mod allocation;
mod binding;
use binding::SharedBinding;
pub use binding::{SharedBindingError, SharedMemoryConfig, SharedMemoryParticipant};
pub mod backing;
pub mod domain;
pub mod monitor;
pub mod policy;
mod service;
pub use service::GuestServiceMemory;
pub(crate) mod source_ram;
pub mod stage1;
mod storage;
pub mod tag_execution;
pub mod tag_store;
pub mod tag_transfer;
pub mod tags;

#[cfg(feature = "std")]
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::sync::Arc;
use anyhow::{Context, Result, bail, ensure};
use core::marker::PhantomData;
use serde::Serialize;
#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::os::fd::AsRawFd;
#[cfg(feature = "std")]
use storage::NativeMapping;
use storage::NativeStorage;

pub use allocation::{
    AllocateDataError, AllocateDataRequest, AllocationOperation, DataAllocation, DataInheritance,
    DataPermissions, DataPlacement, PendingDataAllocation,
};

pub const MAX_IMAGE_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
/// File-backed research mappings have a separate virtual-space budget. Safe
/// snapshot/write operations retain the smaller MAX_IMAGE_MEMORY_BYTES bound.
pub const MAX_FILE_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Exclusive end of the lower canonical user range in the direct-RAM x86-64
/// profile. This native mapping bound does not define a guest kernel VM maximum.
pub const DIRECT_RAM_USER_END: u64 = 1 << 47;

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
/// Retained allocation storage keeps the file descriptor. MAP_PRIVATE prevents our writes
/// from modifying the file; it does not freeze unrelated writes/truncation to
/// that inode. Source identity, provenance and stability for the entire mapping
/// lifetime are the caller's responsibility. Truncation can cause native faults.
#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
enum InitialMemory {
    Anonymous(Vec<u8>),
    File { file: File, offset: u64 },
}

#[cfg(feature = "std")]
struct MappingSpec {
    guest_address: u64,
    virtual_bytes: u64,
    readable: bool,
    writable: bool,
    executable: bool,
    initial: InitialMemory,
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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
    /// Host-page extent of this protection view; views never cross allocations.
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

/// Maximum data rights supplied by the address-space loader. Omitted entries
/// default to initial rights; executable snapshots are never mutable here.
#[derive(Debug, Clone, Copy)]
pub struct DataProtectionLimit {
    pub guest_address: u64,
    pub readable: bool,
    pub writable: bool,
}
#[derive(Debug)]
// The freestanding mount does not create host mappings.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
struct Allocation {
    shared_backing: Option<Arc<backing::MemoryBacking>>,
    storage: Arc<NativeStorage>,
    base: u64,
    bytes: u64,
    logical_bytes: u64,
    maximum_readable: bool,
    maximum_writable: bool,
    maximum_executable: bool,
    executable: bool,
    alias_tag: u8,
    inheritance: DataInheritance,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionError {
    InvalidRange,
    #[cfg(not(feature = "std"))]
    PlatformUnavailable,
    UnmappedRange,
    MaximumProtection,
    ExecutableRegion,
    WriteWithoutRead,
    AddressSpaceUnusable,
    SharedDomainBound,
    AllocationFailure,
    HostFailure {
        errno: Option<i32>,
        rollback_succeeded: bool,
    },
}
impl core::fmt::Display for ProtectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "guest data protection failed: {self:?}")
    }
}
impl core::error::Error for ProtectionError {}

/// Private, non-shareable mappings with retained native storage lifetimes.
///
/// Safe operations copy bytes; they never lend Rust references into memory that
/// native guest code may mutate. Callers executing native code remain responsible
/// for its unsafe execution contract and must keep this owner alive throughout.
/// Internal retained storage can outlive this logical owner; retention alone does
/// not pin host rights or admit concurrent/shared execution.
#[derive(Debug)]
pub struct OwnedMemory {
    shared: Option<Arc<SharedBinding>>,
    regions: Vec<MemoryRegion>,
    allocations: Vec<Allocation>,
    page_bytes: u64,
    usable: bool,
    _not_send_sync: PhantomData<Rc<()>>,
}

#[cfg(feature = "std")]
pub fn host_page_size() -> Result<usize> {
    // SAFETY: sysconf has no pointer arguments or mutable Rust state.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(page > 0, "cannot determine host page size");
    let page = usize::try_from(page)?;
    ensure!(page.is_power_of_two(), "unsupported host page size");
    Ok(page)
}

#[cfg(not(feature = "std"))]
pub fn host_page_size() -> Result<usize> {
    crate::platform::boot::ensure_live()?;
    Ok(4096)
}

#[cfg(feature = "std")]
fn page_rounded(bytes: u64, page: u64) -> Result<u64> {
    Ok(bytes
        .checked_add(page - 1)
        .context("guest mapping size overflow")?
        & !(page - 1))
}

impl OwnedMemory {
    #[cfg(feature = "std")]
    pub fn map(specs: Vec<MemoryRegionSpec>) -> Result<Self> {
        Self::map_specs(
            specs.into_iter().map(MappingSpec::from).collect(),
            MAX_IMAGE_MEMORY_BYTES,
            BTreeMap::new(),
        )
    }

    #[cfg(not(feature = "std"))]
    pub fn map(specs: Vec<MemoryRegionSpec>) -> Result<Self> {
        let _ = specs;
        anyhow::bail!("freestanding guest RAM mappings are not mounted")
    }

    #[cfg(feature = "std")]
    pub fn map_with_data_limits(
        specs: Vec<MemoryRegionSpec>,
        limits: Vec<DataProtectionLimit>,
    ) -> Result<Self> {
        let mut table = BTreeMap::new();
        for limit in limits {
            ensure!(
                table.insert(limit.guest_address, limit).is_none(),
                "duplicate data protection limit"
            );
        }
        for (&address, limit) in &table {
            let spec = specs
                .iter()
                .find(|s| s.guest_address == address)
                .context("data protection limit has no mapping")?;
            ensure!(
                !spec.executable,
                "data protection limit cannot grant executable source rights"
            );
            ensure!(
                !limit.writable || limit.readable,
                "maximum write permission requires read permission"
            );
            ensure!(
                (!spec.readable || limit.readable) && (!spec.writable || limit.writable),
                "initial data protection exceeds maximum"
            );
        }
        Self::map_specs(
            specs.into_iter().map(MappingSpec::from).collect(),
            MAX_IMAGE_MEMORY_BYTES,
            table,
        )
    }

    #[cfg(not(feature = "std"))]
    pub fn map_with_data_limits(
        specs: Vec<MemoryRegionSpec>,
        limits: Vec<DataProtectionLimit>,
    ) -> Result<Self> {
        let _ = (specs, limits);
        anyhow::bail!("freestanding guest RAM mappings are not mounted")
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
    #[cfg(feature = "std")]
    pub unsafe fn map_files(specs: Vec<FileMemoryRegionSpec>) -> Result<Self> {
        Self::map_specs(
            specs.into_iter().map(MappingSpec::from).collect(),
            MAX_FILE_MEMORY_BYTES,
            BTreeMap::new(),
        )
    }

    #[cfg(feature = "std")]
    fn map_specs(
        mut specs: Vec<MappingSpec>,
        limit: u64,
        limits: BTreeMap<u64, DataProtectionLimit>,
    ) -> Result<Self> {
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
                end <= DIRECT_RAM_USER_END,
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
            shared: None,
            regions: Vec::new(),
            allocations: Vec::new(),
            page_bytes: page,
            usable: true,
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
            // SAFETY: exact newly owned complete pages, checked address/extent,
            // coherent Normal-WB storage and no escaping guest references.
            let native = unsafe {
                NativeMapping::adopt(
                    core::ptr::NonNull::new(mapped.cast()).expect("nonzero exact mapping"),
                    length,
                )
            };
            let (storage, initial) = match spec.initial {
                InitialMemory::Anonymous(bytes) => (NativeStorage::anonymous(native), Some(bytes)),
                InitialMemory::File { file, .. } => {
                    (NativeStorage::private_file(native, file), None)
                }
            };
            // Register retained ownership before any later operation can fail.
            let limit = limits.get(&spec.guest_address);
            memory.allocations.push(Allocation {
                shared_backing: None,
                storage,
                base: spec.guest_address,
                bytes: mapped_bytes,
                logical_bytes: spec.virtual_bytes,
                maximum_readable: limit.map_or(spec.readable, |l| l.readable),
                maximum_writable: limit.map_or(spec.writable, |l| l.writable),
                maximum_executable: spec.executable,
                executable: spec.executable,
                alias_tag: 0,
                inheritance: DataInheritance::Copy,
            });
            memory.regions.push(MemoryRegion {
                guest_address: spec.guest_address,
                virtual_bytes: spec.virtual_bytes,
                mapped_bytes,
                initial_bytes,
                readable: spec.readable,
                writable: spec.writable,
                executable: spec.executable,
            });
            if let Some(bytes) = initial {
                // SAFETY: this exact anonymous allocation is RW, bytes fit,
                // and the independent source Vec cannot overlap it.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        mapped.cast::<u8>(),
                        bytes.len(),
                    );
                }
                // Anonymous mmap supplies zeros for the virtual tail.
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

    /// False only if a failed host operation could not restore prior rights.
    /// Safe byte APIs then decline; native executors must also refuse resumption.
    pub fn is_usable(&self) -> bool {
        self.usable
    }

    /// Change owned data pages without ever granting host execute permission.
    /// Address/length must be host-page multiples. Rounded allocation padding
    /// may be protected but remains outside logical byte-access bounds. Source
    /// snapshots require coordinated invalidation and are explicitly declined.
    /// Caller excludes all concurrent translated execution during this operation.
    #[cfg(feature = "std")]
    pub fn protect_data(
        &mut self,
        address: u64,
        bytes: u64,
        readable: bool,
        writable: bool,
    ) -> core::result::Result<(), ProtectionError> {
        self.protect_data_with(
            address,
            bytes,
            readable,
            writable,
            |base, length, protection| {
                // SAFETY: preflight proves exclusive ownership of every covered page.
                let result = unsafe {
                    libc::mprotect(
                        base as usize as *mut libc::c_void,
                        length as usize,
                        protection,
                    )
                };
                if result == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error().raw_os_error())
                }
            },
        )
    }

    #[cfg(not(feature = "std"))]
    pub fn protect_data(
        &mut self,
        address: u64,
        bytes: u64,
        readable: bool,
        writable: bool,
    ) -> core::result::Result<(), ProtectionError> {
        let _ = (address, bytes, readable, writable);
        Err(ProtectionError::PlatformUnavailable)
    }

    #[cfg(feature = "std")]
    fn protect_data_with(
        &mut self,
        address: u64,
        bytes: u64,
        readable: bool,
        writable: bool,
        protect: impl FnMut(u64, u64, i32) -> core::result::Result<(), Option<i32>>,
    ) -> core::result::Result<(), ProtectionError> {
        self.protect_data_with_service(address, bytes, readable, writable, None, protect)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "std")]
    fn protect_data_with_service(
        &mut self,
        address: u64,
        bytes: u64,
        readable: bool,
        writable: bool,
        service: Option<&domain::MemoryServiceLoan>,
        mut protect: impl FnMut(u64, u64, i32) -> core::result::Result<(), Option<i32>>,
    ) -> core::result::Result<(), ProtectionError> {
        use ProtectionError as E;
        if let Some(loan) = service {
            let shared = self.shared.as_ref().ok_or(E::SharedDomainBound)?;
            shared.check().map_err(|_| E::AddressSpaceUnusable)?;
            if !loan.belongs_to(&shared.domain) {
                return Err(E::SharedDomainBound);
            }
        }
        if !self.usable {
            return Err(E::AddressSpaceUnusable);
        }
        if writable && !readable {
            return Err(E::WriteWithoutRead);
        }
        let end = address.checked_add(bytes).ok_or(E::InvalidRange)?;
        if bytes == 0
            || !address.is_multiple_of(self.page_bytes)
            || !bytes.is_multiple_of(self.page_bytes)
        {
            return Err(E::InvalidRange);
        }
        let mut cursor = address;
        for allocation in &self.allocations {
            let limit = allocation.base + allocation.bytes;
            if limit <= cursor {
                continue;
            }
            if allocation.base > cursor {
                return Err(E::UnmappedRange);
            }
            if allocation.executable {
                return Err(E::ExecutableRegion);
            }
            if (readable && !allocation.maximum_readable)
                || (writable && !allocation.maximum_writable)
            {
                return Err(E::MaximumProtection);
            }
            cursor = limit.min(end);
            if cursor == end {
                break;
            }
        }
        if cursor != end {
            return Err(E::UnmappedRange);
        }
        // Allocate the complete replacement metadata/rollback recipe before
        // changing OS rights. No fallible allocation follows successful protect.
        let mut next = Vec::new();
        next.try_reserve(self.regions.len().saturating_mul(3))
            .map_err(|_| E::AllocationFailure)?;
        let mut rollback = Vec::new();
        rollback
            .try_reserve(self.regions.len())
            .map_err(|_| E::AllocationFailure)?;
        for region in &self.regions {
            let physical_end = region.guest_address + region.mapped_bytes;
            let begin = region.guest_address.max(address);
            let stop = physical_end.min(end);
            if begin >= stop {
                next.push(region.clone());
                continue;
            }
            rollback.push((
                begin,
                stop - begin,
                host_protection(region.readable, region.writable),
            ));
            for (base, limit, r, w) in [
                (
                    region.guest_address,
                    begin,
                    region.readable,
                    region.writable,
                ),
                (begin, stop, readable, writable),
                (stop, physical_end, region.readable, region.writable),
            ] {
                if base >= limit {
                    continue;
                }
                let virtual_end = region.end().min(limit);
                if base >= virtual_end {
                    continue;
                }
                let initialized_end = region.guest_address + region.initial_bytes as u64;
                next.push(MemoryRegion {
                    guest_address: base,
                    virtual_bytes: virtual_end - base,
                    mapped_bytes: limit - base,
                    initial_bytes: initialized_end.saturating_sub(base).min(virtual_end - base)
                        as usize,
                    readable: r,
                    writable: w,
                    executable: region.executable,
                });
            }
        }
        if self.shared.is_some() {
            return self.protect_shared(
                address, bytes, readable, writable, next, rollback, service, protect,
            );
        }
        if let Err(errno) = protect(address, bytes, host_protection(readable, writable)) {
            // Some host kernels can partially change a failed range. Restore
            // every covered old view, including the failed call's own pages.
            let mut restored = true;
            for (base, length, rights) in rollback {
                if protect(base, length, rights).is_err() {
                    restored = false;
                }
            }
            if !restored {
                self.usable = false;
            }
            return Err(E::HostFailure {
                errno,
                rollback_succeeded: restored,
            });
        }
        self.regions = next;
        Ok(())
    }

    fn validate_access(&self, address: u64, length: usize, write: bool) -> Result<()> {
        ensure!(
            self.usable,
            "guest address space is unusable after failed protection rollback"
        );
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

    /// Validate one complete private data write without changing any bytes.
    /// Platform copyout owners select whether whole-range preflight is appropriate.
    pub fn validate_write(&self, address: u64, length: usize) -> Result<()> {
        self.validate_access(address, length, true)
    }

    pub fn read_snapshot(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        self.validate_access(address, length, false)?;
        if let Some(shared) = &self.shared {
            return shared
                .domain
                .service_loan()
                .map_err(SharedBindingError::Domain)?
                .snapshot(address, length)
                .map_err(SharedBindingError::Domain)
                .map_err(Into::into);
        }
        let mut bytes = vec![0; length];
        for (start, count, offset) in self.access_spans(address, length) {
            // SAFETY: all requested bytes belong to live readable regions, the
            // destination is independent, and this owner cannot cross threads.
            // Each copy stays within one mmap allocation.
            unsafe {
                core::ptr::copy_nonoverlapping(
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
        if self.shared.is_some() {
            return self.write_shared(address, bytes);
        }
        for (start, count, offset) in self.access_spans(address, bytes.len()) {
            // SAFETY: the exclusive owner validated every byte as writable;
            // callers cannot obtain references into these allocations safely.
            // Each copy stays within one mmap allocation.
            unsafe {
                core::ptr::copy_nonoverlapping(
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

#[cfg(feature = "std")]
fn host_protection(readable: bool, writable: bool) -> i32 {
    (if readable {
        libc::PROT_READ
    } else {
        libc::PROT_NONE
    }) | (if writable { libc::PROT_WRITE } else { 0 })
}

/// Runtime-published data with a permanently read-only, non-executable guest
/// view and an unexposed writable alias. Publication and translated accesses
/// must be serialized by the caller; this is not a concurrent kernel seqlock.
pub struct PublishedReadOnlyRegion {
    shared: Option<Arc<SharedBinding>>,
    shared_backing: Option<Arc<backing::MemoryBacking>>,
    region: MemoryRegion,
    storage: Arc<NativeStorage>,
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
        // SAFETY: exact newly owned RO pages with checked complete extent;
        // native accesses remain serialized and no guest references escape.
        let guest_mapping = unsafe {
            NativeMapping::adopt(
                core::ptr::NonNull::new(guest.cast()).expect("nonzero exact mapping"),
                bytes as usize,
            )
        };
        // SAFETY: the kernel chooses a separate new mapping of the owned backing.
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
        // SAFETY: live RO mapping, bounded copy, independent owned destination;
        // publication cannot run concurrently through this non-Send/Sync owner.
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

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests;
