//! Placing guest regions at their exact addresses, from bytes or files.
use super::DataProtectionLimit;
#[cfg(host_memory)]
use super::storage::NativeMapping;
#[cfg(host_memory)]
use super::storage::NativeStorage;
#[cfg(host_memory)]
use super::{
    Allocation, DIRECT_RAM_USER_END, DataInheritance, MAX_FILE_MEMORY_BYTES,
    MAX_IMAGE_MEMORY_BYTES, MemoryRegion, host_page_size,
};
use super::{MemoryRegionSpec, OwnedMemory};
use crate::Result;
#[cfg(host_memory)]
use crate::error::Io;
#[cfg(host_memory)]
use alloc::collections::BTreeMap;
#[cfg(not(host_memory))]
use alloc::vec::Vec;
#[cfg(host_memory)]
use core::marker::PhantomData;
#[cfg(host_memory)]
use std::fs::File;
#[cfg(host_memory)]
use std::os::fd::AsRawFd;
use stela_contracts::refuse;
#[cfg(host_memory)]
use stela_contracts::require;

/// Exact-address private mapping of existing ordinary file bytes, without a
/// heap copy or implicit guest-visible BSS. The logical extent must fit the file;
/// host-page rounding may include the file's final partial page, whose padding
/// is never exposed through the safe guest-memory API.
///
/// Allocation storage keeps the file descriptor. MAP_PRIVATE prevents our writes
/// from modifying the file; it does not freeze unrelated writes/truncation to
/// that inode. Source identity, provenance and stability for the entire mapping
/// lifetime are the caller's responsibility. Truncation can cause native faults.
#[cfg(host_memory)]
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

#[cfg(host_memory)]
pub(super) enum InitialMemory {
    Anonymous(Vec<u8>),
    File { file: File, offset: u64 },
}

#[cfg(host_memory)]
pub(super) struct MappingSpec {
    guest_address: u64,
    virtual_bytes: u64,
    readable: bool,
    writable: bool,
    executable: bool,
    initial: InitialMemory,
}

#[cfg(host_memory)]
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

#[cfg(host_memory)]
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

#[cfg(host_memory)]
pub(super) fn page_rounded(bytes: u64, page: u64) -> Result<u64> {
    Ok(bytes
        .checked_add(page - 1)
        .ok_or(refuse!("guest mapping size overflow"))?
        & !(page - 1))
}

impl OwnedMemory {
    #[cfg(host_memory)]
    pub fn map(specs: Vec<MemoryRegionSpec>) -> Result<Self> {
        Self::map_specs(
            specs.into_iter().map(MappingSpec::from).collect(),
            MAX_IMAGE_MEMORY_BYTES,
            BTreeMap::new(),
        )
    }

    #[cfg(not(host_memory))]
    pub fn map(specs: Vec<MemoryRegionSpec>) -> Result<Self> {
        let _ = specs;
        Err(refuse!("freestanding guest RAM mappings are not mounted").into())
    }

    #[cfg(host_memory)]
    pub fn map_with_data_limits(
        specs: Vec<MemoryRegionSpec>,
        limits: Vec<DataProtectionLimit>,
    ) -> Result<Self> {
        let mut table = BTreeMap::new();
        for limit in limits {
            require!(
                table.insert(limit.guest_address, limit).is_none(),
                "duplicate data protection limit"
            );
        }
        for (&address, limit) in &table {
            let spec = specs
                .iter()
                .find(|s| s.guest_address == address)
                .ok_or(refuse!("data protection limit has no mapping"))?;
            require!(
                !spec.executable,
                "data protection limit cannot grant executable source rights"
            );
            require!(
                !limit.writable || limit.readable,
                "maximum write permission requires read permission"
            );
            require!(
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

    #[cfg(not(host_memory))]
    pub fn map_with_data_limits(
        specs: Vec<MemoryRegionSpec>,
        limits: Vec<DataProtectionLimit>,
    ) -> Result<Self> {
        let _ = (specs, limits);
        Err(refuse!("freestanding guest RAM mappings are not mounted").into())
    }

    /// Map owned file-backed regions without copying their contents.
    ///
    /// # Safety
    /// The contents and length of every backing file must stay unchanged while
    /// the returned owner lives, including during construction: no writes or
    /// truncation through other descriptors or processes. Private copy-on-write
    /// writes through this owner do not change the file. Renaming a path to
    /// another file does not affect the mapping.
    #[cfg(host_memory)]
    pub unsafe fn map_files(specs: Vec<FileMemoryRegionSpec>) -> Result<Self> {
        Self::map_specs(
            specs.into_iter().map(MappingSpec::from).collect(),
            MAX_FILE_MEMORY_BYTES,
            BTreeMap::new(),
        )
    }

    #[cfg(host_memory)]
    pub(super) fn map_specs(
        mut specs: Vec<MappingSpec>,
        limit: u64,
        limits: BTreeMap<u64, DataProtectionLimit>,
    ) -> Result<Self> {
        require!(
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
            require!(
                spec.guest_address >= page && spec.guest_address.is_multiple_of(page),
                "guest address must be nonzero and host-page aligned"
            );
            require!(
                spec.virtual_bytes > 0,
                "guest virtual size must be positive"
            );
            let mapped_bytes = page_rounded(spec.virtual_bytes, page)?;
            let end = spec
                .guest_address
                .checked_add(mapped_bytes)
                .ok_or(refuse!("guest mapping address overflow"))?;
            require!(
                end <= DIRECT_RAM_USER_END,
                "guest mapping exceeds canonical user range"
            );
            usize::try_from(end)
                .map_err(|_| refuse!("guest mapping exceeds native address range"))?;
            require!(spec.guest_address >= previous_end, "guest mappings overlap");
            match &spec.initial {
                InitialMemory::Anonymous(bytes) => require!(
                    bytes.len() as u64 <= spec.virtual_bytes,
                    "initial bytes exceed guest virtual size"
                ),
                InitialMemory::File { file, offset } => {
                    require!(
                        offset.is_multiple_of(page),
                        "file mapping offset must be host-page aligned"
                    );
                    libc::off_t::try_from(*offset)
                        .map_err(|_| refuse!("file mapping offset exceeds native range"))?;
                    let metadata = file.metadata().io("inspect backing file")?;
                    require!(metadata.is_file(), "file mapping requires an ordinary file");
                    let file_end = offset
                        .checked_add(spec.virtual_bytes)
                        .ok_or(refuse!("file mapping extent overflow"))?;
                    require!(
                        file_end <= metadata.len(),
                        "file mapping exceeds backing file bytes"
                    );
                    // SAFETY: File owns a live descriptor; F_GETFL has no extra
                    // arguments and does not mutate file contents or position.
                    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
                    if flags == -1 {
                        return Err(std::io::Error::last_os_error())
                            .io("inspect backing file access mode");
                    }
                    require!(
                        flags & libc::O_ACCMODE != libc::O_WRONLY,
                        "backing file descriptor is not readable"
                    );
                }
            }
            require!(
                !(spec.writable && spec.executable),
                "writable guest code is unsupported"
            );
            require!(
                !spec.writable || spec.readable,
                "write-only guest memory is unsupported by the x86-64 protection profile"
            );
            total = total
                .checked_add(mapped_bytes)
                .ok_or(refuse!("guest mapping size overflow"))?;
            require!(total <= limit, "guest mappings exceed memory limit");
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
                        .map_err(|_| refuse!("file mapping offset exceeds native range"))?,
                    spec.virtual_bytes as usize,
                ),
            };
            let flags = libc::MAP_PRIVATE | source_flags;
            #[cfg(target_os = "linux")]
            // Linux >=4.17 refuses occupied addresses atomically. Older
            // kernels may ignore this flag; the exact-address check below
            // also handles that case without ever using MAP_FIXED.
            let flags = flags | libc::MAP_FIXED_NOREPLACE;
            // SAFETY: a private allocation that replaces no mapping, with
            // validated size and extent. The descriptors stay open, and the
            // pointer is checked before use.
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
                return Err(std::io::Error::last_os_error())
                    .io(refuse!("map a guest range", address = spec.guest_address));
            }
            if mapped != requested {
                // SAFETY: this allocation belongs to this call, including when
                // macOS substituted a non-overlapping address for an occupied hint.
                unsafe { libc::munmap(mapped, length) };
                return Err(refuse!(
                    "requested guest address is unavailable",
                    address = spec.guest_address
                )
                .into());
            }
            // SAFETY: newly owned whole pages with a checked address and
            // extent, coherent write-back storage and no guest references
            // escaping.
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
            // Register kept ownership before any later operation can fail.
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
                return Err(std::io::Error::last_os_error()).io("protect guest mapping");
            }
        }
        Ok(memory)
    }
}
