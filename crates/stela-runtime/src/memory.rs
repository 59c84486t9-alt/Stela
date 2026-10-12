//! Owned guest-address mappings for the direct-RAM native execution profile.
//!
//! Original Arm instructions are data to the x86 host: a guest executable
//! region never receives host execute permission. Mapping must succeed at the
//! requested address without replacing any existing allocation.

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::marker::PhantomData;
use std::rc::Rc;

pub const MAX_IMAGE_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
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
    pub fn map(mut specs: Vec<MemoryRegionSpec>) -> Result<Self> {
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
            ensure!(
                spec.initial_bytes.len() as u64 <= spec.virtual_bytes,
                "initial bytes exceed guest virtual size"
            );
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
            ensure!(
                total <= MAX_IMAGE_MEMORY_BYTES,
                "guest mappings exceed image memory limit"
            );
            previous_end = end;
        }

        let mut memory = Self {
            regions: Vec::new(),
            _not_send_sync: PhantomData,
        };
        for spec in specs {
            let mapped_bytes = page_rounded(spec.virtual_bytes, page)?;
            let length = mapped_bytes as usize;
            let requested = spec.guest_address as usize as *mut libc::c_void;
            let flags = libc::MAP_PRIVATE | libc::MAP_ANON;
            #[cfg(target_os = "linux")]
            // Linux >=4.17 refuses occupied addresses atomically. Older
            // kernels may ignore this flag; the exact-address check below
            // also handles that case without ever using MAP_FIXED.
            let flags = flags | libc::MAP_FIXED_NOREPLACE;
            // SAFETY: anonymous private allocation, no host mapping replacement,
            // validated bounded size. The returned pointer is checked before use.
            let mapped = unsafe {
                libc::mmap(
                    requested,
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    flags,
                    -1,
                    0,
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
                initial_bytes: spec.initial_bytes.len(),
                readable: spec.readable,
                writable: spec.writable,
                executable: spec.executable,
            });
            // SAFETY: the exact anonymous allocation is RW, initial bytes fit,
            // and the source Vec cannot overlap this freshly allocated range.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    spec.initial_bytes.as_ptr(),
                    mapped.cast::<u8>(),
                    spec.initial_bytes.len(),
                );
            }
            // Anonymous mmap supplies zeros for the remaining virtual tail.
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

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::*;

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
