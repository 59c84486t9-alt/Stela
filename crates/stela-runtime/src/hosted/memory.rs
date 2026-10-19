//! Guest memory as the hosted kernel reaches it: the host process's own
//! address space at the guest's addresses, in the guest's 16 KiB pages.
//!
//! The x86 host allocates in 4 KiB pages. Every allocation the hosted kernel
//! makes for the guest is 16 KiB aligned and sized (`mach_vm_map` with a
//! 16 KiB mask), so guest page arithmetic over `vm_page_size` holds. Copies
//! go through the host kernel and refuse unmapped or protected pages.
use anyhow::{Context as _, Result, bail, ensure};

/// The arm64 user page: XNU `PAGE_SHIFT` 14 on Apple silicon.
pub const PAGE_SHIFT: u32 = 14;
pub const PAGE_BYTES: u64 = 1 << PAGE_SHIFT;
pub const PAGE_MASK: u64 = PAGE_BYTES - 1;
/// `VM_FLAGS_FIXED`, `VM_FLAGS_ANYWHERE`.
pub const VM_FLAGS_FIXED: i32 = 0;
pub const VM_FLAGS_ANYWHERE: i32 = 1;
const VM_PROT_READ: i32 = 1;
const VM_PROT_WRITE: i32 = 2;
const VM_PROT_EXECUTE: i32 = 4;
const VM_INHERIT_COPY: u32 = 1;
const VM_REGION_BASIC_INFO_64: i32 = 9;
const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;
const KERN_SUCCESS: i32 = 0;
/// The longest C string the kernel copies in (`MAXPATHLEN` is 1024; sysctl
/// names and the like are shorter).
pub const MAX_STRING: usize = 4096;

pub const fn trunc_page(address: u64) -> u64 {
    address & !PAGE_MASK
}

pub const fn round_page(address: u64) -> Option<u64> {
    match address.checked_add(PAGE_MASK) {
        Some(end) => Some(end & !PAGE_MASK),
        None => None,
    }
}

/// The x86 host's 4 KiB page, the granule of its file mappings.
pub const HOST_PAGE_MASK: u64 = 0xfff;

pub const fn round_host_page(address: u64) -> Option<u64> {
    match address.checked_add(HOST_PAGE_MASK) {
        Some(end) => Some(end & !HOST_PAGE_MASK),
        None => None,
    }
}

unsafe extern "C" {
    fn mach_vm_region(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
        object: *mut u32,
    ) -> i32;
    fn mach_vm_map(
        task: u32,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        object: u32,
        offset: u64,
        copy: i32,
        current: i32,
        maximum: i32,
        inheritance: u32,
    ) -> i32;
    fn mach_vm_deallocate(task: u32, address: u64, size: u64) -> i32;
    fn mach_vm_remap(
        target: u32,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        source_task: u32,
        source: u64,
        copy: i32,
        current: *mut i32,
        maximum: *mut i32,
        inheritance: u32,
    ) -> i32;
    fn mach_vm_protect(
        task: u32,
        address: u64,
        size: u64,
        set_maximum: i32,
        protection: i32,
    ) -> i32;
}

fn task() -> u32 {
    super::host::task()
}

/// Whether `address` lies in any mapping of this process.
pub fn mapped(address: u64) -> bool {
    let mut start = address;
    let mut size = 0u64;
    let mut info = [0i32; VM_REGION_BASIC_INFO_COUNT_64 as usize];
    let mut count = VM_REGION_BASIC_INFO_COUNT_64;
    let mut object = 0u32;
    // SAFETY: out-parameters sized for VM_REGION_BASIC_INFO_64.
    let status = unsafe {
        mach_vm_region(
            task(),
            &mut start,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr(),
            &mut count,
            &mut object,
        )
    };
    status == KERN_SUCCESS && start <= address
}

/// The current and maximum protections of the mapping holding `address`.
fn protections(address: u64) -> Option<(Protection, Protection)> {
    let mut start = address;
    let mut size = 0u64;
    let mut info = [0i32; VM_REGION_BASIC_INFO_COUNT_64 as usize];
    let mut count = VM_REGION_BASIC_INFO_COUNT_64;
    let mut object = 0u32;
    // SAFETY: out-parameters sized for VM_REGION_BASIC_INFO_64, whose
    // first fields are the current and maximum protections.
    let status = unsafe {
        mach_vm_region(
            task(),
            &mut start,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr(),
            &mut count,
            &mut object,
        )
    };
    (status == KERN_SUCCESS && start <= address).then(|| (Protection(info[0]), Protection(info[1])))
}

/// Whether the mapping holding `address` grants every protection bit of
/// `access` now.
pub fn permits(address: u64, access: Protection) -> bool {
    protections(address).is_some_and(|(current, _)| current.0 & access.0 == access.0)
}

/// Guest protections as `VM_PROT_*` bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection(pub i32);

impl Protection {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(VM_PROT_READ);
    pub const READ_WRITE: Self = Self(VM_PROT_READ | VM_PROT_WRITE);
    pub const READ_EXECUTE: Self = Self(VM_PROT_READ | VM_PROT_EXECUTE);
    pub const ALL: Self = Self(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    /// From Mach-O `initprot`/`maxprot` bits, which use the same values.
    pub fn from_mach_o(bits: u32) -> Self {
        Self(bits as i32 & Self::ALL.0)
    }

    pub fn writable(self) -> bool {
        self.0 & VM_PROT_WRITE != 0
    }

    pub fn executable(self) -> bool {
        self.0 & VM_PROT_EXECUTE != 0
    }
}

/// `mach_vm_map` of anonymous memory as the guest requests it, in 16 KiB
/// pages: the size rounded up and the alignment at least a page. Returns
/// the host's `kern_return_t` and the placed address.
#[allow(clippy::too_many_arguments)]
pub fn map_anonymous(
    address: u64,
    bytes: u64,
    mask: u64,
    flags: i32,
    copy: bool,
    current: Protection,
    maximum: Protection,
    inheritance: u32,
) -> (i32, u64) {
    const KERN_INVALID_ARGUMENT: i32 = 4;
    let Some(size) = round_page(bytes) else {
        return (KERN_INVALID_ARGUMENT, address);
    };
    let mut at = address;
    // SAFETY: anonymous memory placed as the guest asked; overwriting is
    // the guest's own request (`VM_FLAGS_OVERWRITE`).
    let status = unsafe {
        mach_vm_map(
            task(),
            &mut at,
            size,
            mask | PAGE_MASK,
            flags,
            0,
            0,
            i32::from(copy),
            current.0,
            maximum.0,
            inheritance,
        )
    };
    (status, at)
}

/// Replace the host pages of `[address, address + bytes)` with zeroed
/// anonymous memory: the rest of a guest page a shorter host mapping
/// leaves.
pub fn fill_host_pages(address: u64, bytes: u64, protection: Protection) -> i32 {
    const VM_FLAGS_OVERWRITE: i32 = 0x4000;
    let mut at = address;
    // SAFETY: the caller's own range, which it replaces.
    unsafe {
        mach_vm_map(
            task(),
            &mut at,
            bytes,
            0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            0,
            0,
            0,
            protection.0,
            Protection::ALL.0,
            VM_INHERIT_COPY,
        )
    }
}

/// `mach_vm_map` of a memory object (a host memory entry) as the guest
/// requests it. The object is mapped in the host's pages, as the entry's
/// size may be (an x86 process made it); a placement the guest leaves to
/// the kernel reserves the whole 16 KiB range first, so no other
/// allocation shares the guest page, and maps the object over its start.
#[allow(clippy::too_many_arguments)]
pub fn map_object(
    address: u64,
    bytes: u64,
    mask: u64,
    flags: i32,
    object: u32,
    offset: u64,
    copy: bool,
    current: Protection,
    maximum: Protection,
    inheritance: u32,
) -> (i32, u64) {
    const KERN_INVALID_ARGUMENT: i32 = 4;
    const VM_FLAGS_OVERWRITE: i32 = 0x4000;
    let (Some(size), Some(object_size)) = (round_page(bytes), round_host_page(bytes)) else {
        return (KERN_INVALID_ARGUMENT, address);
    };
    let anywhere = flags & VM_FLAGS_ANYWHERE != 0;
    let mut at = address;
    if anywhere {
        let (status, reserved) = map_anonymous(
            address,
            size,
            mask,
            flags,
            false,
            Protection::NONE,
            maximum,
            inheritance,
        );
        if status != KERN_SUCCESS {
            return (status, address);
        }
        at = reserved;
    }
    let placement = if anywhere {
        (flags & !VM_FLAGS_ANYWHERE) | VM_FLAGS_OVERWRITE
    } else {
        flags
    };
    // SAFETY: the object is mapped where the guest asked, or over the
    // reservation just made for it.
    let status = unsafe {
        mach_vm_map(
            task(),
            &mut at,
            object_size,
            0,
            placement,
            object,
            offset,
            i32::from(copy),
            current.0,
            maximum.0,
            inheritance,
        )
    };
    if status != KERN_SUCCESS && anywhere {
        // SAFETY: the reservation made above.
        unsafe { mach_vm_deallocate(task(), at, size) };
    }
    if status == KERN_SUCCESS
        && anywhere
        && size > object_size
        && let Some((current, maximum)) = protections(at)
    {
        // The arm64 kernel maps the last guest page whole: the reserved
        // tail takes the object's own protections, which the host may
        // have lowered from the request (a read-only entry), maximum
        // first.
        let tail = at + object_size;
        // SAFETY: the tail of the reservation made above.
        unsafe {
            mach_vm_protect(task(), tail, size - object_size, 1, maximum.0);
            mach_vm_protect(task(), tail, size - object_size, 0, current.0);
        }
    }
    (status, at)
}

/// Allocate zeroed guest pages: at `address` when `anywhere` is false
/// (refusing an occupied range), else wherever the host finds room, 16 KiB
/// aligned either way.
pub fn allocate(address: u64, bytes: u64, anywhere: bool, protection: Protection) -> Result<u64> {
    let size = round_page(bytes).context("allocation size overflow")?;
    ensure!(size != 0, "empty allocation");
    let mut at = address;
    let flags = if anywhere {
        VM_FLAGS_ANYWHERE
    } else {
        VM_FLAGS_FIXED
    };
    // SAFETY: anonymous memory; a fixed request never overwrites.
    let status = unsafe {
        mach_vm_map(
            task(),
            &mut at,
            size,
            PAGE_MASK,
            flags,
            0,
            0,
            0,
            protection.0,
            Protection::ALL.0,
            VM_INHERIT_COPY,
        )
    };
    if status != KERN_SUCCESS {
        bail!("cannot allocate {size:#x} guest bytes at {address:#x}: kern_return {status}");
    }
    Ok(at)
}

/// Move memory the host kernel placed for this process in its own 4 KiB
/// pages (a received out-of-line region) to guest pages of its own: the
/// arm64 kernel places such memory in whole 16 KiB pages, and the guest
/// releases it rounded to them, which would release a neighbor sharing
/// the host placement's guest pages. Returns the region's new address,
/// at the same offset in its first host page, or `None` when the region
/// already fills whole guest pages.
pub fn own_guest_pages(address: u64, bytes: u64) -> Result<Option<u64>> {
    const VM_FLAGS_OVERWRITE: i32 = 0x4000;
    if bytes == 0 {
        return Ok(None);
    }
    let start = address & !HOST_PAGE_MASK;
    let end = address
        .checked_add(bytes)
        .and_then(round_host_page)
        .context("received region overflows")?;
    if (start | end) & PAGE_MASK == 0 {
        return Ok(None);
    }
    let size = end - start;
    let reserved = allocate(0, size, true, Protection::READ_WRITE)?;
    let mut at = reserved;
    let (mut current, mut maximum) = (0, 0);
    // SAFETY: the host pages move over the start of the reservation just
    // made; the region was the caller's own.
    let status = unsafe {
        mach_vm_remap(
            task(),
            &mut at,
            size,
            0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            task(),
            start,
            0,
            &mut current,
            &mut maximum,
            VM_INHERIT_COPY,
        )
    };
    if status != KERN_SUCCESS {
        deallocate(reserved, size)?;
        bail!("cannot move {size:#x} received bytes at {start:#x}: kern_return {status}");
    }
    deallocate(start, size)?;
    Ok(Some(reserved + (address - start)))
}

pub fn deallocate(address: u64, bytes: u64) -> Result<()> {
    // SAFETY: the caller names guest pages it owns.
    let status = unsafe { mach_vm_deallocate(task(), address, bytes) };
    ensure!(
        status == KERN_SUCCESS,
        "cannot deallocate {bytes:#x} bytes at {address:#x}: kern_return {status}"
    );
    Ok(())
}

pub fn protect(address: u64, bytes: u64, protection: Protection) -> Result<()> {
    // SAFETY: the caller names guest pages it owns.
    let status = unsafe { mach_vm_protect(task(), address, bytes, 0, protection.0) };
    ensure!(
        status == KERN_SUCCESS,
        "cannot protect {bytes:#x} bytes at {address:#x}: kern_return {status}"
    );
    Ok(())
}

/// Copy guest bytes in, or `None` when any page is unreadable (EFAULT).
pub fn read(address: u64, bytes: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0; bytes];
    super::host::copy_in(address, &mut buffer).then_some(buffer)
}

pub fn read_u64(address: u64) -> Option<u64> {
    let mut word = [0u8; 8];
    super::host::copy_in(address, &mut word).then(|| u64::from_le_bytes(word))
}

pub fn read_u32(address: u64) -> Option<u32> {
    let mut word = [0u8; 4];
    super::host::copy_in(address, &mut word).then(|| u32::from_le_bytes(word))
}

pub fn write(address: u64, data: &[u8]) -> bool {
    super::host::copy_out(address, data)
}

pub fn write_u64(address: u64, value: u64) -> bool {
    write(address, &value.to_le_bytes())
}

pub fn write_u32(address: u64, value: u32) -> bool {
    write(address, &value.to_le_bytes())
}

/// A NUL-terminated guest string without its terminator, or `None` when it
/// is unreadable or longer than `limit` (ENAMETOOLONG for paths).
pub fn read_string(address: u64, limit: usize) -> Option<Vec<u8>> {
    let mut string = Vec::new();
    let mut cursor = address;
    loop {
        // Never read past the current page: the next may be unmapped.
        let chunk = (PAGE_BYTES - (cursor & PAGE_MASK)) as usize;
        let bytes = read(cursor, chunk.min(limit + 1 - string.len()))?;
        if let Some(end) = bytes.iter().position(|&byte| byte == 0) {
            string.extend_from_slice(&bytes[..end]);
            return Some(string);
        }
        string.extend_from_slice(&bytes);
        if string.len() > limit {
            return None;
        }
        cursor += bytes.len() as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocations_are_guest_pages_and_strings_stop_at_nul() {
        let address = allocate(0, 100, true, Protection::READ_WRITE).unwrap();
        assert_eq!(address & PAGE_MASK, 0);
        assert!(mapped(address) && mapped(address + PAGE_BYTES - 1));
        assert!(write(address, b"hello\0world"));
        assert_eq!(read_string(address, 64).unwrap(), b"hello");
        assert!(read_string(address + 6, 3).is_none());
        // The string ends exactly at the page's last byte.
        assert!(write(address + PAGE_BYTES - 3, b"ab\0"));
        assert_eq!(read_string(address + PAGE_BYTES - 3, 64).unwrap(), b"ab");
        protect(address, PAGE_BYTES, Protection::READ).unwrap();
        assert!(!write(address, b"x"));
        assert!(permits(address, Protection::READ));
        assert!(!permits(address, Protection::READ_WRITE));
        assert_eq!(read_u32(address).unwrap(), u32::from_le_bytes(*b"hell"));
        assert!(allocate(address, PAGE_BYTES, false, Protection::READ).is_err());
        // Inaccessible pages refuse copies (a freed page could be reused by
        // a concurrent test before the check).
        protect(address, PAGE_BYTES, Protection::NONE).unwrap();
        assert!(read_u64(address).is_none());
        deallocate(address, PAGE_BYTES).unwrap();
        assert_eq!(round_page(1), Some(PAGE_BYTES));
        assert_eq!(trunc_page(PAGE_BYTES + 5), PAGE_BYTES);
        assert_eq!(round_page(u64::MAX), None);
    }

    #[test]
    fn the_rest_of_a_guest_page_fills_with_zeros() {
        let at = allocate(0, PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        assert!(write_u64(at, 7) && write_u64(at + 0x2000, 9));
        assert_eq!(
            fill_host_pages(at + 0x1000, PAGE_BYTES - 0x1000, Protection::READ),
            KERN_SUCCESS
        );
        assert_eq!(read_u64(at), Some(7));
        assert_eq!(read_u64(at + 0x2000), Some(0));
        assert_eq!(
            protections(at + 0x2000),
            Some((Protection::READ, Protection::ALL))
        );
        deallocate(at, PAGE_BYTES).unwrap();
    }

    #[test]
    fn an_object_mapped_anywhere_fills_its_last_guest_page() {
        unsafe extern "C" {
            fn mach_make_memory_entry_64(
                task: u32,
                size: *mut u64,
                offset: u64,
                permission: i32,
                entry: *mut u32,
                parent: u32,
            ) -> i32;
        }
        let source = allocate(0, PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        let (mut size, mut entry) = (0x1000u64, 0u32);
        // SAFETY: a read-only entry over the first host page of `source`.
        let status = unsafe {
            mach_make_memory_entry_64(task(), &mut size, source, VM_PROT_READ, &mut entry, 0)
        };
        assert_eq!((status, size), (KERN_SUCCESS, 0x1000));
        let (status, at) = map_object(
            0,
            0x1000,
            0,
            VM_FLAGS_ANYWHERE,
            entry,
            0,
            false,
            Protection::READ,
            Protection::READ,
            VM_INHERIT_COPY,
        );
        assert_eq!(status, KERN_SUCCESS);
        assert_eq!(at & PAGE_MASK, 0);
        assert_eq!(
            protections(at + PAGE_BYTES - 8),
            Some((Protection::READ, Protection::READ))
        );
        assert!(read_u64(at + PAGE_BYTES - 8).is_some());
        deallocate(at, PAGE_BYTES).unwrap();
        deallocate(source, PAGE_BYTES).unwrap();
    }

    #[test]
    fn received_host_pages_move_to_guest_pages_of_their_own() {
        let block = allocate(0, 2 * PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        // A region in the second host page of the first guest page, as the
        // host kernel may place one.
        let region = block + 0x1000 + 0x10;
        assert!(write(region, b"payload"));
        let moved = own_guest_pages(region, 0x2000).unwrap().unwrap();
        assert_eq!(moved & PAGE_MASK, 0x10);
        assert_eq!(read(moved, 7).unwrap(), b"payload");
        // The old host pages are gone, the guest page's other host pages
        // stay, and the new region fills its guest page alone.
        assert!(read_u64(block + 0x1000).is_none());
        assert!(read_u64(block).is_some());
        assert!(read_u64(moved - 0x10 + PAGE_BYTES - 8).is_some());
        assert_eq!(
            own_guest_pages(block + PAGE_BYTES, PAGE_BYTES).unwrap(),
            None
        );
        deallocate(moved & !PAGE_MASK, PAGE_BYTES).unwrap();
        deallocate(block, 0x1000).unwrap();
        deallocate(block + 0x4000, 2 * PAGE_BYTES - 0x4000).unwrap();
    }
}
