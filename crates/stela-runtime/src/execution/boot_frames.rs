//! Boot-reserved storage backing native images in the freestanding build.
#![cfg(all(target_arch = "x86_64", target_os = "uefi"))]

use super::native_image::ExecutableStorage;
use crate::platform::sync::Mutex;
use alloc::sync::Arc;
use core::{arch::asm, ptr::NonNull};

const PAGE_SHIFT: u32 = 12;
const PAGE_BYTES: usize = 1 << PAGE_SHIFT;
const TABLE_INDEX_BITS: u32 = 9;
const TABLE_ENTRIES: usize = 1 << TABLE_INDEX_BITS;
const TABLE_INDEX_MASK: usize = TABLE_ENTRIES - 1;
const PARENT_SHIFTS: [u32; 3] = [
    PAGE_SHIFT + 3 * TABLE_INDEX_BITS,
    PAGE_SHIFT + 2 * TABLE_INDEX_BITS,
    PAGE_SHIFT + TABLE_INDEX_BITS,
];
const BITMAP_WORD_BITS: usize = u64::BITS as usize;
const ARENA_ALIGNMENT: usize = PAGE_BYTES * TABLE_ENTRIES;
const BITMAP_WORDS: usize = TABLE_ENTRIES / u64::BITS as usize;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
const NO_EXECUTE: u64 = 1 << 63;
const CPUID_EXTENDED_MAX: u32 = 0x8000_0000;
const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
const CPUID_ADDRESS_SIZE: u32 = 0x8000_0008;
const CPUID_NX: u32 = 1 << 20;
const CPUID_PHYSICAL_BITS_MASK: u32 = 0xff;
const MIN_PHYSICAL_BITS: u32 = 32;
const MAX_PHYSICAL_BITS: u32 = 52;
const CR0_PROTECTED: u64 = 1;
const CR0_WRITE_PROTECT: u64 = 1 << 16;
const CR0_PAGING: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;
const CR4_GLOBAL: u64 = 1 << 7;
const CR4_LA57: u64 = 1 << 12;
const CR4_PCID: u64 = 1 << 17;
const EFER_MSR: u32 = 0xc000_0080;
const EFER_LONG_ACTIVE: u64 = 1 << 10;
const EFER_NX_ENABLE: u64 = 1 << 11;
const LOWER_CANONICAL_END: usize = 1 << 47;
const PRIVILEGE_MASK: u16 = 3;
const INTERRUPT_ENABLE: u64 = 1 << 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    UnsupportedControls,
    InvalidArena,
    InvalidParent,
    ArenaAlreadyMapped,
    Exhausted,
    Busy,
    EmptyNative,
    ChangedRoot,
    ChangedParent,
    ChangedProtection,
    Quarantined,
}

struct Controls {
    root: u64,
    address_mask: u64,
}

// Privileged reads only; this component never changes root, WP, NXE or security.
fn controls() -> Result<Controls, FrameError> {
    let selector: u16;
    let flags: u64;
    // SAFETY: reading CS and RFLAGS is unprivileged and does not alter state.
    unsafe {
        asm!("mov {0:x}, cs", out(reg) selector, options(nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    if selector & PRIVILEGE_MASK != 0 || flags & INTERRUPT_ENABLE != 0 {
        return Err(FrameError::UnsupportedControls);
    }
    let (cr0, cr3, cr4): (u64, u64, u64);
    let (low, high): (u32, u32);
    // SAFETY: module is restricted to the freestanding x86 kernel platform.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
        asm!("rdmsr", in("ecx") EFER_MSR, out("eax") low, out("edx") high,
            options(nostack, preserves_flags));
    }
    // SAFETY: CPUID is available on all x86-64 processors. Query only reported leaves.
    let maximum_leaf = core::arch::x86_64::__cpuid(CPUID_EXTENDED_MAX).eax;
    if maximum_leaf < CPUID_ADDRESS_SIZE {
        return Err(FrameError::UnsupportedControls);
    }
    let features = core::arch::x86_64::__cpuid(CPUID_EXTENDED_FEATURES);
    let physical_bits =
        core::arch::x86_64::__cpuid(CPUID_ADDRESS_SIZE).eax & CPUID_PHYSICAL_BITS_MASK;
    if features.edx & CPUID_NX == 0
        || !(MIN_PHYSICAL_BITS..=MAX_PHYSICAL_BITS).contains(&physical_bits)
    {
        return Err(FrameError::UnsupportedControls);
    }
    let address_mask = ((1u64 << physical_bits) - 1) & !(PAGE_BYTES as u64 - 1);
    let efer = u64::from(low) | (u64::from(high) << u32::BITS);
    let required_cr0 = CR0_PROTECTED | CR0_WRITE_PROTECT | CR0_PAGING;
    let required_efer = EFER_LONG_ACTIVE | EFER_NX_ENABLE;
    if cr0 & required_cr0 != required_cr0
        || cr4 & CR4_PAE == 0
        || cr4 & (CR4_GLOBAL | CR4_LA57 | CR4_PCID) != 0
        || efer & required_efer != required_efer
        || cr3 == 0
        || cr3 & !address_mask != 0
        || cr3 >= LOWER_CANONICAL_END as u64
    {
        return Err(FrameError::UnsupportedControls);
    }
    Ok(Controls {
        root: cr3,
        address_mask,
    })
}

#[derive(Clone, Copy)]
struct Parent {
    slot: usize,
    expected: u64,
}

struct Allocation {
    occupied: [u64; BITMAP_WORDS],
    permissions: [u64; TABLE_ENTRIES],
}

impl Allocation {
    fn used(&self, page: usize) -> bool {
        self.occupied[page / BITMAP_WORD_BITS] & (1 << (page % BITMAP_WORD_BITS)) != 0
    }
    fn mark(&mut self, first: usize, pages: usize, occupied: bool) {
        for page in first..first + pages {
            let bit = 1 << (page % BITMAP_WORD_BITS);
            if occupied {
                self.occupied[page / BITMAP_WORD_BITS] |= bit;
            } else {
                self.occupied[page / BITMAP_WORD_BITS] &= !bit;
                self.permissions[page] = 0;
            }
        }
    }
    fn find(&self, total: usize, pages: usize) -> Option<usize> {
        if pages > total {
            return None;
        }
        (0..=total - pages).find(|&first| (first..first + pages).all(|page| !self.used(page)))
    }
}

/// Owns one boot-reserved identity-mapped arena and its active 4 KiB page
/// table. A lock serializes allocation and PTE writes. Table locations are
/// stored as integers, so no Rust references alias them.
pub(crate) struct BootFramePool {
    base: usize,
    pages: usize,
    root: u64,
    parents: [Parent; 3],
    table: usize,
    allocation: Mutex<Allocation>,
    failure: Mutex<Option<FrameError>>,
}

impl BootFramePool {
    /// Claim boot-reserved frames and their empty page table.
    ///
    /// # Safety
    /// Run at CPL0 after four-level identity paging is installed, with every
    /// table page reachable from CR3 identity-mapped Normal write-back memory.
    /// `base` is a 2 MiB-aligned reservation of `pages` (1 to 512) whole
    /// frames; they and their page table are owned here for the rest of the
    /// boot. Nothing else (aliases, huge or global mappings, allocators,
    /// firmware, DMA, interrupt handlers, other CPUs) may access or reclaim
    /// them or change their path or controls. The arena and table are disjoint
    /// from guest RAM, source bytes, the stack and metadata, and the loader
    /// keeps every parent table identity-mapped.
    pub(crate) unsafe fn claim(base: NonNull<u8>, pages: usize) -> Result<Arc<Self>, FrameError> {
        let address = base.as_ptr() as usize;
        let end = pages
            .checked_mul(PAGE_BYTES)
            .and_then(|bytes| address.checked_add(bytes))
            .ok_or(FrameError::InvalidArena)?;
        if pages == 0
            || pages > TABLE_ENTRIES
            || !address.is_multiple_of(ARENA_ALIGNMENT)
            || end > LOWER_CANONICAL_END
        {
            return Err(FrameError::InvalidArena);
        }
        let active = controls()?;
        if address as u64 & active.address_mask != address as u64
            || (end - 1) as u64 > (active.address_mask | (PAGE_BYTES as u64 - 1))
        {
            return Err(FrameError::InvalidArena);
        }
        let mut table = NonNull::new(active.root as *mut u64).ok_or(FrameError::InvalidParent)?;
        let empty = Parent {
            slot: table.as_ptr() as usize,
            expected: 0,
        };
        let mut parents = [empty; 3];
        for (index, shift) in PARENT_SHIFTS.into_iter().enumerate() {
            let table_address = table.as_ptr() as usize;
            if table_address >= address && table_address < end {
                return Err(FrameError::InvalidArena);
            }
            // SAFETY: the claim contract keeps the reached table pages
            // identity-mapped.
            let slot = unsafe {
                NonNull::new_unchecked(table.as_ptr().add((address >> shift) & TABLE_INDEX_MASK))
            };
            let value = unsafe { slot.as_ptr().read_volatile() };
            // Exact supervisor RW nonleaf: reject PS, global, NX and unknown flags.
            if value & !active.address_mask & !ACCESSED != (PRESENT | WRITABLE)
                || value & active.address_mask == 0
                || value & active.address_mask >= LOWER_CANONICAL_END as u64
            {
                return Err(FrameError::InvalidParent);
            }
            parents[index] = Parent {
                slot: slot.as_ptr() as usize,
                expected: value & !ACCESSED,
            };
            table = NonNull::new((value & active.address_mask) as *mut u64)
                .ok_or(FrameError::InvalidParent)?;
        }
        let table_address = table.as_ptr() as usize;
        if table_address >= address && table_address < end {
            return Err(FrameError::InvalidArena);
        }
        for index in 0..TABLE_ENTRIES {
            // SAFETY: this page table is owned under the claim contract.
            if unsafe { table.as_ptr().add(index).read_volatile() } != 0 {
                return Err(FrameError::ArenaAlreadyMapped);
            }
        }
        let pool = Self {
            base: address,
            pages,
            root: active.root,
            parents,
            table: table.as_ptr() as usize,
            allocation: Mutex::new(Allocation {
                occupied: [0; BITMAP_WORDS],
                permissions: [0; TABLE_ENTRIES],
            }),
            failure: Mutex::new(None),
        };
        pool.validate_path()?;
        Ok(Arc::new(pool))
    }

    fn validate_path(&self) -> Result<(), FrameError> {
        if self.failure.lock().unwrap().is_some() {
            return Err(FrameError::Quarantined);
        }
        if controls()?.root != self.root {
            return Err(FrameError::ChangedRoot);
        }
        for parent in self.parents {
            // SAFETY: the root owner keeps every table on the path for the
            // whole boot.
            if unsafe { (parent.slot as *const u64).read_volatile() } & !ACCESSED != parent.expected
            {
                return Err(FrameError::ChangedParent);
            }
        }
        Ok(())
    }

    /// Check every claimed leaf against its allocation record, before and after
    /// each native call. No lock is held across the call; a concurrent PTE
    /// change fails the check.
    pub(crate) fn validate_live(&self) -> Result<(), FrameError> {
        self.validate_path()?;
        let allocation = self.allocation.try_lock().map_err(|_| FrameError::Busy)?;
        for page in 0..TABLE_ENTRIES {
            let permissions = allocation.permissions[page];
            let expected = if allocation.used(page) && permissions != 0 {
                self.address(page) as u64 | permissions
            } else {
                0
            };
            if self.pte(page) & !(ACCESSED | DIRTY) != expected {
                self.quarantine(FrameError::ChangedProtection);
                return Err(FrameError::ChangedProtection);
            }
        }
        Ok(())
    }

    /// Descriptive sticky storage failure, never a reset/retry capability.
    pub(crate) fn failure(&self) -> Option<FrameError> {
        *self.failure.lock().unwrap()
    }

    fn quarantine(&self, error: FrameError) {
        let mut failure = self.failure.lock().unwrap();
        if failure.is_none() {
            *failure = Some(error);
        }
    }

    fn address(&self, page: usize) -> usize {
        self.base + page * PAGE_BYTES
    }

    fn pte(&self, page: usize) -> u64 {
        // SAFETY: the index is a checked arena page in the owned table.
        unsafe { (self.table as *mut u64).add(page).read_volatile() }
    }

    fn set_pte(&self, page: usize, value: u64) {
        // SAFETY: only this owner writes these PTEs, on one CPU, and the
        // mapping has no global or PCID translations or other aliases.
        unsafe {
            (self.table as *mut u64).add(page).write_volatile(value);
            asm!("invlpg [{}]", in(reg) self.address(page), options(nostack, preserves_flags));
        }
    }

    /// Copy native code into a new allocation and map it read-only and
    /// executable. The caller still validates the artifact, source, map and
    /// requirements.
    pub(crate) fn copy_native(self: &Arc<Self>, bytes: &[u8]) -> Result<BootFrames, FrameError> {
        self.initialize(
            bytes,
            0,
            bytes.len().div_ceil(PAGE_BYTES) * PAGE_BYTES,
            PRESENT,
        )
    }

    pub(crate) fn copy_ram(
        self: &Arc<Self>,
        initial: &[u8],
        leading: usize,
        bytes: usize,
        readable: bool,
        writable: bool,
    ) -> Result<BootRam, FrameError> {
        if bytes == 0
            || !bytes.is_multiple_of(PAGE_BYTES)
            || leading
                .checked_add(initial.len())
                .is_none_or(|end| end > bytes)
            || writable && !readable
        {
            return Err(FrameError::InvalidArena);
        }
        let permissions = if readable {
            PRESENT | NO_EXECUTE | if writable { WRITABLE } else { 0 }
        } else {
            0
        };
        self.initialize(initial, leading, bytes, permissions)
            .map(BootRam)
    }

    fn initialize(
        self: &Arc<Self>,
        bytes: &[u8],
        leading: usize,
        mapped_bytes: usize,
        permissions: u64,
    ) -> Result<BootFrames, FrameError> {
        if bytes.is_empty() {
            return Err(FrameError::EmptyNative);
        }
        if mapped_bytes == 0
            || !mapped_bytes.is_multiple_of(PAGE_BYTES)
            || leading
                .checked_add(bytes.len())
                .is_none_or(|end| end > mapped_bytes)
        {
            return Err(FrameError::InvalidArena);
        }
        let pages = mapped_bytes / PAGE_BYTES;
        let mut allocation = self.allocation.try_lock().map_err(|_| FrameError::Busy)?;
        if let Err(error) = self.validate_path() {
            self.quarantine(error);
            return Err(error);
        }
        let first = allocation
            .find(self.pages, pages)
            .ok_or(FrameError::Exhausted)?;
        for page in first..first + pages {
            if self.pte(page) != 0 {
                self.quarantine(FrameError::ChangedProtection);
                return Err(FrameError::ChangedProtection);
            }
        }
        // Mark first. If a subsequent check fails, quarantine rather than recycle.
        allocation.mark(first, pages, true);
        for page in first..first + pages {
            allocation.permissions[page] = permissions;
        }
        for page in first..first + pages {
            self.set_pte(
                page,
                self.address(page) as u64 | PRESENT | WRITABLE | NO_EXECUTE,
            );
        }
        let entry = self.address(first) as *mut u8;
        // SAFETY: freshly mapped RW+NX exclusive arena frames cannot alias bytes;
        // caller owns initialized immutable bytes, pool owns the distinct output.
        unsafe {
            entry.write_bytes(0, pages * PAGE_BYTES);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), entry.add(leading), bytes.len());
        }
        for page in first..first + pages {
            self.set_pte(
                page,
                if permissions == 0 {
                    0
                } else {
                    self.address(page) as u64 | permissions
                },
            );
        }
        let owner = BootFrames {
            pool: Arc::clone(self),
            first,
            pages,
            native_bytes: bytes.len(),
            permissions,
            live: true,
        };
        if let Err(error) = owner.validate() {
            self.quarantine(error);
            return Err(error);
        }
        Ok(owner)
    }
}

/// Unique executable storage, dropped through its LoadedBlock when the cache
/// replaces it.
pub(crate) struct BootFrames {
    pool: Arc<BootFramePool>,
    first: usize,
    pages: usize,
    native_bytes: usize,
    permissions: u64,
    live: bool,
}

impl BootFrames {
    fn validate(&self) -> Result<(), FrameError> {
        self.pool.validate_path()?;
        if !self.live || self.native_bytes == 0 {
            return Err(FrameError::ChangedProtection);
        }
        for page in self.first..self.first + self.pages {
            // Hardware alone may set A/D. All address and permission bits are exact.
            if self.pool.pte(page) & !(ACCESSED | DIRTY)
                != (if self.permissions == 0 {
                    0
                } else {
                    self.pool.address(page) as u64 | self.permissions
                })
            {
                return Err(FrameError::ChangedProtection);
            }
        }
        Ok(())
    }

    fn unmap(&mut self) -> Result<(), FrameError> {
        self.validate()?;
        let mut allocation = self
            .pool
            .allocation
            .try_lock()
            .map_err(|_| FrameError::Busy)?;
        for page in self.first..self.first + self.pages {
            self.pool.set_pte(page, 0);
        }
        allocation.mark(self.first, self.pages, false);
        self.live = false;
        Ok(())
    }
}

// SAFETY: this owner keeps the frames, page table and root, and checks the live
// CR3 path, WP, NXE and PTEs on every call. Code is copied with RW+NX, then
// write permission is removed before returning; no writable alias remains. Only
// `NativeImage` enters the code.
unsafe impl ExecutableStorage for BootFrames {
    type Error = FrameError;
    fn entry(&self) -> NonNull<u8> {
        // SAFETY: the arena base is non-null and the offset is checked.
        unsafe { NonNull::new_unchecked(self.pool.address(self.first) as *mut u8) }
    }
    fn revalidate(&self) -> Result<(), Self::Error> {
        crate::platform::boot::ensure_live().map_err(|error| error.storage_failure())?;
        let result = if self.permissions == PRESENT {
            self.validate()
        } else {
            Err(FrameError::ChangedProtection)
        };
        if let Err(error) = result {
            self.pool.quarantine(error);
        }
        result
    }
}

impl Drop for BootFrames {
    fn drop(&mut self) {
        if self.live {
            // Failed validation never clears/recycles suspect storage. The pool
            // bitmap retains it as quarantined until the whole boot arena dies.
            if let Err(error) = self.unmap() {
                self.pool.quarantine(error);
            }
        }
    }
}

/// Actual private physical RAM ownership; no executable image API is exposed.
pub(crate) struct BootRam(BootFrames);
impl BootRam {
    pub(crate) fn base(&self) -> NonNull<u8> {
        // SAFETY: the retained allocation has a non-null base.
        unsafe { NonNull::new_unchecked(self.0.pool.address(self.0.first) as *mut u8) }
    }
    pub(crate) fn bytes(&self) -> usize {
        self.0.pages * PAGE_BYTES
    }
    pub(crate) fn revalidate(&self) -> Result<(), FrameError> {
        self.0.validate()
    }
}
impl core::fmt::Debug for BootFrames {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BootFrames")
            .field("base", &self.pool.address(self.first))
            .field("pages", &self.pages)
            .field("permissions", &self.permissions)
            .field("live", &self.live)
            .finish()
    }
}
impl core::fmt::Debug for BootRam {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("BootRam").field(&self.0).finish()
    }
}
impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "boot frame storage failed: {self:?}")
    }
}
impl core::error::Error for FrameError {}
