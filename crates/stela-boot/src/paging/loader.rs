//! Original Engine loader allocations, including their real catalog storage.
//! Allocation ownership supplies no controller, firmware-service or CPU grant.
use super::{AllocatedTablePage, RootError, allocate_table};
use alloc::vec::Vec;
use core::arch::asm;
use stela_boot_core::guarded_stacks::mappings;

pub(crate) struct Builder {
    root: u64,
    pages: Vec<AllocatedTablePage>,
    levels: u32,
}
impl Builder {
    pub(crate) fn new() -> Result<Self, &'static str> {
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(1)
            .map_err(|_| "loader table catalog allocation failed")?;
        // The real-mode/AP trampoline loads this original root below 4 GiB.
        let allocation = allocate_table(uefi::boot::AllocateType::MaxAddress(u32::MAX as u64))?;
        let root = allocation.physical;
        pages.push(allocation);
        Ok(Self {
            root,
            pages,
            levels: crate::layout::top_level() + 1,
        })
    }
    pub(crate) fn root(&self) -> u64 {
        self.root
    }
    pub(crate) fn retain(self) -> Result<LoaderTables, RootError> {
        let mut catalog = CatalogBacking::reserve(self.pages.len())?;
        for (index, owner) in self.pages.into_iter().enumerate() {
            catalog.place(index, owner);
        }
        let owner = LoaderTables {
            root: self.root,
            levels: self.levels,
            catalog,
        };
        owner.validate_aliases()?;
        Ok(owner)
    }
}
impl crate::tables::Frames for Builder {
    fn frame(&mut self) -> Option<u64> {
        self.pages.try_reserve(1).ok()?;
        let allocation = allocate_table(uefi::boot::AllocateType::AnyPages).ok()?;
        let physical = allocation.physical;
        self.pages.push(allocation);
        Some(physical)
    }
    fn table(&self, physical: u64) -> *mut u64 {
        assert!(
            self.pages.iter().any(|page| page.physical == physical),
            "foreign loader table frame"
        );
        physical as *mut u64
    }
}

/// A genuine separate LOADER_DATA allocation contains the MOVED original
/// non-Clone page owners. No firmware-heap Vec or Arc pointer crosses roots.
struct CatalogBacking {
    physical: u64,
    bytes: u64,
    count: usize,
}
impl CatalogBacking {
    fn reserve(count: usize) -> Result<Self, RootError> {
        let bytes = count
            .checked_mul(size_of::<AllocatedTablePage>())
            .filter(|bytes| *bytes != 0)
            .ok_or(RootError::CatalogSize)?;
        let pages = bytes.div_ceil(super::PAGE);
        let bytes = pages
            .checked_mul(super::PAGE)
            .ok_or(RootError::CatalogSize)?;
        let allocation = uefi::boot::allocate_pages(
            uefi::boot::AllocateType::AnyPages,
            uefi::boot::MemoryType::LOADER_DATA,
            pages,
        )
        .map_err(|error| RootError::CatalogAllocation(error.status()))?;
        // SAFETY: this fresh, exclusive actual allocation has exactly bytes
        // writable bytes. It is not a table, DMA buffer or published catalog.
        unsafe {
            allocation.as_ptr().write_bytes(0, bytes);
        }
        Ok(Self {
            physical: allocation.as_ptr() as u64,
            bytes: bytes as u64,
            count,
        })
    }
    fn place(&mut self, index: usize, owner: AllocatedTablePage) {
        assert!(index < self.count);
        // SAFETY: actual original catalog allocation, checked slot geometry;
        // each owner is moved once before publication, with no active readers.
        unsafe {
            (self.physical as *mut AllocatedTablePage)
                .add(index)
                .write(owner);
        }
    }
    fn physical(&self, index: usize) -> Option<u64> {
        if index >= self.count {
            return None;
        }
        // SAFETY: retained original metadata allocation; construction or actual
        // original-loader context supplies its checked identity alias. Read only
        // the observation field, without cloning the original allocation owner.
        Some(unsafe {
            core::ptr::addr_of!((*(self.physical as *const AllocatedTablePage).add(index)).physical)
                .read_volatile()
        })
    }
}

/// Inline Handoff owner of ORIGINAL table pages and catalog allocation. None
/// are freed to firmware, guest RAM or DMA for the complete shared-root boot.
/// Native consumers still need their real CPU/root/controller exclusion grants.
pub(crate) struct LoaderTables {
    root: u64,
    levels: u32,
    catalog: CatalogBacking,
}
impl LoaderTables {
    pub(crate) fn root(&self) -> u64 {
        self.root
    }
    fn read_owned(&self, table: u64, index: usize) -> Option<u64> {
        if index >= super::ENTRIES
            || !(0..self.catalog.count).any(|slot| self.catalog.physical(slot) == Some(table))
        {
            return None;
        }
        // SAFETY: original allocated page owner is retained in the actual
        // catalog; construction or checked loader context supplies its alias.
        Some(unsafe { (table as *const u64).add(index).read_volatile() })
    }
    fn observe(&self, address: u64) -> Result<Option<mappings::Observation>, mappings::Error> {
        mappings::observe(address, self.root, self.levels, |table, index| {
            self.read_owned(table, index)
        })
    }
    fn validate_page(&self, physical: u64) -> Result<(), RootError> {
        for alias in [physical, crate::layout::physical(physical)] {
            let leaf = self
                .observe(alias)
                .map_err(RootError::Traversal)?
                .ok_or(RootError::AliasMissing { physical })?;
            if leaf.physical != physical || !leaf.writable || leaf.user {
                return Err(RootError::AliasMismatch { physical });
            }
        }
        Ok(())
    }
    fn validate_aliases(&self) -> Result<(), RootError> {
        for index in 0..self.catalog.count {
            self.validate_page(self.catalog.physical(index).ok_or(RootError::CatalogSize)?)?;
        }
        for offset in (0..self.catalog.bytes).step_by(super::PAGE) {
            self.validate_page(
                self.catalog
                    .physical
                    .checked_add(offset)
                    .ok_or(RootError::CatalogSize)?,
            )?;
        }
        Ok(())
    }
    pub(crate) fn boot_entry(&self, index: usize) -> Result<u64, RootError> {
        let selector: u16;
        // SAFETY: read-only CPL observation precedes privileged operations.
        unsafe {
            asm!("mov {0:x}, cs", out(reg) selector, options(nomem, nostack, preserves_flags));
        }
        if selector & 3 != 0 {
            return Err(RootError::Privilege);
        }
        let (flags, root, cr4): (u64, u64, u64);
        // SAFETY: actual CPL0; controlled boot installation runs without
        // migration, callbacks or another table builder using these pages.
        unsafe {
            asm!("pushfq", "pop {}", "mov {}, cr3", "mov {}, cr4", out(reg) flags, out(reg) root, out(reg) cr4, options(nomem, preserves_flags));
        }
        if flags & (1 << 9) != 0 {
            return Err(RootError::InterruptsEnabled);
        }
        if root != self.root {
            return Err(RootError::RootChanged);
        }
        if self.levels != if cr4 & (1 << 12) != 0 { 5 } else { 4 } {
            return Err(RootError::ControlsChanged);
        }
        // Sealing checked all original identity and high-window aliases. The
        // sole builder was consumed; later native mappings must preserve them.
        self.read_owned(self.root, index)
            .ok_or(RootError::Transition(
                "loader root entry is outside its owned table",
            ))
    }
}
