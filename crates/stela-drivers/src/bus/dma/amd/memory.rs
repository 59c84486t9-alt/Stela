//! Actual retained WB memory for one AMD 4 KiB page table. This component
//! grants no remapper access and performs no implicit IOTLB acknowledgement.
use super::format::{FormatError, PageEntry, PhysicalAddress};
use crate::bus::dma::memory::{CacheAttribute, CpuMapping, MemoryError, PageSource};
use core::ptr::NonNull;

pub const TABLE_BYTES: usize = 4096;
pub const TABLE_ENTRIES: usize = TABLE_BYTES / size_of::<u64>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    Memory(MemoryError),
    Format(FormatError),
    EntryIndex,
    InvalidProvider,
}

/// Real cache/order publication for the current platform and remapping unit.
///
/// # Safety
/// An implementation must qualify actual IOMMU table-walk coherency and the
/// CPU/root/cache context, then perform the required coherent ordering or
/// qualified cache maintenance for the entire WB CPU span. Success means
/// hardware can observe every preceding table store. No compiler-only fence,
/// CPU-pointer-as-PA inference or unsupported-success path satisfies this.
/// It cannot retain the borrowed pointer, modify entries, reenter their owner
/// or use this callback as an IOTLB invalidation/completion witness.
pub unsafe trait TableVisibility {
    /// # Safety
    /// `cpu..cpu+bytes` is retained, aligned WB CPU RAM for this call. All
    /// software table writers are excluded; no access escapes this borrowing.
    unsafe fn publish(&self, cpu: NonNull<u8>, bytes: usize) -> Result<(), MemoryError>;
}

/// The CPU view retains the complete original platform pin, even when only
/// the first 4 KiB of a larger native allocation is used by the table walker.
///
/// A consumer publishing this physical address must retain the table through
/// all hardware walks and acknowledged invalidation/reset. A live unit's Drop
/// must quarantine uncertain owners rather than release them. This memory
/// object does not know whether a caller programmed hardware with its address.
pub struct TablePage {
    cpu: CpuMapping,
    physical: PhysicalAddress,
    native_shift: u8,
    retained_bytes: usize,
}

impl TablePage {
    /// # Safety
    /// Each successful source allocation supplies fresh, currently zeroed CPU
    /// storage exclusively for this table's mutation until Drop. No cloned pin,
    /// other table, hardware writer or raw CPU writer may alias it. PageSource
    /// is a shared safe allocator interface and cannot itself attest this grant.
    /// The consumer separately retains tables through live hardware ownership.
    pub unsafe fn allocate(source: &dyn PageSource, physical_bits: u8) -> Result<Self, TableError> {
        // Validate the device's width before any provider allocation.
        PhysicalAddress::new(0, physical_bits).map_err(TableError::Format)?;
        let geometry = source.page_geometry().map_err(TableError::Memory)?;
        let bytes = geometry.base_bytes();
        let pages = source
            .allocate(bytes, bytes, CacheAttribute::WriteBack)
            .map_err(TableError::Memory)?;
        if !geometry.supports(pages.page_shift())
            || pages.logical_bytes() != bytes
            || pages.bytes() < TABLE_BYTES
            || pages.cache_attribute() != CacheAttribute::WriteBack
        {
            return Err(TableError::InvalidProvider);
        }
        let physical = PhysicalAddress::new(pages.physical_pages()[0], physical_bits)
            .map_err(TableError::Format)?;
        if !physical.value().is_multiple_of(TABLE_BYTES as u64)
            || physical
                .value()
                .checked_add(TABLE_BYTES as u64)
                .is_none_or(|end| end > 1u64 << physical_bits)
        {
            return Err(TableError::InvalidProvider);
        }
        let cpu = pages
            .cpu_mapping_range(CacheAttribute::WriteBack, 0..TABLE_BYTES)
            .map_err(TableError::Memory)?;
        let address = cpu.address(0, TABLE_BYTES).map_err(TableError::Memory)?;
        if !(address.as_ptr() as usize).is_multiple_of(TABLE_BYTES) {
            return Err(TableError::InvalidProvider);
        }
        let native_shift = pages.page_shift();
        let retained_bytes = pages.bytes();
        // The producer grants fresh, currently zeroed bytes; do not clear a
        // second time after the real provider's allocation initialization.
        Ok(Self {
            cpu,
            physical,
            native_shift,
            retained_bytes,
        })
    }

    pub fn physical(&self) -> PhysicalAddress {
        self.physical
    }

    pub fn native_shift(&self) -> u8 {
        self.native_shift
    }

    /// Complete native pin, including every unused allocation tail retained by
    /// the CPU view. This is distinct from the 4 KiB hardware table extent.
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    fn pointer(&self, index: usize) -> Result<NonNull<u64>, TableError> {
        if index >= TABLE_ENTRIES {
            return Err(TableError::EntryIndex);
        }
        self.cpu
            .address(index * size_of::<u64>(), size_of::<u64>())
            .map(NonNull::cast)
            .map_err(TableError::Memory)
    }

    pub fn read(&self, index: usize) -> Result<u64, TableError> {
        // SAFETY: bounded aligned retained WB table word, no Rust data slice
        // aliases the hardware table. The consumer excludes software writers.
        Ok(u64::from_le(unsafe {
            self.pointer(index)?.as_ptr().read_volatile()
        }))
    }

    pub fn write(&mut self, index: usize, entry: PageEntry) -> Result<(), TableError> {
        // SAFETY: exclusive CPU mutation of a complete checked table word.
        // The live consumer owns cache publication and invalidation sequencing.
        unsafe {
            self.pointer(index)?
                .as_ptr()
                .write_volatile(entry.bits().to_le())
        };
        Ok(())
    }

    /// Clear every actual entry. This does not establish hardware retirement.
    pub fn clear(&mut self) {
        for index in 0..TABLE_ENTRIES {
            // Every index is inside the fixed retained page; no allocation or
            // platform callback can fail while zeroing an established table.
            self.write(index, PageEntry::EMPTY)
                .expect("bounded table clear");
        }
    }

    pub fn publish(&self, visibility: &impl TableVisibility) -> Result<(), TableError> {
        let cpu = self
            .cpu
            .address(0, TABLE_BYTES)
            .map_err(TableError::Memory)?;
        // SAFETY: the exact retained, aligned WB table span; &self excludes
        // safe software mutation until the real visibility operation returns.
        unsafe { visibility.publish(cpu, TABLE_BYTES) }.map_err(TableError::Memory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::{
        mapping::Direction,
        memory::{PageBacking, PageGeometry, PinnedPages},
    };
    use alloc::{
        alloc::{alloc_zeroed, dealloc},
        boxed::Box,
        sync::Arc,
        vec::Vec,
    };
    use core::{
        alloc::Layout,
        cell::Cell,
        sync::atomic::{AtomicUsize, Ordering},
    };

    const PHYSICAL: u64 = 0x1122_0000;

    struct Backing {
        cpu: NonNull<u8>,
        layout: Layout,
        physical: Vec<u64>,
        shift: u8,
        attribute: CacheAttribute,
        drops: Arc<AtomicUsize>,
    }
    // SAFETY: uniquely owned aligned zeroed CPU RAM and immutable symbolic PA
    // metadata. No safe references or asynchronous DMA exist in this fixture.
    unsafe impl Send for Backing {}
    // SAFETY: shared access exposes metadata/raw pointers only; test CPU writes
    // are serialized and never overlap software table mutation/publication.
    unsafe impl Sync for Backing {}
    // SAFETY: actual retained CPU RAM models the named immutable physical pages.
    // The labels are deliberately not CPU addresses and never reach hardware.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            self.cpu
        }
        fn physical_pages(&self) -> &[u64] {
            &self.physical
        }
        fn page_shift(&self) -> u8 {
            self.shift
        }
        fn cache_attribute(&self) -> CacheAttribute {
            self.attribute
        }
    }
    impl Drop for Backing {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
            // SAFETY: exactly this backing's unique original CPU allocation.
            unsafe { dealloc(self.cpu.as_ptr(), self.layout) };
        }
    }

    struct Source {
        geometry: Result<PageGeometry, MemoryError>,
        shift: u8,
        bytes: usize,
        physical: u64,
        logical: Option<usize>,
        attribute: CacheAttribute,
        failure: Option<MemoryError>,
        queries: Cell<usize>,
        allocations: Cell<usize>,
        request: Cell<Option<(usize, usize, CacheAttribute)>>,
        cpu: Cell<Option<NonNull<u8>>>,
        drops: Arc<AtomicUsize>,
    }
    impl Source {
        fn new(shift: u8) -> Self {
            Self {
                geometry: PageGeometry::base_only(shift),
                shift,
                bytes: 1usize << shift,
                physical: PHYSICAL,
                logical: None,
                attribute: CacheAttribute::WriteBack,
                failure: None,
                queries: Cell::new(0),
                allocations: Cell::new(0),
                request: Cell::new(None),
                cpu: Cell::new(None),
                drops: Arc::new(AtomicUsize::new(0)),
            }
        }

        /// Unowned observation only while the table retains this source's one
        /// actual backing; never a replacement pin, mapping or safe RAM view.
        fn live_cpu(&self) -> NonNull<u8> {
            assert_eq!(self.allocations.get(), 1);
            assert_eq!(self.drops.load(Ordering::Relaxed), 0);
            self.cpu.get().expect("one live fixture allocation")
        }
    }
    impl PageSource for Source {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            self.queries.set(self.queries.get() + 1);
            self.geometry
        }

        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            self.allocations.set(self.allocations.get() + 1);
            self.request.set(Some((bytes, alignment, attribute)));
            if let Some(error) = self.failure {
                return Err(error);
            }
            let granule = 1usize << self.shift;
            let layout = Layout::from_size_align(self.bytes, granule).unwrap();
            // SAFETY: actual unique zeroed CPU storage, released by Backing.
            let cpu =
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
            self.cpu.set(Some(cpu));
            PinnedPages::new(
                Box::new(Backing {
                    cpu,
                    layout,
                    physical: (0..self.bytes / granule)
                        .map(|index| self.physical + (index * granule) as u64)
                        .collect(),
                    shift: self.shift,
                    attribute: self.attribute,
                    drops: self.drops.clone(),
                }),
                self.logical.unwrap_or(bytes),
                granule,
            )
        }
    }

    fn allocate(source: &Source, physical_bits: u8) -> Result<TablePage, TableError> {
        // SAFETY: this concrete fixture source always allocates fresh, uniquely
        // owned, currently zeroed CPU RAM. It retains no pin or writer alias;
        // raw observations occur only synchronously while the table is live.
        unsafe { TablePage::allocate(source, physical_bits) }
    }

    fn entry(index: usize) -> PageEntry {
        PageEntry::page(
            PhysicalAddress::new(0x0123_4567_8000 + (index as u64) * 4096, 48).unwrap(),
            Direction::Bidirectional,
            true,
        )
        .unwrap()
    }

    #[test]
    fn attested_native_granules_retain_the_complete_original_allocation() {
        for (base, returned, backing_pages) in [(12, 12, 1), (13, 13, 1), (12, 13, 1), (12, 12, 2)]
        {
            let mut source = Source::new(returned);
            source.bytes *= backing_pages;
            source.geometry = PageGeometry::contiguous(base, returned);
            let mut table = allocate(&source, 48).unwrap();
            assert_eq!(
                source.request.get(),
                Some((1usize << base, 1usize << base, CacheAttribute::WriteBack))
            );
            assert_eq!(table.native_shift(), returned);
            assert_eq!(table.retained_bytes(), source.bytes);
            assert_eq!(table.physical().value(), PHYSICAL);
            assert_ne!(source.live_cpu().as_ptr() as usize as u64, PHYSICAL);
            for index in 0..TABLE_ENTRIES {
                assert_eq!(table.read(index), Ok(0));
            }
            if source.bytes > TABLE_BYTES {
                // SAFETY: the complete actual backing is retained by table.
                // Its unused tail has no table words or asynchronous users.
                unsafe {
                    source
                        .live_cpu()
                        .as_ptr()
                        .add(TABLE_BYTES)
                        .write_bytes(0xa7, source.bytes - TABLE_BYTES)
                };
            }
            table.write(TABLE_ENTRIES - 1, entry(511)).unwrap();
            table.clear();
            if source.bytes > TABLE_BYTES {
                for offset in TABLE_BYTES..source.bytes {
                    // SAFETY: only the unused tail of this live complete pin.
                    assert_eq!(
                        unsafe { source.live_cpu().as_ptr().add(offset).read_volatile() },
                        0xa7
                    );
                }
            }
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            drop(table);
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn all_words_clear_and_first_last_native_stores_have_exact_little_endian_bytes() {
        let source = Source::new(12);
        let mut table = allocate(&source, 48).unwrap();
        for index in 0..TABLE_ENTRIES {
            table.write(index, entry(index)).unwrap();
            assert_eq!(table.read(index), Ok(entry(index).bits()));
        }
        for index in [0, TABLE_ENTRIES - 1] {
            for (byte, expected) in entry(index).bits().to_le_bytes().into_iter().enumerate() {
                // SAFETY: a live table word, read as bytes without a Rust alias.
                let actual = unsafe {
                    source
                        .live_cpu()
                        .as_ptr()
                        .add(index * 8 + byte)
                        .read_volatile()
                };
                assert_eq!(actual, expected);
            }
        }
        for index in [TABLE_ENTRIES, usize::MAX] {
            assert_eq!(table.read(index), Err(TableError::EntryIndex));
            assert_eq!(
                table.write(index, PageEntry::EMPTY),
                Err(TableError::EntryIndex)
            );
        }
        assert_eq!(table.read(0), Ok(entry(0).bits()));
        assert_eq!(table.read(511), Ok(entry(511).bits()));
        table.clear();
        for index in 0..TABLE_ENTRIES {
            assert_eq!(table.read(index), Ok(0));
        }
        for offset in 0..TABLE_BYTES {
            // SAFETY: bounded actual live CPU storage, with no concurrent writer.
            assert_eq!(
                unsafe { source.live_cpu().as_ptr().add(offset).read_volatile() },
                0
            );
        }
        drop(table);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn invalid_width_and_unknown_geometry_never_request_backing() {
        for width in [0, 31, 53, u8::MAX] {
            let source = Source::new(12);
            assert!(matches!(
                allocate(&source, width),
                Err(TableError::Format(FormatError::PhysicalWidth))
            ));
            assert_eq!((source.queries.get(), source.allocations.get()), (0, 0));
        }
        let mut source = Source::new(12);
        source.geometry = Err(MemoryError::Unavailable);
        assert!(matches!(
            allocate(&source, 48),
            Err(TableError::Memory(MemoryError::Unavailable))
        ));
        assert_eq!((source.queries.get(), source.allocations.get()), (1, 0));
        struct Unknown(Cell<usize>);
        impl PageSource for Unknown {
            fn allocate(
                &self,
                _: usize,
                _: usize,
                _: CacheAttribute,
            ) -> Result<PinnedPages, MemoryError> {
                self.0.set(self.0.get() + 1);
                Err(MemoryError::Unavailable)
            }
        }
        let unknown = Unknown(Cell::new(0));
        // The actual default PageSource profile is unavailable, never an
        // inferred 4K allocation profile merely because allocation exists.
        // SAFETY: Unknown never supplies an allocation or a table alias.
        assert!(matches!(
            unsafe { TablePage::allocate(&unknown, 48) },
            Err(TableError::Memory(MemoryError::Unavailable))
        ));
        assert_eq!(unknown.0.get(), 0);
    }

    #[test]
    fn provider_mismatch_and_address_errors_release_every_unpublished_pin() {
        let mut cases = Vec::new();
        let mut wrong_cache = Source::new(12);
        wrong_cache.attribute = CacheAttribute::WriteCombining;
        cases.push((wrong_cache, TableError::InvalidProvider));
        let mut wrong_geometry = Source::new(13);
        wrong_geometry.geometry = PageGeometry::base_only(12);
        cases.push((wrong_geometry, TableError::InvalidProvider));
        let mut short_logical = Source::new(12);
        short_logical.logical = Some(TABLE_BYTES - 1);
        cases.push((short_logical, TableError::InvalidProvider));
        let mut long_logical = Source::new(12);
        long_logical.bytes = 2 * TABLE_BYTES;
        long_logical.logical = Some(2 * TABLE_BYTES);
        cases.push((long_logical, TableError::InvalidProvider));
        let mut outside_width = Source::new(12);
        outside_width.physical = 1 << 32;
        cases.push((
            outside_width,
            TableError::Format(FormatError::PhysicalAddress),
        ));
        let mut malformed_pin = Source::new(12);
        malformed_pin.physical = PHYSICAL + 1;
        cases.push((
            malformed_pin,
            TableError::Memory(MemoryError::InvalidAlignment),
        ));
        for (source, expected) in cases {
            match allocate(&source, 32) {
                Err(error) => assert_eq!(error, expected),
                Ok(_) => panic!("bad provider accepted"),
            }
            assert_eq!((source.queries.get(), source.allocations.get()), (1, 1));
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
        let mut source = Source::new(12);
        source.failure = Some(MemoryError::OutOfMemory);
        assert!(matches!(
            allocate(&source, 48),
            Err(TableError::Memory(MemoryError::OutOfMemory))
        ));
        assert_eq!(source.allocations.get(), 1);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        // The final aligned hardware page is accepted with its complete extent.
        let mut source = Source::new(12);
        source.physical = (1u64 << 32) - TABLE_BYTES as u64;
        let table = allocate(&source, 32).unwrap();
        assert_eq!(table.physical().value() + TABLE_BYTES as u64, 1u64 << 32);
        drop(table);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }

    struct Observe {
        cpu: NonNull<u8>,
        calls: Cell<usize>,
        fail: Cell<bool>,
    }
    // SAFETY: synchronous software observation of a borrowed actual CPU span,
    // modeling the callback boundary only. No native cache/coherency/IOMMU
    // context is claimed, no pointer is retained from the call or used later,
    // and no mutation/reentry or invalidation/completion is invented.
    unsafe impl TableVisibility for Observe {
        unsafe fn publish(&self, cpu: NonNull<u8>, bytes: usize) -> Result<(), MemoryError> {
            assert_eq!(cpu, self.cpu);
            assert_eq!(bytes, TABLE_BYTES);
            assert!((cpu.as_ptr() as usize).is_multiple_of(TABLE_BYTES));
            for index in [0, TABLE_ENTRIES - 1] {
                for (byte, expected) in entry(index).bits().to_le_bytes().into_iter().enumerate() {
                    // SAFETY: callback borrows this checked live table span;
                    // no writer runs until it returns, including failure.
                    assert_eq!(
                        unsafe { cpu.as_ptr().add(index * 8 + byte).read_volatile() },
                        expected
                    );
                }
            }
            self.calls.set(self.calls.get() + 1);
            if self.fail.get() {
                Err(MemoryError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn publication_observes_actual_stores_and_propagates_failure_without_release() {
        let source = Source::new(13);
        let mut table = allocate(&source, 48).unwrap();
        let observer = Observe {
            cpu: source.live_cpu(),
            calls: Cell::new(0),
            fail: Cell::new(false),
        };
        table.write(0, entry(0)).unwrap();
        table.write(TABLE_ENTRIES - 1, entry(511)).unwrap();
        assert_eq!(observer.calls.get(), 0);
        assert_eq!(table.publish(&observer), Ok(()));
        observer.fail.set(true);
        assert_eq!(
            table.publish(&observer),
            Err(TableError::Memory(MemoryError::Unavailable))
        );
        assert_eq!(observer.calls.get(), 2);
        assert_eq!(table.read(0), Ok(entry(0).bits()));
        assert_eq!(table.read(511), Ok(entry(511).bits()));
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        drop(table);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
}
