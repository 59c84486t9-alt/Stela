// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2007-2010 Advanced Micro Devices, Inc.
// Author: Joerg Roedel <jroedel@suse.de>
//         Leo Duran <leo.duran@amd.com>
// DTE policy and host update ordering adapted from Linux drivers/iommu/amd
// at cc9de5d4b5ab6459f5774946aa3195ad51236fa8. See platform/THIRD_PARTY.md.
//! Complete retained per-segment device-table RAM and native atomic updates.
//! This is not unit takeover, requester admission or a device DMA domain.
mod atomic;
mod entry;

use super::{
    format::{DomainId, FormatError, PhysicalAddress, TableLevel},
    memory::TableVisibility,
};
use crate::bus::dma::{
    mapping::DmaError,
    memory::{CacheAttribute, CpuMapping, MemoryError, PageSource},
};
use alloc::vec::Vec;
use core::{
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};
use entry::{Entry, Policy};

pub const REQUESTERS: usize = 1 << 16;
pub const ENTRY_BYTES: usize = 32;
pub const DEVICE_TABLE_BYTES: usize = REQUESTERS * ENTRY_BYTES;
const TABLE_PAGE_BYTES: u64 = 4096;
const BASE_SIZE: u64 = DEVICE_TABLE_BYTES as u64 / TABLE_PAGE_BYTES - 1;
const DMA32_LIMIT: u64 = 1 << 32;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);

/// Cumulative exposed owners retained by Drop, not reset/reclamation evidence.
pub fn quarantined_tables() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceTableError {
    Memory(MemoryError),
    Format(FormatError),
    Context(DmaError),
    Invalidation(DmaError),
    PolicyCount,
    Policy,
    InvalidProvider,
    PhysicalContiguity,
    AddressLimit,
    UnsupportedAtomic,
    Profile,
    ConcurrentWriter,
    Poisoned,
}

/// Fixed real unit/segment context, allocation and completion ownership.
///
/// # Safety
/// Allocations provide fresh, currently zeroed CPU-exclusive table RAM. The
/// context retains every unit using this segment table plus their actual IRQ,
/// command and completion resources. Only the admitted host-only profile is
/// active: unencrypted/SNP-disabled tables, no hardware DTE writes, guest
/// translation, ATS/PASID/PRI or interrupt-remapping table/pointer owners.
/// `enter` returns a real guard excluding other DTE writers and retaining a
/// qualified CPU/process/root context through its Drop. CPU-affine qualification
/// requires preventing migration; a context qualified on every allowed CPU
/// need not prohibit scheduling. After a successful local CX16 probe every CPU
/// allowed under the guard must support CX16. No IRQ
/// callback may reenter this owner. The guard must admit completion IRQs during
/// invalidation; disabling delivery across that wait is not admissible.
/// Visibility performs actual coherent ordering
/// or qualified cache maintenance, not a compiler-only fence.
/// `invalidate` acknowledges actual DTE/observed alias invalidation in every
/// relevant unit, plus full old-domain IOTLB invalidation when nonzero, before
/// success. It retains all domain-ID reservations through that completion.
/// Unsupported operations, fault and timeout return failure; no queue-head or
/// elapsed-time observation substitutes. Enter/admission must not mutate DTEs.
pub unsafe trait DeviceTableHardware: PageSource + TableVisibility {
    type Access<'a>
    where
        Self: 'a;
    fn enter(&self) -> Result<Self::Access<'_>, DmaError>;
    fn invalidate(&self, requester: u16, old_domain: Option<DomainId>) -> Result<(), DmaError>;
}

struct State<H> {
    hardware: H,
    cpu: CpuMapping,
    physical: u64,
    policies: Vec<u8>,
    physical_bits: u8,
}

impl<H> State<H> {
    fn pointer(&self, requester: u16, word: usize) -> NonNull<u64> {
        assert!(word < 4, "bounded half-DTE word");
        self.cpu
            .address(usize::from(requester) * ENTRY_BYTES + word * 8, 8)
            .expect("complete retained device table")
            .cast()
    }

    fn words(&self, requester: u16) -> [u64; 4] {
        core::array::from_fn(|word| {
            // SAFETY: complete retained WB table, bounded aligned word. The
            // admitted hardware is read-only and safe writers require &mut owner.
            u64::from_le(unsafe { self.pointer(requester, word).as_ptr().read_volatile() })
        })
    }

    fn policy(&self, requester: u16) -> Policy {
        Policy::new(self.policies[usize::from(requester)]).expect("immutable validated IVHD policy")
    }
}

/// A complete actual device table. Root exposure arms Drop quarantine of the
/// original full pin, immutable policy and fixed real unit context together.
pub struct DeviceTable<H: DeviceTableHardware> {
    state: Option<State<H>>,
    exposed: bool,
    poisoned: bool,
}

impl<H: DeviceTableHardware> DeviceTable<H> {
    /// # Safety
    /// The producer admits the exact segment, all units and the host-only
    /// hardware profile/physical width. `policies` is the complete effective
    /// per-RID IVHD policy after actual range/alias resolution, not guessed from
    /// one GPU. All units' firmware ownership is resolved before root activation.
    pub unsafe fn new(
        hardware: H,
        policies: &[u8],
        physical_bits: u8,
    ) -> Result<Self, DeviceTableError> {
        PhysicalAddress::new(0, physical_bits).map_err(DeviceTableError::Format)?;
        if policies.len() != REQUESTERS {
            return Err(DeviceTableError::PolicyCount);
        }
        for &flags in policies {
            Policy::new(flags)?;
        }
        let mut retained_policy = Vec::new();
        retained_policy
            .try_reserve_exact(REQUESTERS)
            .map_err(|_| DeviceTableError::Memory(MemoryError::OutOfMemory))?;
        retained_policy.extend_from_slice(policies);
        let guard = hardware.enter().map_err(DeviceTableError::Context)?;
        if !atomic::supported() {
            return Err(DeviceTableError::UnsupportedAtomic);
        }
        let geometry = hardware.page_geometry().map_err(DeviceTableError::Memory)?;
        let request = DEVICE_TABLE_BYTES.max(geometry.base_bytes());
        let pages = hardware
            .allocate(request, geometry.base_bytes(), CacheAttribute::WriteBack)
            .map_err(DeviceTableError::Memory)?;
        if !geometry.supports(pages.page_shift())
            || pages.logical_bytes() != request
            || pages.bytes() < DEVICE_TABLE_BYTES
            || pages.cache_attribute() != CacheAttribute::WriteBack
        {
            return Err(DeviceTableError::InvalidProvider);
        }
        let physical = pages.physical_pages()[0];
        if !physical.is_multiple_of(TABLE_PAGE_BYTES)
            || physical
                .checked_add(DEVICE_TABLE_BYTES as u64)
                .is_none_or(|end| end > DMA32_LIMIT)
        {
            return Err(DeviceTableError::AddressLimit);
        }
        let native = 1usize << pages.page_shift();
        let used_pages = DEVICE_TABLE_BYTES.div_ceil(native);
        for (index, &page) in pages.physical_pages()[..used_pages].iter().enumerate() {
            if physical.checked_add((index * native) as u64) != Some(page) {
                return Err(DeviceTableError::PhysicalContiguity);
            }
        }
        let cpu = pages
            .cpu_mapping_range(CacheAttribute::WriteBack, 0..DEVICE_TABLE_BYTES)
            .map_err(DeviceTableError::Memory)?;
        let address = cpu
            .address(0, DEVICE_TABLE_BYTES)
            .map_err(DeviceTableError::Memory)?;
        if !(address.as_ptr() as usize).is_multiple_of(TABLE_PAGE_BYTES as usize) {
            return Err(DeviceTableError::InvalidProvider);
        }
        // Initial policy writes happen only while this fresh allocation is
        // unreachable by every remapper. Live IRQ-field preservation would
        // incorrectly erase the initial policy if applied to its zero image.
        for (requester, &flags) in retained_policy.iter().enumerate() {
            let words = Entry::blocked(Policy::new(flags).expect("validated IVHD policy")).words();
            for (word, value) in words.into_iter().enumerate() {
                // SAFETY: fresh exclusive complete table RAM, checked aligned
                // CPU span; no hardware or other software writer can reach it.
                unsafe {
                    address
                        .as_ptr()
                        .cast::<u64>()
                        .add(requester * 4 + word)
                        .write_volatile(value.to_le())
                };
            }
        }
        // SAFETY: exact retained WB CPU span; the guard excludes writers and
        // the fixed unsafe implementation supplies real hardware visibility.
        unsafe { hardware.publish(address, DEVICE_TABLE_BYTES) }
            .map_err(DeviceTableError::Memory)?;
        drop(guard);
        Ok(Self {
            state: Some(State {
                hardware,
                cpu,
                physical,
                policies: retained_policy,
                physical_bits,
            }),
            exposed: false,
            poisoned: false,
        })
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Return the actual base-register image, arming retention before PA escape.
    /// This programs no register and grants no unit or requester ownership.
    pub fn register_for_publication(&mut self) -> Result<u64, DeviceTableError> {
        if self.poisoned {
            return Err(DeviceTableError::Poisoned);
        }
        self.exposed = true;
        Ok(self.state.as_ref().expect("retained device table").physical | BASE_SIZE)
    }

    /// Read the actual image under the real CPU/writer guard. Diagnostics may
    /// observe a poisoned owner; this grants no mutation, reuse or retirement.
    pub fn snapshot(&self, requester: u16) -> Result<[u64; 4], DeviceTableError> {
        let state = self.state.as_ref().expect("retained device table");
        let _guard = state.hardware.enter().map_err(DeviceTableError::Context)?;
        Ok(state.words(requester))
    }

    /// # Safety
    /// The requester and complete actual alias group are stopped/drained with
    /// no queued DMA. The real root/mode is admitted; retain both old/new roots,
    /// domain reservations and pins until all group entries and required unit
    /// invalidations complete. Expose each page-table root before hardware use.
    /// Do not resume an alias until the complete group transaction succeeds.
    pub unsafe fn translate(
        &mut self,
        requester: u16,
        root: PhysicalAddress,
        level: TableLevel,
        domain: DomainId,
    ) -> Result<(), DeviceTableError> {
        if self.poisoned {
            return Err(DeviceTableError::Poisoned);
        }
        let state = self.state.as_ref().expect("retained device table");
        let root = PhysicalAddress::new(root.value(), state.physical_bits)
            .map_err(DeviceTableError::Format)?;
        let new = Entry::translated(state.policy(requester), root, level, domain)?;
        self.update(requester, new)
    }

    /// # Safety
    /// As for translate: the entire actual alias group and all DMA/IRQ/deferred
    /// users are stopped/drained. Keep the old domain/root until every group
    /// entry is blocked and actual old-domain invalidation has completed.
    pub unsafe fn block(&mut self, requester: u16) -> Result<(), DeviceTableError> {
        if self.poisoned {
            return Err(DeviceTableError::Poisoned);
        }
        let state = self.state.as_ref().expect("retained device table");
        self.update(requester, Entry::blocked(state.policy(requester)))
    }

    fn update(&mut self, requester: u16, new: Entry) -> Result<(), DeviceTableError> {
        let state = self.state.as_ref().expect("retained device table");
        let guard = state.hardware.enter().map_err(DeviceTableError::Context)?;
        if !atomic::supported() {
            return Err(DeviceTableError::UnsupportedAtomic);
        }
        self.poisoned = true;
        let old = Entry::existing(
            state.words(requester),
            state.policy(requester),
            state.physical_bits,
        )?;
        let new = new.preserving_interrupts(old).words();
        let words = old.words();
        // No callback/unwind may leave a partially changed live entry reusable.
        // Both admitted images have V=1 and GV=0: Linux's host-only transition
        // writes upper then lower. Advanced/invalid old profiles were refused.
        for (word, previous, next) in [
            (2, [words[2], words[3]], [new[2], new[3]]),
            (0, [words[0], words[1]], [new[0], new[1]]),
        ] {
            // SAFETY: actual CX16 execution context remains qualified by the guard;
            // aligned half-DTE in retained WB RAM with every writer excluded.
            if !unsafe {
                atomic::replace(
                    state.pointer(requester, word),
                    previous.map(u64::to_le),
                    next.map(u64::to_le),
                )
            } {
                return Err(DeviceTableError::ConcurrentWriter);
            }
        }
        let cpu = state
            .cpu
            .address(usize::from(requester) * ENTRY_BYTES, ENTRY_BYTES)
            .map_err(DeviceTableError::Memory)?;
        // SAFETY: exact aligned retained entry span; the fixed guard excludes
        // writers while real visibility completes, including its failure path.
        unsafe { state.hardware.publish(cpu, ENTRY_BYTES) }.map_err(DeviceTableError::Memory)?;
        state
            .hardware
            .invalidate(requester, old.domain())
            .map_err(DeviceTableError::Invalidation)?;
        // Guard teardown may also unwind in a hosted context. Do not mark the
        // owner reusable until the real execution/exclusion context is released.
        drop(guard);
        self.poisoned = false;
        Ok(())
    }

    /// # Safety
    /// Every unit using this base is detached/stopped and all walkers,
    /// invalidations/reset and posted writes have acknowledged completion.
    /// All old/new root, domain and IRQ-table lifetimes were separately retired.
    pub unsafe fn retire(&mut self) {
        self.exposed = false;
    }
}

impl<H: DeviceTableHardware> Drop for DeviceTable<H> {
    fn drop(&mut self) {
        if self.exposed {
            let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
            core::mem::forget(self.state.take());
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::bus::dma::memory::{PageBacking, PageGeometry, PinnedPages};
    use alloc::{
        alloc::{alloc_zeroed, dealloc},
        boxed::Box,
        sync::Arc,
        vec,
        vec::Vec,
    };
    use core::{alloc::Layout, sync::atomic::AtomicUsize};
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Mutex,
    };

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Enter,
        RefuseContext,
        Exit,
        Allocate(usize, usize),
        Publish(usize, Vec<[u64; 4]>),
        Invalidate(u16, Option<u16>),
        CompletionInterrupt,
        SimulatedRetirement,
    }
    struct Allocation {
        cpu: usize,
        bytes: usize,
    }
    struct Model {
        active: bool,
        context_error: bool,
        geometry: Result<PageGeometry, MemoryError>,
        returned_shift: u8,
        returned_bytes: usize,
        logical: Option<usize>,
        attribute: CacheAttribute,
        next_physical: u64,
        swap_pages: bool,
        allocation_error: bool,
        expect_zero_release: bool,
        allocation_calls: usize,
        geometry_queries: usize,
        publication_calls: usize,
        fail_publish: Option<usize>,
        panic_publish: Option<usize>,
        fail_invalidate: bool,
        panic_invalidate: bool,
        panic_guard_drop: bool,
        allocations: Vec<Allocation>,
        events: Vec<Event>,
    }
    struct Monitor {
        model: Mutex<Model>,
        released_pins: AtomicUsize,
        released_bytes: AtomicUsize,
        hardware_drops: AtomicUsize,
    }
    impl Monitor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                model: Mutex::new(Model {
                    active: false,
                    context_error: false,
                    geometry: PageGeometry::base_only(12),
                    returned_shift: 12,
                    returned_bytes: DEVICE_TABLE_BYTES,
                    logical: None,
                    attribute: CacheAttribute::WriteBack,
                    next_physical: 0x0200_0000,
                    swap_pages: false,
                    allocation_error: false,
                    expect_zero_release: false,
                    allocation_calls: 0,
                    geometry_queries: 0,
                    publication_calls: 0,
                    fail_publish: None,
                    panic_publish: None,
                    fail_invalidate: false,
                    panic_invalidate: false,
                    panic_guard_drop: false,
                    allocations: Vec::new(),
                    events: Vec::new(),
                }),
                released_pins: AtomicUsize::new(0),
                released_bytes: AtomicUsize::new(0),
                hardware_drops: AtomicUsize::new(0),
            })
        }

        fn live_pins(&self) -> usize {
            self.model.lock().unwrap().allocations.len()
        }

        fn raw(&self, cpu: usize, requester: u16) -> [u64; 4] {
            let model = self.model.lock().unwrap();
            assert!(
                model
                    .allocations
                    .iter()
                    .any(|allocation| allocation.cpu == cpu
                        && allocation.bytes >= DEVICE_TABLE_BYTES)
            );
            core::array::from_fn(|word| {
                // SAFETY: the real complete fixture allocation remains pinned.
                // Observation is synchronous between mutations, with no writer.
                u64::from_le(unsafe {
                    (cpu as *const u64)
                        .add(usize::from(requester) * 4 + word)
                        .read_volatile()
                })
            })
        }

        fn cpu(&self) -> usize {
            self.model.lock().unwrap().allocations[0].cpu
        }
    }
    struct Backing {
        cpu: NonNull<u8>,
        layout: Layout,
        physical: Vec<u64>,
        shift: u8,
        attribute: CacheAttribute,
        monitor: Arc<Monitor>,
    }
    // SAFETY: actual uniquely owned zeroed storage and immutable symbolic PA
    // metadata; no safe references or asynchronous device accesses exist.
    unsafe impl Send for Backing {}
    // SAFETY: raw CPU effects are serialized by fixture ownership and its guard;
    // lifetime metadata is mutex-protected. No hardware writes these bytes.
    unsafe impl Sync for Backing {}
    // SAFETY: fresh real CPU RAM models the immutable named physical pages.
    // Malformed provider cases deliberately return inadmissible geometry/policy
    // metadata for rejection; no label or modeled cache policy reaches hardware.
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
            let mut model = self.monitor.model.lock().unwrap();
            let at = model
                .allocations
                .iter()
                .position(|allocation| allocation.cpu == self.cpu.as_ptr() as usize)
                .unwrap();
            model.allocations.remove(at);
            if model.expect_zero_release {
                for word in 0..self.layout.size() / 8 {
                    // SAFETY: this still-owned aligned buffer has not been
                    // deallocated. Preflight rejection must leave every byte at
                    // its real alloc_zeroed image, not merely avoid publishing.
                    assert_eq!(
                        unsafe { self.cpu.as_ptr().cast::<u64>().add(word).read_volatile() },
                        0
                    );
                }
            }
            drop(model);
            self.monitor.released_pins.fetch_add(1, Ordering::Relaxed);
            self.monitor
                .released_bytes
                .fetch_add(self.layout.size(), Ordering::Relaxed);
            // SAFETY: exactly the original unique allocation after its last pin.
            unsafe { dealloc(self.cpu.as_ptr(), self.layout) };
        }
    }

    struct Hardware(Arc<Monitor>);
    struct Access<'a>(&'a Monitor);
    impl Drop for Access<'_> {
        fn drop(&mut self) {
            let mut model = self.0.model.lock().unwrap();
            assert!(model.active);
            model.active = false;
            model.events.push(Event::Exit);
            let panic = core::mem::take(&mut model.panic_guard_drop);
            drop(model);
            assert!(!panic, "injected guard teardown unwind");
        }
    }
    impl Drop for Hardware {
        fn drop(&mut self) {
            assert!(
                !self.0.model.lock().unwrap().active,
                "context must outlive its guard"
            );
            self.0.hardware_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl PageSource for Hardware {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            let mut model = self.0.model.lock().unwrap();
            assert!(model.active);
            model.geometry_queries += 1;
            model.geometry
        }
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            let (shift, returned_bytes, physical, logical, actual_attribute, swap) = {
                let mut model = self.0.model.lock().unwrap();
                assert!(model.active);
                assert_eq!(attribute, CacheAttribute::WriteBack);
                model.events.push(Event::Allocate(bytes, alignment));
                model.allocation_calls += 1;
                if model.allocation_error {
                    return Err(MemoryError::OutOfMemory);
                }
                let physical = model.next_physical;
                model.next_physical += 0x0040_0000;
                (
                    model.returned_shift,
                    model.returned_bytes,
                    physical,
                    model.logical.unwrap_or(bytes),
                    model.attribute,
                    model.swap_pages,
                )
            };
            let native = 1usize << shift;
            let layout = Layout::from_size_align(returned_bytes, native).unwrap();
            // SAFETY: each call creates fresh, actually zeroed owned storage,
            // never a cloned pin or alias of an earlier returned allocation.
            let cpu =
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
            let mut pages: Vec<_> = (0..returned_bytes / native)
                .map(|index| physical + (index * native) as u64)
                .collect();
            if swap {
                pages.swap(17, 18);
            }
            assert_ne!(cpu.as_ptr() as usize as u64, physical);
            self.0.model.lock().unwrap().allocations.push(Allocation {
                cpu: cpu.as_ptr() as usize,
                bytes: returned_bytes,
            });
            PinnedPages::new(
                Box::new(Backing {
                    cpu,
                    layout,
                    physical: pages,
                    shift,
                    attribute: actual_attribute,
                    monitor: self.0.clone(),
                }),
                logical,
                native,
            )
        }
    }
    // SAFETY: synchronous software observation of actual retained CPU bytes,
    // with a modeled context/guard only. This supplies no native cache, IRQ,
    // CPU-pinning, IOMMU or real completion implementation or evidence.
    unsafe impl TableVisibility for Hardware {
        unsafe fn publish(&self, cpu: NonNull<u8>, bytes: usize) -> Result<(), MemoryError> {
            let (fail, panic) = {
                let mut model = self.0.model.lock().unwrap();
                assert!(model.active, "guard covers every publication");
                let start = cpu.as_ptr() as usize;
                assert!(model.allocations.iter().any(|allocation| {
                    allocation.cpu <= start
                        && start
                            .checked_add(bytes)
                            .is_some_and(|end| end <= allocation.cpu + allocation.bytes)
                }));
                assert!(bytes == ENTRY_BYTES || bytes == DEVICE_TABLE_BYTES);
                let indices: &[usize] = if bytes == DEVICE_TABLE_BYTES {
                    &[0, 0x8000, 0xffff]
                } else {
                    &[0]
                };
                let images = indices
                    .iter()
                    .map(|index| {
                        core::array::from_fn(|word| {
                            // SAFETY: exact retained borrowed CPU span, no concurrent
                            // writer. Capture literal LE words independently of Entry.
                            u64::from_le(unsafe {
                                cpu.as_ptr()
                                    .cast::<u64>()
                                    .add(index * 4 + word)
                                    .read_volatile()
                            })
                        })
                    })
                    .collect();
                model.events.push(Event::Publish(bytes, images));
                model.publication_calls += 1;
                (
                    model.fail_publish == Some(model.publication_calls),
                    model.panic_publish == Some(model.publication_calls),
                )
            };
            assert!(!panic, "injected visibility unwind");
            if fail {
                Err(MemoryError::Unavailable)
            } else {
                Ok(())
            }
        }
    }
    // SAFETY: isolated synchronous software-only host profile, with no hardware
    // DTE/guest/ATS/IRQ/encryption writer. The guard models writer/CPU exclusion;
    // supported() qualifies CX16 under the host OS process ISA contract across
    // allowed scheduler CPUs; no fake immobility or native IRQ control is claimed.
    unsafe impl DeviceTableHardware for Hardware {
        type Access<'a>
            = Access<'a>
        where
            Self: 'a;
        fn enter(&self) -> Result<Self::Access<'_>, DmaError> {
            let mut model = self.0.model.lock().unwrap();
            if model.context_error {
                model.events.push(Event::RefuseContext);
                return Err(DmaError::MappingFailed);
            }
            assert!(!model.active, "no writer or callback may reenter");
            model.active = true;
            model.events.push(Event::Enter);
            Ok(Access(&self.0))
        }
        fn invalidate(&self, requester: u16, old_domain: Option<DomainId>) -> Result<(), DmaError> {
            let (fail, panic) = {
                let mut model = self.0.model.lock().unwrap();
                assert!(model.active, "guard covers acknowledged invalidation");
                model.events.push(Event::Invalidate(
                    requester,
                    old_domain.map(DomainId::value),
                ));
                // A modeled completion interrupt remains deliverable while the
                // writer guard is active; it never reenters the device owner.
                model.events.push(Event::CompletionInterrupt);
                (model.fail_invalidate, model.panic_invalidate)
            };
            assert!(!panic, "injected invalidation unwind");
            if fail {
                Err(DmaError::InvalidationFailed)
            } else {
                Ok(())
            }
        }
    }

    fn policies() -> Vec<u8> {
        let mut flags = vec![0; REQUESTERS];
        flags[0] = 0x15;
        flags[0x8000] = 0xa2;
        flags[0xffff] = 0xc7;
        flags
    }
    fn blocked(flags: u8) -> [u64; 4] {
        let mut words = [1, u64::from((flags >> 4) & 3) << 40, 0, 0];
        for (flag, bit) in [(1, 56), (2, 57), (4, 58), (64, 62), (128, 63)] {
            if flags & flag != 0 {
                words[2] |= 1u64 << bit;
            }
        }
        if flags & 0x30 == 0x10 {
            words[0] |= 1u64 << 62;
        }
        words
    }
    fn translated(flags: u8, root: u64, mode: u8, domain: u16) -> [u64; 4] {
        let mut words = blocked(flags);
        words[0] |= 2 | (1u64 << 61) | (1u64 << 62) | root | (u64::from(mode) << 9);
        words[1] |= u64::from(domain);
        words
    }
    fn construct(monitor: &Arc<Monitor>, flags: &[u8]) -> Option<DeviceTable<Hardware>> {
        // SAFETY: isolated fixture supplies the admitted software-only profile
        // and complete literal policies. No hardware root is programmed.
        let result = unsafe { DeviceTable::new(Hardware(monitor.clone()), flags, 48) };
        if !atomic::supported() {
            assert!(matches!(result, Err(DeviceTableError::UnsupportedAtomic)));
            assert_eq!(monitor.model.lock().unwrap().allocation_calls, 0);
            assert!(!monitor.model.lock().unwrap().active);
            assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
            return None;
        }
        Some(match result {
            Ok(table) => table,
            Err(error) => panic!("valid fixture: {error:?}"),
        })
    }
    fn retire(mut table: DeviceTable<Hardware>, monitor: &Monitor) {
        monitor
            .model
            .lock()
            .unwrap()
            .events
            .push(Event::SimulatedRetirement);
        // SAFETY: simulated detached/reset units with no device or asynchronous
        // walker. This is not a native invalidation or retirement witness.
        unsafe { table.retire() };
        drop(table);
        assert_eq!(monitor.live_pins(), 0);
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
    }
    fn root() -> PhysicalAddress {
        PhysicalAddress::new(0x1234_5000, 48).unwrap()
    }

    #[test]
    fn initial_policy_is_literal_complete_immutable_and_guarded() {
        let monitor = Monitor::new();
        let mut flags = policies();
        let Some(mut table) = construct(&monitor, &flags) else {
            return;
        };
        flags.fill(0); // Caller storage is neither retained nor consulted later.
        let expected = [
            (
                0u16,
                [
                    0x4000_0000_0000_0001,
                    0x0000_0100_0000_0000,
                    0x0500_0000_0000_0000,
                    0,
                ],
            ),
            (0x8000, [1, 0x0000_0200_0000_0000, 0x8200_0000_0000_0000, 0]),
            (0xffff, [1, 0, 0xc700_0000_0000_0000, 0]),
        ];
        for (requester, words) in expected {
            assert_eq!(table.snapshot(requester), Ok(words));
        }
        let cpu = monitor.cpu();
        for requester in 0..REQUESTERS {
            let words = expected
                .iter()
                .find(|(rid, _)| usize::from(*rid) == requester)
                .map_or([1, 0, 0, 0], |(_, words)| *words);
            assert_eq!(monitor.raw(cpu, requester as u16), words);
        }
        assert_eq!(table.snapshot(0x7fff), Ok([1, 0, 0, 0]));
        assert_eq!(table.register_for_publication(), Ok(0x0200_01ff));
        let model = monitor.model.lock().unwrap();
        assert_eq!(model.events[0], Event::Enter);
        assert_eq!(model.events[1], Event::Allocate(DEVICE_TABLE_BYTES, 4096));
        assert_eq!(
            model.events[2],
            Event::Publish(
                DEVICE_TABLE_BYTES,
                expected.into_iter().map(|(_, words)| words).collect()
            )
        );
        assert_eq!(model.events[3], Event::Exit);
        assert!(!model.active);
        drop(model);
        assert_eq!(monitor.released_bytes.load(Ordering::Relaxed), 0);
        retire(table, &monitor);
        assert_eq!(
            monitor.released_bytes.load(Ordering::Relaxed),
            DEVICE_TABLE_BYTES
        );
    }

    #[test]
    fn updates_preserve_policy_and_flush_observed_aliases_and_old_domain() {
        let monitor = Monitor::new();
        let flags = policies();
        let Some(mut table) = construct(&monitor, &flags) else {
            return;
        };
        table.register_for_publication().unwrap();
        for requester in [0, 0x8000, 0xffff] {
            let before = monitor.model.lock().unwrap().events.len();
            // SAFETY: every symbolic root/domain and requester alias is held
            // stopped by this software fixture; no root is used by hardware.
            unsafe {
                table.translate(
                    requester,
                    root(),
                    TableLevel::new(3).unwrap(),
                    DomainId::new(7).unwrap(),
                )
            }
            .unwrap();
            let expected = translated(flags[usize::from(requester)], 0x1234_5000, 3, 7);
            assert_eq!(monitor.raw(monitor.cpu(), requester), expected);
            let model = monitor.model.lock().unwrap();
            assert_eq!(
                &model.events[before..],
                &[
                    Event::Enter,
                    Event::Publish(32, vec![expected]),
                    Event::Invalidate(requester, None),
                    Event::CompletionInterrupt,
                    Event::Exit
                ]
            );
            drop(model);
            assert_eq!(table.snapshot(requester), Ok(expected));
            // SAFETY: same stopped alias transaction, with both old/new symbolic
            // root/domain reservations retained through the modeled completion.
            unsafe {
                table.translate(
                    requester,
                    PhysicalAddress::new(0x5678_9000, 48).unwrap(),
                    TableLevel::new(4).unwrap(),
                    DomainId::new(9).unwrap(),
                )
            }
            .unwrap();
            assert!(
                monitor
                    .model
                    .lock()
                    .unwrap()
                    .events
                    .contains(&Event::Invalidate(requester, Some(7)))
            );
            let expected = translated(flags[usize::from(requester)], 0x5678_9000, 4, 9);
            assert_eq!(table.snapshot(requester), Ok(expected));
            // SAFETY: the entire modeled alias group remains stopped until block.
            unsafe { table.block(requester) }.unwrap();
            assert_eq!(
                table.snapshot(requester),
                Ok(blocked(flags[usize::from(requester)]))
            );
            assert!(
                monitor
                    .model
                    .lock()
                    .unwrap()
                    .events
                    .contains(&Event::Invalidate(requester, Some(9)))
            );
            assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 0);
        }
        assert!(!table.is_poisoned());
        retire(table, &monitor);
    }

    #[test]
    fn width_policy_and_actual_unsupported_atomic_refuse_before_allocation() {
        for (flags, bits, expected) in [
            (
                policies(),
                31,
                DeviceTableError::Format(FormatError::PhysicalWidth),
            ),
            (vec![0; REQUESTERS - 1], 48, DeviceTableError::PolicyCount),
            (
                {
                    let mut flags = policies();
                    flags[0xffff] = 8;
                    flags
                },
                48,
                DeviceTableError::Policy,
            ),
        ] {
            let monitor = Monitor::new();
            // SAFETY: malformed numeric/profile admission is rejected before effects.
            assert!(
                matches!(unsafe { DeviceTable::new(Hardware(monitor.clone()), &flags, bits) }, Err(error) if error == expected)
            );
            assert!(monitor.model.lock().unwrap().events.is_empty());
            assert_eq!(monitor.model.lock().unwrap().allocation_calls, 0);
            assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
        }
        let monitor = Monitor::new();
        let table = construct(&monitor, &policies());
        if let Some(table) = table {
            retire(table, &monitor);
        } else {
            assert!(!atomic::supported());
        }
    }

    #[test]
    fn provider_contiguity_dma32_cache_size_and_geometry_errors_roll_back() {
        if !atomic::supported() {
            assert!(construct(&Monitor::new(), &policies()).is_none());
            return;
        }
        for case in 0..8 {
            let monitor = Monitor::new();
            let expected = {
                let mut model = monitor.model.lock().unwrap();
                model.expect_zero_release = true;
                match case {
                    0 => {
                        model.geometry = Err(MemoryError::Unavailable);
                        DeviceTableError::Memory(MemoryError::Unavailable)
                    }
                    1 => {
                        model.allocation_error = true;
                        DeviceTableError::Memory(MemoryError::OutOfMemory)
                    }
                    2 => {
                        model.attribute = CacheAttribute::WriteCombining;
                        DeviceTableError::InvalidProvider
                    }
                    3 => {
                        model.returned_shift = 13;
                        DeviceTableError::InvalidProvider
                    }
                    4 => {
                        model.logical = Some(DEVICE_TABLE_BYTES - 4096);
                        DeviceTableError::InvalidProvider
                    }
                    5 => {
                        model.swap_pages = true;
                        DeviceTableError::PhysicalContiguity
                    }
                    6 => {
                        model.next_physical = DMA32_LIMIT - DEVICE_TABLE_BYTES as u64 + 4096;
                        DeviceTableError::AddressLimit
                    }
                    _ => {
                        model.returned_bytes -= 4096;
                        model.logical = Some(DEVICE_TABLE_BYTES - 4096);
                        DeviceTableError::InvalidProvider
                    }
                }
            };
            // SAFETY: isolated deliberately unsuitable provider output; no live base.
            assert!(
                matches!(unsafe { DeviceTable::new(Hardware(monitor.clone()), &policies(), 48) }, Err(error) if error == expected)
            );
            let model = monitor.model.lock().unwrap();
            assert!(!model.active);
            assert_eq!(model.publication_calls, 0);
            assert_eq!(model.allocation_calls, usize::from(case != 0));
            drop(model);
            assert_eq!(monitor.live_pins(), 0);
            assert_eq!(
                monitor.released_pins.load(Ordering::Relaxed),
                usize::from(case >= 2)
            );
            assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn native_eight_k_larger_granules_and_distinct_fresh_allocations_are_retained() {
        for shift in [13, 22] {
            let monitor = Monitor::new();
            {
                let mut model = monitor.model.lock().unwrap();
                model.returned_shift = shift;
                model.geometry = PageGeometry::base_only(shift);
                model.returned_bytes = DEVICE_TABLE_BYTES.max(1usize << shift);
                model.next_physical = if shift == 13 {
                    DMA32_LIMIT - DEVICE_TABLE_BYTES as u64
                } else {
                    0x0200_0000
                };
            }
            let Some(mut table) = construct(&monitor, &policies()) else {
                return;
            };
            let expected = monitor.model.lock().unwrap().returned_bytes;
            let actual_base = table.register_for_publication().unwrap() & !0xfff;
            assert!(actual_base + DEVICE_TABLE_BYTES as u64 <= DMA32_LIMIT);
            assert_eq!(monitor.released_bytes.load(Ordering::Relaxed), 0);
            if expected > DEVICE_TABLE_BYTES {
                let cpu = monitor.cpu();
                for offset in [DEVICE_TABLE_BYTES, expected - 8] {
                    // SAFETY: the original larger native pin is fully retained.
                    // Its unused tail must not receive DTE initialization stores.
                    assert_eq!(
                        unsafe { (cpu as *const u8).add(offset).cast::<u64>().read_volatile() },
                        0
                    );
                }
                assert!(monitor.model.lock().unwrap().events.iter().all(|event|
                    !matches!(event, Event::Publish(bytes, _) if *bytes != DEVICE_TABLE_BYTES)));
            }
            retire(table, &monitor);
            assert_eq!(monitor.released_bytes.load(Ordering::Relaxed), expected);
        }
        let monitor = Monitor::new();
        let Some(mut first) = construct(&monitor, &policies()) else {
            return;
        };
        let Some(mut second) = construct(&monitor, &policies()) else {
            unreachable!();
        };
        let first_base = first.register_for_publication().unwrap();
        let second_base = second.register_for_publication().unwrap();
        assert_ne!(first_base, second_base);
        let addresses: Vec<_> = monitor
            .model
            .lock()
            .unwrap()
            .allocations
            .iter()
            .map(|allocation| allocation.cpu)
            .collect();
        assert_eq!(addresses.len(), 2);
        assert_ne!(addresses[0], addresses[1]);
        // SAFETY: independent fresh model tables, neither attached to hardware.
        unsafe {
            first.translate(
                0xffff,
                root(),
                TableLevel::new(2).unwrap(),
                DomainId::new(3).unwrap(),
            )
        }
        .unwrap();
        assert_eq!(second.snapshot(0xffff), Ok(blocked(0xc7)));
        // SAFETY: independent simulated retired roots, no asynchronous accesses.
        unsafe {
            first.retire();
            second.retire();
        }
        drop(first);
        drop(second);
        assert_eq!(monitor.live_pins(), 0);
        assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 2);
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn context_refusal_guards_snapshot_and_updates_without_owner_release() {
        let monitor = Monitor::new();
        let Some(mut table) = construct(&monitor, &policies()) else {
            return;
        };
        monitor.model.lock().unwrap().context_error = true;
        let before = monitor.model.lock().unwrap().events.len();
        assert_eq!(
            table.snapshot(0xffff),
            Err(DeviceTableError::Context(DmaError::MappingFailed))
        );
        // SAFETY: fixture owns stopped requester; context refusal precedes CPU stores.
        assert_eq!(
            unsafe { table.block(0xffff) },
            Err(DeviceTableError::Context(DmaError::MappingFailed))
        );
        assert_eq!(
            &monitor.model.lock().unwrap().events[before..],
            &[Event::RefuseContext, Event::RefuseContext]
        );
        assert!(!table.is_poisoned());
        assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 0);
        monitor.model.lock().unwrap().context_error = false;
        assert_eq!(table.snapshot(0xffff), Ok(blocked(0xc7)));
        retire(table, &monitor);
    }

    #[test]
    fn bad_new_root_leaves_owner_usable_but_unknown_old_profile_poisoned() {
        let monitor = Monitor::new();
        let Some(mut table) = construct(&monitor, &policies()) else {
            return;
        };
        table.register_for_publication().unwrap();
        for (root, expected) in [
            (
                PhysicalAddress::new(0x1234_5001, 48).unwrap(),
                DeviceTableError::Format(FormatError::Alignment),
            ),
            (
                PhysicalAddress::new(1u64 << 48, 52).unwrap(),
                DeviceTableError::Format(FormatError::PhysicalAddress),
            ),
        ] {
            let before = monitor.model.lock().unwrap().events.len();
            // SAFETY: only unsuitable new numeric root metadata is being tested;
            // it must be rejected before entering the mutation-capable context.
            assert_eq!(
                unsafe {
                    table.translate(
                        0xffff,
                        root,
                        TableLevel::new(3).unwrap(),
                        DomainId::new(7).unwrap(),
                    )
                },
                Err(expected)
            );
            assert!(!table.is_poisoned());
            assert_eq!(monitor.model.lock().unwrap().events.len(), before);
            assert_eq!(table.snapshot(0xffff), Ok(blocked(0xc7)));
        }
        let cpu = monitor.cpu();
        // SAFETY: deliberate old-image corruption in isolated owned CPU RAM,
        // between all accesses with no device or competing writer. This does
        // not pretend a valid aliased fresh allocation or admitted live profile.
        unsafe {
            (cpu as *mut u64)
                .add(usize::from(0xffffu16) * 4)
                .write_volatile((1u64 | (1 << 8)).to_le())
        };
        let old = monitor.raw(cpu, 0xffff);
        let before = monitor.model.lock().unwrap().events.len();
        // SAFETY: the stopped fixture exercises malformed-old-profile refusal;
        // no store or visibility/invalidation may run under the unknown image.
        assert_eq!(
            unsafe { table.block(0xffff) },
            Err(DeviceTableError::Profile)
        );
        assert!(table.is_poisoned());
        assert_eq!(monitor.raw(cpu, 0xffff), old);
        assert_eq!(
            &monitor.model.lock().unwrap().events[before..],
            &[Event::Enter, Event::Exit]
        );
        assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 0);
        retire(table, &monitor);
    }

    #[test]
    fn publication_and_invalidation_failure_or_unwind_poison_before_reuse() {
        for case in 0..5 {
            let monitor = Monitor::new();
            let Some(mut table) = construct(&monitor, &policies()) else {
                return;
            };
            table.register_for_publication().unwrap();
            // SAFETY: stopped symbolic requester, retained roots/domains.
            unsafe {
                table.translate(
                    0xffff,
                    root(),
                    TableLevel::new(3).unwrap(),
                    DomainId::new(7).unwrap(),
                )
            }
            .unwrap();
            {
                let mut model = monitor.model.lock().unwrap();
                match case {
                    0 => model.fail_publish = Some(model.publication_calls + 1),
                    1 => model.fail_invalidate = true,
                    2 => model.panic_publish = Some(model.publication_calls + 1),
                    3 => model.panic_invalidate = true,
                    _ => model.panic_guard_drop = true,
                }
            }
            if case < 2 {
                let expected = if case == 0 {
                    DeviceTableError::Memory(MemoryError::Unavailable)
                } else {
                    DeviceTableError::Invalidation(DmaError::InvalidationFailed)
                };
                // SAFETY: no real DMA; injected callback failure is uncertain.
                assert_eq!(unsafe { table.block(0xffff) }, Err(expected));
            } else {
                // SAFETY: same software profile, now injecting a callback unwind.
                assert!(catch_unwind(AssertUnwindSafe(|| unsafe { table.block(0xffff) })).is_err());
            }
            assert!(table.is_poisoned());
            assert!(
                !monitor.model.lock().unwrap().active,
                "guard must release on all exits"
            );
            assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 0);
            assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);
            // Poisoned reads remain useful under the actual context guard.
            assert_eq!(table.snapshot(0xffff), Ok(blocked(0xc7)));
            let before = monitor.model.lock().unwrap().events.len();
            // SAFETY: only poisoned-owner refusal; no second store may happen.
            assert_eq!(
                unsafe { table.block(0xffff) },
                Err(DeviceTableError::Poisoned)
            );
            assert_eq!(
                table.register_for_publication(),
                Err(DeviceTableError::Poisoned)
            );
            assert_eq!(monitor.model.lock().unwrap().events.len(), before);
            if case == 1 || case >= 3 {
                assert!(
                    monitor
                        .model
                        .lock()
                        .unwrap()
                        .events
                        .contains(&Event::Invalidate(0xffff, Some(7)))
                );
            }
            retire(table, &monitor);
        }
    }

    #[test]
    fn initial_publication_failure_releases_unexposed_pin_and_context() {
        if !atomic::supported() {
            assert!(construct(&Monitor::new(), &policies()).is_none());
            return;
        }
        for panic in [false, true] {
            let monitor = Monitor::new();
            {
                let mut model = monitor.model.lock().unwrap();
                if panic {
                    model.panic_publish = Some(1);
                } else {
                    model.fail_publish = Some(1);
                }
            }
            if panic {
                // SAFETY: the new table is unreachable by any modeled remapper.
                assert!(
                    catch_unwind(AssertUnwindSafe(|| unsafe {
                        DeviceTable::new(Hardware(monitor.clone()), &policies(), 48)
                    }))
                    .is_err()
                );
            } else {
                // SAFETY: initial visibility fails before a base image escapes.
                assert!(matches!(
                    unsafe { DeviceTable::new(Hardware(monitor.clone()), &policies(), 48) },
                    Err(DeviceTableError::Memory(MemoryError::Unavailable))
                ));
            }
            assert!(!monitor.model.lock().unwrap().active);
            assert_eq!(monitor.live_pins(), 0);
            assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 1);
            assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn exposed_drop_keeps_entire_two_megabyte_pin_and_hardware_context() {
        let monitor = Monitor::new();
        let Some(table) = construct(&monitor, &policies()) else {
            return;
        };
        drop(table);
        assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 1);
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 1);
        let monitor = Monitor::new();
        let Some(mut table) = construct(&monitor, &policies()) else {
            return;
        };
        table.register_for_publication().unwrap();
        let before = quarantined_tables();
        // One deliberate complete 2MiB leak proves actual quarantine. Do not
        // reclaim bytes behind the retained forgotten pin/context owners.
        drop(table);
        assert!(quarantined_tables() >= before.saturating_add(1));
        assert_eq!(monitor.live_pins(), 1);
        assert_eq!(monitor.released_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 0);
        assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);
    }
}
