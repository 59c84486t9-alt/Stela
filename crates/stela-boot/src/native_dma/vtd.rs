// SPDX-License-Identifier: GPL-2.0-only
// Copyright © 2006-2015 Intel Corporation.
// Register definitions and legacy invalidation/context sequencing adapted from
// Linux drivers/iommu/intel/{iommu.h,iommu.c,dmar.c}, commit
// a804c5742bff224d4cb4d25dd383554d598be32b. Source hashes and license terms:
// crates/stela-drivers/src/platform/THIRD_PARTY.md and LICENSES/GPL-2.0-only.txt.
//! Exclusive legacy VT-d unit with distinct owned requester contexts/domains.
//! Noncoherent table walks use actual CPUID-qualified CLFLUSH plus MFENCE.
//! This never attaches by guessing a DMAR scope or changes active firmware
//! domains. ATS, scalable mode, RMRR preservation, peer groups and AMD-Vi need
//! their actual platform owners and are not supplied by this backend.
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    cell::UnsafeCell,
    mem::ManuallyDrop,
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use stela_drivers::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DomainMapping},
    memory::{CacheAttribute, CpuMapping, PageSource, PinnedPages},
    pages::DmaPages,
};

#[cfg(not(test))]
use super::requester::RequesterClaim;
#[cfg(test)]
use crate::boot_requester::RequesterClaim;

const PAGE: usize = 4096;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const READ: u64 = 1;
const WRITE: u64 = 2;
const CAP: usize = 0x08;
const ECAP: usize = 0x10;
const GCMD: usize = 0x18;
const GSTS: usize = 0x1c;
const RTADDR: usize = 0x20;
const CCMD: usize = 0x28;
const FSTS: usize = 0x34;
const FECTL: usize = 0x38;
const PMEN: usize = 0x64;
const TRANSLATION: u32 = 1 << 31;
const ROOT_POINTER: u32 = 1 << 30;
const WRITE_BUFFER: u32 = 1 << 27;
const QUEUED_INVALIDATION: u32 = 1 << 26;
const INTERRUPT_REMAP: u32 = 1 << 25;
const CONTEXT_INVALIDATE: u64 = 1 << 63;
const CONTEXT_GLOBAL: u64 = 1 << 61;
const IOTLB_INVALIDATE: u64 = 1 << 63;
const IOTLB_GLOBAL: u64 = 1 << 60;
const IOTLB_DOMAIN: u64 = 2 << 60;
const IOTLB_DOMAIN_SHIFT: u32 = 32;
const IOTLB_WRITE_DRAIN: u64 = 1 << 48;
const IOTLB_READ_DRAIN: u64 = 1 << 49;
const CAP_WRITE_DRAIN: u64 = 1 << 54;
const CAP_READ_DRAIN: u64 = 1 << 55;
/// The unit needs its write buffer flushed after table updates (RWBF).
const CAP_WRITE_BUFFER: u64 = 1 << 4;
/// The unit may cache not-present entries (CM), so a new entry needs an
/// IOTLB invalidation too.
const CAP_CACHING_MODE: u64 = 1 << 7;
const MSI_START: u64 = 0xfee0_0000;
const MSI_END: u64 = 0xfef0_0000;

static QUARANTINED_DOMAINS: AtomicU64 = AtomicU64::new(0);

pub fn quarantined_domains() -> u64 {
    QUARANTINED_DOMAINS.load(Ordering::Relaxed)
}

static QUARANTINED_UNITS: AtomicU64 = AtomicU64::new(0);

pub fn quarantined_units() -> u64 {
    QUARANTINED_UNITS.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdError {
    Busy,
    Unsupported,
    RegisterRange,
    RegisterRead,
    Memory,
    Timeout,
    Invalidation,
    FaultOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRecord {
    pub index: usize,
    pub address: u64,
    pub requester: u16,
    pub reason: u8,
    pub read: bool,
}

/// An actual exclusive, mapped VT-d register window and monotonic deadline.
///
/// # Safety
/// All register accesses have their real effects, obey width/order and stay
/// within an exclusively owned UC mapping. Its lifetime includes uncertain
/// hardware teardown. The clock must advance while polling on this CPU.
pub unsafe trait Registers: Send + Sync {
    fn bytes(&self) -> usize;
    fn read32(&self, offset: usize) -> u32;
    fn read64(&self, offset: usize) -> u64;
    fn write32(&self, offset: usize, value: u32);
    fn write64(&self, offset: usize, value: u64);
    fn ticks(&self) -> u64;
    fn timeout_ticks(&self) -> u64;
    /// Evict actual dirty WB table lines for a noncoherent walker.
    ///
    /// # Safety
    /// The whole CPU span is retained mapped WB RAM, line-aligned, and
    /// CLFLUSH/`line` have been qualified by actual CPUID on this CPU.
    unsafe fn flush_table(&self, cpu: NonNull<u8>, bytes: usize, line: usize) {
        // SAFETY: caller supplied the qualified, retained actual CPU span.
        unsafe { flush_table(cpu, bytes, line) };
    }
}

unsafe fn flush_table(cpu: NonNull<u8>, bytes: usize, line: usize) {
    for offset in (0..bytes).step_by(line) {
        // SAFETY: caller retains the complete qualified WB CPU span.
        unsafe {
            core::arch::asm!("clflush [{}]", in(reg) cpu.as_ptr().add(offset), options(nostack, preserves_flags));
        }
    }
}

fn qualified_flush_line(edx: u32, ebx: u32) -> Result<usize, VtdError> {
    let line = ((ebx >> 8) & 255) as usize * 8;
    if edx & (1 << 19) == 0 || !line.is_power_of_two() || !(8..=PAGE).contains(&line) {
        Err(VtdError::Unsupported)
    } else {
        Ok(line)
    }
}

/// Physical MMIO, kept valid by the platform's unit/mapping owner.
pub struct MmioRegisters {
    base: NonNull<u8>,
    bytes: usize,
    clock: fn() -> u64,
    timeout: u64,
}

impl MmioRegisters {
    /// # Safety
    /// `base..base+bytes` is the real exclusively owned UC register window,
    /// stable across roots and retained until successful shutdown or quarantine.
    /// `clock` is monotonic and `timeout` is nonzero and less than half its wrap.
    pub unsafe fn new(
        base: NonNull<u8>,
        bytes: usize,
        clock: fn() -> u64,
        timeout: u64,
    ) -> Result<Self, VtdError> {
        if bytes < 4096
            || (base.as_ptr() as usize).checked_add(bytes).is_none()
            || !(base.as_ptr() as usize).is_multiple_of(8)
            || timeout == 0
            || timeout > u64::MAX / 2
        {
            return Err(VtdError::RegisterRange);
        }
        Ok(Self {
            base,
            bytes,
            clock,
            timeout,
        })
    }

    fn address<T>(&self, offset: usize) -> *mut T {
        assert!(offset.is_multiple_of(core::mem::align_of::<T>()));
        assert!(
            offset
                .checked_add(size_of::<T>())
                .is_some_and(|end| end <= self.bytes)
        );
        // SAFETY: the full checked register access is in the retained mapping.
        unsafe { self.base.as_ptr().add(offset).cast() }
    }
}

// SAFETY: exclusive register ownership is serialized by Unit; no safe CPU
// memory references are exposed, and its physical mapping is root-stable.
unsafe impl Send for MmioRegisters {}
// SAFETY: volatile accesses are serialized by the unit's process-context lock.
unsafe impl Sync for MmioRegisters {}
// SAFETY: construction requires the actual UC mapping and monotonic clock.
unsafe impl Registers for MmioRegisters {
    fn bytes(&self) -> usize {
        self.bytes
    }
    fn read32(&self, offset: usize) -> u32 {
        unsafe { self.address::<u32>(offset).read_volatile() }
    }
    fn read64(&self, offset: usize) -> u64 {
        unsafe { self.address::<u64>(offset).read_volatile() }
    }
    fn write32(&self, offset: usize, value: u32) {
        unsafe { self.address::<u32>(offset).write_volatile(value) }
    }
    fn write64(&self, offset: usize, value: u64) {
        unsafe { self.address::<u64>(offset).write_volatile(value) }
    }
    fn ticks(&self) -> u64 {
        (self.clock)()
    }
    fn timeout_ticks(&self) -> u64 {
        self.timeout
    }
}

struct Table {
    pages: PinnedPages,
    cpu: CpuMapping,
}

impl Table {
    fn new(source: &dyn PageSource, physical_bits: u8) -> Result<Self, VtdError> {
        let pages = source
            .allocate(PAGE, PAGE, CacheAttribute::WriteBack)
            .map_err(|_| VtdError::Memory)?;
        if pages.bytes() != PAGE
            || pages.page_shift() != 12
            || pages.physical_pages().len() != 1
            || pages.physical_pages()[0] >= (1u64 << physical_bits)
        {
            return Err(VtdError::Memory);
        }
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(|_| VtdError::Memory)?;
        Ok(Self { pages, cpu })
    }
    fn physical(&self) -> u64 {
        self.pages.physical_pages()[0]
    }
    fn pointer(&self, index: usize) -> *mut u64 {
        self.cpu
            .address(index * 8, 8)
            .expect("bounded page-table entry")
            .as_ptr()
            .cast()
    }
    fn read(&self, index: usize) -> u64 {
        // SAFETY: live coherent table page, accessed with the unit lock held.
        unsafe { self.pointer(index).read_volatile() }
    }
    fn write(&self, index: usize, value: u64) {
        // SAFETY: unique software table owner under the unit lock; publication
        // and acknowledged invalidations precede device use/page release.
        unsafe { self.pointer(index).write_volatile(value) };
    }

    fn flush<R: Registers>(&self, registers: &R, line: usize) {
        let pointer = self.cpu.address(0, PAGE).expect("retained table page");
        // SAFETY: qualified CLFLUSH/line; actual retained page-aligned WB RAM.
        unsafe { registers.flush_table(pointer, PAGE, line) };
    }
}

struct LiveMapping {
    info: DomainMapping,
    direction: Direction,
    _pages: DmaPages,
    leaves: Vec<(usize, usize)>,
}

struct DomainState {
    did: u16,
    generation: u64,
    claim: RequesterClaim,
    tables: Vec<Table>,
    table_index: BTreeMap<u64, usize>,
    mappings: BTreeMap<u64, LiveMapping>,
    quarantined: bool,
}
struct State {
    root: Table,
    /// Each allowed requester bus's context table, under its root entry.
    contexts: BTreeMap<u8, Table>,
    allowed: Vec<u16>,
    domains: BTreeMap<u16, DomainState>,
    next_id: u64,
    next_generation: u64,
    poisoned: bool,
    shutdown: bool,
}

/// A single exclusive hardware remapping owner. All operations and final Drop
/// require process/deferred context; the lock is not a hard-IRQ service.
pub struct Unit<R: Registers> {
    registers: ManuallyDrop<R>,
    source: &'static (dyn PageSource + Sync),
    held: AtomicBool,
    state: ManuallyDrop<UnsafeCell<State>>,
    levels: u8,
    physical_bits: u8,
    iotlb: usize,
    cap: u64,
    max_domains: u32,
    table_cacheline: Option<usize>,
}

// SAFETY: all mutable state/register accesses use the acquire/release lock.
// IRQ reentry and platform ownership changes are excluded by construction.
unsafe impl<R: Registers> Sync for Unit<R> {}

struct Guard<'a, R: Registers>(&'a Unit<R>);
impl<R: Registers> Guard<'_, R> {
    fn state(&mut self) -> &mut State {
        // SAFETY: only one guard owns the unit's acquire/release lock; the
        // mutable borrow cannot escape the guard or overlap another borrow.
        unsafe { &mut *self.0.state.get() }
    }
}
impl<R: Registers> Drop for Guard<'_, R> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}

pub(super) fn publish() {
    // SAFETY: MFENCE is in the x86-64 baseline. The default memory clobber
    // prevents compiler motion; the coherent platform makes actual WB stores
    // visible before subsequent UC register/descriptor publication.
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

impl<R: Registers> Unit<R> {
    /// Snapshot real primary fault records while fault interrupts are masked.
    /// This polled path does not supply a native interrupt handler.
    pub fn pending_faults(&self) -> Result<Vec<FaultRecord>, VtdError> {
        let _guard = self.lock();
        let status = self.registers.read32(FSTS);
        if status & 1 != 0 {
            return Err(VtdError::FaultOverflow);
        }
        let mut faults = Vec::new();
        if status & 2 == 0 {
            return Ok(faults);
        }
        let base = ((self.cap >> 24) & 0x3ff) as usize * 16;
        let count = ((self.cap >> 40) & 255) as usize + 1;
        if base < 0x80
            || base
                .checked_add(count * 16)
                .is_none_or(|end| end > self.registers.bytes())
        {
            return Err(VtdError::RegisterRange);
        }
        for index in 0..count {
            let register = base + index * 16;
            let high = self.registers.read32(register + 12);
            if high & (1 << 31) == 0 {
                continue;
            }
            let requester = self.registers.read32(register + 8) as u16;
            let address = self.registers.read64(register) & !4095;
            faults.push(FaultRecord {
                index,
                address,
                requester,
                reason: high as u8,
                read: high & (1 << 30) != 0,
            });
        }
        Ok(faults)
    }

    /// Acknowledge an observed record only after its owner recorded/handled it.
    pub fn acknowledge_fault(&self, index: usize) -> Result<(), VtdError> {
        let _guard = self.lock();
        let base = ((self.cap >> 24) & 0x3ff) as usize * 16;
        let count = ((self.cap >> 40) & 255) as usize + 1;
        if index >= count
            || base < 0x80
            || base
                .checked_add(count * 16)
                .is_none_or(|end| end > self.registers.bytes())
        {
            return Err(VtdError::RegisterRange);
        }
        self.registers.write32(base + index * 16 + 12, 1 << 31);
        self.registers.write32(FSTS, 1 | 2 | 1 << 7);
        Ok(())
    }
    /// Take ownership of an inactive unit, not an active firmware domain.
    ///
    /// # Safety
    /// Platform discovery has proved this physical unit routes exactly this
    /// complete unique flat requester inventory, with no unresolved aliases,
    /// bridge routes/groups/RMRRs. All requesters
    /// behind the unit are stopped and drained, with ATS/PRI/PASID and device
    /// NoSnoop disabled. No other CPU/firmware/SMM owner can change it. Native
    /// WB RAM DMA is coherent independently of the ECAP table-walk coherency
    /// bit. Bus mastering remains stopped until real mapping publication.
    /// The register mapping and source's backing mappings stay valid across
    /// roots and uncertain failures. No operation/final release runs in an IRQ.
    pub unsafe fn take_over(
        registers: R,
        source: &'static (dyn PageSource + Sync),
        requesters: &[u16],
        physical_bits: u8,
    ) -> Result<Arc<Self>, VtdError> {
        let mut allowed = requesters.to_vec();
        allowed.sort_unstable();
        if allowed.is_empty() || allowed.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(VtdError::Unsupported);
        }
        if !(32..=52).contains(&physical_bits) || registers.bytes() < 4096 {
            return Err(VtdError::Unsupported);
        }
        let cap = registers.read64(CAP);
        let ecap = registers.read64(ECAP);
        let status = registers.read32(GSTS);
        let protected = registers.read32(PMEN);
        if cap == u64::MAX || ecap == u64::MAX || status == u32::MAX || protected == u32::MAX {
            return Err(VtdError::RegisterRead);
        }
        if status & (TRANSLATION | QUEUED_INVALIDATION | INTERRUPT_REMAP) != 0
            || protected & (1 << 31 | 1) != 0
        {
            return Err(VtdError::Busy);
        }
        let table_cacheline = if ecap & 1 == 0 {
            let cpu = core::arch::x86_64::__cpuid(1);
            Some(qualified_flush_line(cpu.edx, cpu.ebx)?)
        } else {
            None
        };
        let nd = (cap & 7) as u32;
        if nd > 6 {
            return Err(VtdError::Unsupported);
        }
        let max_domains = 1u32.checked_shl(4 + 2 * nd).ok_or(VtdError::Unsupported)?;
        let widths = (cap >> 8) & 31;
        let maximum = ((cap >> 16) & 63) + 1;
        let levels = if widths & 4 != 0 && maximum >= 48 {
            4
        } else if widths & 2 != 0 && maximum >= 39 {
            3
        } else {
            return Err(VtdError::Unsupported);
        };
        let iotlb = ((ecap >> 8) & 0x3ff) as usize * 16 + 8;
        if iotlb < 0x80
            || iotlb
                .checked_add(8)
                .is_none_or(|end| end > registers.bytes())
        {
            return Err(VtdError::RegisterRange);
        }
        let root = Table::new(source, physical_bits)?;
        // Initial takeover is TE-off and every context is absent. Dynamic
        // context publication separately flushes the child before Present.
        let mut contexts = BTreeMap::new();
        for bus in allowed.iter().map(|rid| (rid >> 8) as u8) {
            if let alloc::collections::btree_map::Entry::Vacant(entry) = contexts.entry(bus) {
                let context = Table::new(source, physical_bits)?;
                root.write(usize::from(bus), context.physical() | 1);
                entry.insert(context);
            }
        }
        let unit = Arc::new(Self {
            registers: ManuallyDrop::new(registers),
            source,
            held: AtomicBool::new(false),
            state: ManuallyDrop::new(UnsafeCell::new(State {
                root,
                contexts,
                allowed,
                domains: BTreeMap::new(),
                next_id: 1,
                next_generation: 1,
                poisoned: false,
                shutdown: false,
            })),
            levels,
            physical_bits,
            iotlb,
            cap,
            max_domains,
            table_cacheline,
        });
        let mut guard = unit.lock();
        let state = guard.state();
        unit.publish_tables(state);
        // Mask fault interrupts; fault delivery needs its own registered IRQ
        // owner, never a firmware handler retained across ownership transfer.
        unit.registers.write32(FECTL, 1 << 31);
        unit.registers.write64(RTADDR, state.root.physical());
        unit.registers.write32(GCMD, ROOT_POINTER);
        unit.wait32(GSTS, ROOT_POINTER, true)?;
        unit.invalidate(0, true)?;
        unit.registers.write32(GCMD, TRANSLATION);
        unit.wait32(GSTS, TRANSLATION, true)?;
        drop(guard);
        Ok(unit)
    }

    /// Publish one owned stopped requester into this already owned unit.
    ///
    /// # Safety
    /// The claim's actual engine/reset/IRQ/work epoch is stopped and drained,
    /// its coherent-DMA/config/root ownership grant remains valid, and no other
    /// owner can resume it before this returned domain's mapping publication.
    pub unsafe fn attach_requester(
        self: &Arc<Self>,
        mut claim: RequesterClaim,
    ) -> Result<Arc<RequesterDomain<R>>, VtdError> {
        claim.check_stopped()?;
        let rid = claim.requester();
        let mut guard = self.lock();
        let state = guard.state();
        if state.shutdown
            || state.poisoned
            || !state.allowed.contains(&rid)
            || state.domains.contains_key(&rid)
        {
            return Err(VtdError::Busy);
        }
        let did = (1..self.max_domains)
            .find(|did| !state.domains.values().any(|d| u32::from(d.did) == *did))
            .ok_or(VtdError::Busy)? as u16;
        let generation = state.next_generation;
        state.next_generation = generation.checked_add(1).ok_or(VtdError::Unsupported)?;
        let root = Table::new(self.source, self.physical_bits)?;
        let physical = root.physical();
        // Even an unsolicited access while TE is active must never walk stale
        // child contents. Publish this complete zero root before its context.
        if let Some(line) = self.table_cacheline {
            root.flush(&*self.registers, line);
        }
        publish();
        let mut table_index = BTreeMap::new();
        table_index.insert(physical, 0);
        state.domains.insert(
            rid,
            DomainState {
                did,
                generation,
                claim,
                tables: vec![root],
                table_index,
                mappings: BTreeMap::new(),
                quarantined: false,
            },
        );
        let (context, index) = state.context(rid);
        context.write(index + 1, u64::from(did) << 8 | u64::from(self.levels - 2));
        if let Some(line) = self.table_cacheline {
            context.flush(&*self.registers, line);
        }
        publish();
        context.write(index, physical | 1);
        if let Some(line) = self.table_cacheline {
            context.flush(&*self.registers, line);
        }
        publish();
        if let Err(error) = self.invalidate(TRANSLATION, true) {
            state.poisoned = true;
            return Err(error);
        }
        Ok(Arc::new(RequesterDomain {
            unit: ManuallyDrop::new(self.clone()),
            rid,
            did,
            generation,
        }))
    }

    fn lock(&self) -> Guard<'_, R> {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard(self)
    }
    /// Evict the tables holding `leaves`, the entries one mapping changed;
    /// every new intermediate table was evicted as it was linked ([`leaf`]).
    ///
    /// [`leaf`]: DomainState::leaf
    fn publish_leaves(&self, domain: &DomainState, leaves: &[(usize, usize)]) {
        if let Some(line) = self.table_cacheline {
            let mut tables: Vec<usize> = leaves.iter().map(|&(table, _)| table).collect();
            tables.sort_unstable();
            tables.dedup();
            for table in tables {
                domain.tables[table].flush(&*self.registers, line);
            }
        }
        // Orders actual dirty-line eviction before UC command submission.
        publish();
    }
    /// Make entries that were not present visible to the walker. Without
    /// Caching Mode the unit caches no not-present entry, so VT-d 6.1 needs
    /// only the write-buffer flush, as Linux's `__mapping_notify_one` does.
    fn publish_new_entries(&self, did: u16) -> Result<(), VtdError> {
        if self.cap & CAP_CACHING_MODE != 0 {
            return self.invalidate_domain(did);
        }
        self.flush_write_buffer()
    }
    fn flush_write_buffer(&self) -> Result<(), VtdError> {
        if self.cap & CAP_WRITE_BUFFER != 0 {
            self.registers.write32(GCMD, TRANSLATION | WRITE_BUFFER);
            self.wait32(GSTS, WRITE_BUFFER, false)?;
        }
        Ok(())
    }
    /// Invalidate one domain's IOTLB entries, draining its queued DMA: the
    /// unit may grant the global invalidation instead.
    fn invalidate_domain(&self, did: u16) -> Result<(), VtdError> {
        publish();
        self.flush_write_buffer()?;
        let mut request = IOTLB_INVALIDATE | IOTLB_DOMAIN | u64::from(did) << IOTLB_DOMAIN_SHIFT;
        if self.cap & CAP_WRITE_DRAIN != 0 {
            request |= IOTLB_WRITE_DRAIN;
        }
        if self.cap & CAP_READ_DRAIN != 0 {
            request |= IOTLB_READ_DRAIN;
        }
        self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
        self.registers.write64(self.iotlb, request);
        let value = self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
        if !matches!((value >> 57) & 3, 1 | 2) {
            return Err(VtdError::Invalidation);
        }
        Ok(())
    }
    fn publish_tables(&self, state: &State) {
        if let Some(line) = self.table_cacheline {
            state.root.flush(&*self.registers, line);
            for context in state.contexts.values() {
                context.flush(&*self.registers, line);
            }
            for domain in state.domains.values() {
                for table in &domain.tables {
                    table.flush(&*self.registers, line);
                }
            }
        }
        // Orders actual dirty-line eviction before UC command submission.
        publish();
    }
    fn wait32(&self, register: usize, mask: u32, set: bool) -> Result<(), VtdError> {
        let start = self.registers.ticks();
        loop {
            let value = self.registers.read32(register);
            if value == u32::MAX {
                return Err(VtdError::RegisterRead);
            }
            if (value & mask != 0) == set {
                return Ok(());
            }
            if self.registers.ticks().wrapping_sub(start) >= self.registers.timeout_ticks() {
                return Err(VtdError::Timeout);
            }
            core::hint::spin_loop();
        }
    }
    fn wait64(&self, register: usize, mask: u64) -> Result<u64, VtdError> {
        let start = self.registers.ticks();
        loop {
            let value = self.registers.read64(register);
            if value & mask == 0 {
                return Ok(value);
            }
            if self.registers.ticks().wrapping_sub(start) >= self.registers.timeout_ticks() {
                return Err(VtdError::Timeout);
            }
            core::hint::spin_loop();
        }
    }
    fn invalidate(&self, command: u32, context: bool) -> Result<(), VtdError> {
        publish();
        if context {
            self.wait64(CCMD, CONTEXT_INVALIDATE)?;
            self.registers
                .write64(CCMD, CONTEXT_INVALIDATE | CONTEXT_GLOBAL);
            let value = self.wait64(CCMD, CONTEXT_INVALIDATE)?;
            if (value >> 59) & 3 != 1 {
                return Err(VtdError::Invalidation);
            }
        }
        let mut request = IOTLB_INVALIDATE | IOTLB_GLOBAL;
        if self.cap & CAP_WRITE_DRAIN != 0 {
            request |= IOTLB_WRITE_DRAIN;
        }
        if self.cap & CAP_READ_DRAIN != 0 {
            request |= IOTLB_READ_DRAIN;
        }
        self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
        self.registers.write64(self.iotlb, request);
        let value = self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
        if (value >> 57) & 3 != 1 {
            return Err(VtdError::Invalidation);
        }
        if self.cap & CAP_WRITE_BUFFER != 0 {
            self.registers.write32(GCMD, command | WRITE_BUFFER);
            self.wait32(GSTS, WRITE_BUFFER, false)?;
        }
        Ok(())
    }

    /// Disable after device-specific stop, completion and worker/IRQ drain.
    /// The unit remains retained on any failed hardware acknowledgement.
    ///
    /// # Safety
    /// Every requester is stopped/drained and cannot issue further DMA. The
    /// caller owns the platform exclusion against submissions and IRQ workers.
    pub unsafe fn shut_down(&self) -> Result<(), VtdError> {
        let mut guard = self.lock();
        let state = guard.state();
        if state.shutdown {
            return Ok(());
        }
        if !state.domains.is_empty() {
            return Err(VtdError::Busy);
        }
        self.invalidate(TRANSLATION, true)?;
        self.registers.write32(GCMD, 0);
        self.wait32(GSTS, TRANSLATION, false)?;
        state.shutdown = true;
        Ok(())
    }
}

impl<R: Registers> Drop for Unit<R> {
    fn drop(&mut self) {
        // SAFETY: final owner, so no lock/operation can still borrow state.
        let shutdown = unsafe { &*self.state.get() }.shutdown;
        if shutdown {
            // SAFETY: actual device quiescence, all mappings retired, IOTLB
            // acknowledgement and TE-off acknowledgement preceded shutdown.
            unsafe {
                ManuallyDrop::drop(&mut self.state);
                ManuallyDrop::drop(&mut self.registers);
            }
        } else {
            // Hardware may still hold any of these PA references. Deliberately
            // retain the register owner, tables and pins, including map errors.
            let _ = QUARANTINED_UNITS.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
        }
    }
}

impl State {
    /// The context table and entry index of requester `rid`, whose bus
    /// every allowed requester's has.
    fn context(&self, rid: u16) -> (&Table, usize) {
        (
            &self.contexts[&((rid >> 8) as u8)],
            usize::from(rid & 0xff) * 2,
        )
    }
}

impl DomainState {
    fn iova(&self, bytes: usize, limit: u64, width: u8) -> Result<u64, DmaError> {
        let limit = limit.min((1u64 << (12 + 9 * u32::from(width))) - 1);
        let mut candidate = PAGE as u64;
        for live in self.mappings.values() {
            let mut end = candidate
                .checked_add(bytes as u64)
                .ok_or(DmaError::AddressLimit)?;
            if candidate < MSI_END && end > MSI_START {
                candidate = MSI_END;
                end = candidate
                    .checked_add(bytes as u64)
                    .ok_or(DmaError::AddressLimit)?;
            }
            if end - 1 <= limit && end <= live.info.address {
                return Ok(candidate);
            }
            candidate = candidate.max(live.info.address + live.info.bytes as u64);
        }
        let mut end = candidate
            .checked_add(bytes as u64)
            .ok_or(DmaError::AddressLimit)?;
        if candidate < MSI_END && end > MSI_START {
            candidate = MSI_END;
            end = candidate
                .checked_add(bytes as u64)
                .ok_or(DmaError::AddressLimit)?;
        }
        if end - 1 > limit {
            Err(DmaError::AddressLimit)
        } else {
            Ok(candidate)
        }
    }

    fn leaf<R: Registers>(
        &mut self,
        source: &dyn PageSource,
        levels: u8,
        physical_bits: u8,
        iova: u64,
        registers: &R,
        table_cacheline: Option<usize>,
    ) -> Result<(usize, usize), VtdError> {
        let mut table = 0;
        for level in (1..levels).rev() {
            let index = ((iova >> (12 + 9 * u32::from(level))) & 511) as usize;
            let entry = self.tables[table].read(index);
            if entry & (READ | WRITE) == 0 {
                let child = Table::new(source, physical_bits)?;
                let physical = child.physical();
                // The walker can follow this branch as soon as Present is
                // visible, including an unsolicited device access before map
                // returns. Evict the complete zeroed child before exposing
                // its parent; eventual final invalidation is insufficient.
                if let Some(line) = table_cacheline {
                    child.flush(registers, line);
                }
                publish();
                let next = self.tables.len();
                self.tables.push(child);
                self.table_index.insert(physical, next);
                publish();
                self.tables[table].write(index, physical | READ | WRITE);
                if let Some(line) = table_cacheline {
                    self.tables[table].flush(registers, line);
                }
                publish();
                table = next;
            } else {
                table = *self
                    .table_index
                    .get(&(entry & ADDRESS))
                    .ok_or(VtdError::Memory)?;
            }
        }
        Ok((table, ((iova >> 12) & 511) as usize))
    }

    fn mapping(
        &self,
        info: DomainMapping,
        range: &Range<usize>,
        direction: Direction,
    ) -> Result<&LiveMapping, DmaError> {
        let live = self
            .mappings
            .get(&info.address)
            .filter(|live| live.info == info)
            .ok_or(DmaError::Unmapped)?;
        if range.start > range.end || range.end > live.info.bytes || live.direction != direction {
            return Err(DmaError::InvalidRange);
        }
        Ok(live)
    }
}

/// One actual requester context, hardware DID and non-reused software epoch.
/// It retains the hardware owner and consumed PCI claim through every DMA lease.
/// Final release is process/deferred context, never an IRQ callback.
pub struct RequesterDomain<R: Registers> {
    unit: ManuallyDrop<Arc<Unit<R>>>,
    rid: u16,
    did: u16,
    generation: u64,
}
impl<R: Registers> RequesterDomain<R> {
    pub fn requester(&self) -> u16 {
        self.rid
    }
    pub fn domain_id(&self) -> u16 {
        self.did
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    fn domain<'a>(
        &self,
        state: &'a mut State,
        live: bool,
    ) -> Result<&'a mut DomainState, DmaError> {
        if state.shutdown || (live && state.poisoned) {
            return Err(DmaError::MappingFailed);
        }
        state
            .domains
            .get_mut(&self.rid)
            .filter(|d| d.did == self.did && d.generation == self.generation && !d.quarantined)
            .ok_or(DmaError::Unmapped)
    }
    /// # Safety
    /// The actual device is stopped before disabling, or every enabled DMA
    /// address is published under this owned domain. Device IRQ/work/reset and
    /// configuration ownership remain excluded. This is not a stop/drain ACK.
    /// Controlled fault probes must retain all possible target backing too.
    pub unsafe fn set_bus_master(&self, enabled: bool) -> Result<(), VtdError> {
        let mut guard = self.unit.lock();
        self.domain(guard.state(), enabled)
            .map_err(|_| VtdError::Busy)?
            .claim
            .set_bus_master(enabled)
    }
    /// # Safety
    /// Actual engines, posted requests, IRQ/work/reset and submissions from
    /// this owned requester are stopped/drained and cannot restart. No numeric
    /// RID or BusMaster-clear bit alone establishes this proof.
    pub unsafe fn detach(&self) -> Result<RequesterClaim, VtdError> {
        let mut guard = self.unit.lock();
        let state = guard.state();
        let domain = self.domain(state, false).map_err(|_| VtdError::Busy)?;
        if !domain.mappings.is_empty() {
            return Err(VtdError::Busy);
        }
        domain.claim.check_stopped()?;
        let (context, index) = state.context(self.rid);
        context.write(index, 0);
        if let Some(line) = self.unit.table_cacheline {
            context.flush(&*self.unit.registers, line);
        }
        publish();
        if let Err(error) = self.unit.invalidate(TRANSLATION, true) {
            state.poisoned = true;
            return Err(error);
        }
        let (context, index) = state.context(self.rid);
        context.write(index + 1, 0);
        if let Some(line) = self.unit.table_cacheline {
            context.flush(&*self.unit.registers, line);
        }
        publish();
        let DomainState { claim, .. } = state
            .domains
            .remove(&self.rid)
            .expect("retained owned context");
        Ok(claim)
    }
}
impl<R: Registers> Drop for RequesterDomain<R> {
    fn drop(&mut self) {
        let active = {
            let mut guard = self.unit.lock();
            let state = guard.state();
            if let Some(domain) = state
                .domains
                .get_mut(&self.rid)
                .filter(|d| d.did == self.did && d.generation == self.generation)
            {
                if !domain.quarantined {
                    domain.quarantined = true;
                    let _ =
                        QUARANTINED_DOMAINS.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_add(1))
                        });
                }
                true
            } else {
                false
            }
        };
        // An unacknowledged context retains its actual claim/tables/unit Arc;
        // a later attach can neither reuse that RID nor steal its hardware DID.
        if !active {
            unsafe {
                ManuallyDrop::drop(&mut self.unit);
            }
        }
    }
}

// SAFETY: the platform's takeover contract establishes actual exclusive
// requester ownership, coherent WB DMA and stopped ATS/NoSnoop. Real native
// pages and hardware tables are retained through acknowledged invalidation;
// every failed/abandoned hardware lifetime preserves its backing. All mutable
// operations are serialized outside hard IRQ context.
unsafe impl<R: Registers + 'static> DmaDomain for RequesterDomain<R> {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        address_limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        if pages.cache_attribute() != CacheAttribute::WriteBack
            || pages.page_shift() < 12
            || pages.physical_pages().iter().any(|pa| {
                pa.checked_add(1u64 << pages.page_shift())
                    .is_none_or(|end| end > 1u64 << self.unit.physical_bits)
            })
        {
            return Err(DmaError::MappingFailed);
        }
        let mut guard = self.unit.lock();
        let state = guard.state();
        if state.shutdown || state.poisoned {
            return Err(DmaError::MappingFailed);
        }
        let id = state.next_id;
        state.next_id = id.checked_add(1).ok_or(DmaError::MappingFailed)?;
        let domain = self.domain(state, true)?;
        let address = domain.iova(pages.bytes(), address_limit, self.unit.levels)?;
        let info = DomainMapping {
            id,
            address,
            bytes: pages.bytes(),
        };
        let mut leaves = Vec::with_capacity(pages.bytes() / PAGE);
        // Build all required table paths first. No leaf may be published until
        // the owned mapping/pin and complete leaf inventory have been retained.
        for offset in (0..pages.bytes()).step_by(PAGE) {
            leaves.push(
                domain
                    .leaf(
                        self.unit.source,
                        self.unit.levels,
                        self.unit.physical_bits,
                        address + offset as u64,
                        &*self.unit.registers,
                        self.unit.table_cacheline,
                    )
                    .map_err(|_| DmaError::MappingFailed)?,
            );
        }
        domain.mappings.insert(
            address,
            LiveMapping {
                info,
                direction,
                _pages: pages.clone(),
                leaves,
            },
        );
        let rights = match direction {
            Direction::ToDevice => READ,
            Direction::FromDevice => WRITE,
            Direction::Bidirectional => READ | WRITE,
        };
        let live = &domain.mappings[&address];
        let native_size = 1usize << pages.page_shift();
        for (page, &(table, index)) in live.leaves.iter().enumerate() {
            let offset = page * PAGE;
            let physical =
                pages.physical_pages()[offset / native_size] + (offset % native_size) as u64;
            domain.tables[table].write(index, physical | rights);
        }
        self.unit.publish_leaves(domain, &live.leaves);
        if self.unit.publish_new_entries(self.did).is_err() {
            // An unacknowledged translation is never returned as a live lease;
            // retain its pin/table inventory and poison further submissions.
            state.poisoned = true;
            return Err(DmaError::InvalidationFailed);
        }
        Ok(info)
    }

    unsafe fn unmap(&self, info: DomainMapping) -> Result<(), DmaError> {
        let mut guard = self.unit.lock();
        let state = guard.state();
        if state.shutdown {
            return Err(DmaError::Unmapped);
        }
        let domain = self.domain(state, false)?;
        let live = domain
            .mappings
            .get(&info.address)
            .filter(|live| live.info == info)
            .ok_or(DmaError::Unmapped)?;
        for &(table, index) in &live.leaves {
            domain.tables[table].write(index, 0);
        }
        self.unit.publish_leaves(domain, &live.leaves);
        if self.unit.invalidate_domain(self.did).is_err() {
            state.poisoned = true;
            return Err(DmaError::InvalidationFailed);
        }
        self.domain(state, false)?.mappings.remove(&info.address);
        // Once poisoned, this initial backend requires full platform recovery;
        // another mapping cannot assume an unrelated failed map was retired.
        Ok(())
    }

    unsafe fn sync_for_device(
        &self,
        info: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        let mut guard = self.unit.lock();
        self.domain(guard.state(), true)?
            .mapping(info, &range, direction)?;
        // DMA coherence is an explicit platform/requester qualification, not
        // inferred from ECAP page-table coherency or WB CPU attributes alone.
        publish();
        Ok(())
    }

    unsafe fn sync_for_cpu(
        &self,
        info: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        let mut guard = self.unit.lock();
        self.domain(guard.state(), true)?
            .mapping(info, &range, direction)?;
        // Caller has observed actual hardware completion before this acquire
        // boundary; no completion or cache invalidation is invented here.
        publish();
        Ok(())
    }

    unsafe fn read_coherent_u32(
        &self,
        info: DomainMapping,
        offset: usize,
        direction: Direction,
    ) -> Result<u32, DmaError> {
        let end = offset.checked_add(4).ok_or(DmaError::InvalidRange)?;
        if !offset.is_multiple_of(4) || direction == Direction::ToDevice {
            return Err(DmaError::InvalidRange);
        }
        let mut guard = self.unit.lock();
        let live = self
            .domain(guard.state(), true)?
            .mapping(info, &(offset..end), direction)?;
        // The takeover/claim contracts independently qualify coherent WB
        // payload DMA and exclude ATS/NoSnoop and incompatible aliases. ECAP
        // table-walk coherency is not that grant. Scatter mappings do not
        // manufacture a contiguous CPU view.
        let pages = live
            ._pages
            .as_single()
            .ok_or(DmaError::CoherenceUnavailable)?;
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(|_| DmaError::CoherenceUnavailable)?;
        let pointer = cpu.address(offset, 4).map_err(|_| DmaError::InvalidRange)?;
        if !(pointer.as_ptr() as usize).is_multiple_of(4) {
            return Err(DmaError::InvalidRange);
        }
        publish();
        // SAFETY: this live domain retains its actual aligned WB allocation;
        // only raw access is exposed. The qualified platform supports these
        // per-word observations during device writes, not atomic whole frames.
        let value = unsafe { pointer.as_ptr().cast::<u32>().read_volatile() };
        publish();
        Ok(u32::from_le(value))
    }

    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        let mut guard = self.unit.lock();
        let state = guard.state();
        self.domain(state, true)?;
        if self.unit.cap & CAP_WRITE_DRAIN == 0 {
            return Err(DmaError::DrainUnavailable);
        }
        // VT-d section 6.5.4: with DWD support, the actual DW invalidation
        // completes queued translated writes through this root path before
        // returning. It neither establishes device stop nor drains peer DMA.
        // The existing operation verifies completion/granularity and performs
        // the real write-buffer flush where the unit requires it.
        if self.unit.invalidate(TRANSLATION, false).is_err() {
            state.poisoned = true;
            return Err(DmaError::InvalidationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use self::std::sync::Mutex;
    use super::*;
    use alloc::{
        alloc::{alloc_zeroed, dealloc},
        boxed::Box,
    };
    use core::alloc::Layout;
    use stela_drivers::bus::dma::{
        mapping::DmaMapping,
        memory::{MemoryError, PageBacking},
    };

    struct Backing {
        pointer: NonNull<u8>,
        layout: Layout,
        pages: Vec<u64>,
        shift: u8,
        released: Arc<AtomicU64>,
    }
    // SAFETY: test-owned, immovable allocated RAM; immutable page metadata,
    // no safe CPU aliases and no asynchronous physical hardware in the model.
    unsafe impl Send for Backing {}
    // SAFETY: shared access exposes metadata and raw pointers only.
    unsafe impl Sync for Backing {}
    // SAFETY: this is an explicit native physical-memory model. CPU RAM really
    // exists and is retained; the named PAs are modeled, not identity-inferred.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            self.pointer
        }
        fn physical_pages(&self) -> &[u64] {
            &self.pages
        }
        fn page_shift(&self) -> u8 {
            self.shift
        }
        fn cache_attribute(&self) -> CacheAttribute {
            CacheAttribute::WriteBack
        }
    }
    impl Drop for Backing {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::Relaxed);
            // SAFETY: exact unique test allocation and original layout.
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }
    fn pages(bytes: usize, shift: u8, physical: u64, released: Arc<AtomicU64>) -> PinnedPages {
        let size = 1usize << shift;
        let layout = Layout::from_size_align(bytes, size).unwrap();
        // SAFETY: actual exclusive zeroed model RAM, released by Backing.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let backing = Backing {
            pointer,
            layout,
            pages: (0..bytes / size)
                .map(|index| physical + (index * size) as u64)
                .collect(),
            shift,
            released,
        };
        PinnedPages::new(Box::new(backing), bytes, size).unwrap()
    }
    struct Source {
        next: AtomicU64,
        released: Arc<AtomicU64>,
        table_addresses: Mutex<BTreeMap<u64, usize>>,
    }
    impl PageSource for Source {
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            assert_eq!(
                (bytes, alignment, attribute),
                (PAGE, PAGE, CacheAttribute::WriteBack)
            );
            let physical = self.next.fetch_add(PAGE as u64, Ordering::Relaxed);
            let pages = pages(bytes, 12, physical, self.released.clone());
            let cpu = pages.cpu_mapping(CacheAttribute::WriteBack).unwrap();
            self.table_addresses
                .lock()
                .unwrap()
                .insert(physical, cpu.address(0, PAGE).unwrap().as_ptr() as usize);
            Ok(pages)
        }
    }
    fn source() -> &'static Source {
        Box::leak(Box::new(Source {
            next: AtomicU64::new(0x100000),
            released: Arc::new(AtomicU64::new(0)),
            table_addresses: Mutex::new(BTreeMap::new()),
        }))
    }
    struct Model {
        values: BTreeMap<usize, u64>,
        writes: Vec<(usize, u64)>,
        ticks: u64,
        block_iotlb: bool,
        block_context: bool,
        block_te_off: bool,
        cache_events: Vec<(bool, usize)>,
        fail_gsts_after: Option<u32>,
        source: Option<&'static Source>,
        visible_tables: BTreeMap<u64, Vec<u64>>,
        active_observations: usize,
        pending_payload: Vec<(usize, u32)>,
        iotlb_granularity: u64,
    }
    impl Model {
        fn visible_table(&self, physical: u64) -> &[u64] {
            self.visible_tables
                .get(&physical)
                .expect("walker reached an unflushed child table")
        }
        fn observe_level(&self, physical: u64, level: u8) {
            let entries = self.visible_table(physical);
            if level != 0 {
                for entry in entries.iter().filter(|entry| **entry & (READ | WRITE) != 0) {
                    self.observe_level(entry & ADDRESS, level - 1);
                }
            }
        }
        fn observe_tables(&mut self) {
            if self.source.is_none()
                || self.values.get(&GSTS).copied().unwrap_or(0) & u64::from(TRANSLATION) == 0
            {
                return;
            }
            self.active_observations += 1;
            let root = self.values[&RTADDR] & ADDRESS;
            for root_pair in self.visible_table(root).as_chunks::<2>().0 {
                if root_pair[0] & 1 == 0 {
                    continue;
                }
                for context_pair in self
                    .visible_table(root_pair[0] & ADDRESS)
                    .as_chunks::<2>()
                    .0
                {
                    if context_pair[0] & 1 != 0 {
                        let levels = (context_pair[1] & 7) as u8 + 2;
                        self.observe_level(context_pair[0] & ADDRESS, levels - 1);
                    }
                }
            }
        }
        fn translation(&self, requester: u16, iova: u64) -> Option<u64> {
            let root = self.visible_table(self.values[&RTADDR] & ADDRESS);
            let root_entry = root[usize::from(requester >> 8) * 2];
            if root_entry & 1 == 0 {
                return None;
            }
            let context = self.visible_table(root_entry & ADDRESS);
            let index = usize::from(requester & 255) * 2;
            if context[index] & 1 == 0 {
                return None;
            }
            let levels = (context[index + 1] & 7) as u8 + 2;
            let mut physical = context[index] & ADDRESS;
            for level in (0..levels).rev() {
                let index = ((iova >> (12 + 9 * u32::from(level))) & 511) as usize;
                let entry = self.visible_table(physical)[index];
                if entry & (READ | WRITE) == 0 {
                    return None;
                }
                physical = entry & ADDRESS;
            }
            Some(physical | iova & 4095)
        }
    }
    #[derive(Clone)]
    struct ModelRegisters(Arc<Mutex<Model>>);
    impl ModelRegisters {
        fn new() -> Self {
            let mut values = BTreeMap::new();
            values.insert(
                CAP,
                (47 << 16) | (4 << 8) | (1 << 4) | (1 << 54) | (1 << 55),
            );
            values.insert(ECAP, 1 | (0x10 << 8));
            Self(Arc::new(Mutex::new(Model {
                values,
                writes: Vec::new(),
                ticks: 0,
                block_iotlb: false,
                block_context: false,
                block_te_off: false,
                cache_events: Vec::new(),
                fail_gsts_after: None,
                source: None,
                visible_tables: BTreeMap::new(),
                active_observations: 0,
                pending_payload: Vec::new(),
                iotlb_granularity: 1,
            })))
        }
    }
    // SAFETY: synchronous model of the real registers and acknowledgements.
    // Timeout injection leaves requests genuinely unacknowledged in the model.
    unsafe impl Registers for ModelRegisters {
        fn bytes(&self) -> usize {
            4096
        }
        fn read32(&self, offset: usize) -> u32 {
            self.0
                .lock()
                .unwrap()
                .values
                .get(&offset)
                .copied()
                .unwrap_or(0) as u32
        }
        fn read64(&self, offset: usize) -> u64 {
            let mut model = self.0.lock().unwrap();
            let mut value = model.values.get(&offset).copied().unwrap_or(0);
            if offset == CCMD && value & CONTEXT_INVALIDATE != 0 && !model.block_context {
                value = value & !CONTEXT_INVALIDATE | 1 << 59;
                model.values.insert(offset, value);
            }
            if offset == 0x108 && value & IOTLB_INVALIDATE != 0 && !model.block_iotlb {
                if value & IOTLB_WRITE_DRAIN != 0 && model.iotlb_granularity == 1 {
                    for (address, word) in model.pending_payload.drain(..) {
                        // SAFETY: each test retains the actual owned allocation
                        // through this modeled device-write completion.
                        unsafe { (address as *mut u32).write_volatile(word.to_le()) };
                    }
                }
                value = value & !(IOTLB_INVALIDATE | 3 << 57) | model.iotlb_granularity << 57;
                model.values.insert(offset, value);
            }
            value
        }
        fn write32(&self, offset: usize, value: u32) {
            let mut model = self.0.lock().unwrap();
            model.writes.push((offset, u64::from(value)));
            model.cache_events.push((false, offset));
            model.values.insert(offset, u64::from(value));
            if offset == GCMD {
                let mut status = model.values.get(&GSTS).copied().unwrap_or(0) as u32;
                if value & ROOT_POINTER != 0 {
                    status |= ROOT_POINTER;
                }
                if value & TRANSLATION != 0 {
                    status |= TRANSLATION;
                } else if !model.block_te_off {
                    status &= !TRANSLATION;
                }
                status &= !WRITE_BUFFER;
                model.values.insert(GSTS, u64::from(status));
                model.observe_tables();
                if model.fail_gsts_after == Some(value) {
                    model.values.insert(GSTS, u64::from(u32::MAX));
                }
            }
        }
        fn write64(&self, offset: usize, value: u64) {
            let mut model = self.0.lock().unwrap();
            model.writes.push((offset, value));
            model.cache_events.push((false, offset));
            model.values.insert(offset, value);
        }
        fn ticks(&self) -> u64 {
            let mut model = self.0.lock().unwrap();
            model.ticks += 1;
            model.ticks
        }
        fn timeout_ticks(&self) -> u64 {
            16
        }
        unsafe fn flush_table(&self, cpu: NonNull<u8>, bytes: usize, line: usize) {
            assert_eq!(bytes, PAGE);
            assert!((cpu.as_ptr() as usize).is_multiple_of(PAGE));
            let mut model = self.0.lock().unwrap();
            model.cache_events.push((true, cpu.as_ptr() as usize));
            if let Some(source) = model.source {
                let addresses = source.table_addresses.lock().unwrap();
                let physical = *addresses
                    .iter()
                    .rev()
                    .find(|(_, pointer)| **pointer == cpu.as_ptr() as usize)
                    .unwrap()
                    .0;
                // SAFETY: retained model table mapping; snapshot represents
                // what a noncoherent walker can see after this real eviction.
                let visible =
                    unsafe { core::slice::from_raw_parts(cpu.as_ptr().cast::<u64>(), PAGE / 8) }
                        .to_vec();
                model.visible_tables.insert(physical, visible);
                model.observe_tables();
            }
            // SAFETY: the model uses actual retained allocated table RAM and
            // the production CPUID qualification; keep real cache effects too.
            unsafe { super::flush_table(cpu, bytes, line) };
        }
    }

    fn stopped_claim(rid: u16) -> RequesterClaim {
        RequesterClaim::model(rid, Arc::new(AtomicU64::new(0)))
    }

    #[test]
    fn coherent_words_observe_only_the_live_domains_actual_pins() {
        let registers = ModelRegisters::new();
        let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8, 16], 48) }.unwrap();
        let first = unsafe { unit.attach_requester(stopped_claim(8)) }.unwrap();
        let second = unsafe { unit.attach_requester(stopped_claim(16)) }.unwrap();
        let released = Arc::new(AtomicU64::new(0));
        let pin = pages(PAGE, 12, 0x810000, released.clone());
        let cpu = pin.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        let pointer = cpu.address(0, 4).unwrap().as_ptr().cast::<u32>();
        let mut mapping =
            DmaMapping::map(first.clone(), pin, Direction::FromDevice, u64::MAX).unwrap();
        let mut other = DmaMapping::map(
            second.clone(),
            pages(PAGE, 12, 0x910000, released.clone()),
            Direction::FromDevice,
            u64::MAX,
        )
        .unwrap();
        assert_eq!(mapping.address(), other.address());
        let token = {
            let mut guard = unit.lock();
            guard.state().domains[&8].mappings[&mapping.address().unwrap()].info
        };
        let before = registers.0.lock().unwrap().writes.len();
        for value in [0u32, 1, 0x8000_0000, 0x1234_5678, u32::MAX] {
            // SAFETY: synchronous modeled device producer writes its actual
            // retained allocation, without a CPU ownership transfer.
            unsafe { pointer.write_volatile(value.to_le()) };
            assert_eq!(mapping.read_coherent_u32(0), Ok(value));
            assert_eq!(other.read_coherent_u32(0), Ok(0));
        }
        // Observing coherent payloads does not invent a device stop, perform
        // cache invalidation, or trigger IOTLB/ownership-transfer commands.
        assert_eq!(registers.0.lock().unwrap().writes.len(), before);
        for offset in [1, PAGE - 3, PAGE, usize::MAX] {
            assert_eq!(
                mapping.read_coherent_u32(offset),
                Err(DmaError::InvalidRange)
            );
        }
        assert_eq!(
            unsafe { second.read_coherent_u32(token, 0, Direction::FromDevice) },
            Err(DmaError::Unmapped)
        );
        assert_eq!(
            unsafe { first.read_coherent_u32(token, 0, Direction::ToDevice) },
            Err(DmaError::InvalidRange)
        );
        // SAFETY: modeled producer and workers are stopped; no writes pending.
        unsafe { mapping.unmap() }.unwrap();
        assert_eq!(mapping.read_coherent_u32(0), Err(DmaError::Unmapped));
        assert_eq!(
            unsafe { first.read_coherent_u32(token, 0, Direction::FromDevice) },
            Err(DmaError::Unmapped)
        );
        drop(unsafe { first.detach() }.unwrap());
        assert_eq!(
            unsafe { first.read_coherent_u32(token, 0, Direction::FromDevice) },
            Err(DmaError::Unmapped)
        );
        drop(first);
        unsafe { other.unmap() }.unwrap();
        drop(unsafe { second.detach() }.unwrap());
        drop(second);
        drop(cpu);
        assert_eq!(released.load(Ordering::Relaxed), 2);
        unsafe { unit.shut_down() }.unwrap();
    }

    #[test]
    fn payload_drain_requires_real_write_capability_and_acknowledged_visibility() {
        for supported in [false, true] {
            let registers = ModelRegisters::new();
            if !supported {
                *registers.0.lock().unwrap().values.get_mut(&CAP).unwrap() &= !CAP_WRITE_DRAIN;
            }
            let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48) }.unwrap();
            let domain = unsafe { unit.attach_requester(stopped_claim(8)) }.unwrap();
            let pin = pages(PAGE, 12, 0xa10000, Arc::new(AtomicU64::new(0)));
            let cpu = pin.cpu_mapping(CacheAttribute::WriteBack).unwrap();
            let pointer = cpu.address(0, 4).unwrap().as_ptr().cast::<u32>();
            let mut mapping =
                DmaMapping::map(domain.clone(), pin, Direction::FromDevice, u64::MAX).unwrap();
            let before = registers.0.lock().unwrap().writes.len();
            if supported {
                registers
                    .0
                    .lock()
                    .unwrap()
                    .pending_payload
                    .push((pointer as usize, 0x1234_abcd));
                assert_eq!(mapping.read_coherent_u32(0), Ok(0));
                // SAFETY: modeled engine cannot submit more requests; queued
                // translated payload remains retained until real model ACK.
                unsafe { domain.drain_posted_writes() }.unwrap();
                assert_eq!(mapping.read_coherent_u32(0), Ok(0x1234_abcd));
                let model = registers.0.lock().unwrap();
                let writes = &model.writes[before..];
                assert!(model.pending_payload.is_empty());
                assert_eq!(
                    writes[0],
                    (
                        unit.iotlb,
                        IOTLB_INVALIDATE | IOTLB_GLOBAL | IOTLB_WRITE_DRAIN | IOTLB_READ_DRAIN
                    )
                );
                assert_eq!(writes[1], (GCMD, u64::from(TRANSLATION | WRITE_BUFFER)));
            } else {
                assert_eq!(
                    unsafe { domain.drain_posted_writes() },
                    Err(DmaError::DrainUnavailable)
                );
                assert_eq!(registers.0.lock().unwrap().writes.len(), before);
            }
            assert_eq!(unit.lock().state().domains[&8].mappings.len(), 1);
            // SAFETY: the model has no engine and no queued payload now.
            unsafe { mapping.unmap() }.unwrap();
            drop(unsafe { domain.detach() }.unwrap());
            drop(domain);
            unsafe { unit.shut_down() }.unwrap();
        }
    }

    #[test]
    fn withheld_drain_bad_granularity_and_write_buffer_fault_keep_all_backing() {
        for failure in 0..3 {
            let registers = ModelRegisters::new();
            let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48) }.unwrap();
            let claim_drops = Arc::new(AtomicU64::new(0));
            let domain =
                unsafe { unit.attach_requester(RequesterClaim::model(8, claim_drops.clone())) }
                    .unwrap();
            let pin_drops = Arc::new(AtomicU64::new(0));
            let pin = pages(PAGE, 12, 0xb10000, pin_drops.clone());
            let cpu = pin.cpu_mapping(CacheAttribute::WriteBack).unwrap();
            let pointer = cpu.address(0, 4).unwrap().as_ptr().cast::<u32>();
            let mapping =
                DmaMapping::map(domain.clone(), pin, Direction::FromDevice, u64::MAX).unwrap();
            {
                let mut model = registers.0.lock().unwrap();
                model.pending_payload.push((pointer as usize, 0xfeed_beef));
                match failure {
                    0 => model.block_iotlb = true,
                    1 => model.iotlb_granularity = 0,
                    _ => model.fail_gsts_after = Some(TRANSLATION | WRITE_BUFFER),
                }
            }
            assert_eq!(
                unsafe { domain.drain_posted_writes() },
                Err(DmaError::InvalidationFailed)
            );
            {
                let mut guard = unit.lock();
                let state = guard.state();
                assert!(state.poisoned);
                assert_eq!(state.domains[&8].mappings.len(), 1);
            }
            assert_eq!(mapping.read_coherent_u32(0), Err(DmaError::MappingFailed));
            assert_eq!(
                unsafe { domain.drain_posted_writes() },
                Err(DmaError::MappingFailed)
            );
            drop(cpu);
            drop(mapping);
            drop(domain);
            drop(unit);
            assert_eq!(pin_drops.load(Ordering::Relaxed), 0);
            assert_eq!(claim_drops.load(Ordering::Relaxed), 0);
            // Deliberate quarantine: only external platform recovery can
            // acknowledge the retained hardware lifetime after these faults.
        }
    }
    #[test]
    fn scatter_maps_retained_native_subranges_and_releases_only_after_invalidation() {
        use stela_drivers::bus::dma::pages::PageRange;
        let source = source();
        let registers = ModelRegisters::new();
        {
            let mut model = registers.0.lock().unwrap();
            model.values.insert(ECAP, 0x10 << 8);
            model.source = Some(source);
        }
        // SAFETY: exclusive deterministic register/requester model; no device.
        let unit = unsafe { Unit::take_over(registers.clone(), source, &[8], 48) }.unwrap();
        // SAFETY: the model supplies the exact stopped requester claim.
        let domain = unsafe { unit.attach_requester(stopped_claim(8)) }.unwrap();
        let released = Arc::new(AtomicU64::new(0));
        let granule = 2 * PAGE;
        let first = pages(2 * granule, 13, 0x900000, released.clone());
        let second = pages(granule, 13, 0x300000, released.clone());
        let scatter = DmaPages::from_ranges(vec![
            PageRange::new(first.clone(), granule..2 * granule).unwrap(),
            PageRange::new(second, 0..granule).unwrap(),
            PageRange::new(first, granule..2 * granule).unwrap(),
        ])
        .unwrap();
        assert!(scatter.as_single().is_none());
        assert_eq!(scatter.page_shift(), 13);
        let mut mapping =
            DmaMapping::map(domain.clone(), scatter, Direction::Bidirectional, u64::MAX).unwrap();
        let address = mapping.address().unwrap();
        assert_eq!(mapping.bytes(), 3 * granule);
        assert_eq!(
            mapping.read_coherent_u32(0),
            Err(DmaError::CoherenceUnavailable)
        );
        {
            let model = registers.0.lock().unwrap();
            for (index, physical) in [0x902000, 0x903000, 0x300000, 0x301000, 0x902000, 0x903000]
                .into_iter()
                .enumerate()
            {
                assert_eq!(
                    model.translation(8, address + (index * PAGE) as u64),
                    Some(physical)
                );
            }
            assert_eq!(model.translation(8, address + 3 * granule as u64), None);
            assert_eq!(model.translation(16, address), None);
        }
        assert_eq!(released.load(Ordering::Relaxed), 0);
        registers.0.lock().unwrap().block_iotlb = true;
        // SAFETY: model is quiescent; an unacknowledged removal retains pins.
        assert_eq!(
            unsafe { mapping.unmap() },
            Err(DmaError::InvalidationFailed)
        );
        assert_eq!(released.load(Ordering::Relaxed), 0);
        registers.0.lock().unwrap().block_iotlb = false;
        // SAFETY: same stopped requester and unreused retained mapping token.
        unsafe { mapping.unmap() }.unwrap();
        assert_eq!(released.load(Ordering::Relaxed), 2);
        assert_eq!(registers.0.lock().unwrap().translation(8, address), None);
        // SAFETY: no mapping remains and the requester is still stopped.
        drop(unsafe { domain.detach() }.unwrap());
        drop(domain);
        // SAFETY: all contexts/mappings are retired; model has no DMA worker.
        unsafe { unit.shut_down() }.unwrap();
    }

    #[test]
    fn actual_contexts_separate_same_iova_and_reject_cross_domain_or_stale_tokens() {
        let source = source();
        let registers = ModelRegisters::new();
        {
            let mut m = registers.0.lock().unwrap();
            m.values.insert(ECAP, 0x10 << 8);
            m.source = Some(source);
        }
        let unit = unsafe { Unit::take_over(registers.clone(), source, &[8, 16, 24], 48) }.unwrap();
        let first = unsafe { unit.attach_requester(stopped_claim(8)) }.unwrap();
        let second = unsafe { unit.attach_requester(stopped_claim(16)) }.unwrap();
        assert_ne!(first.domain_id(), second.domain_id());
        let next_table = source.next.load(Ordering::Relaxed);
        for rejected in [8, 0x20] {
            assert!(matches!(
                unsafe { unit.attach_requester(stopped_claim(rejected)) },
                Err(VtdError::Busy)
            ));
        }
        assert_eq!(
            source.next.load(Ordering::Relaxed),
            next_table,
            "duplicate/unlisted claims must not allocate or publish contexts"
        );
        let mut a = DmaMapping::map(
            first.clone(),
            pages(PAGE, 12, 0xd000000, Arc::new(AtomicU64::new(0))),
            Direction::Bidirectional,
            u64::MAX,
        )
        .unwrap();
        let mut b = DmaMapping::map(
            second.clone(),
            pages(PAGE, 12, 0xe000000, Arc::new(AtomicU64::new(0))),
            Direction::Bidirectional,
            u64::MAX,
        )
        .unwrap();
        assert_eq!(a.address(), b.address());
        let address = a.address().unwrap();
        {
            let m = registers.0.lock().unwrap();
            let root = m.visible_table(m.values[&RTADDR] & ADDRESS);
            let context = m.visible_table(root[0] & ADDRESS);
            assert_eq!(
                (context[8 * 2 + 1] >> 8) & 0xffff,
                u64::from(first.domain_id())
            );
            assert_eq!(
                (context[16 * 2 + 1] >> 8) & 0xffff,
                u64::from(second.domain_id())
            );
            assert_ne!(context[8 * 2] & ADDRESS, context[16 * 2] & ADDRESS);
            assert_eq!(m.translation(8, address), Some(0xd000000));
            assert_eq!(m.translation(16, address), Some(0xe000000));
            assert_eq!(m.translation(24, address), None);
        }
        let token = {
            let mut g = unit.lock();
            g.state().domains[&8].mappings[&address].info
        };
        assert_eq!(
            unsafe { second.sync_for_device(token, 0..PAGE, Direction::Bidirectional) },
            Err(DmaError::Unmapped)
        );
        assert!(matches!(unsafe { first.detach() }, Err(VtdError::Busy)));
        assert_eq!(unsafe { unit.shut_down() }, Err(VtdError::Busy));
        unsafe { a.unmap() }.unwrap();
        let old_did = first.domain_id();
        let old_epoch = first.generation();
        drop(unsafe { first.detach() }.unwrap());
        assert_eq!(registers.0.lock().unwrap().translation(8, address), None);
        let replacement = unsafe { unit.attach_requester(stopped_claim(8)) }.unwrap();
        assert_eq!(replacement.domain_id(), old_did);
        assert!(replacement.generation() > old_epoch);
        let mut c = DmaMapping::map(
            replacement.clone(),
            pages(PAGE, 12, 0xf000000, Arc::new(AtomicU64::new(0))),
            Direction::Bidirectional,
            u64::MAX,
        )
        .unwrap();
        assert_eq!(c.address(), Ok(address));
        assert_eq!(
            unsafe { first.sync_for_device(token, 0..PAGE, Direction::Bidirectional) },
            Err(DmaError::Unmapped)
        );
        assert!(matches!(unsafe { first.detach() }, Err(VtdError::Busy)));
        drop(first);
        {
            let m = registers.0.lock().unwrap();
            assert_eq!(m.translation(8, address), Some(0xf000000));
            assert_eq!(m.translation(16, address), Some(0xe000000));
        }
        unsafe { c.unmap() }.unwrap();
        drop(unsafe { replacement.detach() }.unwrap());
        drop(replacement);
        unsafe { b.unmap() }.unwrap();
        drop(unsafe { second.detach() }.unwrap());
        drop(second);
        unsafe { unit.shut_down() }.unwrap();
    }
    #[test]
    fn failed_context_detach_keeps_hardware_did_claim_and_tables_until_ack() {
        let source = source();
        let registers = ModelRegisters::new();
        let unit = unsafe { Unit::take_over(registers.clone(), source, &[8, 16], 48) }.unwrap();
        let released = Arc::new(AtomicU64::new(0));
        let first =
            unsafe { unit.attach_requester(RequesterClaim::model(8, released.clone())) }.unwrap();
        let second = unsafe { unit.attach_requester(stopped_claim(16)) }.unwrap();
        let before = source.released.load(Ordering::Relaxed);
        registers.0.lock().unwrap().block_context = true;
        assert!(matches!(unsafe { first.detach() }, Err(VtdError::Timeout)));
        assert_eq!(released.load(Ordering::Relaxed), 0);
        assert_eq!(source.released.load(Ordering::Relaxed), before);
        {
            let mut g = unit.lock();
            let state = g.state();
            assert!(state.poisoned);
            assert!(state.domains.contains_key(&8));
            assert_eq!(state.domains[&8].did, first.domain_id());
        }
        assert!(matches!(
            unsafe { unit.attach_requester(stopped_claim(8)) },
            Err(VtdError::Busy)
        ));
        assert_eq!(unsafe { unit.shut_down() }, Err(VtdError::Busy));
        registers.0.lock().unwrap().block_context = false;
        drop(unsafe { first.detach() }.unwrap());
        assert_eq!(released.load(Ordering::Relaxed), 1);
        drop(first);
        drop(unsafe { second.detach() }.unwrap());
        drop(second);
        unsafe { unit.shut_down() }.unwrap();
    }
    #[test]
    fn hardware_did_capacity_quarantine_and_software_epochs_never_wrap_or_reuse_early() {
        for nd in 0..=7 {
            let registers = ModelRegisters::new();
            registers
                .0
                .lock()
                .unwrap()
                .values
                .entry(CAP)
                .and_modify(|v| *v = (*v & !7) | nd);
            let source = source();
            let result = unsafe { Unit::take_over(registers, source, &[8], 48) };
            if nd == 7 {
                assert!(matches!(result, Err(VtdError::Unsupported)));
                assert_eq!(source.next.load(Ordering::Relaxed), 0x100000);
            } else {
                let unit = result.unwrap();
                assert_eq!(unit.max_domains, 1u32 << (4 + 2 * nd));
                unsafe { unit.shut_down() }.unwrap();
            }
        }
        for invalid in [&[][..], &[8, 8][..]] {
            assert!(matches!(
                unsafe { Unit::take_over(ModelRegisters::new(), source(), invalid, 48) },
                Err(VtdError::Unsupported)
            ));
        }
        // Requesters on two buses: a context table under each root entry.
        let unit =
            unsafe { Unit::take_over(ModelRegisters::new(), source(), &[8, 0x308], 48) }.unwrap();
        {
            let mut guard = unit.lock();
            let state = guard.state();
            assert_eq!(state.contexts.len(), 2);
            for bus in [0, 3] {
                assert_eq!(
                    state.root.read(bus),
                    state.contexts[&(bus as u8)].physical() | 1
                );
            }
            assert_eq!(state.root.read(1), 0);
        }
        unsafe { unit.shut_down() }.unwrap();
        let registers = ModelRegisters::new();
        let inventory: Vec<u16> = (0..16).collect();
        let unit = unsafe { Unit::take_over(registers, source(), &inventory, 48) }.unwrap();
        let mut domains = Vec::new();
        for rid in 0..15 {
            domains.push(unsafe { unit.attach_requester(stopped_claim(rid)) }.unwrap());
        }
        assert!(matches!(
            unsafe { unit.attach_requester(stopped_claim(15)) },
            Err(VtdError::Busy)
        ));
        let abandoned = domains.remove(3);
        let quarantined_did = abandoned.domain_id();
        drop(abandoned);
        {
            let mut g = unit.lock();
            assert!(g.state().domains[&3].quarantined);
        }
        let retired = domains.remove(3);
        let reusable = retired.domain_id();
        drop(unsafe { retired.detach() }.unwrap());
        drop(retired);
        let replacement = unsafe { unit.attach_requester(stopped_claim(15)) }.unwrap();
        assert_eq!(replacement.domain_id(), reusable);
        assert_ne!(replacement.domain_id(), quarantined_did);
        drop(unsafe { replacement.detach() }.unwrap());
        drop(replacement);
        {
            let mut g = unit.lock();
            g.state().next_generation = u64::MAX;
        }
        assert!(matches!(
            unsafe { unit.attach_requester(stopped_claim(15)) },
            Err(VtdError::Unsupported)
        ));
        {
            let mut g = unit.lock();
            g.state().next_id = u64::MAX;
        }
        assert!(matches!(
            DmaMapping::map(
                domains[0].clone(),
                pages(PAGE, 12, 0x11000000, Arc::new(AtomicU64::new(0))),
                Direction::Bidirectional,
                u64::MAX
            ),
            Err(DmaError::MappingFailed)
        ));
        for domain in domains {
            drop(unsafe { domain.detach() }.unwrap());
        }
        assert_eq!(
            unsafe { unit.shut_down() },
            Err(VtdError::Busy),
            "abandoned claim must permanently reserve its actual context"
        );
    }

    #[test]
    fn active_noncoherent_walker_never_reaches_unpublished_children() {
        let source = source();
        let registers = ModelRegisters::new();
        {
            let mut model = registers.0.lock().unwrap();
            model.values.insert(ECAP, 0x10 << 8);
            model.source = Some(source);
        }
        // SAFETY: stopped isolated model; enabling TE activates the observer.
        let unit = unsafe { Unit::take_over(registers.clone(), source, &[8], 48) }.unwrap();
        let domain =
            unsafe { unit.attach_requester(RequesterClaim::model(8, Arc::new(AtomicU64::new(0)))) }
                .unwrap();
        let mut first = DmaMapping::map(
            domain.clone(),
            pages(PAGE, 12, 0xb000000, Arc::new(AtomicU64::new(0))),
            Direction::Bidirectional,
            u64::MAX,
        )
        .unwrap();
        let first_iova = first.address().unwrap();
        // Cross a 2 MiB boundary while an older mapping is reachable. Every
        // individual visible parent publication invokes the walker observer;
        // delaying all child evictions until final invalidation fails here.
        let mut second = DmaMapping::map(
            domain.clone(),
            pages(2 * 1024 * 1024, 12, 0xc000000, Arc::new(AtomicU64::new(0))),
            Direction::Bidirectional,
            u64::MAX,
        )
        .unwrap();
        let second_iova = second.address().unwrap();
        {
            let model = registers.0.lock().unwrap();
            assert!(model.active_observations > 10);
            assert_eq!(model.translation(8, first_iova), Some(0xb000000));
            assert_eq!(
                model.translation(8, second_iova + 511 * 4096),
                Some(0xc000000 + 511 * 4096)
            );
        }
        // SAFETY: stopped synchronous model; removal must evict the leaves.
        unsafe { second.unmap() }.unwrap();
        assert_eq!(
            registers.0.lock().unwrap().translation(8, second_iova),
            None
        );
        assert_eq!(
            registers.0.lock().unwrap().translation(8, first_iova),
            Some(0xb000000)
        );
        // SAFETY: no pending DMA or asynchronous work exists in the model.
        unsafe { first.unmap() }.unwrap();
        assert_eq!(registers.0.lock().unwrap().translation(8, first_iova), None);
        // SAFETY: all mappings retired and requester stays stopped.
        unsafe { domain.detach() }.unwrap();
        drop(domain);
        unsafe { unit.shut_down() }.unwrap();
    }

    #[test]
    fn all_ones_control_reads_never_establish_a_domain() {
        for offset in [CAP, ECAP, GSTS, PMEN] {
            let registers = ModelRegisters::new();
            let value = if matches!(offset, CAP | ECAP) {
                u64::MAX
            } else {
                u64::from(u32::MAX)
            };
            registers.0.lock().unwrap().values.insert(offset, value);
            let source = source();
            // SAFETY: explicit failed-register model; no takeover may occur.
            assert!(matches!(
                unsafe { Unit::take_over(registers.clone(), source, &[8], 48) },
                Err(VtdError::RegisterRead)
            ));
            assert_eq!(source.next.load(Ordering::Relaxed), 0x100000);
            assert!(registers.0.lock().unwrap().writes.is_empty());
        }
        for command in [ROOT_POINTER, TRANSLATION] {
            let registers = ModelRegisters::new();
            registers.0.lock().unwrap().fail_gsts_after = Some(command);
            let source = source();
            let before = quarantined_units();
            // SAFETY: model injects failed GSTS only after this real stage's
            // command; no acknowledged usable Arc may escape.
            assert!(matches!(
                unsafe { Unit::take_over(registers.clone(), source, &[8], 48) },
                Err(VtdError::RegisterRead)
            ));
            assert!(quarantined_units() > before);
            assert!(source.next.load(Ordering::Relaxed) > 0x100000);
            assert_eq!(source.released.load(Ordering::Relaxed), 0);
            if command == ROOT_POINTER {
                assert!(
                    !registers
                        .0
                        .lock()
                        .unwrap()
                        .writes
                        .contains(&(GCMD, u64::from(TRANSLATION)))
                );
            }
        }
    }

    #[test]
    fn missing_flush_capability_and_malformed_line_sizes_are_refused() {
        assert_eq!(qualified_flush_line(0, 8 << 8), Err(VtdError::Unsupported));
        for encoded in [0, 3, 255] {
            assert_eq!(
                qualified_flush_line(1 << 19, encoded << 8),
                Err(VtdError::Unsupported)
            );
        }
        assert_eq!(qualified_flush_line(1 << 19, 8 << 8), Ok(64));
    }

    #[test]
    fn noncoherent_table_flushes_precede_root_and_each_mapping_invalidation() {
        let registers = ModelRegisters::new();
        registers.0.lock().unwrap().values.insert(ECAP, 0x10 << 8);
        // SAFETY: exclusive stopped model with CPUID-qualified native flushes.
        let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48) }.unwrap();
        let domain =
            unsafe { unit.attach_requester(RequesterClaim::model(8, Arc::new(AtomicU64::new(0)))) }
                .unwrap();
        assert!(unit.table_cacheline.is_some());
        let root_position = registers
            .0
            .lock()
            .unwrap()
            .cache_events
            .iter()
            .position(|event| *event == (false, RTADDR))
            .unwrap();
        assert_eq!(
            registers.0.lock().unwrap().cache_events[..root_position]
                .iter()
                .filter(|event| event.0)
                .count(),
            2
        );
        registers.0.lock().unwrap().cache_events.clear();
        let pin = pages(PAGE, 12, 0xa000000, Arc::new(AtomicU64::new(0)));
        let mut mapping =
            DmaMapping::map(domain.clone(), pin, Direction::Bidirectional, u64::MAX).unwrap();
        // Every table the mapping touched, and no other, is flushed before
        // the publication: here the write-buffer flush, then the IOTLB's.
        let check = |publication: usize, count: usize| {
            let events = &registers.0.lock().unwrap().cache_events;
            let published = events
                .iter()
                .position(|event| *event == (false, publication))
                .unwrap();
            let flushed: alloc::collections::BTreeSet<_> = events[..published]
                .iter()
                .filter(|event| event.0)
                .map(|event| event.1)
                .collect();
            assert_eq!(flushed.len(), count);
            assert!(!events[published..].iter().any(|event| event.0));
        };
        // A fresh domain's mapping builds a path through every one of its
        // tables; the unit's root and context tables stay as they were.
        let tables = {
            let mut guard = unit.lock();
            guard.state().domains[&8].tables.len()
        };
        check(GCMD, tables);
        assert!(
            !registers
                .0
                .lock()
                .unwrap()
                .cache_events
                .contains(&(false, unit.iotlb))
        );
        registers.0.lock().unwrap().cache_events.clear();
        registers.0.lock().unwrap().block_iotlb = true;
        // SAFETY: stopped synchronous model; unmap flush must precede IOTLB.
        assert_eq!(
            unsafe { mapping.unmap() },
            Err(DmaError::InvalidationFailed)
        );
        // Only the leaf table changes.
        check(unit.iotlb, 1);
        registers.0.lock().unwrap().cache_events.clear();
        registers.0.lock().unwrap().block_iotlb = false;
        // SAFETY: same stopped requester; retained retry must flush again.
        unsafe { mapping.unmap() }.unwrap();
        check(unit.iotlb, 1);
        // SAFETY: all mappings removed and no model DMA can restart.
        unsafe { domain.detach() }.unwrap();
        drop(domain);
        unsafe { unit.shut_down() }.unwrap();
    }

    #[test]
    fn native_page_array_maps_through_real_tables_and_reclaims_after_acknowledged_unmap() {
        let registers = ModelRegisters::new();
        let source = source();
        // SAFETY: exclusively owned stopped requester in the explicit model.
        let unit = unsafe { Unit::take_over(registers.clone(), source, &[0x18], 48) }.unwrap();
        let domain = unsafe {
            unit.attach_requester(RequesterClaim::model(0x18, Arc::new(AtomicU64::new(0))))
        }
        .unwrap();
        let released = Arc::new(AtomicU64::new(0));
        // One actual 16 KiB native page; VT-d uses four 4 KiB leaves.
        let pin = pages(16384, 14, 0x8000000, released.clone());
        let mut mapping =
            DmaMapping::map(domain.clone(), pin, Direction::ToDevice, u32::MAX as u64).unwrap();
        let address = mapping.address().unwrap();
        assert_ne!(address, 0x8000000);
        {
            let mut guard = unit.lock();
            let state = guard.state();
            let live = &state.domains[&0x18].mappings[&address];
            assert_eq!(live.leaves.len(), 4);
            for (index, &(table, slot)) in live.leaves.iter().enumerate() {
                assert_eq!(
                    state.domains[&0x18].tables[table].read(slot),
                    (0x8000000 + (index * 4096) as u64) | READ
                );
            }
            assert_eq!(state.root.read(0), state.contexts[&0].physical() | 1);
            assert_eq!(state.contexts[&0].read(0x18 * 2 + 1), (1 << 8) | 2);
        }
        mapping.sync_for_device(0..16384).unwrap();
        let token = {
            let mut guard = unit.lock();
            guard.state().domains[&0x18].mappings[&address].info
        };
        // SAFETY: defensive error-path probe; invalid metadata is rejected
        // before any model DMA cache/memory operation can occur.
        assert_eq!(
            unsafe {
                domain.sync_for_device(
                    DomainMapping {
                        id: token.id + 1,
                        ..token
                    },
                    0..4096,
                    Direction::ToDevice,
                )
            },
            Err(DmaError::Unmapped)
        );
        assert_eq!(released.load(Ordering::Relaxed), 0);
        registers.0.lock().unwrap().block_iotlb = true;
        // SAFETY: model requester has no outstanding DMA and is stopped.
        assert_eq!(
            unsafe { mapping.unmap() },
            Err(DmaError::InvalidationFailed)
        );
        assert_eq!(released.load(Ordering::Relaxed), 0);
        registers.0.lock().unwrap().block_iotlb = false;
        // SAFETY: same stopped requester, retry of retained original mapping.
        unsafe { mapping.unmap() }.unwrap();
        assert_eq!(released.load(Ordering::Relaxed), 1);
        // SAFETY: all mappings are retired and model requester remains stopped.
        unsafe { domain.detach() }.unwrap();
        drop(domain);
        unsafe { unit.shut_down() }.unwrap();
        let table_count = source.next.load(Ordering::Relaxed).saturating_sub(0x100000) / 4096;
        drop(unit);
        assert_eq!(source.released.load(Ordering::Relaxed), table_count);
        let model = registers.0.lock().unwrap();
        let root = model
            .writes
            .iter()
            .position(|(offset, _)| *offset == RTADDR)
            .unwrap();
        let context = model
            .writes
            .iter()
            .position(|(offset, _)| *offset == CCMD)
            .unwrap();
        let enable = model
            .writes
            .iter()
            .position(|(offset, value)| *offset == GCMD && *value == u64::from(TRANSLATION))
            .unwrap();
        assert!(root < context && context < enable);
    }

    #[test]
    fn failed_translation_disable_retains_tables_until_actual_acknowledgement() {
        let registers = ModelRegisters::new();
        let source = source();
        // SAFETY: exclusively stopped model unit, with real allocated tables.
        let unit = unsafe { Unit::take_over(registers.clone(), source, &[8], 48) }.unwrap();
        let domain =
            unsafe { unit.attach_requester(RequesterClaim::model(8, Arc::new(AtomicU64::new(0)))) }
                .unwrap();
        unsafe { domain.detach() }.unwrap();
        drop(domain);
        let retained_before = source.released.load(Ordering::Relaxed);
        registers.0.lock().unwrap().block_te_off = true;
        // SAFETY: no model requesters or live mappings; inject TE-off timeout.
        assert_eq!(unsafe { unit.shut_down() }, Err(VtdError::Timeout));
        assert_eq!(source.released.load(Ordering::Relaxed), retained_before);
        assert_ne!(registers.read32(GSTS) & TRANSLATION, 0);
        let before = quarantined_units();
        drop(unit);
        assert!(quarantined_units() > before);
        assert_eq!(source.released.load(Ordering::Relaxed), retained_before);
    }

    #[test]
    fn busy_firmware_unit_is_refused_and_failed_map_keeps_pins_and_hardware_tables() {
        let registers = ModelRegisters::new();
        registers
            .0
            .lock()
            .unwrap()
            .values
            .insert(GSTS, u64::from(TRANSLATION));
        let source = source();
        // SAFETY: model probe; active firmware translation must be refused.
        assert!(matches!(
            unsafe { Unit::take_over(registers.clone(), source, &[8], 48) },
            Err(VtdError::Busy)
        ));
        assert_eq!(source.next.load(Ordering::Relaxed), 0x100000);
        assert!(registers.0.lock().unwrap().writes.is_empty());
        registers.0.lock().unwrap().values.insert(GSTS, 0);
        // SAFETY: exclusively owned model unit, all DMA stopped.
        let unit = unsafe { Unit::take_over(registers.clone(), source, &[8], 48) }.unwrap();
        let domain =
            unsafe { unit.attach_requester(RequesterClaim::model(8, Arc::new(AtomicU64::new(0)))) }
                .unwrap();
        let released = Arc::new(AtomicU64::new(0));
        let pin = pages(4096, 12, 0x9000000, released.clone());
        // Without Caching Mode a new mapping needs only the write-buffer
        // flush, which fails here.
        registers.0.lock().unwrap().fail_gsts_after = Some(TRANSLATION | WRITE_BUFFER);
        assert!(matches!(
            DmaMapping::map(domain.clone(), pin, Direction::Bidirectional, u64::MAX),
            Err(DmaError::InvalidationFailed)
        ));
        assert_eq!(released.load(Ordering::Relaxed), 0);
        let before = quarantined_domains();
        drop(domain);
        drop(unit);
        assert!(quarantined_domains() > before);
        assert_eq!(source.released.load(Ordering::Relaxed), 0);
        assert_eq!(released.load(Ordering::Relaxed), 0);
    }
}
