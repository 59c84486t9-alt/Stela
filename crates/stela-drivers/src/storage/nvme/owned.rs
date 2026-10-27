//! Retained native NVMe transport and requester-domain memory. No physical
//! address is interpreted as a CPU pointer or a device IOVA.
use super::*;
use crate::bus::{
    dma::{
        DmaBuffer,
        mapping::{Direction, DmaDomain, DmaError, DmaMapping},
        memory::{CacheAttribute, CpuMapping, PageSource},
    },
    mmio::{
        Mmio,
        owned::{Mapping, Protection},
    },
};
use alloc::{boxed::Box, string::String, sync::Arc};
use core::{mem, ptr};

/// Exclusive, fallible controller registers, retained through final retirement.
///
/// # Safety
/// Implementors retain the actual controller BAR mapping, CPU-root/resource
/// reservation and its mapping epoch. The paired Lifecycle retains PCI/reset
/// hierarchy ownership through register retirement. Every access checks its
/// complete range and alignment, uses the actual device's UC mapping and
/// preserves device ordering. Failures
/// must remain errors, never synthetic all-ones reads or acknowledged writes.
/// No other controller or register accessor may drive this controller.
pub unsafe trait Registers {
    fn read32(&self, offset: usize) -> Result<u32, BlockError>;
    fn write32(&self, offset: usize, value: u32) -> Result<(), BlockError>;
    fn read64(&self, offset: usize) -> Result<u64, BlockError> {
        let high = offset.checked_add(4).ok_or_else(register_error)?;
        Ok(u64::from(self.read32(offset)?) | u64::from(self.read32(high)?) << 32)
    }
    fn write64(&self, offset: usize, value: u64) -> Result<(), BlockError> {
        let high = offset.checked_add(4).ok_or_else(register_error)?;
        self.write32(offset, value as u32)?;
        self.write32(high, (value >> 32) as u32)
    }
    /// End CPU views/mapping while the configuration/resource owner is held.
    ///
    /// # Safety
    /// Controller/submission paths are stopped, requester BME is contained,
    /// domain payload writes drained, and all RAM mappings unmapped. No access
    /// to these registers may follow success. Failure retains the exact owner.
    unsafe fn retire(&mut self) -> Result<(), BlockError>;
}

/// The actual retained PCI/child hierarchy; a BDF is not this authority.
///
/// # Safety
/// Implementors retain exclusive controller/configuration/reset/resource and
/// parent root owners until release. On entry, the entire retained hierarchy
/// must have acknowledged BME-clear, with no uncontrolled DMA engine. `prepare`
/// establishes actual D0 and memory decode while preserving containment.
/// `enable_dma` establishes actual memory decode/BME for this exact domain-bound requester; errors after any
/// possible effect retain that authority. `disable_dma` acknowledges actual
/// BME-clear and excludes new requester DMA. It is not a payload-write drain.
/// Failed `prepare` does not authorize any NVMe MMIO: the caller quarantines
/// the complete owner because no generic recovery can establish D0.
/// `release` returns owners only after its caller's completed teardown; failed
/// operations retain the same hardware epoch and are retryable or quarantined.
pub unsafe trait Lifecycle {
    fn prepare(&mut self) -> Result<(), BlockError>;
    fn enable_dma(&mut self) -> Result<(), BlockError>;
    fn disable_dma(&mut self) -> Result<(), BlockError>;
    fn release(&mut self) -> Result<(), BlockError>;
}

/// An actual exclusively reserved, owned UC BAR mapping.
pub struct MappingRegisters {
    mapping: Mapping,
}
impl MappingRegisters {
    pub fn new(mapping: Mapping) -> Result<Self, (BlockError, Mapping)> {
        if mapping.attribute() != Ok(CacheAttribute::Uncached)
            || mapping.protection() != Ok(Protection::ReadWrite)
            || !mapping
                .address(0, 0x2000)
                .is_ok_and(|p| (p.as_ptr() as usize).is_multiple_of(align_of::<u32>()))
        {
            return Err((register_error(), mapping));
        }
        Ok(Self { mapping })
    }
    fn word(&self, offset: usize) -> Result<*mut u32, BlockError> {
        if !offset.is_multiple_of(4) {
            return Err(register_error());
        }
        let pointer = self
            .mapping
            .address(offset, size_of::<u32>())
            .map_err(|_| register_error())?;
        if !(pointer.as_ptr() as usize).is_multiple_of(align_of::<u32>()) {
            return Err(register_error());
        }
        Ok(pointer.as_ptr().cast())
    }
}
// SAFETY: the owned Mapping retains the actual exclusive resource, UC policy,
// CPU root and span; checked volatile accesses preserve their exact effects.
unsafe impl Registers for MappingRegisters {
    fn read32(&self, offset: usize) -> Result<u32, BlockError> {
        // SAFETY: word validated the complete live aligned UC register.
        Ok(unsafe { self.word(offset)?.read_volatile() })
    }
    fn write32(&self, offset: usize, value: u32) -> Result<(), BlockError> {
        // SAFETY: same live exclusive register boundary.
        unsafe { self.word(offset)?.write_volatile(value) };
        Ok(())
    }
    unsafe fn retire(&mut self) -> Result<(), BlockError> {
        // SAFETY: the caller establishes stopped/drained exclusive access.
        unsafe { self.mapping.retire() }.map_err(|_| register_error())
    }
}
fn register_error() -> BlockError {
    BlockError::Protocol("NVMe owned register mapping")
}
fn dma_error() -> BlockError {
    BlockError::Protocol("NVMe requester-domain DMA")
}
fn map_dma_error(error: DmaError) -> BlockError {
    match error {
        DmaError::IommuUnavailable => BlockError::Unsupported("NVMe requester IOMMU domain"),
        DmaError::CoherenceUnavailable => BlockError::Unsupported("NVMe coherent CQ observation"),
        DmaError::DrainUnavailable => BlockError::Unsupported("NVMe original-domain payload drain"),
        DmaError::VisibilityFailed => BlockError::Protocol("NVMe DMA cache visibility"),
        DmaError::InvalidationFailed => BlockError::Protocol("NVMe DMA invalidation"),
        _ => dma_error(),
    }
}

pub(super) enum RegisterIo {
    Legacy(Mmio),
    Owned(Option<Box<dyn Registers>>),
}
impl RegisterIo {
    pub(super) fn read32(&self, offset: usize) -> Result<u32, BlockError> {
        match self {
            Self::Legacy(m) => Ok(m.read32(offset)),
            Self::Owned(Some(m)) => m.read32(offset),
            _ => Err(register_error()),
        }
    }
    pub(super) fn write32(&self, offset: usize, value: u32) -> Result<(), BlockError> {
        match self {
            Self::Legacy(m) => {
                m.write32(offset, value);
                Ok(())
            }
            Self::Owned(Some(m)) => m.write32(offset, value),
            _ => Err(register_error()),
        }
    }
    pub(super) fn read64(&self, offset: usize) -> Result<u64, BlockError> {
        match self {
            Self::Legacy(m) => Ok(m.read64(offset)),
            Self::Owned(Some(m)) => m.read64(offset),
            _ => Err(register_error()),
        }
    }
    pub(super) fn write64(&self, offset: usize, value: u64) -> Result<(), BlockError> {
        match self {
            Self::Legacy(m) => {
                m.write64(offset, value);
                Ok(())
            }
            Self::Owned(Some(m)) => m.write64(offset, value),
            _ => Err(register_error()),
        }
    }
    unsafe fn retire(&mut self) -> Result<(), BlockError> {
        if let Self::Owned(Some(r)) = self {
            // SAFETY: forwarded stopped/drained contract from Controller.
            unsafe { r.retire()? };
        }
        Ok(())
    }
    fn quarantine(&mut self) {
        if let Self::Owned(owner) = self
            && let Some(r) = owner.take()
        {
            mem::forget(r);
        }
    }
}

pub(super) struct Memory {
    cpu: CpuMapping,
    dma: DmaMapping,
    cpu_owned: bool,
    published: bool,
}
pub(super) enum Buffer {
    Legacy(DmaBuffer),
    Owned(Memory),
    Empty,
}
impl Buffer {
    fn allocate(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        direction: Direction,
    ) -> Result<Self, BlockError> {
        let pages = source
            .allocate(bytes, PAGE, CacheAttribute::WriteBack)
            .map_err(|_| BlockError::NoDmaMemory)?;
        if pages.logical_bytes() < bytes || pages.page_shift() != 12 {
            return Err(BlockError::Unsupported("NVMe requires 4 KiB DMA pages"));
        }
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(|_| BlockError::Protocol("NVMe retained CPU mapping"))?;
        let dma = DmaMapping::map(domain, pages, direction, u64::MAX).map_err(map_dma_error)?;
        Ok(Self::Owned(Memory {
            cpu,
            dma,
            cpu_owned: true,
            published: false,
        }))
    }
    pub(super) fn address(&self) -> Result<u64, BlockError> {
        match self {
            Self::Legacy(b) => Ok(b.physical()),
            Self::Owned(b) => b.dma.address().map_err(map_dma_error),
            Self::Empty => Err(dma_error()),
        }
    }
    pub(super) fn bytes(&self) -> &[u8] {
        match self {
            Self::Legacy(b) => b.bytes(),
            Self::Owned(b) => {
                assert!(b.cpu_owned, "CPU view while NVMe owns DMA");
                // SAFETY: allocation is retained and CPU ownership established
                // by completion or before any publication; no device writer.
                unsafe {
                    core::slice::from_raw_parts(
                        b.cpu
                            .address(0, b.cpu.bytes())
                            .expect("validated CPU span")
                            .as_ptr(),
                        b.cpu.bytes(),
                    )
                }
            }
            Self::Empty => &[],
        }
    }
    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Legacy(b) => b.bytes_mut(),
            Self::Owned(b) => {
                assert!(b.cpu_owned, "CPU write while NVMe owns DMA");
                // SAFETY: exclusive CPU ownership and retained mapped span.
                unsafe {
                    core::slice::from_raw_parts_mut(
                        b.cpu
                            .address(0, b.cpu.bytes())
                            .expect("validated CPU span")
                            .as_ptr(),
                        b.cpu.bytes(),
                    )
                }
            }
            Self::Empty => &mut [],
        }
    }
    pub(super) fn write<T: crate::bus::dma::DmaValue>(&mut self, offset: usize, value: T) {
        let bytes = self.bytes_mut();
        assert!(
            offset
                .checked_add(size_of::<T>())
                .is_some_and(|end| end <= bytes.len())
        );
        // SAFETY: bytes_mut established a unique CPU-owned mapped slice, and
        // the checked complete T span above keeps offset within that allocation.
        // Pointer arithmetic alone does not dereference the cast T pointer;
        // its alignment is checked below before the volatile write.
        let p = unsafe { bytes.as_mut_ptr().add(offset) }.cast::<T>();
        assert!((p as usize).is_multiple_of(align_of::<T>()));
        // SAFETY: complete aligned span in uniquely CPU-owned memory.
        unsafe { ptr::write_volatile(p, value) };
    }
    pub(super) fn coherent(&self, offset: usize) -> Result<u32, BlockError> {
        match self {
            Self::Legacy(b) => Ok(b.read(offset)),
            Self::Owned(b) => b.dma.read_coherent_u32(offset).map_err(map_dma_error),
            Self::Empty => Err(dma_error()),
        }
    }
    pub(super) fn publish(&mut self) {
        if let Self::Owned(b) = self {
            b.published = true;
        }
    }
    pub(super) fn give(&mut self) -> Result<(), BlockError> {
        if let Self::Owned(b) = self {
            if b.cpu_owned {
                b.dma
                    .sync_for_device(0..b.dma.bytes())
                    .map_err(map_dma_error)?;
                b.cpu_owned = false;
            }
            b.published = true;
        }
        Ok(())
    }
    /// Only after actual command completion or acknowledged stopped/drained DMA.
    pub(super) unsafe fn take(&mut self) -> Result<(), BlockError> {
        if let Self::Owned(b) = self
            && !b.cpu_owned
        {
            // SAFETY: caller establishes actual hardware completion.
            unsafe { b.dma.sync_for_cpu(0..b.dma.bytes()) }.map_err(map_dma_error)?;
            b.cpu_owned = true;
        }
        Ok(())
    }
    unsafe fn unmap(&mut self) -> Result<(), BlockError> {
        if let Self::Owned(b) = self {
            // SAFETY: stopped requester and completed original-domain drain.
            unsafe { b.dma.unmap() }.map_err(map_dma_error)?;
            b.published = false;
        }
        *self = Self::Empty;
        Ok(())
    }
    fn quarantine(&mut self) {
        let old = mem::replace(self, Self::Empty);
        mem::forget(old);
    }
}
impl Drop for Memory {
    fn drop(&mut self) {
        if !self.published {
            // SAFETY: IOVA was never exposed, or unmap already succeeded.
            let _ = unsafe { self.dma.unmap() };
        }
        // A published lease automatically retains pins/domain on Drop. The
        // controller additionally retains the CPU/config/root owners on failure.
    }
}
/// Monotonic observations, not inferred hardware state. A failed step leaves
/// its phase unchanged; completed hardware steps are never replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Teardown {
    Unadmitted,
    Unprepared,
    Preparing,
    Active,
    Stopped,
    Contained,
    Drained,
    RamUnmapped,
    RegistersRetired,
    Released,
}

pub(super) struct Owner {
    pub(super) lifecycle: Box<dyn Lifecycle>,
    pub(super) domain: Arc<dyn DmaDomain>,
}

/// Initialize real admin/I/O queues and discover ordinary NVM namespaces using
/// the same command/namespace engine as the boot NVMe API. This is a synchronous
/// polled transport; it does not claim interrupts, hotplug or live reset recovery.
/// # Safety
/// The supplied register/lifecycle owners and domain must denote the same
/// actual exclusive controller, its requester and every DMA alias/root/reset
/// epoch. Bind that real domain before entry, and keep the complete hierarchy
/// BME-contained. This identity cannot be established from numeric BDFs or by
/// combining independently obtained type-erased owners.
pub unsafe fn attach(
    registers: Box<dyn Registers>,
    lifecycle: Box<dyn Lifecycle>,
    source: &dyn PageSource,
    domain: Arc<dyn DmaDomain>,
    clock: Clock,
    location: String,
) -> Result<Attached, BlockError> {
    // SAFETY: this is the same exclusive original-controller contract; the
    // production command budget is not exposed as an attachment capability.
    unsafe {
        attach_with_timeout(
            registers,
            lifecycle,
            source,
            domain,
            clock,
            location,
            COMMAND_TIMEOUT_US,
        )
    }
}

unsafe fn attach_with_timeout(
    registers: Box<dyn Registers>,
    lifecycle: Box<dyn Lifecycle>,
    source: &dyn PageSource,
    domain: Arc<dyn DmaDomain>,
    clock: Clock,
    location: String,
    command_timeout_us: u64,
) -> Result<Attached, BlockError> {
    // Install the complete owner before fallible allocation or hardware effects.
    let mut controller = Controller {
        registers: RegisterIo::Owned(Some(registers)),
        doorbell_stride: 0,
        admin: Queue {
            submissions: Buffer::Empty,
            completions: Buffer::Empty,
            id: 0,
            tail: 0,
            head: 0,
            phase: true,
        },
        io: Queue {
            submissions: Buffer::Empty,
            completions: Buffer::Empty,
            id: 1,
            tail: 0,
            head: 0,
            phase: true,
        },
        bounce: Buffer::Empty,
        prp_list: Buffer::Empty,
        max_transfer: BOUNCE_BYTES,
        shutdown_timeout_us: SHUTDOWN_MINIMUM_US,
        shut_down: false,
        command_id: 0,
        clock,
        command_timeout_us,
        fault: None,
        owned: Some(Owner {
            lifecycle,
            domain: domain.clone(),
        }),
        teardown: Teardown::Unadmitted,
        ready_timeout_us: 500_000,
    };
    validate_clock(clock)?;
    controller.teardown = Teardown::Unprepared;
    controller.admin.submissions =
        Buffer::allocate(source, domain.clone(), PAGE, Direction::ToDevice)?;
    controller.admin.completions =
        Buffer::allocate(source, domain.clone(), PAGE, Direction::FromDevice)?;
    controller.io.submissions =
        Buffer::allocate(source, domain.clone(), PAGE, Direction::ToDevice)?;
    controller.io.completions =
        Buffer::allocate(source, domain.clone(), PAGE, Direction::FromDevice)?;
    controller.bounce = Buffer::allocate(
        source,
        domain.clone(),
        BOUNCE_BYTES,
        Direction::Bidirectional,
    )?;
    controller.prp_list = Buffer::allocate(source, domain, PAGE, Direction::ToDevice)?;
    // Polling live CQ memory requires the domain's independently qualified
    // coherent observation; refuse absent support before enabling the engine.
    controller.admin.completions.coherent(12)?;
    controller.io.completions.coherent(12)?;
    controller.initialize()?;
    discover(controller, location)
}

impl Controller {
    /// Stop once for all sibling namespaces. A failed step retains every
    /// remaining owner, and a retry continues against the same exact epoch.
    fn retire_owned(&mut self) -> Result<(), BlockError> {
        if self.teardown == Teardown::Released || self.owned.is_none() {
            return Ok(());
        }
        self.shut_down = true;
        match self.teardown {
            Teardown::Unadmitted => {
                // Clock refusal authorizes neither configuration nor MMIO.
                // Keep every original owner while the old error-only API
                // cannot return this complete still-contained authority.
                return Err(BlockError::Unsupported("NVMe clock admission quarantined"));
            }
            Teardown::Preparing => {
                // The hierarchy may still be in D3. Neither reset nor any
                // register read is authorized. Drop retains the complete epoch.
                return Err(BlockError::Unsupported(
                    "NVMe uncertain preparation quarantined",
                ));
            }
            Teardown::Unprepared => {
                // No prepare/engine/register effect was attempted; attachment
                // required an already contained hierarchy with no DMA engine.
                self.teardown = Teardown::Stopped;
            }
            Teardown::Active => {
                self.registers.write32(CONFIGURATION, 0)?;
                self.wait_status(self.ready_timeout_us, |status| status & READY == 0)?;
                self.teardown = Teardown::Stopped;
            }
            _ => {}
        }
        let owner = self.owned.as_mut().expect("owned");
        if self.teardown == Teardown::Stopped {
            owner.lifecycle.disable_dma()?;
            self.teardown = Teardown::Contained;
        }
        if self.teardown == Teardown::Contained {
            // SAFETY: acknowledged stopped engine and actual BME containment.
            unsafe { owner.domain.drain_posted_writes() }.map_err(map_dma_error)?;
            self.teardown = Teardown::Drained;
        }
        if self.teardown == Teardown::Drained {
            for buffer in [
                &mut self.admin.submissions,
                &mut self.admin.completions,
                &mut self.io.submissions,
                &mut self.io.completions,
                &mut self.bounce,
                &mut self.prp_list,
            ] {
                // SAFETY: actual stop/containment/drain remain acknowledged;
                // each successful unmap becomes Empty before the next step.
                // Retry therefore only visits still-retained RAM mappings.
                unsafe { buffer.unmap()? };
            }
            self.teardown = Teardown::RamUnmapped;
        }
        if self.teardown == Teardown::RamUnmapped {
            // SAFETY: all RAM removed, no CPU/device access survives.
            unsafe { self.registers.retire()? };
            self.teardown = Teardown::RegistersRetired;
        }
        if self.teardown == Teardown::RegistersRetired {
            owner.lifecycle.release()?;
            self.teardown = Teardown::Released;
        }
        Ok(())
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        if self.owned.is_some() && self.retire_owned().is_err() {
            self.registers.quarantine();
            for buffer in [
                &mut self.admin.submissions,
                &mut self.admin.completions,
                &mut self.io.submissions,
                &mut self.io.completions,
                &mut self.bounce,
                &mut self.prp_list,
            ] {
                buffer.quarantine();
            }
            if let Some(owner) = self.owned.take() {
                mem::forget(owner);
            }
        }
    }
}

impl Namespace {
    /// Disable the entire shared owned controller and retire its real resources.
    /// Siblings refuse commands thereafter. Failure preserves ownership for retry.
    pub fn retire_owned(&mut self) -> Result<(), BlockError> {
        let mut controller = self.controller.borrow_mut();
        if controller.owned.is_none() {
            return Err(BlockError::Unsupported("legacy NVMe resource retirement"));
        }
        controller.retire_owned()
    }
}

#[cfg(test)]
pub(crate) use tests::protocol;

#[cfg(test)]
mod tests {
    pub(crate) mod protocol;
    use super::*;
    use crate::bus::dma::{
        mapping::DomainMapping,
        memory::{MemoryError, PageBacking, PinnedPages},
        pages::DmaPages,
    };
    use alloc::{
        alloc::{alloc_zeroed, dealloc},
        collections::BTreeMap,
    };
    use core::{
        alloc::Layout,
        ops::Range,
        ptr::NonNull,
        sync::atomic::{AtomicU64, AtomicUsize},
    };
    extern crate std;
    use std::sync::Mutex;

    struct Backing {
        pointer: NonNull<u8>,
        pages: Vec<u64>,
        bytes: usize,
        released: Arc<AtomicUsize>,
    }
    // SAFETY: exclusive aligned model allocation, retained by actual pins; raw
    // device/CPU effects are serialized by the model and ownership protocol.
    unsafe impl Send for Backing {}
    // SAFETY: same serialized model accesses, no safe overlapping slices.
    unsafe impl Sync for Backing {}
    // SAFETY: these physical numbers are explicitly model metadata; cpu_base
    // names independently allocated, aligned, retained zeroed model RAM.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            self.pointer
        }
        fn physical_pages(&self) -> &[u64] {
            &self.pages
        }
        fn page_shift(&self) -> u8 {
            12
        }
        fn cache_attribute(&self) -> CacheAttribute {
            CacheAttribute::WriteBack
        }
    }
    impl Drop for Backing {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::SeqCst);
            // SAFETY: exact unique allocation retained until its final pin.
            unsafe {
                dealloc(
                    self.pointer.as_ptr(),
                    Layout::from_size_align(self.bytes, PAGE).unwrap(),
                )
            };
        }
    }
    struct Source {
        next: AtomicU64,
        released: Arc<AtomicUsize>,
    }
    impl PageSource for Source {
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            assert_eq!((alignment, attribute), (PAGE, CacheAttribute::WriteBack));
            let bytes = bytes.next_multiple_of(PAGE);
            let layout = Layout::from_size_align(bytes, PAGE).unwrap();
            // SAFETY: aligned model RAM, checked for allocation failure.
            let pointer =
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
            let first = self.next.fetch_add((bytes * 2) as u64, Ordering::SeqCst);
            let pages = (0..bytes / PAGE)
                .map(|n| first + (n * PAGE * 2) as u64)
                .collect();
            PinnedPages::new(
                Box::new(Backing {
                    pointer,
                    pages,
                    bytes,
                    released: self.released.clone(),
                }),
                bytes,
                alignment,
            )
        }
    }
    struct Lease {
        cpu: CpuMapping,
        token: DomainMapping,
        direction: Direction,
        device: Vec<u8>,
        visible: bool,
    }
    #[derive(Clone, Copy, Default)]
    enum Mutation {
        #[default]
        None,
        Cid,
        Sqid,
        Head,
        Phase,
        Delayed,
    }
    struct Model {
        access: Option<Arc<dyn protocol::Access>>,
        registers: BTreeMap<usize, u32>,
        maps: BTreeMap<u64, Lease>,
        next: u64,
        queues: [(u64, u64); 2],
        heads: [u16; 2],
        phases: [bool; 2],
        disk: Vec<u8>,
        prepared: bool,
        bme: bool,
        enabled: bool,
        drained: bool,
        outstanding: bool,
        stopped: bool,
        retired: bool,
        released: bool,
        mutation: Mutation,
        fail_read: bool,
        fail_after_doorbell: bool,
        fail_device_sync: bool,
        fail_cpu_sync: bool,
        fail_drain: bool,
        fail_unmap: bool,
        fail_unmap_at: Option<usize>,
        unmap_attempts: usize,
        fail_prepare: bool,
        fail_retire: bool,
        fail_release: bool,
        mmio_accesses: usize,
        register_owner_drops: usize,
        lifecycle_owner_drops: usize,
        fail_disable: bool,
        stuck_ready: bool,
        coherent: bool,
        events: Vec<&'static str>,
        commands: usize,
        sync_cpu: usize,
        pending: Option<(usize, [u32; 16])>,
    }
    impl Model {
        fn new() -> Self {
            let mut registers = BTreeMap::new();
            // Model literal CAP: NVM supported,16-entry depth,500ms timeout.
            registers.insert(0, 15 | 1 << 24);
            registers.insert(4, 1 << 5);
            registers.insert(8, 0x0001_0100);
            Self {
                access: None,
                registers,
                maps: BTreeMap::new(),
                next: 1,
                queues: [(0, 0); 2],
                heads: [0; 2],
                phases: [true; 2],
                disk: vec![0; 1024 * 512],
                prepared: false,
                bme: false,
                enabled: false,
                drained: false,
                outstanding: false,
                stopped: true,
                retired: false,
                released: false,
                mutation: Mutation::None,
                fail_read: false,
                fail_after_doorbell: false,
                fail_device_sync: false,
                fail_cpu_sync: false,
                fail_drain: false,
                fail_unmap: false,
                fail_unmap_at: None,
                unmap_attempts: 0,
                fail_prepare: false,
                fail_retire: false,
                fail_release: false,
                mmio_accesses: 0,
                register_owner_drops: 0,
                lifecycle_owner_drops: 0,
                fail_disable: false,
                stuck_ready: false,
                coherent: true,
                events: Vec::new(),
                commands: 0,
                sync_cpu: 0,
                pending: None,
            }
        }
        fn registers_available(&self) -> bool {
            self.access
                .as_ref()
                .map_or(self.prepared, |a| a.registers_available())
        }
        fn dma_enabled(&self) -> bool {
            self.access.as_ref().map_or(self.bme, |a| a.dma_enabled())
        }
        fn any_bus_master(&self) -> bool {
            self.access
                .as_ref()
                .map_or(self.bme, |a| a.any_bus_master())
        }
        fn record(&mut self, event: &'static str) {
            self.events.push(event);
            if let Some(access) = &self.access {
                access.observe(event);
            }
        }
        fn register64(&self, offset: usize) -> u64 {
            u64::from(*self.registers.get(&offset).unwrap_or(&0))
                | u64::from(*self.registers.get(&(offset + 4)).unwrap_or(&0)) << 32
        }
        fn read_iova(&self, address: u64, bytes: usize) -> Vec<u8> {
            let lease = self
                .maps
                .values()
                .find(|m| {
                    address >= m.token.address
                        && address
                            .checked_add(bytes as u64)
                            .is_some_and(|end| end <= m.token.address + m.token.bytes as u64)
                })
                .expect("actual mapped IOVA");
            assert!(lease.visible, "device read before cache visibility");
            assert_ne!(lease.direction, Direction::FromDevice);
            let at = (address - lease.token.address) as usize;
            lease.device[at..at + bytes].to_vec()
        }
        fn write_iova(&mut self, address: u64, data: &[u8]) {
            let lease = self
                .maps
                .values_mut()
                .find(|m| {
                    address >= m.token.address
                        && address
                            .checked_add(data.len() as u64)
                            .is_some_and(|end| end <= m.token.address + m.token.bytes as u64)
                })
                .expect("actual mapped writable IOVA");
            assert!(lease.visible, "device write before ownership transfer");
            assert_ne!(lease.direction, Direction::ToDevice);
            let at = (address - lease.token.address) as usize;
            lease.device[at..at + data.len()].copy_from_slice(data);
        }
        fn pages(&self, command: &[u32; 16], bytes: usize) -> Vec<u64> {
            let first = u64::from(command[6]) | u64::from(command[7]) << 32;
            let second = u64::from(command[8]) | u64::from(command[9]) << 32;
            let mut out = vec![first];
            let count = bytes.div_ceil(4096);
            if count == 2 {
                out.push(second);
            } else if count > 2 {
                let list = self.read_iova(second, (count - 1) * 8);
                out.extend(
                    list.as_chunks::<8>()
                        .0
                        .iter()
                        .map(|b| u64::from_le_bytes(*b)),
                );
            }
            out
        }
        fn process(&mut self, queue: usize, tail: u16) {
            assert!(
                self.registers_available()
                    && self.dma_enabled()
                    && self.enabled
                    && !self.outstanding
            );
            assert_eq!(tail, (self.heads[queue] + 1) % 16);
            let bytes =
                self.read_iova(self.queues[queue].0 + u64::from(self.heads[queue]) * 64, 64);
            let command: [u32; 16] = core::array::from_fn(|i| {
                u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap())
            });
            self.commands += 1;
            self.outstanding = true;
            self.drained = false;
            self.record("command");
            if matches!(self.mutation, Mutation::Delayed) {
                self.pending = Some((queue, command));
                return;
            }
            self.complete(queue, command);
        }
        fn complete(&mut self, queue: usize, command: [u32; 16]) {
            match (queue, command[0] as u8) {
                (0, 6) => {
                    let mut data = vec![0; 4096];
                    match command[10] {
                        1 => {
                            data[4..24].fill(b'S');
                            data[24..64].fill(b'M');
                            data[516..520].copy_from_slice(&1u32.to_le_bytes());
                        }
                        2 => data[..4].copy_from_slice(&1u32.to_le_bytes()),
                        0 => {
                            assert_eq!(command[1], 1);
                            data[..8].copy_from_slice(&1024u64.to_le_bytes());
                            data[128..132].copy_from_slice(&(9u32 << 16).to_le_bytes());
                        }
                        _ => panic!("unsupported model CNS"),
                    }
                    self.write_iova(u64::from(command[6]) | u64::from(command[7]) << 32, &data);
                }
                (0, 5) => {
                    assert_eq!(
                        (command[10] & 0xffff, command[10] >> 16, command[11]),
                        (1, 15, 1)
                    );
                    self.queues[1].1 = u64::from(command[6]) | u64::from(command[7]) << 32;
                }
                (0, 1) => {
                    assert_eq!(
                        (command[10] & 0xffff, command[10] >> 16, command[11]),
                        (1, 15, 0x10001)
                    );
                    self.queues[1].0 = u64::from(command[6]) | u64::from(command[7]) << 32;
                }
                // Delete I/O SQ, then its CQ: a CQ with a live SQ is Invalid
                // Queue Deletion (NVMe Base 2.1 §5.2.2).
                (0, 0) => {
                    assert_eq!(command[10] & 0xffff, 1);
                    assert_ne!(self.queues[1].0, 0, "deleting an absent SQ");
                    self.queues[1].0 = 0;
                }
                (0, 4) => {
                    assert_eq!(command[10] & 0xffff, 1);
                    assert_eq!(self.queues[1].0, 0, "CQ deleted before its SQ");
                    self.queues[1].1 = 0;
                }
                (1, 0) => assert_eq!(command[1], 1),
                (1, opcode @ (1 | 2)) => {
                    assert_eq!(command[1], 1);
                    let lba = (u64::from(command[10]) | u64::from(command[11]) << 32) as usize;
                    let bytes = ((command[12] & 0xffff) + 1) as usize * 512;
                    for (index, page) in self.pages(&command, bytes).into_iter().enumerate() {
                        let count = (bytes - index * 4096).min(4096);
                        let at = lba * 512 + index * 4096;
                        if opcode == 1 {
                            let data = self.read_iova(page, count);
                            self.disk[at..at + count].copy_from_slice(&data);
                        } else {
                            let data = self.disk[at..at + count].to_vec();
                            self.write_iova(page, &data);
                        }
                    }
                }
                _ => panic!("unimplemented independent NVMe model command"),
            }
            let mut cid = command[0] >> 16;
            let mut sqid = queue as u32;
            let mut head = u32::from((self.heads[queue] + 1) % 16);
            let mut phase = self.phases[queue];
            match self.mutation {
                Mutation::Cid => cid ^= 0x10,
                Mutation::Sqid => sqid ^= 1,
                Mutation::Head => head = (head + 1) % 16,
                Mutation::Phase => phase = !phase,
                _ => {}
            }
            let mut cqe = [0u8; 16];
            cqe[8..12].copy_from_slice(&(sqid << 16 | head).to_le_bytes());
            cqe[12..16].copy_from_slice(&(u32::from(phase) << 16 | cid).to_le_bytes());
            self.write_iova(
                self.queues[queue].1 + u64::from(self.heads[queue]) * 16,
                &cqe,
            );
            self.outstanding = false;
            self.record("completion");
        }
    }
    struct Domain(Arc<Mutex<Model>>);
    // SAFETY: independent device/CPU visibility model retains exact page pins
    // via CpuMapping and isolated IOVAs. It models no real hardware capability.
    unsafe impl DmaDomain for Domain {
        unsafe fn map(
            &self,
            pages: &DmaPages,
            direction: Direction,
            limit: u64,
        ) -> Result<DomainMapping, DmaError> {
            let mut m = self.0.lock().unwrap();
            let id = m.next;
            m.next += 1;
            let token = DomainMapping {
                id,
                address: 0x4_0000_0000 + id * 0x10_0000,
                bytes: pages.bytes(),
            };
            assert!(token.address + token.bytes as u64 - 1 <= limit);
            let cpu = pages
                .as_single()
                .unwrap()
                .cpu_mapping(CacheAttribute::WriteBack)
                .unwrap();
            assert_ne!(cpu.address(0, 1).unwrap().as_ptr() as u64, token.address);
            assert!(pages.physical_pages().iter().all(|pa| *pa < 0x4_0000_0000));
            m.maps.insert(
                id,
                Lease {
                    cpu,
                    token,
                    direction,
                    device: vec![0; token.bytes],
                    visible: false,
                },
            );
            m.record("map");
            Ok(token)
        }
        unsafe fn unmap(&self, token: DomainMapping) -> Result<(), DmaError> {
            let mut m = self.0.lock().unwrap();
            let unpublished = !m.maps[&token.id].visible;
            assert!(
                unpublished || (!m.enabled && !m.any_bus_master() && m.drained && !m.outstanding)
            );
            m.unmap_attempts += 1;
            if m.fail_unmap || m.fail_unmap_at == Some(m.unmap_attempts) {
                return Err(DmaError::InvalidationFailed);
            }
            m.maps.remove(&token.id).expect("live exact map");
            m.record("unmap");
            Ok(())
        }
        unsafe fn sync_for_device(
            &self,
            token: DomainMapping,
            range: Range<usize>,
            direction: Direction,
        ) -> Result<(), DmaError> {
            let mut m = self.0.lock().unwrap();
            if m.fail_device_sync {
                return Err(DmaError::VisibilityFailed);
            }
            let b = m.maps.get_mut(&token.id).unwrap();
            assert_eq!(direction, b.direction);
            let p = b.cpu.address(range.start, range.len()).unwrap();
            for (i, at) in range.enumerate() {
                // explicit CPU-to-device visibility
                // SAFETY: CPU owns this exact range before publication.
                b.device[at] = unsafe { p.as_ptr().add(i).read_volatile() };
            }
            b.visible = true;
            m.record("visible");
            Ok(())
        }
        unsafe fn sync_for_cpu(
            &self,
            token: DomainMapping,
            range: Range<usize>,
            direction: Direction,
        ) -> Result<(), DmaError> {
            let mut m = self.0.lock().unwrap();
            assert!(!m.outstanding, "CPU acquire before command completion");
            if m.fail_cpu_sync {
                return Err(DmaError::VisibilityFailed);
            }
            let b = m.maps.get_mut(&token.id).unwrap();
            assert_eq!(direction, b.direction);
            let p = b.cpu.address(range.start, range.len()).unwrap();
            for (i, at) in range.enumerate() {
                // SAFETY: actual model command completion established CPU ownership.
                unsafe { p.as_ptr().add(i).write_volatile(b.device[at]) };
            }
            m.sync_cpu += 1;
            m.record("cpu");
            Ok(())
        }
        unsafe fn read_coherent_u32(
            &self,
            token: DomainMapping,
            offset: usize,
            direction: Direction,
        ) -> Result<u32, DmaError> {
            let m = self.0.lock().unwrap();
            if !m.coherent {
                return Err(DmaError::CoherenceUnavailable);
            }
            let b = &m.maps[&token.id];
            assert_eq!(direction, b.direction);
            assert_ne!(direction, Direction::ToDevice);
            Ok(u32::from_le_bytes(
                b.device[offset..offset + 4].try_into().unwrap(),
            ))
        }
        unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
            let mut m = self.0.lock().unwrap();
            assert!(!m.any_bus_master() && !m.enabled && !m.outstanding);
            m.record("drain");
            if m.fail_drain {
                return Err(DmaError::DrainUnavailable);
            }
            m.drained = true;
            Ok(())
        }
    }
    struct Regs(Arc<Mutex<Model>>);
    // SAFETY: this independent controller model serializes exact bounded
    // register effects and retains model RAM/configuration until retirement.
    unsafe impl Registers for Regs {
        fn read32(&self, offset: usize) -> Result<u32, BlockError> {
            assert!(offset < 0x2000 && offset.is_multiple_of(4));
            let mut m = self.0.lock().unwrap();
            m.mmio_accesses += 1;
            assert!(m.registers_available() && !m.retired);
            if m.fail_read {
                return Err(register_error());
            }
            if offset == 0x1c {
                return Ok(u32::from(m.enabled || m.stuck_ready) | if m.stopped { 8 } else { 0 });
            }
            Ok(*m.registers.get(&offset).unwrap_or(&0))
        }
        fn write32(&self, offset: usize, value: u32) -> Result<(), BlockError> {
            assert!(offset < 0x2000 && offset.is_multiple_of(4));
            let mut m = self.0.lock().unwrap();
            m.mmio_accesses += 1;
            assert!(m.registers_available() && !m.retired);
            m.registers.insert(offset, value);
            match offset {
                0x14 => {
                    if value & 1 != 0 {
                        assert!(m.dma_enabled());
                        m.enabled = true;
                        m.stopped = false;
                        m.queues[0] = (m.register64(0x28), m.register64(0x30));
                        m.record("enable");
                    } else {
                        m.record("stop");
                        if !m.stuck_ready {
                            m.enabled = false;
                            m.outstanding = false;
                            m.pending = None;
                            m.stopped = true;
                        }
                    }
                    if value & (3 << 14) == 1 << 14 {
                        m.stopped = true;
                    }
                }
                0x1000 => m.process(0, value as u16),
                0x1008 => {
                    m.process(1, value as u16);
                    if m.fail_after_doorbell {
                        m.fail_read = true;
                    }
                }
                0x1004 | 0x100c => {
                    let q = usize::from(offset == 0x100c);
                    assert_eq!(value as u16, (m.heads[q] + 1) % 16);
                    m.heads[q] = value as u16;
                    if value == 0 {
                        m.phases[q] = !m.phases[q];
                    }
                    m.record("cq_ack");
                }
                _ => {}
            }
            Ok(())
        }
        unsafe fn retire(&mut self) -> Result<(), BlockError> {
            let mut m = self.0.lock().unwrap();
            assert!(m.maps.is_empty() && m.drained && !m.any_bus_master() && !m.enabled);
            m.record("retire_regs_attempt");
            if m.fail_retire {
                return Err(register_error());
            }
            m.retired = true;
            m.record("retire_regs");
            Ok(())
        }
    }
    impl Drop for Regs {
        fn drop(&mut self) {
            self.0.lock().unwrap().register_owner_drops += 1;
        }
    }
    struct Life(Arc<Mutex<Model>>);
    impl Drop for Life {
        fn drop(&mut self) {
            self.0.lock().unwrap().lifecycle_owner_drops += 1;
        }
    }
    // SAFETY: models exclusive hierarchy ownership, actual separate preparation
    // and BME effects, and refuses release before full native-owner teardown.
    unsafe impl Lifecycle for Life {
        fn prepare(&mut self) -> Result<(), BlockError> {
            let mut m = self.0.lock().unwrap();
            assert!(!m.bme);
            m.record("prepare_attempt");
            if m.fail_prepare {
                // Actual power remains D3; no BAR access is possible.
                return Err(register_error());
            }
            m.prepared = true;
            m.record("prepare");
            Ok(())
        }
        fn enable_dma(&mut self) -> Result<(), BlockError> {
            let mut m = self.0.lock().unwrap();
            assert!(m.prepared && !m.enabled && m.maps.len() == 6);
            m.bme = true;
            m.record("bme_on");
            Ok(())
        }
        fn disable_dma(&mut self) -> Result<(), BlockError> {
            let mut m = self.0.lock().unwrap();
            assert!(!m.enabled);
            m.record("bme_off");
            if m.fail_disable {
                return Err(register_error());
            }
            m.bme = false;
            Ok(())
        }
        fn release(&mut self) -> Result<(), BlockError> {
            let mut m = self.0.lock().unwrap();
            assert!(m.retired && m.maps.is_empty() && !m.bme && m.drained);
            m.record("release_attempt");
            if m.fail_release {
                return Err(register_error());
            }
            m.released = true;
            m.record("release");
            Ok(())
        }
    }
    struct Fixture {
        model: Arc<Mutex<Model>>,
        source: Source,
    }
    impl Fixture {
        fn new() -> Self {
            Self {
                model: Arc::new(Mutex::new(Model::new())),
                source: Source {
                    next: AtomicU64::new(0x9000_0000),
                    released: Arc::new(AtomicUsize::new(0)),
                },
            }
        }
        fn attach(&self) -> Result<Attached, BlockError> {
            // SAFETY: every owner retains the same exclusive independent
            // model controller/root and domain, initially BME-contained.
            unsafe {
                attach_with_timeout(
                    Box::new(Regs(self.model.clone())),
                    Box::new(Life(self.model.clone())),
                    &self.source,
                    Arc::new(Domain(self.model.clone())),
                    Clock {
                        ticks_per_microsecond: 1000,
                    },
                    "VMD model requester".into(),
                    1000,
                )
            }
        }
    }

    #[test]
    fn owned_protocol_initializes_identifies_transfers_prps_wraps_and_retires() {
        let f = Fixture::new();
        let mut attached = f.attach().unwrap();
        assert!(attached.failures.is_empty());
        assert_eq!(attached.namespaces.len(), 1);
        let disk = &mut attached.namespaces[0];
        assert_eq!(
            (disk.identity().block_size, disk.identity().blocks),
            (512, 1024)
        );
        let pattern: Vec<u8> = (0..128 * 1024).map(|n| (n * 17) as u8).collect();
        disk.write(8, &pattern).unwrap();
        let mut read = vec![0; pattern.len()];
        disk.read(8, &mut read).unwrap();
        assert_eq!(read, pattern);
        let replacement: Vec<u8> = pattern.iter().map(|byte| byte ^ 0xa5).collect();
        disk.write(8, &replacement).unwrap();
        disk.read(8, &mut read).unwrap();
        assert_eq!(read, replacement);
        for _ in 0..35 {
            disk.flush().unwrap();
        }
        disk.shutdown(false).unwrap();
        assert!(disk.flush().is_err());
        disk.retire_owned().unwrap();
        let m = f.model.lock().unwrap();
        assert!(m.released && m.maps.is_empty());
        assert_eq!(f.source.released.load(Ordering::SeqCst), 6);
        let at = |event| m.events.iter().rposition(|e| *e == event).unwrap();
        assert!(
            at("stop") < at("bme_off")
                && at("bme_off") < at("drain")
                && at("drain") < at("unmap")
                && at("unmap") < at("retire_regs")
                && at("retire_regs") < at("release")
        );
    }
    #[test]
    fn invalid_clock_retains_unadmitted_original_owners_without_any_effect() {
        for ticks_per_microsecond in [0, u64::MAX, u64::MAX / (2 * 255 * 500_000) + 1] {
            let f = Fixture::new();
            // SAFETY: the complete same-controller authority is transferred;
            // clock refusal must retain it before PCI/MMIO or DMA allocation.
            let result = unsafe {
                attach(
                    Box::new(Regs(f.model.clone())),
                    Box::new(Life(f.model.clone())),
                    &f.source,
                    Arc::new(Domain(f.model.clone())),
                    Clock {
                        ticks_per_microsecond,
                    },
                    "unadmitted original NVMe".into(),
                )
            };
            assert!(result.is_err());
            let model = f.model.lock().unwrap();
            assert!(model.events.is_empty());
            assert!(model.maps.is_empty());
            assert_eq!(model.register_owner_drops, 0);
            assert_eq!(model.lifecycle_owner_drops, 0);
            assert_eq!(f.source.next.load(Ordering::SeqCst), 0x9000_0000);
            assert_eq!(f.source.released.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn owned_bad_cqe_identity_phase_or_timeout_never_reuses_dma() {
        for mutation in [
            Mutation::Cid,
            Mutation::Sqid,
            Mutation::Head,
            Mutation::Phase,
            Mutation::Delayed,
        ] {
            let f = Fixture::new();
            let mut a = f.attach().unwrap();
            let disk = &mut a.namespaces[0];
            let mut sibling = Namespace {
                controller: disk.controller.clone(),
                namespace: disk.namespace,
                identity: disk.identity.clone(),
            };
            let before = f.model.lock().unwrap().sync_cpu;
            f.model.lock().unwrap().mutation = mutation;
            assert!(disk.read(0, &mut [0xa5; 512]).is_err());
            let commands = f.model.lock().unwrap().commands;
            assert!(disk.write(0, &[1; 512]).is_err());
            assert!(disk.flush().is_err());
            let mut output = [0xa5; 512];
            assert!(sibling.read(0, &mut output).is_err());
            assert_eq!(output, [0xa5; 512]);
            let m = f.model.lock().unwrap();
            assert_eq!(m.commands, commands);
            assert_eq!(m.sync_cpu, before);
            assert_eq!(m.maps.len(), 6);
            drop(m);
            disk.retire_owned().unwrap();
            assert!(f.model.lock().unwrap().released);
        }
    }
    #[test]
    fn owned_late_completion_does_not_reopen_poisoned_siblings() {
        let f = Fixture::new();
        let mut a = f.attach().unwrap();
        let disk = &mut a.namespaces[0];
        f.model.lock().unwrap().mutation = Mutation::Delayed;
        assert_eq!(disk.flush(), Err(BlockError::Timeout));
        {
            let mut m = f.model.lock().unwrap();
            m.mutation = Mutation::None;
            let (q, c) = m.pending.take().unwrap();
            m.complete(q, c);
        }
        let mut output = [0xa5; 512];
        assert_eq!(disk.read(0, &mut output), Err(BlockError::Timeout));
        assert_eq!(output, [0xa5; 512]);
        disk.retire_owned().unwrap();
    }
    #[test]
    fn owned_stop_bme_drain_and_unmap_failures_retain_exact_original_owners() {
        for stage in 0..4 {
            let f = Fixture::new();
            let mut a = f.attach().unwrap();
            {
                let mut m = f.model.lock().unwrap();
                match stage {
                    0 => m.stuck_ready = true,
                    1 => m.fail_disable = true,
                    2 => m.fail_drain = true,
                    _ => m.fail_unmap = true,
                }
            }
            assert!(a.namespaces[0].retire_owned().is_err());
            {
                let m = f.model.lock().unwrap();
                assert_eq!(m.maps.len(), 6);
                assert!(!m.retired && !m.released);
                assert_eq!(f.source.released.load(Ordering::SeqCst), 0);
            }
            {
                let mut m = f.model.lock().unwrap();
                m.stuck_ready = false;
                m.fail_disable = false;
                m.fail_drain = false;
                m.fail_unmap = false;
            }
            a.namespaces[0].retire_owned().unwrap();
            assert!(f.model.lock().unwrap().released);
        }
    }
    #[test]
    fn owned_visibility_failures_poison_without_exposing_unacquired_data() {
        for device in [true, false] {
            let f = Fixture::new();
            let mut a = f.attach().unwrap();
            {
                let mut m = f.model.lock().unwrap();
                m.fail_device_sync = device;
                m.fail_cpu_sync = !device;
            }
            let mut output = [0xa5; 512];
            assert!(a.namespaces[0].read(0, &mut output).is_err());
            assert_eq!(output, [0xa5; 512]);
            let commands = f.model.lock().unwrap().commands;
            assert!(a.namespaces[0].write(0, &[1; 512]).is_err());
            assert_eq!(f.model.lock().unwrap().commands, commands);
            {
                let mut m = f.model.lock().unwrap();
                m.fail_device_sync = false;
                m.fail_cpu_sync = false;
            }
            a.namespaces[0].retire_owned().unwrap();
            assert!(f.model.lock().unwrap().released);
        }
    }
    #[test]
    fn owned_last_namespace_drop_retires_successful_controller() {
        let f = Fixture::new();
        let a = f.attach().unwrap();
        drop(a);
        let m = f.model.lock().unwrap();
        assert!(m.released && m.retired && m.maps.is_empty());
        assert_eq!(f.source.released.load(Ordering::SeqCst), 6);
    }
    #[test]
    fn owned_drop_quarantines_hierarchy_and_cpu_pins_after_failed_drain() {
        let f = Fixture::new();
        let a = f.attach().unwrap();
        f.model.lock().unwrap().fail_drain = true;
        drop(a);
        let m = f.model.lock().unwrap();
        assert_eq!(m.maps.len(), 6);
        assert!(!m.retired && !m.released);
        assert_eq!(f.source.released.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn owned_absent_coherent_observation_refuses_before_enable_and_releases_unpublished_maps() {
        let f = Fixture::new();
        f.model.lock().unwrap().coherent = false;
        assert!(f.attach().is_err());
        let m = f.model.lock().unwrap();
        assert!(!m.bme && !m.enabled && !m.prepared);
        assert!(m.released && m.maps.is_empty());
        assert!(!m.events.contains(&"command") && !m.events.contains(&"bme_on"));
    }
    #[test]
    fn owned_register_failure_after_doorbell_poison_retains_no_cpu_reacquire() {
        let f = Fixture::new();
        let mut a = f.attach().unwrap();
        let before = f.model.lock().unwrap().sync_cpu;
        let commands = f.model.lock().unwrap().commands;
        f.model.lock().unwrap().fail_after_doorbell = true;
        assert!(a.namespaces[0].flush().is_err());
        {
            let m = f.model.lock().unwrap();
            assert!(!m.released);
            assert_eq!(m.commands, commands + 1);
            assert_eq!(m.sync_cpu, before);
        }
        assert!(a.namespaces[0].write(0, &[1; 512]).is_err());
        f.model.lock().unwrap().fail_read = false;
        a.namespaces[0].retire_owned().unwrap();
    }
    #[test]
    fn owned_failed_prepare_in_d3_quarantines_without_any_nvme_mmio() {
        let f = Fixture::new();
        f.model.lock().unwrap().fail_prepare = true;
        assert!(f.attach().is_err());
        let m = f.model.lock().unwrap();
        assert!(!m.prepared && !m.enabled && !m.bme);
        assert_eq!(m.mmio_accesses, 0);
        assert_eq!(
            m.events.iter().filter(|e| **e == "prepare_attempt").count(),
            1
        );
        assert_eq!(m.maps.len(), 6);
        assert_eq!(m.unmap_attempts, 0);
        assert!(!m.retired && !m.released);
        assert_eq!((m.register_owner_drops, m.lifecycle_owner_drops), (0, 0));
        assert_eq!(f.source.released.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn owned_register_retirement_failure_retries_only_that_step_and_release() {
        let f = Fixture::new();
        let mut a = f.attach().unwrap();
        f.model.lock().unwrap().fail_retire = true;
        assert!(a.namespaces[0].retire_owned().is_err());
        let accesses = {
            let m = f.model.lock().unwrap();
            assert!(m.maps.is_empty() && m.drained && !m.bme && !m.enabled);
            assert!(!m.retired && !m.released);
            assert_eq!(m.unmap_attempts, 6);
            assert_eq!((m.register_owner_drops, m.lifecycle_owner_drops), (0, 0));
            assert_eq!(f.source.released.load(Ordering::SeqCst), 6);
            m.mmio_accesses
        };
        f.model.lock().unwrap().fail_retire = false;
        a.namespaces[0].retire_owned().unwrap();
        let m = f.model.lock().unwrap();
        assert_eq!(m.mmio_accesses, accesses);
        assert_eq!(m.unmap_attempts, 6);
        assert_eq!(
            m.events
                .iter()
                .filter(|e| **e == "retire_regs_attempt")
                .count(),
            2
        );
        assert_eq!(m.events.iter().filter(|e| **e == "bme_off").count(), 1);
        assert_eq!(m.events.iter().filter(|e| **e == "drain").count(), 1);
        assert!(m.retired && m.released);
    }

    #[test]
    fn owned_hierarchy_release_failure_never_accesses_retired_registers_on_retry() {
        let f = Fixture::new();
        let mut a = f.attach().unwrap();
        f.model.lock().unwrap().fail_release = true;
        assert!(a.namespaces[0].retire_owned().is_err());
        let accesses = {
            let m = f.model.lock().unwrap();
            assert!(m.retired && !m.released && m.maps.is_empty());
            assert_eq!((m.register_owner_drops, m.lifecycle_owner_drops), (0, 0));
            m.mmio_accesses
        };
        f.model.lock().unwrap().fail_release = false;
        a.namespaces[0].retire_owned().unwrap();
        a.namespaces[0].retire_owned().unwrap();
        let m = f.model.lock().unwrap();
        assert_eq!(m.mmio_accesses, accesses);
        assert_eq!(m.unmap_attempts, 6);
        assert_eq!(
            m.events
                .iter()
                .filter(|e| **e == "retire_regs_attempt")
                .count(),
            1
        );
        assert_eq!(
            m.events.iter().filter(|e| **e == "release_attempt").count(),
            2
        );
        assert!(m.released);
    }

    #[test]
    fn owned_partial_ram_unmap_retries_only_remaining_original_leases() {
        for nth in 2..=6 {
            let f = Fixture::new();
            let mut a = f.attach().unwrap();
            let ids: Vec<_> = f.model.lock().unwrap().maps.keys().copied().collect();
            f.model.lock().unwrap().fail_unmap_at = Some(nth);
            assert!(a.namespaces[0].retire_owned().is_err());
            let accesses = {
                let m = f.model.lock().unwrap();
                assert_eq!(m.maps.keys().copied().collect::<Vec<_>>(), ids[nth - 1..]);
                assert_eq!(m.unmap_attempts, nth);
                assert!(m.drained && !m.bme && !m.enabled && !m.retired && !m.released);
                assert_eq!(f.source.released.load(Ordering::SeqCst), nth - 1);
                m.mmio_accesses
            };
            f.model.lock().unwrap().fail_unmap_at = None;
            a.namespaces[0].retire_owned().unwrap();
            let m = f.model.lock().unwrap();
            assert_eq!(m.mmio_accesses, accesses);
            assert_eq!(m.unmap_attempts, 7);
            assert_eq!(m.events.iter().filter(|e| **e == "drain").count(), 1);
            assert_eq!(m.events.iter().filter(|e| **e == "bme_off").count(), 1);
            assert!(m.released && m.retired && m.maps.is_empty());
            assert_eq!(f.source.released.load(Ordering::SeqCst), 6);
        }
    }

    #[repr(align(4096))]
    struct RegisterPages([u8; 0x4000]);
    struct RegisterPlatform {
        pages: Mutex<Box<RegisterPages>>,
        unmaps: AtomicUsize,
    }
    struct RegisterResource(Arc<AtomicUsize>);
    impl Drop for RegisterResource {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    // SAFETY: isolated model reservation, retained through the real Authority;
    // this physical interval is metadata, not a CPU or DMA pointer.
    unsafe impl crate::bus::mmio::owned::ResourceBacking for RegisterResource {
        fn physical_span(&self) -> crate::bus::mmio::owned::PhysicalSpan {
            crate::bus::mmio::owned::PhysicalSpan::new(0x2000_0000, 0x4000).unwrap()
        }
        fn kind(&self) -> crate::bus::mmio::owned::ResourceKind {
            crate::bus::mmio::owned::ResourceKind::Registers
        }
    }
    // SAFETY: isolated aligned RAM models UC register storage, retained by this
    // actual platform owner. Real registry reservations/retirement are used;
    // only a legitimate sub-page Mapping offset creates an unaligned accessor.
    unsafe impl crate::bus::mmio::owned::MappingPlatform for RegisterPlatform {
        fn check_context(
            &self,
            _: crate::bus::mmio::owned::AddressSpace,
        ) -> Result<(), crate::bus::mmio::owned::Error> {
            Ok(())
        }
        unsafe fn map(
            &self,
            resource: &crate::bus::mmio::owned::Resource,
            request: crate::bus::mmio::owned::MapRequest,
        ) -> Result<crate::bus::mmio::owned::InstalledMapping, crate::bus::mmio::owned::MapFailure>
        {
            assert!(resource.backing().is::<RegisterResource>());
            assert_eq!(request.physical.start(), 0x2000_0000);
            assert!(request.physical.bytes() <= 0x4000);
            let pointer = NonNull::new(self.pages.lock().unwrap().0.as_mut_ptr()).unwrap();
            Ok(crate::bus::mmio::owned::InstalledMapping {
                token: request.id,
                cpu_base: pointer,
                physical: request.physical,
                attribute: request.attribute,
                protection: request.protection,
            })
        }
        unsafe fn unmap(
            &self,
            request: crate::bus::mmio::owned::MapRequest,
            installed: crate::bus::mmio::owned::InstalledMapping,
        ) -> Result<(), crate::bus::mmio::owned::Error> {
            assert_eq!(request.id, installed.token);
            assert_eq!(request.physical, installed.physical);
            self.unmaps.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn owned_mapping_registers_reject_actual_unaligned_mapping_and_return_its_owner() {
        use crate::bus::mmio::owned::{AddressSpace, Authority, Resource};
        for offset in [1, 2, 3, 0] {
            let platform = Arc::new(RegisterPlatform {
                pages: Mutex::new(Box::new(RegisterPages([0; 0x4000]))),
                unmaps: AtomicUsize::new(0),
            });
            let released = Arc::new(AtomicUsize::new(0));
            // SAFETY: exclusive isolated model resource/root, no other aliases.
            let authority = unsafe {
                Authority::isolated_model(
                    platform.clone(),
                    AddressSpace {
                        identity: 1,
                        physical_bits: 48,
                        virtual_bits: 48,
                    },
                    vec![],
                )
            }
            .unwrap();
            let mapping = authority
                .map(
                    Resource::new(Box::new(RegisterResource(released.clone()))),
                    offset,
                    0x2000,
                    CacheAttribute::Uncached,
                    Protection::ReadWrite,
                )
                .unwrap();
            let original = mapping.address(0, 0x2000).unwrap();
            assert_eq!((original.as_ptr() as usize) % 4, offset);
            if offset == 0 {
                let mut registers = MappingRegisters::new(mapping).ok().unwrap();
                assert!(registers.read32(1).is_err());
                assert!(registers.write32(0x1ffe, 1).is_err());
                assert!(registers.read32(0x2000).is_err());
                registers.write32(0x1ffc, 0x1234_abcd).unwrap();
                assert_eq!(registers.read32(0x1ffc).unwrap(), 0x1234_abcd);
                // SAFETY: only these synchronous CPU accesses existed.
                unsafe { registers.retire() }.unwrap();
                assert!(registers.read32(0).is_err());
            } else {
                let (_, mut returned) = MappingRegisters::new(mapping).err().unwrap();
                assert_eq!(returned.address(0, 0x2000).unwrap(), original);
                assert_eq!(
                    returned.physical_span().unwrap().start(),
                    0x2000_0000 + offset as u64
                );
                assert_eq!(authority.status().unwrap().live, 1);
                assert_eq!(released.load(Ordering::SeqCst), 0);
                assert_eq!(platform.unmaps.load(Ordering::SeqCst), 0);
                // SAFETY: constructor refused before any register access.
                unsafe { returned.retire() }.unwrap();
            }
            assert_eq!(platform.unmaps.load(Ordering::SeqCst), 1);
            assert_eq!(released.load(Ordering::SeqCst), 1);
            assert_eq!(authority.status().unwrap().live, 0);
        }
    }
}
