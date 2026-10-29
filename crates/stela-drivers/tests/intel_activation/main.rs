//! Explicit RAM/MMIO models; never a production PCI/power/cache provider.
extern crate alloc;
mod intel;
use activation::{Device, Error, PciIdentity, ProbeOwner};
use bus::mmio::owned::*;
mod firmware_storage_tests;
mod wopcm_tests;
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ptr::NonNull,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
pub use stela_drivers::{bus, firmware, gpu::intel::activation};

const BYTES: usize = 16 * 1024 * 1024;
const CONTROL: usize = 0xa188;
const ACK: usize = 0x130044;
struct Memory {
    pointer: NonNull<u8>,
    layout: Layout,
}
// SAFETY: model memory is accessed through raw volatile words under the single
// CPU-affine Device; no Rust reference or concurrently driven hardware exists.
unsafe impl Send for Memory {}
// SAFETY: same explicitly serialized RAM-only model access contract.
unsafe impl Sync for Memory {}
impl Drop for Memory {
    fn drop(&mut self) {
        // SAFETY: exact standard allocation; canonical/resource owners ended.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}
struct Reservation {
    base: u64,
    memory: Arc<Memory>,
    epoch: Arc<Counts>,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.epoch
            .reservation_dropped
            .fetch_add(1, Ordering::SeqCst);
    }
}
// SAFETY: a model reservation of its own live host RAM, not a hardware claim.
unsafe impl ResourceBacking for Reservation {
    fn physical_span(&self) -> PhysicalSpan {
        PhysicalSpan::new(self.base, BYTES as u64).unwrap()
    }
    fn kind(&self) -> ResourceKind {
        ResourceKind::Registers
    }
}
#[derive(Default)]
struct Platform {
    fail_unmap: AtomicUsize,
    fail_map: AtomicUsize,
    calls: Mutex<Vec<(bool, u64)>>,
}
// SAFETY: test-only page-table model returns actual aligned live RAM and tracks
// exact unique tokens. It does not qualify real PAT/MTRR/device mappings.
unsafe impl MappingPlatform for Platform {
    fn check_context(&self, _: AddressSpace) -> Result<(), bus::mmio::owned::Error> {
        Ok(())
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        let backing = resource.backing().downcast_ref::<Reservation>().unwrap();
        assert!(request.physical.start() >= resource.physical_span().start());
        let offset =
            usize::try_from(request.physical.start() - resource.physical_span().start()).unwrap();
        let bytes = usize::try_from(request.physical.bytes()).unwrap();
        assert!(offset <= BYTES && bytes <= BYTES - offset);
        assert!(matches!(
            (offset, bytes),
            (0, 4_194_304) | (8_388_608, 2_097_152 | 4_194_304 | 8_388_608)
        ));
        assert_eq!(
            request.protection,
            if offset == 0 {
                Protection::ReadWrite
            } else {
                Protection::ReadOnly
            }
        );
        self.calls.lock().unwrap().push((true, request.id));
        if self.fail_map.swap(0, Ordering::SeqCst) != 0 {
            return Err(MapFailure::Uncertain(
                bus::mmio::owned::Error::MappingFailed,
            ));
        }
        Ok(InstalledMapping {
            token: request.id,
            // SAFETY: actual same-allocation subspan proved above; no fabricated
            // CPU base for BAR+8MiB. Registers and GSM are distinct real leases.
            cpu_base: unsafe {
                NonNull::new_unchecked(backing.memory.pointer.as_ptr().add(offset))
            },
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(
        &self,
        request: MapRequest,
        mapping: InstalledMapping,
    ) -> Result<(), bus::mmio::owned::Error> {
        assert_eq!(request.id, mapping.token);
        self.calls.lock().unwrap().push((false, mapping.token));
        if self.fail_unmap.swap(0, Ordering::SeqCst) != 0 {
            Err(bus::mmio::owned::Error::UnmapFailed)
        } else {
            Ok(())
        }
    }
}
#[derive(Default)]
struct Counts {
    prepared: AtomicUsize,
    fail_prepare: AtomicUsize,
    finished: AtomicUsize,
    drained: AtomicUsize,
    fail_finish: AtomicUsize,
    context_checks: AtomicUsize,
    dropped: AtomicUsize,
    reservation_dropped: AtomicUsize,
    wopcm_reads: AtomicUsize,
    wopcm_writes: AtomicUsize,
    wopcm_fail_at: AtomicUsize,
    sleep_writes: AtomicUsize,
    pat_writes: AtomicUsize,
    pat_trace: [AtomicU64; 4],
    config_reads: AtomicUsize,
    config_unavailable: AtomicUsize,
    gmch: AtomicUsize,
    reads64: AtomicUsize,
    read64_unavailable: AtomicUsize,
    guc_reset_mode: AtomicUsize,
    guc_reset_reads: AtomicUsize,
    guc_reset_writes: AtomicUsize,
}
struct Owner {
    resource: Resource,
    memory: Arc<Memory>,
    counts: Arc<Counts>,
    clock_ns: AtomicU64,
    thread: std::thread::ThreadId,
    device: u16,
}
impl Owner {
    /// Advance only this isolated register model's coherent logical clock.
    fn advance_clock(&self, nanoseconds: u64) -> i64 {
        let previous = self
            .clock_ns
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current
                    .checked_add(nanoseconds)
                    .filter(|next| *next <= i64::MAX as u64)
            })
            .expect("model nanosecond counter remains representable");
        previous as i64
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.counts.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl bus::pci::ConfigSpace for Owner {
    fn read32(&self, _: u16) -> u32 {
        panic!("read16 must use the actual model width");
    }
    fn read16(&self, offset: u16) -> u16 {
        assert_eq!(offset, 0x50);
        self.counts.config_reads.fetch_add(1, Ordering::SeqCst);
        u16::try_from(self.counts.gmch.load(Ordering::SeqCst)).unwrap()
    }
    fn write32(&mut self, _: u16, _: u32) {
        panic!("read-only probe");
    }
    fn write16(&mut self, _: u16, _: u16) {
        panic!("read-only probe");
    }
    fn write8(&mut self, _: u16, _: u8) {
        panic!("read-only probe");
    }
}
// SAFETY: this implements only the explicitly simulated single-thread RAM model.
// No test is evidence of PCI power, native cache attributes, IRQ or real MMIO.
unsafe impl ProbeOwner for Owner {
    fn check_context(&self) -> Result<(), i32> {
        self.counts.context_checks.fetch_add(1, Ordering::SeqCst);
        if std::thread::current().id() == self.thread {
            Ok(())
        } else {
            Err(-16)
        }
    }
    fn identity(&self) -> PciIdentity {
        PciIdentity {
            vendor: 0x8086,
            device: self.device,
            class: 0x030000,
            revision: 0,
            virtual_function: false,
            bar0_start: self.resource.physical_span().start(),
            bar0_bytes: BYTES as u64,
        }
    }
    fn bar0(&self) -> Resource {
        self.resource.clone()
    }
    fn config_space(&self) -> Result<&dyn bus::pci::ConfigSpace, i32> {
        if self.counts.config_unavailable.load(Ordering::SeqCst) != 0 {
            Err(-95)
        } else {
            Ok(self)
        }
    }
    unsafe fn read64(&self, pointer: NonNull<u64>) -> Result<u64, i32> {
        if self.counts.read64_unavailable.load(Ordering::SeqCst) != 0 {
            return Err(-95);
        }
        assert_eq!(self.counts.finished.load(Ordering::SeqCst), 0);
        let offset = pointer.as_ptr() as usize - self.memory.pointer.as_ptr() as usize;
        assert!((8 * 1024 * 1024..BYTES).contains(&offset));
        assert!(offset.is_multiple_of(8));
        self.counts.reads64.fetch_add(1, Ordering::SeqCst);
        // SAFETY: same actual aligned GSM model allocation, no shared references.
        Ok(unsafe { pointer.as_ptr().read_volatile() })
    }
    fn prepare(&self, registers: &MappingView, _: u32, _: u32, _: bool) -> Result<(), i32> {
        assert_eq!(registers.address(0, 4).unwrap(), self.memory.pointer);
        self.counts.prepared.fetch_add(1, Ordering::SeqCst);
        if self.counts.fail_prepare.load(Ordering::SeqCst) != 0 {
            Err(-5)
        } else {
            Ok(())
        }
    }
    unsafe fn read32(&self, pointer: NonNull<u32>) -> u32 {
        assert_eq!(
            self.counts.finished.load(Ordering::SeqCst),
            0,
            "drain start must permanently exclude device operations"
        );
        let offset = pointer.as_ptr() as usize - self.memory.pointer.as_ptr() as usize;
        if matches!(offset, 0x941c | 0xc000) {
            self.counts.guc_reset_reads.fetch_add(1, Ordering::SeqCst);
            let mode = self.counts.guc_reset_mode.load(Ordering::SeqCst);
            return if offset == 0x941c {
                if mode == 1 { 8 } else { 0 }
            } else if mode == 2 {
                0
            } else {
                1
            };
        }
        assert!(matches!(
            offset,
            ACK | 0xdfc | 0xd8c | 0x380d8c | 0xc050 | 0xc340
        ));
        if matches!(offset, 0xc050 | 0xc340) {
            self.counts.wopcm_reads.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: actual aligned bounded model RAM, no Rust references.
        unsafe { pointer.as_ptr().read_volatile() }
    }
    unsafe fn write32(&self, pointer: NonNull<u32>, value: u32) {
        assert_eq!(
            self.counts.finished.load(Ordering::SeqCst),
            0,
            "drain start must permanently exclude device operations"
        );
        let offset = pointer.as_ptr() as usize - self.memory.pointer.as_ptr() as usize;
        if offset == 0x941c {
            assert_eq!(value, 8);
            self.counts.guc_reset_writes.fetch_add(1, Ordering::SeqCst);
            // SAFETY: this test writes its own aligned bounded RAM mapping.
            // The read callback separately models real clear/status outcomes.
            unsafe { pointer.as_ptr().write_volatile(value) };
            return;
        }
        if (0x4800..=0x480c).contains(&offset) {
            let index = self.counts.pat_writes.fetch_add(1, Ordering::SeqCst);
            assert!(index < 4 && offset == 0x4800 + index * 4);
            self.counts.pat_trace[index]
                .store(((offset as u64) << 32) | u64::from(value), Ordering::SeqCst);
            // SAFETY: same actual aligned bounded model UC mapping; ordered
            // register writes only, no fabricated readback or GPU cache state.
            unsafe { pointer.as_ptr().write_volatile(value) };
            return;
        }
        if matches!(offset, 0xc050 | 0xc340) {
            let index = self.counts.wopcm_writes.fetch_add(1, Ordering::SeqCst) + 1;
            // SAFETY: exact aligned RAM model word; missing ACK still retains
            // the exposed write, deliberately modeling uncertain partial state.
            unsafe {
                let current = pointer.as_ptr().read_volatile();
                if current & 1 == 0 {
                    pointer.as_ptr().write_volatile(
                        value
                            | u32::from(self.counts.wopcm_fail_at.load(Ordering::SeqCst) != index),
                    );
                }
            }
            return;
        }
        assert_eq!(offset, CONTROL);
        assert!(value == 0x10001 || value == 0x10000);
        if value == 0x10000 {
            self.counts.sleep_writes.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: live model mapping. ACK simulates the device effect only.
        unsafe {
            pointer.as_ptr().write_volatile(value);
            self.memory
                .pointer
                .as_ptr()
                .add(if self.device == 0xe202 { 0xdfc } else { ACK })
                .cast::<u32>()
                .write_volatile(value & 1);
        }
    }
    fn now_ns(&self) -> i64 {
        // One modeled observation advances the delay hook's microsecond unit.
        // Zero-delay polling therefore expires without host scheduling/time.
        self.advance_clock(1_000)
    }
    fn delay_us(&self, min: u32, max: u32, _atomic: bool) {
        assert!(min <= max);
        // Both paths are nonblocking RAM-model events, not native timing or
        // permission to sleep in an atomic context. Preserve the minimum delay.
        self.advance_clock(u64::from(min) * 1_000);
    }
    fn report(&self, domains: u32, _: bool, status: i32, _: u32) {
        assert_eq!(domains, 1);
        assert_eq!(status, 0);
    }
    fn finish(&self) -> Result<(), i32> {
        // Record a genuine model drain side effect BEFORE the possible error.
        // The owner/resource survive; a retry completes this same drain.
        self.counts.finished.fetch_add(1, Ordering::SeqCst);
        if self.counts.fail_finish.swap(0, Ordering::SeqCst) != 0 {
            Err(-5)
        } else {
            self.counts.drained.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    fn fatal(&self) -> ! {
        std::process::abort()
    }
}
fn owner(base: u64, device: u16) -> (Box<dyn ProbeOwner>, Arc<Counts>) {
    owner_with_registers(base, device, 0, 0)
}
fn owner_with_registers(
    base: u64,
    device: u16,
    wopcm_offset: u32,
    wopcm_size: u32,
) -> (Box<dyn ProbeOwner>, Arc<Counts>) {
    let layout = Layout::from_size_align(BYTES, 4096).unwrap();
    // SAFETY: nonzero validated layout, actual host RAM test allocation.
    let memory = Arc::new(Memory {
        pointer: NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap(),
        layout,
    });
    // SAFETY: test fixture initializes its own real aligned RAM before sharing.
    // Runtime GMDID words are explicit simulated inputs, not physical facts.
    unsafe {
        let bytes = memory.pointer.as_ptr();
        bytes.add(0xc340).cast::<u32>().write(wopcm_offset);
        bytes.add(0xc050).cast::<u32>().write(wopcm_size);
        // Independent raw-PTE oracle at prefix, default-WOPCM and last valid
        // page indices. No value establishes PTE validity or GPU readiness.
        bytes
            .add(8 << 20)
            .cast::<u64>()
            .write(0xfedc_ba98_7654_3210);
        for offset in [4096, 8192] {
            bytes
                .add((8 << 20) + offset)
                .cast::<u64>()
                .write(0x0123_4567_89ab_cdef);
        }
        for end in [2usize << 30, 0xfee0_0000] {
            bytes
                .add((8 << 20) + (end / 4096 - 1) * 8)
                .cast::<u64>()
                .write(u64::MAX);
        }
        if device == 0xe202 {
            bytes.add(0xd8c).cast::<u32>().write((20 << 22) | (1 << 14));
            bytes
                .add(0x380d8c)
                .cast::<u32>()
                .write((13 << 22) | (1 << 14));
        }
    }
    let counts = Arc::new(Counts::default());
    counts.gmch.store(2 << 6, Ordering::SeqCst);
    let resource = Resource::new(Box::new(Reservation {
        base,
        memory: memory.clone(),
        epoch: counts.clone(),
    }));
    (
        Box::new(Owner {
            resource,
            memory,
            counts: counts.clone(),
            clock_ns: AtomicU64::new(0),
            thread: std::thread::current().id(),
            device,
        }),
        counts,
    )
}

#[test]
fn activation_owned_model_lifetime_and_failed_unmap_retry() {
    static NEXT: AtomicU64 = AtomicU64::new(0x1000_0000);
    let platform = Arc::new(Platform::default());
    // SAFETY: only this test activates the isolated executable's model roots.
    let authority = unsafe {
        Authority::activate(
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
    // Pure source selection rejects unsupported IDs/disabled force-probe before
    // any map or power preparation and releases the ordinary unstarted owner.
    for (id, force_probe) in [(0xffff, true), (0x9a49, false)] {
        let calls = platform.calls.lock().unwrap().len();
        let (input, counts) = owner(NEXT.fetch_add(BYTES as u64, Ordering::SeqCst), id);
        assert!(matches!(
            Device::open(&authority, input, force_probe),
            Err(Error::Native(_))
        ));
        assert_eq!(platform.calls.lock().unwrap().len(), calls);
        assert_eq!(counts.prepared.load(Ordering::SeqCst), 0);
        assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
    }
    // Canonical uncertain-map quarantine must retain the separate native
    // power/reset owner too; no prepare, CPU access or fabricated drain occurs.
    let before = authority.status().unwrap().quarantined;
    platform.fail_map.store(1, Ordering::SeqCst);
    let (input, counts) = owner(NEXT.fetch_add(BYTES as u64, Ordering::SeqCst), 0x9a49);
    assert!(matches!(
        Device::open(&authority, input, true),
        Err(Error::Mapping(bus::mmio::owned::Error::MappingFailed))
    ));
    assert_eq!(counts.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 0);
    assert_eq!(authority.status().unwrap().quarantined, before + 1);
    // A failed real preparation may already have hardware effects. Its mapped
    // resource and entire owner must remain quarantined, with no fake finish.
    let before = authority.status().unwrap().quarantined;
    let (input, counts) = owner(NEXT.fetch_add(BYTES as u64, Ordering::SeqCst), 0x9a49);
    counts.fail_prepare.store(1, Ordering::SeqCst);
    assert!(matches!(
        Device::open(&authority, input, true),
        Err(Error::Native(-5))
    ));
    assert_eq!(counts.prepared.load(Ordering::SeqCst), 1);
    assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 0);
    assert_eq!(authority.status().unwrap().quarantined, before + 1);
    pat_owned_contract(&authority, &NEXT);
    guc_reset_owned_contract(&authority, &NEXT);
    gsm_owned_contract(&authority, &platform, &NEXT);
    wopcm_tests::owned_wopcm_contract(&authority, &platform, &NEXT);
    firmware_storage_tests::owned_firmware_backing(&authority, &NEXT);
    huc_default_absence_never_looks_up_provider(&authority);
    platform.calls.lock().unwrap().clear();
    let (input, counts) = owner(NEXT.fetch_add(BYTES as u64, Ordering::SeqCst), 0x9a49);
    let mut device = Device::open(&authority, input, true).unwrap();
    let facts = device.facts().unwrap();
    assert_eq!(facts.graphics_verx100, 1200);
    assert_eq!(facts.gt_ack as usize, ACK);
    intel::canonical_catalog_contract(&device);
    intel::huc_catalog_contract(&device);
    device.wake().unwrap();
    assert_eq!(device.retire(), Err(Error::Awake));
    assert_eq!(device.wake(), Err(Error::Awake));
    assert_eq!(device.facts().unwrap().awake, 1);
    device.sleep().unwrap();
    counts.fail_finish.store(1, Ordering::SeqCst);
    platform.fail_unmap.store(1, Ordering::SeqCst);
    let calls_before = platform.calls.lock().unwrap().len();
    assert_eq!(device.retire(), Err(Error::Native(-5)));
    assert_eq!(
        platform.calls.lock().unwrap().len(),
        calls_before,
        "failed drain must not start native unmapping"
    );
    assert_eq!(counts.finished.load(Ordering::SeqCst), 1);
    assert_eq!(counts.drained.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 0);
    let checks = counts.context_checks.load(Ordering::SeqCst);
    assert_eq!(device.facts(), Err(Error::Closing));
    assert!(matches!(
        device.guc_firmware(),
        Err(intel::firmware::Error::Device(Error::Closing))
    ));
    assert!(matches!(device.program_pat(), Err(Error::Closing)));
    assert_eq!(device.wake(), Err(Error::Closing));
    assert_eq!(device.sleep(), Err(Error::Closing));
    assert_eq!(
        counts.context_checks.load(Ordering::SeqCst),
        checks,
        "closed operations must not enter C or owner callbacks"
    );
    assert!(matches!(
        device.retire(),
        Err(Error::Mapping(bus::mmio::owned::Error::UnmapFailed))
    ));
    assert_eq!(counts.finished.load(Ordering::SeqCst), 2);
    assert_eq!(counts.drained.load(Ordering::SeqCst), 1);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 0);
    assert_eq!(device.facts(), Err(Error::Closing));
    assert!(matches!(
        device.guc_firmware(),
        Err(intel::firmware::Error::Device(Error::Closing))
    ));
    assert!(matches!(device.program_pat(), Err(Error::Closing)));
    assert_eq!(device.wake(), Err(Error::Closing));
    assert_eq!(device.sleep(), Err(Error::Closing));
    device.retire().unwrap();
    assert_eq!(
        counts.finished.load(Ordering::SeqCst),
        2,
        "unmap retry must not repeat the successful drain or access uncertain MMIO"
    );
    assert_eq!(counts.drained.load(Ordering::SeqCst), 1);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 1);
    let calls = platform.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1].1, calls[2].1);
    drop(calls);

    let before = authority.status().unwrap().quarantined;
    let (input, counts) = owner(NEXT.fetch_add(BYTES as u64, Ordering::SeqCst), 0x9a49);
    let mut device = Device::open(&authority, input, true).unwrap();
    device.wake().unwrap();
    drop(device);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
    assert_eq!(authority.status().unwrap().quarantined, before + 1);
}

// Test-executable-only allocator. Each armed failure runs in a fresh process;
// there is no production fault hook or alternative ownership implementation.
mod allocation_failure {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
        ptr,
    };

    #[derive(Clone, Copy)]
    pub struct Observation {
        remaining: Option<usize>,
        pub attempts: usize,
        pub failed: bool,
        pub first: usize,
        pub first_freed: bool,
    }
    const IDLE: Observation = Observation {
        remaining: None,
        attempts: 0,
        failed: false,
        first: 0,
        first_freed: false,
    };
    std::thread_local! {
        static OBSERVATION: Cell<Observation> = const { Cell::new(IDLE) };
    }
    fn deny() -> bool {
        OBSERVATION
            .try_with(|state| {
                let mut value = state.get();
                let Some(left) = value.remaining else {
                    return false;
                };
                value.attempts += 1;
                let denied = left == 0;
                value.remaining = if denied { None } else { Some(left - 1) };
                value.failed = denied;
                state.set(value);
                denied
            })
            .unwrap_or(false)
    }
    fn allocated(pointer: *mut u8) {
        let _ = OBSERVATION.try_with(|state| {
            let mut value = state.get();
            if value.remaining.is_some() && value.first == 0 {
                value.first = pointer as usize;
                state.set(value);
            }
        });
    }
    pub struct Allocator;
    // SAFETY: delegates all actual storage operations to System with the exact
    // layout. The isolated test can deny an allocation by returning null; it
    // never changes successful pointer provenance, layout or deallocation.
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if deny() {
                return ptr::null_mut();
            }
            // SAFETY: unchanged GlobalAlloc request to the real allocator.
            let pointer = unsafe { System.alloc(layout) };
            allocated(pointer);
            pointer
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if deny() {
                return ptr::null_mut();
            }
            // SAFETY: unchanged GlobalAlloc request to the real allocator.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            allocated(pointer);
            pointer
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            let _ = OBSERVATION.try_with(|state| {
                let mut value = state.get();
                if value.first == pointer as usize {
                    value.first_freed = true;
                    state.set(value);
                }
            });
            // SAFETY: exact pointer/layout returned by System above.
            unsafe { System.dealloc(pointer, layout) };
        }
    }
    pub fn arm(successes: usize) {
        OBSERVATION.with(|state| {
            state.set(Observation {
                remaining: Some(successes),
                ..IDLE
            });
        });
    }
    pub fn disarm() -> Observation {
        OBSERVATION.with(|state| state.replace(IDLE))
    }
}
#[global_allocator]
static ALLOCATOR: allocation_failure::Allocator = allocation_failure::Allocator;

#[test]
fn activation_allocation_failure_child() {
    let Ok(value) = std::env::var("STELA_INTEL_ACTIVATION_ALLOC_FAIL_AT") else {
        return;
    };
    let index: usize = value.parse().unwrap();
    assert!(index < 2);
    let platform = Arc::new(Platform::default());
    // SAFETY: a fresh process owns this test-only RAM mapping authority.
    let authority = unsafe {
        Authority::activate(
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
    let (input, counts) = owner(0x1000_0000, 0x9a49);
    allocation_failure::arm(index);
    let result = Device::open(&authority, input, true);
    let observed = allocation_failure::disarm();
    assert!(matches!(result, Err(Error::OutOfMemory)));
    assert!(observed.failed, "must deny a real allocator request");
    assert_eq!(observed.attempts, index + 1);
    if index == 1 {
        assert_ne!(observed.first, 0, "State allocation must really succeed");
        assert!(
            observed.first_freed,
            "context OOM must release State storage"
        );
    }
    assert_eq!(counts.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 1);
    assert!(platform.calls.lock().unwrap().is_empty());
    assert_eq!(authority.status().unwrap().quarantined, 0);
}

#[test]
fn activation_allocation_failures_are_recoverable() {
    for index in 0..2 {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "activation_allocation_failure_child",
                "--nocapture",
            ])
            .env("STELA_INTEL_ACTIVATION_ALLOC_FAIL_AT", index.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "actual allocation failure {index} must return an error, not abort: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn huc_default_absence_never_looks_up_provider(authority: &Authority) {
    struct Never;
    impl firmware::Provider for Never {
        fn load(
            &self,
            _: firmware::Requirement<'_>,
        ) -> Result<firmware::Image<'_>, firmware::Error> {
            panic!("absent original role/catalog cannot perform provider lookup");
        }
    }
    use intel::firmware::{Error as FirmwareError, HucDisposition};
    for (index, pci, disposition) in [
        (0u64, 0xe202, HucDisposition::Absent),
        (1, 0x56a0, HucDisposition::Absent),
        (2, 0x46d0, HucDisposition::Absent),
    ] {
        let (owner, counts) = owner(0x1b0000000 + index * BYTES as u64, pci);
        let mut device = Device::open(authority, owner, true).unwrap();
        let request = device.huc_firmware().unwrap();
        assert_eq!(request.disposition(), disposition);
        assert_eq!(request.name(), None);
        assert_eq!(request.wanted(), None);
        allocation_failure::arm(0);
        let result = request.load(&Never);
        let observed = allocation_failure::disarm();
        assert_eq!(observed.attempts, 0);
        assert!(matches!(result, Err(FirmwareError::HucAbsent(value)) if value == disposition));
        assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
        device.retire().unwrap();
    }
}

fn gsm_owned_contract(authority: &Authority, platform: &Platform, next: &AtomicU64) {
    for (pci, expected_bytes, expected_start) in
        [(0x9a49, 4 << 20, 2 << 20), (0x56a0, 8 << 20, 4 << 20)]
    {
        let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), pci);
        let mut device = Device::open(authority, input, true).unwrap();
        assert!(matches!(device.probe_gsm(authority), Err(Error::Awake)));
        device.wake().unwrap();
        if pci == 0x56a0 {
            counts.config_unavailable.store(1, Ordering::SeqCst);
        }
        let mut probe = device.probe_gsm(authority).unwrap();
        let geometry = probe.geometry();
        assert_eq!(geometry.gsm_offset, 8 << 20);
        assert_eq!(geometry.gsm_bytes, expected_bytes);
        assert_eq!(geometry.ggtt_start, expected_start);
        assert_eq!(
            counts.config_reads.load(Ordering::SeqCst),
            usize::from(pci == 0x9a49)
        );
        // Prefix reads are intentionally admitted by original xe_ggtt_get_pte,
        // even below allocator start. Raw PTE bits are never called valid/ready.
        assert_eq!(probe.read_pte(0), Ok(0xfedc_ba98_7654_3210));
        assert_eq!(
            probe.read_pte(geometry.ggtt_start),
            Ok(0x0123_4567_89ab_cdef)
        );
        assert_eq!(
            probe.read_pte(geometry.ggtt_start + geometry.ggtt_bytes - 4096),
            Ok(u64::MAX)
        );
        let reads = counts.reads64.load(Ordering::SeqCst);
        assert_eq!(probe.read_pte(1), Err(Error::Native(-22)));
        assert_eq!(
            probe.read_pte(geometry.ggtt_start + geometry.ggtt_bytes),
            Err(Error::Native(-22))
        );
        assert_eq!(probe.read_pte(u64::MAX), Err(Error::Native(-22)));
        assert_eq!(counts.reads64.load(Ordering::SeqCst), reads);
        counts.read64_unavailable.store(1, Ordering::SeqCst);
        assert_eq!(probe.read_pte(0), Err(Error::Native(-95)));
        assert_eq!(counts.reads64.load(Ordering::SeqCst), reads);
        probe.retire().unwrap();
        assert_eq!(probe.read_pte(0), Err(Error::Closing));
        drop(probe);
        device.sleep().unwrap();
        device.retire().unwrap();
        assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
        assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 1);
    }
    // Missing actual PCI access and original zero-GGMS refusal happen before
    // mapping effects and do not fabricate geometry or permanently poison GT.
    for (unavailable, gmch, error) in [(1, 2 << 6, -95), (0, 0, -12)] {
        let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), 0x9a49);
        let mut device = Device::open(authority, input, true).unwrap();
        device.wake().unwrap();
        counts
            .config_unavailable
            .store(unavailable, Ordering::SeqCst);
        counts.gmch.store(gmch, Ordering::SeqCst);
        let before = platform.calls.lock().unwrap().len();
        assert!(matches!(device.probe_gsm(authority), Err(Error::Native(value)) if value == error));
        assert_eq!(platform.calls.lock().unwrap().len(), before);
        device.sleep().unwrap();
        device.retire().unwrap();
    }
    // Real uncertain second-map retirement retries the SAME token, without
    // finish/sleep/new reads or release of the actual reset/forcewake owner.
    let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), 0x9a49);
    let mut device = Device::open(authority, input, true).unwrap();
    device.wake().unwrap();
    let mut probe = device.probe_gsm(authority).unwrap();
    platform.fail_unmap.store(1, Ordering::SeqCst);
    let before = platform.calls.lock().unwrap().len();
    assert_eq!(
        probe.retire(),
        Err(Error::Mapping(bus::mmio::owned::Error::UnmapFailed))
    );
    assert_eq!(probe.read_pte(0), Err(Error::Closing));
    probe.retire().unwrap();
    {
        let calls = platform.calls.lock().unwrap();
        assert_eq!(calls[before].1, calls[before + 1].1);
    }
    drop(probe);
    assert_eq!(device.facts(), Err(Error::Closing));
    assert_eq!(device.sleep(), Err(Error::Closing));
    assert_eq!(device.retire(), Err(Error::Awake));
    drop(device);
    assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
    assert_eq!(counts.sleep_writes.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 0);
    // No explicit retirement: both leases quarantine; actual epoch stays pinned.
    let before = authority.status().unwrap().quarantined;
    let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), 0x9a49);
    let mut device = Device::open(authority, input, true).unwrap();
    device.wake().unwrap();
    drop(device.probe_gsm(authority).unwrap());
    assert_eq!(device.sleep(), Err(Error::Closing));
    drop(device);
    assert_eq!(authority.status().unwrap().quarantined, before + 2);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    // Ambiguous second-map failure likewise permanently blocks all device IO.
    let before = authority.status().unwrap().quarantined;
    let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), 0x9a49);
    let mut device = Device::open(authority, input, true).unwrap();
    device.wake().unwrap();
    platform.fail_map.store(1, Ordering::SeqCst);
    assert!(matches!(
        device.probe_gsm(authority),
        Err(Error::Mapping(bus::mmio::owned::Error::MappingFailed))
    ));
    assert_eq!(device.facts(), Err(Error::Closing));
    drop(device);
    assert_eq!(authority.status().unwrap().quarantined, before + 2);
    assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn gsm_allocation_failure_child() {
    if std::env::var_os("STELA_INTEL_GSM_ALLOC_FAIL").is_none() {
        return;
    }
    let platform = Arc::new(Platform::default());
    // SAFETY: fresh process, isolated RAM-only canonical mapping model.
    let authority = unsafe {
        Authority::activate(
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
    let (input, counts) = owner(0x1000_0000, 0x9a49);
    let mut device = Device::open(&authority, input, true).unwrap();
    device.wake().unwrap();
    let before = platform.calls.lock().unwrap().len();
    allocation_failure::arm(0);
    let result = device.probe_gsm(&authority);
    let observed = allocation_failure::disarm();
    assert!(matches!(
        result,
        Err(Error::Mapping(bus::mmio::owned::Error::Unavailable))
    ));
    drop(result);
    assert!(observed.failed);
    assert_eq!(observed.attempts, 1);
    assert_eq!(
        platform.calls.lock().unwrap().len(),
        before,
        "fallible canonical metadata precedes map effects"
    );
    // Canonical map Error does not attest rollback. Conservative poison retains
    // the original acknowledged wake and device owner, with no cleanup effects.
    assert_eq!(device.sleep(), Err(Error::Closing));
    drop(device);
    assert_eq!(counts.sleep_writes.load(Ordering::SeqCst), 0);
    assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 0);
}
#[test]
fn gsm_actual_metadata_allocation_failure_is_recoverable() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "gsm_allocation_failure_child", "--nocapture"])
        .env("STELA_INTEL_GSM_ALLOC_FAIL", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "actual allocation NULL must not abort: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn pat_owned_contract(authority: &Authority, next: &AtomicU64) {
    for (pci, llc, discrete) in [(0x9a49, 1, 0), (0x4905, 0, 1)] {
        let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), pci);
        let mut device = Device::open(authority, input, true).unwrap();
        let facts = device.facts().unwrap();
        assert_eq!(
            (facts.has_llc, facts.gt_type, facts.discrete),
            (llc, 1, discrete)
        );
        assert!(matches!(device.program_pat(), Err(Error::Awake)));
        assert_eq!(counts.pat_writes.load(Ordering::SeqCst), 0);
        device.wake().unwrap();
        {
            allocation_failure::arm(0);
            let result = device.program_pat();
            let observed = allocation_failure::disarm();
            let report = result.unwrap();
            assert_eq!(
                observed.attempts, 0,
                "no allocation during policy/program effects"
            );
            assert!(!observed.failed);
            assert_eq!(report.writes_issued(), 4);
            assert_eq!(report.entries(), &[3, 1, 2, 0]);
            assert_eq!(
                (report.cache_none(), report.cache_wt(), report.cache_wb()),
                (3, 2, 0)
            );
        }
        assert_eq!(counts.pat_writes.load(Ordering::SeqCst), 4);
        for (index, value) in [3u64, 1, 2, 0].iter().enumerate() {
            assert_eq!(
                counts.pat_trace[index].load(Ordering::SeqCst),
                ((0x4800 + index as u64 * 4) << 32) | value
            );
        }
        assert!(matches!(device.program_pat(), Err(Error::Native(-114))));
        assert_eq!(counts.pat_writes.load(Ordering::SeqCst), 4);
        device.sleep().unwrap();
        device.retire().unwrap();
        assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
        assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 1);
    }
    // Same actual root device/GT ownership but genuinely unavailable MCR/
    // modern ATS/PTA method; no substituted direct writes or fake ACK.
    for pci in [0x56a0, 0xe202] {
        let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), pci);
        let mut device = Device::open(authority, input, true).unwrap();
        device.wake().unwrap();
        assert!(matches!(device.program_pat(), Err(Error::Native(-95))));
        assert_eq!(counts.pat_writes.load(Ordering::SeqCst), 0);
        device.sleep().unwrap();
        device.retire().unwrap();
    }
}

fn guc_reset_owned_contract(authority: &Authority, next: &AtomicU64) {
    for pci in [0x9a49, 0x4905, 0x46d0] {
        let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), pci);
        let mut device = Device::open(authority, input, true).unwrap();
        assert!(matches!(device.reset_guc(), Err(Error::Awake)));
        assert_eq!(counts.guc_reset_writes.load(Ordering::SeqCst), 0);
        device.wake().unwrap();
        {
            allocation_failure::arm(0);
            let reset = device.reset_guc();
            let observed = allocation_failure::disarm();
            let reset = reset.unwrap();
            assert_eq!(observed.attempts, 0, "no allocation after reset effects");
            assert!(!observed.failed);
            assert_eq!(reset.writes_issued(), 1);
            assert_eq!(reset.gdrst_observed(), 0);
            assert_eq!(reset.guc_status_observed() & 1, 1);
        }
        assert!(matches!(device.reset_guc(), Err(Error::Native(-114))));
        assert_eq!(counts.guc_reset_writes.load(Ordering::SeqCst), 1);
        device.sleep().unwrap();
        device.retire().unwrap();
        assert!(matches!(device.reset_guc(), Err(Error::Closing)));
        assert_eq!(counts.finished.load(Ordering::SeqCst), 1);
        assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
        assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 1);
    }
    for mode in [1, 2] {
        let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), 0x9a49);
        let mut device = Device::open(authority, input, true).unwrap();
        device.wake().unwrap();
        counts.guc_reset_mode.store(mode, Ordering::SeqCst);
        let quarantined = authority.status().unwrap().quarantined;
        allocation_failure::arm(0);
        let result = device.reset_guc();
        let observed = allocation_failure::disarm();
        assert_eq!(
            observed.attempts, 0,
            "uncertain reset retention must not allocate"
        );
        assert!(!observed.failed);
        assert!(
            matches!(result, Err(Error::Native(status)) if status == if mode == 1 { -110 } else { -5 })
        );
        assert_eq!(counts.guc_reset_writes.load(Ordering::SeqCst), 1);
        assert!(matches!(device.facts(), Err(Error::Closing)));
        assert!(matches!(device.wake(), Err(Error::Closing)));
        assert!(matches!(device.sleep(), Err(Error::Closing)));
        assert!(matches!(device.program_pat(), Err(Error::Closing)));
        assert!(matches!(device.reset_guc(), Err(Error::Closing)));
        assert!(matches!(device.probe_gsm(authority), Err(Error::Closing)));
        assert!(device.guc_firmware().is_err());
        assert!(device.huc_firmware().is_err());
        assert!(matches!(device.retire(), Err(Error::Awake)));
        assert_eq!(counts.sleep_writes.load(Ordering::SeqCst), 0);
        assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
        drop(device);
        assert_eq!(authority.status().unwrap().quarantined, quarantined + 1);
        assert_eq!(counts.guc_reset_writes.load(Ordering::SeqCst), 1);
        assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
        assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
        assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 0);
    }
    for pci in [0x56a0, 0xe202] {
        let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), pci);
        let mut device = Device::open(authority, input, true).unwrap();
        device.wake().unwrap();
        assert!(matches!(device.reset_guc(), Err(Error::Native(-95))));
        assert_eq!(counts.guc_reset_writes.load(Ordering::SeqCst), 0);
        assert_eq!(counts.guc_reset_reads.load(Ordering::SeqCst), 0);
        device.sleep().unwrap();
        device.retire().unwrap();
    }
}
