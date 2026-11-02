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
                .any(|allocation| allocation.cpu == cpu && allocation.bytes >= DEVICE_TABLE_BYTES)
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
// SAFETY: uniquely owned zeroed storage and immutable symbolic PA
// metadata; no safe references or asynchronous device accesses exist.
unsafe impl Send for Backing {}
// SAFETY: raw CPU effects are serialized by fixture ownership and its guard;
// lifetime metadata is mutex-protected. No hardware writes these bytes.
unsafe impl Sync for Backing {}
// SAFETY: fresh real CPU RAM models the immutable named physical pages.
// Malformed provider cases return inadmissible geometry/policy
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
                assert_eq!(
                    // SAFETY: this still-owned aligned buffer has not been deallocated.
                    // Preflight rejection must leave every byte at its real alloc_zeroed image,
                    // not avoid publishing.
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
        // SAFETY: each call creates fresh, zeroed owned storage,
        // never a cloned pin or alias of an earlier returned allocation.
        let cpu = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
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
// SAFETY: synchronous software observation of kept CPU bytes,
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
                        // SAFETY: exact borrowed CPU span, no concurrent
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
// supported() checks CX16 under the host OS process ISA contract across
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

fn original_table(monitor: &Arc<Monitor>, bytes: usize) -> (Hardware, PinnedPages, u64) {
    {
        let mut m = monitor.model.lock().unwrap();
        m.returned_bytes = bytes;
        m.logical = Some(bytes);
    }
    let hardware = Hardware(monitor.clone());
    let guard = hardware.enter().unwrap();
    let pages = hardware
        .allocate(bytes, 4096, CacheAttribute::WriteBack)
        .unwrap();
    let physical = pages.physical_pages()[0];
    let cpu = pages.cpu_mapping(CacheAttribute::WriteBack).unwrap();
    for index in 0..bytes / ENTRY_BYTES {
        // SAFETY: actual CPU allocation is exclusively owned by this fixture,
        // before any modeled walker exposure or table mutation owner exists.
        unsafe {
            cpu.address(index * ENTRY_BYTES, 8)
                .unwrap()
                .cast::<u64>()
                .as_ptr()
                .write_volatile(1u64.to_le())
        };
    }
    let words: [u64; 4] = [1, 0x55, 1 | (1 << 58) | (1 << 60), 0];
    for (word, value) in words.into_iter().enumerate() {
        // SAFETY: actual retained WB table, original writer guard held, exact
        // bounded aligned DWORD pair; this isolated model has no device writer.
        unsafe {
            cpu.address(8 * ENTRY_BYTES + word * 8, 8)
                .unwrap()
                .cast::<u64>()
                .as_ptr()
                .write_volatile(value.to_le())
        };
    }
    drop(cpu);
    drop(guard);
    (hardware, pages, physical | (bytes as u64 / 4096 - 1))
}

#[test]
fn original_same_table_adoption_mutates_data_only_and_keeps_real_irq_storage() {
    if !atomic::supported() {
        return;
    }
    let monitor = Monitor::new();
    let (hardware, pages, register) = original_table(&monitor, 4096);
    // SAFETY: closed synchronous owned fixture models completed original data
    // handoff, no native hardware or IRQ/history authority is supplied.
    let mut table = unsafe {
        DeviceTable::adopt_original_blocked(hardware, pages, &vec![0; REQUESTERS], 48, register)
    }
    .unwrap();
    assert_eq!(table.entries(), 128);
    assert_eq!(table.register_for_publication().unwrap(), register);
    assert_eq!(table.snapshot(128), Err(DeviceTableError::Profile));
    let irq = [1 | (1 << 58) | (1 << 60), 0];
    // SAFETY: actual fixture has no requester, writer or alias while attaching.
    unsafe {
        table.translate(
            8,
            PhysicalAddress::new(0x800000, 48).unwrap(),
            TableLevel::new(2).unwrap(),
            DomainId::new(7).unwrap(),
        )
    }
    .unwrap();
    assert_eq!(&table.snapshot(8).unwrap()[2..], &irq);
    assert!(
        monitor
            .model
            .lock()
            .unwrap()
            .events
            .contains(&Event::Invalidate(8, None)),
        "TV0 logging DomainID is not an active translation domain"
    );
    // SAFETY: same closed actual fixture, prior domain is retained until invalidate.
    unsafe { table.block(8) }.unwrap();
    assert_eq!(&table.snapshot(8).unwrap()[2..], &irq);
    assert!(
        monitor
            .model
            .lock()
            .unwrap()
            .events
            .contains(&Event::Invalidate(8, Some(7)))
    );
    drop(table);
    assert_eq!(monitor.live_pins(), 1);
    assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 0);
    assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn failed_original_adoption_keeps_same_active_ram_and_context_owner() {
    if !atomic::supported() {
        return;
    }
    let monitor = Monitor::new();
    let (hardware, pages, register) = original_table(&monitor, 4096);
    // An illegal guest/hardware-writer bit arrives in the actual active table.
    let cpu = pages.cpu_mapping(CacheAttribute::WriteBack).unwrap();
    // SAFETY: exact retained isolated table RAM and aligned bounded word;
    // deliberate malformed data tests rejection, not a hardware permission.
    unsafe {
        cpu.address(8 * ENTRY_BYTES, 8)
            .unwrap()
            .cast::<u64>()
            .as_ptr()
            .write_volatile((1u64 | (1 << 55)).to_le())
    };
    drop(cpu);
    // SAFETY: malformed image is isolated owned fixture RAM; rejection must
    // quarantine its real pin, not trust a metadata snapshot or inactivity.
    assert!(matches!(
        // SAFETY: original model table/pin and sole writer remain retained;
        // malformed data must refuse while preserving those same owners.
        unsafe {
            DeviceTable::adopt_original_blocked(hardware, pages, &vec![0; REQUESTERS], 48, register)
        },
        Err(DeviceTableError::Profile)
    ));
    assert_eq!(monitor.live_pins(), 1);
    assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 0);
    assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);
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
fn all_policy_metadata_is_kept_without_turning_permission_into_ats_enable() {
    let monitor = Monitor::new();
    let mut flags: Vec<u8> = (0..REQUESTERS).map(|requester| requester as u8).collect();
    let Some(mut table) = construct(&monitor, &flags) else {
        return;
    };
    flags.fill(0);
    assert_eq!(table.state.as_ref().unwrap().policies[0xffff], 0xff);
    for flags in (0u8..=u8::MAX).filter(|flags| flags & 8 == 0) {
        let first = u16::from(flags);
        let second = u16::from(flags | 8);
        let state = table.state.as_ref().unwrap();
        assert_eq!(state.policies[usize::from(first)], flags);
        assert_eq!(state.policies[usize::from(second)], flags | 8);
        assert_eq!(table.snapshot(first).unwrap(), blocked(flags));
        assert_eq!(table.snapshot(second).unwrap(), blocked(flags));
    }
    table.register_for_publication().unwrap();
    for requester in [0u16, 8, 0xffff] {
        // SAFETY: the model has no active device/ATC/worker. These independent RIDs use the
        // same symbolic root/domain; no native alias or integrated-device admission is
        // inferred from the permission metadata.
        unsafe {
            table.translate(
                requester,
                root(),
                TableLevel::new(4).unwrap(),
                DomainId::new(7).unwrap(),
            )
        }
        .unwrap();
        let words = table.snapshot(requester).unwrap();
        assert_eq!(words, translated(requester as u8, root().value(), 4, 7));
        assert_eq!((words[0] & 8, words[1] & (1 << 32)), (0, 0));
        // SAFETY: the model requester is stopped, so blocking its table entry interrupts no
        // DMA.
        unsafe { table.block(requester) }.unwrap();
        assert_eq!(table.snapshot(requester).unwrap(), blocked(requester as u8));
    }
    retire(table, &monitor);
}

#[test]
fn initial_policy_is_literal_complete_immutable_and_guarded() {
    let monitor = Monitor::new();
    let mut flags = policies();
    let Some(mut table) = construct(&monitor, &flags) else {
        return;
    };
    flags.fill(0); // Caller storage is neither kept nor consulted later.
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
fn translation_updates_flush_aliases_and_old_domain() {
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
        // root/domain reservations kept through the modeled completion.
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
fn width_policy_and_unsupported_atomic_refuse_before_allocation() {
    for (flags, bits, expected) in [
        (
            policies(),
            31,
            DeviceTableError::Format(FormatError::PhysicalWidth),
        ),
        (vec![0; REQUESTERS - 1], 48, DeviceTableError::PolicyCount),
    ] {
        let monitor = Monitor::new();
        assert!(
            // SAFETY: malformed numeric/profile admission is rejected before effects.
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
        assert!(
            // SAFETY: isolated unsuitable provider output; no live base.
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
fn native_eight_k_larger_granules_and_distinct_fresh_allocations_are_kept() {
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
                assert_eq!(
                    // SAFETY: the original larger native pin is fully kept. Its unused tail
                    // must not receive DTE initialization stores.
                    unsafe { (cpu as *const u8).add(offset).cast::<u64>().read_volatile() },
                    0
                );
            }
            assert!(monitor.model.lock().unwrap().events.iter().all(
                |event| !matches!(event, Event::Publish(bytes, _) if *bytes != DEVICE_TABLE_BYTES)
            ));
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
    assert_eq!(
        // SAFETY: fixture owns stopped requester; context refusal precedes CPU stores.
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
        assert_eq!(
            // SAFETY: only unsuitable new numeric root metadata is being tested; it must be
            // rejected before entering the mutation-capable context.
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
    assert_eq!(
        // SAFETY: the stopped fixture exercises malformed-old-profile refusal; no store or
        // visibility/invalidation may run under the unknown image.
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
        // SAFETY: stopped symbolic requester, kept roots/domains.
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
        // Poisoned reads remain useful under the context guard.
        assert_eq!(table.snapshot(0xffff), Ok(blocked(0xc7)));
        let before = monitor.model.lock().unwrap().events.len();
        assert_eq!(
            // SAFETY: only poisoned-owner refusal; no second store may happen.
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
            assert!(
                // SAFETY: the new table is unreachable by any modeled remapper.
                catch_unwind(AssertUnwindSafe(|| unsafe {
                    DeviceTable::new(Hardware(monitor.clone()), &policies(), 48)
                }))
                .is_err()
            );
        } else {
            assert!(matches!(
                // SAFETY: initial visibility fails before a base image escapes.
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
    // One deliberate complete 2MiB leak proves quarantine. Do not
    // reclaim bytes behind the forgotten pin/context owners.
    drop(table);
    assert!(quarantined_tables() >= before.saturating_add(1));
    assert_eq!(monitor.live_pins(), 1);
    assert_eq!(monitor.released_bytes.load(Ordering::Relaxed), 0);
    assert_eq!(monitor.released_pins.load(Ordering::Relaxed), 0);
    assert_eq!(monitor.hardware_drops.load(Ordering::Relaxed), 0);
}
