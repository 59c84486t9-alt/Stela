//! Canonical-owner model in a separate test process: one real Permission::activate
//! call, immutable synthetic PCI/resources and native C policy/ABI.
//! No physical GPU, page table, cache-policy or hardware activation is modeled
//! as completed by a production adapter.
extern crate alloc;
mod pci_tests;
use stela_driver_base::{Clock, bus};
use stela_driver_core::firmware;
use stela_driver_gpu::amd::{discovery, native_mmio, pci};

use bus::{
    mmio::owned::{
        AddressSpace, Authority, CacheAttribute, Error as MmioError, InstalledMapping, MapFailure,
        MapRequest, MappingPlatform, PhysicalSpan, Protection, Resource, ResourceBacking,
        ResourceKind,
    },
    pci::{Address, ConfigSpace, Function},
};
use native_mmio::{AttachedBars, Error, KernelDoorbells, RegisterBar, Rollback, Stage};
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    cell::RefCell,
    collections::BTreeMap,
    ptr::NonNull,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

#[link(name = "stela-amd-test-fixtures", kind = "static")]
unsafe extern "C" {
    fn stela_amd_test_asic(which: u32) -> u32;
    fn stela_amd_test_discovery(binary: *mut u8, capacity: usize) -> usize;
}
/// CHIP_TAHITI, CHIP_BONAIRE, CHIP_VEGA10 and CHIP_IP_DISCOVERY, by index.
fn asic(which: u32) -> u32 {
    // SAFETY: a pure lookup of Linux's enum values.
    unsafe { stela_amd_test_asic(which) }
}
/// The fixture IP discovery binary that fixtures.h describes.
fn discovery_binary() -> Vec<u8> {
    let mut binary = vec![0; 4096];
    // SAFETY: a writable buffer of the stated capacity.
    let bytes = unsafe { stela_amd_test_discovery(binary.as_mut_ptr(), binary.len()) };
    assert_ne!(bytes, 0);
    binary.truncate(bytes);
    binary
}

/// Calibrated at one tick per microsecond, so on the real TSC each wait
/// expires within a fraction of a millisecond. An uncalibrated clock is
/// refused rather than expiring at once.
const CLOCK: Clock = Clock {
    ticks_per_microsecond: 1,
};

struct Config;
impl ConfigSpace for Config {
    fn read32(&self, offset: u16) -> Result<u32, bus::pci::ConfigError> {
        Ok(match offset {
            0 => 0x1234_1002,
            8 => 0x1200_0000, // Original matching is not restricted to display inventory.
            _ => panic!("resource attachment must not probe or activate hardware"),
        })
    }
    fn write32(&mut self, _: u16, _: u32) -> Result<(), bus::pci::ConfigError> {
        panic!("no PCI writes")
    }
    fn write16(&mut self, _: u16, _: u16) -> Result<(), bus::pci::ConfigError> {
        panic!("no PCI writes")
    }
    fn write8(&mut self, _: u16, _: u8) -> Result<(), bus::pci::ConfigError> {
        panic!("no PCI writes")
    }

    fn read8(&self, offset: u16) -> Result<u8, bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> (8 * (offset & 3))) as u8)
    }

    fn read16(&self, offset: u16) -> Result<u16, bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> (8 * (offset & 2))) as u16)
    }
}
fn function() -> Function<Config> {
    Function::new(
        Address {
            segment: 0,
            bus: 1,
            device: 0,
            function: 0,
        },
        Config,
    )
    .unwrap()
}

struct Backing {
    span: PhysicalSpan,
    kind: ResourceKind,
    drops: Arc<AtomicUsize>,
    mapping: bus::mmio::owned::model::MappingRetention<Arc<Model>>,
}
fn mapping_context(pool: &Arc<Model>) -> Result<(), bus::pci::assignment::Error> {
    if !pool.0.is_poisoned() {
        Ok(())
    } else {
        Err(bus::pci::assignment::Error::Context)
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: test-only exclusive immutable synthetic resource, kept by the
// canonical owner. It neither stands in for physical ownership nor drives a GPU.
unsafe impl ResourceBacking for Backing {
    fn begin_mapping(&self) -> Result<bus::pci::assignment::OpaqueUse, MmioError> {
        self.mapping.begin_mapping()
    }
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    fn kind(&self) -> ResourceKind {
        self.kind
    }
}
fn resource(
    base: u64,
    bytes: u64,
    kind: ResourceKind,
    model: &Fixture,
) -> (Resource, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    // SAFETY: this SAME actual pool owns allocated CPU buffers/tokens and the
    // original synchronized model guard. It contains no Authority/Resource/view,
    // Source, native control or callback backedge; labels grant no custody.
    let mapping = unsafe {
        bus::mmio::owned::model::MappingOwner::from_owned(model.pool.clone(), mapping_context)
    };
    let retained = mapping.retention().unwrap();
    model.controls.borrow_mut().push(mapping);
    let result = Resource::new(Box::new(Backing {
        span: PhysicalSpan::new(base, bytes).unwrap(),
        kind,
        drops: Arc::clone(&drops),
        mapping: retained,
    }));
    (result, drops)
}
fn registers(base: u64, bar: u8, model: &Fixture) -> RegisterBar {
    RegisterBar {
        index: bar,
        resource: resource(base, 16384, ResourceKind::Registers, model).0,
    }
}
fn doors(base: u64, modern: bool, model: &Fixture) -> KernelDoorbells {
    KernelDoorbells {
        index: 2,
        resource: resource(base, 65536, ResourceKind::PrefetchableMemory, model).0,
        offset: 4096,
        reserved_bytes: if modern { 16384 } else { 8192 },
        logical_dwords: if modern { 3072 } else { 2048 },
        max_assignment: 1023,
    }
}

struct Allocation {
    address: usize,
    bytes: usize,
}
#[derive(Default)]
struct ModelState {
    calls: usize,
    unmaps: usize,
    fail_map: usize,
    fail_uncertain: bool,
    fail_unmaps: usize,
    next_token: u64,
    allocations: BTreeMap<u64, Allocation>,
    requests: Vec<MapRequest>,
}
#[derive(Default)]
struct Model(Mutex<ModelState>);
// Affine source controls are outside the mapping provider and all backings.
// The actual pool contains no reference to this fixture, so no retention cycle.
struct Fixture {
    pool: Arc<Model>,
    controls: RefCell<Vec<bus::mmio::owned::model::MappingOwner<Arc<Model>>>>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            pool: Arc::new(Model::default()),
            controls: RefCell::new(Vec::new()),
        }
    }
}
impl core::ops::Deref for Fixture {
    type Target = Arc<Model>;
    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for owner in self.controls.get_mut() {
            // SAFETY: this source fixture drops after test consumers/locals.
            // Acknowledged mappings freed their actual allocations; never-mapped
            // reservations exposed no pointer. Real quarantine/retention users
            // make this same owner's retirement refuse, never certify cleanup.
            if let Err(error) = unsafe { owner.retire() } {
                owner.record_retention(error);
            }
        }
    }
}
// SAFETY: isolated CPU model. Its own aligned allocation is exact and kept
// through acknowledged unmap or the canonical quarantine. No native root/cache
// implementation is claimed; production requires the mount provider.
unsafe impl MappingPlatform for Model {
    fn check_context(&self, _: AddressSpace) -> Result<(), MmioError> {
        Ok(())
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        assert_eq!(request.attribute, CacheAttribute::Uncached);
        assert_eq!(request.protection, Protection::ReadWrite);
        assert!(request.physical.start() >= resource.physical_span().start());
        assert!(request.physical.end() <= resource.physical_span().end());
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        state.requests.push(request);
        let failing = state.calls == state.fail_map;
        if failing && !state.fail_uncertain {
            return Err(MapFailure::Unchanged(MmioError::MappingFailed));
        }
        let bytes = usize::try_from(request.physical.bytes()).unwrap();
        let layout = Layout::from_size_align(bytes, 4096).unwrap();
        // SAFETY: nonempty checked model allocation, kept below.
        let address = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        state.next_token += 1;
        let token = state.next_token;
        state.allocations.insert(
            token,
            Allocation {
                address: address.as_ptr() as usize,
                bytes,
            },
        );
        if failing {
            return Err(MapFailure::Uncertain(MmioError::MappingFailed));
        }
        Ok(InstalledMapping {
            token,
            cpu_base: address,
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(
        &self,
        request: MapRequest,
        mapping: InstalledMapping,
    ) -> Result<(), MmioError> {
        let mut state = self.0.lock().unwrap();
        state.unmaps += 1;
        assert_eq!(request.physical, mapping.physical);
        if state.fail_unmaps != 0 {
            state.fail_unmaps -= 1;
            return Err(MmioError::UnmapFailed);
        }
        let allocation = state.allocations.remove(&mapping.token).unwrap();
        assert_eq!(allocation.address, mapping.cpu_base.as_ptr() as usize);
        assert_eq!(allocation.bytes as u64, request.physical.bytes());
        // SAFETY: the caller's canonical model lease guarantees consumer drain;
        // this exact allocation/token has been removed once, before deallocation.
        unsafe {
            dealloc(
                allocation.address as *mut u8,
                Layout::from_size_align(allocation.bytes, 4096).unwrap(),
            )
        };
        Ok(())
    }
}

#[test]
fn canonical_amd_attachment() {
    let model = Fixture::new();
    // SAFETY: a single isolated CPU test process, complete empty model alias
    // inventory and one canonical permission. This does not activate real MMIO.
    let authority = unsafe {
        Authority::activate(
            model.pool.clone(),
            AddressSpace {
                identity: 1,
                physical_bits: 48,
                virtual_bits: 48,
            },
            Vec::new(),
        )
    }
    .unwrap();
    pci_tests::original_match(&authority, &model);
    let pci = function();

    // SI: original BAR2 and no manufactured doorbell allocation.
    // SAFETY: model function/enum/resources belong to this one isolated owner.
    let mut si = unsafe {
        AttachedBars::attach(
            &authority,
            &pci,
            asic(0),
            asic(0),
            registers(0x100000, 2, &model),
            None,
        )
    }
    .unwrap();
    // SAFETY: the model has no device; discovery is refused before access.
    let refused =
        unsafe { discovery::discover(&si, &CLOCK, &firmware::HandoffProvider::new(None)) };
    assert_eq!(
        refused.err(),
        Some(discovery::Error::Window(Error::AdmissionRequired))
    );
    assert_eq!(si.ip_path(), None);
    assert_eq!(si.identity().address, pci.address);
    assert_eq!(si.identity().device, pci.device);
    assert_eq!(si.identity().asic_type, asic(0));
    assert_eq!(si.identity().original_flags, asic(0));
    assert_eq!(si.register_physical_span().unwrap().start(), 0x100000);
    assert!(si.doorbells().unwrap().is_none());
    {
        let window = si.registers().unwrap();
        assert_eq!(window.bytes(), 16384);
        // SAFETY: pointer is only inspected and never kept outside borrow.
        let base = unsafe { window.native_base() }.unwrap().as_ptr() as usize;
        assert_eq!(window.direct_dword(0).unwrap().as_ptr() as usize, base);
        assert_eq!(
            window.direct_dword(4095).unwrap().as_ptr() as usize,
            base + 16380
        );
        assert_eq!(
            window.direct_dword(4096).unwrap_err(),
            Error::IndirectRegisterRequired
        );
        assert_eq!(
            window.direct_dword(u32::MAX).unwrap_err(),
            Error::IndirectRegisterRequired
        );
    }
    // SAFETY: model has no device/CPU/C consumer; all borrowed views ended.
    unsafe { si.retire() }.unwrap();
    assert_eq!(si.registers().err(), Some(Error::Retired));
    assert_eq!(authority.status().unwrap().live, 0);

    // Boot ordering: registers precede discovery and kernel doorbell BO
    // creation. Keep original C's register view while attaching doors later.
    // SAFETY: same immutable synthetic original match and kept resource.
    let mut staged = unsafe {
        AttachedBars::attach(
            &authority,
            &pci,
            asic(1),
            asic(1),
            registers(0x180000, 5, &model),
            None,
        )
    }
    .unwrap();
    let retained = staged.registers().unwrap();
    let pointer = retained.direct_dword(0).unwrap();
    assert!(staged.doorbells().unwrap().is_none());
    {
        let mut state = model.0.lock().unwrap();
        state.fail_map = state.calls + 1;
    }
    // SAFETY: test-only original BO owner, unchanged injected doorbell failure.
    let failed =
        unsafe { staged.attach_kernel_doorbells(&authority, doors(0x190000, false, &model)) }
            .unwrap_err();
    assert_eq!(failed.stage, Stage::Doorbells);
    assert_eq!(failed.rollback, Rollback::NotAttempted);
    assert_eq!(retained.direct_dword(0).unwrap(), pointer);
    assert!(staged.doorbells().unwrap().is_none());
    // SAFETY: same original owner retries reservation after unchanged failure.
    unsafe { staged.attach_kernel_doorbells(&authority, doors(0x190000, false, &model)) }.unwrap();
    assert_eq!(staged.doorbells().unwrap().unwrap().bytes(), 8192);
    assert_eq!(retained.direct_dword(0).unwrap(), pointer);
    let register_maps = model
        .0
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|r| r.physical.start() == 0x180000)
        .count();
    assert_eq!(register_maps, 1);
    let before = model.0.lock().unwrap().calls;
    assert!(
        // SAFETY: duplicate original reservation, rejected pre-map.
        unsafe { staged.attach_kernel_doorbells(&authority, doors(0x1a0000, false, &model)) }
            .is_err()
    );
    assert_eq!(model.0.lock().unwrap().calls, before);
    assert_eq!(
        // SAFETY: model accesses stopped, but kept C view still pins its lease.
        unsafe { staged.retire() },
        Err(Error::Mapping(MmioError::Busy))
    );
    drop(retained);
    // SAFETY: all original model views drained; retry removes exact register lease.
    unsafe { staged.retire() }.unwrap();
    assert_eq!(authority.status().unwrap().live, 0);

    // IP-discovery/Vega+ policy: logical extent includes paging+MES
    // pages, distinct from the larger reserved physical span.
    // SAFETY: the isolated model pins both original-role resources/reservation.
    let mut modern = unsafe {
        AttachedBars::attach(
            &authority,
            &pci,
            asic(3),
            asic(3),
            registers(0x200000, 5, &model),
            Some(doors(0x300000, true, &model)),
        )
    }
    .unwrap();
    {
        let window = modern.doorbells().unwrap().unwrap();
        assert_eq!(window.bytes(), 12288);
        assert!(window.dword(3071).is_ok());
        assert!(window.dword(3072).is_err());
        assert!(window.qword(3070).is_ok());
        assert!(window.qword(3071).is_err());
        assert!(window.qword(1).is_err());
        assert!(window.qword(u32::MAX).is_err());
        let requests = &model.0.lock().unwrap().requests;
        let door = requests.last().unwrap();
        assert_eq!(door.physical.start(), 0x301000);
        assert_eq!(door.physical.bytes(), 16384);
    }
    // Failed teardown blocks new views and keeps exact canonical token for
    // acknowledged retry rather than freeing or manufacturing completion.
    model.0.lock().unwrap().fail_unmaps = 1;
    assert_eq!(
        // SAFETY: no real consumers or active views in this model.
        unsafe { modern.retire() },
        Err(Error::Mapping(MmioError::UnmapFailed))
    );
    assert_eq!(modern.registers().err(), Some(Error::Retired));
    assert_eq!(modern.doorbells().err(), Some(Error::Retired));
    // SAFETY: original model drain still holds; retry targets kept token.
    unsafe { modern.retire() }.unwrap();
    assert_eq!(authority.status().unwrap().live, 0);

    let calls = model.0.lock().unwrap().calls;
    let malformed = [
        (4, asic(1), Some(doors(0x400000, false, &model))),
        (2, asic(0), Some(doors(0x400000, false, &model))),
        (5, u32::MAX, Some(doors(0x400000, false, &model))),
    ];
    for (bar, chip, door) in malformed {
        // SAFETY: invalid model facts, expected refusal pre-map.
        let error = unsafe {
            AttachedBars::attach(
                &authority,
                &pci,
                chip,
                chip,
                registers(0x500000, bar, &model),
                door,
            )
        }
        .err()
        .unwrap();
        assert_eq!(error.stage, Stage::Preflight);
        assert_eq!(error.rollback, Rollback::NotAttempted);
    }
    for which in 0..8 {
        let mut door = doors(0x600000, false, &model);
        match which {
            0 => door.offset += 1,
            1 => door.reserved_bytes -= 1,
            2 => door.logical_dwords += 1,
            3 => door.resource = resource(0x500000, 65536, ResourceKind::Registers, &model).0,
            4 => door.reserved_bytes = 4096,
            5 => door.index = 0,
            6 => door.offset = 65536,
            7 => door.reserved_bytes = usize::MAX,
            _ => unreachable!(),
        }
        assert!(
            // SAFETY: malformed isolated-owner input.
            unsafe {
                AttachedBars::attach(
                    &authority,
                    &pci,
                    asic(1),
                    asic(1),
                    registers(0x500000, 5, &model),
                    Some(door),
                )
            }
            .is_err()
        );
    }
    assert!(
        // SAFETY: unaligned backing fails complete-page ownership.
        unsafe {
            AttachedBars::attach(
                &authority,
                &pci,
                asic(0),
                asic(0),
                RegisterBar {
                    index: 2,
                    resource: resource(0x700001, 16384, ResourceKind::Registers, &model).0,
                },
                None,
            )
        }
        .is_err()
    );
    assert_eq!(model.0.lock().unwrap().calls, calls);

    // Failed second map rolls back the first unpublished window exactly once.
    model.0.lock().unwrap().fail_map = calls + 2;
    // SAFETY: isolated model ownership, platform injects unchanged error.
    let error = unsafe {
        AttachedBars::attach(
            &authority,
            &pci,
            asic(1),
            asic(1),
            registers(0x800000, 5, &model),
            Some(doors(0x900000, false, &model)),
        )
    }
    .err()
    .unwrap();
    assert_eq!(error.stage, Stage::Doorbells);
    assert_eq!(error.rollback, Rollback::Retired);
    assert_eq!(authority.status().unwrap().live, 0);

    // Failed rollback leaves that real model allocation/owner quarantined.
    {
        let mut state = model.0.lock().unwrap();
        state.fail_map = state.calls + 2;
        state.fail_unmaps = 1;
    }
    let (reg, reg_drops) = resource(0xa00000, 16384, ResourceKind::Registers, &model);
    let (door, door_drops) = resource(0xb00000, 65536, ResourceKind::Registers, &model);
    let mut kernel = doors(0xc00000, false, &model);
    kernel.resource = door;
    // SAFETY: owned model resources; failed unmap must preserve exact backing.
    let error = unsafe {
        AttachedBars::attach(
            &authority,
            &pci,
            asic(1),
            asic(1),
            RegisterBar {
                index: 5,
                resource: reg,
            },
            Some(kernel),
        )
    }
    .err()
    .unwrap();
    assert_eq!(
        error.rollback,
        Rollback::Quarantined(MmioError::UnmapFailed)
    );
    assert_eq!(reg_drops.load(Ordering::Relaxed), 0);
    assert_eq!(door_drops.load(Ordering::Relaxed), 1);
    assert_eq!(authority.status().unwrap().quarantined, 1);

    // A primary uncertain map failure has no returned window to roll back;
    // canonical ownership still quarantines its resource/allocation.
    {
        let mut state = model.0.lock().unwrap();
        state.fail_map = state.calls + 1;
        state.fail_uncertain = true;
    }
    let (reg, reg_drops) = resource(0xd00000, 16384, ResourceKind::Registers, &model);
    // SAFETY: isolated model returns an uncertain partial map.
    let error = unsafe {
        AttachedBars::attach(
            &authority,
            &pci,
            asic(0),
            asic(0),
            RegisterBar {
                index: 2,
                resource: reg,
            },
            None,
        )
    }
    .err()
    .unwrap();
    assert_eq!(error.stage, Stage::Registers);
    assert_eq!(error.rollback, Rollback::NotAttempted);
    assert_eq!(reg_drops.load(Ordering::Relaxed), 0);
    assert_eq!(authority.status().unwrap().quarantined, 2);
    // A late uncertain doorbell map cannot invalidate previously published
    // RMMIO. The canonical owner keeps only that uncertain doorbell backing.
    // SAFETY: separate model resources; no hardware consumers.
    let mut late = unsafe {
        AttachedBars::attach(
            &authority,
            &pci,
            asic(1),
            asic(1),
            registers(0xe00000, 5, &model),
            None,
        )
    }
    .unwrap();
    let retained = late.registers().unwrap();
    let pointer = retained.direct_dword(0).unwrap();
    let (reservation, drops) = resource(0xf00000, 65536, ResourceKind::Registers, &model);
    let mut kernel = doors(0xf00000, false, &model);
    kernel.resource = reservation;
    {
        let mut state = model.0.lock().unwrap();
        state.fail_map = state.calls + 1;
        state.fail_uncertain = true;
    }
    // SAFETY: the model injects uncertain mapping, requiring kept ownership.
    let failed = unsafe { late.attach_kernel_doorbells(&authority, kernel) }.unwrap_err();
    assert_eq!(failed.stage, Stage::Doorbells);
    assert_eq!(failed.rollback, Rollback::NotAttempted);
    assert_eq!(retained.direct_dword(0).unwrap(), pointer);
    assert!(late.doorbells().unwrap().is_none());
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(authority.status().unwrap().quarantined, 3);
    drop(retained);
    // SAFETY: published register view drained; unrelated quarantine stays pinned.
    unsafe { late.retire() }.unwrap();
    assert_eq!(authority.status().unwrap().live, 0);
    assert_eq!(drops.load(Ordering::Relaxed), 0);

    println!(
        "AMD native MMIO: original policy, canonical ownership/bounds/rollback/quarantine; no hardware"
    );
}
