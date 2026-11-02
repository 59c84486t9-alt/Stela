//! CPU-only original-C-ABI integration model; never maps hardware or a PA cast.
use std::{
    cell::UnsafeCell,
    ffi::c_void,
    pin::Pin,
    ptr::{self, NonNull},
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use stela_driver_base::bus::mmio::owned::{
    AddressSpace, Authority, CacheAttribute, Error as MappingError, ExistingAlias,
    InstalledMapping, MapFailure, MapRequest, MappingPlatform, PhysicalSpan, Protection, Resource,
    ResourceBacking, ResourceKind,
};
use stela_driver_gpu::nvidia::mmio::{Error, MmioServices};

const PAGE: u64 = 4096;
const BASE: u64 = 0x800000;
const PREFETCH: u64 = 0x900000;
const PARTIAL: u64 = 0xa00000;
const SPACE: AddressSpace = AddressSpace {
    identity: 31,
    physical_bits: 48,
    virtual_bits: 48,
};

unsafe extern "C" {
    fn os_map_kernel_space(physical: u64, bytes: u64, mode: u32) -> *mut c_void;
    fn os_unmap_kernel_space(address: *mut c_void, bytes: u64);
}

#[repr(align(4096))]
struct Pages([u8; 65536]);
struct Window(UnsafeCell<Pages>);
// SAFETY: model memory is accessed only as raw bytes while an exclusive mapping
// lease is live. Mutex-protected model bookkeeping does not create references
// to mapped bytes. The test drains all uses before acknowledged unmap.
unsafe impl Send for Window {}
// SAFETY: shared references rely on the same argument as `Send` above.
unsafe impl Sync for Window {}
struct Backing {
    span: PhysicalSpan,
    kind: ResourceKind,
    window: Arc<Window>,
    dropped: Arc<AtomicUsize>,
    mapping: stela_driver_base::bus::mmio::owned::model::MappingRetention<(
        Arc<Window>,
        Arc<AtomicBool>,
    )>,
}
fn mapping_context(
    pin: &(Arc<Window>, Arc<AtomicBool>),
) -> Result<(), stela_driver_base::bus::pci::assignment::Error> {
    if pin.1.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(stela_driver_base::bus::pci::assignment::Error::Context)
    }
}
// SAFETY: each immutable model reservation owns a distinct aligned allocation
// and isolated physical interval. There is no firmware, physical map or device.
unsafe impl ResourceBacking for Backing {
    fn begin_mapping(
        &self,
    ) -> Result<stela_driver_base::bus::pci::assignment::OpaqueUse, MappingError> {
        self.mapping.begin_mapping()
    }
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    fn kind(&self) -> ResourceKind {
        self.kind
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Normal,
    Unchanged,
    Uncertain,
    WrongCache,
    RefuseWc,
}
struct Installed {
    request: MapRequest,
    cpu: usize,
    window: Arc<Window>,
}
struct State {
    installed: Vec<Installed>,
    mode: Mode,
    calls: usize,
    unmaps: usize,
    ack: bool,
    busy_unmap: bool,
    reenter: Option<(u64, usize, u64)>,
    map_gates: Option<(Arc<Barrier>, Arc<Barrier>)>,
}
struct Model {
    state: Mutex<State>,
    allowed: Arc<AtomicBool>,
}
impl Model {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                installed: Vec::new(),
                mode: Mode::Normal,
                calls: 0,
                unmaps: 0,
                ack: true,
                busy_unmap: false,
                reenter: None,
                map_gates: None,
            }),
            allowed: Arc::new(AtomicBool::new(true)),
        })
    }
    fn calls(&self) -> (usize, usize, usize) {
        let state = self.state.lock().unwrap();
        (state.calls, state.unmaps, state.installed.len())
    }
    fn mode(&self, mode: Mode) {
        self.state.lock().unwrap().mode = mode;
    }
    fn reenter(&self) {
        let reenter = self.state.lock().unwrap().reenter.take();
        if let Some((physical, address, bytes)) = reenter {
            // SAFETY: model native callback reentry while the
            // adapter's entry guard is held; neither nested call may act.
            unsafe {
                assert!(os_map_kernel_space(physical, bytes, 1).is_null());
                os_unmap_kernel_space(address as *mut c_void, bytes);
            }
        }
    }
}
// SAFETY: model maps kept allocations, never physical addresses as
// pointers. It preserves the request and exact aligned CPU range through ack.
// Fault modes return malformed/uncertain replies for refusal tests.
unsafe impl MappingPlatform for Model {
    fn check_context(&self, space: AddressSpace) -> Result<(), MappingError> {
        if space == SPACE && self.allowed.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(MappingError::Unavailable)
        }
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        let backing = resource.backing().downcast_ref::<Backing>().unwrap();
        assert_eq!(request.address_space, SPACE);
        assert_eq!(request.physical.start() % PAGE, 0);
        assert_eq!(request.physical.bytes() % PAGE, 0);
        assert!(request.physical.start() >= backing.span.start());
        assert!(request.physical.end() <= backing.span.end());
        assert_eq!(request.protection, Protection::ReadWrite);
        let (mode, gates) = {
            let mut state = self.state.lock().unwrap();
            state.calls += 1;
            (state.mode, state.map_gates.take())
        };
        self.reenter();
        if mode == Mode::Unchanged {
            return Err(MapFailure::Unchanged(MappingError::MappingFailed));
        }
        if mode == Mode::RefuseWc && request.attribute == CacheAttribute::WriteCombining {
            return Err(MapFailure::Unchanged(MappingError::UnsupportedCache));
        }
        let offset = (request.physical.start() - backing.span.start()) as usize;
        // SAFETY: pinned model allocation, full request bounds checked
        // against its immutable physical reservation; never derive VA from PA.
        let cpu = unsafe {
            ptr::addr_of_mut!((*backing.window.0.get()).0)
                .cast::<u8>()
                .add(offset)
        };
        let reply = InstalledMapping {
            token: request.id,
            cpu_base: NonNull::new(cpu).unwrap(),
            physical: request.physical,
            attribute: if mode == Mode::WrongCache {
                CacheAttribute::WriteBack
            } else {
                request.attribute
            },
            protection: request.protection,
        };
        self.state.lock().unwrap().installed.push(Installed {
            request,
            cpu: cpu as usize,
            window: Arc::clone(&backing.window),
        });
        if let Some((ready, release)) = gates {
            ready.wait();
            release.wait();
        }
        if mode == Mode::Uncertain {
            return Err(MapFailure::Uncertain(MappingError::MappingFailed));
        }
        Ok(reply)
    }
    unsafe fn unmap(
        &self,
        request: MapRequest,
        mapping: InstalledMapping,
    ) -> Result<(), MappingError> {
        {
            let mut state = self.state.lock().unwrap();
            state.unmaps += 1;
            let live = state
                .installed
                .iter()
                .find(|live| live.request == request)
                .unwrap();
            assert_eq!(mapping.token, request.id);
            assert_eq!(mapping.cpu_base.as_ptr() as usize, live.cpu);
            assert_eq!(mapping.physical, request.physical);
            assert_eq!(mapping.attribute, request.attribute);
            assert_eq!(mapping.protection, request.protection);
            assert!(Arc::strong_count(&live.window) >= 2);
        }
        self.reenter();
        let mut state = self.state.lock().unwrap();
        if state.busy_unmap {
            return Err(MappingError::Busy);
        }
        if !state.ack {
            return Err(MappingError::UnmapFailed);
        }
        let at = state
            .installed
            .iter()
            .position(|live| live.request == request)
            .unwrap();
        state.installed.swap_remove(at);
        Ok(()) // model all-root TLB/write drain acknowledgement
    }
}

type MappingControl =
    stela_driver_base::bus::mmio::owned::model::MappingOwner<(Arc<Window>, Arc<AtomicBool>)>;
fn resource(
    start: u64,
    bytes: u64,
    kind: ResourceKind,
    guard: &Arc<AtomicBool>,
) -> (Resource, Arc<AtomicUsize>, MappingControl) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let window = Arc::new(Window(UnsafeCell::new(Pages([0; 65536]))));
    // SAFETY: the SAME real allocated model RAM and original isolated guard;
    // neither owns a Resource, Authority, Source or mapping/control callback.
    let mapping = unsafe {
        stela_driver_base::bus::mmio::owned::model::MappingOwner::from_owned(
            (window.clone(), guard.clone()),
            mapping_context,
        )
    };
    (
        Resource::new(Box::new(Backing {
            span: PhysicalSpan::new(start, bytes).unwrap(),
            kind,
            window,
            mapping: mapping.retention().unwrap(),
            dropped: Arc::clone(&dropped),
        })),
        dropped,
        mapping,
    )
}

fn rejected(
    services: &Pin<Box<MmioServices>>,
    model: &Model,
    physical: u64,
    bytes: u64,
    mode: u32,
    expected: MappingError,
    provider_called: bool,
) {
    let before = services.status();
    let calls = model.calls();
    // SAFETY: installed service/model, serialized process-context call.
    assert!(unsafe { os_map_kernel_space(physical, bytes, mode) }.is_null());
    assert_eq!(services.status().live, before.live);
    assert_eq!(services.status().failed_maps, before.failed_maps + 1);
    assert_eq!(
        services.status().last_failure,
        Some(Error::Mapping(expected))
    );
    assert_eq!(model.calls().0, calls.0 + usize::from(provider_called));
}

#[test]
fn original_global_abi_keeps_real_canonical_leases_and_quarantines_failures() {
    // Separate integration process preserves canonical production singleton.
    // SAFETY: no installed services; hooks must refuse without a provider call.
    unsafe {
        assert!(os_map_kernel_space(BASE, PAGE, 1).is_null());
        os_unmap_kernel_space(ptr::null_mut(), PAGE);
    }
    let model = Model::new();
    // SAFETY: isolated CPU model machine, complete alias inventory, genuine
    // backing and explicit all-root/cache/context acknowledgements.
    let authority = unsafe {
        Authority::activate(
            model.clone(),
            SPACE,
            vec![
                ExistingAlias {
                    physical: PhysicalSpan::new(BASE + 4 * PAGE, PAGE).unwrap(),
                    attribute: Some(CacheAttribute::WriteBack),
                },
                ExistingAlias {
                    physical: PhysicalSpan::new(BASE + 5 * PAGE, PAGE).unwrap(),
                    attribute: None,
                },
                ExistingAlias {
                    physical: PhysicalSpan::new(BASE + 6 * PAGE, PAGE).unwrap(),
                    attribute: Some(CacheAttribute::Uncached),
                },
            ],
        )
    }
    .unwrap();
    let (registers, register_drop, mut register_control) =
        resource(BASE, 16 * PAGE, ResourceKind::Registers, &model.allowed);
    let register_id = authority.register_resource(registers.clone()).unwrap();
    let (prefetch, prefetch_drop, mut prefetch_control) = resource(
        PREFETCH,
        16 * PAGE,
        ResourceKind::PrefetchableMemory,
        &model.allowed,
    );
    let prefetch_id = authority.register_resource(prefetch).unwrap();
    let (partial, partial_drop, mut partial_control) = resource(
        PARTIAL + 1,
        PAGE - 2,
        ResourceKind::Registers,
        &model.allowed,
    );
    let partial_id = authority.register_resource(partial).unwrap();
    let mut services = Box::pin(MmioServices::new(authority.clone()));
    let mut second = Box::pin(MmioServices::new(authority.clone()));
    // SAFETY: pinned services remain alive, serial callbacks in this one test;
    // all raw consumers stop before exact unmap and successful uninstall.
    unsafe {
        services.as_mut().install().unwrap();
        assert_eq!(second.as_mut().install(), Err(Error::AlreadyInstalled));
        assert_eq!(second.as_mut().uninstall(), Err(Error::NotInstalled));
    }
    for (physical, bytes) in [(0, PAGE), (BASE, 0), (u64::MAX - 1, 4), (BASE, u64::MAX)] {
        rejected(
            &services,
            &model,
            physical,
            bytes,
            1,
            MappingError::InvalidRange,
            false,
        );
    }
    for mode in [0, 3, 4, 5, 7, u32::MAX] {
        rejected(
            &services,
            &model,
            BASE,
            PAGE,
            mode,
            MappingError::UnsupportedCache,
            false,
        );
    }
    for (physical, bytes) in [
        (PARTIAL + 1, 1),
        (BASE - 1, 2),
        (BASE + 16 * PAGE - 1, 2),
        (0xb00000, PAGE),
        (BASE, (1u64 << 32) + PAGE),
    ] {
        rejected(
            &services,
            &model,
            physical,
            bytes,
            1,
            MappingError::OutsideResource,
            false,
        );
    }
    for page in [4, 5] {
        rejected(
            &services,
            &model,
            BASE + page * PAGE + 1,
            1,
            1,
            MappingError::CacheConflict,
            false,
        );
    }
    rejected(
        &services,
        &model,
        BASE,
        PAGE,
        2,
        MappingError::UnsupportedCache,
        false,
    );
    model.allowed.store(false, Ordering::Release);
    rejected(
        &services,
        &model,
        BASE,
        PAGE,
        1,
        MappingError::Unavailable,
        false,
    );
    model.allowed.store(true, Ordering::Release);

    // Unaligned logical bytes map only owned rounded pages, preserving offset.
    // SAFETY: model storage remains mapped and exclusively raw-accessed.
    let address = unsafe { os_map_kernel_space(BASE + 17, 100, 1) };
    assert!(!address.is_null());
    let actual = registers.backing().downcast_ref::<Backing>().unwrap();
    assert_eq!(
        address.cast::<u8>(),
        actual.window.0.get().cast::<u8>().wrapping_add(17)
    );
    // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and nothing
    // accesses it concurrently.
    unsafe {
        address.cast::<u8>().write_volatile(0x19);
        address.cast::<u8>().add(99).write_volatile(0xe7);
        assert_eq!(address.cast::<u8>().read_volatile(), 0x19);
        assert_eq!(address.cast::<u8>().add(99).read_volatile(), 0xe7);
    }
    assert_eq!(
        model.state.lock().unwrap().installed[0].request.physical,
        PhysicalSpan::new(BASE, PAGE).unwrap()
    );
    assert_eq!(services.status().live, 1);
    assert_eq!(
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { services.as_mut().uninstall() },
        Err(Error::LiveMappings)
    );
    rejected(
        &services,
        &model,
        BASE + 1,
        1,
        1,
        MappingError::ResourceConflict,
        false,
    );
    let calls = model.calls();
    for (pointer, bytes) in [
        (address, 99),
        (address.wrapping_byte_add(1), 100),
        (ptr::null_mut(), 0),
    ] {
        // SAFETY: invalid keys are never dereferenced or allowed to retire.
        unsafe { os_unmap_kernel_space(pointer, bytes) };
        assert_eq!(services.status().live, 1);
        assert_eq!(services.status().last_failure, Some(Error::UnknownMapping));
        assert_eq!(model.calls(), calls);
    }
    // Default is original UC, including a compatible imported raw UC alias.
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    let default = unsafe { os_map_kernel_space(BASE + 6 * PAGE, PAGE, 6) };
    assert!(!default.is_null());
    assert_eq!(
        model.state.lock().unwrap().installed[1].request.attribute,
        CacheAttribute::Uncached
    );
    model.state.lock().unwrap().reenter = Some((BASE + 2 * PAGE, address as usize, 100));
    let refused = services.status().refused_calls;
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    let third = unsafe { os_map_kernel_space(BASE + PAGE, PAGE, 1) };
    assert!(!third.is_null());
    assert_eq!(services.status().refused_calls, refused + 2);
    assert_eq!(services.status().live, 3);
    model.state.lock().unwrap().reenter = Some((BASE + 2 * PAGE, address as usize, 100));
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(third, PAGE) };
    assert_eq!(services.status().refused_calls, refused + 4);
    assert_eq!(services.status().live, 2);
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe {
        os_unmap_kernel_space(default, PAGE);
        os_unmap_kernel_space(address, 100);
    }
    assert_eq!(model.calls().2, 0);
    assert_eq!(services.status().live, 0);
    let calls = model.calls();
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(address, 100) };
    assert_eq!(services.status().last_failure, Some(Error::UnknownMapping));
    assert_eq!(model.calls(), calls);

    model.mode(Mode::RefuseWc);
    rejected(
        &services,
        &model,
        PREFETCH,
        PAGE,
        2,
        MappingError::UnsupportedCache,
        true,
    );
    model.mode(Mode::Normal);
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    let wc = unsafe { os_map_kernel_space(PREFETCH, PAGE, 2) };
    assert!(!wc.is_null());
    assert_eq!(
        model.state.lock().unwrap().installed[0].request.attribute,
        CacheAttribute::WriteCombining
    );
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(wc, PAGE) };
    model.mode(Mode::Unchanged);
    rejected(
        &services,
        &model,
        BASE + 7 * PAGE,
        PAGE,
        1,
        MappingError::MappingFailed,
        true,
    );
    assert_eq!(services.authority_status().unwrap().uncertain, 0);
    model.mode(Mode::Normal);
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    let restored = unsafe { os_map_kernel_space(BASE + 7 * PAGE, PAGE, 1) };
    assert!(!restored.is_null());
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(restored, PAGE) };

    // A canonical independent view keeps its backing alive; NVIDIA gets
    // no alternate permission, widened pointer or safe Rust reference to it.
    let mut parent = authority
        .map_physical(
            PhysicalSpan::new(BASE + 8 * PAGE, PAGE).unwrap(),
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    let view = parent.view(17..117).unwrap();
    assert_eq!(view.bytes(), 100);
    // SAFETY: the model device is stopped and drained, so nothing still uses what this releases.
    assert_eq!(unsafe { parent.retire() }, Err(MappingError::Busy));
    drop(view);
    // SAFETY: the model device is stopped and drained, so nothing still uses what this releases.
    unsafe { parent.retire() }.unwrap();

    // Another real canonical consumer may have a platform map in flight.
    // Original void unmap ends raw access now, keeping the same ledger slot
    // and Mapping until the native owner reaches a true quiescent retry point.
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    let busy = unsafe { os_map_kernel_space(BASE + 12 * PAGE, PAGE, 1) };
    assert!(!busy.is_null());
    let ready = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    model.state.lock().unwrap().map_gates = Some((ready.clone(), release.clone()));
    let other_authority = authority.clone();
    let other = std::thread::spawn(move || {
        other_authority
            .map_physical(
                PhysicalSpan::new(PREFETCH + PAGE, PAGE).unwrap(),
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .unwrap()
    });
    ready.wait();
    let before = services.status();
    let calls = model.calls();
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(busy, PAGE) };
    assert_eq!(services.status().live, 0);
    assert_eq!(services.status().pending, 1);
    assert_eq!(
        services.status().busy_retirements,
        before.busy_retirements + 1
    );
    assert_eq!(services.status().failed_unmaps, before.failed_unmaps);
    assert_eq!(
        services.status().unmap_quarantines,
        before.unmap_quarantines
    );
    assert_eq!(services.authority_status().unwrap().quarantined, 0);
    assert_eq!(
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { services.as_mut().uninstall() },
        Err(Error::LiveMappings)
    );
    for _ in 0..3 {
        assert_eq!(
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            unsafe { services.as_mut().drain_pending_retirements() },
            Err(Error::Mapping(MappingError::Busy))
        );
        assert_eq!(services.status().pending, 1);
        assert_eq!(model.calls(), calls); // no native unmap or new mapping
    }
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(busy, PAGE - 1) };
    assert_eq!(services.status().last_failure, Some(Error::UnknownMapping));
    assert_eq!(services.status().pending, 1);
    assert_eq!(model.calls(), calls);
    let before_duplicate = services.status();
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(busy, PAGE) };
    assert_eq!(services.status().last_failure, Some(Error::UnknownMapping));
    assert_eq!(services.status().pending, 1);
    assert_eq!(
        services.status().busy_retirements,
        before_duplicate.busy_retirements
    );
    assert_eq!(
        services.status().unmap_quarantines,
        before_duplicate.unmap_quarantines
    );
    assert_eq!(model.calls(), calls); // consumed raw-use key cannot retry
    release.wait();
    let mut other = other.join().unwrap();
    model.state.lock().unwrap().reenter = Some((BASE + 2 * PAGE, busy as usize, PAGE));
    let refused = services.status().refused_calls;
    assert_eq!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe { services.as_mut().drain_pending_retirements() },
        Ok(1)
    );
    assert_eq!(services.status().refused_calls, refused + 2);
    assert_eq!(services.status().pending, 0);
    assert_eq!(services.authority_status().unwrap().quarantined, 0);
    assert_eq!(model.calls().1, calls.1 + 1); // one acknowledged retire
    // SAFETY: the model device is stopped and drained, so nothing still uses what this releases.
    unsafe { other.retire() }.unwrap();

    // Busy returned AFTER entering native unmap makes canonical state uncertain.
    // Do not infer that Busy means unchanged: keep/block access and retry the
    // exact token. The model verifies the same token/request on every attempt.
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    let busy = unsafe { os_map_kernel_space(BASE + 13 * PAGE, PAGE, 1) };
    assert!(!busy.is_null());
    let before = services.status();
    let calls = model.calls();
    model.state.lock().unwrap().busy_unmap = true;
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(busy, PAGE) };
    assert_eq!(services.status().pending, 1);
    assert_eq!(services.status().live, 0);
    assert_eq!(services.authority_status().unwrap().uncertain, 1);
    assert_eq!(services.authority_status().unwrap().quarantined, 0);
    assert_eq!(model.calls().1, calls.1 + 1);
    let duplicate_calls = model.calls();
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(busy, PAGE) };
    assert_eq!(services.status().last_failure, Some(Error::UnknownMapping));
    assert_eq!(services.status().pending, 1);
    assert_eq!(services.authority_status().unwrap().uncertain, 1);
    assert_eq!(model.calls(), duplicate_calls); // owner drain is sole retry seam
    assert_eq!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe { services.as_mut().drain_pending_retirements() },
        Err(Error::Mapping(MappingError::Busy))
    );
    assert_eq!(model.calls().1, calls.1 + 2);
    assert_eq!(services.authority_status().unwrap().uncertain, 1);
    rejected(
        &services,
        &model,
        BASE + 13 * PAGE,
        PAGE,
        1,
        MappingError::ResourceConflict,
        false,
    );
    model.state.lock().unwrap().busy_unmap = false;
    assert_eq!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe { services.as_mut().drain_pending_retirements() },
        Ok(1)
    );
    assert_eq!(
        services.status().busy_retirements,
        before.busy_retirements + 2
    );
    assert_eq!(services.status().failed_unmaps, before.failed_unmaps + 1); // duplicate key only
    assert_eq!(
        services.status().unmap_quarantines,
        before.unmap_quarantines
    );
    assert_eq!(services.status().pending, 0);
    assert_eq!(services.authority_status().unwrap().uncertain, 0);
    assert_eq!(model.calls().1, calls.1 + 3);
    assert_eq!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe { services.as_mut().drain_pending_retirements() },
        Ok(0)
    );

    // Failed retirement consumes the void native ABI into canonical
    // quarantine. The provider's allocation/token and resource stay held.
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    let failed = unsafe { os_map_kernel_space(BASE + 9 * PAGE, PAGE, 1) };
    assert!(!failed.is_null());
    model.state.lock().unwrap().ack = false;
    let before = services.status();
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(failed, PAGE) };
    assert_eq!(services.status().live, 0);
    assert_eq!(services.status().failed_unmaps, before.failed_unmaps + 1);
    assert_eq!(
        services.status().unmap_quarantines,
        before.unmap_quarantines + 1
    );
    assert_eq!(
        services.status().last_failure,
        Some(Error::Mapping(MappingError::UnmapFailed))
    );
    assert_eq!(services.authority_status().unwrap().quarantined, 1);
    assert_eq!(model.calls().2, 1);
    assert_eq!(
        authority.unregister_resource(register_id),
        Err(MappingError::Busy)
    );
    let calls = model.calls();
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe { os_unmap_kernel_space(failed, PAGE) };
    assert_eq!(model.calls(), calls); // no guessed retry/double unmap
    model.state.lock().unwrap().ack = true;
    rejected(
        &services,
        &model,
        BASE + 9 * PAGE,
        PAGE,
        1,
        MappingError::ResourceConflict,
        false,
    );

    model.mode(Mode::Uncertain);
    rejected(
        &services,
        &model,
        BASE + 10 * PAGE,
        PAGE,
        1,
        MappingError::MappingFailed,
        true,
    );
    assert_eq!(services.authority_status().unwrap().quarantined, 2);
    model.mode(Mode::WrongCache);
    rejected(
        &services,
        &model,
        BASE + 11 * PAGE,
        PAGE,
        1,
        MappingError::InvalidPlatformReply,
        true,
    );
    assert_eq!(services.authority_status().unwrap().quarantined, 3);
    assert_eq!(model.calls().2, 3);

    // SAFETY: the model device is stopped and drained, so nothing still uses what this releases.
    unsafe { services.as_mut().uninstall() }.unwrap();
    assert_eq!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe { services.as_mut().drain_pending_retirements() },
        Err(Error::NotInstalled)
    );
    assert_eq!(
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { services.as_mut().uninstall() },
        Err(Error::NotInstalled)
    );
    let calls = model.calls();
    // SAFETY: the installed test services own the model BAR and refuse any address or length they
    // did not map.
    unsafe {
        assert!(os_map_kernel_space(PREFETCH, PAGE, 1).is_null());
        os_unmap_kernel_space(failed, PAGE);
    }
    assert_eq!(model.calls(), calls);
    drop(services);
    drop(registers);
    assert_eq!(register_drop.load(Ordering::Relaxed), 0);
    assert_eq!(
        authority.unregister_resource(register_id),
        Err(MappingError::Busy)
    );
    authority.unregister_resource(prefetch_id).unwrap();
    authority.unregister_resource(partial_id).unwrap();
    // SAFETY: these exact normal resources have no lookup, mapping/view or raw
    // C tail after acknowledged unmaps and service uninstall above. Controllers
    // stay outside their backings and return the same actual allocated Windows.
    unsafe { prefetch_control.retire() }.unwrap();
    // SAFETY: the partial resource never produced a pointer and lookup is gone.
    unsafe { partial_control.retire() }.unwrap();
    // The register resource still has real quarantined users. Deny admission
    // only; default source-control abandonment keeps its same actual allocation.
    register_control.abandon_admission();
    assert_eq!(prefetch_drop.load(Ordering::Relaxed), 1);
    assert_eq!(partial_drop.load(Ordering::Relaxed), 1);
    assert_eq!(authority.status().unwrap().quarantined, 3);
    assert_eq!(model.calls().2, 3);
}
