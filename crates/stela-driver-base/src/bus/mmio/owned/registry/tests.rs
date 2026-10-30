extern crate std;
use super::*;
use alloc::{boxed::Box, vec};
use core::sync::atomic::AtomicUsize;
use std::sync::Mutex;

const BASE: u64 = 0x1000_0000;
const SPACE: AddressSpace = AddressSpace {
    identity: 7,
    physical_bits: 48,
    virtual_bits: 48,
};
#[repr(align(4096))]
struct Pages([u8; 16384]);
struct Backing {
    span: PhysicalSpan,
    kind: ResourceKind,
    dropped: Arc<AtomicUsize>,
    drop_context: Option<Authority>,
}
// SAFETY: isolated model physical inventory; each backing pins its one
// model resource. Metadata is immutable and no firmware exists.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    fn kind(&self) -> ResourceKind {
        self.kind
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        if let Some(authority) = &self.drop_context {
            assert!(
                authority.inner.lock().is_ok(),
                "resource released under inventory lock"
            );
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
struct Installed {
    id: u64,
    token: u64,
    request: MapRequest,
    memory: Box<Pages>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Normal,
    Unchanged,
    Uncertain,
    WrongCache,
    WrongSpan,
    NullToken,
    WrongProtection,
    Unaligned,
    Noncanonical,
    WrapVirtual,
    RefuseWc,
    DuplicateToken,
}
struct State {
    installed: Vec<Installed>,
    mode: Mode,
    calls: usize,
    ack: bool,
    reenter: Option<(Authority, Resource)>,
    events: Vec<&'static str>,
    reply_gates: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    unmap_gates: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    freeze_shared_allocations: bool,
}
struct Model {
    state: Mutex<State>,
    allowed: AtomicBool,
    dropped: Arc<AtomicUsize>,
}
impl Model {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                installed: Vec::new(),
                mode: Mode::Normal,
                calls: 0,
                ack: true,
                reenter: None,
                events: Vec::new(),
                reply_gates: None,
                unmap_gates: None,
                freeze_shared_allocations: false,
            }),
            allowed: AtomicBool::new(true),
            dropped: Arc::new(AtomicUsize::new(0)),
        })
    }
    fn mode(&self, mode: Mode) {
        self.state.lock().unwrap().mode = mode;
    }
    fn live(&self) -> usize {
        self.state.lock().unwrap().installed.len()
    }
    fn calls(&self) -> usize {
        self.state.lock().unwrap().calls
    }
}
impl Drop for Model {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: this models real separate CPU backing and physical inventory;
// operations keep Box storage until acknowledged unmap. Fault
// modes provide malformed metadata without dereferencing it.
unsafe impl MappingPlatform for Model {
    fn check_context(&self, space: AddressSpace) -> Result<(), Error> {
        if space == SPACE && self.allowed.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(Error::Unavailable)
        }
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        assert!(resource.backing().is::<Backing>());
        assert!(resource.physical_span().contains(request.physical));
        assert_eq!(request.address_space, SPACE);
        assert_ne!(request.id, 0);
        let reenter = {
            let mut state = self.state.lock().unwrap();
            state.calls += 1;
            state.events.push("reserve observed before map");
            if state.freeze_shared_allocations {
                metadata::allocation::budget(Some(0));
            }
            state.reenter.take()
        };
        if let Some((authority, resource)) = reenter {
            assert!(matches!(
                authority.map(
                    resource,
                    0,
                    1,
                    CacheAttribute::Uncached,
                    Protection::ReadWrite
                ),
                Err(Error::ResourceConflict)
            ));
            assert_eq!(authority.status().unwrap().installing, 1);
            assert!(matches!(
                // SAFETY: model attempts a conflicting outside alias before any table
                // publication; rejection must precede effects.
                unsafe {
                    authority.reserve_alias(ExistingAlias {
                        physical: request.physical,
                        attribute: Some(CacheAttribute::WriteBack),
                    })
                },
                Err(Error::CacheConflict)
            ));
        }
        let mut state = self.state.lock().unwrap();
        if state.mode == Mode::Unchanged {
            return Err(MapFailure::Unchanged(Error::MappingFailed));
        }
        if state.mode == Mode::RefuseWc && request.attribute == CacheAttribute::WriteCombining {
            return Err(MapFailure::Unchanged(Error::UnsupportedCache));
        }
        let mut memory = Box::new(Pages([0; 16384]));
        let pointer = NonNull::new(memory.0.as_mut_ptr()).unwrap();
        let mut result = InstalledMapping {
            token: request.id,
            cpu_base: pointer,
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        };
        state.installed.push(Installed {
            id: request.id,
            token: request.id,
            request,
            memory,
        });
        match state.mode {
            Mode::Uncertain => return Err(MapFailure::Uncertain(Error::MappingFailed)),
            Mode::WrongCache => result.attribute = CacheAttribute::WriteBack,
            Mode::WrongSpan => result.physical = PhysicalSpan::new(BASE + 4096, 4096).unwrap(),
            Mode::NullToken => result.token = 0,
            Mode::DuplicateToken => result.token = 1,
            Mode::WrongProtection => result.protection = Protection::ReadOnly,
            Mode::Unaligned => {
                result.cpu_base = NonNull::new(pointer.as_ptr().wrapping_add(1)).unwrap()
            }
            Mode::Noncanonical => {
                result.cpu_base = NonNull::new(0x0000_8000_0000_0000usize as *mut u8).unwrap()
            }
            Mode::WrapVirtual => {
                result.cpu_base = NonNull::new((usize::MAX - 4095) as *mut u8).unwrap()
            }
            _ => {}
        }
        state.installed.last_mut().unwrap().token = result.token;
        let gates = state.reply_gates.clone();
        drop(state);
        if let Some((ready, release)) = gates {
            ready.wait();
            release.wait();
        }
        Ok(result)
    }
    unsafe fn unmap(&self, request: MapRequest, mapping: InstalledMapping) -> Result<(), Error> {
        let mut state = self.state.lock().unwrap();
        let at = state
            .installed
            .iter()
            .position(|installed| installed.token == mapping.token && installed.id == request.id)
            .unwrap();
        assert_eq!(state.installed[at].request, request);
        assert_eq!(
            state.installed[at].memory.0.as_ptr() as usize,
            mapping.cpu_base.as_ptr() as usize
        );
        state.events.push("unmap requested");
        if !state.ack {
            return Err(Error::UnmapFailed);
        }
        let gates = state.unmap_gates.clone();
        drop(state);
        if let Some((ready, release)) = gates {
            ready.wait();
            release.wait();
        }
        let mut state = self.state.lock().unwrap();
        if !state.ack {
            return Err(Error::UnmapFailed);
        }
        let at = state
            .installed
            .iter()
            .position(|installed| installed.token == mapping.token && installed.id == request.id)
            .unwrap();
        state.events.push("all root TLB and WC drain acknowledged");
        state.installed.swap_remove(at);
        Ok(())
    }
}
fn make_resource(span: PhysicalSpan, kind: ResourceKind) -> (Resource, Arc<AtomicUsize>) {
    let dropped = Arc::new(AtomicUsize::new(0));
    (
        Resource::new(Box::new(Backing {
            span,
            kind,
            dropped: Arc::clone(&dropped),
            drop_context: None,
        })),
        dropped,
    )
}
// SAFETY: unit fixtures represent independent simulated native machines,
// not a second permission in any production address space. This private
// helper is cfg(test) only and never bypasses the production activation.
unsafe fn fixture(model: Arc<Model>, aliases: Vec<ExistingAlias>) -> Authority {
    Authority::prepare(model, SPACE, aliases).unwrap()
}
fn basic() -> (Arc<Model>, Authority, Resource, Arc<AtomicUsize>) {
    let model = Model::new();
    // SAFETY: isolated model machine/root set, no outside mappings.
    let authority = unsafe { fixture(Arc::clone(&model), Vec::new()) };
    let (resource, dropped) = make_resource(
        PhysicalSpan::new(BASE, 16384).unwrap(),
        ResourceKind::Registers,
    );
    (model, authority, resource, dropped)
}
fn map(authority: &Authority, resource: Resource) -> Mapping {
    authority
        .map(
            resource,
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap()
}

#[test]
fn exact_lease_pairing_distinguishes_other_mapping_in_same_permission() {
    let (_, authority, resource, _) = basic();
    let mut first = map(&authority, resource);
    let view = first.view(0..4096).unwrap();
    let (resource, _) = make_resource(
        PhysicalSpan::new(BASE + 0x10000, 16384).unwrap(),
        ResourceKind::Registers,
    );
    let mut second = map(&authority, resource);
    assert_eq!(first.shares_mapping(&view), Ok(true));
    assert_eq!(second.shares_authority(&view), Ok(true));
    assert_eq!(second.shares_mapping(&view), Ok(false));
    drop(view);
    // SAFETY: these isolated mappings have no outside pointer/worker use.
    unsafe { first.retire() }.unwrap();
    // SAFETY: same stopped isolated owner, distinct original lease/token.
    unsafe { second.retire() }.unwrap();
}

#[test]
fn current_context_refusal_precedes_pointer_view_and_provenance_publication() {
    let (model, authority, resource, _) = basic();
    let mut mapping = map(&authority, resource);
    let view = mapping.view(0..4096).unwrap();
    let pointer = mapping.address(0, 4).unwrap();
    let before_calls = model.calls();
    let before_events = model.state.lock().unwrap().events.clone();
    model.allowed.store(false, Ordering::Release);
    assert_eq!(mapping.check_current(), Err(Error::Unavailable));
    assert_eq!(view.check_current(), Err(Error::Unavailable));
    assert_eq!(mapping.address(0, 4), Err(Error::Unavailable));
    assert_eq!(view.address(0, 4), Err(Error::Unavailable));
    assert_eq!(mapping.view(0..4096).err(), Some(Error::Unavailable));
    assert_eq!(mapping.shares_mapping(&view), Err(Error::Unavailable));
    assert_eq!(mapping.shares_authority(&view), Err(Error::Unavailable));
    assert_eq!(model.calls(), before_calls);
    assert_eq!(model.state.lock().unwrap().events, before_events);
    assert_eq!(model.live(), 1);
    model.allowed.store(true, Ordering::Release);
    assert_eq!(mapping.address(0, 4), Ok(pointer));
    assert_eq!(view.address(0, 4), Ok(pointer));
    assert_eq!(mapping.shares_mapping(&view), Ok(true));
    drop(view);
    // SAFETY: isolated sequential fixture, every pointer/view user stopped;
    // original context was restored before this unmap.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(model.live(), 0);
}
fn device_regions() -> Vec<DeviceCacheRegion> {
    vec![
        DeviceCacheRegion {
            physical: PhysicalSpan::new(BASE, 4096).unwrap(),
            attribute: CacheAttribute::Uncached,
        },
        DeviceCacheRegion {
            physical: PhysicalSpan::new(BASE + 8192, 4096).unwrap(),
            attribute: CacheAttribute::WriteCombining,
        },
    ]
}
fn make_device_resource(regions: Vec<DeviceCacheRegion>) -> (Resource, Arc<AtomicUsize>) {
    let dropped = Arc::new(AtomicUsize::new(0));
    // SAFETY: this isolated model owns one whole Registers BAR at this
    // immutable requester/reset epoch; its model device checks precisely
    // the declared register/aperture pages. No RAM/firmware is involved.
    let resource = unsafe {
        Resource::with_device_cache_regions(
            Box::new(Backing {
                span: PhysicalSpan::new(BASE, 16384).unwrap(),
                kind: ResourceKind::Registers,
                dropped: Arc::clone(&dropped),
                drop_context: None,
            }),
            regions,
        )
    }
    .unwrap();
    (resource, dropped)
}
#[test]
fn one_original_bar_maps_disjoint_checked_uc_wc_and_keeps_whole_owner() {
    let (model, authority, _, _) = basic();
    let (resource, dropped) = make_device_resource(device_regions());
    assert_eq!(resource.kind(), ResourceKind::Registers);
    let cloned = resource.clone();
    assert!(Arc::ptr_eq(&cloned.backing, &resource.backing));
    assert_eq!(
        cloned.device_cache_regions().unwrap().as_ptr(),
        resource.device_cache_regions().unwrap().as_ptr()
    );
    drop(cloned);
    let id = authority.register_resource(resource.clone()).unwrap();
    let mut registers = authority
        .map(
            resource.clone(),
            7,
            100,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    let mut aperture = authority
        .map_physical(
            PhysicalSpan::new(BASE + 8192 + 17, 100).unwrap(),
            CacheAttribute::WriteCombining,
            Protection::ReadWrite,
        )
        .unwrap();
    assert_eq!(model.calls(), 2);
    assert_eq!(model.live(), 2);
    assert_ne!(
        registers.address(0, 1).unwrap(),
        aperture.address(0, 1).unwrap()
    );
    assert!(matches!(
        authority.map(
            resource.clone(),
            8192,
            1,
            CacheAttribute::WriteCombining,
            Protection::ReadWrite
        ),
        Err(Error::ResourceConflict)
    ));
    assert!(matches!(
        authority.unregister_resource(id),
        Err(Error::Busy)
    ));
    let (competing, competing_dropped) = make_resource(
        PhysicalSpan::new(BASE, 16384).unwrap(),
        ResourceKind::Registers,
    );
    assert!(matches!(
        authority.map(
            competing,
            12288,
            1,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::ResourceConflict)
    ));
    assert_eq!(competing_dropped.load(Ordering::Relaxed), 1);
    let view = aperture.view(0..16).unwrap();
    drop(resource);
    // SAFETY: register consumers stopped; aperture still keeps same BAR.
    unsafe { registers.retire() }.unwrap();
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    // SAFETY: bounded aperture view still exists, so retirement must refuse.
    assert_eq!(unsafe { aperture.retire() }, Err(Error::Busy));
    drop(view);
    // SAFETY: all aperture consumers/views drained.
    unsafe { aperture.retire() }.unwrap();
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    authority.unregister_resource(id).unwrap();
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}
#[test]
fn device_permissions_cover_only_whole_typed_pages() {
    let (model, authority, _, _) = basic();
    let (resource, _) = make_device_resource(device_regions());
    for (offset, bytes, attribute) in [
        (4096, 1, CacheAttribute::Uncached),
        (4095, 2, CacheAttribute::Uncached),
        (0, 16384, CacheAttribute::Uncached),
        (8192, 1, CacheAttribute::Uncached),
        (0, 1, CacheAttribute::WriteCombining),
        (8191, 2, CacheAttribute::WriteCombining),
        (12288, 1, CacheAttribute::WriteCombining),
        (8192, 1, CacheAttribute::WriteBack),
    ] {
        assert!(matches!(
            authority.map(
                resource.clone(),
                offset,
                bytes,
                attribute,
                Protection::ReadWrite
            ),
            Err(Error::UnsupportedCache)
        ));
    }
    let id = authority.register_resource(resource).unwrap();
    assert!(matches!(
        authority.map_physical(
            PhysicalSpan::new(BASE + 4096, 1).unwrap(),
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::UnsupportedCache)
    ));
    authority.unregister_resource(id).unwrap();
    assert_eq!(model.calls(), 0);
    // Adjacent regions stay separately checked, even with identical UC.
    let (adjacent, _) = make_device_resource(vec![
        DeviceCacheRegion {
            physical: PhysicalSpan::new(BASE, 4096).unwrap(),
            attribute: CacheAttribute::Uncached,
        },
        DeviceCacheRegion {
            physical: PhysicalSpan::new(BASE + 4096, 4096).unwrap(),
            attribute: CacheAttribute::Uncached,
        },
    ]);
    assert!(matches!(
        authority.map(
            adjacent,
            4095,
            2,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::UnsupportedCache)
    ));
    assert_eq!(model.calls(), 0);
}
#[test]
fn malformed_device_permission_tables_release_owner_before_any_map() {
    let (model, _authority, _, _) = basic();
    let uc = device_regions()[0];
    for (regions, expected) in [
        (vec![], Error::InvalidRange),
        (
            vec![DeviceCacheRegion {
                attribute: CacheAttribute::WriteBack,
                ..uc
            }],
            Error::UnsupportedCache,
        ),
        (
            vec![DeviceCacheRegion {
                physical: PhysicalSpan::new(BASE + 1, 4095).unwrap(),
                ..uc
            }],
            Error::InvalidRange,
        ),
        (
            vec![DeviceCacheRegion {
                physical: PhysicalSpan::new(BASE + 16384, 4096).unwrap(),
                ..uc
            }],
            Error::OutsideResource,
        ),
        (vec![uc, uc], Error::ResourceConflict),
        (
            vec![
                uc,
                DeviceCacheRegion {
                    attribute: CacheAttribute::WriteCombining,
                    ..uc
                },
            ],
            Error::ResourceConflict,
        ),
    ] {
        let dropped = Arc::new(AtomicUsize::new(0));
        // SAFETY: isolated model's owned device BAR; invalid
        // declaration data is rejected before publication.
        let result = unsafe {
            Resource::with_device_cache_regions(
                Box::new(Backing {
                    span: PhysicalSpan::new(BASE, 16384).unwrap(),
                    kind: ResourceKind::Registers,
                    dropped: Arc::clone(&dropped),
                    drop_context: None,
                }),
                regions,
            )
        };
        assert!(matches!(result,Err(error) if error==expected));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
    assert_eq!(model.calls(), 0);
}
#[test]
fn source_device_permissions_never_override_unknown_alias_or_native_wc_refusal() {
    for attribute in [
        None,
        Some(CacheAttribute::WriteBack),
        Some(CacheAttribute::Uncached),
    ] {
        let model = Model::new();
        // SAFETY: exact isolated root-set alias includes the aperture page.
        let authority = unsafe {
            fixture(
                Arc::clone(&model),
                vec![ExistingAlias {
                    physical: PhysicalSpan::new(BASE + 8192, 4096).unwrap(),
                    attribute,
                }],
            )
        };
        let (resource, dropped) = make_device_resource(device_regions());
        assert!(matches!(
            authority.map(
                resource.clone(),
                8192,
                1,
                CacheAttribute::WriteCombining,
                Protection::ReadWrite
            ),
            Err(Error::CacheConflict)
        ));
        assert_eq!(model.calls(), 0);
        let alias = authority.aliases().unwrap()[0].0;
        // SAFETY: model root owner removed/drained the alias.
        unsafe { authority.retire_alias(alias) }.unwrap();
        model.mode(Mode::RefuseWc);
        assert!(matches!(
            authority.map(
                resource.clone(),
                8192,
                1,
                CacheAttribute::WriteCombining,
                Protection::ReadWrite
            ),
            Err(Error::UnsupportedCache)
        ));
        assert_eq!(model.calls(), 1);
        assert_eq!(model.live(), 0);
        assert_eq!(authority.status().unwrap().installing, 0);
        model.mode(Mode::Normal);
        let mut mapping = authority
            .map(
                resource,
                8192,
                1,
                CacheAttribute::WriteCombining,
                Protection::ReadWrite,
            )
            .unwrap();
        // SAFETY: no model accesses; native proof and all-root ACK succeed.
        unsafe { mapping.retire() }.unwrap();
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn explicit_uc_permissions_replace_prefetchable_defaults_and_quarantine_keeps_original_bar() {
    let (model, authority, _, _) = basic();
    let dropped = Arc::new(AtomicUsize::new(0));
    // SAFETY: this device model's prefetchable resource permits only UC in
    // its one declared page; no source-checked WC permission exists.
    let uc_only = unsafe {
        Resource::with_device_cache_regions(
            Box::new(Backing {
                span: PhysicalSpan::new(BASE, 16384).unwrap(),
                kind: ResourceKind::PrefetchableMemory,
                dropped: Arc::clone(&dropped),
                drop_context: None,
            }),
            vec![device_regions()[0]],
        )
    }
    .unwrap();
    assert_eq!(uc_only.kind(), ResourceKind::PrefetchableMemory);
    assert!(matches!(
        authority.map(
            uc_only,
            0,
            1,
            CacheAttribute::WriteCombining,
            Protection::ReadWrite
        ),
        Err(Error::UnsupportedCache)
    ));
    assert_eq!(model.calls(), 0);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    let (resource, dropped) = make_device_resource(device_regions());
    let root_dropped = Arc::clone(&model.dropped);
    model.mode(Mode::WrongCache);
    assert!(matches!(
        authority.map(
            resource,
            8192,
            1,
            CacheAttribute::WriteCombining,
            Protection::ReadWrite
        ),
        Err(Error::InvalidPlatformReply)
    ));
    assert_eq!(authority.status().unwrap().quarantined, 1);
    drop(authority);
    drop(model);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    assert_eq!(root_dropped.load(Ordering::Relaxed), 0);
}
#[test]
fn each_shared_metadata_failure_precedes_reservation_and_native_effects() {
    for successful_reservations in 0..3 {
        let model = Model::new();
        // SAFETY: isolated model machine/root set, no outside mappings.
        let authority = unsafe { fixture(Arc::clone(&model), Vec::new()) };
        let dropped = Arc::new(AtomicUsize::new(0));
        let resource = Resource::new(Box::new(Backing {
            span: PhysicalSpan::new(BASE, 16384).unwrap(),
            kind: ResourceKind::Registers,
            dropped: Arc::clone(&dropped),
            drop_context: Some(authority.clone()),
        }));
        metadata::allocation::budget(Some(successful_reservations));
        let outcome = authority.map(
            resource,
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        );
        let attempts = metadata::allocation::attempts();
        metadata::allocation::budget(None);
        assert!(matches!(outcome, Err(Error::Unavailable)));
        assert_eq!(attempts, successful_reservations + 1);
        assert_eq!(model.calls(), 0);
        assert_eq!(model.live(), 0);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        {
            let mut guard = authority.inner.finish_lock();
            assert!(guard.inventory().records.is_empty());
            assert_eq!(guard.inventory().pending_maps, 0);
        }
        // The same physical span remains available after either failure.
        let (replacement, released) = make_resource(
            PhysicalSpan::new(BASE, 16384).unwrap(),
            ResourceKind::Registers,
        );
        let mut mapping = map(&authority, replacement);
        // SAFETY: no model consumer issued any device access.
        unsafe { mapping.retire() }.unwrap();
        assert_eq!(released.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn native_publication_views_and_retirement_need_no_late_shared_allocation() {
    let (model, authority, resource, dropped) = basic();
    model.state.lock().unwrap().freeze_shared_allocations = true;
    let mut mapping = map(&authority, resource);
    let view = mapping.view(32..64).unwrap();
    let second = view.clone();
    assert_eq!(view.address(0, 1), second.address(0, 1));
    drop(view);
    // SAFETY: native accesses stopped; a live subview must still refuse.
    assert_eq!(unsafe { mapping.retire() }, Err(Error::Busy));
    drop(second);
    // SAFETY: all consumers and views are drained.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(metadata::allocation::attempts(), 0);
    metadata::allocation::budget(None);
    assert_eq!(model.calls(), 1);
    assert_eq!(model.live(), 0);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}

#[test]
fn unpublished_lease_drop_preserves_uncertain_and_invalid_native_ownership() {
    for mode in [Mode::Unchanged, Mode::Uncertain, Mode::WrongCache] {
        let (model, authority, resource, dropped) = basic();
        let platform_dropped = Arc::clone(&model.dropped);
        model.mode(mode);
        model.state.lock().unwrap().freeze_shared_allocations = true;
        let outcome = authority.map(
            resource,
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        );
        assert!(outcome.is_err());
        assert_eq!(metadata::allocation::attempts(), 0);
        metadata::allocation::budget(None);
        assert_eq!(model.calls(), 1);
        let uncertain = mode != Mode::Unchanged;
        assert_eq!(model.live(), usize::from(uncertain));
        assert_eq!(
            authority.status().unwrap().quarantined,
            u64::from(uncertain)
        );
        assert!(
            !model
                .state
                .lock()
                .unwrap()
                .events
                .contains(&"unmap requested")
        );
        drop(authority);
        drop(model);
        assert_eq!(dropped.load(Ordering::Relaxed), usize::from(!uncertain));
        assert_eq!(
            platform_dropped.load(Ordering::Relaxed),
            usize::from(!uncertain)
        );
    }
}

#[test]
fn owned_mapping_uses_virtual_backing_and_checked_subviews() {
    let (model, authority, resource, dropped) = basic();
    let mut mapping = authority
        .map(
            resource,
            123,
            8193,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    assert_eq!(
        mapping.physical_span().unwrap(),
        PhysicalSpan::new(BASE + 123, 8193).unwrap()
    );
    assert_eq!(mapping.bytes().unwrap(), 8193);
    assert_ne!(
        mapping.address(0, 1).unwrap().as_ptr() as usize,
        BASE as usize + 123
    );
    let pointer = mapping.address(0, 4).unwrap().as_ptr();
    // SAFETY: model-only owned bytes, no simultaneous device access, exact
    // checked width; production consumers must apply device semantics.
    unsafe {
        pointer.write_volatile(0xa5);
        assert_eq!(pointer.read_volatile(), 0xa5);
    }
    let view = mapping.view(7..17).unwrap();
    assert_eq!(
        view.address(2, 8).unwrap().as_ptr(),
        pointer.wrapping_add(9)
    );
    assert!(matches!(mapping.address(8192, 2), Err(Error::InvalidRange)));
    assert!(matches!(
        mapping.address(usize::MAX, 2),
        Err(Error::InvalidRange)
    ));
    assert!(matches!(view.address(10, 1), Err(Error::InvalidRange)));
    assert!(matches!(
        mapping.view(Range { start: 17, end: 7 }),
        Err(Error::InvalidRange)
    ));
    // SAFETY: model has no users except the view.
    assert_eq!(unsafe { mapping.retire() }, Err(Error::Busy));
    assert_eq!(model.live(), 1);
    drop(view);
    // SAFETY: model accesses stopped, no kept views/raw users.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(model.live(), 0);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    assert!(matches!(mapping.address(0, 1), Err(Error::Retired)));
}
#[test]
fn full_page_reservation_precedes_platform_reentry_and_refuses_overlap() {
    let (model, authority, resource, _) = basic();
    model.state.lock().unwrap().reenter = Some((authority.clone(), resource.clone()));
    let mut first = authority
        .map(
            resource.clone(),
            1,
            1,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    assert!(matches!(
        authority.map(
            resource.clone(),
            4095,
            1,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::ResourceConflict)
    ));
    let mut second = authority
        .map(
            resource,
            4096,
            1,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    assert_eq!(model.calls(), 2);
    // SAFETY: independent model windows, no active users/views.
    unsafe {
        first.retire().unwrap();
        second.retire().unwrap();
    }
    assert_eq!(authority.status().unwrap().live, 0);
}
#[test]
fn imported_effective_wb_or_unknown_alias_blocks_uc_and_wc_until_real_removal() {
    for attribute in [Some(CacheAttribute::WriteBack), None] {
        let model = Model::new();
        // SAFETY: model has exactly the imported page-alias policy.
        let authority = unsafe {
            fixture(
                Arc::clone(&model),
                vec![ExistingAlias {
                    physical: PhysicalSpan::new(BASE + 4095, 1).unwrap(),
                    attribute,
                }],
            )
        };
        let (resource, _) = make_resource(
            PhysicalSpan::new(BASE, 8192).unwrap(),
            ResourceKind::PrefetchableMemory,
        );
        for requested in [CacheAttribute::Uncached, CacheAttribute::WriteCombining] {
            assert!(matches!(
                authority.map(resource.clone(), 0, 1, requested, Protection::ReadWrite),
                Err(Error::CacheConflict)
            ));
        }
        assert_eq!(model.calls(), 0);
        let id = authority.aliases().unwrap()[0].0;
        // SAFETY: this model has acknowledged removal of its sole alias;
        // native callers need real removal/cache/TLB ACK first.
        unsafe { authority.retire_alias(id) }.unwrap();
        let mut mapped = map(&authority, resource);
        // SAFETY: no model device/CPU users remain.
        unsafe { mapped.retire() }.unwrap();
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        assert_eq!(unsafe { authority.retire_alias(id) }, Err(Error::Retired));
    }
}
#[test]
fn compatible_effective_uc_alias_is_distinct_from_wb_pte_flags() {
    let model = Model::new();
    // SAFETY: model describes effective UC despite hypothetical WB
    // PTE bits (MTRR UC precedence); no cached Rust reference aliases it.
    let authority = unsafe {
        fixture(
            Arc::clone(&model),
            vec![ExistingAlias {
                physical: PhysicalSpan::new(BASE, 4096).unwrap(),
                attribute: Some(CacheAttribute::Uncached),
            }],
        )
    };
    let (resource, _) = make_resource(
        PhysicalSpan::new(BASE, 4096).unwrap(),
        ResourceKind::Registers,
    );
    let mut mapping = map(&authority, resource);
    // SAFETY: all model consumers stopped.
    unsafe { mapping.retire() }.unwrap();
}
#[test]
fn outside_alias_reservation_blocks_conflicts_before_publication() {
    let (_, authority, resource, _) = basic();
    // SAFETY: simulated outside root owner reserves before table mutation.
    let id = unsafe {
        authority.reserve_alias(ExistingAlias {
            physical: PhysicalSpan::new(BASE, 1).unwrap(),
            attribute: Some(CacheAttribute::WriteBack),
        })
    }
    .unwrap();
    assert!(matches!(
        authority.map(
            resource.clone(),
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::CacheConflict)
    ));
    // SAFETY: model outside alias was never published; rollback is exact.
    unsafe { authority.retire_alias(id) }.unwrap();
    let mut mapping = map(&authority, resource);
    assert!(matches!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe {
            authority.reserve_alias(ExistingAlias {
                physical: PhysicalSpan::new(BASE, 1).unwrap(),
                attribute: Some(CacheAttribute::WriteCombining),
            })
        },
        Err(Error::CacheConflict)
    ));
    // SAFETY: model consumers stopped.
    unsafe { mapping.retire() }.unwrap();
}
#[test]
fn invalid_ranges_and_unowned_rounding_never_reach_platform() {
    let (model, authority, resource, _) = basic();
    for (offset, bytes) in [
        (0, 0),
        (16384, 1),
        (16383, 2),
        (usize::MAX, 1),
        (0, usize::MAX),
    ] {
        assert!(
            authority
                .map(
                    resource.clone(),
                    offset,
                    bytes,
                    CacheAttribute::Uncached,
                    Protection::ReadWrite
                )
                .is_err()
        );
    }
    let (partial, _) = make_resource(
        PhysicalSpan::new(BASE + 1, 8191).unwrap(),
        ResourceKind::Registers,
    );
    assert!(matches!(
        authority.map(
            partial,
            0,
            1,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::OutsideResource)
    ));
    assert_eq!(model.calls(), 0);
    assert_eq!(PhysicalSpan::new(u64::MAX, 1), Err(Error::InvalidRange));
    let (above, _) = make_resource(
        PhysicalSpan::new((1u64 << 48) - 4096, 8192).unwrap(),
        ResourceKind::Registers,
    );
    assert!(matches!(
        authority.map(
            above,
            0,
            8192,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::InvalidRange)
    ));
}
#[test]
fn prefetchable_bar_never_establishes_wc_by_itself() {
    let (model, authority, registers, _) = basic();
    assert!(matches!(
        authority.map(
            registers,
            0,
            1,
            CacheAttribute::WriteCombining,
            Protection::ReadWrite
        ),
        Err(Error::UnsupportedCache)
    ));
    let (memory, _) = make_resource(
        PhysicalSpan::new(BASE, 4096).unwrap(),
        ResourceKind::PrefetchableMemory,
    );
    model.mode(Mode::RefuseWc);
    assert!(matches!(
        authority.map(
            memory.clone(),
            0,
            1,
            CacheAttribute::WriteCombining,
            Protection::ReadWrite
        ),
        Err(Error::UnsupportedCache)
    ));
    assert_eq!(model.live(), 0);
    model.mode(Mode::Normal);
    let mut mapping = authority
        .map(
            memory,
            0,
            1,
            CacheAttribute::WriteCombining,
            Protection::ReadOnly,
        )
        .unwrap();
    assert_eq!(mapping.protection().unwrap(), Protection::ReadOnly);
    assert_eq!(mapping.attribute().unwrap(), CacheAttribute::WriteCombining);
    // SAFETY: model users stopped and modeled WC drain acknowledged.
    unsafe { mapping.retire() }.unwrap();
}
#[test]
fn unchanged_failure_releases_but_uncertain_map_keeps_resource_and_provider() {
    let (model, authority, resource, dropped) = basic();
    let platform_dropped = Arc::clone(&model.dropped);
    model.mode(Mode::Unchanged);
    assert!(
        authority
            .map(
                resource.clone(),
                0,
                1,
                CacheAttribute::Uncached,
                Protection::ReadWrite
            )
            .is_err()
    );
    assert_eq!(authority.status().unwrap().quarantined, 0);
    model.mode(Mode::Uncertain);
    assert!(
        authority
            .map(
                resource,
                0,
                1,
                CacheAttribute::Uncached,
                Protection::ReadWrite
            )
            .is_err()
    );
    assert_eq!(authority.status().unwrap().quarantined, 1);
    assert_eq!(model.live(), 1);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    drop(authority);
    drop(model);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    assert_eq!(platform_dropped.load(Ordering::Relaxed), 0);
}
#[test]
fn malformed_provider_responses_quarantine_without_trusting_unmap_token() {
    for mode in [
        Mode::WrongCache,
        Mode::WrongSpan,
        Mode::NullToken,
        Mode::WrongProtection,
        Mode::Unaligned,
        Mode::Noncanonical,
        Mode::WrapVirtual,
    ] {
        let (model, authority, resource, dropped) = basic();
        model.mode(mode);
        assert!(matches!(
            authority.map(
                resource,
                0,
                1,
                CacheAttribute::Uncached,
                Protection::ReadWrite
            ),
            Err(Error::InvalidPlatformReply)
        ));
        assert_eq!(authority.status().unwrap().quarantined, 1);
        assert_eq!(model.live(), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert!(
            !model
                .state
                .lock()
                .unwrap()
                .events
                .contains(&"unmap requested")
        );
    }
}
#[test]
fn unmap_failure_preserves_token_and_blocks_access_until_acknowledged_retry() {
    let (model, authority, resource, dropped) = basic();
    let mut mapping = map(&authority, resource.clone());
    model.state.lock().unwrap().ack = false;
    // SAFETY: no model consumers remain, but provider must still prove ACK.
    assert_eq!(unsafe { mapping.retire() }, Err(Error::UnmapFailed));
    assert_eq!(authority.status().unwrap().uncertain, 1);
    assert!(matches!(mapping.address(0, 1), Err(Error::Unavailable)));
    assert!(matches!(mapping.view(0..1), Err(Error::Unavailable)));
    assert!(matches!(
        authority.map(
            resource.clone(),
            0,
            1,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::ResourceConflict)
    ));
    assert_eq!(model.live(), 1);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    model.state.lock().unwrap().ack = true;
    // SAFETY: still no consumers; same exact token retried with ACK.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(model.live(), 0);
    let mut second = map(&authority, resource);
    // SAFETY: no consumers of the new model mapping.
    unsafe { second.retire() }.unwrap();
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}
#[test]
fn dropped_active_mapping_keeps_views_and_native_owner_without_unmapping() {
    let (model, authority, resource, dropped) = basic();
    let mapping = map(&authority, resource);
    let view = mapping.view(0..16).unwrap();
    let cloned = view.clone();
    drop(mapping);
    assert_eq!(authority.status().unwrap().quarantined, 1);
    assert!(matches!(view.address(0, 1), Err(Error::Unavailable)));
    drop(view);
    drop(cloned);
    drop(authority);
    assert_eq!(model.live(), 1);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
}
#[test]
fn lock_contention_and_context_refusal_do_not_publish_or_reuse_state() {
    let (model, authority, resource, _) = basic();
    let guard = authority.inner.lock().unwrap();
    assert!(matches!(
        authority.map(
            resource.clone(),
            0,
            1,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::Busy)
    ));
    drop(guard);
    model.allowed.store(false, Ordering::Release);
    assert!(matches!(
        authority.map(
            resource,
            0,
            1,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::Unavailable)
    ));
    assert_eq!(model.calls(), 0);
}
#[test]
fn nonwrapping_ids_and_single_production_permission_survive_last_public_drop() {
    let model = Model::new();
    let provider_dropped = Arc::clone(&model.dropped);
    // SAFETY: this sole production-constructor test models one complete
    // machine/root set. Other fixtures are cfg(test) simulated machines.
    let authority = unsafe { Authority::activate(model.clone(), SPACE, Vec::new()) }.unwrap();
    assert!(matches!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { Authority::activate(model.clone(), SPACE, Vec::new()) },
        Err(Error::AlreadyActive)
    ));
    {
        let mut guard = authority.inner.lock().unwrap();
        guard.inventory().next = u64::MAX;
    }
    let (resource, _) = make_resource(
        PhysicalSpan::new(BASE, 4096).unwrap(),
        ResourceKind::Registers,
    );
    assert!(matches!(
        authority.map(
            resource,
            0,
            1,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::Exhausted)
    ));
    drop(authority);
    assert!(matches!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { Authority::activate(model.clone(), SPACE, Vec::new()) },
        Err(Error::AlreadyActive)
    ));
    drop(model);
    assert_eq!(provider_dropped.load(Ordering::Relaxed), 0);
}
#[test]
fn simultaneous_overlapping_requests_have_exactly_one_publication() {
    let (model, authority, resource, _) = basic();
    let ready = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            ready.wait();
            authority.map(
                resource.clone(),
                0,
                1,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
        });
        let second = scope.spawn(|| {
            ready.wait();
            authority.map(
                resource.clone(),
                4095,
                1,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
        });
        [first.join().unwrap(), second.join().unwrap()]
    });
    let mut successes = 0;
    let mut conflicts = 0;
    for outcome in outcomes {
        match outcome {
            Ok(mut mapping) => {
                successes += 1;
                // SAFETY: model consumer threads returned without keeping
                // pointers/views; only this owner remains for retirement.
                unsafe { mapping.retire() }.unwrap();
            }
            Err(Error::ResourceConflict | Error::Busy) => conflicts += 1,
            Err(error) => panic!("unexpected overlap outcome: {error:?}"),
        }
    }
    assert_eq!((successes, conflicts), (1, 1));
    assert_eq!(model.calls(), 1);
}
#[test]
fn physical_only_abi_requires_registered_full_owner_and_keeps_it_through_ack() {
    let (model, authority, resource, dropped) = basic();
    let span = PhysicalSpan::new(BASE + 123, 4097).unwrap();
    assert!(matches!(
        authority.resolve_resource(span),
        Err(Error::OutsideResource)
    ));
    assert!(matches!(
        authority.map_physical(span, CacheAttribute::Uncached, Protection::ReadWrite),
        Err(Error::OutsideResource)
    ));
    assert_eq!(model.calls(), 0);
    let id = authority.register_resource(resource).unwrap();
    let pin = authority.resolve_resource(span).unwrap();
    assert!(pin.backing().is::<Backing>());
    assert_eq!(authority.register_resource(pin).unwrap(), id);
    let mut mapping = authority
        .map_physical(span, CacheAttribute::Uncached, Protection::ReadWrite)
        .unwrap();
    assert_eq!(mapping.physical_span().unwrap(), span);
    assert_eq!(authority.unregister_resource(id), Err(Error::Busy));
    model.state.lock().unwrap().ack = false;
    // SAFETY: no model users remain; provider acknowledgement is required.
    assert_eq!(unsafe { mapping.retire() }, Err(Error::UnmapFailed));
    assert_eq!(authority.unregister_resource(id), Err(Error::Busy));
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    model.state.lock().unwrap().ack = true;
    // SAFETY: same model token, stopped users and modeled ACK.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    authority.unregister_resource(id).unwrap();
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    assert!(matches!(
        authority.resolve_resource(span),
        Err(Error::OutsideResource)
    ));
    assert_eq!(authority.unregister_resource(id), Err(Error::Retired));
}
#[test]
fn registered_resource_conflicts_include_whole_grant_and_page_rounded_lookup() {
    let (_, authority, resource, _) = basic();
    let id = authority.register_resource(resource.clone()).unwrap();
    let (other, _) = make_resource(
        PhysicalSpan::new(BASE + 4096, 4096).unwrap(),
        ResourceKind::Registers,
    );
    assert_eq!(
        authority.register_resource(other.clone()),
        Err(Error::ResourceConflict)
    );
    assert!(matches!(
        authority.map(other, 0, 1, CacheAttribute::Uncached, Protection::ReadWrite),
        Err(Error::ResourceConflict)
    ));
    authority.unregister_resource(id).unwrap();
    let (partial, _) = make_resource(
        PhysicalSpan::new(BASE + 1, 4095).unwrap(),
        ResourceKind::Registers,
    );
    let id = authority.register_resource(partial).unwrap();
    assert!(matches!(
        authority.resolve_resource(PhysicalSpan::new(BASE + 1, 1).unwrap()),
        Err(Error::OutsideResource)
    ));
    authority.unregister_resource(id).unwrap();
    let mut mapping = map(&authority, resource);
    let (other, _) = make_resource(
        PhysicalSpan::new(BASE + 8192, 4096).unwrap(),
        ResourceKind::Registers,
    );
    // Although no live mapped page intersects this request, a second
    // alleged resource owner must not overlap the first whole grant.
    assert_eq!(
        authority.register_resource(other.clone()),
        Err(Error::ResourceConflict)
    );
    assert!(matches!(
        authority.map(other, 0, 1, CacheAttribute::Uncached, Protection::ReadWrite),
        Err(Error::ResourceConflict)
    ));
    // SAFETY: model consumers stopped; remove original mapping exactly.
    unsafe { mapping.retire() }.unwrap();
}
fn disjoint_resource() -> (Resource, Arc<AtomicUsize>) {
    make_resource(
        PhysicalSpan::new(BASE + 16384, 16384).unwrap(),
        ResourceKind::Registers,
    )
}
fn map_retry(authority: &Authority, resource: Resource) -> Result<Mapping, Error> {
    loop {
        match authority.map(
            resource.clone(),
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        ) {
            Err(Error::Busy) => std::thread::yield_now(),
            result => return result,
        }
    }
}
#[test]
fn duplicate_nonzero_token_quarantines_both_windows_and_forbids_unmap() {
    let (model, authority, resource, first_dropped) = basic();
    let mut first = map(&authority, resource);
    let first_cpu = first.address(0, 1).unwrap();
    let (second, second_dropped) = disjoint_resource();
    model.mode(Mode::DuplicateToken);
    assert!(matches!(
        authority.map(
            second,
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite
        ),
        Err(Error::InvalidPlatformReply)
    ));
    assert_eq!(model.live(), 2);
    {
        let state = model.state.lock().unwrap();
        assert_ne!(
            state.installed[0].request.physical,
            state.installed[1].request.physical
        );
        assert_ne!(
            state.installed[0].memory.0.as_ptr(),
            state.installed[1].memory.0.as_ptr()
        );
        assert_eq!(
            state.installed[0].memory.0.as_ptr() as usize,
            first_cpu.as_ptr() as usize
        );
        assert_eq!(state.installed[0].token, state.installed[1].token);
        assert!(!state.events.contains(&"unmap requested"));
    }
    assert!(matches!(first.address(0, 1), Err(Error::Unavailable)));
    // SAFETY: model consumers stopped, but token collision must refuse
    // before calling the native provider through ambiguous identity.
    assert_eq!(unsafe { first.retire() }, Err(Error::InvalidPlatformReply));
    assert_eq!(authority.status().unwrap().quarantined, 2);
    assert_eq!(authority.status().unwrap().live, 0);
    let provider_dropped = Arc::clone(&model.dropped);
    drop(first);
    drop(authority);
    drop(model);
    assert_eq!(first_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(second_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(provider_dropped.load(Ordering::Relaxed), 0);
}
#[test]
fn duplicate_tokens_remain_reserved_for_uncertain_and_quarantined_records() {
    for scenario in 0..3 {
        let (model, authority, resource, first_dropped) = basic();
        let mut first = if scenario == 0 {
            model.mode(Mode::WrongCache);
            assert!(matches!(
                authority.map(
                    resource,
                    0,
                    4096,
                    CacheAttribute::Uncached,
                    Protection::ReadWrite
                ),
                Err(Error::InvalidPlatformReply)
            ));
            None
        } else {
            let mut mapping = map(&authority, resource);
            if scenario == 1 {
                model.state.lock().unwrap().ack = false;
                // SAFETY: model consumers stopped; unmap ACK fails.
                assert_eq!(unsafe { mapping.retire() }, Err(Error::UnmapFailed));
                Some(mapping)
            } else {
                drop(mapping);
                None
            }
        };
        let attempts = model
            .state
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|event| **event == "unmap requested")
            .count();
        model.mode(Mode::DuplicateToken);
        let (second, second_dropped) = disjoint_resource();
        assert!(matches!(
            authority.map(
                second,
                0,
                4096,
                CacheAttribute::Uncached,
                Protection::ReadWrite
            ),
            Err(Error::InvalidPlatformReply)
        ));
        if let Some(mapping) = &mut first {
            assert_eq!(
                // SAFETY: stopped model users; duplicate identity cannot retry.
                unsafe { mapping.retire() },
                Err(Error::InvalidPlatformReply)
            );
        }
        assert_eq!(authority.status().unwrap().quarantined, 2);
        assert_eq!(
            model
                .state
                .lock()
                .unwrap()
                .events
                .iter()
                .filter(|event| **event == "unmap requested")
                .count(),
            attempts
        );
        assert_eq!(model.live(), 2);
        drop(first);
        drop(authority);
        drop(model);
        assert_eq!(first_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(second_dropped.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn simultaneous_duplicate_replies_cannot_resurrect_quarantined_installations() {
    let (model, authority, first, first_dropped) = basic();
    let (second, second_dropped) = disjoint_resource();
    let ready = Arc::new(std::sync::Barrier::new(3));
    let release = Arc::new(std::sync::Barrier::new(3));
    {
        let mut state = model.state.lock().unwrap();
        state.mode = Mode::DuplicateToken;
        state.reply_gates = Some((Arc::clone(&ready), Arc::clone(&release)));
    }
    let (outcomes, observed_tokens, installing) = std::thread::scope(|scope| {
        let a = scope.spawn(|| map_retry(&authority, first));
        let b = scope.spawn(|| map_retry(&authority, second));
        ready.wait();
        let mut guard = authority.inner.finish_lock();
        release.wait();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let (observed_tokens, installing) = loop {
            let records = &guard.inventory().records;
            if records
                .iter()
                .all(|record| record.token.load(Ordering::Acquire) == 1)
            {
                break (
                    true,
                    records
                        .iter()
                        .all(|record| record.phase.load(Ordering::Acquire) == INSTALLING),
                );
            }
            if std::time::Instant::now() >= deadline {
                break (false, false);
            }
            std::thread::yield_now();
        };
        // Always release the fixture's lock/gates before assertions so a
        // deliberate regression fails instead of deadlocking test cleanup.
        drop(guard);
        (
            [a.join().unwrap(), b.join().unwrap()],
            observed_tokens,
            installing,
        )
    });
    assert!(observed_tokens && installing);
    assert!(
        outcomes
            .into_iter()
            .all(|result| matches!(result, Err(Error::InvalidPlatformReply)))
    );
    let status = authority.status().unwrap();
    assert_eq!(
        (
            status.installing,
            status.live,
            status.uncertain,
            status.quarantined
        ),
        (0, 0, 0, 2)
    );
    assert!(
        !model
            .state
            .lock()
            .unwrap()
            .events
            .contains(&"unmap requested")
    );
    assert_eq!(model.live(), 2);
    drop(authority);
    drop(model);
    assert_eq!(first_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(second_dropped.load(Ordering::Relaxed), 0);
}
#[test]
fn pending_reply_blocks_old_retirement_before_duplicate_identity_is_known() {
    let (model, authority, resource, _) = basic();
    let mut old = map(&authority, resource);
    let (second, _) = disjoint_resource();
    let ready = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    {
        let mut state = model.state.lock().unwrap();
        state.mode = Mode::DuplicateToken;
        state.reply_gates = Some((Arc::clone(&ready), Arc::clone(&release)));
    }
    let (retire, attempted, outcome) = std::thread::scope(|scope| {
        let pending = scope.spawn(|| map_retry(&authority, second));
        ready.wait();
        // SAFETY: model users stopped; the unchecked response must still
        // exclude teardown until identity validation finishes.
        let retire = unsafe { old.retire() };
        let attempted = model
            .state
            .lock()
            .unwrap()
            .events
            .contains(&"unmap requested");
        release.wait();
        (retire, attempted, pending.join().unwrap())
    });
    assert_eq!(retire, Err(Error::Busy));
    assert!(!attempted);
    assert!(matches!(outcome, Err(Error::InvalidPlatformReply)));
    // SAFETY: stopped old users; identity is now known to be ambiguous.
    assert_eq!(unsafe { old.retire() }, Err(Error::InvalidPlatformReply));
    assert_eq!(authority.status().unwrap().quarantined, 2);
}
#[test]
fn unmap_excludes_new_map_callbacks_until_all_root_acknowledgement() {
    let (model, authority, resource, _) = basic();
    let mut old = map(&authority, resource);
    let (second, _) = disjoint_resource();
    let ready = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    model.state.lock().unwrap().unmap_gates = Some((Arc::clone(&ready), Arc::clone(&release)));
    let (attempt, calls, live) = std::thread::scope(|scope| {
        // SAFETY: model consumers stopped; modeled root/cache/TLB
        // acknowledgement is held until the test explicitly admits it.
        let retiring = scope.spawn(|| unsafe { old.retire() });
        ready.wait();
        let attempt = authority.map(
            second.clone(),
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        );
        let calls = model.calls();
        let live = model.live();
        release.wait();
        retiring.join().unwrap().unwrap();
        (attempt, calls, live)
    });
    assert!(matches!(attempt, Err(Error::Busy)));
    assert_eq!((calls, live), (1, 1));
    model.state.lock().unwrap().unmap_gates = None;
    let mut next = map(&authority, second);
    // SAFETY: new model users stopped and provider now acknowledges.
    unsafe { next.retire() }.unwrap();
    assert_eq!(model.calls(), 2);
    assert_eq!(model.live(), 0);
}
