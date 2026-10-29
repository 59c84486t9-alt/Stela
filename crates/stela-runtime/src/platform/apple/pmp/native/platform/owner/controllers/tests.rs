use super::super::super::super::Packets;
use super::super::super::Evaluation;
use super::*;
use alloc::{rc::Rc, vec};
use core::cell::RefCell;
use {
    stela_contracts::bus::Direction, stela_contracts::bus::refuse,
    stela_contracts::interrupt::InterruptLatch,
};

#[derive(Default)]
struct DeviceState {
    words: [u32; 4],
    reads: Vec<u64>,
    writes: Vec<(u64, u32)>,
    fail_write: Option<usize>,
}
struct Device(Rc<RefCell<DeviceState>>);
impl MmioDevice for Device {
    fn name(&self) -> &'static str {
        "authored native manager controls"
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        assert_eq!(width, Width::Word);
        let mut state = self.0.borrow_mut();
        state.reads.push(offset);
        Ok(u64::from(state.words[(offset / 4) as usize]))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        assert_eq!(width, Width::Word);
        let mut state = self.0.borrow_mut();
        state.writes.push((offset, value as u32));
        state.words[(offset / 4) as usize] = value as u32;
        if state.fail_write == Some(state.writes.len()) {
            Err(refuse(
                self.name(),
                offset,
                width,
                Direction::Write,
                "authored post-effect failure",
            ))
        } else {
            Ok(())
        }
    }
}
#[derive(Default)]
struct QueryState {
    attempts: Vec<CounterRequest>,
    retired: Vec<(u8, u32, u8)>,
    busy_once: bool,
    refusal_once: bool,
    retired_refusal_once: bool,
}
struct Queries(Rc<RefCell<QueryState>>);
impl Counters for Queries {
    fn read(&mut self, request: &CounterRequest, _: &mut Access<'_>) -> Completion<u32> {
        let mut q = self.0.borrow_mut();
        q.attempts.push(request.clone());
        if core::mem::take(&mut q.busy_once) {
            return Completion::Busy { deadline: Some(99) };
        }
        if core::mem::take(&mut q.refusal_once) {
            return Completion::Refused("authored callback unavailable");
        }
        q.retired.push((
            request.ordinal().index() as u8,
            request.selector(),
            request.kind(),
        ));
        Completion::Retired {
            value: u32::MAX - u32::from(request.kind()),
            refusal: core::mem::take(&mut q.retired_refusal_once)
                .then_some("authored retired callback failure"),
        }
    }
}
fn record(mask: u64, selector: u32, domain: u32) -> Vec<u8> {
    [
        0x123456789abcdef0u64.to_le_bytes().as_slice(),
        mask.to_le_bytes().as_slice(),
        selector.to_le_bytes().as_slice(),
        domain.to_le_bytes().as_slice(),
    ]
    .concat()
}
fn configuration(ids: &[u32], records: &[u8], states: &[u32]) -> Configuration {
    let list: Vec<u8> = core::iter::once(ids.len() as u32)
        .chain(ids.iter().copied())
        .flat_map(u32::to_le_bytes)
        .collect();
    let map: Vec<u8> = [8u32, 0, 12, 4]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    Configuration::new(
        &list,
        &map,
        16,
        (records.len() / 24) as u32,
        records,
        states,
    )
    .unwrap()
}
fn request(serial: u64, operation: u64, prior: Option<&Request>) -> Request {
    Request {
        owner: prior.map_or_else(|| Rc::new(()), |p| Rc::clone(&p.owner)),
        serial,
        operation,
    }
}
fn context() -> ManagerContext {
    ManagerContext {
        output: Evaluation {
            eligible: 0b10110,
            falling: 0x40,
            prior_pending: 0x80,
        },
        tick: 20,
        current_packet: Packets([0x21, 0x3, u64::MAX, 7, 8, 9]),
    }
}
fn advance(
    m: &mut Manager<Device, Queries>,
    r: &Request,
    e: ManagerEffect,
    c: ManagerContext,
) -> Completion<()> {
    let mut interrupts = InterruptLatch::default();
    let mut access = Access::new(0, 25, &mut interrupts);
    m.advance(r, e, c, &mut access)
}
type Harness = (
    Manager<Device, Queries>,
    Rc<RefCell<DeviceState>>,
    Rc<RefCell<QueryState>>,
);
fn manager(config: Configuration) -> Harness {
    let device = Rc::new(RefCell::new(DeviceState::default()));
    let queries = Rc::new(RefCell::new(QueryState::default()));
    (
        Manager::initialized_software(
            config,
            Device(Rc::clone(&device)),
            Queries(Rc::clone(&queries)),
        ),
        device,
        queries,
    )
}
fn bracket(m: &mut Manager<Device, Queries>, c: ManagerContext) -> Request {
    let r = request(1, 10, None);
    assert!(matches!(
        advance(m, &r, ManagerEffect::BeforeCapture, c),
        Completion::Retired { .. }
    ));
    let restore = request(1, 20, Some(&r));
    assert!(matches!(
        advance(m, &restore, ManagerEffect::RestoreControllers, c),
        Completion::Retired { .. }
    ));
    r
}
#[test]
fn complete_source_lists_retain_opaque_records_and_resolve_controller_offsets() {
    let bytes = record(0x16, 17, 1);
    let c = configuration(&[3, 0, 3], &bytes, &[2, 3]);
    assert_eq!(c.controller_offsets(), &[4, 8, 4]);
    assert_eq!(c.records().next().unwrap().as_slice(), bytes);
    for list in [
        vec![],
        1u32.to_le_bytes().to_vec(),
        [5u32, 0, 0, 0, 0, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    ] {
        assert!(Configuration::new(&list, &[], 16, 0, &[], &[]).is_err());
    }
    let list: Vec<_> = [1u32, 0].into_iter().flat_map(u32::to_le_bytes).collect();
    assert!(Configuration::new(&list, &2u32.to_le_bytes(), 16, 0, &[], &[]).is_err());
    assert!(Configuration::new(&list, &16u32.to_le_bytes(), 16, 0, &[], &[]).is_err());
    assert!(Configuration::new(&0u32.to_le_bytes(), &[], 0, 1, &bytes, &[2]).is_err());
    assert!(Configuration::new(&0u32.to_le_bytes(), &[], 0, 0, &bytes, &[2, 3]).is_err());
}
#[test]
fn controller_rmw_preserves_intervening_bits_and_repeated_source_indices() {
    let (mut m, d, _) = manager(configuration(&[3, 0, 3], &[], &[]));
    d.borrow_mut().words = [0, 0x81212345, 0x45670089, 0];
    m.scratch.test_bytes_mut().fill(0xa5);
    let c = context();
    let r = request(1, 1, None);
    assert!(m.capture_scratch().is_err());
    assert!(matches!(
        advance(&mut m, &r, ManagerEffect::BeforeCapture, c),
        Completion::Retired { .. }
    ));
    assert_eq!(m.scratch(), [0; 32]);
    m.capture_scratch().unwrap()[0] = 17;
    assert_eq!(
        d.borrow().writes,
        [(4, 0x812f2345), (8, 0x456f0089), (4, 0x812f2345)]
    );
    d.borrow_mut().words[1] ^= 0x40000001;
    d.borrow_mut().words[2] ^= 0x20000002;
    let restore = request(1, 2, Some(&r));
    let mut later = c;
    later.tick += 10;
    assert!(matches!(
        advance(&mut m, &restore, ManagerEffect::RestoreControllers, later),
        Completion::Retired { .. }
    ));
    let s = d.borrow();
    assert_eq!(s.words[1], 0xc12f2344);
    assert_eq!(s.words[2], 0x6567008b);
    assert_eq!(m.scratch()[0], 17);
    assert!(m.capture_scratch().is_err());
}
#[test]
fn uncertain_mmio_failure_keeps_actual_prefix_and_never_replays_the_write() {
    let (mut m, d, _) = manager(configuration(&[1, 0], &[], &[]));
    d.borrow_mut().fail_write = Some(2);
    let r = request(1, 1, None);
    let c = context();
    assert!(matches!(
        advance(&mut m, &r, ManagerEffect::BeforeCapture, c),
        Completion::Refused(_)
    ));
    assert_eq!(d.borrow().writes.len(), 2);
    assert_eq!(d.borrow().words[2], CONTROL_MASK);
    assert!(m.uncertain_access().is_some());
    assert!(matches!(
        advance(&mut m, &r, ManagerEffect::BeforeCapture, c),
        Completion::Refused(_)
    ));
    assert_eq!(d.borrow().writes.len(), 2);
    assert_eq!(m.saved, [Some(0), None]);
}
#[test]
fn actual_callback_pairs_use_current_packet_bucket_and_preserve_busy_and_refusal_prefixes() {
    let rows = [record(0x16, 17, 0), record(4, 28, 16)].concat();
    let mut states = vec![4; 17];
    states[0] = 2;
    let (mut m, _, q) = manager(configuration(&[], &rows, &states));
    let c = context();
    let r = bracket(&mut m, c);
    m.buckets[0][1][0] = u64::MAX - 1;
    let a = request(1, 30, Some(&r));
    q.borrow_mut().busy_once = true;
    assert_eq!(
        advance(&mut m, &a, ManagerEffect::AccumulateCounters, c),
        Completion::Busy { deadline: Some(99) }
    );
    q.borrow_mut().refusal_once = true;
    assert!(matches!(
        advance(&mut m, &a, ManagerEffect::AccumulateCounters, c),
        Completion::Refused(_)
    ));
    q.borrow_mut().retired_refusal_once = true;
    assert!(matches!(
        advance(&mut m, &a, ManagerEffect::AccumulateCounters, c),
        Completion::Refused(_)
    ));
    assert_eq!(m.buckets[0][1], [u64::from(u32::MAX) - 2, 0]);
    assert!(matches!(
        advance(&mut m, &a, ManagerEffect::AccumulateCounters, c),
        Completion::Retired { .. }
    ));
    let q = q.borrow();
    assert!(q.attempts[0].same_operation(&q.attempts[1]));
    assert!(q.attempts[1].same_operation(&q.attempts[2]));
    assert!(!q.attempts[2].same_operation(&q.attempts[3]));
    assert_eq!(
        q.retired,
        [
            (1, 17, 0),
            (1, 17, 1),
            (2, 17, 0),
            (2, 17, 1),
            (4, 17, 0),
            (4, 17, 1),
            (2, 28, 0),
            (2, 28, 1)
        ]
    );
    assert_eq!(
        m.buckets[0][1],
        [u64::from(u32::MAX) * 3 - 2, u64::from(u32::MAX - 1) * 3]
    );
    assert_eq!(
        m.buckets[1][3],
        [u64::from(u32::MAX), u64::from(u32::MAX - 1)]
    );
    assert_eq!(m.buckets[0][0], [0, 0]);
}
#[test]
fn foreign_changed_and_stale_manager_operations_cannot_replace_the_retained_cycle() {
    let (mut m, _, q) = manager(configuration(&[], &record(2, 1, 0), &[2]));
    let c = context();
    let r = bracket(&mut m, c);
    let a = request(1, 30, Some(&r));
    q.borrow_mut().busy_once = true;
    assert!(matches!(
        advance(&mut m, &a, ManagerEffect::AccumulateCounters, c),
        Completion::Busy { .. }
    ));
    let mut changed = c;
    changed.current_packet.0[0] = 0;
    assert!(matches!(
        advance(&mut m, &a, ManagerEffect::AccumulateCounters, changed),
        Completion::Refused(_)
    ));
    assert!(matches!(
        advance(
            &mut m,
            &request(1, 30, None),
            ManagerEffect::AccumulateCounters,
            c
        ),
        Completion::Refused(_)
    ));
    assert!(matches!(
        advance(&mut m, &a, ManagerEffect::AccumulateCounters, c),
        Completion::Retired { .. }
    ));
    let calls = q.borrow().retired.len();
    assert!(matches!(
        advance(&mut m, &a, ManagerEffect::AccumulateCounters, c),
        Completion::Refused(_)
    ));
    assert!(matches!(
        advance(&mut m, &r, ManagerEffect::BeforeCapture, c),
        Completion::Refused(_)
    ));
    assert_eq!(q.borrow().retired.len(), calls);
    let next = request(2, 1, Some(&r));
    assert!(matches!(
        advance(&mut m, &next, ManagerEffect::BeforeCapture, c),
        Completion::Retired { .. }
    ));
}
#[test]
fn bucket_bounds_precede_callbacks_and_absent_eligibility_skips_even_an_invalid_packet_index() {
    let (mut m, _, q) = manager(configuration(&[], &record(2, 1, 0), &[1]));
    let c = context();
    let r = bracket(&mut m, c);
    let a = request(1, 30, Some(&r));
    assert!(matches!(
        advance(&mut m, &a, ManagerEffect::AccumulateCounters, c),
        Completion::Refused(_)
    ));
    assert!(q.borrow().attempts.is_empty());
    let (mut m, _, q) = manager(configuration(&[], &record(1 << 17, 1, 0), &[1]));
    let r = bracket(&mut m, c);
    let a = request(1, 30, Some(&r));
    assert!(matches!(
        advance(&mut m, &a, ManagerEffect::AccumulateCounters, c),
        Completion::Retired { .. }
    ));
    assert!(q.borrow().attempts.is_empty());
}

#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_PMP_T8112"]
fn original_manager_operands_pin_packet_buckets_mapping_and_allocation() {
    use sha2::{Digest, Sha256};
    let pmp = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&pmp)),
        "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
    );
    // These are full byte intervals, checked independently of the ignored
    // research extractor. Original Mach-O mapping here is VA - 0xfff000.
    for (start, end, hash) in [
        (
            0x100d350,
            0x100f398,
            "695e380297e530acc096962be77bbb96d0e7fc081db16d3e1072a489348de4fd",
        ),
        (
            0x100f398,
            0x100fb50,
            "c0a2955d8d27aafc9afbfdb4230e61e2cf515812c66884b658fb5d02b12f8654",
        ),
        (
            0x10338e4,
            0x1033a38,
            "23e41581267408139d133a098c95832f318c87717491e0bb0d4711ff8725eb2a",
        ),
        (
            0x1045fa0,
            0x10461e8,
            "11989d391f96d99d2d487ea39ec7a169ddfd90dca447ec9df575c9c37ab38500",
        ),
        (
            0x1007d04,
            0x1007da0,
            "11b5ec6736df5790c32e7a74ecfa50194005c57292ee9cce204fce5a23d96008",
        ),
    ] {
        assert_eq!(
            hex::encode(Sha256::digest(&pmp[start - 0xfff000..end - 0xfff000])),
            hash
        );
    }
    for (va, expected) in [
        (0x1033928, 0x9105e16cu32), // manager+20 <- source configuration+178
        (0x1033940, 0xa902290c),
        (0x100f8fc, 0xb86e794e), // controller ID -> byte offset
        (0x100f904, 0x32100df0), // OR bits19:16 before capture
        (0x100f908, 0x53104def),
        (0x100f9d4, 0x33100df0), // restore nibble, preserve current other bits
        (0x100f45c, 0x910283e9), // packet sp+a0
        (0x100f4e8, 0xa9002829),
        (0x100fa48, 0xa94a2beb), // bucket input is that packet, not G540
        (0x100e674, 0xb940151c), // joined DVFS count
        (0x100e678, 0xd37cef80), // count*16 bucket bytes
        (0x1007d24, 0xf900001f), // initialized software scalar is zero
        (0x100fac4, 0x8b204129), // zero-extended u32 callback return
        (0x100faf0, 0x8b204129),
    ] {
        assert_eq!(
            u32::from_le_bytes(pmp[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap()),
            expected
        );
    }
    // Compiled counts are explicit zero data, not proof that a later
    // initialized/overlaid manager configuration remains empty.
    assert_eq!(&pmp[0x1046140 - 0xfff000..0x1046144 - 0xfff000], &[0; 4]);
    assert_eq!(&pmp[0x1046188 - 0xfff000..0x104618c - 0xfff000], &[0; 4]);
}
struct MissingNativeResources;
impl crate::platform::apple::pmp::native::Resources for MissingNativeResources {
    fn inventory(&self) -> crate::platform::apple::pmp::native::Inventory {
        crate::platform::apple::pmp::native::Inventory { power_groups: 1 }
    }
    fn refresh_power_states(
        &mut self,
        _: &crate::platform::apple::pmp::native::Request,
        _: &mut Access<'_>,
    ) -> crate::platform::apple::pmp::native::Refresh {
        crate::platform::apple::pmp::native::Refresh::Refused(
            "authored native hardware unavailable",
        )
    }
    fn snapshot_observer_packets(
        &mut self,
        _: &crate::platform::apple::pmp::native::Request,
        _: &mut Access<'_>,
    ) -> crate::platform::apple::pmp::native::Refresh {
        crate::platform::apple::pmp::native::Refresh::Refused(
            "authored native observer unavailable",
        )
    }
    fn effect(
        &mut self,
        _: &crate::platform::apple::pmp::native::Request,
        _: crate::platform::apple::pmp::native::Effect,
        _: Option<&crate::platform::apple::pmp::native::PublicationTarget>,
        _: &crate::platform::apple::pmp::native::Packets,
        _: &mut Access<'_>,
    ) -> crate::platform::apple::pmp::native::Step {
        crate::platform::apple::pmp::native::Step::Refused("authored native effect unavailable")
    }
}
type CacheHarness = (
    crate::platform::apple::pmp::native::Owner<MissingNativeResources>,
    crate::platform::apple::pmp::native::counters::Frames,
    super::super::super::counter_cache::Cache,
    Manager<Device, Queries>,
);
fn cache_fixture() -> CacheHarness {
    use native::{counters::Frames, platform::counter_cache::Cache, power::DeviceTable};
    use {
        crate::platform::apple::pmp::native, crate::platform::apple::ptd::Ptd,
        crate::platform::apple::ptd::transport::notifications::NativeProfile,
        stela_contracts::bus::LifecycleState, stela_soc_data::ptd::Geometry,
        stela_soc_data::ptd::PTD_BYTES, stela_soc_data::ptd::Range,
        stela_soc_data::ptd::UPDATE_OFFSET,
    };
    let ranges: Vec<Range> = [
        (1, 0, 1),
        (2, 1, 1),
        (3, 2, 4),
        (4, 6, 1),
        (5, 8, 8),
        (6, 16, 8),
        (7, 24, 8),
        (8, 32, 8),
        (10, 64, 144),
        (11, 208, 1),
        (12, 209, 1),
        (13, 210, 1),
        (14, 211, 1),
    ]
    .into_iter()
    .map(|(id, start, count)| Range {
        id,
        start,
        count,
        name: alloc::format!("authored-{id}"),
    })
    .collect();
    let geometry = Geometry::new((0x100000, PTD_BYTES), (0x100000 + UPDATE_OFFSET, 0x800)).unwrap();
    let (_, local) = Ptd::initialized_local_profile(
        NativeProfile::T8112,
        geometry,
        &ranges,
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        },
    )
    .unwrap();
    let mut native = native::Owner::initialized(
        local,
        [1, 2, 3, 4, 5, 6, 7, 8, 0, 10, 11, 12, 13, 14, 0],
        MissingNativeResources,
    )
    .unwrap();
    let profile = native::platform::authored_profile();
    let raw: Vec<u8> = profile
        .descriptors()
        .iter()
        .flat_map(|d| d.raw_soc_device().iter().flat_map(|w| w.to_le_bytes()))
        .collect();
    let table = DeviceTable::from_properties(&raw, &0x3fff0u64.to_le_bytes(), None).unwrap();
    let frames =
        Frames::initialized(native.claim_counter_frames().unwrap(), &table, &[0; 144]).unwrap();
    let claim = native.claim_provider_frames().unwrap();
    let manager = Manager::initialized_for_native(
        configuration(&[], &[], &[]),
        Device(Rc::new(RefCell::new(DeviceState::default()))),
        Queries(Rc::new(RefCell::new(QueryState::default()))),
        native.claim_manager_read_masks().unwrap(),
    )
    .unwrap();
    assert!(native.claim_manager_read_masks().is_err());
    assert!(native.claim_provider_frames().is_err());
    let cache = Cache::initialized(
        claim,
        &[[1; 4]],
        manager.read_masks(),
        core::array::from_fn(|_| alloc::vec![0xa5;8]),
    )
    .unwrap();
    (native, frames, cache, manager)
}
#[test]
fn provider_cache_uses_actual_before_capture_masks_and_preserves_newer_ptd_until_next_reset() {
    use {stela_contracts::bus::MmioDevice, stela_soc_data::ptd::UPDATE_OFFSET};
    let (native, mut frames, mut cache, mut manager) = cache_fixture();
    let masks = manager.read_masks();
    let mut irq = InterruptLatch::default();
    let mut access = Access::new(0, 25, &mut irq);
    let captured = frames.capture_pending(&access).unwrap();
    assert!(cache.bind_capture(&frames, &captured).is_err()); // Constructor zeros are not source reset.
    let first = request(1, 1, None);
    assert!(matches!(
        manager.advance(&first, ManagerEffect::BeforeCapture, context(), &mut access),
        Completion::Retired { .. }
    ));
    cache.bind_capture(&frames, &captured).unwrap();
    let mut bank = frames.notifications().bank().clone();
    bank.write(UPDATE_OFFSET + 24 * 8, Width::Double, 0x1122, &mut access)
        .unwrap();
    let Completion::Retired {
        value: one,
        refusal: None,
    } = cache.read(&frames, &captured, 2, 0, &mut access)
    else {
        panic!("actual provider consume refused")
    };
    assert_eq!(one.value, 0x1122);
    assert!(one.copied);
    assert_eq!(one.metadata >> 56, 0xa5);
    assert_ne!(one.metadata & (1 << 54), 0);
    assert_eq!(masks.bytes()[16], 1);
    assert_eq!(manager.scratch()[16], 1);
    assert_eq!(cache.consumed(), 1);
    bank.write(UPDATE_OFFSET + 24 * 8, Width::Double, 0x3344, &mut access)
        .unwrap();
    let Completion::Retired {
        value: two,
        refusal: None,
    } = cache.read(&frames, &captured, 2, 0, &mut access)
    else {
        panic!("retained cache read refused")
    };
    assert_eq!(one, two);
    assert_eq!(cache.consumed(), 1);
    assert_ne!(bank.pending_range(24, 8).unwrap().low & 1, 0);
    let newer = frames.capture_pending(&access).unwrap();
    assert!(cache.bind_capture(&frames, &newer).is_err());
    let restore = request(1, 2, Some(&first));
    manager.advance(
        &restore,
        ManagerEffect::RestoreControllers,
        context(),
        &mut access,
    );
    let accumulate = request(1, 3, Some(&first));
    manager.advance(
        &accumulate,
        ManagerEffect::AccumulateCounters,
        context(),
        &mut access,
    );
    let next = request(2, 4, Some(&first));
    manager.advance(&next, ManagerEffect::BeforeCapture, context(), &mut access);
    assert_eq!(masks.bytes(), [0; 32]);
    cache.bind_capture(&frames, &newer).unwrap();
    let Completion::Retired {
        value: three,
        refusal: None,
    } = cache.read(&frames, &newer, 2, 0, &mut access)
    else {
        panic!("new cycle consume refused")
    };
    assert_eq!(three.value, 0x3344);
    assert_eq!(cache.consumed(), 2);
    drop(native);
}
#[test]
fn provider_cache_refuses_foreign_capture_and_abandoned_native_owner_before_consumption() {
    let (native, mut frames, mut cache, mut manager) = cache_fixture();
    let first = request(1, 1, None);
    advance(
        &mut manager,
        &first,
        ManagerEffect::BeforeCapture,
        context(),
    );
    let (_other, mut other_frames, _other_cache, mut other_manager) = cache_fixture();
    advance(
        &mut other_manager,
        &request(1, 1, None),
        ManagerEffect::BeforeCapture,
        context(),
    );
    let mut irq = InterruptLatch::default();
    let mut access = Access::new(0, 25, &mut irq);
    let foreign = other_frames.capture_pending(&access).unwrap();
    assert!(cache.bind_capture(&other_frames, &foreign).is_err());
    let own = frames.capture_pending(&access).unwrap();
    cache.bind_capture(&frames, &own).unwrap();
    drop(native);
    assert!(matches!(
        cache.read(&frames, &own, 2, 0, &mut access),
        Completion::Refused(_)
    ));
    assert_eq!(cache.consumed(), 0);
}
#[test]
fn provider_cache_rejects_unbound_and_other_recipient_masks_even_on_same_ptd() {
    use crate::platform::apple::pmp::native;
    use core::cell::Cell;
    use native::platform::counter_cache::Cache;
    use native::platform::counter_cache::Claim;
    let (fixture, _, actual_cache, actual_manager) = cache_fixture();
    let selected = [1, 2, 3, 4, 5, 6, 7, 8, 0, 10, 11, 12, 13, 14, 0];
    assert!(matches!(
        native::Owner::initialized(
            fixture.notifications().clone(),
            selected,
            MissingNativeResources,
        ),
        Err(native::Error::Contract(
            "PTD actual bank already admitted its native PMP recipient"
        ))
    ));
    let local = fixture.notifications().clone();
    let ranges = local.bank().ranges();
    let recipient = Rc::new(());
    let alive = Rc::new(Cell::new(true));
    // Explicit hostile test-only claims through native-private constructors.
    // A second real NativeOwner cannot be admitted on this PTD.
    let claim = |identity: Rc<()>| {
        Claim::new(
            identity,
            local.clone(),
            core::array::from_fn(|i| ranges.iter().find(|r| r.id == i as u32 + 5).cloned()),
            alive.clone(),
        )
    };
    let bound = Manager::initialized_for_native(
        configuration(&[], &[], &[]),
        Device(Rc::new(RefCell::new(DeviceState::default()))),
        Queries(Rc::new(RefCell::new(QueryState::default()))),
        ManagerClaim::new(recipient.clone(), local.clone(), alive.clone()),
    )
    .unwrap();
    let top = || core::array::from_fn(|_| alloc::vec![0; 8]);
    assert!(matches!(
        Cache::initialized(claim(Rc::new(())), &[[1; 4]], bound.read_masks(), top()),
        Err("provider cache and manager G540 have different native recipients")
    ));
    assert_eq!(bound.scratch(), [0; 32]);
    let accepted = Cache::initialized(
        claim(recipient.clone()),
        &[[1; 4]],
        bound.read_masks(),
        top(),
    )
    .unwrap();
    assert_eq!(accepted.consumed(), 0);
    let (unbound, _, _) = manager(configuration(&[], &[], &[]));
    assert!(matches!(
        Cache::initialized(claim(recipient), &[[1; 4]], unbound.read_masks(), top()),
        Err("provider cache requires a native-bound manager G540")
    ));
    assert_eq!(actual_cache.consumed(), 0);
    assert_eq!(actual_manager.scratch(), [0; 32]);
}
#[test]
fn provider_cache_refuses_another_native_capture_on_the_same_actual_ptd() {
    use crate::platform::apple::pmp::native;
    use native::{counters::Frames, power::DeviceTable};
    let (native, mut own_frames, mut cache, mut manager) = cache_fixture();
    assert!(matches!(
        native::Owner::initialized(
            native.notifications().clone(),
            [1, 2, 3, 4, 5, 6, 7, 8, 0, 10, 11, 12, 13, 14, 0],
            MissingNativeResources,
        ),
        Err(native::Error::Contract(
            "PTD actual bank already admitted its native PMP recipient"
        ))
    ));
    let profile = native::platform::authored_profile();
    let raw: Vec<u8> = profile
        .descriptors()
        .iter()
        .flat_map(|d| d.raw_soc_device().iter().flat_map(|w| w.to_le_bytes()))
        .collect();
    let table = DeviceTable::from_properties(&raw, &0x3fff0u64.to_le_bytes(), None).unwrap();
    // Explicit hostile test-only claim: no second native recipient exists.
    // Same physical PTD, but a fresh foreign liveness Rc must be rejected.
    let foreign_claim = native::counters::Claim::new(
        native.notifications().clone(),
        native
            .notifications()
            .bank()
            .ranges()
            .into_iter()
            .find(|r| r.id == 10)
            .unwrap(),
        Rc::new(core::cell::Cell::new(true)),
    );
    let mut foreign_frames = Frames::initialized(foreign_claim, &table, &[0; 144]).unwrap();
    assert!(
        native
            .notifications()
            .owns(foreign_frames.notifications().bank())
    );
    advance(
        &mut manager,
        &request(1, 1, None),
        ManagerEffect::BeforeCapture,
        context(),
    );
    let mut irq = InterruptLatch::default();
    let mut access = Access::new(0, 25, &mut irq);
    let foreign_capture = foreign_frames.capture_pending(&access).unwrap();
    assert_eq!(
        cache.bind_capture(&foreign_frames, &foreign_capture),
        Err("PMP frames belong to a different actual native recipient")
    );
    let own_capture = own_frames.capture_pending(&access).unwrap();
    cache.bind_capture(&own_frames, &own_capture).unwrap();
    assert!(matches!(
        cache.read(&foreign_frames, &foreign_capture, 2, 0, &mut access),
        Completion::Refused("PMP frames belong to a different actual native recipient")
    ));
    assert!(matches!(
        cache.read_bound(&foreign_frames, 2, 0, &mut access),
        Completion::Refused("PMP frames belong to a different actual native recipient")
    ));
    assert_eq!(cache.consumed(), 0);
    assert_eq!(manager.scratch(), [0; 32]);
    assert!(matches!(
        cache.read(&own_frames, &own_capture, 2, 0, &mut access),
        Completion::Retired { refusal: None, .. }
    ));
    assert_eq!(cache.consumed(), 1);
}
