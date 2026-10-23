//! Actual manager controller RMWs and source-ordered counter accumulation.
//!
//! Original T8112 PMP b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! 100f8cc..100f934 saves controller bits19:16 and clears G540; 100f990..100f9e8
//! restores those bits; 100fa18..100fb14 accumulates real slot50 results. The
//! bucket comes from the current packet at sp+a0, never G540's four provider
//! read masks. Those same bytes are lent to counter_cache, not copied.
//! 100e648..100e678 sizes each bucket array from its joined DVFS state count.
//! This owner supplies neither the outer manager tail nor counter-event/IRQ
//! production. The fixed callback owner must implement every reached query.
use super::super::Ordinal;
use super::super::counter_cache::{ManagerClaim, ReadMasks};
use super::{Completion, ManagerContext, ManagerEffect, Request};
use crate::platform::apple::bus::{Access, MmioDevice, MmioError, Width};
use alloc::vec::Vec;

type Error = &'static str;
const CONTROL_MASK: u32 = 0xf << 16;
const SAVED_CONTROLS: usize = 4;
const RECORD_BYTES: usize = 24;
const REGISTRY_MASK: u64 = (1 << 18) - 1;

#[derive(Clone, Copy, Debug)]
struct Descriptor {
    raw: [u8; RECORD_BYTES],
    eligible: u64,
    selector: u32,
    domain: usize,
    states: usize,
}

/// Complete configured lists, not inferred empty inventories. Controller IDs
/// resolve through the actual byte-offset map. Counts and state lengths must
/// come from the joined source configuration and DVFS records respectively.
pub struct Configuration {
    controls: Vec<u64>,
    descriptors: Vec<Descriptor>,
}
impl Configuration {
    pub fn new(
        control_list: &[u8],
        index_map: &[u8],
        aperture_bytes: u64,
        accumulator_count: u32,
        records: &[u8],
        state_counts: &[u32],
    ) -> Result<Self, Error> {
        let count = control_list
            .get(..4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
            .ok_or("native manager controller count is absent")?;
        if count > SAVED_CONTROLS || control_list.len() != 4 + count * 4 {
            return Err("native manager controller list exceeds its source save area");
        }
        if !index_map.len().is_multiple_of(4) {
            return Err("native manager controller index map has a partial word");
        }
        let mut controls = Vec::new();
        for b in control_list[4..].as_chunks::<4>().0 {
            let index = u32::from_le_bytes(*b) as usize;
            let offset = index
                .checked_mul(4)
                .and_then(|start| index_map.get(start..start.checked_add(4)?))
                .map(|b| u64::from(u32::from_le_bytes(b.try_into().unwrap())))
                .ok_or("native manager controller ID has no actual index-map row")?;
            if offset % 4 != 0 || offset.checked_add(4).is_none_or(|end| end > aperture_bytes) {
                return Err("native manager controller word exceeds its actual aperture");
            }
            // Repeated IDs are intentional source operations, not deduplicated.
            controls.push(offset);
        }
        if records.len() / RECORD_BYTES != accumulator_count as usize
            || !records.len().is_multiple_of(RECORD_BYTES)
        {
            return Err("native manager accumulator count differs from its complete records");
        }
        let mut descriptors = Vec::new();
        for raw in records.as_chunks::<RECORD_BYTES>().0 {
            let eligible = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            let selector = u32::from_le_bytes(raw[16..20].try_into().unwrap());
            let domain = u32::from_le_bytes(raw[20..24].try_into().unwrap()) as usize;
            let states = *state_counts
                .get(domain)
                .ok_or("native manager accumulator lacks its joined DVFS domain")?;
            if eligible & !REGISTRY_MASK != 0 || domain >= 32 || !(1..=16).contains(&states) {
                return Err(
                    "native manager accumulator geometry exceeds its source packet/registry",
                );
            }
            descriptors.push(Descriptor {
                raw: *raw,
                eligible,
                selector,
                domain,
                states: states as usize,
            });
        }
        Ok(Self {
            controls,
            descriptors,
        })
    }
    pub fn controller_offsets(&self) -> &[u64] {
        &self.controls
    }
    pub fn records(&self) -> impl Iterator<Item = &[u8; RECORD_BYTES]> {
        self.descriptors.iter().map(|d| &d.raw)
    }
}

/// Stable identity for one actual platform slot50 call, including its parent
/// manager operation. Selector/kind alone cannot distinguish repeated rows.
#[derive(Clone)]
pub struct CounterRequest {
    parent: Request,
    row: usize,
    ordinal: Ordinal,
    selector: u32,
    kind: u8,
}
impl CounterRequest {
    pub fn same_operation(&self, other: &Self) -> bool {
        self.parent.same_operation(&other.parent)
            && self.row == other.row
            && self.ordinal == other.ordinal
            && self.selector == other.selector
            && self.kind == other.kind
    }
    pub fn ordinal(&self) -> Ordinal {
        self.ordinal
    }
    pub fn selector(&self) -> u32 {
        self.selector
    }
    pub fn kind(&self) -> u8 {
        self.kind
    }
}
/// The actual fixed registry/counter owner. Busy/refusal retains its real inner
/// cursor under this request. Retired-with-refusal still returns a real result;
/// it must be accumulated once before the refusal is surfaced.
pub trait Counters {
    fn read(&mut self, request: &CounterRequest, access: &mut Access<'_>) -> Completion<u32>;
}

struct Pending {
    request: Request,
    effect: ManagerEffect,
    context: ManagerContext,
    index: usize,
    word: Option<u32>,
    remaining: Option<u64>,
    kind: u8,
    bucket: usize,
}

/// Owns the actual mapped control device and registry callbacks throughout all
/// stages. Passing an MMIO proxy must retain that same physical backing; an
/// unrelated copied word array is not an adapter to a controller. Construction
/// initializes software accumulators only; metrics registration is separate.
pub struct Manager<D, C> {
    configuration: Configuration,
    device: D,
    counters: C,
    buckets: Vec<Vec<[u64; 2]>>,
    saved: Vec<Option<u32>>,
    scratch: ReadMasks,
    cycle: Option<(Request, ManagerContext)>,
    expected: ManagerEffect,
    pending: Option<Pending>,
    uncertain: Option<MmioError>,
}
impl<D: MmioDevice, C: Counters> Manager<D, C> {
    /// Unbound software state for pure use. A provider cache rejects its masks.
    pub fn initialized_software(configuration: Configuration, device: D, counters: C) -> Self {
        Self::with_masks(configuration, device, counters, ReadMasks::initialized())
    }
    /// Bind this manager's G540 to the same live native recipient as its cache.
    /// The caller must still supply the source physical controller/aperture and
    /// source-derived configuration; the claim does not prove either mapping.
    pub fn initialized_for_native(
        configuration: Configuration,
        device: D,
        counters: C,
        claim: ManagerClaim,
    ) -> Result<Self, Error> {
        Ok(Self::with_masks(
            configuration,
            device,
            counters,
            ReadMasks::initialized_for_native(claim)?,
        ))
    }
    fn with_masks(
        configuration: Configuration,
        device: D,
        counters: C,
        scratch: ReadMasks,
    ) -> Self {
        let buckets = configuration
            .descriptors
            .iter()
            .map(|d| alloc::vec![[0; 2]; d.states])
            .collect();
        let saved = alloc::vec![None; configuration.controls.len()];
        Self {
            configuration,
            device,
            counters,
            buckets,
            saved,
            scratch,
            cycle: None,
            expected: ManagerEffect::BeforeCapture,
            pending: None,
            uncertain: None,
        }
    }
    pub fn buckets(&self) -> &[Vec<[u64; 2]>] {
        &self.buckets
    }
    pub fn scratch(&self) -> [u8; 32] {
        self.scratch.bytes()
    }
    /// The actual G540 storage used by every platform's P250+40 cache masks.
    /// Cloning does not create another mask array or a reset authority.
    pub fn read_masks(&self) -> ReadMasks {
        self.scratch.clone()
    }
    // Authored mutation for the original stage-order fixture only. Production
    // mask writes belong to the same shared provider cache and source reset.
    #[cfg(test)]
    fn capture_scratch(&mut self) -> Result<core::cell::RefMut<'_, [u8; 32]>, Error> {
        if self.pending.is_some() || self.expected != ManagerEffect::RestoreControllers {
            return Err("native manager scratch requires the completed pre-capture stage");
        }
        Ok(self.scratch.test_bytes_mut())
    }
    /// Ordinary MmioError proves no retirement boundary. Preserve it and never
    /// replay the uncertain device operation; no reset/replacement API exists.
    pub fn uncertain_access(&self) -> Option<MmioError> {
        self.uncertain
    }

    fn begin(
        &mut self,
        request: &Request,
        effect: ManagerEffect,
        context: ManagerContext,
    ) -> Result<(), Error> {
        if self.uncertain.is_some() {
            return Err("native manager MMIO effect is uncertain; replay refused");
        }
        if effect == ManagerEffect::BeforeCapture && self.pending.is_none() {
            self.scratch.preflight_reset()?;
        }
        if let Some(pending) = &self.pending {
            if !pending.request.same_operation(request)
                || pending.effect != effect
                || pending.context != context
            {
                return Err("native manager pending operation cannot be replaced");
            }
            return Ok(());
        }
        if effect != self.expected {
            return Err("native manager effects are out of source order");
        }
        if let Some((first, prior)) = &self.cycle {
            if !alloc::rc::Rc::ptr_eq(&first.owner, &request.owner) {
                return Err("native manager effect belongs to a different evaluator");
            }
            if effect == ManagerEffect::BeforeCapture {
                if request.serial <= first.serial {
                    return Err("native manager cycle is stale or already retired");
                }
            } else if request.serial != first.serial
                || context.output != prior.output
                || context.current_packet != prior.current_packet
            {
                return Err("native manager cycle packet or identity changed between hooks");
            }
        } else if effect != ManagerEffect::BeforeCapture {
            return Err("native manager controller save stage is absent");
        }
        if effect == ManagerEffect::BeforeCapture {
            self.cycle = Some((request.clone(), context));
            self.saved.fill(None);
        }
        self.pending = Some(Pending {
            request: request.clone(),
            effect,
            context,
            index: 0,
            word: None,
            remaining: None,
            kind: 0,
            bucket: 0,
        });
        Ok(())
    }

    pub fn advance(
        &mut self,
        request: &Request,
        effect: ManagerEffect,
        context: ManagerContext,
        access: &mut Access<'_>,
    ) -> Completion<()> {
        if let Err(reason) = self.begin(request, effect, context) {
            return Completion::Refused(reason);
        }
        let mut pending = self.pending.take().unwrap();
        let result = self.advance_pending(&mut pending, access);
        match result {
            Completion::Retired { .. } => {
                self.expected = match effect {
                    ManagerEffect::BeforeCapture => ManagerEffect::RestoreControllers,
                    ManagerEffect::RestoreControllers => ManagerEffect::AccumulateCounters,
                    ManagerEffect::AccumulateCounters => ManagerEffect::BeforeCapture,
                };
            }
            _ => self.pending = Some(pending),
        }
        result
    }
    fn advance_pending(&mut self, p: &mut Pending, access: &mut Access<'_>) -> Completion<()> {
        if p.effect != ManagerEffect::AccumulateCounters {
            while let Some(&offset) = self.configuration.controls.get(p.index) {
                let word = if let Some(word) = p.word {
                    word
                } else {
                    match self.device.read(offset, Width::Word, access) {
                        Ok(value) => {
                            let word = value as u32;
                            p.word = Some(word);
                            word
                        }
                        Err(error) => {
                            self.uncertain = Some(error);
                            return Completion::Refused(
                                "native manager controller read refused; effect retained as uncertain",
                            );
                        }
                    }
                };
                let value = if p.effect == ManagerEffect::BeforeCapture {
                    word | CONTROL_MASK
                } else {
                    (word & !CONTROL_MASK) | (self.saved[p.index].unwrap() << 16)
                };
                if let Err(error) = self
                    .device
                    .write(offset, Width::Word, u64::from(value), access)
                {
                    self.uncertain = Some(error);
                    return Completion::Refused(
                        "native manager controller write refused; effect retained as uncertain",
                    );
                }
                if p.effect == ManagerEffect::BeforeCapture {
                    self.saved[p.index] = Some((word & CONTROL_MASK) >> 16);
                }
                p.word = None;
                p.index += 1;
            }
            if p.effect == ManagerEffect::BeforeCapture
                && let Err(reason) = self.scratch.reset()
            {
                return Completion::Refused(reason);
            }
        } else {
            while let Some(descriptor) = self.configuration.descriptors.get(p.index) {
                let remaining = if let Some(bits) = p.remaining {
                    bits
                } else {
                    let bits = descriptor.eligible & p.context.output.eligible;
                    let bucket = ((p.context.current_packet.0[descriptor.domain / 16]
                        >> ((descriptor.domain % 16) * 4))
                        & 15) as usize;
                    if bits != 0 && bucket >= self.buckets[p.index].len() {
                        return Completion::Refused(
                            "native manager current packet exceeds joined DVFS bucket count",
                        );
                    }
                    p.remaining = Some(bits);
                    p.bucket = bucket;
                    bits
                };
                if remaining == 0 {
                    p.index += 1;
                    p.remaining = None;
                    continue;
                }
                let ordinal = Ordinal::new(remaining.trailing_zeros() as u8).unwrap();
                let request = CounterRequest {
                    parent: p.request.clone(),
                    row: p.index,
                    ordinal,
                    selector: descriptor.selector,
                    kind: p.kind,
                };
                let (value, refusal) = match self.counters.read(&request, access) {
                    Completion::Busy { deadline } => return Completion::Busy { deadline },
                    Completion::Refused(reason) => return Completion::Refused(reason),
                    Completion::Retired { value, refusal } => (value, refusal),
                };
                let total = &mut self.buckets[p.index][p.bucket][usize::from(p.kind)];
                *total = total.wrapping_add(u64::from(value));
                if p.kind == 0 {
                    p.kind = 1;
                } else {
                    p.kind = 0;
                    p.remaining = Some(remaining & (remaining - 1));
                }
                if let Some(reason) = refusal {
                    return Completion::Refused(reason);
                }
            }
        }
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::super::Packets;
    use super::super::super::Evaluation;
    use super::*;
    use crate::platform::apple::{
        bus::{Direction, refuse},
        interrupt::InterruptLatch,
    };
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;

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
        fn read(
            &mut self,
            offset: u64,
            width: Width,
            _: &mut Access<'_>,
        ) -> Result<u64, MmioError> {
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
    #[ignore = "requires original T8112 PMP via STELA_TEST_PMP_T8112"]
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
            (0x100f45c, 0x910283e9), // retained packet sp+a0
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
        use crate::platform::apple::{
            bus::LifecycleState,
            pmp::native,
            ptd::{
                Geometry, PTD_BYTES, Ptd, Range, UPDATE_OFFSET,
                transport::notifications::NativeProfile,
            },
        };
        use native::{counters::Frames, platform::counter_cache::Cache, power::DeviceTable};
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
        let geometry =
            Geometry::new((0x100000, PTD_BYTES), (0x100000 + UPDATE_OFFSET, 0x800)).unwrap();
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
        use crate::platform::apple::{bus::MmioDevice, ptd::UPDATE_OFFSET};
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
        use native::platform::counter_cache::Cache;
        let (fixture, _, _, _) = cache_fixture();
        let selected = [1, 2, 3, 4, 5, 6, 7, 8, 0, 10, 11, 12, 13, 14, 0];
        let make = || {
            native::Owner::initialized(
                fixture.notifications().clone(),
                selected,
                MissingNativeResources,
            )
            .unwrap()
        };
        // Same PTD object deliberately; native recipient identity must also match.
        let mut native = make();
        let mut foreign = make();
        let bound = Manager::initialized_for_native(
            configuration(&[], &[], &[]),
            Device(Rc::new(RefCell::new(DeviceState::default()))),
            Queries(Rc::new(RefCell::new(QueryState::default()))),
            native.claim_manager_read_masks().unwrap(),
        )
        .unwrap();
        let top = || core::array::from_fn(|_| alloc::vec![0; 8]);
        assert!(
            Cache::initialized(
                foreign.claim_provider_frames().unwrap(),
                &[[1; 4]],
                bound.read_masks(),
                top()
            )
            .is_err()
        );
        // Rejection must not claim or mutate the same source storage.
        assert_eq!(bound.scratch(), [0; 32]);
        assert!(
            Cache::initialized(
                native.claim_provider_frames().unwrap(),
                &[[1; 4]],
                bound.read_masks(),
                top()
            )
            .is_ok()
        );
        let mut unbound_native = make();
        let (unbound, _, _) = manager(configuration(&[], &[], &[]));
        assert!(
            Cache::initialized(
                unbound_native.claim_provider_frames().unwrap(),
                &[[1; 4]],
                unbound.read_masks(),
                top()
            )
            .is_err()
        );
    }
}
