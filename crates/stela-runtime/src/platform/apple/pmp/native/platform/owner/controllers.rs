//! Manager controller RMWs and source-ordered counter accumulation.
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
use alloc::vec::Vec;
use {
    stela_contracts::bus::Access, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width,
};

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
/// resolve through the byte-offset map. Counts and state lengths must
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

/// Stable identity for one platform slot50 call, including its parent
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
/// The fixed registry/counter owner. Busy/refusal keeps its real inner
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

/// Owns the mapped control device and registry callbacks throughout all
/// stages. Passing an MMIO proxy must keep that same physical backing; an
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
    /// The G540 storage used by every platform's P250+40 cache masks.
    /// Cloning does not create another mask array or a reset permission.
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
mod tests;
