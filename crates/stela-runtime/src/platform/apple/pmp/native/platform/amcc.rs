//! Specialized native AMCC Capture/Postprocess/query around the generic owner.
//!
//! Original26A434 t8112pmp SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//!1004894..100499c calls generic Capture before twelve descriptors/P85c/arrivals;
//!10049b0..1004b50 computes specialized deltas before generic Postprocess;
//!1004c90..1004d6c overrides both query slots.1003ad4..1003bc8 copies groups
//! later, in the MC event path. GroupView supplies bytes, never that timing,
//! event completion, hardware counter production, IRQ state or a command ACK.
use super::super::counters::{CaptureIdentity, Captured, Copied, Frame, Frames, Retained};
use super::ingestion::{self, Backend, Pair, Statistics};
use super::owner::{CounterContext, EffectValue};
use super::{CounterReference, Descriptor};
use alloc::rc::Rc;
use stela_contracts::bus::Access;

pub use ingestion::{Error, Progress};
const TIME_MASK: u64 = (1 << 54) - 1;
const METRICS: usize = 12;
const GROUPS: usize = 24;
const GROUP_ENTRIES: usize = 4;
const GROUP_BYTES: usize = GROUP_ENTRIES * 16;
const PREFIX: usize = 16;

/// Source software configuration, not observed counter or activation state.
/// The twelve original T8112 specialized descriptors are all absent. Declared
/// local overrides preserve their complete words; unsupported providers refuse
/// after the generic Capture prefix, rather than silently becoming empty data.
#[derive(Clone, Debug)]
pub struct Configuration {
    generic: ingestion::Configuration,
    references: [CounterReference; METRICS],
}
impl Configuration {
    pub fn t8112(d: &Descriptor) -> Result<Self, Error> {
        Self::declared_t8112(d, [CounterReference::default(); METRICS])
    }
    pub fn declared_t8112(
        d: &Descriptor,
        references: [CounterReference; METRICS],
    ) -> Result<Self, Error> {
        descriptor(d)?;
        Ok(Self {
            generic: ingestion::Configuration::t8112(d)?,
            references,
        })
    }
    pub fn references(&self) -> &[CounterReference; METRICS] {
        &self.references
    }
}

/// Move the real copy receipt when source P10 is nonzero. The no-bulk path
/// keeps same-owner storage without consuming any selected entry.
pub enum Input {
    Copied(Copied),
    Retained(Retained),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Query {
    /// Source vtable+50: generic P3b0, specialized P5b8.
    Slot50,
    /// Source vtable+58: generic P3c8, specialized P5e8.
    Slot58,
}
#[derive(Clone, Copy)]
enum Phase {
    CaptureBase,
    Capture(usize),
    Post(usize),
    PostBaseBegin,
    PostBase,
}
struct Batch {
    phase: Phase,
    context: CounterContext,
    activation: u32,
    descriptor: Descriptor,
    capture: CaptureIdentity,
}
struct CapturedState {
    context: CounterContext,
    capture: CaptureIdentity,
}

/// Sole specialized software fields. The generic owner keeps its
/// input receipt; this wrapper never clones it or reconsumes PTD entries.
pub struct Owner<B: Backend> {
    identity: Rc<()>,
    generic: ingestion::Owner<B>,
    config: Configuration,
    pairs: [[Pair; 2]; METRICS],
    metrics: [[u32; 3]; 4],
    rates: [[u32; 3]; 4],
    statistics: [[Option<Statistics>; 3]; 4],
    packet_low: u32,
    arrived: u128,
    batch: Option<Batch>,
    awaiting_post: Option<CapturedState>,
}
impl<B: Backend> Owner<B> {
    /// Explicit source software initialization; none of these zeros describes
    /// hardware reset, a produced frame, a completed provider or readiness.
    pub fn initialized_software(config: Configuration, backend: B) -> Result<Self, Error> {
        let mut statistics = core::array::from_fn(|_| core::array::from_fn(|_| None));
        for (g, row) in statistics.iter_mut().enumerate() {
            for (k, stat) in row.iter_mut().enumerate() {
                if configured(&config.references, g, k) {
                    //101c1a8: cfg25c128 means range128 ->32bins/shift2.
                    *stat = Some(Statistics::from_source_layout(32, 2)?);
                }
            }
        }
        Ok(Self {
            identity: Rc::new(()),
            generic: ingestion::Owner::initialized_software(config.generic.clone(), backend),
            config,
            pairs: [[Pair::default(); 2]; METRICS],
            metrics: [[0; 3]; 4],
            rates: [[0; 3]; 4],
            statistics,
            packet_low: 0,
            arrived: 0,
            batch: None,
            awaiting_post: None,
        })
    }
    pub fn generic(&self) -> &ingestion::Owner<B> {
        &self.generic
    }
    pub(in crate::platform::apple::pmp::native) fn identity(&self) -> Rc<()> {
        self.identity.clone()
    }
    /// The later MC event's source1003ad8..1003bbc operation, not Capture.
    /// Copy every selected group before clearing low96 arrival bits.
    /// Unequal masks leave both destinations and arrivals untouched.
    pub(in crate::platform::apple::pmp::native) fn copy_completed_groups(
        &mut self,
        frames: &Frames,
        expected: u128,
        destination: &mut [[u8; GROUP_BYTES]],
    ) -> Result<Option<u32>, Error> {
        if self.batch.is_some() || self.awaiting_post.is_some() || destination.len() != GROUPS {
            return Err(Error::Contract(
                "AMCC MC-event copy has unfinished work or foreign geometry",
            ));
        }
        if expected != self.arrived {
            return Ok(None);
        }
        // Source1003b34 skips the frame read for every empty group. When a
        // copy is reached, preflight the full buffer before any write.
        let low_mask = (1u128 << (4 * GROUPS)) - 1;
        if self.arrived & low_mask != 0 {
            self.generic.cells(frames)?;
        }
        let mut copied = 0;
        for (group, out) in destination.iter_mut().enumerate() {
            if self.arrived & (15u128 << (4 * group)) != 0 {
                self.group(frames, group)?.copy_into_existing(out)?;
                copied |= 1 << group;
            }
        }
        self.arrived &= !low_mask;
        Ok(Some(copied))
    }
    pub fn group_count(&self) -> usize {
        GROUPS
    }
    pub fn packet_low(&self) -> u32 {
        self.packet_low
    }
    /// Observed source software arrival, never expected selection or an ACK.
    pub fn arrivals(&self) -> u128 {
        self.arrived
    }
    pub fn metrics(&self) -> &[[u32; 3]; 4] {
        &self.metrics
    }
    pub fn rates(&self) -> &[[u32; 3]; 4] {
        &self.rates
    }
    pub fn statistics(&self) -> &[[Option<Statistics>; 3]; 4] {
        &self.statistics
    }
    pub fn begin_capture(
        &mut self,
        frames: &Frames,
        captured: &Captured,
        input: Input,
        d: &Descriptor,
        context: CounterContext,
        activation: u32,
    ) -> Result<(), Error> {
        // A prior-pending-only Capture does not increment P14. The source
        // dispatcher may omit its Postprocess unless forced; the next
        // Capture then replaces that optional post context. The dispatcher
        // still owns whether to call the prior post hook.
        if self.batch.is_some()
            || self
                .awaiting_post
                .as_ref()
                .is_some_and(|s| s.context.evaluated != 0 || s.context.pending != 1)
        {
            return Err(Error::Contract("AMCC Capture has unfinished prior work"));
        }
        descriptor(d)?;
        let capture = frames.capture_identity(captured).map_err(Error::Contract)?;
        let observed = captured.bits(16, 112).map_err(Error::Contract)?;
        if context.selected != observed & d.selection().bits() {
            return Err(Error::Contract(
                "AMCC selection differs from its actual PTD capture",
            ));
        }
        match input {
            Input::Copied(copied) => {
                if context.activity == 0 || copied.selected() != context.selected {
                    return Err(Error::Contract(
                        "AMCC bulk receipt differs from reached source bulk",
                    ));
                }
                frames
                    .validate_copied_capture(&copied, captured)
                    .map_err(Error::Contract)?;
                self.generic
                    .begin_capture(frames, copied, d, context, activation)?;
            }
            Input::Retained(retained) => {
                if context.activity != 0 {
                    return Err(Error::Contract(
                        "AMCC active bulk requires its actual copy receipt",
                    ));
                }
                self.generic
                    .begin_retained_capture(frames, retained, d, context, activation)?;
            }
        }
        self.awaiting_post = None;
        self.batch = Some(Batch {
            phase: Phase::CaptureBase,
            context,
            activation,
            descriptor: d.clone(),
            capture,
        });
        Ok(())
    }
    pub fn begin_postprocess(
        &mut self,
        frames: &Frames,
        d: &Descriptor,
        context: CounterContext,
        activation: u32,
    ) -> Result<(), Error> {
        if self.batch.is_some() {
            return Err(Error::Contract("AMCC Postprocess has unfinished work"));
        }
        descriptor(d)?;
        let retained = self.awaiting_post.as_ref().ok_or(Error::Contract(
            "AMCC Postprocess requires its unreplayed Capture",
        ))?;
        if context != retained.context {
            return Err(Error::Contract(
                "AMCC Postprocess context differs from retained Capture",
            ));
        }
        frames
            .validate_capture_identity(&retained.capture)
            .map_err(Error::Contract)?;
        self.generic.cells(frames)?;
        let retained = self.awaiting_post.take().unwrap();
        self.batch = Some(Batch {
            phase: Phase::Post(0),
            context,
            activation,
            descriptor: d.clone(),
            capture: retained.capture,
        });
        Ok(())
    }
    pub fn advance(&mut self, frames: &Frames, access: &mut Access<'_>) -> Result<Progress, Error> {
        loop {
            let batch = self
                .batch
                .as_ref()
                .ok_or(Error::Contract("AMCC hook has no pending work"))?;
            frames
                .validate_capture_identity(&batch.capture)
                .map_err(Error::Contract)?;
            match batch.phase {
                Phase::CaptureBase => match self.generic.advance(frames, access)? {
                    Progress::Busy { deadline } => return Ok(Progress::Busy { deadline }),
                    Progress::Complete(value) => {
                        let batch = self.batch.as_mut().unwrap();
                        products(&mut batch.context, value)?;
                        batch.phase = Phase::Capture(0);
                    }
                },
                Phase::Capture(index) if index < METRICS => {
                    let r = self.config.references[index];
                    if r.kind != 0 {
                        let context = self.batch.as_ref().unwrap().context;
                        let cells = self.generic.cells(frames)?;
                        self.pairs[index][(!context.buffer_index & 1) as usize] =
                            local_pair(r, cells, context)?;
                    }
                    self.batch.as_mut().unwrap().phase = Phase::Capture(index + 1);
                }
                Phase::Capture(_) => {
                    let cells = self.generic.cells(frames)?;
                    if cells.len() != 112 {
                        return Err(Error::Contract("AMCC retained buffer has foreign geometry"));
                    }
                    let batch = self.batch.take().unwrap();
                    self.packet_low = batch.context.current_packet.0[0] as u32 & 15;
                    self.arrived |= shift_arrival(batch.context.selected, 2);
                    let value = hook(batch.context);
                    self.awaiting_post = Some(CapturedState {
                        context: batch.context,
                        capture: batch.capture,
                    });
                    return Ok(Progress::Complete(value));
                }
                Phase::Post(index) if index < METRICS => {
                    self.generic.cells(frames)?;
                    let context = self.batch.as_ref().unwrap().context;
                    self.post_metric(index, context)?;
                    self.batch.as_mut().unwrap().phase = Phase::Post(index + 1);
                }
                Phase::Post(_) => self.batch.as_mut().unwrap().phase = Phase::PostBaseBegin,
                Phase::PostBaseBegin => {
                    let batch = self.batch.as_ref().unwrap();
                    self.generic.begin_postprocess(
                        frames,
                        &batch.descriptor,
                        batch.context,
                        batch.activation,
                    )?;
                    self.batch.as_mut().unwrap().phase = Phase::PostBase;
                }
                Phase::PostBase => match self.generic.advance(frames, access)? {
                    Progress::Busy { deadline } => return Ok(Progress::Busy { deadline }),
                    Progress::Complete(value) => {
                        self.batch = None;
                        return Ok(Progress::Complete(value));
                    }
                },
            }
        }
    }
    fn post_metric(&mut self, index: usize, context: CounterContext) -> Result<(), Error> {
        let g = index / 3;
        let k = index % 3;
        let r = self.config.references[index];
        if r.kind != 0 {
            let d = ingestion::scaled_delta(
                context.buffer_index,
                r,
                self.pairs[index],
                self.config.generic.periods(),
            )?;
            self.metrics[g][k] = d.value as u32;
            self.rates[g][k] = (d
                .value
                .wrapping_mul(1_000_000)
                .checked_div(d.micros)
                .unwrap_or(0)
                >> 20) as u32;
        } else if k == 2 && configured(&self.config.references, g, k) {
            self.metrics[g][k] = self.metrics[g][0].wrapping_add(self.metrics[g][1]);
            self.rates[g][k] = self.rates[g][0].wrapping_add(self.rates[g][1]);
        } else {
            return Ok(());
        }
        self.statistics[g][k]
            .as_mut()
            .ok_or(Error::Contract(
                "AMCC metric has no initialized source histogram",
            ))?
            .record(self.rates[g][k] >> 10);
        Ok(())
    }
    /// Both source query slots have specialized fallback behavior. Slot50 is
    /// not an alias of generic.query() or of generic rates.
    pub fn query(
        &self,
        slot: Query,
        evaluated: u32,
        selector: u32,
        kind: u32,
    ) -> Result<u32, Error> {
        if evaluated != 1 {
            return Ok(0);
        }
        if selector >= 6 || kind >= 3 {
            return Err(Error::Contract("AMCC query exceeds source metric geometry"));
        }
        let kind = kind as usize;
        let special = if slot == Query::Slot50 {
            &self.rates
        } else {
            &self.metrics
        };
        if selector >= 2 {
            return Ok(special[(selector - 2) as usize][kind]);
        }
        let g = selector as usize;
        let refs = self.config.generic.references();
        if configured(refs, g, kind) {
            let generic = if slot == Query::Slot50 {
                self.generic.metrics()
            } else {
                self.generic.rates()
            };
            return Ok(generic[g][kind]);
        }
        Ok(if selector == 0 {
            special
                .iter()
                .fold(0u32, |sum, row| sum.wrapping_add(row[kind]))
        } else {
            0
        })
    }
    /// Source MC group bytes, revalidated through the generic
    /// receipt on every new view. The later MC event owner decides when to copy.
    pub fn group<'a>(&self, frames: &'a Frames, group: usize) -> Result<GroupView<'a>, Error> {
        let cells = self.generic.cells(frames)?;
        if group >= GROUPS || cells.len() != 112 {
            return Err(Error::Contract(
                "AMCC group view exceeds retained T8112 cells",
            ));
        }
        let start = PREFIX + GROUP_ENTRIES * group;
        Ok(GroupView {
            cells: &cells[start..start + GROUP_ENTRIES],
        })
    }
    /// Source activation store resets generic P14 only; AMCC buffers,
    /// metrics and arrival words survive. This is not activation completion.
    pub fn apply_source_activation_reset(&mut self) -> Result<(), Error> {
        if self.batch.is_some() {
            return Err(Error::Contract(
                "AMCC activation reset overlaps a pending hook",
            ));
        }
        self.generic.apply_source_activation_reset()?;
        self.awaiting_post = None;
        Ok(())
    }
}
/// Borrowed data only; it carries no event-stage, arrival-clear or ACK permission.
pub struct GroupView<'a> {
    cells: &'a [Frame],
}
impl GroupView<'_> {
    pub fn copy_into_existing(&self, destination: &mut [u8]) -> Result<(), Error> {
        if destination.len() != GROUP_BYTES {
            return Err(Error::Contract(
                "AMCC group destination must already own64 bytes",
            ));
        }
        for (cell, out) in self.cells.iter().zip(destination.as_chunks_mut::<16>().0) {
            out[..8].copy_from_slice(&cell.value.to_le_bytes());
            out[8..].copy_from_slice(&cell.metadata.to_le_bytes());
        }
        Ok(())
    }
}
fn descriptor(d: &Descriptor) -> Result<(), Error> {
    if d.ordinal().index() != 1
        || d.source_id() != 2
        || d.counter_slice()
            != Some(super::Slice {
                start: 16,
                count: 112,
            })
    {
        return Err(Error::Contract(
            "AMCC wrapper requires original checked T8112 ordinal/range",
        ));
    }
    Ok(())
}
fn configured<const N: usize>(refs: &[CounterReference; N], g: usize, k: usize) -> bool {
    refs[g * 3 + k].kind != 0 || (k == 2 && (refs[g * 3].kind != 0 || refs[g * 3 + 1].kind != 0))
}
fn local_pair(
    r: CounterReference,
    cells: &[Frame],
    context: CounterContext,
) -> Result<Pair, Error> {
    if r.kind != 2 {
        return Err(Error::Refused(
            "AMCC specialized provider descriptor has no qualified owner",
        ));
    }
    let value = if context.activity == 0 {
        0
    } else {
        ingestion::extract_field(cells, r.start, r.width)?
    };
    let tick = if context.evaluated == 1 {
        context.evaluation_tick
    } else {
        cells
            .first()
            .ok_or(Error::Contract("AMCC retained timestamp cell absent"))?
            .metadata
            & TIME_MASK
    };
    Ok(Pair { value, tick })
}
fn shift_arrival(selected: u128, base_channels: u32) -> u128 {
    let shift = base_channels.wrapping_shl(3);
    if shift > 127 {
        return 0;
    }
    let words = [selected as u64, (selected >> 64) as u64];
    let bits = shift & 0x38;
    let low = words[(shift >> 6) as usize].wrapping_shr(bits);
    if shift > 63 {
        u128::from(low)
    } else {
        let high = words[1].wrapping_shr(bits);
        let low = low | words[1].wrapping_shl(bits.wrapping_neg());
        u128::from(low) | (u128::from(high) << 64)
    }
}
fn products(context: &mut CounterContext, value: EffectValue) -> Result<(), Error> {
    match value {
        EffectValue::Hook {
            buffer_index,
            state_index,
            previous_state_index,
        } => {
            context.buffer_index = buffer_index;
            context.state_index = state_index;
            context.previous_state_index = previous_state_index;
            Ok(())
        }
        EffectValue::Complete => Err(Error::Contract(
            "AMCC generic hook returned no retained products",
        )),
    }
}
fn hook(context: CounterContext) -> EffectValue {
    EffectValue::Hook {
        buffer_index: context.buffer_index,
        state_index: context.state_index,
        previous_state_index: context.previous_state_index,
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{
        Packets,
        counters::{Claim, CopyStep},
        power::DeviceTable,
    };
    use super::super::ingestion::{Call, Request, Value};
    use super::super::owner::Completion;
    use super::*;
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::Cell;
    use {
        crate::platform::apple::ptd::Ptd,
        crate::platform::apple::ptd::transport::notifications::LocalNotifications,
        crate::platform::apple::ptd::transport::notifications::NativeProfile,
        stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
        stela_contracts::bus::Width, stela_contracts::interrupt::InterruptLatch,
        stela_soc_data::ptd::Geometry, stela_soc_data::ptd::Range,
        stela_soc_data::ptd::UPDATE_OFFSET,
    };

    struct NoProviders;
    impl Backend for NoProviders {
        fn call(&mut self, _: &Request, _: &Call, _: &mut Access<'_>) -> Completion<Value> {
            Completion::Refused("authored actual provider absent")
        }
    }
    fn d() -> Descriptor {
        super::super::profile::tests::fixture().descriptors()[1].clone()
    }
    fn ctx(selected: u128) -> CounterContext {
        CounterContext {
            selected,
            evaluation_tick: 480,
            current_packet: Packets([0x43, 0, 0, 0, 0, 0]),
            activity: 1,
            buffer_index: 0,
            state_index: 0,
            previous_state_index: 0,
            evaluated: 1,
            pending: 0,
        }
    }
    fn setup() -> (Frames, LocalNotifications, InterruptLatch) {
        let range = Range {
            id: 9,
            start: 16,
            count: 144,
            name: "authored AMCC range".into(),
        };
        let live = LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        };
        let local = Ptd::initialized_local_profile(
            NativeProfile::T8112,
            Geometry::new((0x23b3c0000, 0x20000), (0x23b3d0000, 0x4000)).unwrap(),
            core::slice::from_ref(&range),
            live,
        )
        .unwrap()
        .1;
        let ids = [
            1, 2, 16, 17, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18,
        ];
        let bytes: Vec<_> = ids
            .into_iter()
            .enumerate()
            .flat_map(|(i, id)| {
                let mut row = [0u32; 31];
                row[0] = id;
                row[3] = if i == 1 {
                    14
                } else if (4..=7).contains(&i) {
                    1
                } else {
                    0
                };
                row.into_iter().flat_map(u32::to_le_bytes)
            })
            .collect();
        let table = DeviceTable::from_properties(&bytes, &[0; 8], None).unwrap();
        let frames = Frames::initialized(
            Claim::new(local.clone(), range, Rc::new(Cell::new(true))),
            &table,
            &[0xa5; 144],
        )
        .unwrap();
        (frames, local, InterruptLatch::new())
    }
    fn publish(local: &LocalNotifications, entry: u32, value: u64, latch: &mut InterruptLatch) {
        local
            .bank()
            .clone()
            .write(
                UPDATE_OFFSET + u64::from(entry) * 8,
                Width::Double,
                value,
                &mut Access::new(0, 24, latch),
            )
            .unwrap();
    }
    fn copied(
        frames: &mut Frames,
        local: &LocalNotifications,
        latch: &mut InterruptLatch,
    ) -> (Captured, Copied, u128) {
        for (entry, value) in [(16, 70 | (100 << 32)), (32, 0x1234), (124, 0x9876)] {
            publish(local, entry, value, latch);
        }
        let captured = frames.capture_pending(&Access::new(0, 48, latch)).unwrap();
        let selected = captured.bits(16, 112).unwrap() & d().selection().bits();
        frames
            .begin_copy(&captured, 1, d().selection().bits())
            .unwrap();
        while frames.step(&mut Access::new(0, 49, latch)).unwrap() != CopyStep::Complete {}
        (captured, frames.finish_copy().unwrap(), selected)
    }
    fn run(
        o: &mut Owner<NoProviders>,
        frames: &Frames,
        latch: &mut InterruptLatch,
    ) -> Result<EffectValue, Error> {
        match o.advance(frames, &mut Access::new(0, 50, latch))? {
            Progress::Complete(value) => Ok(value),
            _ => panic!("unexpected authored asynchronous AMCC provider"),
        }
    }
    #[test]
    fn actual_generic_capture_precedes_absent_special_descriptors_and_arrival() {
        let (mut frames, local, mut latch) = setup();
        let (capture, copy, selected) = copied(&mut frames, &local, &mut latch);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
        o.begin_capture(
            &frames,
            &capture,
            Input::Copied(copy),
            &d(),
            ctx(selected),
            1,
        )
        .unwrap();
        assert_eq!(o.arrivals(), 0);
        assert!(o.statistics().iter().flatten().all(Option::is_none));
        let value = run(&mut o, &frames, &mut latch).unwrap();
        assert!(matches!(
            value,
            EffectValue::Hook {
                buffer_index: 1,
                ..
            }
        ));
        assert_eq!(frames.progress().consumed, 3);
        assert_eq!(o.packet_low(), 3);
        assert_eq!(o.arrivals(), (1u128 << 0) | (1u128 << 92));
        assert_eq!(o.generic().metrics(), [[0; 3]; 2]); // Generic Postprocess has not run.
        let mut context = ctx(selected);
        products(&mut context, value).unwrap();
        o.begin_postprocess(&frames, &d(), context, 1).unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        assert_eq!(o.generic().metrics()[1], [560, 800, 1360]);
        assert_eq!(o.query(Query::Slot50, 1, 1, 0).unwrap(), 560);
        assert_eq!(
            o.query(Query::Slot58, 1, 1, 0).unwrap(),
            o.generic().rates()[1][0]
        );
        assert!(o.begin_postprocess(&frames, &d(), context, 1).is_err());
        assert_eq!(frames.progress().consumed, 3);
    }
    #[test]
    fn prior_pending_only_capture_allows_the_next_actual_cycle_without_optional_post() {
        let (mut frames, local, mut latch) = setup();
        let (first, copy, selected) = copied(&mut frames, &local, &mut latch);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
        let mut pending = ctx(selected);
        pending.evaluated = 0;
        pending.pending = 1;
        o.begin_capture(&frames, &first, Input::Copied(copy), &d(), pending, 1)
            .unwrap();
        let first_products = run(&mut o, &frames, &mut latch).unwrap();
        products(&mut pending, first_products).unwrap();
        assert_eq!(pending.buffer_index, 0);
        assert_eq!(o.generic().metrics(), [[0; 3]; 2]);
        assert_eq!(frames.progress().consumed, 3);

        let (second, copy, selected) = copied(&mut frames, &local, &mut latch);
        let retained = frames.retain_cells(1).unwrap();
        let mut bad = ctx(0);
        bad.activity = 0;
        assert!(
            o.begin_capture(&frames, &second, Input::Retained(retained), &d(), bad, 1)
                .is_err()
        );
        assert_eq!(o.awaiting_post.as_ref().unwrap().context, pending);
        assert!(o.batch.is_none());

        o.begin_capture(
            &frames,
            &second,
            Input::Copied(copy),
            &d(),
            ctx(selected),
            1,
        )
        .unwrap();
        let mut current = ctx(selected);
        products(&mut current, run(&mut o, &frames, &mut latch).unwrap()).unwrap();
        assert_eq!(current.buffer_index, 1);
        assert_eq!(frames.progress().consumed, 6);
        let retained = frames.retain_cells(1).unwrap();
        assert!(
            o.begin_capture(
                &frames,
                &second,
                Input::Retained(retained),
                &d(),
                current,
                1,
            )
            .is_err()
        ); // Evaluated Capture still requires its post hook.
        assert!(o.begin_postprocess(&frames, &d(), pending, 1).is_err());
        o.begin_postprocess(&frames, &d(), current, 1).unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        assert_eq!(frames.progress().consumed, 6);
    }
    #[test]
    fn empty_mc_event_mask_reads_no_frames_and_preserves_initialized_samples() {
        let (frames, _, _) = setup();
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
        assert!(o.generic.cells(&frames).is_err());
        let mut destination = [[0x55; GROUP_BYTES]; GROUPS];
        assert_eq!(
            o.copy_completed_groups(&frames, 0, &mut destination),
            Ok(Some(0))
        );
        assert_eq!(destination, [[0x55; GROUP_BYTES]; GROUPS]);
        assert_eq!(o.arrivals(), 0);
    }
    #[test]
    fn mc_event_copy_preflights_storage_and_clears_only_low96_arrivals() {
        let (mut frames, local, mut latch) = setup();
        let (capture, copy, selected) = copied(&mut frames, &local, &mut latch);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
        let mut context = ctx(selected);
        o.begin_capture(&frames, &capture, Input::Copied(copy), &d(), context, 1)
            .unwrap();
        products(&mut context, run(&mut o, &frames, &mut latch).unwrap()).unwrap();
        let mut destination = [[0x55; GROUP_BYTES]; GROUPS];
        assert!(
            o.copy_completed_groups(&frames, o.arrivals(), &mut destination)
                .is_err()
        );
        assert_eq!(destination, [[0x55; GROUP_BYTES]; GROUPS]);
        o.begin_postprocess(&frames, &d(), context, 1).unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        // Authored high-bit state checks the clear width, not a new producer.
        o.arrived = (1 << 100) | 1 | (1 << 92);
        let expected = o.arrivals();
        assert_eq!(
            o.copy_completed_groups(&frames, 1, &mut destination),
            Ok(None)
        );
        assert_eq!(destination, [[0x55; GROUP_BYTES]; GROUPS]);
        let (foreign, _, _) = setup();
        assert!(
            o.copy_completed_groups(&foreign, expected, &mut destination)
                .is_err()
        );
        assert_eq!(destination, [[0x55; GROUP_BYTES]; GROUPS]);
        assert_eq!(o.arrivals(), expected);
        assert_eq!(
            o.copy_completed_groups(&frames, expected, &mut destination),
            Ok(Some(1 | (1 << 23)))
        );
        assert_eq!(o.arrivals(), 1 << 100);
        assert_eq!(
            u64::from_le_bytes(destination[0][..8].try_into().unwrap()),
            0x1234
        );
        assert_eq!(
            u64::from_le_bytes(destination[23][..8].try_into().unwrap()),
            0x9876
        );
        assert_eq!(destination[1], [0x55; GROUP_BYTES]);
        assert_eq!(frames.progress().consumed, 3);
    }
    #[test]
    fn group_views_copy_exact_retained_value_metadata_without_reconsume_or_early_copy() {
        let (mut frames, local, mut latch) = setup();
        let (capture, copy, selected) = copied(&mut frames, &local, &mut latch);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
        o.begin_capture(
            &frames,
            &capture,
            Input::Copied(copy),
            &d(),
            ctx(selected),
            1,
        )
        .unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        let mut destination = [0x55; 64];
        assert!(o.group(&frames, 24).is_err());
        assert!(
            o.group(&frames, 0)
                .unwrap()
                .copy_into_existing(&mut destination[..63])
                .is_err()
        );
        assert_eq!(destination, [0x55; 64]);
        o.group(&frames, 0)
            .unwrap()
            .copy_into_existing(&mut destination)
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(destination[..8].try_into().unwrap()),
            0x1234
        );
        assert_eq!(
            u64::from_le_bytes(destination[8..16].try_into().unwrap()),
            (0xa5u64 << 56) | (1 << 54) | 24
        );
        assert_eq!(
            u64::from_le_bytes(destination[24..32].try_into().unwrap()),
            0xa5u64 << 56
        );
        o.group(&frames, 23)
            .unwrap()
            .copy_into_existing(&mut destination)
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(destination[..8].try_into().unwrap()),
            0x9876
        );
        assert_eq!(frames.progress().consumed, 3);
        let (foreign, _, _) = setup();
        assert!(o.group(&foreign, 0).is_err());
        let next = frames
            .capture_pending(&Access::new(0, 51, &mut latch))
            .unwrap();
        frames.begin_copy(&next, 1, 0).unwrap();
        frames.finish_copy().unwrap();
        assert!(o.group(&frames, 0).is_err());
    }
    #[test]
    fn unknown_special_provider_retains_generic_and_local_prefix_without_arrival() {
        let (mut frames, local, mut latch) = setup();
        let (capture, copy, selected) = copied(&mut frames, &local, &mut latch);
        let mut refs = [CounterReference::default(); 12];
        refs[0] = CounterReference {
            kind: 2,
            provider: 7,
            start: 0,
            width: 32,
            flags: 1,
            scale: 0,
        };
        refs[1] = CounterReference {
            kind: 3,
            ..CounterReference::default()
        };
        let mut o = Owner::initialized_software(
            Configuration::declared_t8112(&d(), refs).unwrap(),
            NoProviders,
        )
        .unwrap();
        o.begin_capture(
            &frames,
            &capture,
            Input::Copied(copy),
            &d(),
            ctx(selected),
            1,
        )
        .unwrap();
        assert!(matches!(
            run(&mut o, &frames, &mut latch),
            Err(Error::Refused(_))
        ));
        assert_eq!(
            o.pairs[0][0],
            Pair {
                value: 70,
                tick: 480
            }
        );
        let before = o.pairs;
        assert_eq!(o.packet_low(), 0);
        assert_eq!(o.arrivals(), 0);
        assert!(run(&mut o, &frames, &mut latch).is_err());
        assert_eq!(o.pairs, before);
        assert_eq!(frames.progress().consumed, 3);
        frames
            .capture_pending(&Access::new(0, 53, &mut latch))
            .unwrap();
        assert!(matches!(
            run(&mut o, &frames, &mut latch),
            Err(Error::Contract(_))
        ));
        assert_eq!(o.arrivals(), 0);
    }
    #[test]
    fn retained_activity_zero_does_not_copy_again_or_derive_arrival_from_expected() {
        let (mut frames, local, mut latch) = setup();
        publish(&local, 32, 777, &mut latch);
        let capture = frames
            .capture_pending(&Access::new(0, 48, &mut latch))
            .unwrap();
        let selected = capture.bits(16, 112).unwrap() & d().selection().bits();
        frames.begin_discard(&capture, 1, selected).unwrap();
        while frames.step(&mut Access::new(0, 49, &mut latch)).unwrap() != CopyStep::Complete {}
        frames.finish_discard().unwrap();
        let before = frames.progress();
        let retained = frames.retain_cells(1).unwrap();
        let mut context = ctx(selected);
        context.activity = 0;
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
        o.begin_capture(
            &frames,
            &capture,
            Input::Retained(retained),
            &d(),
            context,
            1,
        )
        .unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        assert_eq!(frames.progress(), before);
        assert_eq!(o.arrivals(), 1);
        let mut out = [0xff; 64];
        o.group(&frames, 0)
            .unwrap()
            .copy_into_existing(&mut out)
            .unwrap();
        assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), 0); // Declared software cell, not published777.
        assert_eq!(
            u64::from_le_bytes(out[8..16].try_into().unwrap()),
            0xa5u64 << 56
        );
    }
    #[test]
    fn foreign_capture_expected_masks_and_wrong_ordinal_refuse_before_source_mutation() {
        let (mut frames, local, mut latch) = setup();
        let (capture, copy, selected) = copied(&mut frames, &local, &mut latch);
        let (mut foreign, _, mut fl) = setup();
        let forged = foreign
            .capture_pending(&Access::new(0, 48, &mut fl))
            .unwrap();
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
        assert!(
            o.begin_capture(
                &frames,
                &forged,
                Input::Copied(copy),
                &d(),
                ctx(selected),
                1
            )
            .is_err()
        );
        assert_eq!(o.arrivals(), 0);
        assert!(o.batch.is_none());
        let retained = frames.retain_cells(1).unwrap();
        let mut context = ctx(u128::MAX);
        context.activity = 0;
        assert!(
            o.begin_capture(
                &frames,
                &capture,
                Input::Retained(retained),
                &d(),
                context,
                1
            )
            .is_err()
        );
        let other = super::super::profile::tests::fixture().descriptors()[0].clone();
        assert!(Configuration::t8112(&other).is_err());
        assert!(o.batch.is_none());
    }
    #[test]
    fn source_special_postprocess_scaling_low32_rates_fallback_and_histograms() {
        let mut refs = [CounterReference::default(); 12];
        refs[0] = CounterReference {
            kind: 2,
            provider: 0,
            start: 0,
            width: 32,
            flags: 1,
            scale: 3,
        };
        refs[1] = CounterReference {
            kind: 2,
            provider: 0,
            start: 32,
            width: 32,
            flags: 1,
            scale: 0,
        };
        let mut o = Owner::initialized_software(
            Configuration::declared_t8112(&d(), refs).unwrap(),
            NoProviders,
        )
        .unwrap();
        o.pairs[0] = [
            Pair {
                value: u64::MAX - 7,
                tick: 0,
            },
            Pair::default(),
        ];
        o.pairs[1] = [
            Pair {
                value: 100,
                tick: 0,
            },
            Pair::default(),
        ];
        let mut context = ctx(0);
        context.buffer_index = 1;
        for i in 0..3 {
            o.post_metric(i, context).unwrap();
        }
        let delta = (u64::MAX - 7).wrapping_mul(3);
        let micros = o.config.generic.periods().1;
        let rate = ((delta.wrapping_mul(1_000_000) / micros) >> 20) as u32;
        assert_eq!(
            o.metrics[0],
            [delta as u32, 100, (delta as u32).wrapping_add(100)]
        );
        assert_eq!(o.rates[0][0], rate);
        assert_eq!(o.rates[0][2], o.rates[0][0].wrapping_add(o.rates[0][1]));
        let stat = o.statistics[0][0].as_ref().unwrap();
        assert_eq!(stat.bins().len(), 32);
        assert_eq!(stat.retained_run(), ((rate >> 12).min(31), 1));
        assert_eq!(o.query(Query::Slot50, 1, 2, 0).unwrap(), rate);
        assert_eq!(o.query(Query::Slot58, 1, 2, 0).unwrap(), delta as u32);
    }
    #[test]
    fn query_slot50_uses_source_fallback_sum_instead_of_generic_rate_alias() {
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
        o.rates = [[u32::MAX, 7, 9], [5, 8, 10], [6, 9, 11], [7, 10, 12]];
        o.metrics = [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12]];
        assert_eq!(o.query(Query::Slot50, 1, 0, 0).unwrap(), 17);
        assert_eq!(o.query(Query::Slot58, 1, 0, 0).unwrap(), 22);
        assert_eq!(o.query(Query::Slot50, 1, 1, 0).unwrap(), 0); // Configured generic cell, not sum.
        assert_eq!(o.query(Query::Slot50, 0, u32::MAX, u32::MAX), Ok(0));
        assert!(o.query(Query::Slot50, 1, 6, 0).is_err());
        assert!(o.query(Query::Slot58, 1, 0, 3).is_err());
    }
    #[test]
    fn old_copy_cannot_claim_a_new_equal_timestamp_capture_with_equal_selection() {
        let (mut frames, local, mut latch) = setup();
        let (_first, copy, selected) = copied(&mut frames, &local, &mut latch);
        for (entry, value) in [(16, 9), (32, 8), (124, 7)] {
            publish(&local, entry, value, &mut latch);
        }
        let second = frames
            .capture_pending(&Access::new(0, 48, &mut latch))
            .unwrap();
        assert_eq!(
            second.bits(16, 112).unwrap() & d().selection().bits(),
            selected
        );
        assert!(frames.cells(&copy).is_ok());
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
        assert!(
            o.begin_capture(
                &frames,
                &second,
                Input::Copied(copy),
                &d(),
                ctx(selected),
                1
            )
            .is_err()
        );
        assert!(o.batch.is_none());
        assert_eq!(o.arrivals(), 0);
        assert_eq!(frames.progress().consumed, 3);
    }
    #[test]
    fn special_delta_wrap_and_zero_microsecond_rate_keep_source_products() {
        let mut refs = [CounterReference::default(); 12];
        refs[0] = CounterReference {
            kind: 2,
            width: 64,
            ..CounterReference::default()
        };
        let mut o = Owner::initialized_software(
            Configuration::declared_t8112(&d(), refs).unwrap(),
            NoProviders,
        )
        .unwrap();
        o.pairs[0] = [
            Pair {
                value: u64::MAX - 3,
                tick: u64::MAX - 47,
            },
            Pair { value: 5, tick: 48 },
        ];
        let mut context = ctx(0);
        context.buffer_index = 2;
        o.post_metric(0, context).unwrap();
        assert_eq!(o.metrics[0][0], 9);
        assert_eq!(o.rates[0][0], 2);
        o.pairs[0] = [
            Pair {
                value: 10,
                tick: 96,
            },
            Pair {
                value: 20,
                tick: 96,
            },
        ];
        o.post_metric(0, context).unwrap();
        assert_eq!(o.metrics[0][0], 10);
        assert_eq!(o.rates[0][0], 0);
    }
    #[test]
    fn arrival_register_shifts_preserve_zero_prefix_and_high_word_modulo_behavior() {
        let value = 0x778899aabbccddee0011223344556677u128;
        assert_eq!(shift_arrival(value, 2), value >> 16);
        assert_eq!(shift_arrival(value, 8), value >> 64);
        assert_eq!(shift_arrival(value, 16), 0);
        let low = value as u64 | (value >> 64) as u64;
        assert_eq!(
            shift_arrival(value, 0),
            u128::from(low) | (value & (!0u128 << 64))
        );
    }
    #[test]
    #[cfg(feature = "std")]
    #[ignore = "oracle: STELA_TEST_MCC_J473_DT, STELA_TEST_PMP_T8112"]
    fn original_t8112_amcc_specialized_descriptors_query_and_histogram_operands() {
        use sha2::{Digest, Sha256};
        let p = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&p)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        let word =
            |va: usize| u32::from_le_bytes(p[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap());
        let config = Configuration::t8112(&d()).unwrap();
        for (i, r) in config.references().iter().enumerate() {
            let raw = [r.kind, r.provider, r.start, r.width, r.flags, r.scale];
            assert_eq!(
                raw,
                core::array::from_fn(|j| word(0x1046ab8 + 0x27c + 24 * i + 4 * j))
            );
        }
        assert_eq!(word(0x1046ab8 + 0x278), 2);
        assert_eq!((word(0x1004cdc) >> 10) & 0xfff, 0x3b0 / 4);
        assert_eq!((word(0x1004d14) >> 10) & 0xfff, 0x3c8 / 4);
        assert_eq!((word(0x101c1d4) >> 5) & 0xffff, 32);
        let dt = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&dt)),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let root = stela_contracts::adt::Node::root(&dt).unwrap();
        let nub = root
            .child("arm-io")
            .unwrap()
            .child("pmp")
            .unwrap()
            .child("iop-pmp-nub")
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(
                nub.property("soc-device").unwrap()[124 + 12..124 + 16]
                    .try_into()
                    .unwrap()
            ),
            14
        );
    }
}
