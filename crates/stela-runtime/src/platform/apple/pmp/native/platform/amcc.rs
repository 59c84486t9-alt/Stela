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
use stela_contracts::refuse;

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
            return Err(Error::Contract(refuse!(
                "AMCC MC-event copy has unfinished work or foreign geometry"
            )));
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
            return Err(Error::Contract(refuse!(
                "AMCC Capture has unfinished prior work"
            )));
        }
        descriptor(d)?;
        let capture = frames.capture_identity(captured).map_err(Error::Contract)?;
        let observed = captured.bits(16, 112).map_err(Error::Contract)?;
        if context.selected != observed & d.selection().bits() {
            return Err(Error::Contract(refuse!(
                "AMCC selection differs from its actual PTD capture"
            )));
        }
        match input {
            Input::Copied(copied) => {
                if context.activity == 0 || copied.selected() != context.selected {
                    return Err(Error::Contract(refuse!(
                        "AMCC bulk receipt differs from reached source bulk"
                    )));
                }
                frames
                    .validate_copied_capture(&copied, captured)
                    .map_err(Error::Contract)?;
                self.generic
                    .begin_capture(frames, copied, d, context, activation)?;
            }
            Input::Retained(retained) => {
                if context.activity != 0 {
                    return Err(Error::Contract(refuse!(
                        "AMCC active bulk requires its actual copy receipt"
                    )));
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
            return Err(Error::Contract(refuse!(
                "AMCC Postprocess has unfinished work"
            )));
        }
        descriptor(d)?;
        let retained = self.awaiting_post.as_ref().ok_or(Error::Contract(refuse!(
            "AMCC Postprocess requires its unreplayed Capture"
        )))?;
        if context != retained.context {
            return Err(Error::Contract(refuse!(
                "AMCC Postprocess context differs from retained Capture"
            )));
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
                .ok_or(Error::Contract(refuse!("AMCC hook has no pending work")))?;
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
                        return Err(Error::Contract(refuse!(
                            "AMCC retained buffer has foreign geometry"
                        )));
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
            .ok_or(Error::Contract(refuse!(
                "AMCC metric has no initialized source histogram"
            )))?
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
            return Err(Error::Contract(refuse!(
                "AMCC query exceeds source metric geometry"
            )));
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
            return Err(Error::Contract(refuse!(
                "AMCC group view exceeds retained T8112 cells"
            )));
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
            return Err(Error::Contract(refuse!(
                "AMCC activation reset overlaps a pending hook"
            )));
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
            return Err(Error::Contract(refuse!(
                "AMCC group destination must already own64 bytes"
            )));
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
        return Err(Error::Contract(refuse!(
            "AMCC wrapper requires original checked T8112 ordinal/range"
        )));
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
        return Err(Error::Refused(refuse!(
            "AMCC specialized provider descriptor has no qualified owner"
        )));
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
            .ok_or(Error::Contract(refuse!(
                "AMCC retained timestamp cell absent"
            )))?
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
        EffectValue::Complete => Err(Error::Contract(refuse!(
            "AMCC generic hook returned no retained products"
        ))),
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
mod tests;
