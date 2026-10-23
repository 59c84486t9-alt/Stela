//! Actual PTD counter-frame capture and irreversible source-ordered copying.
//!
//! Original26A434 t8112pmp SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! VA100d54c..100d580 resolves row+c blocks to cfg64/68 entry slices;
//! VA101b3d0..101b464 skips zero selected chunks and copies in64-entry chunks;
//! VA1012c8c..1012d5c consumes ascending selected entries and reshapes metadata.
//! Exact windows: memory/counter-frame-producer-r1 in the ignored goal ledger.
//! No hardware events, lifecycle eligibility, generic provider decode, arrival
//! mask, IRQ admission, metrics completion or command ACK is supplied here.
use super::power::DeviceTable;
use crate::platform::apple::{
    bus::Access,
    ptd::{
        Range,
        transport::{Entry, notifications::LocalNotifications},
    },
};
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;

type Error = &'static str;
const ENTRIES_PER_BLOCK: u32 = 8;
const SELECTED_BITS: u32 = 128;

/// Unique association issued by the actual native PMP owner. Dropping it or
/// its frame storage never reopens admission; owner abandonment invalidates it.
pub struct Claim {
    local: LocalNotifications,
    range: Range,
    alive: Rc<Cell<bool>>,
}
impl Claim {
    pub(super) fn new(local: LocalNotifications, range: Range, alive: Rc<Cell<bool>>) -> Self {
        Self {
            local,
            range,
            alive,
        }
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        if self.alive.get() {
            Ok(())
        } else {
            Err("PMP counter-frame native owner was abandoned")
        }
    }
}

/// Source ordinal and PTD indices are different identities. These numbers
/// describe the parsed slice and grant no consumption/completion authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub ordinal: u32,
    pub start: u32,
    pub count: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub value: u64,
    /// Native copied layout: timestamp0..53, NEW54, DROPPED55, retained byte56..63.
    pub metadata: u64,
    /// Actual PTD entry copied, not proof of a hardware counter event. Initial
    /// software cells stay explicitly distinguishable from copied entries.
    pub copied: bool,
}
impl Frame {
    pub(in crate::platform::apple::pmp::native) fn initialized(top: u8) -> Self {
        Self {
            value: 0,
            metadata: u64::from(top) << 56,
            copied: false,
        }
    }
    pub(in crate::platform::apple::pmp::native) fn copy(&mut self, entry: Entry) {
        self.value = entry.value;
        self.metadata = entry.metadata >> 10
            | (entry.metadata & 2) << 53
            | (entry.metadata & 1) << 55
            | (self.metadata & (u64::MAX << 56));
        self.copied = true;
    }
}
struct Slice {
    layout: Layout,
    offset: usize,
    generation: u64,
    last_snapshot: u64,
    last_freshness: u64,
}
struct Pending {
    slice: usize,
    destination: Destination,
    selected: u128,
    remaining: u128,
    consumed: u32,
    at: u64,
    captured_generation: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Destination {
    Buffer,
    Discard,
}

/// A completed bulk-copy receipt, not completion of generic ingestion or
/// arrival publication. A later copy of this ordinal invalidates its cells.
pub struct Copied {
    owner: Rc<()>,
    generation: u64,
    layout: Layout,
    selected: u128,
    copied: u32,
    captured_at: u64,
    captured_generation: u64,
}
/// Completed source NULL-destination consumption. This grants no access to
/// copied cells and supplies no arrival, hardware event or hook completion.
pub struct Discarded {
    layout: Layout,
    selected: u128,
    consumed: u32,
    captured_at: u64,
}
impl Discarded {
    pub fn layout(&self) -> Layout {
        self.layout
    }
    pub fn selected(&self) -> u128 {
        self.selected
    }
    pub fn consumed(&self) -> u32 {
        self.consumed
    }
    pub fn captured_at(&self) -> u64 {
        self.captured_at
    }
}
/// One actual manager SOC-DEV-PKT pending capture, shared by all platform
/// evaluations and copies in that cycle. Numeric desired masks cannot create
/// it. Later manager capture invalidates it for new consumption.
pub struct Captured {
    owner: Rc<()>,
    generation: u64,
    start: u32,
    count: u32,
    chunks: Vec<u128>,
    at: u64,
}
/// Retained identity of an actual manager capture. This contains no selected
/// bits or completion claim. It lets a source callback revalidate its same
/// capture after Busy without cloning the pending observation or resurveying.
pub struct CaptureIdentity {
    owner: Rc<()>,
    generation: u64,
    start: u32,
    count: u32,
}
/// Read-only retained storage when the source skips bulk consumption. Initial
/// software bytes remain marked Frame::copied=false; this is not a copy receipt
/// or evidence of counter events, arrival, source eligibility or completion.
pub struct Retained {
    owner: Rc<()>,
    generation: u64,
    layout: Layout,
}
impl Retained {
    pub fn layout(&self) -> Layout {
        self.layout
    }
}
impl Captured {
    /// Pure selection from this retained observation, not arrival authority.
    pub fn bits(&self, start: u32, count: u32) -> Result<u128, Error> {
        let offset = start
            .checked_sub(self.start)
            .ok_or("PMP counter snapshot starts before its range")?;
        if count > SELECTED_BITS || offset.checked_add(count).is_none_or(|end| end > self.count) {
            return Err("PMP counter snapshot selection exceeds its actual capture");
        }
        if count == 0 {
            return Ok(0);
        }
        let index = (offset / SELECTED_BITS) as usize;
        let shift = offset % SELECTED_BITS;
        let mut bits = self.chunks[index] >> shift;
        if shift != 0
            && let Some(next) = self.chunks.get(index + 1)
        {
            bits |= next << (SELECTED_BITS - shift);
        }
        if count < SELECTED_BITS {
            bits &= (1u128 << count) - 1;
        }
        Ok(bits)
    }
    pub fn captured_at(&self) -> u64 {
        self.at
    }
}
impl Copied {
    pub fn layout(&self) -> Layout {
        self.layout
    }
    pub fn selected(&self) -> u128 {
        self.selected
    }
    pub fn copied(&self) -> u32 {
        self.copied
    }
    /// Stela transport observation time, not an inferred Apple lifecycle tick.
    pub fn captured_at(&self) -> u64 {
        self.captured_at
    }
}
/// Progress of either buffered copying or NULL-destination discarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyStep {
    Consumed { relative: u32 },
    Complete,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    pub captures: u64,
    pub consumed: u64,
    pub completed_copies: u64,
    pub discarded: u64,
    pub completed_discards: u64,
    pub freshness_consumed: u64,
    pub next_entry: Option<u32>,
}

/// All source-ordinal buffers for one actual native PTD recipient. Software
/// initialization clears low15 bytes and explicitly retains caller-declared
/// byte15; it never asserts original allocator/reset or counter observations.
/// Source lifecycle/selection/packet owners must invoke this at their actual
/// bulk-copy stage and separately retain all later descriptor/provider effects.
pub struct Frames {
    claim: Claim,
    identity: Rc<()>,
    slices: Vec<Slice>,
    frames: Vec<Frame>,
    pending: Option<Pending>,
    progress: Progress,
    copy_generation: u64,
}
impl Frames {
    pub(in crate::platform::apple::pmp::native) fn check_bank(
        &self,
        local: &LocalNotifications,
    ) -> Result<(), Error> {
        self.claim.check()?;
        if !self.claim.local.owns(local.bank()) {
            return Err("PMP frames belong to a different actual PTD owner");
        }
        Ok(())
    }
    pub fn initialized(
        claim: Claim,
        table: &DeviceTable,
        preserved_top_bytes: &[u8],
    ) -> Result<Self, Error> {
        claim.check()?;
        let end = claim
            .range
            .start
            .checked_add(claim.range.count)
            .ok_or("PMP counter frame source range wraps")?;
        let mut next = claim.range.start;
        let mut slices = Vec::new();
        slices
            .try_reserve_exact(table.len())
            .map_err(|_| "PMP counter slice allocation failed")?;
        for (ordinal, row) in table.records().iter().enumerate() {
            let count = row[3]
                .checked_mul(ENTRIES_PER_BLOCK)
                .filter(|count| *count <= SELECTED_BITS)
                .ok_or("PMP counter slice exceeds source128-bit selected state")?;
            let slice_end = next
                .checked_add(count)
                .filter(|last| *last <= end)
                .ok_or("PMP counter slices exceed the actual selected PTD range")?;
            slices.push(Slice {
                layout: Layout {
                    ordinal: ordinal as u32,
                    start: next,
                    count,
                },
                offset: (next - claim.range.start) as usize,
                generation: 0,
                last_snapshot: 0,
                last_freshness: 0,
            });
            next = slice_end;
        }
        if preserved_top_bytes.len() != (next - claim.range.start) as usize {
            return Err("PMP counter software image differs from its source slices");
        }
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(preserved_top_bytes.len())
            .map_err(|_| "PMP counter frame allocation failed")?;
        frames.extend(
            preserved_top_bytes
                .iter()
                .map(|top| Frame::initialized(*top)),
        );
        Ok(Self {
            claim,
            identity: Rc::new(()),
            slices,
            frames,
            pending: None,
            progress: Progress::default(),
            copy_generation: 0,
        })
    }
    pub fn layout(&self, ordinal: u32) -> Option<Layout> {
        self.slices.get(ordinal as usize).map(|slice| slice.layout)
    }
    pub fn capture_identity(&self, captured: &Captured) -> Result<CaptureIdentity, Error> {
        self.validate_capture(captured)?;
        Ok(CaptureIdentity {
            owner: self.identity.clone(),
            generation: captured.generation,
            start: captured.start,
            count: captured.count,
        })
    }
    pub fn validate_capture(&self, captured: &Captured) -> Result<(), Error> {
        self.check_capture(
            &captured.owner,
            captured.generation,
            captured.start,
            captured.count,
        )
    }
    pub fn validate_capture_identity(&self, captured: &CaptureIdentity) -> Result<(), Error> {
        self.check_capture(
            &captured.owner,
            captured.generation,
            captured.start,
            captured.count,
        )
    }
    /// A valid old buffer is not proof that this cycle copied it. In particular
    /// a newer discard preserves old cells while advancing the bulk cursor.
    pub fn validate_copied_capture(
        &self,
        copied: &Copied,
        captured: &Captured,
    ) -> Result<(), Error> {
        self.validate_capture(captured)?;
        self.cells(copied)?;
        if copied.captured_generation != captured.generation {
            return Err("PMP counter copied storage belongs to a different pending capture");
        }
        Ok(())
    }
    fn check_capture(
        &self,
        owner: &Rc<()>,
        generation: u64,
        start: u32,
        count: u32,
    ) -> Result<(), Error> {
        self.claim.check()?;
        if !Rc::ptr_eq(owner, &self.identity)
            || generation != self.progress.captures
            || start != self.claim.range.start
            || count != self.claim.range.count
        {
            return Err("PMP counter transfer requires the latest same-owner pending capture");
        }
        Ok(())
    }
    pub fn retain_cells(&self, ordinal: u32) -> Result<Retained, Error> {
        self.claim.check()?;
        let slice = self
            .slices
            .get(ordinal as usize)
            .ok_or("PMP counter ordinal is absent")?;
        self.storage(&self.identity, slice.generation, slice.layout)?;
        Ok(Retained {
            owner: self.identity.clone(),
            generation: slice.generation,
            layout: slice.layout,
        })
    }
    pub fn retained_cells(&self, retained: &Retained) -> Result<&[Frame], Error> {
        self.storage(&retained.owner, retained.generation, retained.layout)
    }
    pub fn notifications(&self) -> &LocalNotifications {
        &self.claim.local
    }
    pub fn progress(&self) -> Progress {
        Progress {
            next_entry: self.pending.as_ref().and_then(|pending| {
                (pending.remaining != 0).then(|| {
                    self.slices[pending.slice].layout.start + pending.remaining.trailing_zeros()
                })
            }),
            ..self.progress
        }
    }
    /// Manager VA100f820 captures its whole selected range in <=128-bit chunks
    /// before individual platform predicates. Retain this object through the
    /// predicates and bulk copies; do not resurvey pending state at ingestion.
    pub fn capture_pending(&mut self, access: &Access<'_>) -> Result<Captured, Error> {
        self.claim.check()?;
        if self.pending.is_some() {
            return Err("PMP counter copy still retains its captured prefix");
        }
        let generation = next(self.progress.captures)?;
        let count = self.claim.range.count;
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(count.div_ceil(SELECTED_BITS) as usize)
            .map_err(|_| "PMP counter pending capture allocation failed")?;
        let mut offset = 0;
        while offset < count {
            let width = SELECTED_BITS.min(count - offset);
            let raw = self
                .claim
                .local
                .bank()
                .pending_range(self.claim.range.start + offset, width)?;
            chunks.push(u128::from(raw.low) | u128::from(raw.high) << 64);
            offset += width;
        }
        self.progress.captures = generation;
        Ok(Captured {
            owner: self.identity.clone(),
            generation,
            start: self.claim.range.start,
            count,
            chunks,
            at: access.now,
        })
    }
    /// Select from the SAME pending capture used by the evaluator. Desired
    /// masks cannot create publications. Each platform bulk copy runs at most
    /// once per capture; separate source freshness consumption is not this stage.
    pub fn begin_copy(
        &mut self,
        captured: &Captured,
        ordinal: u32,
        desired: u128,
    ) -> Result<(), Error> {
        self.begin(captured, ordinal, desired, Destination::Buffer)
    }
    /// Source VA10112c8..10112d8 and 101164c pass a NULL destination to
    /// bulk consumption. Retain actual consume prefixes without touching any
    /// software frame byte or invalidating the previous copied-cell receipt.
    /// Activity-zero generic ingestion must not schedule a second bulk copy.
    pub fn begin_discard(
        &mut self,
        captured: &Captured,
        ordinal: u32,
        desired: u128,
    ) -> Result<(), Error> {
        self.begin(captured, ordinal, desired, Destination::Discard)
    }
    /// Source VA10115d4..10115f8 consumes the first actual slice entry into a
    /// temporary, then reads its VALUE low32 for freshness. It does not read
    /// metadata as a clock or replace the retained platform buffer. The source
    /// caller must qualify its separate freshness-arm and selection predicates.
    /// Frozen pending bits are deliberately not retested, including bit0.
    pub fn consume_freshness(
        &mut self,
        captured: &Captured,
        ordinal: u32,
        access: &mut Access<'_>,
    ) -> Result<Entry, Error> {
        self.claim.check()?;
        if self.pending.is_some() {
            return Err("PMP counter transfer still retains its captured prefix");
        }
        let slice = self.captured_slice(captured, ordinal)?;
        if slice.layout.count == 0
            || slice.last_freshness == captured.generation
            || slice.last_snapshot == captured.generation
        {
            return Err(
                "PMP first-entry freshness consumption is absent, repeated or out of order",
            );
        }
        let consumed = next(self.progress.consumed)?;
        let freshness = next(self.progress.freshness_consumed)?;
        let entry = self
            .claim
            .local
            .bank()
            .consume_entry(slice.layout.start, access)?;
        self.slices[ordinal as usize].last_freshness = captured.generation;
        self.progress.consumed = consumed;
        self.progress.freshness_consumed = freshness;
        Ok(entry)
    }
    fn captured_slice(&self, captured: &Captured, ordinal: u32) -> Result<&Slice, Error> {
        self.validate_capture(captured)?;
        self.slices
            .get(ordinal as usize)
            .ok_or("PMP counter ordinal is absent")
    }
    fn begin(
        &mut self,
        captured: &Captured,
        ordinal: u32,
        desired: u128,
        destination: Destination,
    ) -> Result<(), Error> {
        self.claim.check()?;
        if self.pending.is_some() {
            return Err("PMP counter transfer still retains its captured prefix");
        }
        let slice = self.captured_slice(captured, ordinal)?;
        if slice.last_snapshot == captured.generation {
            return Err("PMP counter platform copy already began for this pending capture");
        }
        let selected = captured.bits(slice.layout.start, slice.layout.count)? & desired;
        if destination == Destination::Buffer {
            let generation = next(self.copy_generation)?;
            self.slices[ordinal as usize].generation = generation;
            self.copy_generation = generation;
        }
        self.slices[ordinal as usize].last_snapshot = captured.generation;
        self.pending = Some(Pending {
            slice: ordinal as usize,
            destination,
            selected,
            remaining: selected,
            consumed: 0,
            at: captured.at,
            captured_generation: captured.generation,
        });
        Ok(())
    }
    #[cfg(test)]
    fn capture(&mut self, ordinal: u32, desired: u128, access: &Access<'_>) -> Result<(), Error> {
        let captured = self.capture_pending(access)?;
        self.begin_copy(&captured, ordinal, desired)
    }
    /// Consume at most one actual entry. A later failure leaves every earlier
    /// entry consumed and, when requested, cell copied. No callback, allocation
    /// or fallible step occurs between consume and its retained software effects.
    /// Frozen selection is not retested against NEW after source snapshot races.
    pub fn step(&mut self, access: &mut Access<'_>) -> Result<CopyStep, Error> {
        self.claim.check()?;
        let pending = self
            .pending
            .as_mut()
            .ok_or("PMP counter copy has no captured input")?;
        if pending.remaining == 0 {
            return Ok(CopyStep::Complete);
        }
        let consumed = next(self.progress.consumed)?;
        let discarded = if pending.destination == Destination::Discard {
            next(self.progress.discarded)?
        } else {
            self.progress.discarded
        };
        let relative = pending.remaining.trailing_zeros();
        let slice = &self.slices[pending.slice];
        let index = slice.offset + relative as usize;
        let raw = self
            .claim
            .local
            .bank()
            .consume_entry(slice.layout.start + relative, access)?;
        if pending.destination == Destination::Buffer {
            self.frames[index].copy(raw);
        }
        pending.remaining &= pending.remaining - 1;
        pending.consumed += 1;
        self.progress.consumed = consumed;
        self.progress.discarded = discarded;
        Ok(CopyStep::Consumed { relative })
    }
    /// Finish the bulk-copy stage only. Generic extraction, auxiliary providers
    /// and MC arrival OR occur later and require their own actual owners.
    pub fn finish_copy(&mut self) -> Result<Copied, Error> {
        self.claim.check()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or("PMP counter copy has no captured input")?;
        if pending.destination != Destination::Buffer {
            return Err("PMP counter discard cannot produce a copied-cell receipt");
        }
        if pending.remaining != 0 {
            return Err("PMP counter copy has unconsumed selected entries");
        }
        let completed = next(self.progress.completed_copies)?;
        let pending = self.pending.take().unwrap();
        self.progress.completed_copies = completed;
        Ok(Copied {
            owner: self.identity.clone(),
            generation: self.copy_generation,
            layout: self.slices[pending.slice].layout,
            selected: pending.selected,
            copied: pending.consumed,
            captured_at: pending.at,
            captured_generation: pending.captured_generation,
        })
    }
    pub fn finish_discard(&mut self) -> Result<Discarded, Error> {
        self.claim.check()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or("PMP counter discard has no captured input")?;
        if pending.destination != Destination::Discard || pending.remaining != 0 {
            return Err("PMP counter discard has not completed its actual consumption");
        }
        let completed = next(self.progress.completed_discards)?;
        let pending = self.pending.take().unwrap();
        self.progress.completed_discards = completed;
        Ok(Discarded {
            layout: self.slices[pending.slice].layout,
            selected: pending.selected,
            consumed: pending.consumed,
            captured_at: pending.at,
        })
    }
    pub fn cells(&self, copied: &Copied) -> Result<&[Frame], Error> {
        self.storage(&copied.owner, copied.generation, copied.layout)
    }
    fn storage(&self, owner: &Rc<()>, generation: u64, layout: Layout) -> Result<&[Frame], Error> {
        self.claim.check()?;
        if !Rc::ptr_eq(&self.identity, owner) {
            return Err("PMP counter storage requires the same-owner unchanged buffer");
        }
        let index = layout.ordinal as usize;
        let slice = self
            .slices
            .get(index)
            .ok_or("PMP counter ordinal is absent")?;
        if generation != slice.generation
            || layout != slice.layout
            || self.pending.as_ref().is_some_and(|pending| {
                pending.slice == index && pending.destination == Destination::Buffer
            })
        {
            return Err("PMP counter storage requires the same-owner unchanged buffer");
        }
        Ok(&self.frames[slice.offset..slice.offset + slice.layout.count as usize])
    }
}
fn next(value: u64) -> Result<u64, Error> {
    value
        .checked_add(1)
        .ok_or("PMP counter copy accounting exhausted before effect")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::{
        bus::{Lifecycle, LifecycleState, MmioDevice, Width},
        interrupt::InterruptLatch,
        ptd::{Geometry, Ptd, UPDATE_OFFSET, transport::notifications::NativeProfile},
    };
    use alloc::vec;
    const LIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    fn range() -> Range {
        Range {
            id: 9,
            start: 16,
            count: 144,
            name: "authored counter range".into(),
        }
    }
    fn local() -> LocalNotifications {
        Ptd::initialized_local_profile(
            NativeProfile::T8112,
            Geometry::new((0x23b3c0000, 0x20000), (0x23b3d0000, 0x4000)).unwrap(),
            &[range()],
            LIVE,
        )
        .unwrap()
        .1
    }
    fn table(counts: &[u32]) -> DeviceTable {
        let bytes: Vec<_> = counts
            .iter()
            .enumerate()
            .flat_map(|(ordinal, count)| {
                let mut row = [0u32; 31];
                row[0] = ordinal as u32;
                row[3] = *count;
                row.into_iter().flat_map(u32::to_le_bytes)
            })
            .collect();
        DeviceTable::from_properties(&bytes, &[0; 8], None).unwrap()
    }
    fn frames(local: &LocalNotifications, counts: &[u32], tops: &[u8]) -> Frames {
        Frames::initialized(
            Claim::new(local.clone(), range(), Rc::new(Cell::new(true))),
            &table(counts),
            tops,
        )
        .unwrap()
    }
    fn publish(
        local: &LocalNotifications,
        entry: u32,
        value: u64,
        at: u64,
        latch: &mut InterruptLatch,
    ) {
        local
            .bank()
            .clone()
            .write(
                UPDATE_OFFSET + u64::from(entry) * 8,
                Width::Double,
                value,
                &mut Access::new(0, at, latch),
            )
            .unwrap();
    }
    #[test]
    fn retained_software_cells_and_capture_identity_grant_no_consumption_or_arrival() {
        let local = local();
        let mut frames = frames(&local, &[0, 14, 0, 0, 1, 1, 1, 1], &[0xa5; 144]);
        let view = frames.retain_cells(1).unwrap();
        let before = frames.progress();
        assert!(
            frames
                .retained_cells(&view)
                .unwrap()
                .iter()
                .all(|f| !f.copied && f.value == 0 && f.metadata == 0xa5 << 56)
        );
        assert_eq!(frames.progress(), before);
        let mut latch = InterruptLatch::new();
        let captured = frames
            .capture_pending(&Access::new(0, 1, &mut latch))
            .unwrap();
        let identity = frames.capture_identity(&captured).unwrap();
        frames.validate_capture_identity(&identity).unwrap();
        let foreign = super::tests::frames(&local, &[0, 14, 0, 0, 1, 1, 1, 1], &[0; 144]);
        assert!(foreign.retained_cells(&view).is_err());
        assert!(foreign.validate_capture_identity(&identity).is_err());
        assert!(foreign.capture_identity(&captured).is_err());
        frames
            .capture_pending(&Access::new(0, 2, &mut latch))
            .unwrap();
        assert!(frames.validate_capture_identity(&identity).is_err());
        assert!(frames.validate_capture(&captured).is_err());
        assert!(frames.retained_cells(&view).is_ok());
        assert_eq!(frames.progress().completed_copies, 0);
        assert_eq!(frames.progress().consumed, 0);
        frames.claim.alive.set(false);
        assert!(frames.retained_cells(&view).is_err());
        assert!(frames.retain_cells(1).is_err());
    }
    #[test]
    fn retained_cells_survive_source_discard_and_refuse_a_later_partial_buffer_copy() {
        let local = local();
        let mut frames = frames(&local, &[0, 14, 0, 0, 1, 1, 1, 1], &[0; 144]);
        let mut latch = InterruptLatch::new();
        publish(&local, 16, 7, 1, &mut latch);
        let captured = frames
            .capture_pending(&Access::new(0, 2, &mut latch))
            .unwrap();
        frames.begin_copy(&captured, 1, 1).unwrap();
        let copied = drain(&mut frames, &mut latch);
        let view = frames.retain_cells(1).unwrap();
        assert_eq!(frames.retained_cells(&view).unwrap()[0].value, 7);
        publish(&local, 16, 9, 3, &mut latch);
        let captured = frames
            .capture_pending(&Access::new(0, 4, &mut latch))
            .unwrap();
        frames.begin_discard(&captured, 1, 1).unwrap();
        assert_eq!(frames.retained_cells(&view).unwrap()[0].value, 7);
        while frames.step(&mut Access::new(0, 5, &mut latch)).unwrap() != CopyStep::Complete {}
        frames.finish_discard().unwrap();
        assert_eq!(frames.retained_cells(&view).unwrap()[0].value, 7);
        assert_eq!(frames.cells(&copied).unwrap()[0].value, 7);
        assert_eq!(frames.progress().completed_copies, 1);
        assert_eq!(frames.progress().completed_discards, 1);
        publish(&local, 17, 11, 6, &mut latch);
        let captured = frames
            .capture_pending(&Access::new(0, 7, &mut latch))
            .unwrap();
        frames.begin_copy(&captured, 1, 2).unwrap();
        assert!(frames.retained_cells(&view).is_err());
        assert!(frames.retain_cells(1).is_err());
        drain(&mut frames, &mut latch);
        let view = frames.retain_cells(1).unwrap();
        assert_eq!(frames.retained_cells(&view).unwrap()[1].value, 11);
    }
    #[test]
    fn valid_old_copy_cannot_claim_a_new_equal_timestamp_capture_or_discard() {
        let local = local();
        let mut frames = frames(&local, &[0, 14, 0, 0, 1, 1, 1, 1], &[0; 144]);
        let mut latch = InterruptLatch::new();
        publish(&local, 16, 7, 1, &mut latch);
        let first = frames
            .capture_pending(&Access::new(0, 2, &mut latch))
            .unwrap();
        frames.begin_copy(&first, 1, 1).unwrap();
        let copied = drain(&mut frames, &mut latch);
        frames.validate_copied_capture(&copied, &first).unwrap();
        publish(&local, 16, 9, 1, &mut latch);
        let second = frames
            .capture_pending(&Access::new(0, 2, &mut latch))
            .unwrap();
        assert_eq!(first.captured_at(), second.captured_at());
        assert!(frames.validate_copied_capture(&copied, &second).is_err());
        frames.begin_discard(&second, 1, 1).unwrap();
        while frames.step(&mut Access::new(0, 3, &mut latch)).unwrap() != CopyStep::Complete {}
        frames.finish_discard().unwrap();
        assert_eq!(frames.cells(&copied).unwrap()[0].value, 7);
        assert!(frames.validate_copied_capture(&copied, &second).is_err());
        assert_eq!(frames.slices[1].last_snapshot, second.generation);
    }
    fn drain(frames: &mut Frames, latch: &mut InterruptLatch) -> Copied {
        while frames.step(&mut Access::new(0, 99, latch)).unwrap() != CopyStep::Complete {}
        frames.finish_copy().unwrap()
    }
    #[test]
    fn source_counts_and_declared_software_bytes_never_create_observed_frames() {
        let local = local();
        let mut frames = frames(&local, &[0, 14, 0, 0, 1, 1, 1, 1], &[0xa5; 144]);
        assert_eq!(
            frames.layout(1),
            Some(Layout {
                ordinal: 1,
                start: 16,
                count: 112
            })
        );
        assert_eq!(
            frames.layout(4),
            Some(Layout {
                ordinal: 4,
                start: 128,
                count: 8
            })
        );
        assert_eq!(frames.layout(7).unwrap().start, 152);
        let mut latch = InterruptLatch::new();
        frames
            .capture(1, u128::MAX, &Access::new(0, 7, &mut latch))
            .unwrap();
        let copied = drain(&mut frames, &mut latch);
        assert_eq!(
            (copied.selected(), copied.copied(), copied.captured_at()),
            (0, 0, 7)
        );
        assert!(frames.cells(&copied).unwrap().iter().all(|cell| *cell
            == Frame {
                value: 0,
                metadata: 0xa5 << 56,
                copied: false
            }));
        assert_eq!(frames.progress().consumed, 0);
        assert!(local.bank().requests().is_empty());
        assert_eq!(local.asserted(), 0);
    }
    #[test]
    fn actual_entries_partial_pause_overwrite_and_snapshot_races_keep_exact_prefixes() {
        let local = local();
        let mut frames = frames(&local, &[0, 14, 0, 0, 1, 1, 1, 1], &[0xa5; 144]);
        let mut latch = InterruptLatch::new();
        for entry in [16, 17, 19, 79, 80, 127, 128, 194] {
            publish(&local, entry, 1000 + u64::from(entry), 7, &mut latch);
        }
        let desired = [0, 3, 63, 64, 111]
            .into_iter()
            .fold(0u128, |mask, bit| mask | (1u128 << bit));
        frames
            .capture(1, desired, &Access::new(0, 10, &mut latch))
            .unwrap();
        assert_eq!(
            frames.step(&mut Access::new(0, 11, &mut latch)),
            Ok(CopyStep::Consumed { relative: 0 })
        );
        assert_eq!(frames.progress().next_entry, Some(19));
        let mut bank = local.bank().clone();
        bank.set_lifecycle(
            LifecycleState {
                quiesced: true,
                ..LIVE
            },
            &mut Access::new(0, 12, &mut latch),
        );
        assert!(frames.step(&mut Access::new(0, 13, &mut latch)).is_err());
        assert_eq!(frames.progress().consumed, 1);
        assert_eq!(frames.progress().next_entry, Some(19));
        assert!(
            frames
                .capture(4, u128::MAX, &Access::new(0, 13, &mut latch))
                .is_err()
        );
        assert!(frames.finish_copy().is_err());
        bank.set_lifecycle(LIVE, &mut Access::new(0, 14, &mut latch));
        publish(&local, 16, 5000, 15, &mut latch); // newer publication on already consumed prefix
        publish(&local, 80, 6000, 16, &mut latch); // overwrite creates actual DROPPED
        assert_eq!(
            bank.consume_entry(19, &mut Access::new(0, 17, &mut latch))
                .unwrap()
                .metadata
                & 2,
            2
        );
        let history = bank.requests();
        let mut order = vec![];
        while let CopyStep::Consumed { relative } =
            frames.step(&mut Access::new(0, 18, &mut latch)).unwrap()
        {
            order.push(relative);
        }
        assert_eq!(order, [3, 63, 64, 111]);
        let copied = frames.finish_copy().unwrap();
        assert_eq!(copied.selected(), desired);
        assert_eq!(copied.copied(), 5);
        let cells = frames.cells(&copied).unwrap();
        assert_eq!(cells[0].value, 1016); // never reconsumed as5000
        assert_eq!(cells[0].metadata, 0xa5 << 56 | 1 << 54 | 7);
        assert!(!cells[1].copied); // desired selection excluded real entry17
        assert_eq!(cells[3].value, 1019);
        assert_eq!(cells[3].metadata, 0xa5 << 56 | 7); // captured pending but raced consume; no NEW retest
        assert_eq!(cells[64].value, 6000);
        assert_eq!(cells[64].metadata, 0xa5 << 56 | 1 << 55 | 1 << 54 | 16);
        assert_eq!(bank.requests(), history); // copying publishes neither arrival nor ACK
        assert_eq!(frames.progress().consumed, 5);
        assert!(frames.finish_copy().is_err());
        assert!(frames.step(&mut Access::new(0, 19, &mut latch)).is_err());
        let pending = bank.pending_range(16, 128).unwrap();
        assert_eq!(
            u128::from(pending.low) | u128::from(pending.high) << 64,
            3 | 1u128 << 112
        );
        frames
            .capture(1, 1, &Access::new(0, 20, &mut latch))
            .unwrap();
        assert!(frames.cells(&copied).is_err());
        let newer = drain(&mut frames, &mut latch);
        assert_eq!(frames.cells(&newer).unwrap()[0].value, 5000);
        assert_eq!(frames.cells(&newer).unwrap()[64].value, 6000);
        assert!(frames.cells(&copied).is_err());
        assert_eq!(
            bank.consume_entry(194, &mut Access::new(0, 21, &mut latch))
                .unwrap()
                .metadata
                & 2,
            2
        );
    }
    #[test]
    fn foreign_receipts_abandonment_and_invalid_plans_refuse_without_consumption() {
        let local = local();
        for (counts, tops) in [
            (vec![17], vec![0; 136]),
            (vec![u32::MAX], vec![]),
            (vec![14, 14], vec![0; 224]),
            (vec![14], vec![0; 111]),
        ] {
            assert!(
                Frames::initialized(
                    Claim::new(local.clone(), range(), Rc::new(Cell::new(true))),
                    &table(&counts),
                    &tops
                )
                .is_err()
            );
        }
        assert!(local.bank().requests().is_empty());
        let alive = Rc::new(Cell::new(true));
        let mut a = Frames::initialized(
            Claim::new(local.clone(), range(), alive.clone()),
            &table(&[14]),
            &[0; 112],
        )
        .unwrap();
        let mut b = frames(&self::local(), &[14], &[0; 112]);
        let mut latch = InterruptLatch::new();
        a.capture(0, 0, &Access::new(0, 0, &mut latch)).unwrap();
        let copied = drain(&mut a, &mut latch);
        b.capture(0, 0, &Access::new(0, 0, &mut latch)).unwrap();
        let foreign = drain(&mut b, &mut latch);
        assert!(a.cells(&foreign).is_err());
        assert!(b.cells(&copied).is_err());
        alive.set(false);
        assert!(a.cells(&copied).is_err());
        assert!(a.capture(0, 0, &Access::new(0, 0, &mut latch)).is_err());
        assert!(a.step(&mut Access::new(0, 0, &mut latch)).is_err());
        assert!(a.finish_copy().is_err());
    }
    #[test]
    fn accounting_overflow_refuses_before_capture_or_actual_consume() {
        let local = local();
        let mut frames = frames(&local, &[14], &[0; 112]);
        let mut latch = InterruptLatch::new();
        publish(&local, 16, 9, 5, &mut latch);
        frames.progress.captures = u64::MAX;
        assert!(
            frames
                .capture(0, 1, &Access::new(0, 6, &mut latch))
                .is_err()
        );
        assert!(frames.pending.is_none());
        frames.progress.captures = 0; // authored private-state exhaustion test only
        frames
            .capture(0, 1, &Access::new(0, 6, &mut latch))
            .unwrap();
        frames.progress.consumed = u64::MAX;
        assert!(frames.step(&mut Access::new(0, 7, &mut latch)).is_err());
        assert_eq!(frames.progress().next_entry, Some(16));
        assert_eq!(
            local
                .bank()
                .consume_entry(16, &mut Access::new(0, 8, &mut latch))
                .unwrap()
                .metadata,
            5 << 10 | 2
        );
    }
    #[test]
    fn one_manager_capture_drives_all_platform_copies_without_resurvey_or_replay() {
        let local = local();
        let mut frames = frames(&local, &[0, 14, 0, 0, 1, 1, 1, 1], &[0; 144]);
        let mut latch = InterruptLatch::new();
        for entry in [16, 128, 144] {
            publish(&local, entry, u64::from(entry), 7, &mut latch);
        }
        let captured = frames
            .capture_pending(&Access::new(0, 8, &mut latch))
            .unwrap();
        assert_eq!(captured.bits(16, 112), Ok(1));
        assert_eq!(captured.bits(128, 8), Ok(1));
        assert_eq!(captured.bits(144, 8), Ok(1)); // second manager128-bit chunk
        assert!(captured.bits(15, 1).is_err());
        assert!(captured.bits(159, 2).is_err());
        publish(&local, 80, 8000, 9, &mut latch);
        publish(&local, 136, 13600, 9, &mut latch);
        assert_eq!(captured.bits(136, 8), Ok(0));
        frames.begin_copy(&captured, 1, u128::MAX).unwrap();
        let amcc = drain(&mut frames, &mut latch);
        assert_eq!(amcc.selected(), 1);
        assert!(frames.begin_copy(&captured, 1, u128::MAX).is_err());
        frames.begin_copy(&captured, 6, u128::MAX).unwrap();
        assert!(
            frames
                .capture_pending(&Access::new(0, 10, &mut latch))
                .is_err()
        );
        assert_eq!(frames.cells(&amcc).unwrap()[0].value, 16); // independent source buffer remains valid
        let agx = drain(&mut frames, &mut latch);
        assert_eq!(agx.selected(), 1);
        frames.begin_copy(&captured, 5, u128::MAX).unwrap();
        let pacc = drain(&mut frames, &mut latch);
        assert_eq!(pacc.copied(), 0);
        assert!(frames.cells(&pacc).unwrap().iter().all(|cell| !cell.copied));
        assert_eq!(frames.cells(&amcc).unwrap()[0].value, 16);
        let next = frames
            .capture_pending(&Access::new(0, 11, &mut latch))
            .unwrap();
        assert!(frames.begin_copy(&captured, 4, u128::MAX).is_err()); // stale manager capture
        assert_eq!(next.bits(16, 112), Ok(1u128 << 64));
        assert_eq!(next.bits(136, 8), Ok(1));
        frames.begin_copy(&next, 1, u128::MAX).unwrap();
        assert!(frames.cells(&amcc).is_err());
        let newer = drain(&mut frames, &mut latch);
        assert_eq!(frames.cells(&newer).unwrap()[64].value, 8000);
        assert_eq!(frames.cells(&agx).unwrap()[0].value, 144);
        let mut foreign = self::frames(&self::local(), &[0, 14, 0, 0, 1, 1, 1, 1], &[0; 144]);
        assert!(foreign.begin_copy(&next, 1, u128::MAX).is_err());
    }
    #[test]
    fn raw_metadata_layout_preserves_destination_byte_and_distinct_flags() {
        for (raw, converted) in [
            (0, 0),
            (1, 1u64 << 55),
            (2, 1u64 << 54),
            (3, 3u64 << 54),
            (0x3fc, 0),
            (u64::MAX, (1u64 << 56) - 1),
        ] {
            let mut cell = Frame::initialized(0x5a);
            cell.copy(Entry {
                value: 0x1122334455667788,
                metadata: raw,
            });
            assert_eq!(cell.value, 0x1122334455667788);
            assert_eq!(cell.metadata, 0x5a << 56 | converted);
            assert!(cell.copied);
        }
    }
    #[test]
    fn null_destination_discard_retains_cells_and_real_partial_consumption() {
        let local = local();
        let mut frames = frames(&local, &[14], &[0xa5; 112]);
        let mut latch = InterruptLatch::new();
        for entry in [16, 19] {
            publish(&local, entry, u64::from(entry), 7, &mut latch);
        }
        frames
            .capture(0, u128::MAX, &Access::new(0, 8, &mut latch))
            .unwrap();
        assert!(frames.finish_discard().is_err());
        let copied = drain(&mut frames, &mut latch);
        let before = frames.cells(&copied).unwrap().to_vec();
        for entry in [16, 17, 79, 80] {
            publish(&local, entry, 1000 + u64::from(entry), 9, &mut latch);
        }
        let captured = frames
            .capture_pending(&Access::new(0, 10, &mut latch))
            .unwrap();
        let desired = 1 | 1u128 << 63 | 1u128 << 64;
        frames.begin_discard(&captured, 0, desired).unwrap();
        assert!(frames.finish_copy().is_err());
        assert!(frames.finish_discard().is_err());
        assert_eq!(frames.cells(&copied).unwrap(), before);
        assert_eq!(
            frames.step(&mut Access::new(0, 11, &mut latch)),
            Ok(CopyStep::Consumed { relative: 0 })
        );
        let mut bank = local.bank().clone();
        bank.set_lifecycle(
            LifecycleState {
                quiesced: true,
                ..LIVE
            },
            &mut Access::new(0, 12, &mut latch),
        );
        assert!(frames.step(&mut Access::new(0, 13, &mut latch)).is_err());
        assert_eq!(frames.progress().next_entry, Some(79));
        assert_eq!(frames.progress().discarded, 1);
        assert_eq!(frames.cells(&copied).unwrap(), before);
        bank.set_lifecycle(LIVE, &mut Access::new(0, 14, &mut latch));
        publish(&local, 16, 9000, 15, &mut latch); // cannot replay the consumed prefix
        while frames.step(&mut Access::new(0, 16, &mut latch)).unwrap() != CopyStep::Complete {}
        let discarded = frames.finish_discard().unwrap();
        assert_eq!(discarded.layout(), copied.layout());
        assert_eq!(
            (
                discarded.selected(),
                discarded.consumed(),
                discarded.captured_at()
            ),
            (desired, 3, 10)
        );
        assert_eq!(frames.cells(&copied).unwrap(), before);
        assert_eq!(
            (frames.progress().consumed, frames.progress().discarded),
            (5, 3)
        );
        assert_eq!(
            (
                frames.progress().completed_copies,
                frames.progress().completed_discards
            ),
            (1, 1)
        );
        assert!(frames.finish_discard().is_err());
        assert!(frames.begin_copy(&captured, 0, desired).is_err());
        assert!(frames.begin_discard(&captured, 0, desired).is_err());
        let next = frames
            .capture_pending(&Access::new(0, 17, &mut latch))
            .unwrap();
        assert_eq!(next.bits(16, 112), Ok(3)); // newer16 and unselected17 remain pending
        assert!(frames.begin_discard(&captured, 0, desired).is_err());
        let mut foreign = self::frames(&self::local(), &[14], &[0; 112]);
        assert!(foreign.begin_discard(&next, 0, desired).is_err());
        frames.begin_copy(&next, 0, u128::MAX).unwrap();
        assert!(frames.cells(&copied).is_err());
        let newer = drain(&mut frames, &mut latch);
        assert_eq!(frames.cells(&newer).unwrap()[0].value, 9000);
        assert_eq!(frames.cells(&newer).unwrap()[1].value, 1017);
        assert_eq!(frames.cells(&newer).unwrap()[63], before[63]); // discarded input was never copied
    }
    #[test]
    fn discard_exhaustion_refuses_before_consume_or_receipt_and_empty_selection_reads_nothing() {
        let local = local();
        let mut frames = frames(&local, &[1], &[0x4a; 8]);
        let mut latch = InterruptLatch::new();
        publish(&local, 16, 100, 7, &mut latch);
        let captured = frames
            .capture_pending(&Access::new(0, 8, &mut latch))
            .unwrap();
        frames.begin_discard(&captured, 0, 1).unwrap();
        frames.progress.discarded = u64::MAX; // authored accounting exhaustion only
        assert!(frames.step(&mut Access::new(0, 9, &mut latch)).is_err());
        assert_eq!(local.bank().pending_range(16, 8).unwrap().low, 1);
        assert_eq!(frames.progress().consumed, 0);
        frames.progress.discarded = 0;
        assert_eq!(
            frames.step(&mut Access::new(0, 10, &mut latch)),
            Ok(CopyStep::Consumed { relative: 0 })
        );
        frames.progress.completed_discards = u64::MAX;
        assert!(frames.finish_discard().is_err());
        assert!(frames.pending.is_some());
        frames.progress.completed_discards = 0;
        assert_eq!(frames.finish_discard().unwrap().consumed(), 1);
        publish(&local, 16, 200, 11, &mut latch);
        let captured = frames
            .capture_pending(&Access::new(0, 12, &mut latch))
            .unwrap();
        frames.begin_discard(&captured, 0, 0).unwrap();
        assert_eq!(
            frames.step(&mut Access::new(0, 13, &mut latch)),
            Ok(CopyStep::Complete)
        );
        let empty = frames.finish_discard().unwrap();
        assert_eq!((empty.selected(), empty.consumed()), (0, 0));
        assert_eq!(local.bank().pending_range(16, 8).unwrap().low, 1);
        assert_eq!(frames.progress().consumed, 1);
        assert!(
            frames
                .frames
                .iter()
                .all(|cell| *cell == Frame::initialized(0x4a))
        );
    }
    #[test]
    fn freshness_consumes_actual_first_value_without_copy_or_retesting_frozen_bits() {
        let local = local();
        let mut frames = frames(&local, &[1, 0], &[0x6a; 8]);
        let mut latch = InterruptLatch::new();
        publish(&local, 16, 0xfeed00000007, 42, &mut latch);
        publish(&local, 17, 17, 43, &mut latch);
        let captured = frames
            .capture_pending(&Access::new(0, 44, &mut latch))
            .unwrap();
        assert!(
            frames
                .consume_freshness(&captured, 1, &mut Access::new(0, 44, &mut latch))
                .is_err()
        );
        let mut foreign = self::frames(&self::local(), &[1], &[0; 8]);
        assert!(
            foreign
                .consume_freshness(&captured, 0, &mut Access::new(0, 44, &mut latch))
                .is_err()
        );
        let entry = frames
            .consume_freshness(&captured, 0, &mut Access::new(0, 45, &mut latch))
            .unwrap();
        assert_eq!(entry.value as u32, 7); // source LDR W8 of the copied VALUE
        assert_eq!(entry.metadata, 42 << 10 | 2); // distinct actual transport metadata
        assert!(
            frames
                .consume_freshness(&captured, 0, &mut Access::new(0, 46, &mut latch))
                .is_err()
        );
        assert_eq!(captured.bits(16, 8), Ok(3)); // original pending snapshot remains unchanged
        frames.begin_discard(&captured, 0, u128::MAX).unwrap();
        while frames.step(&mut Access::new(0, 47, &mut latch)).unwrap() != CopyStep::Complete {}
        assert_eq!(frames.finish_discard().unwrap().consumed(), 2); // includes the already consumed first entry
        assert_eq!(
            (
                frames.progress().consumed,
                frames.progress().freshness_consumed
            ),
            (3, 1)
        );
        assert!(
            frames
                .frames
                .iter()
                .all(|cell| *cell == Frame::initialized(0x6a))
        );
        publish(&local, 17, 1700, 48, &mut latch);
        let next = frames
            .capture_pending(&Access::new(0, 49, &mut latch))
            .unwrap();
        assert!(
            frames
                .consume_freshness(&captured, 0, &mut Access::new(0, 50, &mut latch))
                .is_err()
        );
        assert_eq!(next.bits(16, 8), Ok(2));
        let unchanged = frames
            .consume_freshness(&next, 0, &mut Access::new(0, 51, &mut latch))
            .unwrap();
        assert_eq!(unchanged.value as u32, 7); // bit0 need not be pending; the source still consumes entry0
        assert_eq!(unchanged.metadata, 42 << 10);
        frames.begin_copy(&next, 0, u128::MAX).unwrap();
        let copied = drain(&mut frames, &mut latch);
        assert_eq!(frames.cells(&copied).unwrap()[0], Frame::initialized(0x6a));
        assert_eq!(frames.cells(&copied).unwrap()[1].value, 1700);
        assert!(
            frames
                .consume_freshness(&next, 0, &mut Access::new(0, 52, &mut latch))
                .is_err()
        );
    }
    #[test]
    fn freshness_failure_and_exhaustion_leave_first_entry_available_for_the_same_operation() {
        let local = local();
        let mut frames = frames(&local, &[1], &[0; 8]);
        let mut latch = InterruptLatch::new();
        publish(&local, 16, 100, 7, &mut latch);
        let captured = frames
            .capture_pending(&Access::new(0, 8, &mut latch))
            .unwrap();
        frames.progress.freshness_consumed = u64::MAX;
        assert!(
            frames
                .consume_freshness(&captured, 0, &mut Access::new(0, 9, &mut latch))
                .is_err()
        );
        assert_eq!(frames.progress().consumed, 0);
        assert_eq!(local.bank().pending_range(16, 8).unwrap().low, 1);
        frames.progress.freshness_consumed = 0;
        let mut bank = local.bank().clone();
        bank.set_lifecycle(
            LifecycleState {
                quiesced: true,
                ..LIVE
            },
            &mut Access::new(0, 10, &mut latch),
        );
        assert!(
            frames
                .consume_freshness(&captured, 0, &mut Access::new(0, 11, &mut latch))
                .is_err()
        );
        assert_eq!(frames.slices[0].last_freshness, 0);
        assert_eq!(frames.progress().consumed, 0);
        bank.set_lifecycle(LIVE, &mut Access::new(0, 12, &mut latch));
        assert_eq!(
            frames
                .consume_freshness(&captured, 0, &mut Access::new(0, 13, &mut latch))
                .unwrap()
                .metadata,
            7 << 10 | 2
        );
        assert_eq!(frames.progress().freshness_consumed, 1);
        assert_eq!(local.bank().pending_range(16, 8).unwrap().low, 0);
    }
    #[test]
    #[cfg(feature = "std")]
    #[ignore = "requires original T8112 PMP and J473 DT via STELA_TEST_PMP_T8112 and STELA_TEST_MCC_J473_DT"]
    fn original_dynamic_slices_and_metadata_copy_match_actual_ptd_effects() {
        use crate::machine::adt::Node;
        let pmp = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        let dt = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&pmp),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        assert_eq!(
            crate::sha256(&dt),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        for (start, end, hash) in [
            (
                0xe358,
                0xe5c8,
                "7625301e8c97b8d337ace54c4be9dce54dd44199760d4d81c371a517d3ccd89d",
            ),
            (
                0x1accc,
                0x1ada0,
                "5f8476d42b23efc91eb9c5989ed846190b0a19cb907d51e4546c261473238df2",
            ),
            (
                0x1c3d0,
                0x1c464,
                "f7c06d8a23a7e3448cf0ba8acdc918c9c8de7eed3fd914fb2c5c0a717d5d77a7",
            ),
            (
                0x13c8c,
                0x13dc4,
                "a23120f06f85ec8b1696dcb355695f02335ae478d544686b4db99c7f501a069d",
            ),
            (
                0x13e40,
                0x13fa8,
                "5b3d66502b0b3dae1f718d5deda7da3a0942e3346931e2e8cbf27f77ae0e13b5",
            ),
            (
                0x12160,
                0x12674,
                "5ffb9090d6b2b23dcf29a50bca350fb6c57a73815f27d0ccab92c25f7a1e40aa",
            ),
        ] {
            assert_eq!(crate::sha256(&pmp[start..end]), hash);
        }
        let io = Node::root(&dt).unwrap().child("arm-io").unwrap();
        let pmp_node = io.child("pmp").unwrap();
        let mcc = io.child("mcc").unwrap();
        let nub = pmp_node.child("iop-pmp-nub").unwrap();
        let table = DeviceTable::from_properties(
            nub.property("soc-device").unwrap(),
            nub.property("soc-device-ps-group").unwrap(),
            nub.property("soc-device-die-offset"),
        )
        .unwrap();
        let selected = nub.property("pm-ptd-ranges").unwrap();
        let id = u32::from_le_bytes(selected[36..40].try_into().unwrap());
        assert_eq!(id, 9);
        let ranges: Vec<_> = nub
            .property("ptd-range")
            .unwrap()
            .as_chunks::<32>()
            .0
            .iter()
            .map(|row| {
                let word = |offset| u32::from_le_bytes(row[offset..offset + 4].try_into().unwrap());
                Range {
                    id: word(0),
                    start: word(4),
                    count: word(8),
                    name: core::str::from_utf8(row[16..].split(|b| *b == 0).next().unwrap())
                        .unwrap()
                        .into(),
                }
            })
            .collect();
        let source_range = ranges.iter().find(|range| range.id == id).unwrap().clone();
        assert_eq!((source_range.start, source_range.count), (16, 144));
        let translate = |(base, bytes)| (io.translate_range(base, bytes).unwrap(), bytes);
        let bank = translate(
            mcc.pairs("reg").unwrap()[mcc.first_u32("pmp_ptd_reg_idx").unwrap() as usize],
        );
        let updates = translate(
            pmp_node.pairs("reg").unwrap()
                [pmp_node.first_u32("ptd-update-reg-index").unwrap() as usize],
        );
        let (_, local) = Ptd::initialized_local_profile(
            NativeProfile::T8112,
            Geometry::new(bank, updates).unwrap(),
            &ranges,
            LIVE,
        )
        .unwrap();
        let mut frames = Frames::initialized(
            Claim::new(local.clone(), source_range, Rc::new(Cell::new(true))),
            &table,
            &[0x6d; 144],
        )
        .unwrap();
        assert_eq!(
            frames.layout(1),
            Some(Layout {
                ordinal: 1,
                start: 16,
                count: 112
            })
        );
        for ordinal in 4..8 {
            assert_eq!(
                frames.layout(ordinal).unwrap().start,
                128 + 8 * (ordinal - 4)
            );
        }
        let word = |offset| u32::from_le_bytes(pmp[offset..offset + 4].try_into().unwrap());
        assert_eq!(word(0x122cc), 0xaa1f03e1); // wrap calls bulk with NULL destination
        assert_eq!(word(0x13c98), 0xb4000102); // consume skips copying for NULL destination
        assert_eq!(word(0x125f8), 0xb94033e8); // freshness reads VALUE low32 at temporary+0
        // These on-disk zeros are rewritten during source initialization.
        assert_eq!((word(0x47ab8 + 0x64), word(0x47ab8 + 0x68)), (0, 0));
        let mut latch = InterruptLatch::new();
        for entry in 32..36 {
            publish(&local, entry, u64::from(entry) * 100, 25, &mut latch);
        }
        frames
            .capture(1, u128::MAX, &Access::new(0, 26, &mut latch))
            .unwrap();
        let copied = drain(&mut frames, &mut latch);
        assert_eq!(copied.selected(), 0xf << 16);
        assert_eq!(copied.copied(), 4);
        let cells = frames.cells(&copied).unwrap();
        for (relative, cell) in cells.iter().enumerate().take(20).skip(16) {
            assert_eq!(
                *cell,
                Frame {
                    value: (16 + relative as u64) * 100,
                    metadata: 0x6d << 56 | 1 << 54 | 25,
                    copied: true
                }
            );
        }
        assert!(cells[..16].iter().all(|cell| !cell.copied));
        assert_eq!(local.bank().requests().len(), 4); // actual input writes only
        assert_eq!(local.asserted(), 0); // source IRQ routing not admitted here
    }
}
