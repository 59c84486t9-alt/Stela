//! PTD counter-frame capture and irreversible source-ordered copying.
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
use crate::Result;
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;
use stela_contracts::refuse;
use {
    crate::platform::apple::ptd::transport::Entry,
    crate::platform::apple::ptd::transport::notifications::LocalNotifications,
    stela_contracts::bus::Access, stela_soc_data::ptd::Range,
};

const ENTRIES_PER_BLOCK: u32 = 8;
const SELECTED_BITS: u32 = 128;

/// Unique association issued by the native PMP owner. Dropping it or
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
    pub(super) fn check(&self) -> Result<()> {
        if self.alive.get() {
            Ok(())
        } else {
            Err(refuse!("PMP counter-frame native owner was abandoned"))
        }
    }
}

/// Source ordinal and PTD indices are different identities. These numbers
/// describe the parsed slice and grant no consumption/completion permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub ordinal: u32,
    pub start: u32,
    pub count: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub value: u64,
    /// Native copied layout: timestamp0..53, NEW54, DROPPED55, kept byte56..63.
    pub metadata: u64,
    /// PTD entry copied, not proof of a hardware counter event. Initial
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
/// One manager SOC-DEV-PKT pending capture, shared by all platform
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
/// Identity of a manager capture. This contains no selected
/// bits or completion claim. It lets a source callback revalidate its same
/// capture after Busy without cloning the pending observation or resurveying.
pub struct CaptureIdentity {
    owner: Rc<()>,
    generation: u64,
    start: u32,
    count: u32,
}
/// Read-only kept storage when the source skips bulk consumption. Initial
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
    /// Pure selection from this observation, not arrival permission.
    pub fn bits(&self, start: u32, count: u32) -> Result<u128> {
        let offset = start
            .checked_sub(self.start)
            .ok_or(refuse!("PMP counter snapshot starts before its range"))?;
        if count > SELECTED_BITS || offset.checked_add(count).is_none_or(|end| end > self.count) {
            return Err(refuse!(
                "PMP counter snapshot selection exceeds its actual capture"
            ));
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

/// All source-ordinal buffers for one native PTD recipient. Software
/// initialization clears low15 bytes and explicitly keeps caller-declared
/// byte15; it never asserts original allocator/reset or counter observations.
/// Source lifecycle/selection/packet owners must invoke this at their
/// bulk-copy stage and separately keep all later descriptor/provider effects.
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
    ) -> Result<()> {
        self.claim.check()?;
        if !self.claim.local.owns(local.bank()) {
            return Err(refuse!("PMP frames belong to a different actual PTD owner"));
        }
        Ok(())
    }
    /// Same native recipient, not another Frames over this PTD.
    /// The supplied liveness Rc is the existing native claim identity; it does
    /// not mint a recipient, revive an owner or authorize a capture/consume.
    pub(in crate::platform::apple::pmp::native) fn validate_native_recipient(
        &self,
        local: &LocalNotifications,
        alive: &Rc<Cell<bool>>,
    ) -> Result<()> {
        self.check_bank(local)?;
        if !Rc::ptr_eq(&self.claim.alive, alive) || !alive.get() {
            return Err(refuse!(
                "PMP frames belong to a different actual native recipient"
            ));
        }
        Ok(())
    }
    pub fn initialized(
        claim: Claim,
        table: &DeviceTable,
        preserved_top_bytes: &[u8],
    ) -> Result<Self> {
        claim.check()?;
        let end = claim
            .range
            .start
            .checked_add(claim.range.count)
            .ok_or(refuse!("PMP counter frame source range wraps"))?;
        let mut next = claim.range.start;
        let mut slices = Vec::new();
        slices
            .try_reserve_exact(table.len())
            .map_err(|_| refuse!("PMP counter slice allocation failed"))?;
        for (ordinal, row) in table.records().iter().enumerate() {
            let count = row[3]
                .checked_mul(ENTRIES_PER_BLOCK)
                .filter(|count| *count <= SELECTED_BITS)
                .ok_or(refuse!(
                    "PMP counter slice exceeds source128-bit selected state"
                ))?;
            let slice_end = next
                .checked_add(count)
                .filter(|last| *last <= end)
                .ok_or(refuse!(
                    "PMP counter slices exceed the actual selected PTD range"
                ))?;
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
            return Err(refuse!(
                "PMP counter software image differs from its source slices"
            ));
        }
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(preserved_top_bytes.len())
            .map_err(|_| refuse!("PMP counter frame allocation failed"))?;
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
    pub fn capture_identity(&self, captured: &Captured) -> Result<CaptureIdentity> {
        self.validate_capture(captured)?;
        Ok(CaptureIdentity {
            owner: self.identity.clone(),
            generation: captured.generation,
            start: captured.start,
            count: captured.count,
        })
    }
    pub fn validate_capture(&self, captured: &Captured) -> Result<()> {
        self.check_capture(
            &captured.owner,
            captured.generation,
            captured.start,
            captured.count,
        )
    }
    pub fn validate_capture_identity(&self, captured: &CaptureIdentity) -> Result<()> {
        self.check_capture(
            &captured.owner,
            captured.generation,
            captured.start,
            captured.count,
        )
    }
    /// A valid old buffer is not proof that this cycle copied it. In particular
    /// a newer discard preserves old cells while advancing the bulk cursor.
    pub fn validate_copied_capture(&self, copied: &Copied, captured: &Captured) -> Result<()> {
        self.validate_capture(captured)?;
        self.cells(copied)?;
        if copied.captured_generation != captured.generation {
            return Err(refuse!(
                "PMP counter copied storage belongs to a different pending capture"
            ));
        }
        Ok(())
    }
    fn check_capture(&self, owner: &Rc<()>, generation: u64, start: u32, count: u32) -> Result<()> {
        self.claim.check()?;
        if !Rc::ptr_eq(owner, &self.identity)
            || generation != self.progress.captures
            || start != self.claim.range.start
            || count != self.claim.range.count
        {
            return Err(refuse!(
                "PMP counter transfer requires the latest same-owner pending capture"
            ));
        }
        Ok(())
    }
    pub fn retain_cells(&self, ordinal: u32) -> Result<Retained> {
        self.claim.check()?;
        let slice = self
            .slices
            .get(ordinal as usize)
            .ok_or(refuse!("PMP counter ordinal is absent"))?;
        self.storage(&self.identity, slice.generation, slice.layout)?;
        Ok(Retained {
            owner: self.identity.clone(),
            generation: slice.generation,
            layout: slice.layout,
        })
    }
    pub fn retained_cells(&self, retained: &Retained) -> Result<&[Frame]> {
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
    /// before individual platform predicates. Keep this object through the
    /// predicates and bulk copies; do not resurvey pending state at ingestion.
    pub fn capture_pending(&mut self, access: &Access<'_>) -> Result<Captured> {
        self.claim.check()?;
        if self.pending.is_some() {
            return Err(refuse!(
                "PMP counter copy still retains its captured prefix"
            ));
        }
        let generation = next(self.progress.captures)?;
        let count = self.claim.range.count;
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(count.div_ceil(SELECTED_BITS) as usize)
            .map_err(|_| refuse!("PMP counter pending capture allocation failed"))?;
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
    pub fn begin_copy(&mut self, captured: &Captured, ordinal: u32, desired: u128) -> Result<()> {
        self.begin(captured, ordinal, desired, Destination::Buffer)
    }
    /// Source VA10112c8..10112d8 and 101164c pass a NULL destination to
    /// bulk consumption. Keep consume prefixes without touching any
    /// software frame byte or invalidating the previous copied-cell receipt.
    /// Activity-zero generic ingestion must not schedule a second bulk copy.
    pub fn begin_discard(
        &mut self,
        captured: &Captured,
        ordinal: u32,
        desired: u128,
    ) -> Result<()> {
        self.begin(captured, ordinal, desired, Destination::Discard)
    }
    /// Source VA10115d4..10115f8 consumes the first slice entry into a
    /// temporary, then reads its VALUE low32 for freshness. It does not read
    /// metadata as a clock or replace the platform buffer. The source
    /// caller must check its separate freshness-arm and selection predicates.
    /// Frozen pending bits are not retested, including bit0.
    pub fn consume_freshness(
        &mut self,
        captured: &Captured,
        ordinal: u32,
        access: &mut Access<'_>,
    ) -> Result<Entry> {
        self.claim.check()?;
        if self.pending.is_some() {
            return Err(refuse!(
                "PMP counter transfer still retains its captured prefix"
            ));
        }
        let slice = self.captured_slice(captured, ordinal)?;
        if slice.layout.count == 0
            || slice.last_freshness == captured.generation
            || slice.last_snapshot == captured.generation
        {
            return Err(refuse!(
                "PMP first-entry freshness consumption is absent, repeated or out of order"
            ));
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
    fn captured_slice(&self, captured: &Captured, ordinal: u32) -> Result<&Slice> {
        self.validate_capture(captured)?;
        self.slices
            .get(ordinal as usize)
            .ok_or(refuse!("PMP counter ordinal is absent"))
    }
    fn begin(
        &mut self,
        captured: &Captured,
        ordinal: u32,
        desired: u128,
        destination: Destination,
    ) -> Result<()> {
        self.claim.check()?;
        if self.pending.is_some() {
            return Err(refuse!(
                "PMP counter transfer still retains its captured prefix"
            ));
        }
        let slice = self.captured_slice(captured, ordinal)?;
        if slice.last_snapshot == captured.generation {
            return Err(refuse!(
                "PMP counter platform copy already began for this pending capture"
            ));
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
    fn capture(&mut self, ordinal: u32, desired: u128, access: &Access<'_>) -> Result<()> {
        let captured = self.capture_pending(access)?;
        self.begin_copy(&captured, ordinal, desired)
    }
    /// Consume at most one entry. A later failure leaves every earlier
    /// entry consumed and, when requested, cell copied. No callback, allocation
    /// or fallible step occurs between consume and its software effects.
    /// Frozen selection is not retested against NEW after source snapshot races.
    pub fn step(&mut self, access: &mut Access<'_>) -> Result<CopyStep> {
        self.claim.check()?;
        let pending = self
            .pending
            .as_mut()
            .ok_or(refuse!("PMP counter copy has no captured input"))?;
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
    /// and MC arrival OR occur later and require their own owners.
    pub fn finish_copy(&mut self) -> Result<Copied> {
        self.claim.check()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or(refuse!("PMP counter copy has no captured input"))?;
        if pending.destination != Destination::Buffer {
            return Err(refuse!(
                "PMP counter discard cannot produce a copied-cell receipt"
            ));
        }
        if pending.remaining != 0 {
            return Err(refuse!("PMP counter copy has unconsumed selected entries"));
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
    pub fn finish_discard(&mut self) -> Result<Discarded> {
        self.claim.check()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or(refuse!("PMP counter discard has no captured input"))?;
        if pending.destination != Destination::Discard || pending.remaining != 0 {
            return Err(refuse!(
                "PMP counter discard has not completed its actual consumption"
            ));
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
    pub fn cells(&self, copied: &Copied) -> Result<&[Frame]> {
        self.storage(&copied.owner, copied.generation, copied.layout)
    }
    fn storage(&self, owner: &Rc<()>, generation: u64, layout: Layout) -> Result<&[Frame]> {
        self.claim.check()?;
        if !Rc::ptr_eq(&self.identity, owner) {
            return Err(refuse!(
                "PMP counter storage requires the same-owner unchanged buffer"
            ));
        }
        let index = layout.ordinal as usize;
        let slice = self
            .slices
            .get(index)
            .ok_or(refuse!("PMP counter ordinal is absent"))?;
        if generation != slice.generation
            || layout != slice.layout
            || self.pending.as_ref().is_some_and(|pending| {
                pending.slice == index && pending.destination == Destination::Buffer
            })
        {
            return Err(refuse!(
                "PMP counter storage requires the same-owner unchanged buffer"
            ));
        }
        Ok(&self.frames[slice.offset..slice.offset + slice.layout.count as usize])
    }
}
fn next(value: u64) -> Result<u64> {
    value.checked_add(1).ok_or(refuse!(
        "PMP counter copy accounting exhausted before effect"
    ))
}

#[cfg(test)]
mod tests;
