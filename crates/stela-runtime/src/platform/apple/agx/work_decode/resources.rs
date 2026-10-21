//! Fixed-family firmware attachment ownership (original G13G/G13X/G14G).
//!
//! The native acquire/release routines own 32 resource windows, a 24-byte
//! record per window, a 16-byte DSID record, and six execution-slot masks per
//! pipe. This is separate from the G14X/G15 generated packet programs.
//! Accepted transitions retain every derived RAM value and native operation
//! through faults. A native operation returning an error must have no effect;
//! a later error never repeats an already committed native operation.

use super::{Encoding, Frame};
use crate::platform::apple::agx::{
    channel::Record,
    generation::{self, Family},
    initdata::Root,
    ring::{self, Shared},
};
use alloc::vec::Vec;

const SLOTS: usize = 32;
const SLOT_BYTES: usize = 24;
const DSIDS: usize = 256;
const LEASES: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub pipe: u8,
    pub slot: u8,
}
impl Lease {
    fn index(self) -> Result<usize, &'static str> {
        if self.pipe >= 3 || self.slot >= 6 {
            return Err("GFX resource lease is outside three pipes/six execution slots");
        }
        Ok(usize::from(self.pipe) * 6 + usize::from(self.slot))
    }
}

/// All fields copied by the original setup producers. The unused byte is
/// retained too; no packet serialization or hardware effect is implied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attachment {
    pub address: u64,
    pub units: u32,
    pub dsid: u8,
    pub reserved: u8,
    pub parameter: u16,
}

impl Attachment {
    pub fn read_setup(encoding: Encoding, frame: &Frame) -> Result<Vec<Self>, &'static str> {
        if frame.bytes().len() as u64 != encoding.record_bytes(frame.record) {
            return Err("GFX attachment setup does not have its family's record size");
        }
        let offset = match frame.record {
            Record::SetupTa => 0x80,
            Record::Setup3d => 0xa0,
            Record::SetupFastBlit => 0x58,
            Record::SetupCl => 0x50,
            _ => return Err("GFX attachments require a work setup record"),
        } + if encoding == Encoding::Fixed { 0 } else { 8 };
        let count = frame.u32(offset + 0x100)?;
        if count > 16 {
            return Err("GFX setup has more than sixteen attachment rows");
        }
        let mut rows = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let at = offset + i * 16;
            let bytes = frame.field(at, 16)?;
            rows.push(Self {
                address: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                units: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
                dsid: bytes[12],
                reserved: bytes[13],
                parameter: u16::from_le_bytes(bytes[14..].try_into().unwrap()),
            });
        }
        Ok(rows)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    G13G,
    G13X,
    G14G,
}
impl Policy {
    pub fn for_family(family: &Family) -> Result<Self, &'static str> {
        if family == &generation::G13G {
            Ok(Self::G13G)
        } else if family == &generation::G13X {
            Ok(Self::G13X)
        } else if family == &generation::G14G {
            Ok(Self::G14G)
        } else {
            Err("GFX fixed resource pool does not implement newer-family attachment packets")
        }
    }
    pub fn window(self, slot: u8) -> Result<u32, &'static str> {
        if usize::from(slot) >= SLOTS {
            return Err("GFX resource window index exceeds thirty-two slots");
        }
        Ok(0x17040
            + u32::from(slot) * 16
            + if self != Self::G13G && slot >= 16 {
                0x1a0
            } else {
                0
            })
    }
    fn release_controls(self, slot: u8) -> Result<Vec<NativeWrite>, &'static str> {
        let mut writes = alloc::vec![NativeWrite::Window {
            offset: self.window(slot)? + 8,
            value: 0
        }];
        // Original G13X release 0x26644..26680 additionally clears the low
        // bank for high slots; G14G clears only its selected high bank.
        if self == Self::G13X && slot >= 16 {
            writes.push(NativeWrite::Window {
                offset: 0x17048 + u32::from(slot) * 16,
                value: 0,
            });
        }
        Ok(writes)
    }
    fn dsid_release(self, native_clusters: u8, dsid: u8) -> Vec<NativeWrite> {
        if self == Self::G14G {
            return alloc::vec![NativeWrite::MCache {
                offset: 0xfffc + u32::from(dsid) * 4
            }];
        }
        let groups = u32::from(native_clusters) * if self == Self::G13X { 2 } else { 1 };
        let mut writes = Vec::with_capacity(groups as usize * 4);
        for group in 0..groups {
            for bank in [0xfffc, 0x23ffc, 0x37ffc, 0x4bffc] {
                writes.push(NativeWrite::MCache {
                    offset: group * 0x50000 + bank + u32::from(dsid) * 4,
                });
            }
        }
        writes
    }
}

/// Exact source-native operations, never sent through RAM DMA. MCache
/// completion always writes one to its source-selected 32-bit register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeWrite {
    Window { offset: u32, value: u64 },
    MCache { offset: u32 },
}

/// The actual SGX native owner supplies this adapter. `check_native` is
/// side-effect-free qualification; a failed write commits no native effect.
/// RAM failures retain the per-range/prefix contract documented by Shared.
pub trait Access {
    fn memory(&mut self) -> &mut dyn Shared;
    /// Retained power/clock gates cover RAM tails as well as native writes.
    fn check_available(&self) -> Result<(), &'static str>;
    fn check_native(&self, write: NativeWrite) -> Result<(), &'static str>;
    fn write_native(&mut self, write: NativeWrite) -> Result<(), &'static str>;
}

#[derive(Debug, Clone, Copy, Default)]
struct Dsid {
    mask: u32,
}
#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    dsid: u8,
    refs: u32,
}
#[derive(Debug)]
struct Tables {
    dsids: u64,
    slots: u64,
    masks: u64,
}
#[derive(Debug)]
struct Snapshot {
    dsids: [Dsid; DSIDS],
    slots: [Slot; SLOTS],
    masks: [u32; LEASES],
    occupied: u32,
}

fn at(base: u64, offset: u64, bytes: usize) -> Result<u64, &'static str> {
    let start = base
        .checked_add(offset)
        .ok_or("GFX resource address wraps")?;
    start
        .checked_add(bytes as u64 - 1)
        .ok_or("GFX resource range wraps")?;
    Ok(start)
}

impl Tables {
    fn read(memory: &mut dyn Shared, root: &Root) -> Result<Self, &'static str> {
        let dsids = memory.read_u64(at(root.rings, 0x2c8, 8)?)?;
        let slots = memory.read_u64(at(root.rings, 0x2d0, 8)?)?;
        let masks = memory.read_u64(at(root.rings, 0x2d8, 8)?)?;
        if [dsids, slots, masks].contains(&0) {
            return Err("GFX fixed resource pool has an absent shared table");
        }
        let tables = Self {
            dsids,
            slots,
            masks,
        };
        // These are separately allocated AP objects. Their disjointness is
        // necessary to retain read-derived values without hoisting a read
        // across a source write to the same bytes.
        let ranges = [
            (dsids, DSIDS * 16),
            (slots, SLOTS * SLOT_BYTES),
            (masks, 0x4c),
        ];
        for (i, (base, bytes)) in ranges.iter().copied().enumerate() {
            let end = at(base, 0, bytes)?;
            let end = end + bytes as u64 - 1;
            for (other, other_bytes) in ranges[..i].iter().copied() {
                let other_end = at(other, 0, other_bytes)? + other_bytes as u64 - 1;
                if base <= other_end && other <= end {
                    return Err("GFX resource tables overlap their separately owned allocations");
                }
            }
        }
        Ok(tables)
    }
    fn snapshot(&self, memory: &mut dyn Shared) -> Result<Snapshot, &'static str> {
        let mut snapshot = Snapshot {
            dsids: [Dsid::default(); DSIDS],
            slots: [Slot::default(); SLOTS],
            masks: [0; LEASES],
            occupied: 0,
        };
        let mut d = [0; DSIDS * 16];
        memory.read(at(self.dsids, 0, d.len())?, &mut d)?;
        for (i, row) in d.as_chunks::<16>().0.iter().enumerate() {
            snapshot.dsids[i] = Dsid {
                mask: u32::from_le_bytes(row[8..12].try_into().unwrap()),
            };
        }
        let mut s = [0; SLOTS * SLOT_BYTES];
        memory.read(at(self.slots, 0, s.len())?, &mut s)?;
        for (i, row) in s.as_chunks::<SLOT_BYTES>().0.iter().enumerate() {
            snapshot.slots[i] = Slot {
                dsid: row[0],
                refs: u32::from_le_bytes(row[13..17].try_into().unwrap()),
            };
        }
        let mut m = [0; 0x4c];
        memory.read(at(self.masks, 0, m.len())?, &mut m)?;
        for (i, word) in m[..0x48].as_chunks::<4>().0.iter().enumerate() {
            snapshot.masks[i] = u32::from_le_bytes(*word);
        }
        snapshot.occupied = u32::from_le_bytes(m[0x48..].try_into().unwrap());
        for (i, slot) in snapshot.slots.iter().enumerate() {
            let bit = 1 << i;
            if snapshot.occupied & bit != 0
                && (slot.refs == 0 || snapshot.dsids[usize::from(slot.dsid)].mask & bit == 0)
            {
                return Err(
                    "GFX resource pool slot has inconsistent reference/residency ownership",
                );
            }
            if snapshot.masks.iter().any(|mask| mask & bit != 0) && snapshot.occupied & bit == 0 {
                return Err("GFX execution-slot resource mask names an unoccupied window");
            }
            let owners = snapshot
                .masks
                .iter()
                .filter(|mask| **mask & bit != 0)
                .count();
            if owners > slot.refs as usize {
                return Err("GFX resource reference count is below its execution-slot owners");
            }
        }
        for (dsid, row) in snapshot.dsids.iter().enumerate() {
            for i in 0..SLOTS {
                if row.mask & (1 << i) != 0
                    && (snapshot.occupied & (1 << i) == 0
                        || usize::from(snapshot.slots[i].dsid) != dsid)
                {
                    return Err("GFX DSID residency names an unowned resource window");
                }
            }
        }
        Ok(snapshot)
    }
}

#[derive(Debug)]
struct Update {
    address: u64,
    set: u32,
    clear: u32,
    value: Option<u32>,
    committed: bool,
}
impl Update {
    fn new(address: u64, set: u32, clear: u32) -> Result<Self, &'static str> {
        ring::scalar_range(address, 4)?;
        Ok(Self {
            address,
            set,
            clear,
            value: None,
            committed: false,
        })
    }
    fn advance(&mut self, memory: &mut dyn Shared) -> Result<(), &'static str> {
        if self.committed {
            return Ok(());
        }
        let value = if let Some(value) = self.value {
            value
        } else {
            let value = (memory.read_u32(self.address)? & !self.clear) | self.set;
            self.value = Some(value);
            value
        };
        memory.write(self.address, &value.to_le_bytes())?;
        self.committed = true;
        Ok(())
    }
}

#[derive(Debug)]
struct Completion {
    address: u64,
    policy: Policy,
    native_clusters: u8,
    dsid: u8,
    increment: Option<u32>,
    written: bool,
    matched: Option<bool>,
    native_checked: bool,
    native: Vec<NativeWrite>,
    next: usize,
    cleared: bool,
}
impl Completion {
    fn advance(&mut self, access: &mut dyn Access) -> Result<(), &'static str> {
        if !self.written {
            let value = if let Some(value) = self.increment {
                value
            } else {
                let value = access.memory().read_u32(self.address + 4)?.wrapping_add(1);
                self.increment = Some(value);
                value
            };
            access
                .memory()
                .write(self.address + 4, &value.to_le_bytes())?;
            self.written = true;
        }
        if self.matched.is_none() {
            // The native comparison load follows the committed increment.
            // A fault here must not move the read before that store.
            let words = access.memory().read_u64(self.address)?;
            let requested = words as u32;
            let current = (words >> 32) as u32;
            self.matched = Some(requested != 0 && requested == current);
            if self.matched == Some(true) {
                self.native = self.policy.dsid_release(self.native_clusters, self.dsid);
            }
        }
        if !self.native_checked {
            for write in &self.native {
                access.check_native(*write)?;
            }
            self.native_checked = true;
        }
        while let Some(write) = self.native.get(self.next) {
            access.check_available()?;
            access.write_native(*write)?;
            self.next += 1;
        }
        if self.matched == Some(true) && !self.cleared {
            access.check_available()?;
            access.memory().write(self.address, &[0; 8])?;
            self.cleared = true;
        }
        Ok(())
    }
}

#[derive(Debug)]
enum Action {
    Ram {
        address: u64,
        bytes: Vec<u8>,
    },
    Native(NativeWrite),
    Update(Update),
    Residency {
        record: u64,
        table: u64,
        bit: u32,
        update: Option<Update>,
    },
    Completion(Completion),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentResult {
    Allocated(u8),
    Reused(u8),
    Overlapping,
    Full,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Acquired(Vec<AttachmentResult>),
    Released,
    Aborted,
}
#[derive(Debug, Default)]
struct Transition {
    actions: Vec<Action>,
    next: usize,
    checked: bool,
}
impl Transition {
    fn ram(&mut self, address: u64, bytes: &[u8]) -> Result<(), &'static str> {
        ring::scalar_range(address, bytes.len() as u64)?;
        self.actions.push(Action::Ram {
            address,
            bytes: bytes.to_vec(),
        });
        Ok(())
    }
    fn u32(&mut self, address: u64, value: u32) -> Result<(), &'static str> {
        self.ram(address, &value.to_le_bytes())
    }
    fn native(&mut self, write: NativeWrite) {
        self.actions.push(Action::Native(write));
    }
    fn update(&mut self, address: u64, set: u32, clear: u32) -> Result<(), &'static str> {
        self.actions
            .push(Action::Update(Update::new(address, set, clear)?));
        Ok(())
    }
    fn advance(&mut self, access: &mut dyn Access) -> Result<(), &'static str> {
        access.check_available()?;
        if !self.checked {
            for action in &self.actions {
                if let Action::Native(write) = action {
                    access.check_native(*write)?;
                }
            }
            self.checked = true;
        }
        while let Some(action) = self.actions.get_mut(self.next) {
            access.check_available()?;
            match action {
                Action::Ram { address, bytes } => access.memory().write(*address, bytes)?,
                Action::Native(write) => access.write_native(*write)?,
                Action::Update(update) => update.advance(access.memory())?,
                Action::Residency {
                    record,
                    table,
                    bit,
                    update,
                } => {
                    if update.is_none() {
                        // Native window disable precedes this DSID-byte load.
                        let mut dsid = [0];
                        access.memory().read(*record, &mut dsid)?;
                        *update = Some(Update::new(
                            at(*table, u64::from(dsid[0]) * 16 + 8, 4)?,
                            0,
                            *bit,
                        )?);
                    }
                    update.as_mut().unwrap().advance(access.memory())?;
                }
                Action::Completion(completion) => completion.advance(access)?,
            }
            self.next += 1;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Acquisition {
    lease: Lease,
    context: u32,
    rows: Vec<Attachment>,
    next: usize,
    active: Option<(AttachmentResult, Transition)>,
    results: Vec<AttachmentResult>,
    abort: bool,
}
#[derive(Debug, Clone, Copy)]
enum ReleaseStage {
    Scan,
    Window(u8),
    Clear,
    DsidScan,
    Dsid(usize),
}
#[derive(Debug)]
struct Release {
    leases: Vec<Lease>,
    lease: usize,
    below: u8,
    next_dsid: usize,
    completions: Option<[u64; 4]>,
    stage: ReleaseStage,
    active: Option<Transition>,
}
impl Release {
    fn new(leases: Vec<Lease>, completions: Option<[u64; 4]>) -> Self {
        Self {
            leases,
            lease: 0,
            below: 32,
            next_dsid: DSIDS,
            completions,
            stage: ReleaseStage::Scan,
            active: None,
        }
    }
}
#[derive(Debug)]
enum PendingKind {
    Acquire(Acquisition),
    Release(Release),
}
#[derive(Debug)]
struct Pending {
    kind: PendingKind,
    outcome: Outcome,
    done: bool,
}

/// One firmware owner serializes this pool and its DSID-control commands.
/// Table reads remain at their original phases; accepted rows, committed
/// effects and completed comparisons survive every later DMA failure.
#[derive(Debug)]
pub struct Pool {
    tables: Tables,
    policy: Policy,
    native_clusters: u8,
    pending: Option<Pending>,
}
impl Pool {
    pub fn bind(
        memory: &mut dyn Shared,
        root: &Root,
        family: &Family,
        native_clusters: u8,
    ) -> Result<Self, &'static str> {
        let policy = Policy::for_family(family)?;
        let tables = Tables::read(memory, root)?;
        tables.snapshot(memory)?;
        Ok(Self {
            tables,
            policy,
            native_clusters,
            pending: None,
        })
    }
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn check_reset(&self, memory: &mut dyn Shared) -> Result<(), &'static str> {
        if self.pending() {
            return Err("GFX reset with an unsettled resource transition");
        }
        let state = self.tables.snapshot(memory)?;
        if state.occupied != 0 || state.masks.iter().any(|mask| *mask != 0) {
            return Err("GFX reset with retained resource windows");
        }
        Ok(())
    }
    pub fn acquire(
        &mut self,
        _: &mut dyn Shared,
        lease: Lease,
        context: u32,
        rows: &[Attachment],
    ) -> Result<(), &'static str> {
        if self.pending() {
            return Err("GFX resource transition is already owned");
        }
        lease.index()?;
        if context >= 64 || rows.len() > 16 {
            return Err(
                "GFX resource acquisition context/attachment count is outside its source bounds",
            );
        }
        self.pending = Some(Pending {
            kind: PendingKind::Acquire(Acquisition {
                lease,
                context,
                rows: rows.to_vec(),
                next: 0,
                active: None,
                results: Vec::with_capacity(rows.len()),
                abort: false,
            }),
            outcome: Outcome::Acquired(Vec::new()),
            done: false,
        });
        Ok(())
    }
    pub fn release(
        &mut self,
        _: &mut dyn Shared,
        lease: Lease,
        completions: Option<[u64; 4]>,
    ) -> Result<(), &'static str> {
        if self.pending() {
            return Err("GFX resource transition is already owned");
        }
        lease.index()?;
        self.pending = Some(Pending {
            kind: PendingKind::Release(Release::new(alloc::vec![lease], completions)),
            outcome: if completions.is_none() {
                Outcome::Aborted
            } else {
                Outcome::Released
            },
            done: false,
        });
        Ok(())
    }
    pub fn abort_all(&mut self, _: &mut dyn Shared) -> Result<(), &'static str> {
        if self.pending() {
            return Err("GFX resource transition is already owned");
        }
        let leases = (0..3)
            .flat_map(|pipe| (0..6).map(move |slot| Lease { pipe, slot }))
            .collect();
        self.pending = Some(Pending {
            kind: PendingKind::Release(Release::new(leases, None)),
            outcome: Outcome::Aborted,
            done: false,
        });
        Ok(())
    }
    pub fn abort_pending_acquire(&mut self) -> Result<(), &'static str> {
        let Some(Pending {
            kind: PendingKind::Acquire(acquire),
            ..
        }) = self.pending.as_mut()
        else {
            return Err("GFX has no accepted resource acquisition to abort");
        };
        acquire.abort = true;
        Ok(())
    }
    pub fn advance(&mut self, access: &mut dyn Access) -> Result<Option<&Outcome>, &'static str> {
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        if !pending.done {
            access.check_available()?;
            match &mut pending.kind {
                PendingKind::Acquire(acquire) => loop {
                    access.check_available()?;
                    if acquire.abort
                        && acquire
                            .active
                            .as_ref()
                            .is_some_and(|(_, unit)| unit.next == 0)
                    {
                        acquire.active = None;
                    }
                    if let Some((result, unit)) = acquire.active.as_mut() {
                        unit.advance(access)?;
                        acquire.results.push(*result);
                        acquire.next += 1;
                        acquire.active = None;
                    }
                    if acquire.abort {
                        pending.kind =
                            PendingKind::Release(Release::new(alloc::vec![acquire.lease], None));
                        pending.outcome = Outcome::Aborted;
                        break;
                    }
                    if acquire.next == acquire.rows.len() {
                        pending.outcome = Outcome::Acquired(core::mem::take(&mut acquire.results));
                        pending.done = true;
                        break;
                    }
                    acquire.active = Some(acquire_row(
                        &self.tables,
                        self.policy,
                        access.memory(),
                        acquire.lease,
                        acquire.context,
                        acquire.rows[acquire.next],
                    )?);
                },
                PendingKind::Release(_) => {}
            }
            if let PendingKind::Release(release) = &mut pending.kind {
                release_advance(
                    &self.tables,
                    self.policy,
                    self.native_clusters,
                    release,
                    access,
                )?;
                pending.done = true;
            }
        }
        Ok(Some(&pending.outcome))
    }
    pub fn finish(&mut self) -> Result<Outcome, &'static str> {
        let pending = self
            .pending
            .as_ref()
            .ok_or("GFX has no completed resource transition")?;
        if !pending.done {
            return Err("GFX resource transition has unfinished effects or abort settlement");
        }
        Ok(self.pending.take().unwrap().outcome)
    }
}

fn acquire_row(
    tables: &Tables,
    policy: Policy,
    memory: &mut dyn Shared,
    lease: Lease,
    context: u32,
    row: Attachment,
) -> Result<(AttachmentResult, Transition), &'static str> {
    let end = row
        .address
        .checked_add(u64::from(row.units.wrapping_shl(7)))
        .ok_or("GFX attachment range wraps")?;
    let dsid = at(tables.dsids, u64::from(row.dsid) * 16, 16)?;
    let mut resident = memory.read_u32(dsid + 8)?;
    let mut found = None;
    while resident != 0 {
        let index = (31 - resident.leading_zeros()) as u8;
        resident &= !(1 << index);
        let slot = at(
            tables.slots,
            u64::from(index) * SLOT_BYTES as u64,
            SLOT_BYTES,
        )?;
        if memory.read_u32(slot + 17)? != context {
            continue;
        }
        let address = memory.read_u64(slot + 1)?;
        let units = memory.read_u32(slot + 9)?;
        let slot_end = address
            .checked_add(u64::from(units.wrapping_shl(7)))
            .ok_or("GFX resident attachment range wraps")?;
        if address <= row.address && slot_end >= end {
            found = Some(AttachmentResult::Reused(index));
            break;
        }
        if row.address <= slot_end && address <= end {
            found = Some(AttachmentResult::Overlapping);
            break;
        }
    }
    let result = if let Some(result) = found {
        result
    } else {
        let occupied = memory.read_u32(tables.masks + 0x48)?;
        if occupied == u32::MAX {
            AttachmentResult::Full
        } else {
            AttachmentResult::Allocated((!occupied).trailing_zeros() as u8)
        }
    };
    let mut transition = Transition::default();
    match result {
        AttachmentResult::Allocated(index) => {
            let address = (row.address >> 7)
                | (u64::from(context) << 33)
                | (u64::from(row.dsid) << 39)
                | (1 << 47);
            let end = (row.address >> 7)
                .checked_add(u64::from(row.units))
                .ok_or("GFX resource window end wraps")?;
            let control = end | (u64::from(1u32 << row.parameter.min(4)) << 34) | (1 << 33);
            let offset = policy.window(index)?;
            transition.native(NativeWrite::Window {
                offset: offset + 8,
                value: 0,
            });
            transition.native(NativeWrite::Window {
                offset,
                value: address,
            });
            transition.native(NativeWrite::Window {
                offset: offset + 8,
                value: control,
            });
            let slot = at(
                tables.slots,
                u64::from(index) * SLOT_BYTES as u64,
                SLOT_BYTES,
            )?;
            transition.ram(slot + 1, &row.address.to_le_bytes())?;
            transition.ram(slot, &[row.dsid])?;
            transition.u32(slot + 9, row.units)?;
            transition.u32(slot + 17, context)?;
            transition.u32(slot + 13, 1)?;
            transition.update(tables.masks + 0x48, 1 << index, 0)?;
            transition.update(dsid + 8, 1 << index, 0)?;
            transition.update(
                at(tables.masks, lease.index()? as u64 * 4, 4)?,
                1 << index,
                0,
            )?;
        }
        AttachmentResult::Reused(index) => {
            let refs = at(tables.slots, u64::from(index) * SLOT_BYTES as u64 + 13, 4)?;
            let value = memory
                .read_u32(refs)?
                .checked_add(1)
                .ok_or("GFX resource reference count overflows")?;
            transition.u32(refs, value)?;
            transition.update(
                at(tables.masks, lease.index()? as u64 * 4, 4)?,
                1 << index,
                0,
            )?;
        }
        AttachmentResult::Overlapping | AttachmentResult::Full => {}
    }
    Ok((result, transition))
}

fn release_window(
    tables: &Tables,
    policy: Policy,
    memory: &mut dyn Shared,
    index: u8,
) -> Result<Transition, &'static str> {
    let slot = at(
        tables.slots,
        u64::from(index) * SLOT_BYTES as u64,
        SLOT_BYTES,
    )?;
    let refs = memory
        .read_u32(slot + 13)?
        .checked_sub(1)
        .ok_or("GFX resource release underflows an unowned window")?;
    let mut transition = Transition::default();
    transition.u32(slot + 13, refs)?;
    if refs == 0 {
        for write in policy.release_controls(index)? {
            transition.native(write);
        }
        transition.actions.push(Action::Residency {
            record: slot,
            table: tables.dsids,
            bit: 1 << index,
            update: None,
        });
        transition.ram(slot + 1, &[0; 8])?;
        transition.ram(slot, &[0])?;
        transition.u32(slot + 9, 0)?;
        transition.u32(slot + 17, u32::MAX)?;
        transition.update(tables.masks + 0x48, 0, 1 << index)?;
    }
    Ok(transition)
}

fn release_advance(
    tables: &Tables,
    policy: Policy,
    native_clusters: u8,
    release: &mut Release,
    access: &mut dyn Access,
) -> Result<(), &'static str> {
    loop {
        access.check_available()?;
        if let Some(unit) = release.active.as_mut() {
            unit.advance(access)?;
            release.active = None;
            match release.stage {
                ReleaseStage::Window(index) => {
                    release.below = index;
                    release.stage = ReleaseStage::Scan;
                }
                ReleaseStage::Clear => {
                    release.lease += 1;
                    release.below = 32;
                    release.stage = ReleaseStage::Scan;
                }
                ReleaseStage::Dsid(index) => {
                    release.next_dsid = index;
                    release.stage = ReleaseStage::DsidScan;
                }
                _ => unreachable!("only native release units own an active transition"),
            }
        }
        match release.stage {
            ReleaseStage::Scan => {
                if release.lease == release.leases.len() {
                    release.stage = ReleaseStage::DsidScan;
                    continue;
                }
                let address = at(
                    tables.masks,
                    release.leases[release.lease].index()? as u64 * 4,
                    4,
                )?;
                if release.below == 0 {
                    release.stage = ReleaseStage::Clear;
                    continue;
                }
                let lower = u32::MAX >> (32 - release.below);
                let mask = access.memory().read_u32(address)? & lower;
                if mask == 0 {
                    release.stage = ReleaseStage::Clear;
                    continue;
                }
                let index = (31 - mask.leading_zeros()) as u8;
                let unit = release_window(tables, policy, access.memory(), index)?;
                release.stage = ReleaseStage::Window(index);
                release.active = Some(unit);
            }
            ReleaseStage::Clear => {
                let mut unit = Transition::default();
                unit.u32(
                    at(
                        tables.masks,
                        release.leases[release.lease].index()? as u64 * 4,
                        4,
                    )?,
                    0,
                )?;
                release.active = Some(unit);
            }
            ReleaseStage::DsidScan => {
                let next = release.completions.and_then(|mask| {
                    (0..release.next_dsid)
                        .rev()
                        .find(|index| mask[index / 64] & (1 << (index % 64)) != 0)
                });
                let Some(dsid) = next else {
                    return Ok(());
                };
                let address = at(tables.dsids, dsid as u64 * 16, 16)?;
                ring::scalar_range(address, 8)?;
                let mut unit = Transition::default();
                unit.actions.push(Action::Completion(Completion {
                    address,
                    policy,
                    native_clusters,
                    dsid: dsid as u8,
                    increment: None,
                    written: false,
                    matched: None,
                    native_checked: false,
                    native: Vec::new(),
                    next: 0,
                    cleared: false,
                }));
                release.stage = ReleaseStage::Dsid(dsid);
                release.active = Some(unit);
            }
            _ => unreachable!("selected native release unit must be retained"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const RINGS: u64 = 0x1000;
    const DSID: u64 = 0x4000;
    const RECORDS: u64 = 0x6000;
    const MASKS: u64 = 0x7000;
    const A: Lease = Lease { pipe: 0, slot: 2 };
    const B: Lease = Lease { pipe: 2, slot: 5 };

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Effect {
        Ram(u64, Vec<u8>),
        Native(NativeWrite),
    }
    struct Harness {
        bytes: Vec<u8>,
        effects: Vec<Effect>,
        fail: Option<usize>,
        fail_read: Option<u64>,
        skip_read_faults: usize,
        available: bool,
        native_supported: bool,
    }
    impl Harness {
        fn new() -> Self {
            let mut value = Self {
                bytes: vec![0xa5; 0x10000],
                effects: Vec::new(),
                fail: None,
                fail_read: None,
                skip_read_faults: 0,
                available: true,
                native_supported: true,
            };
            value.bytes[DSID as usize..DSID as usize + DSIDS * 16].fill(0);
            value.bytes[RECORDS as usize..RECORDS as usize + SLOTS * SLOT_BYTES].fill(0);
            value.bytes[MASKS as usize..MASKS as usize + 0x4c].fill(0);
            value.put(RINGS + 0x2c8, &DSID.to_le_bytes());
            value.put(RINGS + 0x2d0, &RECORDS.to_le_bytes());
            value.put(RINGS + 0x2d8, &MASKS.to_le_bytes());
            value
        }
        fn put(&mut self, at: u64, bytes: &[u8]) {
            self.bytes[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        }
        fn fault(&mut self) -> Result<(), &'static str> {
            if self.fail == Some(self.effects.len()) {
                self.fail = None;
                Err("injected resource effect fault")
            } else {
                Ok(())
            }
        }
        fn pool(&mut self, family: &Family) -> Pool {
            Pool::bind(self, &root(), family, 2).unwrap()
        }
    }
    impl Shared for Harness {
        fn read(&mut self, at: u64, out: &mut [u8]) -> Result<(), &'static str> {
            if self.fail_read == Some(at) {
                if self.skip_read_faults == 0 {
                    self.fail_read = None;
                    return Err("injected resource read fault");
                }
                self.skip_read_faults -= 1;
            }
            let bytes = self
                .bytes
                .get(at as usize..at as usize + out.len())
                .ok_or("resource input is outside test RAM")?;
            out.copy_from_slice(bytes);
            Ok(())
        }
        fn write(&mut self, at: u64, bytes: &[u8]) -> Result<(), &'static str> {
            self.fault()?;
            let out = self
                .bytes
                .get_mut(at as usize..at as usize + bytes.len())
                .ok_or("resource output is outside test RAM")?;
            out.copy_from_slice(bytes);
            self.effects.push(Effect::Ram(at, bytes.to_vec()));
            Ok(())
        }
        fn gpu_read(
            &mut self,
            _: usize,
            _: u64,
            _: &mut [u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            panic!("resource ownership cannot execute GPU work");
        }
        fn gpu_write(
            &mut self,
            _: usize,
            _: u64,
            _: &[u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            panic!("resource ownership cannot execute GPU work");
        }
    }
    impl Access for Harness {
        fn memory(&mut self) -> &mut dyn Shared {
            self
        }
        fn check_available(&self) -> Result<(), &'static str> {
            if self.available {
                Ok(())
            } else {
                Err("resource owner is retained behind its clock gate")
            }
        }
        fn check_native(&self, _: NativeWrite) -> Result<(), &'static str> {
            if self.native_supported {
                Ok(())
            } else {
                Err("resource native target is not qualified")
            }
        }
        fn write_native(&mut self, write: NativeWrite) -> Result<(), &'static str> {
            self.check_available()?;
            self.check_native(write)?;
            self.fault()?;
            self.effects.push(Effect::Native(write));
            Ok(())
        }
    }
    fn root() -> Root {
        Root {
            page_1660: 1,
            rings: RINGS,
            object_358: 2,
            object_848: 3,
            object_928: 4,
            object_930: 5,
            object_368: 6,
            config: [0; super::super::super::initdata::CONFIG_BYTES],
        }
    }
    fn row(address: u64, dsid: u8) -> Attachment {
        Attachment {
            address,
            units: 8,
            dsid,
            reserved: 0xa6,
            parameter: 7,
        }
    }
    fn settle(pool: &mut Pool, memory: &mut Harness) -> Outcome {
        assert!(pool.advance(memory).unwrap().is_some());
        pool.finish().unwrap()
    }
    fn acquire(
        pool: &mut Pool,
        memory: &mut Harness,
        lease: Lease,
        rows: &[Attachment],
    ) -> Outcome {
        pool.acquire(memory, lease, 3, rows).unwrap();
        settle(pool, memory)
    }

    #[test]
    fn all_setup_producers_preserve_the_full_attachment_row() {
        for family in [
            &generation::G13G,
            &generation::G13X,
            &generation::G14G,
            &generation::G14X,
            &generation::G15G,
        ] {
            let encoding = Encoding::for_family(family).unwrap();
            for (record, base) in [
                (Record::SetupTa, 0x80),
                (Record::Setup3d, 0xa0),
                (Record::SetupFastBlit, 0x58),
                (Record::SetupCl, 0x50),
            ] {
                let offset = base + if encoding == Encoding::Fixed { 0 } else { 8 };
                let expected = row(0x1234_5678_9abc, 0xf4);
                let mut frame = Frame {
                    va: 0x1000,
                    record,
                    data: vec![0; encoding.record_bytes(record) as usize],
                };
                frame.data[offset..offset + 8].copy_from_slice(&expected.address.to_le_bytes());
                frame.data[offset + 8..offset + 12].copy_from_slice(&expected.units.to_le_bytes());
                frame.data[offset + 12] = expected.dsid;
                frame.data[offset + 13] = expected.reserved;
                frame.data[offset + 14..offset + 16]
                    .copy_from_slice(&expected.parameter.to_le_bytes());
                frame.data[offset + 0x100..offset + 0x104].copy_from_slice(&1u32.to_le_bytes());
                assert_eq!(Attachment::read_setup(encoding, &frame), Ok(vec![expected]));
                frame.data[offset + 0x100..offset + 0x104].copy_from_slice(&17u32.to_le_bytes());
                assert!(
                    Attachment::read_setup(encoding, &frame)
                        .unwrap_err()
                        .contains("sixteen")
                );
            }
        }
        assert!(Policy::for_family(&generation::G14X).is_err());
        assert!(Policy::for_family(&generation::G15G).is_err());
    }

    #[test]
    fn allocation_reuse_overlap_and_last_owner_release_have_native_order() {
        let mut memory = Harness::new();
        let mut pool = memory.pool(&generation::G14G);
        assert_eq!(
            acquire(&mut pool, &mut memory, A, &[row(0x8000, 4)]),
            Outcome::Acquired(vec![AttachmentResult::Allocated(0)])
        );
        let expected_address = (0x8000 >> 7) | (3 << 33) | (4 << 39) | (1 << 47);
        assert_eq!(
            &memory.effects[..4],
            &[
                Effect::Native(NativeWrite::Window {
                    offset: 0x17048,
                    value: 0
                }),
                Effect::Native(NativeWrite::Window {
                    offset: 0x17040,
                    value: expected_address
                }),
                Effect::Native(NativeWrite::Window {
                    offset: 0x17048,
                    value: ((0x8000 >> 7) + 8) | (16 << 34) | (1 << 33)
                }),
                Effect::Ram(RECORDS + 1, 0x8000u64.to_le_bytes().to_vec()),
            ]
        );
        memory.effects.clear();
        let mut contained = row(0x8080, 4);
        contained.units = 1;
        assert_eq!(
            acquire(&mut pool, &mut memory, B, &[contained, row(0x8400, 4)]),
            Outcome::Acquired(vec![
                AttachmentResult::Reused(0),
                AttachmentResult::Overlapping
            ])
        );
        assert_eq!(
            memory.effects,
            vec![
                Effect::Ram(RECORDS + 13, 2u32.to_le_bytes().to_vec()),
                Effect::Ram(MASKS + 17 * 4, 1u32.to_le_bytes().to_vec()),
            ]
        );
        pool.release(&mut memory, A, None).unwrap();
        assert_eq!(settle(&mut pool, &mut memory), Outcome::Aborted);
        assert_eq!(memory.read_u32(RECORDS + 13), Ok(1));
        assert_eq!(memory.read_u32(MASKS + 0x48), Ok(1));
        memory.effects.clear();
        pool.release(&mut memory, B, Some([0; 4])).unwrap();
        assert_eq!(settle(&mut pool, &mut memory), Outcome::Released);
        assert_eq!(
            &memory.effects[..2],
            &[
                Effect::Ram(RECORDS + 13, 0u32.to_le_bytes().to_vec()),
                Effect::Native(NativeWrite::Window {
                    offset: 0x17048,
                    value: 0
                }),
            ]
        );
        assert_eq!(memory.read_u32(RECORDS + 17), Ok(u32::MAX));
        assert_eq!(memory.read_u32(MASKS + 0x48), Ok(0));
        assert_eq!(memory.read_u32(DSID + 4 * 16 + 8), Ok(0));
        pool.check_reset(&mut memory).unwrap();
    }

    #[test]
    fn family_high_windows_and_cluster_replicated_dsid_completions_are_distinct() {
        for (family, policy, native_count) in [
            (&generation::G13G, Policy::G13G, 8),
            (&generation::G13X, Policy::G13X, 16),
            (&generation::G14G, Policy::G14G, 1),
        ] {
            let mut memory = Harness::new();
            let mut pool = memory.pool(family);
            let rows: Vec<_> = (0..16).map(|i| row(0x8000 + i * 0x1000, 4)).collect();
            acquire(&mut pool, &mut memory, A, &rows);
            acquire(&mut pool, &mut memory, B, &[row(0x28000, 4)]);
            assert_eq!(memory.read_u32(MASKS + 17 * 4), Ok(1 << 16));
            let expected_high = if policy == Policy::G13G {
                0x17140
            } else {
                0x172e0
            };
            assert!(
                memory
                    .effects
                    .contains(&Effect::Native(NativeWrite::Window {
                        offset: expected_high + 8,
                        value: 0
                    }))
            );
            memory.put(DSID + 4 * 16, &1u32.to_le_bytes());
            memory.effects.clear();
            pool.release(&mut memory, B, Some([1 << 4, 0, 0, 0]))
                .unwrap();
            settle(&mut pool, &mut memory);
            let native: Vec<_> = memory
                .effects
                .iter()
                .filter_map(|effect| {
                    if let Effect::Native(write) = effect {
                        Some(*write)
                    } else {
                        None
                    }
                })
                .collect();
            let controls = if policy == Policy::G13X { 2 } else { 1 };
            assert_eq!(native.len(), native_count + controls);
            assert_eq!(
                native[0],
                NativeWrite::Window {
                    offset: expected_high + 8,
                    value: 0
                }
            );
            if policy == Policy::G13X {
                assert_eq!(
                    native[1],
                    NativeWrite::Window {
                        offset: 0x17148,
                        value: 0
                    }
                );
            }
            assert_eq!(
                native[controls],
                NativeWrite::MCache {
                    offset: 0xfffc + 16
                }
            );
            if policy != Policy::G14G {
                assert_eq!(
                    native[controls + 1],
                    NativeWrite::MCache {
                        offset: 0x23ffc + 16
                    }
                );
                assert_eq!(
                    native.last(),
                    Some(&NativeWrite::MCache {
                        offset: (if policy == Policy::G13X { 3 } else { 1 }) * 0x50000
                            + 0x4bffc
                            + 16
                    })
                );
            }
            assert_eq!(memory.read_u64(DSID + 4 * 16), Ok(0));
            // Residency in the other lease survives the DSID counter clear.
            assert_eq!(memory.read_u32(DSID + 4 * 16 + 8), Ok(0xffff));
        }
    }

    #[test]
    fn every_acquire_release_fault_retries_only_the_uncommitted_suffix() {
        for family in [&generation::G13G, &generation::G13X, &generation::G14G] {
            let mut baseline = Harness::new();
            let mut pool = baseline.pool(family);
            acquire(&mut pool, &mut baseline, A, &[row(0x8000, 4)]);
            let acquire_effects = baseline.effects.clone();
            baseline.effects.clear();
            baseline.put(DSID + 4 * 16, &1u32.to_le_bytes());
            pool.release(&mut baseline, A, Some([1 << 4, 0, 0, 0]))
                .unwrap();
            settle(&mut pool, &mut baseline);
            let release_effects = baseline.effects.clone();
            for release in [false, true] {
                let effects = if release {
                    &release_effects
                } else {
                    &acquire_effects
                };
                for failed in 0..effects.len() {
                    let mut memory = Harness::new();
                    let mut pool = memory.pool(family);
                    if release {
                        acquire(&mut pool, &mut memory, A, &[row(0x8000, 4)]);
                        memory.effects.clear();
                        memory.put(DSID + 4 * 16, &1u32.to_le_bytes());
                        pool.release(&mut memory, A, Some([1 << 4, 0, 0, 0]))
                            .unwrap();
                    } else {
                        pool.acquire(&mut memory, A, 3, &[row(0x8000, 4)]).unwrap();
                    }
                    memory.fail = Some(failed);
                    assert_eq!(
                        pool.advance(&mut memory),
                        Err("injected resource effect fault")
                    );
                    assert_eq!(memory.effects, effects[..failed]);
                    assert!(pool.finish().is_err());
                    assert!(
                        pool.check_reset(&mut memory)
                            .unwrap_err()
                            .contains("unsettled")
                    );
                    // Retried output values belong to acceptance, not changed AP input.
                    memory.put(RINGS + 0x2c8, &0x9000u64.to_le_bytes());
                    memory.available = false;
                    assert!(
                        pool.advance(&mut memory)
                            .unwrap_err()
                            .contains("clock gate")
                    );
                    assert_eq!(memory.effects, effects[..failed]);
                    memory.available = true;
                    settle(&mut pool, &mut memory);
                    assert_eq!(&memory.effects, effects);
                }
            }
        }
    }

    #[test]
    fn accepted_acquire_abort_settles_native_ownership_without_successful_dsid_completion() {
        for failed in 0..11 {
            let mut memory = Harness::new();
            let mut pool = memory.pool(&generation::G14G);
            pool.acquire(&mut memory, A, 3, &[row(0x8000, 4)]).unwrap();
            memory.fail = Some(failed);
            assert!(pool.advance(&mut memory).is_err());
            pool.abort_pending_acquire().unwrap();
            assert_eq!(settle(&mut pool, &mut memory), Outcome::Aborted);
            assert_eq!(memory.read_u32(MASKS + 0x48), Ok(0));
            assert!(
                memory
                    .effects
                    .iter()
                    .all(|effect| !matches!(effect, Effect::Native(NativeWrite::MCache { .. })))
            );
            pool.check_reset(&mut memory).unwrap();
        }
        let mut memory = Harness::new();
        let mut pool = memory.pool(&generation::G14G);
        acquire(&mut pool, &mut memory, A, &[row(0x8000, 4)]);
        acquire(&mut pool, &mut memory, B, &[row(0xa000, 5)]);
        memory.effects.clear();
        pool.abort_all(&mut memory).unwrap();
        assert_eq!(settle(&mut pool, &mut memory), Outcome::Aborted);
        pool.check_reset(&mut memory).unwrap();
        assert!(
            memory
                .effects
                .iter()
                .all(|effect| !matches!(effect, Effect::Native(NativeWrite::MCache { .. })))
        );
    }

    #[test]
    fn unsupported_native_backend_and_input_faults_keep_transitions_effect_free() {
        let mut memory = Harness::new();
        let mut pool = memory.pool(&generation::G14G);
        memory.fail_read = Some(DSID + 4 * 16 + 8);
        pool.acquire(&mut memory, A, 3, &[row(0x8000, 4)]).unwrap();
        assert_eq!(
            pool.advance(&mut memory),
            Err("injected resource read fault")
        );
        assert!(pool.pending() && memory.effects.is_empty());
        memory.native_supported = false;
        assert_eq!(
            pool.advance(&mut memory),
            Err("resource native target is not qualified")
        );
        assert!(memory.effects.is_empty());
        pool.abort_pending_acquire().unwrap();
        assert_eq!(settle(&mut pool, &mut memory), Outcome::Aborted);
        assert_eq!(
            memory.effects,
            vec![Effect::Ram(MASKS + 8, 0u32.to_le_bytes().to_vec())]
        );
        memory.put(RINGS + 0x2d0, &DSID.to_le_bytes());
        assert!(
            Pool::bind(&mut memory, &root(), &generation::G14G, 2)
                .unwrap_err()
                .contains("overlap")
        );
    }

    #[test]
    fn all_thirty_two_slots_exhaust_and_can_be_reallocated_after_abort() {
        let mut memory = Harness::new();
        let mut pool = memory.pool(&generation::G14G);
        for (lease, start) in [(A, 0u64), (B, 16)] {
            let rows: Vec<_> = (start..start + 16)
                .map(|i| row(0x8000 + i * 0x1000, i as u8))
                .collect();
            let expected: Vec<_> = (start..start + 16)
                .map(|i| AttachmentResult::Allocated(i as u8))
                .collect();
            assert_eq!(
                acquire(&mut pool, &mut memory, lease, &rows),
                Outcome::Acquired(expected)
            );
        }
        memory.effects.clear();
        assert_eq!(
            acquire(
                &mut pool,
                &mut memory,
                Lease { pipe: 1, slot: 1 },
                &[row(0x800000, 255)]
            ),
            Outcome::Acquired(vec![AttachmentResult::Full])
        );
        assert!(memory.effects.is_empty());
        assert_eq!(memory.read_u32(MASKS + 0x48), Ok(u32::MAX));
        assert!(
            pool.check_reset(&mut memory)
                .unwrap_err()
                .contains("retained")
        );
        pool.abort_all(&mut memory).unwrap();
        settle(&mut pool, &mut memory);
        pool.check_reset(&mut memory).unwrap();
        assert_eq!(
            acquire(&mut pool, &mut memory, A, &[row(0x800000, 255)]),
            Outcome::Acquired(vec![AttachmentResult::Allocated(0)])
        );
    }

    #[test]
    fn dsid_completions_descend_and_wrap_without_synthesizing_matches() {
        let mut memory = Harness::new();
        let mut pool = memory.pool(&generation::G14G);
        memory.put(DSID + 255 * 16, &1u32.to_le_bytes());
        memory.put(DSID + 64 * 16, &2u32.to_le_bytes());
        memory.put(DSID + 64 * 16 + 4, &u32::MAX.to_le_bytes());
        memory.put(DSID, &0u32.to_le_bytes());
        pool.release(&mut memory, A, Some([1, 1, 0, 1 << 63]))
            .unwrap();
        settle(&mut pool, &mut memory);
        assert_eq!(
            memory.effects,
            vec![
                Effect::Ram(MASKS + 8, 0u32.to_le_bytes().to_vec()),
                Effect::Ram(DSID + 255 * 16 + 4, 1u32.to_le_bytes().to_vec()),
                Effect::Native(NativeWrite::MCache {
                    offset: 0xfffc + 255 * 4
                }),
                Effect::Ram(DSID + 255 * 16, vec![0; 8]),
                Effect::Ram(DSID + 64 * 16 + 4, 0u32.to_le_bytes().to_vec()),
                Effect::Ram(DSID + 4, 1u32.to_le_bytes().to_vec()),
            ]
        );
        assert_eq!(memory.read_u32(DSID + 64 * 16), Ok(2));
        assert_eq!(memory.read_u32(DSID + 4), Ok(1));
    }

    #[test]
    fn abort_preparation_fault_retains_the_completed_acquisition_until_release_is_owned() {
        let mut memory = Harness::new();
        let mut pool = memory.pool(&generation::G14G);
        pool.acquire(&mut memory, A, 3, &[row(0x8000, 4)]).unwrap();
        memory.fail = Some(1);
        assert!(pool.advance(&mut memory).is_err());
        pool.abort_pending_acquire().unwrap();
        memory.fail_read = Some(MASKS + 8);
        memory.skip_read_faults = 1; // acquisition's final RMW precedes release's mask load
        assert_eq!(
            pool.advance(&mut memory),
            Err("injected resource read fault")
        );
        assert_eq!(memory.effects.len(), 11);
        assert!(pool.finish().is_err());
        memory.fail = Some(12); // refcount commits, native disable then faults
        assert!(pool.advance(&mut memory).is_err());
        assert_eq!(memory.read_u32(RECORDS + 13), Ok(0));
        assert_eq!(settle(&mut pool, &mut memory), Outcome::Aborted);
        pool.check_reset(&mut memory).unwrap();
        assert_eq!(
            memory
                .effects
                .iter()
                .filter(|effect| matches!(
                    effect,
                    Effect::Native(NativeWrite::Window {
                        offset: 0x17040,
                        ..
                    })
                ))
                .count(),
            1
        );
    }

    #[test]
    fn duplicate_contained_rows_preserve_original_refcounts_and_do_not_invent_reset_cleanup() {
        let mut memory = Harness::new();
        let mut pool = memory.pool(&generation::G14G);
        assert_eq!(
            acquire(&mut pool, &mut memory, A, &[row(0x8000, 4), row(0x8000, 4)]),
            Outcome::Acquired(vec![
                AttachmentResult::Allocated(0),
                AttachmentResult::Reused(0)
            ])
        );
        pool.abort_all(&mut memory).unwrap();
        settle(&mut pool, &mut memory);
        // The original counts each row but release visits one lease bit.
        // Do not normalize malformed/repeated producer rows or free a window
        // still carrying a reference by fabricating destructive reset.
        assert_eq!(memory.read_u32(RECORDS + 13), Ok(1));
        assert_eq!(memory.read_u32(MASKS + 0x48), Ok(1));
        assert!(pool.check_reset(&mut memory).is_err());
        assert!(
            pool.acquire(&mut memory, Lease { pipe: 3, slot: 0 }, 3, &[])
                .is_err()
        );
        assert!(pool.acquire(&mut memory, A, 64, &[]).is_err());
        assert!(!pool.pending());
    }
    #[test]
    fn acquisition_mask_reads_follow_committed_native_and_slot_stores() {
        let mut memory = Harness::new();
        let mut pool = memory.pool(&generation::G14G);
        pool.acquire(&mut memory, A, 3, &[row(0x8000, 4)]).unwrap();
        memory.fail_read = Some(MASKS + 0x48);
        memory.skip_read_faults = 1;
        assert_eq!(
            pool.advance(&mut memory),
            Err("injected resource read fault")
        );
        assert_eq!(memory.effects.len(), 8); // three native + five slot fields
        assert_eq!(memory.read_u64(RECORDS + 1), Ok(0x8000));
        assert_eq!(memory.read_u32(MASKS + 0x48), Ok(0));
        memory.fail = Some(8); // capture the RMW result, then fault its store
        assert!(pool.advance(&mut memory).is_err());
        memory.put(MASKS + 0x48, &0x80u32.to_le_bytes());
        settle(&mut pool, &mut memory);
        assert_eq!(memory.read_u32(MASKS + 0x48), Ok(1));
        assert_eq!(
            memory
                .effects
                .iter()
                .filter(|effect| matches!(effect, Effect::Native(_)))
                .count(),
            3
        );
    }

    #[test]
    fn later_row_read_fault_preserves_the_first_row_and_abort_does_not_accept_the_next() {
        let mut memory = Harness::new();
        let mut pool = memory.pool(&generation::G14G);
        pool.acquire(&mut memory, A, 3, &[row(0x8000, 4), row(0xa000, 5)])
            .unwrap();
        memory.fail_read = Some(DSID + 5 * 16 + 8);
        assert_eq!(
            pool.advance(&mut memory),
            Err("injected resource read fault")
        );
        assert_eq!(memory.effects.len(), 11);
        assert_eq!(memory.read_u32(MASKS + 8), Ok(1));
        memory.fail_read = Some(DSID + 5 * 16 + 8);
        pool.abort_pending_acquire().unwrap();
        assert_eq!(settle(&mut pool, &mut memory), Outcome::Aborted);
        assert_eq!(memory.read_u32(MASKS + 0x48), Ok(0));
        assert_eq!(
            memory
                .effects
                .iter()
                .filter(|effect| matches!(
                    effect,
                    Effect::Native(NativeWrite::Window {
                        offset: 0x17040,
                        ..
                    })
                ))
                .count(),
            1
        );
    }

    #[test]
    fn release_dsid_reads_and_completion_comparison_keep_their_source_phases() {
        let mut memory = Harness::new();
        let mut pool = memory.pool(&generation::G14G);
        acquire(&mut pool, &mut memory, A, &[row(0x8000, 4)]);
        memory.effects.clear();
        pool.release(&mut memory, A, None).unwrap();
        memory.fail_read = Some(RECORDS);
        assert_eq!(
            pool.advance(&mut memory),
            Err("injected resource read fault")
        );
        assert_eq!(memory.effects.len(), 2); // refcount store then native disable
        assert_eq!(memory.read_u32(RECORDS + 13), Ok(0));
        memory.fail_read = Some(DSID + 4 * 16 + 8);
        assert!(pool.advance(&mut memory).is_err());
        memory.put(RECORDS, &[5]); // already captured DSID4 must remain owned
        settle(&mut pool, &mut memory);
        assert_eq!(memory.read_u32(DSID + 4 * 16 + 8), Ok(0));
        assert_eq!(
            memory
                .effects
                .iter()
                .filter(|effect| matches!(effect, Effect::Native(_)))
                .count(),
            1
        );

        memory.effects.clear();
        memory.put(DSID + 4 * 16, &1u32.to_le_bytes());
        pool.release(&mut memory, A, Some([1 << 4, 0, 0, 0]))
            .unwrap();
        memory.fail_read = Some(DSID + 4 * 16);
        assert_eq!(
            pool.advance(&mut memory),
            Err("injected resource read fault")
        );
        assert_eq!(memory.read_u32(DSID + 4 * 16 + 4), Ok(1));
        assert_eq!(memory.effects.len(), 2); // lease clear then increment
        memory.fail = Some(2); // comparison captures true, first native command faults
        assert!(pool.advance(&mut memory).is_err());
        memory.put(DSID + 4 * 16, &0xdeadbeefdeadbeefu64.to_le_bytes());
        settle(&mut pool, &mut memory);
        assert_eq!(memory.read_u64(DSID + 4 * 16), Ok(0));
        assert_eq!(
            memory
                .effects
                .iter()
                .filter(|effect| matches!(effect, Effect::Native(NativeWrite::MCache { .. })))
                .count(),
            1
        );
    }
    #[test]
    fn source_zero_legacy_native_count_skips_mcc_commands_but_keeps_the_dsid_release() {
        for family in [&generation::G13G, &generation::G13X] {
            let mut memory = Harness::new();
            let mut pool = Pool::bind(&mut memory, &root(), family, 0).unwrap();
            memory.put(DSID + 4 * 16, &1u32.to_le_bytes());
            memory.native_supported = false; // no native command may be invented
            pool.release(&mut memory, A, Some([1 << 4, 0, 0, 0]))
                .unwrap();
            assert_eq!(settle(&mut pool, &mut memory), Outcome::Released);
            assert_eq!(
                memory.effects,
                vec![
                    Effect::Ram(MASKS + 8, 0u32.to_le_bytes().to_vec()),
                    Effect::Ram(DSID + 4 * 16 + 4, 1u32.to_le_bytes().to_vec()),
                    Effect::Ram(DSID + 4 * 16, vec![0; 8]),
                ]
            );
        }
        let mut memory = Harness::new();
        let mut pool = Pool::bind(&mut memory, &root(), &generation::G14G, 0).unwrap();
        memory.put(DSID + 4 * 16, &1u32.to_le_bytes());
        pool.release(&mut memory, A, Some([1 << 4, 0, 0, 0]))
            .unwrap();
        settle(&mut pool, &mut memory);
        assert_eq!(
            memory
                .effects
                .iter()
                .filter(|effect| matches!(effect, Effect::Native(NativeWrite::MCache { .. })))
                .count(),
            1
        );
    }
}
