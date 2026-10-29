//! Optional copies of each owner's last materialized Cpu image. These are
//! observations, never retirement, coherence, or quiescence receipts.
use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

/// The engine boundary at which an owner copied its materialized state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SourcePhase {
    SliceEnter,
    SliceExit,
    BroadcastEnter,
    BroadcastExit,
    ParkEnter,
    ParkExit,
    ForwardEnter,
    ForwardExit,
    DeviceAdvanceEnter,
    DeviceAdvanceExit,
}

impl SourcePhase {
    fn decode(value: u64) -> Option<Self> {
        Some(match value {
            0 => Self::SliceEnter,
            1 => Self::SliceExit,
            2 => Self::BroadcastEnter,
            3 => Self::BroadcastExit,
            4 => Self::ParkEnter,
            5 => Self::ParkExit,
            6 => Self::ForwardEnter,
            7 => Self::ForwardExit,
            8 => Self::DeviceAdvanceEnter,
            9 => Self::DeviceAdvanceExit,
            _ => return None,
        })
    }
}

/// Last copied source fields, which may already be stale. The host counter
/// dates the copy, not the instruction's retirement or the last native write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializedSource {
    pub host_counter: u64,
    pub phase: SourcePhase,
    pub pc: u64,
    pub sp: u64,
    pub lr: u64,
    pub el: u8,
    pub daif: u8,
}

/// One validated copy from one PE; never a coherent snapshot of other PEs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceObservation {
    pub sequence: u64,
    pub source: MaterializedSource,
}

/// One fixed-size slot per PE, normally written by its owning Machine.
/// All words are atomic. SeqCst keeps sequence and payload in one order, so a
/// reader accepting the same even sequence cannot accept a torn publication.
#[derive(Default)]
pub(super) struct Slot {
    sequence: AtomicU64,
    counter: AtomicU64,
    pc: AtomicU64,
    sp: AtomicU64,
    lr: AtomicU64,
    mode: AtomicU64,
}

impl Slot {
    pub(super) fn publish(&self, source: MaterializedSource) {
        let sequence = self.sequence.load(SeqCst);
        let Some(next) = sequence.checked_add(2).filter(|_| sequence & 1 == 0) else {
            // Never wrap and make a newer copy appear to have an old sequence.
            // Retain the last observation, which remains explicitly stale.
            return;
        };
        // Do not wait if an accidental duplicate attachment also publishes.
        // Only the writer that claims this version may change its payload.
        if self
            .sequence
            .compare_exchange(sequence, sequence + 1, SeqCst, SeqCst)
            .is_err()
        {
            return;
        }
        self.counter.store(source.host_counter, SeqCst);
        self.pc.store(source.pc, SeqCst);
        self.sp.store(source.sp, SeqCst);
        self.lr.store(source.lr, SeqCst);
        self.mode.store(
            (source.phase as u64) << 16 | u64::from(source.el) << 8 | u64::from(source.daif),
            SeqCst,
        );
        self.sequence.store(next, SeqCst);
    }

    pub(super) fn read(&self) -> Option<SourceObservation> {
        // A busy writer cannot make a report wait indefinitely.
        for _ in 0..3 {
            let sequence = self.sequence.load(SeqCst);
            if sequence == 0 {
                return None;
            }
            if sequence & 1 != 0 {
                continue;
            }
            let counter = self.counter.load(SeqCst);
            let pc = self.pc.load(SeqCst);
            let sp = self.sp.load(SeqCst);
            let lr = self.lr.load(SeqCst);
            let mode = self.mode.load(SeqCst);
            if self.sequence.load(SeqCst) == sequence {
                return Some(SourceObservation {
                    sequence,
                    source: MaterializedSource {
                        host_counter: counter,
                        phase: SourcePhase::decode(mode >> 16)?,
                        pc,
                        sp,
                        lr,
                        el: (mode >> 8) as u8,
                        daif: mode as u8,
                    },
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests;
