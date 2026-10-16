//! Owned copies of retained diagnostics.
use crate::{clock, thread};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use stela_compiler::{GuestAddress, GuestState};

/// Taken from the PE while a read-only service borrow excludes native
/// execution, finalizers and mapping changes. Every field is an owned copy.
#[derive(Debug, Clone)]
pub(crate) struct OwnedProcessObservation {
    pub actual_pc: GuestAddress,
    pub registers: GuestState,
    /// Complete virtual extent of the retained clock's legacy facade.
    pub legacy_clock_bytes: Vec<u8>,
    pub clock_events: Vec<clock::CounterEvent>,
    pub thread: thread::Snapshot,
}
