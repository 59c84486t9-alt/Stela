//! Owned retained-process diagnostics. These copies confer no PE authority.
use crate::{clock, thread};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use stela_compiler::{GuestAddress, GuestState};

/// Produced only from the actual retained owner while a same-domain read-only
/// service loan excludes native execution, finalizers and mapping/publication.
/// All fields are owned diagnostics; changing them cannot change actual state.
#[derive(Debug, Clone)]
pub(crate) struct OwnedProcessObservation {
    pub actual_pc: GuestAddress,
    pub registers: GuestState,
    /// Complete virtual extent of the retained clock's legacy facade.
    pub legacy_clock_bytes: Vec<u8>,
    pub clock_events: Vec<clock::CounterEvent>,
    pub thread: thread::Snapshot,
}
