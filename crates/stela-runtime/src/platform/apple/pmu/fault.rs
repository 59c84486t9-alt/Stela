//! History and the original AP's complete-snapshot acknowledgement.
//!
//! mac13j26A434 `_readFaultLog` (VA 9d59cf4..9d59edc) reads the declared
//! log, then writes it back outside scratch. Extended-long SPMI transports it
//! in at most eight-byte chunks. This establishes the captured snapshot and
//! ordered chunk/retry forms, not arbitrary W1C masks, physical reset state or
//! concurrent fault arrivals.
use super::Window;
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::refuse;

/// The extended-long opcode carries a three-bit length-minus-one.
const CHUNK_BYTES: usize = 8;

use stela_soc_data::pmu::history::FaultHistory;

struct Snapshot {
    bytes: Vec<u8>,
    /// The prefix consumed by successful SPMI commands.
    acknowledged: usize,
    /// The next chunk, including a possible whole-provider retry from base.
    next: usize,
}

pub(super) struct FaultLog {
    pub window: Window,
    pending: Vec<u8>,
    reading: Vec<u8>,
    captured: Option<Snapshot>,
}

impl From<FaultHistory> for FaultLog {
    fn from(history: FaultHistory) -> Self {
        let (window, initial) = history.into_parts();
        Self {
            window,
            pending: initial,
            reading: Vec::new(),
            captured: None,
        }
    }
}

impl FaultLog {
    pub fn check_read(&self) -> Result<()> {
        if self.captured.as_ref().is_some_and(|snapshot| {
            snapshot.acknowledged != 0 && snapshot.acknowledged < self.pending.len()
        }) {
            return Err(refuse!(
                "PMU fault visibility during a partial acknowledgement is unqualified"
            ));
        }
        Ok(())
    }

    pub fn byte(&self, offset: u16) -> u8 {
        self.pending[usize::from(offset)]
    }

    /// Capture the complete logical read or its contiguous extended-long
    /// chunks. Unknown read shapes remain non-clearing but supply no ACK proof.
    pub fn capture(&mut self, address: u16, bytes: usize) {
        if address == self.window.base && bytes == self.pending.len() {
            self.reading.clear();
            self.captured = Some(Snapshot {
                bytes: self.pending.clone(),
                acknowledged: 0,
                next: 0,
            });
            return;
        }
        let offset = usize::from(address.wrapping_sub(self.window.base));
        if offset == 0 && bytes == CHUNK_BYTES.min(self.pending.len()) {
            self.reading.clear();
            self.captured = None;
        } else if self.reading.is_empty()
            || offset != self.reading.len()
            || bytes != CHUNK_BYTES.min(self.pending.len() - self.reading.len())
        {
            self.reading.clear();
            return;
        }
        self.reading
            .extend_from_slice(&self.pending[offset..offset + bytes]);
        if self.reading.len() == self.pending.len() {
            self.captured = Some(Snapshot {
                bytes: core::mem::take(&mut self.reading),
                acknowledged: 0,
                next: 0,
            });
        }
    }

    pub fn check_acknowledge(&self, address: u16, bytes: &[u8]) -> Result<()> {
        let Some(snapshot) = &self.captured else {
            return Err(refuse!(
                "PMU fault acknowledge requires a complete captured snapshot"
            ));
        };
        let offset = usize::from(address.wrapping_sub(self.window.base));
        let whole = offset == 0 && bytes.len() == self.pending.len();
        let chunk = (offset == snapshot.next || offset == 0)
            && offset < self.pending.len()
            && bytes.len() == CHUNK_BYTES.min(self.pending.len() - offset);
        if !(whole || chunk)
            || self.pending[..snapshot.acknowledged]
                .iter()
                .any(|&byte| byte != 0)
            || self.pending[snapshot.acknowledged..] != snapshot.bytes[snapshot.acknowledged..]
            || bytes != &snapshot.bytes[offset..offset + bytes.len()]
        {
            return Err(refuse!(
                "PMU fault acknowledge differs from the ordered captured snapshot"
            ));
        }
        Ok(())
    }

    /// Each preflighted command consumes only its byte prefix. Retaining
    /// the completed snapshot admits the source driver's exact retry after a
    /// lost response, without inventing new pending events or clearing new bits.
    pub fn acknowledge(&mut self, address: u16, bytes: usize) {
        let snapshot = self
            .captured
            .as_mut()
            .expect("fault acknowledgement preflight");
        let offset = usize::from(address - self.window.base);
        let end = offset + bytes;
        self.pending[offset..end].fill(0);
        snapshot.acknowledged = snapshot.acknowledged.max(end);
        snapshot.next = end;
    }
}

#[cfg(test)]
mod tests;
