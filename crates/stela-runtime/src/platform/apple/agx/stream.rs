//! The GPU's control streams: the compute data master's CDM stream, the
//! vertex data master's VDM stream, the PPP state records it points to, and
//! the USC shader-state words both name (docs/research/agx.md §5.3).
//!
//! Layouts are Mesa's `src/asahi/genxml/cmdbuf.xml` and the walk is its
//! `lib/decode.c` (Public). Every walker reads through the job's address
//! space, follows links with a bounded return stack, and refuses an unknown
//! block, a word with bits no source names, or a runaway stream by name.

pub mod cdm;
pub mod ppp;
pub mod usc;
pub mod vdm;

use super::isa::machine::{Fault, Memory};

/// Most nested stream calls (Mesa's decoder keeps 16).
pub const CALL_DEPTH: usize = 16;
/// Most blocks one walk visits before it is a runaway.
pub const BLOCK_BUDGET: usize = 1 << 20;

/// Why a stream cannot be walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    Fault(Fault),
    /// The word at `address` has a layout or value no source defines.
    Refused {
        address: u64,
        reason: &'static str,
    },
}

impl From<Fault> for StreamError {
    fn from(fault: Fault) -> Self {
        StreamError::Fault(fault)
    }
}

pub(crate) fn refuse<T>(address: u64, reason: &'static str) -> Result<T, StreamError> {
    Err(StreamError::Refused { address, reason })
}

/// Little-endian words of GPU memory.
pub(crate) fn read_u32(memory: &mut dyn Memory, address: u64) -> Result<u32, StreamError> {
    let mut bytes = [0u8; 4];
    memory.read(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn read_u64(memory: &mut dyn Memory, address: u64) -> Result<u64, StreamError> {
    let mut bytes = [0u8; 8];
    memory.read(address, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

/// `size` bits of `word` from `start`.
pub(crate) fn field(word: u64, start: u32, size: u32) -> u64 {
    (word >> start) & ((1u64 << size) - 1)
}

/// cmdbuf.xml's `groups(n)` modifier: `n` per unit, zero meaning all
/// `2^size` units.
pub(crate) fn groups(value: u64, group: u64, size: u32) -> u64 {
    group * if value == 0 { 1u64 << size } else { value }
}

/// Refuse `word` when it sets bits outside `known`.
pub(crate) fn check_known(
    address: u64,
    word: u64,
    known: u64,
    reason: &'static str,
) -> Result<(), StreamError> {
    if word & !known != 0 {
        return refuse(address, reason);
    }
    Ok(())
}

/// A bit mask of the listed `(start, size)` fields.
pub(crate) const fn mask(fields: &[(u32, u32)]) -> u64 {
    let mut mask = 0;
    let mut i = 0;
    while i < fields.len() {
        let (start, size) = fields[i];
        mask |= ((1u64 << size) - 1) << start;
        i += 1;
    }
    mask
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) use crate::platform::apple::agx::isa::machine::tests::Flat;

    /// Append little-endian words at `address`.
    pub(crate) fn words(memory: &mut Flat, address: u64, words: &[u32]) {
        for (i, word) in words.iter().enumerate() {
            memory.put(address + 4 * i as u64, &word.to_le_bytes());
        }
    }
}
