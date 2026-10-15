//! Internal GPR-location validation. Full native intervals and retirement recipes
//! are retained for tests, without a production host-context recovery service.
use super::encoding::{HostGpr, POOL};
#[cfg(test)]
use crate::GuestAddress;

pub const GPR_SLOTS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    Frame { byte_offset: u16 },
    Host(HostGpr),
}

pub const FRAME_LOCATIONS: [Location; GPR_SLOTS] = {
    let mut values = [Location::Frame { byte_offset: 0 }; GPR_SLOTS];
    let mut index = 0;
    while index < GPR_SLOTS {
        values[index] = Location::Frame {
            byte_offset: (index * 8) as u16,
        };
        index += 1;
    }
    values
};

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The named guest instruction has not committed; earlier ones have.
    BeforeGuestCommit,
    /// All consumed instructions committed; frame settlement is in progress.
    ExitSettlement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPoint {
    #[cfg(test)]
    pub native_start: usize,
    #[cfg(test)]
    pub native_end: usize,
    /// PC of the next unretired original instruction; never a native address.
    #[cfg(test)]
    pub guest_pc: GuestAddress,
    #[cfg(test)]
    pub retired_instructions: usize,
    #[cfg(test)]
    pub phase: Phase,
    pub gprs: [Location; GPR_SLOTS],
}

impl RecoveryPoint {
    pub fn validate(&self) -> bool {
        let mut used = 0u16;
        self.gprs
            .iter()
            .enumerate()
            .all(|(index, location)| match location {
                Location::Frame { byte_offset } => usize::from(*byte_offset) == index * 8,
                Location::Host(host) => {
                    let bit = 1u16 << (*host as u8);
                    let valid = POOL.contains(host) && used & bit == 0;
                    used |= bit;
                    valid
                }
            })
    }

    /// Read-only reconstruction. Caller owns the exact interrupted host context,
    /// frame snapshot and code identity. This is not a runtime authority loan.
    #[cfg(test)]
    pub fn reconstruct(
        &self,
        frame: &[u64; GPR_SLOTS],
        host: &[u64; 16],
    ) -> Option<[u64; GPR_SLOTS]> {
        if !self.validate() {
            return None;
        }
        Some(std::array::from_fn(|index| match self.gprs[index] {
            Location::Frame { byte_offset } => frame[usize::from(byte_offset) / 8],
            Location::Host(register) => host[register as usize],
        }))
    }
}
