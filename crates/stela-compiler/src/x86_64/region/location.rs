//! Where each guest GPR currently lives while a region is being emitted.
use super::encoding::{HostGpr, POOL};

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

/// Each GPR is in its own frame slot or in a distinct pool register.
pub fn valid(locations: &[Location; GPR_SLOTS]) -> bool {
    let mut used = 0u16;
    locations
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
