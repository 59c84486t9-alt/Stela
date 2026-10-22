//! Shared native 802.11 frame and security boundaries.
//!
//! Vendor transports supply normalized MPDUs, preserving the actual Protected
//! bit and removing FCS and vendor alignment padding. Decryption observations
//! never imply association, authentication, replay validation or Ethernet
//! carrier. Station management and scanning require actual vendor commands
//! and completion/retirement. The OS owns credentials and WPA authentication.

pub mod frame;
pub mod intel;
pub mod mediatek;
pub mod realtek;
pub mod regulatory;
pub mod scan;
pub mod security;
pub mod station;

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    pub band: Band,
    pub number: u16,
    pub frequency_mhz: u16,
}

/// On-air band, independent of a driver's raw channel encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    Ghz2,
    Ghz5,
    Ghz6,
}

/// Actual received radio information. This is not regulatory permission to TX.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RadioStatus {
    pub band: Band,
    pub channel: u16,
    pub frequency_mhz: u16,
    /// `None` when the device did not measure a usable value.
    pub signal_dbm: Option<i8>,
    pub chain_signal_dbm: [Option<i8>; 4],
    /// Vendor rate/vector encoding with its negotiated layout version.
    pub rate: RawRate,
    pub tsf: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawRate {
    pub layout: u16,
    pub words: [u32; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timestamp {
    Low32(u32),
    Full64(u64),
}

/// Retained aggregation observations. Single-MPDU replay checks refuse them;
/// `security::aggregate` checks aggregates after the backend reorders them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aggregation {
    pub ampdu: Option<u32>,
    pub reorder: Option<Reorder>,
    pub amsdu: Option<Amsdu>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reorder {
    pub ba_id: u16,
    pub next_sequence: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Amsdu {
    pub index: u16,
    pub first: bool,
    pub last: bool,
}

/// A process-wide source of nonzero identities that never wraps, so a stale
/// owner, epoch or ticket can never match a later one.
pub(crate) struct Identities(AtomicU64);

impl Identities {
    pub(crate) const fn new() -> Self {
        Self(AtomicU64::new(1))
    }

    /// The next identity, or `None` once the 64-bit space is used up.
    pub(crate) fn next(&self) -> Option<u64> {
        self.0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                id.checked_add(1).filter(|_| id != 0)
            })
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_never_wrap_or_return_zero() {
        let ids = Identities(AtomicU64::new(u64::MAX - 1));
        assert_eq!(ids.next(), Some(u64::MAX - 1));
        assert_eq!(ids.next(), None);
        assert_eq!(ids.next(), None);
        assert_eq!(Identities(AtomicU64::new(0)).next(), None);
        assert_eq!(Identities::new().next(), Some(1));
    }
}
