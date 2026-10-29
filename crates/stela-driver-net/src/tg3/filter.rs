// SPDX-License-Identifier: GPL-2.0-only
//! tg3's raw-tag, unmanaged receive-mode policy.
use super::Error;
use crate::Mac;
use alloc::vec::Vec;

/// Requested hardware receive policy. The station address always remains.
/// Multicast uses the source 128-bit hash and can admit hash collisions. Up to
/// three additional unicast addresses use exact slots; larger lists select
/// promiscuous mode, as the pinned driver does. Lists are additional to the
/// station address, not a replacement MAC or a device ownership grant.
///
/// As in the source helper, shortening `unicast` leaves old unused slots until
/// the next complete rebuild. This is a hardware filter, not packet isolation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveFilter {
    pub promiscuous: bool,
    pub all_multicast: bool,
    pub multicast: Vec<Mac>,
    pub unicast: Vec<Mac>,
}
impl Default for ReceiveFilter {
    fn default() -> Self {
        Self {
            promiscuous: false,
            all_multicast: true,
            multicast: Vec::new(),
            unicast: Vec::new(),
        }
    }
}
impl ReceiveFilter {
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.multicast.iter().any(|mac| !mac.is_multicast())
            || self
                .unicast
                .iter()
                .any(|mac| mac.is_multicast() || mac.0 == [0; 6])
        {
            Err(Error::InvalidMac)
        } else {
            Ok(())
        }
    }
    pub(super) fn promiscuous(&self) -> bool {
        self.promiscuous || self.unicast.len() > 3
    }
    pub(super) fn hashes(&self) -> [u32; 4] {
        if self.all_multicast {
            return [u32::MAX; 4];
        }
        let mut hashes = [0; 4];
        for mac in &self.multicast {
            let bit = multicast_bit(*mac);
            hashes[bit / 32] |= 1 << (bit % 32);
        }
        hashes
    }
}

// calc_crc returns ~crc32(~0, mac, 6); the source uses ~calc_crc &0x7f.
// This bitwise IEEE implementation is compared against the unchanged Linux
// table generator and crc32_le_base, not a copy of this loop.
pub(super) fn multicast_bit(mac: Mac) -> usize {
    let mut crc = u32::MAX;
    for byte in mac.0 {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
        }
    }
    (crc & 0x7f) as usize
}
