// SPDX-License-Identifier: GPL-2.0-only
// Original Synaptics notices: ../synaptics.rs and input/THIRD_PARTY.md.
//! Physical source passthrough fields. Parent command acknowledgement never
//! invents child acknowledgement, identity, activation or input ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Three,
    Four,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub raw: [u8; 6],
    pub native_sequence: u64,
    /// Last accepted parent client-format setting. None while it is changing;
    /// this is not evidence that a child is active or its stream bytes are valid.
    pub programmed_format: Option<Format>,
}
impl Record {
    /// The source always forwards this byte to the bound child's receiver.
    pub fn first(&self) -> u8 {
        self.raw[1]
    }
    /// Source ordering when a real child owner is active: first three fields,
    /// plus the fourth only in four-byte mode. During child command mode only
    /// first() is delivered. Full raw fields survive either interpretation.
    pub fn fields(&self) -> [u8; 4] {
        [self.raw[1], self.raw[4], self.raw[5], self.raw[2]]
    }
}
pub(super) fn is_packet(raw: [u8; 6]) -> bool {
    raw[0] & 0xfc == 0x84 && raw[3] & 0xcc == 0xc4
}
