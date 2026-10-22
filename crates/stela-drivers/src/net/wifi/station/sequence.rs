// SPDX-License-Identifier: GPL-2.0-only
// Linux net/mac80211/tx.c ieee80211_tx_next_seq/ieee80211_tx_h_sequence.
// Original mac80211 notices are retained in THIRD_PARTY.md.
//! Per-station software QoS sequence input, independent of on-air assignment.

use super::{AssociationContext, Error, Phase, Station};
use crate::net::wifi::frame::next_sequence;

impl Station {
    fn qos_sequence_index(&self, context: &AssociationContext, tid: u8) -> Result<usize, Error> {
        self.validate_association_context(context)?;
        if self.phase != Phase::Associated {
            return Err(Error::NotAssociated);
        }
        if context.negotiated().wmm.is_none() {
            return Err(Error::Unsupported("QoS sequence requires actual WMM"));
        }
        if tid >= 16 {
            return Err(Error::Unsupported("QoS TID"));
        }
        Ok(usize::from(tid))
    }

    /// Actual next software sequence input, never an observed on-air sequence.
    /// A preview is not allocation, queue synchronization or a BA agreement.
    /// For ADDBA, native code must first block this TID, synchronize its real
    /// preparation/publication users, and retain that block through the actual
    /// source exchange. Preview intentionally remains available while blocked.
    pub fn next_qos_sequence(&self, context: &AssociationContext, tid: u8) -> Result<u16, Error> {
        let index = self.qos_sequence_index(context, tid)?;
        Ok(self.qos_sequence[index])
    }

    /// Consume one host-prepared sequence for a real unicast QoS data plan.
    /// Call only after all other fallible preparation succeeds, and put this
    /// number in the MAC header (shifted left four, with zero fragment bits).
    /// Device-owned air assignment and the actual descriptor fields remain
    /// independent: this does not enable SN_VALID or prove the on-air value.
    ///
    /// Consumption is not rolled back for a failed publication/air outcome.
    /// Current private association and TID blocking are checked again here;
    /// actual publication still needs its own context/radio/key validation.
    pub fn allocate_qos_sequence(
        &mut self,
        context: &AssociationContext,
        tid: u8,
    ) -> Result<u16, Error> {
        let index = self.qos_sequence_index(context, tid)?;
        if self.tx_block_ack_blocks_data(tid) {
            return Err(Error::Busy);
        }
        let sequence = self.qos_sequence[index];
        self.qos_sequence[index] = next_sequence(sequence);
        Ok(sequence)
    }
}
