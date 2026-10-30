// SPDX-License-Identifier: GPL-2.0-only
// Linux net/mac80211/tx.c ieee80211_tx_next_seq/ieee80211_tx_h_sequence.
// Original mac80211 notices are held in THIRD_PARTY.md.
//! Per-station software QoS sequence input, independent of on-air assignment.

use super::{AssociationContext, Error, Phase, Station};
use crate::wifi::frame::next_sequence;

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

    /// Next software sequence input, never an observed on-air sequence.
    /// A preview is not allocation, queue synchronization or a BA agreement.
    /// For ADDBA, native code must first block this TID, synchronize its real
    /// preparation/publication users, and keep that block through the
    /// source exchange. Preview remains available while blocked.
    pub fn next_qos_sequence(&self, context: &AssociationContext, tid: u8) -> Result<u16, Error> {
        let index = self.qos_sequence_index(context, tid)?;
        Ok(self.qos_sequence[index])
    }

    /// Consume one host-prepared sequence for a real unicast QoS data plan.
    /// Call only after all other fallible preparation succeeds, and put this
    /// number in the MAC header (shifted left four, with zero fragment bits).
    /// Device-owned air assignment and the descriptor fields remain
    /// independent: this does not enable SN_VALID or prove the on-air value.
    ///
    /// Consumption is not rolled back for a failed publication/air outcome.
    /// Current private association and TID blocking are checked again here;
    /// publication still needs its own context/radio/key validation.
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

#[cfg(test)]
mod tests {
    use crate::wifi::station::{tests::*, *};

    fn associated() -> (Station, Arc<AssociationContext>) {
        let mut station = Station::new(LOCAL).unwrap();
        let join = modern_join();
        let Action::Configure {
            ticket,
            context: Some(context),
            ..
        } = configuration(&mut station, join.clone(), beacon(&join)).unwrap()
        else {
            panic!("actual modern context");
        };
        station
            .complete_configuration(ticket, Completion::Accepted, 3)
            .unwrap();
        (station, context)
    }

    #[test]
    fn software_qos_sequences_are_independent_modulo_4096_inputs() {
        let (mut station, context) = associated();
        for tid in 0..16 {
            assert_eq!(station.next_qos_sequence(&context, tid), Ok(0));
            for value in 0..4096 {
                assert_eq!(station.allocate_qos_sequence(&context, tid), Ok(value));
            }
            assert_eq!(station.next_qos_sequence(&context, tid), Ok(0));
            assert_eq!(station.allocate_qos_sequence(&context, tid), Ok(0));
            assert_eq!(station.next_qos_sequence(&context, tid), Ok(1));
        }
        assert!(station.next_qos_sequence(&context, 16).is_err());
        assert!(station.allocate_qos_sequence(&context, 16).is_err());
    }

    #[test]
    fn preview_does_not_consume_and_allocation_never_rolls_back_without_air_proof() {
        let (mut station, context) = associated();
        assert_eq!(station.next_qos_sequence(&context, 3), Ok(0));
        assert_eq!(station.next_qos_sequence(&context, 3), Ok(0));
        assert_eq!(station.allocate_qos_sequence(&context, 3), Ok(0));
        // A caller may discard a prepared plan; no TX status is invented here.
        assert_eq!(station.allocate_qos_sequence(&context, 3), Ok(1));
        assert_eq!(station.next_qos_sequence(&context, 3), Ok(2));
        assert_eq!(station.next_qos_sequence(&context, 4), Ok(0));
    }

    #[test]
    fn stale_private_context_and_configuration_phase_cannot_consume_sequences() {
        let (mut station, old) = associated();
        let (_, unrelated) = associated();
        assert_eq!(
            station.allocate_qos_sequence(&unrelated, 0),
            Err(Error::Stale)
        );
        assert_eq!(station.next_qos_sequence(&old, 0), Ok(0));
        station.disconnect().unwrap();
        assert!(station.allocate_qos_sequence(&old, 0).is_err());
        assert!(station.next_qos_sequence(&old, 0).is_err());
        let mut station = Station::new(LOCAL).unwrap();
        let join = modern_join();
        let Action::Configure {
            context: Some(context),
            ..
        } = configuration(&mut station, join.clone(), beacon(&join)).unwrap()
        else {
            panic!("actual modern context");
        };
        assert_eq!(
            station.allocate_qos_sequence(&context, 0),
            Err(Error::NotAssociated)
        );
    }

    #[test]
    fn software_next_inputs_match_complete_unchanged_linux_helper() {
        use sha2::{Digest, Sha256};
        let (mut station, context) = associated();
        let mut trace = Sha256::new();
        for tid in 0..16 {
            for _ in 0..8194 {
                let input = station.allocate_qos_sequence(&context, tid).unwrap() << 4;
                let next = station.next_qos_sequence(&context, tid).unwrap() << 4;
                trace.update(input.to_le_bytes());
                trace.update(next.to_le_bytes());
            }
        }
        let actual: [u8; 32] = trace.finalize().into();
        assert_eq!(
            actual,
            [
                0x18, 0x9e, 0x48, 0x56, 0x56, 0xe1, 0x1b, 0xf8, 0x72, 0xf6, 0x44, 0xef, 0x17, 0x43,
                0x4c, 0xa3, 0xec, 0xf2, 0x47, 0x6f, 0x44, 0xbe, 0xce, 0x2e, 0x6a, 0xc1, 0x1f, 0xe9,
                0xd1, 0x0a, 0x40, 0x5e
            ]
        );
    }

    #[test]
    fn only_accepted_removal_resets_retired_peer_software_counters() {
        for outcome in [Completion::Accepted, Completion::Uncertain] {
            let (mut station, context) = associated();
            assert_eq!(station.allocate_qos_sequence(&context, 3), Ok(0));
            let Action::Remove { ticket, .. } = station.disconnect().unwrap() else {
                panic!("actual removal");
            };
            assert_eq!(station.qos_sequence[3], 1);
            station.complete_removal(ticket, outcome).unwrap();
            assert_eq!(
                station.qos_sequence[3],
                if outcome == Completion::Accepted {
                    0
                } else {
                    1
                }
            );
            assert!(station.next_qos_sequence(&context, 3).is_err());
        }
    }
}
