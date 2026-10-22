//! Native tag4 cycle delays, independent of trigger or end retirement.
//!
//! Matching LLB10cd8 emits4|(count<<6), with count bounded to26bits.
//! Only the retained controller's qualified native-cycle owner may supply
//! progress. The host/system counter itself is not this packet's timebase.
use super::{Error, PacketCursor};

pub(super) struct Packet {
    cycles: u32,
    start: u128,
    last: u128,
    end: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub remaining: u32,
    /// Only this instruction's cycle wait finished. No controller/request or
    /// enclosing program is acknowledged by advancing its packet cursor.
    pub complete: bool,
}
impl PacketCursor {
    pub(crate) fn remaining_delay_at(&self, cycles: u128) -> Result<Option<u32>, Error> {
        self.delay
            .as_ref()
            .map(|packet| {
                if cycles < packet.last {
                    return Err(Error::RegressedCycles);
                }
                Ok(packet
                    .cycles
                    .saturating_sub((cycles - packet.start).min(u128::from(u32::MAX)) as u32))
            })
            .transpose()
    }
    pub fn pending_delay(&self) -> Option<u32> {
        self.delay.as_ref().map(|packet| {
            packet
                .cycles
                .saturating_sub((packet.last - packet.start).min(u128::from(u32::MAX)) as u32)
        })
    }
    // Crate-private: external callers cannot manufacture an absolute native
    // clock. The actual shared power::t6000 controller owns that counter.
    pub(crate) fn advance_delay(&mut self, cycles: u128) -> Result<Progress, Error> {
        if self.quarantined() {
            return Err(Error::UncertainEffects);
        }
        if self.in_flight.is_some() {
            return Err(Error::InFlight);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        if self.packet.is_some() || self.poll.is_some() {
            return Err(Error::ExpectedDelay);
        }
        if self.delay.is_none() {
            let sram = self.sram.as_ref().ok_or(Error::UnknownSram)?;
            let header = *sram.words.get(self.pc).ok_or(Error::TruncatedPacket)?;
            if header == 0 {
                return Err(Error::UnqualifiedRetirement);
            }
            if header & 0x3f != 4 {
                return Err(Error::DelayEncoding);
            }
            self.delay = Some(Packet {
                cycles: header >> 6,
                start: cycles,
                last: cycles,
                end: self.pc + 1,
            });
        }
        let packet = self.delay.as_mut().expect("checked delay");
        if cycles < packet.last {
            return Err(Error::RegressedCycles);
        }
        packet.last = cycles;
        let elapsed = (cycles - packet.start).min(u128::from(packet.cycles)) as u32;
        let remaining = packet.cycles - elapsed;
        if remaining == 0 {
            self.pc = packet.end;
            self.delay = None;
        }
        Ok(Progress {
            remaining,
            complete: remaining == 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::bus::Width;
    use crate::platform::apple::pmgr::sequencer::control::{test_fields, test_initial};
    use crate::platform::apple::pmgr::sequencer::{AddressFormat, PhysicalWrite, RouteOutcome};
    use alloc::vec::Vec;
    fn cursor(words: &[u32]) -> PacketCursor {
        let mut cursor = PacketCursor::unknown();
        cursor.bind_initial_control(test_initial()).unwrap();
        cursor
            .install_sram(
                0x292f01a00,
                &words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>(),
                AddressFormat::Compact,
            )
            .unwrap();
        cursor
    }
    #[test]
    fn actual_cycles_hold_pc_without_repeated_sample_progress_or_end_completion() {
        let mut cursor = cursor(&[4 | (3 << 6), 0]);
        assert_eq!(
            cursor.advance_delay(7),
            Ok(Progress {
                remaining: 3,
                complete: false
            })
        );
        assert_eq!(
            cursor.advance_delay(7),
            Ok(Progress {
                remaining: 3,
                complete: false
            })
        );
        assert_eq!(
            cursor.advance_delay(9),
            Ok(Progress {
                remaining: 1,
                complete: false
            })
        );
        assert_eq!(cursor.packet_pc(), Some(0x292f01a00));
        assert_eq!(cursor.begin_write().unwrap_err(), Error::ExpectedWrite);
        assert_eq!(cursor.begin_read().unwrap_err(), Error::ExpectedRead);
        assert_eq!(cursor.advance_delay(8), Err(Error::RegressedCycles));
        assert_eq!(cursor.pending_delay(), Some(1));
        cursor.set_suspended(true);
        assert_eq!(cursor.advance_delay(10), Err(Error::Suspended));
        cursor.set_suspended(false);
        assert_eq!(
            cursor.advance_delay(10),
            Ok(Progress {
                remaining: 0,
                complete: true
            })
        );
        assert_eq!(cursor.packet_pc(), Some(0x292f01a04));
        assert_eq!(cursor.advance_delay(10), Err(Error::UnqualifiedRetirement));
    }
    #[test]
    fn malformed_delay_and_inflight_store_preserve_real_committed_prefix() {
        for header in [0x24, 0x5, 0x3f] {
            let mut cursor = cursor(&[header]);
            assert_eq!(cursor.advance_delay(0), Err(Error::DelayEncoding));
            assert_eq!(cursor.packet_pc(), Some(0x292f01a00));
        }
        // Original tag1 write layout, followed by a real cycle wait and end.
        let mut cursor = cursor(&[1, 0, 0x55, 4 | (1 << 6), 0]);
        let claim = cursor.begin_write().unwrap();
        assert_eq!(cursor.advance_delay(0), Err(Error::InFlight));
        assert_eq!(
            cursor
                .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
                .unwrap(),
            PhysicalWrite {
                address: 0,
                width: Width::Word,
                value: 0x55
            }
        );
        cursor
            .finish_write::<()>(&claim, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(cursor.committed_writes(), 1);
        assert_eq!(
            cursor.advance_delay(0),
            Ok(Progress {
                remaining: 1,
                complete: false
            })
        );
        assert_eq!(
            cursor.advance_delay(1),
            Ok(Progress {
                remaining: 0,
                complete: true
            })
        );
        assert_eq!(cursor.committed_writes(), 1);
        let mut blocked = self::cursor(&[1, 0, 0x55, 4 | (1 << 6), 0]);
        let claim = blocked.begin_write().unwrap();
        blocked
            .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert!(
            blocked
                .finish_write(
                    &claim,
                    RouteOutcome::Uncertain("actual write may have committed")
                )
                .is_err()
        );
        assert_eq!(blocked.advance_delay(100), Err(Error::UncertainEffects));
        assert_eq!(blocked.packet_pc(), Some(0x292f01a00));
    }
}
