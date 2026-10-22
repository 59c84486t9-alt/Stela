//! Retained physical segment-copy effects from matching LLB11008/12104.
//!
//! Both source/destination addresses and the byte count come from the actual
//! packet. The source compiler permits one pending copy, emits its join, then
//! advances the next physical chunk. Nothing here supplies firmware bytes or
//! makes an unmodeled destination accept DMA. Copy data is retained after a
//! real read; a later destination refusal must not repeat that read.
use super::{Error, FlightKind, InFlight, PacketCursor, RouteOutcome, Sram, control};
use alloc::{rc::Rc, vec::Vec};
use core::fmt;

const TAG: u32 = 8;
const JOIN_TAG: u32 = 0x38;
const HIGH_FIELDS: u32 = 0x003f_003f;
const ADDRESS_FIELDS: u32 = 0xffff_fff8;
const ALIGNMENT: u64 = 128;
/// Every original RCfg33/34 join uses all26 emitted bits set; source helpers
/// also pass7ffffff which truncates to the same26-bit operand. Finite operand
/// meanings/timebases are not inferred from this complete-join form.
const COMPLETE_JOIN: u32 = (1 << 26) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transfer {
    pub source: u64,
    pub destination: u64,
    pub bytes: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRead {
    pub address: u64,
    pub bytes: u32,
}
#[derive(Clone, PartialEq, Eq)]
pub struct PhysicalWrite {
    pub address: u64,
    data: Rc<[u8]>,
}
impl PhysicalWrite {
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}
impl fmt::Debug for PhysicalWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhysicalWrite")
            .field("address", &self.address)
            .field("bytes", &self.data.len())
            .finish()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Read,
    Write,
    Join,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub transfer: Transfer,
    pub phase: Phase,
    /// Includes an invalid short read retained after quarantine.
    pub retained_bytes: Option<usize>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completed {
    pub transfer: Transfer,
    pub join_operand: u32,
}
pub(super) struct Packet {
    transfer: Transfer,
    end: usize,
    data: Option<Rc<[u8]>>,
    written: bool,
}

#[derive(Debug)]
pub struct ReadClaim {
    owner: Rc<()>,
    ticket: u64,
    read: PhysicalRead,
    context: Option<control::Snapshot>,
}
impl ReadClaim {
    pub fn read(&self) -> PhysicalRead {
        self.read
    }
    pub fn control_context(&self) -> Option<control::Snapshot> {
        self.context
    }
    pub fn qualify_context(
        &self,
        accepted: control::Fields,
    ) -> Result<control::Qualification, Error> {
        control::qualify(
            &self.owner,
            self.ticket,
            FlightKind::CopyRead,
            self.context,
            accepted,
        )
    }
}
#[derive(Debug)]
pub struct WriteClaim {
    owner: Rc<()>,
    ticket: u64,
    write: PhysicalWrite,
    context: Option<control::Snapshot>,
}
impl WriteClaim {
    pub fn write(&self) -> &PhysicalWrite {
        &self.write
    }
    pub fn control_context(&self) -> Option<control::Snapshot> {
        self.context
    }
    pub fn qualify_context(
        &self,
        accepted: control::Fields,
    ) -> Result<control::Qualification, Error> {
        control::qualify(
            &self.owner,
            self.ticket,
            FlightKind::CopyWrite,
            self.context,
            accepted,
        )
    }
}
#[derive(PartialEq, Eq)]
pub enum ReadOutcome<E> {
    Read(Vec<u8>),
    NoEffect(E),
    Uncertain(E),
}
impl<E: fmt::Debug> fmt::Debug for ReadOutcome<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(bytes) => f.debug_struct("Read").field("bytes", &bytes.len()).finish(),
            Self::NoEffect(error) => f.debug_tuple("NoEffect").field(error).finish(),
            Self::Uncertain(error) => f.debug_tuple("Uncertain").field(error).finish(),
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum ReadFinishError<E> {
    Ownership(Error, ReadOutcome<E>),
    NoEffect(E),
    Uncertain(E),
    InvalidLength { expected: u32, actual: usize },
}

impl PacketCursor {
    pub fn pending_copy(&self) -> Option<Snapshot> {
        self.copy.as_ref().map(|packet| Snapshot {
            transfer: packet.transfer,
            phase: if packet.written {
                Phase::Join
            } else if packet.data.is_some() {
                Phase::Write
            } else {
                Phase::Read
            },
            retained_bytes: packet.data.as_ref().map(|bytes| bytes.len()),
        })
    }
    pub fn last_copy(&self) -> Option<Completed> {
        self.last_copy
    }
    pub fn uncertain_copy_read(&self) -> Option<PhysicalRead> {
        self.uncertain_copy_read
    }
    pub fn uncertain_copy_write(&self) -> Option<Transfer> {
        self.uncertain_copy_write
    }

    fn claim_copy(&mut self, kind: FlightKind) -> Result<u64, Error> {
        self.check_progress()?;
        if self.packet.is_some() || self.poll.is_some() || self.delay.is_some() {
            return Err(Error::ExpectedCopyRead);
        }
        if self.copy.is_none() {
            self.copy = Some(decode(
                self.sram.as_ref().ok_or(Error::UnknownSram)?,
                self.pc,
            )?);
        }
        let packet = self.copy.as_ref().expect("decoded copy");
        if packet.written {
            return Err(Error::ExpectedCopyJoin);
        }
        match kind {
            FlightKind::CopyRead if packet.data.is_some() => return Err(Error::ExpectedCopyWrite),
            FlightKind::CopyWrite if packet.data.is_none() => return Err(Error::ExpectedCopyRead),
            _ => {}
        }
        if (kind == FlightKind::CopyRead && self.committed_reads == u64::MAX)
            || (kind == FlightKind::CopyWrite && self.committed_writes == u64::MAX)
        {
            return Err(Error::CounterExhausted);
        }
        let ticket = self.ticket.checked_add(1).ok_or(Error::TicketExhausted)?;
        self.ticket = ticket;
        self.in_flight = Some(InFlight {
            ticket,
            dispatched: false,
            kind,
        });
        Ok(ticket)
    }
    fn check_copy(&self, owner: &Rc<()>, ticket: u64, kind: FlightKind) -> Result<(), Error> {
        if self.quarantined() {
            return Err(Error::UncertainEffects);
        }
        if !Rc::ptr_eq(&self.owner, owner)
            || !self
                .in_flight
                .as_ref()
                .is_some_and(|flight| flight.ticket == ticket && flight.kind == kind)
        {
            return Err(Error::StaleClaim);
        }
        Ok(())
    }
    fn dispatch_copy(
        &mut self,
        owner: &Rc<()>,
        ticket: u64,
        kind: FlightKind,
        context: Option<control::Snapshot>,
        qualification: &control::Qualification,
    ) -> Result<(), Error> {
        self.check_copy(owner, ticket, kind)?;
        control::check(qualification, owner, ticket, kind, context)?;
        let flight = self.in_flight.as_mut().expect("checked copy claim");
        if flight.dispatched {
            return Err(Error::AlreadyDispatched);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        flight.dispatched = true;
        Ok(())
    }
    fn cancel_copy(&mut self, owner: &Rc<()>, ticket: u64, kind: FlightKind) -> Result<(), Error> {
        self.check_copy(owner, ticket, kind)?;
        if self
            .in_flight
            .as_ref()
            .expect("checked copy claim")
            .dispatched
        {
            return Err(Error::AlreadyDispatched);
        }
        self.in_flight = None;
        Ok(())
    }
    pub fn begin_copy_read(&mut self) -> Result<ReadClaim, Error> {
        let ticket = self.claim_copy(FlightKind::CopyRead)?;
        let transfer = self.copy.as_ref().expect("claimed copy").transfer;
        Ok(ReadClaim {
            owner: self.owner.clone(),
            ticket,
            read: PhysicalRead {
                address: transfer.source,
                bytes: transfer.bytes,
            },
            context: self.control,
        })
    }
    pub fn dispatch_copy_read(
        &mut self,
        claim: &ReadClaim,
        qualification: &control::Qualification,
    ) -> Result<PhysicalRead, Error> {
        self.dispatch_copy(
            &claim.owner,
            claim.ticket,
            FlightKind::CopyRead,
            claim.context,
            qualification,
        )?;
        Ok(claim.read)
    }
    pub fn cancel_copy_read(&mut self, claim: &ReadClaim) -> Result<(), Error> {
        self.cancel_copy(&claim.owner, claim.ticket, FlightKind::CopyRead)
    }
    pub fn finish_copy_read<E>(
        &mut self,
        claim: &ReadClaim,
        outcome: ReadOutcome<E>,
    ) -> Result<(), ReadFinishError<E>> {
        if let Err(error) = self.check_copy(&claim.owner, claim.ticket, FlightKind::CopyRead) {
            return Err(ReadFinishError::Ownership(error, outcome));
        }
        if !self
            .in_flight
            .as_ref()
            .expect("checked copy claim")
            .dispatched
        {
            return Err(ReadFinishError::Ownership(Error::NotDispatched, outcome));
        }
        self.in_flight = None;
        let bytes = match outcome {
            ReadOutcome::NoEffect(error) => return Err(ReadFinishError::NoEffect(error)),
            ReadOutcome::Uncertain(error) => {
                self.uncertain_copy_read = Some(claim.read);
                return Err(ReadFinishError::Uncertain(error));
            }
            ReadOutcome::Read(bytes) => bytes,
        };
        self.committed_reads += 1;
        let actual = bytes.len();
        self.copy.as_mut().expect("claim owns copy").data = Some(bytes.into());
        if actual != claim.read.bytes as usize {
            self.uncertain_copy_read = Some(claim.read);
            return Err(ReadFinishError::InvalidLength {
                expected: claim.read.bytes,
                actual,
            });
        }
        Ok(())
    }
    pub fn begin_copy_write(&mut self) -> Result<WriteClaim, Error> {
        let ticket = self.claim_copy(FlightKind::CopyWrite)?;
        let packet = self.copy.as_ref().expect("claimed copy");
        Ok(WriteClaim {
            owner: self.owner.clone(),
            ticket,
            write: PhysicalWrite {
                address: packet.transfer.destination,
                data: packet.data.as_ref().expect("copy read committed").clone(),
            },
            context: self.control,
        })
    }
    pub fn dispatch_copy_write(
        &mut self,
        claim: &WriteClaim,
        qualification: &control::Qualification,
    ) -> Result<PhysicalWrite, Error> {
        self.dispatch_copy(
            &claim.owner,
            claim.ticket,
            FlightKind::CopyWrite,
            claim.context,
            qualification,
        )?;
        Ok(claim.write.clone())
    }
    pub fn cancel_copy_write(&mut self, claim: &WriteClaim) -> Result<(), Error> {
        self.cancel_copy(&claim.owner, claim.ticket, FlightKind::CopyWrite)
    }
    pub fn finish_copy_write<E>(
        &mut self,
        claim: &WriteClaim,
        outcome: RouteOutcome<E>,
    ) -> Result<(), super::FinishError<E>> {
        if let Err(error) = self.check_copy(&claim.owner, claim.ticket, FlightKind::CopyWrite) {
            return Err(super::FinishError::Ownership(error, outcome));
        }
        if !self
            .in_flight
            .as_ref()
            .expect("checked copy claim")
            .dispatched
        {
            return Err(super::FinishError::Ownership(Error::NotDispatched, outcome));
        }
        self.in_flight = None;
        match outcome {
            RouteOutcome::NoEffect(error) => return Err(super::FinishError::NoEffect(error)),
            RouteOutcome::Uncertain(error) => {
                self.uncertain_copy_write =
                    Some(self.copy.as_ref().expect("claim owns copy").transfer);
                return Err(super::FinishError::Uncertain(error));
            }
            RouteOutcome::Committed => {}
        }
        self.committed_writes += 1;
        let packet = self.copy.as_mut().expect("claim owns copy");
        packet.written = true;
        self.pc = packet.end;
        Ok(())
    }
    /// Source's all-fields join is admitted only after this actual copy's full
    /// physical write committed. Unknown finite joins refuse; neither a wait
    /// operand nor a zero word may stand in for unsettled physical effects.
    pub(crate) fn advance_copy_join(&mut self) -> Result<Completed, Error> {
        self.check_progress()?;
        if self.packet.is_some() || self.poll.is_some() || self.delay.is_some() {
            return Err(Error::ExpectedCopyJoin);
        }
        let header = *self
            .sram
            .as_ref()
            .ok_or(Error::UnknownSram)?
            .words
            .get(self.pc)
            .ok_or(Error::TruncatedPacket)?;
        if header & 0x3f != JOIN_TAG {
            return Err(Error::ExpectedCopyJoin);
        }
        let operand = header >> 6;
        if operand != COMPLETE_JOIN {
            return Err(Error::UnqualifiedCopyJoin(operand));
        }
        let packet = self
            .copy
            .as_ref()
            .filter(|packet| packet.written)
            .ok_or(Error::ExpectedCopyJoin)?;
        let done = Completed {
            transfer: packet.transfer,
            join_operand: operand,
        };
        self.pc += 1;
        self.copy = None;
        self.last_copy = Some(done);
        Ok(done)
    }
}

fn decode(sram: &Sram, pc: usize) -> Result<Packet, Error> {
    let mut cursor = pc;
    let mut next = || {
        let value = *sram.words.get(cursor).ok_or(Error::TruncatedPacket)?;
        cursor += 1;
        Ok(value)
    };
    let header = next()?;
    if header & 0x3f != TAG {
        return Err(Error::CopyEncoding);
    }
    let count = (header >> 6) + 1;
    let high = if sram.format == super::AddressFormat::HighWord {
        next()?
    } else {
        0
    };
    if high & !HIGH_FIELDS != 0 {
        return Err(Error::HighAddress);
    }
    let source = next()?;
    let destination = next()?;
    if (source | destination) & !ADDRESS_FIELDS != 0 {
        return Err(Error::CopyAlignment);
    }
    let source = (u64::from(source) << 4) | (u64::from(high & 63) << 36);
    let destination = (u64::from(destination) << 4) | (u64::from(high >> 16) << 36);
    if !u64::from(count).is_multiple_of(ALIGNMENT) {
        return Err(Error::CopyAlignment);
    }
    let source_end = source
        .checked_add(u64::from(count))
        .ok_or(Error::PhysicalAddress)?;
    let destination_end = destination
        .checked_add(u64::from(count))
        .ok_or(Error::PhysicalAddress)?;
    if source_end > super::MAX_PHYSICAL || destination_end > super::MAX_PHYSICAL {
        return Err(Error::PhysicalAddress);
    }
    if source < destination_end && destination < source_end {
        return Err(Error::CopyOverlap);
    }
    Ok(Packet {
        transfer: Transfer {
            source,
            destination,
            bytes: count,
        },
        end: cursor,
        data: None,
        written: false,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{AddressFormat, FinishError, PacketKind};
    use super::*;
    use crate::platform::apple::pmgr::sequencer::control::{test_fields, test_initial};
    use alloc::vec;
    const SOURCE: u64 = 0x292f60000;
    const DESTINATION: u64 = 0x1301000000;
    fn words(source: u64, destination: u64, bytes: u32) -> Vec<u32> {
        vec![
            ((bytes - 1) << 6) | TAG,
            ((source >> 36) & 63) as u32 | (((destination >> 36) & 63) as u32) << 16,
            ((source >> 4) & u64::from(ADDRESS_FIELDS)) as u32,
            ((destination >> 4) & u64::from(ADDRESS_FIELDS)) as u32,
            (COMPLETE_JOIN << 6) | JOIN_TAG,
            0,
        ]
    }
    fn cursor(words: &[u32], format: AddressFormat) -> PacketCursor {
        let mut cursor = PacketCursor::unknown();
        cursor.bind_initial_control(test_initial()).unwrap();
        cursor
            .install_sram(
                0x292f01a00,
                &words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>(),
                format,
            )
            .unwrap();
        cursor
    }
    fn payload(bytes: u32) -> Vec<u8> {
        (0..bytes)
            .map(|index| (index ^ (index >> 8)) as u8)
            .collect()
    }

    #[test]
    fn actual_read_bytes_survive_destination_refusal_and_only_real_write_can_join() {
        let mut cursor = cursor(&words(SOURCE, DESTINATION, 256), AddressFormat::HighWord);
        let start = cursor.packet_pc();
        assert_eq!(cursor.packet_kind(), Ok(PacketKind::Copy));
        let read = cursor.begin_copy_read().unwrap();
        assert_eq!(
            read.read(),
            PhysicalRead {
                address: SOURCE,
                bytes: 256
            }
        );
        assert_eq!(cursor.begin_copy_read().unwrap_err(), Error::InFlight);
        cursor
            .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(
            cursor.cancel_copy_read(&read),
            Err(Error::AlreadyDispatched)
        );
        let source_ram = payload(256);
        cursor
            .finish_copy_read::<()>(&read, ReadOutcome::Read(source_ram.clone()))
            .unwrap();
        assert_eq!(cursor.packet_pc(), start);
        assert_eq!(
            cursor.begin_copy_read().unwrap_err(),
            Error::ExpectedCopyWrite
        );
        assert_eq!(cursor.pending_copy().unwrap().phase, Phase::Write);
        let claim = cursor.begin_copy_write().unwrap();
        let write = cursor
            .dispatch_copy_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(write.address, DESTINATION);
        assert_eq!(write.bytes(), source_ram);
        assert_eq!(
            cursor.finish_copy_write(&claim, RouteOutcome::NoEffect("target preflight")),
            Err(FinishError::NoEffect("target preflight"))
        );
        assert_eq!(
            cursor.dispatch_copy_write(&claim, &claim.qualify_context(test_fields()).unwrap()),
            Err(Error::StaleClaim)
        );
        assert_eq!(cursor.committed_reads(), 1);
        let retry = cursor.begin_copy_write().unwrap();
        let write = cursor
            .dispatch_copy_write(&retry, &retry.qualify_context(test_fields()).unwrap())
            .unwrap();
        let mut destination_ram = vec![0; 256];
        destination_ram.copy_from_slice(write.bytes());
        cursor
            .finish_copy_write::<()>(&retry, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(destination_ram, source_ram);
        assert_eq!(cursor.pending_copy().unwrap().phase, Phase::Join);
        assert_eq!(cursor.packet_kind(), Ok(PacketKind::CopyJoin));
        assert_eq!(
            cursor.begin_copy_read().unwrap_err(),
            Error::ExpectedCopyJoin
        );
        let done = cursor.advance_copy_join().unwrap();
        assert_eq!(
            done.transfer,
            Transfer {
                source: SOURCE,
                destination: DESTINATION,
                bytes: 256
            }
        );
        assert_eq!(done.join_operand, COMPLETE_JOIN);
        assert_eq!(cursor.last_copy(), Some(done));
        assert_eq!(
            (cursor.committed_reads(), cursor.committed_writes()),
            (1, 1)
        );
        assert!(cursor.pending_copy().is_none());
        assert_eq!(cursor.packet_kind(), Err(Error::UnqualifiedRetirement));
    }

    #[test]
    fn partial_reads_and_writes_quarantine_the_exact_transfer_without_retry_or_join() {
        for read_failure in [true, false] {
            let mut cursor = cursor(&words(SOURCE, DESTINATION, 128), AddressFormat::HighWord);
            let start = cursor.packet_pc();
            let read = cursor.begin_copy_read().unwrap();
            cursor
                .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
                .unwrap();
            if read_failure {
                assert_eq!(
                    cursor.finish_copy_read(
                        &read,
                        ReadOutcome::Uncertain("read changed target before failure")
                    ),
                    Err(ReadFinishError::Uncertain(
                        "read changed target before failure"
                    ))
                );
                assert_eq!(cursor.uncertain_copy_read(), Some(read.read()));
            } else {
                cursor
                    .finish_copy_read::<()>(&read, ReadOutcome::Read(payload(128)))
                    .unwrap();
                let claim = cursor.begin_copy_write().unwrap();
                let write = cursor
                    .dispatch_copy_write(&claim, &claim.qualify_context(test_fields()).unwrap())
                    .unwrap();
                let mut destination_ram = [0; 128];
                destination_ram[..64].copy_from_slice(&write.bytes()[..64]);
                assert_eq!(
                    cursor
                        .finish_copy_write(&claim, RouteOutcome::Uncertain("partial destination")),
                    Err(FinishError::Uncertain("partial destination"))
                );
                assert_eq!(destination_ram[..64], payload(128)[..64]);
                assert_eq!(
                    cursor.uncertain_copy_write(),
                    Some(Transfer {
                        source: SOURCE,
                        destination: DESTINATION,
                        bytes: 128
                    })
                );
            }
            assert_eq!(cursor.packet_pc(), start);
            assert_eq!(
                cursor.begin_copy_read().unwrap_err(),
                Error::UncertainEffects
            );
            assert_eq!(
                cursor.begin_copy_write().unwrap_err(),
                Error::UncertainEffects
            );
            assert_eq!(cursor.advance_copy_join(), Err(Error::UncertainEffects));
        }
        let mut short = cursor(&words(SOURCE, DESTINATION, 128), AddressFormat::HighWord);
        let read = short.begin_copy_read().unwrap();
        short
            .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(
            short.finish_copy_read::<()>(&read, ReadOutcome::Read(vec![0xaa; 64])),
            Err(ReadFinishError::InvalidLength {
                expected: 128,
                actual: 64
            })
        );
        assert_eq!(short.pending_copy().unwrap().retained_bytes, Some(64));
        assert_eq!(
            short.begin_copy_write().unwrap_err(),
            Error::UncertainEffects
        );
    }

    #[test]
    fn suspension_tokens_join_forms_and_encoding_bounds_preserve_effect_ownership() {
        let mut cursor = cursor(&words(SOURCE, DESTINATION, 128), AddressFormat::HighWord);
        let canceled = cursor.begin_copy_read().unwrap();
        cursor.cancel_copy_read(&canceled).unwrap();
        let read = cursor.begin_copy_read().unwrap();
        assert_eq!(
            cursor.dispatch_copy_read(&canceled, &canceled.qualify_context(test_fields()).unwrap()),
            Err(Error::StaleClaim)
        );
        cursor.set_suspended(true);
        assert_eq!(
            cursor.dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap()),
            Err(Error::Suspended)
        );
        cursor.set_suspended(false);
        cursor
            .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
            .unwrap();
        cursor.set_suspended(true);
        cursor
            .finish_copy_read::<()>(&read, ReadOutcome::Read(payload(128)))
            .unwrap();
        assert_eq!(cursor.begin_copy_write().unwrap_err(), Error::Suspended);
        cursor.set_suspended(false);
        let write = cursor.begin_copy_write().unwrap();
        cursor
            .dispatch_copy_write(&write, &write.qualify_context(test_fields()).unwrap())
            .unwrap();
        cursor.set_suspended(true);
        cursor
            .finish_copy_write::<()>(&write, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(cursor.advance_copy_join(), Err(Error::Suspended));
        cursor.set_suspended(false);
        cursor.advance_copy_join().unwrap();
        let mut finite = words(SOURCE, DESTINATION, 128);
        finite[4] = (7 << 6) | JOIN_TAG;
        let mut finite = self::cursor(&finite, AddressFormat::HighWord);
        let read = finite.begin_copy_read().unwrap();
        finite
            .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
            .unwrap();
        finite
            .finish_copy_read::<()>(&read, ReadOutcome::Read(payload(128)))
            .unwrap();
        let write = finite.begin_copy_write().unwrap();
        finite
            .dispatch_copy_write(&write, &write.qualify_context(test_fields()).unwrap())
            .unwrap();
        finite
            .finish_copy_write::<()>(&write, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(
            finite.advance_copy_join(),
            Err(Error::UnqualifiedCopyJoin(7))
        );
        assert_eq!(finite.pending_copy().unwrap().phase, Phase::Join);
        let mut empty_join = self::cursor(
            &[(COMPLETE_JOIN << 6) | JOIN_TAG, 0],
            AddressFormat::HighWord,
        );
        assert_eq!(empty_join.advance_copy_join(), Err(Error::ExpectedCopyJoin));
        for (mut words, expected) in [
            (words(SOURCE, SOURCE + 128, 256), Error::CopyOverlap),
            (words(SOURCE, DESTINATION, 127), Error::CopyAlignment),
            (words(SOURCE, DESTINATION, 128), Error::HighAddress),
        ] {
            if expected == Error::HighAddress {
                words[1] |= 1 << 8;
            }
            assert_eq!(
                self::cursor(&words, AddressFormat::HighWord)
                    .begin_copy_read()
                    .unwrap_err(),
                expected
            );
        }
        let mut compact = words(SOURCE, 0x701000000, 128);
        compact.remove(1);
        let mut compact = self::cursor(&compact, AddressFormat::Compact);
        assert_eq!(compact.begin_copy_read().unwrap().read().address, SOURCE);
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore = "requires original J314s LLB and iBootData"]
    fn original_copy_emitter_segment_resolution_and_single_pending_join_are_pinned() {
        use sha2::{Digest, Sha256};
        let llb = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").unwrap()).unwrap();
        let data = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_IBOOTDATA").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&llb)),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            "6d38d4b30deedb1be526e36179205004957f10e23254392fc3645c63dfd2b095"
        );
        for (lo, hi, digest) in [
            (
                0x11008,
                0x113e8,
                "a31d850998a8858fa7888ac8165f800503246c2c03bf8135a69db3eed155312f",
            ),
            (
                0x12104,
                0x12840,
                "43395858db77a2ecc76cdbdc17fe7ad776c58ad450cf314f9806685b186d7b39",
            ),
            (
                0x4a5c8,
                0x4a660,
                "4cabac3bf3ee41320356244fe7fb58269d6ac85b01464747faaf2e2048586d43",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&llb[lo..hi])), digest);
        }
        assert_eq!(&llb[0x200056..0x20005d], b"__TEXT\0");
        assert_eq!(&llb[0x20005d..0x200064], b"__DATA\0");
        // Preserve the complete original record, including continuations. A
        // raw opcode census alone does not mark each row executable top-level.
        assert_eq!(
            hex::encode(Sha256::digest(&data[0x4000..0x6bf08])),
            "20975d766b7d5bc14ee81c764073359d80fdae6e276523b3f7055e1957ca8e76"
        );
        let mut joins = [0; 2];
        for row in data[0x4000..0x6bf08].as_chunks::<24>().0 {
            let opcode = u16::from_le_bytes(row[2..4].try_into().unwrap());
            if matches!(opcode, 0x33 | 0x34) {
                let operand = u64::from_le_bytes(row[16..24].try_into().unwrap());
                assert!(matches!(operand, 0x3ffffff | 0x7ffffff));
                assert_eq!(((operand as u32) << 6) | JOIN_TAG, 0xfffffff8);
                joins[usize::from(opcode == 0x34)] += 1;
            }
        }
        assert_eq!(joins, [3, 34]);
    }
}
