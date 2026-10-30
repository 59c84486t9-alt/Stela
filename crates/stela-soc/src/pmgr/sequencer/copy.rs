//! Physical segment-copy effects from matching LLB11008/12104.
//!
//! Both source/destination addresses and the byte count come from the
//! packet. The source compiler permits one pending copy, emits its join, then
//! advances the next physical chunk. Nothing here supplies firmware bytes or
//! makes an unmodeled destination accept DMA. Copy data is held after a
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
    /// Includes an invalid short read kept after quarantine.
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
    /// Source's all-fields join is admitted only after this copy's full
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
mod tests;
