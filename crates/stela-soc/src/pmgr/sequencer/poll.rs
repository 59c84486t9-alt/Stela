//! Checked read effects for the matching T6000 tag2 poll emitter.
//!
//! LLB10804/487d0/47f60 check the full 32/64-bit packet layout. Only
//! condition0/timeout0 masked-equality polling is admitted here; no physical
//! timeout scale, other condition, hardware trigger or end retirement is
//! inferred. A nonmatching read keeps the packet PC. Read effects can
//! be partial too: an uncertain route result quarantines all future claims.
use super::{Error, FlightKind, InFlight, PacketCursor, Sram, control};
use alloc::rc::Rc;
use stela_contracts::bus::Width;

const TAG: u32 = 2;
const WIDE: u32 = 1 << 5;
const TIMEOUT: u32 = 1 << 24;
const CONDITION: u32 = 1 << 30;
const FIELDS: u32 = 0x7dff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRead {
    pub address: u64,
    pub width: Width,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Poll {
    pub read: PhysicalRead,
    pub mask: u64,
    pub expected: u64,
}
pub(super) struct Packet {
    poll: Poll,
    end: usize,
    last: Option<u64>,
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
            FlightKind::Poll,
            self.context,
            accepted,
        )
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<E> {
    Read(u64),
    NoEffect(E),
    Uncertain(E),
}
#[derive(Debug, PartialEq, Eq)]
pub enum FinishError<E> {
    Ownership(Error, Outcome<E>),
    NoEffect(E),
    Uncertain(E),
    /// The read was routed; an out-of-width result cannot authorize retry.
    InvalidValue(u64),
}
impl PacketCursor {
    pub fn committed_reads(&self) -> u64 {
        self.committed_reads
    }
    pub fn pending_poll(&self) -> Option<Poll> {
        self.poll.as_ref().map(|packet| packet.poll)
    }
    pub fn last_poll_value(&self) -> Option<u64> {
        self.poll.as_ref().and_then(|packet| packet.last)
    }
    pub fn uncertain_read(&self) -> Option<PhysicalRead> {
        self.uncertain_read
    }
    pub fn begin_read(&mut self) -> Result<ReadClaim, Error> {
        if self.quarantined() {
            return Err(Error::UncertainEffects);
        }
        if self.in_flight.is_some() {
            return Err(Error::InFlight);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        if self.delay.is_some() {
            return Err(Error::ExpectedRead);
        }
        if self.packet.is_some() {
            return Err(Error::ExpectedRead);
        }
        if self.committed_reads == u64::MAX {
            return Err(Error::CounterExhausted);
        }
        if self.poll.is_none() {
            self.poll = Some(decode(
                self.sram.as_ref().ok_or(Error::UnknownSram)?,
                self.pc,
            )?);
        }
        let ticket = self.ticket.checked_add(1).ok_or(Error::TicketExhausted)?;
        self.ticket = ticket;
        self.in_flight = Some(InFlight {
            ticket,
            dispatched: false,
            kind: FlightKind::Poll,
        });
        Ok(ReadClaim {
            owner: self.owner.clone(),
            ticket,
            read: self.poll.as_ref().expect("validated poll").poll.read,
            context: self.control,
        })
    }
    fn check_read(&self, claim: &ReadClaim) -> Result<(), Error> {
        if self.quarantined() {
            return Err(Error::UncertainEffects);
        }
        if Rc::ptr_eq(&self.owner, &claim.owner)
            && self.in_flight.as_ref().is_some_and(|flight| {
                flight.kind == FlightKind::Poll && flight.ticket == claim.ticket
            })
        {
            Ok(())
        } else {
            Err(Error::StaleClaim)
        }
    }
    pub fn dispatch_read(
        &mut self,
        claim: &ReadClaim,
        qualification: &control::Qualification,
    ) -> Result<PhysicalRead, Error> {
        self.check_read(claim)?;
        control::check(
            qualification,
            &claim.owner,
            claim.ticket,
            FlightKind::Poll,
            claim.context,
        )?;
        let flight = self.in_flight.as_mut().expect("checked read claim");
        if flight.dispatched {
            return Err(Error::AlreadyDispatched);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        flight.dispatched = true;
        Ok(claim.read)
    }
    pub fn cancel_read(&mut self, claim: &ReadClaim) -> Result<(), Error> {
        self.check_read(claim)?;
        if self
            .in_flight
            .as_ref()
            .expect("checked read claim")
            .dispatched
        {
            return Err(Error::AlreadyDispatched);
        }
        self.in_flight = None;
        Ok(())
    }
    /// True means this masked poll matched, not that the program/controller
    /// retired. False keeps the same packet PC and its last sample.
    pub fn finish_read<E>(
        &mut self,
        claim: &ReadClaim,
        outcome: Outcome<E>,
    ) -> Result<bool, FinishError<E>> {
        if let Err(error) = self.check_read(claim) {
            return Err(FinishError::Ownership(error, outcome));
        }
        if !self
            .in_flight
            .as_ref()
            .expect("checked read claim")
            .dispatched
        {
            return Err(FinishError::Ownership(Error::NotDispatched, outcome));
        }
        self.in_flight = None;
        let value = match outcome {
            Outcome::NoEffect(error) => return Err(FinishError::NoEffect(error)),
            Outcome::Uncertain(error) => {
                self.uncertain_read = Some(claim.read);
                return Err(FinishError::Uncertain(error));
            }
            Outcome::Read(value) => value,
        };
        self.committed_reads += 1; // capacity checked before dispatch
        if claim.read.width == Width::Word && value > u64::from(u32::MAX) {
            self.uncertain_read = Some(claim.read);
            return Err(FinishError::InvalidValue(value));
        }
        let packet = self.poll.as_mut().expect("claim owns actual poll");
        packet.last = Some(value);
        if value & packet.poll.mask != packet.poll.expected {
            return Ok(false);
        }
        self.pc = packet.end;
        self.poll = None;
        Ok(true)
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
    if header == 0 {
        return Err(Error::UnqualifiedRetirement);
    }
    if header & 1 != 0 {
        return Err(Error::ExpectedRead);
    }
    if header & 0x1f != TAG {
        return Err(Error::UnqualifiedInstruction(header));
    }
    let wide = header & WIDE != 0;
    let mut address = u64::from(header & super::ADDRESS_MASK) << 4;
    if sram.format == super::AddressFormat::HighWord {
        let high = next()?;
        if high & !super::HIGH_ADDRESS_MASK != 0 {
            return Err(Error::HighAddress);
        }
        address |= u64::from(high) << super::HIGH_ADDRESS_SHIFT;
    }
    let control = next()?;
    if control & !FIELDS != 0 {
        return Err(Error::PollEncoding);
    }
    let timeout = ((control >> 8) & 0xffff) as u16;
    let condition = ((control >> 26) & 15) as u8;
    if (control & TIMEOUT != 0) != (timeout != 0) || (control & CONDITION != 0) != (condition != 0)
    {
        return Err(Error::PollEncoding);
    }
    address += u64::from(control & 255) << 2;
    let width = if wide { Width::Double } else { Width::Word };
    if address + width.bytes() > super::MAX_PHYSICAL {
        return Err(Error::PhysicalAddress);
    }
    let values_start = pc + 2 + usize::from(sram.format == super::AddressFormat::HighWord);
    if wide && !values_start.is_multiple_of(2) && next()? != super::WIDE_PADDING {
        return Err(Error::WidePadding);
    }
    let low = u64::from(next()?);
    let mask = if wide {
        low | u64::from(next()?) << 32
    } else {
        low
    };
    let low = u64::from(next()?);
    let expected = if wide {
        low | u64::from(next()?) << 32
    } else {
        low
    };
    if condition != 0 {
        return Err(Error::UnqualifiedPollCondition(condition));
    }
    if timeout != 0 {
        return Err(Error::UnqualifiedPollTimeout(timeout));
    }
    // The admitted source operands already place expected bits inside mask.
    // Do not invent whether other hardware encodings mask both operands.
    if expected & !mask != 0 {
        return Err(Error::PollExpectedMask);
    }
    Ok(Packet {
        poll: Poll {
            read: PhysicalRead { address, width },
            mask,
            expected,
        },
        end: cursor,
        last: None,
    })
}

#[cfg(test)]
mod tests;
