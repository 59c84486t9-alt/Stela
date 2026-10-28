//! Checked read effects for the matching T6000 tag2 poll emitter.
//!
//! LLB10804/487d0/47f60 qualify the full 32/64-bit packet layout. Only
//! condition0/timeout0 masked-equality polling is admitted here; no physical
//! timeout scale, other condition, hardware trigger or end retirement is
//! inferred. A nonmatching actual read retains the packet PC. Read effects can
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
    /// retired. False retains the same packet PC and its actual last sample.
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
mod tests {
    use super::super::{AddressFormat, RouteOutcome};
    use super::*;
    use crate::platform::apple::pmgr::sequencer::control::{test_fields, test_initial};
    use alloc::{vec, vec::Vec};

    fn cursor(words: &[u32], format: AddressFormat) -> PacketCursor {
        let mut cursor = PacketCursor::unknown();
        cursor.bind_initial_control(test_initial()).unwrap();
        let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        cursor.install_sram(0x292f01a00, &bytes, format).unwrap();
        cursor
    }
    #[test]
    fn actual_reads_hold_no_match_then_advance_to_a_real_store_without_program_retirement() {
        let mut cursor = cursor(
            &[2, 3, 0x10, 0x10, 0x101, 4, 0x1234, 0],
            AddressFormat::Compact,
        );
        assert_eq!(cursor.begin_write().unwrap_err(), Error::ExpectedWrite);
        for (value, matched) in [(0x89, false), (0x10, true)] {
            let claim = cursor.begin_read().unwrap();
            assert_eq!(cursor.begin_write().unwrap_err(), Error::InFlight);
            assert_eq!(cursor.begin_read().unwrap_err(), Error::InFlight);
            assert_eq!(
                cursor.dispatch_read(&claim, &claim.qualify_context(test_fields()).unwrap()),
                Ok(PhysicalRead {
                    address: 12,
                    width: Width::Word
                })
            );
            assert_eq!(cursor.cancel_read(&claim), Err(Error::AlreadyDispatched));
            assert_eq!(
                cursor.finish_read::<()>(&claim, Outcome::Read(value)),
                Ok(matched)
            );
            assert_eq!(
                cursor.dispatch_read(&claim, &claim.qualify_context(test_fields()).unwrap()),
                Err(Error::StaleClaim)
            );
            if !matched {
                assert_eq!(cursor.packet_pc(), Some(0x292f01a00));
                assert_eq!(cursor.last_poll_value(), Some(value));
            }
        }
        assert_eq!(cursor.committed_reads(), 2);
        assert_eq!(cursor.packet_pc(), Some(0x292f01a10));
        let write = cursor.begin_write().unwrap();
        assert_eq!(
            cursor
                .dispatch_write(&write, &write.qualify_context(test_fields()).unwrap())
                .unwrap()
                .value,
            0x1234
        );
        cursor
            .finish_write::<()>(&write, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(cursor.committed_writes(), 1);
        assert_eq!(
            cursor.begin_read().unwrap_err(),
            Error::UnqualifiedRetirement
        );
        assert_eq!(
            cursor.begin_write().unwrap_err(),
            Error::UnqualifiedRetirement
        );
    }
    #[test]
    fn uncertainty_and_out_of_width_results_cannot_repeat_a_side_effecting_read() {
        let mut cursor = cursor(&[2, 0, 0x10, 0], AddressFormat::Compact);
        let cancelled = cursor.begin_read().unwrap();
        cursor.cancel_read(&cancelled).unwrap();
        assert_eq!(
            cursor.dispatch_read(
                &cancelled,
                &cancelled.qualify_context(test_fields()).unwrap()
            ),
            Err(Error::StaleClaim)
        );
        let claim = cursor.begin_read().unwrap();
        cursor
            .dispatch_read(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(
            cursor.finish_read(&claim, Outcome::NoEffect("preflight")),
            Err(FinishError::NoEffect("preflight"))
        );
        let claim = cursor.begin_read().unwrap();
        cursor
            .dispatch_read(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        cursor.set_suspended(true);
        assert_eq!(
            cursor.finish_read(&claim, Outcome::Uncertain(vec![1, 2, 3])),
            Err(FinishError::Uncertain(vec![1, 2, 3]))
        );
        cursor.set_suspended(false);
        assert_eq!(cursor.begin_read().unwrap_err(), Error::UncertainEffects);
        assert_eq!(cursor.begin_write().unwrap_err(), Error::UncertainEffects);
        assert_eq!(
            cursor.uncertain_read(),
            Some(PhysicalRead {
                address: 0,
                width: Width::Word
            })
        );
        assert_eq!(cursor.committed_reads(), 0);
        let mut invalid = super::tests::cursor(&[2, 0, 0, 0], AddressFormat::Compact);
        let claim = invalid.begin_read().unwrap();
        invalid
            .dispatch_read(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(
            invalid.finish_read::<()>(&claim, Outcome::Read(1 << 32)),
            Err(FinishError::InvalidValue(1 << 32))
        );
        assert_eq!(invalid.committed_reads(), 1);
        assert_eq!(invalid.begin_read().unwrap_err(), Error::UncertainEffects);
    }
    #[test]
    fn wide_high_address_padding_and_unknown_controls_are_checked_before_effects() {
        let words = [
            0x12345662, 0x12, 0xff, 0xdeadbeef, 0x89abcdef, 0x12345678, 0x89abcdef, 0x12345678, 0,
        ];
        let mut cursor = cursor(&words, AddressFormat::HighWord);
        let claim = cursor.begin_read().unwrap();
        assert_eq!(
            claim.read(),
            PhysicalRead {
                address: 0x121234567fc,
                width: Width::Double
            }
        );
        cursor.set_suspended(true);
        assert_eq!(
            cursor.dispatch_read(&claim, &claim.qualify_context(test_fields()).unwrap()),
            Err(Error::Suspended)
        );
        cursor.set_suspended(false);
        cursor
            .dispatch_read(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(
            cursor.finish_read::<()>(&claim, Outcome::Read(0x1234567889abcdef)),
            Ok(true)
        );
        assert_eq!(cursor.packet_pc(), Some(0x292f01a20));
        for (words, expected) in [
            (vec![2, 0x4000000, 0, 0], Error::PollEncoding),
            (vec![2, 0x40000000, 0, 0], Error::PollEncoding),
            (
                vec![2, 0x44000000, 0, 0],
                Error::UnqualifiedPollCondition(1),
            ),
            (vec![2, 0x1000100, 0, 0], Error::UnqualifiedPollTimeout(1)),
            (vec![2, 0x1000000, 0, 0], Error::PollEncoding),
            (vec![2, 0, 1, 2], Error::PollExpectedMask),
            (vec![0x22, 0, 1, 0, 1], Error::TruncatedPacket),
        ] {
            let mut cursor = super::tests::cursor(&words, AddressFormat::Compact);
            assert_eq!(cursor.begin_read().unwrap_err(), expected);
            assert_eq!(cursor.packet_pc(), Some(0x292f01a00));
            assert_eq!(cursor.committed_reads(), 0);
        }
        let mut wrong_pad = words;
        wrong_pad[3] = 0;
        assert_eq!(
            super::tests::cursor(&wrong_pad, AddressFormat::HighWord)
                .begin_read()
                .unwrap_err(),
            Error::WidePadding
        );
    }
    #[test]
    fn mounted_partial_read_error_preserves_actual_mmio_effect_and_cannot_be_replayed() {
        use alloc::boxed::Box;
        use core::cell::Cell;
        use {
            stela_contracts::bus::Access, stela_contracts::bus::Bus,
            stela_contracts::bus::Direction, stela_contracts::bus::MmioDevice,
            stela_contracts::bus::MmioError, stela_contracts::bus::refuse,
            stela_contracts::interrupt::InterruptLatch,
        };
        struct ClearOnRead {
            value: Rc<Cell<u32>>,
            reads: Rc<Cell<usize>>,
        }
        impl MmioDevice for ClearOnRead {
            fn name(&self) -> &'static str {
                "checked-read-effect-test"
            }
            fn read(
                &mut self,
                offset: u64,
                width: Width,
                _: &mut Access<'_>,
            ) -> Result<u64, MmioError> {
                self.reads.set(self.reads.get() + 1);
                self.value.set(0); // real committed read effect before refusal
                Err(refuse(
                    self.name(),
                    offset,
                    width,
                    Direction::Read,
                    "error after clearing actual test status",
                ))
            }
            fn write(
                &mut self,
                _: u64,
                _: Width,
                value: u64,
                _: &mut Access<'_>,
            ) -> Result<(), MmioError> {
                self.value.set(value as u32);
                Ok(())
            }
        }
        let value = Rc::new(Cell::new(0));
        let reads = Rc::new(Cell::new(0));
        let mut bus = Bus::new();
        let id = bus.add(Box::new(ClearOnRead {
            value: value.clone(),
            reads: reads.clone(),
        }));
        bus.map(id, 0, 4, 0).unwrap();
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut cursor = cursor(&[1, 0, 0x55, 2, 0, 0, 0, 0], AddressFormat::Compact);
        let claim = cursor.begin_write().unwrap();
        let actual = cursor
            .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        bus.write(actual.address, actual.width, actual.value, &mut access)
            .unwrap();
        cursor
            .finish_write::<MmioError>(&claim, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(value.get(), 0x55);
        let claim = cursor.begin_read().unwrap();
        let actual = cursor
            .dispatch_read(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        let error = bus
            .read(actual.address, actual.width, &mut access)
            .unwrap_err();
        assert_eq!(
            cursor.finish_read(&claim, Outcome::Uncertain(error)),
            Err(FinishError::Uncertain(error))
        );
        assert_eq!(value.get(), 0);
        assert_eq!(reads.get(), 1);
        assert_eq!(cursor.committed_writes(), 1);
        assert_eq!(cursor.packet_pc(), Some(0x292f01a0c));
        assert_eq!(cursor.begin_read().unwrap_err(), Error::UncertainEffects);
        assert_eq!(cursor.begin_write().unwrap_err(), Error::UncertainEffects);
        assert_eq!(reads.get(), 1);
    }
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "requires matching original J314s LLB and iBootData"]
    fn original_poll_emitter_and_actual_source_operands_are_pinned() {
        use sha2::{Digest, Sha256};
        let llb =
            std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").expect("matching original LLB"))
                .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&llb)),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        for (lo, hi, digest) in [
            (
                0x10084,
                0x10678,
                "083937873b3a09af08f8dbdd1c3e966ad73539d5f8cb3c3b9077efd188e70663",
            ),
            (
                0x10804,
                0x10cd8,
                "e652b49ae789d9a376ec397fb8a151e924b85fa6ff358cb2591167dbb9645491",
            ),
            (
                0x487d0,
                0x488e0,
                "96105535e87988926e98a55aa34068697bf4ecf52eb5ad970d90a4c99cb7d19a",
            ),
            (
                0x47f60,
                0x48034,
                "47e3abcc183224fb11e3189ff91bbbb1e7679f19f2af3d41a8b763c11ef72198",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&llb[lo..hi])), digest);
        }
        let input = std::fs::read(
            std::env::var("STELA_TEST_PMGR_M1_IBOOTDATA").expect("matching original iBootData"),
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&input)),
            "6d38d4b30deedb1be526e36179205004957f10e23254392fc3645c63dfd2b095"
        );
        let quad = |offset| u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap());
        assert_eq!(&input[0x24e20..0x24e28], &[6, 0, 0x25, 0, 0, 0, 0, 0]);
        let address = quad(0x24e28);
        let control = quad(0x24e30);
        let expected = quad(0x24e40);
        let mask = quad(0x24e48);
        assert_eq!(
            (address, control, expected, mask),
            (0x28e502100, 0x40, 0x1000000, 0x1000000)
        );
        // Source-derived emitter output from actual original operands, not a
        // native SRAM capture or proof that this source row was triggered.
        let words = [
            ((address >> 4) as u32 & 0xffffffc0) | 2,
            (address >> 36) as u32 & 63,
            ((address >> 2) & 255) as u32,
            mask as u32,
            expected as u32,
            0,
        ];
        let mut cursor = cursor(&words, AddressFormat::HighWord);
        let claim = cursor.begin_read().unwrap();
        assert_eq!(
            claim.read(),
            PhysicalRead {
                address,
                width: Width::Word
            }
        );
        assert_eq!(
            cursor.pending_poll(),
            Some(Poll {
                read: claim.read(),
                mask,
                expected
            })
        );
        cursor
            .dispatch_read(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(
            cursor.finish_read::<()>(&claim, Outcome::Read(0)),
            Ok(false)
        );
        assert_eq!(cursor.packet_pc(), Some(0x292f01a00));
    }
}
